//! The engine in its network lab (ADR 0044, decision 6): a real tun device in an unprivileged user and
//! network namespace (`scripts/netlab-enter.py`), so that Linux's own TCP stack terminates connections
//! at the engine's listener as Android's does, and timing can be driven with small limits.
//!
//! Each test re-runs itself inside a fresh namespace and passes or fails with that run. They need
//! `unshare` and unprivileged user namespaces, so a plain `cargo test` lists them as ignored, with the
//! reason; `scripts/check.sh rust` runs them, and fails if the namespace cannot be made.
#![cfg(target_os = "linux")]

use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::{Config, Engine, Platform};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, RawFd};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::timeout;

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Set in the test's environment when it runs inside its namespace.
const INSIDE: &str = "NETLAB_INSIDE";
/// The "internet": an address on the namespace's loopback (scripts/netlab-enter.py).
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
/// The UID the lab's Android names for every app in the tunnel.
const APP: u32 = 10_500;
/// The places of counters in `Engine::counters`.
const TCP_FLOWS: usize = 0;
const UDP_FLOWS: usize = 1;
const STRANGERS: usize = 18;
/// How long any one step may take before the test fails.
const STEP: Duration = Duration::from_secs(5);

/// Android as the lab plays it: every app in the tunnel is one app, and protection is the namespace's
/// routing (the engine's sockets are not bound to the tunnel's address, so they never enter it).
struct Lab;

impl Platform for Lab {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        (local.ip() == IpAddr::V4(Addresses::COMMON.tun4)).then_some(APP)
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// Runs `body` with the engine on the namespace's tunnel. Outside the namespace, it runs this same
/// test inside a fresh one instead, and fails unless exactly that test ran there and passed: a lab
/// that could not be built never passes silently.
fn lab<F, Fut>(name: &str, limits: Limits, body: F) -> Outcome
where
    F: FnOnce(Arc<Engine>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    if std::env::var_os(INSIDE).is_none() {
        let enter = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/netlab-enter.py");
        let me = std::env::current_exe()?;
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--"])
            .args(["python3", "-I", enter, "--"])
            .arg(me)
            .args([
                name,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INSIDE, "1")
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() && text.contains("test result: ok. 1 passed") {
            return Ok(());
        }
        return Err(format!("{name}, in its network namespace:\n{text}").into());
    }
    let tunnel = io::stdin().as_fd().try_clone_to_owned()?;
    let config = Config {
        limits,
        mtu: 1500,
        keep_flows: 64,
        addresses: Addresses::COMMON,
    };
    let engine = Arc::new(Engine::start(tunnel, config, Arc::new(Lab), None)?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // The lab keeps the engine until the body is done: a body that does not use it would otherwise
    // drop it at once, and dropping it stops it. A failure says what the engine saw, which tells a
    // fault of the engine from one of the lab.
    runtime
        .block_on(body(Arc::clone(&engine)))
        .map_err(|error| {
            format!(
                "{error}\n  counters {:?}\n  flows {:?}",
                engine.counters(),
                engine.flows()
            )
            .into()
        })
}

/// `step`, failing with `what` if it takes longer than [`STEP`].
async fn within<T>(
    what: &str,
    step: impl Future<Output = io::Result<T>>,
) -> Result<T, Box<dyn std::error::Error>> {
    match timeout(STEP, step).await {
        Ok(result) => Ok(result.map_err(|e| format!("{what}: {e}"))?),
        Err(_) => Err(format!("{what}: no answer within {STEP:?}").into()),
    }
}

/// An app's connection: from the tunnel's address, so the namespace sends it into the tunnel.
async fn app_connect(to: SocketAddr) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
    within(&format!("an app's connection to {to}"), socket.connect(to)).await
}

/// A server on the "internet" that answers each connection's first read with the same bytes.
async fn echo_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind((SERVER, 0)).await?;
    let at = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                if let Ok(n) = connection.read(&mut buffer).await {
                    let _ = connection.write_all(&buffer[..n]).await;
                }
            });
        }
    });
    Ok(at)
}

async fn exchange(
    connection: &mut TcpStream,
    said: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    connection.write_all(said).await?;
    let mut heard = vec![0u8; said.len()];
    let what = format!("the answer to {:?}", String::from_utf8_lossy(said));
    within(&what, connection.read_exact(&mut heard)).await?;
    Ok(heard)
}

/// The engine's listener on the tunnel's address, from the namespace's own table of sockets.
fn listener_port() -> Option<u16> {
    let tun4 = u32::from(Addresses::COMMON.tun4).swap_bytes();
    let wanted = format!("{tun4:08X}");
    std::fs::read_to_string("/proc/net/tcp")
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (address, port) = fields.get(1)?.split_once(':')?;
            (address == wanted && fields.get(3) == Some(&"0A"))
                .then(|| u16::from_str_radix(port, 16).ok())?
        })
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn tcp_and_udp_pass_through_the_engine() -> Outcome {
    lab(
        "tcp_and_udp_pass_through_the_engine",
        Limits::default(),
        |engine| async move {
            let server = echo_server().await?;
            let mut connection = app_connect(server).await?;
            assert_eq!(
                exchange(&mut connection, b"through the tunnel").await?,
                b"through the tunnel"
            );

            let echo = UdpSocket::bind((SERVER, 0)).await?;
            let echo_at = echo.local_addr()?;
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                while let Ok((n, from)) = echo.recv_from(&mut buffer).await {
                    let _ = echo.send_to(&buffer[..n], from).await;
                }
            });
            let app = UdpSocket::bind((Addresses::COMMON.tun4, 0)).await?;
            app.send_to(b"a datagram", echo_at).await?;
            let mut buffer = [0u8; 64];
            let (n, from) = timeout(STEP, app.recv_from(&mut buffer)).await??;
            assert_eq!((&buffer[..n], from), (&b"a datagram"[..], echo_at));

            let counters = engine.counters();
            assert!(
                counters[TCP_FLOWS] >= 1 && counters[UDP_FLOWS] >= 1,
                "counters {counters:?}"
            );
            Ok(())
        },
    )
}

/// Review finding 15: a connection to the engine's listener that does not come from the fake peer, as
/// another app could make, is closed at once and counted, and real connections still pass.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_stranger_at_the_engines_listener_is_turned_away() -> Outcome {
    lab(
        "a_stranger_at_the_engines_listener_is_turned_away",
        Limits::default(),
        |engine| async move {
            let server = echo_server().await?;
            // A first connection, so that the listener is surely up.
            let mut first = app_connect(server).await?;
            exchange(&mut first, b"first").await?;
            let port = listener_port().ok_or("the engine's listener on the tunnel's address")?;

            // Not bound to the tunnel's address: the namespace takes it straight to the listener.
            let mut stranger =
                timeout(STEP, TcpStream::connect((Addresses::COMMON.tun4, port))).await??;
            let mut buffer = [0u8; 16];
            let read = timeout(STEP, stranger.read(&mut buffer)).await?;
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "the stranger was answered: {read:?}"
            );
            assert_eq!(engine.counters()[STRANGERS], 1);

            let mut after = app_connect(server).await?;
            assert_eq!(exchange(&mut after, b"after").await?, b"after");
            Ok(())
        },
    )
}

/// Review finding 16: a relayed connection silent for longer than the sweep's idle limit is the
/// relay's, not the sweep's, and its late answer still reaches the app.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_silent_relayed_connection_outlives_the_sweep() -> Outcome {
    let limits = Limits {
        tcp_idle: Duration::from_secs(2),
        sweep_every: Duration::from_millis(500),
        ..Limits::default()
    };
    lab(
        "a_silent_relayed_connection_outlives_the_sweep",
        limits,
        |_engine| async move {
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let at = listener.local_addr()?;
            let (speak, when) = oneshot::channel::<()>();
            tokio::spawn(async move {
                if let Ok((mut connection, _)) = listener.accept().await {
                    let mut buffer = [0u8; 16];
                    let _ = connection.read(&mut buffer).await;
                    let _ = when.await;
                    let _ = connection.write_all(b"late").await;
                }
            });
            let mut quiet = app_connect(at).await?;
            quiet.write_all(b"hello").await?;
            tokio::time::sleep(Duration::from_secs(4)).await;

            // Packets of another connection make the engine sweep, now that the limit has passed.
            let other = echo_server().await?;
            let mut busy = app_connect(other).await?;
            exchange(&mut busy, b"sweep now").await?;
            tokio::time::sleep(Duration::from_millis(600)).await;
            let mut again = app_connect(other).await?;
            exchange(&mut again, b"and again").await?;

            speak.send(()).map_err(|()| "the server is gone")?;
            let mut late = [0u8; 4];
            within("the late answer", quiet.read_exact(&mut late)).await?;
            assert_eq!(&late, b"late");
            Ok(())
        },
    )
}
