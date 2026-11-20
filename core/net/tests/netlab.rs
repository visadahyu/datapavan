//! The engine in its network lab (ADR 0044, decision 6): a real tun device in an unprivileged user and
//! network namespace (`scripts/netlab-enter.py`), so that Linux's own TCP stack terminates connections
//! at the engine's listener as Android's does, and timing can be driven with small limits.
//!
//! Each test re-runs itself inside a fresh namespace and passes or fails with that run. They need
//! `unshare` and unprivileged user namespaces, so a plain `cargo test` lists them as ignored, with the
//! reason; `scripts/check.sh rust` runs them, and fails if the namespace cannot be made.
#![cfg(target_os = "linux")]

mod common;

use common::{Settings, proxy};
use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::{Chain, Config, Engine, Handover, Platform, packet};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Set in the test's environment when it runs inside its namespace.
const INSIDE: &str = "NETLAB_INSIDE";
/// The script that builds the namespace, and changes it as a test asks.
const ENTER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/netlab-enter.py");
/// The "internet": an address on the namespace's loopback (scripts/netlab-enter.py).
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
/// A second address beside it: another server, or a stranger to the apps.
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
/// The "internet" through IPv6 (RFC 3849), where the machine has IPv6.
const SERVER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
/// The UID the lab's Android names for every app in the tunnel, but the second app.
const APP: u32 = 10_500;
/// A second app: the lab's Android names it for a socket bound to one of [`SECOND_PORTS`], below the
/// ports the kernel hands out by itself.
const SECOND_APP: u32 = 10_600;
const SECOND_PORTS: std::ops::Range<u16> = 20_000..20_100;
/// Ports for which the lab's Android takes [`SLOW_ANSWER`] to name the app, still the first one.
const SLOW_PORTS: std::ops::Range<u16> = 21_000..21_100;
const SLOW_ANSWER: Duration = Duration::from_millis(300);
/// The places of counters in `Engine::counters`.
const TCP_FLOWS: usize = 0;
const UDP_FLOWS: usize = 1;
const PACKETS_IN: usize = 9;
const STRANGERS: usize = 18;
const FRAGMENTS: usize = 19;
const RESETS: usize = 22;
const TCP_REFUSED: usize = 23;
const UDP_MAPPINGS: usize = 24;
const UDP_FILTERED: usize = 25;
const UDP_RELAY_ELSEWHERE: usize = 28;
const UDP_REFUSED: usize = 31;
const UDP_EVICTED: usize = 32;
const ECHO_CARRIED: usize = 33;
const ECHO_REPLIES: usize = 34;
const ECHO_REFUSED: usize = 35;
const ECHO_UNSUPPORTED: usize = 36;
const ECHO_DROPPED: usize = 37;
const REASSEMBLED: usize = 38;
const TOO_BIG: usize = 39;
const PATH_MTU: usize = 40;
/// A server that never answers (scripts/netlab-enter.py routes it into a tunnel no one reads).
const SILENT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
/// How long any one step may take before the test fails.
const STEP: Duration = Duration::from_secs(5);

/// How long the lab's Android takes to protect a socket, in milliseconds: no time, unless a test sets
/// it, so that a chain can come on while a socket is being made. Each test runs in a process of its
/// own.
static PROTECT_DELAY: AtomicU64 = AtomicU64::new(0);

/// Android as the lab plays it: every app in the tunnel is one app, but one whose socket is bound to
/// one of [`SECOND_PORTS`], and it answers slowly for one bound to one of [`SLOW_PORTS`]; protection is
/// the namespace's routing (the engine's sockets are not bound to the tunnel's address, so they never
/// enter it), and takes [`PROTECT_DELAY`].
struct Lab;

impl Platform for Lab {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        if SLOW_PORTS.contains(&local.port()) {
            std::thread::sleep(SLOW_ANSWER);
        }
        let second = SECOND_PORTS.contains(&local.port());
        (local.ip() == IpAddr::V4(Addresses::COMMON.tun4)).then_some(if second {
            SECOND_APP
        } else {
            APP
        })
    }

    fn protect(&self, _: RawFd) -> bool {
        let delay = PROTECT_DELAY.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        true
    }

    fn log(&self, batch: &[u8]) {
        LOGGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(batch);
    }
}

/// Every batch of records the engine handed the log in this test's process, one after another.
static LOGGED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// Runs `body` with the engine on the namespace's tunnel. Outside the namespace, it runs this same
/// test inside a fresh one instead, and fails unless exactly that test ran there and passed: a lab
/// that could not be built never passes silently.
fn lab<F, Fut>(name: &str, limits: &Limits, body: F) -> Outcome
where
    F: FnOnce(Arc<Engine>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    lab_with(name, limits, &[], body)
}

/// [`lab`], with `settings` for scripts/netlab-enter.py in the namespace's environment: for a test
/// that changes what the engine finds as it starts.
fn lab_with<F, Fut>(name: &str, limits: &Limits, settings: &[(&str, &str)], body: F) -> Outcome
where
    F: FnOnce(Arc<Engine>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    if let Some(outcome) = in_namespace(name, settings) {
        return outcome;
    }
    let tunnel = io::stdin().as_fd().try_clone_to_owned()?;
    let engine = Arc::new(Engine::start(
        tunnel,
        lab_config(limits),
        Arc::new(Lab),
        None,
    )?);
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

/// The engine's settings in the lab.
fn lab_config(limits: &Limits) -> Config {
    Config {
        limits: *limits,
        mtu: 1500,
        keep_flows: 64,
        addresses: Addresses::COMMON,
    }
}

/// Engines on the namespace's tunnel, for a test that sets the tunnel up again: each on a descriptor
/// of its own, a duplicate of the tunnel's, as Watch's Kotlin side starts each on a new tunnel, with
/// these limits.
struct Tunnels {
    limits: Limits,
}

impl Tunnels {
    /// An engine on the tunnel, going on from what the engine before it handed over, if any.
    fn start(&self, handover: Option<Handover>) -> io::Result<Engine> {
        let tunnel = io::stdin().as_fd().try_clone_to_owned()?;
        Engine::start_with(
            tunnel,
            lab_config(&self.limits),
            Arc::new(Lab),
            None,
            (handover, None),
        )
    }
}

/// [`lab`], for a test that starts its engines itself ([`Tunnels`]).
fn lab_engines<F, Fut>(name: &str, body: F) -> Outcome
where
    F: FnOnce(Tunnels) -> Fut,
    Fut: Future<Output = Outcome>,
{
    if let Some(outcome) = in_namespace(name, &[]) {
        return outcome;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(body(Tunnels {
            limits: Limits::default(),
        }))
}

/// Outside the namespace, runs the test `name` inside a fresh one, with `settings` in its environment,
/// and gives its outcome; inside, `None`.
fn in_namespace(name: &str, settings: &[(&str, &str)]) -> Option<Outcome> {
    if std::env::var_os(INSIDE).is_some() {
        return None;
    }
    Some(rerun_inside(name, settings))
}

/// Runs the test `name` inside a fresh namespace, and fails unless exactly that test ran there and
/// passed: a lab that could not be built never passes silently.
fn rerun_inside(name: &str, settings: &[(&str, &str)]) -> Outcome {
    let me = std::env::current_exe()?;
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .args(["python3", "-I", ENTER, "--"])
        .arg(me)
        .args([
            name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(INSIDE, "1")
        .envs(settings.iter().copied())
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() && text.contains("test result: ok. 1 passed") {
        return Ok(());
    }
    Err(format!("{name}, in its network namespace:\n{text}").into())
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

/// The port of the engine's listener on the tunnel's address of one IP version, from the namespace's
/// own table of sockets, which prints each 32-bit word of an address as the machine holds it.
fn listener_port(v4: bool) -> Option<u16> {
    let word = |w: &[u8]| {
        let bytes: [u8; 4] = w.try_into().unwrap_or_default();
        format!("{:08X}", u32::from_ne_bytes(bytes))
    };
    let (table, wanted) = if v4 {
        ("/proc/net/tcp", word(&Addresses::COMMON.tun4.octets()))
    } else {
        let octets = Addresses::COMMON.tun6.octets();
        ("/proc/net/tcp6", octets.chunks(4).map(word).collect())
    };
    std::fs::read_to_string(table)
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
        &Limits::default(),
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
        &Limits::default(),
        |engine| async move {
            let server = echo_server().await?;
            // A first connection, so that the listener is surely up.
            let mut first = app_connect(server).await?;
            exchange(&mut first, b"first").await?;
            let port =
                listener_port(true).ok_or("the engine's listener on the tunnel's address")?;

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
        &limits,
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

/// How a connection's reading ended: what it read, and the error that ended it (`None`: a clean close).
async fn read_to_end_or_error(
    connection: &mut TcpStream,
) -> Result<(Vec<u8>, Option<io::ErrorKind>), String> {
    let mut read = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        match timeout(STEP, connection.read(&mut buffer)).await {
            Err(_) => return Err(format!("no end after {read:?}")),
            Ok(Ok(0)) => return Ok((read, None)),
            Ok(Ok(n)) => read.extend_from_slice(&buffer[..n]),
            Ok(Err(error)) => return Ok((read, Some(error.kind()))),
        }
    }
}

/// Review finding 21: a server that resets its connection after part of an answer leaves the app with
/// that part and a reset, not a clean close it would take for a finished answer.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_servers_reset_reaches_the_app_as_a_reset() -> Outcome {
    lab(
        "a_servers_reset_reaches_the_app_as_a_reset",
        &Limits::default(),
        |engine| async move {
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let at = listener.local_addr()?;
            tokio::spawn(async move {
                if let Ok((mut connection, _)) = listener.accept().await {
                    let mut buffer = [0u8; 16];
                    let _ = connection.read(&mut buffer).await;
                    let _ = connection.write_all(b"partial").await;
                    // Long enough for the part to reach the app before the reset.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = connection.set_zero_linger();
                }
            });
            let mut app = app_connect(at).await?;
            app.write_all(b"ask").await?;
            let (read, end) = read_to_end_or_error(&mut app).await?;
            assert_eq!(read, b"partial");
            assert_eq!(end, Some(io::ErrorKind::ConnectionReset));
            assert_eq!(engine.counters()[RESETS], 1);
            Ok(())
        },
    )
}

/// The other way: an app that resets its connection resets the server's too.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_apps_reset_reaches_the_server_as_a_reset() -> Outcome {
    lab(
        "an_apps_reset_reaches_the_server_as_a_reset",
        &Limits::default(),
        |engine| async move {
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let at = listener.local_addr()?;
            let (tell, heard) = oneshot::channel();
            tokio::spawn(async move {
                if let Ok((mut connection, _)) = listener.accept().await {
                    let _ = tell.send(read_to_end_or_error(&mut connection).await);
                }
            });
            let app = app_connect(at).await?;
            let mut app = app;
            app.write_all(b"hello").await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            app.set_zero_linger()?;
            drop(app);
            let (read, end) = timeout(STEP, heard).await???;
            assert_eq!(read, b"hello");
            assert_eq!(end, Some(io::ErrorKind::ConnectionReset));
            assert_eq!(engine.counters()[RESETS], 1);
            Ok(())
        },
    )
}

/// A clean close stays a clean close, both ways, and is not counted as a reset.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_clean_close_stays_clean() -> Outcome {
    lab(
        "a_clean_close_stays_clean",
        &Limits::default(),
        |engine| async move {
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let at = listener.local_addr()?;
            tokio::spawn(async move {
                if let Ok((mut connection, _)) = listener.accept().await
                    && let Ok((read, None)) = read_to_end_or_error(&mut connection).await
                {
                    let _ = connection.write_all(&read).await;
                }
            });
            let mut app = app_connect(at).await?;
            app.write_all(b"bye").await?;
            app.shutdown().await?;
            let (read, end) = read_to_end_or_error(&mut app).await?;
            assert_eq!((read.as_slice(), end), (&b"bye"[..], None));
            assert_eq!(engine.counters()[RESETS], 0);
            Ok(())
        },
    )
}

/// Review finding 18: connections waiting for servers that never answer are capped for the engine as a
/// whole. A SYN beyond the cap is dropped and counted, and its app tries again; once the waiting ones
/// give up, another app's connection opens at once.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn connections_waiting_for_silent_servers_are_capped() -> Outcome {
    let limits = Limits {
        tcp_waiting: 4,
        connect_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    lab(
        "connections_waiting_for_silent_servers_are_capped",
        &limits,
        |engine| async move {
            let mut attempts = Vec::new();
            for port in 1..=6 {
                attempts.push(tokio::spawn(async move {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
                    match timeout(
                        Duration::from_secs(12),
                        socket.connect(SocketAddr::from((SILENT, port))),
                    )
                    .await
                    {
                        Ok(result) => result.map(|_| ()),
                        Err(_) => Err(io::ErrorKind::TimedOut.into()),
                    }
                }));
            }
            // While four wait, the others' SYNs are dropped.
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(
                engine.counters()[TCP_REFUSED] >= 2,
                "counters {:?}",
                engine.counters()
            );
            for attempt in attempts {
                assert!(
                    attempt.await?.is_err(),
                    "a connection to a silent server opened"
                );
            }
            let server = echo_server().await?;
            let mut after = app_connect(server).await?;
            assert_eq!(exchange(&mut after, b"room again").await?, b"room again");
            Ok(())
        },
    )
}

/// ADR 0044, decision 3: each app may hold only its share of the connections waiting for their
/// servers. One app's SYNs to a server that never answers, beyond its share, are dropped and counted,
/// and their ports freed, though the cap for every app has room; so another app's connection opens at
/// once, before any SYN of its own would be sent again. Without the share the first app would fill
/// the cap, and the second's first SYN would be dropped. The SYNs come a little apart, so that Android
/// has named the app of each before the next is decided.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn each_app_holds_only_its_share_of_waiting_connections() -> Outcome {
    let limits = Limits {
        tcp_waiting: 4,
        tcp_share: 2,
        connect_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    lab(
        "each_app_holds_only_its_share_of_waiting_connections",
        &limits,
        |engine| async move {
            let mut attempts = Vec::new();
            for port in 1..=6 {
                attempts.push(tokio::spawn(async move {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
                    match timeout(
                        Duration::from_secs(12),
                        socket.connect(SocketAddr::from((SILENT, port))),
                    )
                    .await
                    {
                        Ok(result) => result.map(|_| ()),
                        Err(_) => Err(io::ErrorKind::TimedOut.into()),
                    }
                }));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                engine.counters()[TCP_REFUSED] >= 4,
                "the first app's SYNs beyond its share were not dropped: counters {:?}",
                engine.counters()
            );
            // The second app's first SYN finds room: well within the second a SYN sent again waits.
            let server = echo_server().await?;
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::from((
                Addresses::COMMON.tun4,
                SECOND_PORTS.start,
            )))?;
            let mut second = timeout(Duration::from_millis(700), socket.connect(server))
                .await
                .map_err(|_| "the second app's connection waited for a SYN sent again")??;
            assert_eq!(exchange(&mut second, b"my share").await?, b"my share");
            for attempt in attempts {
                assert!(
                    attempt.await?.is_err(),
                    "a connection to a silent server opened"
                );
            }
            Ok(())
        },
    )
}

/// How many TCP connections the namespace's sockets began, from its own count in `/proc/net/snmp`
/// (`ActiveOpens`): the apps' and the engine's own.
fn active_opens() -> Result<u64, Box<dyn std::error::Error>> {
    let snmp = std::fs::read_to_string("/proc/net/snmp")?;
    let mut tcp = snmp.lines().filter(|line| line.starts_with("Tcp:"));
    let (names, values) = (
        tcp.next().ok_or("no Tcp: names")?,
        tcp.next().ok_or("no Tcp: values")?,
    );
    let at = names
        .split_whitespace()
        .position(|name| name == "ActiveOpens")
        .ok_or("no ActiveOpens")?;
    Ok(values
        .split_whitespace()
        .nth(at)
        .ok_or("no value")?
        .parse()?)
}

/// The independent review of unit 10, major: a SYN dropped for its app's share never left the phone,
/// and every connection that did is logged under its app. Two of an app's connections to a server that
/// never answers take its share of two; its third, once Android has named the app for those, is
/// dropped before the engine opens a connection of its own for it. Counted from the namespace's own
/// count of connections begun: the app's three, and the engine's, which must be the ones logged.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_syn_refused_for_its_share_never_leaves_the_phone() -> Outcome {
    let limits = Limits {
        tcp_waiting: 8,
        tcp_share: 2,
        connect_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    lab(
        "a_syn_refused_for_its_share_never_leaves_the_phone",
        &limits,
        |engine| async move {
            let before = active_opens()?;
            let mut attempts = Vec::new();
            for port in 1..=3 {
                attempts.push(tokio::spawn(async move {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
                    socket
                        .connect(SocketAddr::from((SILENT, port)))
                        .await
                        .map(|_| ())
                }));
                // Android names each connection's app before the next comes.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(engine.counters()[TCP_REFUSED], 1, "the third SYN dropped");
            // The app gives up before its stack sends a SYN again, a second after the first.
            for attempt in &attempts {
                attempt.abort();
            }
            // The engine's own connections end at its connect timeout, and are logged then.
            let mut logged = Vec::new();
            for _ in 0..100 {
                logged = engine
                    .flows()
                    .into_iter()
                    .filter(|flow| flow.protocol == packet::TCP)
                    .collect();
                if logged.len() >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let began = active_opens()? - before - 3;
            assert_eq!(
                began,
                logged.len() as u64,
                "connections the engine began against those logged: {logged:?}"
            );
            assert_eq!(logged.len(), 2);
            assert!(logged.iter().all(|flow| flow.uid == Some(APP)));
            Ok(())
        },
    )
}

/// The same, where Android is slow: two of an app's connections begin beside Android while few wait,
/// and two more, once more than a share's worth wait, take the app's share of two before Android has
/// named the first two. Those first two have left the phone already, so they take places beyond the
/// share, twice it at most, and are logged under their app; a fifth, with the app at twice its share,
/// is dropped before it leaves.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_connection_begun_beside_android_is_never_dropped_unlogged() -> Outcome {
    let limits = Limits {
        tcp_waiting: 8,
        tcp_share: 2,
        connect_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    lab(
        "a_connection_begun_beside_android_is_never_dropped_unlogged",
        &limits,
        |engine| async move {
            let before = active_opens()?;
            let mut attempts = Vec::new();
            for (port, bound) in [
                (1, SLOW_PORTS.start),
                (2, SLOW_PORTS.start + 1),
                (3, 0),
                (4, 0),
            ] {
                attempts.push(tokio::spawn(async move {
                    let socket = TcpSocket::new_v4()?;
                    socket.bind(SocketAddr::from((Addresses::COMMON.tun4, bound)))?;
                    socket
                        .connect(SocketAddr::from((SILENT, port)))
                        .await
                        .map(|_| ())
                }));
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            // Android has named the first two now.
            tokio::time::sleep(SLOW_ANSWER).await;
            assert_eq!(
                engine.counters()[TCP_REFUSED],
                0,
                "nothing that left was dropped"
            );
            attempts.push(tokio::spawn(async move {
                let socket = TcpSocket::new_v4()?;
                socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
                socket
                    .connect(SocketAddr::from((SILENT, 5)))
                    .await
                    .map(|_| ())
            }));
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(engine.counters()[TCP_REFUSED], 1, "the fifth SYN dropped");
            for attempt in &attempts {
                attempt.abort();
            }
            let mut logged = Vec::new();
            for _ in 0..100 {
                logged = engine
                    .flows()
                    .into_iter()
                    .filter(|flow| flow.protocol == packet::TCP)
                    .collect();
                if logged.len() >= 4 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let began = active_opens()? - before - 5;
            assert_eq!(
                began,
                logged.len() as u64,
                "connections the engine began against those logged: {logged:?}"
            );
            assert_eq!(logged.len(), 4);
            assert!(logged.iter().all(|flow| flow.uid == Some(APP)));
            Ok(())
        },
    )
}

/// ADR 0044, decision 3, on the direct path: at its share, an app's answered lookup ends first to make
/// room for its new mapping, though it is its most recently active one; an app's own resolver leaves
/// one behind each answer, from a socket of its own. A resolver on port 53, which the lab may bind,
/// answers it.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_answered_lookup_ends_first_to_make_room() -> Outcome {
    let limits = Limits {
        udp_mappings: 8,
        udp_share: 2,
        udp_quiet: Duration::from_secs(60),
        ..Limits::default()
    };
    lab(
        "an_answered_lookup_ends_first_to_make_room",
        &limits,
        |engine| async move {
            let resolver = UdpSocket::bind((SERVER, 53)).await?;
            let resolver_at = resolver.local_addr()?;
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok((n, from)) = resolver.recv_from(&mut buffer).await {
                    // The query's ID, then the flags of a response.
                    let mut answer = buffer[..n].to_vec();
                    if answer.len() > 3 {
                        answer[2..4].copy_from_slice(&[0x81, 0x80]);
                    }
                    let _ = resolver.send_to(&answer, from).await;
                }
            });
            let reporter = port_reporter(SERVER).await?;
            let busy = app_socket().await?;
            busy.send_to(b"busy", reporter).await?;
            app_receive(&busy).await?;
            let lookup = app_socket().await?;
            let mut query = 0x6d6du16.to_be_bytes().to_vec();
            query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
            lookup.send_to(&query, resolver_at).await?;
            let (answer, from) = app_receive(&lookup).await?;
            assert_eq!((answer.get(..2), from), (query.get(..2), resolver_at));
            let new = app_socket().await?;
            new.send_to(b"new", reporter).await?;
            app_receive(&new).await?;
            busy.send_to(b"kept", reporter).await?;
            app_receive(&busy).await?;
            let counters = engine.counters();
            assert_eq!(
                (
                    counters[UDP_EVICTED],
                    counters[UDP_REFUSED],
                    counters[UDP_MAPPINGS]
                ),
                (1, 0, 3),
                "evicted, refused and mapped"
            );
            Ok(())
        },
    )
}

/// A server that answers each datagram with the port it came from, in two bytes, as a STUN server
/// tells a client the port its NAT mapped it to.
async fn port_reporter(ip: Ipv4Addr) -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind((ip, 0)).await?;
    let at = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((_, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&from.port().to_be_bytes(), from).await;
        }
    });
    Ok(at)
}

/// An app's UDP socket: on the tunnel's address, so the namespace sends what it sends into the tunnel.
async fn app_socket() -> io::Result<UdpSocket> {
    UdpSocket::bind((Addresses::COMMON.tun4, 0)).await
}

/// The next datagram to the app: what it holds, and where it came from.
async fn app_receive(app: &UdpSocket) -> Result<(Vec<u8>, SocketAddr), Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let (n, from) = within("a datagram to the app", app.recv_from(&mut buffer)).await?;
    buffer.truncate(n);
    Ok((buffer, from))
}

/// The port a [`port_reporter`] saw.
fn reported(answer: &[u8]) -> Result<u16, String> {
    match *answer {
        [high, low] => Ok(u16::from_be_bytes([high, low])),
        _ => Err(format!("not a port: {answer:?}")),
    }
}

/// Review finding 19: one app socket leaves through one port, whatever the destination (RFC 4787,
/// REQ-1). Two servers, at two addresses, see the same port, as two STUN servers would; each server is
/// a flow of its own.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn one_app_socket_leaves_through_one_port_whatever_the_destination() -> Outcome {
    lab(
        "one_app_socket_leaves_through_one_port_whatever_the_destination",
        &Limits::default(),
        |engine| async move {
            let app = app_socket().await?;
            let mut seen = Vec::new();
            for server in [port_reporter(SERVER).await?, port_reporter(OTHER).await?] {
                app.send_to(b"which port?", server).await?;
                let (answer, from) = app_receive(&app).await?;
                assert_eq!(from, server);
                seen.push(reported(&answer)?);
            }
            assert_eq!(seen[0], seen[1], "two ports for one app socket");
            let counters = engine.counters();
            assert_eq!(
                (counters[UDP_MAPPINGS], counters[UDP_FLOWS]),
                (1, 2),
                "one mapping, two flows"
            );
            Ok(())
        },
    )
}

/// Address-dependent filtering (RFC 4787, REQ-8): what comes to a mapping's port from an address its
/// app never sent to is dropped and counted; another port of an address it sent to gets through.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_mapping_lets_in_only_the_addresses_its_app_sent_to() -> Outcome {
    lab(
        "a_mapping_lets_in_only_the_addresses_its_app_sent_to",
        &Limits::default(),
        |engine| async move {
            let app = app_socket().await?;
            let server = port_reporter(SERVER).await?;
            app.send_to(b"hello", server).await?;
            let (answer, _) = app_receive(&app).await?;
            let mapped = SocketAddr::from((SERVER, reported(&answer)?));

            // Sent first: had it got through, the app would read it first.
            let stranger = UdpSocket::bind((OTHER, 0)).await?;
            stranger.send_to(b"from a stranger", mapped).await?;
            let same_address = UdpSocket::bind((SERVER, 0)).await?;
            same_address
                .send_to(b"from the server's address", mapped)
                .await?;

            let (heard, from) = app_receive(&app).await?;
            assert_eq!(
                (heard.as_slice(), from),
                (
                    &b"from the server's address"[..],
                    same_address.local_addr()?
                )
            );
            assert_eq!(engine.counters()[UDP_FILTERED], 1);
            Ok(())
        },
    )
}

/// ADR 0044, decision 1: a mapping's socket is not connected, yet the ICMP error a closed port sends
/// back reaches the app (through `IP_RECVERR`), and a connected app socket reports it.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_closed_port_refuses_an_apps_datagram() -> Outcome {
    lab(
        "a_closed_port_refuses_an_apps_datagram",
        &Limits::default(),
        |_engine| async move {
            let closed = std::net::UdpSocket::bind((SERVER, 0))?.local_addr()?;
            // A blocking socket: its read wakes for the error, which Tokio's does not.
            let app = std::net::UdpSocket::bind((Addresses::COMMON.tun4, 0))?;
            app.connect(closed)?;
            app.set_read_timeout(Some(STEP))?;
            app.send(b"anyone there?")?;
            let mut buffer = [0u8; 64];
            let read = app.recv(&mut buffer);
            assert!(
                matches!(&read, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused),
                "not refused: {read:?}"
            );
            Ok(())
        },
    )
}

/// An answer much larger than the tunnel's MTU reaches the app whole, from the engine's one receive
/// buffer.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_large_answer_arrives_whole() -> Outcome {
    lab(
        "a_large_answer_arrives_whole",
        &Limits::default(),
        |_engine| async move {
            let large: Vec<u8> = (0..=250u8).cycle().take(4_000).collect();
            let server = UdpSocket::bind((SERVER, 0)).await?;
            let at = server.local_addr()?;
            let answer = large.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                if let Ok((_, from)) = server.recv_from(&mut buffer).await {
                    let _ = server.send_to(&answer, from).await;
                }
            });
            let app = app_socket().await?;
            app.send_to(b"a large one, please", at).await?;
            let (heard, from) = app_receive(&app).await?;
            assert_eq!(from, at);
            assert!(heard == large, "{} bytes of 4,000", heard.len());
            Ok(())
        },
    )
}

/// Bytes that differ from one place to the next, so that a datagram put together wrongly shows.
fn large(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// A UDP server at `at` that sends each datagram back as it received it, whole.
async fn udp_echo(at: IpAddr) -> io::Result<SocketAddr> {
    let server = UdpSocket::bind((at, 0)).await?;
    let address = server.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        while let Ok((n, from)) = server.recv_from(&mut buffer).await {
            let _ = server.send_to(&buffer[..n], from).await;
        }
    });
    Ok(address)
}

/// Fails, saying why, where the lab has no IPv6.
fn ipv6_here() -> Outcome {
    if std::env::var_os("NETLAB_IPV6").is_some_and(|v| v == "absent") {
        return Err("the lab has no IPv6 on this machine: scripts/netlab-enter.py says why".into());
    }
    Ok(())
}

/// ADR 0044, decision 5 as amended: a datagram larger than the tunnel's MTU, which the app's kernel
/// cuts into fragments at tun0's 1,500 bytes, reaches the server whole, put together by the engine,
/// and as large an answer reaches the app whole; in IPv4 and IPv6. Before, the engine dropped every
/// fragment.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_datagram_the_apps_kernel_fragmented_reaches_the_server_whole() -> Outcome {
    lab(
        "a_datagram_the_apps_kernel_fragmented_reaches_the_server_whole",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            let datagram = large(3_000);
            for (app_at, server_at) in [
                (IpAddr::V4(Addresses::COMMON.tun4), IpAddr::V4(SERVER)),
                (IpAddr::V6(Addresses::COMMON.tun6), IpAddr::V6(SERVER6)),
            ] {
                let server = udp_echo(server_at).await?;
                let app = UdpSocket::bind((app_at, 0)).await?;
                app.send_to(&datagram, server).await?;
                let (heard, from) = app_receive(&app).await?;
                assert_eq!(from, server);
                assert!(heard == datagram, "{} bytes of 3,000", heard.len());
            }
            let counters = engine.counters();
            assert_eq!((counters[REASSEMBLED], counters[FRAGMENTS]), (2, 0));
            Ok(())
        },
    )
}

/// ADR 0044, decision 3: a lookup to the tunnel's DNS address ends its flow with its answer, so the
/// same app socket's next lookup is a flow of its own.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_lookups_flow_ends_with_its_answer() -> Outcome {
    lab(
        "a_lookups_flow_ends_with_its_answer",
        &Limits::default(),
        |engine| async move {
            // The network's resolver, which sends each lookup back.
            let resolver = UdpSocket::bind((SERVER, 53)).await?;
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok((n, from)) = resolver.recv_from(&mut buffer).await {
                    let _ = resolver.send_to(&buffer[..n], from).await;
                }
            });
            engine.network_changed(Some(IpAddr::V4(SERVER)), false);
            let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
            let app = app_socket().await?;
            for lookup in [&b"first lookup"[..], b"second lookup"] {
                app.send_to(lookup, dns).await?;
                let (heard, from) = app_receive(&app).await?;
                assert_eq!((heard.as_slice(), from), (lookup, dns));
            }
            let lookups = engine
                .flows()
                .iter()
                .filter(|flow| flow.destination == dns)
                .count();
            assert_eq!(lookups, 2, "the first lookup's flow outlived its answer");
            assert_eq!(engine.counters()[UDP_MAPPINGS], 0);
            Ok(())
        },
    )
}

/// RFC 4787, REQ-6: what the app sends keeps its mapping open, not only what comes back. With a
/// two-second limit, a mapping that only sends, once a second, still gets its answer after three
/// seconds, on the same port; once silent both ways for longer, it ends.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn sending_keeps_a_mapping_open() -> Outcome {
    let limits = Limits {
        udp_idle: Duration::from_secs(2),
        ..Limits::default()
    };
    lab(
        "sending_keeps_a_mapping_open",
        &limits,
        |engine| async move {
            let server = UdpSocket::bind((SERVER, 0)).await?;
            let at = server.local_addr()?;
            let (tell, told) = oneshot::channel();
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buffer = [0u8; 64];
                while seen.len() < 4 {
                    match server.recv_from(&mut buffer).await {
                        Ok((_, from)) => seen.push(from),
                        Err(_) => return,
                    }
                }
                if let Some(&last) = seen.last() {
                    let _ = server.send_to(b"late", last).await;
                }
                let _ = tell.send(seen);
            });
            let app = app_socket().await?;
            for tick in 0..4 {
                if tick > 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                app.send_to(b"tick", at).await?;
            }
            let (heard, from) = app_receive(&app).await?;
            assert_eq!((heard.as_slice(), from), (&b"late"[..], at));
            let seen = timeout(STEP, told).await??;
            assert!(
                seen.windows(2).all(|pair| pair[0] == pair[1]),
                "the mapping changed: {seen:?}"
            );
            assert_eq!(engine.counters()[UDP_MAPPINGS], 1);

            tokio::time::sleep(Duration::from_secs(3)).await;
            let reporter = port_reporter(SERVER).await?;
            app.send_to(b"after the silence", reporter).await?;
            app_receive(&app).await?;
            assert_eq!(engine.counters()[UDP_MAPPINGS], 2, "a silent mapping ended");
            Ok(())
        },
    )
}

/// The lab's chain: the app the lab's Android names for every socket in the tunnel goes through the
/// tool's proxy at `proxy`, the tool being another app.
fn lab_chain(proxy: SocketAddr) -> Chain {
    Chain {
        proxy,
        credentials: None,
        tool: APP + 1,
        apps: Some(HashSet::from([APP])),
        udp: true,
        log_destinations: false,
    }
}

/// ADR 0044, decision 2: a chained app's socket reaches two servers over one `UDP ASSOCIATE`, so both
/// see the port of the tool's one relay, and each answer comes back from its own server.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_chained_app_socket_leaves_through_one_association() -> Outcome {
    lab(
        "a_chained_app_socket_leaves_through_one_association",
        &Limits::default(),
        |engine| async move {
            let tool = proxy(Settings::default()).await?;
            engine.chain(Some(lab_chain(tool.address)));
            let app = app_socket().await?;
            let mut seen = Vec::new();
            for server in [port_reporter(SERVER).await?, port_reporter(OTHER).await?] {
                app.send_to(b"which port?", server).await?;
                let (answer, from) = app_receive(&app).await?;
                assert_eq!(from, server);
                seen.push(reported(&answer)?);
            }
            assert_eq!(seen[0], seen[1], "two relays for one app socket");
            assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");
            assert_eq!(engine.counters()[UDP_MAPPINGS], 1);
            Ok(())
        },
    )
}

/// A server that sends a long answer and resets at once: the app still gets the whole answer before
/// the reset, as it would on a real network, where the bytes travel ahead of the reset that follows
/// them (CI, 2026-11-12: the engine's reset discarded the tail it still held for the app).
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_reset_after_a_long_answer_keeps_the_answer() -> Outcome {
    const ANSWER: usize = 400_000;
    lab(
        "a_reset_after_a_long_answer_keeps_the_answer",
        &Limits::default(),
        |engine| async move {
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let at = listener.local_addr()?;
            tokio::spawn(async move {
                if let Ok((mut connection, _)) = listener.accept().await {
                    let mut buffer = [0u8; 16];
                    let _ = connection.read(&mut buffer).await;
                    let _ = connection.write_all(&vec![7u8; ANSWER]).await;
                    // Long enough for the engine to have read it all from the server, not to have
                    // passed it all to the app. The answer fits in the sockets' buffers, so none of it
                    // waits in the server, whose own reset would discard it, as on a real network.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let _ = connection.set_zero_linger();
                }
            });
            let mut app = app_connect(at).await?;
            app.write_all(b"ask").await?;
            // The app reads late, so that much of the answer still waits in the engine's socket toward
            // it when the server's reset comes.
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (read, end) = read_to_end_or_error(&mut app).await?;
            assert_eq!(read.len(), ANSWER);
            assert_eq!(end, Some(io::ErrorKind::ConnectionReset));
            assert_eq!(engine.counters()[RESETS], 1);
            Ok(())
        },
    )
}

/// A tool that shares its proxy on the local network announces its UDP relay at the phone's own address,
/// not on the loopback: datagrams to it never leave the phone, so the relay is used (second review of
/// unit 9, finding 5). The lab's "internet" address is one the namespace holds, as a phone holds its
/// Wi-Fi address.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_relay_at_the_phones_own_address_is_used() -> Outcome {
    lab(
        "a_relay_at_the_phones_own_address_is_used",
        &Limits::default(),
        |engine| async move {
            let settings = Settings {
                relay_at: Some(IpAddr::V4(SERVER)),
                ..Settings::default()
            };
            let tool = proxy(settings).await?;
            engine.chain(Some(lab_chain(tool.address)));
            let server = port_reporter(OTHER).await?;
            let app = app_socket().await?;
            app.send_to(b"which port?", server).await?;
            let (_, from) = app_receive(&app).await?;
            assert_eq!(from, server);
            let relays = tool.relays();
            assert!(
                relays.iter().all(|relay| relay.ip() == IpAddr::V4(SERVER)),
                "relays {relays:?}"
            );
            assert_eq!(engine.counters()[UDP_RELAY_ELSEWHERE], 0);
            Ok(())
        },
    )
}

/// A relay announced at the broadcast address would carry the app's datagrams onto the network beneath,
/// to every host on it: refused and counted, though Linux would let a socket bind that address.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_relay_at_the_broadcast_address_is_refused() -> Outcome {
    lab(
        "a_relay_at_the_broadcast_address_is_refused",
        &Limits::default(),
        |engine| async move {
            let settings = Settings {
                relay_at: Some(IpAddr::V4(Ipv4Addr::BROADCAST)),
                ..Settings::default()
            };
            let tool = proxy(settings).await?;
            engine.chain(Some(lab_chain(tool.address)));
            let server = port_reporter(OTHER).await?;
            let app = app_socket().await?;
            app.send_to(b"which port?", server).await?;
            let mut buffer = [0u8; 64];
            let answer = timeout(Duration::from_secs(1), app.recv_from(&mut buffer)).await;
            assert!(answer.is_err(), "an answer came: {answer:?}");
            assert_eq!(tool.commands(), [3]);
            assert_eq!(engine.counters()[UDP_RELAY_ELSEWHERE], 1);
            Ok(())
        },
    )
}

/// An app's ping socket, made as Android's apps make theirs: unprivileged (the namespace's
/// `ping_group_range` holds its one group), on the tunnel's address so that the namespace sends its
/// requests into the tunnel, and with the echo identifier `id`, which its kernel writes into each
/// request and by which it hands the socket its replies.
fn app_ping_socket(id: u16) -> io::Result<Socket> {
    ping_socket_at(IpAddr::V4(Addresses::COMMON.tun4), id)
}

/// The same on the tunnel's IPv6 address.
fn ping_socket_at(at: IpAddr, id: u16) -> io::Result<Socket> {
    let socket = if at.is_ipv4() {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?
    } else {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?
    };
    socket.bind(&SocketAddr::new(at, id).into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// [`app_ping_socket`], read and written through Tokio, which sends and receives its datagrams.
fn app_pinger(id: u16) -> io::Result<UdpSocket> {
    UdpSocket::from_std(std::net::UdpSocket::from(app_ping_socket(id)?))
}

/// An echo request numbered `sequence` with `data`, ICMP's or `ICMPv6`'s, as an app hands it to its
/// ping socket: the kernel fills in the identifier and the checksum.
fn echo_request(v4: bool, sequence: u16, data: &[u8]) -> Vec<u8> {
    let kind = if v4 {
        packet::ECHO_REQUEST
    } else {
        packet::ECHO_REQUEST_V6
    };
    let mut request = vec![kind, 0, 0, 0, 0, 0];
    request.extend_from_slice(&sequence.to_be_bytes());
    request.extend_from_slice(data);
    request
}

async fn ping(
    app: &UdpSocket,
    to: impl Into<IpAddr>,
    sequence: u16,
    data: &[u8],
) -> io::Result<()> {
    let to = to.into();
    app.send_to(&echo_request(to.is_ipv4(), sequence, data), (to, 0))
        .await
        .map(|_| ())
}

/// An echo reply as an app's ping socket reads it: its identifier, sequence number and data, and who
/// sent it.
type Pong = (u16, u16, Vec<u8>, IpAddr);

fn pong_of(message: &[u8], from: SocketAddr) -> Result<Pong, Box<dyn std::error::Error>> {
    match message {
        [
            packet::ECHO_REPLY | packet::ECHO_REPLY_V6,
            0,
            _,
            _,
            id_high,
            id_low,
            high,
            low,
            data @ ..,
        ] => Ok((
            u16::from_be_bytes([*id_high, *id_low]),
            u16::from_be_bytes([*high, *low]),
            data.to_vec(),
            from.ip(),
        )),
        other => Err(format!("not an echo reply: {other:?}").into()),
    }
}

/// The next echo reply to the app.
async fn pong(app: &UdpSocket) -> Result<Pong, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 2048];
    let (n, from) = within("an echo reply", app.recv_from(&mut buffer)).await?;
    pong_of(&buffer[..n], from)
}

/// That no echo reply reaches the app within a second.
async fn no_pong(app: &UdpSocket) -> Outcome {
    let mut buffer = vec![0u8; 2048];
    match timeout(Duration::from_secs(1), app.recv_from(&mut buffer)).await {
        Err(_) => Ok(()),
        Ok(read) => Err(format!("an answer came: {read:?}").into()),
    }
}

/// The IPv4 ping sockets open in the namespace, the apps' and the engine's, from its own table.
fn ping_sockets() -> Result<usize, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string("/proc/net/icmp")?
        .lines()
        .skip(1)
        .count())
}

const SERVER_IP: IpAddr = IpAddr::V4(SERVER);

/// ADR 0044, decision 5 (review finding 21): an app's ping leaves through a ping socket of the
/// engine's own, whose kernel gives its requests an identifier of that socket's, and each reply
/// reaches the app with the app's own identifier, sequence number and data. The app's kernel hands a
/// ping socket only the replies that bear its identifier, so a reply whose identifier was not
/// restored, or whose checksum is wrong, never reaches it. A ping to the tunnel's DNS address reaches
/// the network's resolver, and its reply comes from the address the app pinged.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_apps_ping_gets_its_reply_with_its_own_id_and_sequence() -> Outcome {
    lab(
        "an_apps_ping_gets_its_reply_with_its_own_id_and_sequence",
        &Limits::default(),
        |engine| async move {
            let app = app_pinger(4242)?;
            for sequence in [1, 2, 65_535] {
                ping(&app, SERVER, sequence, b"a time stamp, say").await?;
                assert_eq!(
                    pong(&app).await?,
                    (4242, sequence, b"a time stamp, say".to_vec(), SERVER_IP)
                );
            }
            let counters = engine.counters();
            assert_eq!((counters[ECHO_CARRIED], counters[ECHO_REPLIES]), (3, 3));
            // One socket of the app's, and one of the engine's for it.
            assert_eq!(ping_sockets()?, 2);

            engine.network_changed(Some(IpAddr::V4(OTHER)), false);
            let dns = Addresses::COMMON.dns4;
            ping(&app, dns, 9, b"the resolver").await?;
            assert_eq!(
                pong(&app).await?,
                (4242, 9, b"the resolver".to_vec(), IpAddr::V4(dns))
            );
            Ok(())
        },
    )
}

/// The same through IPv6, whose echo checksum covers a pseudo-header with both addresses, so that a
/// reply rebuilt from another address, or not rebuilt, fails it. The lab gives the tunnel the common
/// IPv6 address where the machine has IPv6; where it has not, this test fails and says so.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_apps_ipv6_ping_gets_its_reply_with_its_own_id_and_sequence() -> Outcome {
    lab(
        "an_apps_ipv6_ping_gets_its_reply_with_its_own_id_and_sequence",
        &Limits::default(),
        |engine| async move {
            if std::env::var_os("NETLAB_IPV6").is_some_and(|v| v == "absent") {
                return Err(
                    "the lab has no IPv6 on this machine: scripts/netlab-enter.py says why".into(),
                );
            }
            let socket = ping_socket_at(IpAddr::V6(Addresses::COMMON.tun6), 4243)?;
            let app = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
            for sequence in [1, 2] {
                ping(&app, SERVER6, sequence, b"through IPv6").await?;
                assert_eq!(
                    pong(&app).await?,
                    (
                        4243,
                        sequence,
                        b"through IPv6".to_vec(),
                        IpAddr::V6(SERVER6)
                    )
                );
            }
            let counters = engine.counters();
            assert_eq!((counters[ECHO_CARRIED], counters[ECHO_REPLIES]), (2, 2));
            Ok(())
        },
    )
}

/// One engine socket for each app socket and address pinged: three apps' pings at once, each with its
/// own identifier, each get their own reply, and one app pinging a second address gets a second
/// socket of the engine's.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn pings_with_their_own_ids_each_get_their_own_reply() -> Outcome {
    lab(
        "pings_with_their_own_ids_each_get_their_own_reply",
        &Limits::default(),
        |engine| async move {
            let ids = [4301, 4302, 4303];
            let mut apps = Vec::new();
            for id in ids {
                apps.push(app_pinger(id)?);
            }
            for (app, id) in apps.iter().zip(ids) {
                ping(app, SERVER, id % 100, &id.to_be_bytes()).await?;
            }
            for (app, id) in apps.iter().zip(ids) {
                assert_eq!(
                    pong(app).await?,
                    (id, id % 100, id.to_be_bytes().to_vec(), SERVER_IP)
                );
            }
            assert_eq!(ping_sockets()?, 6, "three apps' and three of the engine's");
            ping(&apps[0], OTHER, 4, b"elsewhere").await?;
            assert_eq!(
                pong(&apps[0]).await?,
                (ids[0], 4, b"elsewhere".to_vec(), IpAddr::V4(OTHER))
            );
            assert_eq!(ping_sockets()?, 7);
            let counters = engine.counters();
            assert_eq!((counters[ECHO_CARRIED], counters[ECHO_REPLIES]), (4, 4));
            Ok(())
        },
    )
}

/// The echo identifier of the engine's one ping socket, from the namespace's table: the only one not
/// bound to the tunnel's address. Only for a test with IPv4 ping sockets alone, whose table lists no
/// socket of the other version ([`unbound_pings`]).
fn engine_ping_id() -> Result<u16, Box<dyn std::error::Error>> {
    let table = std::fs::read_to_string("/proc/net/icmp")?;
    let ids: Vec<u16> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (address, port) = line.split_whitespace().nth(1)?.split_once(':')?;
            (address == "00000000").then(|| u16::from_str_radix(port, 16).ok())?
        })
        .collect();
    match ids[..] {
        [id] => Ok(id),
        _ => Err(format!("not one engine socket: {table}").into()),
    }
}

/// The kernel hands a ping socket every echo reply that bears its identifier, from wherever it comes:
/// a reply forged from another address, with the engine socket's identifier, never reaches the app,
/// and the destination's own next reply still does.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_reply_from_another_address_never_reaches_the_app() -> Outcome {
    lab(
        "a_reply_from_another_address_never_reaches_the_app",
        &Limits::default(),
        |_engine| async move {
            let app = app_pinger(4251)?;
            ping(&app, SERVER, 1, b"first").await?;
            assert_eq!(pong(&app).await?, (4251, 1, b"first".to_vec(), SERVER_IP));
            let id = engine_ping_id()?;
            // A stranger, with a raw socket, which the namespace's root may make.
            let stranger = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
            stranger.bind(&SocketAddr::from((OTHER, 0)).into())?;
            let Some(forged) = packet::echo_reply(IpAddr::V4(OTHER), SERVER_IP, id, 99, b"forged")
            else {
                return Err("no reply built".into());
            };
            stranger.send_to(&forged[20..], &SocketAddr::from((SERVER, 0)).into())?;
            ping(&app, SERVER, 2, b"second").await?;
            assert_eq!(pong(&app).await?, (4251, 2, b"second".to_vec(), SERVER_IP));
            no_pong(&app).await
        },
    )
}

/// At most `Limits::echo_sockets` ping sockets: with two pinging an address that never answers, each
/// waiting on its reply and active within `Limits::echo_quiet`, a third app's ping is dropped and
/// counted, while an app that has a socket still pings through it; once both sockets are idle for
/// `Limits::echo_idle`, they are swept, with no packet needed, and the third app's next ping gets
/// through.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn pings_beyond_the_cap_are_dropped_until_a_socket_goes_idle() -> Outcome {
    let limits = Limits {
        echo_sockets: 2,
        echo_idle: Duration::from_secs(2),
        echo_quiet: Duration::from_secs(60),
        ..Limits::default()
    };
    lab(
        "pings_beyond_the_cap_are_dropped_until_a_socket_goes_idle",
        &limits,
        |engine| async move {
            let (first, second, third) = (app_pinger(4401)?, app_pinger(4402)?, app_pinger(4403)?);
            for app in [&first, &second] {
                ping(app, SILENT, 1, b"anyone?").await?;
            }
            counted(&engine, ECHO_CARRIED, 2).await?;
            ping(&third, SERVER, 1, b"beyond the cap").await?;
            no_pong(&third).await?;
            assert_eq!(engine.counters()[ECHO_DROPPED], 1);
            ping(&first, SILENT, 2, b"still in").await?;
            counted(&engine, ECHO_CARRIED, 3).await?;
            assert_eq!(ping_sockets()?, 5, "three apps' and two of the engine's");

            until_count("the engine's idle sockets were swept", ping_sockets, 3).await?;
            ping(&third, SERVER, 2, b"in at last").await?;
            assert_eq!(
                pong(&third).await?,
                (4403, 2, b"in at last".to_vec(), SERVER_IP)
            );
            let counters = engine.counters();
            assert_eq!(
                (
                    counters[ECHO_CARRIED],
                    counters[ECHO_DROPPED],
                    counters[ECHO_EVICTED]
                ),
                (4, 1, 0)
            );
            Ok(())
        },
    )
}

const ECHO_EVICTED: usize = 45;

/// ADR 0044, unit 11b (second review, major 1): a traceroute app runs `ping -c 1 -t N` once for each
/// probe, each with a ping socket and an identifier of its own that never pings again, so 40 such
/// pings take 40 sockets of the engine's, beyond its cap of 32. At the cap each makes room by ending
/// the least recently active socket whose every request has had its reply, so all 40 get their reply,
/// 8 sockets are ended and counted, and the engine holds 32 at most, the ended ones closed. Before, the
/// last 8 found the cap full for 10 seconds and were dropped.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn forty_one_shot_pings_all_get_their_reply() -> Outcome {
    lab(
        "forty_one_shot_pings_all_get_their_reply",
        &Limits::default(),
        |engine| async move {
            for id in 4901..4941 {
                let app = app_pinger(id)?;
                ping(&app, SERVER, 1, b"one shot").await?;
                assert_eq!(pong(&app).await?, (id, 1, b"one shot".to_vec(), SERVER_IP));
            }
            let counters = engine.counters();
            assert_eq!(
                (
                    counters[ECHO_CARRIED],
                    counters[ECHO_REPLIES],
                    counters[ECHO_DROPPED],
                    counters[ECHO_EVICTED]
                ),
                (40, 40, 0, 8)
            );
            // The apps' sockets are closed: what is left is the engine's.
            until_count("the engine's sockets", ping_sockets, 32).await
        },
    )
}

/// ADR 0044, unit 11b: at the cap, with no socket whose every request has had its reply, the one
/// through which nothing passed for `Limits::echo_quiet` makes room: two pings of an address that never
/// answers hold the cap of two, a third app's ping is dropped at once, and once both have been quiet
/// for a second, its next ping ends the one quiet longest and gets its reply.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn at_the_cap_a_quiet_socket_makes_room() -> Outcome {
    let limits = Limits {
        echo_sockets: 2,
        echo_quiet: Duration::from_secs(1),
        echo_idle: Duration::from_secs(60),
        ..Limits::default()
    };
    lab(
        "at_the_cap_a_quiet_socket_makes_room",
        &limits,
        |engine| async move {
            let (first, second, third) = (app_pinger(4951)?, app_pinger(4952)?, app_pinger(4953)?);
            for app in [&first, &second] {
                ping(app, SILENT, 1, b"anyone?").await?;
            }
            counted(&engine, ECHO_CARRIED, 2).await?;
            ping(&third, SERVER, 1, b"too soon").await?;
            counted(&engine, ECHO_DROPPED, 1).await?;
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            ping(&third, SERVER, 2, b"now").await?;
            assert_eq!(pong(&third).await?, (4953, 2, b"now".to_vec(), SERVER_IP));
            assert_eq!(engine.counters()[ECHO_EVICTED], 1);
            until_count("an app's and two of the engine's", ping_sockets, 5).await
        },
    )
}

/// The IPv6 ping sockets open in the namespace.
fn ping_sockets6() -> Result<usize, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string("/proc/net/icmp6")?
        .lines()
        .skip(1)
        .count())
}

/// How many echo requests the namespace's own stack, the lab's "internet", received: `InEchos` of
/// `/proc/net/snmp`, or `Icmp6InEchos` of `/proc/net/snmp6`.
fn echoes_received(v4: bool) -> Result<u64, Box<dyn std::error::Error>> {
    let found = if v4 {
        let snmp = std::fs::read_to_string("/proc/net/snmp")?;
        let mut icmp = snmp.lines().filter(|line| line.starts_with("Icmp: "));
        let (names, values) = (icmp.next().unwrap_or(""), icmp.next().unwrap_or(""));
        names
            .split_whitespace()
            .zip(values.split_whitespace())
            .find(|(name, _)| *name == "InEchos")
            .and_then(|(_, value)| value.parse().ok())
    } else {
        std::fs::read_to_string("/proc/net/snmp6")?
            .lines()
            .find_map(|line| line.strip_prefix("Icmp6InEchos"))
            .and_then(|value| value.trim().parse().ok())
    };
    found.ok_or_else(|| "no count of echo requests received".into())
}

/// Waits until the counter at `index` reaches `value`, for five seconds at most.
async fn counted(engine: &Engine, index: usize, value: u64) -> Outcome {
    for _ in 0..500 {
        if engine.counters()[index] >= value {
            assert_eq!(engine.counters()[index], value, "counted more than once");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!(
        "counter {index} never reached {value}: {:?}",
        engine.counters()
    )
    .into())
}

/// Waits until `count` gives `value`, for five seconds at most.
async fn until_count(
    what: &str,
    count: impl Fn() -> Result<usize, Box<dyn std::error::Error>>,
    value: usize,
) -> Outcome {
    for _ in 0..500 {
        if count()? == value {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("{what}: {} rather than {value}", count()?).into())
}

/// A ping from a blocking app socket that asks for its ICMP errors, `IP_RECVERR` or `IPV6_RECVERR`,
/// as a ping program does: its read wakes for the error, which Tokio's does not.
fn erring_pinger(at: IpAddr, id: u16) -> io::Result<Socket> {
    let socket = ping_socket_at(at, id)?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(STEP))?;
    if at.is_ipv4() {
        nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv4RecvErr, &true)?;
    } else {
        nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Ipv6RecvErr, &true)?;
    }
    Ok(socket)
}

/// What a blocking ping socket reads next: the reply, as [`pong_of`] reads it, or the error its read
/// failed with and the ICMP errors on its queue, each as (origin, type, code).
type Heard = Result<Pong, (io::ErrorKind, Vec<(u8, u8, u8)>)>;

fn hear(app: &Socket, from: IpAddr) -> Result<Heard, Box<dyn std::error::Error>> {
    use nix::libc;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 256];
    let error = match (&*app).read(&mut buffer) {
        Ok(n) => return Ok(Ok(pong_of(&buffer[..n], SocketAddr::new(from, 0))?)),
        Err(error) => error.kind(),
    };
    let mut control = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6);
    let mut quoted = [0u8; 256];
    let mut parts = [io::IoSliceMut::new(&mut quoted)];
    let mut errors = Vec::new();
    if let Ok(message) = recvmsg::<SockaddrStorage>(
        app.as_raw_fd(),
        &mut parts,
        Some(&mut control),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    ) {
        for message in message.cmsgs()? {
            if let ControlMessageOwned::Ipv4RecvErr(error, _)
            | ControlMessageOwned::Ipv6RecvErr(error, _) = message
            {
                errors.push((error.ee_origin, error.ee_type, error.ee_code));
            }
        }
    }
    Ok(Err((error, errors)))
}

/// An app pings with the chain off, so that its socket and the engine's are open; then a chain comes
/// on. Android cannot say whose a ping is, so the next one, from the same app socket, leaves through
/// no socket: the app learns at once that its destination is "administratively prohibited", from the
/// error the engine quotes its request in, and the "internet" receives no request. Once the chain is
/// off, the same socket's ping gets its reply.
fn refused_once_a_chain_comes_on(engine: &Engine, v4: bool) -> Outcome {
    let (at, server, id) = if v4 {
        (IpAddr::V4(Addresses::COMMON.tun4), SERVER_IP, 4601)
    } else {
        (
            IpAddr::V6(Addresses::COMMON.tun6),
            IpAddr::V6(SERVER6),
            4602,
        )
    };
    let app = erring_pinger(at, id)?;
    let to = SocketAddr::new(server, 0).into();
    app.send_to(&echo_request(v4, 1, b"before"), &to)?;
    assert_eq!(hear(&app, server)?, Ok((id, 1, b"before".to_vec(), server)));
    let received = echoes_received(v4)?;

    // The tool's proxy is never asked: a ping does not go through it.
    engine.chain(Some(lab_chain(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))));
    app.send_to(&echo_request(v4, 2, b"may I?"), &to)?;
    let refused = if v4 {
        // Linux's ping socket: "host unreachable" for ICMP's code 13.
        (
            io::ErrorKind::HostUnreachable,
            vec![(nix::libc::SO_EE_ORIGIN_ICMP, 3, 13)],
        )
    } else {
        // And "permission denied" for ICMPv6's code 1.
        (
            io::ErrorKind::PermissionDenied,
            vec![(nix::libc::SO_EE_ORIGIN_ICMP6, 1, 1)],
        )
    };
    assert_eq!(hear(&app, server)?, Err(refused));
    assert_eq!(echoes_received(v4)?, received, "the refused request left");
    let counters = engine.counters();
    assert_eq!((counters[ECHO_REFUSED], counters[ECHO_CARRIED]), (1, 1));

    engine.chain(None);
    app.send_to(&echo_request(v4, 3, b"and now?"), &to)?;
    assert_eq!(
        hear(&app, server)?,
        Ok((id, 3, b"and now?".to_vec(), server))
    );
    Ok(())
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_ping_is_refused_once_a_chain_comes_on() -> Outcome {
    lab(
        "a_ping_is_refused_once_a_chain_comes_on",
        &Limits::default(),
        |engine| async move { refused_once_a_chain_comes_on(&engine, true) },
    )
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_ipv6_ping_is_refused_once_a_chain_comes_on() -> Outcome {
    lab(
        "an_ipv6_ping_is_refused_once_a_chain_comes_on",
        &Limits::default(),
        |engine| async move {
            if std::env::var_os("NETLAB_IPV6").is_some_and(|v| v == "absent") {
                return Err(
                    "the lab has no IPv6 on this machine: scripts/netlab-enter.py says why".into(),
                );
            }
            refused_once_a_chain_comes_on(&engine, false)
        },
    )
}

/// Nothing comes in on the direct path while a chain is on: a reply the engine's socket receives
/// once a chain is on, here one sent from the address pinged with that socket's identifier, never
/// reaches the app, and the socket ends.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_reply_after_a_chain_comes_on_never_reaches_the_app() -> Outcome {
    lab(
        "a_reply_after_a_chain_comes_on_never_reaches_the_app",
        &Limits::default(),
        |engine| async move {
            let app = app_pinger(4611)?;
            ping(&app, SERVER, 1, b"before").await?;
            assert_eq!(pong(&app).await?, (4611, 1, b"before".to_vec(), SERVER_IP));
            let id = engine_ping_id()?;
            engine.chain(Some(lab_chain(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))));
            let late = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
            late.bind(&SocketAddr::from((SERVER, 0)).into())?;
            let Some(reply) = packet::echo_reply(SERVER_IP, SERVER_IP, id, 77, b"late") else {
                return Err("no reply built".into());
            };
            late.send_to(&reply[20..], &SocketAddr::from((SERVER, 0)).into())?;
            no_pong(&app).await?;
            until_count("the engine's socket after the late reply", ping_sockets, 1).await
        },
    )
}

/// A chain that comes on while a ping's socket is being made, here while the lab's Android takes half
/// a second to protect it, lets nothing that waited for it leave: the request is counted refused, and
/// the "internet" receives none.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_ping_waiting_for_its_socket_stays_once_a_chain_comes_on() -> Outcome {
    lab(
        "a_ping_waiting_for_its_socket_stays_once_a_chain_comes_on",
        &Limits::default(),
        |engine| async move {
            PROTECT_DELAY.store(500, Ordering::Relaxed);
            let app = app_pinger(4621)?;
            let received = echoes_received(true)?;
            ping(&app, SERVER, 1, b"waiting").await?;
            // By now the engine has read the request and is protecting its new socket, which waits 500 ms;
            // an unbound ping socket is not listed in /proc/net/icmp until its first send, so this cannot be
            // counted there.
            tokio::time::sleep(Duration::from_millis(150)).await;
            engine.chain(Some(lab_chain(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))));
            counted(&engine, ECHO_REFUSED, 1).await?;
            no_pong(&app).await?;
            assert_eq!(echoes_received(true)?, received, "the waiting request left");
            assert_eq!(engine.counters()[ECHO_CARRIED], 0);
            Ok(())
        },
    )
}

/// When the network beneath is another one, the ping sockets end, as UDP mappings do, so that the next
/// ping goes out on the new network. A ping to the tunnel's DNS address while the network's resolver
/// is of the other IP version goes nowhere and takes no socket.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_network_move_ends_the_ping_sockets() -> Outcome {
    lab(
        "a_network_move_ends_the_ping_sockets",
        &Limits::default(),
        |engine| async move {
            let app = app_pinger(4631)?;
            ping(&app, SERVER, 1, b"before").await?;
            assert_eq!(pong(&app).await?, (4631, 1, b"before".to_vec(), SERVER_IP));
            assert_eq!(ping_sockets()?, 2);
            engine.network_changed(Some(IpAddr::V6(SERVER6)), true);
            until_count("the engine's socket after the move", ping_sockets, 1).await?;
            ping(&app, SERVER, 2, b"after").await?;
            assert_eq!(pong(&app).await?, (4631, 2, b"after".to_vec(), SERVER_IP));

            ping(&app, Addresses::COMMON.dns4, 3, b"the resolver").await?;
            counted(&engine, ECHO_DROPPED, 1).await?;
            assert_eq!(ping_sockets6()?, 0, "a socket of the resolver's version");
            no_pong(&app).await
        },
    )
}

/// Where the kernel refuses the engine's ping sockets, as a probe at its start finds, an app's ping is
/// dropped as before the engine carried echo, and counted apart. The lab leaves the namespace's
/// `ping_group_range` at its default, which allows no group, so the app pings from a raw socket, as a
/// privileged ping does: the namespace's root may make one.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn where_the_kernel_refuses_ping_sockets_echo_is_dropped_and_counted() -> Outcome {
    lab_with(
        "where_the_kernel_refuses_ping_sockets_echo_is_dropped_and_counted",
        &Limits::default(),
        &[("NETLAB_PING_GROUPS", "none")],
        |engine| async move {
            assert!(
                app_ping_socket(4701).is_err(),
                "the namespace allows ping sockets"
            );
            let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
            raw.bind(&SocketAddr::from((Addresses::COMMON.tun4, 0)).into())?;
            // A raw ICMP socket sends the message as it is given, checksum included.
            let mut request = Vec::new();
            etherparse::PacketBuilder::ipv4(Addresses::COMMON.tun4.octets(), SERVER.octets(), 64)
                .icmpv4_echo_request(4701, 1)
                .write(&mut request, b"anyone?")?;
            raw.send_to(&request[20..], &SocketAddr::from((SERVER, 0)).into())?;
            counted(&engine, ECHO_UNSUPPORTED, 1).await?;
            let counters = engine.counters();
            assert_eq!(
                (
                    counters[ECHO_UNSUPPORTED],
                    counters[ECHO_CARRIED],
                    counters[ECHO_DROPPED]
                ),
                (1, 0, 0)
            );
            Ok(())
        },
    )
}

/// The narrow network's server (scripts/netlab-enter.py): what the namespace itself sends there leaves
/// through `near`, whose MTU is 1,280, while the apps' datagrams reach it through tun0 first.
const NARROW: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const NARROW6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x20);
const ICMP_ORIGIN: u8 = nix::libc::SO_EE_ORIGIN_ICMP;
const ICMP6_ORIGIN: u8 = nix::libc::SO_EE_ORIGIN_ICMP6;
const EMSGSIZE: i32 = nix::libc::EMSGSIZE;

/// What became of the datagrams of an app of each path MTU discovery mode (scripts/netlab-app.py),
/// sending `size` bytes from `source` to the echo server at `server`: one line for each of its
/// sockets, in their order. It runs beside the test's runtime, which serves the echo.
async fn modes(
    source: IpAddr,
    server: SocketAddr,
    size: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let app = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/netlab-app.py");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .args(["-I", app])
            .arg(source.to_string())
            .arg(server.ip().to_string())
            .arg(server.port().to_string())
            .arg(size.to_string())
            .output()
    })
    .await??;
    if !output.status.success() {
        return Err(format!("{app}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_owned)
        .collect())
}

/// ADR 0044, decision 5 as amended, and the second review of unit 12 (R1, R3): while the tunnel's MTU
/// is still 1,500 and the network beneath is narrower, as in the moment before Watch sets the tunnel up
/// again with that network's MTU, each app socket's datagram that fits the tunnel reaches the server
/// whole, whatever its path MTU discovery mode, as before this unit: the engine's kernel fragments it
/// for the narrow network, and the engine answers nothing as too large. So a connected default socket
/// sees no error, and an IPv6 socket that ignores path MTU (OMIT) loses nothing. IPv4 and IPv6.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn at_the_tunnels_mtu_every_socket_reaches_a_narrower_network() -> Outcome {
    lab(
        "at_the_tunnels_mtu_every_socket_reaches_a_narrower_network",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            for (app_at, server_at, size, sockets) in [
                (
                    IpAddr::V4(Addresses::COMMON.tun4),
                    IpAddr::V4(NARROW),
                    1_472,
                    12,
                ),
                (
                    IpAddr::V6(Addresses::COMMON.tun6),
                    IpAddr::V6(NARROW6),
                    1_452,
                    14,
                ),
            ] {
                let server = udp_echo(server_at).await?;
                let seen = modes(app_at, server, size).await?;
                assert_eq!(seen.len(), sockets, "{seen:#?}");
                let echoed = format!(": echoed {size}; echoed {size}");
                for line in &seen {
                    assert!(line.ends_with(&echoed), "{line}");
                }
            }
            let counters = engine.counters();
            assert_eq!(
                (counters[TOO_BIG], counters[PATH_MTU], counters[FRAGMENTS]),
                (0, 0, 0)
            );
            Ok(())
        },
    )
}

/// Sets tun0's MTU, as Watch's Kotlin side sets the tunnel's to the network's first hop's
/// (`Builder.setMtu`).
fn set_tunnel_mtu(mtu: u16) -> Outcome {
    let set = Command::new("ip")
        .args(["link", "set", "tun0", "mtu", &mtu.to_string()])
        .status()?;
    if !set.success() {
        return Err(format!("ip link set tun0 mtu {mtu}: {set}").into());
    }
    Ok(())
}

/// ADR 0044, decision 5 as amended: with the tunnel's MTU at the network's, 1,280, each app socket's
/// datagram of 1,500 bytes meets the tunnel as it would meet that network without Watch, measured here
/// against the same app on the narrow network itself, from an address of the namespace's own. A socket
/// that may fragment (dont, want, omit) is fragmented by its own kernel, the engine puts the fragments
/// together, and the server gets the datagram whole; one that may not (do, probe, interface, IPv6's
/// `IPV6_DONTFRAG`) is refused by its own kernel with `EMSGSIZE`, at once. A connected default socket
/// sees no error. The answers, 1,500 bytes, reach the app though the tunnel's MTU is smaller: Linux
/// takes them.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn at_the_networks_mtu_apps_fragment_or_refuse_as_without_watch() -> Outcome {
    lab(
        "at_the_networks_mtu_apps_fragment_or_refuse_as_without_watch",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            set_tunnel_mtu(1_280)?;
            for (app_at, own_at, server_at, size) in [
                (
                    IpAddr::V4(Addresses::COMMON.tun4),
                    IpAddr::V4(SERVER),
                    IpAddr::V4(NARROW),
                    1_472,
                ),
                (
                    IpAddr::V6(Addresses::COMMON.tun6),
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(NARROW6),
                    1_452,
                ),
            ] {
                let server = udp_echo(server_at).await?;
                let through_watch = modes(app_at, server, size).await?;
                let without_watch = modes(own_at, server, size).await?;
                assert_eq!(through_watch, without_watch);
                for line in &through_watch {
                    let refused = ["do ", "probe ", "interface ", "dontfrag "]
                        .iter()
                        .any(|mode| line.starts_with(mode));
                    let expected = if refused {
                        ": refused EMSGSIZE; refused EMSGSIZE".to_owned()
                    } else {
                        format!(": echoed {size}; echoed {size}")
                    };
                    assert!(line.ends_with(&expected), "{line}");
                }
            }
            // dont, want and omit, unconnected and connected, two datagrams each, in both versions.
            let counters = engine.counters();
            assert_eq!(
                (
                    counters[REASSEMBLED],
                    counters[FRAGMENTS],
                    counters[TOO_BIG]
                ),
                (24, 0, 0)
            );
            Ok(())
        },
    )
}

/// An app's UDP socket on the tunnel's address of `server`'s IP version, which queues the ICMP
/// errors it is told of (`IP_RECVERR`, `IPV6_RECVERR`), as an app that asks for them does.
async fn erring_app(server: SocketAddr) -> io::Result<UdpSocket> {
    let app = UdpSocket::bind((tunnel_of(server), 0)).await?;
    if server.is_ipv4() {
        nix::sys::socket::setsockopt(&app, nix::sys::socket::sockopt::Ipv4RecvErr, &true)?;
    } else {
        nix::sys::socket::setsockopt(&app, nix::sys::socket::sockopt::Ipv6RecvErr, &true)?;
    }
    Ok(app)
}

/// The tunnel's address of `to`'s IP version.
fn tunnel_of(to: SocketAddr) -> IpAddr {
    if to.is_ipv4() {
        IpAddr::V4(Addresses::COMMON.tun4)
    } else {
        IpAddr::V6(Addresses::COMMON.tun6)
    }
}

/// An ICMP error as the kernel queues it for a socket: its origin, type and code, and the MTU or other
/// information it gives.
type Queued = (u8, u8, u8, u32);

/// The ICMP errors on a socket's error queue now.
fn queued(socket: &impl AsFd) -> Result<Vec<Queued>, Box<dyn std::error::Error>> {
    use nix::libc;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
    use std::os::fd::AsRawFd;
    let mut errors = Vec::new();
    loop {
        let mut control = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6);
        let mut quoted = [0u8; 2048];
        let mut parts = [io::IoSliceMut::new(&mut quoted)];
        let Ok(message) = recvmsg::<SockaddrStorage>(
            socket.as_fd().as_raw_fd(),
            &mut parts,
            Some(&mut control),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) else {
            return Ok(errors);
        };
        for message in message.cmsgs()? {
            if let ControlMessageOwned::Ipv4RecvErr(error, _)
            | ControlMessageOwned::Ipv6RecvErr(error, _) = message
            {
                errors.push((error.ee_origin, error.ee_type, error.ee_code, error.ee_info));
            }
        }
    }
}

/// The ICMP errors an app socket is told of next, waiting up to [`STEP`] for the first.
async fn told(socket: &impl AsFd) -> Result<Vec<Queued>, Box<dyn std::error::Error>> {
    for _ in 0..500 {
        let errors = queued(socket)?;
        if !errors.is_empty() {
            return Ok(errors);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no ICMP error reached the app".into())
}

/// The path MTU the apps' kernel keeps toward `to`: `IP_MTU` of a socket on the tunnel's address
/// connected there, which takes the apps' route, into tun0. On Linux `IP_MTU` answers for IPv6 too.
fn app_path_mtu(to: SocketAddr) -> Result<u32, Box<dyn std::error::Error>> {
    let socket = std::net::UdpSocket::bind((tunnel_of(to), 0))?;
    socket.connect(to)?;
    let mtu = nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::IpMtu)?;
    Ok(u32::try_from(mtu)?)
}

/// A UDP server at `at` that sends each datagram back, and tells, once, where the first came from:
/// the address and port of the engine's mapping.
async fn reporting_echo(at: IpAddr) -> io::Result<(SocketAddr, oneshot::Receiver<SocketAddr>)> {
    let server = UdpSocket::bind((at, 0)).await?;
    let address = server.local_addr()?;
    let (tell, told) = oneshot::channel();
    tokio::spawn(async move {
        let mut tell = Some(tell);
        let mut buffer = vec![0u8; 65_535];
        while let Ok((n, from)) = server.recv_from(&mut buffer).await {
            if let Some(tell) = tell.take() {
                let _ = tell.send(from);
            }
            let _ = server.send_to(&buffer[..n], from).await;
        }
    });
    Ok((address, told))
}

/// A router on the path says the path to `server` takes only `mtu` bytes, in a "fragmentation needed"
/// or "packet too big" sent from `router` to the engine's mapping at `mapped`, quoting a datagram the
/// mapping sent the server, as a router quotes the packet it could not pass on. A raw socket of the
/// namespace's root sends it; for `ICMPv6` the kernel makes the checksum itself.
fn router_says(router: IpAddr, (mapped, server): (SocketAddr, SocketAddr), mtu: u32) -> Outcome {
    let quoted = packet::udp(mapped, server, b"hello").ok_or("no datagram built")?;
    let error = packet::too_big(&quoted, router, mapped.ip(), mtu).ok_or("no error built")?;
    let (domain, protocol, header) = if router.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4, 20)
    } else {
        (Domain::IPV6, Protocol::ICMPV6, 40)
    };
    let raw = Socket::new(domain, Type::RAW, Some(protocol))?;
    raw.bind(&SocketAddr::new(router, 0).into())?;
    raw.send_to(&error[header..], &SocketAddr::new(mapped.ip(), 0).into())?;
    Ok(())
}

/// A router past the first hop says a destination's path is narrower: the engine's mapping reads it
/// off its error queue, and the app is told at once, as if from the destination, with the router's
/// MTU, and counted; the app's kernel then keeps that MTU for the path. An app's connected default
/// socket fails its next read once with `EMSGSIZE`, then goes on, as it would without Watch. IPv4 and
/// IPv6.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_routers_too_big_reaches_the_app() -> Outcome {
    lab(
        "a_routers_too_big_reaches_the_app",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            for (at, router, kind) in [
                (IpAddr::V4(SERVER), IpAddr::V4(OTHER), (ICMP_ORIGIN, 3, 4)),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(SERVER6),
                    (ICMP6_ORIGIN, 2, 0),
                ),
            ] {
                let (server, mapping) = reporting_echo(at).await?;
                let app = erring_app(server).await?;
                app.send_to(b"hello", server).await?;
                app_receive(&app).await?;
                let mapped = timeout(STEP, mapping).await??;
                router_says(router, (mapped, server), 1_400)?;
                assert_eq!(told(&app).await?, [(kind.0, kind.1, kind.2, 1_400)]);
                assert_eq!(app_path_mtu(server)?, 1_400);

                let (server, mapping) = reporting_echo(at).await?;
                let connected = UdpSocket::bind((tunnel_of(server), 0)).await?;
                connected.connect(server).await?;
                connected.send(b"hello").await?;
                let mut buffer = [0u8; 64];
                within("the echo", connected.recv(&mut buffer)).await?;
                let mapped = timeout(STEP, mapping).await??;
                router_says(router, (mapped, server), 1_300)?;
                let failed = timeout(STEP, connected.recv(&mut buffer)).await?;
                assert!(
                    matches!(&failed, Err(e) if e.raw_os_error() == Some(EMSGSIZE)),
                    "not told: {failed:?}"
                );
                connected.send(b"and on").await?;
                let n = within("the echo after", connected.recv(&mut buffer)).await?;
                assert_eq!(&buffer[..n], b"and on");
            }
            assert_eq!(engine.counters()[PATH_MTU], 4);
            Ok(())
        },
    )
}

/// A UDP server that answers each datagram with the address it came from, as text: through the tool,
/// the test proxy's relay on 127.0.0.1; directly, the engine's own socket.
async fn source_reporter(ip: Ipv4Addr) -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind((ip, 0)).await?;
    let at = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((_, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(from.ip().to_string().as_bytes(), from).await;
        }
    });
    Ok(at)
}

/// The network's resolver at `ip`, port 53: it answers each query with one A record, `answer`, with
/// a time to live of 300 seconds.
async fn resolver(ip: Ipv4Addr, answer: Ipv4Addr) -> io::Result<()> {
    let socket = UdpSocket::bind((ip, 53)).await?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let mut response = buffer[..n].to_vec();
            if response.len() < 12 {
                continue;
            }
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&[0, 1]);
            response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
            response.extend_from_slice(&answer.octets());
            let _ = socket.send_to(&response, from).await;
        }
    });
    Ok(())
}

/// A query for the A record of `example.test`.
fn query_example() -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x04test\x00\x00\x01\x00\x01");
    query
}

/// The time to live of the one answer of a response to [`query_example`].
fn answer_ttl(response: &[u8]) -> Option<u32> {
    let at = query_example().len() + 6;
    Some(u32::from_be_bytes(
        response.get(at..at + 4)?.try_into().ok()?,
    ))
}

/// ADR 0044, decision 5 as amended (re-review of unit 12, major 1): when the tunnel is set up again,
/// the running engine stops and hands the new one its chain, the network's resolver, whether answers go
/// uncached, the names DNS answers gave, and its counters, all before the new engine reads a packet. So
/// a chained app's first datagram and first connection on the new tunnel go through the tool, and
/// nothing of them reaches the server directly; a direct app's lookup reaches the network's resolver,
/// and its answer comes uncached, as while a chain is on; a flow to an address an answer named before
/// is named by it; and the counters go on. Before, the new engine started with no chain, and those
/// went directly until Watch's Kotlin side set the chain again.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_tunnel_set_up_again_keeps_the_chain_from_its_first_packet() -> Outcome {
    lab_engines(
        "a_tunnel_set_up_again_keeps_the_chain_from_its_first_packet",
        |tunnels| async move {
            let tool = proxy(Settings::default()).await?;
            resolver(SERVER, OTHER).await?;
            let reporter = source_reporter(SERVER).await?;
            let named = udp_echo(IpAddr::V4(OTHER)).await?;
            let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
            let first = tunnels.start(None)?;
            first.chain(Some(lab_chain(tool.address)));
            first.network_changed(Some(IpAddr::V4(SERVER)), false);
            let app = app_socket().await?;
            app.send_to(b"before", reporter).await?;
            assert_eq!(
                app_receive(&app).await?.0,
                b"127.0.0.1",
                "before: not through the tool"
            );
            // A direct app learns a name, as Android's resolver asks for every app.
            let direct = UdpSocket::bind((Addresses::COMMON.tun4, SECOND_PORTS.start)).await?;
            direct.send_to(&query_example(), dns).await?;
            app_receive(&direct).await?;
            let before = first.counters();

            // As nativeStart does when it finds an engine running, then at once, before anything else
            // is said to the new engine, the chained app's first datagram and first connection.
            let second = tunnels.start(Some(first.hand_over()))?;
            let app = app_socket().await?;
            app.send_to(b"after", reporter).await?;
            let listener = TcpListener::bind((SERVER, 0)).await?;
            let mut connection = app_connect(listener.local_addr()?).await?;
            assert_eq!(
                app_receive(&app).await?.0,
                b"127.0.0.1",
                "the datagram reached the server directly"
            );
            let (mut accepted, _) = within("the connection", listener.accept()).await?;
            connection.write_all(b"through").await?;
            let mut heard = [0u8; 7];
            within("the connection's bytes", accepted.read_exact(&mut heard)).await?;
            let mut commands = tool.commands();
            commands.sort_unstable();
            assert_eq!(
                commands,
                [1, 3, 3],
                "the one connection the server accepted was not the tool's CONNECT"
            );

            // The name the first engine learned, before a lookup could teach the second one.
            direct.send_to(b"by name", named).await?;
            app_receive(&direct).await?;
            let flows = second.flows();
            let to_named = flows.iter().find(|flow| flow.destination == named);
            assert_eq!(
                to_named.and_then(|flow| flow.name.as_deref()),
                Some("example.test"),
                "flows {flows:?}"
            );
            direct.send_to(&query_example(), dns).await?;
            let (answer, _) = app_receive(&direct).await?;
            assert_eq!(
                answer_ttl(&answer),
                Some(0),
                "an answer kept by Android's resolver"
            );
            let after = second.counters();
            assert!(
                after.iter().zip(before).all(|(&now, then)| now >= then),
                "the counters went back: {before:?}, then {after:?}"
            );
            assert_eq!(after[UDP_MAPPINGS], before[UDP_MAPPINGS] + 2);
            Ok(())
        },
    )
}

/// Runs scripts/netlab-enter.py inside the namespace with `arguments`, its standard input `input`.
fn change_lab(arguments: &[&str], input: Stdio) -> Outcome {
    let output = Command::new("python3")
        .args(["-I", ENTER])
        .args(arguments)
        .stdin(input)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "netlab-enter.py {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

/// A second tun device of the namespace, `name`, up, as Android makes a new interface for each tunnel
/// it establishes; its descriptor is the test's, to hand to the engine. The test opens `/dev/net/tun`
/// and scripts/netlab-enter.py names the device on that open file, since Rust makes a tun device only
/// with unsafe ioctls.
fn second_tunnel(name: &str) -> Result<OwnedFd, Box<dyn std::error::Error>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    change_lab(&["--tunnel", name], Stdio::from(file.try_clone()?))?;
    Ok(OwnedFd::from(file))
}

/// Android's in-place update of the VPN network (AOSP's `Vpn.establish`, ADR 0044's amendment of
/// decision 5): the tunnel's addresses and the apps' routes go from the tun device `from` to `to`,
/// then `from`'s addresses go and it goes down, as Android resets the old interface.
fn move_tunnel(from: &str, to: &str) -> Outcome {
    change_lab(&["--move", from, to], Stdio::null())
}

/// How many of this process's descriptors are of the tun device `name`: its line in
/// `/proc/self/fdinfo` names the device.
fn descriptors_of(name: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let wanted = format!("iff:\t{name}");
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/fdinfo")? {
        // A descriptor closed while the directory is read has no file left to read.
        let Ok(info) = std::fs::read_to_string(entry?.path()) else {
            continue;
        };
        if info.lines().any(|line| line == wanted) {
            count += 1;
        }
    }
    Ok(count)
}

/// A server on the "internet" at `ip` that sends back each read, for as long as the connection lasts,
/// and counts the connections it accepted.
async fn echoing_server(ip: IpAddr) -> io::Result<(SocketAddr, Arc<AtomicU64>)> {
    let listener = TcpListener::bind((ip, 0)).await?;
    let at = listener.local_addr()?;
    let accepted = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                while let Ok(n) = connection.read(&mut buffer).await {
                    if n == 0 || connection.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok((at, accepted))
}

/// Sets the tunnel up again as Android does when it keeps the VPN network, as for a new MTU, and as
/// Watch's Kotlin side then does: a second tun device, tun2, Android's in-place update from tun0 to it,
/// and its descriptor handed to the running engine, which waits off the test's runtime, whose servers
/// go on meanwhile. Then the engine's descriptor of tun0 is closed, and the test's own, its standard
/// input, is the one left.
async fn set_up_again(engine: &Arc<Engine>) -> Outcome {
    assert_eq!(
        descriptors_of("tun0")?,
        2,
        "the test's and the engine's descriptors of tun0"
    );
    let next = second_tunnel("tun2")?;
    move_tunnel("tun0", "tun2")?;
    let swapping = Arc::clone(engine);
    tokio::task::spawn_blocking(move || swapping.swap_tunnel(next)).await??;
    until_count("the descriptors of tun0", || descriptors_of("tun0"), 1).await
}

/// ADR 0044, unit 12b: a tunnel set up again with the same addresses on the same VPN network, as for a
/// new MTU, is handed to the running engine, which keeps every flow. With traffic flowing,
/// Android's in-place update is played as AOSP's `Vpn.establish` does it, then the new tunnel is handed
/// over. After it, the same TCP connection carries bytes both ways, and the server accepted no other;
/// the app socket's UDP mapping leaves through the same port, and a peer the app sent to before gets in
/// unasked; the app's ping goes through the same ping socket of the engine's; the counters go on, with
/// no flow begun anew; and the engine's descriptor of the old tunnel is closed. Before, the engine
/// stopped and a new one started: every connection and mapping ended.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_tunnel_set_up_again_with_the_same_addresses_keeps_every_flow() -> Outcome {
    lab(
        "a_tunnel_set_up_again_with_the_same_addresses_keeps_every_flow",
        &Limits::default(),
        |engine| async move {
            let (server, accepted) = echoing_server(SERVER_IP).await?;
            let mut connection = app_connect(server).await?;
            assert_eq!(exchange(&mut connection, b"before").await?, b"before");
            let app = app_socket().await?;
            let reporter = port_reporter(SERVER).await?;
            app.send_to(b"which port?", reporter).await?;
            let port = reported(&app_receive(&app).await?.0)?;
            let peer = UdpSocket::bind((OTHER, 0)).await?;
            app.send_to(b"to the peer", peer.local_addr()?).await?;
            let mut buffer = [0u8; 64];
            let (_, mapping) = within(
                "the app's datagram at its peer",
                peer.recv_from(&mut buffer),
            )
            .await?;
            assert_eq!(mapping.port(), port, "two ports for one app socket");
            let pinger = app_pinger(4500)?;
            ping(&pinger, SERVER, 1, b"before").await?;
            assert_eq!(
                pong(&pinger).await?,
                (4500, 1, b"before".to_vec(), SERVER_IP)
            );
            let engine_socket = engine_ping_id()?;
            let before = engine.counters();

            set_up_again(&engine).await?;

            assert_eq!(
                exchange(&mut connection, b"after").await?,
                b"after",
                "the connection"
            );
            peer.send_to(b"from the peer", mapping).await?;
            assert_eq!(
                app_receive(&app).await?,
                (b"from the peer".to_vec(), peer.local_addr()?),
                "the peer the app sent to before"
            );
            app.send_to(b"which port?", reporter).await?;
            assert_eq!(reported(&app_receive(&app).await?.0)?, port, "the port");
            ping(&pinger, SERVER, 2, b"after").await?;
            assert_eq!(
                pong(&pinger).await?,
                (4500, 2, b"after".to_vec(), SERVER_IP)
            );
            assert_eq!(engine_ping_id()?, engine_socket, "another ping socket");
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                1,
                "the server accepted another connection"
            );
            let after = engine.counters();
            assert!(
                after.iter().zip(before).all(|(&now, then)| now >= then),
                "the counters went back: {before:?}, then {after:?}"
            );
            assert_eq!(
                (after[TCP_FLOWS], after[UDP_MAPPINGS]),
                (before[TCP_FLOWS], before[UDP_MAPPINGS]),
                "a flow begun anew"
            );
            assert!(after[PACKETS_IN] > before[PACKETS_IN]);
            assert_eq!(after[ECHO_CARRIED], before[ECHO_CARRIED] + 1);
            Ok(())
        },
    )
}

/// Unit 12b, with a chain on: a chained app's connection and UDP association through the tool go on
/// across a tunnel set up again with the same addresses on the same network, and its new connection and
/// datagram after it go through the tool too, so nothing reaches the server directly: the chain stays
/// the running engine's, with nothing handed over or set again. A chain refuses every ping, so the
/// ping's socket is [`a_tunnel_set_up_again_with_the_same_addresses_keeps_every_flow`]'s.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_chained_app_goes_on_through_the_tool_across_a_tunnel_set_up_again() -> Outcome {
    lab(
        "a_chained_app_goes_on_through_the_tool_across_a_tunnel_set_up_again",
        &Limits::default(),
        |engine| async move {
            let tool = proxy(Settings::default()).await?;
            engine.chain(Some(lab_chain(tool.address)));
            let (server, accepted) = echoing_server(SERVER_IP).await?;
            let mut connection = app_connect(server).await?;
            assert_eq!(exchange(&mut connection, b"before").await?, b"before");
            let reporter = source_reporter(SERVER).await?;
            let app = app_socket().await?;
            app.send_to(b"before", reporter).await?;
            assert_eq!(
                app_receive(&app).await?.0,
                b"127.0.0.1",
                "before: not through the tool"
            );

            set_up_again(&engine).await?;

            assert_eq!(
                exchange(&mut connection, b"after").await?,
                b"after",
                "the connection"
            );
            app.send_to(b"after", reporter).await?;
            assert_eq!(
                app_receive(&app).await?.0,
                b"127.0.0.1",
                "the datagram reached the server directly"
            );
            let mut new = app_connect(server).await?;
            assert_eq!(exchange(&mut new, b"a new one").await?, b"a new one");
            let mut commands = tool.commands();
            commands.sort_unstable();
            assert_eq!(
                commands,
                [1, 1, 3],
                "two CONNECTs and the one UDP ASSOCIATE"
            );
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                2,
                "the server accepted a connection that was not the tool's"
            );
            Ok(())
        },
    )
}

/// Unit 12b, through IPv6: an app's TCP connection over IPv6 goes on across a tunnel set up again on
/// the same network, as its IPv4 one does: Android's in-place update moves the tunnel's IPv6 address
/// too, and the engine's listener on it keeps the connection it accepted. The server accepted no other,
/// and the engine began no other TCP flow. Where the lab has no IPv6, this test fails and says so.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_ipv6_connection_goes_on_across_a_tunnel_set_up_again() -> Outcome {
    lab(
        "an_ipv6_connection_goes_on_across_a_tunnel_set_up_again",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            let (server, accepted) = echoing_server(IpAddr::V6(SERVER6)).await?;
            let socket = TcpSocket::new_v6()?;
            socket.bind(SocketAddr::from((Addresses::COMMON.tun6, 0)))?;
            let mut connection = within("an app's IPv6 connection", socket.connect(server)).await?;
            assert_eq!(exchange(&mut connection, b"before").await?, b"before");
            let before = engine.counters();

            set_up_again(&engine).await?;

            assert_eq!(
                exchange(&mut connection, b"after").await?,
                b"after",
                "the IPv6 connection"
            );
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                1,
                "the server accepted another connection"
            );
            assert_eq!(engine.counters()[TCP_FLOWS], before[TCP_FLOWS]);
            Ok(())
        },
    )
}

/// Unit 12b, writes in the gap, on a real tun device: once Android's in-place update has taken tun0
/// down, before the new tunnel is handed over, a datagram a peer sends the app's mapping is written to
/// tun0, which refuses it with `EIO`, as Linux refuses writes to a tun device that is down; the write
/// waits for the new tunnel and the app gets the datagram through it. Before, it was lost. The swap
/// comes 200 ms after the datagram, within the 2 s this test waits.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_write_the_reset_tunnel_refuses_waits_for_the_new_one() -> Outcome {
    let limits = Limits {
        tunnel_wait: Duration::from_secs(2),
        ..Limits::default()
    };
    lab(
        "a_write_the_reset_tunnel_refuses_waits_for_the_new_one",
        &limits,
        |engine| async move {
            let app = app_socket().await?;
            let peer = UdpSocket::bind((OTHER, 0)).await?;
            app.send_to(b"to the peer", peer.local_addr()?).await?;
            let mut buffer = [0u8; 64];
            let (_, mapping) = within(
                "the app's datagram at its peer",
                peer.recv_from(&mut buffer),
            )
            .await?;

            let next = second_tunnel("tun2")?;
            move_tunnel("tun0", "tun2")?;
            peer.send_to(b"in the gap", mapping).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let swapping = Arc::clone(&engine);
            tokio::task::spawn_blocking(move || swapping.swap_tunnel(next)).await??;
            assert_eq!(
                app_receive(&app).await?,
                (b"in the gap".to_vec(), peer.local_addr()?),
                "the datagram written in the gap"
            );
            Ok(())
        },
    )
}

/// The netId of the VPN network the lab's Android marks, and of the one it brings up when the apps of
/// the tunnel change.
const NETWORK: &str = "100";
const NEW_NETWORK: &str = "101";

/// A connection through the engine with Android's marks on (`netlab-enter.py --marks`), which the
/// engine's listener accepted marked with [`NETWORK`]'s netId: the server, and the connection after
/// its first exchange.
async fn marked_connection() -> Result<(SocketAddr, TcpStream), Box<dyn std::error::Error>> {
    change_lab(&["--marks", NETWORK, "tun0"], Stdio::null())?;
    let (server, _) = echoing_server(SERVER_IP).await?;
    let mut connection = app_connect(server).await?;
    assert_eq!(exchange(&mut connection, b"before").await?, b"before");
    Ok((server, connection))
}

/// The second tun device, with Android's in-place update of the tunnel's addresses and the apps'
/// routes (`--move`), and the network's marks either moved with it (`same_network`) or a new
/// network brought up on it and the old one taken away.
fn marked_move(same_network: bool) -> Result<OwnedFd, Box<dyn std::error::Error>> {
    let next = second_tunnel("tun2")?;
    move_tunnel("tun0", "tun2")?;
    if same_network {
        change_lab(&["--marks-move", NETWORK, "tun0", "tun2"], Stdio::null())?;
    } else {
        change_lab(
            &["--marks-new-network", NETWORK, NEW_NETWORK, "tun0", "tun2"],
            Stdio::null(),
        )?;
    }
    Ok(next)
}

/// Unit 12b, the second review's major 1, with Android's marks: when Android updates the VPN network
/// in place, the network keeps its netId on the new interface, and a connection the engine's listener
/// accepted, which carries that netId, goes on across the swap, as without the marks.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn with_androids_marks_a_swap_on_the_same_network_keeps_a_connection() -> Outcome {
    lab(
        "with_androids_marks_a_swap_on_the_same_network_keeps_a_connection",
        &Limits::default(),
        |engine| async move {
            let (server, mut connection) = marked_connection().await?;
            let next = marked_move(true)?;
            let swapping = Arc::clone(&engine);
            tokio::task::spawn_blocking(move || swapping.swap_tunnel(next)).await??;
            assert_eq!(
                exchange(&mut connection, b"after").await?,
                b"after",
                "the connection kept across the swap"
            );
            let mut new = app_connect(server).await?;
            assert_eq!(exchange(&mut new, b"a new one").await?, b"a new one");
            Ok(())
        },
    )
}

/// Why Watch does not swap when Android brings up a new VPN network, as when the apps left out change:
/// a connection the engine's listener accepted carries the old network's netId, and once the old
/// network is gone what it sends routes nowhere, so the app's connection hangs, here for the 3 s it is
/// given, while a new connection on the new network passes. The engine is not at fault, and nothing in
/// it could be: the marks are Android's, so Watch starts a new engine there instead.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn with_androids_marks_a_swap_onto_a_new_network_would_hang_a_connection() -> Outcome {
    lab(
        "with_androids_marks_a_swap_onto_a_new_network_would_hang_a_connection",
        &Limits::default(),
        |engine| async move {
            let (server, mut connection) = marked_connection().await?;
            let next = marked_move(false)?;
            let swapping = Arc::clone(&engine);
            tokio::task::spawn_blocking(move || swapping.swap_tunnel(next)).await??;
            let mut new = app_connect(server).await?;
            assert_eq!(
                exchange(&mut new, b"a new one").await?,
                b"a new one",
                "a new connection on the new network"
            );
            connection.write_all(b"after").await?;
            let mut heard = [0u8; 5];
            let read = timeout(Duration::from_secs(3), connection.read_exact(&mut heard)).await;
            assert!(
                read.is_err(),
                "the kept connection did not hang: {read:?}; the model no longer shows why Watch \
                 starts a new engine on a new network"
            );
            Ok(())
        },
    )
}

/// What Watch does instead when Android brings up a new VPN network (unit 12's path): the old engine
/// hands over and a new one starts on the new tunnel, which knows nothing of the old connection and
/// resets it at once, so that the app opens a new one.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn with_androids_marks_a_new_engine_on_a_new_network_resets_a_connection_at_once() -> Outcome {
    lab_engines(
        "with_androids_marks_a_new_engine_on_a_new_network_resets_a_connection_at_once",
        |tunnels| async move {
            let first = tunnels.start(None)?;
            let (server, mut connection) = marked_connection().await?;
            let next = marked_move(false)?;
            let handover = tokio::task::spawn_blocking(move || first.hand_over()).await?;
            let second = Engine::start_with(
                next,
                lab_config(&tunnels.limits),
                Arc::new(Lab),
                None,
                (Some(handover), None),
            )?;
            connection.write_all(b"after").await?;
            let mut heard = [0u8; 5];
            let read = timeout(Duration::from_secs(1), connection.read_exact(&mut heard)).await;
            assert!(
                matches!(&read, Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset),
                "the kept connection was not reset at once: {read:?}"
            );
            let mut new = app_connect(server).await?;
            assert_eq!(exchange(&mut new, b"a new one").await?, b"a new one");
            drop(second);
            Ok(())
        },
    )
}

/// Gives a socket the hop limit `hops`, IPv4's time to live or IPv6's unicast hop limit, as an app or a
/// traceroute sets it (ADR 0044, unit 11b).
fn set_hops(socket: &impl AsFd, v4: bool, hops: i32) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    if v4 {
        setsockopt(socket, sockopt::Ipv4Ttl, &hops)
    } else {
        setsockopt(socket, sockopt::Ipv6Ttl, &hops)
    }
    .map_err(io::Error::from)
}

/// Asks a socket for the hop limit each packet it reads arrived with (`IP_RECVTTL`,
/// `IPV6_RECVHOPLIMIT`).
fn ask_hops(socket: &impl AsFd, v4: bool) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    if v4 {
        setsockopt(socket, sockopt::Ipv4RecvTtl, &true)
    } else {
        setsockopt(socket, sockopt::Ipv6RecvHopLimit, &true)
    }
    .map_err(io::Error::from)
}

/// What a socket read: how many bytes, from where, and the hop limit they arrived with, if the kernel
/// gave one.
type ReadWithHops = (usize, Option<SocketAddr>, Option<u8>);

/// What a socket that asks for hop limits ([`ask_hops`]) reads next, into `buffer`. A blocking socket
/// waits as long as its timeout says.
fn read_with_hops(
    socket: &impl AsFd,
    buffer: &mut [u8],
) -> Result<ReadWithHops, Box<dyn std::error::Error>> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;
    let mut control = nix::cmsg_space!(nix::libc::c_int);
    let mut parts = [io::IoSliceMut::new(buffer)];
    let message = recvmsg::<SockaddrStorage>(
        socket.as_fd().as_raw_fd(),
        &mut parts,
        Some(&mut control),
        MsgFlags::empty(),
    )?;
    let mut hops = None;
    for message in message.cmsgs()? {
        if let ControlMessageOwned::Ipv4Ttl(limit) | ControlMessageOwned::Ipv6HopLimit(limit) =
            message
        {
            hops = u8::try_from(limit).ok();
        }
    }
    let from = message.address.and_then(|address| {
        address
            .as_sockaddr_in()
            .map(|v4| SocketAddr::from(SocketAddrV4::from(*v4)))
            .or_else(|| {
                address
                    .as_sockaddr_in6()
                    .map(|v6| SocketAddr::from(SocketAddrV6::from(*v6)))
            })
    });
    Ok((message.bytes, from, hops))
}

/// A UDP server at `at` that answers each datagram with the hop limit it arrived with, in one byte (255
/// when the kernel gave none), from a socket whose own datagrams leave with the hop limit `answers_with`.
/// It reads on a thread of its own, beside the test's runtime.
fn hop_reporter(at: SocketAddr, answers_with: i32) -> io::Result<SocketAddr> {
    let server = std::net::UdpSocket::bind(at)?;
    ask_hops(&server, at.is_ipv4())?;
    set_hops(&server, at.is_ipv4(), answers_with)?;
    let address = server.local_addr()?;
    std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        while let Ok((_, Some(from), hops)) = read_with_hops(&server, &mut buffer) {
            let _ = server.send_to(&[hops.unwrap_or(255)], from);
        }
    });
    Ok(address)
}

/// A raw ICMP socket of the namespace, IPv4's or IPv6's, which a copy of every ICMP message the
/// namespace receives reaches, the engine's echo requests among them, with the hop limit each arrived
/// with: IPv4's in the IP header a raw socket reads, IPv6's as ancillary data.
fn icmp_sniffer(v4: bool) -> io::Result<Socket> {
    let socket = if v4 {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?
    } else {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        ask_hops(&socket, false)?;
        socket
    };
    socket.set_read_timeout(Some(STEP))?;
    Ok(socket)
}

/// The hop limit of the next echo request a [`icmp_sniffer`] read, of the IP version `v4` or IPv6.
fn sniffed_request(sniffer: &Socket, v4: bool) -> Result<u8, Box<dyn std::error::Error>> {
    let mut buffer = [0u8; 2048];
    for _ in 0..16 {
        let (n, _, hops) = read_with_hops(sniffer, &mut buffer)?;
        if v4 {
            let header = usize::from(buffer[0] & 0x0f) * 4;
            if n > header && buffer[header] == packet::ECHO_REQUEST {
                return Ok(buffer[8]);
            }
        } else if n > 0 && buffer[0] == packet::ECHO_REQUEST_V6 {
            return hops.ok_or_else(|| "an echo request without its hop limit".into());
        }
    }
    Err("no echo request among what the namespace received".into())
}

/// ADR 0044, unit 11b: Watch is not a hop. An app's datagram on the direct path and its echo request
/// leave with the time to live (IPv4) or hop limit (IPv6) the app sent them with, here 3, as the
/// server's socket (`IP_RECVTTL`, `IPV6_RECVHOPLIMIT`) and a raw socket of the namespace see them;
/// before, they left with the engine's own, 64. A lookup to the tunnel's DNS address still leaves with
/// the engine's own: Android's resolver sends those, whatever the app's socket says.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_apps_hop_limit_leaves_with_its_datagram_and_its_ping() -> Outcome {
    lab(
        "an_apps_hop_limit_leaves_with_its_datagram_and_its_ping",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            for (server, tunnel, id) in [
                (SERVER_IP, IpAddr::V4(Addresses::COMMON.tun4), 4801),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(Addresses::COMMON.tun6),
                    4802,
                ),
            ] {
                let v4 = server.is_ipv4();
                let reporter = hop_reporter(SocketAddr::new(server, 0), 64)?;
                let app = UdpSocket::bind((tunnel, 0)).await?;
                set_hops(&app, v4, 3)?;
                app.send_to(b"which hop limit?", reporter).await?;
                assert_eq!(app_receive(&app).await?, (vec![3], reporter), "{server}");

                let sniffer = icmp_sniffer(v4)?;
                let pinger = ping_socket_at(tunnel, id)?;
                set_hops(&pinger, v4, 3)?;
                let pinger = UdpSocket::from_std(std::net::UdpSocket::from(pinger))?;
                ping(&pinger, server, 1, b"which hop limit?").await?;
                assert_eq!(
                    pong(&pinger).await?,
                    (id, 1, b"which hop limit?".to_vec(), server)
                );
                assert_eq!(sniffed_request(&sniffer, v4)?, 3, "{server}");
            }

            let resolver = hop_reporter(SocketAddr::from((OTHER, 53)), 64)?;
            engine.network_changed(Some(resolver.ip()), false);
            let app = app_socket().await?;
            set_hops(&app, true, 3)?;
            app.send_to(&query_example(), (Addresses::COMMON.dns4, 53))
                .await?;
            let (answer, _) = app_receive(&app).await?;
            assert_eq!(answer, [64], "a lookup left with the app's hop limit");
            Ok(())
        },
    )
}

/// Makes the namespace's own packets, the kernel's echo replies among them, leave with the hop limit
/// `hops` unless their socket says otherwise: IPv4's `ip_default_ttl`, and IPv6's `hop_limit` of the
/// loopback, which the "internet" is on, and of every interface.
fn namespace_hops(hops: u8) -> Outcome {
    for setting in [
        "/proc/sys/net/ipv4/ip_default_ttl",
        "/proc/sys/net/ipv6/conf/lo/hop_limit",
        "/proc/sys/net/ipv6/conf/all/hop_limit",
    ] {
        std::fs::write(setting, hops.to_string()).map_err(|e| format!("{setting}: {e}"))?;
    }
    Ok(())
}

/// ADR 0044, unit 11b: what comes back reaches the app with the hop limit it arrived with, as a tool
/// that reads it, ping's `ttl=` or a traceroute's guess of the way back, would see it without Watch: a
/// server's answer sent with 7, and the namespace's echo reply, sent with 7 by its kernel, reach the
/// app's socket with 7, IPv4 and IPv6. Before, both reached it with the engine's own 64.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn answers_reach_the_app_with_the_hop_limit_they_arrived_with() -> Outcome {
    lab(
        "answers_reach_the_app_with_the_hop_limit_they_arrived_with",
        &Limits::default(),
        |_engine| async move {
            ipv6_here()?;
            namespace_hops(7)?;
            for (server, tunnel, id) in [
                (SERVER_IP, IpAddr::V4(Addresses::COMMON.tun4), 4811),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(Addresses::COMMON.tun6),
                    4812,
                ),
            ] {
                let v4 = server.is_ipv4();
                let reporter = hop_reporter(SocketAddr::new(server, 0), 7)?;
                // Blocking sockets, which wait for their answer as their timeout says.
                let app = std::net::UdpSocket::bind((tunnel, 0))?;
                app.set_read_timeout(Some(STEP))?;
                ask_hops(&app, v4)?;
                app.send_to(b"with which hop limit?", reporter)?;
                let mut buffer = [0u8; 64];
                let (_, from, hops) = read_with_hops(&app, &mut buffer)?;
                assert_eq!((from, hops), (Some(reporter), Some(7)), "{server}");

                let pinger = ping_socket_at(tunnel, id)?;
                pinger.set_nonblocking(false)?;
                pinger.set_read_timeout(Some(STEP))?;
                ask_hops(&pinger, v4)?;
                pinger.send_to(
                    &echo_request(v4, 1, b"with which hop limit?"),
                    &SocketAddr::new(server, 0).into(),
                )?;
                let (n, from, hops) = read_with_hops(&pinger, &mut buffer)?;
                let from = from.ok_or("no sender")?;
                assert_eq!(
                    pong_of(&buffer[..n], from)?,
                    (id, 1, b"with which hop limit?".to_vec(), server)
                );
                assert_eq!(hops, Some(7), "the echo reply from {server}");
            }
            Ok(())
        },
    )
}

/// Routers on the path, of no address of the namespace's own, as a router on a phone's path is of none
/// of the phone's: the engine tells the app of an error from one of the phone's own addresses as if
/// from the destination, since the app's kernel would drop it as a martian source.
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const ROUTER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
const TIME_EXCEEDED: usize = 41;
const PATH_UNREACHABLE: usize = 42;
const ECHO_ERRORS: usize = 43;
const ERRORS_DROPPED: usize = 44;

/// A router or host at `router` on the path sends the engine's socket at `to` the ICMP error `kind`
/// (type and code), quoting `quoted`, the packet the engine sent, as a router quotes the packet it
/// could not pass on; it leaves with the hop limit 9. A raw socket of the namespace's root sends it,
/// whole, its IP header included (`IP_HDRINCL`, `IPV6_HDRINCL`), so that it comes from an address the
/// namespace does not hold.
fn path_says(router: IpAddr, (to, quoted): (IpAddr, &[u8]), kind: (u8, u8)) -> Outcome {
    let mut error =
        packet::path_error(quoted, (router, to), kind, [0; 4]).ok_or("no error built")?;
    packet::set_hops(&mut error, 9);
    let raw = if router.is_ipv4() {
        let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        raw.set_header_included_v4(true)?;
        raw
    } else {
        let raw = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        raw.set_header_included_v6(true)?;
        raw
    };
    raw.send_to(&error, &SocketAddr::new(to, 0).into())?;
    Ok(())
}

/// An ICMP error as an app's socket reads it off its queue.
#[derive(Debug)]
struct FromPath {
    /// Its origin, type and code.
    kind: (u8, u8, u8),
    /// The destination of the packet it answered, with its port.
    about: Option<SocketAddr>,
    /// Who sent it (`SO_EE_OFFENDER`).
    from: Option<IpAddr>,
    /// The hop limit it came with.
    hops: Option<u8>,
    /// What it quoted of the app's packet, from its transport header on.
    quoted: Vec<u8>,
}

/// The ICMP errors on a socket's error queue now.
fn from_path(socket: &impl AsFd) -> Result<Vec<FromPath>, Box<dyn std::error::Error>> {
    use nix::libc;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;
    let mut errors = Vec::new();
    loop {
        let mut control =
            nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6, libc::c_int);
        let mut quoted = [0u8; 2048];
        let mut parts = [io::IoSliceMut::new(&mut quoted)];
        let Ok(message) = recvmsg::<SockaddrStorage>(
            socket.as_fd().as_raw_fd(),
            &mut parts,
            Some(&mut control),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) else {
            return Ok(errors);
        };
        let n = message.bytes;
        let about = message.address.and_then(|address| {
            address
                .as_sockaddr_in()
                .map(|v4| SocketAddr::from(SocketAddrV4::from(*v4)))
                .or_else(|| {
                    address
                        .as_sockaddr_in6()
                        .map(|v6| SocketAddr::from(SocketAddrV6::from(*v6)))
                })
        });
        let (mut error, mut hops) = (None, None);
        for message in message.cmsgs()? {
            match message {
                ControlMessageOwned::Ipv4RecvErr(read, offender) => {
                    let offender = offender
                        .map(|a| IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))));
                    error = Some((read, offender));
                }
                ControlMessageOwned::Ipv6RecvErr(read, offender) => {
                    let offender =
                        offender.map(|a| IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)));
                    error = Some((read, offender));
                }
                ControlMessageOwned::Ipv4Ttl(limit) | ControlMessageOwned::Ipv6HopLimit(limit) => {
                    hops = u8::try_from(limit).ok();
                }
                _ => {}
            }
        }
        if let Some((read, from)) = error {
            errors.push(FromPath {
                kind: (read.ee_origin, read.ee_type, read.ee_code),
                about,
                from,
                hops,
                quoted: quoted[..n.min(quoted.len())].to_vec(),
            });
        }
    }
}

/// The ICMP errors an app socket reads next, waiting up to [`STEP`] for the first.
async fn told_from_path(socket: &impl AsFd) -> Result<Vec<FromPath>, Box<dyn std::error::Error>> {
    for _ in 0..500 {
        let errors = from_path(socket)?;
        if !errors.is_empty() {
            return Ok(errors);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("no ICMP error reached the app".into())
}

/// The kinds of error a traceroute meets, of the IP version `v4` or IPv6: the error's origin, "time
/// exceeded in transit", and "destination unreachable" for no route to the network (IPv4's code 0,
/// IPv6's "no route to destination").
fn traced(v4: bool) -> (u8, (u8, u8), (u8, u8)) {
    if v4 {
        (ICMP_ORIGIN, (11, 0), (3, 0))
    } else {
        (ICMP6_ORIGIN, (3, 0), (1, 0))
    }
}

/// ADR 0044, unit 11b: a router's "time exceeded" for a datagram the app sent reaches the app's socket
/// (`IP_RECVERR`) from that router, as without Watch, with the hop limit it came with, where before it
/// was dropped; an unreachable with its code too. One error at most for each datagram: a second for one
/// datagram is dropped and counted, and so is one forged for a destination the app never sent to, which
/// the engine's kernel queues all the same, its socket not being connected. IPv4 and IPv6, the router
/// another address than the destination.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_routers_time_exceeded_reaches_the_apps_datagram_from_the_router() -> Outcome {
    lab(
        "a_routers_time_exceeded_reaches_the_apps_datagram_from_the_router",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            // With the errors dropped so far once the second for one datagram is: the forged ones and
            // the second ones, one of each in each IP version.
            for (at, router, elsewhere, dropped) in [
                (SERVER_IP, IpAddr::V4(ROUTER), IpAddr::V4(SILENT), 2),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(ROUTER6),
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x99)),
                    4,
                ),
            ] {
                let (origin, exceeded, unreachable) = traced(at.is_ipv4());
                let (server, mapping) = reporting_echo(at).await?;
                let app = erring_app(server).await?;
                ask_hops(&app, at.is_ipv4())?;
                app.send_to(b"a probe", server).await?;
                app_receive(&app).await?;
                let mapped = timeout(STEP, mapping).await??;
                let sent = |to| packet::udp(mapped, to, b"a probe").ok_or("no datagram built");
                // Forged, and sent first: had it got through, the app would read it first.
                let forged = sent(SocketAddr::new(elsewhere, server.port()))?;
                path_says(router, (mapped.ip(), &forged), exceeded)?;
                path_says(router, (mapped.ip(), &sent(server)?), exceeded)?;
                let heard = told_from_path(&app).await?;
                let [error] = &heard[..] else {
                    return Err(format!("not one error: {heard:?}").into());
                };
                assert_eq!(
                    (error.kind, error.about, error.from, error.hops),
                    (
                        (origin, exceeded.0, exceeded.1),
                        Some(server),
                        Some(router),
                        Some(9)
                    )
                );
                assert!(error.quoted.is_empty(), "the payload quoted: {error:?}");

                // A second for that one datagram is dropped: the app is told of the next one's only.
                // It is counted before the app sends again, which the error could otherwise answer.
                path_says(router, (mapped.ip(), &sent(server)?), exceeded)?;
                counted(&engine, ERRORS_DROPPED, dropped).await?;
                app.send_to(b"again", server).await?;
                app_receive(&app).await?;
                path_says(router, (mapped.ip(), &sent(server)?), unreachable)?;
                let heard = told_from_path(&app).await?;
                let kinds: Vec<_> = heard.iter().map(|e| (e.kind, e.about, e.from)).collect();
                assert_eq!(
                    kinds,
                    [(
                        (origin, unreachable.0, unreachable.1),
                        Some(server),
                        Some(router)
                    )]
                );
            }
            let counters = engine.counters();
            assert_eq!(
                [TIME_EXCEEDED, PATH_UNREACHABLE, ERRORS_DROPPED, ECHO_ERRORS]
                    .map(|at| counters[at]),
                [2, 2, 4, 0]
            );
            Ok(())
        },
    )
}

/// An error the engine's own kernel sends from one of the phone's addresses, as "host unreachable" when a
/// neighbour on the network beneath does not answer, reaches the app as if from the destination, as
/// before unit 11b: the app's kernel would drop a packet from the phone's own address coming in on the
/// tunnel as a martian source. Here the namespace's 198.51.100.10 stands for the phone's address (the
/// lab's tun0 takes local sources, so the test sees what the engine chose). IPv4: the lab's IPv6 holds no
/// address of its own beside the destination that its rules route as local.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_error_from_the_phones_own_address_comes_from_the_destination() -> Outcome {
    lab(
        "an_error_from_the_phones_own_address_comes_from_the_destination",
        &Limits::default(),
        |_engine| async move {
            let (server, mapping) = reporting_echo(SERVER_IP).await?;
            let app = erring_app(server).await?;
            app.send_to(b"a probe", server).await?;
            app_receive(&app).await?;
            let mapped = timeout(STEP, mapping).await??;
            let sent = packet::udp(mapped, server, b"a probe").ok_or("no datagram built")?;
            path_says(IpAddr::V4(OTHER), (mapped.ip(), &sent), (3, 1))?;
            let heard = told_from_path(&app).await?;
            let kinds: Vec<_> = heard.iter().map(|e| (e.kind, e.about, e.from)).collect();
            assert_eq!(
                kinds,
                [((ICMP_ORIGIN, 3, 1), Some(server), Some(SERVER_IP))]
            );
            Ok(())
        },
    )
}

/// The ping sockets of the IP version `v4` or IPv6 that the namespace's table lists as bound to no
/// address: each one's echo identifier, by its inode. Linux lists in one IP version's table every
/// socket that follows one of that version in its hash chain, whatever its own version
/// (`ping_get_next` checks the namespace, not the family), so an older socket of the other version,
/// whose identifier shares a chain with one of this version's, is listed too, its address read as
/// none. Whether one does depends on the identifiers the kernel hands out, from one counter for every
/// namespace: run beside other tests, a test that took the one unbound socket of the table for the
/// engine's failed at times (unit 9b, fix round 2, review C: 4 runs of 192, 16 at once).
fn unbound_pings(v4: bool) -> Result<HashMap<u64, u16>, Box<dyn std::error::Error>> {
    let (table, unbound) = if v4 {
        ("/proc/net/icmp", "00000000")
    } else {
        ("/proc/net/icmp6", "00000000000000000000000000000000")
    };
    Ok(std::fs::read_to_string(table)?
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (address, port) = fields.get(1)?.split_once(':')?;
            let inode = fields.get(9)?.parse().ok()?;
            (address == unbound).then(|| Some((inode, u16::from_str_radix(port, 16).ok()?)))?
        })
        .collect())
}

/// The inode and echo identifier of the ping socket of the IP version `v4` or IPv6 that the engine
/// opened since the table read `before` ([`unbound_pings`]). The newest socket heads its hash chain, so
/// that its own version's table lists it and the other's does not; the other version's sockets after it
/// in that chain, which its table now lists too, are listed in their own version's table, and are left
/// out (unit 9b, fix round 3, review F: fix round 2 took every socket listed since, those among them).
fn engine_ping_since(
    v4: bool,
    before: &HashMap<u64, u16>,
) -> Result<(u64, u16), Box<dyn std::error::Error>> {
    let now = unbound_pings(v4)?;
    // Every socket of the other table, bound or not: one bound to an address of its version reads as
    // bound to none in this version's.
    let others: HashSet<u64> = std::fs::read_to_string(if v4 {
        "/proc/net/icmp6"
    } else {
        "/proc/net/icmp"
    })?
    .lines()
    .skip(1)
    .filter_map(|line| line.split_whitespace().nth(9)?.parse().ok())
    .collect();
    let new: Vec<(u64, u16)> = now
        .iter()
        .filter(|(inode, _)| !before.contains_key(inode) && !others.contains(inode))
        .map(|(&inode, &id)| (inode, id))
        .collect();
    match new[..] {
        [one] => Ok(one),
        _ => {
            Err(format!("not one new engine socket: {new:?} of {now:?}, {before:?} before").into())
        }
    }
}

/// ADR 0044, unit 11b: the ping sockets queue their errors from the path now. A router's "time
/// exceeded" for an app's echo request reaches the app's ping socket (`IP_RECVERR`), as `ping -t`
/// shows it without Watch: from that router, with the hop limit it came with, quoting the app's own
/// request, with the app's identifier and that request's sequence number, by which the app's kernel
/// finds the socket and the app its request. Errors forged for a destination the socket never pinged
/// and for a request it never sent are dropped and counted, as is a second for one request; the
/// pending error does not end the engine's socket, through which the next ping gets its reply; and an
/// unreachable with its code reaches the app too. IPv4 and IPv6, the router another address than the
/// destination. Before, every error was dropped: the app saw a timeout.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_routers_time_exceeded_reaches_the_apps_ping_from_the_router() -> Outcome {
    lab(
        "a_routers_time_exceeded_reaches_the_apps_ping_from_the_router",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            // With the errors dropped so far once the second for one request is: two forged ones and
            // the second one in each IP version.
            for (server, tunnel, router, id, dropped) in [
                (
                    SERVER_IP,
                    IpAddr::V4(Addresses::COMMON.tun4),
                    IpAddr::V4(ROUTER),
                    4821,
                    3,
                ),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(Addresses::COMMON.tun6),
                    IpAddr::V6(ROUTER6),
                    4822,
                    6,
                ),
            ] {
                let v4 = server.is_ipv4();
                let (origin, exceeded, unreachable) = traced(v4);
                let app = erring_pinger(tunnel, id)?;
                ask_hops(&app, v4)?;
                let before = unbound_pings(v4)?;
                let to = SocketAddr::new(server, 0).into();
                app.send_to(&echo_request(v4, 1, b"a probe"), &to)?;
                assert_eq!(
                    hear(&app, server)?,
                    Ok((id, 1, b"a probe".to_vec(), server))
                );
                let (socket, engines) = engine_ping_since(v4, &before)?;
                // What the engine's socket sent, from the "internet"'s address it sends from here, and
                // what forged errors say it sent.
                let quoting = |to, sequence, data: &[u8]| {
                    packet::echo_request_of(server, to, engines, sequence, data)
                        .ok_or("no request built")
                };
                let sent = |to, sequence| quoting(to, sequence, b"a probe");
                // Forged, and sent first: had they got through, the app would read them first, and
                // their data.
                path_says(router, (server, &quoting(router, 1, b"forged")?), exceeded)?;
                path_says(router, (server, &quoting(server, 99, b"forged")?), exceeded)?;
                path_says(router, (server, &sent(server, 1)?), exceeded)?;
                let heard = told_from_path(&app).await?;
                let [error] = &heard[..] else {
                    return Err(format!("not one error: {heard:?}").into());
                };
                assert_eq!(
                    (error.kind, error.about, error.from, error.hops),
                    (
                        (origin, exceeded.0, exceeded.1),
                        Some(SocketAddr::new(server, 0)),
                        Some(router),
                        Some(9)
                    )
                );
                let quoted = &error.quoted;
                let request = if v4 {
                    packet::ECHO_REQUEST
                } else {
                    packet::ECHO_REQUEST_V6
                };
                let mut expected = vec![request, 0];
                expected.extend_from_slice(&id.to_be_bytes());
                expected.extend_from_slice(&[0, 1]);
                assert_eq!(
                    (quoted.get(..2), quoted.get(4..8), quoted.get(8..)),
                    (
                        Some(&expected[..2]),
                        Some(&expected[2..]),
                        Some(&b"a probe"[..])
                    ),
                    "the request quoted: {quoted:?}"
                );

                // A second for that one request is dropped, and counted: had it got through, the app's
                // next read would fail with it rather than read the reply.
                path_says(router, (server, &sent(server, 1)?), exceeded)?;
                counted(&engine, ERRORS_DROPPED, dropped).await?;
                app.send_to(&echo_request(v4, 2, b"and on"), &to)?;
                assert_eq!(hear(&app, server)?, Ok((id, 2, b"and on".to_vec(), server)));
                assert_eq!(
                    unbound_pings(v4)?.get(&socket),
                    Some(&engines),
                    "the engine's socket ended"
                );
                path_says(router, (server, &sent(server, 2)?), unreachable)?;
                let heard = told_from_path(&app).await?;
                let kinds: Vec<_> = heard.iter().map(|e| (e.kind, e.from)).collect();
                assert_eq!(
                    kinds,
                    [((origin, unreachable.0, unreachable.1), Some(router))]
                );
            }
            let counters = engine.counters();
            assert_eq!(
                [TIME_EXCEEDED, PATH_UNREACHABLE, ECHO_ERRORS, ERRORS_DROPPED]
                    .map(|at| counters[at]),
                [2, 2, 4, 6]
            );
            Ok(())
        },
    )
}

const BYTES_UP: usize = 2;
const BYTES_DOWN: usize = 3;

/// ADR 0044, unit 11b: echo's bytes are in the engine's byte counters, up and down, as Android counts
/// them to Watch: what the ping socket sends and reads, the ICMP message, header and data, as UDP's are
/// what its sockets carry. A ping of 20 bytes of data is 28 each way, here the first, which waits for
/// its socket, and the next; before, echo counted none. IPv4 and IPv6.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn echos_bytes_are_counted_both_ways() -> Outcome {
    lab(
        "echos_bytes_are_counted_both_ways",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            let data = b"twenty bytes of data";
            for (server, tunnel, id, total) in [
                (SERVER_IP, IpAddr::V4(Addresses::COMMON.tun4), 4831, 56),
                (
                    IpAddr::V6(SERVER6),
                    IpAddr::V6(Addresses::COMMON.tun6),
                    4832,
                    112,
                ),
            ] {
                let app =
                    UdpSocket::from_std(std::net::UdpSocket::from(ping_socket_at(tunnel, id)?))?;
                for sequence in [1, 2] {
                    ping(&app, server, sequence, data).await?;
                    assert_eq!(pong(&app).await?, (id, sequence, data.to_vec(), server));
                }
                let counters = engine.counters();
                assert_eq!(
                    (counters[BYTES_UP], counters[BYTES_DOWN]),
                    (total, total),
                    "{server}"
                );
            }
            Ok(())
        },
    )
}

const SKIPPED: usize = 8;

/// Slows the namespace's way to the server that never answers (`tun1`) to a trickle, so that what the
/// engine sends there waits in the kernel and fills its socket's send buffer, as a slow uplink does: a
/// token bucket of 8 kbit/s holding up to `limit` bytes, beyond which it drops.
fn slow_silent_route(limit: &str) -> Outcome {
    let output = Command::new("tc")
        .args([
            "qdisc", "add", "dev", "tun1", "root", "tbf", "rate", "8kbit",
        ])
        .args(["burst", "1600", "limit", limit])
        .output()
        .map_err(|e| format!("tc, which this test needs: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "tc could not slow tun1 (sch_tbf): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// ADR 0044, unit 11b (second review): a mapping whose socket's send buffer is full drops the app's
/// datagram, counted as by a full queue, and the engine goes on reading the tunnel. Before, the engine
/// waited in its event loop for room in that one socket, every app's packets behind it; and once an
/// ICMP error had come for the socket, which marks it closed for writing in tokio's readiness for
/// good, it spun on "would block" rather than waiting. Here a closed port's "port unreachable" comes
/// first, then 300 datagrams of 1,400 bytes to an address whose way drains at 8 kbit/s; another app's
/// datagram to a server still gets its answer at once.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_full_send_buffer_drops_a_datagram_and_holds_no_one_up() -> Outcome {
    // Android is asked whose a socket is again only after a minute's silence, so that every datagram
    // of the burst goes by the mapping, none waiting for an answer.
    let limits = Limits {
        udp_reask: Duration::from_secs(60),
        ..Limits::default()
    };
    lab(
        "a_full_send_buffer_drops_a_datagram_and_holds_no_one_up",
        &limits,
        |engine| async move {
            slow_silent_route("10000000")?;
            let app = app_socket().await?;
            let closed = std::net::UdpSocket::bind((SERVER, 0))?.local_addr()?;
            app.send_to(b"anyone there?", closed).await?;
            counted(&engine, PATH_UNREACHABLE, 1).await?;
            // The first opens the way there, while the next would wait for it; the rest go by it.
            let silent = SocketAddr::from((SILENT, 9));
            app.send_to(&[7; 1_400], silent).await?;
            counted(&engine, UDP_FLOWS, 2).await?;
            for _ in 0..300 {
                app.send_to(&[7; 1_400], silent).await?;
            }
            let echo = udp_echo(SERVER_IP).await?;
            let other = app_socket().await?;
            other.send_to(b"still there?", echo).await?;
            let mut buffer = [0u8; 64];
            let answered = timeout(Duration::from_secs(2), other.recv_from(&mut buffer)).await;
            assert!(
                matches!(&answered, Ok(Ok((12, _)))),
                "no answer while a mapping's buffer is full: {answered:?}"
            );
            assert!(engine.counters()[SKIPPED] > 0, "no datagram dropped");
            Ok(())
        },
    )
}

/// Runs `ip` with `arguments` in the namespace, failing with what it said.
fn ip(arguments: &[&str]) -> Outcome {
    let output = Command::new("ip").args(arguments).output()?;
    if !output.status.success() {
        return Err(format!(
            "ip {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// ADR 0044, unit 11b (second review, minor 1): a ping to the tunnel's DNS address goes to the
/// network's resolver, so that its socket's target is another address than the one the app pinged. A
/// router's "time exceeded" for it reaches the app from that router, about the address the app pinged,
/// quoting the app's own request; an error the resolver itself sends comes from the address the app
/// pinged, by which the app knows the resolver. The resolver is an address the namespace does not hold,
/// routed into the tunnel no one reads (`tun1`), as a resolver beyond a router would be. IPv4 and IPv6.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_error_for_a_ping_to_the_tunnels_dns_address_reaches_the_app() -> Outcome {
    lab(
        "an_error_for_a_ping_to_the_tunnels_dns_address_reaches_the_app",
        &Limits::default(),
        |engine| async move {
            ipv6_here()?;
            let mut carried = 0;
            for (resolver, dns, tunnel, router, id) in [
                (
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
                    IpAddr::V4(Addresses::COMMON.dns4),
                    IpAddr::V4(Addresses::COMMON.tun4),
                    IpAddr::V4(ROUTER),
                    4861,
                ),
                (
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0x53)),
                    IpAddr::V6(Addresses::COMMON.dns6),
                    IpAddr::V6(Addresses::COMMON.tun6),
                    IpAddr::V6(ROUTER6),
                    4862,
                ),
            ] {
                let v4 = resolver.is_ipv4();
                let (version, prefix, local) = if v4 {
                    ("-4", 32, SERVER_IP)
                } else {
                    ("-6", 128, IpAddr::V6(SERVER6))
                };
                ip(&[
                    version,
                    "route",
                    "add",
                    &format!("{resolver}/{prefix}"),
                    "dev",
                    "tun1",
                ])?;
                engine.network_changed(Some(resolver), false);
                let (origin, exceeded, _) = traced(v4);
                let unreachable = if v4 { (3, 1) } else { (1, 3) };
                let app = erring_pinger(tunnel, id)?;
                let before = unbound_pings(v4)?;
                let to = SocketAddr::new(dns, 0).into();
                let about = Some(SocketAddr::new(dns, 0));
                for (sequence, from, kind, shown) in [
                    (1, router, exceeded, router),
                    (2, resolver, unreachable, dns),
                ] {
                    app.send_to(&echo_request(v4, sequence, b"the resolver?"), &to)?;
                    carried += 1;
                    counted(&engine, ECHO_CARRIED, carried).await?;
                    // What the engine's socket sent the resolver, as the error quotes it: the
                    // address it sent from does not matter to its kernel, the identifier does.
                    let (_, engines) = engine_ping_since(v4, &before)?;
                    let sent = packet::echo_request_of(
                        local,
                        resolver,
                        engines,
                        sequence,
                        b"the resolver?",
                    )
                    .ok_or("no request built")?;
                    path_says(from, (local, &sent), kind)?;
                    let heard = told_from_path(&app).await?;
                    let kinds: Vec<_> = heard.iter().map(|e| (e.kind, e.about, e.from)).collect();
                    assert_eq!(
                        kinds,
                        [((origin, kind.0, kind.1), about, Some(shown))],
                        "{resolver}"
                    );
                }
            }
            Ok(())
        },
    )
}

/// ADR 0044, unit 11b (third round, finding 2): a mapping's datagram that the network beneath's queue
/// drops is dropped and counted, never told to the app as "host unreachable". A mapping's socket asks
/// for its ICMP errors, so the kernel fails a send whose packet its queue drops with `ENOBUFS`; told
/// as unreachable, an app socket that asks for its errors too failed its next send with
/// `EHOSTUNREACH`, losing that datagram as well. Here the way to an address that never answers holds
/// 3,000 bytes, and the app sends forty datagrams of 1,400 bytes there: none of its sends fails, no
/// error reaches it, and the drops are counted.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_datagram_the_network_queue_drops_is_not_told_as_unreachable() -> Outcome {
    // Android is asked whose a socket is again only after a minute's silence, so that every datagram
    // goes by the mapping, none waiting for an answer.
    let limits = Limits {
        udp_reask: Duration::from_secs(60),
        ..Limits::default()
    };
    lab(
        "a_datagram_the_network_queue_drops_is_not_told_as_unreachable",
        &limits,
        |engine| async move {
            slow_silent_route("3000")?;
            let silent = SocketAddr::from((SILENT, 9));
            let app = erring_app(silent).await?;
            app.send_to(&[7; 1_400], silent).await?;
            counted(&engine, UDP_FLOWS, 1).await?;
            let mut failed = Vec::new();
            for _ in 0..40 {
                if let Err(error) = app.send_to(&[7; 1_400], silent).await {
                    failed.push(error);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            let errors = from_path(&app)?;
            assert!(
                failed.is_empty() && errors.is_empty(),
                "the app's sends failed with {failed:?}, and it was told {errors:?}"
            );
            assert!(engine.counters()[SKIPPED] > 0, "no drop counted");
            Ok(())
        },
    )
}

/// The place of `listener_recoveries` in `Engine::counters`.
const LISTENER_RECOVERIES: usize = 46;

/// Runs `ss -K -t` with `filter`: the kernel destroys each TCP socket it matches (`SOCK_DESTROY`), as
/// Android's netd destroys those on an address it believes was removed.
fn destroy(filter: &[&str]) -> Outcome {
    let output = Command::new("ss")
        .args(["-K", "-t"])
        .args(filter)
        .output()
        .map_err(|error| {
            format!("ss (iproute2) could not be run here ({error}), so this test did NOT run")
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "ss -K -t {filter:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

/// Fails, and says plainly that the test did not run, where `ss` or the kernel's `SOCK_DESTROY` is
/// missing. `ss -K` passes over a socket the kernel will not destroy without a word (a kernel built
/// without `CONFIG_INET_DIAG_DESTROY` answers `EOPNOTSUPP`, which `ss` takes as nothing to do), so a
/// listener of the test's own is destroyed first, and must have stopped listening.
fn sock_destroy_here() -> Outcome {
    let probe = std::net::TcpListener::bind((OTHER, 0))?;
    let at = probe.local_addr()?.to_string();
    destroy(&["state", "listening", "src", &at])?;
    if nix::sys::socket::getsockopt(&probe, nix::sys::socket::sockopt::AcceptConn)? {
        return Err(
            "ss -K destroyed nothing here: the kernel has no SOCK_DESTROY \
                    (CONFIG_INET_DIAG_DESTROY), so this test did NOT run"
                .into(),
        );
    }
    Ok(())
}

/// The tunnel's address of one IP version, as `ss` takes it in a filter.
fn tunnel_filter(v4: bool) -> String {
    if v4 {
        Addresses::COMMON.tun4.to_string()
    } else {
        format!("[{}]", Addresses::COMMON.tun6)
    }
}

/// The "internet" of one IP version.
fn server_ip(v4: bool) -> IpAddr {
    if v4 {
        IpAddr::V4(SERVER)
    } else {
        IpAddr::V6(SERVER6)
    }
}

/// An app's connection of one IP version: from the tunnel's address, so the namespace sends it into
/// the tunnel.
async fn app_connect_from(
    v4: bool,
    to: SocketAddr,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let socket = if v4 {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let tun = if v4 {
        IpAddr::V4(Addresses::COMMON.tun4)
    } else {
        IpAddr::V6(Addresses::COMMON.tun6)
    };
    socket.bind(SocketAddr::new(tun, 0))?;
    within(&format!("an app's connection to {to}"), socket.connect(to)).await
}

/// ADR 0044, unit 12b: the engine's listener, destroyed as Android's netd destroys the sockets on the
/// tunnel's address (here only the listening one), is bound anew, on a new port: a new connection
/// through the engine passes, and one it relayed before, kept open, goes on through the old port. On the Android 15
/// emulator netd destroyed it when the tunnel was set up again with the same addresses, and every TCP
/// connection through Watch was refused for the rest of the run: the accept loop had ended at its first
/// error.
async fn a_destroyed_listener(engine: &Engine, v4: bool) -> Outcome {
    if !v4 {
        ipv6_here()?;
    }
    sock_destroy_here()?;
    let (server, accepted) = echoing_server(server_ip(v4)).await?;
    let mut kept = app_connect_from(v4, server).await?;
    assert_eq!(exchange(&mut kept, b"before").await?, b"before");
    let port = listener_port(v4).ok_or("the engine's listener on the tunnel's address")?;

    destroy(&["state", "listening", "src", &tunnel_filter(v4)])?;

    counted(engine, LISTENER_RECOVERIES, 1).await?;
    let mut new = app_connect_from(v4, server).await?;
    assert_eq!(exchange(&mut new, b"a new one").await?, b"a new one");
    // The kept connection's socket holds the old port, which a port the kernel picks is never.
    assert!(
        listener_port(v4).is_some_and(|now| now != port),
        "the listener: {:?}, the old port {port}",
        listener_port(v4)
    );
    assert_eq!(
        exchange(&mut kept, b"kept").await?,
        b"kept",
        "the connection kept open"
    );
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    Ok(())
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_listener_destroyed_as_netd_does_is_bound_anew() -> Outcome {
    lab(
        "a_listener_destroyed_as_netd_does_is_bound_anew",
        &Limits::default(),
        |engine| async move { a_destroyed_listener(&engine, true).await },
    )
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn an_ipv6_listener_destroyed_as_netd_does_is_bound_anew() -> Outcome {
    lab(
        "an_ipv6_listener_destroyed_as_netd_does_is_bound_anew",
        &Limits::default(),
        |engine| async move { a_destroyed_listener(&engine, false).await },
    )
}

/// A server on the "internet" that hands the test each connection it accepts.
async fn handing_server(
    ip: IpAddr,
) -> io::Result<(SocketAddr, mpsc::UnboundedReceiver<TcpStream>)> {
    let listener = TcpListener::bind((ip, 0)).await?;
    let at = listener.local_addr()?;
    let (hand, handed) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((connection, _)) = listener.accept().await {
            if hand.send(connection).is_err() {
                break;
            }
        }
    });
    Ok((at, handed))
}

/// An app's connection through the engine to `server`, and the server's end of it, with `said` passed
/// both ways.
async fn both_ends(
    v4: bool,
    (server, handed): (SocketAddr, &mut mpsc::UnboundedReceiver<TcpStream>),
    said: &[u8],
) -> Result<(TcpStream, TcpStream), Box<dyn std::error::Error>> {
    let mut app = app_connect_from(v4, server).await?;
    app.write_all(said).await?;
    let mut server_end = timeout(STEP, handed.recv())
        .await?
        .ok_or("the server is gone")?;
    let mut heard = vec![0u8; said.len()];
    within(
        "the app's bytes at the server",
        server_end.read_exact(&mut heard),
    )
    .await?;
    server_end.write_all(&heard).await?;
    within("the server's answer", app.read_exact(&mut heard)).await?;
    assert_eq!(heard, said);
    Ok((app, server_end))
}

/// Whether the namespace still holds a TCP socket connected to `to`, as the engine's upstream
/// connection to the server is.
fn connected_to(to: SocketAddr) -> bool {
    let wanted = format!(":{:04X}", to.port());
    let table = if to.is_ipv4() {
        "/proc/net/tcp"
    } else {
        "/proc/net/tcp6"
    };
    std::fs::read_to_string(table).is_ok_and(|text| {
        text.lines().skip(1).any(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // The remote end, in an established state.
            fields
                .get(2)
                .is_some_and(|remote| remote.ends_with(&wanted))
                && fields.get(3) == Some(&"01")
        })
    })
}

/// ADR 0044, unit 12b, as Android's netd does it when it believes the tunnel's address was removed:
/// every TCP socket on that address is destroyed, the engine's listener and its end of each relayed
/// connection among them, and the apps' own. The app's connection ends at once with an error, not a
/// hang; the server's end with a reset, from the relay, which saw the error, so that no upstream
/// connection is left open; the listener is bound anew; and a new connection through the engine
/// passes.
async fn netd_destroys_the_sockets(engine: &Engine, v4: bool) -> Outcome {
    if !v4 {
        ipv6_here()?;
    }
    sock_destroy_here()?;
    let (server, mut handed) = handing_server(server_ip(v4)).await?;
    let (mut app, mut server_end) = both_ends(v4, (server, &mut handed), b"before").await?;
    listener_port(v4).ok_or("the engine's listener on the tunnel's address")?;
    let resets = engine.counters()[RESETS];

    destroy(&["state", "all", "src", &tunnel_filter(v4)])?;

    let (_, end) = read_to_end_or_error(&mut app).await?;
    assert!(end.is_some(), "the app's connection ended cleanly");
    let (_, end) = read_to_end_or_error(&mut server_end).await?;
    assert_eq!(
        end,
        Some(io::ErrorKind::ConnectionReset),
        "the server's end"
    );
    assert_eq!(engine.counters()[RESETS], resets + 1);
    assert!(
        !connected_to(server),
        "a connection to the server is still open"
    );
    counted(engine, LISTENER_RECOVERIES, 1).await?;
    both_ends(v4, (server, &mut handed), b"a new one").await?;
    assert!(listener_port(v4).is_some(), "no listener");
    Ok(())
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn when_netd_destroys_the_sockets_on_the_tunnels_address_connections_end_and_new_ones_pass()
-> Outcome {
    lab(
        "when_netd_destroys_the_sockets_on_the_tunnels_address_connections_end_and_new_ones_pass",
        &Limits::default(),
        |engine| async move { netd_destroys_the_sockets(&engine, true).await },
    )
}

#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn when_netd_destroys_the_sockets_on_the_tunnels_ipv6_address_connections_end_and_new_ones_pass()
-> Outcome {
    lab(
        "when_netd_destroys_the_sockets_on_the_tunnels_ipv6_address_connections_end_and_new_ones_pass",
        &Limits::default(),
        |engine| async move { netd_destroys_the_sockets(&engine, false).await },
    )
}

/// Unit 12b: only the engine's end of a relayed connection destroyed, the one Android's stack holds
/// toward the fake peer, while the app's own socket stays. Android's stack resets the connection as it
/// destroys it, and the reset reaches the app through the engine's rewriting: the app reads a reset at
/// once, not a hang. The relay sees the error and resets the server's end; the listener, untouched,
/// takes a new connection.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn when_the_engines_end_is_destroyed_the_app_gets_a_reset() -> Outcome {
    lab(
        "when_the_engines_end_is_destroyed_the_app_gets_a_reset",
        &Limits::default(),
        |engine| async move {
            sock_destroy_here()?;
            let (server, mut handed) = handing_server(server_ip(true)).await?;
            let (mut app, mut server_end) =
                both_ends(true, (server, &mut handed), b"before").await?;
            let resets = engine.counters()[RESETS];

            let fake = Addresses::COMMON.fake4.to_string();
            destroy(&["src", &tunnel_filter(true), "dst", &fake])?;

            let (_, end) = read_to_end_or_error(&mut app).await?;
            assert_eq!(end, Some(io::ErrorKind::ConnectionReset), "the app's end");
            let (_, end) = read_to_end_or_error(&mut server_end).await?;
            assert_eq!(
                end,
                Some(io::ErrorKind::ConnectionReset),
                "the server's end"
            );
            assert_eq!(engine.counters()[RESETS], resets + 1);
            assert!(!connected_to(server), "a connection to the server is open");
            both_ends(true, (server, &mut handed), b"a new one").await?;
            assert_eq!(engine.counters()[LISTENER_RECOVERIES], 0);
            Ok(())
        },
    )
}

/// A server on the "internet" that sends back each read, and accepts again after an error, as when the
/// process is out of descriptors; it counts the connections it accepted.
async fn patient_server(ip: IpAddr) -> io::Result<(SocketAddr, Arc<AtomicU64>)> {
    let listener = TcpListener::bind((ip, 0)).await?;
    let at = listener.local_addr()?;
    let accepted = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut connection, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            counted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                while let Ok(n) = connection.read(&mut buffer).await {
                    if n == 0 || connection.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok((at, accepted))
}

/// Takes every descriptor the process may still open, with `/dev/null`, until the kernel answers
/// `EMFILE`; they are given back when the files are dropped. The lab lowers the process's limit first
/// (`NETLAB_NOFILE`).
fn every_descriptor_left() -> Result<Vec<std::fs::File>, Box<dyn std::error::Error>> {
    let mut held = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => held.push(file),
            Err(error) if error.raw_os_error() == Some(nix::libc::EMFILE) => return Ok(held),
            Err(error) => return Err(error.into()),
        }
        if held.len() > 4_096 {
            return Err("the lab did not lower the limit on open files".into());
        }
    }
}

/// Waits until the counter at `index` reaches at least `value`, for five seconds at most.
async fn at_least(engine: &Engine, index: usize, value: u64) -> Outcome {
    for _ in 0..500 {
        if engine.counters()[index] >= value {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!(
        "counter {index} never reached {value}: {:?}",
        engine.counters()
    )
    .into())
}

/// Unit 12b, the transient case: the engine's process out of descriptors when a connection reaches its
/// listener. `accept` fails with `EMFILE` while the listener still listens, and the connection waits in
/// its queue; the accept loop pauses and accepts again, and once descriptors are free the connection is
/// accepted and relayed. Before, the first error ended the loop, the listener closed, and the
/// connection in its queue was reset, as every later one was refused. The lab's Android takes 300 ms to
/// name the app of a connection from one of `SLOW_PORTS`, while the server is asked at once beside it:
/// the test takes every descriptor left once the server has the engine's connection and before the
/// engine rewrites the app's SYN to its listener, and gives them back once the app's connection is
/// complete and the engine's accept has failed.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_listener_out_of_descriptors_accepts_once_there_are_some() -> Outcome {
    lab_with(
        "a_listener_out_of_descriptors_accepts_once_there_are_some",
        &Limits::default(),
        &[("NETLAB_NOFILE", "256")],
        |engine| async move {
            let (server, accepted) = patient_server(server_ip(true)).await?;
            let mut first = app_connect(server).await?;
            assert_eq!(exchange(&mut first, b"first").await?, b"first");
            let port =
                listener_port(true).ok_or("the engine's listener on the tunnel's address")?;
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::from((Addresses::COMMON.tun4, SLOW_PORTS.start)))?;
            let (done, mut connected) = oneshot::channel();
            tokio::spawn(async move {
                let _ = done.send(socket.connect(server).await);
            });
            until_count(
                "the engine's connections at the server",
                || Ok(usize::try_from(accepted.load(Ordering::Relaxed))?),
                2,
            )
            .await?;

            let held = every_descriptor_left()?;
            if connected.try_recv().is_ok() {
                return Err(
                    "the app's connection was complete before the descriptors were taken: \
                            the lab's timing failed, so this test did NOT run"
                        .into(),
                );
            }
            let mut connection = timeout(STEP, connected).await???;
            at_least(&engine, LISTENER_RECOVERIES, 1).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(held);

            assert_eq!(
                exchange(&mut connection, b"once there is room").await?,
                b"once there is room"
            );
            // It still listened: no listener was bound anew, whose closing of the old one would have
            // reset the connection in its queue.
            assert_eq!(listener_port(true), Some(port));
            Ok(())
        },
    )
}

/// ADR 0044, unit 12b, second round: another app takes the engine's listener's port the moment the
/// listener stops listening, as any app may, binding it with `SO_REUSEADDR`, which Linux allows
/// whatever the app's UID. The lab plays it with `netlab-enter.py --interloper`: it stops this
/// process, so that the engine cannot bind the port again first, destroys the engine's listener with
/// `ss -K`, binds the port and listens, and lets the process go on.
///
/// Beforehand, an app's connection is rewritten to the listener and not yet relayed: a policy rule
/// drops what the tunnel carries to the listener's port, its SYN among it, so that the connection
/// waits there; the interloper takes the rule away. Once the engine's listener is bound anew, on
/// another port since the old one is taken: the waiting connection's SYN, sent again by the app's
/// stack a second after the first, is refused, never rewritten to the old port; a new connection goes
/// to the engine's new listener; a connection the relay held goes on through the old port, where the
/// engine's own socket holds its ends; and the interloper accepted nothing. Before, the SYN sent again
/// went to the old port, where the interloper accepted it and its bytes reached the app.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn another_app_on_the_listeners_old_port_gets_nothing_through_the_engine() -> Outcome {
    lab(
        "another_app_on_the_listeners_old_port_gets_nothing_through_the_engine",
        &Limits::default(),
        |engine| async move {
            sock_destroy_here()?;
            let (server, accepted) = echoing_server(SERVER_IP).await?;
            let mut kept = app_connect(server).await?;
            assert_eq!(exchange(&mut kept, b"before").await?, b"before");
            let port = listener_port(true)
                .ok_or("the engine's listener on the tunnel's address")?
                .to_string();
            ip(&[
                "rule",
                "add",
                "pref",
                "10",
                "iif",
                "tun0",
                "ipproto",
                "tcp",
                "dport",
                &port,
                "blackhole",
            ])?;
            let began = std::time::Instant::now();
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::from((Addresses::COMMON.tun4, 0)))?;
            let (done, mut waiting) = oneshot::channel();
            tokio::spawn(async move {
                let _ = done.send(socket.connect(server).await);
            });
            // The engine's connection to the server for it, then a moment for its SYN to be rewritten.
            until_count(
                "the engine's connections at the server",
                || Ok(usize::try_from(accepted.load(Ordering::Relaxed))?),
                2,
            )
            .await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            if waiting.try_recv().is_ok() {
                return Err("the waiting connection was answered: the rule did not hold it".into());
            }

            let me = std::process::id().to_string();
            let mut interloper = Command::new("python3")
                .args(["-I", ENTER, "--interloper", &me])
                .args([&Addresses::COMMON.tun4.to_string(), &port, "10"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?;
            let output = interloper.stdout.take().ok_or("no output")?;
            let (said, lines) = tokio::task::spawn_blocking(move || {
                use std::io::BufRead;
                let mut lines = io::BufReader::new(output).lines();
                (lines.next(), lines)
            })
            .await?;
            let said = said.transpose()?;
            if said.as_deref() != Some("listening") {
                return Err(format!("the interloper said {said:?}, not that it listens").into());
            }
            // The app's stack sends the SYN again a second after the first: by then the engine must
            // have bound its listener anew, or the test says nothing.
            if began.elapsed() > Duration::from_millis(900) {
                return Err(
                    "the interloper took longer than the app's stack waits before it sends \
                            its SYN again: the lab's timing failed, so this test did NOT run"
                        .into(),
                );
            }
            counted(&engine, LISTENER_RECOVERIES, 1).await?;

            let refused = timeout(STEP, waiting).await??;
            assert_eq!(
                refused.map(|_| ()).map_err(|e| e.kind()),
                Err(io::ErrorKind::ConnectionRefused),
                "the waiting connection"
            );
            let mut new = app_connect(server).await?;
            assert_eq!(exchange(&mut new, b"a new one").await?, b"a new one");
            assert_eq!(
                exchange(&mut kept, b"kept").await?,
                b"kept",
                "the relayed connection"
            );

            drop(interloper.stdin.take());
            let rest = tokio::task::spawn_blocking(move || {
                lines.map_while(Result::ok).collect::<Vec<String>>()
            })
            .await?;
            interloper.wait()?;
            assert!(rest.is_empty(), "the interloper accepted: {rest:?}");
            Ok(())
        },
    )
}

/// A scripted proxy's answers (ADR 0052).
static SOCKS: &[&[u8]] = &[&[5, 2], &[1, 0], &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]];

/// A scripted proxy's answers (ADR 0052).
static HTTP: &[&[u8]] = &[b"HTTP/1.1 200 Connection established\r\n\r\n"];

/// A scripted proxy's answers (ADR 0052).
static PLAIN: &[&[u8]] = &[b"HTTP/1.1 204 No Content\r\n\r\n"];

/// A synthetic secret no flow, record or dump may hold (W8, part 2a; ADR 0052).
const SECRET: &[u8] = b"hunter2-synthetic-secret";

/// A minimal TLS `ClientHello` record for `name`.
fn client_hello(name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let length = u16::try_from(name.len()).unwrap_or(0);
    let mut extension = vec![0, 0];
    extension.extend_from_slice(&(length + 5).to_be_bytes());
    extension.extend_from_slice(&(length + 3).to_be_bytes());
    extension.push(0);
    extension.extend_from_slice(&length.to_be_bytes());
    extension.extend_from_slice(name);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&u16::try_from(extension.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&extension);
    let mut handshake = vec![1, 0];
    handshake.extend_from_slice(&u16::try_from(body.len()).unwrap_or(0).to_be_bytes());
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A proxy on the lab's "internet" that answers each step of a handshake with `replies`, in order, one for each
/// read, then echoes what follows: enough for an app's own SOCKS5 or HTTP proxy, which the engine only reads.
async fn scripted_proxy(at: Ipv4Addr, replies: &'static [&'static [u8]]) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind((at, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                for reply in replies {
                    if !matches!(connection.read(&mut buffer).await, Ok(n) if n > 0) {
                        return;
                    }
                    if connection.write_all(reply).await.is_err() {
                        return;
                    }
                }
                while let Ok(n) = connection.read(&mut buffer).await {
                    if n == 0 || connection.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(address)
}

/// Sends `said`, and reads `expected.len()` bytes back, which must be `expected`.
async fn step(connection: &mut TcpStream, said: &[u8], expected: &[u8]) -> Outcome {
    connection.write_all(said).await?;
    let mut heard = vec![0u8; expected.len()];
    within("a proxy's answer", connection.read_exact(&mut heard)).await?;
    assert_eq!(heard, expected);
    Ok(())
}

/// The kept flow to `destination`, once the engine has named it as `done` says, within [`STEP`].
async fn flow_to(
    engine: &Engine,
    destination: SocketAddr,
    done: impl Fn(&datapavan_net::Flow) -> bool,
) -> Result<datapavan_net::Flow, Box<dyn std::error::Error>> {
    let until = tokio::time::Instant::now() + STEP;
    loop {
        if let Some(flow) = engine
            .flows()
            .into_iter()
            .rev()
            .find(|f| f.destination == destination && done(f))
        {
            return Ok(flow);
        }
        if tokio::time::Instant::now() > until {
            return Err(format!("no flow to {destination} as wanted: {:?}", engine.flows()).into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// An app's own SOCKS5 proxy with a password, an HTTP proxy asked with `CONNECT` and one sent a plain request,
/// through the whole engine on Linux's TCP stack (ADR 0052): each flow is named by the destination asked for,
/// the inner hello read after the handshake, and no password reaches a flow, the log or what the engine shows;
/// with "Log where these apps connect" off, the next ones keep their kind alone.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
#[allow(clippy::too_many_lines)]
fn an_apps_own_proxies_are_named_and_no_password_is_kept() -> Outcome {
    lab(
        "an_apps_own_proxies_are_named_and_no_password_is_kept",
        &Limits {
            close_linger: Duration::from_millis(50),
            ..Limits::default()
        },
        |engine| async move {
            engine.tunnels(&datapavan_net::TunnelSetting {
                log_destinations: true,
                ..datapavan_net::TunnelSetting::default()
            });
            let socks = scripted_proxy(SERVER, SOCKS).await?;
            let mut app = app_connect(socks).await?;
            step(&mut app, &[5, 2, 0, 2], &[5, 2]).await?;
            let mut auth = vec![1, 4];
            auth.extend_from_slice(b"user");
            auth.push(u8::try_from(SECRET.len()).unwrap_or(0));
            auth.extend_from_slice(SECRET);
            step(&mut app, &auth, &[1, 0]).await?;
            let mut request = vec![5, 1, 0, 3, 11];
            request.extend_from_slice(b"example.com");
            request.extend_from_slice(&443u16.to_be_bytes());
            step(&mut app, &request, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let hello = client_hello("example.com");
            step(&mut app, &hello, &hello).await?;
            let flow = flow_to(&engine, socks, |f| {
                f.named_by == datapavan_net::NamedBy::Tls
            })
            .await?;
            assert_eq!(flow.name.as_deref(), Some("example.com"));
            let proxy = flow.proxy.clone().ok_or("no proxy kept")?;
            assert_eq!(proxy.kind, datapavan_net::proxies::Kind::Socks5);
            assert!(proxy.password, "a password crossed unencrypted");

            let http = scripted_proxy(OTHER, HTTP).await?;
            let mut connect = app_connect(http).await?;
            let mut asked =
                b"CONNECT example.net:443 HTTP/1.1\r\nProxy-Authorization: Basic ".to_vec();
            asked.extend_from_slice(SECRET);
            asked.extend_from_slice(b"\r\n\r\n");
            step(
                &mut connect,
                &asked,
                b"HTTP/1.1 200 Connection established\r\n\r\n",
            )
            .await?;
            let hello = client_hello("example.net");
            step(&mut connect, &hello, &hello).await?;
            let flow =
                flow_to(&engine, http, |f| f.named_by == datapavan_net::NamedBy::Tls).await?;
            assert_eq!(flow.name.as_deref(), Some("example.net"));
            assert_eq!(
                flow.proxy.map(|p| (p.kind, p.password)),
                Some((datapavan_net::proxies::Kind::Connect, true))
            );

            let plain = scripted_proxy(SERVER, PLAIN).await?;
            let mut forward = app_connect(plain).await?;
            step(
                &mut forward,
                b"GET http://example.org/private?q=1 HTTP/1.1\r\nHost: example.org\r\n\r\n",
                b"HTTP/1.1 204 No Content\r\n\r\n",
            )
            .await?;
            let flow = flow_to(&engine, plain, |f| f.proxy.is_some()).await?;
            assert_eq!(flow.name.as_deref(), Some("example.org"));

            // Their last segments are written once they end, the rewriting's short linger after.
            drop((app, connect, forward));
            tokio::time::sleep(Duration::from_millis(300)).await;
            engine.flush_log();
            let logged = LOGGED.lock().map_err(|e| e.to_string())?.clone();
            assert!(
                holds(&logged, b"example.com"),
                "the destinations asked for are logged while the switch is on: {} bytes {:?}",
                logged.len(),
                String::from_utf8_lossy(&logged)
            );
            assert!(
                !holds(&logged, b"private"),
                "a plain request's path is never kept"
            );
            assert!(!holds(&logged, SECRET), "no password in the log");

            // "Log where these apps connect" off: the next proxy keeps its kind alone, in the log too.
            engine.tunnels(&datapavan_net::TunnelSetting::default());
            let mut hidden = app_connect(socks).await?;
            hidden_request(&mut hidden, &auth).await?;
            drop(hidden);
            tokio::time::sleep(Duration::from_millis(300)).await;
            engine.flush_log();
            let logged = LOGGED.lock().map_err(|e| e.to_string())?.clone();
            assert!(!holds(&logged, b"hidden.example"), "not once it is off");
            assert!(!holds(&logged, SECRET), "no password in the log");
            assert!(
                !format!("{:?}", engine.flows()).contains("hunter2"),
                "no password in a flow"
            );
            assert!(
                !holds(&engine.activity(), SECRET),
                "no password in the live view"
            );
            let counters = engine.counters();
            assert_eq!(
                (counters[61], counters[62]),
                (4, 3),
                "requests declared, and with a password"
            );
            Ok(())
        },
    )
}

/// The handshake of a SOCKS5 proxy with a password, asking for `hidden.example`.
async fn hidden_request(connection: &mut TcpStream, auth: &[u8]) -> Outcome {
    step(connection, &[5, 2, 0, 2], &[5, 2]).await?;
    step(connection, auth, &[1, 0]).await?;
    let mut other = vec![5, 1, 0, 3, 14];
    other.extend_from_slice(b"hidden.example");
    other.extend_from_slice(&443u16.to_be_bytes());
    step(connection, &other, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

/// 64 random-looking bytes that start Telegram's obfuscated transport.
fn obfuscated_start() -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut header: Vec<u8> = (0..64)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24).to_le_bytes()[0]
        })
        .collect();
    header[0] = 0x3c;
    header
}

/// Telegram's proxy inferred end to end (ADR 0052): an obfuscated start to an address outside Telegram's published
/// ranges is its `MTProto` proxy while it reaches none of them; once it does (an address of its ranges on the lab's
/// loopback, never the real one), a CDN data centre reached directly is not its proxy, nor a fake-TLS hello, whose
/// cover never names the flow.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn telegrams_proxy_is_inferred_only_while_it_does_not_reach_its_own_ranges() -> Outcome {
    lab(
        "telegrams_proxy_is_inferred_only_while_it_does_not_reach_its_own_ranges",
        &Limits::default(),
        |engine| async move {
            // An address of Telegram's ranges on the namespace's own loopback: nothing leaves the lab.
            let telegram = Ipv4Addr::new(149, 154, 167, 51);
            let added = Command::new("ip")
                .args(["address", "add", "149.154.167.51/32", "dev", "lo"])
                .status()?;
            assert!(added.success(), "the lab's address of Telegram's ranges");
            engine.tunnels(&datapavan_net::TunnelSetting {
                log_destinations: true,
                ..datapavan_net::TunnelSetting::default()
            });
            engine.proxies(datapavan_net::ProxySetting {
                messengers: vec![(datapavan_net::messengers::Family::Telegram, APP)],
                android: Vec::new(),
            });
            let start = obfuscated_start();
            let proxy = scripted_proxy(OTHER, &[]).await?;
            let mut via = app_connect(proxy).await?;
            step(&mut via, &start, &start).await?;
            let flow = flow_to(&engine, proxy, |f| f.proxy.is_some()).await?;
            assert_eq!(
                flow.proxy.map(|p| (p.kind, p.outside_maker)),
                Some((datapavan_net::proxies::Kind::MtProto, true))
            );

            let own = scripted_proxy(telegram, &[]).await?;
            let mut direct = app_connect(own).await?;
            step(&mut direct, &start, &start).await?;
            // The proxy's name is taken back, and a CDN data centre reached now is no proxy.
            flow_to(&engine, proxy, |f| f.proxy.is_none()).await?;
            let cdn = scripted_proxy(SERVER, &[]).await?;
            let mut media = app_connect(cdn).await?;
            step(&mut media, &start, &start).await?;
            let mut cover = app_connect(cdn).await?;
            let hello = client_hello("www.google.com");
            step(&mut cover, &hello, &hello).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let to_cdn: Vec<_> = engine
                .flows()
                .into_iter()
                .filter(|f| f.destination == cdn)
                .collect();
            assert_eq!(to_cdn.len(), 2, "{to_cdn:?}");
            assert!(to_cdn.iter().all(|f| f.proxy.is_none()), "{to_cdn:?}");
            assert!(
                to_cdn
                    .iter()
                    .all(|f| f.name.as_deref() != Some("www.google.com")),
                "Telegram → google.com"
            );
            let counters = engine.counters();
            assert_eq!(
                (counters[63], counters[64], counters[65], counters[66]),
                (1, 2, 1, 1)
            );
            drop((via, direct, media, cover));
            Ok(())
        },
    )
}
