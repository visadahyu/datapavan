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
use datapavan_net::{Chain, Config, Engine, Platform};
use std::collections::HashSet;
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
/// A second address beside it: another server, or a stranger to the apps.
const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
/// The UID the lab's Android names for every app in the tunnel.
const APP: u32 = 10_500;
/// The places of counters in `Engine::counters`.
const TCP_FLOWS: usize = 0;
const UDP_FLOWS: usize = 1;
const STRANGERS: usize = 18;
const RESETS: usize = 22;
const TCP_REFUSED: usize = 23;
const UDP_MAPPINGS: usize = 24;
const UDP_FILTERED: usize = 25;
const UDP_RELAY_ELSEWHERE: usize = 28;
/// A server that never answers (scripts/netlab-enter.py routes it into a tunnel no one reads).
const SILENT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
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
        Limits::default(),
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
        Limits::default(),
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
        Limits::default(),
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
        limits,
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
        Limits::default(),
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
        Limits::default(),
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
        Limits::default(),
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
        Limits::default(),
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

/// ADR 0044, decision 3: a lookup to the tunnel's DNS address ends its flow with its answer, so the
/// same app socket's next lookup is a flow of its own.
#[test]
#[ignore = "needs an unprivileged network namespace; scripts/check.sh rust runs it"]
fn a_lookups_flow_ends_with_its_answer() -> Outcome {
    lab(
        "a_lookups_flow_ends_with_its_answer",
        Limits::default(),
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
        limits,
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
        Limits::default(),
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
        Limits::default(),
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
        Limits::default(),
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
        Limits::default(),
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
