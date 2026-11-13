//! Chaining (W6) through the whole engine: a pair of datagram sockets stands in for the tunnel, the
//! small proxy of `common` for the user's tool. Chained apps' UDP goes through the tool's relay, the
//! other apps' directly; chained apps' lookups get stand-in addresses, and the name behind one goes to
//! the tool; other questions go to the resolver through the tool and come back with a time to live of
//! 0, sharing one kept connection, which is opened again when the resolver closes it; a stopped tool
//! gets the app an ICMP error and sends nothing directly. An app socket's datagrams to every
//! destination share one `UDP ASSOCIATE`, and each answer is matched to its destination by the
//! address its header gives, with the direct path's filtering (ADR 0044, decision 2).

mod common;

use common::{Headers, Settings, proxy, udp_echo};
use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::{Chain, Config, Engine, Platform, dns, packet};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket, UnixDatagram};
use tokio::sync::{Barrier, oneshot};

type Outcome = Result<(), Box<dyn std::error::Error>>;

const TOOL: u32 = 10_200;
const CHAINED: u32 = 10_300;
const DIRECT: u32 = 10_400;
/// The app's ports inside the tunnel: the chained app's, then the direct app's.
const CHAINED_PORT: u16 = 40_000;
const DIRECT_PORT: u16 = 40_001;
/// The places of counters in `Engine::counters`.
const UDP_FLOWS: usize = 1;
const UDP_MAPPINGS: usize = 24;
const UDP_FILTERED: usize = 25;
const UDP_UNMATCHED: usize = 26;
const UDP_CAME_IN_CAPPED: usize = 27;
const UDP_RELAY_ELSEWHERE: usize = 28;

/// Android names the app by its port inside the tunnel.
struct ByPort;

impl Platform for ByPort {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() {
            CHAINED_PORT => Some(CHAINED),
            DIRECT_PORT => Some(DIRECT),
            _ => None,
        }
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// The engine on a datagram pair, with `chain` on, and the app's end of the pair.
fn engine(chain: Chain) -> io::Result<(Engine, UnixDatagram)> {
    engine_at(chain, Addresses::COMMON)
}

/// As [`engine`], with the tunnel's addresses `addresses`.
fn engine_at(chain: Chain, addresses: Addresses) -> io::Result<(Engine, UnixDatagram)> {
    started(chain, addresses, Limits::default(), Arc::new(ByPort))
}

/// As [`engine`], with `limits`, and `platform` for Android.
fn engine_with(
    chain: Chain,
    limits: Limits,
    platform: Arc<dyn Platform>,
) -> io::Result<(Engine, UnixDatagram)> {
    started(chain, Addresses::COMMON, limits, platform)
}

fn started(
    chain: Chain,
    addresses: Addresses,
    limits: Limits,
    platform: Arc<dyn Platform>,
) -> io::Result<(Engine, UnixDatagram)> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            limits,
            mtu: 1500,
            keep_flows: 64,
            addresses,
        },
        platform,
        None,
    )?;
    engine.chain(Some(chain));
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

fn chain(proxy: SocketAddr) -> Chain {
    Chain {
        proxy,
        credentials: None,
        tool: TOOL,
        apps: Some(HashSet::from([CHAINED])),
        udp: true,
        log_destinations: false,
    }
}

fn app(port: u16) -> SocketAddr {
    SocketAddr::from((Addresses::COMMON.tun4, port))
}

async fn send(tunnel: &UnixDatagram, from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Outcome {
    let datagram = packet::udp(from, to, payload).ok_or("a datagram")?;
    tunnel.send(&datagram).await?;
    Ok(())
}

/// The next packet to the app: its source and payload, or `None` for anything but UDP (an ICMP error).
async fn receive(
    tunnel: &UnixDatagram,
) -> Result<Option<(SocketAddr, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(5), tunnel.recv(&mut buffer)).await??;
    let Ok(parsed) = packet::parse(&buffer[..n]) else {
        return Ok(None);
    };
    Ok(packet::udp_payload(&buffer[..n], &parsed).map(|p| (parsed.source, p.to_vec())))
}

fn query(name: &[u8], kind: u16) -> Vec<u8> {
    let mut q = vec![0x51, 0x52, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(name);
    q.extend_from_slice(&kind.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

#[tokio::test(flavor = "current_thread")]
async fn chained_udp_goes_through_the_tool_and_the_rest_directly() -> Outcome {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    send(&tunnel, app(CHAINED_PORT), echo, b"chained").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (echo, b"chained".to_vec()));
    assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");

    send(&tunnel, app(DIRECT_PORT), echo, b"direct").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (echo, b"direct".to_vec()));
    assert_eq!(tool.commands(), [3], "the direct app did not use the tool");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_chained_lookup_gets_a_stand_in_whose_name_goes_to_the_tool() -> Outcome {
    let echo = udp_echo().await?;
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), echo.ip());
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x04echo\x04test\x00", 1),
    )
    .await?;
    let (from, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(from, dns);
    let read = dns::response(&answer).ok_or("a response")?;
    let [(IpAddr::V4(stand_in), 0)] = read.addresses[..] else {
        return Err(format!(
            "not one stand-in with a time to live of 0: {:?}",
            read.addresses
        )
        .into());
    };
    assert_eq!(stand_in, Ipv4Addr::new(198, 18, 0, 1));

    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((stand_in, echo.port())),
        b"by name",
    )
    .await?;
    let (from, payload) = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(
        (from, payload.as_slice()),
        (SocketAddr::from((stand_in, echo.port())), &b"by name"[..])
    );
    assert_eq!(tool.commands(), [3]);

    // The direct app cannot use a stand-in.
    send(
        &tunnel,
        app(DIRECT_PORT),
        SocketAddr::from((stand_in, echo.port())),
        b"no",
    )
    .await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error");
    Ok(())
}

/// With the spare addresses (ADR 0041), the tunnel's DNS server is the spare one: a chained app's lookup
/// to it gets its stand-in, answered from that address.
#[tokio::test(flavor = "current_thread")]
async fn the_spare_addresses_carry_the_tunnels_lookups() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (_engine, tunnel) = engine_at(chain(tool.address), Addresses::SPARE)?;
    let dns = SocketAddr::from((Addresses::SPARE.dns4, 53));
    let from_app = SocketAddr::from((Addresses::SPARE.tun4, CHAINED_PORT));
    send(&tunnel, from_app, dns, &query(b"\x04echo\x04test\x00", 1)).await?;
    let (from, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(from, dns);
    let read = dns::response(&answer).ok_or("a response")?;
    assert!(
        matches!(read.addresses[..], [(IpAddr::V4(_), 0)]),
        "not one stand-in: {:?}",
        read.addresses
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn other_questions_go_to_the_resolver_through_the_tool() -> Outcome {
    // A resolver here, reached when the tool is asked for Quad9.
    let resolver = TcpListener::bind("127.0.0.1:0").await?;
    let resolver_address = resolver.local_addr()?;
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&asked);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = resolver.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).await.is_err() {
                continue;
            }
            let mut question = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut question).await.is_err() {
                continue;
            }
            // The question's ID and question, one TXT record of 300 s.
            let mut answer = question[..2].to_vec();
            answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            answer.extend_from_slice(&question[12..]);
            answer.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 1, 44, 0, 6, 5]);
            answer.extend_from_slice(b"hello");
            let mut framed = u16::try_from(answer.len())
                .unwrap_or(0)
                .to_be_bytes()
                .to_vec();
            framed.extend_from_slice(&answer);
            let _ = stream.write_all(&framed).await;
        }
    });
    let mut settings = Settings::default();
    settings
        .remap
        .insert(SocketAddr::from(([9, 9, 9, 10], 53)), resolver_address);
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x07example\x03com\x00", 16),
    )
    .await?;
    let (_, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(answer[..4], [0x51, 0x52, 0x81, 0x80]);
    assert_eq!(answer[6..8], [0, 1], "one record");
    assert!(answer.ends_with(&[
        0, 16, 0, 1, 0, 0, 0, 0, 0, 6, 5, b'h', b'e', b'l', b'l', b'o'
    ]));
    assert_eq!(tool.commands(), [1], "one CONNECT, to the resolver");
    // Asked again within the record's 300 s, from another port: Watch answers from what it kept.
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x07example\x03com\x00", 16),
    )
    .await?;
    let (_, again) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(
        again, answer,
        "the same answer, again with a time to live of 0"
    );
    assert_eq!(
        asked.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the resolver was asked once"
    );
    assert_eq!(tool.commands(), [1]);
    Ok(())
}

/// The next DNS message on a DNS over TCP connection.
async fn read_message(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).await?;
    Ok(message)
}

/// The answer to a TXT question of one label and a domain: one record holding that label, framed.
fn txt_answer(question: &[u8]) -> Vec<u8> {
    let label = usize::from(question[12]);
    let mut answer = question[..2].to_vec();
    answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&question[12..]);
    let size = |n: usize| u8::try_from(n).unwrap_or(0);
    answer.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 1, 44, 0, size(label + 1)]);
    answer.push(size(label));
    answer.extend_from_slice(&question[13..13 + label]);
    let mut framed = u16::try_from(answer.len())
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&answer);
    framed
}

#[tokio::test(flavor = "current_thread")]
async fn questions_share_one_kept_connection_to_the_resolver() -> Outcome {
    // A resolver here that holds the first two questions on a connection and answers them in reverse
    // order, then answers each as it comes; it counts its connections and notes the IDs it is asked
    // under.
    let resolver = TcpListener::bind("127.0.0.1:0").await?;
    let resolver_address = resolver.local_addr()?;
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ids = Arc::new(std::sync::Mutex::new(Vec::<u16>::new()));
    let (counted, noted) = (Arc::clone(&connections), Arc::clone(&ids));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = resolver.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let noted = Arc::clone(&noted);
            tokio::spawn(async move {
                let mut held = Vec::new();
                let mut answered = 0;
                while let Ok(question) = read_message(&mut stream).await {
                    noted
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(u16::from_be_bytes([question[0], question[1]]));
                    held.push(question);
                    if answered == 0 && held.len() < 2 {
                        continue;
                    }
                    for question in held.drain(..).rev() {
                        answered += 1;
                        if stream.write_all(&txt_answer(&question)).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    let mut settings = Settings::default();
    settings
        .remap
        .insert(SocketAddr::from(([9, 9, 9, 10], 53)), resolver_address);
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));

    // Two questions at once, under the same ID, as two apps may ask.
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x01a\x04test\x00", 16),
    )
    .await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x01b\x04test\x00", 16),
    )
    .await?;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let (_, answer) = receive(&tunnel).await?.ok_or("an answer")?;
        answers.push(answer);
    }
    answers.sort_by_key(|answer| answer[13]);
    for (answer, label) in answers.iter().zip(*b"ab") {
        assert_eq!(answer[..4], [0x51, 0x52, 0x81, 0x80], "the app's own ID");
        assert_eq!(answer[13], label, "the answer to its own question");
        assert!(answer.ends_with(&[1, label]), "its own record");
    }
    // A third question, after the first two were answered: the same connection.
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x01c\x04test\x00", 16),
    )
    .await?;
    let (_, third) = receive(&tunnel).await?.ok_or("an answer")?;
    assert!(third.ends_with(&[1, b'c']));
    assert_eq!(tool.commands(), [1], "one CONNECT, to the resolver");
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "one connection for the three questions"
    );
    let ids = ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(ids.len(), 3);
    assert!(
        ids[0] != ids[1] && !ids.contains(&0x5152),
        "each question under an ID of the connection's own: {ids:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_connection_the_resolver_closed_is_opened_again() -> Outcome {
    // A resolver here that answers one question on each connection and closes it.
    let resolver = TcpListener::bind("127.0.0.1:0").await?;
    let resolver_address = resolver.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = resolver.accept().await {
            if let Ok(question) = read_message(&mut stream).await {
                let _ = stream.write_all(&txt_answer(&question)).await;
            }
        }
    });
    let mut settings = Settings::default();
    settings
        .remap
        .insert(SocketAddr::from(([9, 9, 9, 10], 53)), resolver_address);
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    for (name, label) in [
        (&b"\x01a\x04test\x00"[..], b'a'),
        (b"\x01b\x04test\x00", b'b'),
    ] {
        send(&tunnel, app(CHAINED_PORT), dns, &query(name, 16)).await?;
        let (_, answer) = receive(&tunnel).await?.ok_or("an answer")?;
        assert_eq!(answer[3] & 0x0f, 0, "an answer, not a failure");
        assert!(answer.ends_with(&[1, label]));
    }
    assert_eq!(tool.commands(), [1, 1], "a new connection for the second");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_stopped_tool_gets_the_app_an_error_and_sends_nothing_directly() -> Outcome {
    let echo = udp_echo().await?;
    // A port nobody listens on: the tool stopped. It stays bound, so that another test's proxy, in the
    // same process, cannot take it meanwhile.
    let held = tokio::net::TcpSocket::new_v4()?;
    held.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let stopped = held.local_addr()?;
    let (_engine, tunnel) = engine(chain(stopped))?;
    send(&tunnel, app(CHAINED_PORT), echo, b"waits").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error, no echo");
    // Had the datagram gone directly, the echo would come now.
    let mut buffer = [0u8; 2048];
    let later = tokio::time::timeout(Duration::from_millis(500), tunnel.recv(&mut buffer)).await;
    assert!(later.is_err(), "nothing more reaches the app");
    Ok(())
}

/// The stand-in a chained app's lookup of `name` (in DNS's form) gets.
async fn stand_in(
    tunnel: &UnixDatagram,
    name: &[u8],
) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    send(tunnel, app(CHAINED_PORT), dns, &query(name, 1)).await?;
    let (_, answer) = receive(tunnel).await?.ok_or("an answer")?;
    let read = dns::response(&answer).ok_or("a response")?;
    match read.addresses[..] {
        [(IpAddr::V4(stand_in), 0)] => Ok(stand_in),
        _ => Err(format!("not one stand-in: {:?}", read.addresses).into()),
    }
}

/// The chained app sends `said` to `to`, and its echo comes back from there.
async fn echoed(tunnel: &UnixDatagram, to: SocketAddr, said: &[u8]) -> Outcome {
    send(tunnel, app(CHAINED_PORT), to, said).await?;
    let answer = receive(tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (to, said.to_vec()));
    Ok(())
}

/// ADR 0044, decision 2: one app socket's datagrams to two destinations go over one `UDP ASSOCIATE`,
/// each with a header that names its own, and each answer comes back from its own destination.
#[tokio::test(flavor = "current_thread")]
async fn one_app_socket_reaches_two_destinations_over_one_association() -> Outcome {
    let (first, second) = (udp_echo().await?, udp_echo().await?);
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    echoed(&tunnel, first, b"to the first").await?;
    echoed(&tunnel, second, b"to the second").await?;
    echoed(&tunnel, first, b"to the first again").await?;
    assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");
    let counters = engine.counters();
    assert_eq!(
        (counters[UDP_MAPPINGS], counters[UDP_FLOWS]),
        (1, 2),
        "one mapping, two flows"
    );
    Ok(())
}

/// Address-dependent filtering through the tool: an answer whose header names an address the app never
/// sent to is dropped and counted, not given to the app as if from its destination.
#[tokio::test(flavor = "current_thread")]
async fn an_answer_from_an_address_the_app_never_sent_to_is_dropped() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let stranger = UdpSocket::bind("127.0.0.2:0").await?;
    let at = server.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((_, relay)) = server.recv_from(&mut buffer).await {
            // To the tool's relay, which names each sender in its header.
            let _ = stranger.send_to(b"from a stranger", relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = server.send_to(b"from the server", relay).await;
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(CHAINED_PORT), at, b"hello").await?;
    // Sent first: had it got through, the app would read it first.
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (at, b"from the server".to_vec()));
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// An answer from another port of an address the app sent to opens a flow of its own, that came in,
/// from that port; what the app sends back goes there over the same association.
#[tokio::test(flavor = "current_thread")]
async fn another_port_of_a_destination_opens_a_flow_that_came_in() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let other_port = UdpSocket::bind("127.0.0.1:0").await?;
    let (at, other) = (server.local_addr()?, other_port.local_addr()?);
    let (tell, heard) = oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((_, relay)) = server.recv_from(&mut buffer).await {
            let _ = other_port.send_to(b"from another port", relay).await;
            if let Ok((n, _)) = other_port.recv_from(&mut buffer).await {
                let _ = tell.send(buffer[..n].to_vec());
            }
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(CHAINED_PORT), at, b"hello").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (other, b"from another port".to_vec()));
    send(&tunnel, app(CHAINED_PORT), other, b"back").await?;
    let back = tokio::time::timeout(Duration::from_secs(5), heard).await??;
    assert_eq!(back, b"back");
    assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");
    let destinations: Vec<_> = engine
        .flows()
        .iter()
        .filter(|flow| flow.protocol == packet::UDP)
        .map(|flow| flow.destination)
        .collect();
    assert_eq!(destinations, [at, other], "the port that came in is a flow");
    assert_eq!(engine.counters()[UDP_FILTERED], 0);
    Ok(())
}

/// ADR 0044, decision 2: the tool resolves a stand-in's name itself, so its relay answers from the real
/// address. The answer reaches the app from the stand-in, which is bound to that address, and the same
/// socket's datagrams to an address share its association.
#[tokio::test(flavor = "current_thread")]
async fn a_stand_in_gets_the_answer_from_the_real_address() -> Outcome {
    let (named, by_address) = (udp_echo().await?, udp_echo().await?);
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), named.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let stand_in = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        named.port(),
    ));
    echoed(&tunnel, stand_in, b"by name").await?;
    echoed(&tunnel, by_address, b"by address").await?;
    echoed(&tunnel, stand_in, b"by name again").await?;
    assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");
    let counters = engine.counters();
    assert_eq!(
        [
            counters[UDP_MAPPINGS],
            counters[UDP_FILTERED],
            counters[UDP_UNMATCHED]
        ],
        [1, 0, 0]
    );
    Ok(())
}

/// Two stand-ins waiting on one port: an answer from that port could be either name's, so it is
/// dropped and counted rather than given to the app under the wrong name.
#[tokio::test(flavor = "current_thread")]
async fn an_answer_two_stand_ins_could_take_is_dropped() -> Outcome {
    let first = UdpSocket::bind("127.0.0.1:0").await?;
    let port = first.local_addr()?.port();
    let second = UdpSocket::bind(("127.0.0.2", port)).await?;
    // Each answers once both were asked, so that both stand-ins wait when the answers come.
    let both = Arc::new(Barrier::new(2));
    for server in [first, second] {
        let both = Arc::clone(&both);
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            if let Ok((n, relay)) = server.recv_from(&mut buffer).await {
                both.wait().await;
                let _ = server.send_to(&buffer[..n], relay).await;
            }
        });
    }
    let mut settings = Settings::default();
    settings
        .names
        .insert("a.test".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    settings
        .names
        .insert("b.test".into(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    let b = stand_in(&tunnel, b"\x01b\x04test\x00").await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((a, port)),
        b"to a",
    )
    .await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((b, port)),
        b"to b",
    )
    .await?;
    let mut buffer = [0u8; 2048];
    let later = tokio::time::timeout(Duration::from_millis(500), tunnel.recv(&mut buffer)).await;
    assert!(later.is_err(), "an answer reached the app under a name");
    assert_eq!(engine.counters()[UDP_UNMATCHED], 2);
    assert_eq!(tool.commands(), [3]);
    Ok(())
}

/// ADR 0044, decision 1: a mapping ends when the chain changes. Set again with the same tool, the chain
/// keeps a chained app's relay; with another tool, the app's next datagram goes through that one; with
/// none, directly.
#[tokio::test(flavor = "current_thread")]
async fn a_new_chain_moves_a_mapping_only_when_its_way_changes() -> Outcome {
    let echo = udp_echo().await?;
    let (first, second) = (
        proxy(Settings::default()).await?,
        proxy(Settings::default()).await?,
    );
    let (engine, tunnel) = engine(chain(first.address))?;
    echoed(&tunnel, echo, b"one").await?;
    engine.chain(Some(chain(first.address)));
    echoed(&tunnel, echo, b"two").await?;
    assert_eq!(first.commands(), [3], "the same tool kept its relay");
    engine.chain(Some(chain(second.address)));
    echoed(&tunnel, echo, b"three").await?;
    assert_eq!(
        (first.commands(), second.commands()),
        (vec![3], vec![3]),
        "the other tool's relay"
    );
    engine.chain(None);
    echoed(&tunnel, echo, b"four").await?;
    assert_eq!(second.commands(), [3], "directly");
    assert_eq!(engine.counters()[UDP_MAPPINGS], 3);
    Ok(())
}

/// What the server at a socket heard: each sender and payload.
type Heard = Arc<std::sync::Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

/// Everything heard, so far.
fn heard_so_far(heard: &Heard) -> Vec<(SocketAddr, Vec<u8>)> {
    heard
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// What reaches the app until the tunnel stays silent for half a second.
async fn everything(tunnel: &UnixDatagram) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut seen = Vec::new();
    let mut buffer = vec![0u8; 65_535];
    while let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_millis(500), tunnel.recv(&mut buffer)).await
    {
        if let Ok(parsed) = packet::parse(&buffer[..n])
            && let Some(payload) = packet::udp_payload(&buffer[..n], &parsed)
        {
            seen.push((parsed.source, payload.to_vec()));
        }
    }
    seen
}

/// Nothing more reaches the app for half a second.
async fn silent(tunnel: &UnixDatagram) -> bool {
    let mut buffer = [0u8; 2048];
    tokio::time::timeout(Duration::from_millis(500), tunnel.recv(&mut buffer))
        .await
        .is_err()
}

/// A DNS response to `query` under the ID `id`, with no records.
fn dns_response(query: &[u8], id: u16) -> Vec<u8> {
    let mut response = query.to_vec();
    response[..2].copy_from_slice(&id.to_be_bytes());
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response
}

/// Two names the tool resolves to one address and port, asked one after the other: once the first is
/// bound to that address, an answer from it while the second waits could be either name's. It is
/// dropped and counted, never given to the app under the first name (review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_second_name_at_a_bound_address_is_not_answered_as_the_first() -> Outcome {
    let echo = udp_echo().await?;
    let mut settings = Settings::default();
    settings.names.insert("a.test".into(), echo.ip());
    settings.names.insert("b.test".into(), echo.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let a = SocketAddr::from((stand_in(&tunnel, b"\x01a\x04test\x00").await?, echo.port()));
    let b = SocketAddr::from((stand_in(&tunnel, b"\x01b\x04test\x00").await?, echo.port()));
    echoed(&tunnel, a, b"to a").await?;
    send(&tunnel, app(CHAINED_PORT), b, b"to b").await?;
    assert!(silent(&tunnel).await, "b's answer reached the app as a's");
    assert_eq!(engine.counters()[UDP_UNMATCHED], 1);
    Ok(())
}

/// On port 53, a stand-in is bound only by a DNS response to a query the app sent it: a stranger that
/// answers first, with something else or under another ID, takes nothing, and feeds Watch no names
/// (review of unit 9, finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_stranger_cannot_take_a_stand_in_on_port_53() -> Outcome {
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let stranger = UdpSocket::bind("127.0.0.2:0").await?;
    let named = SocketAddr::from(([192, 0, 2, 53], 53));
    let elsewhere = SocketAddr::from(([198, 51, 100, 66], 53));
    let mut settings = Settings::default();
    settings.names.insert("dns.test".into(), named.ip());
    // The relay reaches the resolver and the stranger here, and names them as if on port 53.
    settings.remap.insert(named, resolver.local_addr()?);
    settings.remap.insert(elsewhere, stranger.local_addr()?);
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        if let Ok((n, relay)) = resolver.recv_from(&mut buffer).await {
            let query = buffer[..n].to_vec();
            let _ = stranger.send_to(b"not a response", relay).await;
            let _ = stranger.send_to(&dns_response(&query, 0x9999), relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = resolver.send_to(&dns_response(&query, 0x5152), relay).await;
        }
    });
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((stand_in(&tunnel, b"\x03dns\x04test\x00").await?, 53));
    let asked = query(b"\x07example\x03com\x00", 16);
    send(&tunnel, app(CHAINED_PORT), at, &asked).await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (at, dns_response(&asked, 0x5152)));
    assert_eq!(engine.counters()[UDP_FILTERED], 2);
    Ok(())
}

/// Another port of an address the app sent to comes in as that address's, even on the port a stand-in
/// waits on: it does not take the stand-in, whose own answer then binds it (review of unit 9, finding
/// 2).
#[tokio::test(flavor = "current_thread")]
async fn another_port_of_a_destination_is_not_a_stand_ins_first_answer() -> Outcome {
    let destination = udp_echo().await?;
    let named = UdpSocket::bind("127.0.0.2:0").await?;
    let port = named.local_addr()?.port();
    let beside = UdpSocket::bind((destination.ip(), port)).await?;
    let other_port = beside.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, relay)) = named.recv_from(&mut buffer).await {
            let _ = beside.send_to(b"from the destination", relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = named.send_to(&buffer[..n], relay).await;
        }
    });
    let mut settings = Settings::default();
    settings
        .names
        .insert("a.test".into(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    echoed(&tunnel, destination, b"to the destination").await?;
    let a = SocketAddr::from((stand_in(&tunnel, b"\x01a\x04test\x00").await?, port));
    send(&tunnel, app(CHAINED_PORT), a, b"to a").await?;
    let first = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(first, (other_port, b"from the destination".to_vec()));
    let second = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(second, (a, b"to a".to_vec()));
    Ok(())
}

/// Through the tool and directly alike, a mapping lets in at most 64 other ports of an address its app
/// sent to: what comes from more is dropped and counted (review of unit 9, finding 3).
#[tokio::test(flavor = "current_thread")]
async fn a_mapping_lets_in_at_most_64_other_ports() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    for (round, from) in [(1, app(CHAINED_PORT)), (2, app(DIRECT_PORT))] {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let at = server.local_addr()?;
        let mut ports = Vec::new();
        for _ in 0..70 {
            ports.push(UdpSocket::bind("127.0.0.1:0").await?);
        }
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            if let Ok((_, mapped)) = server.recv_from(&mut buffer).await {
                for port in &ports {
                    let _ = port.send_to(b"another port", mapped).await;
                }
            }
        });
        send(&tunnel, from, at, b"hello").await?;
        let seen = everything(&tunnel).await;
        assert_eq!(seen.len(), 64, "round {round}: ports let in");
        assert_eq!(engine.counters()[UDP_CAME_IN_CAPPED], 6 * round);
    }
    Ok(())
}

/// A direct app's mapping, then a chain that takes the app: its next datagram goes through the tool
/// (the review of unit 9's experiment, kept).
#[tokio::test(flavor = "current_thread")]
async fn a_direct_mapping_moves_into_the_tool_when_the_chain_takes_its_app() -> Outcome {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(DIRECT_PORT), echo, b"one").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(tool.commands(), Vec::<u8>::new());
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    send(&tunnel, app(DIRECT_PORT), echo, b"two").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (echo, b"two".to_vec()));
    assert_eq!(tool.commands(), [3], "through the tool now");
    Ok(())
}

/// As [`ByPort`], with a protect that takes 300 ms, as a busy Binder may.
struct SlowProtect;

impl Platform for SlowProtect {
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        ByPort.owner(protocol, local, remote)
    }

    fn protect(&self, _: RawFd) -> bool {
        std::thread::sleep(Duration::from_millis(300));
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// The chain takes a direct app while its first mapping opens: what the app sent after that leaves
/// through the tool, not directly (review of unit 9, finding 4).
#[tokio::test(flavor = "current_thread")]
async fn what_is_sent_once_the_chain_takes_an_app_goes_through_the_tool() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        while let Ok((n, from)) = server.recv_from(&mut buffer).await {
            noted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((from, buffer[..n].to_vec()));
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine_with(
        chain(tool.address),
        Limits::default(),
        Arc::new(SlowProtect),
    )?;
    send(&tunnel, app(DIRECT_PORT), at, b"before the chain").await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    send(&tunnel, app(DIRECT_PORT), at, b"after the chain").await?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let after: Vec<_> = heard_so_far(&heard)
        .into_iter()
        .filter(|(_, payload)| payload == b"after the chain")
        .map(|(from, _)| from)
        .collect();
    assert_eq!(after.len(), 1, "heard {after:?}");
    assert!(
        tool.relays().contains(&after[0]),
        "from {}, not the tool's relay {:?}",
        after[0],
        tool.relays()
    );
    Ok(())
}

/// A tool that offers its UDP relay elsewhere than on the phone or at its proxy's address would take
/// the app's datagrams, with their destinations in the header, across the network beneath: its UDP is
/// refused, as a tool's without UDP, and counted (review of unit 9, finding 5).
#[tokio::test(flavor = "current_thread")]
async fn a_relay_elsewhere_is_refused() -> Outcome {
    let echo = udp_echo().await?;
    let settings = Settings {
        relay_at: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        ..Settings::default()
    };
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(CHAINED_PORT), echo, b"stays").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error");
    assert_eq!(engine.counters()[UDP_RELAY_ELSEWHERE], 1);
    Ok(())
}

/// A stand-in waits on the port the app asked: an answer from an address the app never saw, on another
/// port, does not bind it.
#[tokio::test(flavor = "current_thread")]
async fn an_answer_on_another_port_does_not_bind_a_stand_in() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let port = server.local_addr()?.port();
    let elsewhere = UdpSocket::bind("127.0.0.2:0").await?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, relay)) = server.recv_from(&mut buffer).await {
            let _ = elsewhere.send_to(b"another port", relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = server.send_to(&buffer[..n], relay).await;
        }
    });
    let mut settings = Settings::default();
    settings
        .names
        .insert("echo.test".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((stand_in(&tunnel, b"\x04echo\x04test\x00").await?, port));
    send(&tunnel, app(CHAINED_PORT), at, b"hello").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (at, b"hello".to_vec()));
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// A relay that gives back the name each datagram was sent to: its answers reach the app from that
/// name's stand-in.
#[tokio::test(flavor = "current_thread")]
async fn a_relay_that_names_the_name_is_matched_by_it() -> Outcome {
    let echo = udp_echo().await?;
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), echo.ip());
    settings.headers = Headers::Name;
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        echo.port(),
    ));
    echoed(&tunnel, at, b"by name").await?;
    echoed(&tunnel, at, b"by name again").await?;
    let counters = engine.counters();
    assert_eq!([counters[UDP_FILTERED], counters[UDP_UNMATCHED]], [0, 0]);
    Ok(())
}

/// A relay that names an IPv4 sender as an IPv4-mapped IPv6 address names the address the app sent to.
#[tokio::test(flavor = "current_thread")]
async fn a_relay_that_names_ipv4_as_ipv6_is_understood() -> Outcome {
    let echo = udp_echo().await?;
    let settings = Settings {
        headers: Headers::Mapped,
        ..Settings::default()
    };
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    echoed(&tunnel, echo, b"as IPv6").await?;
    assert_eq!(engine.counters()[UDP_FILTERED], 0);
    Ok(())
}

/// Two destinations opened at once wait for one relay; when the tool never answers, the one waiting
/// fails with the one that asked, at once, instead of asking the silent tool again.
#[tokio::test(flavor = "current_thread")]
async fn destinations_that_wait_for_a_relay_fail_with_it() -> Outcome {
    let silent_tool = TcpListener::bind("127.0.0.1:0").await?;
    let address = silent_tool.local_addr()?;
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&accepted);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((connection, _)) = silent_tool.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            held.push(connection);
        }
    });
    let limits = Limits {
        connect_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let (_engine, tunnel) = engine_with(chain(address), limits, Arc::new(ByPort))?;
    let (first, second) = (udp_echo().await?, udp_echo().await?);
    let started = tokio::time::Instant::now();
    send(&tunnel, app(CHAINED_PORT), first, b"one").await?;
    send(&tunnel, app(CHAINED_PORT), second, b"two").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error");
    assert_eq!(receive(&tunnel).await?, None, "another");
    assert!(
        started.elapsed() < Duration::from_millis(1_800),
        "the second waited {:?}",
        started.elapsed()
    );
    assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 1);
    Ok(())
}

/// A tool that ends its relay ends the mapping: the app's next datagram asks for another.
#[tokio::test(flavor = "current_thread")]
async fn a_tool_that_ends_its_relay_is_asked_for_another() -> Outcome {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    echoed(&tunnel, echo, b"one").await?;
    tool.close_relays();
    tokio::time::sleep(Duration::from_millis(200)).await;
    echoed(&tunnel, echo, b"two").await?;
    assert_eq!(tool.commands(), [3, 3]);
    assert_eq!(engine.counters()[UDP_MAPPINGS], 2);
    Ok(())
}

/// A fragment and a header cut short, from the tool's relay, reach no destination and are counted.
#[tokio::test(flavor = "current_thread")]
async fn bad_headers_from_the_relay_are_dropped_and_counted() -> Outcome {
    let echo = udp_echo().await?;
    let settings = Settings {
        bad_headers_first: true,
        ..Settings::default()
    };
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    echoed(&tunnel, echo, b"after two bad ones").await?;
    assert_eq!(engine.counters()[UDP_UNMATCHED], 2);
    Ok(())
}

/// Another port of an address that a stand-in was bound to and that the app then sent to itself comes
/// in from that address, not from the stand-in (review of unit 9, finding 5).
#[tokio::test(flavor = "current_thread")]
async fn another_port_comes_in_from_the_address_the_app_sent_to() -> Outcome {
    let named = udp_echo().await?;
    let destination = UdpSocket::bind((named.ip(), 0)).await?;
    let beside = UdpSocket::bind((named.ip(), 0)).await?;
    let (at, other_port) = (destination.local_addr()?, beside.local_addr()?);
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, relay)) = destination.recv_from(&mut buffer).await {
            let _ = destination.send_to(&buffer[..n], relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = beside.send_to(b"another port", relay).await;
        }
    });
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), named.ip());
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    let stand_in = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        named.port(),
    ));
    echoed(&tunnel, stand_in, b"by name").await?;
    echoed(&tunnel, at, b"by address").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (other_port, b"another port".to_vec()));
    Ok(())
}

/// A resolver on this computer that hears every lookup and answers none, and the tunnel's DNS address
/// at its port: any port of that address leads to the same port of the network's resolver, so the
/// tests need not bind port 53.
async fn deaf_resolver(engine: &Engine) -> Result<(SocketAddr, Heard), Box<dyn std::error::Error>> {
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let port = resolver.local_addr()?.port();
    engine.network_changed(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), false);
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((n, from)) = resolver.recv_from(&mut buffer).await {
            noted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((from, buffer[..n].to_vec()));
        }
    });
    Ok((SocketAddr::from((Addresses::COMMON.dns4, port)), heard))
}

/// Whether the resolver heard a lookup of the name `private.test`.
fn heard_private(heard: &Heard) -> bool {
    heard_so_far(heard)
        .iter()
        .any(|(_, query)| query.windows(7).any(|w| w == b"private"))
}

/// A direct app's lookup still waits for its answer when the chain takes the app: the app's next lookup
/// from that socket goes through the tool, not to the network's resolver (second review of unit 9,
/// finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_sent_once_the_chain_takes_the_app_stays_off_the_network() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x06before\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    let (from, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(from, dns);
    let read = dns::response(&answer).ok_or("a response")?;
    assert!(
        matches!(read.addresses[..], [(IpAddr::V4(_), 0)]),
        "not Watch's stand-in: {:?}",
        read.addresses
    );
    assert!(
        !heard_private(&heard),
        "the lookup reached the network's resolver"
    );
    Ok(())
}

/// The chain takes a direct app while its first lookup's socket is being protected: the lookups that
/// waited, one sent once the chain took the app, go through the tool (second review of unit 9, finding
/// 2).
#[tokio::test(flavor = "current_thread")]
async fn lookups_that_wait_while_the_chain_takes_the_app_stay_off_the_network() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine_with(
        chain(tool.address),
        Limits::default(),
        Arc::new(SlowProtect),
    )?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x06before\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        !heard_private(&heard),
        "the lookup reached the network's resolver"
    );
    Ok(())
}

/// Android as a table of the tunnel's ports and their apps, which a test changes as Android hands a
/// port to another app.
#[derive(Default)]
struct Owners(std::sync::Mutex<std::collections::HashMap<u16, u32>>);

impl Owners {
    /// The app that holds `port` from now on, or none that Android can name.
    fn set(&self, port: u16, uid: Option<u32>) {
        let mut owners = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match uid {
            Some(uid) => owners.insert(port, uid),
            None => owners.remove(&port),
        };
    }
}

impl Platform for Owners {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&local.port())
            .copied()
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// A server that notes what it hears, and from where.
async fn listening() -> Result<(SocketAddr, Heard), Box<dyn std::error::Error>> {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        while let Ok((n, from)) = server.recv_from(&mut buffer).await {
            noted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((from, buffer[..n].to_vec()));
        }
    });
    Ok((at, heard))
}

/// The ports `payload` reached the server from.
fn heard_from(heard: &Heard, payload: &[u8]) -> Vec<SocketAddr> {
    heard_so_far(heard)
        .into_iter()
        .filter(|(_, said)| said == payload)
        .map(|(from, _)| from)
        .collect()
}

/// A short silence before Android is asked again, so that the tests take little time.
fn quick_reask() -> Limits {
    Limits {
        udp_reask: Duration::from_millis(100),
        ..Limits::default()
    }
}

/// A direct app's port, which Android hands to a chained app after a silence, to the same destination:
/// the chained app's datagram goes through the tool, not out of the direct app's mapping (second review
/// of unit 9, finding 3).
#[tokio::test(flavor = "current_thread")]
async fn a_port_handed_to_a_chained_app_leaves_through_the_tool() -> Outcome {
    const PORT: u16 = 50_000;
    let (at, heard) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    send(&tunnel, app(PORT), at, b"direct app").await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    owners.set(PORT, Some(CHAINED));
    send(&tunnel, app(PORT), at, b"chained app").await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let from = heard_from(&heard, b"chained app");
    assert_eq!(from.len(), 1, "heard {from:?}");
    assert!(
        tool.relays().contains(&from[0]),
        "the chained app's datagram left directly, from {}",
        from[0]
    );
    Ok(())
}

/// An app that sends without a pause is asked about again thirty silences after Android last named it:
/// a port handed over without a pause reaches the tool in time, not never.
#[tokio::test(flavor = "current_thread")]
async fn a_port_handed_over_without_a_pause_is_noticed_in_time() -> Outcome {
    const PORT: u16 = 50_001;
    // A server that answers the first datagram only, and notes everything.
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let mut answered = false;
        while let Ok((n, from)) = server.recv_from(&mut buffer).await {
            if !answered {
                answered = true;
                let _ = server.send_to(&buffer[..n], from).await;
            }
            noted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((from, buffer[..n].to_vec()));
        }
    });
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    // The direct app's mapping is open once its answer comes; the port is the chained app's at once.
    send(&tunnel, app(PORT), at, b"direct app").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    owners.set(PORT, Some(CHAINED));
    // Every 10 ms, never silent for the 100 ms that asks again, for longer than thirty of them.
    for _ in 0..400 {
        send(&tunnel, app(PORT), at, b"chained app").await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let from = heard_from(&heard, b"chained app");
    assert!(
        from.iter().any(|from| tool.relays().contains(from)),
        "none of {} datagrams reached the tool",
        from.len()
    );
    Ok(())
}

/// While a chain is on, an app socket whose app Android cannot name goes nowhere, even when Android
/// named it before: the port may be another app's now (second review of unit 9, finding 3).
#[tokio::test(flavor = "current_thread")]
async fn an_app_android_cannot_name_goes_nowhere_while_a_chain_is_on() -> Outcome {
    const PORT: u16 = 50_002;
    let (first, second) = (udp_echo().await?, udp_echo().await?);
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (_engine, tunnel) = engine_with(chain(tool.address), Limits::default(), owners.clone())?;
    send(&tunnel, app(PORT), first, b"named").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    owners.set(PORT, None);
    send(&tunnel, app(PORT), second, b"unnamed").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error, no echo");
    Ok(())
}

/// One name the tool resolves to one address, asked on two ports: once its stand-in is bound on the
/// first, the answer on the second is the same name's, and binds it there too (second review of unit
/// 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn one_name_on_two_ports_is_answered_on_both() -> Outcome {
    let (one, two) = (udp_echo().await?, udp_echo().await?);
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), one.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = stand_in(&tunnel, b"\x04echo\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((at, one.port())), b"first port").await?;
    echoed(&tunnel, SocketAddr::from((at, two.port())), b"second port").await?;
    echoed(
        &tunnel,
        SocketAddr::from((at, two.port())),
        b"second port again",
    )
    .await?;
    assert_eq!(engine.counters()[UDP_UNMATCHED], 0);
    Ok(())
}

/// Two names the tool resolves to one address: the first bound on one port, the second waiting on
/// another. An answer from that address on the second port could be either name's: it is dropped and
/// counted, not shown from the first name's stand-in.
#[tokio::test(flavor = "current_thread")]
async fn another_port_of_a_bound_address_is_not_given_to_its_name_while_another_waits() -> Outcome {
    let (one, two) = (udp_echo().await?, udp_echo().await?);
    let mut settings = Settings::default();
    settings.names.insert("a.test".into(), one.ip());
    settings.names.insert("b.test".into(), one.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    let b = stand_in(&tunnel, b"\x01b\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((a, one.port())), b"to a").await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((b, two.port())),
        b"to b",
    )
    .await?;
    assert!(silent(&tunnel).await, "b's answer reached the app");
    assert_eq!(engine.counters()[UDP_UNMATCHED], 1);
    Ok(())
}

/// Two names the tool resolves to one address, the first bound on one port, both then asked on a second
/// port: an answer there could be either name's, even the bound one's, so it is dropped and counted.
#[tokio::test(flavor = "current_thread")]
async fn a_bound_name_does_not_take_a_port_another_name_also_waits_on() -> Outcome {
    let one = udp_echo().await?;
    let second = UdpSocket::bind((one.ip(), 0)).await?;
    let two = second.local_addr()?;
    // It answers both datagrams once both came, so that both stand-ins wait when the answers come.
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let mut asked = Vec::new();
        while asked.len() < 2 {
            match second.recv_from(&mut buffer).await {
                Ok((n, relay)) => asked.push((buffer[..n].to_vec(), relay)),
                Err(_) => return,
            }
        }
        for (said, relay) in asked {
            let _ = second.send_to(&said, relay).await;
        }
    });
    let mut settings = Settings::default();
    settings.names.insert("a.test".into(), one.ip());
    settings.names.insert("b.test".into(), one.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    let b = stand_in(&tunnel, b"\x01b\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((a, one.port())), b"to a").await?;
    for (to, said) in [(a, &b"a again"[..]), (b, b"to b")] {
        send(
            &tunnel,
            app(CHAINED_PORT),
            SocketAddr::from((to, two.port())),
            said,
        )
        .await?;
    }
    assert!(
        silent(&tunnel).await,
        "an answer reached the app under a name"
    );
    assert_eq!(engine.counters()[UDP_UNMATCHED], 2);
    Ok(())
}

/// A name bound on one port, then asked on port 53 of the same address: there it is bound only by an
/// answer to the app's own query, not by anything else that comes from that port.
#[tokio::test(flavor = "current_thread")]
async fn a_bound_name_on_port_53_takes_only_an_answer_to_its_query() -> Outcome {
    let one = udp_echo().await?;
    let resolver = UdpSocket::bind((one.ip(), 0)).await?;
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), one.ip());
    // The relay reaches port 53 of the name's address here, and names it as port 53.
    settings
        .remap
        .insert(SocketAddr::new(one.ip(), 53), resolver.local_addr()?);
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        if let Ok((n, relay)) = resolver.recv_from(&mut buffer).await {
            let query = buffer[..n].to_vec();
            let _ = resolver.send_to(&dns_response(&query, 0x9999), relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = resolver.send_to(&dns_response(&query, 0x5152), relay).await;
        }
    });
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = stand_in(&tunnel, b"\x04echo\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((at, one.port())), b"first port").await?;
    let asked = query(b"\x07example\x03com\x00", 16);
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((at, 53)),
        &asked,
    )
    .await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(
        answer,
        (SocketAddr::from((at, 53)), dns_response(&asked, 0x5152))
    );
    assert_eq!(engine.counters()[UDP_UNMATCHED], 1);
    Ok(())
}

/// A DNS response under the ID `id` that names `address` `name` (in DNS's form) for 300 s.
fn named_response(id: u16, name: &[u8], address: [u8; 4]) -> Vec<u8> {
    let mut response = id.to_be_bytes().to_vec();
    response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(name);
    response.extend_from_slice(&[0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
    response.extend_from_slice(&address);
    response
}

/// Port 53 of an address a stand-in was bound to, which the app never asked anything, sends a DNS
/// response: it comes in as another port of that address, but Watch learns no name from it (second
/// review of unit 9, finding 4). The answer to a query the app then sends it does name; another unasked
/// response after it, once the app has sent there, still does not (fifth review, finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_flow_that_came_in_from_port_53_teaches_no_names() -> Outcome {
    let named = UdpSocket::bind("127.0.0.1:0").await?;
    let port = named.local_addr()?.port();
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let (elsewhere, also_elsewhere) = (udp_echo().await?, udp_echo().await?);
    let still_elsewhere = udp_echo().await?;
    let mut settings = Settings::default();
    settings
        .names
        .insert("a.test".into(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    // The relay reaches port 53 of the name's address here, and names it as port 53; and the address
    // the forged answer names, here too, so that nothing leaves this computer.
    settings.remap.insert(
        SocketAddr::from(([127, 0, 0, 1], 53)),
        resolver.local_addr()?,
    );
    let forged = SocketAddr::from(([192, 0, 2, 77], 9));
    let answered = SocketAddr::from(([192, 0, 2, 88], 9));
    let later = SocketAddr::from(([192, 0, 2, 99], 9));
    settings.remap.insert(forged, elsewhere);
    settings.remap.insert(answered, also_elsewhere);
    settings.remap.insert(later, still_elsewhere);
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        if let Ok((n, relay)) = named.recv_from(&mut buffer).await {
            let _ = named.send_to(&buffer[..n], relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let unasked = named_response(0x1234, b"\x04evil\x04test\x00", [192, 0, 2, 77]);
            // Twice: the first opens the flow that came in, the second is an answer on it.
            for _ in 0..2 {
                let _ = resolver.send_to(&unasked, relay).await;
            }
        }
        if let Ok((_, relay)) = resolver.recv_from(&mut buffer).await {
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            let asked = named_response(id, b"\x04good\x04test\x00", [192, 0, 2, 88]);
            let _ = resolver.send_to(&asked, relay).await;
            let unasked = named_response(id ^ 1, b"\x04late\x04test\x00", [192, 0, 2, 99]);
            let _ = resolver.send_to(&unasked, relay).await;
        }
    });
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((at, port)), b"hello").await?;
    let port_53 = SocketAddr::from((at, 53));
    for _ in 0..2 {
        let (from, _) = receive(&tunnel).await?.ok_or("a datagram")?;
        assert_eq!(from, port_53, "came in from port 53");
    }
    send(
        &tunnel,
        app(CHAINED_PORT),
        port_53,
        &query(b"\x04good\x04test\x00", 1),
    )
    .await?;
    for _ in 0..2 {
        let (from, _) = receive(&tunnel).await?.ok_or("an answer")?;
        assert_eq!(from, port_53);
    }
    echoed(&tunnel, forged, b"to the address it named").await?;
    echoed(&tunnel, answered, b"to the address it was asked for").await?;
    echoed(&tunnel, later, b"to the address named after").await?;
    let learned: Vec<_> = engine
        .flows()
        .into_iter()
        .filter(|flow| [forged, answered, later].contains(&flow.destination))
        .map(|flow| flow.name)
        .collect();
    assert_eq!(learned, [None, Some("good.test".into()), None]);
    Ok(())
}

/// A direct app's mapping, then a chain that takes the app: what its server sends afterwards no longer
/// comes in on the direct path (the second review of unit 9's M12).
#[tokio::test(flavor = "current_thread")]
async fn nothing_comes_in_on_a_direct_mapping_once_the_chain_takes_its_app() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let (go, later) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, mapped)) = server.recv_from(&mut buffer).await {
            let _ = server.send_to(&buffer[..n], mapped).await;
            if later.await.is_ok() {
                let _ = server.send_to(b"late", mapped).await;
            }
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(DIRECT_PORT), at, b"direct").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    go.send(()).map_err(|()| "the server is gone")?;
    assert!(
        silent(&tunnel).await,
        "an answer came in on the direct path"
    );
    Ok(())
}

/// A server that answers each datagram with the port it came from, in two bytes, as a STUN server
/// tells a client its mapped port.
async fn port_reporter() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let at = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((_, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&from.port().to_be_bytes(), from).await;
        }
    });
    Ok(at)
}

/// A mapping ends when Android hands its port to another app: the new app's first new destination
/// opens a mapping of its own, from another port (ADR 0044, decision 1; the second review's M19).
#[tokio::test(flavor = "current_thread")]
async fn a_mapping_ends_when_its_port_is_another_apps() -> Outcome {
    const PORT: u16 = 50_003;
    const ANOTHER: u32 = 10_500;
    let (first, second) = (port_reporter().await?, port_reporter().await?);
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), Limits::default(), owners.clone())?;
    let mut seen = Vec::new();
    for (server, uid) in [(first, DIRECT), (second, ANOTHER)] {
        owners.set(PORT, Some(uid));
        send(&tunnel, app(PORT), server, b"which port?").await?;
        let (_, answer) = receive(&tunnel).await?.ok_or("a datagram")?;
        seen.push(u16::from_be_bytes([answer[0], answer[1]]));
    }
    assert_ne!(
        seen[0], seen[1],
        "the other app left from the first app's port"
    );
    assert_eq!(engine.counters()[UDP_MAPPINGS], 2);
    Ok(())
}

/// A relay that names an answer by a name the app never asked for: it is dropped and counted, not shown
/// from another name's stand-in (the second review of unit 9's M21).
#[tokio::test(flavor = "current_thread")]
async fn an_answer_named_by_a_name_nobody_asked_for_is_dropped() -> Outcome {
    let echo = udp_echo().await?;
    let mut settings = Settings {
        answer_name: Some("other.test".into()),
        ..Settings::default()
    };
    settings.names.insert("echo.test".into(), echo.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        echo.port(),
    ));
    send(&tunnel, app(CHAINED_PORT), at, b"hello").await?;
    assert!(
        silent(&tunnel).await,
        "an answer under another name reached the app"
    );
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// A direct app's lookup still waits for its answer when Android hands its port to a chained app: after
/// a silence, the chained app's lookup from that port asks Android again, and goes through the tool,
/// not to the network's resolver (third review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_on_a_port_handed_to_a_chained_app_stays_off_the_network() -> Outcome {
    const PORT: u16 = 50_100;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x06before\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    owners.set(PORT, Some(CHAINED));
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    let (from, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(from, dns);
    let read = dns::response(&answer).ok_or("a response")?;
    assert!(
        matches!(read.addresses[..], [(IpAddr::V4(_), 0)]),
        "not Watch's stand-in: {:?}",
        read.addresses
    );
    assert!(
        !heard_private(&heard),
        "the lookup reached the network's resolver"
    );
    Ok(())
}

/// A chained app's flow of lookups still owes an answer, from a resolver through the tool that takes its
/// time, when Android hands its port to the tool itself: after a silence, the tool's lookup asks Android
/// again and goes to the network's resolver, not answered through the chain under the chained app (third
/// review of unit 9, finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_on_a_port_handed_from_a_chained_app_leaves_its_way() -> Outcome {
    const PORT: u16 = 50_101;
    // The resolver the tool reaches for a chained app's other questions holds them unanswered.
    let slow = TcpListener::bind("127.0.0.1:0").await?;
    let mut settings = Settings::default();
    settings
        .remap
        .insert(SocketAddr::from(([9, 9, 9, 10], 53)), slow.local_addr()?);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((connection, _)) = slow.accept().await {
            held.push(connection);
        }
    });
    let tool = proxy(settings).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(CHAINED));
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x07chained\x04test\x00", 16),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    owners.set(PORT, Some(TOOL));
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    assert!(
        silent(&tunnel).await,
        "the tool's lookup was answered through the chain"
    );
    assert!(
        heard_private(&heard),
        "the tool's lookup did not reach the resolver"
    );
    Ok(())
}

/// A chained app's flow of lookups ends once its last lookup has its answer, as a direct one does: the
/// next lookup from that port, at once and from the tool now, asks Android again (third review of unit 9,
/// finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_chained_apps_flow_of_lookups_ends_with_its_last_answer() -> Outcome {
    const PORT: u16 = 50_102;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(CHAINED));
    let (engine, tunnel) = engine_with(chain(tool.address), Limits::default(), owners.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x07chained\x04test\x00", 1),
    )
    .await?;
    receive(&tunnel).await?.ok_or("the chained app's answer")?;
    owners.set(PORT, Some(TOOL));
    send(
        &tunnel,
        app(PORT),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    assert!(
        silent(&tunnel).await,
        "the tool's lookup was answered through the chain"
    );
    assert!(
        heard_private(&heard),
        "the tool's lookup did not reach the resolver"
    );
    Ok(())
}

/// A direct app's two lookups still wait when the chain takes it, and its next lookup opens a flow on
/// the new route: the old flow still hands the app both answers it owes (third review of unit 9,
/// finding 4).
#[tokio::test(flavor = "current_thread")]
async fn a_flow_of_lookups_that_gave_way_hands_over_every_answer_it_owes() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let port = resolver.local_addr()?.port();
    engine.network_changed(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), false);
    let dns = SocketAddr::from((Addresses::COMMON.dns4, port));
    let (go, later) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let mut asked = Vec::new();
        while asked.len() < 2 {
            match resolver.recv_from(&mut buffer).await {
                Ok((n, from)) => asked.push((buffer[..n].to_vec(), from)),
                Err(_) => return,
            }
        }
        if later.await.is_ok() {
            for (query, from) in asked {
                let _ = resolver.send_to(&dns_response(&query, 0x5152), from).await;
            }
        }
    });
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03one\x04test\x00", 16),
    )
    .await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03two\x04test\x00", 16),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut both = chain(tool.address);
    both.apps = Some(HashSet::from([CHAINED, DIRECT]));
    engine.chain(Some(both));
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x05three\x04test\x00", 1),
    )
    .await?;
    receive(&tunnel).await?.ok_or("the chained answer")?;
    go.send(()).map_err(|()| "the resolver is gone")?;
    let seen = everything(&tunnel).await;
    assert_eq!(seen.len(), 2, "answers to the two earlier lookups");
    Ok(())
}

/// The UIDs of the UDP flows the engine kept to `destination`, oldest first.
fn uids_to(engine: &Engine, destination: SocketAddr) -> Vec<Option<u32>> {
    engine
        .flows()
        .into_iter()
        .filter(|flow| flow.protocol == packet::UDP && flow.destination == destination)
        .map(|flow| flow.uid)
        .collect()
}

/// Without a chain too, a port Android hands to another app, after a silence, to a destination the old
/// app sent to: the new app's datagram asks Android again and leaves through a mapping of its own,
/// logged under it (third review of unit 9, finding 5; ADR 0044, decision 1).
#[tokio::test(flavor = "current_thread")]
async fn a_port_handed_to_another_app_is_logged_under_it_without_a_chain() -> Outcome {
    const PORT: u16 = 50_104;
    const ANOTHER: u32 = 10_500;
    let server = port_reporter().await?;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    engine.chain(None);
    let mut seen = Vec::new();
    for (uid, said) in [(DIRECT, &b"first app"[..]), (ANOTHER, b"second app")] {
        owners.set(PORT, Some(uid));
        send(&tunnel, app(PORT), server, said).await?;
        let (_, answer) = receive(&tunnel).await?.ok_or("a datagram")?;
        seen.push(u16::from_be_bytes([answer[0], answer[1]]));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_ne!(
        seen[0], seen[1],
        "the second app left from the first app's port"
    );
    assert_eq!(uids_to(&engine, server), [Some(DIRECT), Some(ANOTHER)]);
    Ok(())
}

/// An app socket whose app Android cannot name is logged as unknown, even when Android named it before,
/// never under the app it had (third review of unit 9, finding 5). Without a chain, it still reaches its
/// destination.
#[tokio::test(flavor = "current_thread")]
async fn an_app_android_cannot_name_is_logged_as_unknown() -> Outcome {
    const PORT: u16 = 50_105;
    let (first, second) = (udp_echo().await?, udp_echo().await?);
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), Limits::default(), owners.clone())?;
    engine.chain(None);
    send(&tunnel, app(PORT), first, b"named").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    owners.set(PORT, None);
    send(&tunnel, app(PORT), second, b"unnamed").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (second, b"unnamed".to_vec()));
    assert_eq!(uids_to(&engine, second), [None]);
    Ok(())
}

/// Under a relay that gives back the name, a stand-in's answer by name stops it waiting: a stranger that
/// later reaches the relay from its port, at an address the app never saw, does not take it (third review
/// of unit 9, finding 3).
#[tokio::test(flavor = "current_thread")]
async fn a_stand_in_answered_by_name_waits_no_more() -> Outcome {
    let echo = udp_echo().await?;
    let stranger = UdpSocket::bind(("127.0.0.2", echo.port())).await?;
    let mut settings = Settings {
        headers: Headers::Name,
        ..Settings::default()
    };
    settings.names.insert("echo.test".into(), echo.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        echo.port(),
    ));
    echoed(&tunnel, at, b"by name").await?;
    let relay = *tool.relays().first().ok_or("a relay")?;
    stranger.send_to(b"from a stranger", relay).await?;
    assert!(silent(&tunnel).await, "the stranger took the stand-in");
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// A stand-in on port 53 that the app sends ten queries before the first answer comes: the answer to
/// the first of them still binds it (third review of unit 9, finding 6).
#[tokio::test(flavor = "current_thread")]
async fn a_burst_of_lookups_before_the_first_answer_still_binds() -> Outcome {
    const BURST: usize = 10;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let named = SocketAddr::from(([192, 0, 2, 53], 53));
    let mut settings = Settings::default();
    settings.names.insert("dns.test".into(), named.ip());
    settings.remap.insert(named, resolver.local_addr()?);
    // It answers the first query, once all of them came.
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let mut first = None;
        for _ in 0..BURST {
            match resolver.recv_from(&mut buffer).await {
                Ok((n, relay)) => {
                    first.get_or_insert((buffer[..n].to_vec(), relay));
                }
                Err(_) => return,
            }
        }
        if let Some((query, relay)) = first {
            let _ = resolver.send_to(&dns_response(&query, 0x5152), relay).await;
        }
    });
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((stand_in(&tunnel, b"\x03dns\x04test\x00").await?, 53));
    let mut queries = Vec::new();
    for label in b'a'..b'a' + 10 {
        let mut name = vec![1, label];
        name.extend_from_slice(b"\x04test\x00");
        queries.push(query(&name, 1));
    }
    for asked in &queries {
        send(&tunnel, app(CHAINED_PORT), at, asked).await?;
    }
    let answer = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(answer, (at, dns_response(&queries[0], 0x5152)));
    Ok(())
}

/// Once the chain lets a chained app go, what its server sends afterwards no longer comes in through the
/// old tool's relay: the tool's counterpart of the direct path's guard (the third review's r4).
#[tokio::test(flavor = "current_thread")]
async fn nothing_comes_in_through_the_old_relay_once_the_chain_lets_the_app_go() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let (go, later) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, relay)) = server.recv_from(&mut buffer).await {
            let _ = server.send_to(&buffer[..n], relay).await;
            if later.await.is_ok() {
                let _ = server.send_to(b"late", relay).await;
            }
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(CHAINED_PORT), at, b"chained").await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    engine.chain(None);
    go.send(()).map_err(|()| "the server is gone")?;
    assert!(
        silent(&tunnel).await,
        "an answer came in through the old relay"
    );
    Ok(())
}

/// One name the tool reached at two addresses: the stand-in bound on one port to the first, on another
/// to the second. The first address's answer on the second port could be the name's at either address:
/// it is dropped and counted, not given to the stand-in bound there to the other (the guard in
/// `Mapping::come_in`).
#[tokio::test(flavor = "current_thread")]
async fn an_answer_on_a_port_bound_to_another_address_is_dropped() -> Outcome {
    let first = udp_echo().await?;
    // The second port: asked at the first address, answered from the second.
    let asked = UdpSocket::bind((first.ip(), 0)).await?;
    let port = asked.local_addr()?.port();
    let answering = UdpSocket::bind(("127.0.0.2", port)).await?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((n, relay)) = asked.recv_from(&mut buffer).await {
            let _ = answering.send_to(&buffer[..n], relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = asked.send_to(b"from the first address", relay).await;
        }
    });
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), first.ip());
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = stand_in(&tunnel, b"\x04echo\x04test\x00").await?;
    echoed(&tunnel, SocketAddr::from((at, first.port())), b"first port").await?;
    echoed(&tunnel, SocketAddr::from((at, port)), b"second port").await?;
    assert!(
        silent(&tunnel).await,
        "an answer reached the app from the other address's port"
    );
    assert_eq!(engine.counters()[UDP_UNMATCHED], 1);
    Ok(())
}

/// A mapping's flows that came in, silent for longer than `udp_idle` while the mapping lives on, end,
/// and make room under the cap for others, also those the app answered (sixth review of unit 9, finding
/// 3).
#[tokio::test(flavor = "current_thread")]
async fn flows_that_came_in_and_ended_make_room_for_others() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let mut ports = Vec::new();
    for _ in 0..70 {
        ports.push(UdpSocket::bind("127.0.0.1:0").await?);
    }
    let (go, later) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((_, mapped)) = server.recv_from(&mut buffer).await {
            for port in &ports[..64] {
                let _ = port.send_to(b"came in", mapped).await;
            }
            if later.await.is_ok() {
                for port in &ports[64..] {
                    let _ = port.send_to(b"came in later", mapped).await;
                }
            }
        }
    });
    let tool = proxy(Settings::default()).await?;
    let limits = Limits {
        udp_idle: Duration::from_secs(1),
        ..Limits::default()
    };
    let (engine, tunnel) = engine_with(chain(tool.address), limits, Arc::new(ByPort))?;
    send(&tunnel, app(DIRECT_PORT), at, b"hello").await?;
    let seen = everything(&tunnel).await;
    assert_eq!(seen.len(), 64);
    for (from, _) in &seen {
        send(&tunnel, app(DIRECT_PORT), *from, b"an answer").await?;
    }
    // The app keeps its mapping alive while the flows that came in fall silent and end.
    for _ in 0..8 {
        send(&tunnel, app(DIRECT_PORT), at, b"still here").await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    go.send(()).map_err(|()| "the server is gone")?;
    assert_eq!(everything(&tunnel).await.len(), 6, "ports let in again");
    assert_eq!(engine.counters()[UDP_CAME_IN_CAPPED], 0);
    Ok(())
}

/// A stand-in that ended, silent, while its mapping lived on, and that the app asks again: its address is
/// forgotten with it, so the answer binds it anew.
#[tokio::test(flavor = "current_thread")]
async fn a_stand_in_that_ended_is_bound_anew() -> Outcome {
    let named = udp_echo().await?;
    // Another destination at another address: one the app sent to itself would take the stand-in's
    // answers as its own other port's.
    let elsewhere = UdpSocket::bind("127.0.0.2:0").await?;
    let other = elsewhere.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        while let Ok((n, from)) = elsewhere.recv_from(&mut buffer).await {
            let _ = elsewhere.send_to(&buffer[..n], from).await;
        }
    });
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), named.ip());
    let tool = proxy(settings).await?;
    let limits = Limits {
        udp_idle: Duration::from_secs(1),
        ..Limits::default()
    };
    let (_engine, tunnel) = engine_with(chain(tool.address), limits, Arc::new(ByPort))?;
    let at = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        named.port(),
    ));
    echoed(&tunnel, at, b"by name").await?;
    for _ in 0..8 {
        echoed(&tunnel, other, b"the mapping lives on").await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    echoed(&tunnel, at, b"by name again").await?;
    Ok(())
}

/// A mapping that the chain, set again, sends another way ends at once, with its task: the old tool's
/// relay is let go, not kept until the mapping falls silent.
#[tokio::test(flavor = "current_thread")]
async fn a_mapping_ended_by_a_new_chain_lets_the_old_relay_go() -> Outcome {
    let echo = udp_echo().await?;
    let (first, second) = (
        proxy(Settings::default()).await?,
        proxy(Settings::default()).await?,
    );
    let (engine, tunnel) = engine(chain(first.address))?;
    echoed(&tunnel, echo, b"one").await?;
    assert_eq!(first.open_relays(), 1);
    engine.chain(Some(chain(second.address)));
    echoed(&tunnel, echo, b"two").await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(first.open_relays(), 0, "the old tool's relay is still open");
    Ok(())
}

/// The chain set again with other credentials for the same tool: a mapping through it ends, and the
/// next datagram asks for a relay with the new ones, which this tool refuses.
#[tokio::test(flavor = "current_thread")]
async fn new_credentials_for_the_tool_move_a_mapping() -> Outcome {
    let echo = udp_echo().await?;
    let settings = Settings {
        password: Some((b"watch".to_vec(), b"secret".to_vec())),
        ..Settings::default()
    };
    let tool = proxy(settings).await?;
    let with = |password: &[u8]| {
        let mut chained = chain(tool.address);
        chained.credentials = datapavan_net::socks5::Credentials::new(b"watch", password);
        chained
    };
    let (engine, tunnel) = engine(with(b"secret"))?;
    echoed(&tunnel, echo, b"right password").await?;
    engine.chain(Some(with(b"wrong")));
    send(&tunnel, app(CHAINED_PORT), echo, b"wrong password").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error, no echo");
    Ok(())
}

/// A tool whose relay gives a stand-in's answer from an address that happens to be the stand-in itself,
/// as a tool's own fake address from the same range can: the stand-in is bound to it, and waits no
/// more, so a stranger on its port does not take it.
#[tokio::test(flavor = "current_thread")]
async fn a_stand_in_answered_from_its_own_address_waits_no_more() -> Outcome {
    let echo = udp_echo().await?;
    let stranger = UdpSocket::bind(("127.0.0.2", echo.port())).await?;
    // The first stand-in an engine gives (the chain's lookup test checks it).
    let own = SocketAddr::from(([198, 18, 0, 1], echo.port()));
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), echo.ip());
    settings.remap.insert(own, echo);
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((
        stand_in(&tunnel, b"\x04echo\x04test\x00").await?,
        echo.port(),
    ));
    assert_eq!(at, own);
    echoed(&tunnel, at, b"by name").await?;
    let relay = *tool.relays().first().ok_or("a relay")?;
    stranger.send_to(b"from a stranger", relay).await?;
    assert!(silent(&tunnel).await, "the stranger took the stand-in");
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// What a scripted relay heard: the engine's address and each datagram, header and all.
type Script = tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>;

/// A tool whose proxy grants every `UDP ASSOCIATE` one relay, which hands the test what the engine sends
/// it and sends the engine whatever header the test writes: the proxy's address, the relay, and what
/// it heard.
async fn scripted() -> io::Result<(SocketAddr, Arc<UdpSocket>, Script)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy = listener.local_addr()?;
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let at = relay.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                // The greeting, no password, then a request for an IPv4 or IPv6 address.
                let mut head = [0u8; 2];
                if client.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; usize::from(head[1])];
                let _ = client.read_exact(&mut methods).await;
                let _ = client.write_all(&[5, 0]).await;
                let mut request = [0u8; 4];
                let _ = client.read_exact(&mut request).await;
                let rest = match request[3] {
                    1 => 6,
                    4 => 18,
                    _ => return,
                };
                let mut skip = vec![0u8; rest];
                let _ = client.read_exact(&mut skip).await;
                let mut reply = vec![5, 0, 0];
                reply.extend_from_slice(&header_by_address(at)[3..]);
                let _ = client.write_all(&reply).await;
                let mut byte = [0u8; 1];
                while matches!(client.read(&mut byte).await, Ok(n) if n > 0) {}
            });
        }
    });
    let (tell, heard) = tokio::sync::mpsc::unbounded_channel();
    let reader = Arc::clone(&relay);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        while let Ok((n, from)) = reader.recv_from(&mut buffer).await {
            let _ = tell.send((from, buffer[..n].to_vec()));
        }
    });
    Ok((proxy, relay, heard))
}

/// A relay's header naming `name` and `port`.
fn header_by_name(name: &str, port: u16) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 3, u8::try_from(name.len()).unwrap_or(0)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// A relay's header naming the address `from`.
fn header_by_address(from: SocketAddr) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    match from {
        SocketAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    out
}

/// A datagram from the relay: `header`, then `payload`.
fn relayed(header: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    let mut out = header;
    out.extend_from_slice(payload);
    out
}

/// The next datagram the scripted relay heard: the engine's address.
async fn heard_from_engine(script: &mut Script) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let (engine_at, _) = tokio::time::timeout(Duration::from_secs(5), script.recv())
        .await?
        .ok_or("the relay heard nothing")?;
    Ok(engine_at)
}

/// A relay that answers by name gives another port of a stand-in's name: a flow that came in. The app
/// asked it nothing, so it waits for no first answer, and a stranger that later reaches the relay from
/// that port does not take it (fourth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_flow_that_came_in_by_name_is_not_taken_by_a_stranger() -> Outcome {
    let (proxy, relay, mut script) = scripted().await?;
    let (engine, tunnel) = engine(chain(proxy))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((a, 443)),
        b"hello",
    )
    .await?;
    let engine_at = heard_from_engine(&mut script).await?;
    for (port, said) in [(443, &b"by name"[..]), (5_000, b"another port by name")] {
        let answer = relayed(header_by_name("a.test", port), said);
        relay.send_to(&answer, engine_at).await?;
        let got = receive(&tunnel).await?;
        assert_eq!(got, Some((SocketAddr::from((a, port)), said.to_vec())));
    }
    let stranger = SocketAddr::from(([203, 0, 113, 66], 5_000));
    let forged = relayed(header_by_address(stranger), b"from a stranger");
    relay.send_to(&forged, engine_at).await?;
    assert!(
        silent(&tunnel).await,
        "the stranger took the flow that came in"
    );
    assert_eq!(engine.counters()[UDP_FILTERED], 1);
    Ok(())
}

/// A flow that came in by name does not stand beside a stand-in the app did ask on that port: the
/// stand-in alone takes its first answer (fourth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_flow_that_came_in_by_name_does_not_block_an_asked_stand_in() -> Outcome {
    let (proxy, relay, mut script) = scripted().await?;
    let (_engine, tunnel) = engine(chain(proxy))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    let b = stand_in(&tunnel, b"\x01b\x04test\x00").await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((a, 443)),
        b"hello",
    )
    .await?;
    let engine_at = heard_from_engine(&mut script).await?;
    for (port, said) in [(443, &b"a by name"[..]), (3_478, b"a's other port")] {
        let answer = relayed(header_by_name("a.test", port), said);
        relay.send_to(&answer, engine_at).await?;
        receive(&tunnel).await?.ok_or("a datagram")?;
    }
    let to_b = SocketAddr::from((b, 3_478));
    send(&tunnel, app(CHAINED_PORT), to_b, b"to b").await?;
    heard_from_engine(&mut script).await?;
    let b_server = SocketAddr::from(([198, 51, 100, 7], 3_478));
    let answer = relayed(header_by_address(b_server), b"b's answer");
    relay.send_to(&answer, engine_at).await?;
    assert_eq!(
        receive(&tunnel).await?,
        Some((to_b, b"b's answer".to_vec()))
    );
    Ok(())
}

/// Waits until the engine keeps a UDP flow to `destination`: until Android named its app and its way
/// opened.
async fn until_a_flow_to(engine: &Engine, destination: SocketAddr) -> Outcome {
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !engine
        .flows()
        .iter()
        .any(|flow| flow.protocol == packet::UDP && flow.destination == destination)
    {
        if tokio::time::Instant::now() > until {
            return Err(format!("no flow to {destination}").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

/// What [`a_bound_name_beside_a_silent_one`] sets up: the engine, the tunnel, both stand-ins, and the
/// tool and the silent server, which must live as long as the test.
type BesideASilentOne = (
    Engine,
    UnixDatagram,
    (SocketAddr, SocketAddr),
    (common::Proxy, UdpSocket),
);

/// A bound name `a` and a second name `b` on its port whose server never answers; `contest` is
/// `Limits::udp_contest`.
async fn a_bound_name_beside_a_silent_one(
    contest: Duration,
) -> Result<BesideASilentOne, Box<dyn std::error::Error>> {
    let echo = udp_echo().await?;
    let quiet = UdpSocket::bind(("127.0.0.2", echo.port())).await?;
    let mut settings = Settings::default();
    settings.names.insert("a.test".into(), echo.ip());
    settings
        .names
        .insert("b.test".into(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let tool = proxy(settings).await?;
    let limits = Limits {
        udp_contest: contest,
        ..Limits::default()
    };
    let (engine, tunnel) = engine_with(chain(tool.address), limits, Arc::new(ByPort))?;
    let a = SocketAddr::from((stand_in(&tunnel, b"\x01a\x04test\x00").await?, echo.port()));
    let b = SocketAddr::from((stand_in(&tunnel, b"\x01b\x04test\x00").await?, echo.port()));
    echoed(&tunnel, a, b"bound").await?;
    Ok((engine, tunnel, (a, b), (tool, quiet)))
}

/// Sends `a` a datagram every 200 ms, and `b` one too when `retry`, for 4 s: which ticks `a` answered,
/// each with the time from `since` to its answer.
async fn ticks_answered(
    tunnel: &UnixDatagram,
    (a, b): (SocketAddr, SocketAddr),
    (retry, since): (bool, std::time::Instant),
) -> Result<Vec<(u8, Duration)>, Box<dyn std::error::Error>> {
    let mut answered = Vec::new();
    for tick in 0..20u8 {
        if retry {
            send(tunnel, app(CHAINED_PORT), b, b"retry").await?;
        }
        send(tunnel, app(CHAINED_PORT), a, &[tick]).await?;
        let mut buffer = [0u8; 2048];
        let got = tokio::time::timeout(Duration::from_millis(200), tunnel.recv(&mut buffer)).await;
        if matches!(got, Ok(Ok(_))) {
            answered.push((tick, since.elapsed()));
        }
    }
    Ok(answered)
}

/// Whether `answered`, from [`ticks_answered`], shows a cut of `contest` from `since`: no answer in the
/// first tick, nor before `contest` had passed since the app first sent to the second name, which made
/// its contest begin no earlier; some answer after it. Load can only make the first answer later.
fn cut_for(answered: &[(u8, Duration)], contest: Duration) -> Outcome {
    let &(tick, after) = answered
        .first()
        .ok_or("the bound name never got its answers back")?;
    assert!(tick > 0, "an answer came while b contested: {answered:?}");
    assert!(
        after >= contest,
        "the cut lasted only {after:?}: {answered:?}"
    );
    Ok(())
}

/// One datagram to a second name on a bound stand-in's port, never answered: the bound stand-in's
/// answers, which could be the second name's, are dropped while it contests the port, for
/// `Limits::udp_contest`, and then reach the app again (fourth review of unit 9, finding 2). The ticks
/// start once the second name is a flow, so that its contest has surely begun (fifth review, finding 4),
/// and the first answer comes no sooner than the contest's length (sixth review, finding 5).
#[tokio::test(flavor = "current_thread")]
async fn an_unanswered_name_cuts_a_bound_one_only_for_a_while() -> Outcome {
    let contest = Duration::from_secs(2);
    let (engine, tunnel, (a, b), _kept) = a_bound_name_beside_a_silent_one(contest).await?;
    let since = std::time::Instant::now();
    send(&tunnel, app(CHAINED_PORT), b, b"one try").await?;
    until_a_flow_to(&engine, b).await?;
    cut_for(
        &ticks_answered(&tunnel, (a, b), (false, since)).await?,
        contest,
    )?;
    assert!(engine.counters()[UDP_UNMATCHED] >= 1);
    Ok(())
}

/// The same when the app retries the second name at every tick, as a STUN client does: the cut ends all
/// the same, since the contest runs from the app's first datagram to it (the fifth review's experiment).
#[tokio::test(flavor = "current_thread")]
async fn a_retried_unanswered_name_cuts_a_bound_one_only_for_a_while() -> Outcome {
    let contest = Duration::from_secs(2);
    let (engine, tunnel, (a, b), _kept) = a_bound_name_beside_a_silent_one(contest).await?;
    let since = std::time::Instant::now();
    send(&tunnel, app(CHAINED_PORT), b, b"first try").await?;
    until_a_flow_to(&engine, b).await?;
    cut_for(
        &ticks_answered(&tunnel, (a, b), (true, since)).await?,
        contest,
    )
}

/// Android, which names every app socket the direct app's, and counts how often it is asked.
#[derive(Default)]
struct Counting(std::sync::atomic::AtomicUsize);

impl Counting {
    fn asked(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Platform for Counting {
    fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(DIRECT)
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// After a pause, an app socket that sends to five destinations it knows asks Android once, not once
/// for each, and every datagram still reaches its destination (fourth review of unit 9, finding 3).
#[tokio::test(flavor = "current_thread")]
async fn one_pause_asks_android_once() -> Outcome {
    let mut echoes = Vec::new();
    for _ in 0..5 {
        echoes.push(udp_echo().await?);
    }
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(Counting::default());
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    for &echo in &echoes {
        echoed(&tunnel, echo, b"first").await?;
    }
    let before = android.asked();
    tokio::time::sleep(Duration::from_millis(300)).await;
    for &echo in &echoes {
        send(&tunnel, app(CHAINED_PORT), echo, b"after a pause").await?;
    }
    let mut from = Vec::new();
    for _ in 0..5 {
        from.push(receive(&tunnel).await?.ok_or("a datagram")?.0);
    }
    from.sort_unstable();
    echoes.sort_unstable();
    assert_eq!(from, echoes);
    assert_eq!(
        android.asked() - before,
        1,
        "questions to Android for one pause"
    );
    Ok(())
}

/// An app socket that never pauses for `udp_reask` is asked about when it opens, then once each thirty
/// times that, not at every datagram: what it sends keeps it fresh, and so does each answer from Android.
/// The count allows for a pause the test's own load may cause; the engine's own tests hold the rule to
/// its instant.
#[tokio::test(flavor = "current_thread")]
async fn a_mapping_that_never_pauses_is_asked_about_seldom() -> Outcome {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(Counting::default());
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    // Every 20 ms, for longer than thirty times the 100 ms that asks again.
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_millis(3_400) {
        send(&tunnel, app(DIRECT_PORT), echo, b"tick").await?;
        receive(&tunnel).await?.ok_or("a datagram")?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let asked = android.asked();
    assert!((2..=4).contains(&asked), "Android was asked {asked} times");
    Ok(())
}

/// The same for a flow of lookups to the tunnel's DNS address that never pauses: asked about when it
/// opens, and again after thirty times `udp_reask`.
#[tokio::test(flavor = "current_thread")]
async fn a_flow_of_lookups_that_never_pauses_is_asked_about_seldom() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(Counting::default());
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    let (dns, _heard) = deaf_resolver(&engine).await?;
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_millis(3_400) {
        send(
            &tunnel,
            app(DIRECT_PORT),
            dns,
            &query(b"\x04tick\x04test\x00", 1),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let asked = android.asked();
    assert!((2..=4).contains(&asked), "Android was asked {asked} times");
    Ok(())
}

/// A resolver here that answers two lookups as `answer` scripts it, given both queries and where they
/// came from; and the tunnel's DNS address that leads to it.
async fn scripted_resolver<F, Fut>(
    engine: &Engine,
    answer: F,
) -> Result<SocketAddr, Box<dyn std::error::Error>>
where
    F: FnOnce(Arc<UdpSocket>, Vec<(Vec<u8>, SocketAddr)>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let resolver = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let port = resolver.local_addr()?.port();
    engine.network_changed(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), false);
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let mut asked = Vec::new();
        while asked.len() < 2 {
            match resolver.recv_from(&mut buffer).await {
                Ok((n, from)) => asked.push((buffer[..n].to_vec(), from)),
                Err(_) => return,
            }
        }
        answer(resolver, asked).await;
    });
    Ok(SocketAddr::from((Addresses::COMMON.dns4, port)))
}

/// The questions of the answers that reached the app.
fn answered_questions(seen: &[(SocketAddr, Vec<u8>)]) -> Vec<String> {
    seen.iter()
        .filter_map(|(_, answer)| dns::response(answer).map(|read| read.question))
        .collect()
}

/// A flow of lookups owes two answers, and the resolver sends the first twice: the repeat does not
/// count for the second lookup, and the second answer still reaches the app (fourth review of unit 9,
/// finding 4).
#[tokio::test(flavor = "current_thread")]
async fn a_repeated_answer_does_not_end_a_flow_of_lookups() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let dns = scripted_resolver(&engine, |resolver, asked| async move {
        let (first, from) = &asked[0];
        for _ in 0..2 {
            let _ = resolver.send_to(&dns_response(first, 0x5152), *from).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (second, from) = &asked[1];
        let _ = resolver.send_to(&dns_response(second, 0x5152), *from).await;
    })
    .await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03one\x04test\x00", 1),
    )
    .await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03two\x04test\x00", 1),
    )
    .await?;
    let questions = answered_questions(&everything(&tunnel).await);
    assert_eq!(questions, ["one.test", "one.test", "two.test"]);
    Ok(())
}

/// The same when the two lookups ask one question under two IDs: the repeated answer to the first does
/// not count for the second, which is told apart by its ID (fifth review of unit 9, finding 5c).
#[tokio::test(flavor = "current_thread")]
async fn a_repeated_answer_does_not_count_for_another_id_of_its_question() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let dns = scripted_resolver(&engine, |resolver, asked| async move {
        let own_id = |query: &[u8]| u16::from_be_bytes([query[0], query[1]]);
        let (first, from) = &asked[0];
        for _ in 0..2 {
            let _ = resolver
                .send_to(&dns_response(first, own_id(first)), *from)
                .await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (second, from) = &asked[1];
        let _ = resolver
            .send_to(&dns_response(second, own_id(second)), *from)
            .await;
    })
    .await?;
    let first = query(b"\x03one\x04test\x00", 1);
    let mut second = first.clone();
    second[..2].copy_from_slice(&0x6162u16.to_be_bytes());
    for lookup in [&first, &second] {
        send(&tunnel, app(DIRECT_PORT), dns, lookup).await?;
    }
    let ids: Vec<u16> = everything(&tunnel)
        .await
        .iter()
        .map(|(_, answer)| u16::from_be_bytes([answer[0], answer[1]]))
        .collect();
    assert_eq!(ids, [0x5152, 0x5152, 0x6162]);
    Ok(())
}

/// A lookup sent on a flow that is already open waits for its answer too: the flow does not end with
/// the first lookup's.
#[tokio::test(flavor = "current_thread")]
async fn a_later_lookup_on_an_open_flow_keeps_it_open() -> Outcome {
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    let dns = scripted_resolver(&engine, |resolver, asked| async move {
        for (query, from) in &asked {
            let _ = resolver.send_to(&dns_response(query, 0x5152), *from).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03one\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(
        &tunnel,
        app(DIRECT_PORT),
        dns,
        &query(b"\x03two\x04test\x00", 1),
    )
    .await?;
    let questions = answered_questions(&everything(&tunnel).await);
    assert_eq!(questions, ["one.test", "two.test"]);
    Ok(())
}

/// A stand-in on port 53 keeps the last 64 queries the app sent it while it waits: of 70, the answer to
/// the first, given up, does not bind it; the answer to the eleventh, among the last 64, does. A cap
/// lower than 60, or none, fails this (the fourth review's finding 6).
#[tokio::test(flavor = "current_thread")]
async fn a_stand_in_on_port_53_keeps_its_last_64_queries() -> Outcome {
    const QUERIES: usize = 70;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let named = SocketAddr::from(([192, 0, 2, 53], 53));
    let mut settings = Settings::default();
    settings.names.insert("dns.test".into(), named.ip());
    settings.remap.insert(named, resolver.local_addr()?);
    // It answers the first query, then the eleventh, once all of them came.
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        let mut asked = Vec::new();
        while asked.len() < QUERIES {
            match resolver.recv_from(&mut buffer).await {
                Ok((n, relay)) => asked.push((buffer[..n].to_vec(), relay)),
                Err(_) => return,
            }
        }
        for at in [0, 10] {
            let (query, relay) = &asked[at];
            let _ = resolver.send_to(&dns_response(query, 0x5152), *relay).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;
    let at = SocketAddr::from((stand_in(&tunnel, b"\x03dns\x04test\x00").await?, 53));
    let queries: Vec<_> = (0..QUERIES)
        .map(|i| {
            let label = format!("q{i}");
            let mut name = vec![u8::try_from(label.len()).unwrap_or(0)];
            name.extend_from_slice(label.as_bytes());
            name.extend_from_slice(b"\x04test\x00");
            query(&name, 1)
        })
        .collect();
    // The first opens the mapping; the others follow on it, more than wait for a new way.
    send(&tunnel, app(CHAINED_PORT), at, &queries[0]).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    for asked in &queries[1..] {
        send(&tunnel, app(CHAINED_PORT), at, asked).await?;
    }
    let seen = everything(&tunnel).await;
    assert_eq!(seen, [(at, dns_response(&queries[10], 0x5152))]);
    Ok(())
}

/// Android, slow to answer (300 ms), which names the app that held the port when the question began,
/// and notes when each question began.
#[derive(Default)]
struct SlowOwners(
    std::sync::Mutex<std::collections::HashMap<u16, u32>>,
    std::sync::Mutex<Vec<std::time::Instant>>,
);

impl SlowOwners {
    fn set(&self, port: u16, uid: u32) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(port, uid);
    }

    /// When the `nth` question began (from 1), once it has: the engine asked it no later.
    async fn asked(&self, nth: usize) -> Result<tokio::time::Instant, Box<dyn std::error::Error>> {
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let asked = self
                .1
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(nth - 1)
                .copied();
            if let Some(asked) = asked {
                return Ok(tokio::time::Instant::from_std(asked));
            }
            if tokio::time::Instant::now() > until {
                return Err(format!("Android was not asked {nth} times").into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

impl Platform for SlowOwners {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        self.1
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(std::time::Instant::now());
        let uid = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&local.port())
            .copied();
        std::thread::sleep(Duration::from_millis(300));
        uid
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// A direct app's datagram after a pause asks Android again, slowly, and Android hands the port to a
/// chained app meanwhile. Returns the engine, the tunnel, the tool, and the port.
async fn handed_over_while_asked(
    port: u16,
) -> Result<(Engine, UnixDatagram, common::Proxy), Box<dyn std::error::Error>> {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(port, DIRECT);
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    send(&tunnel, app(port), echo, b"direct app").await?;
    receive(&tunnel).await?.ok_or("an echo")?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    send(&tunnel, app(port), echo, b"direct app again").await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    android.set(port, CHAINED);
    Ok((engine, tunnel, tool))
}

/// A chained app's datagram to a new destination, sent while a question that began for the port's
/// previous, direct app is still out, asks Android on its own and goes through the tool: it does not
/// take the old app's answer (fifth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_new_destination_does_not_join_the_old_apps_question() -> Outcome {
    let (at, heard) = listening().await?;
    let (_engine, tunnel, tool) = handed_over_while_asked(50_200).await?;
    send(&tunnel, app(50_200), at, b"chained app").await?;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let from = heard_from(&heard, b"chained app");
    assert_eq!(from.len(), 1, "heard {from:?}");
    assert!(
        tool.relays().contains(&from[0]),
        "the chained app's datagram left directly, from {}",
        from[0]
    );
    Ok(())
}

/// The same for a lookup to the tunnel's DNS address: the chained app's lookup does not take the old
/// app's answer, and stays off the network's resolver (fifth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_does_not_join_the_old_apps_question() -> Outcome {
    let (engine, tunnel, _tool) = handed_over_while_asked(50_201).await?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    send(
        &tunnel,
        app(50_201),
        dns,
        &query(b"\x07private\x04test\x00", 1),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert!(
        !heard_private(&heard),
        "the lookup reached the network's resolver"
    );
    Ok(())
}

/// Nor does a stream the chained app keeps sending to its new destination leave directly, for as long as
/// it does not pause (fifth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_new_destinations_stream_never_leaves_directly() -> Outcome {
    let (at, heard) = listening().await?;
    let (_engine, tunnel, tool) = handed_over_while_asked(50_202).await?;
    for _ in 0..40 {
        send(&tunnel, app(50_202), at, b"chained").await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let from = heard_from(&heard, b"chained");
    let relays = tool.relays();
    let direct = from.iter().filter(|from| !relays.contains(from)).count();
    assert!(!from.is_empty(), "nothing reached the destination");
    assert_eq!(direct, 0, "{direct} of {} left directly", from.len());
    Ok(())
}

/// Another port of a bound stand-in's address comes in, shown as the stand-in. The app's reply to it
/// goes to the tool by the stand-in's name, as the stand-in's own datagrams do (fifth review of unit 9,
/// finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_reply_to_a_flow_that_came_in_as_a_stand_in_goes_by_name() -> Outcome {
    let (proxy, relay, mut script) = scripted().await?;
    let (_engine, tunnel) = engine(chain(proxy))?;
    let a = stand_in(&tunnel, b"\x01a\x04test\x00").await?;
    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((a, 443)),
        b"hello",
    )
    .await?;
    let engine_at = heard_from_engine(&mut script).await?;
    let server = SocketAddr::from(([198, 51, 100, 9], 443));
    relay
        .send_to(&relayed(header_by_address(server), b"bound"), engine_at)
        .await?;
    receive(&tunnel).await?.ok_or("a datagram")?;
    let other = SocketAddr::from(([198, 51, 100, 9], 3_478));
    relay
        .send_to(&relayed(header_by_address(other), b"from 3478"), engine_at)
        .await?;
    let shown = SocketAddr::from((a, 3_478));
    assert_eq!(
        receive(&tunnel).await?,
        Some((shown, b"from 3478".to_vec()))
    );
    send(&tunnel, app(CHAINED_PORT), shown, b"reply").await?;
    let (_, datagram) = tokio::time::timeout(Duration::from_secs(5), script.recv())
        .await?
        .ok_or("the relay heard nothing")?;
    assert_eq!(datagram, relayed(header_by_name("a.test", 3_478), b"reply"));
    Ok(())
}

/// An app that answers every port that comes in, as a DHT node or a QUIC listener does, still lets in at
/// most 64 of them: a flow that came in counts under the cap for as long as it lives, even once the app
/// answers it (sixth review of unit 9, finding 3; the fifth review's finding 2 had let it leave the cap).
#[tokio::test(flavor = "current_thread")]
async fn an_app_that_answers_every_port_that_came_in_lets_in_64() -> Outcome {
    let server = UdpSocket::bind("127.0.0.1:0").await?;
    let at = server.local_addr()?;
    let mut ports = Vec::new();
    for _ in 0..(64 * 4) {
        ports.push(UdpSocket::bind("127.0.0.1:0").await?);
    }
    let (go, mut next) = tokio::sync::mpsc::channel::<()>(4);
    tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        if let Ok((_, mapped)) = server.recv_from(&mut buffer).await {
            for some in ports.chunks(64) {
                for port in some {
                    let _ = port.send_to(b"came in", mapped).await;
                }
                if next.recv().await.is_none() {
                    return;
                }
            }
        }
    });
    let tool = proxy(Settings::default()).await?;
    let (engine, tunnel) = engine(chain(tool.address))?;
    send(&tunnel, app(DIRECT_PORT), at, b"hello").await?;
    let mut came_in = 0;
    for _ in 0..4 {
        let seen = everything(&tunnel).await;
        came_in += seen.len();
        for (from, _) in &seen {
            send(&tunnel, app(DIRECT_PORT), *from, b"an answer").await?;
        }
        go.send(()).await?;
    }
    assert_eq!(came_in, 64, "ports that came in");
    assert_eq!(engine.counters()[UDP_CAME_IN_CAPPED], 64 * 3);
    Ok(())
}

/// A server that answers the app's first datagram from another of its ports, which keeps what it hears:
/// the server's address, the other port's, and what that heard.
async fn answered_from_another_port()
-> Result<(SocketAddr, SocketAddr, Heard), Box<dyn std::error::Error>> {
    let first = UdpSocket::bind("127.0.0.1:0").await?;
    let second = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let (at, other) = (first.local_addr()?, second.local_addr()?);
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    let answers = Arc::clone(&second);
    tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        if let Ok((_, from)) = first.recv_from(&mut buffer).await {
            let _ = answers.send_to(b"from another port", from).await;
        }
    });
    tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        while let Ok((n, from)) = second.recv_from(&mut buffer).await {
            noted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((from, buffer[..n].to_vec()));
        }
    });
    Ok((at, other, heard))
}

/// A port that came in to the old app's mapping is no destination that app knew: the new app's first
/// datagram to it, though the mapping is fresh, asks Android, and goes through the tool (sixth review of
/// unit 9, finding 4).
#[tokio::test(flavor = "current_thread")]
async fn a_port_that_came_in_is_no_destination_the_app_knew() -> Outcome {
    const PORT: u16 = 50_303;
    let (at, other, heard) = answered_from_another_port().await?;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (_engine, tunnel) = engine_with(chain(tool.address), Limits::default(), owners.clone())?;
    send(&tunnel, app(PORT), at, b"x").await?;
    let (from, _) = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(from, other);
    owners.set(PORT, Some(CHAINED));
    send(&tunnel, app(PORT), other, b"y").await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let from = heard_from(&heard, b"y");
    assert_eq!(from.len(), 1);
    assert!(
        tool.relays().contains(&from[0]),
        "left directly from {}",
        from[0]
    );
    Ok(())
}

/// Once the app has answered a port that came in, that port is its destination: the next datagram to it
/// leaves by the mapping, without another question to Android (sixth review of unit 9, finding 6).
#[tokio::test(flavor = "current_thread")]
async fn a_port_that_came_in_and_was_answered_asks_android_once() -> Outcome {
    let (at, other, heard) = answered_from_another_port().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(Counting::default());
    let (_engine, tunnel) = engine_with(chain(tool.address), Limits::default(), android.clone())?;
    send(&tunnel, app(DIRECT_PORT), at, b"x").await?;
    let (from, _) = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(from, other);
    for (asked, reply) in [(2, &b"first reply"[..]), (2, b"second reply")] {
        send(&tunnel, app(DIRECT_PORT), other, reply).await?;
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        while heard_from(&heard, reply).is_empty() {
            if tokio::time::Instant::now() > until {
                return Err("the reply never arrived".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            android.asked(),
            asked,
            "questions to Android after {reply:?}"
        );
    }
    Ok(())
}

/// The old app's lookup asks Android, slowly; the port is handed to a chained app 50 ms after the
/// question began; the chained app's lookup, sent 150 ms after it, more than `udp_reask` (100 ms here),
/// and held behind the old one's, does not take its answer: it asks again, and stays off the network's
/// resolver (sixth review of unit 9, finding 1). The times count from when Android was asked, which
/// the engine did no later, so that a slow start under load cannot narrow them.
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_held_behind_the_old_apps_asks_again() -> Outcome {
    const PORT: u16 = 50_304;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(PORT, DIRECT);
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    let public = query(b"\x06public\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &public).await?;
    let asked = android.asked(1).await?;
    tokio::time::sleep_until(asked + Duration::from_millis(50)).await;
    android.set(PORT, CHAINED);
    tokio::time::sleep_until(asked + Duration::from_millis(150)).await;
    let private = query(b"\x07private\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &private).await?;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !heard_private(&heard),
        "the chained app's lookup reached the network's resolver"
    );
    Ok(())
}

/// The same for datagrams to a new destination, held behind the old app's first one.
#[tokio::test(flavor = "current_thread")]
async fn a_datagram_held_behind_the_old_apps_asks_again() -> Outcome {
    const PORT: u16 = 50_305;
    let (c, heard) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(PORT, DIRECT);
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    send(&tunnel, app(PORT), c, b"x").await?;
    let asked = android.asked(1).await?;
    tokio::time::sleep_until(asked + Duration::from_millis(50)).await;
    android.set(PORT, CHAINED);
    tokio::time::sleep_until(asked + Duration::from_millis(150)).await;
    for _ in 0..30 {
        send(&tunnel, app(PORT), c, b"y").await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let from = heard_from(&heard, b"y");
    let relays = tool.relays();
    let direct = from.iter().filter(|f| !relays.contains(f)).count();
    assert_eq!(direct, 0, "{direct} of {} left directly", from.len());
    assert_eq!(heard_from(&heard, b"x").len(), 1, "the old app's datagram");
    Ok(())
}

/// The old app's last datagram to a destination it knows asks Android, slowly; the port is handed to a
/// chained app 50 ms after the question began; the new app's datagrams to another destination the
/// mapping knows, from 150 ms after it, more than `udp_reask` (100 ms here), neither join that question
/// nor take its answer: they go through the tool (sixth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_known_destination_joins_no_question_older_than_the_window() -> Outcome {
    const PORT: u16 = 50_301;
    let (a, _) = listening().await?;
    let (b, heard_b) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(PORT, DIRECT);
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    send(&tunnel, app(PORT), a, b"x to a").await?;
    tokio::time::sleep_until(android.asked(1).await? + Duration::from_millis(500)).await;
    send(&tunnel, app(PORT), b, b"x to b").await?;
    tokio::time::sleep_until(android.asked(2).await? + Duration::from_millis(700)).await;
    send(&tunnel, app(PORT), a, b"x again").await?;
    let asked = android.asked(3).await?;
    tokio::time::sleep_until(asked + Duration::from_millis(50)).await;
    android.set(PORT, CHAINED);
    tokio::time::sleep_until(asked + Duration::from_millis(150)).await;
    for _ in 0..30 {
        send(&tunnel, app(PORT), b, b"y to b").await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let from = heard_from(&heard_b, b"y to b");
    let relays = tool.relays();
    let direct = from.iter().filter(|f| !relays.contains(f)).count();
    assert_eq!(direct, 0, "{direct} of {} left directly", from.len());
    Ok(())
}

/// After a pause, the old app's datagram to a destination it knows asks Android, slowly (300 ms); the
/// port is handed to a chained app 50 ms after the question began. The new app's datagrams to that
/// destination, sent once the answer is in, do not leave by the old app's mapping: the answer made it
/// fresh from when Android was asked, not from when it answered (sixth review of unit 9, finding 1).
#[tokio::test(flavor = "current_thread")]
async fn a_slow_answer_makes_a_mapping_fresh_only_from_its_question() -> Outcome {
    const PORT: u16 = 50_306;
    let (a, heard) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(PORT, DIRECT);
    let (_engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    send(&tunnel, app(PORT), a, b"x").await?;
    tokio::time::sleep_until(android.asked(1).await? + Duration::from_millis(600)).await;
    send(&tunnel, app(PORT), a, b"x again").await?;
    let asked = android.asked(2).await?;
    tokio::time::sleep_until(asked + Duration::from_millis(50)).await;
    android.set(PORT, CHAINED);
    tokio::time::sleep_until(asked + Duration::from_millis(350)).await;
    for _ in 0..10 {
        send(&tunnel, app(PORT), a, b"y").await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    let from = heard_from(&heard, b"y");
    let relays = tool.relays();
    let direct = from.iter().filter(|f| !relays.contains(f)).count();
    assert_eq!(direct, 0, "{direct} of {} left directly", from.len());
    Ok(())
}

/// The same for a flow of lookups: the chained app's lookup, sent once the old app's slow answer is in,
/// does not leave by the old app's flow to the network's resolver.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_answer_makes_a_flow_of_lookups_fresh_only_from_its_question() -> Outcome {
    const PORT: u16 = 50_307;
    let tool = proxy(Settings::default()).await?;
    let android = Arc::new(SlowOwners::default());
    android.set(PORT, DIRECT);
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), android.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    let public = query(b"\x06public\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &public).await?;
    let asked = android.asked(1).await?;
    tokio::time::sleep_until(asked + Duration::from_millis(50)).await;
    android.set(PORT, CHAINED);
    tokio::time::sleep_until(asked + Duration::from_millis(350)).await;
    let private = query(b"\x07private\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &private).await?;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !heard_private(&heard),
        "the chained app's lookup reached the network's resolver"
    );
    Ok(())
}

/// A direct app's datagram opens its mapping; the port is handed to a chained app, whose lookup makes
/// Android name it: the old app's mapping ends then, and the new app's datagrams to the old app's
/// destination go through the tool (sixth review of unit 9, finding 2).
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_that_names_a_new_app_ends_the_old_apps_mapping() -> Outcome {
    const PORT: u16 = 50_300;
    let (at, heard) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    let (dns, dns_heard) = deaf_resolver(&engine).await?;
    send(&tunnel, app(PORT), at, b"x").await?;
    until_a_flow_to(&engine, at).await?;
    owners.set(PORT, Some(CHAINED));
    let private = query(b"\x07private\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &private).await?;
    until_a_flow_to(&engine, dns).await?;
    for _ in 0..5 {
        send(&tunnel, app(PORT), at, b"y").await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!heard_private(&dns_heard), "the lookup went to the network");
    let from = heard_from(&heard, b"y");
    let relays = tool.relays();
    let direct = from.iter().filter(|f| !relays.contains(f)).count();
    assert_eq!(direct, 0, "{direct} of {} left directly", from.len());
    Ok(())
}

/// The other way round: a direct app's lookup opens its flow of lookups, which waits for an answer that
/// never comes; the port is handed to a chained app, whose datagram makes Android name it. The old
/// app's flow of lookups gives way then, and the new app's lookup stays off the network's resolver.
#[tokio::test(flavor = "current_thread")]
async fn a_datagram_that_names_a_new_app_ends_the_old_apps_flow_of_lookups() -> Outcome {
    const PORT: u16 = 50_308;
    let (at, _) = listening().await?;
    let tool = proxy(Settings::default()).await?;
    let owners = Arc::new(Owners::default());
    owners.set(PORT, Some(DIRECT));
    let (engine, tunnel) = engine_with(chain(tool.address), quick_reask(), owners.clone())?;
    let (dns, heard) = deaf_resolver(&engine).await?;
    let public = query(b"\x06public\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &public).await?;
    until_a_flow_to(&engine, dns).await?;
    owners.set(PORT, Some(CHAINED));
    send(&tunnel, app(PORT), at, b"x").await?;
    until_a_flow_to(&engine, at).await?;
    let private = query(b"\x07private\x04test\x00", 1);
    send(&tunnel, app(PORT), dns, &private).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !heard_private(&heard),
        "the chained app's lookup reached the network's resolver"
    );
    Ok(())
}
