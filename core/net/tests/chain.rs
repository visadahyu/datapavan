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
