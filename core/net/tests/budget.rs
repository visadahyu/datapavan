//! The engine's budget for UDP (ADR 0044, decision 3) through the whole engine: a pair of datagram
//! sockets stands in for the tunnel, and echo servers on this computer for the internet. The UDP ways
//! that hold a socket of their own, mappings and flows of lookups on the direct path, are capped for
//! every app together, and each app may hold a share of the cap; the apps Android cannot name share
//! one share. A new way beyond them is refused, and its datagrams dropped and counted.

mod common;

use common::udp_echo;
use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::{Config, Engine, Platform, packet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UdpSocket, UnixDatagram};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Two apps, each named by Android for the ports of its own range inside the tunnel; a socket on any
/// other port is one Android cannot name.
const FIRST: u32 = 10_710;
const SECOND: u32 = 10_720;
const FIRST_PORTS: u16 = 41_000;
const SECOND_PORTS: u16 = 42_000;
const UNNAMED_PORTS: u16 = 43_000;
/// The places of counters in `Engine::counters`.
const UDP_MAPPINGS: usize = 24;
const UDP_REFUSED: usize = 31;

/// Android names the app by the range its port inside the tunnel is in.
struct ByRange;

impl Platform for ByRange {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() / 1_000 {
            41 => Some(FIRST),
            42 => Some(SECOND),
            _ => None,
        }
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// The engine on a datagram pair, with `limits` and no chain, and the app's end of the pair.
fn engine(limits: Limits) -> io::Result<(Engine, UnixDatagram)> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            limits,
            mtu: 1500,
            keep_flows: 64,
            addresses: Addresses::COMMON,
        },
        Arc::new(ByRange),
        None,
    )?;
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

/// Small caps, which a test then sets: no mapping ends to make room, since every one passed a datagram
/// less than `udp_quiet` ago.
fn small(udp_mappings: usize, udp_share: usize) -> Limits {
    Limits {
        udp_mappings,
        udp_share,
        udp_quiet: Duration::from_secs(60),
        ..Limits::default()
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

/// The next packet to the apps, within five seconds: where it came from and went to, and its payload;
/// `None` for anything but UDP (an ICMP error).
async fn receive(tunnel: &UnixDatagram) -> Result<Option<Received>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(5), tunnel.recv(&mut buffer)).await??;
    let Ok(parsed) = packet::parse(&buffer[..n]) else {
        return Ok(None);
    };
    Ok(packet::udp_payload(&buffer[..n], &parsed)
        .map(|payload| (parsed.source, parsed.destination, payload.to_vec())))
}

/// A datagram to the apps: from, to, and its payload.
type Received = (SocketAddr, SocketAddr, Vec<u8>);

/// The app at `from` sends `payload` to `to` and gets it back from there.
async fn echoed(
    tunnel: &UnixDatagram,
    from: SocketAddr,
    to: SocketAddr,
    payload: &[u8],
) -> Outcome {
    send(tunnel, from, to, payload).await?;
    let answer = receive(tunnel)
        .await?
        .ok_or("a datagram, not an ICMP error")?;
    assert_eq!(answer, (to, from, payload.to_vec()));
    Ok(())
}

/// A standard query for the A record of example.com, under the ID `id`.
fn query(id: u16) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(b"\x07example\x03com\x00");
    query.extend_from_slice(&[0, 1, 0, 1]);
    query
}

/// The answer to `query`, with no records.
fn response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    response
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

/// Nothing came to the apps, not even an ICMP error: a datagram refused is dropped, as by a full
/// queue.
fn nothing_came(tunnel: &UnixDatagram) -> Outcome {
    let mut buffer = [0u8; 2_048];
    match tunnel.try_recv(&mut buffer) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(n) => Err(format!("{n} bytes came to the apps").into()),
    }
}

/// An app that holds its whole share gets no new mapping: its datagram from a new socket is dropped and
/// counted, with nothing sent back. Another app's new socket gets one at once, as the cap for every app
/// still has room.
#[tokio::test(flavor = "current_thread")]
async fn an_app_at_its_share_gets_no_new_mapping_while_another_app_does() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(small(8, 2))?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"one").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"two").await?;
    send(&tunnel, app(FIRST_PORTS + 2), echo, b"three").await?;
    counted(&engine, UDP_REFUSED, 1).await?;
    nothing_came(&tunnel)?;
    echoed(&tunnel, app(SECOND_PORTS), echo, b"another app's").await?;
    // The first app's sockets that have a mapping keep it.
    echoed(&tunnel, app(FIRST_PORTS), echo, b"again").await?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 3);
    assert_eq!(engine.counters()[UDP_REFUSED], 1);
    Ok(())
}

/// Once every app together holds the whole cap, a new mapping is refused, whoever's it is, though its
/// app holds less than its share.
#[tokio::test(flavor = "current_thread")]
async fn the_cap_for_every_app_refuses_a_new_mapping_once_full() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(small(3, 2))?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"one").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"two").await?;
    echoed(&tunnel, app(SECOND_PORTS), echo, b"three").await?;
    send(
        &tunnel,
        app(SECOND_PORTS + 1),
        echo,
        b"the second app's second",
    )
    .await?;
    counted(&engine, UDP_REFUSED, 1).await?;
    send(&tunnel, app(UNNAMED_PORTS), echo, b"an unnamed app's first").await?;
    counted(&engine, UDP_REFUSED, 2).await?;
    nothing_came(&tunnel)?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 3);
    Ok(())
}

/// The sockets whose app Android cannot name share one share, whatever app each is.
#[tokio::test(flavor = "current_thread")]
async fn apps_android_cannot_name_share_one_share() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(small(8, 2))?;
    echoed(&tunnel, app(UNNAMED_PORTS), echo, b"one").await?;
    echoed(&tunnel, app(UNNAMED_PORTS + 1), echo, b"two").await?;
    send(&tunnel, app(UNNAMED_PORTS + 2), echo, b"three").await?;
    counted(&engine, UDP_REFUSED, 1).await?;
    nothing_came(&tunnel)?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"a named app's").await?;
    Ok(())
}

/// A lookup to the tunnel's DNS address on the direct path holds a socket, and so a place of its app's
/// share, while it waits for its answer, and gives it back with the answer: the network's resolver
/// here answers when the test says.
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_holds_a_place_until_its_answer() -> Outcome {
    let echo = udp_echo().await?;
    let resolver = UdpSocket::bind("127.0.0.1:0").await?;
    let (engine, tunnel) = engine(small(8, 2))?;
    engine.network_changed(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), false);
    // Any port of the tunnel's DNS address leads to the same port of the network's resolver.
    let dns = SocketAddr::from((Addresses::COMMON.dns4, resolver.local_addr()?.port()));
    let lookup = query(0x5150);
    send(&tunnel, app(FIRST_PORTS), dns, &lookup).await?;
    let mut question = [0u8; 512];
    let (n, asker) =
        tokio::time::timeout(Duration::from_secs(5), resolver.recv_from(&mut question)).await??;
    assert_eq!(&question[..n], lookup.as_slice());
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"a mapping").await?;
    send(&tunnel, app(FIRST_PORTS + 2), echo, b"beyond the share").await?;
    counted(&engine, UDP_REFUSED, 1).await?;
    resolver.send_to(&response(&lookup), asker).await?;
    let answer = receive(&tunnel).await?.ok_or("the lookup's answer")?;
    assert_eq!(answer, (dns, app(FIRST_PORTS), response(&lookup)));
    // The flow of lookups ends with its answer, a moment after the app has it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    echoed(&tunnel, app(FIRST_PORTS + 3), echo, b"room again").await?;
    assert_eq!(engine.counters()[UDP_REFUSED], 1);
    Ok(())
}
