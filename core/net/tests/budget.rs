//! The engine's budget for UDP (ADR 0044, decision 3) through the whole engine: a pair of datagram
//! sockets stands in for the tunnel, and echo servers on this computer for the internet. The UDP ways
//! that hold a socket of their own, mappings and flows of lookups on the direct path, are capped for
//! every app together, and each app may hold a share of the cap; the apps Android cannot name share
//! one share. A new way beyond them makes room by ending a mapping, in the order ADR 0044 gives: an
//! answered lookup, the app's own least recently active mapping quiet for `udp_quiet`, any app's; an
//! app at its share ends only its own. Where none may end, the new way is refused, and its datagrams
//! dropped and counted.

mod common;

use common::{Settings, proxy, udp_echo};
use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::{Chain, Config, Engine, Platform, packet};
use std::collections::HashSet;
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
const UDP_EVICTED: usize = 32;

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
    quiet_after(udp_mappings, udp_share, Duration::from_secs(60))
}

/// Small caps, with mappings quiet once they passed nothing for `udp_quiet`.
fn quiet_after(udp_mappings: usize, udp_share: usize, udp_quiet: Duration) -> Limits {
    Limits {
        udp_mappings,
        udp_share,
        udp_quiet,
        ..Limits::default()
    }
}

/// The tests' `udp_quiet`, long enough that a busy mapping stays busy on a loaded computer, and a
/// pause longer than it, after which what passed nothing is quiet.
const QUIET: Duration = Duration::from_millis(500);
const QUIETER: Duration = Duration::from_millis(900);

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
    // The flow of lookups ends with its answer, a moment after the app has it: the app sends again
    // until its datagram finds room, for five seconds at most.
    let from = app(FIRST_PORTS + 3);
    let mut tries = 0;
    let echoed = loop {
        tries += 1;
        send(&tunnel, from, echo, b"room again").await?;
        let mut buffer = vec![0u8; 2_048];
        if let Ok(n) =
            tokio::time::timeout(Duration::from_millis(100), tunnel.recv(&mut buffer)).await
        {
            let n = n?;
            let parsed = packet::parse(&buffer[..n]).map_err(|_| "a packet")?;
            let payload = packet::udp_payload(&buffer[..n], &parsed).ok_or("a datagram")?;
            break (parsed.source, parsed.destination, payload.to_vec());
        }
        if tries == 50 {
            return Err("no room again within five seconds".into());
        }
    };
    assert_eq!(echoed, (echo, from, b"room again".to_vec()));
    assert!(
        engine.counters()[UDP_REFUSED] <= tries,
        "refused more than tried"
    );
    Ok(())
}

/// An app at its share makes room among its own: its least recently active mapping, quiet for
/// `udp_quiet`, ends for its new one, and is counted. Another app's mapping, quieter still, is not
/// touched, since it would make no room in this app's share; nor is the app's mapping that passed a
/// datagram less than `udp_quiet` ago, so that once only such ones are left, the next is refused.
#[tokio::test(flavor = "current_thread")]
async fn an_app_at_its_share_ends_its_own_quiet_mapping_for_a_new_one() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(quiet_after(8, 2, QUIET))?;
    echoed(&tunnel, app(SECOND_PORTS), echo, b"the other app's").await?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"quiet soon").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"busy").await?;
    for _ in 0..6 {
        tokio::time::sleep(QUIET / 3).await;
        echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"still busy").await?;
    }
    echoed(&tunnel, app(FIRST_PORTS + 2), echo, b"new").await?;
    assert_eq!(engine.counters()[UDP_EVICTED], 1);
    assert_eq!(engine.counters()[UDP_REFUSED], 0);
    // The busy one and the other app's kept their mappings.
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"kept").await?;
    echoed(&tunnel, app(SECOND_PORTS), echo, b"kept too").await?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 4);
    // Both of the app's mappings passed a datagram just now: none ends.
    send(&tunnel, app(FIRST_PORTS + 3), echo, b"no room").await?;
    counted(&engine, UDP_REFUSED, 1).await?;
    nothing_came(&tunnel)?;
    assert_eq!(engine.counters()[UDP_EVICTED], 1);
    Ok(())
}

/// At the cap for every app, the app's own least recently active quiet mapping ends first, before
/// another app's quieter one.
#[tokio::test(flavor = "current_thread")]
async fn at_the_cap_the_apps_own_quiet_mapping_ends_before_another_apps() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(quiet_after(3, 3, QUIET))?;
    echoed(
        &tunnel,
        app(SECOND_PORTS),
        echo,
        b"the other app's, quietest",
    )
    .await?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"one").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"two").await?;
    tokio::time::sleep(QUIETER).await;
    echoed(&tunnel, app(FIRST_PORTS + 2), echo, b"three").await?;
    assert_eq!(engine.counters()[UDP_EVICTED], 1);
    echoed(&tunnel, app(SECOND_PORTS), echo, b"kept").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"kept too").await?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 4);
    Ok(())
}

/// At the cap for every app, an app with no mapping of its own that may end ends another app's least
/// recently active quiet one.
#[tokio::test(flavor = "current_thread")]
async fn at_the_cap_an_app_without_one_of_its_own_ends_another_apps() -> Outcome {
    let echo = udp_echo().await?;
    let (engine, tunnel) = engine(quiet_after(2, 2, QUIET))?;
    echoed(&tunnel, app(SECOND_PORTS), echo, b"quietest").await?;
    echoed(&tunnel, app(SECOND_PORTS + 1), echo, b"quiet").await?;
    tokio::time::sleep(QUIETER).await;
    echoed(&tunnel, app(SECOND_PORTS + 1), echo, b"busy again").await?;
    echoed(&tunnel, app(FIRST_PORTS), echo, b"new").await?;
    assert_eq!(engine.counters()[UDP_EVICTED], 1);
    echoed(&tunnel, app(SECOND_PORTS + 1), echo, b"kept").await?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 3);
    Ok(())
}

/// A server that answers each DNS query it gets with a response to it, with no records.
async fn resolver() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let at = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&response(&buffer[..n]), from).await;
        }
    });
    Ok(at)
}

/// At the cap for every app, an answered lookup ends first, before any quiet mapping: an app's own
/// resolver, which sends each query from a socket of its own, leaves one behind each answer. The
/// second app here is chained, so that its lookup to port 53 reaches a resolver on this computer
/// through the test proxy.
#[tokio::test(flavor = "current_thread")]
async fn at_the_cap_an_answered_lookup_ends_first() -> Outcome {
    let echo = udp_echo().await?;
    let public = SocketAddr::from(([9, 9, 9, 9], 53));
    let mut settings = Settings::default();
    settings.remap.insert(public, resolver().await?);
    let tool = proxy(settings).await?;
    let (engine, tunnel) = engine(quiet_after(3, 3, QUIET))?;
    engine.chain(Some(Chain {
        proxy: tool.address,
        credentials: None,
        tool: 10_200,
        apps: Some(HashSet::from([SECOND])),
        udp: true,
        log_destinations: false,
    }));
    echoed(&tunnel, app(FIRST_PORTS), echo, b"one").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"two").await?;
    tokio::time::sleep(QUIETER).await;
    // The lookup is the most recently active of the three when the room is made.
    let lookup = query(0x7a7a);
    send(&tunnel, app(SECOND_PORTS), public, &lookup).await?;
    let answer = receive(&tunnel).await?.ok_or("the lookup's answer")?;
    assert_eq!(answer, (public, app(SECOND_PORTS), response(&lookup)));
    echoed(&tunnel, app(FIRST_PORTS + 2), echo, b"three").await?;
    assert_eq!(engine.counters()[UDP_EVICTED], 1);
    echoed(&tunnel, app(FIRST_PORTS), echo, b"kept").await?;
    echoed(&tunnel, app(FIRST_PORTS + 1), echo, b"kept too").await?;
    assert_eq!(engine.counters()[UDP_MAPPINGS], 4);
    Ok(())
}

/// A server that answers the first DNS query it gets, and nothing after.
async fn resolver_once() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let at = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        if let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&response(&buffer[..n]), from).await;
        }
        while socket.recv_from(&mut buffer).await.is_ok() {}
    });
    Ok(at)
}

/// A mapping on port 53 is an answered lookup only while every datagram the app sent it is a DNS query
/// with its answer: once the app sends another query, or anything but a query, after an answer, it no
/// longer ends first, and here, with nothing quiet, the new way is refused.
#[tokio::test(flavor = "current_thread")]
async fn a_lookup_sent_on_after_its_answer_is_not_ended_first() -> Outcome {
    for after in [query(0x7c7c), b"not a query".to_vec()] {
        let echo = udp_echo().await?;
        let public = SocketAddr::from(([9, 9, 9, 9], 53));
        let mut settings = Settings::default();
        settings.remap.insert(public, resolver_once().await?);
        let tool = proxy(settings).await?;
        let (engine, tunnel) = engine(small(2, 2))?;
        engine.chain(Some(Chain {
            proxy: tool.address,
            credentials: None,
            tool: 10_200,
            apps: Some(HashSet::from([SECOND])),
            udp: true,
            log_destinations: false,
        }));
        echoed(&tunnel, app(FIRST_PORTS), echo, b"one").await?;
        let lookup = query(0x7b7b);
        send(&tunnel, app(SECOND_PORTS), public, &lookup).await?;
        let answer = receive(&tunnel).await?.ok_or("the lookup's answer")?;
        assert_eq!(answer, (public, app(SECOND_PORTS), response(&lookup)));
        send(&tunnel, app(SECOND_PORTS), public, &after).await?;
        // The datagram after the answer has left before the room is asked for.
        tokio::time::sleep(Duration::from_millis(100)).await;
        send(&tunnel, app(FIRST_PORTS + 1), echo, b"no room").await?;
        counted(&engine, UDP_REFUSED, 1).await?;
        assert_eq!(engine.counters()[UDP_EVICTED], 0, "after {after:?}");
    }
    Ok(())
}
