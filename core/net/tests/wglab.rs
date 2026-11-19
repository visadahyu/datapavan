//! W7's interoperation lab through the engine itself (ADR 0035, "Tests without a provider"): Watch's engine on
//! a pair of datagram sockets for its tunnel, its `WireGuard` tunnels to two peers of the Linux kernel's
//! `WireGuard`, the reference implementation, in the Compose project `datapavan-wglab`. Chosen apps' TCP, UDP,
//! ICMP and DNS on IPv4 and IPv6, a packet from outside `AllowedIPs` refused, a `PresharedKey`, and two
//! tunnels at once to two peers.
//!
//! Ignored by default: `scripts/wglab.sh` (`scripts/check.sh wglab`) starts the peers, makes the clients'
//! keys with the peers' own `wg`, and runs these with the settings in the environment (`WGLAB_*`).
#![cfg(target_os = "linux")]

use datapavan_net::engine::{Addresses, Configured, Limits, TunnelSetting};
use datapavan_net::wireguard::config::Config as WgConfig;
use datapavan_net::{Config, Engine, Platform, packet};
use etherparse::{
    IcmpEchoHeader, Icmpv4Type, Icmpv6Type, PacketBuilder, SlicedPacket, TransportSlice,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixDatagram;

type Outcome = Result<(), Box<dyn std::error::Error>>;

const FIRST: u32 = 10_300;
const SECOND: u32 = 10_301;
/// The peers' addresses inside their tunnels (spikes/wireguard-core/peer/start.sh).
const PEER4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 1);
const TUNNEL_FILTERED: usize = 54;
const STEP: Duration = Duration::from_secs(8);

struct ByPort;

impl Platform for ByPort {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() {
            40_000..=40_999 => Some(FIRST),
            41_000..=41_999 => Some(SECOND),
            _ => None,
        }
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

fn setting(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is not set: run scripts/wglab.sh").into())
}

/// The lab's client configuration: `key` and `address` the client's, `peer` and `public` the peer's.
fn client(
    key: &str,
    (v4, v6): (&str, &str),
    peer: &str,
    public: &str,
    psk: Option<&str>,
) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    let psk = psk.map_or_else(String::new, |psk| format!("PresharedKey = {psk}\n"));
    let text = format!(
        "[Interface]\nPrivateKey = {key}\nAddress = {v4}/32, {v6}/128\nDNS = 10.77.0.1, fd77::1\n\n[Peer]\n\
         PublicKey = {public}\n{psk}AllowedIPs = 10.77.0.0/24, fd77::/64\nEndpoint = {peer}\n"
    );
    Ok(Arc::new(
        WgConfig::parse(text.as_bytes()).map_err(|r| r.to_string())?,
    ))
}

fn engine(tunnels: Vec<Configured>, routes: &[(u32, u32)]) -> io::Result<(Engine, UnixDatagram)> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            limits: Limits::default(),
            mtu: 1500,
            keep_flows: 64,
            addresses: Addresses::COMMON,
        },
        Arc::new(ByPort),
        None,
    )?;
    engine.tunnels(&TunnelSetting {
        tunnels,
        routes: routes.iter().copied().collect::<HashMap<_, _>>(),
        log_destinations: false,
    });
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

fn app(v6: bool, port: u16) -> SocketAddr {
    if v6 {
        SocketAddr::from((Addresses::COMMON.tun6, port))
    } else {
        SocketAddr::from((Addresses::COMMON.tun4, port))
    }
}

fn peer(v6: bool, port: u16) -> SocketAddr {
    if v6 {
        SocketAddr::from((PEER6, port))
    } else {
        SocketAddr::from((PEER4, port))
    }
}

fn builder(
    from: IpAddr,
    to: IpAddr,
) -> Result<etherparse::PacketBuilderStep<etherparse::IpHeaders>, Box<dyn std::error::Error>> {
    Ok(match (from, to) {
        (IpAddr::V4(f), IpAddr::V4(t)) => PacketBuilder::ipv4(f.octets(), t.octets(), 64),
        (IpAddr::V6(f), IpAddr::V6(t)) => PacketBuilder::ipv6(f.octets(), t.octets(), 64),
        _ => return Err("mixed versions".into()),
    })
}

/// The next packet to the app that `want` takes, within a step; others are passed over.
async fn next(
    tunnel: &UnixDatagram,
    want: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + STEP;
    loop {
        let n = tokio::time::timeout_at(deadline, tunnel.recv(&mut buffer)).await??;
        if want(&buffer[..n]) {
            return Ok(buffer[..n].to_vec());
        }
    }
}

fn udp_from(packet: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let parsed = packet::parse(packet).ok()?;
    (parsed.protocol == packet::UDP && parsed.source == from)
        .then(|| packet::udp_payload(packet, &parsed).map(<[u8]>::to_vec))?
}

/// A UDP datagram from the app at `from` to `to`, and the payload of the answer from `to`.
async fn udp(
    tunnel: &UnixDatagram,
    from: SocketAddr,
    to: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    tunnel
        .send(&packet::udp(from, to, payload).ok_or("datagram")?)
        .await?;
    let answer = next(tunnel, |p| udp_from(p, to).is_some()).await?;
    udp_from(&answer, to).ok_or_else(|| "no payload".into())
}

/// A SYN, the request, and the first segment of the peer's web server's answer: its text.
async fn http(
    tunnel: &UnixDatagram,
    from: SocketAddr,
    to: SocketAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let isn = 0x2000_0000u32;
    let mut syn = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn, 64_240)
        .syn()
        .write(&mut syn, &[])?;
    tunnel.send(&syn).await?;
    let tcp = |packet: &[u8]| -> Option<(etherparse::TcpHeader, Vec<u8>)> {
        match SlicedPacket::from_ip(packet).ok()?.transport? {
            TransportSlice::Tcp(t)
                if t.source_port() == to.port() && t.destination_port() == from.port() =>
            {
                Some((t.to_header(), t.payload().to_vec()))
            }
            _ => None,
        }
    };
    let synack = next(tunnel, |p| tcp(p).is_some_and(|(h, _)| h.syn && h.ack)).await?;
    let (header, _) = tcp(&synack).ok_or("unread")?;
    if header.acknowledgment_number != isn.wrapping_add(1) {
        return Err("the SYN-ACK acknowledges another sequence number".into());
    }
    let mut request = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn.wrapping_add(1), 64_240)
        .ack(header.sequence_number.wrapping_add(1))
        .psh()
        .write(&mut request, b"GET / HTTP/1.0\r\nHost: wglab\r\n\r\n")?;
    tunnel.send(&request).await?;
    let mut text = String::new();
    // The answer may come in more than one segment: its head, then its body.
    while !text.contains("wglab peer") {
        let data = next(tunnel, |p| {
            tcp(p).is_some_and(|(_, payload)| !payload.is_empty())
        })
        .await?;
        let (_, payload) = tcp(&data).ok_or("unread")?;
        text.push_str(&String::from_utf8_lossy(&payload));
    }
    let mut reset = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn.wrapping_add(33), 0)
        .rst()
        .write(&mut reset, &[])?;
    tunnel.send(&reset).await?;
    Ok(text)
}

/// An echo from the app to `to`, and whether its reply came.
async fn ping(tunnel: &UnixDatagram, to: IpAddr, sequence: u16) -> Outcome {
    let from = if to.is_ipv4() {
        IpAddr::V4(Addresses::COMMON.tun4)
    } else {
        IpAddr::V6(Addresses::COMMON.tun6)
    };
    let header = IcmpEchoHeader {
        id: 0x4242,
        seq: sequence,
    };
    let mut request = Vec::new();
    match to {
        IpAddr::V4(_) => builder(from, to)?
            .icmpv4(Icmpv4Type::EchoRequest(header))
            .write(&mut request, b"lab")?,
        IpAddr::V6(_) => builder(from, to)?
            .icmpv6(Icmpv6Type::EchoRequest(header))
            .write(&mut request, b"lab")?,
    }
    tunnel.send(&request).await?;
    next(tunnel, |p| {
        match SlicedPacket::from_ip(p).ok().and_then(|s| s.transport) {
            Some(TransportSlice::Icmpv4(i)) => {
                matches!(i.icmp_type(), Icmpv4Type::EchoReply(h) if h.seq == sequence)
            }
            Some(TransportSlice::Icmpv6(i)) => {
                matches!(i.icmp_type(), Icmpv6Type::EchoReply(h) if h.seq == sequence)
            }
            _ => false,
        }
    })
    .await?;
    Ok(())
}

/// A lookup to Watch's DNS address of `kind` for `lab.test`, and its answer.
async fn lookup(
    tunnel: &UnixDatagram,
    v6: bool,
    kind: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut query = vec![
        0x77, 0x01, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'l', b'a', b'b', 4, b't', b'e', b's', b't', 0,
    ];
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    let at = Addresses::COMMON;
    let dns = if v6 {
        SocketAddr::from((at.dns6, 53))
    } else {
        SocketAddr::from((at.dns4, 53))
    };
    udp(tunnel, app(v6, 40_100 + kind), dns, &query).await
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the lab's peers: scripts/wglab.sh"]
async fn tcp_udp_icmp_and_dns_pass_on_both_versions_and_nothing_from_outside_allowed_ips() -> Outcome
{
    let config = client(
        &setting("WGLAB_PLAIN")?,
        ("10.77.0.2", "fd77::2"),
        &setting("WGLAB_PEER")?,
        &setting("WGLAB_PEER_PUBLIC")?,
        None,
    )?;
    let (engine, tunnel) = engine(
        vec![Configured {
            id: 1,
            config,
            local_network: false,
        }],
        &[(FIRST, 1)],
    )?;
    for v6 in [false, true] {
        let version = if v6 { "IPv6" } else { "IPv4" };
        let text = http(&tunnel, app(v6, 40_001 + u16::from(v6)), peer(v6, 80)).await?;
        let own = if v6 { "fd77::2" } else { "10.77.0.2" };
        assert!(
            text.starts_with("HTTP/1.0 200") || text.contains("wglab-peer1"),
            "{text}"
        );
        assert!(
            text.contains(&format!("wglab-peer1 {own}")),
            "{version}: the peer saw {text}"
        );
        println!(
            "PASS tcp-{version}: the peer's web server answered the configuration's address {own}"
        );
        let echoed = udp(
            &tunnel,
            app(v6, 40_010 + u16::from(v6)),
            peer(v6, 7),
            b"lab echo",
        )
        .await?;
        assert_eq!(echoed, b"lab echo");
        let seen = udp(
            &tunnel,
            app(v6, 40_020 + u16::from(v6)),
            peer(v6, 8),
            b"who",
        )
        .await?;
        let seen = String::from_utf8_lossy(&seen).into_owned();
        assert!(
            seen.starts_with(&format!("{own} {} wglab-peer1", 40_020 + u16::from(v6))),
            "{seen}"
        );
        println!(
            "PASS udp-{version}: echoed, and the peer saw {}",
            seen.trim()
        );
        ping(&tunnel, peer(v6, 0).ip(), 1 + u16::from(v6)).await?;
        println!("PASS icmp-{version}: the kernel's echo reply came back");
        let kind = if v6 { 28 } else { 1 };
        let answer = lookup(&tunnel, v6, kind).await?;
        let response = datapavan_net::dns::response(&answer).ok_or("no DNS response")?;
        let expected = if v6 {
            IpAddr::V6(PEER6)
        } else {
            IpAddr::V4(PEER4)
        };
        assert_eq!(
            response.addresses,
            vec![(expected, 0)],
            "{version}: the peer's answer with a time to live of 0"
        );
        println!(
            "PASS dns-{version}: Watch's DNS address answered from the configuration's server, TTL 0"
        );
    }
    // The reflector answers from 10.77.1.1 and fd77:1::1, outside the client's AllowedIPs.
    for v6 in [false, true] {
        let from = app(v6, 40_030 + u16::from(v6));
        tunnel
            .send(&packet::udp(from, peer(v6, 9), b"reflect").ok_or("datagram")?)
            .await?;
    }
    // What else reaches the app meanwhile, the web server's last segments among it, is passed over.
    let reflected = |p: &[u8]| {
        packet::parse(p).is_ok_and(|parsed| {
            parsed.protocol == packet::UDP && (40_030..=40_031).contains(&parsed.destination.port())
        })
    };
    assert!(
        next(&tunnel, reflected).await.is_err(),
        "nothing reflected passed"
    );
    assert_eq!(engine.counters()[TUNNEL_FILTERED], 2);
    println!("PASS outside-allowed-ips: both reflected answers dropped and counted");
    let state = engine
        .tunnel_states()
        .into_iter()
        .next()
        .ok_or("no state")?;
    assert!(
        state.handshake.is_some() && !state.not_answering && state.error.is_none(),
        "{state:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the lab's peers: scripts/wglab.sh"]
async fn a_preshared_key_makes_the_session_on_both_versions() -> Outcome {
    let psk = setting("WGLAB_PSK")?;
    let config = client(
        &setting("WGLAB_PSK_KEY")?,
        ("10.77.0.3", "fd77::3"),
        &setting("WGLAB_PEER")?,
        &setting("WGLAB_PEER_PUBLIC")?,
        Some(&psk),
    )?;
    let (_engine, tunnel) = engine(
        vec![Configured {
            id: 1,
            config,
            local_network: false,
        }],
        &[(FIRST, 1)],
    )?;
    for v6 in [false, true] {
        ping(&tunnel, peer(v6, 0).ip(), 10 + u16::from(v6)).await?;
        let seen = udp(
            &tunnel,
            app(v6, 40_040 + u16::from(v6)),
            peer(v6, 8),
            b"who",
        )
        .await?;
        let own = if v6 { "fd77::3" } else { "10.77.0.3" };
        assert!(String::from_utf8_lossy(&seen).starts_with(own));
    }
    println!("PASS preshared-key: the session holds with the peer's preshared key, both versions");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the lab's peers: scripts/wglab.sh"]
async fn two_tunnels_at_once_carry_two_apps_to_two_peers() -> Outcome {
    let first = client(
        &setting("WGLAB_PLAIN")?,
        ("10.77.0.2", "fd77::2"),
        &setting("WGLAB_PEER")?,
        &setting("WGLAB_PEER_PUBLIC")?,
        None,
    )?;
    let second = client(
        &setting("WGLAB_SECOND")?,
        ("10.77.0.4", "fd77::4"),
        &setting("WGLAB_PEER2")?,
        &setting("WGLAB_PEER2_PUBLIC")?,
        None,
    )?;
    let (engine, tunnel) = engine(
        vec![
            Configured {
                id: 1,
                config: first,
                local_network: false,
            },
            Configured {
                id: 2,
                config: second,
                local_network: false,
            },
        ],
        &[(FIRST, 1), (SECOND, 2)],
    )?;
    let one = udp(&tunnel, app(false, 40_050), peer(false, 8), b"who").await?;
    let two = udp(&tunnel, app(false, 41_050), peer(false, 8), b"who").await?;
    let (one, two) = (
        String::from_utf8_lossy(&one).into_owned(),
        String::from_utf8_lossy(&two).into_owned(),
    );
    assert!(one.starts_with("10.77.0.2 40050 wglab-peer1"), "{one}");
    assert!(two.starts_with("10.77.0.4 41050 wglab-peer2"), "{two}");
    let text = http(&tunnel, app(true, 41_051), peer(true, 80)).await?;
    assert!(text.contains("wglab-peer2 fd77::4"), "{text}");
    println!(
        "PASS two-tunnels: the first app reached peer1 as 10.77.0.2, the second peer2 as 10.77.0.4 and fd77::4"
    );
    assert_eq!(
        engine
            .tunnel_states()
            .iter()
            .filter(|s| s.handshake.is_some())
            .count(),
        2
    );
    Ok(())
}
