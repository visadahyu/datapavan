//! W7's interoperation lab through the engine itself (ADR 0035, "Tests without a provider"): Watch's engine on
//! a pair of datagram sockets for its tunnel, its `WireGuard` tunnels to two peers of the Linux kernel's
//! `WireGuard`, the reference implementation, in the Compose project `datapavan-wglab`. Chosen apps' TCP, UDP,
//! ICMP and DNS on IPv4 and IPv6, a packet from outside `AllowedIPs` refused, a `PresharedKey`, two tunnels at
//! once to two peers, and the MTU's second way: a SYN's MSS clamped as the peer's kernel takes it, a datagram
//! larger than the configuration's MTU answered with "fragmentation needed" or "packet too big", and one of
//! the MTU's size passing whole to the peer and back.
//!
//! Ignored by default: `scripts/wglab.sh` (`scripts/check.sh wglab`) starts the peers, makes the clients'
//! keys with the peers' own `wg`, and runs these with the settings in the environment (`WGLAB_*`).
#![cfg(target_os = "linux")]

use datapavan_net::engine::{Addresses, Configured, Limits, TunnelSetting};
use datapavan_net::wireguard::config::Config as WgConfig;
use datapavan_net::{Config, Engine, Platform, packet};
use etherparse::{
    IcmpEchoHeader, Icmpv4Type, Icmpv6Type, PacketBuilder, SlicedPacket, TcpOptionElement,
    TransportSlice,
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
const TUNNEL_TOO_BIG: usize = 57;
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
    addresses: (&str, &str),
    peer: &str,
    public: &str,
    psk: Option<&str>,
) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    client_with(key, addresses, peer, public, psk, "")
}

/// [`client`], with `interface` more lines for its `[Interface]`.
fn client_with(
    key: &str,
    (v4, v6): (&str, &str),
    peer: &str,
    public: &str,
    psk: Option<&str>,
    interface: &str,
) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    let psk = psk.map_or_else(String::new, |psk| format!("PresharedKey = {psk}\n"));
    let text = format!(
        "[Interface]\nPrivateKey = {key}\nAddress = {v4}/32, {v6}/128\nDNS = 10.77.0.1, fd77::1\n{interface}\n\
         [Peer]\nPublicKey = {public}\n{psk}AllowedIPs = 10.77.0.0/24, fd77::/64\nEndpoint = {peer}\n"
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
        default: None,
        known: None,
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

/// An echo from the app to `to`, and whether its reply came, from `to` itself.
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
        (match SlicedPacket::from_ip(p).ok().and_then(|s| s.transport) {
            Some(TransportSlice::Icmpv4(i)) => {
                matches!(i.icmp_type(), Icmpv4Type::EchoReply(h) if h.seq == sequence)
            }
            Some(TransportSlice::Icmpv6(i)) => {
                matches!(i.icmp_type(), Icmpv6Type::EchoReply(h) if h.seq == sequence)
            }
            _ => false,
        }) && source_of(p) == Some(to)
    })
    .await?;
    Ok(())
}

/// A SYN with an MSS of 1,460 and no other option from the app at `from` to the peer's MSS service at `to`,
/// the SYN-ACK's MSS as the app gets it, and the largest segment the peer's kernel may send on the connection,
/// as the service says it: with no timestamps, the smaller of the SYN's MSS as it arrived and the peer's own.
async fn mss(
    tunnel: &UnixDatagram,
    from: SocketAddr,
    to: SocketAddr,
) -> Result<(u16, u16), Box<dyn std::error::Error>> {
    let isn = 0x3000_0000u32;
    let mut syn = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn, 64_240)
        .syn()
        .options(&[TcpOptionElement::MaximumSegmentSize(1_460)])?
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
    let offered = header
        .options_iterator()
        .find_map(|o| match o {
            Ok(TcpOptionElement::MaximumSegmentSize(n)) => Some(n),
            _ => None,
        })
        .ok_or("a SYN-ACK without an MSS")?;
    let mut ack = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn.wrapping_add(1), 64_240)
        .ack(header.sequence_number.wrapping_add(1))
        .write(&mut ack, &[])?;
    tunnel.send(&ack).await?;
    let data = next(tunnel, |p| {
        tcp(p).is_some_and(|(_, payload)| !payload.is_empty())
    })
    .await?;
    let (_, payload) = tcp(&data).ok_or("unread")?;
    let text = String::from_utf8_lossy(&payload).into_owned();
    let mut reset = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn.wrapping_add(1), 0)
        .rst()
        .write(&mut reset, &[])?;
    tunnel.send(&reset).await?;
    let largest = text
        .trim()
        .strip_prefix("mss ")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("the MSS service said {text}"))?;
    Ok((offered, largest))
}

/// A UDP datagram of `size` bytes in all, IP header included, from the app at `from` to `to`, which may not
/// be fragmented: IPv4's "don't fragment" set; `IPv6` routers never fragment.
fn datagram_of(from: SocketAddr, to: SocketAddr, size: usize) -> Option<Vec<u8>> {
    let header = if from.is_ipv4() { 20 + 8 } else { 40 + 8 };
    let mut datagram = packet::udp(from, to, &vec![0x6c; size.checked_sub(header)?])?;
    if from.is_ipv4() {
        datagram[6] |= 0x40;
        datagram[10..12].fill(0);
        let sum = datagram[..20]
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum::<u32>();
        let folded = (sum & 0xffff) + (sum >> 16);
        let folded = (folded & 0xffff) + (folded >> 16);
        let checksum = !u16::try_from(folded).ok()?;
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    Some(datagram)
}

/// A packet's source address, read from its IP header.
fn source_of(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?)),
        6 => Some(IpAddr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?)),
        _ => None,
    }
}

/// The path MTU an ICMP error to the app says: IPv4's "fragmentation needed" or `ICMPv6`'s "packet too big",
/// with the source it comes from. The engine's own errors carry no IPv4 options or `IPv6` extension headers.
fn too_big_said(packet: &[u8]) -> Option<(IpAddr, u32)> {
    let source = source_of(packet)?;
    let (icmp, kind) = if source.is_ipv4() {
        (packet.get(20..)?, (1, 3, 4))
    } else {
        (packet.get(40..)?, (58, 2, 0))
    };
    let protocol = if source.is_ipv4() {
        packet.get(9)?
    } else {
        packet.get(6)?
    };
    if (*protocol, *icmp.first()?, *icmp.get(1)?) != kind {
        return None;
    }
    let said = if source.is_ipv4() {
        u32::from(u16::from_be_bytes([*icmp.get(6)?, *icmp.get(7)?]))
    } else {
        u32::from_be_bytes(icmp.get(4..8)?.try_into().ok()?)
    };
    Some((source, said))
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
async fn the_mtu_holds_on_the_path_to_the_kernel_peer() -> Outcome {
    // A configuration's MTU of 1,280, below the peer's own 1,420, so that the clamp is what the peer reads.
    let config = client_with(
        &setting("WGLAB_PLAIN")?,
        ("10.77.0.2", "fd77::2"),
        &setting("WGLAB_PEER")?,
        &setting("WGLAB_PEER_PUBLIC")?,
        None,
        "MTU = 1280\n",
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
        // The largest segment a 1,280-byte packet carries: 1,240 in IPv4, 1,220 in IPv6.
        let clamp = if v6 { 1_220 } else { 1_240 };
        let (offered, largest) =
            mss(&tunnel, app(v6, 40_060 + u16::from(v6)), peer(v6, 9001)).await?;
        assert_eq!(
            largest, clamp,
            "{version}: the peer's kernel took the SYN's MSS as {largest}"
        );
        assert!(
            offered <= clamp,
            "{version}: the app got the SYN-ACK's MSS as {offered}"
        );
        println!(
            "PASS mss-{version}: the SYN's MSS of 1460 reached the peer's kernel as {largest}, the SYN-ACK's the app as {offered}"
        );
        let from = app(v6, 40_070 + u16::from(v6));
        let whole = udp_whole(&tunnel, from, peer(v6, 7), 1_280).await?;
        assert_eq!(whole, 1_280 - if v6 { 48 } else { 28 }, "{version}");
        tunnel
            .send(&datagram_of(from, peer(v6, 7), 1_281).ok_or("datagram")?)
            .await?;
        let error = next(&tunnel, |p| too_big_said(p).is_some()).await?;
        assert_eq!(
            too_big_said(&error),
            Some((peer(v6, 7).ip(), 1_280)),
            "{version}: the error names the destination and the MTU"
        );
        println!(
            "PASS too-big-{version}: a datagram of 1280 bytes passed whole to the peer and back; one of 1281 got the app the error with 1280"
        );
    }
    let counters = engine.counters();
    assert_eq!(counters[TUNNEL_TOO_BIG], 2, "{counters:?}");
    Ok(())
}

/// A datagram of `size` bytes in all, which may not be fragmented, from the app at `from` to the echo at
/// `to`, and the size of the echo's payload.
async fn udp_whole(
    tunnel: &UnixDatagram,
    from: SocketAddr,
    to: SocketAddr,
    size: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    tunnel
        .send(&datagram_of(from, to, size).ok_or("datagram")?)
        .await?;
    let answer = next(tunnel, |p| udp_from(p, to).is_some()).await?;
    Ok(udp_from(&answer, to).ok_or("no payload")?.len())
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
