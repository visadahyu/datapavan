//! W7's interoperation lab through the engine itself (ADR 0035, "Tests without a provider"): Watch's engine on
//! a pair of datagram sockets for its tunnel, its `WireGuard` tunnels to peers of both reference implementations,
//! the Linux kernel's `WireGuard` and wireguard-go, in the Compose project `datapavan-wglab`. Chosen apps' TCP,
//! UDP, ICMP and DNS on IPv4 and IPv6, a packet from outside `AllowedIPs` refused, a `PresharedKey`, two tunnels
//! at once to two peers, the MTU's second way (a SYN's MSS clamped as the peer's kernel takes it, a datagram
//! larger than the configuration's MTU answered with "fragmentation needed" or "packet too big", and one of the
//! MTU's size passing whole to the peer and back), a server at an IPv6 address, and no session with a wrong
//! preshared key or a wrong key for the peer, where the right one makes one. Each runs against one
//! implementation at a time, the one `WGLAB_IMPL` names.
//!
//! The `long_` tests take minutes and run against both implementations at once (W7, part 3a): a rekey 120 s after
//! the first handshake, keepalives on time both ways, and a cookie reply under a flood of initiations, each through
//! the engine.
//!
//! Ignored by default: `scripts/wglab.sh` (`scripts/check.sh wglab`) starts the peers, makes the clients' keys
//! with the peers' own `wg`, and runs these with the settings in the environment (`WGLAB_*`), the `long_` ones
//! with `WGLAB_LONG=1`. What the peers saw is read with `docker exec` and `wg show`.
#![cfg(target_os = "linux")]

use datapavan_net::engine::{Addresses, Configured, Limits, TunnelSetting};
use datapavan_net::wireguard::config::Config as WgConfig;
use datapavan_net::wireguard::core::{Core, GotaTun};
use datapavan_net::{Config, Engine, Platform, packet};
use etherparse::{
    IcmpEchoHeader, Icmpv4Type, Icmpv6Type, PacketBuilder, SlicedPacket, TcpOptionElement,
    TransportSlice,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UnixDatagram;

type Outcome = Result<(), Box<dyn std::error::Error>>;

const FIRST: u32 = 10_300;
const SECOND: u32 = 10_301;
const THIRD: u32 = 10_302;
const FOURTH: u32 = 10_303;
/// The peers' addresses inside their tunnels (spikes/wireguard-core/peer/start.sh).
const PEER4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 1);
const TUNNEL_FILTERED: usize = 54;
const TUNNEL_TOO_BIG: usize = 57;
const TUNNEL_HANDSHAKES: usize = 59;
const TUNNEL_REJECTED: usize = 60;
const STEP: Duration = Duration::from_secs(8);
/// What the long checks run against, in their settings' names: `WGLAB_KERNEL_*`, `WGLAB_GO_*`.
const REFERENCES: [&str; 2] = ["KERNEL", "GO"];

struct ByPort;

impl Platform for ByPort {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() {
            40_000..=40_999 => Some(FIRST),
            41_000..=41_999 => Some(SECOND),
            42_000..=42_999 => Some(THIRD),
            43_000..=43_999 => Some(FOURTH),
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

/// A long check's setting for one reference: `WGLAB_<reference>_<name>`.
fn of(reference: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    setting(&format!("WGLAB_{reference}_{name}"))
}

/// What a peer's `wg` says, through `docker exec` in the peer's container: what the peer itself saw.
fn peer_wg(container: &str, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("docker")
        .arg("exec")
        .arg(container)
        .arg("wg")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docker exec {container} wg {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// What the peer's `wg show wg0 <field>` gives for the client whose public key is `public`.
fn peer_field(
    container: &str,
    field: &str,
    public: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    peer_wg(container, &["show", "wg0", field])?
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(public)).then(|| words.next().unwrap_or_default().to_owned())
        })
        .ok_or_else(|| format!("the peer has no client {public}").into())
}

/// When the peer's last handshake with the client `public` completed, in seconds since 1970; 0 for never.
fn peer_handshake(container: &str, public: &str) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(peer_field(container, "latest-handshakes", public)?.parse()?)
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
    addresses: (&str, &str),
    peer: &str,
    public: &str,
    psk: Option<&str>,
    interface: &str,
) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    let psk = psk.map_or_else(String::new, |psk| format!("PresharedKey = {psk}\n"));
    configuration(key, addresses, peer, public, interface, &psk)
}

/// The lab's client configuration with `interface` more lines for its `[Interface]` and `more` for its `[Peer]`.
fn configuration(
    key: &str,
    (v4, v6): (&str, &str),
    peer: &str,
    public: &str,
    interface: &str,
    more: &str,
) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    let text = format!(
        "[Interface]\nPrivateKey = {key}\nAddress = {v4}/32, {v6}/128\nDNS = 10.77.0.1, fd77::1\n{interface}\n\
         [Peer]\nPublicKey = {public}\n{more}AllowedIPs = 10.77.0.0/24, fd77::/64\nEndpoint = {peer}\n"
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
    next_within(tunnel, want, STEP).await
}

/// [`next`], within `within`.
async fn next_within(
    tunnel: &UnixDatagram,
    want: impl Fn(&[u8]) -> bool,
    within: Duration,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let deadline = tokio::time::Instant::now() + within;
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
    // The reset at the next sequence number, after the SYN's one and the request's 31: one past it, the peer's
    // kernel would answer it with an ACK and keep the connection (RFC 5961, 3.2).
    let mut reset = Vec::new();
    builder(from.ip(), to.ip())?
        .tcp(from.port(), to.port(), isn.wrapping_add(32), 0)
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
    let host = setting("WGLAB_PEER_HOST")?;
    for v6 in [false, true] {
        let version = if v6 { "IPv6" } else { "IPv4" };
        let text = http(&tunnel, app(v6, 40_001 + u16::from(v6)), peer(v6, 80)).await?;
        let own = if v6 { "fd77::2" } else { "10.77.0.2" };
        // The answer's head and its body, which names the peer and the address it saw.
        assert!(
            text.starts_with("HTTP/1.0 200") && text.contains(&format!("{host} {own}")),
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
            seen.starts_with(&format!("{own} {} {host}", 40_020 + u16::from(v6))),
            "{seen}"
        );
        println!(
            "PASS udp-{version}: echoed, and the peer saw {}",
            seen.trim()
        );
        ping(&tunnel, peer(v6, 0).ip(), 1 + u16::from(v6)).await?;
        println!("PASS icmp-{version}: the peer's echo reply came back");
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
async fn the_mtu_holds_on_the_path_to_the_peer() -> Outcome {
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
    let (host, host2) = (setting("WGLAB_PEER_HOST")?, setting("WGLAB_PEER2_HOST")?);
    let one = udp(&tunnel, app(false, 40_050), peer(false, 8), b"who").await?;
    let two = udp(&tunnel, app(false, 41_050), peer(false, 8), b"who").await?;
    let (one, two) = (
        String::from_utf8_lossy(&one).into_owned(),
        String::from_utf8_lossy(&two).into_owned(),
    );
    assert!(one.starts_with(&format!("10.77.0.2 40050 {host}")), "{one}");
    assert!(
        two.starts_with(&format!("10.77.0.4 41050 {host2}")),
        "{two}"
    );
    let text = http(&tunnel, app(true, 41_051), peer(true, 80)).await?;
    assert!(text.contains(&format!("{host2} fd77::4")), "{text}");
    println!(
        "PASS two-tunnels: the first app reached {host} as 10.77.0.2, the second {host2} as 10.77.0.4 and fd77::4"
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

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the lab's peers: scripts/wglab.sh"]
async fn a_server_at_an_ipv6_address_carries_both_versions() -> Outcome {
    // The peer's own IPv6 address on the lab's network, as the configuration's endpoint (W7, part 3a).
    let config = client(
        &setting("WGLAB_SIX")?,
        ("10.77.0.5", "fd77::5"),
        &setting("WGLAB_PEER6")?,
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
    let host = setting("WGLAB_PEER_HOST")?;
    let steps = async {
        for v6 in [false, true] {
            let own = if v6 { "fd77::5" } else { "10.77.0.5" };
            let seen = udp(
                &tunnel,
                app(v6, 40_080 + u16::from(v6)),
                peer(v6, 8),
                b"who",
            )
            .await?;
            let seen = String::from_utf8_lossy(&seen).into_owned();
            assert!(seen.starts_with(&format!("{own} ")), "{seen}");
            let text = http(&tunnel, app(v6, 40_082 + u16::from(v6)), peer(v6, 80)).await?;
            assert!(text.contains(&format!("{host} {own}")), "{text}");
            ping(&tunnel, peer(v6, 0).ip(), 20 + u16::from(v6)).await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    steps.await.inspect_err(|_| explain(&engine))?;
    let endpoint = peer_field(
        &setting("WGLAB_PEER_CONTAINER")?,
        "endpoints",
        &setting("WGLAB_SIX_PUBLIC")?,
    )?;
    let at: SocketAddr = endpoint.parse()?;
    assert!(at.is_ipv6(), "the peer has the client at {endpoint}");
    assert!(
        engine
            .tunnel_states()
            .first()
            .is_some_and(|s| s.handshake.is_some()),
        "no session"
    );
    println!(
        "PASS ipv6-server: UDP, TCP and ICMP on both versions through a server at an IPv6 address, which has the engine's socket at an IPv6 address"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the lab's peers: scripts/wglab.sh"]
async fn a_wrong_preshared_key_or_peer_key_makes_no_session_and_the_right_one_does() -> Outcome {
    let (endpoint, public, other) = (
        setting("WGLAB_PEER")?,
        setting("WGLAB_PEER_PUBLIC")?,
        setting("WGLAB_PEER2_PUBLIC")?,
    );
    let container = setting("WGLAB_PEER_CONTAINER")?;
    let (psk_key, psk_public) = (
        setting("WGLAB_WRONG_PSK_KEY")?,
        setting("WGLAB_WRONG_PSK_PUBLIC")?,
    );
    let (peer_key, peer_public) = (
        setting("WGLAB_WRONG_PEER_KEY")?,
        setting("WGLAB_WRONG_PEER_PUBLIC")?,
    );
    let addresses = (("10.77.0.6", "fd77::6"), ("10.77.0.7", "fd77::7"));
    // Two tunnels at once: one with a preshared key the peer does not hold for its client, one that gives the second
    // peer's public key for the first peer's server, as a configuration for another server would. Each app sends,
    // and nothing comes back while the core sends its initiation and, 5 s later, the next.
    let wrong = vec![
        Configured {
            id: 1,
            config: client(
                &psk_key,
                addresses.0,
                &endpoint,
                &public,
                Some(&setting("WGLAB_WRONG_PSK")?),
            )?,
            local_network: false,
        },
        Configured {
            id: 2,
            config: client(&peer_key, addresses.1, &endpoint, &other, None)?,
            local_network: false,
        },
    ];
    let (wrong_engine, wrong_tunnel) = engine(wrong, &[(FIRST, 1), (SECOND, 2)])?;
    for from in [40_090, 41_090] {
        wrong_tunnel
            .send(&packet::udp(app(false, from), peer(false, 7), b"none").ok_or("datagram")?)
            .await?;
    }
    let echo_back = |p: &[u8]| udp_from(p, peer(false, 7)).is_some();
    assert!(
        next_within(&wrong_tunnel, echo_back, Duration::from_secs(7))
            .await
            .is_err(),
        "an answer came through a tunnel with a wrong key"
    );
    let states = wrong_engine.tunnel_states();
    let state = |id| states.iter().find(|s| s.id == id).ok_or("no state");
    let (psk_state, peer_state) = (state(1)?, state(2)?);
    assert!(
        psk_state.handshake.is_none() && psk_state.error == Some("aead"),
        "{psk_state:?}"
    );
    assert!(
        peer_state.handshake.is_none() && peer_state.not_answering && peer_state.error.is_none(),
        "{peer_state:?}"
    );
    let counters = wrong_engine.counters();
    assert!(
        counters[TUNNEL_HANDSHAKES] >= 4 && counters[TUNNEL_REJECTED] >= 1,
        "{counters:?}"
    );
    for (client_public, which) in [(&psk_public, "preshared"), (&peer_public, "peer")] {
        assert_eq!(
            peer_handshake(&container, client_public)?,
            0,
            "the peer has a handshake with the wrong {which} key's client"
        );
    }
    println!(
        "PASS wrong-preshared-key: the peer's responses were refused (aead), no session at either end"
    );
    println!(
        "PASS wrong-peer-key: the peer answered no initiation, the tunnel says its server does not answer, no session at either end"
    );
    drop((wrong_engine, wrong_tunnel));
    // The control: the same clients with the right keys make their sessions.
    the_right_keys_make_sessions(
        &endpoint,
        &public,
        addresses,
        [(&psk_key, &psk_public), (&peer_key, &peer_public)],
    )
    .await
}

/// The negative check's control: its two clients, each a key and its public key, the first with the peer's preshared
/// key and the second with the peer's own public key, make their sessions, seen at both ends.
async fn the_right_keys_make_sessions(
    endpoint: &str,
    public: &str,
    addresses: ((&str, &str), (&str, &str)),
    [(psk_key, psk_public), (peer_key, peer_public)]: [(&str, &str); 2],
) -> Outcome {
    let container = setting("WGLAB_PEER_CONTAINER")?;
    let right = vec![
        Configured {
            id: 1,
            config: client(
                psk_key,
                addresses.0,
                endpoint,
                public,
                Some(&setting("WGLAB_PSK")?),
            )?,
            local_network: false,
        },
        Configured {
            id: 2,
            config: client(peer_key, addresses.1, endpoint, public, None)?,
            local_network: false,
        },
    ];
    let (_engine, tunnel) = engine(right, &[(FIRST, 1), (SECOND, 2)])?;
    for from in [40_091, 41_091] {
        let echoed = udp(&tunnel, app(false, from), peer(false, 7), b"right").await?;
        assert_eq!(echoed, b"right");
    }
    for (client_public, which) in [(psk_public, "preshared"), (peer_public, "peer")] {
        assert!(
            peer_handshake(&container, client_public)? > 0,
            "the peer has no handshake with the right {which} key's client"
        );
    }
    println!(
        "PASS right-keys: the same clients with the right keys make their sessions and are answered"
    );
    Ok(())
}

/// What the engine says of its tunnels, for a step that failed.
fn explain(engine: &Engine) {
    eprintln!(
        "the engine's tunnels: {:?}\nits counters: {:?}",
        engine.tunnel_states(),
        engine.counters()
    );
}

/// The tunnel's session: when its handshake completed, as time since `start`.
fn session_made(engine: &Engine, id: u32, start: Instant) -> Option<Duration> {
    let age = engine
        .tunnel_states()
        .into_iter()
        .find(|s| s.id == id)?
        .handshake?;
    start.elapsed().checked_sub(age)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "takes minutes: scripts/wglab.sh with WGLAB_LONG=1"]
async fn long_a_rekey_two_minutes_after_the_first_handshake_with_both_references() -> Outcome {
    // One engine, a tunnel to each reference; each app sends an echo every two seconds through its tunnel.
    let mut tunnels = Vec::new();
    let mut ids = Vec::new();
    for (n, reference) in (1u32..).zip(REFERENCES) {
        let v4 = format!("10.77.0.{}", 7 + n);
        let v6 = format!("fd77::{}", 7 + n);
        tunnels.push(Configured {
            id: n,
            config: client(
                &of(reference, "REKEY")?,
                (&v4, &v6),
                &of(reference, "PEER")?,
                &of(reference, "PUBLIC")?,
                None,
            )?,
            local_network: false,
        });
        ids.push((n, reference));
    }
    let (engine, tunnel) = engine(tunnels, &[(FIRST, 1), (SECOND, 2)])?;
    let start = Instant::now();
    let mut first = [None::<Duration>; 2];
    let mut again = [None::<Duration>; 2];
    let mut seen_first = [0u64; 2];
    let mut rounds = 0u32;
    while start.elapsed() < Duration::from_secs(150) && again.iter().any(Option::is_none) {
        for (slot, from) in [(0usize, 40_200u16), (1, 41_200)] {
            let payload = format!("rekey {rounds}");
            let echoed = udp(
                &tunnel,
                app(false, from),
                peer(false, 7),
                payload.as_bytes(),
            )
            .await?;
            assert_eq!(echoed, payload.as_bytes(), "{}", REFERENCES[slot]);
        }
        rounds += 1;
        for (n, reference) in &ids {
            let slot = *n as usize - 1;
            let Some(made) = session_made(&engine, *n, start) else {
                continue;
            };
            match (first[slot], again[slot]) {
                (None, _) => {
                    first[slot] = Some(made);
                    seen_first[slot] = peer_handshake(
                        &of(reference, "CONTAINER")?,
                        &of(reference, "REKEY_PUBLIC")?,
                    )?;
                }
                (Some(f), None) if made > f + Duration::from_secs(1) => again[slot] = Some(made),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    for (n, reference) in &ids {
        let slot = *n as usize - 1;
        let (Some(f), Some(a)) = (first[slot], again[slot]) else {
            return Err(format!("{reference}: no new session within 150 s").into());
        };
        let after = a.saturating_sub(f);
        assert!(
            (Duration::from_secs(120)..=Duration::from_secs(125)).contains(&after),
            "{reference}: the new session came {after:?} after the first"
        );
        let peer_saw = peer_handshake(
            &of(reference, "CONTAINER")?,
            &of(reference, "REKEY_PUBLIC")?,
        )?
        .saturating_sub(seen_first[slot]);
        assert!(
            (119..=126).contains(&peer_saw),
            "{reference}: the peer's handshake moved on by {peer_saw} s"
        );
        println!(
            "PASS rekey [{}]: the engine began a new session {:.1} s after the first, the peer's moved on by {peer_saw} s, all {rounds} rounds answered across it",
            reference.to_lowercase(),
            after.as_secs_f64()
        );
    }
    Ok(())
}

/// Every `wg show wg0 transfer` of the peer in `container`, a tenth of a second apart for `seconds`, each line with
/// the peer's own clock: `<seconds since 1970> <client> <received> <sent>`. Started now; read with `wait`.
fn sample_transfer(container: &str, seconds: u32) -> io::Result<std::process::Child> {
    Command::new("docker")
        .arg("exec")
        .arg(container)
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "end=$(( $(date +%s) + {seconds} )); while [ \"$(date +%s)\" -lt \"$end\" ]; do \
             t=$(date +%s.%N); wg show wg0 transfer | sed \"s/^/$t /\"; sleep 0.1; done"
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
}

/// When the client `public` sent the peer anything, from [`sample_transfer`]'s lines: the peer's times at which
/// what it received from the client grew.
fn grew(lines: &str, public: &str) -> Vec<f64> {
    let mut last = None;
    let mut times = Vec::new();
    for line in lines.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (Some(at), Some(key), Some(received)) = (words.first(), words.get(1), words.get(2))
        else {
            continue;
        };
        if *key != public {
            continue;
        }
        let (Ok(at), Ok(received)) = (at.parse::<f64>(), received.parse::<u64>()) else {
            continue;
        };
        if last.is_some_and(|l| received > l) {
            times.push(at);
        }
        last = Some(received);
    }
    times
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "takes minutes: scripts/wglab.sh with WGLAB_LONG=1"]
async fn long_keepalives_on_time_both_ways_with_both_references() -> Outcome {
    // For each reference two tunnels: one whose configuration asks for a keepalive every 5 s, to a peer that sends
    // none, whose arrivals the peer's counters time; and one with none, to a peer that sends one every 3 s, which
    // the engine's state times. Either side's keepalive starts the other's period anew, so they are apart.
    let mut tunnels = Vec::new();
    let mut routes = Vec::new();
    for (n, reference) in (0u32..).zip(REFERENCES) {
        for (k, name, keepalive) in [
            (0u32, "KEEPALIVE", "PersistentKeepalive = 5\n"),
            (1, "PEER_KEEPALIVE", ""),
        ] {
            let id = 2 * n + k + 1;
            let v4 = format!("10.77.0.{}", 9 + id);
            let v6 = format!("fd77::{}", 9 + id);
            tunnels.push(Configured {
                id,
                config: configuration(
                    &of(reference, name)?,
                    (&v4, &v6),
                    &of(reference, "PEER")?,
                    &of(reference, "PUBLIC")?,
                    "",
                    keepalive,
                )?,
                local_network: false,
            });
            routes.push((FIRST + id - 1, id));
        }
    }
    let (engine, tunnel) = engine(tunnels, &routes)?;
    for (base, n) in [(40_300u16, 1u32), (41_300, 2), (42_300, 3), (43_300, 4)] {
        let echoed = udp(&tunnel, app(false, base), peer(false, 7), b"alive").await?;
        assert_eq!(echoed, b"alive", "tunnel {n}");
    }
    // Then nothing from the apps for 21 s.
    let quiet = 21;
    let samplers = REFERENCES
        .iter()
        .map(|r| sample_transfer(&of(r, "CONTAINER")?, quiet).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let start = Instant::now();
    let mut longest = [Duration::ZERO; 2];
    let mut arrivals = [0u32; 2];
    let mut last = [None::<Duration>; 2];
    while start.elapsed() < Duration::from_secs(u64::from(quiet)) {
        for state in engine.tunnel_states() {
            if state.id % 2 == 1 {
                continue;
            }
            let slot = state.id as usize / 2 - 1;
            let Some(age) = state.received else { continue };
            longest[slot] = longest[slot].max(age);
            if last[slot].is_some_and(|l| age + Duration::from_millis(500) < l) {
                arrivals[slot] += 1;
            }
            last[slot] = Some(age);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for (slot, (reference, sampler)) in REFERENCES.iter().zip(samplers).enumerate() {
        let output = sampler.wait_with_output()?;
        let lines = String::from_utf8(output.stdout)?;
        let times = grew(&lines, &of(reference, "KEEPALIVE_PUBLIC")?);
        let apart: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        let name = reference.to_lowercase();
        assert!(
            times.len() >= 3 && apart.iter().all(|a| (4.5..=6.6).contains(a)),
            "{name}: the engine's keepalives reached the peer at {times:?}"
        );
        println!(
            "PASS keepalive-sent [{name}]: {} of the engine's keepalives reached the peer in {quiet} s of silence, {:.1} to {:.1} s apart (configured 5 s, the timers' tick 1 s)",
            times.len(),
            apart.iter().copied().fold(f64::MAX, f64::min),
            apart.iter().copied().fold(0.0, f64::max)
        );
        assert!(
            arrivals[slot] >= 5 && longest[slot] <= Duration::from_secs(5),
            "{name}: the peer's keepalives reached the engine {} times, the longest silence {:?}",
            arrivals[slot],
            longest[slot]
        );
        println!(
            "PASS keepalive-received [{name}]: {} of the peer's keepalives (every 3 s) reached the engine in {quiet} s, the longest silence {:.1} s",
            arrivals[slot],
            longest[slot].as_secs_f64()
        );
    }
    Ok(())
}

/// A flood of handshake initiations at one peer (W7, part 3a): a burst every [`FLOOD_PERIOD`] from several
/// threads, each burst led by a probe of its own, an initiation whose sender index no other carries. Every
/// initiation has a valid MAC for the peer, made by `GotaTun` for a key the peer does not know, so the peer
/// does the work of a handshake for it, or, under load, answers it with a cookie reply. A probe answered so shows
/// the peer under load as its burst came. Between bursts nothing comes that could count it under load again, so
/// where the probes of the bursts on either side of a moment were both answered, the peer was under load at that
/// moment ([`Flood::loaded_at`]).
///
/// Under load a peer answers fast, so a burst counts it under load again only if it comes faster than the peer
/// answers: the burst grows ([`Flood::grow`]) until every probe is answered, within a bound below where the peer's
/// queue would drop the engine's own initiation. On a machine with many cores the peer may still lapse out of load
/// now and then for a moment, until the next burst.
struct Flood {
    stop: Arc<AtomicBool>,
    burst: Arc<std::sync::atomic::AtomicUsize>,
    threads: Vec<std::thread::JoinHandle<()>>,
    /// The probes' sender indices, in the order sent, with when.
    sent: Arc<Mutex<Vec<(u32, Instant)>>>,
    /// When cookie replies came, by the sender index they name.
    answered: Arc<Mutex<HashMap<u32, Vec<Instant>>>>,
    replies: Arc<AtomicU64>,
}

const FLOOD_PERIOD: Duration = Duration::from_millis(100);

fn index_of(datagram: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(datagram.get(4..8)?.try_into().ok()?))
}

impl Flood {
    fn start(
        target: SocketAddr,
        initiations: &[Vec<u8>],
        burst: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = std::net::UdpSocket::bind(packet::unspecified_like(&target))?;
        socket.connect(target)?;
        let socket = Arc::new(socket);
        let fillers = std::thread::available_parallelism()
            .map_or(2, std::num::NonZero::get)
            .div_ceil(2)
            .clamp(2, 12);
        let (filler, probes) = initiations.split_first().ok_or("no initiation")?;
        let filler = Arc::new(filler.clone());
        let probes = probes.to_vec();
        let stop = Arc::new(AtomicBool::new(false));
        let size = Arc::new(std::sync::atomic::AtomicUsize::new(burst));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let answered = Arc::new(Mutex::new(HashMap::<u32, Vec<Instant>>::new()));
        let replies = Arc::new(AtomicU64::new(0));
        let barrier = Arc::new(Barrier::new(fillers + 1));
        let mut threads = Vec::new();
        // The reader: cookie replies are 64 bytes of type 3, naming the initiation's sender index.
        let reader = socket.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_millis(50)))?;
        let (r_stop, r_answered, r_replies) = (stop.clone(), answered.clone(), replies.clone());
        threads.push(std::thread::spawn(move || {
            let mut buffer = [0u8; 256];
            while !r_stop.load(Ordering::Relaxed) {
                if let Ok(n) = reader.recv(&mut buffer)
                    && n == 64
                    && buffer[0] == 3
                    && let Some(index) = index_of(&buffer[..n])
                {
                    r_replies.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut answered) = r_answered.lock() {
                        let times = answered.entry(index).or_default();
                        if times.len() < 4 {
                            times.push(Instant::now());
                        }
                    }
                }
            }
        }));
        for _ in 0..fillers {
            let (f_socket, f_stop, f_barrier, f_filler, f_size) = (
                socket.clone(),
                stop.clone(),
                barrier.clone(),
                filler.clone(),
                size.clone(),
            );
            threads.push(std::thread::spawn(move || {
                loop {
                    f_barrier.wait();
                    if f_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    for _ in 0..f_size.load(Ordering::Relaxed) / fillers {
                        let _ = f_socket.send(&f_filler);
                    }
                    f_barrier.wait();
                }
            }));
        }
        let (p_stop, p_sent) = (stop.clone(), sent.clone());
        threads.push(std::thread::spawn(move || {
            for probe in probes.iter().cycle() {
                if p_stop.load(Ordering::Relaxed) {
                    break;
                }
                if socket.send(probe).is_ok()
                    && let (Some(index), Ok(mut sent)) = (index_of(probe), p_sent.lock())
                {
                    sent.push((index, Instant::now()));
                }
                barrier.wait();
                barrier.wait();
                std::thread::sleep(FLOOD_PERIOD);
            }
            barrier.wait();
        }));
        Ok(Self {
            stop,
            burst: size,
            threads,
            sent,
            answered,
            replies,
        })
    }

    /// The probes sent from `since` on, the last left out, whose answer may not have come yet: each with whether a
    /// cookie reply answered it.
    fn probes(&self, since: Instant) -> Vec<(Instant, bool)> {
        let (Ok(sent), Ok(answered)) = (self.sent.lock(), self.answered.lock()) else {
            return Vec::new();
        };
        let mut probes: Vec<(Instant, bool)> = sent
            .iter()
            .filter(|(_, at)| *at >= since)
            .map(|(index, at)| {
                let replied = answered
                    .get(index)
                    .is_some_and(|times| times.iter().any(|t| t >= at));
                (*at, replied)
            })
            .collect();
        probes.pop();
        probes
    }

    /// Whether the peer was under load at `at`: the probes of the bursts just before and just after it both answered.
    /// `None` until the probe after it has had its time to be answered.
    fn loaded_at(&self, at: Instant) -> Option<bool> {
        let probes = self.probes(at.checked_sub(FLOOD_PERIOD * 3).unwrap_or(at));
        let before = probes.iter().rev().find(|(sent, _)| *sent <= at)?;
        let after = probes.iter().find(|(sent, _)| *sent > at)?;
        Some(before.1 && after.1)
    }

    /// The burst grows by half, up to `largest`, while a probe of the last `streak` went unanswered: until the peer
    /// stays under load. `Ok` with the burst once `streak` probes in a row since the last growth were answered, or, at
    /// the largest burst, nine in ten of them, the moments the peer lapsed out of load left to [`Flood::loaded_at`].
    async fn grow(&self, largest: usize, streak: usize) -> Result<usize, String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut since = Instant::now();
        while Instant::now() < deadline {
            tokio::time::sleep(FLOOD_PERIOD).await;
            let probes = self.probes(since);
            let burst = self.burst.load(Ordering::Relaxed);
            let answered = probes.iter().filter(|(_, replied)| *replied).count();
            let lapsed = answered > 0 && answered < probes.len();
            if probes.len() >= streak && answered == probes.len() {
                return Ok(burst);
            }
            if burst >= largest && probes.len() >= streak && answered * 10 >= probes.len() * 9 {
                return Ok(burst);
            }
            if burst < largest && (lapsed || probes.len() >= streak) {
                self.burst
                    .store((burst + burst / 2).min(largest), Ordering::Relaxed);
                since = Instant::now();
            }
        }
        Err("the flood did not put the peer under load in 30 s".into())
    }

    /// Stops it, and says how many probes were sent from `since` to its end, how many of them no cookie reply
    /// answered, and how many cookie replies came in all.
    fn stop(self, since: Instant) -> Result<(usize, usize, u64), Box<dyn std::error::Error>> {
        let probes = self.probes(since);
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            thread.join().map_err(|_| "a flood thread failed")?;
        }
        let unanswered = probes.iter().filter(|(_, replied)| !replied).count();
        Ok((
            probes.len(),
            unanswered,
            self.replies.load(Ordering::Relaxed),
        ))
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "takes minutes: scripts/wglab.sh with WGLAB_LONG=1"]
async fn long_a_cookie_reply_under_a_flood_of_initiations_with_each_reference() -> Outcome {
    // The kernel counts itself under load at 512 queued handshakes (MAX_QUEUED_INCOMING_HANDSHAKES / 8), wireguard-go
    // at 128 (QueueHandshakeSize / 8), each for a second after. The bursts start well above that and stay below
    // where either queue drops (the kernel's at 4,096, wireguard-go's at 1,024).
    for (reference, first, largest) in [("KERNEL", 1_000usize, 3_600usize), ("GO", 300, 900)] {
        let name = reference.to_lowercase();
        let (endpoint, public) = (of(reference, "PEER")?, of(reference, "PUBLIC")?);
        let target: SocketAddr = endpoint.parse()?;
        let stranger = client(
            &of(reference, "FLOOD")?,
            ("10.77.0.99", "fd77::99"),
            &endpoint,
            &public,
            None,
        )?;
        let mut initiations = Vec::new();
        let mut indices = std::collections::HashSet::new();
        while initiations.len() < 600 {
            let initiation = GotaTun::new(&stranger).handshake().ok_or("no initiation")?;
            if index_of(&initiation).is_some_and(|i| indices.insert(i)) {
                initiations.push(initiation);
            }
        }
        let flood = Flood::start(target, &initiations, first)?;
        let started = Instant::now();
        let burst = match flood.grow(largest, 20).await {
            Ok(burst) => burst,
            Err(why) => {
                let _ = flood.stop(Instant::now());
                return Err(format!("{name}: {why}").into());
            }
        };
        // The engine's first initiation comes now, the peer under load: a cookie reply answers it, and only the next,
        // 5 s later, carrying the cookie's MAC, makes the session. Where the peer lapsed out of load next to either
        // initiation the attempt shows nothing either way, and the engine tries again, three times at most.
        let mut shown = None;
        for attempt in 1..=3 {
            let outcome = cookie_attempt(reference, &endpoint, &public, &flood).await;
            match outcome {
                Ok(Some(found)) => {
                    shown = Some((attempt, found));
                    break;
                }
                Ok(None) => {}
                Err(why) => {
                    let _ = flood.stop(Instant::now());
                    return Err(format!("{name}: {why}").into());
                }
            }
        }
        let (probes, unanswered, replies) = flood.stop(started)?;
        let Some((attempt, (up, handshakes))) = shown else {
            return Err(format!(
                "{name}: in three attempts the peer lapsed out of load next to the engine's initiations ({unanswered} of {probes} probes unanswered)"
            )
            .into());
        };
        println!(
            "PASS cookie [{name}]: the peer under load at the engine's initiations (bursts of {burst} every 0.1 s; {} of the flood's {probes} probes answered with cookie replies, {replies} replies in all), a cookie reply answered the engine's first, and its initiation {handshakes}, carrying the cookie, made the session {:.1} s in (attempt {attempt})",
            probes - unanswered,
            up.as_secs_f64()
        );
    }
    Ok(())
}

/// One attempt of the engine's under a flood: a fresh engine whose app sends an echo through a tunnel to the peer.
/// `Some` with when its session came and after how many initiations, where the peer was under load at its first
/// initiation and at the one that made the session, and that was not the first; `None` where the peer lapsed out of
/// load next to either; an error where the engine made no session, or made it at its first initiation though the
/// peer was under load.
async fn cookie_attempt(
    reference: &str,
    endpoint: &str,
    public: &str,
    flood: &Flood,
) -> Result<Option<(Duration, u64)>, String> {
    let config = client(
        &of(reference, "COOKIE").map_err(|e| e.to_string())?,
        ("10.77.0.14", "fd77::14"),
        endpoint,
        public,
        None,
    )
    .map_err(|e| e.to_string())?;
    let (engine, tunnel) = engine(
        vec![Configured {
            id: 1,
            config,
            local_network: false,
        }],
        &[(FIRST, 1)],
    )
    .map_err(|e| e.to_string())?;
    let start = Instant::now();
    let datagram = packet::udp(app(false, 40_400), peer(false, 7), b"cookie").ok_or("datagram")?;
    tunnel.send(&datagram).await.map_err(|e| e.to_string())?;
    let answer = next_within(
        &tunnel,
        |p| udp_from(p, peer(false, 7)).is_some(),
        Duration::from_secs(20),
    )
    .await
    .map_err(|e| format!("the engine's echo was not answered under load: {e}"))?;
    if udp_from(&answer, peer(false, 7)) != Some(b"cookie".to_vec()) {
        return Err("another answer".into());
    }
    let up = session_made(&engine, 1, start).ok_or("no session")?;
    let handshakes = engine.counters()[TUNNEL_HANDSHAKES];
    // The flood's next bursts show whether the peer was under load at either initiation.
    tokio::time::sleep(FLOOD_PERIOD * 4).await;
    let (first, last) = (
        flood
            .loaded_at(start)
            .ok_or("no probe around the first initiation")?,
        flood
            .loaded_at(start + up)
            .ok_or("no probe around the session")?,
    );
    if !first || !last {
        return Ok(None);
    }
    if handshakes < 2 {
        return Err(
            "the session came at the engine's first initiation, though the peer was under load"
                .into(),
        );
    }
    Ok(Some((up, handshakes)))
}
