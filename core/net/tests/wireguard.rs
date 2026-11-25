//! `WireGuard` upstreams (W7) through the whole engine: a pair of datagram sockets stands in for the tunnel,
//! and a `WireGuard` server of `GotaTun`'s own core on the loopback stands in for the provider. A chosen app's
//! TCP, UDP, lookups and the echo of every app go into the session from the configuration's address, and
//! what comes back reaches the app as from its destination; what comes from outside `AllowedIPs`, or for no
//! flow an app started, is dropped; a destination the tunnel cannot carry is refused; two tunnels carry two
//! apps; a direct app's packets never enter a tunnel, and a tunnelled app's never leave directly.
//!
//! The interoperation with `WireGuard` itself, the kernel's, is `wglab.rs`, which `scripts/check.sh lab`
//! runs against the lab's peer.
#![cfg(any(target_os = "linux", target_os = "android"))]

use datapavan_net::engine::{Addresses, Configured, Limits, TunnelSetting};
use datapavan_net::wireguard::config::Config as WgConfig;
use datapavan_net::wireguard::core::{Core, GotaTun, Received, Sent};
use datapavan_net::{Config, Engine, Platform, Via, packet};
use etherparse::{
    IcmpEchoHeader, Icmpv4Type, PacketBuilder, SlicedPacket, TcpOptionElement, TransportSlice,
};
use gotatun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UdpSocket, UnixDatagram};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// The apps: two sent through tunnels 1 and 2, one that goes directly, by their ports in the tunnel.
const FIRST: u32 = 10_300;
const SECOND: u32 = 10_301;
const DIRECT: u32 = 10_400;
/// Ports Android names no app for.
const NOBODY: std::ops::Range<u16> = 43_000..43_100;

const PHONE_KEY: [u8; 32] = [0x21; 32];
const SERVER_KEY: [u8; 32] = [0x31; 32];
const SERVER2_KEY: [u8; 32] = [0x41; 32];
const PHONE4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const PHONE4_2: Ipv4Addr = Ipv4Addr::new(10, 78, 0, 2);
const DNS4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const WEB4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const WEB6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x34);
/// The places of counters in `Engine::counters`.
const ECHO_CARRIED: usize = 33;
const TUNNEL_UP: usize = 52;
const TUNNEL_DOWN: usize = 53;
const TUNNEL_FILTERED: usize = 54;
const TUNNEL_UNMATCHED: usize = 55;
const TUNNEL_REFUSED: usize = 56;
const TUNNEL_TOO_BIG: usize = 57;
const STEP: Duration = Duration::from_secs(5);

/// Android names the app by its port in the tunnel.
struct ByPort;

impl Platform for ByPort {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() {
            40_000..=40_999 => Some(FIRST),
            41_000..=41_999 => Some(SECOND),
            42_000..=42_999 => Some(DIRECT),
            _ => None,
        }
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

fn base64(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out.push('=');
    out
}

fn public(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

/// A configuration in `wg-quick`'s form.
fn config(text: &str) -> Result<Arc<WgConfig>, Box<dyn std::error::Error>> {
    Ok(Arc::new(
        WgConfig::parse(text.as_bytes()).map_err(|r| r.to_string())?,
    ))
}

/// The phone's configuration for the server at `endpoint` with the key `server`: `addresses` and
/// `allowed` as given.
fn phone_config(endpoint: SocketAddr, server: [u8; 32], addresses: &str, allowed: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {addresses}\nDNS = 10.77.0.1, 10.78.0.1\n[Peer]\nPublicKey = {}\n\
         AllowedIPs = {allowed}\nEndpoint = {endpoint}\n",
        base64(&PHONE_KEY),
        base64(&public(server)),
    )
}

/// A provider's server: `GotaTun`'s core on the loopback, its peer the phone.
struct Server {
    core: GotaTun,
    socket: UdpSocket,
    phone: Option<SocketAddr>,
}

impl Server {
    async fn new(key: [u8; 32]) -> Result<Self, Box<dyn std::error::Error>> {
        let text = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.1/24\nDNS = 10.77.0.1\n[Peer]\nPublicKey = {}\n\
             AllowedIPs = 10.77.0.0/24, fd77::2/128, 10.78.0.2/32\nEndpoint = 192.0.2.1:51820\n",
            base64(&key),
            base64(&public(PHONE_KEY)),
        );
        Ok(Self {
            core: GotaTun::new(&*config(&text)?),
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?,
            phone: None,
        })
    }

    fn address(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The next IP packet the phone sent into the session, the handshake answered on the way.
    async fn next(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let (n, from) =
                tokio::time::timeout(STEP, self.socket.recv_from(&mut buffer)).await??;
            self.phone = Some(from);
            match self.core.receive(from, &buffer[..n]) {
                Received::Send { datagrams, .. } => {
                    for datagram in datagrams {
                        self.socket.send_to(&datagram, from).await?;
                    }
                }
                Received::Packet(packet) => return Ok(packet),
                Received::Keepalive | Received::Refused(_) => {}
            }
        }
    }

    /// Whether the phone sends nothing but keepalives and handshakes for `wait`.
    async fn quiet(&mut self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.next()).await.is_err()
    }

    /// Sends `packet` to the phone in the session.
    async fn send(&mut self, packet: &[u8]) -> Outcome {
        let phone = self.phone.ok_or("the phone has not spoken")?;
        match self.core.send(packet) {
            Sent::Data(datagram) => {
                self.socket.send_to(&datagram, phone).await?;
                Ok(())
            }
            other => Err(format!("no session on the server: {other:?}").into()),
        }
    }
}

/// The engine on a datagram pair with `setting`, and the app's end.
fn engine(setting: &TunnelSetting) -> io::Result<(Engine, UnixDatagram)> {
    engine_on(setting, Arc::new(ByPort))
}

/// As [`engine`], with `platform` for Android.
fn engine_on(
    setting: &TunnelSetting,
    platform: Arc<dyn Platform>,
) -> io::Result<(Engine, UnixDatagram)> {
    engine_with(setting, platform, &Limits::default())
}

/// As [`engine_on`], with `limits`.
fn engine_with(
    setting: &TunnelSetting,
    platform: Arc<dyn Platform>,
    limits: &Limits,
) -> io::Result<(Engine, UnixDatagram)> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            limits: *limits,
            mtu: 1500,
            keep_flows: 64,
            addresses: Addresses::COMMON,
        },
        platform,
        None,
    )?;
    engine.tunnels(setting);
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

/// One tunnel to `server`, the apps `uids` through it.
fn one(
    server: &Server,
    uids: &[u32],
    addresses: &str,
    allowed: &str,
) -> Result<TunnelSetting, Box<dyn std::error::Error>> {
    let text = phone_config(server.address()?, SERVER_KEY, addresses, allowed);
    Ok(TunnelSetting {
        tunnels: vec![Configured {
            id: 1,
            config: config(&text)?,
            local_network: false,
        }],
        routes: uids.iter().map(|&uid| (uid, 1)).collect::<HashMap<_, _>>(),
        log_destinations: true,
        default: None,
        known: None,
    })
}

fn tun4(port: u16) -> SocketAddr {
    SocketAddr::from((Addresses::COMMON.tun4, port))
}

fn tun6(port: u16) -> SocketAddr {
    SocketAddr::from((Addresses::COMMON.tun6, port))
}

fn syn(from: SocketAddr, to: SocketAddr) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let builder = match (from.ip(), to.ip()) {
        (IpAddr::V4(f), IpAddr::V4(t)) => PacketBuilder::ipv4(f.octets(), t.octets(), 64),
        (IpAddr::V6(f), IpAddr::V6(t)) => PacketBuilder::ipv6(f.octets(), t.octets(), 64),
        _ => return Err("mixed versions".into()),
    };
    let mut out = Vec::new();
    builder
        .tcp(from.port(), to.port(), 1_000, 64_240)
        .syn()
        .options(&[TcpOptionElement::MaximumSegmentSize(1460)])?
        .write(&mut out, &[])?;
    Ok(out)
}

fn syn_ack(from: SocketAddr, to: SocketAddr) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (IpAddr::V4(f), IpAddr::V4(t)) = (from.ip(), to.ip()) else {
        return Err("IPv4 only".into());
    };
    let mut out = Vec::new();
    PacketBuilder::ipv4(f.octets(), t.octets(), 64)
        .tcp(from.port(), to.port(), 9_000, 65_535)
        .syn()
        .ack(1_001)
        .options(&[TcpOptionElement::MaximumSegmentSize(1460)])?
        .write(&mut out, &[])?;
    Ok(out)
}

fn echo(from: IpAddr, to: IpAddr, reply: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (IpAddr::V4(f), IpAddr::V4(t)) = (from, to) else {
        return Err("IPv4 only".into());
    };
    let header = IcmpEchoHeader { id: 0x0707, seq: 3 };
    let kind = if reply {
        Icmpv4Type::EchoReply(header)
    } else {
        Icmpv4Type::EchoRequest(header)
    };
    let mut out = Vec::new();
    PacketBuilder::ipv4(f.octets(), t.octets(), 64)
        .icmpv4(kind)
        .write(&mut out, b"ping")?;
    Ok(out)
}

/// The next packet the engine wrote to the app, within a step.
async fn to_app(tunnel: &UnixDatagram) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let n = tokio::time::timeout(STEP, tunnel.recv(&mut buffer)).await??;
    buffer.truncate(n);
    Ok(buffer)
}

/// Whether nothing reaches the app for `wait`.
async fn nothing_to_app(tunnel: &UnixDatagram, wait: Duration) -> bool {
    let mut buffer = vec![0u8; 65_535];
    tokio::time::timeout(wait, tunnel.recv(&mut buffer))
        .await
        .is_err()
}

/// Whether every checksum of the packet holds, by etherparse's recomputation.
fn checks_out(packet: &[u8]) -> bool {
    let Ok(sliced) = SlicedPacket::from_ip(packet) else {
        return false;
    };
    let ip_ok = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(v4)) => {
            let header = v4.header().to_header();
            header.calc_header_checksum() == header.header_checksum
        }
        _ => true,
    };
    let (s, d) = match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(v4)) => (
            v4.header().source_addr().octets(),
            v4.header().destination_addr().octets(),
        ),
        _ => return ip_ok,
    };
    let transport_ok = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            tcp.to_header()
                .calc_checksum_ipv4_raw(s, d, tcp.payload())
                .ok()
                == Some(tcp.checksum())
        }
        Some(TransportSlice::Udp(udp)) => {
            udp.checksum() == 0
                || udp
                    .to_header()
                    .calc_checksum_ipv4_raw(s, d, udp.payload())
                    .ok()
                    == Some(udp.checksum())
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            icmp.header().icmp_type.calc_checksum(icmp.payload()) == icmp.checksum()
        }
        _ => true,
    };
    ip_ok && transport_ok
}

fn mss_of(packet: &[u8]) -> Option<u16> {
    let Ok(SlicedPacket {
        transport: Some(TransportSlice::Tcp(tcp)),
        ..
    }) = SlicedPacket::from_ip(packet)
    else {
        return None;
    };
    tcp.options_iterator().find_map(|o| match o {
        Ok(TcpOptionElement::MaximumSegmentSize(mss)) => Some(mss),
        _ => None,
    })
}

/// A chosen app's SYN reaches the server from the configuration's address, its port kept and its MSS
/// clamped to the tunnel's MTU; the server's SYN-ACK reaches the app from the destination, clamped too, and
/// the flow is in the log as through tunnel 1.
#[tokio::test(flavor = "current_thread")]
async fn a_chosen_apps_tcp_goes_through_its_tunnel_from_the_configurations_address() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    let (app, web) = (tun4(40_001), SocketAddr::from((WEB4, 443)));
    tunnel.send(&syn(app, web)?).await?;
    let seen = server.next().await?;
    let parsed = packet::parse(&seen).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        (parsed.source, parsed.destination),
        (SocketAddr::from((PHONE4, 40_001)), web)
    );
    assert!(checks_out(&seen), "the server's packet checks out");
    assert_eq!(
        mss_of(&seen),
        Some(1_280 - 40),
        "clamped to the default MTU"
    );
    server
        .send(&syn_ack(web, SocketAddr::from((PHONE4, 40_001)))?)
        .await?;
    let back = to_app(&tunnel).await?;
    let parsed = packet::parse(&back).map_err(|e| format!("{e:?}"))?;
    assert_eq!((parsed.source, parsed.destination), (web, app));
    assert!(checks_out(&back));
    assert_eq!(mss_of(&back), Some(1_240), "the server's MSS clamped too");
    let flows = engine.flows();
    assert!(
        flows
            .iter()
            .any(|f| f.app == app && f.destination == web && f.via == Via::Tunnel(1)),
        "{flows:?}"
    );
    assert!(engine.counters()[TUNNEL_UP] >= 1 && engine.counters()[TUNNEL_DOWN] == 1);
    Ok(())
}

/// UDP both ways; then what the server sends from outside the peer's `AllowedIPs`, and what it sends for no
/// flow an app started, never reach the app, and are counted.
#[tokio::test(flavor = "current_thread")]
async fn udp_passes_back_only_from_inside_allowed_ips_on_a_flow_the_app_started() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(
        &server,
        &[FIRST],
        "10.77.0.2/32",
        "10.77.0.0/24, 93.184.216.0/24",
    )?;
    let (engine, tunnel) = engine(&setting)?;
    let (app, echo_at) = (
        tun4(40_002),
        SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 7)),
    );
    tunnel
        .send(&packet::udp(app, echo_at, b"hello").ok_or("datagram")?)
        .await?;
    let seen = server.next().await?;
    let parsed = packet::parse(&seen).map_err(|e| format!("{e:?}"))?;
    assert_eq!(parsed.source, SocketAddr::from((PHONE4, 40_002)));
    assert!(checks_out(&seen));
    let phone = SocketAddr::from((PHONE4, 40_002));
    server
        .send(&packet::udp(echo_at, phone, b"hello").ok_or("datagram")?)
        .await?;
    let back = to_app(&tunnel).await?;
    let parsed = packet::parse(&back).map_err(|e| format!("{e:?}"))?;
    assert_eq!((parsed.source, parsed.destination), (echo_at, app));
    assert_eq!(packet::udp_payload(&back, &parsed), Some(&b"hello"[..]));
    // From outside AllowedIPs, to the app's very port.
    let outside = SocketAddr::from((Ipv4Addr::new(10, 99, 0, 1), 7));
    server
        .send(&packet::udp(outside, phone, b"stranger").ok_or("datagram")?)
        .await?;
    // Inside AllowedIPs, but from a port the app never sent to.
    let other_port = SocketAddr::from((Ipv4Addr::new(10, 77, 0, 1), 8));
    server
        .send(&packet::udp(other_port, phone, b"stranger").ok_or("datagram")?)
        .await?;
    // To another address than the configuration's.
    let elsewhere = SocketAddr::from((Ipv4Addr::new(10, 77, 0, 3), 40_002));
    server
        .send(&packet::udp(echo_at, elsewhere, b"stranger").ok_or("datagram")?)
        .await?;
    // An unsolicited SYN.
    server.send(&syn_ack(echo_at, phone)?).await?;
    assert!(nothing_to_app(&tunnel, Duration::from_millis(500)).await);
    let counters = engine.counters();
    assert_eq!(
        counters[TUNNEL_FILTERED], 2,
        "outside AllowedIPs, and to another address"
    );
    assert_eq!(
        counters[TUNNEL_UNMATCHED], 2,
        "another port, and a SYN no app sent for"
    );
    Ok(())
}

/// A chosen app's lookup to the network part's own DNS address goes to the configuration's DNS server through the
/// tunnel, and its answer reaches the app from the network part's address with a time to live of 0; the same question
/// again is answered from the tunnel's own cache.
#[tokio::test(flavor = "current_thread")]
async fn a_chosen_apps_lookup_goes_to_its_configurations_dns_server() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (_engine, tunnel) = engine(&setting)?;
    let (app, own_dns) = (tun4(40_003), SocketAddr::from((Addresses::COMMON.dns4, 53)));
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    tunnel
        .send(&packet::udp(app, own_dns, &query).ok_or("datagram")?)
        .await?;
    let seen = server.next().await?;
    let parsed = packet::parse(&seen).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        (parsed.source, parsed.destination),
        (
            SocketAddr::from((PHONE4, 40_003)),
            SocketAddr::from((DNS4, 53))
        )
    );
    let mut answer = query.to_vec();
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[7] = 1;
    answer.extend_from_slice(&[
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 93, 184, 216, 34,
    ]);
    server
        .send(
            &packet::udp(
                SocketAddr::from((DNS4, 53)),
                SocketAddr::from((PHONE4, 40_003)),
                &answer,
            )
            .ok_or("datagram")?,
        )
        .await?;
    let back = to_app(&tunnel).await?;
    let parsed = packet::parse(&back).map_err(|e| format!("{e:?}"))?;
    assert_eq!((parsed.source, parsed.destination), (own_dns, app));
    let payload = packet::udp_payload(&back, &parsed).ok_or("payload")?;
    assert_eq!(
        &payload[payload.len() - 10..payload.len() - 6],
        &[0, 0, 0, 0],
        "time to live 0"
    );
    // Asked again, answered from the tunnel's cache: the server sees nothing.
    tunnel
        .send(&packet::udp(app, own_dns, &query).ok_or("datagram")?)
        .await?;
    let again = to_app(&tunnel).await?;
    let parsed = packet::parse(&again).map_err(|e| format!("{e:?}"))?;
    assert_eq!(parsed.source, own_dns);
    let payload = packet::udp_payload(&again, &parsed).ok_or("payload")?;
    assert_eq!(
        &payload[payload.len() - 10..payload.len() - 6],
        &[0, 0, 0, 0],
        "the cache's answer with a time to live of 0 too"
    );
    assert!(server.quiet(Duration::from_millis(300)).await);
    Ok(())
}

/// Every app's echo goes through the default tunnel while any app goes through one, since Android cannot
/// say whose it is; the reply reaches the app.
#[tokio::test(flavor = "current_thread")]
async fn echo_goes_through_the_default_tunnel() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    let app = IpAddr::V4(Addresses::COMMON.tun4);
    tunnel.send(&echo(app, IpAddr::V4(WEB4), false)?).await?;
    let seen = server.next().await?;
    assert_eq!(
        &seen[12..16],
        &PHONE4.octets(),
        "from the configuration's address"
    );
    assert!(checks_out(&seen));
    server
        .send(&echo(IpAddr::V4(WEB4), IpAddr::V4(PHONE4), true)?)
        .await?;
    let back = to_app(&tunnel).await?;
    assert_eq!(&back[16..20], &Addresses::COMMON.tun4.octets());
    assert!(checks_out(&back));
    assert_eq!(engine.counters()[ECHO_CARRIED], 1);
    Ok(())
}

/// An ICMP error from inside the tunnel about the app's datagram reaches the app with its quote swapped
/// back: the app's kernel finds its socket by it.
#[tokio::test(flavor = "current_thread")]
async fn an_error_from_inside_the_tunnel_quotes_the_apps_own_datagram() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    let (app, closed) = (tun4(40_004), SocketAddr::from((WEB4, 9)));
    tunnel
        .send(&packet::udp(app, closed, b"anyone?").ok_or("datagram")?)
        .await?;
    let seen = server.next().await?;
    let error = packet::path_error(
        &seen,
        (IpAddr::V4(WEB4), IpAddr::V4(PHONE4)),
        (3, 3),
        [0; 4],
    )
    .ok_or("error")?;
    server.send(&error).await?;
    let back = to_app(&tunnel).await?;
    assert_eq!(
        &back[16..20],
        &Addresses::COMMON.tun4.octets(),
        "to the app"
    );
    assert_eq!(
        &back[28 + 12..28 + 16],
        &Addresses::COMMON.tun4.octets(),
        "quoting it from the app"
    );
    assert!(checks_out(&back));
    // An error quoting a packet that left from another address than the configuration's: no app's.
    let mut stranger = seen.clone();
    stranger[12..16].copy_from_slice(&[10, 77, 0, 9]);
    let forged = packet::path_error(
        &stranger,
        (IpAddr::V4(WEB4), IpAddr::V4(PHONE4)),
        (3, 3),
        [0; 4],
    )
    .ok_or("error")?;
    let filtered = engine.counters()[TUNNEL_FILTERED];
    server.send(&forged).await?;
    assert!(nothing_to_app(&tunnel, Duration::from_millis(300)).await);
    assert_eq!(engine.counters()[TUNNEL_FILTERED], filtered + 1);
    Ok(())
}

/// Without an IPv6 address in the configuration, a chosen app's IPv6 is refused at once, so that it falls
/// back to IPv4 inside the tunnel; a destination outside a narrower `AllowedIPs` is refused too. Nothing of
/// either reaches the server, or leaves directly.
#[tokio::test(flavor = "current_thread")]
async fn what_the_tunnel_cannot_carry_is_refused_never_sent_directly() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "10.77.0.0/24")?;
    let (engine, tunnel) = engine(&setting)?;
    tunnel
        .send(&syn(tun6(40_005), SocketAddr::from((WEB6, 443)))?)
        .await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!(refused[0] >> 4, 6);
    assert_eq!(
        (refused[6], refused[40], refused[41]),
        (58, 1, 1),
        "ICMPv6 administratively prohibited"
    );
    tunnel
        .send(&syn(tun4(40_006), SocketAddr::from((WEB4, 443)))?)
        .await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!(
        (refused[9], refused[20], refused[21]),
        (1, 3, 13),
        "ICMP administratively prohibited"
    );
    assert!(server.quiet(Duration::from_millis(300)).await);
    assert_eq!(engine.counters()[TUNNEL_REFUSED], 2);
    Ok(())
}

/// A packet larger than the tunnel's MTU that may not be fragmented gets "fragmentation needed" with the
/// MTU that passes; it does not reach the server.
#[tokio::test(flavor = "current_thread")]
async fn a_packet_too_big_for_the_tunnel_is_answered_as_a_router_answers() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    let (app, web) = (tun4(40_007), SocketAddr::from((WEB4, 443)));
    tunnel
        .send(&packet::udp(app, web, b"first").ok_or("datagram")?)
        .await?;
    let _ = server.next().await?;
    let mut big = packet::udp(app, web, &[7; 1_400]).ok_or("datagram")?;
    big[6] |= 0x40;
    big[10..12].fill(0);
    let checksum = !fold(&big[..20]);
    big[10..12].copy_from_slice(&checksum.to_be_bytes());
    tunnel.send(&big).await?;
    let answer = to_app(&tunnel).await?;
    assert_eq!(
        (answer[9], answer[20], answer[21]),
        (1, 3, 4),
        "fragmentation needed"
    );
    assert_eq!(u16::from_be_bytes([answer[26], answer[27]]), 1_280);
    assert!(server.quiet(Duration::from_millis(300)).await);
    assert_eq!(engine.counters()[TUNNEL_TOO_BIG], 1);
    Ok(())
}

fn fold(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).unwrap_or(0)
}

/// Two configurations at once carry two apps to two servers, each from its own address; a flow Android
/// names no app for goes through the default one, the first set.
#[tokio::test(flavor = "current_thread")]
async fn two_tunnels_carry_two_apps_and_the_first_takes_flows_of_no_app() -> Outcome {
    let mut first = Server::new(SERVER_KEY).await?;
    let mut second = Server::new(SERVER2_KEY).await?;
    let setting = TunnelSetting {
        tunnels: vec![
            Configured {
                id: 1,
                config: config(&phone_config(
                    first.address()?,
                    SERVER_KEY,
                    "10.77.0.2/32",
                    "0.0.0.0/0",
                ))?,
                local_network: false,
            },
            Configured {
                id: 2,
                config: config(&phone_config(
                    second.address()?,
                    SERVER2_KEY,
                    "10.78.0.2/32",
                    "0.0.0.0/0",
                ))?,
                local_network: false,
            },
        ],
        routes: HashMap::from([(FIRST, 1), (SECOND, 2)]),
        log_destinations: true,
        default: None,
        known: None,
    };
    let (engine, tunnel) = engine(&setting)?;
    let web = SocketAddr::from((WEB4, 443));
    tunnel.send(&syn(tun4(41_001), web)?).await?;
    let seen = second.next().await?;
    assert_eq!(
        &seen[12..16],
        &PHONE4_2.octets(),
        "the second app, through the second tunnel"
    );
    tunnel.send(&syn(tun4(40_008), web)?).await?;
    let seen = first.next().await?;
    assert_eq!(
        &seen[12..16],
        &PHONE4.octets(),
        "the first app, through the first"
    );
    tunnel.send(&syn(tun4(NOBODY.start), web)?).await?;
    let seen = first.next().await?;
    assert_eq!(
        u16::from_be_bytes([seen[20], seen[21]]),
        NOBODY.start,
        "no app's, through the default"
    );
    let states = engine.tunnel_states();
    assert_eq!(states.iter().map(|s| s.id).collect::<Vec<_>>(), [1, 2]);
    assert!(states.iter().all(|s| s.connected && !s.not_answering));
    Ok(())
}

/// A direct app's SYN never enters the tunnel (it is refused here, where no listener of the system stack
/// can be bound on the tunnel's address), while the tunnelled app's goes in.
#[tokio::test(flavor = "current_thread")]
async fn a_direct_apps_packets_never_enter_a_tunnel() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    tunnel
        .send(&syn(
            tun4(42_001),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        )?)
        .await?;
    let _ = to_app(&tunnel).await?;
    assert!(server.quiet(Duration::from_millis(300)).await);
    assert_eq!(engine.counters()[TUNNEL_UP], 0);
    Ok(())
}

/// A server that stops answering holds its app: what the app sends waits or is lost, nothing reaches the
/// network another way, and the tunnel's state says the server does not answer once two handshakes went
/// unanswered.
#[tokio::test(flavor = "current_thread")]
async fn a_tunnel_whose_server_stops_answering_holds_its_apps() -> Outcome {
    let server = Server::new(SERVER_KEY).await?;
    let address = server.address()?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    // The server is gone; its port stays bound by nothing that answers.
    let silent = server.socket;
    let (engine, tunnel) = engine(&setting)?;
    tunnel
        .send(&syn(tun4(40_009), SocketAddr::from((WEB4, 443)))?)
        .await?;
    let mut buffer = vec![0u8; 2_048];
    let (n, _) = tokio::time::timeout(STEP, silent.recv_from(&mut buffer)).await??;
    assert_eq!(buffer[0], 1, "a handshake initiation, nothing else");
    assert!(n > 100);
    tokio::time::sleep(Duration::from_secs(11)).await;
    let state = engine.tunnel_states().into_iter().next().ok_or("a state")?;
    assert!(state.not_answering, "{state:?}");
    assert_eq!(state.handshake, None);
    assert!(nothing_to_app(&tunnel, Duration::from_millis(100)).await);
    let _ = address;
    Ok(())
}

/// After a network change the tunnel's socket is made anew, and the server hears from the new port at
/// once, with no packet of the app's needed: a keepalive while the session is young.
#[tokio::test(flavor = "current_thread")]
async fn a_network_change_makes_the_socket_anew_and_tells_the_server_at_once() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    tunnel
        .send(&syn(tun4(40_010), SocketAddr::from((WEB4, 443)))?)
        .await?;
    let _ = server.next().await?;
    let before = server.phone.ok_or("the phone's port")?;
    engine.network_changed(None, true);
    let mut buffer = vec![0u8; 2_048];
    let (_, from) = tokio::time::timeout(STEP, server.socket.recv_from(&mut buffer)).await??;
    assert_ne!(from.port(), before.port(), "a new socket");
    assert_eq!(buffer[0], 4, "a data message: the keepalive");
    let _ = tunnel;
    Ok(())
}

/// The CPU time of the engine's thread so far, from `/proc`, in clock ticks of 10 ms.
fn engine_ticks() -> Result<u64, Box<dyn std::error::Error>> {
    for task in std::fs::read_dir("/proc/self/task")? {
        let path = task?.path();
        if std::fs::read_to_string(path.join("comm"))?.trim() == "network-engine" {
            let stat = std::fs::read_to_string(path.join("stat"))?;
            let after = stat.rsplit_once(") ").ok_or("stat")?.1;
            let fields: Vec<&str> = after.split(' ').collect();
            return Ok(fields[11].parse::<u64>()? + fields[12].parse::<u64>()?);
        }
    }
    Err("no engine thread".into())
}

/// The engine's CPU time for one UDP packet of `size` bytes from an app, through a tunnel (`GotaTun`'s
/// encryption, the swap, the socket) or directly (a mapping's socket), to a server on the loopback that
/// only reads them; `cargo test --release -- --ignored per_packet --nocapture` prints both. Run on the
/// development machine and, built for Android, on the emulator (ADR 0035, "How it is built").
#[tokio::test(flavor = "current_thread")]
#[ignore = "a measurement, not a check: run it by name"]
async fn per_packet_cost() -> Outcome {
    const PACKETS: usize = 200_000;
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    // On this machine's own address: the engine refuses an app's packet to the loopback, which a measure of the
    // direct path to 127.0.0.1 measured instead (until W7's fix round).
    let sink = UdpSocket::bind((local_address()?, 0)).await?;
    let sink_at = sink.local_addr()?;
    let tunnel_lost = engine.counters().len() - 1;
    // The tunnel's session first, then the server only reads what comes.
    let web = SocketAddr::from((WEB4, 9));
    tunnel
        .send(&packet::udp(tun4(40_100), web, b"first").ok_or("datagram")?)
        .await?;
    let _ = server.next().await?;
    // What reached each reader, counted: a packet the engine dropped would cost it less, and flatter it.
    let drain = |socket: UdpSocket, count: Arc<std::sync::atomic::AtomicUsize>| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2_048];
            // Until aborted: a reader that stopped while the other path was measured closed its port, and the
            // direct measure then counted the engine's handling of "port unreachable" (until W7's fix round).
            while tokio::time::timeout(Duration::from_secs(60), socket.recv(&mut buffer))
                .await
                .is_ok()
            {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        })
    };
    let reached = [
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    ];
    let readers = [
        drain(server.socket, Arc::clone(&reached[0])),
        drain(sink, Arc::clone(&reached[1])),
    ];
    for (path, (name, to, from)) in [
        ("tunnelled", web, tun4(40_101)),
        ("direct", sink_at, tun4(42_101)),
    ]
    .into_iter()
    .enumerate()
    {
        for size in [1_280usize, 100] {
            let datagram = packet::udp(from, to, &vec![7u8; size - 28]).ok_or("datagram")?;
            tunnel.send(&datagram).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let before = engine_ticks()?;
            let arrived = reached[path].load(std::sync::atomic::Ordering::Relaxed);
            let started = std::time::Instant::now();
            for i in 0..PACKETS {
                tunnel.send(&datagram).await?;
                if i % 64 == 63 {
                    tokio::task::yield_now().await;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            let ticks = engine_ticks()? - before;
            #[allow(clippy::cast_precision_loss)]
            let ns = ticks as f64 * 10_000_000.0 / PACKETS as f64;
            let arrived = reached[path].load(std::sync::atomic::Ordering::Relaxed) - arrived;
            println!(
                "{name} {size} B: {ns:.0} ns of the engine's CPU per packet ({:.2} s wall), {arrived} of {PACKETS} read by the far end",
                started.elapsed().as_secs_f64()
            );
        }
    }
    for reader in readers {
        reader.abort();
    }
    assert_eq!(
        engine.counters()[tunnel_lost],
        0,
        "the engine dropped tunnelled packets: the measure would flatter it"
    );
    let read = [0, 1].map(|path| reached[path].load(std::sync::atomic::Ordering::Relaxed));
    assert!(
        read.iter().all(|&n| n > PACKETS),
        "the far ends read {read:?}: a path that delivers nothing measures something else"
    );
    Ok(())
}

/// The CPU time so far, in nanoseconds, from `/proc`'s `schedstat` (the ticks of `stat` are 10 ms, longer than many
/// opens together): of the engine's thread, and of every thread of the process, the blocking pool's among them, which
/// asks Android whose a socket is and protects it.
fn cpu_ns() -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let (mut engine, mut all) = (None, 0);
    for task in std::fs::read_dir("/proc/self/task")? {
        let path = task?.path();
        let stat = std::fs::read_to_string(path.join("schedstat"))?;
        let ns: u64 = stat.split(' ').next().ok_or("schedstat")?.parse()?;
        all += ns;
        if std::fs::read_to_string(path.join("comm"))?.trim() == "network-engine" {
            engine = Some(ns);
        }
    }
    Ok((engine.ok_or("no engine thread")?, all))
}

/// A lookup of `name`'s address, with the ID `id`.
fn query(id: u16, name: &str) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap_or(63));
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

/// What opening a UDP flow costs through the whole engine (the cold paths' size pass, ADR 0053): one datagram from each
/// of `OPENS` new ports, each waited for at the far end before the next is sent, on three paths:
/// - directly to a sink on this machine's address: Android is asked whose the socket is, and a mapping opens with a
///   protected socket of its own;
/// - a lookup to the network part's DNS address, as Android's resolver sends each from a new port: Android is asked,
///   and a flow of lookups opens to the network's DNS server, here a sink, with a protected socket of its own;
/// - through tunnel 1 to its server: Android is asked, and the tunnel's flow opens.
///
/// Prints the median and p90 of the time from the send to the arrival, and the CPU per open of the engine's thread and
/// of the whole process. Each open hands work to the blocking pool and back, so a few hundred nanoseconds more or less
/// are below what it resolves; the spread of runs is its resolution. `cargo test --release -- --ignored
/// opening_a_udp_flow --nocapture`; built for Android too, and run on the emulator.
#[tokio::test(flavor = "current_thread")]
#[ignore = "a measurement, not a check: run it by name"]
async fn opening_a_udp_flow() -> Outcome {
    const OPENS: u16 = 400;
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    // Room for every mapping and flow: no open makes room by ending an older one.
    let limits = Limits {
        udp_mappings: 4_096,
        udp_share: 4_096,
        ..Limits::default()
    };
    let (engine, tunnel) = engine_with(&setting, Arc::new(ByPort), &limits)?;
    let local = local_address()?;
    let sink = UdpSocket::bind((local, 0)).await?;
    let sink_at = sink.local_addr()?;
    // The network's DNS server is a sink too, on its own port, which the lookups name.
    let resolver = UdpSocket::bind((local, 0)).await?;
    engine.network_changed(Some(IpAddr::V4(local)), false);
    let dns = SocketAddr::from((Addresses::COMMON.dns4, resolver.local_addr()?.port()));
    // The tunnel's session first: no open pays for its handshake.
    let web = SocketAddr::from((WEB4, 9));
    tunnel
        .send(&packet::udp(tun4(40_000), web, b"first").ok_or("datagram")?)
        .await?;
    let _ = server.next().await?;
    let mut buffer = vec![0u8; 2_048];
    for (path, first, to) in [
        ("direct", 42_000u16, sink_at),
        ("lookup", 42_400, dns),
        ("tunnelled", 40_001, web),
    ] {
        let mut times = Vec::with_capacity(usize::from(OPENS));
        let before = cpu_ns()?;
        for i in 0..OPENS {
            let payload = if path == "lookup" {
                query(i, &format!("a{i}.example.com"))
            } else {
                i.to_be_bytes().to_vec()
            };
            let datagram = packet::udp(tun4(first + i), to, &payload).ok_or("datagram")?;
            let started = std::time::Instant::now();
            tunnel.send(&datagram).await?;
            let arrived = match path {
                "direct" => {
                    let n = tokio::time::timeout(STEP, sink.recv(&mut buffer)).await??;
                    buffer[..n].to_vec()
                }
                "lookup" => {
                    let n = tokio::time::timeout(STEP, resolver.recv(&mut buffer)).await??;
                    buffer[..n].to_vec()
                }
                _ => server.next().await?,
            };
            times.push(started.elapsed());
            assert!(
                arrived.ends_with(&payload),
                "{path} open {i}: another datagram arrived"
            );
        }
        let after = cpu_ns()?;
        times.sort();
        let micros = |at: usize| times[at].as_secs_f64() * 1e6;
        #[allow(clippy::cast_precision_loss)]
        let per_open = |ns: u64| ns as f64 / 1e3 / f64::from(OPENS);
        println!(
            "{path}: {OPENS} opens, median {:.1} us, p90 {:.1} us from the send to the arrival; CPU per open {:.1} us of \
             the engine's thread, {:.1} us of the process",
            micros(times.len() / 2),
            micros(times.len() * 9 / 10),
            per_open(after.0 - before.0),
            per_open(after.1 - before.1),
        );
    }
    Ok(())
}

/// An app taken off its tunnel while its UDP flow is open: the flow ends, in the log too, on the engine's
/// own thread, where alone the log's clock is read (the network shard on 2026-11-19: ended from the network part's
/// thread, a debug build panicked), and the app's next datagram goes its new way, here directly to a local echo.
#[tokio::test(flavor = "current_thread")]
async fn an_app_taken_off_its_tunnel_ends_its_flows_on_the_engines_thread() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&setting)?;
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let echo_at = echo.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2_048];
        while let Ok((n, from)) = echo.recv_from(&mut buffer).await {
            let _ = echo.send_to(&buffer[..n], from).await;
        }
    });
    let app = tun4(40_200);
    tunnel
        .send(&packet::udp(app, echo_at, b"through").ok_or("datagram")?)
        .await?;
    let seen = server.next().await?;
    assert_eq!(&seen[12..16], &PHONE4.octets(), "first through the tunnel");
    // From this thread, as the network part's Kotlin side sets it from its own.
    engine.tunnels(&TunnelSetting {
        routes: HashMap::new(),
        ..setting
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    tunnel
        .send(&packet::udp(app, echo_at, b"direct").ok_or("datagram")?)
        .await?;
    let back = to_app(&tunnel).await?;
    let parsed = packet::parse(&back).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        packet::udp_payload(&back, &parsed),
        Some(&b"direct"[..]),
        "now directly"
    );
    assert!(
        server.quiet(Duration::from_millis(300)).await,
        "nothing more through the tunnel"
    );
    Ok(())
}

/// Android as some tests play it: the app of port 40,900 as a test sets it (0 for none), every other port
/// as [`ByPort`] says; and a host name its resolver answers, with whether it did so encrypted.
struct Switchable {
    owner: std::sync::atomic::AtomicU32,
    name: Option<(String, Vec<IpAddr>, bool)>,
    asked: std::sync::atomic::AtomicUsize,
}

impl Switchable {
    fn new(owner: u32, name: Option<(String, Vec<IpAddr>, bool)>) -> Arc<Self> {
        Arc::new(Self {
            owner: owner.into(),
            name,
            asked: 0.into(),
        })
    }
}

impl Platform for Switchable {
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        if local.port() == 40_900 {
            let uid = self.owner.load(std::sync::atomic::Ordering::Relaxed);
            return (uid != 0).then_some(uid);
        }
        ByPort.owner(protocol, local, remote)
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}

    fn resolve(&self, name: &str) -> Option<datapavan_net::Resolution> {
        self.asked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (known, addresses, encrypted) = self.name.as_ref()?;
        Some(datapavan_net::Resolution {
            addresses: if name == known {
                addresses.clone()
            } else {
                Vec::new()
            },
            encrypted: *encrypted,
        })
    }
}

/// A local UDP echo, and how many datagrams it saw.
async fn local_echo() -> io::Result<(SocketAddr, Arc<std::sync::atomic::AtomicUsize>)> {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let at = echo.local_addr()?;
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2_048];
        while let Ok((n, from)) = echo.recv_from(&mut buffer).await {
            counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = echo.send_to(&buffer[..n], from).await;
        }
    });
    Ok((at, seen))
}

/// An app routed to a tunnel whose configuration is not set, or was removed, waits: its TCP and UDP are
/// refused at once with "administratively prohibited", and nothing of it leaves directly; once the
/// configuration is set it goes through it (fix round: both reviews' first major finding).
#[tokio::test(flavor = "current_thread")]
async fn an_app_routed_to_a_tunnel_not_set_waits_and_never_goes_directly() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let routes_only = TunnelSetting {
        tunnels: Vec::new(),
        ..setting.clone()
    };
    let (engine, tunnel) = engine(&routes_only)?;
    let (echo_at, seen) = local_echo().await?;
    tunnel
        .send(&packet::udp(tun4(40_600), echo_at, b"direct?").ok_or("datagram")?)
        .await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!(
        (refused[9], refused[20], refused[21]),
        (1, 3, 13),
        "prohibited"
    );
    tunnel.send(&syn(tun4(40_601), echo_at)?).await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!(
        (refused[9], refused[20], refused[21]),
        (1, 3, 13),
        "a SYN too"
    );
    let state = engine.tunnel_states();
    assert_eq!(
        state
            .iter()
            .map(|s| (s.id, s.configured))
            .collect::<Vec<_>>(),
        [(1, false)]
    );
    // The configuration comes: the app goes through it.
    engine.tunnels(&setting);
    tunnel
        .send(&packet::udp(tun4(40_602), echo_at, b"through").ok_or("datagram")?)
        .await?;
    let through = server.next().await?;
    assert_eq!(&through[12..16], &PHONE4.octets());
    // Removed while the app is routed to it: it waits again.
    engine.tunnels(&routes_only);
    tunnel
        .send(&packet::udp(tun4(40_603), echo_at, b"direct?").ok_or("datagram")?)
        .await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!((refused[20], refused[21]), (3, 13));
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "nothing reached the local echo directly"
    );
    Ok(())
}

/// An app with a direct UDP mapping, then sent through a tunnel: its next datagram on that socket goes into
/// the tunnel, never by the mapping (the engine reviewer's R1, which kills the mutant that drops
/// `Engine::tunnels`' bump of the chains' count); and the network part's DNS answers go uncached from then on.
#[tokio::test(flavor = "current_thread")]
async fn an_app_newly_routed_leaves_its_direct_mapping() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (engine, tunnel) = engine(&TunnelSetting {
        routes: HashMap::new(),
        ..setting.clone()
    })?;
    assert!(!engine.answers_uncached());
    let (echo_at, seen) = local_echo().await?;
    let app = tun4(40_300);
    tunnel
        .send(&packet::udp(app, echo_at, b"direct").ok_or("datagram")?)
        .await?;
    let _ = to_app(&tunnel).await?;
    assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 1);
    engine.tunnels(&setting);
    assert!(
        engine.answers_uncached(),
        "TTL 0 while any app goes through a tunnel"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    tunnel
        .send(&packet::udp(app, echo_at, b"through").ok_or("datagram")?)
        .await?;
    let through = server.next().await?;
    assert_eq!(&through[12..16], &PHONE4.octets(), "through the tunnel");
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "nothing more directly"
    );
    Ok(())
}

/// After a pause of its app, a tunnelled UDP flow asks Android again whose the socket is: the same app, and
/// its datagram goes on through the tunnel; another, and the flow ends, its datagram dropped, the socket's
/// next datagram routed for its new app (the maintainer's answer 5, 2026-11-19).
#[tokio::test(flavor = "current_thread")]
async fn a_tunnelled_udp_flow_asks_android_again_after_a_pause() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let platform = Switchable::new(FIRST, None);
    let (_engine, tunnel) = engine_on(&setting, Arc::clone(&platform) as Arc<dyn Platform>)?;
    let (echo_at, seen) = local_echo().await?;
    let app = tun4(40_900);
    for (round, uid, through) in [(0u8, FIRST, true), (1, FIRST, true), (2, DIRECT, false)] {
        platform
            .owner
            .store(uid, std::sync::atomic::Ordering::Relaxed);
        if round > 0 {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
        }
        tunnel
            .send(&packet::udp(app, echo_at, &[round]).ok_or("datagram")?)
            .await?;
        if through {
            let seen_by_server = server.next().await?;
            assert_eq!(seen_by_server.last(), Some(&round), "round {round} through");
        } else {
            assert!(
                server.quiet(Duration::from_millis(500)).await,
                "round {round}"
            );
        }
    }
    // The socket is the direct app's now: its next datagram goes its way.
    tunnel
        .send(&packet::udp(app, echo_at, b"direct").ok_or("datagram")?)
        .await?;
    let _ = to_app(&tunnel).await?;
    assert_eq!(seen.load(std::sync::atomic::Ordering::Relaxed), 1);
    Ok(())
}

/// The local address the machine would send from: a server bound there is reached without anything
/// leaving the machine, and is no loopback address, which an endpoint's name may not resolve to.
fn local_address() -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    // `connect` on UDP sends nothing: it only picks the route and the source address.
    probe.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(address) if !address.is_loopback() => Ok(address),
        _ => Err(io::Error::other("no local address")),
    }
}

/// An endpoint given by name is resolved by Android's resolver on the network beneath (here the test's
/// platform), and the state says whether that was encrypted; the tunnel then works through it.
#[tokio::test(flavor = "current_thread")]
async fn an_endpoints_name_is_resolved_by_the_platform_and_the_state_says_how() -> Outcome {
    let local = local_address()?;
    for encrypted in [true, false] {
        let socket = UdpSocket::bind((local, 0)).await?;
        let port = socket.local_addr()?.port();
        let mut server = Server::new(SERVER_KEY).await?;
        server.socket = socket;
        let text = phone_config(
            SocketAddr::from((local, port)),
            SERVER_KEY,
            "10.77.0.2/32",
            "0.0.0.0/0",
        )
        .replace(
            &format!("{local}:{port}"),
            &format!("provider.example:{port}"),
        );
        let setting = TunnelSetting {
            tunnels: vec![Configured {
                id: 1,
                config: config(&text)?,
                local_network: false,
            }],
            routes: HashMap::from([(FIRST, 1)]),
            log_destinations: false,
            default: None,
            known: None,
        };
        // A multicast and a loopback address first, as a hostile resolver might answer: never taken.
        let platform = Switchable::new(
            FIRST,
            Some((
                "provider.example".into(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V4(local),
                ],
                encrypted,
            )),
        );
        let (engine, tunnel) = engine_on(&setting, platform)?;
        tunnel
            .send(&packet::udp(tun4(40_700), SocketAddr::from((WEB4, 9)), b"x").ok_or("d")?)
            .await?;
        let seen = server.next().await?;
        assert_eq!(&seen[12..16], &PHONE4.octets());
        let state = engine.tunnel_states().into_iter().next().ok_or("state")?;
        assert_eq!(
            (state.plain_dns, state.resolutions, state.connected),
            (!encrypted, 1, true),
            "encrypted: {encrypted}"
        );
    }
    Ok(())
}

/// An endpoint's name that does not resolve is not asked again for every packet: the tunnel's task waits,
/// its pauses doubling from five seconds, and its apps' packets start no other (fix round, the engine's
/// review, finding 2; its R2).
#[tokio::test(flavor = "current_thread")]
async fn a_name_that_does_not_resolve_is_not_asked_again_per_packet() -> Outcome {
    let text = format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\n[Peer]\nPublicKey = {}\n\
         AllowedIPs = 0.0.0.0/0\nEndpoint = provider.example:51820\n",
        base64(&PHONE_KEY),
        base64(&public(SERVER_KEY)),
    );
    let setting = TunnelSetting {
        tunnels: vec![Configured {
            id: 1,
            config: config(&text)?,
            local_network: false,
        }],
        routes: HashMap::from([(FIRST, 1)]),
        log_destinations: false,
        default: None,
        known: None,
    };
    // Android's resolver refuses the name, as a censor's resolver answers a blocked provider's.
    let platform = Switchable::new(FIRST, Some(("other.example".into(), Vec::new(), false)));
    let (engine, tunnel) = engine_on(&setting, Arc::clone(&platform) as Arc<dyn Platform>)?;
    for i in 0..20u16 {
        tunnel
            .send(
                &packet::udp(
                    tun4(40_400),
                    SocketAddr::from((WEB4, 443)),
                    &i.to_be_bytes(),
                )
                .ok_or("datagram")?,
            )
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let asked = platform.asked.load(std::sync::atomic::Ordering::Relaxed);
    let state = engine.tunnel_states().into_iter().next().ok_or("state")?;
    assert_eq!(
        asked, 1,
        "one resolution in two seconds, not one per packet"
    );
    assert_eq!(
        (state.error, state.resolutions, state.connected),
        (Some("resolve"), 1, false)
    );
    Ok(())
}

/// A UDP reply the far side fragmented (larger than the server's own tunnel MTU, DF clear, as a kernel
/// forwarding it fragments it) is put together and reaches the app (fix round, the engine's review, finding
/// 4; its R5).
#[tokio::test(flavor = "current_thread")]
async fn a_fragmented_reply_from_the_tunnel_reaches_the_app() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (_engine, tunnel) = engine(&setting)?;
    let (app, far) = (tun4(40_500), SocketAddr::from((WEB4, 5_000)));
    tunnel
        .send(&packet::udp(app, far, b"ask").ok_or("datagram")?)
        .await?;
    let _ = server.next().await?;
    let whole =
        packet::udp(far, SocketAddr::from((PHONE4, 40_500)), &[7u8; 1_400]).ok_or("datagram")?;
    for (part, more) in fragments(&whole, 1_000) {
        let _ = more;
        server.send(&part).await?;
    }
    let got = to_app(&tunnel).await?;
    let parsed = packet::parse(&got).map_err(|e| format!("{e:?}"))?;
    assert_eq!((parsed.source, parsed.destination), (far, app));
    assert_eq!(
        packet::udp_payload(&got, &parsed).map(<[u8]>::len),
        Some(1_400)
    );
    Ok(())
}

/// `whole`, an IPv4 packet, cut into fragments whose data holds at most `size` bytes (a multiple of 8),
/// with DF clear, each with its header's checksum.
fn fragments(whole: &[u8], size: usize) -> Vec<(Vec<u8>, bool)> {
    let data = &whole[20..];
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + size).min(data.len());
        let more = end < data.len();
        let mut p = whole[..20].to_vec();
        p.extend_from_slice(&data[offset..end]);
        let total = u16::try_from(p.len()).unwrap_or(0);
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        let field = u16::try_from(offset / 8).unwrap_or(0) | if more { 0x2000 } else { 0 };
        p[6..8].copy_from_slice(&field.to_be_bytes());
        p[10..12].fill(0);
        let sum = !fold(&p[..20]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        out.push((p, more));
        offset = end;
    }
    out
}

/// A datagram the engine put together from the app's own fragments, larger than the tunnel's MTU, goes into
/// the tunnel whole, since it came fragmented: no "fragmentation needed", which would only have it
/// fragmented again; the outer datagram is fragmented on the way instead.
#[tokio::test(flavor = "current_thread")]
async fn a_datagram_put_together_from_the_apps_fragments_passes_whole() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(
        &server,
        &[FIRST],
        "10.77.0.2/32, fd77::2/128",
        "0.0.0.0/0, ::/0",
    )?;
    let (engine, tunnel) = engine(&setting)?;
    let (app, far) = (tun4(40_510), SocketAddr::from((WEB4, 5_000)));
    let whole = packet::udp(app, far, &[9u8; 1_400]).ok_or("datagram")?;
    for (part, _) in fragments(&whole, 1_000) {
        tunnel.send(&part).await?;
    }
    let seen = server.next().await?;
    assert_eq!(seen.len(), 1_428, "whole, over the MTU of 1,280");
    // In IPv6, where no router fragments and every packet counts as "don't fragment", only having been put
    // together lets it pass (the engine reviewer's mutant M5 survived the IPv4 case alone). The flow is open,
    // and after a pause, so that the datagram waits while Android is asked again whose the socket is, and
    // keeps its mark meanwhile.
    let (app, far) = (tun6(40_511), SocketAddr::from((WEB6, 5_000)));
    tunnel
        .send(&packet::udp(app, far, b"open").ok_or("datagram")?)
        .await?;
    let _ = server.next().await?;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let whole = packet::udp(app, far, &[9u8; 1_400]).ok_or("datagram")?;
    for part in fragments6(&whole, 1_000) {
        tunnel.send(&part).await?;
    }
    let seen = server.next().await?;
    assert_eq!(seen.len(), 1_448, "whole, over the MTU of 1,280");
    assert_eq!(engine.counters()[TUNNEL_TOO_BIG], 0);
    Ok(())
}

/// The IPv6 datagram `whole` cut into fragments of at most `size` bytes of its payload, a multiple of 8, as an
/// app's kernel cuts one, each with a fragment header.
fn fragments6(whole: &[u8], size: usize) -> Vec<Vec<u8>> {
    let data = &whole[40..];
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + size).min(data.len());
        let more = end < data.len();
        let mut p = whole[..40].to_vec();
        p[6] = 44;
        let length = u16::try_from(8 + end - offset).unwrap_or(0);
        p[4..6].copy_from_slice(&length.to_be_bytes());
        let field = u16::try_from(offset).unwrap_or(0) | u16::from(more);
        p.extend_from_slice(&[17, 0]);
        p.extend_from_slice(&field.to_be_bytes());
        p.extend_from_slice(&0x5678_u32.to_be_bytes());
        p.extend_from_slice(&data[offset..end]);
        out.push(p);
        offset = end;
    }
    out
}

/// A ping to a stand-in address, which only the tool reaches, is refused, never carried by a tunnel.
#[tokio::test(flavor = "current_thread")]
async fn a_ping_to_a_stand_in_is_refused() -> Outcome {
    let server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (_engine, tunnel) = engine(&setting)?;
    tunnel
        .send(&echo(
            IpAddr::V4(Addresses::COMMON.tun4),
            IpAddr::from([198, 18, 0, 1]),
            false,
        )?)
        .await?;
    let refused = to_app(&tunnel).await?;
    assert_eq!((refused[9], refused[20], refused[21]), (1, 3, 13));
    Ok(())
}
