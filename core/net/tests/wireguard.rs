//! `WireGuard` upstreams (W7) through the whole engine: a pair of datagram sockets stands in for the tunnel,
//! and a `WireGuard` server of `GotaTun`'s own core on the loopback stands in for the provider. A chosen app's
//! TCP, UDP, lookups and the echo of every app go into the session from the configuration's address, and
//! what comes back reaches the app as from its destination; what comes from outside `AllowedIPs`, or for no
//! flow an app started, is dropped; a destination the tunnel cannot carry is refused; two tunnels carry two
//! apps; a direct app's packets never enter a tunnel, and a tunnelled app's never leave directly.
//!
//! The interoperation with `WireGuard` itself, the kernel's, is `wglab.rs`, which `scripts/check.sh lab`
//! runs against the lab's peer.
#![cfg(target_os = "linux")]

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

/// A chosen app's lookup to Watch's own DNS address goes to the configuration's DNS server through the
/// tunnel, and its answer reaches the app from Watch's address with a time to live of 0; the same question
/// again is answered from the tunnel's own cache.
#[tokio::test(flavor = "current_thread")]
async fn a_chosen_apps_lookup_goes_to_its_configurations_dns_server() -> Outcome {
    let mut server = Server::new(SERVER_KEY).await?;
    let setting = one(&server, &[FIRST], "10.77.0.2/32", "0.0.0.0/0")?;
    let (_engine, tunnel) = engine(&setting)?;
    let (app, watch_dns) = (tun4(40_003), SocketAddr::from((Addresses::COMMON.dns4, 53)));
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    tunnel
        .send(&packet::udp(app, watch_dns, &query).ok_or("datagram")?)
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
    assert_eq!((parsed.source, parsed.destination), (watch_dns, app));
    let payload = packet::udp_payload(&back, &parsed).ok_or("payload")?;
    assert_eq!(
        &payload[payload.len() - 10..payload.len() - 6],
        &[0, 0, 0, 0],
        "time to live 0"
    );
    // Asked again, answered from the tunnel's cache: the server sees nothing.
    tunnel
        .send(&packet::udp(app, watch_dns, &query).ok_or("datagram")?)
        .await?;
    let again = to_app(&tunnel).await?;
    let parsed = packet::parse(&again).map_err(|e| format!("{e:?}"))?;
    assert_eq!(parsed.source, watch_dns);
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
    let (_engine, tunnel) = engine(&setting)?;
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
