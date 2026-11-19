//! The interoperation lab's client (W7's spike, ADR 0035): GotaTun's `Tunn` over one UDP socket against a
//! WireGuard peer of the reference implementation (`peer/`, started by `lab.sh`), with hand-built IP
//! packets and no TCP stack. It drives `Tunn` as W7's engine would: the timers once a second, every
//! datagram through the `RateLimiter` first, answers only from the configured server address, decrypted
//! packets checked against the peer's AllowedIPs by the caller, and the queued packets sent once a
//! handshake completes.
//!
//!   WG_PRIVATE=<base64> WG_PEER_PUBLIC=<base64> [WG_PSK=<base64>] \
//!       wg-lab --peer ADDR:PORT --v4 10.77.0.2 --v6 fd77::2 --scenario full|psk|wrong-psk [--keepalive 5]
//!       [--skip-rekey]
//!
//! - `full`: the handshake, ICMP echo, UDP echo and a TCP SYN (then a request and its answer) on IPv4 and
//!   IPv6, a packet from outside the AllowedIPs dropped, `PersistentKeepalive`, a changed local port, and
//!   the rekey after REKEY_AFTER_TIME (about two and a half minutes);
//! - `psk`: the handshake with a preshared key, echo on both versions, and the peer's own keepalives;
//! - `wrong-psk`: a preshared key the peer does not have: the handshake must fail.
//!
//! Each check prints `PASS name: detail` or `FAIL name: detail`; the last line is `local-port N`, the port
//! the peer should now have as this client's endpoint. The exit status is 1 if any check failed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::BytesMut;
use etherparse::{IcmpEchoHeader, Icmpv4Type, Icmpv6Type, NetHeaders, PacketBuilder, PacketHeaders, TransportHeader};
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::tun::MtuWatcher;
use gotatun::x25519::{PublicKey, StaticSecret};

/// The peer's own addresses inside the tunnel (peer/start.sh).
const SERVER_V4: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const SERVER_V6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 1);
/// The AllowedIPs this client has for the peer: the peer's addresses above are inside, the addresses the
/// peer's reflector answers from (10.77.1.1, fd77:1::1) are not.
const ALLOWED: [(IpAddr, u8); 2] = [
    (IpAddr::V4(Ipv4Addr::new(10, 77, 0, 0)), 24),
    (IpAddr::V6(Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 0)), 64),
];
/// The engine's timer tick (ADR 0035: about once a second while a session exists).
const TICK: Duration = Duration::from_secs(1);
const MTU: u16 = 1420;

fn allowed(source: IpAddr) -> bool {
    ALLOWED.iter().any(|&(net, bits)| match (net, source) {
        (IpAddr::V4(n), IpAddr::V4(s)) => bits == 0 || (u32::from(n) ^ u32::from(s)) >> (32 - u32::from(bits)) == 0,
        (IpAddr::V6(n), IpAddr::V6(s)) => bits == 0 || (u128::from(n) ^ u128::from(s)) >> (128 - u32::from(bits)) == 0,
        _ => false,
    })
}

#[derive(Default, Debug)]
struct Counts {
    handshakes_sent: u32,
    handshakes_completed: u32,
    keepalives_sent: u32,
    keepalives_received: u32,
    dropped_outside: u32,
    dropped_foreign_sender: u32,
    tunnel_errors: u32,
    data_sent: u32,
    data_received: u32,
}

struct Client {
    tunn: Tunn,
    limiter: Arc<RateLimiter>,
    socket: UdpSocket,
    peer: SocketAddr,
    mtu: MtuWatcher,
    counts: Counts,
    last_tick: Instant,
    started: Instant,
    /// When each keepalive was sent, since the start.
    keepalive_times: Vec<Duration>,
    /// When each handshake completed, since the start.
    handshake_times: Vec<Duration>,
    failed: bool,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

fn decode_key(name: &str) -> [u8; 32] {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .unwrap_or_else(|_| panic!("{name} is not base64"));
    bytes.try_into().unwrap_or_else(|_| panic!("{name} is not 32 bytes"))
}

impl Client {
    fn check(&mut self, ok: bool, name: &str, detail: impl AsRef<str>) -> bool {
        println!("{} {name}: {}", if ok { "PASS" } else { "FAIL" }, detail.as_ref());
        self.failed |= !ok;
        ok
    }

    fn since_start(&self) -> Duration {
        self.started.elapsed()
    }

    fn send_wire(&mut self, datagram: WgKind) {
        match &datagram {
            WgKind::HandshakeInit(_) => self.counts.handshakes_sent += 1,
            WgKind::Data(data) if data.is_keepalive() => {
                self.counts.keepalives_sent += 1;
                let at = self.since_start();
                self.keepalive_times.push(at);
            }
            WgKind::Data(_) => self.counts.data_sent += 1,
            _ => {}
        }
        let packet = Packet::from(datagram);
        if let Err(error) = self.socket.send_to(packet.as_ref(), self.peer) {
            println!("note: send failed: {error}");
        }
    }

    /// Sends one IP packet into the tunnel; before a session it waits in Tunn's queue and a handshake goes.
    fn send_ip(&mut self, ip: Vec<u8>) {
        let packet = Packet::from_bytes(BytesMut::from(&ip[..]));
        if let Some(datagram) = self.tunn.handle_outgoing_packet(packet, Some(&mut self.mtu)) {
            self.send_wire(datagram);
        }
    }

    fn tick(&mut self) {
        self.last_tick = Instant::now();
        match self.tunn.update_timers() {
            Ok(Some(datagram)) => self.send_wire(datagram),
            Ok(None) => {}
            Err(error) => println!("note: timers: {error:?}"),
        }
    }

    /// Reads datagrams and runs the timers until `deadline`, or until a decrypted packet that `want`
    /// accepts arrives, which it returns.
    fn pump(&mut self, deadline: Instant, want: &mut dyn FnMut(&[u8]) -> bool) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            if now >= self.last_tick + TICK {
                self.tick();
            }
            let wait = (self.last_tick + TICK)
                .min(deadline)
                .saturating_duration_since(Instant::now());
            self.socket
                .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
                .ok();
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(got) => got,
                Err(_) => continue,
            };
            // The server's address stays the configured one (ADR 0035, "Roaming").
            if from != self.peer {
                self.counts.dropped_foreign_sender += 1;
                continue;
            }
            let packet = Packet::from_bytes(BytesMut::from(&buf[..len]));
            let kind = match self.limiter.verify_packet(from, packet) {
                Ok(kind) => kind,
                Err(TunnResult::WriteToNetwork(reply)) => {
                    self.send_wire(reply);
                    continue;
                }
                Err(_) => {
                    self.counts.tunnel_errors += 1;
                    continue;
                }
            };
            let response = matches!(kind, WgKind::HandshakeResp(_));
            match self.tunn.handle_incoming_packet(kind) {
                TunnResult::WriteToNetwork(datagram) => {
                    if response {
                        self.counts.handshakes_completed += 1;
                        let at = self.since_start();
                        self.handshake_times.push(at);
                    }
                    self.send_wire(datagram);
                    let queued: Vec<WgKind> = self.tunn.get_queued_packets(&mut self.mtu).collect();
                    for datagram in queued {
                        self.send_wire(datagram);
                    }
                }
                TunnResult::WriteToTunnel(packet) if packet.is_empty() => self.counts.keepalives_received += 1,
                TunnResult::WriteToTunnel(packet) => {
                    let Ok(ip) = packet.try_into_ipvx() else {
                        self.counts.tunnel_errors += 1;
                        continue;
                    };
                    let bytes: Vec<u8> = ip.either(
                        |v4| v4.into_bytes().as_ref().to_vec(),
                        |v6| v6.into_bytes().as_ref().to_vec(),
                    );
                    let Some(source) = source_of(&bytes) else { continue };
                    if !allowed(source) {
                        self.counts.dropped_outside += 1;
                        println!("note: dropped a decrypted packet from {source}, outside the peer's AllowedIPs");
                        continue;
                    }
                    self.counts.data_received += 1;
                    if want(&bytes) {
                        return Some(bytes);
                    }
                    if std::env::var_os("WGLAB_DEBUG").is_some() {
                        println!("note: not what was awaited: {}", describe(&bytes));
                    }
                }
                TunnResult::Done => {}
                TunnResult::Err(error) => {
                    self.counts.tunnel_errors += 1;
                    println!("note: tunnel: {error:?}");
                }
            }
        }
    }

    fn wait(&mut self, time: Duration) {
        self.pump(Instant::now() + time, &mut |_| false);
    }

    fn ping(&mut self, v6: bool, seq: u16) -> Option<Duration> {
        let start = Instant::now();
        self.send_ip(echo_request(self.v4, self.v6, v6, seq));
        self.pump(start + Duration::from_secs(8), &mut |bytes| {
            is_echo_reply(bytes, v6, seq)
        })?;
        Some(start.elapsed())
    }

    fn udp_echo(&mut self, v6: bool, port: u16, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let (src, dst) = self.ends(v6);
        let builder = ip_builder(src, dst).udp(40007, port);
        let mut ip = Vec::new();
        builder.write(&mut ip, payload).ok()?;
        self.send_ip(ip);
        let start = Instant::now();
        self.pump(start + wait, &mut |bytes| udp_from(bytes, port).is_some())
            .and_then(|bytes| udp_from(&bytes, port))
    }

    fn ends(&self, v6: bool) -> (IpAddr, IpAddr) {
        if v6 {
            (self.v6.into(), SERVER_V6.into())
        } else {
            (self.v4.into(), SERVER_V4.into())
        }
    }

    /// A SYN to the peer's web server, then the request, its answer, and a reset.
    fn tcp(&mut self, v6: bool) -> Result<String, String> {
        let (src, dst) = self.ends(v6);
        let port = if v6 { 41006 } else { 41004 };
        let isn = 0x1000_0000u32;
        let mut syn = Vec::new();
        ip_builder(src, dst)
            .tcp(port, 80, isn, 64240)
            .syn()
            .write(&mut syn, &[])
            .map_err(|e| e.to_string())?;
        self.send_ip(syn);
        let deadline = Instant::now() + Duration::from_secs(8);
        let synack = self
            .pump(
                deadline,
                &mut |bytes| matches!(tcp_of(bytes), Some((h, _)) if h.syn && h.ack && h.destination_port == port),
            )
            .ok_or("no SYN-ACK")?;
        let (h, _) = tcp_of(&synack).ok_or("unreadable SYN-ACK")?;
        if h.acknowledgment_number != isn.wrapping_add(1) {
            return Err(format!(
                "SYN-ACK acknowledges {}, not {}",
                h.acknowledgment_number,
                isn.wrapping_add(1)
            ));
        }
        let server_isn = h.sequence_number;
        let request = b"GET / HTTP/1.0\r\nHost: wglab\r\n\r\n";
        let mut data = Vec::new();
        ip_builder(src, dst)
            .tcp(port, 80, isn.wrapping_add(1), 64240)
            .ack(server_isn.wrapping_add(1))
            .psh()
            .write(&mut data, request)
            .map_err(|e| e.to_string())?;
        self.send_ip(data);
        let answer = self
            .pump(
                deadline,
                &mut |bytes| matches!(tcp_of(bytes), Some((h, p)) if h.destination_port == port && !p.is_empty()),
            )
            .ok_or("SYN-ACK came, but no answer to the request")?;
        let (h, payload) = tcp_of(&answer).ok_or("unreadable answer")?;
        let line = String::from_utf8_lossy(&payload)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let mut rst = Vec::new();
        ip_builder(src, dst)
            .tcp(port, 80, h.acknowledgment_number, 0)
            .rst()
            .write(&mut rst, &[])
            .map_err(|e| e.to_string())?;
        self.send_ip(rst);
        Ok(format!("SYN-ACK acknowledging our ISN+1, then \"{line}\""))
    }
}

fn ip_builder(src: IpAddr, dst: IpAddr) -> etherparse::PacketBuilderStep<etherparse::IpHeaders> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64),
        _ => unreachable!("mixed address families"),
    }
}

fn echo_request(v4: Ipv4Addr, v6addr: Ipv6Addr, v6: bool, seq: u16) -> Vec<u8> {
    let payload = b"datapavan wglab echo";
    let mut ip = Vec::new();
    let written = if v6 {
        PacketBuilder::ipv6(v6addr.octets(), SERVER_V6.octets(), 64)
            .icmpv6_echo_request(0x7777, seq)
            .write(&mut ip, payload)
    } else {
        PacketBuilder::ipv4(v4.octets(), SERVER_V4.octets(), 64)
            .icmpv4_echo_request(0x7777, seq)
            .write(&mut ip, payload)
    };
    written.expect("an echo request builds");
    ip
}

fn describe(bytes: &[u8]) -> String {
    match PacketHeaders::from_ip_slice(bytes) {
        Ok(h) => format!(
            "{:?} {:?} {} bytes of payload",
            h.net.map(|n| match n {
                NetHeaders::Ipv4(h, _) => format!("{} -> {}", Ipv4Addr::from(h.source), Ipv4Addr::from(h.destination)),
                NetHeaders::Ipv6(h, _) => format!("{} -> {}", Ipv6Addr::from(h.source), Ipv6Addr::from(h.destination)),
                NetHeaders::Arp(_) => String::from("arp"),
            }),
            h.transport,
            h.payload.slice().len()
        ),
        Err(e) => format!("unreadable: {e}"),
    }
}

fn source_of(bytes: &[u8]) -> Option<IpAddr> {
    match PacketHeaders::from_ip_slice(bytes).ok()?.net? {
        NetHeaders::Ipv4(h, _) => Some(Ipv4Addr::from(h.source).into()),
        NetHeaders::Ipv6(h, _) => Some(Ipv6Addr::from(h.source).into()),
        NetHeaders::Arp(_) => None,
    }
}

fn is_echo_reply(bytes: &[u8], v6: bool, seq: u16) -> bool {
    let Ok(headers) = PacketHeaders::from_ip_slice(bytes) else {
        return false;
    };
    let want = IcmpEchoHeader { id: 0x7777, seq };
    match headers.transport {
        Some(TransportHeader::Icmpv4(h)) if !v6 => h.icmp_type == Icmpv4Type::EchoReply(want),
        Some(TransportHeader::Icmpv6(h)) if v6 => h.icmp_type == Icmpv6Type::EchoReply(want),
        _ => false,
    }
}

fn udp_from(bytes: &[u8], port: u16) -> Option<Vec<u8>> {
    let headers = PacketHeaders::from_ip_slice(bytes).ok()?;
    match headers.transport {
        Some(TransportHeader::Udp(h)) if h.source_port == port => Some(headers.payload.slice().to_vec()),
        _ => None,
    }
}

fn tcp_of(bytes: &[u8]) -> Option<(etherparse::TcpHeader, Vec<u8>)> {
    let headers = PacketHeaders::from_ip_slice(bytes).ok()?;
    match headers.transport {
        Some(TransportHeader::Tcp(h)) => Some((h, headers.payload.slice().to_vec())),
        _ => None,
    }
}

fn main() {
    let mut peer: Option<SocketAddr> = None;
    let mut v4 = Ipv4Addr::new(10, 77, 0, 2);
    let mut v6 = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 2);
    let mut scenario = String::from("full");
    let mut keepalive: Option<u16> = None;
    let mut skip_rekey = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--skip-rekey" {
            skip_rekey = true;
            continue;
        }
        let value = args.next().unwrap_or_default();
        match arg.as_str() {
            "--peer" => peer = value.parse().ok(),
            "--v4" => v4 = value.parse().expect("--v4"),
            "--v6" => v6 = value.parse().expect("--v6"),
            "--scenario" => scenario = value,
            "--keepalive" => keepalive = value.parse().ok(),
            _ => {
                eprintln!("unknown argument {arg}; see the comment at the top of lab/src/main.rs");
                std::process::exit(2);
            }
        }
    }
    let peer = peer.expect("--peer ADDR:PORT");
    let private = StaticSecret::from(decode_key("WG_PRIVATE"));
    let own_public = PublicKey::from(&private);
    let peer_public = PublicKey::from(decode_key("WG_PEER_PUBLIC"));
    let psk = std::env::var("WG_PSK").ok().map(|_| decode_key("WG_PSK"));
    let limiter = Arc::new(RateLimiter::new(&own_public, 100));
    let tunn = Tunn::new(
        private,
        peer_public,
        psk,
        keepalive,
        IndexTable::from_os_rng(),
        Arc::clone(&limiter),
    );
    let socket = UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
    let mut c = Client {
        tunn,
        limiter,
        socket,
        peer,
        mtu: MtuWatcher::new(MTU),
        counts: Counts::default(),
        last_tick: Instant::now(),
        started: Instant::now(),
        keepalive_times: Vec::new(),
        handshake_times: Vec::new(),
        failed: false,
        v4,
        v6,
    };
    println!(
        "note: scenario {scenario}, peer {peer}, local port {}, preshared key {}, persistent keepalive {keepalive:?}",
        c.socket.local_addr().map(|a| a.port()).unwrap_or(0),
        if psk.is_some() { "yes" } else { "no" },
    );

    match scenario.as_str() {
        "wrong-psk" => {
            let reply = c.ping(false, 1);
            c.wait(Duration::from_secs(4));
            let detail = format!(
                "{} initiations sent, {} completed, {} rejected by Tunn, echo {}",
                c.counts.handshakes_sent,
                c.counts.handshakes_completed,
                c.counts.tunnel_errors,
                if reply.is_some() { "answered" } else { "unanswered" }
            );
            c.check(
                c.counts.handshakes_completed == 0 && reply.is_none() && c.counts.tunnel_errors > 0,
                "wrong-psk-refused",
                detail,
            );
        }
        _ => {
            // The first packet waits in Tunn's queue while the handshake runs, and goes once it completes.
            let first = c.ping(false, 1);
            let detail = format!(
                "{} initiation(s), the queued echo answered after {:?}",
                c.counts.handshakes_sent,
                first.unwrap_or_default()
            );
            let ok = first.is_some() && c.counts.handshakes_completed == 1;
            c.check(
                ok,
                if psk.is_some() {
                    "handshake-with-psk"
                } else {
                    "handshake"
                },
                detail,
            );
            if !ok {
                println!("{:?}", c.counts);
                std::process::exit(1);
            }
            let r = c.ping(false, 2);
            c.check(
                r.is_some(),
                "icmp-v4",
                format!("echo answered in {:?}", r.unwrap_or_default()),
            );
            let r = c.ping(true, 3);
            c.check(
                r.is_some(),
                "icmp-v6",
                format!("echo answered in {:?}", r.unwrap_or_default()),
            );
            for v6 in [false, true] {
                let payload = format!("datapavan wglab udp over IPv{}", if v6 { 6 } else { 4 });
                let back = c.udp_echo(v6, 7, payload.as_bytes(), Duration::from_secs(5));
                let name = if v6 { "udp-v6" } else { "udp-v4" };
                c.check(
                    back.as_deref() == Some(payload.as_bytes()),
                    name,
                    format!("{} bytes echoed", back.map(|b| b.len()).unwrap_or(0)),
                );
            }
            if scenario == "psk" {
                // The peer has PersistentKeepalive for this client: its keepalives arrive while we are idle.
                let before = c.counts.keepalives_received;
                c.wait(Duration::from_secs(8));
                let got = c.counts.keepalives_received - before;
                c.check(
                    got >= 2,
                    "peer-keepalives-received",
                    format!("{got} keepalives from the peer in 8 s of silence"),
                );
            } else {
                full(&mut c, skip_rekey);
            }
        }
    }
    println!("note: {:?}", c.counts);
    println!("local-port {}", c.socket.local_addr().map(|a| a.port()).unwrap_or(0));
    std::process::exit(i32::from(c.failed));
}

/// The rest of the `full` scenario, after the handshake and the echoes.
fn full(c: &mut Client, skip_rekey: bool) {
    for v6 in [false, true] {
        let name = if v6 { "tcp-v6" } else { "tcp-v4" };
        match c.tcp(v6) {
            Ok(detail) => c.check(true, name, detail),
            Err(detail) => c.check(false, name, detail),
        };
    }

    // The reflector on port 9 answers from an address outside this client's AllowedIPs for the peer.
    for v6 in [false, true] {
        let before = c.counts.dropped_outside;
        let back = c.udp_echo(v6, 9, b"reflect", Duration::from_secs(3));
        let dropped = c.counts.dropped_outside - before;
        let name = if v6 {
            "outside-allowed-ips-v6-dropped"
        } else {
            "outside-allowed-ips-v4-dropped"
        };
        c.check(
            back.is_none() && dropped == 1,
            name,
            format!("{dropped} decrypted packet(s) from outside dropped, none passed"),
        );
    }

    // PersistentKeepalive: silence for 12 s, while the timers run once a second.
    if let Some(interval) = c.tunn.persistent_keepalive() {
        let before = c.keepalive_times.len();
        c.wait(Duration::from_secs(12));
        let times: Vec<Duration> = c.keepalive_times[before..].to_vec();
        let gaps: Vec<String> = times
            .windows(2)
            .map(|w| format!("{:.1} s", (w[1] - w[0]).as_secs_f64()))
            .collect();
        let detail = format!(
            "{} keepalives sent in 12 s of silence, {interval} s apart in the configuration, gaps {gaps:?}",
            times.len()
        );
        c.check(times.len() >= 2, "persistent-keepalive", detail);
    }

    // Roaming: a new socket on another local port, as after a network change. The peer learns the new
    // endpoint from the first authenticated packet and answers there.
    let old = c.socket.local_addr().map(|a| a.port()).unwrap_or(0);
    c.socket = UdpSocket::bind("0.0.0.0:0").expect("a new UDP socket");
    let new = c.socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let r = c.ping(false, 20);
    let r6 = c.ping(true, 21);
    c.check(
        r.is_some() && r6.is_some() && old != new,
        "roaming",
        format!("local port {old} -> {new}; the peer answered at the new port (IPv4 and IPv6)"),
    );

    if skip_rekey {
        println!("note: the rekey after REKEY_AFTER_TIME was left out (--skip-rekey)");
        return;
    }
    // The rekey: the initiator starts a new handshake when it sends on a session REKEY_AFTER_TIME old.
    let first = c.handshake_times.first().copied().unwrap_or_default();
    let mut seq = 30;
    let mut answered = 0;
    let mut sent = 0;
    while c.counts.handshakes_completed < 2 && c.since_start() < first + Duration::from_secs(150) {
        sent += 1;
        if c.ping(false, seq).is_some() {
            answered += 1;
        }
        seq += 1;
        c.wait(Duration::from_secs(10));
    }
    let rekey = c.handshake_times.get(1).map(|t| *t - first);
    let after = c.ping(false, 99).is_some() && c.ping(true, 100).is_some();
    let detail = format!(
        "second handshake {:?} after the first, {answered} of {sent} echoes answered meanwhile, the new session carries IPv4 and IPv6: {after}",
        rekey.map(|d| format!("{:.1} s", d.as_secs_f64()))
    );
    let ok = matches!(rekey, Some(d) if d >= Duration::from_secs(120) && d < Duration::from_secs(135))
        && after
        && answered == sent;
    c.check(ok, "rekey-after-time", detail);
}
