//! Engine 2: Android's own TCP stack terminates the connections, as the "system" stack of sing-box
//! and mihomo does. A TCP packet from an app to `D:DP` is rewritten to come from a fake peer
//! `FAKE:fp` and go to a listener of the engine's on the tunnel address; the kernel answers it, and
//! the answer is rewritten back to come from `D:DP`. The listener accepts the connection as if from
//! `FAKE:fp`, the table maps that to `D:DP`, and an ordinary socket outside the tunnel goes there.
//! The engine itself only rewrites addresses, ports and checksums. UDP is relayed in userspace.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use std::os::fd::AsRawFd;

use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::OwnerLookup;
use crate::stats::{Counted, Stats};
use crate::tun::Tun;
use crate::userspace::look_up;

/// The tunnel's own addresses, as the Kotlin side sets them with `Builder.addAddress`.
pub const TUN4: Ipv4Addr = Ipv4Addr::new(10, 111, 0, 1);
/// The fake peer the kernel sees for every connection, inside the tunnel's /24.
pub const FAKE4: Ipv4Addr = Ipv4Addr::new(10, 111, 0, 2);
/// The IPv6 tunnel address, inside fd00:111::/64.
pub const TUN6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x111, 0, 0, 0, 0, 0, 1);
/// The IPv6 fake peer.
pub const FAKE6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x111, 0, 0, 0, 0, 0, 2);

const TCP: u8 = 6;
const UDP: u8 = 17;
const UDP_IDLE: Duration = Duration::from_secs(60);
const TCP_IDLE: Duration = Duration::from_secs(600);
const FIRST_PORT: u16 = 10_000;
const LAST_PORT: u16 = 60_000;

/// One rewritten TCP connection: the app's port and the real destination. It opens once the real
/// server has accepted; until then the app's SYN is held, as gVisor's forwarder does, so that the
/// app's socket still exists when Android is asked whose it is, and a refused server looks refused.
#[derive(Clone, Copy)]
struct Entry {
    app_port: u16,
    destination: SocketAddr,
    seen: Instant,
    open: bool,
}

/// What to do with a TCP packet from the tunnel.
enum Tcp {
    /// Rewritten in place: write it back.
    Send,
    /// The first SYN of a connection: connect upstream first.
    Hold { fake_port: u16, app: SocketAddr, destination: SocketAddr, sequence: u32 },
    /// A segment of a connection the engine does not know, as after it restarted: answer with a
    /// reset, as a real stack would, so that the app opens a new connection at once.
    Reset(Vec<u8>),
    Drop,
}

/// The TCP table, by fake port and by the app's side.
#[derive(Default)]
struct Nat {
    by_fake: HashMap<u16, Entry>,
    by_app: HashMap<(u16, SocketAddr), u16>,
    next: u16,
}

impl Nat {
    /// The fake port of a connection, whether it is open, and whether this call created it.
    fn fake_port(&mut self, app_port: u16, destination: SocketAddr, syn: bool) -> Option<(u16, bool, bool)> {
        if let Some(&port) = self.by_app.get(&(app_port, destination)) {
            let entry = self.by_fake.get_mut(&port)?;
            entry.seen = Instant::now();
            return Some((port, entry.open, false));
        }
        if !syn {
            return None;
        }
        for _ in FIRST_PORT..=LAST_PORT {
            self.next = if self.next < FIRST_PORT || self.next >= LAST_PORT { FIRST_PORT } else { self.next + 1 };
            if !self.by_fake.contains_key(&self.next) {
                let port = self.next;
                self.by_fake.insert(port, Entry { app_port, destination, seen: Instant::now(), open: false });
                self.by_app.insert((app_port, destination), port);
                return Some((port, false, true));
            }
        }
        None
    }

    fn open(&mut self, port: u16) {
        if let Some(entry) = self.by_fake.get_mut(&port) {
            entry.open = true;
        }
    }

    fn remove(&mut self, port: u16) {
        if let Some(entry) = self.by_fake.remove(&port) {
            self.by_app.remove(&(entry.app_port, entry.destination));
        }
    }

    fn by_fake(&mut self, port: u16) -> Option<Entry> {
        let entry = self.by_fake.get_mut(&port)?;
        entry.seen = Instant::now();
        Some(*entry)
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        let stale: Vec<u16> = self.by_fake.iter().filter(|(_, e)| now.duration_since(e.seen) > TCP_IDLE).map(|(p, _)| *p).collect();
        for port in stale {
            if let Some(entry) = self.by_fake.remove(&port) {
                self.by_app.remove(&(entry.app_port, entry.destination));
            }
        }
    }
}

type Shared<T> = Arc<Mutex<T>>;

fn lock<T>(shared: &Shared<T>) -> std::sync::MutexGuard<'_, T> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs until `stop` changes or the tunnel closes.
pub async fn run(tun: Tun, mtu: u16, stats: Arc<Stats>, owners: Arc<dyn OwnerLookup>, proxy: Option<SocketAddr>, mut stop: watch::Receiver<bool>) {
    let tun = Arc::new(tun);
    let nat: Shared<Nat> = Arc::default();
    let pending: Shared<HashMap<u16, TcpStream>> = Arc::default();
    let udp: Shared<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>> = Arc::default();
    let Ok(listener4) = TcpListener::bind((TUN4, 0)).await else { return };
    let listener6 = TcpListener::bind((TUN6, 0)).await.ok();
    let Ok(port4) = listener4.local_addr().map(|a| a.port()) else { return };
    let port6 = listener6.as_ref().and_then(|l| l.local_addr().ok()).map_or(0, |a| a.port());
    tokio::spawn(accept(listener4, Arc::clone(&pending), Arc::clone(&stats)));
    if let Some(listener6) = listener6 {
        tokio::spawn(accept(listener6, Arc::clone(&pending), Arc::clone(&stats)));
    }
    let mut packet = vec![0u8; usize::from(mtu).max(1500) + 64];
    // No timer of its own: an idle tunnel must not wake the phone. Stale connections are swept when
    // packets come anyway, at most once a minute.
    let mut swept = Instant::now();
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            read = tun.recv(&mut packet) => {
                let Ok(n) = read else { return };
                if swept.elapsed() > Duration::from_secs(60) {
                    lock(&nat).sweep();
                    swept = Instant::now();
                }
                let packet = &mut packet[..n];
                match parse(packet) {
                    Some(Parsed { protocol: TCP, header, .. }) => match rewrite_tcp(packet, header, &nat, port4, port6) {
                        Tcp::Send => {
                            let _ = tun.send(packet).await;
                        }
                        Tcp::Hold { fake_port, app, destination, sequence } => {
                            Stats::add(&stats.tcp_flows, 1);
                            let listener = if app.is_ipv4() { port4 } else { port6 };
                            let held = Held { packet: packet.to_vec(), header, fake_port, listener, app, destination, sequence };
                            tokio::spawn(open(held, proxy, Arc::clone(&tun), Arc::clone(&nat), Arc::clone(&pending), Arc::clone(&stats), Arc::clone(&owners)));
                        }
                        Tcp::Reset(reset) => {
                            let _ = tun.send(&reset).await;
                        }
                        Tcp::Drop => {}
                    },
                    Some(Parsed { protocol: UDP, header, source, destination }) => {
                        relay_udp(packet, header, source, destination, &tun, &udp, &stats, &owners).await;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// What the engine needs to know of a packet: its protocol, the IP header's length and the ends.
struct Parsed {
    protocol: u8,
    header: usize,
    source: SocketAddr,
    destination: SocketAddr,
}

fn port(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]))
}

fn parse(packet: &[u8]) -> Option<Parsed> {
    let version = packet.first()? >> 4;
    let (protocol, header, source, destination) = match version {
        4 => {
            let header = usize::from(packet.first()? & 0x0f) * 4;
            let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            (*packet.get(9)?, header, IpAddr::from(source), IpAddr::from(destination))
        }
        // Extension headers are not followed in the spike.
        6 => {
            let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            (*packet.get(6)?, 40, IpAddr::from(source), IpAddr::from(destination))
        }
        _ => return None,
    };
    Some(Parsed {
        protocol,
        header,
        source: SocketAddr::new(source, port(packet, header)?),
        destination: SocketAddr::new(destination, port(packet, header + 2)?),
    })
}

/// RFC 1624: the one's-complement checksum after `old` became `new`, both of whole 16-bit words.
fn adjust(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (o, n) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        sum += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Writes new addresses and ports into an IPv4 or IPv6 TCP packet and fixes both checksums.
fn set_ends(packet: &mut [u8], header: usize, source: SocketAddr, destination: SocketAddr) -> Option<()> {
    let v4 = packet.first()? >> 4 == 4;
    let (src_at, dst_at, len) = if v4 { (12, 16, 4) } else { (8, 24, 16) };
    let old: Vec<u8> = [packet.get(src_at..src_at + len)?, packet.get(dst_at..dst_at + len)?, packet.get(header..header + 4)?].concat();
    let ip = |a: IpAddr| match a {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let new: Vec<u8> = [ip(source.ip()), ip(destination.ip()), source.port().to_be_bytes().to_vec(), destination.port().to_be_bytes().to_vec()].concat();
    if new.len() != old.len() {
        return None;
    }
    packet.get_mut(src_at..src_at + len)?.copy_from_slice(&new[..len]);
    packet.get_mut(dst_at..dst_at + len)?.copy_from_slice(&new[len..2 * len]);
    packet.get_mut(header..header + 4)?.copy_from_slice(&new[2 * len..]);
    let tcp_sum = port(packet, header + 16)?;
    packet.get_mut(header + 16..header + 18)?.copy_from_slice(&adjust(tcp_sum, &old, &new).to_be_bytes());
    if v4 {
        let ip_sum = port(packet, 10)?;
        packet.get_mut(10..12)?.copy_from_slice(&adjust(ip_sum, &old[..2 * len], &new[..2 * len]).to_be_bytes());
    }
    Some(())
}

/// Decides what to do with one TCP packet, rewriting it in place when it is to be sent.
fn rewrite_tcp(packet: &mut [u8], header: usize, nat: &Shared<Nat>, port4: u16, port6: u16) -> Tcp {
    let Some(parsed) = parse(packet) else { return Tcp::Drop };
    let Some(flags) = packet.get(header + 13).copied() else { return Tcp::Drop };
    let (tun, fake, listener) = match parsed.source.ip() {
        IpAddr::V4(_) => (IpAddr::V4(TUN4), IpAddr::V4(FAKE4), port4),
        IpAddr::V6(_) => (IpAddr::V6(TUN6), IpAddr::V6(FAKE6), port6),
    };
    if listener == 0 {
        return Tcp::Drop;
    }
    let mut nat = lock(nat);
    if parsed.source == SocketAddr::new(tun, listener) && parsed.destination.ip() == fake {
        // The kernel's answer: back to the app, as if from the real destination.
        let Some(entry) = nat.by_fake(parsed.destination.port()) else { return Tcp::Drop };
        drop(nat);
        return if set_ends(packet, header, entry.destination, SocketAddr::new(tun, entry.app_port)).is_some() { Tcp::Send } else { Tcp::Drop };
    }
    if parsed.source.ip() != tun {
        return Tcp::Drop;
    }
    let syn = flags & 0x02 != 0 && flags & 0x10 == 0;
    let Some((fake_port, open, created)) = nat.fake_port(parsed.source.port(), parsed.destination, syn) else {
        drop(nat);
        // No reset for a reset; otherwise RFC 9293 3.10.7.1: answer an ACK with a reset numbered as
        // that acknowledgement.
        if flags & 0x04 != 0 || flags & 0x10 == 0 {
            return Tcp::Drop;
        }
        let Some(ack) = packet.get(header + 8..header + 12) else { return Tcp::Drop };
        let ack = u32::from_be_bytes([ack[0], ack[1], ack[2], ack[3]]);
        return reset_for(parsed.source, parsed.destination, ack).map_or(Tcp::Drop, Tcp::Reset);
    };
    drop(nat);
    if created {
        let Some(bytes) = packet.get(header + 4..header + 8) else { return Tcp::Drop };
        let sequence = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        return Tcp::Hold { fake_port, app: parsed.source, destination: parsed.destination, sequence };
    }
    // A SYN sent again while the real server has not answered yet is dropped; the held one goes on.
    if !open {
        return Tcp::Drop;
    }
    if set_ends(packet, header, SocketAddr::new(fake, fake_port), SocketAddr::new(tun, listener)).is_some() { Tcp::Send } else { Tcp::Drop }
}

/// A connection's first SYN, held until the real server accepts.
struct Held {
    packet: Vec<u8>,
    header: usize,
    fake_port: u16,
    listener: u16,
    app: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
}

/// Asks Android whose the connection is while the app still waits for its SYN-ACK, connects to the
/// real server, and only then lets the SYN on to the kernel's listener. A server that refuses or
/// cannot be reached gets the app a reset, as without a VPN.
async fn open(mut held: Held, proxy: Option<SocketAddr>, tun: Arc<Tun>, nat: Shared<Nat>, pending: Shared<HashMap<u16, TcpStream>>, stats: Arc<Stats>, owners: Arc<dyn OwnerLookup>) {
    let lookup = look_up(&owners, &stats, 6, held.app, held.destination);
    let connect = async {
        let Some(proxy) = proxy else { return connect_protected(&owners, held.destination).await };
        let mut stream = connect_protected(&owners, proxy).await?;
        crate::socks::connect(&mut stream, held.destination).await?;
        Ok(stream)
    };
    let (_uid, upstream) = tokio::join!(lookup, connect);
    let (tun_ip, fake) = match held.app.ip() {
        IpAddr::V4(_) => (IpAddr::V4(TUN4), IpAddr::V4(FAKE4)),
        IpAddr::V6(_) => (IpAddr::V6(TUN6), IpAddr::V6(FAKE6)),
    };
    match upstream {
        Ok(upstream) => {
            lock(&pending).insert(held.fake_port, upstream);
            lock(&nat).open(held.fake_port);
            if set_ends(&mut held.packet, held.header, SocketAddr::new(fake, held.fake_port), SocketAddr::new(tun_ip, held.listener)).is_some() {
                let _ = tun.send(&held.packet).await;
            }
        }
        Err(e) => {
            crate::stats::note_error(&format!("connect {}: {e}", held.destination));
            Stats::add(&stats.connect_errors, 1);
            lock(&nat).remove(held.fake_port);
            if let Some(reset) = reset(held.app, held.destination, held.sequence) {
                let _ = tun.send(&reset).await;
            }
        }
    }
}

/// A TCP reset from `destination` to the app, answering its SYN numbered `sequence`.
fn reset(app: SocketAddr, destination: SocketAddr, sequence: u32) -> Option<Vec<u8>> {
    let mut packet = Vec::new();
    let built = match (destination.ip(), app.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => etherparse::PacketBuilder::ipv4(from.octets(), to.octets(), 64)
            .tcp(destination.port(), app.port(), 0, 0)
            .rst()
            .ack(sequence.wrapping_add(1))
            .write(&mut packet, &[]),
        (IpAddr::V6(from), IpAddr::V6(to)) => etherparse::PacketBuilder::ipv6(from.octets(), to.octets(), 64)
            .tcp(destination.port(), app.port(), 0, 0)
            .rst()
            .ack(sequence.wrapping_add(1))
            .write(&mut packet, &[]),
        _ => return None,
    };
    built.ok().map(|()| packet)
}

/// A bare reset from `destination` to the app, numbered `sequence`, for a segment of an unknown
/// connection.
fn reset_for(app: SocketAddr, destination: SocketAddr, sequence: u32) -> Option<Vec<u8>> {
    let mut packet = Vec::new();
    let built = match (destination.ip(), app.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => etherparse::PacketBuilder::ipv4(from.octets(), to.octets(), 64)
            .tcp(destination.port(), app.port(), sequence, 0)
            .rst()
            .write(&mut packet, &[]),
        (IpAddr::V6(from), IpAddr::V6(to)) => etherparse::PacketBuilder::ipv6(from.octets(), to.octets(), 64)
            .tcp(destination.port(), app.port(), sequence, 0)
            .rst()
            .write(&mut packet, &[]),
        _ => return None,
    };
    built.ok().map(|()| packet)
}

/// Accepts the rewritten connections and relays each over the upstream socket opened for it.
async fn accept(listener: TcpListener, pending: Shared<HashMap<u16, TcpStream>>, stats: Arc<Stats>) {
    while let Ok((mut app, peer)) = listener.accept().await {
        let Some(upstream) = lock(&pending).remove(&peer.port()) else { continue };
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let _ = upstream.set_nodelay(true);
            let _ = app.set_nodelay(true);
            let mut upstream = Counted::new(upstream, Arc::clone(&stats));
            let _ = tokio::io::copy_bidirectional(&mut app, &mut upstream).await;
            let _ = upstream.shutdown().await;
        });
    }
}

/// Connects outside the tunnel: the watch app is inside it, so its own sockets must be protected
/// before they connect.
async fn connect_protected(owners: &Arc<dyn OwnerLookup>, destination: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = if destination.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    let (owners, fd) = (Arc::clone(owners), socket.as_raw_fd());
    let protected = tokio::task::spawn_blocking(move || owners.protect(fd)).await.unwrap_or(false);
    if !protected {
        return Err(std::io::Error::other("protect failed"));
    }
    socket.connect(destination).await
}

/// Sends one UDP datagram from an app on through a socket of its own flow, opening it on first use.
#[allow(clippy::too_many_arguments)]
async fn relay_udp(
    packet: &[u8],
    header: usize,
    app: SocketAddr,
    destination: SocketAddr,
    tun: &Arc<Tun>,
    flows: &Shared<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>,
    stats: &Arc<Stats>,
    owners: &Arc<dyn OwnerLookup>,
) {
    let Some(payload) = packet.get(header + 8..) else { return };
    let existing = lock(flows).get(&(app, destination)).cloned();
    let socket = if let Some(socket) = existing {
        socket
    } else {
        let bind: SocketAddr = if destination.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
        let Ok(socket) = UdpSocket::bind(bind).await else { return };
        let (platform, fd) = (Arc::clone(owners), socket.as_raw_fd());
        if !tokio::task::spawn_blocking(move || platform.protect(fd)).await.unwrap_or(false) || socket.connect(destination).await.is_err() {
            Stats::add(&stats.connect_errors, 1);
            return;
        }
        let socket = Arc::new(socket);
        lock(flows).insert((app, destination), Arc::clone(&socket));
        Stats::add(&stats.udp_flows, 1);
        let _uid = look_up(owners, stats, 17, app, destination).await;
        tokio::spawn(answers(Arc::clone(&socket), app, destination, Arc::clone(tun), Arc::clone(flows), Arc::clone(stats)));
        socket
    };
    if socket.send(payload).await.is_ok() {
        Stats::add(&stats.bytes_up, payload.len() as u64);
    }
}

/// Wraps each answer of a UDP flow in an IP packet to the app until the flow falls silent.
async fn answers(
    socket: Arc<UdpSocket>,
    app: SocketAddr,
    destination: SocketAddr,
    tun: Arc<Tun>,
    flows: Shared<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>,
    stats: Arc<Stats>,
) {
    let mut buffer = vec![0u8; 65_535];
    let mut packet = Vec::with_capacity(65_600);
    while let Ok(Ok(n)) = tokio::time::timeout(UDP_IDLE, socket.recv(&mut buffer)).await {
        packet.clear();
        let built = match (destination.ip(), app.ip()) {
            (IpAddr::V4(from), IpAddr::V4(to)) => etherparse::PacketBuilder::ipv4(from.octets(), to.octets(), 64)
                .udp(destination.port(), app.port())
                .write(&mut packet, &buffer[..n]),
            (IpAddr::V6(from), IpAddr::V6(to)) => etherparse::PacketBuilder::ipv6(from.octets(), to.octets(), 64)
                .udp(destination.port(), app.port())
                .write(&mut packet, &buffer[..n]),
            _ => break,
        };
        if built.is_err() || tun.send(&packet).await.is_err() {
            break;
        }
        Stats::add(&stats.bytes_down, n as u64);
    }
    lock(&flows).remove(&(app, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A SYN from 10.111.0.1:40000 to 93.184.216.34:80 with valid checksums (built by etherparse).
    fn syn() -> Vec<u8> {
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv4(TUN4.octets(), [93, 184, 216, 34], 64)
            .tcp(40_000, 80, 1, 65_535)
            .syn()
            .write(&mut packet, &[])
            .unwrap_or_default();
        packet
    }

    fn checksums_valid(packet: &[u8]) -> bool {
        let Ok(sliced) = etherparse::SlicedPacket::from_ip(packet) else { return false };
        let Some(etherparse::NetSlice::Ipv4(ip)) = sliced.net else { return false };
        let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport else { return false };
        let header = ip.header().to_header();
        let ip_ok = header.calc_header_checksum() == header.header_checksum;
        let tcp_ok = tcp.to_header().calc_checksum_ipv4(&header, tcp.payload()).ok() == Some(tcp.checksum());
        ip_ok && tcp_ok
    }

    #[test]
    fn rewrites_a_syn_to_the_listener_and_the_answer_back() {
        let nat: Shared<Nat> = Arc::default();
        let mut packet = syn();
        assert!(checksums_valid(&packet));
        // The first SYN is held until the real server accepts; then it goes on, rewritten.
        let Tcp::Hold { fake_port, sequence, .. } = rewrite_tcp(&mut packet, 20, &nat, 5555, 0) else { panic!("not held") };
        assert_eq!(sequence, 1);
        assert!(matches!(rewrite_tcp(&mut syn(), 20, &nat, 5555, 0), Tcp::Drop), "a repeated SYN is dropped while held");
        lock(&nat).open(fake_port);
        assert!(set_ends(&mut packet, 20, SocketAddr::from((FAKE4, fake_port)), SocketAddr::from((TUN4, 5555))).is_some());
        let parsed = parse(&packet).map(|p| (p.source, p.destination));
        let fake_port = parsed.map_or(0, |(s, _)| s.port());
        assert_eq!(parsed.map(|(s, d)| (s.ip(), d)), Some((IpAddr::V4(FAKE4), SocketAddr::from((TUN4, 5555)))));
        assert!(checksums_valid(&packet));

        let mut answer = Vec::new();
        etherparse::PacketBuilder::ipv4(TUN4.octets(), FAKE4.octets(), 64)
            .tcp(5555, fake_port, 7, 65_535)
            .syn()
            .ack(2)
            .write(&mut answer, &[])
            .unwrap_or_default();
        assert!(matches!(rewrite_tcp(&mut answer, 20, &nat, 5555, 0), Tcp::Send));
        let back = parse(&answer).map(|p| (p.source, p.destination));
        assert_eq!(back, Some((SocketAddr::from(([93, 184, 216, 34], 80)), SocketAddr::from((TUN4, 40_000)))));
        assert!(checksums_valid(&answer));
    }

    #[test]
    fn answers_a_refused_syn_with_a_valid_reset() {
        let app = SocketAddr::from((TUN4, 40_000));
        let server = SocketAddr::from(([93, 184, 216, 34], 80));
        let packet = reset(app, server, 1).unwrap_or_default();
        assert_eq!(parse(&packet).map(|p| (p.source, p.destination)), Some((server, app)));
        assert!(checksums_valid(&packet));
    }

    #[test]
    fn resets_a_segment_of_an_unknown_connection() {
        let nat: Shared<Nat> = Arc::default();
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv4(TUN4.octets(), [1, 1, 1, 1], 64)
            .tcp(40_001, 443, 1, 65_535)
            .ack(77)
            .write(&mut packet, &[])
            .unwrap_or_default();
        let Tcp::Reset(reset) = rewrite_tcp(&mut packet, 20, &nat, 5555, 0) else { panic!("no reset") };
        assert!(checksums_valid(&reset));
        let sliced = etherparse::SlicedPacket::from_ip(&reset).ok();
        let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.and_then(|s| s.transport) else { panic!("not tcp") };
        assert!(tcp.rst() && !tcp.ack());
        assert_eq!((tcp.source_port(), tcp.destination_port(), tcp.sequence_number()), (443, 40_001, 77));
    }
}
