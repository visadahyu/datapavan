//! UDP through the tunnel: one protected socket per flow, opened off the packet loop, the answers
//! relayed back, QUIC Initial packets read for the server name, and lookups to Watch's own DNS address.

use super::logbook::FlowBytes;
use super::naming::Begun;
use super::upstream::{connect_udp, owner};
use super::{
    Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, UDP_IDLE, UDP_WAITING,
    is_tunnel_dns, is_unreachable, lock, send_to_app,
};
use crate::packet::{Packet, UDP, Unreachable};
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{dns, packet, quic};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// A UDP flow: the protected socket, and while its first datagrams may still name it, their QUIC
/// Initial packets read so far, with the flow's number.
pub(super) struct UdpFlow {
    socket: Arc<UdpSocket>,
    quic: Option<(Opened, Box<quic::Initial>)>,
    /// The app's UID, and the flow's bytes for the log (none for Watch's own DNS address).
    uid: Option<u32>,
    bytes: Option<Arc<FlowBytes>>,
}

/// What a flow's QUIC Initial packets gave once they were read to the end, to be noted outside the
/// table's lock.
struct QuicRead {
    opened: Opened,
    read: ServerName,
    was_quic: bool,
}

impl UdpFlow {
    /// Reads a datagram that may still name the flow by its QUIC Initial packets.
    fn read_quic(&mut self, payload: &[u8]) -> Option<QuicRead> {
        let (opened, initial) = self.quic.as_mut()?;
        let opened = *opened;
        let read = initial.push(payload);
        if read == ServerName::Incomplete {
            return None;
        }
        let was_quic = initial.is_quic();
        self.quic = None;
        Some(QuicRead {
            opened,
            read,
            was_quic,
        })
    }
}

/// A UDP flow in the engine's table: opening while Android names its app and its protected socket is
/// made, off the event loop so that no other packet waits for that; then open.
pub(super) enum UdpEntry {
    /// The flow's first datagrams, whole packets in the order the app sent them, at most
    /// [`UDP_WAITING`]: they leave once the socket is there, and the app is known before the first does.
    Opening(Vec<Vec<u8>>),
    Open(UdpFlow),
}

pub(super) type UdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>;

/// A UDP flow's two ends and its app's UID, for the task that relays its answers.
struct UdpEnds {
    app: SocketAddr,
    destination: SocketAddr,
    uid: Option<u32>,
    /// The flow's number and bytes, when the log follows it.
    logged: Option<(u64, Arc<FlowBytes>)>,
}

impl Loop {
    pub(super) async fn udp(&self, packet: &[u8], parsed: &Packet) {
        let Some(payload) = packet::udp_payload(packet, parsed) else {
            Counters::add(&self.shared.counters.skipped, 1);
            return;
        };
        let key = (parsed.source, parsed.destination);
        let (socket, uid, bytes, quic) = {
            let mut flows = lock(&self.udp);
            match flows.get_mut(&key) {
                Some(UdpEntry::Open(flow)) => (
                    Arc::clone(&flow.socket),
                    flow.uid,
                    flow.bytes.clone(),
                    flow.read_quic(payload),
                ),
                Some(UdpEntry::Opening(waiting)) => {
                    if waiting.len() < UDP_WAITING {
                        waiting.push(packet.to_vec());
                    } else {
                        Counters::add(&self.shared.counters.skipped, 1);
                    }
                    return;
                }
                None => {
                    flows.insert(key, UdpEntry::Opening(vec![packet.to_vec()]));
                    drop(flows);
                    tokio::spawn(open_udp(
                        key,
                        Arc::clone(&self.tun),
                        Arc::clone(&self.shared),
                        Arc::clone(&self.udp),
                        self.changes.clone(),
                    ));
                    return;
                }
            }
        };
        note_quic(&self.shared, quic);
        if is_tunnel_dns(key.1.ip()) {
            self.shared.lookup(uid, packet.len());
        }
        let sent = socket.send(payload).await;
        if let Some(error) = count_sent(&self.shared, bytes.as_deref(), packet, parsed, sent) {
            self.send(&error).await;
        }
    }
}

/// Notes what a flow's QUIC Initial packets gave: the name of its hello, or that it could not be read.
fn note_quic(shared: &Shared, quic: Option<QuicRead>) {
    match quic {
        Some(QuicRead {
            opened,
            read: ServerName::Found(hello),
            ..
        }) => shared.hello(opened, &hello, NamedBy::Quic),
        Some(QuicRead { was_quic: true, .. }) => {
            Counters::add(&shared.counters.quic_unread, 1);
        }
        _ => {}
    }
}

/// Counts a datagram that left, or gives the ICMP error that tells the app its destination cannot be
/// reached. One that found the socket's buffer full is dropped, as a full queue drops it.
fn count_sent(
    shared: &Shared,
    bytes: Option<&FlowBytes>,
    packet: &[u8],
    parsed: &Packet,
    sent: io::Result<usize>,
) -> Option<Vec<u8>> {
    match sent {
        Ok(n) => {
            Counters::add(&shared.counters.bytes_up, n as u64);
            if let Some(bytes) = bytes {
                bytes.add_up(n);
                bytes.add_wire_up(packet.len());
            }
            None
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Counters::add(&shared.counters.skipped, 1);
            None
        }
        Err(_) => packet::unreachable(packet, parsed, Unreachable::Host),
    }
}

/// Opens a UDP flow, off the event loop: asks Android whose it is, opens its protected socket, sends
/// the datagrams that waited for it, and starts relaying the answers. The app gets an ICMP error when
/// the destination cannot be reached.
async fn open_udp(
    key: (SocketAddr, SocketAddr),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let (app, destination) = key;
    let uid = owner(&shared, UDP, app, destination).await;
    let (opened, mut flow) = begin_udp(&shared, app, destination, uid);
    let id = opened.id;
    let connected = match shared.target(destination) {
        Some(target) => connect_udp(&shared, target).await,
        None => Err(io::ErrorKind::NetworkUnreachable.into()),
    };
    let socket = match connected {
        Ok(socket) => Arc::new(socket),
        Err(error) => {
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, &tun, &shared, &flows).await;
            return;
        }
    };
    let bytes = shared.record(flow);
    // The tunnel's own DNS address is never QUIC.
    let quic = (!is_tunnel_dns(destination.ip())).then(|| (opened, Box::new(quic::Initial::new())));
    let mut open = UdpFlow {
        socket: Arc::clone(&socket),
        quic,
        uid,
        bytes: bytes.clone(),
    };
    // The waiting datagrams leave at once, under the table's lock, so that none that comes meanwhile
    // overtakes them: the socket must first be known to take them.
    let _ = socket.writable().await;
    let mut reads = Vec::new();
    let mut lookups = Vec::new();
    let mut errors = Vec::new();
    {
        let mut table = lock(&flows);
        let waiting = match table.remove(&key) {
            Some(UdpEntry::Opening(waiting)) => waiting,
            _ => Vec::new(),
        };
        for packet in &waiting {
            let Ok(parsed) = packet::parse(packet) else {
                continue;
            };
            let Some(payload) = packet::udp_payload(packet, &parsed) else {
                continue;
            };
            reads.push(open.read_quic(payload));
            if is_tunnel_dns(destination.ip()) {
                lookups.push(packet.len());
            }
            let sent = socket.try_send(payload);
            errors.extend(count_sent(&shared, bytes.as_deref(), packet, &parsed, sent));
        }
        table.insert(key, UdpEntry::Open(open));
    }
    for read in reads {
        note_quic(&shared, read);
    }
    // Counted before the answers can be: an answer is counted only for a lookup already counted.
    for length in lookups {
        shared.lookup(uid, length);
    }
    for error in errors {
        send_to_app(&tun, &shared, &error).await;
    }
    tokio::spawn(answers(
        socket,
        UdpEnds {
            app,
            destination,
            uid,
            logged: bytes.map(|b| (id, b)),
        },
        tun,
        shared,
        flows,
        changes,
    ));
}

/// What the engine knows of a new UDP flow once Android named its app: its number, name and DNS use.
fn begin_udp(
    shared: &Shared,
    app: SocketAddr,
    destination: SocketAddr,
    uid: Option<u32>,
) -> (Opened, Flow) {
    let Begun {
        id,
        name,
        named_by,
        network,
    } = shared.begin(destination, uid);
    let by_dns = (named_by == NamedBy::Dns)
        .then_some(name.as_deref())
        .flatten();
    let (dns, resolver) = shared.dns_use(destination, by_dns);
    let opened = Opened {
        id,
        port: destination.port(),
        dns,
    };
    let flow = Flow {
        id,
        protocol: UDP,
        app,
        destination,
        uid,
        outcome: Outcome::Opened,
        name,
        named_by,
        ech: Ech::Absent,
        dns,
        resolver,
        network,
    };
    (opened, flow)
}

/// A UDP flow whose socket could not be opened: it is recorded, its waiting datagrams are dropped, and
/// an unreachable destination gets the app one ICMP error, quoting its first datagram.
async fn udp_failed(
    key: (SocketAddr, SocketAddr),
    flow: Flow,
    tun: &Tun,
    shared: &Shared,
    flows: &UdpFlows,
) {
    let unreachable = flow.outcome == Outcome::Unreachable;
    shared.record(flow);
    let waiting = match lock(flows).remove(&key) {
        Some(UdpEntry::Opening(waiting)) => waiting,
        _ => Vec::new(),
    };
    let error = waiting.first().filter(|_| unreachable).and_then(|first| {
        packet::parse(first)
            .ok()
            .and_then(|parsed| packet::unreachable(first, &parsed, Unreachable::Host))
    });
    if let Some(error) = error {
        send_to_app(tun, shared, &error).await;
    }
}

/// Wraps each answer of a UDP flow in an IP packet to the app, until the flow falls silent or the
/// network beneath changes.
async fn answers(
    socket: Arc<UdpSocket>,
    ends: UdpEnds,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
    let UdpEnds {
        app,
        destination,
        uid,
        logged,
    } = ends;
    let mut buffer = vec![0u8; 65_535];
    // Only a change after the flow opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    loop {
        tokio::select! {
            _ = changes.changed() => break,
            received = tokio::time::timeout(UDP_IDLE, socket.recv(&mut buffer)) => {
                let Ok(received) = received else { break };
                let answer = match received {
                    Ok(n) => {
                        Counters::add(&shared.counters.bytes_down, n as u64);
                        if let Some((_, bytes)) = &logged {
                            bytes.add_down(n);
                        }
                        // Android's resolver names every app's flows; an app's own, only its own.
                        if destination.port() == 53 {
                            if is_tunnel_dns(destination.ip()) {
                                shared.learn(&buffer[..n], None);
                                if shared.uncached_answers.load(Ordering::Relaxed) {
                                    dns::uncache(&mut buffer[..n]);
                                }
                            } else if uid.is_some() {
                                shared.learn(&buffer[..n], uid);
                            }
                        }
                        packet::udp(destination, app, &buffer[..n])
                    }
                    // The server's host answered that no one listens there.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        let quoted = packet::udp(app, destination, &[]);
                        quoted.and_then(|q| packet::parse(&q).ok().and_then(|p| packet::unreachable(&q, &p, Unreachable::Port)))
                    }
                    Err(_) => break,
                };
                if let Some(answer) = answer {
                    match &logged {
                        Some((_, bytes)) => bytes.add_wire_down(answer.len()),
                        None if destination.port() == 53 && is_tunnel_dns(destination.ip()) => {
                            shared.lookup_answered(uid, answer.len());
                        }
                        None => {}
                    }
                    if tun.send(&answer).await.is_err() {
                        break;
                    }
                    Counters::add(&shared.counters.packets_out, 1);
                }
            }
        }
    }
    lock(&flows).remove(&(app, destination));
    if let Some((id, _)) = logged {
        shared.finish(id);
    }
}
