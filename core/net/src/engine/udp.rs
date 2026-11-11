//! UDP through the tunnel: one protected socket per flow, opened off the packet loop, the answers
//! relayed back, QUIC Initial packets read for the server name, and lookups to Watch's own DNS address.

use super::chain::{Chain, Route, connect_proxy, io_error};
use super::logbook::FlowBytes;
use super::lookups;
use super::naming::Begun;
use super::upstream::{connect_udp, owner, protect};
use super::{
    CONNECT_TIMEOUT, Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, UDP_IDLE,
    UDP_WAITING, is_tunnel_dns, is_unreachable, lock, send_to_app,
};
use crate::packet::{Packet, UDP, Unreachable};
use crate::socks5::{self, Command, Target};
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{dns, packet, quic};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

/// A UDP flow: the protected socket, and while its first datagrams may still name it, their QUIC
/// Initial packets read so far, with the flow's number.
pub(super) struct UdpFlow {
    way: UdpWay,
    quic: Option<(Opened, Box<quic::Initial>)>,
    /// The app's UID, and the flow's bytes for the log (none for Watch's own DNS address).
    uid: Option<u32>,
    bytes: Option<Arc<FlowBytes>>,
}

/// Where a UDP flow's datagrams go.
#[derive(Clone)]
pub(super) enum UdpWay {
    /// A protected socket connected to the destination.
    Direct(Arc<UdpSocket>),
    /// The tool's UDP relay: each datagram goes with `header`, which names the destination.
    Tool {
        socket: Arc<UdpSocket>,
        header: Arc<[u8]>,
    },
    /// A chained app's lookups to Watch's own DNS address, which Watch answers (ADR 0038).
    Lookups(Arc<Chain>),
}

impl UdpWay {
    /// Sends one datagram's payload; the bytes sent are the payload's. Not for [`UdpWay::Lookups`].
    async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload).await,
            Self::Tool { socket, header } => socket
                .send(&[header, payload].concat())
                .await
                .map(|_| payload.len()),
            Self::Lookups(_) => Ok(payload.len()),
        }
    }

    fn try_send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.try_send(payload),
            Self::Tool { socket, header } => socket
                .try_send(&[header, payload].concat())
                .map(|_| payload.len()),
            Self::Lookups(_) => Ok(payload.len()),
        }
    }

    async fn writable(&self) {
        if let Self::Direct(socket) | Self::Tool { socket, .. } = self {
            let _ = socket.writable().await;
        }
    }
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
        let (way, uid, bytes, quic) = {
            let mut flows = lock(&self.udp);
            match flows.get_mut(&key) {
                Some(UdpEntry::Open(flow)) => (
                    flow.way.clone(),
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
        if let UdpWay::Lookups(chain) = &way {
            tokio::spawn(answer_lookup(
                payload.to_vec(),
                key,
                uid,
                Arc::clone(chain),
                Arc::clone(&self.shared),
                Arc::clone(&self.tun),
            ));
            return;
        }
        let sent = way.send(payload).await;
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
    let (way, control) = match way_for(&shared, uid, destination).await {
        Ok(opened) => opened,
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
        way: way.clone(),
        quic,
        uid,
        bytes: bytes.clone(),
    };
    // The waiting datagrams leave at once, under the table's lock, so that none that comes meanwhile
    // overtakes them: the socket must first be known to take them.
    way.writable().await;
    let mut reads = Vec::new();
    let mut lookups = Vec::new();
    let mut errors = Vec::new();
    let mut questions = Vec::new();
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
            if let UdpWay::Lookups(_) = way {
                questions.push(payload.to_vec());
                continue;
            }
            let sent = way.try_send(payload);
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
    if let UdpWay::Lookups(chain) = way {
        answer_waiting(questions, key, uid, &chain, &shared, &tun, flows);
        return;
    }
    tokio::spawn(answers(
        way,
        control,
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

/// How a new flow's datagrams go, by its route: a protected socket, the tool's relay with the
/// connection that keeps it, or Watch's own answers to a chained app's lookups.
async fn way_for(
    shared: &Arc<Shared>,
    uid: Option<u32>,
    destination: SocketAddr,
) -> io::Result<(UdpWay, Option<TcpStream>)> {
    match shared.route(uid, destination) {
        Route::Direct => match shared.target(destination) {
            Some(target) => connect_udp(shared, target)
                .await
                .map(|socket| (UdpWay::Direct(Arc::new(socket)), None)),
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        },
        Route::Tool(chain) if is_tunnel_dns(destination.ip()) => Ok((UdpWay::Lookups(chain), None)),
        // Without UDP in the tool, a chained app's UDP goes nowhere (VPN.md).
        Route::Tool(chain) if !chain.udp => Err(io::ErrorKind::HostUnreachable.into()),
        Route::Tool(chain) => associate(shared, &chain, destination)
            .await
            .map(|(way, control)| (way, Some(control))),
        Route::Refused => Err(io::ErrorKind::HostUnreachable.into()),
    }
}

/// Answers the lookups that waited for a chained app's flow to open. Android's resolver asks each
/// question from a socket of its own, so the flow's entry goes after a while, with no relay to end it.
fn answer_waiting(
    questions: Vec<Vec<u8>>,
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    chain: &Arc<Chain>,
    shared: &Arc<Shared>,
    tun: &Arc<Tun>,
    flows: UdpFlows,
) {
    for query in questions {
        tokio::spawn(answer_lookup(
            query,
            key,
            uid,
            Arc::clone(chain),
            Arc::clone(shared),
            Arc::clone(tun),
        ));
    }
    tokio::spawn(async move {
        tokio::time::sleep(UDP_IDLE).await;
        lock(&flows).remove(&key);
    });
}

/// A UDP relay of the tool for a flow to `destination`: the request's connection, which must stay open,
/// and a socket to the relay. The relay is on the phone's loopback, as the proxy is; one elsewhere gets
/// a protected socket, so that its datagrams do not loop back into the tunnel.
async fn associate(
    shared: &Arc<Shared>,
    chain: &Chain,
    destination: SocketAddr,
) -> io::Result<(UdpWay, TcpStream)> {
    let target = shared
        .tool_target(destination)
        .ok_or(io::ErrorKind::HostUnreachable)?;
    let opening = async {
        let mut control = connect_proxy(shared, chain.proxy).await?;
        // The address Watch will send from is not known yet: zeros, as RFC 1928 allows.
        let any = Target::Address(packet::unspecified_like(&chain.proxy));
        let bound = socks5::handshake(
            &mut control,
            chain.credentials.as_ref(),
            Command::UdpAssociate,
            &any,
        )
        .await
        .map_err(io_error)?;
        let relay =
            socks5::relay_address(&bound, chain.proxy).ok_or(io::ErrorKind::HostUnreachable)?;
        let socket = UdpSocket::bind(packet::unspecified_like(&relay)).await?;
        if !relay.ip().is_loopback() {
            protect(shared, socket.as_raw_fd()).await?;
        }
        socket.connect(relay).await?;
        let way = UdpWay::Tool {
            socket: Arc::new(socket),
            header: socks5::datagram(&target, &[]).into(),
        };
        Ok((way, control))
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, opening).await {
        Ok(opened) => opened,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// Answers one lookup of a chained app (ADR 0038) and sends the answer to the app.
async fn answer_lookup(
    query: Vec<u8>,
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    chain: Arc<Chain>,
    shared: Arc<Shared>,
    tun: Arc<Tun>,
) {
    let (app, destination) = key;
    let Some(answer) = lookups::answer(&shared, &chain, &query).await else {
        return;
    };
    if let Some(packet) = packet::udp(destination, app, &answer) {
        shared.lookup_answered(uid, packet.len());
        send_to_app(&tun, &shared, &packet).await;
    }
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
    way: UdpWay,
    mut control: Option<TcpStream>,
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
    let (socket, through_tool) = match &way {
        UdpWay::Direct(socket) => (Arc::clone(socket), false),
        UdpWay::Tool { socket, .. } => (Arc::clone(socket), true),
        UdpWay::Lookups(_) => return,
    };
    let mut buffer = vec![0u8; 65_535];
    // The tool keeps a UDP relay for as long as the request's connection is open, and ends it by
    // closing that connection; the flow ends with it.
    let mut closed = std::pin::pin!(async {
        let mut byte = [0u8; 1];
        match control.as_mut() {
            Some(control) => while matches!(control.read(&mut byte).await, Ok(n) if n > 0) {},
            None => std::future::pending::<()>().await,
        }
    });
    // Only a change after the flow opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    loop {
        tokio::select! {
            _ = changes.changed() => break,
            () = &mut closed => break,
            received = tokio::time::timeout(UDP_IDLE, socket.recv(&mut buffer)) => {
                let Ok(received) = received else { break };
                // From the tool's relay, the datagram's header goes; one that is not well formed, or a
                // fragment, is dropped.
                let received = match received {
                    Ok(n) if through_tool => {
                        let Some(length) = socks5::parse_datagram(&buffer[..n]).map(|(_, p)| p.len()) else {
                            continue;
                        };
                        buffer.copy_within(n - length..n, 0);
                        Ok(length)
                    }
                    other => other,
                };
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
