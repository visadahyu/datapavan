//! UDP through the tunnel (ADR 0044, decision 1). On the direct path, each app socket gets one
//! mapping: one protected socket, not connected, whatever the destination (RFC 4787, REQ-1), which lets
//! in only what comes from an address the app sent to (address-dependent filtering). Each destination
//! stays a flow of its own in the log, with its own name, bytes and QUIC reading. Lookups to Watch's
//! own DNS address, and chained apps' UDP, keep one socket for each flow. Sockets are opened off the
//! packet loop, and answers are read into one buffer for each engine thread.

use super::chain::{Chain, Route, connect_proxy, io_error};
use super::logbook::FlowBytes;
use super::lookups;
use super::naming::Begun;
use super::upstream::{connect_udp, owner, protect};
use super::{
    BATCH, Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, errors, is_unreachable,
    lock, send_to_app,
};
use crate::packet::{Packet, UDP, Unreachable};
use crate::socks5::{self, Command, Target};
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{dns, packet, quic};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, Interest};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, watch};

/// How long a lookup to Watch's own DNS address waits for its answer before its flow ends (ADR 0044,
/// decision 3). Android's resolver gives up sooner.
const LOOKUP_WAIT: Duration = Duration::from_secs(10);

/// The largest datagram: every answer reaches the app whole.
const LARGEST: usize = 65_535;

thread_local! {
    /// The one receive buffer of each engine thread, instead of one for each flow (ADR 0044, decision
    /// 3). It is only ever borrowed between two awaits.
    static RECEIVED: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Runs `read` with the engine thread's receive buffer, made the first time it is needed.
fn with_buffer<T>(read: impl FnOnce(&mut [u8]) -> T) -> T {
    RECEIVED.with(|cell| match cell.try_borrow_mut() {
        Ok(mut buffer) => {
            if buffer.len() < LARGEST {
                buffer.resize(LARGEST, 0);
            }
            read(&mut buffer)
        }
        // `read` never comes back here; were it to, it would get a buffer of its own.
        Err(_) => read(&mut vec![0; LARGEST]),
    })
}

/// A UDP flow with a socket of its own (a lookup to Watch's own DNS address, or a chained app's
/// flow), and while its first datagrams may still name it, their QUIC Initial packets read so far,
/// with the flow's number.
pub(super) struct UdpFlow {
    /// The flow's number, which tells its entry from a later flow's between the same two ends.
    id: u64,
    way: UdpWay,
    quic: Option<(Opened, Box<quic::Initial>)>,
    /// The app's UID, and the flow's bytes for the log (none for Watch's own DNS address).
    uid: Option<u32>,
    bytes: Option<Arc<FlowBytes>>,
    /// The lookups sent to the network's resolver that still wait for their answer.
    unanswered: u32,
}

/// Where the datagrams of a flow with a socket of its own go.
#[derive(Clone)]
pub(super) enum UdpWay {
    /// A protected socket connected to the network's resolver, for lookups to Watch's own DNS address.
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

/// Reads a datagram that may still name its flow by its QUIC Initial packets.
fn read_quic(quic: &mut Option<(Opened, Box<quic::Initial>)>, payload: &[u8]) -> Option<QuicRead> {
    let (opened, initial) = quic.as_mut()?;
    let opened = *opened;
    let read = initial.push(payload);
    if read == ServerName::Incomplete {
        return None;
    }
    let was_quic = initial.is_quic();
    *quic = None;
    Some(QuicRead {
        opened,
        read,
        was_quic,
    })
}

/// A destination in the engine's table: opening while Android names its app and its way is made, off
/// the event loop so that no other packet waits for that; then, for a flow with a socket of its own,
/// open.
pub(super) enum UdpEntry {
    /// The destination's first datagrams, whole packets in the order the app sent them, at most
    /// `Limits::udp_waiting`: they leave once the way is there, and the app is known before the first
    /// does.
    Opening(Vec<Vec<u8>>),
    Open(UdpFlow),
}

/// An app socket's way out on the direct path: one protected socket, whatever the destination.
struct Mapping {
    /// Its number, which tells it from a later mapping of the same app socket.
    id: u64,
    socket: Arc<UdpSocket>,
    /// The app's UID, as Android named it for the mapping's first destination.
    uid: Option<u32>,
    /// Each destination the app sent to, and each other port of their addresses that sent to the app:
    /// each a flow of its own.
    peers: HashMap<SocketAddr, Peer>,
    /// How many peers each address has: what comes from these addresses is let in.
    addresses: HashMap<IpAddr, usize>,
    /// When the last datagram passed, either way.
    last: Instant,
    /// Wakes the mapping's task when the mapping is ended from elsewhere.
    ended: Arc<Notify>,
}

/// A peer of a mapping: a flow in the log.
struct Peer {
    /// The flow's number.
    id: u64,
    /// While the app's first datagrams to it may still name it, their QUIC Initial packets read so far.
    quic: Option<(Opened, Box<quic::Initial>)>,
    bytes: Option<Arc<FlowBytes>>,
    /// When the last datagram passed, either way.
    last: Instant,
}

impl Peer {
    /// A new peer of the app at `app`, with its flow begun and recorded. `quic` when the app's
    /// datagrams to it may name it.
    fn new(
        shared: &Shared,
        app: SocketAddr,
        address: SocketAddr,
        uid: Option<u32>,
        now: Instant,
        quic: bool,
    ) -> Self {
        let (opened, flow) = begin_udp(shared, app, address, uid);
        Self {
            id: opened.id,
            quic: quic.then(|| (opened, Box::new(quic::Initial::new()))),
            bytes: shared.record(flow),
            last: now,
        }
    }
}

impl Mapping {
    /// The peer at `address`, made if it is new; the mapping and the peer are refreshed.
    fn peer(
        &mut self,
        shared: &Shared,
        app: SocketAddr,
        address: SocketAddr,
        now: Instant,
        quic: bool,
    ) -> &mut Peer {
        self.last = now;
        let Self {
            peers,
            addresses,
            uid,
            ..
        } = self;
        let peer = peers.entry(address).or_insert_with(|| {
            *addresses.entry(address.ip()).or_default() += 1;
            Peer::new(shared, app, address, *uid, now, quic)
        });
        peer.last = now;
        peer
    }

    /// Ends the flows of the peers silent since `since`; their addresses are let in no more, unless
    /// another peer has the same one.
    fn sweep(&mut self, since: Instant, shared: &Shared) {
        let Self {
            peers, addresses, ..
        } = self;
        peers.retain(|address, peer| {
            if peer.last > since {
                return true;
            }
            shared.finish(peer.id);
            let ip = address.ip();
            let left = addresses.get_mut(&ip).map(|count| {
                *count = count.saturating_sub(1);
                *count
            });
            if left == Some(0) {
                addresses.remove(&ip);
            }
            false
        });
    }
}

/// The engine's UDP: the destinations waiting for their way, the flows with a socket of their own, and
/// the mappings of the direct path.
#[derive(Default)]
pub(super) struct UdpTable {
    /// By the app's address and the destination.
    flows: HashMap<(SocketAddr, SocketAddr), UdpEntry>,
    /// By the app's address.
    mappings: HashMap<SocketAddr, Mapping>,
    /// The number of the last mapping opened.
    opened: u64,
}

pub(super) type UdpFlows = Arc<Mutex<UdpTable>>;

/// What sending a datagram to a peer needs: the mapping's socket, the peer's bytes, and what the
/// datagram's QUIC Initial packets gave.
struct ToPeer {
    socket: Arc<UdpSocket>,
    bytes: Option<Arc<FlowBytes>>,
    quic: Option<QuicRead>,
}

/// What a datagram of the app needs once the table has been read: its flow's way, its peer's, or a
/// way to be opened.
enum Next {
    /// A flow with a socket of its own: its way, its app, its bytes, what the datagram's QUIC Initial
    /// packets gave, and the answer Watch's cache holds for it.
    Flow(
        UdpWay,
        Option<u32>,
        Option<Arc<FlowBytes>>,
        Option<QuicRead>,
        Option<Vec<u8>>,
    ),
    Peer(ToPeer),
    Open,
}

/// What a mapping does with a datagram that came in.
enum LetIn {
    /// The mapping is gone.
    Gone,
    /// It came from an address the app did not send to.
    Dropped,
    /// It came from a peer, whose bytes these are.
    Peer(Option<Arc<FlowBytes>>),
}

impl UdpTable {
    /// The mapping `id` of `app`, if it is still open.
    fn mapping(&mut self, app: SocketAddr, id: u64) -> Option<&mut Mapping> {
        self.mappings.get_mut(&app).filter(|m| m.id == id)
    }

    /// Ends the mapping `id` of `app`, if it is still open, and its peers' flows with it.
    fn end(&mut self, app: SocketAddr, id: u64, shared: &Shared) {
        if self.mapping(app, id).is_none() {
            return;
        }
        if let Some(mapping) = self.mappings.remove(&app) {
            for peer in mapping.peers.values() {
                shared.finish(peer.id);
            }
            mapping.ended.notify_one();
        }
    }

    /// The open mapping of `app`, by its number, with its socket, if it is the app `uid`'s. One of
    /// another app ends: Android handed the port out again.
    fn open_mapping(
        &mut self,
        app: SocketAddr,
        uid: Option<u32>,
        shared: &Shared,
    ) -> Option<(u64, Arc<UdpSocket>)> {
        let mapping = self.mappings.get(&app)?;
        if mapping.uid == uid {
            return Some((mapping.id, Arc::clone(&mapping.socket)));
        }
        let id = mapping.id;
        self.end(app, id, shared);
        None
    }

    /// A datagram from the app to a peer of its mapping: both are refreshed, and its QUIC Initial
    /// packets read.
    fn toward_peer(
        &mut self,
        (app, destination): (SocketAddr, SocketAddr),
        payload: &[u8],
        now: Instant,
    ) -> Option<ToPeer> {
        let mapping = self.mappings.get_mut(&app)?;
        let peer = mapping.peers.get_mut(&destination)?;
        peer.last = now;
        mapping.last = now;
        Some(ToPeer {
            socket: Arc::clone(&mapping.socket),
            bytes: peer.bytes.clone(),
            quic: read_quic(&mut peer.quic, payload),
        })
    }

    /// Whether the mapping `id` of `app` lets in a datagram from `from` (address-dependent filtering,
    /// RFC 4787): one from a peer, or from another port of a peer's address, which becomes a peer of
    /// its own.
    fn let_in(&mut self, app: SocketAddr, id: u64, from: SocketAddr, shared: &Shared) -> LetIn {
        let Some(mapping) = self.mapping(app, id) else {
            return LetIn::Gone;
        };
        let now = Instant::now();
        if let Some(peer) = mapping.peers.get_mut(&from) {
            peer.last = now;
            mapping.last = now;
            return LetIn::Peer(peer.bytes.clone());
        }
        // While a chain sends the app elsewhere, nothing new comes in on its direct path.
        if !mapping.addresses.contains_key(&from.ip())
            || !matches!(shared.route(mapping.uid, from), Route::Direct)
        {
            return LetIn::Dropped;
        }
        // A flow the app did not start, logged as any other: the log's flag for a flow that came in
        // waits for its new record format (ADR 0044, decision 4).
        LetIn::Peer(mapping.peer(shared, app, from, now, false).bytes.clone())
    }

    /// The flow `id` between `key`'s two ends goes, if it is still there.
    fn remove_flow(&mut self, key: (SocketAddr, SocketAddr), id: u64) {
        if matches!(self.flows.get(&key), Some(UdpEntry::Open(flow)) if flow.id == id) {
            self.flows.remove(&key);
        }
    }

    /// `answers` more lookups of the flow `id` have their answer: `true` when none waits any more, and
    /// the flow went.
    fn answered(&mut self, key: (SocketAddr, SocketAddr), id: u64, answers: u32) -> bool {
        let Some(UdpEntry::Open(flow)) = self.flows.get_mut(&key) else {
            return true;
        };
        if flow.id != id {
            return true;
        }
        flow.unanswered = flow.unanswered.saturating_sub(answers);
        if flow.unanswered > 0 {
            return false;
        }
        self.flows.remove(&key);
        true
    }
}

impl Loop {
    pub(super) async fn udp(&self, packet: &[u8], parsed: &Packet) {
        let Some(payload) = packet::udp_payload(packet, parsed) else {
            Counters::add(&self.shared.counters.skipped, 1);
            return;
        };
        let key = (parsed.source, parsed.destination);
        let lookup = self.shared.is_tunnel_dns(key.1.ip());
        let next = {
            let mut table = lock(&self.udp);
            match table.flows.get_mut(&key) {
                Some(UdpEntry::Open(flow)) => {
                    let cached = match flow.way {
                        UdpWay::Lookups(_) => None,
                        _ => cached_answer(&self.shared, key.1, payload),
                    };
                    // The flow ends once every lookup it sent has its answer.
                    if lookup && cached.is_none() && matches!(flow.way, UdpWay::Direct(_)) {
                        flow.unanswered = flow.unanswered.saturating_add(1);
                    }
                    Next::Flow(
                        flow.way.clone(),
                        flow.uid,
                        flow.bytes.clone(),
                        read_quic(&mut flow.quic, payload),
                        cached,
                    )
                }
                Some(UdpEntry::Opening(waiting)) => {
                    if waiting.len() < self.shared.limits.udp_waiting {
                        waiting.push(packet.to_vec());
                    } else {
                        Counters::add(&self.shared.counters.skipped, 1);
                    }
                    return;
                }
                None => {
                    if let Some(to) = table.toward_peer(key, payload, Instant::now()) {
                        Next::Peer(to)
                    } else {
                        table
                            .flows
                            .insert(key, UdpEntry::Opening(vec![packet.to_vec()]));
                        Next::Open
                    }
                }
            }
        };
        let (way, uid, bytes, quic, cached) = match next {
            Next::Flow(way, uid, bytes, quic, cached) => (way, uid, bytes, quic, cached),
            Next::Peer(to) => return self.send_to_peer(to, packet, parsed, payload).await,
            Next::Open => {
                tokio::spawn(open_udp(
                    key,
                    Arc::clone(&self.tun),
                    Arc::clone(&self.shared),
                    Arc::clone(&self.udp),
                    self.changes.clone(),
                ));
                return;
            }
        };
        note_quic(&self.shared, quic);
        if lookup {
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
        if let Some(answer) = cached {
            if let Some(packet) = packet::udp(key.1, key.0, &answer) {
                self.shared.lookup_answered(uid, packet.len());
                self.send(&packet).await;
            }
            return;
        }
        let sent = way.send(payload).await;
        if let Some(error) = count_sent(&self.shared, bytes.as_deref(), packet, parsed, sent) {
            self.send(&error).await;
        }
    }

    /// A datagram to a peer of its app socket's mapping.
    async fn send_to_peer(&self, to: ToPeer, packet: &[u8], parsed: &Packet, payload: &[u8]) {
        note_quic(&self.shared, to.quic);
        let sent = send_to(&to.socket, payload, parsed.destination).await;
        if let Some(error) = count_sent(&self.shared, to.bytes.as_deref(), packet, parsed, sent) {
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

/// Sends a datagram from a mapping's socket. An ICMP error the kernel holds for the socket fails its
/// next send once, and that datagram does not leave: it is sent again. The mapping's task reads the
/// error itself from the socket's error queue, for the destination it was for.
async fn send_to(socket: &UdpSocket, payload: &[u8], destination: SocketAddr) -> io::Result<usize> {
    match socket.send_to(payload, destination).await {
        Err(error) if errors::from_icmp(&error) => socket.send_to(payload, destination).await,
        sent => sent,
    }
}

/// As [`send_to`], without waiting for room in the socket's buffer.
fn try_send_to(socket: &UdpSocket, payload: &[u8], destination: SocketAddr) -> io::Result<usize> {
    match socket.try_send_to(payload, destination) {
        Err(error) if errors::from_icmp(&error) => socket.try_send_to(payload, destination),
        sent => sent,
    }
}

/// Opens a destination's way, off the event loop: asks Android whose it is, then, on the direct path
/// to anywhere but Watch's own DNS address, makes it a peer of its app socket's mapping, else opens a
/// flow with a socket of its own.
async fn open_udp(
    key: (SocketAddr, SocketAddr),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let (app, destination) = key;
    let named = owner(&shared, UDP, app, destination).await;
    // When Android cannot name the app of a socket it named before, the socket's mapping keeps its app.
    let uid = named.or_else(|| lock(&flows).mappings.get(&app).and_then(|m| m.uid));
    if !shared.is_tunnel_dns(destination.ip())
        && matches!(shared.route(uid, destination), Route::Direct)
    {
        open_peer(key, uid, tun, shared, flows, changes).await;
    } else {
        open_flow(key, uid, tun, shared, flows, changes).await;
    }
}

/// Makes a destination a peer of its app socket's mapping, opening the mapping first if the app has
/// none, or if the one it has is another app's. The datagrams that waited leave under the table's
/// lock, so that none that comes meanwhile overtakes them, and the peer is known before its answer
/// can come.
async fn open_peer(
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let (app, destination) = key;
    let Some((id, socket)) =
        mapping_for(app, destination, uid, &tun, &shared, &flows, &changes).await
    else {
        let (_, mut flow) = begin_udp(&shared, app, destination, uid);
        flow.outcome = Outcome::Failed;
        udp_failed(key, flow, &tun, &shared, &flows).await;
        return;
    };
    let _ = socket.writable().await;
    let mut reads = Vec::new();
    let mut errors = Vec::new();
    {
        let mut table = lock(&flows);
        let waiting = match table.flows.remove(&key) {
            Some(UdpEntry::Opening(waiting)) => waiting,
            _ => Vec::new(),
        };
        let Some(mapping) = table.mapping(app, id) else {
            // The mapping ended meanwhile, as the network changed: the datagrams are dropped, as by a
            // full queue.
            Counters::add(&shared.counters.skipped, waiting.len() as u64);
            return;
        };
        let peer = mapping.peer(&shared, app, destination, Instant::now(), true);
        for packet in &waiting {
            let Ok(parsed) = packet::parse(packet) else {
                continue;
            };
            let Some(payload) = packet::udp_payload(packet, &parsed) else {
                continue;
            };
            reads.push(read_quic(&mut peer.quic, payload));
            let sent = try_send_to(&socket, payload, destination);
            errors.extend(count_sent(
                &shared,
                peer.bytes.as_deref(),
                packet,
                &parsed,
                sent,
            ));
        }
    }
    for read in reads {
        note_quic(&shared, read);
    }
    for error in errors {
        send_to_app(&tun, &shared, &error).await;
    }
}

/// The mapping of `app` for a new destination, by its number, with its socket: the app's open one, or
/// a new one when it has none, or when the one it has is another app's. `None` when no socket could be
/// made.
async fn mapping_for(
    app: SocketAddr,
    destination: SocketAddr,
    uid: Option<u32>,
    tun: &Arc<Tun>,
    shared: &Arc<Shared>,
    flows: &UdpFlows,
    changes: &watch::Receiver<u64>,
) -> Option<(u64, Arc<UdpSocket>)> {
    if let Some(open) = lock(flows).open_mapping(app, uid, shared) {
        return Some(open);
    }
    let socket = Arc::new(mapped_socket(shared, destination).await.ok()?);
    let mut table = lock(flows);
    // Another destination of the same app may have opened one meanwhile.
    if let Some(open) = table.open_mapping(app, uid, shared) {
        return Some(open);
    }
    table.opened += 1;
    let id = table.opened;
    let ended = Arc::new(Notify::new());
    table.mappings.insert(
        app,
        Mapping {
            id,
            socket: Arc::clone(&socket),
            uid,
            peers: HashMap::new(),
            addresses: HashMap::new(),
            last: Instant::now(),
            ended: Arc::clone(&ended),
        },
    );
    drop(table);
    Counters::add(&shared.counters.udp_mappings, 1);
    tokio::spawn(mapped(
        MappingTask {
            app,
            id,
            uid,
            socket: Arc::clone(&socket),
            ended,
        },
        Arc::clone(tun),
        Arc::clone(shared),
        Arc::clone(flows),
        changes.clone(),
    ));
    Some((id, socket))
}

/// A mapping's socket: protected, on the unspecified address of the destination's IP version and a
/// port the kernel picks, not connected, and with the ICMP errors that answer its datagrams queued.
async fn mapped_socket(shared: &Arc<Shared>, destination: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(packet::unspecified_like(&destination)).await?;
    protect(shared, socket.as_fd()).await?;
    // Without the queue, the errors are lost, as most userspace NATs lose them; the mapping still works.
    let _ = errors::keep(&socket, destination.is_ipv4());
    Ok(socket)
}

/// What a mapping's task holds.
struct MappingTask {
    app: SocketAddr,
    id: u64,
    uid: Option<u32>,
    socket: Arc<UdpSocket>,
    ended: Arc<Notify>,
}

/// Relays a mapping's answers to the app, each from the peer that sent it, with the ICMP errors that
/// answered its datagrams, until no datagram passed either way for `Limits::udp_idle` (RFC 4787, REQ-5
/// and REQ-6), the network beneath changes, or the mapping is ended elsewhere (its port is another
/// app's now). A peer silent as long ends as the task wakes, without a timer of its own.
async fn mapped(
    task: MappingTask,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
    let MappingTask {
        app,
        id,
        uid,
        socket,
        ended,
    } = task;
    let idle = shared.limits.udp_idle;
    let mut swept = Instant::now();
    // Only a change after the mapping opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    loop {
        let now = Instant::now();
        let last = {
            let mut table = lock(&flows);
            let Some(mapping) = table.mapping(app, id) else {
                break;
            };
            if now.duration_since(swept) >= idle
                && let Some(since) = now.checked_sub(idle)
            {
                mapping.sweep(since, &shared);
                swept = now;
            }
            mapping.last
        };
        let silent = last + idle;
        if now >= silent {
            break;
        }
        tokio::select! {
            _ = changes.changed() => break,
            () = ended.notified() => break,
            () = tokio::time::sleep_until(silent.into()) => {}
            ready = socket.ready(Interest::READABLE | Interest::ERROR) => {
                if !ready.is_ok_and(|ready| !ready.is_read_closed()) {
                    break;
                }
                let queued = take_errors(&socket);
                let (packets, end) = with_buffer(|buffer| {
                    mapped_receive(&socket, buffer, (app, id, uid), queued, &shared, &flows)
                });
                for packet in packets {
                    send_to_app(&tun, &shared, &packet).await;
                }
                if end {
                    break;
                }
            }
        }
    }
    lock(&flows).end(app, id, &shared);
}

/// Reads the errors queued for a socket, which also clears its readiness for errors: a connected
/// socket's own error comes with its next read instead.
fn take_errors(socket: &UdpSocket) -> Vec<(SocketAddr, Unreachable)> {
    let mut found = Vec::new();
    let _ = socket.try_io(Interest::ERROR, || {
        found = errors::queued(socket);
        Err::<(), _>(io::ErrorKind::WouldBlock.into())
    });
    found
}

/// What a mapping lets in now: for each ICMP error `queued` for its datagrams, the error from the peer
/// it is for; then what its socket holds, read into `buffer`, each datagram from the peer that sent
/// it. A datagram from an address the app did not send to is dropped and counted. `true` when the
/// mapping ends: it is gone, or its socket failed.
fn mapped_receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    (app, id, uid): (SocketAddr, u64, Option<u32>),
    queued: Vec<(SocketAddr, Unreachable)>,
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool) {
    let mut packets = Vec::new();
    for (destination, told) in queued {
        let bytes = match lock(flows).mapping(app, id) {
            None => return (packets, true),
            Some(mapping) => match mapping.peers.get(&destination) {
                Some(peer) => peer.bytes.clone(),
                None => continue,
            },
        };
        if let Some(error) = unreachable_to(app, destination, told) {
            if let Some(bytes) = &bytes {
                bytes.add_wire_down(error.len());
            }
            packets.push(error);
        }
    }
    for _ in 0..BATCH {
        let (n, from) = match socket.try_recv_from(buffer) {
            Ok((n, from)) => (n, SocketAddr::new(from.ip(), from.port())),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // An ICMP error, which this read took: the error queue says which destination it was for.
            Err(error) if errors::from_icmp(&error) => continue,
            Err(_) => return (packets, true),
        };
        let bytes = match lock(flows).let_in(app, id, from, shared) {
            LetIn::Gone => return (packets, true),
            LetIn::Dropped => {
                Counters::add(&shared.counters.udp_filtered, 1);
                continue;
            }
            LetIn::Peer(bytes) => bytes,
        };
        let answer = &buffer[..n];
        Counters::add(&shared.counters.bytes_down, n as u64);
        if let Some(bytes) = &bytes {
            bytes.add_down(n);
        }
        // An app's own resolver names only that app's flows.
        if from.port() == 53 && uid.is_some() {
            shared.learn(answer, uid);
        }
        if let Some(packet) = packet::udp(from, app, answer) {
            if let Some(bytes) = &bytes {
                bytes.add_wire_down(packet.len());
            }
            packets.push(packet);
        }
    }
    (packets, false)
}

/// The ICMP error `told` for the app at `app`, as if from `destination`, quoting a datagram between
/// the two.
fn unreachable_to(app: SocketAddr, destination: SocketAddr, told: Unreachable) -> Option<Vec<u8>> {
    let quoted = packet::udp(app, destination, &[])?;
    let parsed = packet::parse(&quoted).ok()?;
    packet::unreachable(&quoted, &parsed, told)
}

/// Opens a flow with a socket of its own, off the event loop: opens its socket, sends the datagrams
/// that waited for it, and starts relaying the answers. The app gets an ICMP error when the
/// destination cannot be reached.
async fn open_flow(
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let (app, destination) = key;
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
    let lookup = shared.is_tunnel_dns(destination.ip());
    // The tunnel's own DNS address is never QUIC.
    let quic = (!lookup).then(|| (opened, Box::new(quic::Initial::new())));
    let mut open = UdpFlow {
        id,
        way: way.clone(),
        quic,
        uid,
        bytes: bytes.clone(),
        unanswered: 0,
    };
    // The waiting datagrams leave at once, under the table's lock, so that none that comes meanwhile
    // overtakes them: the socket must first be known to take them.
    way.writable().await;
    let mut reads = Vec::new();
    let mut lookups = Vec::new();
    let mut errors = Vec::new();
    let mut questions = Vec::new();
    let mut cached = Vec::new();
    {
        let mut table = lock(&flows);
        let waiting = match table.flows.remove(&key) {
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
            reads.push(read_quic(&mut open.quic, payload));
            if lookup {
                lookups.push(packet.len());
            }
            if let UdpWay::Lookups(_) = way {
                questions.push(payload.to_vec());
                continue;
            }
            if let Some(answer) = cached_answer(&shared, destination, payload) {
                cached.extend(packet::udp(destination, app, &answer));
                continue;
            }
            let sent = way.try_send(payload);
            if lookup && sent.is_ok() {
                open.unanswered += 1;
            }
            errors.extend(count_sent(&shared, bytes.as_deref(), packet, &parsed, sent));
        }
        table.flows.insert(key, UdpEntry::Open(open));
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
    for answer in cached {
        shared.lookup_answered(uid, answer.len());
        send_to_app(&tun, &shared, &answer).await;
    }
    if let UdpWay::Lookups(chain) = way {
        answer_waiting(questions, (key, id), uid, &chain, &shared, &tun, flows);
        return;
    }
    tokio::spawn(answers(
        way,
        control,
        UdpEnds {
            app,
            destination,
            id,
            uid,
            bytes,
        },
        tun,
        shared,
        flows,
        changes,
    ));
}

/// While a chain is on, the answer Watch's cache holds for a direct app's lookup, with a time to live
/// of 0 like every answer then, so that the network's resolver is asked no more often than before.
fn cached_answer(shared: &Shared, destination: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    if !shared.is_tunnel_dns(destination.ip()) || !shared.uncached_answers.load(Ordering::Relaxed) {
        return None;
    }
    let mut answer = lock(&shared.direct_answers).answer(query, Instant::now())?;
    dns::uncache(&mut answer);
    Some(answer)
}

/// How a new flow with a socket of its own goes, by its route: a protected socket to the network's
/// resolver, the tool's relay with the connection that keeps it, or Watch's own answers to a chained
/// app's lookups.
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
        Route::Tool(chain) if shared.is_tunnel_dns(destination.ip()) => {
            Ok((UdpWay::Lookups(chain), None))
        }
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
    (key, id): ((SocketAddr, SocketAddr), u64),
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
    let idle = shared.limits.udp_idle;
    tokio::spawn(async move {
        tokio::time::sleep(idle).await;
        lock(&flows).remove_flow(key, id);
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
            protect(shared, socket.as_fd()).await?;
        }
        socket.connect(relay).await?;
        let way = UdpWay::Tool {
            socket: Arc::new(socket),
            header: socks5::datagram(&target, &[]).into(),
        };
        Ok((way, control))
    };
    match tokio::time::timeout(shared.limits.connect_timeout, opening).await {
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

/// A UDP flow whose way could not be opened: it is recorded, its waiting datagrams are dropped, and an
/// unreachable destination gets the app one ICMP error, quoting its first datagram.
async fn udp_failed(
    key: (SocketAddr, SocketAddr),
    flow: Flow,
    tun: &Tun,
    shared: &Shared,
    flows: &UdpFlows,
) {
    let unreachable = flow.outcome == Outcome::Unreachable;
    shared.record(flow);
    let waiting = match lock(flows).flows.remove(&key) {
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

/// A flow with a socket of its own, for the task that relays its answers.
struct UdpEnds {
    app: SocketAddr,
    destination: SocketAddr,
    /// The flow's number.
    id: u64,
    uid: Option<u32>,
    /// The flow's bytes, when the log follows it.
    bytes: Option<Arc<FlowBytes>>,
}

/// Wraps each answer of a flow with a socket of its own in an IP packet to the app, until the flow
/// falls silent, the network beneath changes, or the tool ends its relay. A flow of lookups to Watch's
/// own DNS address ends as soon as every lookup it carried has its answer, or when one waited
/// [`LOOKUP_WAIT`] (ADR 0044, decision 3).
async fn answers(
    way: UdpWay,
    mut control: Option<TcpStream>,
    ends: UdpEnds,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
    let (socket, through_tool) = match &way {
        UdpWay::Direct(socket) => (Arc::clone(socket), false),
        UdpWay::Tool { socket, .. } => (Arc::clone(socket), true),
        UdpWay::Lookups(_) => return,
    };
    let key = (ends.app, ends.destination);
    let lookups = shared.is_tunnel_dns(ends.destination.ip());
    let wait = if lookups {
        LOOKUP_WAIT
    } else {
        shared.limits.udp_idle
    };
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
    // Lookups all answered from Watch's cache leave nothing to wait for.
    let mut done = lookups && lock(&flows).answered(key, ends.id, 0);
    while !done {
        tokio::select! {
            _ = changes.changed() => break,
            () = &mut closed => break,
            ready = tokio::time::timeout(wait, socket.ready(Interest::READABLE | Interest::ERROR)) => {
                if !matches!(ready, Ok(Ok(ready)) if !ready.is_read_closed()) {
                    break;
                }
                let _ = take_errors(&socket);
                let (packets, end) = with_buffer(|buffer| {
                    relayed(&socket, buffer, through_tool, lookups, &ends, &shared, &flows)
                });
                for packet in packets {
                    send_to_app(&tun, &shared, &packet).await;
                }
                done = end;
            }
        }
    }
    lock(&flows).remove_flow(key, ends.id);
    shared.finish(ends.id);
}

/// What a flow's socket holds now, read into `buffer`: the packets for the app, and whether the flow
/// ends (its socket failed, or each lookup it carried has its answer).
fn relayed(
    socket: &UdpSocket,
    buffer: &mut [u8],
    through_tool: bool,
    lookups: bool,
    ends: &UdpEnds,
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool) {
    let &UdpEnds {
        app,
        destination,
        id,
        uid,
        ref bytes,
    } = ends;
    let mut packets = Vec::new();
    for _ in 0..BATCH {
        let packet = match socket.try_recv(buffer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Ok(n) => {
                // From the tool's relay, the datagram's header goes; one that is not well formed, or a
                // fragment, is dropped.
                let n = if through_tool {
                    let Some(length) = socks5::parse_datagram(&buffer[..n]).map(|(_, p)| p.len())
                    else {
                        continue;
                    };
                    buffer.copy_within(n - length..n, 0);
                    length
                } else {
                    n
                };
                Counters::add(&shared.counters.bytes_down, n as u64);
                if let Some(bytes) = bytes {
                    bytes.add_down(n);
                }
                let answer = &mut buffer[..n];
                // Android's resolver names every app's flows; an app's own, only its own.
                if destination.port() == 53 {
                    if lookups {
                        shared.learn(answer, None);
                        if shared.uncached_answers.load(Ordering::Relaxed) {
                            lock(&shared.direct_answers).insert(answer, Instant::now());
                            dns::uncache(answer);
                        }
                    } else if uid.is_some() {
                        shared.learn(answer, uid);
                    }
                }
                packet::udp(destination, app, answer)
            }
            // The server's host answered that no one listens there.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                unreachable_to(app, destination, Unreachable::Port)
            }
            Err(_) => return (packets, true),
        };
        if let Some(packet) = packet {
            match bytes {
                Some(bytes) => bytes.add_wire_down(packet.len()),
                None if lookups => shared.lookup_answered(uid, packet.len()),
                None => {}
            }
            packets.push(packet);
        }
        // A flow of lookups ends with the answer to the last of them.
        if lookups && lock(flows).answered((app, destination), id, 1) {
            return (packets, true);
        }
    }
    (packets, false)
}
