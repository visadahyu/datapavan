//! UDP through the tunnel (ADR 0044, decisions 1 and 2). Each app socket gets one mapping, whatever
//! the destination (RFC 4787, REQ-1): on the direct path, one protected socket, not connected; through
//! the user's tool, one `UDP ASSOCIATE`, each datagram with a header that names its destination. A
//! mapping lets in only what comes from an address the app sent to (address-dependent filtering);
//! through the tool, each answer's header says where it came from. Each destination stays a flow of
//! its own in the log, with its own name, bytes and QUIC reading. Lookups to Watch's own DNS address
//! keep one socket for each flow. Sockets are opened off the packet loop, and answers are read into one
//! buffer for each engine thread.

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
use crate::{answers, dns, packet, quic};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
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

/// At most this many lookups of one flow wait for their answer; an older one is then given up, and its
/// answer, should it come, still reaches the app but no longer keeps the flow open. Android's resolver
/// asks one question from each socket, and a flow holds a lookup at most `LOOKUP_WAIT`, so 256 is far
/// above any app's need, and bounds a flood: 256 questions of at most 255 bytes, about 64 KB.
const OWED: usize = 256;

/// The lookups a flow carried that still wait for their answer, each by its ID and question, so that an
/// answer counts only for the lookup it answers: a resolver that sends one answer twice does not end
/// the flow before a later lookup has its own.
#[derive(Default)]
pub(super) struct Owed(Mutex<VecDeque<(u16, String)>>);

impl Owed {
    /// The ID and question of `message`, a query or its answer; a message that is no DNS query or
    /// response with one question has its ID alone, if it has one.
    fn key(message: &[u8], answer: bool) -> (u16, String) {
        let id = dns::u16_at(message, 0).unwrap_or(0);
        let question = if answer {
            dns::response(message).map(|response| response.question)
        } else {
            answers::question(message).map(|question| question.name)
        };
        (id, question.unwrap_or_default())
    }

    /// One more lookup, `query`, waits for its answer.
    fn add(&self, query: &[u8]) {
        let mut owed = lock(&self.0);
        if owed.len() == OWED {
            owed.pop_front();
        }
        owed.push_back(Self::key(query, false));
    }

    /// The lookup that `answer` answers, if one waits for it, has its answer.
    fn answered(&self, answer: &[u8]) {
        let (id, question) = Self::key(answer, true);
        let mut owed = lock(&self.0);
        let at = owed
            .iter()
            .position(|(asked, of)| *asked == id && (question.is_empty() || *of == question));
        if let Some(at) = at {
            owed.remove(at);
        }
    }

    /// The lookup `query` will have no answer from here, as when Watch could not answer it.
    fn given_up(&self, query: &[u8]) {
        let key = Self::key(query, false);
        let mut owed = lock(&self.0);
        if let Some(at) = owed.iter().position(|asked| *asked == key) {
            owed.remove(at);
        }
    }

    /// None of them will have an answer: no one listens where they went.
    fn clear(&self) {
        lock(&self.0).clear();
    }

    fn is_empty(&self) -> bool {
        lock(&self.0).is_empty()
    }
}

/// A flow of lookups to Watch's own DNS address, with the flow's number.
pub(super) struct UdpFlow {
    /// The flow's number, which tells its entry from a later flow's between the same two ends.
    id: u64,
    way: UdpWay,
    /// The app's UID.
    uid: Option<u32>,
    /// The lookups it carried that still wait for their answer. The flow's task, or the tasks that
    /// answer a chained app's lookups, count it down, also once a later flow took this one's place: the
    /// flow ends when none waits.
    owed: Arc<Owed>,
    /// How many times the chain had been set when the flow last made sure that its way still holds.
    chains: u64,
    /// When the app last sent a lookup on it.
    sent: Instant,
    /// When Android last named its app (`Limits::udp_reask`).
    named: Instant,
}

impl UdpFlow {
    /// Whether the flow may still carry its app's next lookup to `destination`, sent `now`. After a
    /// silence, or long after Android last named its app, it may not: the lookup asks Android again whose
    /// socket this is, as a mapping's datagram does, since the port may be another app's now. Nor may it
    /// once the chain, set again, sends its app another way, so that a lookup an app sends once the chain
    /// takes it never reaches the network's resolver directly, and one sent once the chain lets it go is
    /// not answered through the tool. A flow that may not gives way to a new one at once.
    fn keeps_its_way(&mut self, shared: &Shared, destination: SocketAddr, now: Instant) -> bool {
        let reask = shared.limits.udp_reask;
        if now.duration_since(self.sent) >= reask
            || now.duration_since(self.named) >= reask.saturating_mul(30)
        {
            return false;
        }
        let chains = shared.chains.load(Ordering::Acquire);
        if chains != self.chains {
            if !self.way.keeps(&shared.route(self.uid, destination)) {
                return false;
            }
            self.chains = chains;
        }
        self.sent = now;
        true
    }
}

/// Where the lookups of a flow to Watch's own DNS address go.
#[derive(Clone)]
pub(super) enum UdpWay {
    /// A protected socket connected to the network's resolver.
    Direct(Arc<UdpSocket>),
    /// A chained app's lookups, which Watch answers (ADR 0038).
    Lookups(Arc<Chain>),
}

impl UdpWay {
    /// Sends one datagram's payload; the bytes sent are the payload's. Not for [`UdpWay::Lookups`].
    async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.send(payload).await,
            Self::Lookups(_) => Ok(payload.len()),
        }
    }

    fn try_send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(socket) => socket.try_send(payload),
            Self::Lookups(_) => Ok(payload.len()),
        }
    }

    async fn writable(&self) {
        if let Self::Direct(socket) = self {
            let _ = socket.writable().await;
        }
    }

    /// Whether lookups on `route` may go this way: directly while the app goes directly, through the
    /// same tool, reached the same way, while it is chained.
    fn keeps(&self, route: &Route) -> bool {
        match (self, route) {
            (Self::Direct(_), Route::Direct) => true,
            (Self::Lookups(one), Route::Tool(other)) => one.same_tool(other),
            _ => false,
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
/// the event loop so that no other packet waits for that; then, for a flow of lookups to Watch's own
/// DNS address, open.
pub(super) enum UdpEntry {
    /// The destination's first datagrams, whole packets in the order the app sent them, at most
    /// `Limits::udp_waiting`: they leave once the way is there, and the app is known before the first
    /// does.
    Opening(Vec<Vec<u8>>),
    Open(UdpFlow),
}

/// How a mapping leaves.
#[derive(Clone)]
enum Exit {
    /// On the network beneath, from a protected socket of its own, not connected.
    Direct,
    /// Through the tool's UDP relay (ADR 0044, decision 2): one `UDP ASSOCIATE` for every destination,
    /// whose socket is connected to the relay, and on each datagram a header that names where it goes.
    Tool(Arc<Chain>),
}

impl Exit {
    /// The way a mapping leaves on `route`: none where the app's UDP goes nowhere, as through a tool
    /// that carries no UDP (VPN.md).
    fn of(route: Route) -> Option<Self> {
        match route {
            Route::Direct => Some(Self::Direct),
            Route::Tool(chain) if chain.udp => Some(Self::Tool(chain)),
            Route::Tool(_) | Route::Refused => None,
        }
    }

    /// Whether a mapping that leaves this way may carry what leaves by `other`: the same path, and the
    /// same tool, reached the same way.
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Direct, Self::Direct) => true,
            (Self::Tool(one), Self::Tool(other)) => one.same_tool(other),
            _ => false,
        }
    }
}

/// At most this many flows that came in, each from another port of an address the app sent to, for one
/// mapping; what comes from more ports is dropped and counted. A STUN server's tests of the mapping and a
/// peer's new NAT bindings bring a few such ports, and 64 is the floor ADR 0044 gives each app's
/// mappings. Without a cap, a sender at such an address, or a tool that forges headers, could grow the
/// table without end.
const CAME_IN: usize = 64;

/// At most this many DNS queries are kept for a stand-in on port 53 still waiting for its first answer,
/// or for a flow from a port 53 that came in: an answer to an older one binds nothing and teaches
/// nothing. A resolver of an app's own may send many before the first answer comes, retrying, asking
/// both A and AAAA, and asking several names at once; 64 holds 32 names asked both ways. It is bounded
/// all the same: 64 questions of at most 255 bytes, about 17 KB, and only while the stand-in waits.
/// Binding by any DNS response instead would let any sender at port 53 take the stand-in.
const ASKED: usize = 64;

/// An app socket's way out: one socket, whatever the destination, on the direct path or to the tool's
/// relay.
struct Mapping {
    /// Its number, which tells it from a later mapping of the same app socket.
    id: u64,
    socket: Arc<UdpSocket>,
    exit: Exit,
    /// How many times the chain had been set (`Shared::chains`) when the mapping last made sure that its
    /// app's datagrams still leave its way.
    chains: u64,
    /// The app's UID, as Android named it for the mapping's first destination.
    uid: Option<u32>,
    /// Each destination the app sent to, and each other port of their addresses that sent to the app,
    /// by the address the app knows it by: each a flow of its own.
    peers: HashMap<SocketAddr, Peer>,
    /// Where the peers' answers come from: what is let in.
    sources: Sources,
    /// How many of the peers came in ([`CAME_IN`]).
    came_in: usize,
    /// When the last datagram passed, either way.
    last: Instant,
    /// When the app last sent a datagram on it.
    sent: Instant,
    /// When Android last named its app (`Limits::udp_reask`).
    named: Instant,
    /// Wakes the mapping's task when the mapping is ended from elsewhere.
    ended: Arc<Notify>,
}

/// A peer of a mapping: a flow in the log.
struct Peer {
    /// The flow's number, port and DNS use, for the QUIC Initial packets that may name it.
    opened: Opened,
    /// The flow's number.
    id: u64,
    /// While the app's first datagrams to it may still name it, their QUIC Initial packets read so far.
    quic: Option<(Opened, Box<quic::Initial>)>,
    bytes: Option<Arc<FlowBytes>>,
    /// When the last datagram passed, either way.
    last: Instant,
    /// When it was made: for a stand-in, when the app first sent to it (`Limits::udp_contest`).
    made: Instant,
    way: PeerWay,
    /// Whether it came in, another port of an address the app sent to, and the app has not sent to it
    /// since: it counts under [`CAME_IN`], and its datagrams are not read for a QUIC name.
    came_in: bool,
    /// Whether it came in before the app sent to it: Watch learns names from it only from an answer to a
    /// query the app sent it, even once the app answers it.
    came_in_first: bool,
    /// Whether it is a stand-in the app sent to, waiting for its first answer from an address.
    waiting: bool,
    /// For a stand-in on port 53 while it waits, or a flow from a port 53 that came in first, the ID and
    /// question of each DNS query the app sent it, the latest last: only an answer to one of them binds
    /// the stand-in, or teaches Watch names from a flow the app did not start.
    asked: Vec<(u16, String)>,
}

/// Where a peer's datagrams go and where its answers come from.
struct PeerWay {
    /// Through the tool, the header that names where its datagrams go; none on the direct path, where
    /// they go to the peer itself.
    header: Option<Arc<[u8]>>,
    /// The address its answers come from: the peer itself, or for a stand-in, the address the tool's
    /// relay first answered it from; none until then.
    from: Option<SocketAddr>,
    /// For a stand-in, the name it stands in for, which the tool resolves (ADR 0038).
    name: Option<String>,
}

impl PeerWay {
    /// The way to `destination` for a mapping that leaves by `exit`: through the tool, by the name
    /// behind a stand-in or by the address itself. `None` for a stand-in the map no longer holds.
    fn toward(shared: &Shared, exit: &Exit, destination: SocketAddr) -> Option<Self> {
        if let Exit::Direct = exit {
            return Some(Self::direct(destination));
        }
        let target = shared.tool_target(destination)?;
        Some(Self::through_tool(target))
    }

    /// The way to and from `address` on the direct path.
    fn direct(address: SocketAddr) -> Self {
        Self {
            header: None,
            from: Some(address),
            name: None,
        }
    }

    /// The way to `target` through the tool. A name's answers come from an address the tool chose.
    fn through_tool(target: Target) -> Self {
        let header = Some(socks5::datagram(&target, &[]).into());
        match target {
            Target::Address(address) => Self {
                header,
                from: Some(address),
                name: None,
            },
            Target::Name(name, _) => Self {
                header,
                from: None,
                name: Some(name),
            },
        }
    }
}

impl Peer {
    /// A new peer of the app at `app`, which the app knows as `address`, with its flow begun and
    /// recorded. One the app sent to may be named by its QUIC Initial packets; one that came in is not.
    fn new(
        shared: &Shared,
        app: SocketAddr,
        address: SocketAddr,
        uid: Option<u32>,
        now: Instant,
        (came_in, way): (bool, PeerWay),
    ) -> Self {
        let (opened, flow) = begin_udp(shared, app, address, uid);
        Self {
            opened,
            id: opened.id,
            quic: (!came_in).then(|| (opened, Box::new(quic::Initial::new()))),
            bytes: shared.record(flow),
            last: now,
            made: now,
            came_in,
            came_in_first: came_in,
            waiting: !came_in && way.name.is_some() && way.from.is_none(),
            way,
            asked: Vec::new(),
        }
    }

    /// It waits no more for a first answer from an address: bound to one, or answered by name. The
    /// queries it kept for that go.
    fn answered(&mut self) {
        self.waiting = false;
        if !self.came_in_first {
            self.asked = Vec::new();
        }
    }

    /// Notes a datagram the app sends it to `port`: for a stand-in on port 53 while it waits, or a flow
    /// from a port 53 that came in first, the ID and question of a DNS query.
    fn sent(&mut self, port: u16, payload: &[u8]) {
        if port != 53 || !(self.waiting || self.came_in_first) {
            return;
        }
        let (Some(id), Some(question)) = (dns::u16_at(payload, 0), answers::question(payload))
        else {
            return;
        };
        if self.asked.len() == ASKED {
            self.asked.remove(0);
        }
        self.asked.push((id, question.name));
    }

    /// Whether `answer` is a DNS response to a query the app sent it: its ID and its question.
    fn asked_for(&self, answer: &[u8]) -> bool {
        let (Some(id), Some(response)) = (dns::u16_at(answer, 0), dns::response(answer)) else {
            return false;
        };
        self.asked
            .iter()
            .any(|(asked, question)| *asked == id && *question == response.question)
    }
}

/// Where a mapping's peers' answers come from: what the mapping lets in, with what finds a stand-in
/// without a scan of every peer under the table's lock.
#[derive(Default)]
struct Sources {
    /// Each address answers come from, with the address the app knows it by and how many peers have it.
    addresses: HashMap<IpAddr, Known>,
    /// The peers whose answers come from another address than the one the app knows them by (through
    /// the tool, a stand-in bound to the address the tool reached), by the address they come from.
    aliases: HashMap<SocketAddr, SocketAddr>,
    /// The stand-ins still waiting for their first answer, by the port the app asked.
    waiting: HashMap<u16, Vec<SocketAddr>>,
    /// The names behind the mapping's stand-ins (lower case, without a final dot), each with its
    /// stand-in and how many peers have it.
    names: HashMap<String, Known>,
}

/// An address answers come from, or a name the tool resolves.
struct Known {
    /// The address the app knows it by: itself, or a stand-in the tool resolved to it.
    shown: IpAddr,
    /// How many peers' answers come from it.
    peers: usize,
}

/// The name a target names, if it names one.
fn target_name(target: &Target) -> Option<String> {
    match target {
        Target::Name(name, _) => Some(name.clone()),
        Target::Address(_) => None,
    }
}

/// A name as DNS compares it: whatever its case, and with or without a final dot.
fn name_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Sources {
    /// A new peer, which the app knows as `shown`, that leaves by `way`. Only a stand-in the app sent to
    /// waits for a first answer from an address; one that came in, by a name its relay gave, never does:
    /// the app asked it nothing, so no answer is its first.
    fn add_peer(&mut self, shown: SocketAddr, way: &PeerWay, came_in: bool) {
        if let Some(from) = way.from {
            self.add(shown, from);
        }
        if let Some(name) = &way.name {
            self.names
                .entry(name_key(name))
                .or_insert(Known {
                    shown: shown.ip(),
                    peers: 0,
                })
                .peers += 1;
            if way.from.is_none() && !came_in {
                self.waiting.entry(shown.port()).or_default().push(shown);
            }
        }
    }

    /// The peer the app knows as `shown`, which left by `way`, is gone.
    fn remove_peer(&mut self, shown: SocketAddr, way: &PeerWay) {
        if let Some(from) = way.from {
            self.remove(shown, from);
        }
        if let Some(name) = &way.name {
            let key = name_key(name);
            let left = self.names.get_mut(&key).map(|known| {
                known.peers = known.peers.saturating_sub(1);
                known.peers
            });
            if left == Some(0) {
                self.names.remove(&key);
            }
            if way.from.is_none() {
                self.stop_waiting(shown);
            }
        }
    }

    /// The answers of the peer the app knows as `shown` come from `from`.
    fn add(&mut self, shown: SocketAddr, from: SocketAddr) {
        let known = self.addresses.entry(from.ip()).or_insert(Known {
            shown: shown.ip(),
            peers: 0,
        });
        known.peers += 1;
        // An address the app sent to itself is shown as itself, before a stand-in the tool resolved to
        // it.
        if shown.ip() == from.ip() {
            known.shown = from.ip();
        }
        if from != shown {
            self.aliases.insert(from, shown);
        }
    }

    /// The peer the app knows as `shown`, whose answers came from `from`, is gone: its address is let in
    /// no more, unless another peer has the same one.
    fn remove(&mut self, shown: SocketAddr, from: SocketAddr) {
        let ip = from.ip();
        let left = self.addresses.get_mut(&ip).map(|known| {
            known.peers = known.peers.saturating_sub(1);
            known.peers
        });
        if left == Some(0) {
            self.addresses.remove(&ip);
        }
        if from != shown {
            self.aliases.remove(&from);
        }
    }

    /// The stand-in the app knows as `shown` waits no more.
    fn stop_waiting(&mut self, shown: SocketAddr) {
        if let Some(waiting) = self.waiting.get_mut(&shown.port()) {
            waiting.retain(|&other| other != shown);
            if waiting.is_empty() {
                self.waiting.remove(&shown.port());
            }
        }
    }

    /// The address the app knows `ip` by, if what comes from it is let in.
    fn shown(&self, ip: IpAddr) -> Option<IpAddr> {
        self.addresses.get(&ip).map(|known| known.shown)
    }

    /// The way of a peer that came in from `from` through the tool, which the app knows as `shown`.
    /// Shown as a stand-in, it is that name's other port: the app's datagrams to it go to the tool by the
    /// name, as the stand-in's own do, so that the tool's routing by name still applies.
    fn way_from(&self, shown: SocketAddr, from: SocketAddr) -> PeerWay {
        let name = (shown.ip() != from.ip())
            .then(|| {
                self.names
                    .iter()
                    .find(|(_, known)| known.shown == shown.ip())
            })
            .flatten()
            .map(|(name, _)| name.clone());
        match name.and_then(|name| Target::name(&name, shown.port())) {
            Some(target) => PeerWay {
                header: Some(socks5::datagram(&target, &[]).into()),
                from: Some(from),
                name: target_name(&target),
            },
            None => PeerWay::through_tool(Target::Address(from)),
        }
    }
}

impl Mapping {
    /// The peer the app knows as `address`, made with `way` if it is new; the mapping and the peer are
    /// refreshed.
    fn peer(
        &mut self,
        shared: &Shared,
        (app, address): (SocketAddr, SocketAddr),
        now: Instant,
        (came_in, way): (bool, PeerWay),
    ) -> &mut Peer {
        self.last = now;
        let Self {
            peers,
            sources,
            uid,
            came_in: count,
            ..
        } = self;
        let peer = peers.entry(address).or_insert_with(|| {
            sources.add_peer(address, &way, came_in);
            *count += usize::from(came_in);
            Peer::new(shared, app, address, *uid, now, (came_in, way))
        });
        peer.last = now;
        peer
    }

    /// A new peer that came in, which the app knows as `shown`: dropped beyond [`CAME_IN`], or when the
    /// app already knows another peer by that address.
    fn come_in(
        &mut self,
        shared: &Shared,
        (app, shown): (SocketAddr, SocketAddr),
        now: Instant,
        way: PeerWay,
    ) -> LetIn {
        if self.peers.contains_key(&shown) {
            return LetIn::Unmatched;
        }
        if self.came_in >= CAME_IN {
            return LetIn::Capped;
        }
        // A flow the app did not start, logged as any other: the log's flag for a flow that came in
        // waits for its new record format (ADR 0044, decision 4).
        let peer = self.peer(shared, (app, shown), now, (true, way));
        LetIn::Peer(shown, peer.bytes.clone(), false)
    }

    /// Ends the flows of the peers silent since `since`; their addresses are let in no more, unless
    /// another peer has the same one.
    fn sweep(&mut self, since: Instant, shared: &Shared) {
        let Self {
            peers,
            sources,
            came_in,
            ..
        } = self;
        peers.retain(|&address, peer| {
            if peer.last > since {
                return true;
            }
            shared.finish(peer.id);
            sources.remove_peer(address, &peer.way);
            *came_in = came_in.saturating_sub(usize::from(peer.came_in));
            false
        });
    }

    /// Whether the app's datagrams to its peers may leave without asking Android again whose socket this
    /// is: the app sent within `reask`, and Android named its app within thirty times that.
    fn fresh(&self, now: Instant, reask: Duration) -> bool {
        now.duration_since(self.sent) < reask
            && now.duration_since(self.named) < reask.saturating_mul(30)
    }

    /// Whether the mapping may still carry its app's datagrams: once the chain was set again, whether
    /// the app's datagrams still leave its way. A mapping that may not ends (ADR 0044, decision 1: when
    /// the chain changes), so that the app's next datagram opens one on the new route.
    fn keeps_its_way(&mut self, shared: &Shared) -> bool {
        let chains = shared.chains.load(Ordering::Acquire);
        if chains == self.chains {
            return true;
        }
        if !Exit::of(shared.app_route(self.uid)).is_some_and(|exit| self.exit.same(&exit)) {
            return false;
        }
        self.chains = chains;
        true
    }

    /// The app sends to the peer it knows as `address`: one that came in is a peer of the app from now
    /// on, read for a QUIC name and no longer counted under [`CAME_IN`].
    fn answering(&mut self, address: SocketAddr) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if std::mem::take(&mut peer.came_in) {
            peer.quic = Some((peer.opened, Box::new(quic::Initial::new())));
            self.came_in = self.came_in.saturating_sub(1);
        }
    }

    /// The peer the app knows as `shown`, refreshed by `answer`. Watch learns names only from a peer the
    /// app sent to, or from an answer to a query the app sent one that came in.
    fn answered_by(&mut self, shown: SocketAddr, answer: &[u8], now: Instant) -> LetIn {
        let Some(peer) = self.peers.get_mut(&shown) else {
            return LetIn::Unmatched;
        };
        peer.last = now;
        self.last = now;
        let learns = !peer.came_in_first || peer.asked_for(answer);
        LetIn::Peer(shown, peer.bytes.clone(), learns)
    }

    /// Which peer an answer from the tool's relay is for, by the address or the name its header gives
    /// (ADR 0044, decision 2), with the direct path's filtering: from a peer, to that peer; from another
    /// port of an address the app sent to, to a new peer; from an address the app never saw, to the
    /// stand-in it may be the first answer of; from anywhere else, nowhere.
    fn relayed_answer(
        &mut self,
        shared: &Shared,
        app: SocketAddr,
        (target, answer): (&Target, &[u8]),
        now: Instant,
    ) -> LetIn {
        let (shown, way) = match target {
            Target::Address(address) => {
                // An IPv4 address the relay gives as IPv6 is still the address the app sent to.
                let from = SocketAddr::new(address.ip().to_canonical(), address.port());
                let contest = shared.limits.udp_contest;
                // A destination's own address first, then the one a stand-in was bound to: such an
                // answer never binds a stand-in. A bound stand-in's address, on a port another stand-in
                // waits on, could be answering either name: the tool may have resolved both to it. So
                // for `Limits::udp_contest` after the app first asked the other name.
                if self
                    .peers
                    .get(&from)
                    .is_some_and(|peer| peer.way.from == Some(from))
                {
                    return self.answered_by(from, answer, now);
                }
                if let Some(&shown) = self.sources.aliases.get(&from) {
                    if self.contested(from.port(), None, (now, contest)) {
                        return LetIn::Unmatched;
                    }
                    return self.answered_by(shown, answer, now);
                }
                // Another port of an address the app sent to comes in as that address's, never as a
                // stand-in's first answer. Of an address only a stand-in was bound to, on a port a
                // stand-in waits on: when that is the same stand-in, the name the tool resolved to this
                // address asked on another port, the answer binds it there too; while another name's
                // still contests the port, the answer could again be either name's.
                let Some(ip) = self.sources.shown(from.ip()) else {
                    return self.first_answer(from, answer, now);
                };
                if ip != from.ip() {
                    let same = SocketAddr::new(ip, from.port());
                    if self.contested(from.port(), Some(same), (now, contest)) {
                        return LetIn::Unmatched;
                    }
                    let waits = self
                        .sources
                        .waiting
                        .get(&from.port())
                        .is_some_and(|waiting| waiting.contains(&same));
                    if waits {
                        let asked = from.port() != 53
                            || self
                                .peers
                                .get(&same)
                                .is_some_and(|peer| peer.asked_for(answer));
                        if asked {
                            return self.bind(same, (from, answer), now);
                        }
                        return LetIn::Unmatched;
                    }
                }
                let shown = SocketAddr::new(ip, from.port());
                (shown, self.sources.way_from(shown, from))
            }
            // A relay that gives back the name it was asked for answers for that name's stand-in;
            // another port of the name is another port of the stand-in.
            Target::Name(name, port) => {
                let Some(stand_in) = self.sources.names.get(&name_key(name)).map(|k| k.shown)
                else {
                    return LetIn::Filtered;
                };
                let shown = SocketAddr::new(stand_in, *port);
                if let Some(peer) = self.peers.get_mut(&shown) {
                    // The stand-in's own answer: it no longer waits for a first answer from an address,
                    // which whoever reached the relay later from its port could otherwise send it.
                    peer.answered();
                    self.sources.stop_waiting(shown);
                    return self.answered_by(shown, answer, now);
                }
                (shown, PeerWay::through_tool(target.clone()))
            }
        };
        self.come_in(shared, (app, shown), now, way)
    }

    /// Whether a stand-in other than `except` waits on `port` and still contests the answers from an
    /// address another stand-in was bound to: for `contest` after the app first sent to it, `now`.
    fn contested(
        &self,
        port: u16,
        except: Option<SocketAddr>,
        (now, contest): (Instant, Duration),
    ) -> bool {
        self.sources.waiting.get(&port).is_some_and(|waiting| {
            waiting.iter().any(|shown| {
                Some(*shown) != except
                    && self
                        .peers
                        .get(shown)
                        .is_some_and(|peer| now.duration_since(peer.made) < contest)
            })
        })
    }

    /// An answer from an address the app never saw, through the tool: the first answer of a stand-in
    /// still waiting on its port, or nothing (ADR 0044, decision 2).
    ///
    /// The tool resolved the stand-in's name itself, so its relay answers from an address the app never
    /// saw. A stand-in is bound to the first answer from the port the app asked, when it alone could
    /// take it; the answer then goes to the app from the stand-in, and later ones from that address too.
    /// On port 53 the answer must also be a DNS response to a query the app sent that stand-in, by its
    /// ID and question: so a sender that guesses neither cannot take the stand-in, nor feed Watch's
    /// names. On other ports, until unit 9b reads each protocol's own identifier, any sender that
    /// reaches the tool's relay first from that port, at an address the app never sent to, takes a
    /// waiting stand-in, and the real answer is then dropped.
    ///
    /// When several stand-ins could take it, the answer could be any of their names', and handing it
    /// to one could give the app one name's answer as another's for as long as the mapping lasts: it
    /// is dropped and counted, and so are the next ones, for as long as more than one waits. An app
    /// that asks names on one port one after another, each once the last answered, binds each in turn;
    /// one that asks them all at once, as some apps ask several STUN servers, gets no answer from them
    /// through the tool. The counter says how often (the maintainer's decision, 2026-11-13: the safe
    /// floor until unit 9b).
    fn first_answer(&mut self, from: SocketAddr, answer: &[u8], now: Instant) -> LetIn {
        let takers = {
            let Some(waiting) = self.sources.waiting.get(&from.port()) else {
                return LetIn::Filtered;
            };
            let mut takers = waiting.iter().copied().filter(|shown| {
                from.port() != 53
                    || self
                        .peers
                        .get(shown)
                        .is_some_and(|peer| peer.asked_for(answer))
            });
            (takers.next(), takers.next())
        };
        match takers {
            (Some(shown), None) => self.bind(shown, (from, answer), now),
            (Some(_), Some(_)) => LetIn::Unmatched,
            (None, _) => LetIn::Filtered,
        }
    }

    /// Binds the stand-in the app knows as `shown` to `from`, the address its first answer came from,
    /// and gives it that `answer`.
    fn bind(
        &mut self,
        shown: SocketAddr,
        (from, answer): (SocketAddr, &[u8]),
        now: Instant,
    ) -> LetIn {
        self.sources.stop_waiting(shown);
        self.sources.add(shown, from);
        if let Some(peer) = self.peers.get_mut(&shown) {
            peer.way.from = Some(from);
            peer.answered();
        }
        self.answered_by(shown, answer, now)
    }
}

/// The engine's UDP: the destinations waiting for their way, the flows of lookups to Watch's own DNS
/// address, and the mappings.
#[derive(Default)]
pub(super) struct UdpTable {
    /// By the app's address and the destination.
    flows: HashMap<(SocketAddr, SocketAddr), UdpEntry>,
    /// By the app's address.
    mappings: HashMap<SocketAddr, Mapping>,
    /// The app sockets whose mapping one destination opens now, each with what tells the others that
    /// wait for it how it went: nothing while it opens and once it opened, else why it failed.
    opening: HashMap<SocketAddr, watch::Receiver<Option<io::ErrorKind>>>,
    /// The app sockets whose app Android is asked for now, each with what tells the destinations that
    /// wait for the answer what it is.
    asking: HashMap<SocketAddr, watch::Receiver<Asked>>,
    /// The number of the last mapping opened.
    opened: u64,
}

pub(super) type UdpFlows = Arc<Mutex<UdpTable>>;

/// What sending a datagram to a peer needs: the mapping's socket, the header that names the peer
/// through the tool, the peer's bytes, and what the datagram's QUIC Initial packets gave.
struct ToPeer {
    socket: Arc<UdpSocket>,
    header: Option<Arc<[u8]>>,
    bytes: Option<Arc<FlowBytes>>,
    quic: Option<QuicRead>,
}

/// What a datagram of the app needs once the table has been read: its flow of lookups' way, its app,
/// the answer Watch's cache holds for it, and the flow's number and lookups owed; its peer's way; or a
/// way to be opened.
enum Next {
    Flow(UdpWay, Option<u32>, Option<Vec<u8>>, (u64, Arc<Owed>)),
    Peer(ToPeer),
    Open,
}

/// What a mapping does with a datagram that came in.
enum LetIn {
    /// The mapping is gone, or it no longer carries its app's datagrams.
    Gone,
    /// It came from an address the app did not send to.
    Filtered,
    /// No one peer can be told for it.
    Unmatched,
    /// It came from another port of an address the app sent to, beyond [`CAME_IN`].
    Capped,
    /// It came from the peer the app knows as this address, whose bytes these are; and whether Watch may
    /// learn names from it.
    Peer(SocketAddr, Option<Arc<FlowBytes>>, bool),
}

/// What a new destination's mapping is opened with: the app, the way its route gives, and how many
/// times the chain had been set before the route was asked.
struct Wanted {
    uid: Option<u32>,
    exit: Exit,
    chains: u64,
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

    /// The open mapping of `app`, by its number, with its socket, if it is the app `wanted.uid`'s and
    /// leaves the way wanted. Another ends: Android handed the port out again, or the chain changed.
    fn open_mapping(
        &mut self,
        app: SocketAddr,
        wanted: &Wanted,
        shared: &Shared,
    ) -> Option<(u64, Arc<UdpSocket>)> {
        let mapping = self.mappings.get_mut(&app)?;
        if mapping.uid == wanted.uid
            && mapping.exit.same(&wanted.exit)
            && mapping.keeps_its_way(shared)
        {
            return Some((mapping.id, Arc::clone(&mapping.socket)));
        }
        let id = mapping.id;
        self.end(app, id, shared);
        None
    }

    /// A datagram from the app to a peer of its mapping: both are refreshed, and its QUIC Initial
    /// packets read. A mapping whose app's datagrams leave another way now ends.
    fn toward_peer(
        &mut self,
        (app, destination): (SocketAddr, SocketAddr),
        payload: &[u8],
        now: Instant,
        shared: &Shared,
    ) -> Option<ToPeer> {
        let mapping = self.mappings.get_mut(&app)?;
        if !mapping.keeps_its_way(shared) {
            let id = mapping.id;
            self.end(app, id, shared);
            return None;
        }
        if !mapping.peers.contains_key(&destination) {
            return None;
        }
        // After a silence, or long after Android last named its app, the datagram asks Android again
        // whose socket this is, as a new destination's does, and waits for the answer: the port may be
        // another app's now, which the log must name and the chain may send another way. A port another
        // app holds then gets a mapping of its own (ADR 0044, decision 1).
        if !mapping.fresh(now, shared.limits.udp_reask) {
            return None;
        }
        mapping.sent = now;
        mapping.answering(destination);
        let peer = mapping.peers.get_mut(&destination)?;
        peer.last = now;
        peer.sent(destination.port(), payload);
        mapping.last = now;
        Some(ToPeer {
            socket: Arc::clone(&mapping.socket),
            header: peer.way.header.clone(),
            bytes: peer.bytes.clone(),
            quic: read_quic(&mut peer.quic, payload),
        })
    }

    /// Whether the mapping `id` of `app` lets in a datagram from `from` (address-dependent filtering,
    /// RFC 4787): one from a peer, or from another port of a peer's address, which becomes a peer of
    /// its own.
    fn let_in(
        &mut self,
        (app, id): (SocketAddr, u64),
        (from, answer): (SocketAddr, &[u8]),
        shared: &Shared,
    ) -> LetIn {
        let Some(mapping) = self.mapping(app, id) else {
            return LetIn::Gone;
        };
        // While a chain sends the app elsewhere, nothing comes in on its direct path.
        if !mapping.keeps_its_way(shared) {
            return LetIn::Gone;
        }
        let now = Instant::now();
        if mapping.peers.contains_key(&from) {
            return mapping.answered_by(from, answer, now);
        }
        if mapping.sources.shown(from.ip()).is_none() {
            return LetIn::Filtered;
        }
        mapping.come_in(shared, (app, from), now, PeerWay::direct(from))
    }

    /// Which peer of the mapping `id` of `app` an `answer` from the tool's relay is for, by its
    /// header's `target`.
    fn let_in_relayed(
        &mut self,
        (app, id): (SocketAddr, u64),
        relayed: (&Target, &[u8]),
        shared: &Shared,
    ) -> LetIn {
        let Some(mapping) = self.mapping(app, id) else {
            return LetIn::Gone;
        };
        if !mapping.keeps_its_way(shared) {
            return LetIn::Gone;
        }
        mapping.relayed_answer(shared, app, relayed, Instant::now())
    }

    /// The flow `id` between `key`'s two ends goes, if it is still there.
    fn remove_flow(&mut self, key: (SocketAddr, SocketAddr), id: u64) {
        if matches!(self.flows.get(&key), Some(UdpEntry::Open(flow)) if flow.id == id) {
            self.flows.remove(&key);
        }
    }

    /// Whether no lookup of the flow `id` between `key`'s two ends waits for its answer any more, as
    /// `owed` holds them; its entry, while it is still the table's, then goes.
    fn settled(&mut self, key: (SocketAddr, SocketAddr), id: u64, owed: &Owed) -> bool {
        if !owed.is_empty() {
            return false;
        }
        self.remove_flow(key, id);
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
            let now = Instant::now();
            let stale = match table.flows.get_mut(&key) {
                Some(UdpEntry::Open(flow)) => !flow.keeps_its_way(&self.shared, key.1, now),
                _ => false,
            };
            if stale {
                // A flow of lookups that may not carry this one gives way to a new flow, which this
                // lookup opens once Android has named its app and its route is asked. The old flow
                // still hands the app every answer it owes for what it sent before.
                table
                    .flows
                    .insert(key, UdpEntry::Opening(vec![packet.to_vec()]));
                Next::Open
            } else {
                match table.flows.get_mut(&key) {
                    Some(UdpEntry::Open(flow)) => {
                        let cached = match flow.way {
                            UdpWay::Lookups(_) => None,
                            UdpWay::Direct(_) => cached_answer(&self.shared, key.1, payload),
                        };
                        // The flow ends once every lookup it carried has its answer.
                        if cached.is_none() {
                            flow.owed.add(payload);
                        }
                        Next::Flow(
                            flow.way.clone(),
                            flow.uid,
                            cached,
                            (flow.id, Arc::clone(&flow.owed)),
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
                        if let Some(to) =
                            table.toward_peer(key, payload, Instant::now(), &self.shared)
                        {
                            Next::Peer(to)
                        } else {
                            table
                                .flows
                                .insert(key, UdpEntry::Opening(vec![packet.to_vec()]));
                            Next::Open
                        }
                    }
                }
            }
        };
        let (way, uid, cached, owed) = match next {
            Next::Flow(way, uid, cached, owed) => (way, uid, cached, owed),
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
        if lookup {
            self.shared.lookup(uid, packet.len());
        }
        if let UdpWay::Lookups(chain) = &way {
            tokio::spawn(answer_lookup(
                payload.to_vec(),
                (key, uid),
                Arc::clone(chain),
                (owed, Arc::clone(&self.udp)),
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
        if let Some(error) = count_sent(&self.shared, None, packet, parsed, sent) {
            self.send(&error).await;
        }
    }

    /// A datagram to a peer of its app socket's mapping.
    async fn send_to_peer(&self, to: ToPeer, packet: &[u8], parsed: &Packet, payload: &[u8]) {
        note_quic(&self.shared, to.quic);
        let sent = send_to(
            &to.socket,
            to.header.as_deref(),
            payload,
            parsed.destination,
        )
        .await;
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

/// Sends a datagram from a mapping's socket to `destination`, or through the tool's relay with the
/// `header` that names it; the bytes sent are the payload's. On the direct path, an ICMP error the
/// kernel holds for the socket fails its next send once, and that datagram does not leave: it is sent
/// again. The mapping's task reads the error itself from the socket's error queue, for the destination
/// it was for.
async fn send_to(
    socket: &UdpSocket,
    header: Option<&[u8]>,
    payload: &[u8],
    destination: SocketAddr,
) -> io::Result<usize> {
    if let Some(header) = header {
        return socket
            .send(&[header, payload].concat())
            .await
            .map(|_| payload.len());
    }
    match socket.send_to(payload, destination).await {
        Err(error) if errors::from_icmp(&error) => socket.send_to(payload, destination).await,
        sent => sent,
    }
}

/// As [`send_to`], without waiting for room in the socket's buffer.
fn try_send_to(
    socket: &UdpSocket,
    header: Option<&[u8]>,
    payload: &[u8],
    destination: SocketAddr,
) -> io::Result<usize> {
    if let Some(header) = header {
        return socket
            .try_send(&[header, payload].concat())
            .map(|_| payload.len());
    }
    match socket.try_send_to(payload, destination) {
        Err(error) if errors::from_icmp(&error) => socket.try_send_to(payload, destination),
        sent => sent,
    }
}

/// Opens a destination's way, off the event loop: asks Android whose it is, then makes it a peer of its
/// app socket's mapping, or for Watch's own DNS address opens a flow of its own. Where the route sends
/// the app's UDP nowhere, the app is told the destination cannot be reached. When the chain takes the
/// app, or lets it go, while its way opens, the destination is routed again: what waited leaves by the
/// new route, never by the old.
async fn open_udp(
    key: (SocketAddr, SocketAddr),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let (app, destination) = key;
    // An app Android cannot name is unknown, in the log and to the chain, even when Android named this
    // socket's app before: the port may be another app's now, and a guess would log one app's traffic
    // as another's. While a chain is on, such an app goes nowhere.
    let uid = owner_of(key, &shared, &flows).await;
    if shared.is_tunnel_dns(destination.ip()) {
        open_flow(key, uid, tun, shared, flows, changes).await;
        return;
    }
    loop {
        // Read before the route, so that a chain set meanwhile makes the mapping ask again.
        let chains = shared.chains.load(Ordering::Acquire);
        let Some(exit) = Exit::of(shared.route(uid, destination)) else {
            // A flow whose app Android cannot name while a chain is on, a stand-in outside the chain,
            // or a chained app's UDP through a tool without UDP (VPN.md).
            let (_, mut flow) = begin_udp(&shared, app, destination, uid);
            flow.outcome = Outcome::Unreachable;
            udp_failed(key, flow, &tun, &shared, &flows).await;
            return;
        };
        let wanted = Wanted { uid, exit, chains };
        if open_peer(key, wanted, (&tun, &shared, &flows, &changes)).await {
            return;
        }
    }
}

/// What a mapping is opened with besides its destination and its way.
type Context<'a> = (
    &'a Arc<Tun>,
    &'a Arc<Shared>,
    &'a UdpFlows,
    &'a watch::Receiver<u64>,
);

/// What a destination's question to Android about its app socket comes to.
enum Question {
    /// Its mapping is fresh again: Android named the app since the datagram came, and that is the answer.
    Fresh(Option<u32>),
    /// It asks on its own.
    Alone,
    /// It asks, and tells the answer to the destinations that come while it waits.
    Ask(watch::Sender<Asked>),
    /// It waits for the answer to the question already out.
    Join(watch::Receiver<Asked>),
}

/// Where a question to Android about an app socket's app stands.
#[derive(Clone, Copy)]
enum Asked {
    Waiting,
    /// The app Android named, if it named one.
    Answered(Option<u32>),
}

/// Asks Android whose app socket `key`'s app is. A destination the socket's mapping already knows asks
/// once for all of them: those that come while its question is out wait for its answer instead of
/// asking again, so that a pause in an app socket's sending costs one question to Android, not one for
/// each destination it knows. Their datagrams wait meanwhile, as a new destination's do. An unconnected
/// UDP socket has one app whatever the destination, so the answer is theirs too.
///
/// A new destination, or a lookup to the tunnel's DNS address, asks on its own, never joining a
/// question that began before its datagram came: that answer may name the app that held the port
/// before, and a new destination of a chained app would then leave directly, under the old app. Each
/// new destination so costs a question of its own, as a burst of them from one socket does. A known
/// destination joining an older question is no worse than the window ADR 0044 states: it would have
/// left by its mapping without asking at all.
///
/// An answer that names the mapping's own app makes the mapping fresh as the question ends, under one
/// lock: a datagram to a destination it knows that comes after the answer, before the datagrams that
/// waited for it have left, then leaves by the mapping instead of asking again. So does one that came
/// while the question was out but asks only once it is answered: the answer it would have joined is
/// the mapping's app.
async fn owner_of(
    (app, destination): (SocketAddr, SocketAddr),
    shared: &Arc<Shared>,
    flows: &UdpFlows,
) -> Option<u32> {
    let question = {
        let mut table = lock(flows);
        let mapping = table
            .mappings
            .get(&app)
            .filter(|mapping| mapping.peers.contains_key(&destination))
            .filter(|_| !shared.is_tunnel_dns(destination.ip()));
        match (mapping, table.asking.get(&app)) {
            (None, _) => Question::Alone,
            (Some(mapping), _) if mapping.fresh(Instant::now(), shared.limits.udp_reask) => {
                Question::Fresh(mapping.uid)
            }
            // One whose asker is gone without a word (the engine stopping) holds no one up.
            (Some(_), Some(waiting)) if waiting.has_changed().is_ok() => {
                Question::Join(waiting.clone())
            }
            (Some(_), _) => {
                let (told, waiting) = watch::channel(Asked::Waiting);
                table.asking.insert(app, waiting);
                Question::Ask(told)
            }
        }
    };
    match question {
        Question::Fresh(uid) => uid,
        Question::Alone => owner(shared, UDP, app, destination).await,
        Question::Ask(told) => {
            let uid = owner(shared, UDP, app, destination).await;
            {
                let mut table = lock(flows);
                table.asking.remove(&app);
                if let Some(mapping) = table.mappings.get_mut(&app)
                    && mapping.uid == uid
                {
                    let now = Instant::now();
                    mapping.sent = now;
                    mapping.named = now;
                }
            }
            let _ = told.send(Asked::Answered(uid));
            uid
        }
        Question::Join(mut waiting) => {
            let _ = waiting.changed().await;
            let answer = *waiting.borrow();
            match answer {
                Asked::Answered(uid) => uid,
                Asked::Waiting => owner(shared, UDP, app, destination).await,
            }
        }
    }
}

/// Makes a destination a peer of its app socket's mapping, opening the mapping first if the app has
/// none, or if the one it has is another app's or leaves another way. The datagrams that waited leave
/// under the table's lock, so that none that comes meanwhile overtakes them, and the peer is known
/// before its answer can come. `false` when the chain changed the app's way meanwhile: nothing that
/// waited has left, and the destination is to be routed again.
async fn open_peer(
    key: (SocketAddr, SocketAddr),
    wanted: Wanted,
    (tun, shared, flows, changes): Context<'_>,
) -> bool {
    let (app, destination) = key;
    let opened = match PeerWay::toward(shared, &wanted.exit, destination) {
        // A stand-in the map no longer holds names nothing the tool could reach.
        None => Err(io::ErrorKind::HostUnreachable.into()),
        Some(way) => mapping_for(key, &wanted, (tun, shared, flows, changes))
            .await
            .map(|opened| opened.map(|opened| (opened, way))),
    };
    let ((id, socket), way) = match opened {
        Ok(Some(opened)) => opened,
        Ok(None) => return false,
        Err(error) => {
            let (_, mut flow) = begin_udp(shared, app, destination, wanted.uid);
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, tun, shared, flows).await;
            return true;
        }
    };
    let _ = socket.writable().await;
    let mut reads = Vec::new();
    let mut errors = Vec::new();
    {
        let mut table = lock(flows);
        match table
            .mapping(app, id)
            .map(|mapping| mapping.keeps_its_way(shared))
        {
            // The mapping ended meanwhile, as the network changed: the datagrams are dropped, as by a
            // full queue.
            None => {
                if let Some(UdpEntry::Opening(waiting)) = table.flows.remove(&key) {
                    Counters::add(&shared.counters.skipped, waiting.len() as u64);
                }
                return true;
            }
            // The chain took the app, or let it go, since its route was asked: what waited, some of it
            // sent since, leaves by the new route.
            Some(false) => {
                table.end(app, id, shared);
                return false;
            }
            Some(true) => {}
        }
        let waiting = match table.flows.remove(&key) {
            Some(UdpEntry::Opening(waiting)) => waiting,
            _ => Vec::new(),
        };
        let Some(mapping) = table.mapping(app, id) else {
            return true;
        };
        // Android named the app just now, before this destination's way was asked.
        let now = Instant::now();
        mapping.sent = now;
        mapping.named = now;
        mapping.answering(destination);
        let peer = mapping.peer(shared, key, now, (false, way));
        let header = peer.way.header.clone();
        for packet in &waiting {
            let Ok(parsed) = packet::parse(packet) else {
                continue;
            };
            let Some(payload) = packet::udp_payload(packet, &parsed) else {
                continue;
            };
            reads.push(read_quic(&mut peer.quic, payload));
            peer.sent(destination.port(), payload);
            let sent = try_send_to(&socket, header.as_deref(), payload, destination);
            errors.extend(count_sent(
                shared,
                peer.bytes.as_deref(),
                packet,
                &parsed,
                sent,
            ));
        }
    }
    for read in reads {
        note_quic(shared, read);
    }
    for error in errors {
        send_to_app(tun, shared, &error).await;
    }
    true
}

/// The mapping of `key`'s app for its new destination, by its number, with its socket: the app's open
/// one, or a new one when it has none, or when the one it has is another app's or leaves another way.
/// Through the tool, a new one is a new `UDP ASSOCIATE`.
///
/// One destination of an app socket opens its mapping while the others that come meanwhile wait for
/// it, as when an app asks several servers at once: through the tool, each would otherwise ask for a
/// relay of its own, a connection to the tool, only for all but one to be closed again. When the one
/// that opens it fails, those that wait fail as it did, at once: the tool that refused it, or did not
/// answer it, would do the same to them. `None` when the chain changed the app's way meanwhile.
async fn mapping_for(
    (app, destination): (SocketAddr, SocketAddr),
    wanted: &Wanted,
    (tun, shared, flows, changes): Context<'_>,
) -> io::Result<Option<(u64, Arc<UdpSocket>)>> {
    let told = loop {
        let mut waiting = {
            let mut table = lock(flows);
            if let Some(open) = table.open_mapping(app, wanted, shared) {
                return Ok(Some(open));
            }
            match table.opening.get(&app) {
                // One whose opener is gone without a word (the engine stopping) holds no one up.
                Some(waiting) if waiting.has_changed().is_ok() => waiting.clone(),
                _ => {
                    let (told, waiting) = watch::channel(None);
                    table.opening.insert(app, waiting);
                    break told;
                }
            }
        };
        let _ = waiting.changed().await;
        let failed = *waiting.borrow();
        if let Some(kind) = failed {
            return Err(kind.into());
        }
    };
    let made = match &wanted.exit {
        Exit::Direct => mapped_socket(shared, destination)
            .await
            .map(|socket| (socket, None)),
        Exit::Tool(chain) => associate(shared, chain)
            .await
            .map(|(socket, control)| (socket, Some(control))),
    };
    let mut table = lock(flows);
    table.opening.remove(&app);
    let (socket, control) = match made {
        Ok(made) => made,
        Err(error) => {
            let _ = told.send(Some(error.kind()));
            return Err(error);
        }
    };
    let socket = Arc::new(socket);
    // The chain may have taken the app, or let it go, while the socket was made, or while this
    // destination waited for another's: a mapping that would leave the old way is not opened.
    let chains = shared.chains.load(Ordering::Acquire);
    if chains != wanted.chains
        && !Exit::of(shared.route(wanted.uid, destination))
            .is_some_and(|exit| exit.same(&wanted.exit))
    {
        return Ok(None);
    }
    // Those that waited find this one once the lock is let go, and `told` goes with this function.
    if let Some(open) = table.open_mapping(app, wanted, shared) {
        return Ok(Some(open));
    }
    table.opened += 1;
    let id = table.opened;
    let ended = Arc::new(Notify::new());
    table.mappings.insert(
        app,
        Mapping {
            id,
            socket: Arc::clone(&socket),
            exit: wanted.exit.clone(),
            chains,
            uid: wanted.uid,
            peers: HashMap::new(),
            sources: Sources::default(),
            came_in: 0,
            last: Instant::now(),
            sent: Instant::now(),
            named: Instant::now(),
            ended: Arc::clone(&ended),
        },
    );
    drop(table);
    Counters::add(&shared.counters.udp_mappings, 1);
    tokio::spawn(mapped(
        MappingTask {
            app,
            id,
            uid: wanted.uid,
            socket: Arc::clone(&socket),
            control,
            ended,
        },
        Arc::clone(tun),
        Arc::clone(shared),
        Arc::clone(flows),
        changes.clone(),
    ));
    Ok(Some((id, socket)))
}

/// A mapping's socket on the direct path: protected, on the unspecified address of the destination's
/// IP version and a port the kernel picks, not connected, and with the ICMP errors that answer its
/// datagrams queued.
async fn mapped_socket(shared: &Arc<Shared>, destination: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(packet::unspecified_like(&destination)).await?;
    protect(shared, socket.as_fd()).await?;
    // Without the queue, the errors are lost, as most userspace NATs lose them; the mapping still works.
    let _ = errors::keep(&socket, destination.is_ipv4());
    Ok(socket)
}

/// A UDP relay of the tool for a mapping: a socket connected to the relay, and the request's
/// connection, which must stay open. The relay is on the phone ([`on_the_phone`]) or at the proxy's own
/// address on the local network; one not on the loopback gets a protected socket, so that its datagrams
/// do not loop back into the tunnel. A relay anywhere else would take the app's datagrams, each with a
/// header naming its destination, across the network beneath, outside the tool: such a tool's UDP is
/// refused, as a tool's without UDP, and counted. Whether the tool sends every destination's datagrams
/// from one socket of its own is the tool's choice (ADR 0044, decision 2).
async fn associate(shared: &Arc<Shared>, chain: &Chain) -> io::Result<(UdpSocket, TcpStream)> {
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
        if relay.ip().to_canonical() != chain.proxy.ip().to_canonical() && !on_the_phone(relay) {
            Counters::add(&shared.counters.udp_relay_elsewhere, 1);
            return Err(io::ErrorKind::HostUnreachable.into());
        }
        let socket = UdpSocket::bind(packet::unspecified_like(&relay)).await?;
        if !relay.ip().is_loopback() {
            protect(shared, socket.as_fd()).await?;
        }
        socket.connect(relay).await?;
        Ok((socket, control))
    };
    match tokio::time::timeout(shared.limits.connect_timeout, opening).await {
        Ok(opened) => opened,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// Whether `relay` is on the phone, so that datagrams to it never cross the network beneath: on its
/// loopback, or at any other address the phone holds, as a tool that shares its proxy on the local
/// network announces its Wi-Fi address. A UDP socket connected to an address the phone holds, which
/// sends nothing, sends from that very address; one connected to any other gets the address of its way
/// out, and a broadcast address refuses it. A socket merely bound to the address would not tell, since
/// Linux lets a socket bind a broadcast address too.
fn on_the_phone(relay: SocketAddr) -> bool {
    let relay = SocketAddr::new(relay.ip().to_canonical(), relay.port());
    if relay.ip().is_loopback() {
        return true;
    }
    std::net::UdpSocket::bind(packet::unspecified_like(&relay))
        .and_then(|probe| {
            probe.connect(relay)?;
            probe.local_addr()
        })
        .is_ok_and(|from| from.ip() == relay.ip())
}

/// What a mapping's task holds.
struct MappingTask {
    app: SocketAddr,
    id: u64,
    uid: Option<u32>,
    socket: Arc<UdpSocket>,
    /// Through the tool, the connection that keeps its relay.
    control: Option<TcpStream>,
    ended: Arc<Notify>,
}

/// Relays a mapping's answers to the app, each from the peer that sent it, with the ICMP errors that
/// answered its datagrams on the direct path, until no datagram passed either way for
/// `Limits::udp_idle` (RFC 4787, REQ-5 and REQ-6), the network beneath changes, the mapping is ended
/// elsewhere (its port is another app's now, or the chain sends the app another way), or the tool ends
/// its relay. A peer silent as long ends as the task wakes, without a timer of its own.
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
        mut control,
        ended,
    } = task;
    let through_tool = control.is_some();
    // The tool keeps a UDP relay for as long as the request's connection is open, and ends it by
    // closing that connection; the mapping ends with it.
    let mut closed = std::pin::pin!(async {
        let mut byte = [0u8; 1];
        match control.as_mut() {
            Some(control) => while matches!(control.read(&mut byte).await, Ok(n) if n > 0) {},
            None => std::future::pending::<()>().await,
        }
    });
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
            () = &mut closed => break,
            () = tokio::time::sleep_until(silent.into()) => {}
            ready = socket.ready(Interest::READABLE | Interest::ERROR) => {
                if !ready.is_ok_and(|ready| !ready.is_read_closed()) {
                    break;
                }
                let queued = take_errors(&socket);
                let ends = (app, id, uid);
                let (packets, end) = with_buffer(|buffer| {
                    if through_tool {
                        relayed_receive(&socket, buffer, ends, &shared, &flows)
                    } else {
                        mapped_receive(&socket, buffer, ends, queued, &shared, &flows)
                    }
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

/// What a mapping on the direct path lets in now: for each ICMP error `queued` for its datagrams, the
/// error from the peer it is for; then what its socket holds, read into `buffer`, each datagram from
/// the peer that sent it. A datagram from an address the app did not send to is dropped and counted.
/// `true` when the mapping ends: it is gone, or its socket failed.
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
            Some(mapping) => {
                // While a chain sends the app elsewhere, nothing comes in on its direct path: its
                // errors neither.
                if !mapping.keeps_its_way(shared) {
                    return (packets, true);
                }
                match mapping.peers.get(&destination) {
                    Some(peer) => peer.bytes.clone(),
                    None => continue,
                }
            }
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
        let (bytes, learns) = match lock(flows).let_in((app, id), (from, &buffer[..n]), shared) {
            LetIn::Gone => return (packets, true),
            LetIn::Filtered => {
                Counters::add(&shared.counters.udp_filtered, 1);
                continue;
            }
            LetIn::Unmatched => {
                Counters::add(&shared.counters.udp_unmatched, 1);
                continue;
            }
            LetIn::Capped => {
                Counters::add(&shared.counters.udp_came_in_capped, 1);
                continue;
            }
            LetIn::Peer(_, bytes, learns) => (bytes, learns),
        };
        packets.extend(deliver(
            shared,
            (app, uid),
            (from, &buffer[..n]),
            bytes.as_deref(),
            learns,
        ));
    }
    (packets, false)
}

/// What a mapping through the tool lets in now: each answer its relay holds, read into `buffer`, from
/// the peer its header names (ADR 0044, decision 2). An answer from an address the app did not send to
/// is dropped and counted, as on the direct path; so is one for which no one peer can be told. `true`
/// when the mapping ends: it is gone, or its relay is (the tool closed it, or stopped), and the app's
/// next datagram asks the tool for another.
fn relayed_receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    (app, id, uid): (SocketAddr, u64, Option<u32>),
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool) {
    let mut packets = Vec::new();
    for _ in 0..BATCH {
        let n = match socket.try_recv(buffer) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return (packets, true),
        };
        // A header that is not well formed, or a fragment, which Watch drops as RFC 1928 allows, names
        // no peer.
        let Some((target, answer)) = socks5::parse_datagram(&buffer[..n]) else {
            Counters::add(&shared.counters.udp_unmatched, 1);
            continue;
        };
        let (from, bytes, learns) =
            match lock(flows).let_in_relayed((app, id), (&target, answer), shared) {
                LetIn::Gone => return (packets, true),
                LetIn::Filtered => {
                    Counters::add(&shared.counters.udp_filtered, 1);
                    continue;
                }
                LetIn::Unmatched => {
                    Counters::add(&shared.counters.udp_unmatched, 1);
                    continue;
                }
                LetIn::Capped => {
                    Counters::add(&shared.counters.udp_came_in_capped, 1);
                    continue;
                }
                LetIn::Peer(from, bytes, learns) => (from, bytes, learns),
            };
        packets.extend(deliver(
            shared,
            (app, uid),
            (from, answer),
            bytes.as_deref(),
            learns,
        ));
    }
    (packets, false)
}

/// An `answer` a mapping let in from the peer the app knows as `from`: counted, and wrapped in an IP
/// packet to the app. Watch learns names from it when it `learns`.
fn deliver(
    shared: &Shared,
    (app, uid): (SocketAddr, Option<u32>),
    (from, answer): (SocketAddr, &[u8]),
    bytes: Option<&FlowBytes>,
    learns: bool,
) -> Option<Vec<u8>> {
    Counters::add(&shared.counters.bytes_down, answer.len() as u64);
    if let Some(bytes) = bytes {
        bytes.add_down(answer.len());
    }
    // An app's own resolver names only that app's flows.
    if learns && from.port() == 53 && uid.is_some() {
        shared.learn(answer, uid);
    }
    let packet = packet::udp(from, app, answer)?;
    if let Some(bytes) = bytes {
        bytes.add_wire_down(packet.len());
    }
    Some(packet)
}

/// The ICMP error `told` for the app at `app`, as if from `destination`, quoting a datagram between
/// the two.
fn unreachable_to(app: SocketAddr, destination: SocketAddr, told: Unreachable) -> Option<Vec<u8>> {
    let quoted = packet::udp(app, destination, &[])?;
    let parsed = packet::parse(&quoted).ok()?;
    packet::unreachable(&quoted, &parsed, told)
}

/// Opens a flow of lookups to Watch's own DNS address, off the event loop: opens its way, sends the
/// lookups that waited for it, and starts relaying the answers. The app gets an ICMP error when the
/// network's resolver cannot be reached. When the chain takes the app, or lets it go, while the way
/// opens, the flow is opened again on the new route: what waited never leaves by the old.
async fn open_flow(
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    while !open_lookups(key, uid, (&tun, &shared, &flows, &changes)).await {}
}

/// One try of [`open_flow`]: `false` when the chain changed the app's way meanwhile, and nothing that
/// waited has left.
async fn open_lookups(
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    (tun, shared, flows, changes): Context<'_>,
) -> bool {
    let (app, destination) = key;
    // Read before the route, so that a chain set meanwhile is seen below.
    let chains = shared.chains.load(Ordering::Acquire);
    let (opened, mut flow) = begin_udp(shared, app, destination, uid);
    let id = opened.id;
    let way = match way_for(shared, shared.route(uid, destination), destination).await {
        Ok(way) => way,
        Err(error) => {
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, tun, shared, flows).await;
            return true;
        }
    };
    // The waiting datagrams leave at once, under the table's lock, so that none that comes meanwhile
    // overtakes them: the socket must first be known to take them.
    way.writable().await;
    let mut lookups = Vec::new();
    let mut errors = Vec::new();
    let mut questions = Vec::new();
    let mut cached = Vec::new();
    let owed: Arc<Owed> = Arc::default();
    {
        let mut table = lock(flows);
        // The chain may have taken the app, or let it go, while the socket was made: what waited,
        // some of it sent since, goes by the new route.
        let now = shared.chains.load(Ordering::Acquire);
        if now != chains && !way.keeps(&shared.route(uid, destination)) {
            return false;
        }
        shared.record(flow);
        let at = Instant::now();
        let open = UdpFlow {
            id,
            way: way.clone(),
            uid,
            owed: Arc::clone(&owed),
            chains: now,
            sent: at,
            named: at,
        };
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
            lookups.push(packet.len());
            if let UdpWay::Lookups(_) = way {
                owed.add(payload);
                questions.push(payload.to_vec());
                continue;
            }
            if let Some(answer) = cached_answer(shared, destination, payload) {
                cached.extend(packet::udp(destination, app, &answer));
                continue;
            }
            let sent = way.try_send(payload);
            if sent.is_ok() {
                owed.add(payload);
            }
            errors.extend(count_sent(shared, None, packet, &parsed, sent));
        }
        table.flows.insert(key, UdpEntry::Open(open));
    }
    // Counted before the answers can be: an answer is counted only for a lookup already counted.
    for length in lookups {
        shared.lookup(uid, length);
    }
    for error in errors {
        send_to_app(tun, shared, &error).await;
    }
    for answer in cached {
        shared.lookup_answered(uid, answer.len());
        send_to_app(tun, shared, &answer).await;
    }
    start_answers(
        way,
        questions,
        (key, uid, (id, owed)),
        (tun, shared, flows, changes),
    );
    true
}

/// Starts answering a new flow of lookups: Watch answers a chained app's itself, each in a task of its
/// own; the network's resolver answers the others, which a task hands the app. The flow ends when none
/// of its lookups waits any more.
fn start_answers(
    way: UdpWay,
    questions: Vec<Vec<u8>>,
    (key, uid, (id, owed)): Ends,
    (tun, shared, flows, changes): Context<'_>,
) {
    let (app, destination) = key;
    match way {
        UdpWay::Lookups(chain) => {
            if lock(flows).settled(key, id, &owed) {
                return;
            }
            for query in questions {
                tokio::spawn(answer_lookup(
                    query,
                    (key, uid),
                    Arc::clone(&chain),
                    ((id, Arc::clone(&owed)), Arc::clone(flows)),
                    Arc::clone(shared),
                    Arc::clone(tun),
                ));
            }
        }
        UdpWay::Direct(socket) => {
            tokio::spawn(answers(
                socket,
                UdpEnds {
                    app,
                    destination,
                    id,
                    uid,
                    owed,
                },
                Arc::clone(tun),
                Arc::clone(shared),
                Arc::clone(flows),
                changes.clone(),
            ));
        }
    }
}

/// A flow of lookups' two ends, its app, and its number with the lookups it owes answers to.
type Ends = ((SocketAddr, SocketAddr), Option<u32>, (u64, Arc<Owed>));

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

/// How a new flow of lookups to Watch's own DNS address goes, by its app's `route`: a protected socket
/// to the network's resolver, or Watch's own answers to a chained app's lookups. A flow whose app
/// Android cannot name while a chain is on goes nowhere.
async fn way_for(
    shared: &Arc<Shared>,
    route: Route,
    destination: SocketAddr,
) -> io::Result<UdpWay> {
    match route {
        Route::Direct => match shared.target(destination) {
            Some(target) => connect_udp(shared, target)
                .await
                .map(|socket| UdpWay::Direct(Arc::new(socket))),
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        },
        Route::Tool(chain) => Ok(UdpWay::Lookups(chain)),
        Route::Refused => Err(io::ErrorKind::HostUnreachable.into()),
    }
}

/// Answers one lookup of a chained app (ADR 0038) and sends the answer to the app; then one lookup
/// fewer of its flow `id` waits. Watch's answer comes within a few seconds (`lookups::LOOKUP_TIMEOUT`
/// for each resolver), so the flow ends once its last lookup has its answer, as a direct one does: a
/// later lookup from the same socket asks Android again whose socket it is.
async fn answer_lookup(
    query: Vec<u8>,
    (key, uid): ((SocketAddr, SocketAddr), Option<u32>),
    chain: Arc<Chain>,
    ((id, owed), flows): ((u64, Arc<Owed>), UdpFlows),
    shared: Arc<Shared>,
    tun: Arc<Tun>,
) {
    let (app, destination) = key;
    let answer = lookups::answer(&shared, &chain, &query).await;
    if let Some(packet) = answer.and_then(|answer| packet::udp(destination, app, &answer)) {
        shared.lookup_answered(uid, packet.len());
        send_to_app(&tun, &shared, &packet).await;
    }
    owed.given_up(&query);
    lock(&flows).settled(key, id, &owed);
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

/// A flow of lookups to the network's resolver, for the task that relays its answers.
struct UdpEnds {
    app: SocketAddr,
    destination: SocketAddr,
    /// The flow's number.
    id: u64,
    uid: Option<u32>,
    /// The lookups it carried that still wait for their answer.
    owed: Arc<Owed>,
}

/// Wraps each answer of a flow of lookups to Watch's own DNS address in an IP packet to the app, until
/// every lookup it carried has its answer, one waited [`LOOKUP_WAIT`] (ADR 0044, decision 3), or the
/// network beneath changes. A flow that gave way to a later one still hands the app what it owes.
async fn answers(
    socket: Arc<UdpSocket>,
    ends: UdpEnds,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
    let key = (ends.app, ends.destination);
    // Only a change after the flow opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    // Lookups all answered from Watch's cache leave nothing to wait for.
    let mut done = lock(&flows).settled(key, ends.id, &ends.owed);
    while !done {
        tokio::select! {
            _ = changes.changed() => break,
            ready = tokio::time::timeout(LOOKUP_WAIT, socket.ready(Interest::READABLE | Interest::ERROR)) => {
                if !matches!(ready, Ok(Ok(ready)) if !ready.is_read_closed()) {
                    break;
                }
                let _ = take_errors(&socket);
                let (packets, end) = with_buffer(|buffer| {
                    relayed(&socket, buffer, &ends, &shared, &flows)
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

/// What a flow of lookups' socket holds now, read into `buffer`: the packets for the app, and whether
/// the flow ends (its socket failed, or each lookup it carried has its answer).
fn relayed(
    socket: &UdpSocket,
    buffer: &mut [u8],
    ends: &UdpEnds,
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool) {
    let &UdpEnds {
        app,
        destination,
        id,
        uid,
        ref owed,
    } = ends;
    let mut packets = Vec::new();
    for _ in 0..BATCH {
        let packet = match socket.try_recv(buffer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Ok(n) => {
                Counters::add(&shared.counters.bytes_down, n as u64);
                let answer = &mut buffer[..n];
                owed.answered(answer);
                // Android's resolver names every app's flows.
                if destination.port() == 53 {
                    shared.learn(answer, None);
                    if shared.uncached_answers.load(Ordering::Relaxed) {
                        lock(&shared.direct_answers).insert(answer, Instant::now());
                        dns::uncache(answer);
                    }
                }
                packet::udp(destination, app, answer)
            }
            // The server's host answered that no one listens there: no lookup will have an answer.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                owed.clear();
                unreachable_to(app, destination, Unreachable::Port)
            }
            Err(_) => return (packets, true),
        };
        if let Some(packet) = packet {
            shared.lookup_answered(uid, packet.len());
            packets.push(packet);
        }
        // A flow of lookups ends with the answer to the last of them.
        if lock(flows).settled((app, destination), id, owed) {
            return (packets, true);
        }
    }
    (packets, false)
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;

    /// A standard query for the A record of `name`, in DNS's form, under the ID `id`.
    fn query(id: u16, name: &[u8]) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        query
    }

    /// The answer to `query`, with no records.
    fn response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response
    }

    const APP: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 10, 1)), 40_000);

    fn waiting_stand_in() -> PeerWay {
        PeerWay {
            header: None,
            from: None,
            name: Some("dns.test".into()),
        }
    }

    /// A mapping with no peer yet, last used `now`.
    async fn mapping(now: Instant) -> io::Result<Mapping> {
        Ok(Mapping {
            id: 1,
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
            exit: Exit::Direct,
            chains: 0,
            uid: None,
            peers: HashMap::new(),
            sources: Sources::default(),
            came_in: 0,
            last: now,
            sent: now,
            named: now,
            ended: Arc::new(Notify::new()),
        })
    }

    /// How a datagram is spaced from the one before in the tests of the thirty-times rule: a twentieth of
    /// `udp_reask`, so that the app never pauses for it.
    fn ticks(shared: &Shared, start: Instant) -> impl Iterator<Item = Instant> {
        let step = shared.limits.udp_reask / 20;
        (1..=20 * 40).map(move |tick| start + step * tick)
    }

    /// An app socket whose datagrams to a peer never pause is asked about again, its mapping refusing
    /// the datagram, exactly when thirty times `udp_reask` have passed since Android last named its app,
    /// not before (fifth review of unit 9, finding 5b).
    #[tokio::test(flavor = "current_thread")]
    async fn a_mapping_that_never_pauses_is_asked_about_after_thirty_times_the_pause()
    -> io::Result<()> {
        let shared = shared();
        let start = Instant::now();
        let mut mapping = mapping(start).await?;
        let peer = SocketAddr::from(([192, 0, 2, 1], 443));
        mapping.peer(&shared, (APP, peer), start, (false, PeerWay::direct(peer)));
        let mut table = UdpTable::default();
        table.mappings.insert(APP, mapping);
        let first = ticks(&shared, start).find(|&at| {
            table
                .toward_peer((APP, peer), b"tick", at, &shared)
                .is_none()
        });
        assert_eq!(
            first.map(|at| at.duration_since(start)),
            Some(shared.limits.udp_reask * 30)
        );
        Ok(())
    }

    /// The same for a flow of lookups whose app never pauses (fifth review of unit 9, finding 5b).
    #[tokio::test(flavor = "current_thread")]
    async fn a_flow_of_lookups_that_never_pauses_is_asked_about_after_thirty_times_the_pause()
    -> io::Result<()> {
        let shared = shared();
        let start = Instant::now();
        let mut flow = UdpFlow {
            id: 1,
            way: UdpWay::Direct(Arc::new(UdpSocket::bind("127.0.0.1:0").await?)),
            uid: None,
            owed: Arc::default(),
            chains: 0,
            sent: start,
            named: start,
        };
        let dns = SocketAddr::from(([192, 0, 2, 53], 53));
        let first = ticks(&shared, start).find(|&at| !flow.keeps_its_way(&shared, dns, at));
        assert_eq!(
            first.map(|at| at.duration_since(start)),
            Some(shared.limits.udp_reask * 30)
        );
        Ok(())
    }

    /// The destination whose datagram asks Android about the app socket, and another the mapping knows.
    const ASKER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 443);
    const OTHER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)), 443);

    /// A mapping of the app `uid` that knows [`ASKER`] and [`OTHER`], has been silent for twice
    /// `udp_reask`, and whose app Android last named thirty-one times `udp_reask` ago.
    async fn paused(shared: &Shared, uid: Option<u32>) -> io::Result<UdpFlows> {
        let ago = |times| {
            Instant::now()
                .checked_sub(shared.limits.udp_reask * times)
                .ok_or(io::ErrorKind::Other)
        };
        let paused = ago(2)?;
        let mut mapping = mapping(paused).await?;
        mapping.uid = uid;
        mapping.named = ago(31)?;
        for peer in [ASKER, OTHER] {
            mapping.peer(shared, (APP, peer), paused, (false, PeerWay::direct(peer)));
        }
        let flows = UdpFlows::default();
        lock(&flows).mappings.insert(APP, mapping);
        Ok(flows)
    }

    /// Whether a datagram to [`OTHER`] now leaves by the mapping, without asking Android.
    fn leaves_unasked(flows: &UdpFlows, shared: &Shared) -> bool {
        lock(flows)
            .toward_peer((APP, OTHER), b"after", Instant::now(), shared)
            .is_some()
    }

    /// After a pause, Android's answer that names the mapping's own app makes the mapping fresh as the
    /// question ends: a datagram to another destination it knows, coming before the asker's datagrams
    /// leave, needs no question of its own (the fifth review's run under load).
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_naming_the_mappings_app_makes_it_fresh_at_once() -> io::Result<()> {
        let shared = Arc::new(shared());
        let flows = paused(&shared, None).await?;
        assert!(!leaves_unasked(&flows, &shared), "a pause asks again");
        assert_eq!(owner_of((APP, ASKER), &shared, &flows).await, None);
        assert!(
            leaves_unasked(&flows, &shared),
            "asked again after the answer"
        );
        Ok(())
    }

    /// An answer that names another app leaves the mapping as it was: the next datagram asks again, and
    /// the mapping ends once its asker's turn comes.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_naming_another_app_leaves_the_mapping_stale() -> io::Result<()> {
        let shared = Arc::new(shared());
        let flows = paused(&shared, Some(10_077)).await?;
        assert_eq!(owner_of((APP, ASKER), &shared, &flows).await, None);
        assert!(!leaves_unasked(&flows, &shared));
        Ok(())
    }

    /// A datagram to a destination the mapping knows that came while a question was out, but asks only
    /// once its mapping is fresh again, takes the mapping's app without asking Android (the fifth
    /// review's run under load). Android here names no app.
    #[tokio::test(flavor = "current_thread")]
    async fn a_known_destination_of_a_fresh_mapping_asks_no_more() -> io::Result<()> {
        let shared = Arc::new(shared());
        let flows = paused(&shared, Some(10_077)).await?;
        if let Some(mapping) = lock(&flows).mappings.get_mut(&APP) {
            (mapping.sent, mapping.named) = (Instant::now(), Instant::now());
        }
        assert_eq!(owner_of((APP, OTHER), &shared, &flows).await, Some(10_077));
        Ok(())
    }

    /// A new destination asks Android on its own, even beside a fresh mapping (fifth review of unit 9,
    /// finding 1).
    #[tokio::test(flavor = "current_thread")]
    async fn a_new_destination_asks_beside_a_fresh_mapping() -> io::Result<()> {
        let shared = Arc::new(shared());
        let flows = paused(&shared, Some(10_077)).await?;
        if let Some(mapping) = lock(&flows).mappings.get_mut(&APP) {
            (mapping.sent, mapping.named) = (Instant::now(), Instant::now());
        }
        let new = SocketAddr::from(([192, 0, 2, 3], 443));
        assert_eq!(owner_of((APP, new), &shared, &flows).await, None);
        Ok(())
    }

    /// A stand-in on port 53 that its relay answers by name waits no more: it drops the queries it kept
    /// and records no more (fifth review of unit 9, finding 3).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_answered_by_name_keeps_no_queries() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 53));
        let asked = query(0x1234, b"\x07example\x03com\x00");
        mapping
            .peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()))
            .sent(53, &asked);
        let by_name = Target::Name("dns.test".into(), 53);
        let answered = response(&asked);
        assert!(matches!(
            mapping.relayed_answer(&shared, APP, (&by_name, &answered), now),
            LetIn::Peer(..)
        ));
        let peer = mapping
            .peers
            .get_mut(&stand_in)
            .ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(peer.asked.len(), 0, "kept after its answer by name");
        peer.sent(53, &query(0x4321, b"\x07example\x03org\x00"));
        assert_eq!(peer.asked.len(), 0, "recorded after its answer by name");
        Ok(())
    }

    /// Only a stand-in on port 53 that waits for its first answer, or a flow from a port 53 that came
    /// in, keeps the queries the app sends it: no other peer holds them in memory.
    #[test]
    fn only_a_waiting_stand_in_or_a_flow_that_came_in_keeps_queries() {
        let shared = shared();
        let now = Instant::now();
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 53));
        let server = SocketAddr::from(([192, 0, 2, 53], 53));
        let other = SocketAddr::from(([192, 0, 2, 53], 5_353));
        let mut waiting = Peer::new(
            &shared,
            APP,
            stand_in,
            None,
            now,
            (false, waiting_stand_in()),
        );
        let mut direct = Peer::new(
            &shared,
            APP,
            server,
            None,
            now,
            (false, PeerWay::direct(server)),
        );
        let mut came_in = Peer::new(
            &shared,
            APP,
            server,
            None,
            now,
            (true, PeerWay::direct(server)),
        );
        let mut elsewhere = Peer::new(
            &shared,
            APP,
            other,
            None,
            now,
            (true, PeerWay::direct(other)),
        );
        let asked = query(0x1234, b"\x07example\x03com\x00");
        waiting.sent(53, &asked);
        direct.sent(53, &asked);
        came_in.sent(53, &asked);
        elsewhere.sent(other.port(), &asked);
        let kept = [&waiting, &direct, &came_in, &elsewhere].map(|peer| peer.asked.len());
        assert_eq!(kept, [1, 0, 1, 0]);
    }

    /// A stand-in bound to the address of its first answer keeps none of the queries it waited on.
    #[tokio::test(flavor = "current_thread")]
    async fn a_bound_stand_in_forgets_the_queries_it_waited_on() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 53));
        let asked = query(0x1234, b"\x07example\x03com\x00");
        let peer = mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        peer.sent(53, &asked);
        peer.sent(53, &query(0x4321, b"\x07example\x03org\x00"));
        assert_eq!(peer.asked.len(), 2);
        let answered = response(&asked);
        let from = SocketAddr::from(([192, 0, 2, 53], 53));
        assert!(matches!(
            mapping.bind(stand_in, (from, &answered), now),
            LetIn::Peer(..)
        ));
        assert_eq!(mapping.peers[&stand_in].asked.len(), 0);
        Ok(())
    }
}
