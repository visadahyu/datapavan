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

/// A flow of lookups to Watch's own DNS address, with the flow's number.
pub(super) struct UdpFlow {
    /// The flow's number, which tells its entry from a later flow's between the same two ends.
    id: u64,
    way: UdpWay,
    /// The app's UID.
    uid: Option<u32>,
    /// The lookups sent to the network's resolver that still wait for their answer.
    unanswered: u32,
    /// How many times the chain had been set when the flow last made sure that its way still holds.
    chains: u64,
}

impl UdpFlow {
    /// Whether the flow may still carry its app's lookups to `destination`: once the chain was set
    /// again, whether its app's route still leads the flow's way. One that may not ends at once, so that
    /// a lookup an app sends once the chain takes it never reaches the network's resolver directly, and
    /// one sent once the chain lets it go is not answered through the tool.
    fn keeps_its_way(&mut self, shared: &Shared, destination: SocketAddr) -> bool {
        let chains = shared.chains.load(Ordering::Acquire);
        if chains == self.chains {
            return true;
        }
        if !self.way.keeps(&shared.route(self.uid, destination)) {
            return false;
        }
        self.chains = chains;
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

/// At most this many DNS queries are kept for a stand-in on port 53 still waiting for its first answer.
const ASKED: usize = 8;

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
    /// The flow's number.
    id: u64,
    /// While the app's first datagrams to it may still name it, their QUIC Initial packets read so far.
    quic: Option<(Opened, Box<quic::Initial>)>,
    bytes: Option<Arc<FlowBytes>>,
    /// When the last datagram passed, either way.
    last: Instant,
    way: PeerWay,
    /// Whether it came in: another port of an address the app sent to, not a destination of the app.
    came_in: bool,
    /// For a stand-in on port 53 still waiting for its first answer, or a flow that came in from a port
    /// 53, the ID and question of each DNS query the app sent it, the latest last: only an answer to one
    /// of them binds the stand-in, or teaches Watch names from a flow the app did not start.
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
            id: opened.id,
            quic: (!came_in).then(|| (opened, Box::new(quic::Initial::new()))),
            bytes: shared.record(flow),
            last: now,
            way,
            came_in,
            asked: Vec::new(),
        }
    }

    /// Notes a datagram the app sends it to `port`: for a stand-in on port 53 still waiting for its
    /// first answer, or a flow from a port 53 that came in, the ID and question of a DNS query.
    fn sent(&mut self, port: u16, payload: &[u8]) {
        let waits = self.way.name.is_some() && self.way.from.is_none();
        if port != 53 || !(waits || self.came_in) {
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

/// A name as DNS compares it: whatever its case, and with or without a final dot.
fn name_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Sources {
    /// A new peer, which the app knows as `shown`, that leaves by `way`.
    fn add_peer(&mut self, shown: SocketAddr, way: &PeerWay) {
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
            if way.from.is_none() {
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
            sources.add_peer(address, &way);
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

    /// The peer the app knows as `shown`, refreshed by `answer`. Watch learns names only from a peer the
    /// app sent to, or from an answer to a query the app sent one that came in.
    fn answered_by(&mut self, shown: SocketAddr, answer: &[u8], now: Instant) -> LetIn {
        let Some(peer) = self.peers.get_mut(&shown) else {
            return LetIn::Unmatched;
        };
        peer.last = now;
        self.last = now;
        let learns = !peer.came_in || peer.asked_for(answer);
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
                let waited_on = self.sources.waiting.contains_key(&from.port());
                // A destination's own address first, then the one a stand-in was bound to: such an
                // answer never binds a stand-in. A bound stand-in's address, on a port another stand-in
                // waits on, could be answering either name: the tool may have resolved both to it.
                if self
                    .peers
                    .get(&from)
                    .is_some_and(|peer| peer.way.from == Some(from))
                {
                    return self.answered_by(from, answer, now);
                }
                if let Some(&shown) = self.sources.aliases.get(&from) {
                    if waited_on {
                        return LetIn::Unmatched;
                    }
                    return self.answered_by(shown, answer, now);
                }
                // Another port of an address the app sent to comes in as that address's, never as a
                // stand-in's first answer. Of an address only a stand-in was bound to, on a port a
                // stand-in waits on: when that is the same stand-in, the name the tool resolved to this
                // address asked on another port, the answer binds it there too; when another waits,
                // the answer could again be either name's.
                let Some(ip) = self.sources.shown(from.ip()) else {
                    return self.first_answer(from, answer, now);
                };
                if ip != from.ip() && waited_on {
                    let same = SocketAddr::new(ip, from.port());
                    let alone = self
                        .sources
                        .waiting
                        .get(&from.port())
                        .is_some_and(|waiting| *waiting == [same]);
                    let asked = from.port() != 53
                        || self
                            .peers
                            .get(&same)
                            .is_some_and(|peer| peer.asked_for(answer));
                    if alone && asked {
                        return self.bind(same, (from, answer), now);
                    }
                    return LetIn::Unmatched;
                }
                let shown = SocketAddr::new(ip, from.port());
                (shown, PeerWay::through_tool(Target::Address(from)))
            }
            // A relay that gives back the name it was asked for answers for that name's stand-in;
            // another port of the name is another port of the stand-in.
            Target::Name(name, port) => {
                let Some(stand_in) = self.sources.names.get(&name_key(name)).map(|k| k.shown)
                else {
                    return LetIn::Filtered;
                };
                let shown = SocketAddr::new(stand_in, *port);
                if self.peers.contains_key(&shown) {
                    return self.answered_by(shown, answer, now);
                }
                (shown, PeerWay::through_tool(target.clone()))
            }
        };
        self.come_in(shared, (app, shown), now, way)
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
            peer.asked = Vec::new();
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

/// What a datagram of the app needs once the table has been read: its flow of lookups' way, its app
/// and the answer Watch's cache holds for it; its peer's way; or a way to be opened.
enum Next {
    Flow(UdpWay, Option<u32>, Option<Vec<u8>>),
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
        // While a chain is on, the app decides the way: after a silence, or long after Android last
        // named it, the datagram asks Android again whose socket this is, as a new destination's does,
        // and waits for the answer. A port another app now holds then gets a mapping of its own.
        let reask = shared.limits.udp_reask;
        if (now.duration_since(mapping.sent) >= reask
            || now.duration_since(mapping.named) >= reask.saturating_mul(30))
            && shared.chain().is_some()
        {
            return None;
        }
        mapping.sent = now;
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
            let stale = match table.flows.get_mut(&key) {
                Some(UdpEntry::Open(flow)) => !flow.keeps_its_way(&self.shared, key.1),
                _ => false,
            };
            if stale {
                // A flow of lookups that the chain, set again, sends another way gives way to one on
                // the new route, which this lookup opens. The old flow's task still hands the app the
                // answers to what it sent before.
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
                        // The flow ends once every lookup it sent has its answer.
                        if lookup && cached.is_none() && matches!(flow.way, UdpWay::Direct(_)) {
                            flow.unanswered = flow.unanswered.saturating_add(1);
                        }
                        Next::Flow(flow.way.clone(), flow.uid, cached)
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
        let (way, uid, cached) = match next {
            Next::Flow(way, uid, cached) => (way, uid, cached),
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
    let named = owner(&shared, UDP, app, destination).await;
    // When Android cannot name the app of a socket it named before, the socket's mapping keeps its app;
    // but not while a chain is on, where the app decides the way: there an app Android cannot name goes
    // nowhere, never by a guess that may be another app's (the port may have been handed out again).
    let uid = named.or_else(|| {
        if shared.chain().is_some() {
            return None;
        }
        lock(&flows).mappings.get(&app).and_then(|m| m.uid)
    });
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
    {
        let mut table = lock(flows);
        // The chain may have taken the app, or let it go, while the socket was made: what waited,
        // some of it sent since, goes by the new route.
        let now = shared.chains.load(Ordering::Acquire);
        if now != chains && !way.keeps(&shared.route(uid, destination)) {
            return false;
        }
        shared.record(flow);
        let mut open = UdpFlow {
            id,
            way: way.clone(),
            uid,
            unanswered: 0,
            chains: now,
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
                questions.push(payload.to_vec());
                continue;
            }
            if let Some(answer) = cached_answer(shared, destination, payload) {
                cached.extend(packet::udp(destination, app, &answer));
                continue;
            }
            let sent = way.try_send(payload);
            if sent.is_ok() {
                open.unanswered += 1;
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
        (key, id),
        uid,
        (tun, shared, flows, changes),
    );
    true
}

/// Starts answering a new flow of lookups: Watch answers a chained app's itself; the network's resolver
/// answers the others, which a task hands the app.
fn start_answers(
    way: UdpWay,
    questions: Vec<Vec<u8>>,
    (key, id): ((SocketAddr, SocketAddr), u64),
    uid: Option<u32>,
    (tun, shared, flows, changes): Context<'_>,
) {
    let (app, destination) = key;
    match way {
        UdpWay::Lookups(chain) => {
            answer_waiting(
                questions,
                (key, id),
                uid,
                &chain,
                shared,
                tun,
                Arc::clone(flows),
            );
        }
        UdpWay::Direct(socket) => {
            tokio::spawn(answers(
                socket,
                UdpEnds {
                    app,
                    destination,
                    id,
                    uid,
                },
                Arc::clone(tun),
                Arc::clone(shared),
                Arc::clone(flows),
                changes.clone(),
            ));
        }
    }
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

/// A flow of lookups to the network's resolver, for the task that relays its answers.
struct UdpEnds {
    app: SocketAddr,
    destination: SocketAddr,
    /// The flow's number.
    id: u64,
    uid: Option<u32>,
}

/// Wraps each answer of a flow of lookups to Watch's own DNS address in an IP packet to the app, until
/// every lookup it carried has its answer, one waited [`LOOKUP_WAIT`] (ADR 0044, decision 3), or the
/// network beneath changes.
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
    let mut done = lock(&flows).answered(key, ends.id, 0);
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
    } = ends;
    let mut packets = Vec::new();
    for _ in 0..BATCH {
        let packet = match socket.try_recv(buffer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Ok(n) => {
                Counters::add(&shared.counters.bytes_down, n as u64);
                let answer = &mut buffer[..n];
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
            // The server's host answered that no one listens there.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                unreachable_to(app, destination, Unreachable::Port)
            }
            Err(_) => return (packets, true),
        };
        if let Some(packet) = packet {
            shared.lookup_answered(uid, packet.len());
            packets.push(packet);
        }
        // A flow of lookups ends with the answer to the last of them.
        if lock(flows).answered((app, destination), id, 1) {
            return (packets, true);
        }
    }
    (packets, false)
}
