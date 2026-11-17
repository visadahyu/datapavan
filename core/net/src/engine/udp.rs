//! UDP through the tunnel (ADR 0044, decisions 1 and 2). Each app socket gets one mapping, whatever
//! the destination (RFC 4787, REQ-1): on the direct path, one protected socket, not connected; through
//! the user's tool, one `UDP ASSOCIATE`, each datagram with a header that names its destination, and one
//! more for each stand-in whose answers the address alone could not tell from another's on its port and
//! that carries no identifier to tell them by (unit 9b). A
//! mapping lets in only what comes from an address the app sent to (address-dependent filtering);
//! through the tool, each answer's header says where it came from. Each destination stays a flow of
//! its own in the log, with its own name, bytes and QUIC reading. Lookups to Watch's own DNS address
//! keep one socket for each flow. Sockets are opened off the packet loop, and answers are read into one
//! buffer for each engine thread.

use super::budget::{Full, Place};
use super::chain::{Chain, Route, connect_proxy, io_error};
use super::errors::{Queued, Tally, Told};
use super::logbook::FlowBytes;
use super::lookups;
use super::naming::Begun;
use super::upstream::{connect_udp, owner, protect};
use super::whose::{Named, Record, Settled, Step, Verdict, Waiter};
use super::{
    BATCH, Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, errors, hops,
    is_unreachable, lock, send_to_app,
};
use crate::identifiers;
use crate::packet::{Packet, Sent, UDP, Unreachable};
use crate::socks5::{self, Command, Target};
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{answers, dns, packet, quic};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, Interest};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc, watch};

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
pub(super) fn with_buffer<T>(read: impl FnOnce(&mut [u8]) -> T) -> T {
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
}

impl UdpFlow {
    /// Whether the chain, set again or not, still sends the flow's app to `destination` the flow's way:
    /// a lookup an app sends once the chain takes it never reaches the network's resolver directly, and
    /// one sent once the chain lets it go is not answered through the tool.
    fn keeps_its_way(&mut self, shared: &Shared, destination: SocketAddr) -> bool {
        let chains = shared.chains.load(Ordering::Acquire);
        if chains != self.chains {
            if !self.way.keeps(&shared.route(self.uid, destination)) {
                return false;
            }
            self.chains = chains;
        }
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
    /// Sends one datagram's payload, without waiting for room in the socket's buffer, as
    /// [`try_send_to`] does; the bytes sent are the payload's. Not for [`UdpWay::Lookups`].
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
    Opening(Holding),
    Open(UdpFlow),
}

/// A destination's datagrams that wait for its way, whole packets in the order the app sent them, each
/// with when it came, at most `Limits::udp_waiting`: each leaves once the way is there, if the rule says
/// whose it is ([`Record::whose`]), and the app is known before the first does. For a destination the
/// app had no way to, and for a lookup, `floor` is when the first came: only an answer asked since may
/// stand for them.
pub(super) struct Holding {
    floor: Option<Instant>,
    held: Vec<Held>,
}

/// A datagram that waits for its way: when it came, whose the answers said it was then, and the whole
/// packet.
type Held = Waiter<Vec<u8>>;

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
/// table without end. A flow that came in counts for as long as it lives, even once the app answers it:
/// an app that answers whoever reaches it, as a DHT node or a QUIC listener does, would otherwise lift
/// the cap for every port it answers.
const CAME_IN: usize = 64;

/// At most this many DNS queries are kept for a stand-in on port 53 still waiting for its first answer,
/// or for a flow from a port 53 that came in: an answer to an older one binds nothing and teaches
/// nothing. A resolver of an app's own may send many before the first answer comes, retrying, asking
/// both A and AAAA, and asking several names at once; 64 holds 32 names asked both ways. It is bounded
/// all the same: 64 questions of at most 255 bytes, about 17 KB, and only while the stand-in waits.
/// Binding by any DNS response instead would let any sender at port 53 take the stand-in.
///
/// On other ports a stand-in keeps as many of the identifiers its app's datagrams carry
/// ([`identifiers::of`]), on the same terms (ADR 0044, unit 9b): 64 bytes each in place, a DNS question's
/// name of at most 253 bytes beside it, and for each of at most [`QUIC_ASKED`] QUIC identifiers the
/// server's keys in two versions once an answer needed them (864 bytes each on x86-64), so at most
/// 64 x 64 + 56 x 253 + 8 x 2 x 864 = 32,088 bytes and the vector's 24, only while it is a candidate.
/// That is for each stand-in the app sent to, an address and a port: an app that asks one name on many
/// ports makes one for each, and a stranger makes none. A STUN client retransmits a request with its
/// ID, a QUIC client its Initial with its IDs, so the same one is kept once.
const ASKED: usize = 64;

/// Of those, at most this many QUIC identifiers (ADR 0044, unit 9b, fix round 1): each keeps the server's
/// Initial keys once an answer needed them, in each version a server may answer in. A QUIC client changes
/// the destination ID it asks by only for a Retry, a Version Negotiation or a new attempt, so 8 hold
/// several attempts of one connection.
const QUIC_ASKED: usize = 8;

/// At most this many identifiers the app sent a peer through the tool are remembered for it, those it sent
/// last, one sent again counting as sent then (ADR 0044, unit 9b, fix rounds 2 and 3): each as a fingerprint
/// of 8 bytes ([`identifiers::fingerprint`]), and kept once in its association's [`Fingerprints`], so that an
/// identifier the app also sent another peer on the same port tells neither apart, and one it sent one peer
/// alone names that peer (fix round 5). A stand-in whose first datagram carries one another peer of the
/// mapping's association was sent gets an association of its own ([`UdpTable::own_wanted`]); where it cannot,
/// or where the other peer came after it, the identifier binds it to nothing another peer that was sent it
/// answers from. 64 hold an NTP client's requests to its servers, a stub resolver's retry of one query to the
/// next server, and an ICE agent's checks of one remote candidate. It costs at most 64 x 8 bytes for each
/// peer, and an entry of the association's fingerprints for each of those, 32 bytes (the fingerprint, its
/// count and its keepers' exclusive-or, [`Keepers`]) and a control byte in a table whose buckets are at most
/// 16/7 of its entries, about 75.4 bytes, so at most 64 x 83.4 = 5,339 bytes for a peer the app sent
/// identifiers to, nothing for one it sent none; on the direct path, where no stand-in waits, nothing is
/// kept. A settled peer's are read from the datagram's headers ([`identifiers::named`]), a QUIC Initial
/// unopened. Peers are not capped: each destination the app sent to within `udp_idle` is one, as each is a
/// flow in the log; an app pays these bytes for the identifiers it sends, 83.4 at most for each, within the
/// life of the peer it sends them to.
const TOLD: usize = 64;

/// At most this many errors from the path are owed to one peer of a mapping: one for each datagram the
/// app sent it (ADR 0044, unit 11b). An app that sends a peer many datagrams at once, each too large
/// for a router on the path, may be told of each; a sender that forges errors for a peer the app sends
/// to without pause can pass on no more than one for each of the app's last 64 datagrams there.
const OWED_ERRORS: u8 = 64;

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
    /// How many of the peers came in before the app sent to them ([`CAME_IN`]).
    came_in: usize,
    /// When the last datagram passed, either way.
    last: Instant,
    /// When it was last seen active by the table's ranks ([`UdpTable::recent`]), which order it by that.
    seen: Instant,
    /// Wakes the mapping's task when the mapping is ended from elsewhere.
    ended: Arc<Notify>,
    /// Its place in the budget for its app (ADR 0044, decision 3), given back as it ends.
    _place: Place,
    /// Through the tool, its associations of a stand-in's own (ADR 0044, unit 9b), by number.
    owns: BTreeMap<u64, Own>,
    /// How many of those are being opened now: they count against the caps already.
    owns_opening: usize,
    /// Through the tool, whether its own association is open: the tool may close it, as for idleness,
    /// while an association of a stand-in's own still carries a flow; the mapping then lives on, and the
    /// next datagram that needs its own association opens it anew (ADR 0044, unit 9b, fix round 1).
    main_open: bool,
    /// Hands its task the relay of its own association opened anew.
    reopened: mpsc::UnboundedSender<Relay>,
}

/// A relay of the tool's opened anew for a mapping's own association: its socket, and the request's
/// connection that keeps it.
type Relay = (Arc<UdpSocket>, TcpStream);

/// Through the tool, an association of one stand-in's own (ADR 0044, unit 9b): a `UDP ASSOCIATE`
/// opened for a stand-in whose first datagram would have shared a port another stand-in waits on where
/// the address alone could not tell their answers apart. Only that stand-in leaves by it, and only it and
/// the flows that come in through it take what comes back on it.
struct Own {
    socket: Arc<UdpSocket>,
    /// Where what comes back on it comes from.
    sources: Sources,
    /// Wakes its task when it is ended from elsewhere.
    ended: Arc<Notify>,
    /// Its place in the budget for its app (ADR 0044, decision 3): it holds a socket and a connection to
    /// the tool, as a mapping through the tool does; and its place under `Limits::udp_own_relays`, in its
    /// app's share of them (fix round 5), held while it opens and once it is open, given back when it
    /// goes.
    _places: (Place, Place),
}

/// A peer of a mapping: a flow in the log.
struct Peer {
    /// The flow's number, port and DNS use, for the QUIC Initial packets that may name it.
    opened: Opened,
    /// The app's port, from which it sends to the peer: Multicast DNS answers a query from its own port
    /// otherwise than one from another (RFC 6762 6.7).
    app_port: u16,
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
    /// since: its datagrams are not read for a QUIC name.
    came_in: bool,
    /// Whether it came in before the app sent to it: it counts under [`CAME_IN`], and Watch learns names
    /// from it only from an answer to a query the app sent it, even once the app answers it.
    came_in_first: bool,
    /// Whether it is a stand-in the app sent to that waits for its first answer from an address, or
    /// one bound beside another peer.
    standing: Standing,
    /// Through the tool, the association of a stand-in's own it leaves by, by number (ADR 0044, unit
    /// 9b): its own, or for a flow that came in through one, that one. None for the mapping's.
    via: Option<u64>,
    /// For a stand-in on a port other than 53 while it waits, or while it is bound beside another peer,
    /// what the app's datagrams to it asked an answer to carry ([`identifiers::of`]), each once, the
    /// latest last, at most [`ASKED`]: while it has one, only an answer that carries one of them is its
    /// own.
    ids: Vec<identifiers::Asked>,
    /// For a stand-in on port 53 while it waits, or a flow from a port 53 that came in first, the ID and
    /// question of each DNS query the app sent it, the latest last: only an answer to one of them binds
    /// the stand-in, or teaches Watch names from a flow the app did not start.
    asked: Vec<(u16, String)>,
    /// Through the tool, the fingerprints of the identifiers the app sent it, whatever it stands as, each
    /// once, the latest last, at most [`TOLD`] (ADR 0044, unit 9b, fix round 2).
    told: Vec<u64>,
    /// For a peer on port 53 the app sent to, the IDs of the DNS queries it sent that have no answer
    /// yet; none once the app sent it anything else, or more than [`ASKED`] wait at once, and for a
    /// peer that came in. A mapping of one such peer, with none waiting, is an answered lookup.
    lookups: Option<Vec<u16>>,
    /// How many errors from the path the app may still be told of for it: one for each datagram the
    /// app sent it that left, at most [`OWED_ERRORS`]. None for a peer that came in until the app sends
    /// to it.
    owed_errors: u8,
    /// What a router would quote of the app's last datagram to it that left, which an error passed on
    /// quotes as the app sent it.
    last_sent: Sent,
}

/// Where a stand-in stands with its answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// No stand-in that waits: a destination the app knows by its address, a flow that came in, or a
    /// stand-in bound to an address of its own, or answered by name.
    Settled,
    /// A stand-in the app sent to, waiting for its first answer from an address.
    Waiting,
    /// A stand-in bound by its identifier to an address another peer of its association had first,
    /// beside that peer (ADR 0044, unit 9b): what comes from there is its own only when it carries its
    /// identifiers, which it keeps for that.
    Beside,
}

/// Where a peer's datagrams go and where its answers come from.
#[derive(Clone)]
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
        let (mut opened, mut flow) = begin_udp(shared, app, address, uid);
        // A stand-in whose name gave way in the map keeps it in the log, as long as a peer of its app
        // stands for it: its datagrams still go to that name (seventh review of unit 9, finding 4).
        if flow.name.is_none()
            && let Some(name) = &way.name
        {
            flow.name = Some(name.clone());
            flow.named_by = NamedBy::Dns;
            (flow.dns, flow.resolver) = shared.dns_use(address, Some(name));
            opened.dns = flow.dns;
        }
        Self {
            opened,
            app_port: app.port(),
            id: opened.id,
            quic: (!came_in).then(|| (opened, Box::new(quic::Initial::new()))),
            bytes: shared.record(flow),
            last: now,
            made: now,
            came_in,
            came_in_first: came_in,
            standing: if !came_in && way.name.is_some() && way.from.is_none() {
                Standing::Waiting
            } else {
                Standing::Settled
            },
            way,
            asked: Vec::new(),
            ids: Vec::new(),
            told: Vec::new(),
            via: None,
            lookups: (!came_in && address.port() == 53).then(Vec::new),
            owed_errors: 0,
            last_sent: Sent::default(),
        }
    }

    /// It waits no more for a first answer from an address: bound to one, or answered by name. The
    /// queries and identifiers it kept for that go.
    fn answered(&mut self) {
        self.standing = Standing::Settled;
        self.ids = Vec::new();
        if !self.came_in_first {
            self.asked = Vec::new();
        }
    }

    /// Whether only an answer that carries one of its identifiers is its own (ADR 0044, unit 9b): on
    /// port 53 always, since unit 9, as only a DNS response to a query the app sent it is; elsewhere
    /// once the app's datagrams to it carried one. A stand-in that had one keeps that, also when a later
    /// datagram carries none: the answer to the one it sent still carries it, and a datagram without one
    /// is no reason to take an answer without one, a stranger's, as its first.
    fn strict(&self) -> bool {
        self.opened.port == 53 || !self.ids.is_empty()
    }

    /// Notes a datagram the app sends it to `port`: for a peer on port 53 the app sent to, the ID of a
    /// DNS query, which waits for its answer; for a stand-in on port 53 while it waits or is bound
    /// beside another peer, or a flow from a port 53 that came in first, its ID and question too; for a
    /// stand-in on another port while it waits or is bound beside another peer, what it asked an answer
    /// to carry. Through the tool, whatever it stands as, the fingerprint of each identifier it carries,
    /// kept in its association's `told` with the address the app knows it by (ADR 0044, unit 9b, fix
    /// rounds 2 and 5).
    fn sent(&mut self, port: u16, payload: &[u8], mut told: Option<(&mut Fingerprints, IpAddr)>) {
        let candidate = self.standing != Standing::Settled;
        if port != 53 {
            if !candidate && told.is_none() {
                return;
            }
            // A candidate reads them strictly, QUIC's opened, since they will tell its answers; a settled
            // peer only notes them, QUIC's from the headers, at no AEAD's cost (fix round 3).
            let ports = (self.app_port, port);
            let read = if candidate {
                identifiers::of(ports, payload)
            } else {
                identifiers::named(ports, payload)
            };
            for asked in read {
                if let Some((told, ip)) = told.as_mut() {
                    self.tell(identifiers::fingerprint(port, &asked), (told, *ip));
                    // A QUIC source ID that tells apart, alone: every packet of the server's carries
                    // it, so that the contest spares this peer's answers once it keeps no keys (fix
                    // round 6, review K's m2).
                    if let identifiers::Asked::Quic(ids) = &asked
                        && let Some(source) = ids.telling_source()
                    {
                        self.tell(identifiers::source_fingerprint(port, source), (told, *ip));
                    }
                }
                if candidate {
                    self.keep(asked);
                }
            }
            return;
        }
        if self.lookups.is_none() && !(candidate || self.came_in_first) && told.is_none() {
            return;
        }
        let query = dns::u16_at(payload, 0).zip(answers::question(payload));
        if let Some(waiting) = &mut self.lookups {
            match &query {
                Some((id, _)) if waiting.len() < ASKED => waiting.push(*id),
                _ => self.lookups = None,
            }
        }
        let Some((id, question)) = query else {
            return;
        };
        if let Some(told) = told {
            self.tell(identifiers::dns_fingerprint(port, id, &question.name), told);
        }
        if !(candidate || self.came_in_first) {
            return;
        }
        // One asked again is the latest asked (fix round 3).
        let query = (id, question.name);
        if let Some(at) = self.asked.iter().position(|asked| *asked == query) {
            self.asked.remove(at);
        } else if self.asked.len() == ASKED {
            self.asked.remove(0);
        }
        self.asked.push(query);
    }

    /// Keeps `asked` among its identifiers, the latest, at most [`ASKED`], of which at most [`QUIC_ASKED`]
    /// QUIC ones: the oldest of its kind gives way, a QUIC identifier keeping the server's keys it was
    /// answered with. One sent again, as a client sends a request or an Initial again until it is
    /// answered, moves to the latest place, keeping those keys (fix round 3: it stayed where it was first
    /// sent, and could give way while it was still being sent).
    fn keep(&mut self, asked: identifiers::Asked) {
        if let Some(at) = self.ids.iter().position(|kept| *kept == asked) {
            let kept = self.ids.remove(at);
            self.ids.push(kept);
            return;
        }
        let quic = matches!(asked, identifiers::Asked::Quic(_));
        let oldest = if quic
            && self
                .ids
                .iter()
                .filter(|kept| matches!(kept, identifiers::Asked::Quic(_)))
                .count()
                >= QUIC_ASKED
        {
            self.ids
                .iter()
                .position(|kept| matches!(kept, identifiers::Asked::Quic(_)))
        } else {
            (self.ids.len() == ASKED).then_some(0)
        };
        if let Some(oldest) = oldest {
            self.ids.remove(oldest);
        }
        self.ids.push(asked);
    }

    /// Notes that the app sent it, which the app knows at `ip`, the identifier of `fingerprint`, kept in
    /// its association's `told`: once, the latest, the least recently sent of [`TOLD`] giving way; one
    /// sent again moves to the latest place (fix round 3: it stayed where it was first sent, and was
    /// forgotten while the app was sending it again).
    fn tell(&mut self, fingerprint: u64, (told, ip): (&mut Fingerprints, IpAddr)) {
        if let Some(at) = self.told.iter().position(|&kept| kept == fingerprint) {
            self.told.remove(at);
            self.told.push(fingerprint);
            return;
        }
        if self.told.len() == TOLD {
            told.forget(self.told.remove(0), ip);
        }
        self.told.push(fingerprint);
        told.add(fingerprint, ip);
    }

    /// A datagram the app sent it left, of which a router would quote `sent`: one more error from the
    /// path may answer it. One that did not leave, its socket's buffer full, is never noted, so that no
    /// error passes for it (second review of unit 11b, minor 4).
    fn left(&mut self, sent: Option<Sent>) {
        self.owed_errors = self.owed_errors.saturating_add(1).min(OWED_ERRORS);
        if let Some(sent) = sent {
            self.last_sent = sent;
        }
    }

    /// Whether the app may be told of one more error from the path for it, which it then is, with what
    /// a router quotes of the app's last datagram to it: an error for a peer the app never sent to, as a
    /// forged one, or one more than the app sent it datagrams that left, is dropped (ADR 0044, unit
    /// 11b).
    fn takes_error(&mut self) -> Option<Sent> {
        let owed = self.owed_errors > 0;
        self.owed_errors = self.owed_errors.saturating_sub(1);
        owed.then_some(self.last_sent)
    }

    /// Notes an `answer` that came from it: a DNS response to a query that waits for one answers it.
    fn heard(&mut self, answer: &[u8]) {
        let (Some(waiting), Some(flags), Some(id)) = (
            self.lookups.as_mut(),
            dns::u16_at(answer, 2),
            dns::u16_at(answer, 0),
        ) else {
            return;
        };
        if flags & 0x8000 != 0
            && let Some(at) = waiting.iter().position(|&asked| asked == id)
        {
            waiting.remove(at);
        }
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
    /// Each address answers come from, with the addresses the app knows its peers by.
    addresses: HashMap<IpAddr, Known>,
    /// The peers whose answers come from another address than the one the app knows them by (through
    /// the tool, a stand-in bound to the address the tool reached), by the address they come from.
    aliases: HashMap<SocketAddr, SocketAddr>,
    /// The stand-ins still waiting for their first answer, by the port the app asked, in the order they
    /// came.
    waiting: HashMap<u16, Ordered<SocketAddr>>,
    /// The names behind the mapping's stand-ins (lower case, without a final dot), each with the stand-in
    /// addresses the app knows it by, the newest last, and how many peers have each: a name that gave way
    /// in the stand-in map and was asked again has a second (ADR 0044, unit 9b, fix round 4).
    names: HashMap<String, Vec<(IpAddr, usize)>>,
    /// The stand-ins bound by their identifiers to an address another peer had first, by that address,
    /// in the order they were bound ([`Standing::Beside`]).
    beside: HashMap<SocketAddr, Ordered<SocketAddr>>,
    /// Every stand-in bound beside another, by an address or by a relay's name, by its port: those an
    /// answer under a name on that port may be for (ADR 0044, unit 9b, fix round 1).
    beside_on: HashMap<u16, Ordered<SocketAddr>>,
    /// The stand-ins bound beside another under a relay's name, by the name and the port, the source an
    /// answer under that name on that port came from, in the order they were bound (ADR 0044, unit 9b,
    /// fix rounds 2 to 4): as [`Sources::beside`] by an address.
    named_beside: HashMap<(String, u16), Ordered<SocketAddr>>,
    /// The same, the name and port each such stand-in is beside under (fix round 6, review K: its end
    /// walked every name's).
    named_of: HashMap<SocketAddr, (String, u16)>,
    /// The identifiers the app sent the peers of the association, by fingerprint, each with how many
    /// peers it was sent to and, where one was, which ([`TOLD`]).
    told: Fingerprints,
    /// Where the next answer that cannot open a packet for each stand-in waiting on its port begins
    /// ([`Scope::carried`]): it moves on by those it opened for, so that each is tried in turn.
    turn: Cell<usize>,
}

/// The identifiers the app sent the peers of one association through the tool (ADR 0044, unit 9b, fix
/// round 2), by their fingerprints ([`identifiers::fingerprint`], which holds the port), each with the
/// peers that keep it among those they were sent ([`TOLD`]).
#[derive(Default)]
struct Fingerprints(HashMap<u64, Keepers>);

/// The peers of an association that keep one fingerprint: how many, and the exclusive-or of the
/// addresses the app knows them by, each as an IPv6 address, an IPv4 one mapped (fix round 5). Where one
/// keeps it, that is its address, found without a walk of the mapping's peers, which an answer under a
/// relay's name made under the table's lock (review I's I4: 152 us with 4,000 peers on the port); where
/// several do, it tells nothing, and nothing needs it.
#[derive(Default)]
struct Keepers {
    peers: u32,
    addresses: [u8; 16],
}

impl Keepers {
    /// Adds the peer at `ip` to the exclusive-or, or takes it out: the same either way.
    fn toggle(&mut self, ip: IpAddr) {
        let octets = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        for (kept, byte) in self.addresses.iter_mut().zip(octets) {
            *kept ^= byte;
        }
    }
}

impl Fingerprints {
    /// The peer the app knows at `ip` keeps `fingerprint`.
    fn add(&mut self, fingerprint: u64, ip: IpAddr) {
        let keepers = self.0.entry(fingerprint).or_default();
        keepers.peers += 1;
        keepers.toggle(ip);
    }

    /// The peer the app knows at `ip` keeps `fingerprint` no more.
    fn forget(&mut self, fingerprint: u64, ip: IpAddr) {
        if let Some(keepers) = self.0.get_mut(&fingerprint) {
            keepers.peers = keepers.peers.saturating_sub(1);
            keepers.toggle(ip);
            if keepers.peers == 0 {
                self.0.remove(&fingerprint);
            }
        }
    }

    /// How many peers were sent the identifier of `fingerprint`.
    fn count(&self, fingerprint: u64) -> u32 {
        self.0.get(&fingerprint).map_or(0, |keepers| keepers.peers)
    }

    /// Where one peer alone keeps `fingerprint`, the address the app knows it by on `port`, the port the
    /// fingerprint holds. An address the app knows as an IPv4-mapped IPv6 one comes back as IPv4, which no
    /// peer has: the caller finds no one, as for several.
    fn one(&self, fingerprint: u64, port: u16) -> Option<SocketAddr> {
        let keepers = self.0.get(&fingerprint)?;
        (keepers.peers == 1)
            .then(|| SocketAddr::new(Ipv6Addr::from(keepers.addresses).to_canonical(), port))
    }
}

/// An address answers come from.
#[derive(Default)]
struct Known {
    /// The addresses the app knows the peers whose answers come from it by, itself or stand-ins the tool
    /// resolved to it, each with how many peers have it (fix round 5, review I's I7: one address, the
    /// first peer's, stood for it after that peer ended).
    peers: HashMap<IpAddr, usize>,
    /// The same, in the order they came (fix round 6, review K: walked for each, 16,384 stand-ins bound
    /// to one address took 0.18 s to end under the table's lock).
    order: Ordered<IpAddr>,
}

impl Known {
    /// One more peer the app knows at `ip` has its answers come from it.
    fn add(&mut self, ip: IpAddr) {
        *self.peers.entry(ip).or_default() += 1;
        self.order.push(ip);
    }

    /// One peer the app knows at `ip` has its answers come from it no more; whether none does now.
    fn remove(&mut self, ip: IpAddr) -> bool {
        if let Some(peers) = self.peers.get_mut(&ip) {
            *peers = peers.saturating_sub(1);
            if *peers == 0 {
                self.peers.remove(&ip);
                self.order.remove(&ip);
            }
        }
        self.peers.is_empty()
    }

    /// The address the app knows `address`, this one, by: itself while the app knows a peer by it, as
    /// one it sent to itself, before a stand-in the tool resolved to it; else the stand-in of the
    /// oldest of its peers that lives, the one an address handed over to is among them.
    fn shown_as(&self, address: IpAddr) -> Option<IpAddr> {
        if self.peers.contains_key(&address) {
            return Some(address);
        }
        self.order.first()
    }
}

/// Members in the order they came, each once: pushed, taken out, found, and the first read, each without
/// a walk, so that ending many costs no more than making them (ADR 0044, unit 9b, fix round 6, review K:
/// as vectors walked for each removal, 16,384 stand-ins beside one label took half a second to end under
/// the table's lock).
struct Ordered<T> {
    order: BTreeMap<u64, T>,
    at: HashMap<T, u64>,
    next: u64,
}

impl<T> Default for Ordered<T> {
    fn default() -> Self {
        Self {
            order: BTreeMap::new(),
            at: HashMap::new(),
            next: 0,
        }
    }
}

impl<T: Copy + Eq + std::hash::Hash> Ordered<T> {
    /// Adds `member` last, unless it is in already.
    fn push(&mut self, member: T) {
        if self.at.contains_key(&member) {
            return;
        }
        self.order.insert(self.next, member);
        self.at.insert(member, self.next);
        self.next += 1;
    }

    /// Takes `member` out; whether it was in.
    fn remove(&mut self, member: &T) -> bool {
        let Some(at) = self.at.remove(member) else {
            return false;
        };
        self.order.remove(&at);
        true
    }

    /// Takes out the first, and gives it.
    fn pop_first(&mut self) -> Option<T> {
        let (_, member) = self.order.pop_first()?;
        self.at.remove(&member);
        Some(member)
    }

    fn first(&self) -> Option<T> {
        self.order.values().next().copied()
    }

    fn contains(&self, member: &T) -> bool {
        self.at.contains_key(member)
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.order.values()
    }

    fn len(&self) -> usize {
        self.at.len()
    }

    fn is_empty(&self) -> bool {
        self.at.is_empty()
    }
}

impl<'a, T> IntoIterator for &'a Ordered<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_map::Values<'a, u64, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.order.values()
    }
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
            let addresses = self.names.entry(name_key(name)).or_default();
            match addresses.iter_mut().find(|(ip, _)| *ip == shown.ip()) {
                Some((_, peers)) => *peers += 1,
                None => addresses.push((shown.ip(), 1)),
            }
            if way.from.is_none() && !came_in {
                self.waiting.entry(shown.port()).or_default().push(shown);
            }
        }
    }

    /// The peer the app knows as `shown`, which left by `way` and was sent the identifiers of `told`, is
    /// gone. When it held its address first and a stand-in was bound beside it there, that stand-in now
    /// holds it alone: it is returned, so that it may let go of its identifiers. A name goes with the last
    /// peer that has it; the stand-ins bound beside them under it stay so, and take what comes under it
    /// while no peer has it (`Scope::relayed_answer`, fix round 3).
    fn remove_peer(
        &mut self,
        shown: SocketAddr,
        way: &PeerWay,
        told: &[u64],
    ) -> Option<SocketAddr> {
        self.leave_beside_on(shown);
        for &fingerprint in told {
            self.told.forget(fingerprint, shown.ip());
        }
        let alone = way.from.and_then(|from| self.remove(shown, from));
        if let Some(name) = &way.name {
            let key = name_key(name);
            if let Some(addresses) = self.names.get_mut(&key) {
                for (ip, peers) in addresses.iter_mut() {
                    if *ip == shown.ip() {
                        *peers = peers.saturating_sub(1);
                    }
                }
                addresses.retain(|&(_, peers)| peers > 0);
                if addresses.is_empty() {
                    self.names.remove(&key);
                }
            }
            if way.from.is_none() {
                self.stop_waiting(shown);
            }
        }
        alone
    }

    /// The answers of the peer the app knows as `shown` come from `from`.
    fn add(&mut self, shown: SocketAddr, from: SocketAddr) {
        self.addresses.entry(from.ip()).or_default().add(shown.ip());
        if from != shown {
            self.aliases.insert(from, shown);
        }
    }

    /// The peer the app knows as `shown`, whose answers came from `from`, is gone: its address is let in
    /// no more, unless another peer has the same one. When it held `from` first, the first stand-in bound
    /// beside it there holds it now, and is returned.
    fn remove(&mut self, shown: SocketAddr, from: SocketAddr) -> Option<SocketAddr> {
        self.unknown(shown, from);
        let beside = self.beside.get_mut(&from);
        if let Some(beside) = beside {
            if beside.remove(&shown) {
                if beside.is_empty() {
                    self.beside.remove(&from);
                }
                return None;
            }
            let next = beside.pop_first();
            if beside.is_empty() {
                self.beside.remove(&from);
            }
            if let Some(next) = next {
                self.aliases.insert(from, next);
                self.leave_beside_on(next);
                return Some(next);
            }
        }
        if from != shown {
            self.aliases.remove(&from);
        }
        None
    }

    /// The stand-in the app knows as `shown` is bound by its identifiers to `from`, which another peer
    /// held first: what comes from there is let in still, and the stand-in is among those it may be for.
    fn add_beside(&mut self, shown: SocketAddr, from: SocketAddr) {
        if let Some(known) = self.addresses.get_mut(&from.ip()) {
            known.add(shown.ip());
        }
        self.beside.entry(from).or_default().push(shown);
        self.beside_on.entry(shown.port()).or_default().push(shown);
    }

    /// The stand-in the app knows as `shown` is bound beside another under a relay's name, of `key`, on
    /// its port: the source an answer under that name there comes from.
    fn add_named_beside(&mut self, shown: SocketAddr, key: &str) {
        self.beside_on.entry(shown.port()).or_default().push(shown);
        let label = (key.to_owned(), shown.port());
        self.named_beside
            .entry(label.clone())
            .or_default()
            .push(shown);
        self.named_of.insert(shown, label);
    }

    /// The stand-in the app knows as `shown` is bound beside another no more, as when its relay names
    /// its answers: it leaves the address `from` it was bound to beside the other, if any, which then
    /// lets it in for the others only.
    fn unbind_beside(&mut self, shown: SocketAddr, from: Option<SocketAddr>) {
        self.leave_beside_on(shown);
        let Some(from) = from else {
            return;
        };
        let Some(beside) = self.beside.get_mut(&from) else {
            return;
        };
        if !beside.remove(&shown) {
            return;
        }
        if beside.is_empty() {
            self.beside.remove(&from);
        }
        self.unknown(shown, from);
    }

    /// The answers of the peer the app knows as `shown` come from `from` no more: the address is let
    /// in no more once none of its peers' do.
    fn unknown(&mut self, shown: SocketAddr, from: SocketAddr) {
        let ip = from.ip();
        if self
            .addresses
            .get_mut(&ip)
            .is_some_and(|known| known.remove(shown.ip()))
        {
            self.addresses.remove(&ip);
        }
    }

    /// The stand-in the app knows as `shown` is beside no other on its port any more, by an address or
    /// under a name.
    fn leave_beside_on(&mut self, shown: SocketAddr) {
        if let Some(beside) = self.beside_on.get_mut(&shown.port()) {
            beside.remove(&shown);
            if beside.is_empty() {
                self.beside_on.remove(&shown.port());
            }
        }
        let Some(label) = self.named_of.remove(&shown) else {
            return;
        };
        if let Some(beside) = self.named_beside.get_mut(&label) {
            beside.remove(&shown);
            if beside.is_empty() {
                self.named_beside.remove(&label);
            }
        }
    }

    /// The stand-in the app knows as `shown` waits no more.
    fn stop_waiting(&mut self, shown: SocketAddr) {
        if let Some(waiting) = self.waiting.get_mut(&shown.port()) {
            waiting.remove(&shown);
            if waiting.is_empty() {
                self.waiting.remove(&shown.port());
            }
        }
    }

    /// The address the app knows `ip` by, if what comes from it is let in.
    fn shown(&self, ip: IpAddr) -> Option<IpAddr> {
        self.addresses.get(&ip).and_then(|known| known.shown_as(ip))
    }

    /// The way of a peer that came in from `from` through the tool, which the app knows as `shown`.
    /// Shown as a stand-in, it is that name's other port: the app's datagrams to it go to the tool by the
    /// name, as the stand-in's own do, so that the tool's routing by name still applies.
    fn way_from(&self, shown: SocketAddr, from: SocketAddr) -> PeerWay {
        let name = (shown.ip() != from.ip())
            .then(|| {
                self.names
                    .iter()
                    .find(|(_, addresses)| addresses.iter().any(|&(ip, _)| ip == shown.ip()))
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
    /// What its own association lets in: through the tool, the `UDP ASSOCIATE` it opened first; on the
    /// direct path, its socket.
    fn main(&mut self) -> Scope<'_> {
        let Self {
            peers,
            sources,
            came_in,
            last,
            uid,
            ..
        } = self;
        Scope {
            via: None,
            peers,
            sources,
            came_in,
            last,
            uid: *uid,
        }
    }

    /// What its association `via` lets in: its own, or one of a stand-in's own, if it still has it.
    fn scope(&mut self, via: Option<u64>) -> Option<Scope<'_>> {
        let Some(own) = via else {
            return Some(self.main());
        };
        let Self {
            peers,
            owns,
            came_in,
            last,
            uid,
            ..
        } = self;
        Some(Scope {
            via,
            peers,
            sources: &mut owns.get_mut(&own)?.sources,
            came_in,
            last,
            uid: *uid,
        })
    }

    /// The peer the app knows as `address`, made with `way` if it is new, on the mapping's own
    /// association; the mapping and the peer are refreshed. The engine makes its peers through their
    /// association ([`Scope::into_peer`]); the tests make them here.
    #[cfg(test)]
    fn peer(
        &mut self,
        shared: &Shared,
        (app, address): (SocketAddr, SocketAddr),
        now: Instant,
        (came_in, way): (bool, PeerWay),
    ) -> &mut Peer {
        self.main()
            .into_peer(shared, (app, address), now, (came_in, way))
    }

    /// Ends the flows of the peers silent since `since`; their addresses are let in no more, unless
    /// another peer has the same one. A stand-in bound beside one that ends holds its address, or its
    /// name, alone from then on, and lets go of its identifiers. An association of a stand-in's own ends
    /// with the last flow that leaves by it, its stand-in's or one that came in through it (ADR 0044,
    /// unit 9b, fix round 2): a flow that came in may outlive its stand-in there as on the mapping's own
    /// association.
    fn sweep(&mut self, since: Instant, shared: &Shared) {
        let Self {
            peers,
            sources,
            owns,
            came_in,
            ..
        } = self;
        let mut alone = Vec::new();
        peers.retain(|&address, peer| {
            if peer.last > since {
                return true;
            }
            shared.finish(peer.id);
            let sources = match peer.via {
                None => Some(&mut *sources),
                Some(own) => owns.get_mut(&own).map(|own| &mut own.sources),
            };
            if let Some(sources) = sources {
                alone.extend(sources.remove_peer(address, &peer.way, &peer.told));
            }
            *came_in = came_in.saturating_sub(usize::from(peer.came_in_first));
            false
        });
        for shown in alone {
            if let Some(peer) = peers.get_mut(&shown) {
                peer.answered();
            }
        }
        if owns.is_empty() {
            return;
        }
        let used: HashSet<u64> = peers.values().filter_map(|peer| peer.via).collect();
        let orphans: Vec<u64> = owns
            .keys()
            .filter(|own| !used.contains(own))
            .copied()
            .collect();
        for own in orphans {
            self.end_own(own, shared);
        }
    }

    /// Notes a datagram the app sends the peer it knows as `destination` ([`Peer::sent`]), with, through
    /// the tool, the count of identifiers of the association it leaves by.
    fn sent(&mut self, destination: SocketAddr, payload: &[u8]) {
        let Self {
            peers,
            sources,
            owns,
            ..
        } = self;
        let Some(peer) = peers.get_mut(&destination) else {
            return;
        };
        let told = match (&peer.way.header, peer.via) {
            (None, _) => None,
            (Some(_), None) => Some(&mut sources.told),
            (Some(_), Some(own)) => owns.get_mut(&own).map(|own| &mut own.sources.told),
        };
        peer.sent(
            destination.port(),
            payload,
            told.map(|told| (told, destination.ip())),
        );
    }

    /// The tool closed its own association (ADR 0044, unit 9b, fix round 1): the flows that left by it
    /// end, and where answers come back on it is forgotten, while those that leave by an association of
    /// a stand-in's own go on.
    fn end_main(&mut self, shared: &Shared) {
        self.main_open = false;
        self.sources = Sources::default();
        let came_in = &mut self.came_in;
        self.peers.retain(|_, peer| {
            if peer.via.is_some() {
                return true;
            }
            shared.finish(peer.id);
            *came_in = came_in.saturating_sub(usize::from(peer.came_in_first));
            false
        });
    }

    /// Ends its association of a stand-in's own `own` (ADR 0044, unit 9b), with the flows of every peer
    /// that leaves by it: its stand-in's, and those that came in through it. Its place in the budget is
    /// given back at once, and its task woken to close its socket and its request's connection.
    fn end_own(&mut self, own: u64, shared: &Shared) {
        let Some(ended) = self.owns.remove(&own) else {
            return;
        };
        ended.ended.notify_one();
        let came_in = &mut self.came_in;
        self.peers.retain(|_, peer| {
            if peer.via != Some(own) {
                return true;
            }
            shared.finish(peer.id);
            *came_in = came_in.saturating_sub(usize::from(peer.came_in_first));
            false
        });
    }

    /// How many associations of a stand-in's own it holds, and opens now.
    fn owns(&self) -> usize {
        self.owns.len() + self.owns_opening
    }

    /// Whether the app sent to the peer it knows as `address`: a destination of its own, which may
    /// share a question to Android, or leave without one while the mapping is fresh. A port that came in
    /// and that the app has not answered is no such destination: the app that held the socket when it
    /// came in may be gone, and the first datagram to it asks Android as a new destination's does.
    fn knows(&self, address: SocketAddr) -> bool {
        self.peers.get(&address).is_some_and(|peer| !peer.came_in)
    }

    /// Whether it is an answered lookup, as an app's own resolver leaves one for each query: one peer, on
    /// port 53, to which the app sent DNS queries only, each with its answer. It carries nothing more,
    /// and is the first to end to make room (ADR 0044, decision 3).
    fn answered_lookup(&self) -> bool {
        // An association of a stand-in's own, open or opening, is more than a lookup (fix round 4,
        // review G's G3: an answer while one opened made it an answered lookup again).
        self.owns() == 0
            && self.peers.len() == 1
            && self
                .peers
                .values()
                .all(|peer| peer.lookups.as_ref().is_some_and(Vec::is_empty))
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
    /// on, read for a QUIC name. It still counts under [`CAME_IN`].
    fn answering(&mut self, address: SocketAddr) {
        let Some(peer) = self.peers.get_mut(&address) else {
            return;
        };
        if std::mem::take(&mut peer.came_in) {
            peer.quic = Some((peer.opened, Box::new(quic::Initial::new())));
        }
    }
}

/// What one association of a mapping lets in (ADR 0044, unit 9b): the mapping's peers, and where the
/// answers that come back on that association come from. Through the tool, the mapping's own `UDP
/// ASSOCIATE` and each association of a stand-in's own have their own, so that an answer that comes on
/// one is never taken by a peer that leaves by another; on the direct path there is only the mapping's.
struct Scope<'a> {
    /// The association: a stand-in's own, by its number, or none for the mapping's.
    via: Option<u64>,
    peers: &'a mut HashMap<SocketAddr, Peer>,
    sources: &'a mut Sources,
    /// How many of the mapping's peers came in ([`CAME_IN`]), whichever association they came by.
    came_in: &'a mut usize,
    /// When the last datagram passed the mapping, either way.
    last: &'a mut Instant,
    uid: Option<u32>,
}

impl<'a> Scope<'a> {
    /// The same association, borrowed again.
    fn reborrow(&mut self) -> Scope<'_> {
        Scope {
            via: self.via,
            peers: self.peers,
            sources: self.sources,
            came_in: self.came_in,
            last: self.last,
            uid: self.uid,
        }
    }

    /// The peer the app knows as `address`, made with `way` on this association if it is new; the
    /// mapping and the peer are refreshed.
    fn into_peer(
        self,
        shared: &Shared,
        (app, address): (SocketAddr, SocketAddr),
        now: Instant,
        (came_in, way): (bool, PeerWay),
    ) -> &'a mut Peer {
        *self.last = now;
        let Self {
            via,
            peers,
            sources,
            uid,
            came_in: count,
            ..
        } = self;
        let peer = peers.entry(address).or_insert_with(|| {
            sources.add_peer(address, &way, came_in);
            *count += usize::from(came_in);
            let mut peer = Peer::new(shared, app, address, uid, now, (came_in, way));
            peer.via = via;
            peer
        });
        peer.last = now;
        peer
    }

    /// A new peer that came in, which the app knows as `shown`: dropped beyond [`CAME_IN`], or when the
    /// app already knows another peer by that address. Its way is made only then, so that a sender
    /// spraying ports beyond the cap costs no search of the mapping's names (ninth review of unit 9,
    /// finding 6).
    fn come_in(
        &mut self,
        shared: &Shared,
        (app, shown): (SocketAddr, SocketAddr),
        now: Instant,
        way: impl FnOnce(&Sources) -> PeerWay,
    ) -> LetIn {
        if self.peers.contains_key(&shown) {
            return LetIn::Unmatched;
        }
        if *self.came_in >= CAME_IN {
            return LetIn::Capped;
        }
        let way = way(self.sources);
        // A flow the app did not start, logged as any other: the log's flag for a flow that came in
        // waits for its new record format (ADR 0044, decision 4).
        let peer = self
            .reborrow()
            .into_peer(shared, (app, shown), now, (true, way));
        LetIn::Peer(shown, peer.bytes.clone(), false)
    }

    /// The peer the app knows as `shown`, refreshed by `answer`. Watch learns names only from a peer the
    /// app sent to, or from an answer to a query the app sent one that came in.
    fn answered_by(&mut self, shown: SocketAddr, answer: &[u8], now: Instant) -> LetIn {
        let Some(peer) = self.peers.get_mut(&shown) else {
            return LetIn::Unmatched;
        };
        peer.last = now;
        peer.heard(answer);
        *self.last = now;
        let learns = !peer.came_in_first || peer.asked_for(answer);
        LetIn::Peer(shown, peer.bytes.clone(), learns)
    }

    /// Which peer an answer from the tool's relay is for, by the address or the name its header gives
    /// (ADR 0044, decision 2), with the direct path's filtering: from a peer, to that peer; from another
    /// port of an address the app sent to, to a new peer; from an address the app never saw, to the
    /// stand-in it may be the first answer of; from anywhere else, nowhere. Where the address alone
    /// cannot tell, the identifier the answer carries does (unit 9b).
    fn relayed_answer(
        &mut self,
        shared: &Shared,
        app: SocketAddr,
        (target, answer): (&Target, &[u8]),
        now: Instant,
    ) -> LetIn {
        // Read once, whatever stand-ins it is checked for (unit 9b, fix round 1).
        let read = identifiers::Reading::new(answer);
        let (shown, from) = match target {
            Target::Address(address) => {
                // An IPv4 address the relay gives as IPv6 is still the address the app sent to.
                let from = SocketAddr::new(address.ip().to_canonical(), address.port());
                // A destination's own address first, then the one a stand-in was bound to: such an
                // answer is theirs, unless it carries the identifier of a stand-in that waits on its
                // port, or was bound beside them there, which then takes it (unit 9b). Such an answer
                // never binds a stand-in without identifiers.
                if self
                    .peers
                    .get(&from)
                    .is_some_and(|peer| peer.way.from == Some(from) && peer.via == self.via)
                {
                    return self.beside_or(shared, (from, from), (answer, &read), (now, false));
                }
                if let Some(&owner) = self.sources.aliases.get(&from) {
                    return self.beside_or(shared, (owner, from), (answer, &read), (now, true));
                }
                let Some(ip) = self.sources.shown(from.ip()) else {
                    return self.first_answer(shared, from, (answer, &read), now);
                };
                // Another port of an address the app sent to: a stand-in waiting on this port whose
                // name the tool resolved to this address takes it by its identifier (unit 9b); else
                // it comes in as that address's, never as a stand-in's first answer. Of an address
                // only a stand-in was bound to, on a port a stand-in waits on: when that is the same
                // stand-in, the name the tool resolved to this address asked on another port, the
                // answer binds it there too; while another name's without identifiers still contests
                // the port, the answer could again be either name's.
                let strict = self.waiting_on(from.port(), true);
                match self.carried(&strict, &read, Others::None) {
                    Carried::One(shown) => {
                        Counters::add(&shared.counters.udp_identified, 1);
                        return self.bind(shown, (from, answer), now);
                    }
                    Carried::Several => return LetIn::Unmatched,
                    Carried::None => {}
                }
                if ip != from.ip() {
                    let same = SocketAddr::new(ip, from.port());
                    if self.contested(from.port(), Some(same), (now, shared.limits.udp_contest)) {
                        return LetIn::Unmatched;
                    }
                    let waits = self
                        .sources
                        .waiting
                        .get(&from.port())
                        .is_some_and(|waiting| waiting.contains(&same));
                    if waits {
                        // With identifiers, it waits for an answer that carries one, which this
                        // does not; on port 53, for a response to its query.
                        if self.peers.get(&same).is_some_and(Peer::strict) {
                            return LetIn::Unidentified;
                        }
                        return self.bind(same, (from, answer), now);
                    }
                }
                (SocketAddr::new(ip, from.port()), Some(from))
            }
            // A relay that gives back the name it was asked for answers for that name's stand-in;
            // another port of the name is another port of the stand-in.
            Target::Name(name, port) => {
                match self.by_name(shared, (name, *port), (answer, &read), now) {
                    UnderName::Done(let_in) => return let_in,
                    UnderName::ComeIn(shown) => (shown, None),
                }
            }
        };
        self.come_in(shared, (app, shown), now, |sources| match from {
            Some(from) => sources.way_from(shown, from),
            None => PeerWay::through_tool(target.clone()),
        })
    }

    /// Which peer an answer from the tool's relay under `name` on `port` is for (ADR 0044, decision 2,
    /// unit 9b, fix rounds 4 and 5). The relays read for this unit put a name on an answer to say that it
    /// came from the address the association's first destination, that name, resolved to, at the
    /// answer's own port: a label is a source, as an address and port are, whose address Watch does not
    /// know. So it is resolved by the rules an answer from an address is, with the label in place of the
    /// address:
    /// - its holder is the name's own peer on that port, as a destination holds its own address
    ///   (`Scope::relayed_answer`'s first rule); while none lives, the stand-in first bound beside it under
    ///   the name there, as the first bound beside an address holds it once its holder ends;
    /// - an answer carrying the identifier of a stand-in that waits on the port takes it, bound beside
    ///   under the label, and so does one bound beside, as from an address; one carrying the holder's own
    ///   is the holder's;
    /// - what carries none is the holder's, but for `Limits::udp_contest` after a stand-in without
    ///   identifiers began to wait on the port, as for an address a stand-in was bound to: the holder is a
    ///   stand-in, the name's own peer too; what is addressed to its client's QUIC source ID is the
    ///   holder's all the same, as by an address (fix round 6);
    /// - with no holder, another port of a name the app sent to comes in as that name's stand-in's, its
    ///   newest live address, as another port of a known address does, under the same contest; and a name
    ///   no peer has is a source the app never saw, or no longer sees: a stand-in with identifiers takes
    ///   an answer that carries one, as from an address the app never saw ([`Scope::first_answer`]).
    ///
    /// Where it differs from an address, and why:
    /// - the address behind a label is unknown, so any peer of the association may be at it: an answer
    ///   that names in the clear what the app sent (a STUN, DNS or NTP identifier,
    ///   [`identifiers::Reading::answers`]) is the holder's if the holder was sent it, else the one peer's
    ///   of the association that was, and no one's where several were (fix round 3, review E's minor 2;
    ///   round 4, review G's G4); and what only an opened packet tells (QUIC's) is looked for among every
    ///   stand-in bound beside on the port, by an address or under any name, not those under the label
    ///   alone;
    /// - a stand-in bound beside under a label stays beside, keeping its identifiers, never taking the
    ///   name, which is its own peer's again when the app asks it again (review E's major 1), where the
    ///   first bound beside an address takes it once its holder ends;
    /// - a name may have several stand-in addresses, one from before it gave way in the stand-in map and
    ///   one since: the newest that has a peer on the port holds the label, the one the app uses now;
    /// - the name's own stand-in, waiting with identifiers, takes an answer under its own name without
    ///   them, where from an address the app never saw it would take none: the relay names the address
    ///   the name resolved to, which a stranger who reaches the relay's port from elsewhere is not;
    /// - a name no peer has binds no lone stand-in without identifiers, where an address the app never
    ///   saw binds one by its first answer, unit 9's floor: a name nobody asked for is dropped (unit 9's
    ///   M21), and one whose peers ended cannot be told from it.
    fn by_name(
        &mut self,
        shared: &Shared,
        (name, port): (&str, u16),
        (answer, read): (&[u8], &identifiers::Reading),
        now: Instant,
    ) -> UnderName {
        let key = name_key(name);
        let own = self.own_peer(&key, port);
        let beside = self.named_beside(&key, port);
        let holder = own.or_else(|| beside.first().copied());
        if let Some(fingerprint) = read.answers(port)
            && self.sources.told.count(fingerprint) > 0
        {
            // The holder first, however many others were sent it too (fix round 5, review I's I1: of
            // three or more, the two found first stood for all); else the one peer that was, by the
            // association's count, without a walk of the peers (I4).
            let sent = |shown: &SocketAddr| self.was_sent(*shown, fingerprint);
            let taker = holder
                .filter(sent)
                .or_else(|| self.sources.told.one(fingerprint, port).filter(sent));
            return UnderName::Done(match taker {
                Some(taker) => {
                    if Some(taker) != holder {
                        Counters::add(&shared.counters.udp_identified, 1);
                    }
                    self.label_taken(taker, &key, answer, now)
                }
                None => LetIn::Unmatched,
            });
        }
        // What only an opened packet tells (QUIC's identifiers), among the stand-ins that wait on the
        // port and those bound beside on it.
        let mut candidates = self.waiting_on(port, true);
        candidates.extend(
            self.sources
                .beside_on
                .get(&port)
                .into_iter()
                .flatten()
                .copied(),
        );
        match self.carried(&candidates, read, Others::All) {
            Carried::One(other) if Some(other) != holder => {
                Counters::add(&shared.counters.udp_identified, 1);
                return UnderName::Done(self.label_taken(other, &key, answer, now));
            }
            // The holder's own identifier: a stand-in without identifiers cannot have asked it, and
            // contests nothing of it (fix round 5, review I's I3).
            Carried::One(holder) => {
                return UnderName::Done(self.label_taken(holder, &key, answer, now));
            }
            Carried::Several => return UnderName::Done(LetIn::Unmatched),
            Carried::None => {}
        }
        // What carries no identifier is the holder's, but for `udp_contest` after a stand-in without
        // identifiers began to wait on the port: the tool may have resolved its name to the label's
        // address too, as for an address a stand-in was bound to. So also where the name's own peer
        // holds it, which is a stand-in too (fix round 5, review I's I2: it took the answer at once).
        if let Some(holder) = holder {
            if self.contested(port, Some(holder), (now, shared.limits.udp_contest))
                && !self.addressed_to(holder, read, port)
            {
                return UnderName::Done(LetIn::Unmatched);
            }
            return UnderName::Done(self.label_taken(holder, &key, answer, now));
        }
        if let Some(ip) = self.sources.names.get(&key).and_then(|ips| ips.last()) {
            if self.contested(port, None, (now, shared.limits.udp_contest)) {
                return UnderName::Done(LetIn::Unmatched);
            }
            return UnderName::ComeIn(SocketAddr::new(ip.0, port));
        }
        // A name no peer has: a source the app never saw, or no longer sees. Only an identifier binds a
        // stand-in to it (above): where an address the app never saw binds a lone stand-in without one
        // by its first answer, unit 9's floor, a name no peer has binds none, as a name nobody asked
        // for (the second review of unit 9, M21).
        let all = self.waiting_on(port, false);
        let strict = !all.is_empty()
            && all
                .iter()
                .all(|shown| self.peers.get(shown).is_some_and(Peer::strict));
        UnderName::Done(if strict {
            LetIn::Unidentified
        } else {
            LetIn::Filtered
        })
    }

    /// The peer the app knows as `shown` takes an answer under the name of `key` (`Scope::by_name`): the
    /// name's own peer as its own answer, a waiting one no longer waiting; another stand-in that waits is
    /// bound beside under the name; any other peer takes it as it stands.
    fn label_taken(&mut self, shown: SocketAddr, key: &str, answer: &[u8], now: Instant) -> LetIn {
        let Some(peer) = self.peers.get_mut(&shown) else {
            return LetIn::Unmatched;
        };
        let own = peer
            .way
            .name
            .as_deref()
            .is_some_and(|name| name_key(name) == key);
        if own {
            // The stand-in's own answer: it no longer waits for a first answer from an address,
            // which whoever reached the relay later from its port could otherwise send it. One
            // bound beside another by an address leaves that address to the other.
            if peer.standing == Standing::Beside {
                let from = peer.way.from.take();
                self.sources.unbind_beside(shown, from);
            }
            peer.answered();
            self.sources.stop_waiting(shown);
            return self.answered_by(shown, answer, now);
        }
        self.bind_beside_named(shown, key, answer, now)
    }

    /// The name's own peer on `port` on this association: of the stand-in addresses the name has, the
    /// newest that has a peer there.
    fn own_peer(&self, key: &str, port: u16) -> Option<SocketAddr> {
        self.sources
            .names
            .get(key)?
            .iter()
            .rev()
            .find_map(|&(ip, _)| {
                let shown = SocketAddr::new(ip, port);
                self.peers
                    .get(&shown)
                    .is_some_and(|peer| peer.via == self.via)
                    .then_some(shown)
            })
    }

    /// Whether `read`, an answer on `port`, is addressed to a QUIC source ID of the peer the app knows as
    /// `shown`, of 4 bytes or more ([`identifiers::Reading::addressed`]): its own, which a stand-in without
    /// identifiers cannot have asked (fix round 6, review K's m2: once settled, a stand-in keeps no keys,
    /// and the contest cut its QUIC answers). A client whose source ID is shorter, Chromium's and
    /// Cronet's empty one, is not told so.
    fn addressed_to(&self, shown: SocketAddr, read: &identifiers::Reading, port: u16) -> bool {
        self.peers.get(&shown).is_some_and(|peer| {
            !peer.told.is_empty()
                && read
                    .addressed(port)
                    .iter()
                    .any(|fingerprint| peer.told.contains(fingerprint))
        })
    }

    /// Whether the app sent the peer it knows as `shown` the identifier of `fingerprint`, among the last
    /// [`TOLD`] it sent it. Both peers it is asked of leave by this association: the holder, found on it,
    /// and the one this association's fingerprints name.
    fn was_sent(&self, shown: SocketAddr, fingerprint: u64) -> bool {
        self.peers
            .get(&shown)
            .is_some_and(|peer| peer.told.contains(&fingerprint))
    }

    /// The stand-ins of this association bound beside another under the name of `key`, on `port`, in
    /// the order they were bound.
    fn named_beside(&self, key: &str, port: u16) -> Vec<SocketAddr> {
        self.sources
            .named_beside
            .get(&(key.to_owned(), port))
            .into_iter()
            .flatten()
            .copied()
            .filter(|shown| {
                self.peers
                    .get(shown)
                    .is_some_and(|peer| peer.via == self.via)
            })
            .collect()
    }

    /// An answer from `from`, which the peer the app knows as `owner` holds (ADR 0044, unit 9b): the
    /// stand-in whose identifier it carries, among those that wait on its port and those bound beside
    /// `owner` there, takes it, a waiting one bound beside `owner` by it; else `owner` does. The tool may
    /// have resolved several names to one address and port: the identifier, not the address, tells
    /// their answers apart. An identifier the app also sent `owner`, or another stand-in bound beside it
    /// there, is no one's to take from them (fix round 2): the answer may be theirs, which the address
    /// says. A stand-in without identifiers that waits on the port could be answered from there too, by
    /// nothing that tells: for a stand-in's address (`contestable`), its answers are dropped for
    /// `Limits::udp_contest` after the app first asked it, as unit 9 has it.
    fn beside_or(
        &mut self,
        shared: &Shared,
        (owner, from): (SocketAddr, SocketAddr),
        (answer, read): (&[u8], &identifiers::Reading),
        (now, contestable): (Instant, bool),
    ) -> LetIn {
        let mut candidates = self.waiting_on(from.port(), true);
        candidates.extend(
            self.sources
                .beside
                .get(&from)
                .into_iter()
                .flatten()
                .copied(),
        );
        match self.carried(&candidates, read, Others::At(owner, from)) {
            Carried::One(shown) => {
                Counters::add(&shared.counters.udp_identified, 1);
                if self
                    .peers
                    .get(&shown)
                    .is_some_and(|peer| peer.standing == Standing::Waiting)
                {
                    return self.bind_beside(shown, (from, answer), now);
                }
                return self.answered_by(shown, answer, now);
            }
            Carried::Several => return LetIn::Unmatched,
            Carried::None => {}
        }
        // What names in the clear an identifier `owner` was sent is its own, which a stand-in without
        // identifiers cannot have asked: the contest spares it (fix round 5, review I's I3: a TURN
        // refresh's response was cut).
        if contestable
            && self.contested(from.port(), None, (now, shared.limits.udp_contest))
            && !read
                .answers(from.port())
                .is_some_and(|fingerprint| self.was_sent(owner, fingerprint))
            && !self.addressed_to(owner, read, from.port())
        {
            return LetIn::Unmatched;
        }
        self.answered_by(owner, answer, now)
    }

    /// The stand-ins that wait on `port` for their first answer; with `strict`, only those with
    /// identifiers ([`Peer::strict`]).
    fn waiting_on(&self, port: u16, strict: bool) -> Vec<SocketAddr> {
        self.sources
            .waiting
            .get(&port)
            .into_iter()
            .flatten()
            .copied()
            .filter(|shown| {
                self.peers
                    .get(shown)
                    .is_some_and(|peer| !strict || peer.strict())
            })
            .collect()
    }

    /// Which of `candidates` an answer, `read`, carries an identifier of (ADR 0044, unit 9b), not counting
    /// one the app sent the `others` too (fix round 2). What costs no QUIC packet opened is told first, for
    /// every candidate; the packets left to open, at most [`quic::MOST_OPENED`] for the answer, go to the
    /// candidates' QUIC identifiers round by round, the newest of each first, so that a candidate that asked
    /// once is tried however many identifiers the others keep (review D). Where more candidates wait than
    /// one round can open for, each answer begins the round where the last such one stopped, so that a
    /// server's Initial sent again is tried for the next.
    fn carried(
        &self,
        candidates: &[SocketAddr],
        read: &identifiers::Reading,
        others: Others,
    ) -> Carried {
        let counts =
            |shown: SocketAddr, fingerprint: u64| !self.told_others(&others, shown, fingerprint);
        let mut takers: Vec<SocketAddr> = Vec::new();
        // What only an opened packet tells, with its rank among its candidate's, the newest 0.
        let mut costly: Vec<(usize, SocketAddr, &identifiers::Asked)> = Vec::new();
        for &shown in candidates {
            let Some(peer) = self.peers.get(&shown) else {
                continue;
            };
            let port = shown.port();
            let carries = if port == 53 {
                read.dns_response().is_some_and(|(id, question)| {
                    peer.asked
                        .iter()
                        .any(|(asked, of)| *asked == id && of == question)
                        && counts(shown, identifiers::dns_fingerprint(port, id, question))
                })
            } else {
                let mut rank = 0;
                peer.ids.iter().rev().any(|asked| {
                    if let Some(told) = read.tells(asked) {
                        return told && counts(shown, identifiers::fingerprint(port, asked));
                    }
                    costly.push((rank, shown, asked));
                    rank += 1;
                    false
                })
            };
            if carries {
                takers.push(shown);
            }
        }
        if takers.len() < 2 && !costly.is_empty() {
            costly.sort_by_key(|&(rank, ..)| rank);
            let round = costly.iter().take_while(|&&(rank, ..)| rank == 0).count();
            let turn = self.sources.turn.get() % round.max(1);
            costly[..round].rotate_left(turn);
            let mut tried = 0;
            for &(rank, shown, asked) in &costly {
                if read.opens_left() == 0 || takers.len() > 1 {
                    break;
                }
                if takers.contains(&shown) {
                    continue;
                }
                tried += usize::from(rank == 0);
                if read.opens_for(asked)
                    && counts(shown, identifiers::fingerprint(shown.port(), asked))
                {
                    takers.push(shown);
                }
            }
            if tried < round {
                self.sources.turn.set(turn + tried);
            }
        }
        match takers.as_slice() {
            [] => Carried::None,
            [one] => Carried::One(*one),
            _ => Carried::Several,
        }
    }

    /// Whether the app sent the identifier of `fingerprint` to one of `others` besides the candidate the
    /// app knows as `shown`.
    fn told_others(&self, others: &Others, shown: SocketAddr, fingerprint: u64) -> bool {
        let told = |peer: &SocketAddr| {
            *peer != shown
                && self
                    .peers
                    .get(peer)
                    .is_some_and(|peer| peer.told.contains(&fingerprint))
        };
        match others {
            Others::None => false,
            Others::At(owner, from) => {
                told(owner)
                    || self
                        .sources
                        .beside
                        .get(from)
                        .is_some_and(|beside| beside.iter().any(told))
            }
            Others::All => {
                let own = self
                    .peers
                    .get(&shown)
                    .is_some_and(|peer| peer.told.contains(&fingerprint));
                self.sources.told.count(fingerprint) > u32::from(own)
            }
        }
    }

    /// Whether a stand-in other than `except`, without identifiers, waits on `port` and still contests
    /// the answers from an address another stand-in was bound to: for `contest` after the app first
    /// sent to it, `now`. One with identifiers contests nothing: what carries them is its own, and what
    /// does not, not (ADR 0044, unit 9b).
    fn contested(
        &self,
        port: u16,
        except: Option<SocketAddr>,
        (now, contest): (Instant, Duration),
    ) -> bool {
        self.sources.waiting.get(&port).is_some_and(|waiting| {
            waiting.iter().any(|shown| {
                Some(*shown) != except
                    && self.peers.get(shown).is_some_and(|peer| {
                        !peer.strict() && now.duration_since(peer.made) < contest
                    })
            })
        })
    }

    /// An answer from an address the app never saw, through the tool: the first answer of a stand-in
    /// still waiting on its port, or nothing (ADR 0044, decision 2).
    ///
    /// The tool resolved the stand-in's name itself, so its relay answers from an address the app never
    /// saw. A stand-in with identifiers ([`Peer::strict`]) is bound only by an answer that carries one
    /// of them, also when it waits alone (unit 9b): a sender that reaches the tool's relay first from
    /// its port cannot take it without what the app sent it, and several such stand-ins on one port each
    /// take their own answer. One that carries none of theirs is dropped and counted. On port 53 a
    /// stand-in has them always, its queries' IDs and questions, as since unit 9.
    ///
    /// A stand-in without identifiers is bound to the first answer from its port when it alone waits
    /// there, as unit 9 has it: whoever reaches the tool's relay first from that port, at an address the
    /// app never sent to, takes it, and the real answer is then dropped; one that names in the clear what
    /// the app sent another peer binds it not ([`Scope::answers_another`]). It waits beside another only
    /// where the caps on associations of a stand-in's own, or the budget, refused it one
    /// ([`UdpTable::own_wanted`]): the answer could then be either's, and is dropped and counted, for as
    /// long as more than one waits (the maintainer's decision, 2026-11-13: the safe floor).
    fn first_answer(
        &mut self,
        shared: &Shared,
        from: SocketAddr,
        (answer, read): (&[u8], &identifiers::Reading),
        now: Instant,
    ) -> LetIn {
        let several = self
            .sources
            .waiting
            .get(&from.port())
            .is_some_and(|waiting| waiting.len() > 1);
        let strict = self.waiting_on(from.port(), true);
        let any_strict = !strict.is_empty();
        // From an address no peer's answers came from: another peer sent the same identifier answers
        // from its own (fix round 2).
        match self.carried(&strict, read, Others::None) {
            Carried::One(shown) => {
                if several {
                    Counters::add(&shared.counters.udp_identified, 1);
                }
                return self.bind(shown, (from, answer), now);
            }
            Carried::Several => return LetIn::Unmatched,
            Carried::None => {}
        }
        let all = self.waiting_on(from.port(), false);
        match (any_strict, all.as_slice()) {
            (_, []) => LetIn::Filtered,
            (false, &[_]) if self.answers_another(read, from.port()) => LetIn::Unmatched,
            (false, &[shown]) => self.bind(shown, (from, answer), now),
            (true, _)
                if all
                    .iter()
                    .all(|shown| self.peers.get(shown).is_some_and(Peer::strict)) =>
            {
                LetIn::Unidentified
            }
            _ => LetIn::Unmatched,
        }
    }

    /// Whether `read`, an answer on `port`, names in the clear what the app sent a peer of this
    /// association ([`identifiers::Reading::answers`]): no stand-in without identifiers asked it, and
    /// none is bound by it (fix round 5, review I's I5: from an address the app never saw, it bound
    /// the one waiting on the port, which then took every later answer from there). It is no one's
    /// either: from an address the app never saw, nothing reaches a peer but a stand-in's first answer
    /// (unit 9), where under a relay's name, which may stand for the peer's own address, it would be
    /// that peer's.
    fn answers_another(&self, read: &identifiers::Reading, port: u16) -> bool {
        read.answers(port)
            .is_some_and(|fingerprint| self.sources.told.count(fingerprint) > 0)
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

    /// The stand-in the app knows as `shown`, whose identifier `answer` carries under another stand-in's
    /// name: a waiting one is bound beside that one by it, keeping its identifiers, so that each later
    /// answer under that name is its own only when it carries them (ADR 0044, unit 9b, fix round 1).
    fn bind_beside_named(
        &mut self,
        shown: SocketAddr,
        key: &str,
        answer: &[u8],
        now: Instant,
    ) -> LetIn {
        let waiting = self
            .peers
            .get(&shown)
            .is_some_and(|peer| peer.standing == Standing::Waiting);
        if waiting {
            self.sources.stop_waiting(shown);
            self.sources.add_named_beside(shown, key);
            if let Some(peer) = self.peers.get_mut(&shown) {
                peer.standing = Standing::Beside;
            }
        }
        self.answered_by(shown, answer, now)
    }

    /// Binds the waiting stand-in the app knows as `shown` to `from`, beside the peer that holds it,
    /// by its identifier that `answer` carries (ADR 0044, unit 9b): it keeps its identifiers, and those
    /// of what the app sends it from now on, so that what comes from `from` is its own only when it
    /// carries them.
    fn bind_beside(
        &mut self,
        shown: SocketAddr,
        (from, answer): (SocketAddr, &[u8]),
        now: Instant,
    ) -> LetIn {
        self.sources.stop_waiting(shown);
        self.sources.add_beside(shown, from);
        if let Some(peer) = self.peers.get_mut(&shown) {
            peer.way.from = Some(from);
            peer.standing = Standing::Beside;
        }
        self.answered_by(shown, answer, now)
    }
}

/// What an answer under a relay's name comes to ([`Scope::by_name`]).
enum UnderName {
    /// A peer's, or no one's.
    Done(LetIn),
    /// A new flow, from another port of the stand-in the app knows as this.
    ComeIn(SocketAddr),
}

/// Whose answers may come from where an answer came, besides the stand-ins it is checked for: an
/// identifier the app sent one of them tells none of the stand-ins apart (ADR 0044, unit 9b, fix round 2).
#[derive(Clone, Copy)]
enum Others {
    /// No one's: an address no peer's answers came from.
    None,
    /// Those of the peer that holds an address, the first, and of those bound beside it there, the
    /// second.
    At(SocketAddr, SocketAddr),
    /// Any peer's of the association: under a relay's name, which may stand for any of their addresses.
    All,
}

/// Which stand-ins an answer carries the identifiers of (ADR 0044, unit 9b).
enum Carried {
    None,
    One(SocketAddr),
    Several,
}

/// The engine's UDP: the destinations waiting for their way, the flows of lookups to Watch's own DNS
/// address, and the mappings.
#[derive(Default)]
pub(super) struct UdpTable {
    /// By the app's address and the destination.
    flows: HashMap<(SocketAddr, SocketAddr), UdpEntry>,
    /// By the app's address.
    mappings: HashMap<SocketAddr, Mapping>,
    /// The app sockets whose mapping one destination opens now, each with the app it opens it for and
    /// what tells the others that wait for it how it went: nothing while it opens and once it opened,
    /// else why it failed.
    opening: HashMap<SocketAddr, (Option<u32>, watch::Receiver<Option<io::ErrorKind>>)>,
    /// The app sockets whose app Android is asked for now, each with the question that is out.
    asking: HashMap<SocketAddr, Out>,
    /// Each app socket with a way, opening or open: what the table knows of it beyond its mapping.
    sockets: HashMap<SocketAddr, Socket>,
    /// The number of the last mapping opened.
    opened: u64,
    /// The number of the last question to Android shared among an app socket's destinations.
    questions: u64,
    /// The mappings by when each was last seen active, its number and app socket, with its app: the
    /// least recently active first, for every app and for each. A mapping's own `last` moves on with
    /// every datagram, and its place here only when a search for one to end finds it out of date, so
    /// that a datagram costs this nothing (ADR 0044, decision 3).
    recent: Ranks<(Instant, u64, SocketAddr, Option<u32>)>,
    /// Mappings that were answered lookups when their last answer came, by their number and app
    /// socket, with their app; one that is no longer one goes when a search finds it.
    answered: Ranks<(u64, SocketAddr, Option<u32>)>,
}

/// Whose mappings a search looks at: every app's, or one app's.
#[derive(Clone, Copy)]
enum Of {
    All,
    App(Option<u32>),
}

/// Mappings in an order, for every app together and for each app apart.
struct Ranks<K> {
    all: BTreeSet<K>,
    by_app: HashMap<Option<u32>, BTreeSet<K>>,
}

impl<K> Default for Ranks<K> {
    fn default() -> Self {
        Self {
            all: BTreeSet::new(),
            by_app: HashMap::new(),
        }
    }
}

impl<K: Ord + Copy> Ranks<K> {
    fn insert(&mut self, uid: Option<u32>, key: K) {
        self.all.insert(key);
        self.by_app.entry(uid).or_default().insert(key);
    }

    fn remove(&mut self, uid: Option<u32>, key: &K) {
        self.all.remove(key);
        if let Some(keys) = self.by_app.get_mut(&uid) {
            keys.remove(key);
            if keys.is_empty() {
                self.by_app.remove(&uid);
            }
        }
    }

    /// The first of those `of` says.
    fn first(&self, of: Of) -> Option<K> {
        match of {
            Of::All => self.all.first().copied(),
            Of::App(uid) => self.by_app.get(&uid)?.first().copied(),
        }
    }
}

/// What the table knows of an app socket while it has a way, opening or open: the answers of Android's
/// about it that can still decide a datagram, and its ways. It goes with the socket's last way, and so
/// is bounded by the ways: each question is asked for a datagram that waits in `flows` until its way
/// opens, and the record keeps only the newest answer and those near a datagram that still waits.
#[derive(Default)]
struct Socket {
    /// What decides whose each of its datagrams is.
    record: Record,
    /// How many of its destinations are in `flows`, opening or open.
    entries: usize,
    /// When the first datagram of each destination that waits for its way came, with how many such
    /// destinations: what the record must keep answers for.
    waiting: BTreeMap<Instant, usize>,
    /// The destinations of its open flows of lookups. They are all of the app the newest answer
    /// names, as its mapping is: an answer naming another app ends them all, and one naming the same
    /// app touches none.
    lookups: HashSet<SocketAddr>,
}

impl Socket {
    /// When the first datagram of the socket that still waits came, if one does.
    fn earliest(&self) -> Option<Instant> {
        self.waiting.first_key_value().map(|(&came, _)| came)
    }
}

/// A question to Android about an app socket that is out: its number, when it was asked, and what tells
/// the destinations that wait for the answer what it is.
struct Out {
    id: u64,
    asked: Instant,
    answer: watch::Receiver<Asked>,
}

pub(super) type UdpFlows = Arc<Mutex<UdpTable>>;

/// What became of a datagram sent to a peer: whether it left, the peer's bytes, and what the
/// datagram's QUIC Initial packets gave.
struct ToPeer {
    sent: io::Result<usize>,
    bytes: Option<Arc<FlowBytes>>,
    quic: Option<QuicRead>,
}

/// What a datagram of the app needs once the table has been read: its flow of lookups' way, its app,
/// the answer Watch's cache holds for it, and the flow's number and lookups owed; its peer's way; or a
/// way to be opened.
enum Next {
    Flow(UdpWay, Option<u32>, Option<Vec<u8>>, (u64, Arc<Owed>)),
    Peer(ToPeer),
    /// A way to be opened for the datagrams that wait for it.
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
    /// Only stand-ins with identifiers could take it, and it carries none of theirs (ADR 0044, unit
    /// 9b).
    Unidentified,
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

/// What an app socket's open mapping is to the way a new destination wants.
enum Current {
    /// It is the one: its number, and the socket the destination leaves by.
    Same(u64, Arc<UdpSocket>),
    /// It is the one, but the tool closed its own association, to be opened anew.
    Closed,
    /// There is none, or it ended: another app's, or one that leaves another way.
    Gone,
}

/// How a destination's way went: what waits for it, if anything, is decided again either way.
enum Made {
    /// It opened, or failed, or found the socket another app's.
    Done,
    /// The chain changed the app's way meanwhile: none left, and the destination is routed again.
    Reroute,
}

/// A destination's first datagram, `packet`, which came `now`, waiting for its way: for a destination
/// the app had no way to, and a lookup, with the floor of the answers that may stand for it, so that it
/// takes only an answer asked since it came.
fn holding(packet: &[u8], now: Instant, floor: bool) -> UdpEntry {
    UdpEntry::Opening(Holding {
        floor: floor.then_some(now),
        held: vec![Waiter {
            came: now,
            then: None,
            item: packet.to_vec(),
        }],
    })
}

/// Notes that the datagrams of `entry`, if it held any, wait no more.
fn unwait(socket: &mut Socket, entry: &UdpEntry) {
    if let UdpEntry::Opening(holding) = entry
        && let Some(came) = holding.held.first().map(|waiter| waiter.came)
        && let Some(count) = socket.waiting.get_mut(&came)
    {
        *count -= 1;
        if *count == 0 {
            socket.waiting.remove(&came);
        }
    }
}

impl UdpTable {
    /// The mapping `id` of `app`, if it is still open.
    fn mapping(&mut self, app: SocketAddr, id: u64) -> Option<&mut Mapping> {
        self.mappings.get_mut(&app).filter(|m| m.id == id)
    }

    /// Ends the mapping `id` of `app`, if it is still open, and its peers' flows with it. Its place in the
    /// budget is given back at once, so that [`UdpTable::room`] makes room in one step under the lock;
    /// its socket, and through the tool its request's connection, close a moment later, as its task
    /// next runs (ADR 0044, unit 10, "Known limits").
    fn end(&mut self, app: SocketAddr, id: u64, shared: &Shared) {
        if self.mapping(app, id).is_none() {
            return;
        }
        if let Some(mapping) = self.mappings.remove(&app) {
            for peer in mapping.peers.values() {
                shared.finish(peer.id);
            }
            mapping.ended.notify_one();
            for own in mapping.owns.values() {
                own.ended.notify_one();
            }
            let (id, uid) = (mapping.id, mapping.uid);
            self.recent.remove(uid, &(mapping.seen, id, app, uid));
            self.answered.remove(uid, &(id, app, uid));
        }
        self.forget(app);
    }

    /// The tool closed the own association of the mapping `id` of `app`: with no association of a
    /// stand-in's own, the mapping ends, as before; with one, only what left by its own association ends
    /// ([`Mapping::end_main`]). Whether it ended.
    fn close_main(&mut self, app: SocketAddr, id: u64, shared: &Shared) -> bool {
        let Some(mapping) = self.mapping(app, id) else {
            return true;
        };
        // One being opened counts: it is the stand-in's way (fix round 3).
        if mapping.owns() == 0 {
            self.end(app, id, shared);
            return true;
        }
        mapping.end_main(shared);
        false
    }

    /// A place in the budget for a new UDP way of the app `uid` that holds a socket of its own. Where
    /// the cap for every app, or the app's share, is full, a mapping ends to make room, and is counted
    /// (ADR 0044, decision 3): the first there is of an answered lookup, which carries nothing more;
    /// the app's own least recently active mapping, quiet for `Limits::udp_quiet`; and any app's. An
    /// app at its share makes room among its own only. A mapping that passed a datagram less than
    /// `udp_quiet` ago never ends so, and lookups to the tunnel's DNS address, which wait for their
    /// answers, neither. `None` when nothing may end.
    fn room(&mut self, uid: Option<u32>, shared: &Shared) -> Option<Place> {
        loop {
            let full = match shared.udp_budget.take(uid) {
                Ok(place) => return Some(place),
                Err(full) => full,
            };
            let (app, id) = self.one_to_end(uid, full, shared)?;
            self.end(app, id, shared);
            Counters::add(&shared.counters.udp_evicted, 1);
        }
    }

    /// The mapping to end to make room for a new way of the app `uid`, in the order [`UdpTable::room`]
    /// gives, if one may end.
    fn one_to_end(
        &mut self,
        uid: Option<u32>,
        full: Full,
        shared: &Shared,
    ) -> Option<(SocketAddr, u64)> {
        let quiet = (Instant::now(), shared.limits.udp_quiet);
        match full {
            Full::App => self
                .answered_lookup(Of::App(uid))
                .or_else(|| self.least_recent(Of::App(uid), quiet)),
            Full::All => self
                .answered_lookup(Of::All)
                .or_else(|| self.least_recent(Of::App(uid), quiet))
                .or_else(|| self.least_recent(Of::All, quiet)),
        }
    }

    /// An answered lookup among the mappings `of` says.
    fn answered_lookup(&mut self, of: Of) -> Option<(SocketAddr, u64)> {
        loop {
            let key @ (id, app, uid) = self.answered.first(of)?;
            let still = self
                .mappings
                .get(&app)
                .is_some_and(|mapping| mapping.id == id && mapping.answered_lookup());
            if still {
                return Some((app, id));
            }
            self.answered.remove(uid, &key);
        }
    }

    /// The least recently active mapping among those `of` says, if it has been quiet for `quiet.1` at
    /// `quiet.0`. A mapping active since the ranks last saw it takes its place anew, once for all its
    /// datagrams since, and the search goes on.
    fn least_recent(
        &mut self,
        of: Of,
        (now, quiet): (Instant, Duration),
    ) -> Option<(SocketAddr, u64)> {
        loop {
            let key @ (seen, id, app, uid) = self.recent.first(of)?;
            let Some(mapping) = self
                .mappings
                .get_mut(&app)
                .filter(|mapping| mapping.id == id)
            else {
                self.recent.remove(uid, &key);
                continue;
            };
            if mapping.last > seen {
                mapping.seen = mapping.last;
                self.recent.remove(uid, &key);
                self.recent.insert(uid, (mapping.seen, id, app, uid));
                continue;
            }
            return (now.saturating_duration_since(seen) >= quiet).then_some((app, id));
        }
    }

    /// Notes that the mapping `id` of `app` let an answer in: it may now be an answered lookup.
    fn heard(&mut self, (app, id): (SocketAddr, u64)) {
        if let Some(mapping) = self.mapping(app, id)
            && mapping.answered_lookup()
        {
            let uid = mapping.uid;
            self.answered.insert(uid, (id, app, uid));
        }
    }

    /// Puts `entry` in `flows` for `key`, and notes it for the app socket.
    fn put(&mut self, key: (SocketAddr, SocketAddr), entry: UdpEntry) {
        let socket = self.sockets.entry(key.0).or_default();
        match &entry {
            UdpEntry::Open(_) => {
                socket.lookups.insert(key.1);
            }
            UdpEntry::Opening(holding) => {
                socket.lookups.remove(&key.1);
                if let Some(came) = holding.held.first().map(|waiter| waiter.came) {
                    *socket.waiting.entry(came).or_default() += 1;
                }
            }
        }
        if let Some(before) = self.flows.insert(key, entry) {
            unwait(socket, &before);
        } else {
            socket.entries += 1;
        }
    }

    /// Takes `key`'s entry out of `flows`, and forgets the app socket if it was its last way.
    fn take(&mut self, key: (SocketAddr, SocketAddr)) -> Option<UdpEntry> {
        let entry = self.flows.remove(&key)?;
        if let Some(socket) = self.sockets.get_mut(&key.0) {
            socket.entries = socket.entries.saturating_sub(1);
            socket.lookups.remove(&key.1);
            unwait(socket, &entry);
        }
        self.forget(key.0);
        Some(entry)
    }

    /// Forgets `app`'s socket, with the newest answer about it, once it has no way left.
    fn forget(&mut self, app: SocketAddr) {
        if !self.mappings.contains_key(&app)
            && self
                .sockets
                .get(&app)
                .is_some_and(|socket| socket.entries == 0)
        {
            self.sockets.remove(&app);
        }
    }

    /// The question out about `app`'s socket, if one is. One whose asker is gone without a word (the
    /// engine stopping) holds no one up.
    fn out(&self, app: SocketAddr) -> Option<&Out> {
        self.asking
            .get(&app)
            .filter(|out| out.answer.has_changed().is_ok())
    }

    /// Puts out a question to Android about `app`'s socket, asked `now`, which datagrams of the socket
    /// that come near it may join.
    fn ask(&mut self, app: SocketAddr, now: Instant) -> Asking {
        let (told, answer) = watch::channel(Asked::Waiting);
        self.questions += 1;
        let id = self.questions;
        let out = Out {
            id,
            asked: now,
            answer,
        };
        self.asking.insert(app, out);
        Asking {
            told,
            id,
            asked: now,
        }
    }

    /// A question to put out now for a datagram of `app`'s socket that came at `came`, with `floor`, if
    /// no answer decides it and no question out can ([`Record::step`]): so it asks as it comes, not
    /// once its way opens, when a question could no longer decide it (ninth review of unit 9, finding
    /// 1).
    fn question_for(
        &mut self,
        app: SocketAddr,
        (came, floor, then): (Instant, Option<Instant>, Option<Verdict>),
        reask: Duration,
    ) -> Option<Asking> {
        let out = self.out(app).map(|out| out.asked);
        let socket = self.sockets.get(&app)?;
        (socket.record.step((came, floor, then), out, came, reask) == Step::Ask)
            .then(|| self.ask(app, came))
    }

    /// Something came in `now` to the mapping `id` of `app`, and was let in. Traffic that only comes in
    /// keeps no app's claim to the socket fresh: once the answers no longer presume the mapping's app,
    /// the app having sent nothing for `udp_reask` nor Android named it since, a question is put out,
    /// unless one out can say, at most one each `udp_reask` of such traffic. An answer that names
    /// another app, or none, then ends the mapping (ninth review of unit 9, finding 2).
    fn came_in(
        &mut self,
        (app, id): (SocketAddr, u64),
        now: Instant,
        reask: Duration,
    ) -> Option<Asking> {
        let uid = self.mapping(app, id)?.uid;
        let socket = self.sockets.get(&app)?;
        if socket.record.passes(now, uid, reask) {
            return None;
        }
        self.question_for(app, (now, None, None), reask)
    }

    /// Whether `key`'s app socket has a mapping that knows its destination: one the app sent to.
    fn knows(&self, (app, destination): (SocketAddr, SocketAddr)) -> bool {
        self.mappings
            .get(&app)
            .is_some_and(|mapping| mapping.knows(destination))
    }

    /// Whether a way of the app `uid` may open for `app`'s socket, or stay: the newest answer about the
    /// socket names that app ([`Record::keeps`]).
    fn keeps(&self, app: SocketAddr, uid: Option<u32>) -> bool {
        self.sockets
            .get(&app)
            .is_some_and(|socket| socket.record.keeps(uid))
    }

    /// The open mapping of `app`, by its number, with its socket, if it is the app `wanted.uid`'s and
    /// leaves the way wanted. Another ends: Android handed the port out again, or the chain changed. With
    /// its own association closed by the tool, it is open still for `destination` where that is a peer of
    /// an association of a stand-in's own, which it leaves by, so that the mapping's own is not opened
    /// anew for a destination that does not use it (ADR 0044, unit 9b, fix round 2).
    fn open_mapping(
        &mut self,
        (app, destination): (SocketAddr, SocketAddr),
        wanted: &Wanted,
        shared: &Shared,
    ) -> Current {
        let Some(mapping) = self.mappings.get_mut(&app) else {
            return Current::Gone;
        };
        if mapping.uid == wanted.uid
            && mapping.exit.same(&wanted.exit)
            && mapping.keeps_its_way(shared)
        {
            if !mapping.main_open {
                let own = mapping
                    .peers
                    .get(&destination)
                    .and_then(|peer| mapping.owns.get(&peer.via?));
                return match own {
                    Some(own) => Current::Same(mapping.id, Arc::clone(&own.socket)),
                    None => Current::Closed,
                };
            }
            return Current::Same(mapping.id, Arc::clone(&mapping.socket));
        }
        let id = mapping.id;
        self.end(app, id, shared);
        Current::Gone
    }

    /// Android named `named.uid` the app of `app`'s socket, when asked by question `id`, whichever
    /// destination or lookup asked: the record notes it. If it is now the newest answer and names
    /// another app than the one before, every way of the socket ends, its mapping and its flows of
    /// lookups, all of that app's: Android handed the port out again (sixth review of unit 9, finding
    /// 2). A flow that ends so still hands the app what it owes. The work is the socket's own ways, and
    /// only when the app changes, since they are all of the app the newest answer names: how many ways
    /// it looked at (eighth review, finding 3).
    fn answered(&mut self, app: SocketAddr, (id, named): (u64, Named), shared: &Shared) -> usize {
        let reask = shared.limits.udp_reask;
        let Some(socket) = self.sockets.get_mut(&app) else {
            return 0;
        };
        let changed = socket.record.note(id, named);
        let earliest = socket.earliest();
        socket.record.keep_from(earliest, reask);
        if !changed {
            return 0;
        }
        let lookups: Vec<SocketAddr> = socket.lookups.iter().copied().collect();
        let mut touched = lookups.len();
        if let Some(mapping) = self.mappings.get(&app) {
            touched += 1;
            if mapping.uid != named.uid {
                let id = mapping.id;
                self.end(app, id, shared);
            }
        }
        for destination in lookups {
            let key = (app, destination);
            if matches!(self.flows.get(&key), Some(UdpEntry::Open(flow)) if flow.uid != named.uid) {
                self.take(key);
            }
        }
        touched
    }

    /// Sorts the datagrams held for `key` once a way of the app `way` is there ([`Record::settle`]): those that leave, and those dropped, are taken; the rest wait on,
    /// in order. The socket, with its record, stays even with nothing left waiting: the caller opens a
    /// way for what leaves, or forgets the socket if it has none.
    fn settle(
        &mut self,
        key: (SocketAddr, SocketAddr),
        way: Option<u32>,
        reask: Duration,
    ) -> Settled<Vec<u8>> {
        let nothing = || Settled {
            leave: Vec::new(),
            dropped: Vec::new(),
            rest: Vec::new(),
        };
        if !matches!(self.flows.get(&key), Some(UdpEntry::Opening(_))) {
            return nothing();
        }
        let Some(entry) = self.flows.remove(&key) else {
            return nothing();
        };
        // Not `take`: the socket, with its record, must not be forgotten before the rule is asked.
        let socket = self.sockets.entry(key.0).or_default();
        socket.entries = socket.entries.saturating_sub(1);
        unwait(socket, &entry);
        let UdpEntry::Opening(Holding { floor, held }) = entry else {
            return nothing();
        };
        let mut settled = socket.record.settle(held, floor, way, reask);
        if !settled.rest.is_empty() {
            let held = std::mem::take(&mut settled.rest);
            self.put(key, UdpEntry::Opening(Holding { floor, held }));
        }
        settled
    }

    /// Drops the first datagram held for `key` if it is the one decided, which came at `decided`: the
    /// rule drops it. Another task, for a later queue of the same destination, may have taken it
    /// already (ninth review of unit 9, finding 6).
    fn drop_held(&mut self, key: (SocketAddr, SocketAddr), decided: Instant) -> bool {
        let Some(UdpEntry::Opening(holding)) = self.flows.get_mut(&key) else {
            return false;
        };
        if holding
            .held
            .first()
            .is_none_or(|waiter| waiter.came != decided)
        {
            return false;
        }
        let came = holding.held.remove(0).came;
        let next = holding.held.first().map(|waiter| waiter.came);
        if let Some(socket) = self.sockets.get_mut(&key.0) {
            if let Some(count) = socket.waiting.get_mut(&came) {
                *count -= 1;
                if *count == 0 {
                    socket.waiting.remove(&came);
                }
            }
            if let Some(next) = next {
                *socket.waiting.entry(next).or_default() += 1;
            }
        }
        if next.is_none() {
            self.take(key);
        }
        true
    }

    /// When the first datagram held for `key` came, with the floor of the answers that may stand for it,
    /// and whose they said it was when it came.
    fn first_held(
        &self,
        key: (SocketAddr, SocketAddr),
    ) -> Option<(Instant, Option<Instant>, Option<Verdict>)> {
        match self.flows.get(&key) {
            Some(UdpEntry::Opening(holding)) => holding
                .held
                .first()
                .map(|waiter| (waiter.came, holding.floor, waiter.then)),
            _ => None,
        }
    }

    /// Whether a lookup that came `now` may go by the open flow of lookups between `key`'s two ends: the
    /// rule says it is the flow's app's, and the chain still sends that app the flow's way. The app is
    /// then presumed to send on.
    fn lookup_passes(
        &mut self,
        key: (SocketAddr, SocketAddr),
        now: Instant,
        shared: &Shared,
    ) -> bool {
        let (Some(UdpEntry::Open(flow)), Some(socket)) =
            (self.flows.get_mut(&key), self.sockets.get_mut(&key.0))
        else {
            return false;
        };
        if !socket.record.passes(now, flow.uid, shared.limits.udp_reask)
            || !flow.keeps_its_way(shared, key.1)
        {
            return false;
        }
        socket.record.left(now);
        true
    }

    /// A datagram from the app, `packet`, to a peer of its mapping: both are refreshed, its QUIC
    /// Initial packets read, and it is sent, under the table's lock, without waiting for room in the
    /// mapping's socket ([`try_send_to`]), so that one that left is noted as one an error may answer.
    /// A mapping whose app's datagrams leave another way now ends.
    fn toward_peer(
        &mut self,
        (app, destination): (SocketAddr, SocketAddr),
        (packet, parsed, payload): (&[u8], &Packet, &[u8]),
        now: Instant,
        shared: &Shared,
    ) -> Option<ToPeer> {
        let mapping = self.mappings.get_mut(&app)?;
        if !mapping.keeps_its_way(shared) {
            let id = mapping.id;
            self.end(app, id, shared);
            return None;
        }
        if !mapping.knows(destination) {
            return None;
        }
        // The rule says whose the datagram is (ADR 0044, decision 1). After a silence, or long after
        // Android last named its app, it asks Android again whose socket this is, as a new destination's
        // does, and waits for the answer: the port may be another app's now, which the log must name and
        // the chain may send another way. A port another app holds then gets a mapping of its own.
        let socket = self.sockets.get_mut(&app)?;
        if !socket
            .record
            .passes(now, mapping.uid, shared.limits.udp_reask)
        {
            return None;
        }
        socket.record.left(now);
        // A stand-in, or a flow that came in through it, leaves by its association of its own if it has
        // one (ADR 0044, unit 9b).
        let socket = match mapping.peers.get(&destination)?.via {
            None if mapping.main_open => Arc::clone(&mapping.socket),
            None => return None,
            Some(own) => Arc::clone(&mapping.owns.get(&own)?.socket),
        };
        mapping.sent(destination, payload);
        mapping.last = now;
        let peer = mapping.peers.get_mut(&destination)?;
        peer.last = now;
        let quic = read_quic(&mut peer.quic, payload);
        let header = peer.way.header.clone();
        let sent = try_send_to(
            &socket,
            header.as_deref(),
            payload,
            (destination, parsed.hops),
        );
        if sent.is_ok() {
            peer.left(Sent::of(packet, parsed.transport));
        }
        Some(ToPeer {
            sent,
            bytes: peer.bytes.clone(),
            quic,
        })
    }

    /// Whether the stand-in that `key`'s datagrams, waiting to leave by the mapping `id`, go to needs an
    /// association of its own (ADR 0044, unit 9b). On one association, a port where a stand-in without
    /// identifiers waits has no other stand-in waiting: a new stand-in whose datagrams carry no
    /// identifier, beside any that waits on its port, or one whose datagrams carry one, beside one that
    /// waits without, would break that; and an identifier the app sent another peer of the association on
    /// the port, of whatever standing, tells nothing apart (fix rounds 1 and 2: one DNS query, one ID and
    /// question, sent to two servers, as a stub resolver retries one with the next; one NTP timestamp to
    /// two). Either gets one, if its app's share of them allows it (`Limits::udp_own_share`, under
    /// `Limits::udp_own_relays`) and its app's share of the budget has a place, made room for as for a
    /// mapping. An app asks few names at once on one port without identifiers; beyond its share, a
    /// stand-in waits beside the others on the mapping's association, under unit 9's floor. (A cap of 8
    /// for each mapping, unit 9b's, went in fix round 6: the share of 8 for each app, which fix round 5
    /// set, reached it first, so that it never applied.) Only through the tool; on
    /// port 53, where every stand-in has identifiers, only for an identifier another peer was sent too;
    /// and never for a destination the mapping already knows, which keeps the association it has.
    fn own_wanted(
        &mut self,
        (app, destination): (SocketAddr, SocketAddr),
        id: u64,
        (way, wanted): (&PeerWay, &Wanted),
        shared: &Shared,
    ) -> OwnWanted {
        let Exit::Tool(chain) = &wanted.exit else {
            return OwnWanted::No;
        };
        if way.name.is_none() || way.from.is_some() {
            return OwnWanted::No;
        }
        let asks = self.held_asks((app, destination));
        let Some(mapping) = self.mapping(app, id) else {
            return OwnWanted::No;
        };
        if mapping.peers.contains_key(&destination) {
            return OwnWanted::No;
        }
        let port = destination.port();
        let waiting = mapping.main().waiting_on(port, false);
        let without = waiting
            .iter()
            .any(|shown| mapping.peers.get(shown).is_some_and(|peer| !peer.strict()));
        let collides = asks
            .iter()
            .any(|&fingerprint| mapping.sources.told.count(fingerprint) > 0);
        let carries = !asks.is_empty();
        let beside_one = !waiting.is_empty() && port != 53 && (!carries || without);
        if !beside_one && !collides {
            return OwnWanted::No;
        }
        // Its place under the cap, in its app's share, before room is made for it.
        let uid = mapping.uid;
        let Ok(own) = shared.own_relays.take(uid) else {
            return OwnWanted::Refused;
        };
        // The app sends by it now: making room never ends it, neither as one quiet for `udp_quiet`, nor
        // as an answered lookup, which it still is when its one peer was a resolver that answered (fix
        // round 3: a resolver's failure, then the app's next name, made room by ending this mapping).
        mapping.last = Instant::now();
        self.answered.remove(uid, &(id, app, uid));
        let Some(place) = self.room(uid, shared) else {
            return OwnWanted::Refused;
        };
        let Some(mapping) = self.mapping(app, id) else {
            return OwnWanted::No;
        };
        mapping.owns_opening += 1;
        OwnWanted::Place(Arc::clone(chain), (place, own))
    }

    /// The fingerprints of what the datagrams that wait for `key`'s way ask an answer to carry: on port
    /// 53 each query's ID and question, as a stand-in there keeps them; elsewhere what
    /// [`identifiers::of`] reads.
    fn held_asks(&self, (app, destination): (SocketAddr, SocketAddr)) -> Vec<u64> {
        let mut asks = Vec::new();
        let Some(UdpEntry::Opening(holding)) = self.flows.get(&(app, destination)) else {
            return asks;
        };
        let port = destination.port();
        for waiter in &holding.held {
            let Ok(parsed) = packet::parse(&waiter.item) else {
                continue;
            };
            let Some(payload) = packet::udp_payload(&waiter.item, &parsed) else {
                continue;
            };
            if port == 53 {
                asks.extend(
                    dns::u16_at(payload, 0).zip(answers::question(payload)).map(
                        |(id, question)| identifiers::dns_fingerprint(port, id, &question.name),
                    ),
                );
            } else {
                asks.extend(
                    identifiers::of((app.port(), port), payload)
                        .iter()
                        .map(|asked| identifiers::fingerprint(port, asked)),
                );
            }
        }
        asks
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
        let mut scope = mapping.main();
        if scope.peers.contains_key(&from) {
            let let_in = scope.answered_by(from, answer, now);
            self.heard((app, id));
            return let_in;
        }
        if scope.sources.shown(from.ip()).is_none() {
            return LetIn::Filtered;
        }
        scope.come_in(shared, (app, from), now, |_| PeerWay::direct(from))
    }

    /// Which peer of the mapping `id` of `app` an `answer` from the tool's relay is for, by its
    /// header's `target`, among those that leave by its association `via`: the mapping's own, or a
    /// stand-in's own (ADR 0044, unit 9b). `Gone` once either has ended.
    fn let_in_relayed(
        &mut self,
        (app, id): (SocketAddr, u64),
        via: Option<u64>,
        relayed: (&Target, &[u8]),
        shared: &Shared,
    ) -> LetIn {
        let Some(mapping) = self.mapping(app, id) else {
            return LetIn::Gone;
        };
        if !mapping.keeps_its_way(shared) {
            return LetIn::Gone;
        }
        let Some(mut scope) = mapping.scope(via) else {
            return LetIn::Gone;
        };
        let let_in = scope.relayed_answer(shared, app, relayed, Instant::now());
        if let LetIn::Peer(..) = let_in {
            self.heard((app, id));
        }
        let_in
    }

    /// The flow `id` between `key`'s two ends goes, if it is still there.
    fn remove_flow(&mut self, key: (SocketAddr, SocketAddr), id: u64) {
        if matches!(self.flows.get(&key), Some(UdpEntry::Open(flow)) if flow.id == id) {
            self.take(key);
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
            let stale = matches!(table.flows.get(&key), Some(UdpEntry::Open(_)))
                && !table.lookup_passes(key, now, &self.shared);
            let holding = |floor| holding(packet, now, floor);
            if stale {
                // A flow of lookups that may not carry this one gives way to a new flow, which this
                // lookup opens once the rule says whose it is and its route is asked. The old flow
                // still hands the app every answer it owes for what it sent before.
                table.put(key, holding(true));
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
                    Some(UdpEntry::Opening(holding)) => {
                        let (floor, room) = (
                            holding.floor,
                            holding.held.len() < self.shared.limits.udp_waiting,
                        );
                        if room {
                            self.hold_behind(&mut table, key, packet, (now, floor));
                        } else {
                            Counters::add(&self.shared.counters.skipped, 1);
                        }
                        return;
                    }
                    None => {
                        let datagram = (packet, parsed, payload);
                        if let Some(to) = table.toward_peer(key, datagram, now, &self.shared) {
                            Next::Peer(to)
                        } else {
                            let known = !lookup && table.knows(key);
                            table.put(key, holding(!known));
                            Next::Open
                        }
                    }
                }
            }
        };
        let (way, uid, cached, owed) = match next {
            Next::Flow(way, uid, cached, owed) => (way, uid, cached, owed),
            Next::Peer(to) => return self.sent_to_peer(to, packet, parsed).await,
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
        let sent = way.try_send(payload);
        if let Some(error) = count_sent(&self.shared, None, packet, parsed, sent) {
            self.send(&error).await;
        }
    }

    /// A datagram for a destination whose datagrams wait for its way goes behind them, with whose the
    /// answers say it is as it comes, if they say; and it asks Android as it comes if no answer and no
    /// question out can decide it, so that it never waits on with no answer near it (ninth review of
    /// unit 9, finding 1).
    fn hold_behind(
        &self,
        table: &mut UdpTable,
        key: (SocketAddr, SocketAddr),
        packet: &[u8],
        (came, floor): (Instant, Option<Instant>),
    ) {
        let reask = self.shared.limits.udp_reask;
        let then = table
            .sockets
            .get(&key.0)
            .and_then(|socket| socket.record.presume(came, floor, reask));
        if let Some(UdpEntry::Opening(holding)) = table.flows.get_mut(&key) {
            holding.held.push(Waiter {
                came,
                then,
                item: packet.to_vec(),
            });
        }
        if let Some(asking) = table.question_for(key.0, (came, floor, then), reask) {
            spawn_question(key, asking, &self.shared, &self.udp);
        }
    }

    /// What a datagram sent to a peer of its app socket's mapping gave ([`UdpTable::toward_peer`]):
    /// counted, and the app told when its destination cannot be reached.
    async fn sent_to_peer(&self, to: ToPeer, packet: &[u8], parsed: &Packet) {
        note_quic(&self.shared, to.quic);
        let bytes = to.bytes.as_deref();
        if let Some(error) = count_sent(&self.shared, bytes, packet, parsed, to.sent) {
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
/// reached. One that found the socket's buffer full is dropped, as a full queue drops it; so is one the
/// network beneath's queue dropped, which the kernel reports as `ENOBUFS` to a socket that asks for its
/// ICMP errors, as a mapping's does (third round of unit 11b, finding 2): told as "host unreachable", it
/// failed an app socket that asks for its errors too at its next send, losing that datagram as well.
/// One the engine's kernel refused as too long to send (`EMSGSIZE`) is dropped and counted (ADR 0044,
/// decision 5 as amended): its destination can be reached, and "host unreachable" would tell the app
/// otherwise.
/// The tunnel's MTU is the first hop's, so the app's own kernel has already sized it for the network
/// beneath; the engine's sockets fragment what is larger than the path, and a router beyond answers
/// for itself.
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
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.raw_os_error() == Some(nix::errno::Errno::ENOBUFS as i32) =>
        {
            Counters::add(&shared.counters.skipped, 1);
            None
        }
        Err(error) if error.raw_os_error() == Some(nix::errno::Errno::EMSGSIZE as i32) => {
            Counters::add(&shared.counters.too_big, 1);
            None
        }
        Err(_) => packet::unreachable(packet, parsed, Unreachable::Host),
    }
}

/// Sends a datagram from a mapping's socket to `destination`, or through the tool's relay with the
/// `header` that names it; the bytes sent are the payload's. On the direct path it leaves with the hop
/// limit `hops` the app sent it with (ADR 0044, unit 11b); through the tool, the relay carries it, with
/// a hop limit of its own. On the direct path, an ICMP error the kernel holds for the socket fails its
/// next send once, and that datagram does not leave: it is sent again. The mapping's task reads the
/// error itself from the socket's error queue, for the destination it was for.
///
/// It never waits for room in the socket's buffer: a datagram that finds it full is dropped, and
/// counted ([`count_sent`]), as a full queue drops it (unit 11b's second review). Waiting there held the
/// event loop, and every app's packets behind it, until that one socket drained; and once an ICMP error
/// had come for the socket, epoll's `EPOLLERR` beside `EPOLLOUT` marks it closed for writing in mio,
/// which tokio keeps for good, so the wait spun on "would block" at a whole core rather than waiting
/// (the network lab measured 2 s of CPU time in 2 s). UDP is free to drop, and the app's own stack
/// sends again where it must.
fn try_send_to(
    socket: &UdpSocket,
    header: Option<&[u8]>,
    payload: &[u8],
    (destination, hops): (SocketAddr, u8),
) -> io::Result<usize> {
    if let Some(header) = header {
        return socket
            .try_send(&[header, payload].concat())
            .map(|_| payload.len());
    }
    match hops::try_send(socket, payload, destination, hops) {
        Err(error) if errors::from_icmp(&error) => {
            hops::try_send(socket, payload, destination, hops)
        }
        sent => sent,
    }
}

/// Opens a destination's way, off the event loop: decides whose its first datagram that waits is, by
/// the one rule ([`Record::whose`]), asking Android as it needs, then makes the destination a peer of
/// that app's mapping, or for Watch's own DNS address opens a flow of lookups. Where the route sends the
/// app's UDP nowhere, the app is told the destination cannot be reached. A datagram the rule drops is
/// dropped and counted. When the chain takes the app, or lets it go, while its way opens, the
/// destination is routed again: what waited leaves by the new route, never by the old. It goes on until
/// nothing waits.
async fn open_udp(
    key: (SocketAddr, SocketAddr),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    changes: watch::Receiver<u64>,
) {
    let context = (&tun, &shared, &flows, &changes);
    // An app Android cannot name is unknown, in the log and to the chain, even when Android named this
    // socket's app before: the port may be another app's now, and a guess would log one app's traffic
    // as another's. While a chain is on, such an app goes nowhere.
    while let Some((verdict, came)) = decide(key, &shared, &flows).await {
        match verdict {
            Verdict::Owner(uid) if shared.is_tunnel_dns(key.1.ip()) => {
                while let Made::Reroute = open_lookups(key, uid, context).await {}
            }
            Verdict::Owner(uid) => open_mapped(key, uid, context).await,
            // Who sent it cannot be told, or its app holds the socket no more, or no answer near it can
            // be had: the very datagram decided goes, counted by why.
            why => {
                if lock(&flows).drop_held(key, came) {
                    let ambiguous = why == Verdict::Ambiguous;
                    count_drops(&shared, (u64::from(ambiguous), u64::from(!ambiguous)));
                }
            }
        }
    }
}

/// Counts datagrams the rule dropped: as ambiguous, answers near them naming different apps, or as
/// late, their app having lost the socket before their way opened, or no answer near them to be had.
fn count_drops(shared: &Shared, (ambiguous, late): (u64, u64)) {
    Counters::add(&shared.counters.udp_ambiguous, ambiguous);
    Counters::add(&shared.counters.udp_late, late);
}

/// What the rule says the app `uid` sent to `key`'s destination, whose way could have no socket of its
/// own: the cap for every app, or the app's share, is full (ADR 0044, decision 3). It is dropped, as by
/// a full queue, and counted, and the app sends again, as after a lost datagram; nothing tells it. What
/// another app sent waits on.
fn refused(key: (SocketAddr, SocketAddr), uid: Option<u32>, shared: &Shared, flows: &UdpFlows) {
    let mut table = lock(flows);
    let settled = table.settle(key, uid, shared.limits.udp_reask);
    table.forget(key.0);
    count_drops(shared, settled.drops());
    Counters::add(&shared.counters.udp_refused, settled.leave.len() as u64);
}

/// Makes a destination a peer of the mapping of its app socket's app `uid`, routed again when the chain
/// changes meanwhile.
async fn open_mapped(key: (SocketAddr, SocketAddr), uid: Option<u32>, context: Context<'_>) {
    let (tun, shared, flows, _) = context;
    let (app, destination) = key;
    loop {
        // Read before the route, so that a chain set meanwhile makes the mapping ask again.
        let chains = shared.chains.load(Ordering::Acquire);
        let Some(exit) = Exit::of(shared.route(uid, destination)) else {
            // A flow whose app Android cannot name while a chain is on, a stand-in outside the chain,
            // or a chained app's UDP through a tool without UDP (VPN.md).
            let (_, mut flow) = begin_udp(shared, app, destination, uid);
            flow.outcome = Outcome::Unreachable;
            udp_failed(key, flow, tun, shared, flows).await;
            return;
        };
        let wanted = Wanted { uid, exit, chains };
        if let Made::Done = open_peer(key, wanted, context).await {
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

/// A question to Android that a datagram waits for: one out, which it joins, or its own.
enum Pending {
    Join(watch::Receiver<Asked>),
    Ask(Asking),
}

/// A question to Android about an app socket, put out: what tells those that join it that it was
/// answered, its number, and when it was asked.
struct Asking {
    told: watch::Sender<Asked>,
    id: u64,
    asked: Instant,
}

/// Asks Android whose `app`'s socket is, for the question `asking` put out, with `remote` as the other
/// end Android is told of, and notes the answer ([`UdpTable::answered`]): what waits is decided again.
async fn put_question(
    (app, remote): (SocketAddr, SocketAddr),
    asking: Asking,
    shared: &Arc<Shared>,
    flows: &UdpFlows,
) {
    let named = Named {
        uid: owner(shared, UDP, app, remote).await,
        asked: asking.asked,
    };
    {
        let mut table = lock(flows);
        if table
            .asking
            .get(&app)
            .is_some_and(|out| out.id == asking.id)
        {
            table.asking.remove(&app);
        }
        table.answered(app, (asking.id, named), shared);
    }
    let _ = asking.told.send(Asked::Answered);
}

/// As [`put_question`], in a task of its own.
fn spawn_question(
    key: (SocketAddr, SocketAddr),
    asking: Asking,
    shared: &Arc<Shared>,
    flows: &UdpFlows,
) {
    let (shared, flows) = (Arc::clone(shared), Arc::clone(flows));
    tokio::spawn(async move { put_question(key, asking, &shared, &flows).await });
}
/// Where a question to Android about an app socket's app stands.
#[derive(Clone, Copy)]
enum Asked {
    Waiting,
    Answered,
}

/// Decides whose the first datagram that waits for `key`'s way is, by the one rule
/// ([`Record::step`]): the answers already noted decide it, or it waits for the answer to the question
/// out about its socket, if that can decide it, or it asks Android, and is decided again once the
/// answer is noted. A question asked for one destination serves the others that come near it, so that a
/// pause in an app socket's sending costs one question to Android, not one for each destination it
/// knows; one a destination the app had no way to, or a lookup, joins only if it was asked since its
/// datagram came. The verdict, with when the datagram it is for came; `None` once nothing waits.
async fn decide(
    key: (SocketAddr, SocketAddr),
    shared: &Arc<Shared>,
    flows: &UdpFlows,
) -> Option<(Verdict, Instant)> {
    let reask = shared.limits.udp_reask;
    loop {
        let pending = {
            let mut table = lock(flows);
            let held = table.first_held(key)?;
            let out = table.out(key.0);
            let now = Instant::now();
            let step = table.sockets.get(&key.0).map_or(Step::Ask, |socket| {
                socket
                    .record
                    .step(held, out.map(|out| out.asked), now, reask)
            });
            match step {
                Step::Decided(verdict) => return Some((verdict, held.0)),
                Step::Join => match out {
                    Some(out) => Pending::Join(out.answer.clone()),
                    None => continue,
                },
                Step::Ask => Pending::Ask(table.ask(key.0, now)),
            }
        };
        match pending {
            Pending::Join(mut answer) => {
                let _ = answer.changed().await;
            }
            Pending::Ask(asking) => put_question(key, asking, shared, flows).await,
        }
    }
}

/// Makes a destination a peer of its app socket's mapping, opening the mapping first if the app has
/// none, or if the one it has is another app's or leaves another way. The datagrams that waited leave
/// under the table's lock, so that none that comes meanwhile overtakes them, and the peer is known
/// before its answer can come: those the rule says the mapping's app sent; those it drops are dropped
/// and counted, and from the first of another app's, or undecided, all wait on. A new mapping that the
/// budget refuses leaves nothing: what the app sent is dropped and counted ([`refused`]).
async fn open_peer(
    key: (SocketAddr, SocketAddr),
    wanted: Wanted,
    (tun, shared, flows, changes): Context<'_>,
) -> Made {
    let (app, destination) = key;
    let opened = match way_toward(key, &wanted, shared, flows) {
        None => Err(io::ErrorKind::HostUnreachable.into()),
        Some(way) => mapping_for(key, &wanted, (tun, shared, flows, changes))
            .await
            .map(|opened| (opened, way)),
    };
    let ((id, socket), way) = match opened {
        Ok((Mapped::Open(id, socket), way)) => ((id, socket), way),
        Ok((Mapped::Reroute, _)) => return Made::Reroute,
        // Another app holds the socket now: what waits is decided again.
        Ok((Mapped::Stale, _)) => return Made::Done,
        Ok((Mapped::Refused, _)) => {
            refused(key, wanted.uid, shared, flows);
            return Made::Done;
        }
        Err(error) => {
            let (_, mut flow) = begin_udp(shared, app, destination, wanted.uid);
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, tun, shared, flows).await;
            return Made::Done;
        }
    };
    let _ = socket.writable().await;
    // A stand-in whose first datagrams would share a port another stand-in waits on, where the address
    // alone could not tell their answers apart, leaves by an association of its own (ADR 0044, unit
    // 9b). It is opened as the mapping's was, off the table's lock, while its datagrams wait.
    let wanted_own = {
        let mut table = lock(flows);
        if let Some(made) = still_open(&mut table, (app, id), shared) {
            return made;
        }
        table.own_wanted(key, id, (&way, &wanted), shared)
    };
    let refused = matches!(wanted_own, OwnWanted::Refused);
    let opened = match wanted_own {
        OwnWanted::No | OwnWanted::Refused => None,
        OwnWanted::Place(chain, places) => {
            let made = associate(shared, &chain).await;
            // As for the mapping's socket: the waiting datagrams leave at once, without waiting, so
            // the socket must first be known to take them.
            if let Ok((socket, _)) = &made {
                let _ = socket.writable().await;
            }
            Some((made, places))
        }
    };
    let mut reads = Vec::new();
    let mut errors = Vec::new();
    let leaving = {
        let mut table = lock(flows);
        leave_by(
            &mut table,
            (key, id),
            (way, &wanted, socket, (opened, refused)),
            (shared, &mut reads, &mut errors),
        )
    };
    match leaving {
        Leaving::Made(made) => return made,
        // As when a mapping's association fails: the stand-in's datagrams fail with it, and nothing
        // leaves another way.
        Leaving::Failed(error) => {
            let (_, mut flow) = begin_udp(shared, app, destination, wanted.uid);
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, tun, shared, flows).await;
            return Made::Done;
        }
        Leaving::Left(None) => {}
        Leaving::Left(Some((number, task))) => {
            Counters::add(&shared.counters.udp_own_relays, 1);
            tokio::spawn(own_relayed(
                (task, number),
                Arc::clone(tun),
                Arc::clone(shared),
                Arc::clone(flows),
                changes.clone(),
            ));
        }
    }
    for read in reads {
        note_quic(shared, read);
    }
    for error in errors {
        send_to_app(tun, shared, &error).await;
    }
    Made::Done
}

/// An association of a stand-in's own as it opened, or failed to, with its places.
type OwnOpened = (io::Result<(UdpSocket, TcpStream)>, (Place, Place));

/// What became of the datagrams that waited for a destination's way ([`leave_by`]).
enum Leaving {
    /// They were sent, or none was the mapping's app's to send; with the task of a stand-in's own
    /// association opened for them, to be started.
    Left(Option<(u64, MappingTask)>),
    /// The stand-in's own association could not be opened.
    Failed(io::Error),
    /// The mapping ended meanwhile, or leaves another way now.
    Made(Made),
}

/// A destination's association, opened if it needed one of its own (`opened`), or refused one at a cap
/// (`refused`), and the mapping `id` it waited for, whose own association's socket was `socket`: under
/// the table's lock, the datagrams the rule says the mapping's app sent leave, by the destination's
/// association, its QUIC reads and the errors for the app gathered for after the lock. A destination
/// already a peer of the mapping leaves by the association it has, whatever was opened for it meanwhile,
/// and whatever failed to open (ADR 0044, unit 9b, fix rounds 1 and 2): a peer's association is the
/// peer's, so that after Android was asked again, or once the app answers a flow that came in through a
/// stand-in's own association, its datagrams leave where its answers come back. One that would leave by
/// the mapping's own association once the tool closed it, or opened it anew since `socket`, leaves
/// nothing yet: it is routed again, and waits for that association as it is now.
fn leave_by(
    table: &mut UdpTable,
    ((app, destination), id): ((SocketAddr, SocketAddr), u64),
    (way, wanted, socket, (opened, refused)): (
        PeerWay,
        &Wanted,
        Arc<UdpSocket>,
        (Option<OwnOpened>, bool),
    ),
    (shared, reads, errors): (&Shared, &mut Vec<Option<QuicRead>>, &mut Vec<Vec<u8>>),
) -> Leaving {
    let key = (app, destination);
    if opened.is_some()
        && let Some(mapping) = table.mapping(app, id)
    {
        mapping.owns_opening = mapping.owns_opening.saturating_sub(1);
    }
    if let Some(made) = still_open(table, (app, id), shared) {
        return Leaving::Made(made);
    }
    let Some(mapping) = table.mapping(app, id) else {
        return Leaving::Made(Made::Done);
    };
    let existing = mapping.peers.get(&destination).map(|peer| peer.via);
    let alone = !mapping.main_open && mapping.owns() == 0;
    let own = match (existing, opened) {
        (Some(_), _) | (None, None) => None,
        (None, Some((Err(error), _))) => {
            // Its mapping's own association closed meanwhile, and nothing else of it is open or opening:
            // it ends now, as when its last association ends (fix round 3).
            if alone {
                table.end(app, id, shared);
            }
            return Leaving::Failed(error);
        }
        (None, Some((Ok((out, control)), places))) => Some((Arc::new(out), control, places)),
    };
    let by_main = own.is_none() && !matches!(existing, Some(Some(_)));
    if by_main && !(mapping.main_open && Arc::ptr_eq(&socket, &mapping.socket)) {
        return Leaving::Made(Made::Reroute);
    }
    let settled = table.settle(key, wanted.uid, shared.limits.udp_reask);
    count_drops(shared, settled.drops());
    if settled.leave.is_empty() {
        // Nothing left to leave, the association opened for it goes; a mapping whose own association
        // closed meanwhile then has nothing open, and ends now (fix round 4, review G's G7).
        drop(own);
        if let Some(mapping) = table.mapping(app, id)
            && !mapping.main_open
            && mapping.owns() == 0
        {
            table.end(app, id, shared);
        }
        return Leaving::Made(Made::Done);
    }
    let own = own.map(|own| {
        table.opened += 1;
        (table.opened, own)
    });
    let Some(mapping) = table.mapping(app, id) else {
        return Leaving::Made(Made::Done);
    };
    let now = Instant::now();
    mapping.answering(destination);
    if existing.is_none() && own.is_none() && refused {
        Counters::add(&shared.counters.udp_own_refused, 1);
    }
    let (via, out, task) = match (existing, own) {
        (Some(Some(number)), _) => match mapping.owns.get(&number) {
            Some(own) => (Some(number), Arc::clone(&own.socket), None),
            None => return Leaving::Made(Made::Done),
        },
        (_, Some((number, (out, control, places)))) => {
            let ended = Arc::new(Notify::new());
            mapping.owns.insert(
                number,
                Own {
                    socket: Arc::clone(&out),
                    sources: Sources::default(),
                    ended: Arc::clone(&ended),
                    _places: places,
                },
            );
            let task = MappingTask {
                app,
                id,
                uid: wanted.uid,
                socket: Arc::clone(&out),
                control: Some(control),
                ended,
                reopened: None,
            };
            (Some(number), out, Some((number, task)))
        }
        _ => (None, socket, None),
    };
    if let Some(scope) = mapping.scope(via) {
        scope.into_peer(shared, key, now, (false, way));
    }
    send_waiting(
        mapping,
        (destination, &out),
        &settled.leave,
        (shared, reads, errors),
    );
    Leaving::Left(task)
}

/// Sends the datagrams that waited for `destination`, a peer of `mapping` now, by `out`, its
/// association's socket ([`leave_by`]): each noted as the peer's, its QUIC reads and the errors for the
/// app gathered for after the table's lock.
fn send_waiting(
    mapping: &mut Mapping,
    (destination, out): (SocketAddr, &UdpSocket),
    leave: &[Held],
    (shared, reads, errors): (&Shared, &mut Vec<Option<QuicRead>>, &mut Vec<Vec<u8>>),
) {
    let Some(header) = mapping
        .peers
        .get(&destination)
        .map(|peer| peer.way.header.clone())
    else {
        return;
    };
    for Waiter { item: packet, .. } in leave {
        let Ok(parsed) = packet::parse(packet) else {
            continue;
        };
        let Some(payload) = packet::udp_payload(packet, &parsed) else {
            continue;
        };
        mapping.sent(destination, payload);
        let Some(peer) = mapping.peers.get_mut(&destination) else {
            return;
        };
        reads.push(read_quic(&mut peer.quic, payload));
        let sent = try_send_to(out, header.as_deref(), payload, (destination, parsed.hops));
        if sent.is_ok() {
            peer.left(Sent::of(packet, parsed.transport));
        }
        errors.extend(count_sent(
            shared,
            peer.bytes.as_deref(),
            packet,
            &parsed,
            sent,
        ));
    }
}

/// What a destination does once the mapping `id` of `app` it waited for is open, if not to go on: the
/// mapping ended meanwhile, as the network changed or an answer named another app, and what waits is
/// decided again, by the rule, as it would be had it come now (eighth review of unit 9, finding 6); or
/// the chain took the app, or let it go, since its route was asked, and what waited, some of it sent
/// since, leaves by the new route.
fn still_open(table: &mut UdpTable, (app, id): (SocketAddr, u64), shared: &Shared) -> Option<Made> {
    match table
        .mapping(app, id)
        .map(|mapping| mapping.keeps_its_way(shared))
    {
        None => Some(Made::Done),
        Some(false) => {
            table.end(app, id, shared);
            Some(Made::Reroute)
        }
        Some(true) => None,
    }
}

/// Whether a new stand-in needs an association of its own ([`UdpTable::own_wanted`]).
enum OwnWanted {
    /// It leaves by the mapping's.
    No,
    /// It would, but a cap, or the budget, refuses one: it leaves by the mapping's, under unit 9's floor.
    Refused,
    /// It does, through this tool, with its place in the budget and under `Limits::udp_own_relays`.
    Place(Arc<Chain>, (Place, Place)),
}

/// Relays what comes back on an association of a stand-in's own (ADR 0044, unit 9b) to the app, each
/// answer from the peer of that association its header names, until it is ended from elsewhere (its
/// stand-in's flow ended, silent for `Limits::udp_idle`, or its mapping did), the network beneath
/// changes, or the tool ends it. Its stand-in's flow, and those that came in through it, end with it:
/// the app's next datagram to the stand-in is decided anew. What only comes in asks Android again as
/// what comes in through the mapping's own association does.
async fn own_relayed(
    (task, own): (MappingTask, u64),
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
        ..
    } = task;
    // The tool keeps the relay for as long as the request's connection is open.
    let mut closed = std::pin::pin!(async {
        let mut byte = [0u8; 1];
        match control.as_mut() {
            Some(control) => while matches!(control.read(&mut byte).await, Ok(n) if n > 0) {},
            None => std::future::pending::<()>().await,
        }
    });
    // Only a change after it opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    loop {
        tokio::select! {
            _ = changes.changed() => break,
            () = ended.notified() => break,
            () = &mut closed => break,
            ready = socket.ready(Interest::READABLE | Interest::ERROR) => {
                if !ready.is_ok_and(|ready| !ready.is_read_closed()) {
                    break;
                }
                let _ = errors::take(&socket, &mut []);
                let ends = ((app, id, uid), Some(own));
                let (packets, end, from) = with_buffer(|buffer| {
                    relayed_receive(&socket, buffer, ends, &shared, &flows)
                });
                let reask = shared.limits.udp_reask;
                if let Some(from) = from
                    && let Some(asking) = lock(&flows).came_in((app, id), Instant::now(), reask)
                {
                    spawn_question((app, from), asking, &shared, &flows);
                }
                for packet in packets {
                    send_to_app(&tun, &shared, &packet).await;
                }
                if end {
                    break;
                }
            }
        }
    }
    let mut table = lock(&flows);
    let alone = table.mapping(app, id).is_some_and(|mapping| {
        mapping.end_own(own, &shared);
        !mapping.main_open && mapping.owns() == 0
    });
    // Its mapping's own association closed before it: nothing of the mapping is left open.
    if alone {
        table.end(app, id, &shared);
    }
}

/// The way to `key`'s destination for a mapping that leaves as `wanted` says. A stand-in the map no
/// longer holds names nothing the tool could reach, unless a peer of the same app's mapping still stands
/// for it: a live peer keeps its way when its name gives way in the map to newer ones, which the
/// mapping's own datagrams do not keep in use (sixth review of unit 9, finding 7). Another app that took
/// the socket's port gets no name from the old app's peers (seventh review, finding 4).
fn way_toward(
    (app, destination): (SocketAddr, SocketAddr),
    wanted: &Wanted,
    shared: &Shared,
    flows: &UdpFlows,
) -> Option<PeerWay> {
    PeerWay::toward(shared, &wanted.exit, destination).or_else(|| {
        let table = lock(flows);
        let mapping = table
            .mappings
            .get(&app)
            .filter(|mapping| mapping.uid == wanted.uid)?;
        Some(mapping.peers.get(&destination)?.way.clone())
    })
}

/// What a new destination of an app socket does about the socket's mapping.
enum Turn {
    /// It found the mapping open, or failed as the destination that opened it did, or was refused.
    Done(io::Result<Mapped>),
    /// It opens one, with its place in the budget, telling those that wait for it how it went if it
    /// is the first of its app to open one now; or opens anew the association of the one there, which
    /// holds its place already.
    Open(Option<watch::Sender<Option<io::ErrorKind>>>, Option<Place>),
}

/// Whether a new destination of `app`'s socket opens the socket's mapping, as [`mapping_for`] says, or
/// waits for the one of its app that opens it now. A new mapping holds a socket of its own, and so a
/// place in the budget, taken before the socket is made: where the cap for every app, or the app's
/// share, is full, it is refused (ADR 0044, decision 3).
async fn turn(
    (app, destination): (SocketAddr, SocketAddr),
    wanted: &Wanted,
    shared: &Shared,
    flows: &UdpFlows,
) -> Turn {
    loop {
        let mut waiting = {
            let mut table = lock(flows);
            let reopen = match table.open_mapping((app, destination), wanted, shared) {
                Current::Same(id, socket) => return Turn::Done(Ok(Mapped::Open(id, socket))),
                Current::Closed => true,
                Current::Gone => false,
            };
            let first = match table.opening.get(&app) {
                // One whose opener is gone without a word (the engine stopping) holds no one up.
                Some((uid, waiting)) if waiting.has_changed().is_ok() => {
                    if *uid == wanted.uid {
                        Err(waiting.clone())
                    } else {
                        // Another app's opener, as the port was handed over: its tool's failure, or its
                        // wait, is none of this app's, which opens its own (eighth review of unit 9,
                        // finding 5).
                        Ok(false)
                    }
                }
                _ => Ok(true),
            };
            match first {
                Err(waiting) => waiting,
                Ok(first) => {
                    let place = if reopen {
                        None
                    } else {
                        let Some(place) = table.room(wanted.uid, shared) else {
                            return Turn::Done(Ok(Mapped::Refused));
                        };
                        Some(place)
                    };
                    let told = first.then(|| {
                        let (told, waiting) = watch::channel(None);
                        table.opening.insert(app, (wanted.uid, waiting));
                        told
                    });
                    return Turn::Open(told, place);
                }
            }
        };
        let _ = waiting.changed().await;
        let failed = *waiting.borrow();
        if let Some(kind) = failed {
            return Turn::Done(Err(kind.into()));
        }
    }
}

/// The mapping of `key`'s app for its new destination, by its number, with its socket: the app's open
/// one, or a new one when it has none, or when the one it has is another app's or leaves another way.
/// Through the tool, a new one is a new `UDP ASSOCIATE`.
///
/// One destination of an app socket opens its mapping while the others that come meanwhile wait for
/// it, as when an app asks several servers at once: through the tool, each would otherwise ask for a
/// relay of its own, a connection to the tool, only for all but one to be closed again. When the one
/// that opens it fails, those that wait fail as it did, at once: the tool that refused it, or did not
/// answer it, would do the same to them.
async fn mapping_for(
    (app, destination): (SocketAddr, SocketAddr),
    wanted: &Wanted,
    (tun, shared, flows, changes): Context<'_>,
) -> io::Result<Mapped> {
    let (told, place) = match turn((app, destination), wanted, shared, flows).await {
        Turn::Done(done) => return done,
        Turn::Open(told, place) => (told, place),
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
    if told.is_some() {
        table.opening.remove(&app);
    }
    let (socket, control) = match made {
        Ok(made) => made,
        Err(error) => {
            if let Some(told) = &told {
                let _ = told.send(Some(error.kind()));
            }
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
        return Ok(Mapped::Reroute);
    }
    // A mapping opens only for the app the newest answer about the socket names: one of an app that
    // has since lost the port carries nothing (eighth review of unit 9, finding 1).
    if !table.keeps(app, wanted.uid) {
        return Ok(Mapped::Stale);
    }
    // Those that waited find this one once the lock is let go, and `told` goes with this function.
    match table.open_mapping((app, destination), wanted, shared) {
        Current::Same(id, socket) => return Ok(Mapped::Open(id, socket)),
        Current::Closed => return Ok(reopened(&mut table, app, (socket, control))),
        Current::Gone => {}
    }
    // The mapping that was to be opened anew is gone meanwhile: a new one takes a place of its own.
    let place = match place {
        Some(place) => place,
        None => match table.room(wanted.uid, shared) {
            Some(place) => place,
            None => return Ok(Mapped::Refused),
        },
    };
    table.opened += 1;
    let id = table.opened;
    let ended = Arc::new(Notify::new());
    let (reopened, relays) = mpsc::unbounded_channel();
    let now = Instant::now();
    table.recent.insert(wanted.uid, (now, id, app, wanted.uid));
    table.sockets.entry(app).or_default();
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
            last: now,
            seen: now,
            ended: Arc::clone(&ended),
            _place: place,
            owns: BTreeMap::new(),
            owns_opening: 0,
            main_open: true,
            reopened,
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
            reopened: Some(relays),
        },
        Arc::clone(tun),
        Arc::clone(shared),
        Arc::clone(flows),
        changes.clone(),
    ));
    Ok(Mapped::Open(id, socket))
}

/// The own association of `app`'s mapping, opened anew with `socket` and the request's connection
/// `control`, for the mapping, whose task takes the relay (ADR 0044, unit 9b, fix round 1).
fn reopened(
    table: &mut UdpTable,
    app: SocketAddr,
    (socket, control): (Arc<UdpSocket>, Option<TcpStream>),
) -> Mapped {
    let (Some(mapping), Some(control)) = (table.mappings.get_mut(&app), control) else {
        return Mapped::Stale;
    };
    mapping.socket = Arc::clone(&socket);
    mapping.main_open = true;
    let _ = mapping.reopened.send((Arc::clone(&socket), control));
    Mapped::Open(mapping.id, socket)
}

/// The mapping a new destination of an app socket gets.
enum Mapped {
    /// The app's open one, or a new one: its number and socket.
    Open(u64, Arc<UdpSocket>),
    /// None: the chain changed the app's way meanwhile.
    Reroute,
    /// None: the newest answer about the socket names another app than the destination's.
    Stale,
    /// None: the cap for every app, or the app's share, is full.
    Refused,
}

/// A mapping's socket on the direct path: protected, on the unspecified address of the destination's
/// IP version and a port the kernel picks, not connected, with the ICMP errors that answer its
/// datagrams queued, and the hop limit of each datagram it reads given.
async fn mapped_socket(shared: &Arc<Shared>, destination: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(packet::unspecified_like(&destination)).await?;
    protect(shared, socket.as_fd()).await?;
    // Without the queue, the errors are lost, as most userspace NATs lose them; the mapping still works.
    let _ = errors::keep(&socket, destination.is_ipv4());
    // Without it, the answers reach the app with the engine's own hop limit, as before unit 11b.
    let _ = hops::ask(&socket, destination.is_ipv4());
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
pub(super) fn on_the_phone(relay: SocketAddr) -> bool {
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
    /// For a mapping through the tool, the relays of its own association opened anew.
    reopened: Option<mpsc::UnboundedReceiver<Relay>>,
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
        control,
        ended,
        reopened,
    } = task;
    let through_tool = control.is_some();
    let mut reopened = reopened;
    // Its own association, while it is open: the socket, and through the tool the request's connection,
    // which the tool keeps open for as long as it keeps the relay.
    let mut relay = Some((socket, control));
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
            // With its own association closed, it lives only while one of a stand-in's own does.
            if !mapping.main_open && mapping.owns() == 0 {
                break;
            }
            mapping.last
        };
        let silent = last + idle;
        if now >= silent {
            break;
        }
        let wake = if let Some((socket, control)) = relay.as_mut() {
            tokio::select! {
                _ = changes.changed() => Wake::End,
                () = ended.notified() => Wake::End,
                () = until_closed(control) => Wake::Closed,
                () = tokio::time::sleep_until(silent.into()) => Wake::Again,
                ready = socket.ready(Interest::READABLE | Interest::ERROR) => {
                    if ready.is_ok_and(|ready| !ready.is_read_closed()) {
                        let queued = errors::take(socket, &mut []);
                        let ends = (app, id, uid);
                        // A network that moved ends the mapping: what its socket read meanwhile, a
                        // router's error about the old network's path among it, is not passed on after
                        // the move.
                        let moved = || network_moved(&changes);
                        let (packets, end, from) = with_buffer(|buffer| {
                            if through_tool {
                                relayed_receive(socket, buffer, (ends, None), &shared, &flows)
                            } else {
                                mapped_receive(socket, buffer, ends, (queued, &moved), &shared, &flows)
                            }
                        });
                        let reask = shared.limits.udp_reask;
                        if let Some(from) = from
                            && let Some(asking) = lock(&flows).came_in((app, id), Instant::now(), reask)
                        {
                            spawn_question((app, from), asking, &shared, &flows);
                        }
                        for packet in packets {
                            send_to_app(&tun, &shared, &packet).await;
                        }
                        if end { Wake::Closed } else { Wake::Again }
                    } else {
                        Wake::Closed
                    }
                }
            }
        } else {
            tokio::select! {
                _ = changes.changed() => Wake::End,
                () = ended.notified() => Wake::End,
                () = tokio::time::sleep_until(silent.into()) => Wake::Again,
                anew = next_relay(&mut reopened) => match anew {
                    Some((socket, control)) => Wake::Reopened(socket, control),
                    None => Wake::End,
                },
            }
        };
        match wake {
            Wake::Again => {}
            Wake::End => break,
            Wake::Reopened(socket, control) => relay = Some((socket, Some(control))),
            // On the direct path, a socket that fails ends the mapping. Through the tool, its relay ended:
            // only what left by it ends, while an association of a stand-in's own lives (ADR 0044, unit
            // 9b, fix round 1); the next datagram that needs it opens it anew.
            Wake::Closed => {
                if !through_tool || lock(&flows).close_main(app, id, &shared) {
                    break;
                }
                relay = None;
            }
        }
    }
    lock(&flows).end(app, id, &shared);
}

/// What woke a mapping's task.
enum Wake {
    /// Nothing that ends anything: it looks again.
    Again,
    /// The mapping ends.
    End,
    /// Its own association's relay, or its socket, ended.
    Closed,
    /// Its own association was opened anew.
    Reopened(Arc<UdpSocket>, TcpStream),
}

/// Until the tool closes `control`, the connection that keeps a relay, ending it; never for none, on
/// the direct path. Reading is cancel-safe, so it is waited for anew at each turn.
async fn until_closed(control: &mut Option<TcpStream>) {
    let mut byte = [0u8; 1];
    match control.as_mut() {
        Some(control) => while matches!(control.read(&mut byte).await, Ok(n) if n > 0) {},
        None => std::future::pending::<()>().await,
    }
}

/// The next relay a mapping's own association was opened anew with; never on the direct path.
async fn next_relay(reopened: &mut Option<mpsc::UnboundedReceiver<Relay>>) -> Option<Relay> {
    match reopened.as_mut() {
        Some(reopened) => reopened.recv().await,
        None => std::future::pending().await,
    }
}

/// What a mapping on the direct path lets in now: for each ICMP error `queued` for its datagrams, the
/// error for the app about its datagram to the peer it is for, from the router or host that sent it;
/// then what its socket holds, read into `buffer`, each datagram from the peer that sent it. A datagram
/// from an address the app did not send to is dropped and counted. `true` when the mapping ends: it is
/// gone, or its socket failed, or the network beneath `moved` while it read, and then nothing it read
/// is passed on, nor counted (second review of unit 12, minor 4b).
fn mapped_receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    ends: (SocketAddr, u64, Option<u32>),
    (queued, moved): (Vec<Queued>, &dyn Fn() -> bool),
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool, Option<SocketAddr>) {
    // Every way out of the reading passes here, so that what it read is checked against a move, and
    // the errors from the path it passes on are counted, however it ended (second review, minor 6).
    let Read {
        packets,
        end,
        from_last,
        told,
    } = read_mapped(socket, buffer, ends, queued, shared, flows);
    if moved() {
        return (Vec::new(), true, None);
    }
    told.count(&shared.counters, false);
    (packets, end, from_last)
}

/// Whether the network beneath moved since a mapping or a ping socket opened, by its copy of the
/// network's watch, which saw the generation of then: what it read since is not passed on. A watch
/// whose sender is gone, as when the engine stops, counts as moved.
pub(super) fn network_moved(changes: &watch::Receiver<u64>) -> bool {
    changes.has_changed().unwrap_or(true)
}

/// What [`read_mapped`] read: the packets for the app, whether the mapping ends, the peer the last
/// datagram came from, and the errors from the path it passed on or dropped.
struct Read {
    packets: Vec<Vec<u8>>,
    end: bool,
    from_last: Option<SocketAddr>,
    told: Tally,
}

/// What [`mapped_receive`] reads, before the check against a move.
fn read_mapped(
    socket: &UdpSocket,
    buffer: &mut [u8],
    (app, id, uid): (SocketAddr, u64, Option<u32>),
    queued: Vec<Queued>,
    shared: &Shared,
    flows: &UdpFlows,
) -> Read {
    let mut read = Read {
        packets: Vec::new(),
        end: false,
        from_last: None,
        told: Tally::default(),
    };
    let ended = |mut read: Read| {
        read.end = true;
        read
    };
    for error in queued {
        let destination = error.destination;
        let (bytes, sent) = match lock(flows).mapping(app, id) {
            None => return ended(read),
            Some(mapping) => {
                // While a chain sends the app elsewhere, nothing comes in on its direct path: its
                // errors neither.
                if !mapping.keeps_its_way(shared) {
                    return ended(read);
                }
                // One error at most for each datagram the app sent the destination (ADR 0044, unit
                // 11b): none for a destination the mapping never sent to, as a forged one would be.
                let Some(peer) = mapping.peers.get_mut(&destination) else {
                    read.told.dropped();
                    continue;
                };
                let Some(sent) = peer.takes_error() else {
                    read.told.dropped();
                    continue;
                };
                (peer.bytes.clone(), sent)
            }
        };
        // A router's "time exceeded", "fragmentation needed" or "packet too big" (with its MTU), and an
        // unreachable with its code, reach the app from whoever sent them, as without Watch (ADR 0044,
        // decision 5 as amended, and unit 11b). One for which no error to the app can be built is
        // dropped, and counted.
        match told_to((app, destination), &error, &sent) {
            Some(packet) => {
                if let Some(bytes) = &bytes {
                    bytes.add_wire_down(packet.len());
                }
                read.told.passed(error.told);
                read.packets.push(packet);
            }
            None => read.told.dropped(),
        }
    }
    let mut control = hops::room();
    for _ in 0..BATCH {
        let (n, from, arrived) = match hops::try_recv(socket, buffer, &mut control) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // An ICMP error, which this read took: the error queue says which destination it was for.
            Err(error) if errors::from_icmp(&error) => continue,
            Err(_) => return ended(read),
        };
        let (bytes, learns) = match lock(flows).let_in((app, id), (from, &buffer[..n]), shared) {
            LetIn::Gone => return ended(read),
            LetIn::Filtered => {
                Counters::add(&shared.counters.udp_filtered, 1);
                continue;
            }
            LetIn::Unmatched => {
                Counters::add(&shared.counters.udp_unmatched, 1);
                continue;
            }
            LetIn::Unidentified => {
                Counters::add(&shared.counters.udp_unidentified, 1);
                continue;
            }
            LetIn::Capped => {
                Counters::add(&shared.counters.udp_came_in_capped, 1);
                continue;
            }
            LetIn::Peer(shown, bytes, learns) => {
                read.from_last = Some(shown);
                (bytes, learns)
            }
        };
        read.packets.extend(deliver(
            shared,
            (app, uid),
            (from, &buffer[..n], arrived),
            bytes.as_deref(),
            learns,
        ));
    }
    read
}

/// What a mapping through the tool lets in now on its association `via`, its own or a stand-in's own:
/// each answer its relay holds, read into `buffer`, from the peer its header names (ADR 0044, decision
/// 2). An answer from an address the app did not send to is dropped and counted, as on the direct path;
/// so is one for which no one peer can be told. `true` when the association ends: it is gone, or its
/// relay is (the tool closed it, or stopped), and the app's next datagram asks the tool for another.
fn relayed_receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    ((app, id, uid), via): ((SocketAddr, u64, Option<u32>), Option<u64>),
    shared: &Shared,
    flows: &UdpFlows,
) -> (Vec<Vec<u8>>, bool, Option<SocketAddr>) {
    let mut packets = Vec::new();
    let mut from_last = None;
    for _ in 0..BATCH {
        let n = match socket.try_recv(buffer) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return (packets, true, from_last),
        };
        // A header that is not well formed, or a fragment, which Watch drops as RFC 1928 allows, names
        // no peer.
        let Some((target, answer)) = socks5::parse_datagram(&buffer[..n]) else {
            Counters::add(&shared.counters.udp_unmatched, 1);
            continue;
        };
        let (from, bytes, learns) =
            match lock(flows).let_in_relayed((app, id), via, (&target, answer), shared) {
                LetIn::Gone => return (packets, true, from_last),
                LetIn::Filtered => {
                    Counters::add(&shared.counters.udp_filtered, 1);
                    continue;
                }
                LetIn::Unmatched => {
                    Counters::add(&shared.counters.udp_unmatched, 1);
                    continue;
                }
                LetIn::Unidentified => {
                    Counters::add(&shared.counters.udp_unidentified, 1);
                    continue;
                }
                LetIn::Capped => {
                    Counters::add(&shared.counters.udp_came_in_capped, 1);
                    continue;
                }
                LetIn::Peer(from, bytes, learns) => {
                    from_last = Some(from);
                    (from, bytes, learns)
                }
            };
        // The relay's datagram crossed only the phone: the answer keeps the engine's own hop limit.
        packets.extend(deliver(
            shared,
            (app, uid),
            (from, answer, None),
            bytes.as_deref(),
            learns,
        ));
    }
    (packets, false, from_last)
}

/// An `answer` a mapping let in from the peer the app knows as `from`: counted, and wrapped in an IP
/// packet to the app, with the hop limit it `arrived` with where the kernel gave one (ADR 0044, unit
/// 11b). Watch learns names from it when it `learns`.
fn deliver(
    shared: &Shared,
    (app, uid): (SocketAddr, Option<u32>),
    (from, answer, arrived): (SocketAddr, &[u8], Option<u8>),
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
    let mut packet = packet::udp(from, app, answer)?;
    if let Some(hops) = arrived {
        packet::set_hops(&mut packet, hops);
    }
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

/// An error from the path for the app at `app`, about its datagram to `destination`, from the router or
/// host that sent it, as without Watch, or from the destination where the kernel names no sender (ADR
/// 0044, unit 11b; before, every one came as if from the destination). It quotes the app's last
/// datagram there, `sent`, as a router does: its IP header as the app sent it, with the hop limit the
/// router found (1 for "time exceeded"), and its UDP header, by whose ports the app's kernel finds its
/// socket; its payload, as before, not at all. The app's kernel takes a "packet too big" for the path to
/// the destination whoever reports it.
fn told_to(
    (app, destination): (SocketAddr, SocketAddr),
    error: &Queued,
    sent: &Sent,
) -> Option<Vec<u8>> {
    let expired = error.told == Told::TimeExceeded;
    let quoted = packet::quoted(sent, (app.ip(), destination.ip()), UDP, expired, &[])?;
    let from = errors::sender(error.offender, destination.ip(), destination.ip());
    errors::to_app(error.told, &quoted, (from, app.ip()), error.hops)
}

/// Opens a flow of lookups to Watch's own DNS address for the app `uid`, whose its first lookup that
/// waits is, by the rule: the network's resolver's way, or Watch's own answers for a chained app. Those
/// the rule says the app sent go by it; those it drops are dropped and counted; from the first of
/// another app's, or undecided, all wait on, and the flow then gives way at once, still handing the app
/// the answers it owes. It opens only for the app the newest answer about the socket names.
async fn open_lookups(
    key: (SocketAddr, SocketAddr),
    uid: Option<u32>,
    (tun, shared, flows, changes): Context<'_>,
) -> Made {
    let (app, destination) = key;
    // Read before the route, so that a chain set meanwhile is seen below.
    let chains = shared.chains.load(Ordering::Acquire);
    let route = shared.route(uid, destination);
    // On the direct path a flow of lookups holds a socket of its own, and so a place in the budget, for
    // as long as it waits for answers; a chained app's lookups, which Watch answers, hold none.
    let place = if let Route::Direct = route {
        let room = lock(flows).room(uid, shared);
        let Some(place) = room else {
            refused(key, uid, shared, flows);
            return Made::Done;
        };
        Some(place)
    } else {
        None
    };
    let (opened, mut flow) = begin_udp(shared, app, destination, uid);
    let id = opened.id;
    let way = match way_for(shared, route, destination).await {
        Ok(way) => way,
        Err(error) => {
            flow.outcome = if is_unreachable(&error) {
                Outcome::Unreachable
            } else {
                Outcome::Failed
            };
            udp_failed(key, flow, tun, shared, flows).await;
            return Made::Done;
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
            return Made::Reroute;
        }
        // What the rule says the app sent leaves; if Android named another app, or none, while the way
        // was made, nothing does, the flow does not open, and what waits is decided again (seventh and
        // eighth reviews of unit 9, finding 1).
        let settled = table.settle(key, uid, shared.limits.udp_reask);
        count_drops(shared, settled.drops());
        if settled.leave.is_empty() {
            table.forget(app);
            return Made::Done;
        }
        shared.record(flow);
        let open = UdpFlow {
            id,
            way: way.clone(),
            uid,
            owed: Arc::clone(&owed),
            chains: now,
        };
        for Waiter { item: packet, .. } in &settled.leave {
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
        // What waits on is decided again; this flow then gives way to the next.
        if table.first_held(key).is_none() {
            table.put(key, UdpEntry::Open(open));
        }
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
        (way, place),
        questions,
        (key, uid, (id, owed)),
        (tun, shared, flows, changes),
    );
    Made::Done
}

/// Starts answering a new flow of lookups: Watch answers a chained app's itself, each in a task of its
/// own; the network's resolver answers the others, which a task hands the app. The flow ends when none
/// of its lookups waits any more.
fn start_answers(
    (way, place): (UdpWay, Option<Place>),
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
                    _place: place,
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
    let uid = flow.uid;
    shared.record(flow);
    // Only what the rule says that app sent fails with it; another app's waits on.
    let waiting = {
        let mut table = lock(flows);
        let settled = table.settle(key, uid, shared.limits.udp_reask);
        table.forget(key.0);
        count_drops(shared, settled.drops());
        settled.leave
    };
    let error =
        waiting
            .first()
            .filter(|_| unreachable)
            .and_then(|Waiter { item: first, .. }| {
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
    /// Its socket's place in the budget for its app, given back as its last answer comes.
    _place: Option<Place>,
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
                let _ = errors::take(&socket, &mut []);
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
        ..
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
    use super::super::errors::Told;
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
            seen: now,
            ended: Arc::new(Notify::new()),
            _place: super::super::budget::Budget::new(1, 1)
                .take(None)
                .map_err(|_| io::ErrorKind::OutOfMemory)?,
            owns: BTreeMap::new(),
            owns_opening: 0,
            main_open: true,
            reopened: mpsc::unbounded_channel().0,
        })
    }

    /// Two destinations the app knows.
    const ASKER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 443);
    const OTHER: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)), 443);

    /// The tunnel's DNS address, at port 53.
    fn dns() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(super::super::Addresses::COMMON.dns4), 53)
    }

    /// A table whose app socket has a mapping of the app `uid`, which knows [`ASKER`] and [`OTHER`],
    /// opened on Android's answer naming `uid` when asked at `asked`.
    async fn table_of(shared: &Shared, uid: Option<u32>, asked: Instant) -> io::Result<UdpTable> {
        let mut mapping = mapping(asked).await?;
        mapping.uid = uid;
        for peer in [ASKER, OTHER] {
            mapping.peer(shared, (APP, peer), asked, (false, PeerWay::direct(peer)));
        }
        let mut table = UdpTable::default();
        table.mappings.insert(APP, mapping);
        table.sockets.entry(APP).or_default();
        table.answered(APP, (1, Named { uid, asked }), shared);
        Ok(table)
    }

    /// An open flow of lookups of the app `uid`, numbered `id`, on the network's resolver's way.
    async fn lookup_flow(uid: Option<u32>, id: u64) -> io::Result<UdpEntry> {
        Ok(UdpEntry::Open(UdpFlow {
            id,
            way: UdpWay::Direct(Arc::new(UdpSocket::bind("127.0.0.1:0").await?)),
            uid,
            owed: Arc::default(),
            chains: 0,
        }))
    }

    /// A mapping's datagram passes by it as the one rule says, to the nanosecond: less than
    /// `udp_reask` after the answer it was opened on; while the app never pauses for that long, until
    /// thirty times it; and not after a pause (ADR 0044, the windows; eighth review of unit 9, finding
    /// 2).
    #[tokio::test(flavor = "current_thread")]
    async fn a_mapping_passes_datagrams_as_the_rule_says() -> io::Result<()> {
        let shared = shared();
        let reask = shared.limits.udp_reask;
        let asked = Instant::now();
        let nano = Duration::from_nanos(1);
        let tick = packet::udp(APP, OTHER, b"tick").unwrap_or_default();
        let Ok(parsed) = packet::parse(&tick) else {
            unreachable!("not parsed")
        };
        let passes = |table: &mut UdpTable, at: Instant| {
            table
                .toward_peer((APP, OTHER), (&tick, &parsed, b"tick"), at, &shared)
                .is_some()
        };
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        assert!(!passes(&mut table, asked + reask), "after a pause");
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        assert!(passes(&mut table, asked + reask.saturating_sub(nano)));
        // A stream a twentieth of `udp_reask` apart passes until thirty times it, not at it.
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        let step = reask / 20;
        let first = (1..=20 * 40)
            .map(|tick| asked + step * tick)
            .find(|&at| !passes(&mut table, at));
        assert_eq!(first.map(|at| at.duration_since(asked)), Some(reask * 30));
        Ok(())
    }

    /// The same for a lookup on an open flow of lookups, whose window the one rule now gives (eighth
    /// review of unit 9, finding 4): it passes a nanosecond before `udp_reask` after the answer, not at
    /// it, and a stream of lookups until thirty times it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_flow_of_lookups_passes_lookups_as_the_rule_says() -> io::Result<()> {
        let shared = shared();
        let reask = shared.limits.udp_reask;
        let asked = Instant::now();
        let nano = Duration::from_nanos(1);
        let key = (APP, dns());
        for (at, passes) in [
            (asked + reask.saturating_sub(nano), true),
            (asked + reask, false),
        ] {
            let mut table = table_of(&shared, Some(10_077), asked).await?;
            table.put(key, lookup_flow(Some(10_077), 2).await?);
            assert_eq!(table.lookup_passes(key, at, &shared), passes, "at {at:?}");
        }
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        table.put(key, lookup_flow(Some(10_077), 2).await?);
        let step = reask / 20;
        let first = (1..=20 * 40)
            .map(|tick| asked + step * tick)
            .find(|&at| !table.lookup_passes(key, at, &shared));
        assert_eq!(first.map(|at| at.duration_since(asked)), Some(reask * 30));
        // Another app's flow passes nothing, whatever the time.
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        table.put(key, lookup_flow(Some(10_078), 2).await?);
        assert!(!table.lookup_passes(key, asked, &shared));
        Ok(())
    }

    /// An answer naming another app ends the socket's mapping at once: the next datagram is decided
    /// again (sixth review of unit 9, finding 2).
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_naming_another_app_ends_the_mapping() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        let key = (APP, OTHER);
        table.put(
            key,
            UdpEntry::Opening(Holding {
                floor: None,
                held: vec![Waiter {
                    came: asked,
                    then: None,
                    item: Vec::new(),
                }],
            }),
        );
        table.answered(APP, (2, Named { uid: None, asked }), &shared);
        assert!(!table.mappings.contains_key(&APP));
        let after = packet::udp(key.0, key.1, b"after").unwrap_or_default();
        let Ok(parsed) = packet::parse(&after) else {
            unreachable!("not parsed")
        };
        let datagram = (after.as_slice(), &parsed, &b"after"[..]);
        assert!(table.toward_peer(key, datagram, asked, &shared).is_none());
        Ok(())
    }

    /// An answer touches only the socket's own ways, and only when it names another app than theirs:
    /// 20,000 answers naming the app of 20,000 open flows of lookups look at none of them, and one
    /// naming another app ends each, and nothing else (eighth review of unit 9, finding 3).
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_touches_only_the_ways_it_ends() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let mut table = table_of(&shared, Some(10_077), asked).await?;
        let tool = Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 1080)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        });
        let flows = 20_000u16;
        for port in 1..=flows {
            let flow = UdpFlow {
                id: u64::from(port),
                way: UdpWay::Lookups(Arc::clone(&tool)),
                uid: Some(10_077),
                owed: Arc::default(),
                chains: 0,
            };
            table.put(
                (APP, SocketAddr::from(([10, 1, 10, 53], port))),
                UdpEntry::Open(flow),
            );
        }
        let other = SocketAddr::from(([10, 1, 10, 9], 40_001));
        table.put((other, dns()), lookup_flow(Some(10_077), 1).await?);
        let mut touched = 0;
        for id in 2..=u64::from(flows) + 1 {
            let named = Named {
                uid: Some(10_077),
                asked: Instant::now(),
            };
            touched += table.answered(APP, (id, named), &shared);
        }
        assert_eq!(touched, 0, "answers naming the ways' own app");
        let named = Named {
            uid: Some(10_078),
            asked: Instant::now(),
        };
        let touched = table.answered(APP, (u64::from(flows) + 2, named), &shared);
        assert_eq!(touched, usize::from(flows) + 1, "the flows and the mapping");
        assert!(
            !table.flows.keys().any(|(app, _)| *app == APP),
            "a flow of lookups left"
        );
        assert!(!table.mappings.contains_key(&APP));
        assert!(matches!(
            table.flows.get(&(other, dns())),
            Some(UdpEntry::Open(_))
        ));
        Ok(())
    }

    /// A mapping that ends leaves the ranks by which one is chosen to make room, so that they hold no
    /// more than the mappings open; a search that finds one of them out of date puts it in its place.
    #[tokio::test(flavor = "current_thread")]
    async fn a_mapping_that_ends_leaves_the_ranks() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let mut table = table_of(&shared, uid, asked).await?;
        let (id, seen) = table
            .mappings
            .get(&APP)
            .map(|mapping| (mapping.id, mapping.seen))
            .ok_or(io::ErrorKind::NotFound)?;
        table.recent.insert(uid, (seen, id, APP, uid));
        table.answered.insert(uid, (id, APP, uid));
        // Active since the ranks saw it: found out of date, and put in its place, but not quiet.
        let later = asked + Duration::from_secs(1);
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            mapping.last = later;
        }
        let quiet = shared.limits.udp_quiet;
        assert_eq!(table.least_recent(Of::App(uid), (later, quiet)), None);
        assert_eq!(table.recent.first(Of::All), Some((later, id, APP, uid)));
        assert_eq!(
            table.least_recent(Of::All, (later + quiet, quiet)),
            Some((APP, id))
        );
        table.end(APP, id, &shared);
        assert!(table.recent.all.is_empty() && table.recent.by_app.is_empty());
        assert!(table.answered.all.is_empty() && table.answered.by_app.is_empty());
        Ok(())
    }

    /// The record of the answers about an app socket goes with its last way: a destination that
    /// waited, and a mapping that ends (eighth review of unit 9, finding 4).
    #[tokio::test(flavor = "current_thread")]
    async fn a_socket_is_forgotten_with_its_last_way() -> io::Result<()> {
        let shared = shared();
        let mut table = UdpTable::default();
        let key = (APP, SocketAddr::from(([192, 0, 2, 9], 9)));
        let holding = || Holding {
            floor: None,
            held: vec![Waiter {
                came: Instant::now(),
                then: None,
                item: Vec::new(),
            }],
        };
        table.put(key, UdpEntry::Opening(holding()));
        let named = Named {
            uid: Some(10_077),
            asked: Instant::now(),
        };
        table.answered(APP, (1, named), &shared);
        assert!(
            table
                .sockets
                .get(&APP)
                .is_some_and(|socket| socket.record.newest().is_some())
        );
        table.take(key);
        assert!(!table.sockets.contains_key(&APP));
        let mut table = table_of(&shared, Some(10_077), Instant::now()).await?;
        assert!(table.sockets.contains_key(&APP));
        let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
        table.end(APP, id, &shared);
        assert!(
            !table.sockets.contains_key(&APP),
            "kept once the mapping ended"
        );
        Ok(())
    }

    /// What waits for a destination's way is sorted by the rule once a way is there: a datagram
    /// between two answers that name different apps is dropped, one of the app whose way it is
    /// leaves, and from one the answers do not decide yet all wait on (eighth review of unit 9,
    /// finding 1). The record keeps what what waits on needs.
    #[test]
    fn what_waits_is_sorted_by_the_rule() {
        let shared = shared();
        let reask = shared.limits.udp_reask;
        let base = Instant::now();
        let after = |ms| base + Duration::from_millis(ms);
        let mut table = UdpTable::default();
        let key = (APP, OTHER);
        let waiter = |came, item| Waiter {
            came,
            then: None,
            item,
        };
        let held = vec![
            waiter(base, vec![1]),
            waiter(after(70), vec![2]),
            waiter(after(3_000), vec![3]),
        ];
        table.put(key, UdpEntry::Opening(Holding { floor: None, held }));
        table.answered(
            APP,
            (
                1,
                Named {
                    uid: Some(10_077),
                    asked: after(1),
                },
            ),
            &shared,
        );
        table.answered(
            APP,
            (
                2,
                Named {
                    uid: Some(10_078),
                    asked: after(51),
                },
            ),
            &shared,
        );
        let settled = table.settle(key, Some(10_078), reask);
        let packets = |items: &[Held]| items.iter().map(|w| w.item[0]).collect::<Vec<_>>();
        let dropped: Vec<_> = settled
            .dropped
            .iter()
            .map(|(w, why)| (w.item[0], *why))
            .collect();
        assert_eq!(dropped, [(1, Verdict::Ambiguous)]);
        assert_eq!(packets(&settled.leave), [2]);
        assert_eq!(table.first_held(key), Some((after(3_000), None, None)));
        assert_eq!(
            table.sockets.get(&APP).map(Socket::earliest),
            Some(Some(after(3_000)))
        );
    }

    /// The datagram the rule dropped is the one taken from the queue, by when it came: one another
    /// task has taken already leaves the next in place (ninth review of unit 9, finding 6).
    #[test]
    fn only_the_datagram_decided_is_dropped() {
        let base = Instant::now();
        let after = |ms| base + Duration::from_millis(ms);
        let mut table = UdpTable::default();
        let key = (APP, OTHER);
        let waiter = |came| Waiter {
            came,
            then: None,
            item: Vec::new(),
        };
        let held = vec![waiter(base), waiter(after(70))];
        table.put(key, UdpEntry::Opening(Holding { floor: None, held }));
        assert!(!table.drop_held(key, after(5)));
        assert_eq!(table.first_held(key), Some((base, None, None)));
        assert!(table.drop_held(key, base));
        assert!(!table.drop_held(key, base));
        assert_eq!(table.first_held(key), Some((after(70), None, None)));
        assert!(table.drop_held(key, after(70)));
        assert_eq!(table.first_held(key), None);
    }

    /// A stand-in the map no longer holds keeps the way of the live peer that stands for it, but only
    /// for that peer's own app: another app that took the socket's port gets none (seventh review of
    /// unit 9, finding 4).
    #[tokio::test(flavor = "current_thread")]
    async fn only_the_same_app_keeps_a_live_stand_ins_way() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        mapping.uid = Some(10_077);
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        let flows = UdpFlows::default();
        lock(&flows).mappings.insert(APP, mapping);
        let tool = Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 1080)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        });
        let wanted = |uid| Wanted {
            uid: Some(uid),
            exit: Exit::Tool(Arc::clone(&tool)),
            chains: 0,
        };
        let name = |uid| way_toward((APP, stand_in), &wanted(uid), &shared, &flows)?.name;
        assert_eq!(name(10_077), Some("dns.test".to_owned()));
        assert_eq!(name(10_078), None);
        Ok(())
    }

    /// A peer made with a way that names a name the stand-in map no longer holds is logged under that
    /// name: its datagrams go to it (seventh review of unit 9, finding 4).
    #[tokio::test(flavor = "current_thread")]
    async fn a_peer_keeps_the_name_its_way_names_in_the_log() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        let named: Vec<_> = lock(&shared.flows)
            .iter()
            .filter(|flow| flow.destination == stand_in)
            .map(|flow| (flow.name.clone(), flow.named_by))
            .collect();
        assert_eq!(named, [(Some("dns.test".to_owned()), NamedBy::Dns)]);
        Ok(())
    }

    /// A stand-in that waits for its first answer contests a port's answers from an address another
    /// stand-in was bound to for `udp_contest` after the app first sent to it, to the nanosecond on
    /// both sides, and never its own (ADR 0044, the windows; tenth review of unit 9, minor 3).
    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_stand_in_contests_its_port_for_udp_contest() -> io::Result<()> {
        let shared = shared();
        let contest = shared.limits.udp_contest;
        let nano = Duration::from_nanos(1);
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        let port = stand_in.port();
        let within = now + contest.saturating_sub(nano);
        assert!(mapping.main().contested(port, None, (within, contest)));
        assert!(
            !mapping
                .main()
                .contested(port, None, (now + contest, contest))
        );
        assert!(
            !mapping
                .main()
                .contested(port, Some(stand_in), (now, contest)),
            "its own"
        );
        assert!(
            !mapping.main().contested(port + 1, None, (now, contest)),
            "another port"
        );
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
            .sent(53, &asked, None);
        let by_name = Target::Name("dns.test".into(), 53);
        let answered = response(&asked);
        assert!(matches!(
            mapping
                .main()
                .relayed_answer(&shared, APP, (&by_name, &answered), now),
            LetIn::Peer(..)
        ));
        let peer = mapping
            .peers
            .get_mut(&stand_in)
            .ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(peer.asked.len(), 0, "kept after its answer by name");
        peer.sent(53, &query(0x4321, b"\x07example\x03org\x00"), None);
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
        waiting.sent(53, &asked, None);
        direct.sent(53, &asked, None);
        came_in.sent(53, &asked, None);
        elsewhere.sent(other.port(), &asked, None);
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
        peer.sent(53, &asked, None);
        peer.sent(53, &query(0x4321, b"\x07example\x03org\x00"), None);
        assert_eq!(peer.asked.len(), 2);
        let answered = response(&asked);
        let from = SocketAddr::from(([192, 0, 2, 53], 53));
        assert!(matches!(
            mapping.main().bind(stand_in, (from, &answered), now),
            LetIn::Peer(..)
        ));
        assert_eq!(mapping.peers[&stand_in].asked.len(), 0);
        Ok(())
    }

    /// A STUN Binding request, or with `answer` its success response, under the transaction ID `n` in
    /// each byte.
    fn binding(n: u8, answer: bool) -> Vec<u8> {
        let mut message = vec![u8::from(answer), 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        message.extend_from_slice(&[n; 12]);
        message
    }

    /// A stand-in on a port other than 53 keeps what its app's datagrams asked an answer to carry only
    /// while it is a candidate: at most 64, each once, the oldest giving way. Bound by an answer, or
    /// answered by name, it keeps none and records none after; bound beside another peer by its
    /// identifier, it keeps them and records more, and once that peer ends, it holds the address alone
    /// and keeps none (ADR 0044, unit 9b).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_keeps_identifiers_only_while_it_is_a_candidate() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let first = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let peer = mapping.peer(&shared, (APP, first), now, (false, waiting_stand_in()));
        for n in 0..70 {
            peer.sent(3_478, &binding(n, false), None);
        }
        peer.sent(3_478, &binding(69, false), None);
        let kept = |peer: &Peer| -> Vec<[u8; 12]> {
            peer.ids
                .iter()
                .filter_map(|asked| match asked {
                    identifiers::Asked::Stun { transaction, .. } => Some(*transaction),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(kept(peer).len(), ASKED);
        assert_eq!(kept(peer).first(), Some(&[6; 12]), "the oldest gave way");
        assert_eq!(kept(peer).last(), Some(&[69; 12]), "sent again, kept once");
        // Bound by its answer: none kept, none recorded after.
        let server = SocketAddr::from(([192, 0, 2, 9], 3_478));
        let from_server = Target::Address(server);
        assert!(matches!(
            mapping
                .main()
                .relayed_answer(&shared, APP, (&from_server, &binding(69, true)), now),
            LetIn::Peer(..)
        ));
        let peer = mapping
            .peers
            .get_mut(&first)
            .ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(kept(peer).len(), 0, "kept once bound");
        peer.sent(3_478, &binding(70, false), None);
        assert_eq!(kept(peer).len(), 0, "recorded once bound");
        // A second name, answered from the first's address by its ID: bound beside it, it keeps them.
        let second = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let later = now + Duration::from_secs(10);
        let peer = mapping.peer(&shared, (APP, second), later, (false, waiting_stand_in()));
        peer.sent(3_478, &binding(0x80, false), None);
        assert!(matches!(
            mapping.main().relayed_answer(&shared, APP, (&from_server, &binding(0x80, true)), later),
            LetIn::Peer(shown, ..) if shown == second
        ));
        let peer = mapping
            .peers
            .get_mut(&second)
            .ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(peer.standing, Standing::Beside);
        peer.sent(3_478, &binding(0x81, false), None);
        assert_eq!(kept(peer), [[0x80; 12], [0x81; 12]]);
        // The first ends: the second holds the address alone, and keeps nothing.
        if let Some(peer) = mapping.peers.get_mut(&first) {
            peer.last = now;
        }
        mapping.sweep(now + Duration::from_secs(5), &shared);
        let peer = mapping.peers.get(&second).ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(peer.standing, Standing::Settled);
        assert_eq!(kept(peer).len(), 0);
        assert_eq!(mapping.sources.aliases.get(&server), Some(&second));
        // Answered by name: a third keeps nothing.
        let third = SocketAddr::from(([198, 18, 0, 3], 5_000));
        let named = PeerWay {
            name: Some("third.test".into()),
            ..waiting_stand_in()
        };
        mapping
            .peer(&shared, (APP, third), later, (false, named))
            .sent(5_000, &binding(0x90, false), None);
        let by_name = Target::Name("third.test".into(), 5_000);
        mapping
            .main()
            .relayed_answer(&shared, APP, (&by_name, b"by name"), later);
        let peer = mapping
            .peers
            .get_mut(&third)
            .ok_or(io::ErrorKind::NotFound)?;
        peer.sent(5_000, &binding(0x91, false), None);
        assert_eq!(kept(peer).len(), 0, "kept once answered by name");
        Ok(())
    }

    /// A stand-in waiting for its first answer, under `name`.
    fn named(name: &str) -> PeerWay {
        PeerWay {
            header: None,
            from: None,
            name: Some(name.into()),
        }
    }

    /// Review A, probe 1: a relay that gives every answer from the first destination's address the first
    /// destination's name (Xray's `freedom`, sing-box) gives the second stand-in's answer the first's
    /// name. The second's STUN transaction ID tells it is the second's: it goes there, the second bound
    /// beside the first by it, and so does each later response with its ID, while one with none goes by
    /// the name (unit 9b, fix round 1, item 2).
    #[tokio::test(flavor = "current_thread")]
    async fn identifiers_outrank_a_relays_name() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        mapping
            .peer(&shared, (APP, a), now, (false, named("a.test")))
            .sent(3_478, &binding(0xa1, false), None);
        mapping
            .peer(&shared, (APP, b), now, (false, named("b.test")))
            .sent(3_478, &binding(0xb2, false), None);
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8]| match mapping.main().relayed_answer(
            &shared,
            APP,
            (&by_a, answer),
            now,
        ) {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(
            to(&mut mapping, &binding(0xb2, true)),
            Some(b),
            "b's response under a's name"
        );
        assert_eq!(mapping.peers[&b].standing, Standing::Beside);
        mapping
            .peers
            .get_mut(&b)
            .ok_or(io::ErrorKind::NotFound)?
            .sent(3_478, &binding(0xb3, false), None);
        assert_eq!(
            to(&mut mapping, &binding(0xb3, true)),
            Some(b),
            "b's next response"
        );
        assert_eq!(to(&mut mapping, &binding(0xa1, true)), Some(a), "a's own");
        assert_eq!(to(&mut mapping, b"no identifier"), Some(a), "by the name");
        assert_eq!(shared.counters.snapshot()[IDENTIFIED], 2);
        Ok(())
    }

    /// Review A, probe 2: a server that negotiates a compatible version answers a lone stand-in's
    /// version 1 Initial in version 2, which binds it (unit 9b, fix round 1, item 6).
    #[tokio::test(flavor = "current_thread")]
    async fn a_compatible_versions_answer_binds_a_lone_stand_in() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 443));
        let dcid = [0xa0; 8];
        let initial = crate::quic::client_initial(1, (&dcid, &[]), (0, &[0x01]), 1200)
            .ok_or(io::ErrorKind::InvalidData)?;
        mapping
            .peer(&shared, (APP, a), now, (false, named("a.test")))
            .sent(443, &initial, None);
        assert!(mapping.peers[&a].strict());
        let v2 = crate::quic::server_initial(
            0x6b33_43cf,
            &dcid,
            (&[], &[0x5a; 8]),
            (0, &[2, 0, 0, 0, 0]),
        )
        .ok_or(io::ErrorKind::InvalidData)?;
        let server = Target::Address(SocketAddr::from(([192, 0, 2, 9], 443)));
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&server, &v2), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == a));
        Ok(())
    }

    /// Review A, probe 3: a stranger's datagram shaped as a version 1 Initial of 64,000 bytes, while 8
    /// QUIC stand-ins wait, is dropped at a cost that no longer grows with its size or theirs: it opens
    /// nothing, larger than any server's first answer (unit 9b, fix round 1, item 5). The bound is far
    /// above the microseconds it takes, and far below the 39 ms it took in a debug build before.
    #[tokio::test(flavor = "current_thread")]
    async fn a_strangers_datagram_costs_little_under_the_lock() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        for n in 1..=8u8 {
            let stand_in = SocketAddr::from(([198, 18, 0, n], 443));
            let initial = crate::quic::client_initial(1, (&[n; 8], &[]), (0, &[0x01]), 1200)
                .ok_or(io::ErrorKind::InvalidData)?;
            mapping
                .peer(
                    &shared,
                    (APP, stand_in),
                    now,
                    (false, named(&format!("n{n}.test"))),
                )
                .sent(443, &initial, None);
        }
        let size = 64_000usize;
        let mut forged = vec![0xc0, 0, 0, 0, 1, 0, 0, 0];
        let length = u32::try_from(size - forged.len() - 4).unwrap_or(0) | 0x8000_0000;
        forged.extend_from_slice(&length.to_be_bytes());
        forged.resize(size, 0x5c);
        let stranger = Target::Address(SocketAddr::from(([203, 0, 113, 66], 443)));
        let started = std::time::Instant::now();
        for _ in 0..20 {
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (&stranger, &forged), now);
            assert!(matches!(got, LetIn::Unidentified));
        }
        assert!(started.elapsed() / 20 < Duration::from_millis(5));
        Ok(())
    }

    /// A stand-in bound beside another by an address that its relay then answers by name leaves that
    /// address's record: it holds the address no more, and when the first peer ends, nothing is handed
    /// to it as if it still did (unit 9b, fix round 1, item 9).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_beside_another_answered_by_name_leaves_the_address() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let server = SocketAddr::from(([192, 0, 2, 9], 3_478));
        let from_server = Target::Address(server);
        mapping
            .peer(&shared, (APP, a), now, (false, named("a.test")))
            .sent(3_478, &binding(0xa1, false), None);
        mapping
            .main()
            .relayed_answer(&shared, APP, (&from_server, &binding(0xa1, true)), now);
        mapping
            .peer(&shared, (APP, b), now, (false, named("b.test")))
            .sent(3_478, &binding(0xb2, false), None);
        mapping
            .main()
            .relayed_answer(&shared, APP, (&from_server, &binding(0xb2, true)), now);
        assert_eq!(
            mapping
                .sources
                .beside
                .get(&server)
                .map(|beside| beside.iter().copied().collect::<Vec<_>>()),
            Some(vec![b])
        );
        let by_b = Target::Name("b.test".into(), 3_478);
        mapping
            .main()
            .relayed_answer(&shared, APP, (&by_b, b"by name"), now);
        assert!(!mapping.sources.beside.contains_key(&server));
        assert!(!mapping.sources.beside_on.contains_key(&3_478));
        assert_eq!(mapping.peers[&b].way.from, None);
        // The first ends: the address goes, and is handed to no one.
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = now + Duration::from_secs(10);
        }
        mapping.sweep(now + Duration::from_secs(5), &shared);
        assert_eq!(mapping.sources.aliases.get(&server), None);
        assert_eq!(mapping.sources.shown(server.ip()), None);
        Ok(())
    }

    /// A stand-in refused an association of its own at a cap is counted only when its datagrams then
    /// leave: none that waits for another app's way counts (unit 9b, fix round 1, item 9). And a
    /// destination already a peer leaves by the association it has, whatever was opened for it
    /// meanwhile, which closes (item 1).
    #[tokio::test(flavor = "current_thread")]
    async fn what_leaves_keeps_its_peers_association_and_its_count() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
        let key = (APP, stand_in);
        let wanted = Wanted {
            uid,
            exit: Exit::Direct,
            chains: 0,
        };
        let hold = |table: &mut UdpTable, came: Instant| {
            let packet = packet::udp(APP, stand_in, b"held").unwrap_or_default();
            table.put(
                key,
                UdpEntry::Opening(Holding {
                    floor: None,
                    held: vec![Waiter {
                        came,
                        then: None,
                        item: packet,
                    }],
                }),
            );
        };
        let refused = |table: &mut UdpTable| -> u64 {
            let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
            let socket = table
                .mappings
                .get(&APP)
                .map(|mapping| Arc::clone(&mapping.socket));
            let (mut reads, mut errors) = (Vec::new(), Vec::new());
            if let Some(socket) = socket {
                let _ = leave_by(
                    table,
                    (key, id),
                    (named("a.test"), &wanted, socket, (None, true)),
                    (&shared, &mut reads, &mut errors),
                );
            }
            shared.counters.snapshot()[OWN_REFUSED]
        };
        // Android named another app since: the datagram waits on, and nothing is counted.
        let mut table = table_of(&shared, uid, asked).await?;
        table.answered(
            APP,
            (
                2,
                Named {
                    uid: Some(10_078),
                    asked,
                },
            ),
            &shared,
        );
        hold(&mut table, asked + Duration::from_millis(1));
        assert_eq!(refused(&mut table), 0);
        // The mapping's app's: it leaves, and is counted once.
        let mut table = table_of(&shared, uid, asked).await?;
        hold(&mut table, asked);
        assert_eq!(refused(&mut table), 1);
        // A peer already: it keeps the mapping's association, and what was opened for it closes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let control = TcpStream::from_std({
            let stream = std::net::TcpStream::connect(listener.local_addr()?)?;
            stream.set_nonblocking(true)?;
            stream
        })?;
        let own_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let place = super::super::budget::Budget::new(4, 4)
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut table = table_of(&shared, uid, asked).await?;
        let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
        let socket = table
            .mappings
            .get_mut(&APP)
            .map(|mapping| {
                mapping.peer(&shared, key, asked, (false, named("a.test")));
                Arc::clone(&mapping.socket)
            })
            .ok_or(io::ErrorKind::NotFound)?;
        hold(&mut table, asked);
        let (mut reads, mut errors) = (Vec::new(), Vec::new());
        let own = own_place(&shared)?;
        let left = leave_by(
            &mut table,
            (key, id),
            (
                named("a.test"),
                &wanted,
                socket,
                (Some((Ok((own_socket, control)), (place, own))), false),
            ),
            (&shared, &mut reads, &mut errors),
        );
        assert!(
            matches!(left, Leaving::Left(None)),
            "a task for an association of its own"
        );
        let mapping = table.mappings.get(&APP).ok_or(io::ErrorKind::NotFound)?;
        assert!(mapping.owns.is_empty());
        assert_eq!(mapping.peers[&stand_in].via, None);
        Ok(())
    }

    /// The way of a stand-in for `name` on `port` through the tool, waiting for its first answer.
    fn tooled(name: &str, port: u16) -> PeerWay {
        PeerWay::through_tool(Target::Name(name.into(), port))
    }

    /// An NTP packet of `mode` with `stamp` at `at`: a client's request has its transmit timestamp at
    /// 40, a server's reply the request's as its origin, at 24.
    fn ntp(mode: u8, at: usize, stamp: u64) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = (4 << 3) | mode;
        packet[at..at + 8].copy_from_slice(&stamp.to_be_bytes());
        packet
    }

    /// An association of a stand-in's own for a test, with its places.
    async fn own_for_test(shared: &Shared) -> io::Result<Own> {
        Ok(Own {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
            sources: Sources::default(),
            ended: Arc::new(Notify::new()),
            _places: (
                super::super::budget::Budget::new(4, 4)
                    .take(None)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?,
                own_place(shared)?,
            ),
        })
    }

    /// A place under `Limits::udp_own_relays`, for apps Android cannot name.
    fn own_place(shared: &Shared) -> io::Result<Place> {
        shared
            .own_relays
            .take(None)
            .map_err(|_| io::ErrorKind::OutOfMemory.into())
    }

    /// Under a relay's name, an identifier the app sent the named stand-in too tells no other stand-in
    /// apart (fix round 2, review C, finding 1): one NTP request's timestamp to two names, the second
    /// left beside the first on the mapping's association (as when the caps refuse it one of its own). The
    /// reply under the first's name is the first's, though it carries the second's identifier; one with
    /// an identifier only the second was sent is the second's.
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_an_identifier_two_were_sent_moves_no_answer() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 123));
        let b = SocketAddr::from(([198, 18, 0, 2], 123));
        let by_a = Target::Name("a.test".into(), 123);
        let stamp = 0xe9a1_0000_0000_0001;
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 123)));
        mapping.sent(a, &ntp(3, 40, stamp));
        let to = |mapping: &mut Mapping, answer: &[u8]| match mapping.main().relayed_answer(
            &shared,
            APP,
            (&by_a, answer),
            now,
        ) {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, &ntp(4, 24, stamp)), Some(a));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 123)));
        mapping.sent(b, &ntp(3, 40, stamp));
        assert_eq!(
            mapping.sources.told.count(identifiers::fingerprint(
                123,
                &identifiers::Asked::Ntp(stamp)
            )),
            2
        );
        assert_eq!(
            to(&mut mapping, &ntp(4, 24, stamp)),
            Some(a),
            "the first's reply moved to the second"
        );
        mapping.sent(b, &ntp(3, 40, stamp + 1));
        assert_eq!(to(&mut mapping, &ntp(4, 24, stamp + 1)), Some(b));
        Ok(())
    }

    /// What a peer was sent through the tool is counted for its association once, at most [`TOLD`] of
    /// them, and no longer once it ends; on the direct path nothing is kept (fix round 2).
    #[tokio::test(flavor = "current_thread")]
    async fn what_a_peer_was_sent_is_counted_while_it_lives() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let server = SocketAddr::from(([192, 0, 2, 9], 123));
        let way = PeerWay::through_tool(Target::Address(server));
        mapping.peer(&shared, (APP, server), now, (false, way));
        for stamp in 1..=u64::try_from(TOLD).unwrap_or(0) + 1 {
            mapping.sent(server, &ntp(3, 40, stamp));
            mapping.sent(server, &ntp(3, 40, stamp));
        }
        let fingerprint = |stamp| identifiers::fingerprint(123, &identifiers::Asked::Ntp(stamp));
        // An entry of the association's fingerprints, as `TOLD` counts it.
        assert_eq!(std::mem::size_of::<(u64, Keepers)>(), 32);
        assert_eq!(mapping.peers[&server].told.len(), TOLD);
        assert_eq!(mapping.sources.told.0.len(), TOLD);
        assert_eq!(
            mapping.sources.told.count(fingerprint(1)),
            0,
            "the oldest gave way"
        );
        assert_eq!(mapping.sources.told.count(fingerprint(2)), 1);
        mapping.sweep(now + Duration::from_secs(1), &shared);
        assert!(mapping.peers.is_empty());
        assert!(mapping.sources.told.0.is_empty());
        let direct = SocketAddr::from(([192, 0, 2, 10], 123));
        mapping.peer(
            &shared,
            (APP, direct),
            now,
            (false, PeerWay::direct(direct)),
        );
        mapping.sent(direct, &ntp(3, 40, 7));
        assert_eq!(mapping.peers[&direct].told, Vec::<u64>::new());
        // A settled peer's QUIC Initial is noted from its headers, unopened (fix round 3): one whose
        // tag fails is noted too, as a stand-in's, opened, never is.
        let quic = SocketAddr::from(([192, 0, 2, 11], 443));
        let way = PeerWay::through_tool(Target::Address(quic));
        mapping.peer(&shared, (APP, quic), now, (false, way));
        let mut initial =
            crate::quic::client_initial(1, (&[9; 8], &[]), (0, &[0x01]), 1200).unwrap_or_default();
        let ids = identifiers::of((APP.port(), 443), &initial).remove(0);
        let last = initial.len() - 1;
        initial[last] ^= 1;
        mapping.sent(quic, &initial);
        assert_eq!(
            mapping.peers[&quic].told,
            vec![identifiers::fingerprint(443, &ids)]
        );
        Ok(())
    }

    /// Of the identifiers a stand-in keeps, at most [`QUIC_ASKED`] are QUIC's, the oldest QUIC one giving
    /// way to a ninth, not an older one of another kind (review D's surviving mutants): the 32,088 bytes
    /// ADR 0044 states for a stand-in rest on it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_keeps_at_most_8_quic_identifiers() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        let peer = mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        peer.sent(443, &binding(0x51, false), None);
        let initial = |n: u8| {
            crate::quic::client_initial(1, (&[n; 8], &[]), (0, &[0x01]), 1200).unwrap_or_default()
        };
        for n in 0..=u8::try_from(QUIC_ASKED).unwrap_or(0) {
            peer.sent(443, &initial(n), None);
        }
        let quic = peer
            .ids
            .iter()
            .filter(|asked| matches!(asked, identifiers::Asked::Quic(_)))
            .count();
        assert_eq!(quic, QUIC_ASKED);
        assert!(
            matches!(peer.ids[0], identifiers::Asked::Stun { .. }),
            "the STUN request gave way"
        );
        let answer = |n: u8| {
            crate::quic::server_initial(1, &[n; 8], (&[], &[0x5a; 8]), (0, &[0x02, 0, 0, 0, 0]))
                .unwrap_or_default()
        };
        assert!(
            !identifiers::carries(&peer.ids, &answer(0)),
            "the oldest QUIC identifier is kept"
        );
        assert!(identifiers::carries(&peer.ids, &answer(1)));
        Ok(())
    }

    /// Review C, probe 4: a flow that came in through an association of a stand-in's own, which the app
    /// answers and which is live, outlives the stand-in's silence there, as on the mapping's own
    /// association a flow that came in outlives its stand-in (a TFTP server, which goes on from a port of
    /// its own); the association ends with the last flow that leaves by it (fix round 2).
    #[tokio::test(flavor = "current_thread")]
    async fn a_live_flow_that_came_in_outlives_its_stand_ins_silence() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        mapping.owns.insert(1, own_for_test(&shared).await?);
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 69));
        let server = SocketAddr::from(([192, 0, 2, 9], 69));
        {
            let mut scope = mapping.scope(Some(1)).ok_or(io::ErrorKind::NotFound)?;
            scope
                .reborrow()
                .into_peer(&shared, (APP, stand_in), now, (false, named("tftp.test")));
            let first =
                scope.relayed_answer(&shared, APP, (&Target::Address(server), b"first"), now);
            assert!(matches!(first, LetIn::Peer(shown, ..) if shown == stand_in));
        }
        let later = now + Duration::from_secs(100);
        let data_port = SocketAddr::from(([192, 0, 2, 9], 50_000));
        let came_in = {
            let mut scope = mapping.scope(Some(1)).ok_or(io::ErrorKind::NotFound)?;
            match scope.relayed_answer(&shared, APP, (&Target::Address(data_port), b"data"), later)
            {
                LetIn::Peer(shown, ..) => shown,
                _ => return Err(io::ErrorKind::NotFound.into()),
            }
        };
        mapping.answering(came_in);
        if let Some(peer) = mapping.peers.get_mut(&came_in) {
            peer.last = later;
        }
        // The stand-in was silent since `now`; the flow that came in is live at `later`.
        mapping.sweep(now + Duration::from_secs(10), &shared);
        assert!(!mapping.peers.contains_key(&stand_in));
        assert!(
            mapping.peers.contains_key(&came_in),
            "a live flow ended with its stand-in's silence"
        );
        assert!(mapping.owns.contains_key(&1));
        assert_eq!(shared.own_relays.held(None).1, 1);
        mapping.sweep(later + Duration::from_secs(10), &shared);
        assert!(
            mapping.owns.is_empty(),
            "the association outlived its last flow"
        );
        assert_eq!(shared.own_relays.held(None).1, 0, "its place given back");
        Ok(())
    }

    /// Review C, probe 5: two names the tool resolved to one address, on one association of a relay that
    /// gives every answer from there the first destination's name (Xray's `freedom`, sing-box). The
    /// second is bound beside the first by its STUN transaction ID, and goes on with STUN keepalives
    /// while the app no longer sends to the first. Once the first has been silent for `udp_idle` and
    /// ends, the second takes the name, as one bound beside an address holds it once its holder ends: its
    /// responses, and what comes under the name without an identifier, are its own (fix round 2).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_bound_beside_a_name_outlives_that_name() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        mapping
            .peer(&shared, (APP, a), now, (false, named("a.test")))
            .sent(3_478, &binding(0xa1, false), None);
        mapping
            .peer(&shared, (APP, b), now, (false, named("b.test")))
            .sent(3_478, &binding(0xb2, false), None);
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, answer), at)
        {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, &binding(0xa1, true), now), Some(a));
        assert_eq!(to(&mut mapping, &binding(0xb2, true), now), Some(b));
        // Later, only b is used: a keepalive of b's, and its response under a's name.
        let later = now + Duration::from_secs(200);
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
            peer.sent(3_478, &binding(0xb3, false), None);
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        assert_eq!(
            to(&mut mapping, &binding(0xb3, true), later),
            Some(b),
            "b's own response, under a's name, after a ended"
        );
        assert_eq!(
            to(&mut mapping, b"turn data", later),
            Some(b),
            "data under a's name"
        );
        // It stays bound beside, keeping its identifiers, should a peer of a.test come again.
        assert_eq!(mapping.peers[&b].standing, Standing::Beside);
        // Once b ends too, nothing has the name, and nothing stands beside under it.
        mapping.sweep(later + Duration::from_secs(1), &shared);
        assert!(mapping.sources.names.is_empty());
        assert!(mapping.sources.named_beside.is_empty());
        Ok(())
    }

    /// The datagrams of a destination that waited (fix round 2, review C): one already a peer leaves by
    /// its association, whatever failed to open for it meanwhile (finding 5); one that would leave by
    /// the mapping's own association, once the tool closed it or opened it anew since, leaves nothing yet
    /// and is routed again (finding 6); an association of a stand-in's own counts under
    /// `Limits::udp_own_relays` for as long as it is held, opening or open.
    #[tokio::test(flavor = "current_thread")]
    async fn what_waited_leaves_by_an_association_that_is_there() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
        let key = (APP, stand_in);
        let wanted = Wanted {
            uid,
            exit: Exit::Direct,
            chains: 0,
        };
        let hold = |table: &mut UdpTable| {
            let packet = packet::udp(APP, stand_in, b"held").unwrap_or_default();
            table.put(
                key,
                UdpEntry::Opening(Holding {
                    floor: None,
                    held: vec![Waiter {
                        came: asked,
                        then: None,
                        item: packet,
                    }],
                }),
            );
        };
        let place = || {
            super::super::budget::Budget::new(4, 4)
                .take(uid)
                .map_err(|_| io::ErrorKind::OutOfMemory)
        };
        let leave = |table: &mut UdpTable, socket, opened| {
            let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
            let (mut reads, mut errors) = (Vec::new(), Vec::new());
            leave_by(
                table,
                (key, id),
                (named("a.test"), &wanted, socket, (opened, false)),
                (&shared, &mut reads, &mut errors),
            )
        };
        let main = |table: &UdpTable| {
            table
                .mappings
                .get(&APP)
                .map(|mapping| Arc::clone(&mapping.socket))
                .ok_or(io::ErrorKind::NotFound)
        };
        // A peer already, whose own association failed to open meanwhile.
        let mut table = table_of(&shared, uid, asked).await?;
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            mapping.peer(&shared, key, asked, (false, named("a.test")));
            mapping.owns_opening = 1;
        }
        hold(&mut table);
        let own = own_place(&shared)?;
        let failed = Err(io::ErrorKind::ConnectionRefused.into());
        let socket = main(&table)?;
        let left = leave(&mut table, socket, Some((failed, (place()?, own))));
        assert!(
            matches!(left, Leaving::Left(None)),
            "a peer failed with its new association"
        );
        assert!(!table.flows.contains_key(&key), "nothing waits");
        assert_eq!(shared.own_relays.held(None).1, 0);
        // The mapping's own association closed by the tool, or opened anew since.
        for closed in [true, false] {
            let mut table = table_of(&shared, uid, asked).await?;
            hold(&mut table);
            let socket = main(&table)?;
            if let Some(mapping) = table.mappings.get_mut(&APP) {
                if closed {
                    mapping.end_main(&shared);
                } else {
                    mapping.socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
                }
            }
            let left = leave(&mut table, socket, None);
            assert!(
                matches!(left, Leaving::Made(Made::Reroute)),
                "closed {closed}: left by a stale association"
            );
            assert!(
                table.flows.contains_key(&key),
                "closed {closed}: the datagram waits on"
            );
            assert!(!table.mappings[&APP].peers.contains_key(&stand_in));
        }
        Ok(())
    }

    /// An association of a stand-in's own counts under `Limits::udp_own_relays` from when it is asked
    /// for until it ends, by the place it holds (fix round 2, review C, finding 6): no sum over every
    /// mapping under the table's lock.
    #[tokio::test(flavor = "current_thread")]
    async fn an_association_of_its_own_counts_while_it_is_held() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
        let key = (APP, stand_in);
        let wanted = Wanted {
            uid,
            exit: Exit::Direct,
            chains: 0,
        };
        let mut table = table_of(&shared, uid, asked).await?;
        let packet = packet::udp(APP, stand_in, b"held").unwrap_or_default();
        table.put(
            key,
            UdpEntry::Opening(Holding {
                floor: None,
                held: vec![Waiter {
                    came: asked,
                    then: None,
                    item: packet,
                }],
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let control = TcpStream::from_std({
            let stream = std::net::TcpStream::connect(listener.local_addr()?)?;
            stream.set_nonblocking(true)?;
            stream
        })?;
        let own = own_place(&shared)?;
        let opened = Ok((UdpSocket::bind("127.0.0.1:0").await?, control));
        let place = super::super::budget::Budget::new(4, 4)
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let (id, socket) = table
            .mappings
            .get(&APP)
            .map(|mapping| (mapping.id, Arc::clone(&mapping.socket)))
            .ok_or(io::ErrorKind::NotFound)?;
        let (mut reads, mut errors) = (Vec::new(), Vec::new());
        let left = leave_by(
            &mut table,
            (key, id),
            (
                named("a.test"),
                &wanted,
                socket,
                (Some((opened, (place, own))), false),
            ),
            (&shared, &mut reads, &mut errors),
        );
        let Leaving::Left(Some((number, _task))) = left else {
            return Err(io::ErrorKind::NotFound.into());
        };
        assert_eq!(shared.own_relays.held(None).1, 1);
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            mapping.end_own(number, &shared);
        }
        assert_eq!(shared.own_relays.held(None).1, 0);
        Ok(())
    }

    /// Review E, probe 1: a relay's name is a hint resolved among the peers that live now (fix round 3).
    /// `a.test` and `b.test` on one port, which the tool resolved to one address, under a relay that names
    /// every answer from there `a.test` (Xray's `freedom`, sing-box). `a` ends; what comes under its name
    /// goes to `b`, which stays bound beside it. The app then sends to `a.test`'s stand-in again, a
    /// datagram with no identifier: the relay's answers under `a.test` are `a`'s again, `b`'s identifiers
    /// still `b`'s; and once `b` ends too, `a`'s. Fix round 2 handed the name to `b` for good.
    #[tokio::test(flavor = "current_thread")]
    async fn a_name_goes_to_its_own_peer_again() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, answer), at)
        {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, &binding(0xa1, true), now), Some(a));
        assert_eq!(to(&mut mapping, &binding(0xb2, true), now), Some(b));
        let later = now + Duration::from_secs(200);
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        assert_eq!(
            to(&mut mapping, b"turn data", later),
            Some(b),
            "while a is gone"
        );
        // The app asks a.test again, by a protocol whose datagram carries no identifier.
        mapping.peer(&shared, (APP, a), later, (false, tooled("a.test", 3_478)));
        mapping.sent(a, b"a request of a protocol without identifiers");
        mapping.sent(b, &binding(0xb3, false));
        assert_eq!(to(&mut mapping, b"a.test's answer", later), Some(a));
        assert_eq!(
            to(&mut mapping, &binding(0xb3, true), later),
            Some(b),
            "b's own"
        );
        // Then b ends.
        if let Some(peer) = mapping.peers.get_mut(&a) {
            peer.last = later + Duration::from_secs(200);
        }
        mapping.sweep(later + Duration::from_secs(1), &shared);
        assert!(!mapping.peers.contains_key(&b), "b ended");
        assert_eq!(
            to(
                &mut mapping,
                b"a.test's next answer",
                later + Duration::from_secs(2)
            ),
            Some(a)
        );
        Ok(())
    }

    /// Review E, probe 2 (fix round 3), and review G's G4 (fix round 4): under a relay's name, an answer that
    /// carries an identifier the app sent several other peers of the association, and never the one the name
    /// would give it to, is no one's: a waiting stand-in and a server known by its address were sent one NTP
    /// timestamp, and a reply carrying it, named `a.test`, is dropped as unmatched, not given to `a`, which
    /// never asked it. A reply carrying one the server alone was sent is the server's: the address behind a
    /// label is unknown, and may be the server's (fix round 3 dropped it).
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_what_others_were_sent_goes_to_the_one_sent_it() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 123));
        let b = SocketAddr::from(([198, 18, 0, 2], 123));
        let server = SocketAddr::from(([192, 0, 2, 9], 123));
        let by_a = Target::Name("a.test".into(), 123);
        let to = |mapping: &mut Mapping, answer: &[u8]| {
            mapping
                .main()
                .relayed_answer(&shared, APP, (&by_a, answer), now)
        };
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 123)));
        mapping.sent(a, &ntp(3, 40, 0x1111));
        assert!(
            matches!(to(&mut mapping, &ntp(4, 24, 0x1111)), LetIn::Peer(shown, ..) if shown == a)
        );
        let stamp = 0xe9a1_0000_0000_0007;
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 123)));
        mapping.sent(b, &ntp(3, 40, stamp));
        let way = PeerWay::through_tool(Target::Address(server));
        mapping.peer(&shared, (APP, server), now, (false, way));
        mapping.sent(server, &ntp(3, 40, stamp));
        assert!(matches!(
            to(&mut mapping, &ntp(4, 24, stamp)),
            LetIn::Unmatched
        ));
        mapping.sent(server, &ntp(3, 40, stamp + 1));
        assert!(matches!(
            to(&mut mapping, &ntp(4, 24, stamp + 1)),
            LetIn::Peer(shown, ..) if shown == server
        ));
        // What a asked is still a's, and what no one was sent goes by the name, as before.
        mapping.sent(a, &ntp(3, 40, 0x2222));
        assert!(
            matches!(to(&mut mapping, &ntp(4, 24, 0x2222)), LetIn::Peer(shown, ..) if shown == a)
        );
        assert!(
            matches!(to(&mut mapping, &ntp(4, 24, 0x3333)), LetIn::Peer(shown, ..) if shown == a)
        );
        Ok(())
    }

    /// Review E, probe 4: an identifier sent again is the latest sent (fix round 3). An NTP server known by
    /// its address is sent a timestamp, then 32 others, the first again, then 32 more; a name is then sent
    /// that same timestamp, and the server's reply carrying it, from its own address, is the server's,
    /// not the name's: kept in first-sent order, it had been forgotten while the app sent it again. A
    /// stand-in's own identifiers and port 53's queries keep the same order.
    #[tokio::test(flavor = "current_thread")]
    async fn an_identifier_sent_again_is_the_latest_sent() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let server = SocketAddr::from(([192, 0, 2, 9], 123));
        let name = SocketAddr::from(([198, 18, 0, 1], 123));
        let way = PeerWay::through_tool(Target::Address(server));
        mapping.peer(&shared, (APP, server), now, (false, way));
        let stamp = 0xe9a1_0000_0000_0000;
        mapping.sent(server, &ntp(3, 40, stamp));
        for n in 1..=32 {
            mapping.sent(server, &ntp(3, 40, stamp + n));
        }
        mapping.sent(server, &ntp(3, 40, stamp));
        for n in 33..=u64::try_from(TOLD).unwrap_or(0) {
            mapping.sent(server, &ntp(3, 40, stamp + n));
        }
        mapping.peer(&shared, (APP, name), now, (false, tooled("b.test", 123)));
        mapping.sent(name, &ntp(3, 40, stamp));
        let from_server = Target::Address(server);
        let to =
            mapping
                .main()
                .relayed_answer(&shared, APP, (&from_server, &ntp(4, 24, stamp)), now);
        assert!(
            matches!(to, LetIn::Peer(shown, ..) if shown == server),
            "the server's reply to a request just sent again went to the name"
        );
        // A waiting stand-in's identifiers: the one sent again stays among the last 64.
        let stand_in = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let peer = mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        peer.sent(3_478, &binding(0, false), None);
        for n in 1..=32 {
            peer.sent(3_478, &binding(n, false), None);
        }
        peer.sent(3_478, &binding(0, false), None);
        for n in 33..=u8::try_from(ASKED).unwrap_or(0) {
            peer.sent(3_478, &binding(n, false), None);
        }
        assert!(identifiers::carries(&peer.ids, &binding(0, true)));
        // And port 53's queries.
        let resolver = SocketAddr::from(([198, 18, 0, 3], 53));
        let peer = mapping.peer(&shared, (APP, resolver), now, (false, waiting_stand_in()));
        peer.sent(53, &query(0, b"\x01a\x04test\x00"), None);
        for n in 1..=32 {
            peer.sent(53, &query(n, b"\x01a\x04test\x00"), None);
        }
        peer.sent(53, &query(0, b"\x01a\x04test\x00"), None);
        for n in 33..=u16::try_from(ASKED).unwrap_or(0) {
            peer.sent(53, &query(n, b"\x01a\x04test\x00"), None);
        }
        assert!(peer.asked.iter().any(|(id, _)| *id == 0));
        Ok(())
    }

    /// Making room for an association of a stand-in's own never ends its own mapping (fix round 3, review
    /// E): not as an answered lookup, which it still is when its one peer is a resolver that answered,
    /// before the app asks the next name the resolver was sent the same query for.
    #[tokio::test(flavor = "current_thread")]
    async fn making_room_for_an_own_association_never_ends_its_mapping() -> io::Result<()> {
        let mut shared = shared();
        shared.udp_budget = super::super::budget::Budget::new(1, 1);
        let now = Instant::now();
        let uid = Some(10_077);
        // The app's one place is taken: room is made only by ending a mapping.
        let _full = shared
            .udp_budget
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut mapping = mapping(now).await?;
        mapping.uid = uid;
        let resolver = SocketAddr::from(([192, 0, 2, 53], 53));
        let way = PeerWay::through_tool(Target::Address(resolver));
        mapping.peer(&shared, (APP, resolver), now, (false, way));
        let asked = query(0x5151, b"\x01x\x04test\x00");
        mapping.sent(resolver, &asked);
        let answer = Target::Address(resolver);
        let let_in = mapping
            .main()
            .relayed_answer(&shared, APP, (&answer, &response(&asked)), now);
        assert!(matches!(let_in, LetIn::Peer(..)));
        assert!(mapping.answered_lookup());
        let id = mapping.id;
        let mut table = UdpTable::default();
        table.mappings.insert(APP, mapping);
        table.sockets.entry(APP).or_default();
        table.answered(APP, (1, Named { uid, asked: now }), &shared);
        table.heard((APP, id));
        // The next server's stand-in, sent the same query: an association of its own is wanted.
        let next = SocketAddr::from(([198, 18, 0, 1], 53));
        let packet = packet::udp(APP, next, &asked).unwrap_or_default();
        table.put(
            (APP, next),
            UdpEntry::Opening(Holding {
                floor: None,
                held: vec![Waiter {
                    came: now,
                    then: None,
                    item: packet,
                }],
            }),
        );
        let tool = Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 1080)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        });
        let wanted = Wanted {
            uid,
            exit: Exit::Tool(tool),
            chains: 0,
        };
        let wants = table.own_wanted((APP, next), id, (&named("y.test"), &wanted), &shared);
        assert!(
            matches!(wants, OwnWanted::Refused),
            "no place, and none made"
        );
        assert!(
            table.mapping(APP, id).is_some(),
            "the mapping ended to make room"
        );
        Ok(())
    }

    /// An association of a stand-in's own that is being opened counts as one of the mapping's (fix round
    /// 3, review E): the tool closing the mapping's own association ends only what left by it; and when
    /// the one being opened fails while the mapping's own is closed, nothing of the mapping is left, and
    /// it ends.
    #[tokio::test(flavor = "current_thread")]
    async fn an_own_association_being_opened_keeps_its_mapping() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let mut table = table_of(&shared, uid, asked).await?;
        let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            mapping.owns_opening = 1;
        }
        assert!(!table.close_main(APP, id, &shared), "the mapping ended");
        assert!(
            table
                .mapping(APP, id)
                .is_some_and(|mapping| !mapping.main_open)
        );
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
        let key = (APP, stand_in);
        let packet = packet::udp(APP, stand_in, b"held").unwrap_or_default();
        table.put(
            key,
            UdpEntry::Opening(Holding {
                floor: None,
                held: vec![Waiter {
                    came: asked,
                    then: None,
                    item: packet,
                }],
            }),
        );
        let place = super::super::budget::Budget::new(4, 4)
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let own = own_place(&shared)?;
        let socket = table
            .mappings
            .get(&APP)
            .map(|mapping| Arc::clone(&mapping.socket))
            .ok_or(io::ErrorKind::NotFound)?;
        let wanted = Wanted {
            uid,
            exit: Exit::Direct,
            chains: 0,
        };
        let failed = Err(io::ErrorKind::ConnectionRefused.into());
        let (mut reads, mut errors) = (Vec::new(), Vec::new());
        let left = leave_by(
            &mut table,
            (key, id),
            (
                named("a.test"),
                &wanted,
                socket,
                (Some((failed, (place, own))), false),
            ),
            (&shared, &mut reads, &mut errors),
        );
        assert!(matches!(left, Leaving::Failed(_)));
        assert!(
            table.mapping(APP, id).is_none(),
            "a mapping with nothing open lives on"
        );
        Ok(())
    }

    /// Review G's probe G1a, failing on fix round 3 (fix round 4): under Xray's `freedom` or sing-box,
    /// `a.test` (the association's first destination, on 3478) and `b.test` on 5000, which the tool resolved
    /// to one address. b's STUN response comes under a.test's name on port 5000 and binds b beside a.test
    /// there by its ID. b's server's later datagram that carries no identifier (TURN data, a keepalive) comes
    /// from the same address and port, labelled the same way, where no peer of a.test lives on 5000: it is
    /// b's, the one peer it can be. Fix round 3 made it a new flow of a.test's stand-in on 5000, which then
    /// took all of b's.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_beside_under_a_name_on_another_port_keeps_its_data() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 5_000));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 5_000)));
        mapping.sent(b, &binding(0xb2, false));
        let to =
            |mapping: &mut Mapping, port: u16, answer: &[u8]| match mapping.main().relayed_answer(
                &shared,
                APP,
                (&Target::Name("a.test".into(), port), answer),
                now,
            ) {
                LetIn::Peer(shown, ..) => Some(shown),
                _ => None,
            };
        assert_eq!(to(&mut mapping, 3_478, &binding(0xa1, true)), Some(a));
        assert_eq!(to(&mut mapping, 5_000, &binding(0xb2, true)), Some(b));
        assert_eq!(mapping.peers[&b].standing, Standing::Beside);
        assert_eq!(
            to(&mut mapping, 5_000, b"turn data from b's server"),
            Some(b),
            "b's server's data went to a new flow of a.test's stand-in on 5000"
        );
        Ok(())
    }

    /// Review G's probe G1b, failing on fix round 3 (fix round 4): the same on one port, once a.test's peer
    /// on that port ended while a.test lives on another (here the app's datagrams to a.test:443). b, bound
    /// beside under a.test on 3478, is the one peer left there, and takes b's data; fix round 3 made it a new
    /// flow of a.test's stand-in on 3478, as its rule looked for "no peer has the name" rather than "no peer
    /// of the name on this port".
    #[tokio::test(flavor = "current_thread")]
    async fn a_name_alive_on_another_port_takes_nothing_of_the_one_beside() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let a443 = SocketAddr::from(([198, 18, 0, 1], 443));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, answer), at)
        {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, &binding(0xa1, true), now), Some(a));
        assert_eq!(to(&mut mapping, &binding(0xb2, true), now), Some(b));
        let later = now + Duration::from_secs(200);
        // b and a.test:443 stay in use; a.test:3478 falls silent and ends.
        mapping.peer(&shared, (APP, a443), later, (false, tooled("a.test", 443)));
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        assert_eq!(
            to(&mut mapping, b"turn data", later),
            Some(b),
            "b's data became a new flow of a.test's stand-in on 3478"
        );
        Ok(())
    }

    /// Review G's probe G2, failing on fix round 3 (fix round 4): a name that gave way in the stand-in map,
    /// asked again, has a second stand-in address, and the app's socket sends to both (the old peer still
    /// within `udp_idle`). While both live, the label stands for the newest; once the old one ends, for the
    /// one left. Fix round 3's record of the name kept the first address, so that the relay's answers under
    /// the name, for the one live peer of that name on that port, became a new flow of the dead stand-in
    /// address.
    #[tokio::test(flavor = "current_thread")]
    async fn a_name_with_a_new_stand_in_follows_its_live_peer() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let old = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let new = SocketAddr::from(([198, 18, 7, 9], 3_478));
        mapping.peer(&shared, (APP, old), now, (false, tooled("a.test", 3_478)));
        mapping.sent(old, b"no identifier");
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, answer), at)
        {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, b"first", now), Some(old));
        let later = now + Duration::from_secs(200);
        mapping.peer(&shared, (APP, new), later, (false, tooled("a.test", 3_478)));
        mapping.sent(new, b"no identifier");
        // While both live, the name stands for the newest address, which the app uses now.
        assert_eq!(to(&mut mapping, b"a.test's answer", later), Some(new));
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(
            !mapping.peers.contains_key(&old),
            "the old stand-in's peer ended"
        );
        assert_eq!(
            to(&mut mapping, b"a.test's answer", later),
            Some(new),
            "the answer went to the dead stand-in address"
        );
        Ok(())
    }

    /// Review G's probe G3, failing on fix round 3 (fix round 4): making room for an association of a
    /// stand-in's own ends no mapping when an answer comes while that association opens. Fix round 3's
    /// resolver's answer marked the mapping an answered lookup again (`heard`), and the next way the app
    /// needed a place for ended it, with what was being opened.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_while_its_own_opens_makes_no_answered_lookup() -> io::Result<()> {
        let mut shared = shared();
        shared.udp_budget = super::super::budget::Budget::new(2, 2);
        let now = Instant::now();
        let uid = Some(10_077);
        let _full = shared
            .udp_budget
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut mapping = mapping(now).await?;
        mapping.uid = uid;
        let resolver = SocketAddr::from(([192, 0, 2, 53], 53));
        let way = PeerWay::through_tool(Target::Address(resolver));
        mapping.peer(&shared, (APP, resolver), now, (false, way));
        let asked = query(0x5151, b"\x01x\x04test\x00");
        mapping.sent(resolver, &asked);
        let id = mapping.id;
        let mut table = UdpTable::default();
        table.mappings.insert(APP, mapping);
        table.sockets.entry(APP).or_default();
        table.answered(APP, (1, Named { uid, asked: now }), &shared);
        // The next server's stand-in, sent the same query while the first is slow: one of its own.
        let next = SocketAddr::from(([198, 18, 0, 1], 53));
        let packet = packet::udp(APP, next, &asked).unwrap_or_default();
        table.put(
            (APP, next),
            UdpEntry::Opening(Holding {
                floor: None,
                held: vec![Waiter {
                    came: now,
                    then: None,
                    item: packet,
                }],
            }),
        );
        let tool = Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 1080)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        });
        let wanted = Wanted {
            uid,
            exit: Exit::Tool(tool),
            chains: 0,
        };
        let wants = table.own_wanted((APP, next), id, (&named("y.test"), &wanted), &shared);
        assert!(matches!(wants, OwnWanted::Place(..)), "a place for its own");
        // While it opens, the slow first server answers.
        let from = Target::Address(resolver);
        let let_in = table.let_in_relayed((APP, id), None, (&from, &response(&asked)), &shared);
        assert!(matches!(let_in, LetIn::Peer(..)));
        // The app's next way needs a place: the cap is full.
        let _place = table.room(uid, &shared);
        assert!(
            table.mapping(APP, id).is_some(),
            "the mapping whose association of a stand-in's own is opening ended to make room"
        );
        drop(wants);
        Ok(())
    }

    /// Review G's probe G4, failing on fix round 3 (fix round 4): an answer under a name that carries an
    /// identifier exactly one settled peer of the association was sent, on that port, is that peer's: the
    /// relay put the name on it because it came from the address that name resolved to, and the identifier
    /// says which peer's server sent it. Here the label is `b.test` (Xray with cone off re-dials its link
    /// after a minute without answers, with the datagram that came next as the first destination) and the
    /// response answers `a`'s STUN request, which fix round 3 dropped as unmatched, though `a` alone asked
    /// it.
    #[tokio::test(flavor = "current_thread")]
    async fn one_peers_identifier_under_another_name_reaches_it() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        let to =
            |mapping: &mut Mapping, name: &str, answer: &[u8]| match mapping.main().relayed_answer(
                &shared,
                APP,
                (&Target::Name(name.into(), 3_478), answer),
                now,
            ) {
                LetIn::Peer(shown, ..) => Some(shown),
                _ => None,
            };
        assert_eq!(to(&mut mapping, "a.test", &binding(0xa1, true)), Some(a));
        assert_eq!(to(&mut mapping, "a.test", &binding(0xb2, true)), Some(b));
        // a's keepalive; its response now comes labelled b.test.
        mapping.sent(a, &binding(0xa3, false));
        assert_eq!(
            to(&mut mapping, "b.test", &binding(0xa3, true)),
            Some(a),
            "a's own response, which a alone was sent, dropped as unmatched"
        );
        Ok(())
    }

    /// Review G's probe G5, failing on fix round 3 (fix round 4): Xray's `freedom` and sing-box keep
    /// labelling every answer from the address their association's first destination resolved to with that
    /// destination's name for as long as the association lives. `a.test` was asked first and fell silent, its
    /// peer ended; the app then asks `b.test`, which the tool resolved to the same address, with a STUN
    /// request. b's response carries b's transaction ID under a.test's label, and binds b; fix round 3's
    /// `Scope::by_name` returned `Filtered` before it looked at the identifier, and b waited for ever.
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_no_peer_has_an_identifier_still_binds() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let keep = SocketAddr::from(([192, 0, 2, 7], 9_000));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        let by_a = Target::Name("a.test".into(), 3_478);
        let first = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &binding(0xa1, true)), now);
        assert!(matches!(first, LetIn::Peer(shown, ..) if shown == a));
        // The association lives on through another destination; a falls silent and ends.
        let later = now + Duration::from_secs(200);
        let way = PeerWay::through_tool(Target::Address(keep));
        mapping.peer(&shared, (APP, keep), later, (false, way));
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        mapping.peer(&shared, (APP, b), later, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        let to = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &binding(0xb2, true)), later);
        assert!(
            matches!(to, LetIn::Peer(shown, ..) if shown == b),
            "b's own response, under the label of a name no peer has, was not b's"
        );
        Ok(())
    }

    /// An association of a stand-in's own that opened when nothing was left to send by it goes, and a
    /// mapping whose own association closed meanwhile, with nothing else open, ends with it (fix round 4,
    /// review G's G7: it lingered, holding its place, until `udp_idle`).
    #[tokio::test(flavor = "current_thread")]
    async fn an_own_association_with_nothing_to_send_leaves_no_mapping_open() -> io::Result<()> {
        let shared = shared();
        let asked = Instant::now();
        let uid = Some(10_077);
        let mut table = table_of(&shared, uid, asked).await?;
        let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
        let socket = table
            .mappings
            .get(&APP)
            .map(|mapping| Arc::clone(&mapping.socket))
            .ok_or(io::ErrorKind::NotFound)?;
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            mapping.owns_opening = 1;
            mapping.end_main(&shared);
        }
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let control = TcpStream::from_std({
            let stream = std::net::TcpStream::connect(listener.local_addr()?)?;
            stream.set_nonblocking(true)?;
            stream
        })?;
        let place = super::super::budget::Budget::new(4, 4)
            .take(uid)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let own = own_place(&shared)?;
        let opened = Ok((UdpSocket::bind("127.0.0.1:0").await?, control));
        let wanted = Wanted {
            uid,
            exit: Exit::Direct,
            chains: 0,
        };
        let (mut reads, mut errors) = (Vec::new(), Vec::new());
        // Nothing waits for it any more.
        let left = leave_by(
            &mut table,
            ((APP, stand_in), id),
            (
                named("a.test"),
                &wanted,
                socket,
                (Some((opened, (place, own))), false),
            ),
            (&shared, &mut reads, &mut errors),
        );
        assert!(matches!(left, Leaving::Made(Made::Done)));
        assert_eq!(shared.own_relays.held(None).1, 0);
        assert!(
            table.mapping(APP, id).is_none(),
            "a mapping with nothing open lives on"
        );
        Ok(())
    }

    /// Under a label whose holder is the stand-in bound beside it (the name's own peer gone), an answer
    /// naming what the app sent another peer, and not the holder, is that peer's where it alone was sent
    /// it, and no one's where several were (fix round 4, review H's surviving mutant U2, at its place in
    /// the label's rules).
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_label_held_beside_another_peers_identifier_is_not_the_holders()
    -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let server = SocketAddr::from(([192, 0, 2, 9], 3_478));
        let other = SocketAddr::from(([192, 0, 2, 10], 3_478));
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| {
            mapping
                .main()
                .relayed_answer(&shared, APP, (&by_a, answer), at)
        };
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        assert!(
            matches!(to(&mut mapping, &binding(0xb2, true), now), LetIn::Peer(shown, ..) if shown == b)
        );
        let later = now + Duration::from_secs(200);
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        for at in [server, other] {
            let way = PeerWay::through_tool(Target::Address(at));
            mapping.peer(&shared, (APP, at), later, (false, way));
        }
        mapping.sent(server, &binding(0xc1, false));
        assert!(
            matches!(
                to(&mut mapping, &binding(0xc1, true), later),
                LetIn::Peer(shown, ..) if shown == server
            ),
            "what the server alone was sent"
        );
        mapping.sent(server, &binding(0xc2, false));
        mapping.sent(other, &binding(0xc2, false));
        assert!(matches!(
            to(&mut mapping, &binding(0xc2, true), later),
            LetIn::Unmatched
        ));
        assert!(
            matches!(to(&mut mapping, b"turn data", later), LetIn::Peer(shown, ..) if shown == b)
        );
        Ok(())
    }

    /// A stand-in on port 53 asked for the root name is bound by its response, as off port 53 (fix
    /// round 4, review H's surviving mutant U5: only port 5355 was tested).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_in_on_port_53_asked_for_the_root_is_bound_by_its_answer() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 53));
        let mut root = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        root.extend_from_slice(&[0, 0, 2, 0, 1]);
        mapping
            .peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()))
            .sent(53, &root, None);
        let mut answer = root.clone();
        answer[2..4].copy_from_slice(&[0x81, 0x80]);
        let far = Target::Address(SocketAddr::from(([203, 0, 113, 53], 53)));
        let let_in = mapping
            .main()
            .relayed_answer(&shared, APP, (&far, &answer), now);
        assert!(matches!(let_in, LetIn::Peer(shown, ..) if shown == stand_in));
        Ok(())
    }

    /// A stand-in's QUIC Initial is read opened, its tag checked: one whose tag fails is never noted,
    /// and does not make the stand-in strict with identifiers no answer would carry (fix round 4, review
    /// H's surviving mutant U6; it matters for clients whose Initials have QUIC version 1's header and
    /// other keys).
    #[tokio::test(flavor = "current_thread")]
    async fn a_stand_ins_initial_whose_tag_fails_is_never_noted() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        let peer = mapping.peer(&shared, (APP, stand_in), now, (false, waiting_stand_in()));
        let mut initial =
            crate::quic::client_initial(1, (&[9; 8], &[]), (0, &[0x01]), 1200).unwrap_or_default();
        let last = initial.len() - 1;
        initial[last] ^= 1;
        peer.sent(443, &initial, None);
        assert_eq!(peer.ids.len(), 0);
        assert!(!peer.strict());
        Ok(())
    }

    /// Under a label held by the stand-in bound beside it, as under an address a stand-in was bound to,
    /// what carries no identifier is dropped for `udp_contest` after a stand-in without identifiers began
    /// to wait on the port: the tool may have resolved that one's name there too (fix round 4).
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_label_held_beside_a_waiting_stand_in_contests_the_port() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let contest = shared.limits.udp_contest;
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let c = SocketAddr::from(([198, 18, 0, 3], 3_478));
        let by_a = Target::Name("a.test".into(), 3_478);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| {
            mapping
                .main()
                .relayed_answer(&shared, APP, (&by_a, answer), at)
        };
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        mapping.sent(b, &binding(0xb2, false));
        assert!(
            matches!(to(&mut mapping, &binding(0xb2, true), now), LetIn::Peer(shown, ..) if shown == b)
        );
        let later = now + Duration::from_secs(200);
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        mapping.peer(&shared, (APP, c), later, (false, tooled("c.test", 3_478)));
        mapping.sent(c, b"no identifier");
        assert!(matches!(to(&mut mapping, b"data", later), LetIn::Unmatched));
        assert!(matches!(
            to(&mut mapping, b"data", later + contest),
            LetIn::Peer(shown, ..) if shown == b
        ));
        Ok(())
    }

    /// The places of counters in the snapshot.
    const TOO_BIG: usize = 39;
    const IDENTIFIED: usize = 47;
    const OWN_REFUSED: usize = 50;
    const SKIPPED: usize = 8;
    const PATH_MTU: usize = 40;

    const TIME_EXCEEDED: usize = 41;
    const PATH_UNREACHABLE: usize = 42;
    const ERRORS_DROPPED: usize = 44;
    const ROUTER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    /// An error from the path, as a mapping reads it off its queue, about a datagram to `destination`.
    fn from_path(
        destination: SocketAddr,
        told: Told,
        offender: Option<IpAddr>,
        hops: Option<u8>,
    ) -> Queued {
        Queued {
            destination,
            told,
            offender,
            hops,
            quoted: Vec::new(),
        }
    }

    /// The app sends each of `peers` of its mapping as many datagrams as is given beside it.
    /// Each datagram leaves, as the app sent it: with the identification 0x1234 and a time to live of
    /// 5, which an error's quote keeps.
    fn send_each(flows: &UdpFlows, peers: &[(SocketAddr, usize)]) {
        let mut table = lock(flows);
        let Some(mapping) = table.mappings.get_mut(&APP) else {
            return;
        };
        for &(address, times) in peers {
            let mut datagram = packet::udp(APP, address, b"datagram").unwrap_or_default();
            datagram[4..6].copy_from_slice(&[0x12, 0x34]);
            datagram[8] = 5;
            if let Some(peer) = mapping.peers.get_mut(&address) {
                for _ in 0..times {
                    peer.sent(443, b"datagram", None);
                    peer.left(Sent::of(&datagram, 20));
                }
            }
        }
    }

    /// The datagram an IPv4 error quotes, from its 29th byte on: its identification, time to live,
    /// ends, and its UDP header's length.
    fn quote_of(error: &[u8]) -> ([u8; 2], u8, SocketAddr, SocketAddr, u16) {
        let quote = &error[28..];
        let address = |at: usize| {
            std::net::Ipv4Addr::new(quote[at], quote[at + 1], quote[at + 2], quote[at + 3])
        };
        let port = |at: usize| u16::from_be_bytes([quote[at], quote[at + 1]]);
        (
            [quote[4], quote[5]],
            quote[8],
            SocketAddr::from((address(12), port(20))),
            SocketAddr::from((address(16), port(22))),
            port(24),
        )
    }

    /// The errors a mapping read off its socket's error queue as the network beneath moved are not
    /// passed on after the move, nor counted, and the mapping ends (second review of unit 12, minor 4b);
    /// read while the network stays, they reach the app from whoever sent them, with the hop limit they
    /// came with, one for each datagram the app sent (ADR 0044, unit 11b): a router's "packet too big"
    /// with its MTU, from the router; a router's "time exceeded", one only for the one datagram; an
    /// unreachable port with its code, from the destination where the kernel named no sender; and none
    /// for a destination the app never sent to. Each is counted.
    #[tokio::test(flavor = "current_thread")]
    async fn errors_read_as_the_network_moves_are_not_passed_on() -> io::Result<()> {
        let shared = shared();
        let table = table_of(&shared, Some(10_077), Instant::now()).await?;
        let socket = Arc::clone(&table.mappings[&APP].socket);
        let flows: UdpFlows = Arc::new(Mutex::new(table));
        let stranger = SocketAddr::from(([192, 0, 2, 3], 443));
        let queued = || {
            vec![
                from_path(ASKER, Told::TooBig(1_400), Some(ROUTER), Some(9)),
                from_path(OTHER, Told::Unreachable(3), None, None),
                from_path(stranger, Told::TimeExceeded, Some(ROUTER), None),
                from_path(ASKER, Told::TimeExceeded, Some(ROUTER), None),
            ]
        };
        // The app sent ASKER two datagrams and OTHER one.
        let sent = [(ASKER, 2), (OTHER, 1)];
        let mut buffer = vec![0u8; 2_048];
        let ends = (APP, 1, Some(10_077));
        send_each(&flows, &sent);
        let (packets, end, _) = mapped_receive(
            &socket,
            &mut buffer,
            ends,
            (queued(), &|| true),
            &shared,
            &flows,
        );
        assert!(packets.is_empty() && end, "passed on after the move");
        let counted = |at: usize| shared.counters.snapshot()[at];
        assert_eq!(
            [PATH_MTU, TIME_EXCEEDED, PATH_UNREACHABLE, ERRORS_DROPPED].map(counted),
            [0; 4]
        );

        // The datagrams the errors may answer, anew, as the moved read took theirs.
        send_each(&flows, &sent);
        let (packets, end, _) = mapped_receive(
            &socket,
            &mut buffer,
            ends,
            (queued(), &|| false),
            &shared,
            &flows,
        );
        assert!(!end);
        let [too_big, unreachable, exceeded] = packets.as_slice() else {
            unreachable!("three errors: {packets:?}")
        };
        assert_eq!(&too_big[12..16], &[203, 0, 113, 7], "from the router");
        assert_eq!(too_big[8], 9, "with the hop limit it came with");
        assert_eq!(&too_big[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([too_big[26], too_big[27]]), 1_400);
        // The datagram quoted as the app sent it: its identification and time to live, ends, and its
        // UDP header's length, 16.
        assert_eq!(quote_of(too_big), ([0x12, 0x34], 5, APP, ASKER, 16));
        assert_eq!(
            &unreachable[12..16],
            &[192, 0, 2, 2],
            "from the destination"
        );
        assert_eq!((&unreachable[20..22], unreachable[8]), (&[3, 3][..], 64));
        assert_eq!(&exceeded[12..16], &[203, 0, 113, 7]);
        assert_eq!(&exceeded[20..22], &[11, 0]);
        // A router quotes a packet whose time to live it found spent with 1.
        assert_eq!(quote_of(exceeded), ([0x12, 0x34], 1, APP, ASKER, 16));
        assert_eq!(
            [PATH_MTU, TIME_EXCEEDED, PATH_UNREACHABLE, ERRORS_DROPPED].map(counted),
            [1, 1, 1, 1],
            "the stranger's error dropped"
        );
        // ASKER's two datagrams have had their two errors: a third is dropped.
        let third = vec![from_path(ASKER, Told::TimeExceeded, Some(ROUTER), None)];
        let (packets, _, _) = mapped_receive(
            &socket,
            &mut buffer,
            ends,
            (third, &|| false),
            &shared,
            &flows,
        );
        assert!(packets.is_empty(), "a third error for two datagrams");
        assert_eq!(counted(ERRORS_DROPPED), 2);
        Ok(())
    }

    /// At most [`OWED_ERRORS`] errors are owed to a peer, one for each datagram the app sent it that
    /// left (ADR 0044, unit 11b): after `OWED_ERRORS` and six datagrams, as many errors pass as the
    /// bound, and the six more are dropped and counted; after three to another peer, all three pass. An
    /// error for which no error to the app can be built, one from a multicast destination that named no
    /// sender, is dropped and counted too (second review, minor 4).
    #[tokio::test(flavor = "current_thread")]
    async fn a_peer_is_owed_at_most_owed_errors() -> io::Result<()> {
        let shared = shared();
        let mut table = table_of(&shared, Some(10_077), Instant::now()).await?;
        let group = SocketAddr::from(([224, 0, 0, 251], 5353));
        if let Some(mapping) = table.mappings.get_mut(&APP) {
            let way = (false, PeerWay::direct(group));
            mapping.peer(&shared, (APP, group), Instant::now(), way);
        }
        let socket = Arc::clone(&table.mappings[&APP].socket);
        let flows: UdpFlows = Arc::new(Mutex::new(table));
        let bound = usize::from(OWED_ERRORS);
        send_each(&flows, &[(ASKER, bound + 6), (OTHER, 3), (group, 1)]);
        let exceeded = |to| from_path(to, Told::TimeExceeded, Some(ROUTER), None);
        let mut queued = vec![exceeded(ASKER); bound + 6];
        queued.extend(vec![exceeded(OTHER); 3]);
        queued.push(from_path(group, Told::Unreachable(3), None, None));
        let mut buffer = vec![0u8; 2_048];
        let (packets, end, _) = mapped_receive(
            &socket,
            &mut buffer,
            (APP, 1, Some(10_077)),
            (queued, &|| false),
            &shared,
            &flows,
        );
        assert!(!end);
        assert_eq!(packets.len(), bound + 3);
        let counted = shared.counters.snapshot();
        assert_eq!(
            (
                counted[TIME_EXCEEDED],
                counted[PATH_UNREACHABLE],
                counted[ERRORS_DROPPED]
            ),
            (67, 0, 7)
        );
        Ok(())
    }

    /// What a mapping reads is held back once the network moved since it opened, by its copy of the
    /// network's watch, and once the engine stops, its sender gone; not for a move before it opened,
    /// which its copy saw already (second review of unit 12, minor 6).
    #[test]
    fn a_mapping_sees_a_network_move_since_it_opened() {
        let (moves, mut changes) = watch::channel(0u64);
        moves.send_modify(|generation| *generation += 1);
        changes.borrow_and_update();
        assert!(!network_moved(&changes), "a move before it opened");
        moves.send_modify(|generation| *generation += 1);
        assert!(network_moved(&changes));
        changes.borrow_and_update();
        assert!(!network_moved(&changes));
        drop(moves);
        assert!(network_moved(&changes), "the engine stopping");
    }

    /// A send the engine's kernel refused as too long (`EMSGSIZE`) is dropped and counted, never
    /// answered "host unreachable" (ADR 0044, decision 5 as amended); another failure still is.
    #[test]
    fn a_send_too_long_is_dropped_and_counted() {
        let shared = shared();
        let server = SocketAddr::from(([198, 51, 100, 9], 9_000));
        let large = packet::udp(APP, server, &[7; 1_472]).unwrap_or_default();
        let Ok(parsed) = packet::parse(&large) else {
            unreachable!("not parsed")
        };
        let too_long = Err(io::Error::from_raw_os_error(nix::libc::EMSGSIZE));
        assert_eq!(count_sent(&shared, None, &large, &parsed, too_long), None);
        assert_eq!(shared.counters.snapshot()[TOO_BIG], 1);
        // A datagram the network beneath's queue dropped is dropped and counted too, as by a full queue.
        let queue_full = Err(io::Error::from_raw_os_error(nix::libc::ENOBUFS));
        assert_eq!(count_sent(&shared, None, &large, &parsed, queue_full), None);
        assert_eq!(shared.counters.snapshot()[SKIPPED], 1);
        let unreachable = count_sent(
            &shared,
            None,
            &large,
            &parsed,
            Err(io::ErrorKind::HostUnreachable.into()),
        )
        .unwrap_or_default();
        assert_eq!(&unreachable[20..22], &[3, 1]);
        assert_eq!(shared.counters.snapshot()[TOO_BIG], 1);
    }

    /// Under a relay's name, an answer that names in the clear what the label's holder was sent is the
    /// holder's however many other peers were sent it too (fix round 5, review I's I1: of three or more,
    /// the two found first in the map's order stood for all, and the holder's answer was dropped as
    /// unmatched at random). A stub resolver sends one query to `dns.test`, the label's holder, and, as
    /// glibc's and c-ares' retries do, to two more servers by their address.
    #[tokio::test(flavor = "current_thread")]
    async fn the_holder_sent_an_identifier_among_several_takes_its_answer() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let a = SocketAddr::from(([198, 18, 0, 1], 53));
        let by_a = Target::Name("dns.test".into(), 53);
        let asked = query(0x4242, b"\x07example\x03com\x00");
        for _ in 0..20 {
            let mut mapping = mapping(now).await?;
            mapping.peer(&shared, (APP, a), now, (false, tooled("dns.test", 53)));
            mapping.sent(a, &asked);
            for n in 1..=2u8 {
                let server = SocketAddr::from(([192, 0, 2, n], 53));
                let way = PeerWay::through_tool(Target::Address(server));
                mapping.peer(&shared, (APP, server), now, (false, way));
                mapping.sent(server, &asked);
            }
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (&by_a, &response(&asked)), now);
            assert!(matches!(got, LetIn::Peer(shown, ..) if shown == a));
        }
        Ok(())
    }

    /// Under a relay's name, an answer that names in the clear what one peer alone was sent is that
    /// peer's, found by the association's fingerprints (fix round 5, I4): also once two of three that
    /// were sent it ended, the one left; and a peer of another association that was sent it too, as a
    /// stand-in given one of its own for that very identifier is, makes it no less this one's.
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_the_one_peer_of_the_association_sent_an_identifier_takes_it()
    -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        mapping.owns.insert(1, own_for_test(&shared).await?);
        let stamp = 0xe9a1_0000_0000_0005;
        let a = SocketAddr::from(([198, 18, 0, 1], 123));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 123)));
        mapping.sent(a, &ntp(3, 40, 1));
        let servers: Vec<SocketAddr> = (1..=3u8)
            .map(|n| SocketAddr::from(([192, 0, 2, n], 123)))
            .collect();
        for &server in &servers {
            let way = PeerWay::through_tool(Target::Address(server));
            mapping.peer(&shared, (APP, server), now, (false, way));
            mapping.sent(server, &ntp(3, 40, stamp));
        }
        // A stand-in on an association of its own, sent the same timestamp.
        let own = SocketAddr::from(([198, 18, 0, 7], 123));
        mapping
            .scope(Some(1))
            .ok_or(io::ErrorKind::NotFound)?
            .into_peer(&shared, (APP, own), now, (false, tooled("own.test", 123)));
        mapping.sent(own, &ntp(3, 40, stamp));
        let by_a = Target::Name("a.test".into(), 123);
        let to = |mapping: &mut Mapping, at: Instant| match mapping.main().relayed_answer(
            &shared,
            APP,
            (&by_a, &ntp(4, 24, stamp)),
            at,
        ) {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, now), None, "three were sent it");
        let later = now + Duration::from_secs(200);
        for shown in [a, servers[1], own] {
            if let Some(peer) = mapping.peers.get_mut(&shown) {
                peer.last = later;
            }
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(
            !mapping.peers.contains_key(&servers[0]) && !mapping.peers.contains_key(&servers[2])
        );
        assert_eq!(to(&mut mapping, later), Some(servers[1]));
        Ok(())
    }

    /// Under a relay's name on the mapping's association, a peer of the name on an association of its
    /// own holds nothing: its answers come on that association (fix round 5, review J's J12). `a.test`
    /// is asked on 3478 by the mapping's association and on 5000 by one of its own.
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_its_peer_on_another_association_holds_nothing() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        mapping.owns.insert(1, own_for_test(&shared).await?);
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let a_own = SocketAddr::from(([198, 18, 0, 1], 5_000));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping
            .scope(Some(1))
            .ok_or(io::ErrorKind::NotFound)?
            .into_peer(&shared, (APP, a_own), now, (false, tooled("a.test", 5_000)));
        let by_a = Target::Name("a.test".into(), 5_000);
        let got =
            mapping
                .main()
                .relayed_answer(&shared, APP, (&by_a, b"on the wrong association"), now);
        assert!(
            !matches!(got, LetIn::Peer(shown, ..) if shown == a_own),
            "an answer on the mapping's association reached a peer of another"
        );
        Ok(())
    }

    /// Review I's measure of I4: what an answer under a relay's name costs once it names in the clear an
    /// identifier the app sent one peer of 4,000 on the port, each sent 64. Fix round 5: 152 us before
    /// on x86-64, in a release build, every peer walked.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "a measure, run with --release --ignored"]
    async fn measure_an_answer_under_a_name_among_4_000_peers() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let peers = 4_000u32;
        let mut last = APP;
        for n in 0..peers {
            let [_, _, hi, lo] = n.to_be_bytes();
            let server = SocketAddr::from(([10, 9, hi, lo], 3_478));
            let way = PeerWay::through_tool(Target::Address(server));
            mapping.peer(&shared, (APP, server), now, (false, way));
            for k in 0..64u8 {
                let mut request = binding(k, false);
                request[8..12].copy_from_slice(&n.to_be_bytes());
                mapping.sent(server, &request);
            }
            last = server;
        }
        let mut answer = binding(63, true);
        answer[8..12].copy_from_slice(&(peers - 1).to_be_bytes());
        let label = Target::Name("nobody.test".into(), 3_478);
        let rounds = 1_000u32;
        let start = Instant::now();
        for _ in 0..rounds {
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (&label, &answer), now);
            assert!(matches!(got, LetIn::Peer(shown, ..) if shown == last));
        }
        let each = start.elapsed() / rounds;
        eprintln!("{peers} peers on the port, 64 identifiers each: {each:?} for each answer");
        Ok(())
    }

    /// The contest under a label held by the name's own stand-in, as under an address a stand-in holds
    /// (fix round 5, review I's I2). A stand-in bound to an address has its answers there cut for
    /// `udp_contest` while a stand-in without identifiers, asked meanwhile, waits on the port: the tool
    /// may have resolved both names to that address. Under a label its own stand-in holds, the same
    /// holds (Xray's `freedom` labels every answer from the first destination's address, the second
    /// name's among them where it resolved there too); the answer went to the first name at once.
    #[tokio::test(flavor = "current_thread")]
    async fn a_label_held_by_its_own_stand_in_is_contested_as_an_address() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let later = now + Duration::from_secs(10);
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let c = SocketAddr::from(([198, 18, 0, 3], 3_478));
        let server = Target::Address(SocketAddr::from(([192, 0, 2, 9], 3_478)));
        let by_a = Target::Name("a.test".into(), 3_478);
        for source in [&server, &by_a] {
            let mut mapping = mapping(now).await?;
            mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
            mapping.sent(a, b"a protocol without identifiers");
            let first = mapping
                .main()
                .relayed_answer(&shared, APP, (source, b"first"), now);
            assert!(matches!(first, LetIn::Peer(shown, ..) if shown == a));
            mapping.peer(&shared, (APP, c), later, (false, tooled("c.test", 3_478)));
            mapping.sent(c, b"c's request, no identifier");
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (source, b"c's answer?"), later);
            assert!(
                matches!(got, LetIn::Unmatched),
                "{source:?}: the port was not contested"
            );
            let after = later + shared.limits.udp_contest;
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (source, b"a's again"), after);
            assert!(matches!(got, LetIn::Peer(shown, ..) if shown == a));
        }
        Ok(())
    }

    /// The contest spares an answer that names in the clear what the stand-in holding the address was
    /// sent (fix round 5, review I's I3): `a.test`, bound to its server's address by its STUN response,
    /// sends a TURN refresh, a STUN request; `c.test`, whose datagrams carry no identifier, is asked on
    /// 3478 meanwhile. The refresh's response carries the transaction ID the app sent `a` alone, which
    /// `c`, without identifiers, cannot have asked: it is `a`'s at once, as under a label.
    #[tokio::test(flavor = "current_thread")]
    async fn the_contest_spares_what_the_holder_was_sent() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let later = now + Duration::from_secs(10);
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let c = SocketAddr::from(([198, 18, 0, 3], 3_478));
        let from_server = Target::Address(SocketAddr::from(([192, 0, 2, 9], 3_478)));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        let first =
            mapping
                .main()
                .relayed_answer(&shared, APP, (&from_server, &binding(0xa1, true)), now);
        assert!(matches!(first, LetIn::Peer(shown, ..) if shown == a));
        mapping.peer(&shared, (APP, c), later, (false, tooled("c.test", 3_478)));
        mapping.sent(c, b"c's request, no identifier");
        mapping.sent(a, &binding(0xa2, false));
        let got = mapping.main().relayed_answer(
            &shared,
            APP,
            (&from_server, &binding(0xa2, true)),
            later,
        );
        assert!(
            matches!(got, LetIn::Peer(shown, ..) if shown == a),
            "a's own refresh response was cut by c's contest"
        );
        let got =
            mapping
                .main()
                .relayed_answer(&shared, APP, (&from_server, b"no identifier"), later);
        assert!(matches!(got, LetIn::Unmatched), "the contest itself holds");
        Ok(())
    }

    /// Under a label held by the stand-in bound beside it, an answer its QUIC keys tell is its own is
    /// spared by the contest, as a STUN response it was sent is (fix round 5, review I's I3: it fell
    /// through to the contest and was cut).
    #[tokio::test(flavor = "current_thread")]
    async fn a_beside_holders_quic_answer_is_not_contested() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 443));
        let b = SocketAddr::from(([198, 18, 0, 2], 443));
        let c = SocketAddr::from(([198, 18, 0, 3], 443));
        let by_a = Target::Name("a.test".into(), 443);
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 443)));
        mapping.sent(a, b"a protocol without identifiers");
        let first = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, b"a's"), now);
        assert!(matches!(first, LetIn::Peer(shown, ..) if shown == a));
        let dcid = [0xb0; 8];
        let initial = crate::quic::client_initial(1, (&dcid, &[]), (0, &[0x01]), 1200)
            .ok_or(io::ErrorKind::InvalidData)?;
        mapping.peer(&shared, (APP, b), now, (false, tooled("b.test", 443)));
        mapping.sent(b, &initial);
        let answer = |pn| {
            crate::quic::server_initial(1, &dcid, (&[], &[0x5a; 8]), (pn, &[0x02, 0, 0, 0, 0]))
                .ok_or(io::ErrorKind::InvalidData)
        };
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &answer(0)?), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == b));
        assert_eq!(mapping.peers[&b].standing, Standing::Beside);
        // `a` ends; `b` holds the label beside it. `c`, with no identifier, is asked on 443.
        let later = now + Duration::from_secs(200);
        if let Some(peer) = mapping.peers.get_mut(&b) {
            peer.last = later;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a));
        mapping.peer(&shared, (APP, c), later, (false, tooled("c.test", 443)));
        mapping.sent(c, b"no identifier");
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &answer(1)?), later);
        assert!(
            matches!(got, LetIn::Peer(shown, ..) if shown == b),
            "b's own Initial, told by its keys, was cut by c's contest"
        );
        Ok(())
    }

    /// Another port of an address comes in as the address the app knows a live peer there by (fix round
    /// 5, review I's I7): handed to the stand-in bound beside its holder, the address showed the ended
    /// holder's stand-in still, so that a STUN server's alternate port (RFC 5780) came in as a flow of
    /// `a.test`, which the app no longer has, and was logged under its name; and so it did where two
    /// names were bound to one address on two ports, the second by its identifier, and the first ended.
    #[tokio::test(flavor = "current_thread")]
    async fn another_port_of_an_address_shows_a_live_peer() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let later = now + Duration::from_secs(200);
        let server = SocketAddr::from(([192, 0, 2, 9], 3_478));
        let from_server = Target::Address(server);
        let alternate = Target::Address(SocketAddr::from(([192, 0, 2, 9], 3_479)));
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        // Handed over beside: `b` bound beside `a` by its STUN ID.
        let mut handed = mapping(now).await?;
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        handed.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        handed.sent(a, &binding(0xa1, false));
        handed
            .main()
            .relayed_answer(&shared, APP, (&from_server, &binding(0xa1, true)), now);
        handed.peer(&shared, (APP, b), now, (false, tooled("b.test", 3_478)));
        handed.sent(b, &binding(0xb2, false));
        let got =
            handed
                .main()
                .relayed_answer(&shared, APP, (&from_server, &binding(0xb2, true)), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == b));
        // Two names bound to one address, on two ports.
        let mut two = mapping(now).await?;
        let c = SocketAddr::from(([198, 18, 0, 3], 5_000));
        two.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        two.sent(a, b"no identifier");
        two.main()
            .relayed_answer(&shared, APP, (&from_server, b"a's"), now);
        let at_5000 = Target::Address(SocketAddr::from(([192, 0, 2, 9], 5_000)));
        two.peer(&shared, (APP, c), now, (false, tooled("c.test", 5_000)));
        two.sent(c, &binding(0xc3, false));
        let got = two
            .main()
            .relayed_answer(&shared, APP, (&at_5000, &binding(0xc3, true)), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == c));
        for (mapping, left) in [(&mut two, c), (&mut handed, b)] {
            if let Some(peer) = mapping.peers.get_mut(&left) {
                peer.last = later;
            }
            mapping.sweep(now + Duration::from_secs(120), &shared);
            assert!(!mapping.peers.contains_key(&a), "a ended");
            let got = mapping.main().relayed_answer(
                &shared,
                APP,
                (&alternate, b"from the alternate port"),
                later,
            );
            let LetIn::Peer(shown, ..) = got else {
                unreachable!("{left}: the alternate port came in as nothing")
            };
            assert_eq!(
                shown.ip(),
                left.ip(),
                "came in as a's stand-in, not the live one's"
            );
            let name = mapping.peers[&shown].way.name.clone();
            assert_ne!(
                name.as_deref(),
                Some("a.test"),
                "logged under the ended name"
            );
        }
        Ok(())
    }

    /// An answer that names in the clear what the app sent another peer binds no stand-in without
    /// identifiers, which cannot have asked it (fix round 5, review I's I5). `a.test`, answered by name,
    /// sends a STUN request; its server answers from an address no peer's answers came from (RFC 5780's
    /// CHANGE-REQUEST, or Xray's link dialled anew with another first destination); `c.test`, whose
    /// datagrams carry no identifier, waits alone on 3478. It bound `c`, and every later answer from that
    /// address went to `c`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_clear_answer_to_another_binds_no_stand_in_without_identifiers() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let c = SocketAddr::from(([198, 18, 0, 3], 3_478));
        let by_a = Target::Name("a.test".into(), 3_478);
        let mut labelled = mapping(now).await?;
        labelled.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        labelled.sent(a, &binding(0xa1, false));
        let first =
            labelled
                .main()
                .relayed_answer(&shared, APP, (&by_a, &binding(0xa1, true)), now);
        assert!(matches!(first, LetIn::Peer(shown, ..) if shown == a));
        labelled.peer(&shared, (APP, c), now, (false, tooled("c.test", 3_478)));
        labelled.sent(c, b"c's request, no identifier");
        labelled.sent(a, &binding(0xa2, false));
        let elsewhere = Target::Address(SocketAddr::from(([192, 0, 2, 77], 3_478)));
        let got =
            labelled
                .main()
                .relayed_answer(&shared, APP, (&elsewhere, &binding(0xa2, true)), now);
        assert!(matches!(got, LetIn::Unmatched), "a's STUN response bound c");
        let got = labelled
            .main()
            .relayed_answer(&shared, APP, (&elsewhere, b"c's own"), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == c));
        Ok(())
    }

    /// Each app holds at most a quarter of the associations of a stand-in's own, `udp_own_share`, as
    /// decision 3 shares its caps, the apps Android cannot name sharing one share (fix round 5, review
    /// I's I8: one app could hold all 32, four sockets of 8, and every other app's stand-ins fell to
    /// unit 9's floor).
    #[tokio::test(flavor = "current_thread")]
    async fn an_app_holds_a_quarter_of_the_own_associations() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let (busy, other) = (Some(10_077), Some(10_078));
        let held: Vec<Place> = (0..shared.limits.udp_own_share)
            .map(|_| shared.own_relays.take(busy))
            .collect::<Result<_, _>>()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        assert_eq!(held.len(), 8);
        for (uid, opens) in [(busy, false), (other, true)] {
            let mut mapping = mapping(now).await?;
            mapping.uid = uid;
            let first = SocketAddr::from(([198, 18, 0, 1], 4_000));
            mapping.peer(&shared, (APP, first), now, (false, tooled("x.test", 4_000)));
            mapping.sent(first, b"no identifier");
            let id = mapping.id;
            let mut table = UdpTable::default();
            table.mappings.insert(APP, mapping);
            table.sockets.entry(APP).or_default();
            let next = SocketAddr::from(([198, 18, 0, 2], 4_000));
            let packet = packet::udp(APP, next, b"no identifier either").unwrap_or_default();
            table.put(
                (APP, next),
                UdpEntry::Opening(Holding {
                    floor: None,
                    held: vec![Waiter {
                        came: now,
                        then: None,
                        item: packet,
                    }],
                }),
            );
            let tool = Arc::new(Chain {
                proxy: SocketAddr::from(([127, 0, 0, 1], 1080)),
                credentials: None,
                tool: 10_200,
                apps: None,
                udp: true,
                log_destinations: false,
            });
            let wanted = Wanted {
                uid,
                exit: Exit::Tool(tool),
                chains: 0,
            };
            let wants = table.own_wanted((APP, next), id, (&named("y.test"), &wanted), &shared);
            assert_eq!(matches!(wants, OwnWanted::Place(..)), opens, "{uid:?}");
        }
        assert_eq!(
            shared.own_relays.held(busy),
            (8, 8),
            "the refused app's share held as it was"
        );
        Ok(())
    }

    /// The stand-ins bound beside under a label are recorded per name and port, and on one port the
    /// first bound holds the label once the name's own peer ends (fix round 4, review G's G1; fix round
    /// 5, review J's surviving mutants J23 and J30, each failing this).
    #[tokio::test(flavor = "current_thread")]
    async fn the_stand_ins_beside_a_label_hold_it_on_their_port_the_first_first() -> io::Result<()>
    {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let b = SocketAddr::from(([198, 18, 0, 2], 3_478));
        let c = SocketAddr::from(([198, 18, 0, 3], 5_000));
        let d = SocketAddr::from(([198, 18, 0, 4], 3_478));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        for (shown, name, port, id) in [
            (b, "b.test", 3_478, 0xb2),
            (c, "c.test", 5_000, 0xc3),
            (d, "d.test", 3_478, 0xd4),
        ] {
            mapping.peer(&shared, (APP, shown), now, (false, tooled(name, port)));
            mapping.sent(shown, &binding(id, false));
        }
        let to = |mapping: &mut Mapping, port: u16, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(
                &shared,
                APP,
                (&Target::Name("a.test".into(), port), answer),
                at,
            ) {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(to(&mut mapping, 3_478, &binding(0xa1, true), now), Some(a));
        assert_eq!(to(&mut mapping, 3_478, &binding(0xb2, true), now), Some(b));
        assert_eq!(to(&mut mapping, 5_000, &binding(0xc3, true), now), Some(c));
        assert_eq!(to(&mut mapping, 3_478, &binding(0xd4, true), now), Some(d));
        let later = now + Duration::from_secs(200);
        for shown in [b, c, d] {
            if let Some(peer) = mapping.peers.get_mut(&shown) {
                peer.last = later;
            }
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&a), "a ended");
        assert_eq!(
            to(&mut mapping, 5_000, b"data on 5000", later),
            Some(c),
            "the one beside under a.test on 5000"
        );
        assert_eq!(
            to(&mut mapping, 3_478, b"data on 3478", later),
            Some(b),
            "the first bound beside under a.test on 3478"
        );
        Ok(())
    }

    /// An association of a stand-in's own that opened with nothing to send ends no mapping that still
    /// has its own association open, or another of a stand-in's own opening (fix round 4, G7's guard;
    /// fix round 5, review J's surviving mutants J25 and J26, each failing this).
    #[tokio::test(flavor = "current_thread")]
    async fn nothing_to_send_ends_no_mapping_with_something_open() -> io::Result<()> {
        for (main_open, opening) in [(true, 1), (false, 2)] {
            let shared = shared();
            let asked = Instant::now();
            let uid = Some(10_077);
            let mut table = table_of(&shared, uid, asked).await?;
            let id = table.mappings.get(&APP).map_or(0, |mapping| mapping.id);
            let socket = table
                .mappings
                .get(&APP)
                .map(|mapping| Arc::clone(&mapping.socket))
                .ok_or(io::ErrorKind::NotFound)?;
            if let Some(mapping) = table.mappings.get_mut(&APP) {
                mapping.owns_opening = opening;
                if !main_open {
                    mapping.end_main(&shared);
                }
            }
            let stand_in = SocketAddr::from(([198, 18, 0, 1], 4_000));
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let control = TcpStream::from_std({
                let stream = std::net::TcpStream::connect(listener.local_addr()?)?;
                stream.set_nonblocking(true)?;
                stream
            })?;
            let place = super::super::budget::Budget::new(4, 4)
                .take(uid)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            let own = own_place(&shared)?;
            let opened = Ok((UdpSocket::bind("127.0.0.1:0").await?, control));
            let wanted = Wanted {
                uid,
                exit: Exit::Direct,
                chains: 0,
            };
            let (mut reads, mut errors) = (Vec::new(), Vec::new());
            let left = leave_by(
                &mut table,
                ((APP, stand_in), id),
                (
                    named("a.test"),
                    &wanted,
                    socket,
                    (Some((opened, (place, own))), false),
                ),
                (&shared, &mut reads, &mut errors),
            );
            assert!(matches!(left, Leaving::Made(Made::Done)));
            assert!(
                table.mapping(APP, id).is_some(),
                "main open {main_open}, opening {opening}: a mapping with something open ended"
            );
        }
        Ok(())
    }

    /// Under a relay's name, the counters say what the label's rules did (fix round 5, review J's
    /// surviving mutants J17 and J22): an answer an identifier gave another peer than the holder is
    /// counted identified, one the holder takes is not; under a name no peer has, an answer without the
    /// identifiers of the stand-ins that wait there, all of them with some, is counted unidentified, and
    /// with one without among them, filtered.
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_the_counters_say_what_the_rules_did() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let server = SocketAddr::from(([192, 0, 2, 9], 3_478));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 3_478)));
        mapping.sent(a, &binding(0xa1, false));
        let way = PeerWay::through_tool(Target::Address(server));
        mapping.peer(&shared, (APP, server), now, (false, way));
        mapping.sent(server, &binding(0x51, false));
        let by_a = Target::Name("a.test".into(), 3_478);
        let identified = |shared: &Shared| shared.counters.snapshot()[IDENTIFIED];
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &binding(0xa1, true)), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == a));
        assert_eq!(identified(&shared), 0, "the holder's own");
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &binding(0x51, true)), now);
        assert!(matches!(got, LetIn::Peer(shown, ..) if shown == server));
        assert_eq!(identified(&shared), 1, "another peer's, by its identifier");
        // A name no peer has, `gone.test`, where `s` waits with identifiers.
        let s = SocketAddr::from(([198, 18, 0, 5], 3_478));
        mapping.peer(&shared, (APP, s), now, (false, tooled("s.test", 3_478)));
        mapping.sent(s, &binding(0x55, false));
        let gone = Target::Name("gone.test".into(), 3_478);
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&gone, b"no identifier"), now);
        assert!(matches!(got, LetIn::Unidentified));
        let w = SocketAddr::from(([198, 18, 0, 6], 3_478));
        mapping.peer(&shared, (APP, w), now, (false, tooled("w.test", 3_478)));
        mapping.sent(w, b"no identifier");
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&gone, b"no identifier"), now);
        assert!(matches!(got, LetIn::Filtered));
        Ok(())
    }

    /// Under a relay's name with no holder on the port, an answer comes in as another port of the
    /// name's newest live stand-in address, but not while a stand-in without identifiers contests the
    /// port; and an answer that names in the clear what one settled peer was sent is that peer's
    /// (fix round 5, review J's surviving mutants J20, J21, J24 and J28, each failing this).
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_without_a_holder_on_the_port_an_answer_comes_in() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        // `a.test` on 3478 at two stand-in addresses: the first from before it gave way in the stand-in
        // map, the second since.
        let old = SocketAddr::from(([198, 18, 0, 1], 3_478));
        let new = SocketAddr::from(([198, 18, 0, 9], 3_478));
        for shown in [old, new] {
            mapping.peer(&shared, (APP, shown), now, (false, tooled("a.test", 3_478)));
            mapping.sent(shown, b"no identifier");
        }
        let server = SocketAddr::from(([192, 0, 2, 9], 5_000));
        let way = PeerWay::through_tool(Target::Address(server));
        mapping.peer(&shared, (APP, server), now, (false, way));
        mapping.sent(server, &binding(0x51, false));
        let at_5000 = Target::Name("a.test".into(), 5_000);
        let to = |mapping: &mut Mapping, answer: &[u8], at: Instant| match mapping
            .main()
            .relayed_answer(&shared, APP, (&at_5000, answer), at)
        {
            LetIn::Peer(shown, ..) => Some(shown),
            _ => None,
        };
        assert_eq!(
            to(&mut mapping, &binding(0x51, true), now),
            Some(server),
            "the one settled peer sent it"
        );
        // `c.test`, without identifiers, waits on 5000: the port is contested.
        let c = SocketAddr::from(([198, 18, 0, 3], 5_000));
        mapping.peer(&shared, (APP, c), now, (false, tooled("c.test", 5_000)));
        mapping.sent(c, b"no identifier");
        assert_eq!(to(&mut mapping, b"data", now), None, "contested");
        let later = now + Duration::from_secs(200);
        for shown in [old, c, server] {
            if let Some(peer) = mapping.peers.get_mut(&shown) {
                peer.last = later;
            }
        }
        // While both live, the newest; once it ends, the old one, which lives.
        let newest = to(&mut mapping, b"data", now + shared.limits.udp_contest);
        assert_eq!(newest, Some(SocketAddr::from(([198, 18, 0, 9], 5_000))));
        if let Some(peer) = newest.and_then(|shown| mapping.peers.get_mut(&shown)) {
            peer.last = now;
        }
        mapping.sweep(now + Duration::from_secs(120), &shared);
        assert!(!mapping.peers.contains_key(&new), "the newest ended");
        assert_eq!(
            to(&mut mapping, b"data", later),
            Some(SocketAddr::from(([198, 18, 0, 1], 5_000)))
        );
        Ok(())
    }

    /// Under a relay's name, an identifier several peers were sent, and not the holder, is no one's,
    /// whatever their addresses: the association's fingerprints name a peer only where one alone keeps
    /// one, as the exclusive-or of several addresses may be any address, here a fifth peer's, four of
    /// them cancelling out (fix round 5, I4).
    #[tokio::test(flavor = "current_thread")]
    async fn under_a_name_what_five_were_sent_is_no_ones_whatever_their_addresses() -> io::Result<()>
    {
        let shared = shared();
        let now = Instant::now();
        let mut mapping = mapping(now).await?;
        let a = SocketAddr::from(([198, 18, 0, 1], 123));
        mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 123)));
        mapping.sent(a, &ntp(3, 40, 1));
        let stamp = 0xe9a1_0000_0000_0009;
        // 192.0.2.0 to .3 cancel out; .9 is left.
        for n in [0u8, 1, 2, 3, 9] {
            let server = SocketAddr::from(([192, 0, 2, n], 123));
            let way = PeerWay::through_tool(Target::Address(server));
            mapping.peer(&shared, (APP, server), now, (false, way));
            mapping.sent(server, &ntp(3, 40, stamp));
        }
        let by_a = Target::Name("a.test".into(), 123);
        let got = mapping
            .main()
            .relayed_answer(&shared, APP, (&by_a, &ntp(4, 24, stamp)), now);
        assert!(matches!(got, LetIn::Unmatched), "five were sent it");
        Ok(())
    }

    /// The contest spares a holder's QUIC answers, which carry its client's source ID as their
    /// destination, in the clear, once it keeps no keys (fix round 6, review K's m2): a stand-in settled
    /// under its own label, as review K's probe has it, and one bound to its server's address; a long
    /// header's answer and a short header's alike. A client whose source ID is empty, as Chromium's and
    /// Cronet's are, is not told apart so: its answers are cut while the contest lasts, an accepted limit.
    #[tokio::test(flavor = "current_thread")]
    async fn the_contest_spares_a_holders_quic_answers_by_its_source_id() -> io::Result<()> {
        let shared = shared();
        let now = Instant::now();
        let a = SocketAddr::from(([198, 18, 0, 1], 443));
        let c = SocketAddr::from(([198, 18, 0, 3], 443));
        let by_a = Target::Name("a.test".into(), 443);
        let server = Target::Address(SocketAddr::from(([192, 0, 2, 9], 443)));
        let dcid = [0xa0; 8];
        for (source, scid, spared) in [
            (&by_a, &[0xa5u8; 8][..], true),
            (&server, &[0xa5; 8][..], true),
            (&by_a, &[][..], false),
        ] {
            let mut mapping = mapping(now).await?;
            let initial = crate::quic::client_initial(1, (&dcid, scid), (0, &[0x01]), 1200)
                .ok_or(io::ErrorKind::InvalidData)?;
            mapping.peer(&shared, (APP, a), now, (false, tooled("a.test", 443)));
            mapping.sent(a, &initial);
            let answer = |pn| {
                crate::quic::server_initial(1, &dcid, (scid, &[0x5a; 8]), (pn, &[0x02, 0, 0, 0, 0]))
                    .ok_or(io::ErrorKind::InvalidData)
            };
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (source, &answer(0)?), now);
            assert!(matches!(got, LetIn::Peer(shown, ..) if shown == a));
            assert_eq!(mapping.peers[&a].standing, Standing::Settled);
            mapping.peer(&shared, (APP, c), now, (false, tooled("c.test", 443)));
            mapping.sent(c, b"no identifier");
            // A short header's 1-RTT packet, its destination ID the client's source ID.
            let mut short = vec![0x41];
            short.extend_from_slice(scid);
            short.extend_from_slice(&[0x77; 40]);
            for answer in [answer(1)?, short] {
                let got = mapping
                    .main()
                    .relayed_answer(&shared, APP, (source, &answer), now);
                assert_eq!(
                    matches!(got, LetIn::Peer(shown, ..) if shown == a),
                    spared,
                    "{source:?}, source ID of {} bytes, first byte {:#x}",
                    scid.len(),
                    answer[0]
                );
            }
            let got = mapping
                .main()
                .relayed_answer(&shared, APP, (source, b"no identifier"), now);
            assert!(matches!(got, LetIn::Unmatched), "the contest itself holds");
        }
        Ok(())
    }

    /// Review K's measure of fix round 5: what one address's records cost once many stand-ins of the
    /// app are bound to it, each by its identifier on a port of its own, and then all end. Fix round 6:
    /// 126 to 149 ms for 16,384 before, each step a walk of the address's stand-ins (ADR 0044).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "a measure, run with --release --ignored"]
    async fn measure_many_stand_ins_bound_to_one_address() -> io::Result<()> {
        for n in [1_024u32, 4_096, 16_384] {
            let mut sources = Sources::default();
            let far = IpAddr::from([192, 0, 2, 9]);
            let peers: Vec<(SocketAddr, SocketAddr)> = (0..n)
                .map(|k| {
                    let [_, _, hi, lo] = k.to_be_bytes();
                    let port = 1_024 + u16::try_from(k).unwrap_or(0);
                    (
                        SocketAddr::from(([198, 18, hi, lo], port)),
                        SocketAddr::new(far, port),
                    )
                })
                .collect();
            let start = Instant::now();
            for &(shown, from) in &peers {
                sources.add(shown, from);
            }
            let added = start.elapsed();
            let start = Instant::now();
            for &(_, from) in &peers {
                assert!(sources.shown(from.ip()).is_some());
            }
            let shown = start.elapsed();
            let start = Instant::now();
            for &(shown, from) in peers.iter().rev() {
                sources.remove(shown, from);
            }
            let removed = start.elapsed();
            eprintln!(
                "{n} stand-ins bound to one address: added in {added:?}, shown in {shown:?}, removed in \
                 {removed:?}"
            );
        }
        Ok(())
    }

    /// Review K's measure of fix round 5: the same under a relay's name, each stand-in bound beside under
    /// the first name on a port of its own, as Xray's `freedom` labels every answer from the first
    /// destination's address; and beside one another on one port. Fix round 6: 377 ms for 16,384 under
    /// one label before, each removal a walk of every label's stand-ins (ADR 0044).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "a measure, run with --release --ignored"]
    async fn measure_many_stand_ins_beside_one_label() -> io::Result<()> {
        for n in [1_024u32, 4_096, 16_384] {
            for one_port in [false, true] {
                let mut sources = Sources::default();
                let peers: Vec<SocketAddr> = (0..n)
                    .map(|k| {
                        let [_, _, hi, lo] = k.to_be_bytes();
                        let port = if one_port {
                            3_478
                        } else {
                            1_024 + u16::try_from(k).unwrap_or(0)
                        };
                        SocketAddr::from(([198, 18, hi, lo], port))
                    })
                    .collect();
                let start = Instant::now();
                for &shown in &peers {
                    sources.add_named_beside(shown, "first.test");
                }
                let added = start.elapsed();
                let start = Instant::now();
                for &shown in &peers {
                    sources.leave_beside_on(shown);
                }
                let removed = start.elapsed();
                eprintln!(
                    "{n} stand-ins beside one label, one port {one_port}: added in {added:?}, removed in \
                     {removed:?}"
                );
            }
        }
        Ok(())
    }

    /// Whether each association's fingerprints hold exactly how many of its peers keep each, and their
    /// addresses' exclusive-or, as its peers' own lists say: for the model check below.
    fn fingerprints_match(mapping: &mut Mapping) -> Result<(), String> {
        for via in [None, Some(1u64), Some(2u64)] {
            let mut expected: HashMap<u64, (u32, [u8; 16])> = HashMap::new();
            for (shown, peer) in &mapping.peers {
                if peer.via != via {
                    continue;
                }
                for &fp in &peer.told {
                    let entry = expected.entry(fp).or_insert((0, [0; 16]));
                    entry.0 += 1;
                    let mut keepers = Keepers::default();
                    keepers.toggle(shown.ip());
                    for (kept, byte) in entry.1.iter_mut().zip(keepers.addresses) {
                        *kept ^= byte;
                    }
                }
            }
            let Some(scope) = mapping.scope(via) else {
                if expected.is_empty() {
                    continue;
                }
                return Err(format!("{via:?}: peers with no association"));
            };
            let actual: HashMap<u64, (u32, [u8; 16])> = scope
                .sources
                .told
                .0
                .iter()
                .map(|(&fp, keepers)| (fp, (keepers.peers, keepers.addresses)))
                .collect();
            if actual != expected {
                return Err(format!(
                    "{via:?}: index {} entries, peers {} entries",
                    actual.len(),
                    expected.len()
                ));
            }
        }
        Ok(())
    }

    /// Review K's model check of fix round 5's index: in 40 runs of 3,000 random steps (peers made on the
    /// mapping's association and two of a stand-in's own, by an address and by a name, IPv4 and IPv6;
    /// STUN and NTP identifiers sent them; sweeps; associations ended and made again), each association's
    /// fingerprints hold exactly, after every step, how many of its peers keep each and their addresses'
    /// exclusive-or, as its peers' own lists say (fix round 6; it fails at step 16 with a peer's end not
    /// forgetting its fingerprints).
    #[tokio::test(flavor = "current_thread")]
    async fn the_fingerprint_index_matches_its_peers_at_every_step() -> io::Result<()> {
        let shared = shared();
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..40u64 {
            let start = Instant::now();
            let mut now = start;
            let mut mapping = mapping(now).await?;
            mapping.owns.insert(1, own_for_test(&shared).await?);
            mapping.owns.insert(2, own_for_test(&shared).await?);
            for step in 0..3000u64 {
                now += Duration::from_millis(10);
                match next(10) {
                    0..=2 => {
                        let port = [3_478u16, 123][usize::try_from(next(2)).unwrap_or(0)];
                        let n = u8::try_from(next(3)).unwrap_or(0);
                        let ip: IpAddr = match next(3) {
                            0 => IpAddr::from([198, 18, 0, n]),
                            1 => IpAddr::from([192, 0, 2, n]),
                            _ => IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(n)]),
                        };
                        let shown = SocketAddr::new(ip, port);
                        let way = if next(2) == 0 {
                            tooled(&format!("n{n}.test"), port)
                        } else {
                            PeerWay::through_tool(Target::Address(shown))
                        };
                        let via = [None, Some(1), Some(2)][usize::try_from(next(3)).unwrap_or(0)];
                        if !mapping.peers.contains_key(&shown)
                            && let Some(scope) = mapping.scope(via)
                        {
                            scope.into_peer(&shared, (APP, shown), now, (false, way));
                        }
                    }
                    3..=6 => {
                        let peers: Vec<SocketAddr> = mapping.peers.keys().copied().collect();
                        if peers.is_empty() {
                            continue;
                        }
                        let to = peers[usize::try_from(next(peers.len() as u64)).unwrap_or(0)];
                        let k = u8::try_from(next(80)).unwrap_or(0);
                        let payload = if to.port() == 123 {
                            ntp(3, 40, u64::from(k) + 1)
                        } else {
                            binding(k, false)
                        };
                        mapping.sent(to, &payload);
                    }
                    7 => {
                        let peers: Vec<SocketAddr> = mapping.peers.keys().copied().collect();
                        for shown in peers {
                            if next(3) != 0
                                && let Some(peer) = mapping.peers.get_mut(&shown)
                            {
                                peer.last = now;
                            }
                        }
                        let since = now.checked_sub(Duration::from_millis(5)).unwrap_or(start);
                        mapping.sweep(since, &shared);
                    }
                    8 => {
                        if next(10) == 0 {
                            let own = 1 + next(2);
                            mapping.end_own(own, &shared);
                            mapping.owns.insert(own, own_for_test(&shared).await?);
                        }
                    }
                    _ => {
                        if next(20) == 0 {
                            mapping.end_main(&shared);
                        }
                    }
                }
                fingerprints_match(&mut mapping).map_err(|why| {
                    io::Error::other(format!("round {round}, step {step}: {why}"))
                })?;
            }
        }
        Ok(())
    }
}
