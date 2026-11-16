//! ICMP echo through the tunnel (ADR 0044, decision 5; review finding 21). An app's ping leaves
//! through an unprivileged ping socket of the engine's own (`SOCK_DGRAM` with `IPPROTO_ICMP` or
//! `IPPROTO_ICMPV6`), protected, one for each app address, echo identifier and address pinged, at
//! most `Limits::echo_sockets` at once, each ending once no echo passed either way for
//! `Limits::echo_idle`. The kernel gives such a socket an echo identifier of its own and writes it
//! into every request, so each reply is rebuilt for the app: from the address it pinged, with the
//! app's identifier, the sequence number and data kept, checksums made anew, and the hop limit it
//! arrived with. Each request leaves with the app's own hop limit, and the errors the path answers it
//! with, a router's "time exceeded" among them, reach the app from whoever sent them, one at most for
//! each request (ADR 0044, unit 11b): a traceroute or `ping -t` through Watch sees the path.
//!
//! Android cannot say whose an echo is: `getConnectionOwnerUid` knows only TCP and UDP. So while a
//! chain sends any app through the user's tool, no echo leaves directly, since it could be a chained
//! app's: each is answered at once with "administratively prohibited". Where the kernel refuses ping
//! sockets, as a probe at the engine's start finds, echo of that IP version is dropped, as before this
//! unit, and counted.
//!
//! Echo is not a flow: the connection log gets no record of it, and the log's format is unchanged.
//! The counters are all that is kept of it: since unit 11b its bytes too, in the engine's byte counters,
//! as Android counts them to Watch's own sockets.

use super::errors::{self, Queued, Tally};
use super::udp::{network_moved, with_buffer};
use super::upstream::protect;
use super::{BATCH, Counters, Loop, Shared, hops, lock, send_to_app};
use crate::packet::{self, ECHO_REPLY, ECHO_REPLY_V6, Echo};
use crate::standins::is_stand_in;
use crate::tun::Tun;
use nix::libc;
use nix::sys::socket::{setsockopt, sockopt};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

/// A ping socket's key: the app's address, the echo identifier of its requests, and the address it
/// pings. An app's ping socket keeps one identifier for its life, so each app socket and address
/// pinged gets a socket of the engine's.
type Key = (IpAddr, u16, IpAddr);

/// At most this many requests of a key wait while its socket is made and protected, which takes a
/// question to Android of a few milliseconds; more are dropped, as by a full queue.
const HELD: usize = 8;

/// At most this many of a socket's latest requests may each be answered by one error from the path
/// (ADR 0044, unit 11b). A ping sends one a second and a router answers within a few, so 64 hold every
/// request an error could still come for; an error for an older one is dropped, as is one for a
/// request never sent, or a second for one request.
const ASKED: usize = 64;

/// The engine's ping sockets, and whether the kernel lets it make them.
pub(super) struct Echoes {
    /// Whether the kernel let the engine make an IPv4 ping socket at its start.
    v4: bool,
    /// The same for IPv6.
    v6: bool,
    table: Arc<Mutex<Table<Pinger>>>,
}

impl Echoes {
    /// Makes one ping socket of each IP version, and closes it at once: where the kernel refuses
    /// one (`EACCES` outside `ping_group_range`, `EPERM` or `EPROTONOSUPPORT` on a kernel or a policy
    /// without them, `EAFNOSUPPORT` without IPv6), every request of that version is dropped and
    /// counted, as before the engine carried echo, rather than failing once for each.
    pub(super) fn probe() -> Self {
        Self {
            v4: ping_socket(true).is_ok(),
            v6: ping_socket(false).is_ok(),
            table: Arc::default(),
        }
    }

    fn supports(&self, destination: IpAddr) -> bool {
        if destination.is_ipv4() {
            self.v4
        } else {
            self.v6
        }
    }
}

/// The ping sockets by their key, each open or being made. `S` is the socket: the unit tests hold
/// none.
struct Table<S> {
    sockets: HashMap<Key, Entry<S>>,
    /// The number the last entry got.
    numbered: u64,
    /// How many sockets ended at the cap to make room for a new one, since the counters took them.
    made_room: u64,
}

impl<S> Default for Table<S> {
    fn default() -> Self {
        Self {
            sockets: HashMap::new(),
            numbered: 0,
            made_room: 0,
        }
    }
}

struct Entry<S> {
    /// Tells this entry from a later one under the same key, so that a socket's task never ends the
    /// socket that took its place.
    number: u64,
    /// Where its requests go: the address pinged, or the network's resolver for the tunnel's DNS
    /// address.
    target: IpAddr,
    state: State<S>,
    /// When an echo last passed either way.
    last: Instant,
    /// Its latest requests, the latest last, at most [`ASKED`], until an error from the path answers
    /// one: each may be answered by one, and is noted when its reply came.
    asked: VecDeque<Asked>,
    /// Wakes the socket's task when its place is given to a new socket at the cap, so that it closes
    /// the socket then rather than when it next wakes.
    ended: Arc<Notify>,
}

/// A request of a ping socket's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Asked {
    sequence: u16,
    /// Whether its reply came.
    replied: bool,
}

enum State<S> {
    /// The socket is being made and protected; these requests wait for it, in order, each with the
    /// app's hop limit.
    Opening(Vec<(Vec<u8>, u8)>),
    Open(Arc<S>),
}

/// What becomes of a request.
enum Next<S> {
    /// It goes out through this socket, to this address.
    Send(Arc<S>, IpAddr),
    /// It waits for a socket to be made, numbered so, and goes out first through it; the socket's task
    /// is woken by this when its place is given to another.
    Open(u64, Arc<Notify>),
    /// It waits behind others for the socket being made.
    Held,
    /// It is dropped: the cap is full, or too many wait for the socket.
    Full,
}

impl<S> Table<S> {
    /// What becomes of a request, `message` with the app's hop limit `hops`, of `key` to `target`, at
    /// `now`, with at most `cap` sockets, of which one `quiet` so long may end to make room
    /// ([`Table::make_room`]). A new key takes its place at once, before its socket is made, so that
    /// the cap holds for the sockets being made too. A request that is not dropped may be answered by
    /// one error from the path.
    fn request(
        &mut self,
        key: Key,
        target: IpAddr,
        (message, hops): (&[u8], u8),
        now: Instant,
        (cap, quiet): (usize, Duration),
    ) -> Next<S> {
        let sequence = packet::u16_at(message, 6).unwrap_or(0);
        if let Some(entry) = self.sockets.get_mut(&key) {
            let next = match &mut entry.state {
                State::Open(socket) => Next::Send(Arc::clone(socket), entry.target),
                State::Opening(held) if held.len() < HELD => {
                    held.push((message.to_vec(), hops));
                    Next::Held
                }
                State::Opening(_) => return Next::Full,
            };
            entry.last = now;
            entry.asks(sequence);
            return next;
        }
        if self.sockets.len() >= cap && !self.make_room(now, quiet) {
            return Next::Full;
        }
        self.numbered += 1;
        let ended = Arc::new(Notify::new());
        let mut entry = Entry {
            number: self.numbered,
            target,
            state: State::Opening(vec![(message.to_vec(), hops)]),
            last: now,
            asked: VecDeque::new(),
            ended: Arc::clone(&ended),
        };
        entry.asks(sequence);
        self.sockets.insert(key, entry);
        Next::Open(self.numbered, ended)
    }

    /// At the cap, ends one open socket to make room for a new one (ADR 0044, unit 11b), the first
    /// there is of: the least recently active socket whose every request has had its reply or error,
    /// as one-shot pings leave behind them (`ping -c 1 -t N`, which traceroute apps run once for each
    /// probe, each with a socket and an identifier of its own); then the least recently active through
    /// which nothing passed either way for `quiet`. A socket still being made is never ended, nor one
    /// that a ping still sends through and waits on: it sends every second. Its task is woken to close
    /// it; its app's next request, if any, gets a socket anew. `false` when none may end.
    fn make_room(&mut self, now: Instant, quiet: Duration) -> bool {
        let open = || {
            self.sockets
                .iter()
                .filter(|(_, entry)| matches!(entry.state, State::Open(_)))
        };
        let answered = open()
            .filter(|(_, entry)| entry.answered())
            .min_by_key(|(_, entry)| entry.last);
        let victim = answered
            .or_else(|| {
                open()
                    .filter(|(_, entry)| now.saturating_duration_since(entry.last) >= quiet)
                    .min_by_key(|(_, entry)| entry.last)
            })
            .map(|(key, _)| *key);
        let Some(entry) = victim.and_then(|key| self.sockets.remove(&key)) else {
            return false;
        };
        entry.ended.notify_one();
        self.made_room += 1;
        true
    }

    /// An error from the path for the request numbered `sequence` of the socket of `key` numbered
    /// `number`: whether a request of that number still waited for one, which it then no longer does;
    /// `None` when the place is gone.
    fn answers(&mut self, key: Key, number: u64, sequence: u16) -> Option<bool> {
        let entry = self.entry(key, number)?;
        let at = entry
            .asked
            .iter()
            .position(|asked| asked.sequence == sequence);
        Some(at.and_then(|at| entry.asked.remove(at)).is_some())
    }

    /// The socket of `key` numbered `number` is open: the requests that waited for it, to send now,
    /// or `None` when its place is gone.
    fn opened(&mut self, key: Key, number: u64, socket: Arc<S>) -> Option<Vec<(Vec<u8>, u8)>> {
        let entry = self.entry(key, number)?;
        match std::mem::replace(&mut entry.state, State::Open(socket)) {
            State::Opening(held) => Some(held),
            State::Open(_) => Some(Vec::new()),
        }
    }

    /// The socket could not be made or protected: its place ends, and with it the requests that
    /// waited for it, how many they were.
    fn failed(&mut self, key: Key, number: u64) -> u64 {
        match self.remove(key, number) {
            Some(State::Opening(held)) => held.len() as u64,
            _ => 0,
        }
    }

    /// Replies to the requests numbered `replied`, or errors from the path, came at `now`. `false` when
    /// the place is gone.
    fn heard(&mut self, key: Key, number: u64, now: Instant, replied: &[u16]) -> bool {
        let Some(entry) = self.entry(key, number) else {
            return false;
        };
        entry.last = now;
        for &sequence in replied {
            if let Some(asked) = entry
                .asked
                .iter_mut()
                .find(|asked| asked.sequence == sequence && !asked.replied)
            {
                asked.replied = true;
            }
        }
        true
    }

    /// When the socket of `key` numbered `number` will have passed nothing either way for `idle`, or
    /// `None` once it has, its place then given up, or when the place is gone. Its task asks this
    /// each time it wakes, so an idle socket is swept by its own timer, with no packet needed.
    fn until(&mut self, key: Key, number: u64, now: Instant, idle: Duration) -> Option<Instant> {
        let until = self.entry(key, number)?.last + idle;
        if now < until {
            return Some(until);
        }
        self.remove(key, number);
        None
    }

    /// The place of the socket numbered `number` ends, if it is still under `key`.
    fn end(&mut self, key: Key, number: u64) {
        self.remove(key, number);
    }

    fn entry(&mut self, key: Key, number: u64) -> Option<&mut Entry<S>> {
        self.sockets
            .get_mut(&key)
            .filter(|entry| entry.number == number)
    }

    fn remove(&mut self, key: Key, number: u64) -> Option<State<S>> {
        if self.sockets.get(&key)?.number != number {
            return None;
        }
        self.sockets.remove(&key).map(|entry| entry.state)
    }
}

impl<S> Entry<S> {
    /// A request numbered `sequence` goes out, or waits to: one error from the path may answer it.
    fn asks(&mut self, sequence: u16) {
        if self.asked.len() == ASKED {
            self.asked.pop_front();
        }
        self.asked.push_back(Asked {
            sequence,
            replied: false,
        });
    }

    /// Whether each of its requests has had its reply or an error: nothing more may come for it.
    fn answered(&self) -> bool {
        self.asked.iter().all(|asked| asked.replied)
    }
}

impl Loop {
    /// An app's echo request, `packet`: refused while a chain is on, dropped where the kernel allows
    /// no ping socket, else sent on through the ping socket of its key, made for it if it has none.
    /// No record of it goes to the connection log, whose format this leaves as it is.
    pub(super) async fn echo(&self, packet: &[u8], request: &Echo) {
        let counters = &self.shared.counters;
        // A stand-in address is reached only through the tool, which carries no echo: from an app
        // that goes directly, it can only be one left over from a chain that ended. A ping to a
        // multicast or broadcast address is refused without an answer, which no error may give.
        if self.shared.chains_any_app() || is_stand_in(request.destination) {
            Counters::add(&counters.echo_refused, 1);
            if let Some(error) = packet::echo_refused(packet, request) {
                self.send(&error).await;
            }
            return;
        }
        if !self.echoes.supports(request.destination) {
            Counters::add(&counters.echo_unsupported, 1);
            return;
        }
        // The tunnel's own DNS address leads to the network's resolver, as for UDP and TCP; until
        // Watch knows that resolver, a ping to it goes nowhere, and so does one to a resolver of the
        // other IP version, which the app's ICMP or ICMPv6 message cannot reach: its socket would
        // refuse every request and hold a place for `Limits::echo_idle`.
        let target = self
            .shared
            .target(SocketAddr::new(request.destination, 0))
            .map(|target| target.ip())
            .filter(|target| target.is_ipv4() == request.destination.is_ipv4());
        let (Some(message), Some(target)) = (packet.get(request.icmp..request.length), target)
        else {
            Counters::add(&counters.echo_dropped, 1);
            return;
        };
        let key = (request.source, request.id, request.destination);
        let limits = &self.shared.limits;
        let (next, made_room) = {
            let mut table = lock(&self.echoes.table);
            let next = table.request(
                key,
                target,
                (message, request.hops),
                Instant::now(),
                (limits.echo_sockets, limits.echo_quiet),
            );
            (next, std::mem::take(&mut table.made_room))
        };
        Counters::add(&counters.echo_evicted, made_room);
        // No await between the chain's check above and the send: a chain set meanwhile from Watch's
        // side is seen by the next request.
        match next {
            // The kernel writes the socket's own identifier and the checksum into the request.
            Next::Send(socket, to) => {
                let sent = socket.send(message, SocketAddr::new(to, 0), request.hops);
                count_sent(&self.shared, &sent);
            }
            Next::Open(number, ended) => {
                tokio::spawn(carry(
                    key,
                    (number, target, ended),
                    Arc::clone(&self.tun),
                    Arc::clone(&self.shared),
                    Arc::clone(&self.echoes.table),
                    self.changes.clone(),
                ));
            }
            Next::Held => {}
            Next::Full => Counters::add(&counters.echo_dropped, 1),
        }
    }
}

/// Counts a request that left, with its bytes up (ADR 0044, unit 11b), or one whose socket could not
/// send it, as when its buffer is full. Its bytes are what the ping socket sent, the ICMP message,
/// header and data, as UDP's are what its sockets send: Android counts them, with their IP headers, to
/// Watch, whose own counters left them out before.
fn count_sent(shared: &Shared, sent: &io::Result<usize>) {
    let counters = &shared.counters;
    match sent {
        Ok(n) => {
            Counters::add(&counters.echo_carried, 1);
            Counters::add(&counters.bytes_up, *n as u64);
        }
        Err(_) => Counters::add(&counters.echo_dropped, 1),
    }
}

/// The task of one ping socket: makes and protects it, sends the requests that waited for it, then
/// hands the app each error from the path that answers one of its requests and each reply from its
/// target, until no echo passed either way for `Limits::echo_idle`, the network beneath changes, or a
/// chain comes on.
async fn carry(
    key: Key,
    (number, target, ended): (u64, IpAddr, Arc<Notify>),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    table: Arc<Mutex<Table<Pinger>>>,
    mut changes: watch::Receiver<u64>,
) {
    // Only a change after the socket opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    // A socket that cannot be made, as where Android's policy refuses what the probe allowed, or
    // protected, gives back its place, and what waited for it is dropped.
    let Ok(socket) = open(&shared, target).await.map(Arc::new) else {
        let dropped = lock(&table).failed(key, number);
        Counters::add(&shared.counters.echo_dropped, dropped);
        return;
    };
    // Tokio learns that a new socket is writable only once it waits for it. That wait comes here,
    // while the socket is still being made and every request of its key waits behind it: from here
    // on, each request leaves with `try_send_to`, with no await between the chain's check and the
    // send. Sent with an await, a request could leave after a chain came on, and the next of the key
    // would find the socket not yet known writable, and be dropped ahead of those waiting.
    if socket.socket.writable().await.is_err() {
        let dropped = lock(&table).failed(key, number);
        Counters::add(&shared.counters.echo_dropped, dropped);
        return;
    }
    let held = lock(&table).opened(key, number, Arc::clone(&socket));
    let Some(held) = held else {
        return;
    };
    if shared.chains_any_app() {
        // A chain came on while the socket was made: what waited for it does not leave either. Its
        // app asked before the chain, so it is not answered; its ping finds no reply.
        Counters::add(&shared.counters.echo_refused, held.len() as u64);
        lock(&table).end(key, number);
        return;
    }
    let to = SocketAddr::new(target, 0);
    for (message, hops) in held {
        count_sent(&shared, &socket.send(&message, to, hops));
    }
    let idle = shared.limits.echo_idle;
    loop {
        let until = lock(&table).until(key, number, Instant::now(), idle);
        let Some(until) = until else {
            break;
        };
        tokio::select! {
            _ = changes.changed() => break,
            // Its place went to a new socket at the cap.
            () = ended.notified() => break,
            () = tokio::time::sleep_until(until.into()) => {}
            ready = socket.socket.ready(Interest::READABLE | Interest::ERROR) => {
                if !ready.is_ok_and(|ready| !ready.is_read_closed()) {
                    break;
                }
                // The errors first, which the socket's queue holds apart, each with what it quoted
                // of the request it answers; then the replies, which may come after a read that took
                // a pending error: the socket goes on.
                let (queued, (replies, failed)) = with_buffer(|buffer| {
                    let queued = errors::take(&socket.socket, buffer);
                    (queued, receive(&socket.socket, buffer, key, target))
                });
                // While a chain is on, nothing comes in on the direct path either.
                if shared.chains_any_app() {
                    break;
                }
                // What the socket read as the network beneath moved, an error about the old network's
                // path among it, is not passed on: the socket ends with the move, as a mapping does.
                if network_moved(&changes) {
                    break;
                }
                let mut tally = Tally::default();
                let told = {
                    let mut table = lock(&table);
                    let told = path_errors(queued, key, target, &mut tally, |sequence| {
                        table.answers(key, number, sequence) == Some(true)
                    });
                    let quiet = told.is_empty() && replies.is_empty();
                    let answered: Vec<u16> =
                        replies.iter().map(|&(_, _, sequence)| sequence).collect();
                    if !quiet && !table.heard(key, number, Instant::now(), &answered) {
                        break;
                    }
                    told
                };
                // Counted before they are written: an app that reads them may read the counters next.
                tally.count(&shared.counters, true);
                for error in told {
                    send_to_app(&tun, &shared, &error).await;
                }
                for (reply, read, _) in replies {
                    // Counted before it is written: an app that reads it may read the counters next.
                    Counters::add(&shared.counters.echo_replies, 1);
                    Counters::add(&shared.counters.bytes_down, read as u64);
                    send_to_app(&tun, &shared, &reply).await;
                }
                if failed {
                    break;
                }
            }
        }
    }
    lock(&table).end(key, number);
}

/// A ping socket of the engine's own toward `target`, protected before it sends anything, so that
/// its requests leave on the network beneath rather than back into the tunnel. Tokio's `UdpSocket`
/// holds it: it only sends and receives datagrams, which is all a ping socket takes, and so wraps one
/// without unsafe code. The kernel gives the hop limit each reply arrived with (ADR 0044, unit 11b);
/// where it refuses, a reply keeps the engine's own.
///
/// It queues the ICMP errors that answer its requests on the network beneath (`IP_RECVERR`,
/// `IPV6_RECVERR`): "time exceeded", "destination unreachable", "fragmentation needed" and "packet too
/// big" then reach the app as they would without Watch, where before the app saw no reply (unit 11b).
/// With the option, each such error also fails the socket's next read or send once, which then takes
/// it: such a failure (`errors::from_icmp`) does not end the socket, and the error itself is read off
/// its queue on `Interest::ERROR`. Where the kernel refuses the option, errors are lost, as before.
async fn open(shared: &Arc<Shared>, target: IpAddr) -> io::Result<Pinger> {
    let socket = UdpSocket::from_std(std::net::UdpSocket::from(ping_socket(target.is_ipv4())?))?;
    protect(shared, socket.as_fd()).await?;
    let _ = errors::keep(&socket, target.is_ipv4());
    let _ = hops::ask(&socket, target.is_ipv4());
    Ok(Pinger {
        socket,
        hops: AtomicU16::new(UNSET),
    })
}

/// A ping socket of the engine's, which sends each request with the app's hop limit (ADR 0044, unit
/// 11b): in IPv4 in the request's own ancillary data, as UDP's datagrams go; in IPv6 as the socket's
/// option, set only when it differs from the one the socket has, since Linux's IPv6 ping sockets read
/// no ancillary data before 5.18 (`ping_v6_sendmsg`), and most phones run older kernels. One socket
/// serves one app socket and address pinged, whose hop limit changes only when the app changes it, as
/// a traceroute does between its probes; the engine's tasks share one thread, so no other request
/// comes between the option and its send.
struct Pinger {
    socket: UdpSocket,
    /// The IPv6 hop limit last set on the socket, or [`UNSET`] before the first or after one failed.
    hops: AtomicU16,
}

/// No hop limit set on a ping socket yet: none of the 256 a request can have.
const UNSET: u16 = u16::MAX;

impl Pinger {
    /// Sends a request, `message`, to `to` with the app's hop limit `hops`, without waiting for room
    /// in the socket's buffer. An ICMP error the kernel holds for the socket fails its next send once,
    /// and that request does not leave: it is sent again. The socket's task reads the error itself
    /// from the socket's error queue.
    fn send(&self, message: &[u8], to: SocketAddr, hops: u8) -> io::Result<usize> {
        match self.send_once(message, to, hops) {
            Err(error) if errors::from_icmp(&error) => self.send_once(message, to, hops),
            sent => sent,
        }
    }

    fn send_once(&self, message: &[u8], to: SocketAddr, hops: u8) -> io::Result<usize> {
        if to.is_ipv4() {
            return hops::try_send(&self.socket, message, to, hops);
        }
        let wanted = u16::from(hops);
        if self.hops.load(Ordering::Relaxed) != wanted {
            let set = setsockopt(&self.socket, sockopt::Ipv6Ttl, &libc::c_int::from(hops));
            let now = if set.is_ok() { wanted } else { UNSET };
            self.hops.store(now, Ordering::Relaxed);
        }
        self.socket.try_send_to(message, to)
    }
}

/// An unprivileged ping socket, not blocking, not bound and not connected. Linux makes one only for a
/// process in a group of `net.ipv4.ping_group_range`, which Android sets to every group; the kernel
/// then picks the socket's echo identifier, and writes it and the checksum into every request.
fn ping_socket(v4: bool) -> io::Result<Socket> {
    let (domain, protocol) = if v4 {
        (Domain::IPV4, Protocol::ICMPV4)
    } else {
        (Domain::IPV6, Protocol::ICMPV6)
    };
    Socket::new(domain, Type::DGRAM.nonblocking(), Some(protocol))
}

/// The replies a ping socket holds, read into `buffer`, each rebuilt for the app: from the address it
/// pinged, with its own echo identifier, the sequence number and data kept, and the hop limit it
/// arrived with; each with how many bytes the socket read, the ICMP message, for the byte counters, and
/// the sequence number it answers. The kernel hands a ping socket every echo reply that bears its
/// identifier, from wherever it comes: only the target's are the app's. `true` when the socket failed.
fn receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    (app, id, destination): Key,
    target: IpAddr,
) -> (Vec<(Vec<u8>, usize, u16)>, bool) {
    let reply = if target.is_ipv4() {
        ECHO_REPLY
    } else {
        ECHO_REPLY_V6
    };
    let mut replies = Vec::new();
    let mut control = hops::room();
    for _ in 0..BATCH {
        let (n, from, arrived) = match hops::try_recv(socket, buffer, &mut control) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // An ICMP error, which this read took: the error queue holds it, with what it answered.
            Err(error) if errors::from_icmp(&error) => continue,
            Err(_) => return (replies, true),
        };
        // What a ping socket reads starts with the ICMP header: type, code, checksum, identifier
        // (the socket's own), sequence number.
        let [kind, _, _, _, _, _, high, low, data @ ..] = &buffer[..n] else {
            continue;
        };
        if from.ip() != target || *kind != reply {
            continue;
        }
        let sequence = u16::from_be_bytes([*high, *low]);
        if let Some(mut packet) = packet::echo_reply(destination, app, id, sequence, data) {
            if let Some(hops) = arrived {
                packet::set_hops(&mut packet, hops);
            }
            replies.push((packet, n, sequence));
        }
    }
    (replies, false)
}

/// The errors from the path a ping socket read off its queue, `queued`, each for the app as it would
/// reach it without Watch (ADR 0044, unit 11b): from the router or host that sent it, or from the
/// address the app pinged where the kernel names none or it is the target itself; quoting the app's own
/// request, with the app's identifier and the sequence number and data the error quoted, by which the
/// app's kernel finds its ping socket and the app its request. One is dropped, and counted in `tally`,
/// unless it answers a request of this socket's to its target that no error answered yet, as `asked`
/// says and notes: one for another destination, a sequence number never sent, or a second error for
/// one request, as a forged one would be.
fn path_errors(
    queued: Vec<Queued>,
    (app, id, destination): Key,
    target: IpAddr,
    tally: &mut Tally,
    mut asked: impl FnMut(u16) -> bool,
) -> Vec<Vec<u8>> {
    let request = if target.is_ipv4() {
        packet::ECHO_REQUEST
    } else {
        packet::ECHO_REQUEST_V6
    };
    let mut told = Vec::new();
    for error in queued {
        // What an error queues for a ping socket starts with the request's ICMP header: type, code,
        // checksum, identifier (the socket's own), sequence number; then the data, as far as quoted.
        let sequence = match error.quoted[..] {
            [kind, _, _, _, _, _, high, low, ..]
                if kind == request && error.destination.ip() == target =>
            {
                u16::from_be_bytes([high, low])
            }
            _ => {
                tally.unasked();
                continue;
            }
        };
        if !asked(sequence) {
            tally.unasked();
            continue;
        }
        let data = error.quoted.get(8..).unwrap_or_default();
        let from = errors::sender(error.offender, target, destination);
        let packet = packet::echo_request_of(app, destination, id, sequence, data)
            .and_then(|quoted| errors::to_app(error.told, &quoted, (from, app), error.hops));
        if let Some(packet) = packet {
            tally.passed(error.told);
            told.push(packet);
        }
    }
    told
}

#[cfg(test)]
mod tests {
    use super::super::errors::Told;
    use super::super::tests::shared;
    use super::super::{COUNTERS, run};
    use super::*;
    use crate::Chain;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;
    use std::os::fd::OwnedFd;
    use tokio::sync::mpsc;

    const APP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 10, 1));
    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    /// The places of the echo counters in the snapshot.
    const ECHO_CARRIED: usize = 33;
    const ECHO_REFUSED: usize = 35;
    const ECHO_DROPPED: usize = 37;
    const SKIPPED: usize = 8;
    const TIME_EXCEEDED: usize = 41;
    const ECHO_ERRORS: usize = 43;
    const ERRORS_UNASKED: usize = 44;

    fn key(id: u16, destination: IpAddr) -> Key {
        (APP, id, destination)
    }

    /// A long time: no socket is quiet enough to end at the cap.
    const LONG: Duration = Duration::from_secs(3_600);

    fn request(table: &mut Table<()>, key: Key, now: Instant, cap: usize) -> Next<()> {
        table.request(key, key.2, (b"ping", 64), now, (cap, LONG))
    }

    /// The cap counts the sockets being made as well as the open ones; a request of a key that has a
    /// socket, or one being made, takes no other place, and too many waiting for one are dropped; a
    /// place given up makes room.
    #[test]
    fn the_cap_holds_for_sockets_being_made_and_open() {
        let mut table = Table::<()>::default();
        let now = Instant::now();
        let Next::Open(first, _) = request(&mut table, key(1, SERVER), now, 2) else {
            unreachable!("the first socket")
        };
        for _ in 1..HELD {
            assert!(matches!(
                request(&mut table, key(1, SERVER), now, 2),
                Next::Held
            ));
        }
        assert!(
            matches!(request(&mut table, key(1, SERVER), now, 2), Next::Full),
            "too many wait"
        );
        assert!(matches!(
            request(&mut table, key(2, SERVER), now, 2),
            Next::Open(..)
        ));
        assert!(
            matches!(request(&mut table, key(1, OTHER), now, 2), Next::Full),
            "the cap, with both sockets still being made"
        );
        let held = table.opened(key(1, SERVER), first, Arc::new(()));
        assert_eq!(held.map(|held| held.len()), Some(HELD));
        assert!(matches!(
            request(&mut table, key(1, SERVER), now, 2),
            Next::Send(_, SERVER)
        ));
        assert!(matches!(
            request(&mut table, key(1, OTHER), now, 2),
            Next::Full
        ));
        table.end(key(1, SERVER), first);
        assert!(matches!(
            request(&mut table, key(1, OTHER), now, 2),
            Next::Open(..)
        ));
        // A socket that could not be made gives back its place, and its requests are counted.
        let Some(Entry { number, .. }) = table.sockets.get(&key(2, SERVER)) else {
            unreachable!("the second socket")
        };
        let number = *number;
        assert_eq!(table.failed(key(2, SERVER), number), 1);
        assert_eq!(table.sockets.len(), 1);
    }

    /// A socket through which nothing passed for `idle`, either way, is swept as its task wakes, and
    /// its place freed; a reply keeps it as a request does, and a task that ends late does not end the
    /// socket that took its key since.
    #[test]
    fn an_idle_socket_is_swept_and_its_place_freed() {
        let mut table = Table::<()>::default();
        let start = Instant::now();
        let idle = Duration::from_secs(10);
        let at = |seconds| start + Duration::from_secs(seconds);
        let (one, two) = (key(1, SERVER), key(2, SERVER));
        let (Next::Open(first, _), Next::Open(second, _)) = (
            request(&mut table, one, start, 2),
            request(&mut table, two, start, 2),
        ) else {
            unreachable!("two sockets")
        };
        table.opened(one, first, Arc::new(()));
        table.opened(two, second, Arc::new(()));
        assert!(table.heard(one, first, at(3), &[]), "a reply at 3 s");
        assert!(matches!(request(&mut table, two, at(5), 2), Next::Send(..)));
        assert_eq!(table.until(one, first, at(12), idle), Some(at(13)));
        assert_eq!(table.until(one, first, at(13), idle), None, "swept");
        assert!(!table.heard(one, first, at(13), &[]), "gone");
        assert_eq!(table.until(two, second, at(13), idle), Some(at(15)));
        let Next::Open(third, _) = request(&mut table, key(3, OTHER), at(13), 2) else {
            unreachable!("its place is free")
        };
        // The same key again, once the cap has room.
        table.end(key(3, OTHER), third);
        let Next::Open(again, _) = request(&mut table, one, at(14), 2) else {
            unreachable!("a socket anew")
        };
        assert_ne!(again, first);
        table.end(one, first);
        assert!(
            matches!(request(&mut table, one, at(14), 2), Next::Held),
            "the old task ended the new socket"
        );
    }

    /// At the cap, a socket ends to make room for a new one (ADR 0044, unit 11b): first the least
    /// recently active whose every request has had its reply or error, as a one-shot ping leaves
    /// behind; then, with none such, the least recently active quiet for `quiet`; never one still being
    /// made, nor one that waits on a reply and was active since. The socket ended is woken to close.
    #[test]
    fn at_the_cap_an_answered_or_quiet_socket_makes_room() {
        let mut table = Table::<()>::default();
        let start = Instant::now();
        let at = |millis| start + Duration::from_millis(millis);
        let quiet = Duration::from_secs(2);
        let ask = |table: &mut Table<()>, key: Key, sequence: u16, now| {
            let mut message = vec![packet::ECHO_REQUEST, 0, 0, 0, 0, 1];
            message.extend_from_slice(&sequence.to_be_bytes());
            table.request(key, key.2, (&message, 64), now, (3, quiet))
        };
        let (one, two, three, four) = (
            key(1, SERVER),
            key(2, SERVER),
            key(3, SERVER),
            key(4, OTHER),
        );
        let mut numbers = Vec::new();
        for (key, now) in [(one, 0), (two, 100), (three, 200)] {
            let Next::Open(number, ended) = ask(&mut table, key, 1, at(now)) else {
                unreachable!("a socket")
            };
            table.opened(key, number, Arc::new(()));
            numbers.push((number, ended));
        }
        // Each waits on its reply, and none is quiet for two seconds yet: the cap holds.
        assert!(matches!(ask(&mut table, four, 1, at(1_000)), Next::Full));
        // The second's reply came: it makes room, though the first was active longer ago.
        assert!(table.heard(two, numbers[1].0, at(1_100), &[1]));
        assert!(matches!(
            ask(&mut table, four, 1, at(1_200)),
            Next::Open(..)
        ));
        assert!(!table.sockets.contains_key(&two));
        assert_eq!(table.made_room, 1);
        // Its task is woken: a permit waits for it.
        let woken = numbers[1].1.notified();
        let mut woken = std::pin::pin!(woken);
        assert!(woken.as_mut().enable(), "the socket's task not woken");
        // A request still being made is never ended, and with none answered, the one quiet longest
        // ends once quiet for two seconds: the first, at 2,000 ms.
        let five = key(5, OTHER);
        assert!(matches!(ask(&mut table, five, 1, at(1_900)), Next::Full));
        assert!(matches!(
            ask(&mut table, five, 1, at(2_000)),
            Next::Open(..)
        ));
        assert!(!table.sockets.contains_key(&one));
        assert!(table.sockets.contains_key(&three) && table.sockets.contains_key(&four));
        assert_eq!(table.made_room, 2);
        // A socket that sends on is not quiet: the third asks again at 2,100 ms, the fourth, still
        // being made, may not end, and the fifth was made since: nothing may end at 2,300 ms.
        assert!(matches!(
            ask(&mut table, three, 2, at(2_100)),
            Next::Send(..)
        ));
        assert!(matches!(
            ask(&mut table, key(6, OTHER), 1, at(2_300)),
            Next::Full
        ));
    }

    /// An error from the path reaches the app from the router that sent it, with the hop limit it came
    /// with, quoting the app's own request, with the app's identifier and the sequence number and data
    /// the router quoted (ADR 0044, unit 11b); one at most for each request: one for a request never
    /// sent, for another destination than the socket's, a second for one request, or one that quotes
    /// no echo request, is dropped and counted.
    #[test]
    fn an_error_from_the_path_answers_one_request_once() {
        let mut table = Table::<()>::default();
        let now = Instant::now();
        let key = key(0x0707, SERVER);
        let message = |sequence: u16| {
            let mut message = vec![packet::ECHO_REQUEST, 0, 0, 0, 0x12, 0x34];
            message.extend_from_slice(&sequence.to_be_bytes());
            message.extend_from_slice(b"data");
            message
        };
        let Next::Open(number, _) = table.request(key, SERVER, (&message(1), 3), now, (4, LONG))
        else {
            unreachable!("a socket")
        };
        assert!(matches!(
            table.request(key, SERVER, (&message(2), 3), now, (4, LONG)),
            Next::Held
        ));
        let router = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let error = |destination, quoted: Vec<u8>| Queued {
            destination: SocketAddr::new(destination, 0),
            told: Told::TimeExceeded,
            offender: Some(router),
            hops: Some(9),
            quoted,
        };
        let queued = vec![
            error(SERVER, message(1)),
            error(SERVER, message(1)),
            error(OTHER, message(2)),
            error(SERVER, message(3)),
            error(SERVER, vec![packet::ECHO_REPLY, 0, 0, 0, 0x12, 0x34, 0, 2]),
            error(SERVER, message(2)[..4].to_vec()),
        ];
        let mut tally = Tally::default();
        let told = path_errors(queued, key, SERVER, &mut tally, |sequence| {
            table.answers(key, number, sequence) == Some(true)
        });
        let [told] = told.as_slice() else {
            unreachable!("one error: {told:?}")
        };
        assert_eq!(&told[12..16], &[192, 0, 2, 1], "from the router");
        assert_eq!(&told[16..20], &[10, 1, 10, 1], "to the app");
        assert_eq!((told[8], &told[20..22]), (9, &[11, 0][..]));
        let quoted = packet::echo_request(&told[28..]);
        assert_eq!(
            quoted.map(|request| (
                request.source,
                request.destination,
                request.id,
                request.sequence
            )),
            Ok((APP, SERVER, 0x0707, 1))
        );
        assert_eq!(&told[28 + 28..], b"data");
        let shared = shared();
        tally.count(&shared.counters, true);
        let counters = shared.counters.snapshot();
        assert_eq!(
            (
                counters[ECHO_ERRORS],
                counters[TIME_EXCEEDED],
                counters[ERRORS_UNASKED]
            ),
            (1, 1, 5)
        );
        // The second request's error still passes, once.
        assert_eq!(table.answers(key, number, 2), Some(true));
        assert_eq!(table.answers(key, number, 2), Some(false));
        table.end(key, number);
        assert_eq!(table.answers(key, number, 2), None, "the place is gone");
    }

    /// While a chain sends any app through the tool, an app's ping is answered at once with
    /// "administratively prohibited", quoting it, and counted, unless it went to a multicast address,
    /// which no error answers; so is a ping to a stand-in address without a chain. Neither needs a ping
    /// socket. A request whose checksum is wrong, and an echo reply from an app, stay skipped.
    #[tokio::test(flavor = "current_thread")]
    async fn a_ping_is_refused_at_once_while_a_chain_is_on() -> io::Result<()> {
        let shared = Arc::new(shared());
        *lock(&shared.chain) = Some(Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: 10_200,
            apps: Some([10_300].into_iter().collect()),
            udp: true,
            log_destinations: false,
        }));
        let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        app_end.set_nonblocking(true)?;
        let app = tokio::net::UnixDatagram::from_std(app_end)?;
        let (_stop, stop) = watch::channel(false);
        let (_network, network) = watch::channel(0);
        let (_swaps, swaps) = mpsc::unbounded_channel();
        tokio::spawn(run(
            Tun::new(OwnedFd::from(engine_end))?,
            1500,
            Arc::clone(&shared),
            stop,
            network,
            swaps,
        ));
        let ping = |to: [u8; 4], kind_of: u8| {
            let mut packet = Vec::new();
            PacketBuilder::ipv4([10, 1, 10, 1], to, 64)
                .icmpv4_raw(kind_of, 0, [0x12, 0x34, 0, 7])
                .write(&mut packet, b"ping data")
                .unwrap_or_default();
            packet
        };
        let answer = async || -> io::Result<Vec<u8>> {
            let mut buffer = vec![0u8; 2048];
            let n = tokio::time::timeout(Duration::from_secs(3), app.recv(&mut buffer))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
            buffer.truncate(n);
            Ok(buffer)
        };

        // A ping to a multicast address is refused with no answer: the first answer is the next one's.
        app.send(&ping([224, 0, 0, 1], packet::ECHO_REQUEST))
            .await?;
        let request = ping([198, 51, 100, 9], packet::ECHO_REQUEST);
        app.send(&request).await?;
        let error = answer().await?;
        assert_eq!(
            (&error[12..16], &error[16..20]),
            (&[198, 51, 100, 9][..], &[10, 1, 10, 1][..])
        );
        assert_eq!(&error[20..22], &[3, 13]);
        assert_eq!(&error[28..], &request[..]);

        *lock(&shared.chain) = None;
        let mut bad = ping([198, 51, 100, 9], packet::ECHO_REQUEST);
        let last = bad.len() - 1;
        bad[last] ^= 1;
        app.send(&bad).await?;
        app.send(&ping([198, 51, 100, 9], packet::ECHO_REPLY))
            .await?;
        let stand_in = ping([198, 18, 0, 1], packet::ECHO_REQUEST);
        app.send(&stand_in).await?;
        let error = answer().await?;
        assert_eq!(&error[20..22], &[3, 13]);
        assert_eq!(&error[28..], &stand_in[..]);

        let counters: [u64; COUNTERS] = shared.counters.snapshot();
        assert_eq!(counters[ECHO_REFUSED], 3);
        assert_eq!(counters[SKIPPED], 2);
        assert_eq!((counters[ECHO_CARRIED], counters[ECHO_DROPPED]), (0, 0));
        Ok(())
    }
}
