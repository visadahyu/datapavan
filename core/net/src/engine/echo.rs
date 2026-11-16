//! ICMP echo through the tunnel (ADR 0044, decision 5; review finding 21). An app's ping leaves
//! through an unprivileged ping socket of the engine's own (`SOCK_DGRAM` with `IPPROTO_ICMP` or
//! `IPPROTO_ICMPV6`), protected, one for each app address, echo identifier and address pinged, at
//! most `Limits::echo_sockets` at once, each ending once no echo passed either way for
//! `Limits::echo_idle`. The kernel gives such a socket an echo identifier of its own and writes it
//! into every request, so each reply is rebuilt for the app: from the address it pinged, with the
//! app's identifier, the sequence number and data kept, and checksums made anew.
//!
//! Android cannot say whose an echo is: `getConnectionOwnerUid` knows only TCP and UDP. So while a
//! chain sends any app through the user's tool, no echo leaves directly, since it could be a chained
//! app's: each is answered at once with "administratively prohibited". Where the kernel refuses ping
//! sockets, as a probe at the engine's start finds, echo of that IP version is dropped, as before this
//! unit, and counted.
//!
//! Echo is not a flow: the connection log gets no record of it, and the log's format is unchanged.
//! The counters are all that is kept of it.

use super::udp::with_buffer;
use super::upstream::protect;
use super::{BATCH, Counters, Loop, Shared, lock, send_to_app};
use crate::packet::{self, ECHO_REPLY, ECHO_REPLY_V6, Echo};
use crate::standins::is_stand_in;
use crate::tun::Tun;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// A ping socket's key: the app's address, the echo identifier of its requests, and the address it
/// pings. An app's ping socket keeps one identifier for its life, so each app socket and address
/// pinged gets a socket of the engine's.
type Key = (IpAddr, u16, IpAddr);

/// At most this many requests of a key wait while its socket is made and protected, which takes a
/// question to Android of a few milliseconds; more are dropped, as by a full queue.
const HELD: usize = 8;

/// The engine's ping sockets, and whether the kernel lets it make them.
pub(super) struct Echoes {
    /// Whether the kernel let the engine make an IPv4 ping socket at its start.
    v4: bool,
    /// The same for IPv6.
    v6: bool,
    table: Arc<Mutex<Table<UdpSocket>>>,
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
}

impl<S> Default for Table<S> {
    fn default() -> Self {
        Self {
            sockets: HashMap::new(),
            numbered: 0,
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
}

enum State<S> {
    /// The socket is being made and protected; these requests wait for it, in order.
    Opening(Vec<Vec<u8>>),
    Open(Arc<S>),
}

/// What becomes of a request.
enum Next<S> {
    /// It goes out through this socket, to this address.
    Send(Arc<S>, IpAddr),
    /// It waits for a socket to be made, numbered so, and goes out first through it.
    Open(u64),
    /// It waits behind others for the socket being made.
    Held,
    /// It is dropped: the cap is full, or too many wait for the socket.
    Full,
}

impl<S> Table<S> {
    /// What becomes of a request, `message`, of `key` to `target`, at `now`, with at most `cap`
    /// sockets. A new key takes its place at once, before its socket is made, so that the cap holds
    /// for the sockets being made too.
    fn request(
        &mut self,
        key: Key,
        target: IpAddr,
        message: &[u8],
        now: Instant,
        cap: usize,
    ) -> Next<S> {
        if let Some(entry) = self.sockets.get_mut(&key) {
            return match &mut entry.state {
                State::Open(socket) => {
                    entry.last = now;
                    Next::Send(Arc::clone(socket), entry.target)
                }
                State::Opening(held) if held.len() < HELD => {
                    held.push(message.to_vec());
                    entry.last = now;
                    Next::Held
                }
                State::Opening(_) => Next::Full,
            };
        }
        if self.sockets.len() >= cap {
            return Next::Full;
        }
        self.numbered += 1;
        self.sockets.insert(
            key,
            Entry {
                number: self.numbered,
                target,
                state: State::Opening(vec![message.to_vec()]),
                last: now,
            },
        );
        Next::Open(self.numbered)
    }

    /// The socket of `key` numbered `number` is open: the requests that waited for it, to send now,
    /// or `None` when its place is gone.
    fn opened(&mut self, key: Key, number: u64, socket: Arc<S>) -> Option<Vec<Vec<u8>>> {
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

    /// A reply came at `now`. `false` when the place is gone.
    fn heard(&mut self, key: Key, number: u64, now: Instant) -> bool {
        self.entry(key, number)
            .map(|entry| entry.last = now)
            .is_some()
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
        let next = lock(&self.echoes.table).request(
            key,
            target,
            message,
            Instant::now(),
            self.shared.limits.echo_sockets,
        );
        // No await between the chain's check above and the send: a chain set meanwhile from Watch's
        // side is seen by the next request.
        match next {
            // The kernel writes the socket's own identifier and the checksum into the request.
            Next::Send(socket, to) => {
                let sent = socket.try_send_to(message, SocketAddr::new(to, 0));
                count_sent(&self.shared, sent.is_ok());
            }
            Next::Open(number) => {
                tokio::spawn(carry(
                    key,
                    (number, target),
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

/// Counts a request that left, or one whose socket could not send it, as when its buffer is full.
fn count_sent(shared: &Shared, sent: bool) {
    let counters = &shared.counters;
    Counters::add(
        if sent {
            &counters.echo_carried
        } else {
            &counters.echo_dropped
        },
        1,
    );
}

/// The task of one ping socket: makes and protects it, sends the requests that waited for it, then
/// hands the app each reply from its target until no echo passed either way for `Limits::echo_idle`,
/// the network beneath changes, or a chain comes on.
async fn carry(
    key: Key,
    (number, target): (u64, IpAddr),
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    table: Arc<Mutex<Table<UdpSocket>>>,
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
    if socket.writable().await.is_err() {
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
    for message in held {
        count_sent(&shared, socket.try_send_to(&message, to).is_ok());
    }
    let idle = shared.limits.echo_idle;
    loop {
        let until = lock(&table).until(key, number, Instant::now(), idle);
        let Some(until) = until else {
            break;
        };
        tokio::select! {
            _ = changes.changed() => break,
            () = tokio::time::sleep_until(until.into()) => {}
            ready = socket.readable() => {
                if ready.is_err() {
                    break;
                }
                let (replies, failed) =
                    with_buffer(|buffer| receive(&socket, buffer, key, target));
                // While a chain is on, nothing comes in on the direct path either.
                if shared.chains_any_app() {
                    break;
                }
                if !replies.is_empty() && !lock(&table).heard(key, number, Instant::now()) {
                    break;
                }
                for reply in replies {
                    // Counted before it is written: an app that reads it may read the counters next.
                    Counters::add(&shared.counters.echo_replies, 1);
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
/// holds it: it only sends and receives datagrams, with `sendto` and `recvfrom`, which is all a ping
/// socket takes, and so wraps one without unsafe code.
///
/// It sets no `IP_RECVERR` or `IPV6_RECVERR`: the ICMP errors that answer a ping on the network
/// beneath ("unreachable", "time exceeded") never reach the app, which sees no reply, and the reply's
/// hop limit is the engine's own, not the one it arrived with. Without the option, an unconnected
/// ping socket's reads never fail for such an error. A later unit that sets it must read the error
/// queue on `Interest::ERROR` with `MSG_ERRQUEUE`, as `errors::queued` does for UDP mappings, and treat
/// a read failing with such an error as `errors::from_icmp` does, so that a pending error does not
/// end the socket.
async fn open(shared: &Arc<Shared>, target: IpAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::from_std(std::net::UdpSocket::from(ping_socket(target.is_ipv4())?))?;
    protect(shared, socket.as_fd()).await?;
    Ok(socket)
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
/// pinged, with its own echo identifier, the sequence number and data kept. The kernel hands a ping
/// socket every echo reply that bears its identifier, from wherever it comes: only the target's are
/// the app's. `true` when the socket failed.
fn receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
    (app, id, destination): Key,
    target: IpAddr,
) -> (Vec<Vec<u8>>, bool) {
    let reply = if target.is_ipv4() {
        ECHO_REPLY
    } else {
        ECHO_REPLY_V6
    };
    let mut replies = Vec::new();
    for _ in 0..BATCH {
        let (n, from) = match socket.try_recv_from(buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
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
        if let Some(packet) = packet::echo_reply(destination, app, id, sequence, data) {
            replies.push(packet);
        }
    }
    (replies, false)
}

#[cfg(test)]
mod tests {
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

    fn key(id: u16, destination: IpAddr) -> Key {
        (APP, id, destination)
    }

    fn request(table: &mut Table<()>, key: Key, now: Instant, cap: usize) -> Next<()> {
        table.request(key, key.2, b"ping", now, cap)
    }

    /// The cap counts the sockets being made as well as the open ones; a request of a key that has a
    /// socket, or one being made, takes no other place, and too many waiting for one are dropped; a
    /// place given up makes room.
    #[test]
    fn the_cap_holds_for_sockets_being_made_and_open() {
        let mut table = Table::<()>::default();
        let now = Instant::now();
        let Next::Open(first) = request(&mut table, key(1, SERVER), now, 2) else {
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
            Next::Open(_)
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
            Next::Open(_)
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
        let (Next::Open(first), Next::Open(second)) = (
            request(&mut table, one, start, 2),
            request(&mut table, two, start, 2),
        ) else {
            unreachable!("two sockets")
        };
        table.opened(one, first, Arc::new(()));
        table.opened(two, second, Arc::new(()));
        assert!(table.heard(one, first, at(3)), "a reply at 3 s");
        assert!(matches!(request(&mut table, two, at(5), 2), Next::Send(..)));
        assert_eq!(table.until(one, first, at(12), idle), Some(at(13)));
        assert_eq!(table.until(one, first, at(13), idle), None, "swept");
        assert!(!table.heard(one, first, at(13)), "gone");
        assert_eq!(table.until(two, second, at(13), idle), Some(at(15)));
        let Next::Open(third) = request(&mut table, key(3, OTHER), at(13), 2) else {
            unreachable!("its place is free")
        };
        // The same key again, once the cap has room.
        table.end(key(3, OTHER), third);
        let Next::Open(again) = request(&mut table, one, at(14), 2) else {
            unreachable!("a socket anew")
        };
        assert_ne!(again, first);
        table.end(one, first);
        assert!(
            matches!(request(&mut table, one, at(14), 2), Next::Held),
            "the old task ended the new socket"
        );
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
