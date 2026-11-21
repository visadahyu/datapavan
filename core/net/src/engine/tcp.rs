//! TCP through the tunnel (ADR 0012): the app's SYN held until its owner and the server are known, the
//! rewriting to the engine's listener, Android's own stack ending the connection, and the relay.

use super::blocks::{Gate, Step};
use super::budget::Place;
use super::chain::{Route, connect_through};
use super::logbook::FlowBytes;
use super::naming::Begun;
use super::proxied::{Handshake, Sniff};
use super::resolver::{TcpLookups, connect_lookups};
use super::upstream::{connect_tcp, owner};
use super::{Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, is_unreachable, lock};
use crate::nat::{Listener, Lookup, Nat};
use crate::packet;
use crate::packet::{ACK, Packet, RST, SYN, TCP, Unreachable};
use crate::standins::is_stand_in;
use crate::tun::Tun;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{getsockopt, sockopt};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Notify;
use zeroize::Zeroizing;

/// An upstream connection waiting for Android's TCP stack to hand over the app's end.
pub(super) struct Upstream {
    pub(super) stream: TcpStream,
    /// The flow, as it opened.
    pub(super) opened: Opened,
    /// Its bytes, for the log.
    pub(super) bytes: Option<Arc<FlowBytes>>,
}

pub(super) type Pending = Arc<Mutex<HashMap<u16, Upstream>>>;

/// Binds the listener that terminates rewritten connections of one IP version on the tunnel's
/// address, and accepts them in a task of its own; its port goes to `Shared::listener`. A first bind
/// that fails, as on a tunnel with no address of that version, leaves the task binding one again, as
/// after a listener stopped listening, and the port at 0 meanwhile.
pub(super) fn listen(
    address: IpAddr,
    fake: IpAddr,
    pending: &Pending,
    shared: &Arc<Shared>,
    nat: &Arc<Mutex<Nat>>,
) {
    let first = bind(SocketAddr::new(address, 0))
        .ok()
        .map(|(listener, port)| {
            shared.listener(address.is_ipv4()).bound(port);
            listener
        });
    tokio::spawn(accept(
        first,
        (address, fake),
        Arc::clone(pending),
        Arc::clone(shared),
        Arc::clone(nat),
    ));
}

/// The engine's listener of one IP version, as the rewriting reads it (ADR 0044, unit 12b): its port,
/// 0 while none listens, and its generation, which grows each time a listener stops listening. The two
/// are one atomic value, so that they are read together: the port in the low 16 bits, the generation
/// above.
///
/// A connection not yet relayed is the engine's only while the listener its SYN was rewritten to is the
/// one now. Once a listener stops listening, any app may bind its port with `SO_REUSEADDR`, which Linux
/// allows whatever the app's UID, and listen there: what the engine rewrote to that port, and has not
/// had its own listener accept, may reach that app's listener instead, and what comes from that port
/// may be that app's. A connection the relay holds is the engine's on its port for good, since the
/// engine's own socket holds its four ends there.
pub(super) struct Listening {
    now: AtomicU64,
    /// Woken when an app's SYN finds no listener, so that one is bound again at once rather than at
    /// the end of a pause that may have grown long.
    pub(super) wanted: Notify,
}

impl Listening {
    pub(super) fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            wanted: Notify::new(),
        }
    }

    /// The listener now.
    pub(super) fn now(&self) -> Listener {
        let now = self.now.load(Ordering::Acquire);
        Listener {
            port: u16::try_from(now & 0xffff).unwrap_or(0),
            generation: u32::try_from(now >> 16).unwrap_or(u32::MAX),
        }
    }

    /// A listener of this generation was bound on `port`.
    pub(super) fn bound(&self, port: u16) {
        self.now.update(Ordering::AcqRel, Ordering::Acquire, |now| {
            (now & !0xffff) | u64::from(port)
        });
    }

    /// The listener stopped listening: none listens until one is bound again, and that one is of a new
    /// generation, so that every connection not yet relayed that was rewritten to the old one is the
    /// engine's no more.
    pub(super) fn lost(&self) {
        self.now.update(Ordering::AcqRel, Ordering::Acquire, |now| {
            ((now >> 16) + 1) << 16
        });
    }

    /// An app's SYN found no listener.
    fn want(&self) {
        self.wanted.notify_one();
    }
}

/// A listener on `at`, and its port. `SO_REUSEADDR` is set, as tokio's own `bind` sets it.
fn bind(at: SocketAddr) -> io::Result<(TcpListener, u16)> {
    let socket = if at.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(at)?;
    let listener = socket.listen(BACKLOG)?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// The listener's queue of connections Android's stack completed and the engine has not accepted
/// yet: tokio's own for `TcpListener::bind`.
const BACKLOG: u32 = 1_024;

impl Loop {
    /// Forgets connections that fell silent, and the upstream connections still waiting for them.
    pub(super) fn sweep(&self) {
        let forgotten = lock(&self.nat).sweep(Instant::now());
        let mut pending = lock(&self.pending);
        for port in forgotten {
            lock(&self.shared.wire).remove(&port);
            // A connection Android's stack never handed over still ends in the log.
            if let Some(upstream) = pending.remove(&port) {
                self.shared.finish(upstream.opened.id);
            }
        }
    }

    pub(super) async fn tcp(&self, packet: &mut [u8], parsed: &Packet) {
        let v4 = parsed.source.is_ipv4();
        let (tun, fake) = self.ends(v4);
        let listening = self.shared.listener(v4);
        let listener = listening.now();
        let flags = packet::tcp_flags(packet, parsed);
        let now = Instant::now();
        if parsed.source.ip() == tun
            && parsed.destination.ip() == fake
            && self
                .androids_answer(packet, parsed, (flags, listener), now)
                .await
        {
            return;
        }
        if parsed.source.ip() != tun {
            Counters::add(&self.shared.counters.skipped, 1);
            return;
        }
        let syn = flags & SYN != 0 && flags & ACK == 0;
        let lookup = lock(&self.nat).lookup(parsed.source, parsed.destination, syn, now);
        match lookup {
            Lookup::Open { port, to, relayed } if relayed || to == listener => {
                let bytes = lock(&self.shared.wire).get(&port).cloned();
                if let Some(bytes) = bytes {
                    bytes.up(&self.shared, 0, packet.len());
                }
                // To the listener the connection was rewritten to: a relayed one stays on its port
                // when a listener is bound anew.
                if packet::set_ends(
                    packet,
                    parsed,
                    SocketAddr::new(fake, port),
                    SocketAddr::new(tun, to.port),
                )
                .is_some()
                {
                    self.send(packet).await;
                }
            }
            // Rewritten to a listener that is gone, and never handed to the relay: never rewritten to
            // its port again, which another app may hold now (`Listening`), a SYN sent again among
            // them. The app is reset, as a stack that lost the connection resets it, and the upstream
            // connection with it.
            Lookup::Open { port, .. } => {
                // The log has it as the app saw it end: refused, for a SYN sent again, else reset.
                let saw = if syn {
                    Outcome::Refused
                } else {
                    Outcome::Failed
                };
                self.reset_before_the_relay(port, now, Some(saw));
                self.reset(packet, parsed, flags).await;
            }
            // No listener now: refused at once, as Android's stack refuses a SYN no listener takes,
            // and a listener bound again at once rather than at the end of its pause. While any app goes
            // through a WireGuard tunnel, whose connections need no listener, the route decides first
            // (`open` refuses a direct one there the same way).
            Lookup::New(port) if listener.port == 0 && !self.shared.tunnels.any() => {
                lock(&self.nat).release(port);
                listening.want();
                self.reset(packet, parsed, flags).await;
            }
            Lookup::New(port) => {
                // As many connections as allowed wait for their servers: this SYN is dropped, as by a
                // full queue, and its port freed at once, since it never reached Android's stack. The
                // app's stack sends it again, by then perhaps with room (ADR 0044, decision 3).
                let Some(waiting) = Waiting::take(&self.shared) else {
                    lock(&self.nat).release(port);
                    Counters::add(&self.shared.counters.tcp_refused, 1);
                    return;
                };
                let held = Held {
                    packet: packet.to_vec(),
                    parsed: *parsed,
                    port,
                };
                tokio::spawn(open(
                    held,
                    waiting,
                    Arc::clone(&self.tun),
                    Arc::clone(&self.shared),
                    Arc::clone(&self.nat),
                    Arc::clone(&self.pending),
                ));
            }
            // A SYN sent again while the server has not answered: the held one goes on.
            Lookup::Waiting => {}
            // A segment of a connection the engine does not know, as after it restarted: a reset,
            // as a real stack sends (RFC 9293 3.10.7.1), so that the app opens a new one at once.
            Lookup::Unknown => {
                if !syn {
                    self.reset(packet, parsed, flags).await;
                }
            }
            Lookup::Full => {
                if syn {
                    self.reset(packet, parsed, flags).await;
                }
            }
        }
    }

    /// A segment from the tunnel's address to the fake peer, which Android's stack sends from the
    /// engine's listener: rewritten back to the app as if from the real destination when it may be
    /// Android's answer to a connection, else dropped. Whether it was taken here: one that is not, from
    /// another port than a listener's, is an app's own, to the fake peer, and goes the apps' way.
    async fn androids_answer(
        &self,
        packet: &mut [u8],
        parsed: &Packet,
        (flags, listener): (u8, Listener),
        now: Instant,
    ) -> bool {
        // A SYN without ACK: no listener sends one, only a socket of an app's on the tunnel's address
        // connecting to the fake peer, perhaps from a port bound beside a listener's, which could pass
        // for Android's answer to a connection not yet relayed in the moment before the kernel makes
        // the listener's own request socket for it (third round, nit 1). Dropped.
        if flags & SYN != 0 && flags & ACK == 0 {
            Counters::add(&self.shared.counters.skipped, 1);
            return true;
        }
        // From the port of the listener the connection was rewritten to (`Nat::answered`).
        let (port, from) = (parsed.destination.port(), parsed.source.port());
        let answered = lock(&self.nat).answered(port, from);
        let Some(entry) = answered else {
            // From the listener now, for a connection the engine forgot: dropped, as before.
            return listener.port != 0 && from == listener.port;
        };
        let reset = flags & RST != 0;
        // Rewritten to a listener that is gone, and never handed to the relay: whoever holds its port
        // now may be another app (`Listening`), and only a reset passes, which ends the connection at
        // worst, as Android's stack resets those the old listener held when it stops listening. The
        // app's next segment ends it otherwise.
        if !entry.relayed && entry.listener != listener && !reset {
            return true;
        }
        // Back to the app as if from the real destination. Only a segment that passes keeps the
        // connection from the sweep: one dropped above leaves it to be forgotten.
        if packet::set_ends(packet, parsed, entry.destination, entry.app).is_some() {
            lock(&self.nat).seen(port, now);
            let bytes = lock(&self.shared.wire).get(&port).cloned();
            if let Some(bytes) = bytes {
                bytes.down(&self.shared, 0, packet.len());
            }
            if reset && !entry.relayed {
                self.reset_before_the_relay(port, now, None);
            }
            self.send(packet).await;
        }
        true
    }

    /// Resets the app's end of a connection the engine cannot carry, as a real stack answers a
    /// segment of a connection it does not have (RFC 9293 3.10.7.1): a SYN with a reset that
    /// acknowledges it, so that the app reads "refused", and any other segment but a reset with one
    /// whose sequence number is the segment's acknowledgement, which the app takes.
    async fn reset(&self, packet: &[u8], parsed: &Packet, flags: u8) {
        let reset = if flags & SYN != 0 && flags & ACK == 0 {
            let sequence = packet::tcp_sequence(packet, parsed);
            packet::tcp_reset(
                parsed.destination,
                parsed.source,
                0,
                Some(sequence.wrapping_add(1)),
            )
        } else if flags & RST == 0 && flags & ACK != 0 {
            let ack = packet::tcp_acknowledgement(packet, parsed);
            packet::tcp_reset(parsed.destination, parsed.source, ack, None)
        } else {
            None
        };
        if let Some(reset) = reset {
            self.send(&reset).await;
        }
    }

    /// A connection its listener never handed to the relay ended: Android's stack reset it, as when
    /// the listener it waited in stopped listening, as Android's netd makes it when it destroys the
    /// sockets on the tunnel's address (ADR 0044, unit 12b), or when no listener took its SYN; or the
    /// listener it was rewritten to is gone, and the engine resets the app. The upstream connection
    /// waiting for the handover would otherwise stay open, the server's end with it, until the sweep
    /// forgets the port, ten minutes on. So it is reset now, as the app's end was, the rewriting
    /// forgotten, and the flow ended in the log: as opened when Android's stack reset it, as a relayed
    /// connection a peer resets is, and with `saw`, what the app saw, when the engine reset it itself
    /// (third round, nit 2). One the accept loop has taken already is the relay's to end, as any
    /// connection that fails.
    fn reset_before_the_relay(&self, port: u16, now: Instant, saw: Option<Outcome>) {
        let Some(upstream) = lock(&self.pending).remove(&port) else {
            return;
        };
        lock(&self.nat).remove(port, now);
        lock(&self.shared.wire).remove(&port);
        let _ = upstream.stream.set_zero_linger();
        match saw {
            Some(outcome) => self.shared.finish_as(upstream.opened.id, outcome),
            None => self.shared.finish_closed(upstream.opened.id),
        }
    }
}

/// A connection's first SYN, held until Android has named the app and the server has accepted.
struct Held {
    packet: Vec<u8>,
    parsed: Packet,
    port: u16,
}

/// One of the places for a connection waiting for its server, given back when it is dropped.
struct Waiting(Arc<Shared>);

impl Waiting {
    /// A place, if fewer than `Limits::tcp_waiting` connections wait now.
    fn take(shared: &Arc<Shared>) -> Option<Self> {
        let cap = shared.limits.tcp_waiting;
        shared
            .tcp_waiting
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < cap).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(shared)))
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.tcp_waiting.fetch_sub(1, Ordering::AcqRel);
    }
}

#[allow(clippy::too_many_lines)]
/// Opens the upstream connection for a held SYN; `_waiting` holds its place until the server has
/// answered or failed, and so does its place in its app's share.
async fn open(
    mut held: Held,
    _waiting: Waiting,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
    pending: Pending,
) {
    let (app, destination) = (held.parsed.source, held.parsed.destination);
    let Some((uid, upstream, _share, via, tunnel)) = upstream(&shared, app, destination).await
    else {
        return refused(&held, &shared, &nat);
    };
    // Through a WireGuard tunnel (W7): no upstream connection, and the SYN never reaches Android's stack.
    // Its packets go into the tunnel, its own TCP end to end with the server.
    if let Some(t) = tunnel {
        lock(&nat).release(held.port);
        if let Some(answer) =
            super::tunnels::open_tcp(&shared, (uid, t), (held.packet, held.parsed))
            && tun.send(&answer).await.is_ok()
        {
            Counters::add(&shared.counters.packets_out, 1);
        }
        return;
    }
    // The listener now: one bound anew while the server was asked may be on another port, and none
    // may be bound, which the app then sees as a refusal, and the log records so (third round, nit 2).
    let listening = shared.listener(app.is_ipv4());
    let listener = listening.now();
    let blocked = upstream.as_ref().err().and_then(Blocked::of);
    let outcome = match &upstream {
        Ok(_) if listener.port == 0 => Outcome::Refused,
        Ok(_) => Outcome::Opened,
        Err(_) if blocked.is_some() => Outcome::Blocked,
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Outcome::Refused,
        Err(error) if is_unreachable(error) => Outcome::Unreachable,
        Err(_) => Outcome::Failed,
    };
    let Begun {
        id,
        name,
        named_by,
        network,
        held_until,
    } = shared.begin(destination, uid);
    let by_dns = (named_by == NamedBy::Dns)
        .then_some(name.as_deref())
        .flatten();
    let (dns, resolver) = shared.dns_use(destination, by_dns);
    let dns_name = by_dns.map(str::to_owned);
    // Its first bytes are read for a proxy only where it went directly and is not the user's tool's own: a
    // chained app's flows, and the tool's, carry what the tool carries (ADR 0046, decision 3).
    let sniffs =
        via.is_none() && uid.is_none_or(|uid| shared.chain().is_none_or(|chain| chain.tool != uid));
    let opened = Opened {
        id,
        port: destination.port(),
        destination,
        sniffs,
        dns,
        uid,
        dns_held_until: held_until,
    };
    // Recorded the way it was routed, not by the chain as it is now (review b3 of W5's second part, R2).
    let bytes = shared.record_via(
        Flow {
            id,
            protocol: TCP,
            app,
            destination,
            uid,
            outcome,
            name,
            named_by,
            dns_name: None,
            came_in: false,
            ech: Ech::Absent,
            dns,
            resolver,
            network,
            via: crate::engine::Via::Direct,
            proxy: None,
            blocked: blocked
                .and_then(|entry| shared.row_sdk(entry))
                .map(|sdk| Box::new(super::BlockedBy { sdk })),
        },
        via.as_deref(),
    );
    if let Some(entry) = blocked {
        shared.count_block(uid, entry, false);
    }
    // A messenger's attempt to reach its maker directly counts for substitution, whether or not it got through.
    if sniffs {
        shared.proxies_opened(&opened, dns_name.as_deref());
    }
    let answer = match upstream {
        Ok(stream) if listener.port == 0 => {
            // No listener now, as when its port was taken and none can be bound: the app is refused,
            // and the server's connection reset, rather than the SYN rewritten to a port another app
            // may hold (`Listening`). A listener is bound again at once.
            let _ = stream.set_zero_linger();
            drop(stream);
            lock(&nat).release(held.port);
            listening.want();
            let sequence = packet::tcp_sequence(&held.packet, &held.parsed);
            packet::tcp_reset(destination, app, 0, Some(sequence.wrapping_add(1)))
        }
        Ok(stream) => rewritten(
            &mut held,
            stream,
            (opened, bytes),
            listener,
            (&shared, &nat, &pending),
        ),
        Err(_) => {
            // The SYN never reached Android's stack, so no old connection can linger on the port.
            lock(&nat).release(held.port);
            if matches!(outcome, Outcome::Refused | Outcome::Blocked) {
                let sequence = packet::tcp_sequence(&held.packet, &held.parsed);
                packet::tcp_reset(destination, app, 0, Some(sequence.wrapping_add(1)))
            } else {
                packet::unreachable(&held.packet, &held.parsed, Unreachable::Host)
            }
        }
    };
    if let Some(answer) = answer
        && tun.send(&answer).await.is_ok()
    {
        Counters::add(&shared.counters.packets_out, 1);
    }
}

/// The held SYN rewritten to `listener`, the engine's now, its upstream connection waiting for the
/// listener to hand the app's end over.
fn rewritten(
    held: &mut Held,
    stream: TcpStream,
    (opened, bytes): (Opened, Option<Arc<FlowBytes>>),
    listener: Listener,
    (shared, nat, pending): (&Shared, &Mutex<Nat>, &Pending),
) -> Option<Vec<u8>> {
    if let Some(bytes) = &bytes {
        bytes.up(shared, 0, held.packet.len());
        lock(&shared.wire).insert(held.port, Arc::clone(bytes));
    }
    lock(pending).insert(
        held.port,
        Upstream {
            stream,
            opened,
            bytes,
        },
    );
    lock(nat).open(held.port, listener);
    let at = shared.addresses;
    let (fake, tun_ip) = if held.parsed.source.is_ipv4() {
        (IpAddr::V4(at.fake4), IpAddr::V4(at.tun4))
    } else {
        (IpAddr::V6(at.fake6), IpAddr::V6(at.tun6))
    };
    let parsed = held.parsed;
    packet::set_ends(
        &mut held.packet,
        &parsed,
        SocketAddr::new(fake, held.port),
        SocketAddr::new(tun_ip, listener.port),
    )
    .map(|()| std::mem::take(&mut held.packet))
}

/// The app of a held SYN, as Android names it, and the connection to its server, with the place it
/// took in its app's share of the waiting connections (ADR 0044, decision 3): a connection still
/// waiting for its server once Android has named its app takes one, held until the server answered or
/// failed. `None` when the app holds its whole share: then nothing of it has left the phone.
///
/// Android is asked first, and the place taken before anything leaves, wherever the app could hold its
/// whole share: through the chain, to a stand-in, and once more than a share's worth of connections
/// wait for their servers in all, this one counted. Below that no app can hold its whole share yet, so
/// the server is asked at once beside Android, as before the shares, which spares each connection the
/// time of a question asked first, about 3 ms; its place is taken when Android answers, beyond the share
/// if others of the app took places meanwhile, since what has left the phone is never dropped unlogged
/// (independent review of unit 10, major). Only such connections lift an app above its share, never
/// past twice it: they began while at most a share's worth waited in all.
async fn upstream(
    shared: &Arc<Shared>,
    app: SocketAddr,
    destination: SocketAddr,
) -> Option<(
    Option<u32>,
    io::Result<TcpStream>,
    Option<Place>,
    Option<Arc<super::Chain>>,
    Option<u32>,
)> {
    // DNS over TCP to Watch's address goes the way the app's lookups go, once Watch's encrypted resolver is set:
    // at port 53 to the engine's own listener of it, at any other port (853, Android's opportunistic DNS over
    // TLS, among them) refused, so that Android asks on port 53 (W8, part 1, point 9).
    let lookups = shared.resolver.on() && shared.is_tunnel_dns(destination.ip());
    let direct = |uid: Option<u32>| async move {
        if lookups {
            return if destination.port() == 53 {
                connect_lookups(shared, TcpLookups::Encrypted(uid)).await
            } else {
                Err(io::ErrorKind::ConnectionRefused.into())
            };
        }
        match shared.target(destination) {
            Some(target) => connect_tcp(shared, target).await,
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        }
    };
    let crowded = shared.tcp_waiting.load(Ordering::Acquire) > shared.limits.tcp_share;
    // Tracker blocking needs the app first where it may refuse by the address alone, or where a lookup over TCP is
    // decided for its app (W8, part 3a; ADR 0053, decision 4): nothing leaves before Android named the app.
    let blocking =
        shared.blocking_on() && (lookups || shared.address_tie(destination.ip()).is_some());
    if shared.chain().is_some()
        || shared.tunnels.any()
        || shared.tunnels.asks()
        || is_stand_in(destination.ip())
        || crowded
        || blocking
    {
        // The route waits for the app's name: a chained or tunnelled app's connection must not start
        // directly, nor one its app's share may refuse, nor one of an app Watch did not name, which may be
        // a routed app installed again, nor one tracker blocking may refuse.
        let uid = owner(shared, TCP, app, destination).await;
        let share = shared.tcp_shares.take(uid).ok()?;
        if let Some(entry) = blocked_before(shared, uid, destination) {
            return Some((uid, Err(Blocked::error(entry)), Some(share), None, None));
        }
        let (upstream, via) = match shared.route(uid, destination) {
            Route::Direct => (direct(uid).await, None),
            Route::Tool(chain) if lookups => {
                let stream = if destination.port() == 53 {
                    connect_lookups(shared, TcpLookups::Tool(Arc::clone(&chain), uid)).await
                } else {
                    Err(io::ErrorKind::ConnectionRefused.into())
                };
                (stream, Some(chain))
            }
            Route::Tool(chain) => (
                connect_through(shared, &chain, destination).await,
                Some(chain),
            ),
            Route::Tunnel(t) => {
                return Some((
                    uid,
                    Err(io::ErrorKind::Other.into()),
                    Some(share),
                    None,
                    Some(t),
                ));
            }
            Route::Refused => (Err(io::ErrorKind::ConnectionRefused.into()), None),
        };
        return Some((uid, upstream, Some(share), via, None));
    }
    // The server is asked at once, beside Android. One that answered first leaves nothing waiting.
    let mut direct = std::pin::pin!(direct(None));
    let mut asked = std::pin::pin!(owner(shared, TCP, app, destination));
    let first = tokio::select! {
        biased;
        upstream = &mut direct => Ok(upstream),
        uid = &mut asked => Err(uid),
    };
    match first {
        Ok(upstream) => Some((asked.await, upstream, None, None, None)),
        Err(uid) => {
            let share = shared.tcp_shares.force(uid);
            Some((uid, direct.await, Some(share), None, None))
        }
    }
}

/// The row that refuses a connection of `uid` to `destination` before anything leaves (ADR 0053, decision 4): a
/// stand-in's name, which a chained app's SOCKS request to the tool would carry, or an address an answer Watch
/// passed tied to blocked names alone.
pub(super) fn blocked_before(
    shared: &Shared,
    uid: Option<u32>,
    destination: SocketAddr,
) -> Option<usize> {
    if is_stand_in(destination.ip()) {
        let name = lock(&shared.stand_ins).name(destination.ip())?;
        return shared.verdict(uid, &name, super::blocks::Path::Connection);
    }
    let entry = shared.address_verdict(uid, destination.ip())?;
    Counters::add(&shared.counters.blocked_addresses, 1);
    Some(entry)
}

/// The error a connection tracker blocking refused carries, with its row, so that it is told from a server's
/// refusal.
#[derive(Debug)]
pub(super) struct Blocked(pub(super) usize);

impl Blocked {
    pub(super) fn error(entry: usize) -> io::Error {
        io::Error::other(Self(entry))
    }

    /// The row of a connection refused by blocking, if `error` is one's.
    pub(super) fn of(error: &io::Error) -> Option<usize> {
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<Self>())
            .map(|b| b.0)
    }
}

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused by tracker blocking")
    }
}

impl std::error::Error for Blocked {}

/// A held SYN whose app holds its whole share of the connections waiting for their servers: dropped,
/// as by a full queue, and counted, and its port freed at once, since it never reached Android's
/// stack. The app's stack sends it again, by then perhaps with room. A connection to the server, if one
/// was being made, is given up with it.
fn refused(held: &Held, shared: &Shared, nat: &Mutex<Nat>) {
    lock(nat).release(held.port);
    Counters::add(&shared.counters.tcp_refused, 1);
}

/// Accepts the rewritten connections and relays each over the upstream connection opened for it.
///
/// `address` is the listener's, the tunnel's own. Only a connection from `fake`, the address the
/// engine rewrites the apps' connections to come from, is one of them. The listener is on the tunnel's
/// own address, which any app can reach directly, from a source port it picks: matched by port alone,
/// such a connection could take the upstream connection waiting for another app's, and be counted in
/// the log under that app. Anything else is closed at once and counted.
///
/// The loop never ends while the engine runs (ADR 0044, unit 12b). Before, the first error ended it
/// and dropped the listener, and every connection the engine rewrote after was refused for the rest of
/// the run: on the Android 15 emulator, Android's netd destroyed the sockets on the tunnel's address
/// when the tunnel was set up again with the same addresses, the listener among them. A listener that
/// no longer listens is closed and another bound (`bind_anew`), and so is one when `first` is `None`,
/// the first bind having failed. One that still listens accepts again: at once after an error of one
/// connection, and after a pause when descriptors or memory lacked for a moment, the connections in its
/// queue waiting there meanwhile.
pub(super) async fn accept(
    first: Option<TcpListener>,
    (address, fake): (IpAddr, IpAddr),
    pending: Pending,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
) {
    let listening = shared.listener(address.is_ipv4());
    let mut listener = first;
    let mut pause = Pause::new(Pause::LONGEST);
    // Whether a listener stopped listening and none has been bound since, and whether the one now was
    // bound after one stopped and has accepted nothing since.
    let (mut lost, mut rebound) = (false, false);
    loop {
        let Some(current) = listener.as_ref() else {
            // A listener bound anew that stops listening before it accepted anything is bound anew again
            // only after a pause, so that nothing turns in a tight loop.
            if rebound {
                pause.wait().await;
            }
            listener = Some(bind_anew(address, listening).await);
            if lost {
                Counters::add(&shared.counters.listener_recoveries, 1);
                (lost, rebound) = (false, true);
            }
            continue;
        };
        let (app, peer) = match current.accept().await {
            Ok(accepted) => accepted,
            Err(error) if listens(current, &error) => {
                Counters::add(&shared.counters.listener_recoveries, 1);
                if lacks(&error) {
                    pause.wait().await;
                }
                continue;
            }
            Err(_) => {
                // Closed before another is bound: a socket bound to a port by its number holds it
                // until it is closed. None listens meanwhile (`Listening::lost`).
                listening.lost();
                listener = None;
                lost = true;
                continue;
            }
        };
        pause.reset();
        rebound = false;
        if peer.ip() != fake {
            Counters::add(&shared.counters.strangers, 1);
            drop(app);
            continue;
        }
        let port = peer.port();
        let Some(upstream) = lock(&pending).remove(&port) else {
            continue;
        };
        let Some(entry) = lock(&nat).by_fake(port, Instant::now()) else {
            // The rewriting was forgotten meanwhile: the flow ends here, and in the log too.
            shared.finish(upstream.opened.id);
            continue;
        };
        // From now on the relay alone ends the connection, and its rewriting with it.
        lock(&nat).relayed(port);
        let (shared, nat) = (Arc::clone(&shared), Arc::clone(&nat));
        let id = upstream.opened.id;
        tokio::spawn(async move {
            if let Some(entry) = relay(app, upstream, &shared).await {
                shared.blocked_flow(id, entry);
            }
            // What Android's stack still holds for the app, then its last FIN and ACK, still pass the
            // tunnel and need rewriting for a while; then the port is free. Only then is the flow's last
            // segment written: earlier, the packets of that while were counted after it, and missing
            // from the log (up to a socket's send buffer on each download).
            tokio::time::sleep(shared.limits.close_linger).await;
            lock(&nat).remove_if(port, entry.app, entry.destination, Instant::now());
            shared.finish_closed(id);
        });
    }
}

/// Whether `listener` still listens after `error`: `EINVAL` says it does not, as `accept` answers on a
/// socket that no longer listens, and so does `SO_ACCEPTCONN` at 0, as after `SOCK_DESTROY`. One whose
/// state cannot be read is taken as not listening: a new one takes its place.
fn listens(listener: &TcpListener, error: &io::Error) -> bool {
    error.raw_os_error() != Some(nix::libc::EINVAL)
        && getsockopt(listener, sockopt::AcceptConn).unwrap_or(false)
}

/// Whether an error of a listener that still listens is a lack of descriptors or memory, which lasts a
/// while: then the listener pauses before it accepts again. Any other, as `accept(2)`'s errors of one
/// connection (`ECONNABORTED`, `EPROTO`, `ENETDOWN`, `EHOSTUNREACH` and the like), took that connection
/// off the queue, and the next is accepted at once.
fn lacks(error: &io::Error) -> bool {
    use nix::libc::{EMFILE, ENFILE, ENOBUFS, ENOMEM};
    matches!(
        error.raw_os_error(),
        Some(EMFILE | ENFILE | ENOBUFS | ENOMEM)
    )
}

/// A listener on the tunnel's address `address`, in the place of one that stopped listening or was
/// never bound (ADR 0044, unit 12b), on a port the kernel picks, of a new generation (`Listening`), so
/// that nothing rewritten to the last one before it stopped is the engine's again unless the relay
/// holds it. Until one is bound the port the engine rewrites to is 0: a new connection is refused, never
/// rewritten to a port another app may hold. Never on the old port: with generations it would keep
/// nothing valid, and another app that bound it with `SO_REUSEADDR` in the moment no listener held it
/// keeps it bound beside the new listener, and can connect from it (third round, nit 1).
///
/// An attempt that fails, as when the process is out of descriptors, or the address is gone, is made
/// again after a pause, from 10 ms doubling up to a minute, or at once, after 10 ms, when an app's SYN
/// finds no listener: an address that stays gone, as on a tunnel with none of this version, costs a
/// wake-up a minute, and a listener lacking when an app needs one is bound as soon as it can be.
async fn bind_anew(address: IpAddr, listening: &Listening) -> TcpListener {
    let mut pause = Pause::new(Pause::LONGEST_BIND);
    loop {
        if let Ok((listener, port)) = bind(SocketAddr::new(address, 0)) {
            listening.bound(port);
            return listener;
        }
        tokio::select! {
            () = pause.wait() => {}
            () = listening.wanted.notified() => tokio::time::sleep(Pause::FIRST).await,
        }
    }
}

/// The pause before the accept loop tries again: 10 ms at first, doubling up to `longest`, and 10 ms
/// again once a connection is accepted. Bounded, so that a listener that lacks descriptors for a while
/// tries about once a second, and a lack that ends is noticed within a second.
struct Pause {
    next: Duration,
    longest: Duration,
}

impl Pause {
    const FIRST: Duration = Duration::from_millis(10);
    /// The longest pause before a listener that still listens accepts again.
    const LONGEST: Duration = Duration::from_secs(1);
    /// The longest pause before a listener is bound again, which an app's SYN cuts short.
    const LONGEST_BIND: Duration = Duration::from_secs(64);

    fn new(longest: Duration) -> Self {
        Self {
            next: Self::FIRST,
            longest,
        }
    }

    async fn wait(&mut self) {
        tokio::time::sleep(self.next).await;
        self.next = (self.next * 2).min(self.longest);
    }

    fn reset(&mut self) {
        self.next = Self::FIRST;
    }
}

/// How one direction of a relayed connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Its sender closed it cleanly: the other side gets a FIN.
    Clean,
    /// Reading or writing failed, as when either side reset the connection.
    Failed,
    /// Tracker blocking refused it, by the row given (ADR 0053): both sides get a reset.
    Blocked(usize),
}

/// Relays one connection both ways, counting the bytes as they pass, until both directions end; the
/// caller writes the flow's last segment once the tunnel is done with it. The app's first bytes are
/// read for a TLS hello (at most [`crate::tls::MAX_HELLO`]), even when DNS named the flow, since only the
/// hello tells whether ECH hid the name; nothing is held back for that, so a protocol in which the
/// server speaks first is not delayed.
///
/// A direction that ends cleanly closes the other side's writing with a FIN, and the other direction
/// goes on. One that fails, as when the server or the app resets the connection, ends both sides with
/// a reset (no linger), so that the app can tell a cut-off answer from a finished one (review finding
/// 21).
/// What the engine's listener still held for the app is discarded then, as a reset discards it.
///
/// Tracker blocking (W8, part 3a; ADR 0053, decision 4) holds the app's first bytes while they read as an
/// unfinished TLS hello or plain HTTP request head, at most [`super::blocks::HOLD`], and writes nothing of them
/// upstream, or to the user's tool, until their name is decided ([`Gate`]); a flow it refuses, then or at a later
/// byte either way, ends with a reset on both sides, and its row is returned. The user's tool's own flows and the
/// flows of no app are never held.
#[allow(clippy::too_many_lines)]
async fn relay(mut app: TcpStream, mut upstream: Upstream, shared: &Arc<Shared>) -> Option<usize> {
    let _ = app.set_nodelay(true);
    let _ = upstream.stream.set_nodelay(true);
    // The row that names the flow, once its first bytes named it: the server's side is decided by it again too.
    let named = std::sync::atomic::AtomicUsize::new(usize::MAX);
    let (failed, blocked) = {
        let (mut app_read, mut app_write) = app.split();
        let (mut up_read, mut up_write) = upstream.stream.split();
        let opened = upstream.opened;
        let bytes = upstream.bytes.as_ref();
        // A declared proxy's request waits here for the server's reply, which confirms it or not (ADR 0052).
        let handshake = std::sync::Mutex::new(Handshake::default());
        let up = async {
            // Zeroed when dropped: a proxy's credentials may have passed through it (ADR 0052).
            let mut buffer = Zeroizing::new(vec![0u8; 16 * 1024]);
            let messenger = opened.sniffs && shared.family(opened.uid).is_some();
            let mut sniff = Some(Sniff::new(opened.sniffs, messenger));
            let mut gate = shared.gate(opened.uid);
            loop {
                let read = match gate.as_ref().and_then(Gate::until) {
                    Some(until) => tokio::time::timeout_at(until, app_read.read(&mut buffer)).await,
                    None => Ok(app_read.read(&mut buffer).await),
                };
                let n = match read {
                    // The hold ran out: what it held goes on unread (`blocks::HOLD`).
                    Err(_) => {
                        let held = gate.as_mut().map(Gate::ran_out).unwrap_or_default();
                        if up_write.write_all(&held).await.is_err() {
                            return End::Failed;
                        }
                        counted_up(shared, bytes, held.len());
                        continue;
                    }
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) => return End::Failed,
                };
                if let Some(reading) = sniff.as_mut() {
                    for found in reading.feed(&buffer[..n]) {
                        shared.found(opened, found, &handshake);
                    }
                    if reading.done() {
                        sniff = None;
                    }
                }
                let step = gate.as_mut().map(|g| {
                    let step = g.feed(shared, &buffer[..n]);
                    if let Some(entry) = g.entry() {
                        named.store(entry, Ordering::Relaxed);
                    }
                    step
                });
                let released;
                let out: &[u8] = match step {
                    None | Some(Step::Through) => &buffer[..n],
                    Some(Step::Hold) => {
                        Counters::add(&shared.counters.blocking_holds, 1);
                        continue;
                    }
                    Some(Step::Release(held)) => {
                        released = held;
                        &released
                    }
                    Some(Step::Block(entry)) => return End::Blocked(entry),
                };
                if up_write.write_all(out).await.is_err() {
                    return End::Failed;
                }
                counted_up(shared, bytes, out.len());
            }
            // The app closed its side while its start was held: what it sent goes on, then its FIN.
            let held = gate.as_mut().map(Gate::ran_out).unwrap_or_default();
            if !held.is_empty() {
                if up_write.write_all(&held).await.is_err() {
                    return End::Failed;
                }
                counted_up(shared, bytes, held.len());
            }
            let _ = up_write.shutdown().await;
            End::Clean
        };
        let down = async {
            let mut buffer = vec![0u8; 16 * 1024];
            // The server's first bytes, for a declared proxy's handshake.
            let mut replying = opened.sniffs;
            loop {
                let n = match up_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return End::Failed,
                };
                if replying {
                    replying = shared.replied(opened, &buffer[..n], &handshake);
                }
                // A flow whose row blocks it again, as after the user blocked its app again, ends at its next
                // byte either way (ADR 0053, decision 4: an HTTP/2 connection pools many requests).
                let entry = named.load(Ordering::Relaxed);
                if entry != usize::MAX
                    && let Some(uid) = opened.uid
                    && shared.still_blocks(uid, entry)
                {
                    return End::Blocked(entry);
                }
                if app_write.write_all(&buffer[..n]).await.is_err() {
                    return End::Failed;
                }
                Counters::add(&shared.counters.bytes_down, n as u64);
                if let Some(bytes) = bytes {
                    bytes.down(shared, n, 0);
                }
            }
            let _ = app_write.shutdown().await;
            End::Clean
        };
        tokio::pin!(up, down);
        let (mut up_end, mut down_end) = (None, None);
        'ends: loop {
            tokio::select! {
                end = &mut up, if up_end.is_none() => up_end = Some(end),
                end = &mut down, if down_end.is_none() => down_end = Some(end),
            }
            for end in [up_end, down_end] {
                if let Some(End::Blocked(entry)) = end {
                    break 'ends (true, Some(entry));
                }
            }
            if up_end == Some(End::Failed) || down_end == Some(End::Failed) {
                break (true, None);
            }
            if up_end.is_some() && down_end.is_some() {
                break (false, None);
            }
        }
    };
    if blocked.is_some() {
        // Nothing to drain: what the app sent of a blocked flow never went upstream.
        let _ = app.set_zero_linger();
        let _ = upstream.stream.set_zero_linger();
        return blocked;
    }
    if failed {
        Counters::add(&shared.counters.resets, 1);
        // On a real network the bytes a side was already given reach it before the reset that follows
        // them; here they may still wait in the socket toward it, which a reset would discard (CI,
        // 2026-11-12: a download lost its last 8 %). So the reset waits for them first.
        drain(&app).await;
        drain(&upstream.stream).await;
        let _ = app.set_zero_linger();
        let _ = upstream.stream.set_zero_linger();
    }
    None
}

/// Counts `n` of the app's bytes written upstream.
fn counted_up(shared: &Shared, bytes: Option<&Arc<FlowBytes>>, n: usize) {
    Counters::add(&shared.counters.bytes_up, n as u64);
    if let Some(bytes) = bytes {
        bytes.up(shared, n, 0);
    }
}

/// How long a reset waits for the bytes already given to a side to leave its socket.
const DRAIN: Duration = Duration::from_secs(2);

/// Waits until `stream` holds no unsent bytes, or its peer is gone, or [`DRAIN`] passes. With
/// `TCP_NOTSENT_LOWAT` at 1, the kernel reports the socket writable only once nothing waits to be sent.
async fn drain(stream: &TcpStream) {
    if socket2::SockRef::from(stream)
        .set_tcp_notsent_lowat(1)
        .is_err()
    {
        return;
    }
    let until = tokio::time::Instant::now() + DRAIN;
    while tokio::time::Instant::now() < until {
        let mut fds = [PollFd::new(stream.as_fd(), PollFlags::POLLOUT)];
        if poll(&mut fds, PollTimeout::ZERO).is_ok_and(|n| n > 0)
            && fds[0].revents().is_some_and(|events| {
                events.intersects(PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP)
            })
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::clock::ManualClock;
    use super::super::tests::shared;
    use super::super::{DnsUse, logbook::SEGMENT_MS};
    use super::*;
    use crate::log::Record;

    /// 2026-11-17, 22:10 UTC.
    const EVENING: u64 = 1_794_873_600_000 + (22 * 60 + 10) * 60_000;
    /// 06:16 the next morning, after a night's sleep.
    const MORNING: u64 = EVENING + (8 * 60 + 6) * 60_000;

    /// A relayed connection between two pairs of loopback sockets: the app's end, the server's, and
    /// the flow's bytes, with the log's clock at 22:10.
    async fn relayed(shared: &Arc<Shared>) -> io::Result<(TcpStream, TcpStream, Arc<FlowBytes>)> {
        let pair = || async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let near = TcpStream::connect(listener.local_addr()?).await?;
            let (far, _) = listener.accept().await?;
            io::Result::Ok((near, far))
        };
        let (app, app_end) = pair().await?;
        let (upstream, server) = pair().await?;
        let destination = server.local_addr()?;
        let Some(bytes) = shared.record(Flow {
            id: 1,
            protocol: TCP,
            app: app.local_addr()?,
            destination,
            uid: Some(10_123),
            outcome: Outcome::Opened,
            name: None,
            named_by: NamedBy::Unknown,
            dns_name: None,
            came_in: false,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
            via: crate::engine::Via::Direct,
            proxy: None,
            blocked: None,
        }) else {
            unreachable!("an open flow is live")
        };
        let upstream = Upstream {
            stream: upstream,
            opened: Opened {
                id: 1,
                port: destination.port(),
                destination,
                sniffs: true,
                dns: DnsUse::None,
                uid: Some(10_123),
                dns_held_until: Duration::ZERO,
            },
            bytes: Some(Arc::clone(&bytes)),
        };
        let shared = Arc::clone(shared);
        tokio::spawn(async move { relay(app_end, upstream, &shared).await });
        Ok((app, server, bytes))
    }

    /// The log's segments written so far, as (start, end, bytes), and where the open one starts.
    fn cut_so_far(shared: &Shared) -> (Vec<(u64, u64, [u64; 4])>, u64) {
        let written = lock(&shared.pending_log)
            .iter()
            .filter_map(|r| match r {
                Record::Segment {
                    start, end, bytes, ..
                } => Some((*start, *end, *bytes)),
                Record::Lookups { .. } => None,
            })
            .collect();
        (written, lock(&shared.live)[&1].start)
    }

    /// A night's sleep ended by the server's bytes on a relayed connection, as by a push message: the
    /// relay cuts the flow's segment at 22:15 before it counts them, and they go in the segment of 06:15.
    #[tokio::test(flavor = "current_thread")]
    async fn a_sleep_ended_by_the_servers_bytes_is_cut_by_the_relay_before_it_counts()
    -> io::Result<()> {
        let clock = ManualClock::at(EVENING);
        let mut shared = shared();
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let (mut app, mut server, bytes) = relayed(&shared).await?;
        let mut got = [0u8; 64];
        server.write_all(b"evening").await?;
        app.read_exact(&mut got[..7]).await?;
        clock.set(MORNING);
        server.write_all(b"push message").await?;
        app.read_exact(&mut got[..12]).await?;
        for _ in 0..100 {
            if bytes.now()[1] == 19 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let quarter = |t: u64| t / SEGMENT_MS * SEGMENT_MS;
        assert_eq!(
            cut_so_far(&shared),
            (
                vec![(EVENING, quarter(EVENING) + SEGMENT_MS, [0, 7, 0, 0])],
                quarter(MORNING)
            )
        );
        assert_eq!(bytes.now(), [0, 19, 0, 0]);
        Ok(())
    }

    /// The same, ended by the app's bytes.
    #[tokio::test(flavor = "current_thread")]
    async fn a_sleep_ended_by_the_apps_bytes_is_cut_by_the_relay_before_it_counts() -> io::Result<()>
    {
        let clock = ManualClock::at(EVENING);
        let mut shared = shared();
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let (mut app, mut server, bytes) = relayed(&shared).await?;
        let mut got = [0u8; 64];
        app.write_all(b"evening").await?;
        server.read_exact(&mut got[..7]).await?;
        clock.set(MORNING);
        app.write_all(b"good morning").await?;
        server.read_exact(&mut got[..12]).await?;
        // The relay counts after its write, which the server's read can come before: it is counted by
        // the time the relay waits for the app again.
        for _ in 0..100 {
            if bytes.now()[0] == 19 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let quarter = |t: u64| t / SEGMENT_MS * SEGMENT_MS;
        assert_eq!(
            cut_so_far(&shared),
            (
                vec![(EVENING, quarter(EVENING) + SEGMENT_MS, [7, 0, 0, 0])],
                quarter(MORNING)
            )
        );
        assert_eq!(bytes.now(), [19, 0, 0, 0]);
        Ok(())
    }

    /// A relayed connection of `uid` as [`relayed`] makes one, with tracker blocking on for the row
    /// `tracker.example` and covering `uid`: the app's end, the server's, and the relay's task, which says the row
    /// that refused the flow, if one did.
    async fn relayed_blocking(
        uid: u32,
    ) -> io::Result<(TcpStream, TcpStream, tokio::task::JoinHandle<Option<usize>>)> {
        let shared = Arc::new(shared());
        shared.set_blocking(super::super::BlockSetting {
            on: true,
            table: Some(Arc::new(crate::blocking::tests::table(&[(
                "tracker.example",
                "block",
            )]))),
            covered: vec![10_123],
            ..super::super::BlockSetting::default()
        });
        let pair = || async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let near = TcpStream::connect(listener.local_addr()?).await?;
            let (far, _) = listener.accept().await?;
            io::Result::Ok((near, far))
        };
        let (app, app_end) = pair().await?;
        let (upstream, server) = pair().await?;
        let destination = server.local_addr()?;
        let upstream = Upstream {
            stream: upstream,
            opened: Opened {
                id: 1,
                port: destination.port(),
                destination,
                sniffs: true,
                dns: DnsUse::None,
                uid: Some(uid),
                dns_held_until: Duration::ZERO,
            },
            bytes: None,
        };
        let task = tokio::spawn(async move { relay(app_end, upstream, &shared).await });
        Ok((app, server, task))
    }

    /// What the server read of the connection within a while: its bytes, until the relay closed or reset it.
    async fn read_all(server: &mut TcpStream) -> Vec<u8> {
        let mut got = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), server.read(&mut buffer)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buffer[..n]);
        }
        got
    }

    /// No byte of a blocked flow's payload goes upstream (ADR 0053, decision 4): a hello in two segments, the second
    /// sent after a pause, is held whole and refused, the server reads nothing and the app gets a reset; in an app
    /// blocking does not cover, the same hello reaches the server whole.
    #[tokio::test(flavor = "current_thread")]
    async fn a_blocked_hello_in_two_segments_never_reaches_the_server() -> io::Result<()> {
        let hello = crate::tls::tests::hello("Tracker.Example", 16 * 1024);
        let (first, second) = hello.split_at(hello.len() / 2);
        let (mut app, mut server, task) = relayed_blocking(10_123).await?;
        app.write_all(first).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        app.write_all(second).await?;
        assert_eq!(
            read_all(&mut server).await,
            Vec::<u8>::new(),
            "no byte reached the server"
        );
        assert!(task.await.ok().flatten().is_some(), "refused by its row");
        let mut buffer = [0u8; 16];
        assert!(
            !matches!(app.read(&mut buffer).await, Ok(n) if n > 0),
            "the app read nothing"
        );
        let (mut app, mut server, task) = relayed_blocking(10_124).await?;
        app.write_all(first).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        app.write_all(second).await?;
        app.shutdown().await?;
        assert_eq!(read_all(&mut server).await, hello);
        drop(server);
        assert_eq!(task.await.ok().flatten(), None);
        Ok(())
    }

    /// A plain request's host is read the same way, and a protocol in which the server speaks first is never held:
    /// its bytes reach the app at once.
    #[tokio::test(flavor = "current_thread")]
    async fn a_plain_requests_host_is_blocked_and_a_server_first_protocol_never_waits()
    -> io::Result<()> {
        let (mut app, mut server, task) = relayed_blocking(10_123).await?;
        app.write_all(b"GET /collect HTTP/1.1\r\nHo").await?;
        app.write_all(b"st: tracker.example\r\n\r\n").await?;
        assert_eq!(read_all(&mut server).await, Vec::<u8>::new());
        assert!(task.await.ok().flatten().is_some());
        let (mut app, mut server, task) = relayed_blocking(10_123).await?;
        server.write_all(b"220 mail.example ESMTP\r\n").await?;
        let mut greeting = [0u8; 24];
        tokio::time::timeout(Duration::from_millis(300), app.read_exact(&mut greeting)).await??;
        app.write_all(b"EHLO a\r\n").await?;
        let mut got = [0u8; 8];
        tokio::time::timeout(Duration::from_millis(300), server.read_exact(&mut got)).await??;
        assert_eq!(&got, b"EHLO a\r\n");
        drop((app, server));
        assert_eq!(task.await.ok().flatten(), None);
        Ok(())
    }

    /// A lack of descriptors or memory pauses the accept loop; an error of one connection, which took
    /// that connection off the queue, does not (second round, nit 1).
    #[test]
    fn only_a_lack_of_descriptors_or_memory_pauses_the_accept_loop() {
        use nix::libc::{
            ECONNABORTED, EHOSTUNREACH, EMFILE, ENETDOWN, ENFILE, ENOBUFS, ENOMEM, EPROTO,
        };
        for errno in [EMFILE, ENFILE, ENOBUFS, ENOMEM] {
            assert!(lacks(&io::Error::from_raw_os_error(errno)), "{errno}");
        }
        for errno in [ECONNABORTED, EPROTO, ENETDOWN, EHOSTUNREACH] {
            assert!(!lacks(&io::Error::from_raw_os_error(errno)), "{errno}");
        }
    }

    /// The listener's port and generation are read together: a listener lost leaves port 0 and a new
    /// generation, and the one bound after keeps that generation.
    #[test]
    fn a_lost_listener_leaves_no_port_and_a_new_generation() {
        let listening = Listening::new();
        assert_eq!(listening.now(), Listener::default());
        listening.bound(4_000);
        assert_eq!(
            listening.now(),
            Listener {
                port: 4_000,
                generation: 0
            }
        );
        listening.lost();
        assert_eq!(
            listening.now(),
            Listener {
                port: 0,
                generation: 1
            }
        );
        listening.bound(4_000);
        listening.lost();
        listening.bound(65_535);
        assert_eq!(
            listening.now(),
            Listener {
                port: 65_535,
                generation: 2
            }
        );
    }
}
