//! TCP through the tunnel (ADR 0012): the app's SYN held until its owner and the server are known, the
//! rewriting to the engine's listener, Android's own stack ending the connection, and the relay.

use super::budget::Place;
use super::chain::{Route, connect_through};
use super::logbook::FlowBytes;
use super::naming::Begun;
use super::upstream::{connect_tcp, owner};
use super::{Counters, Ech, Flow, Loop, NamedBy, Opened, Outcome, Shared, is_unreachable, lock};
use crate::nat::{Lookup, Nat};
use crate::packet::{ACK, Packet, RST, SYN, TCP, Unreachable};
use crate::standins::is_stand_in;
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{packet, tls};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An upstream connection waiting for Android's TCP stack to hand over the app's end.
pub(super) struct Upstream {
    pub(super) stream: TcpStream,
    /// The flow, as it opened.
    pub(super) opened: Opened,
    /// Its bytes, for the log.
    pub(super) bytes: Option<Arc<FlowBytes>>,
}

pub(super) type Pending = Arc<Mutex<HashMap<u16, Upstream>>>;

/// Binds the listener that terminates rewritten connections of one IP version and accepts them in
/// a task of its own; returns its port, or 0 when the tunnel has no address of that version.
pub(super) async fn listen(
    address: IpAddr,
    fake: IpAddr,
    pending: &Pending,
    shared: &Arc<Shared>,
    nat: &Arc<Mutex<Nat>>,
) -> u16 {
    let Ok(listener) = TcpListener::bind((address, 0)).await else {
        return 0;
    };
    let port = listener.local_addr().map_or(0, |a| a.port());
    tokio::spawn(accept(
        listener,
        fake,
        Arc::clone(pending),
        Arc::clone(shared),
        Arc::clone(nat),
    ));
    port
}

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
        let (tun, fake, listener) = self.ends(parsed.source.is_ipv4());
        let flags = packet::tcp_flags(packet, parsed);
        let now = Instant::now();
        if listener != 0
            && parsed.source == SocketAddr::new(tun, listener)
            && parsed.destination.ip() == fake
        {
            // Android's answer, back to the app as if from the real destination.
            let port = parsed.destination.port();
            let Some(entry) = lock(&self.nat).by_fake(port, now) else {
                return;
            };
            if packet::set_ends(packet, parsed, entry.destination, entry.app).is_some() {
                if let Some(bytes) = lock(&self.shared.wire).get(&port) {
                    bytes.add_wire_down(packet.len());
                }
                self.send(packet).await;
            }
            return;
        }
        if parsed.source.ip() != tun {
            Counters::add(&self.shared.counters.skipped, 1);
            return;
        }
        let syn = flags & SYN != 0 && flags & ACK == 0;
        let lookup = if listener == 0 {
            Lookup::Full
        } else {
            lock(&self.nat).lookup(parsed.source, parsed.destination, syn, now)
        };
        match lookup {
            Lookup::Open(port) => {
                if let Some(bytes) = lock(&self.shared.wire).get(&port) {
                    bytes.add_wire_up(packet.len());
                }
                if packet::set_ends(
                    packet,
                    parsed,
                    SocketAddr::new(fake, port),
                    SocketAddr::new(tun, listener),
                )
                .is_some()
                {
                    self.send(packet).await;
                }
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
                    listener,
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
                if flags & RST == 0 && flags & ACK != 0 {
                    let ack = packet::tcp_acknowledgement(packet, parsed);
                    if let Some(reset) =
                        packet::tcp_reset(parsed.destination, parsed.source, ack, None)
                    {
                        self.send(&reset).await;
                    }
                }
            }
            Lookup::Full => {
                let sequence = packet::tcp_sequence(packet, parsed);
                if syn
                    && let Some(reset) = packet::tcp_reset(
                        parsed.destination,
                        parsed.source,
                        0,
                        Some(sequence.wrapping_add(1)),
                    )
                {
                    self.send(&reset).await;
                }
            }
        }
    }
}

/// A connection's first SYN, held until Android has named the app and the server has accepted.
struct Held {
    packet: Vec<u8>,
    parsed: Packet,
    port: u16,
    listener: u16,
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
    let Some((uid, upstream, _share)) = upstream(&shared, app, destination).await else {
        return refused(&held, &shared, &nat);
    };
    let outcome = match &upstream {
        Ok(_) => Outcome::Opened,
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Outcome::Refused,
        Err(error) if is_unreachable(error) => Outcome::Unreachable,
        Err(_) => Outcome::Failed,
    };
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
    let bytes = shared.record(Flow {
        id,
        protocol: TCP,
        app,
        destination,
        uid,
        outcome,
        name,
        named_by,
        ech: Ech::Absent,
        dns,
        resolver,
        network,
    });
    let answer = if let Ok(stream) = upstream {
        if let Some(bytes) = &bytes {
            bytes.add_wire_up(held.packet.len());
            lock(&shared.wire).insert(held.port, Arc::clone(bytes));
        }
        lock(&pending).insert(
            held.port,
            Upstream {
                stream,
                opened,
                bytes,
            },
        );
        lock(&nat).open(held.port);
        let at = shared.addresses;
        let (fake, tun_ip) = if app.is_ipv4() {
            (IpAddr::V4(at.fake4), IpAddr::V4(at.tun4))
        } else {
            (IpAddr::V6(at.fake6), IpAddr::V6(at.tun6))
        };
        let parsed = held.parsed;
        packet::set_ends(
            &mut held.packet,
            &parsed,
            SocketAddr::new(fake, held.port),
            SocketAddr::new(tun_ip, held.listener),
        )
        .map(|()| held.packet)
    } else {
        // The SYN never reached Android's stack, so no old connection can linger on the port.
        lock(&nat).release(held.port);
        if outcome == Outcome::Refused {
            let sequence = packet::tcp_sequence(&held.packet, &held.parsed);
            packet::tcp_reset(destination, app, 0, Some(sequence.wrapping_add(1)))
        } else {
            packet::unreachable(&held.packet, &held.parsed, Unreachable::Host)
        }
    };
    if let Some(answer) = answer
        && tun.send(&answer).await.is_ok()
    {
        Counters::add(&shared.counters.packets_out, 1);
    }
}

/// The app of a held SYN, as Android names it, and the connection to its server, with the place it
/// took in its app's share of the waiting connections (ADR 0044, decision 3): a connection still
/// waiting for its server once Android has named its app takes one, held until the server answered or
/// failed. `None` when the app holds its whole share.
async fn upstream(
    shared: &Arc<Shared>,
    app: SocketAddr,
    destination: SocketAddr,
) -> Option<(Option<u32>, io::Result<TcpStream>, Option<Place>)> {
    let direct = async {
        match shared.target(destination) {
            Some(target) => connect_tcp(shared, target).await,
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        }
    };
    if shared.chain().is_some() || is_stand_in(destination.ip()) {
        // The route waits for the app's name: a chained app's connection must not start directly.
        let uid = owner(shared, TCP, app, destination).await;
        let share = shared.tcp_shares.take(uid).ok()?;
        let upstream = match shared.route(uid, destination) {
            Route::Direct => direct.await,
            Route::Tool(chain) => connect_through(shared, &chain, destination).await,
            Route::Refused => Err(io::ErrorKind::ConnectionRefused.into()),
        };
        return Some((uid, upstream, Some(share)));
    }
    // The server is asked at once, beside Android. One that answered first leaves nothing waiting.
    let mut direct = std::pin::pin!(direct);
    let mut asked = std::pin::pin!(owner(shared, TCP, app, destination));
    let first = tokio::select! {
        biased;
        upstream = &mut direct => Ok(upstream),
        uid = &mut asked => Err(uid),
    };
    match first {
        Ok(upstream) => Some((asked.await, upstream, None)),
        Err(uid) => {
            let share = shared.tcp_shares.take(uid).ok()?;
            Some((uid, direct.await, Some(share)))
        }
    }
}

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
/// Only a connection from `fake`, the address the engine rewrites the apps' connections to come from,
/// is one of them. The listener is on the tunnel's own address, which any app can reach directly, from
/// a source port it picks: matched by port alone, such a connection could take the upstream connection
/// waiting for another app's, and be counted in the log under that app. Anything else is closed at once
/// and counted.
pub(super) async fn accept(
    listener: TcpListener,
    fake: IpAddr,
    pending: Pending,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
) {
    while let Ok((app, peer)) = listener.accept().await {
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
            relay(app, upstream, &shared).await;
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

/// How one direction of a relayed connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Its sender closed it cleanly: the other side gets a FIN.
    Clean,
    /// Reading or writing failed, as when either side reset the connection.
    Failed,
}

/// Relays one connection both ways, counting the bytes as they pass, until both directions end; the
/// caller writes the flow's last segment once the tunnel is done with it. The app's first bytes are
/// read for a TLS hello (at most [`tls::MAX_HELLO`]), even when DNS named the flow, since only the
/// hello tells whether ECH hid the name; nothing is held back for that, so a protocol in which the
/// server speaks first is not delayed.
///
/// A direction that ends cleanly closes the other side's writing with a FIN, and the other direction
/// goes on. One that fails, as when the server or the app resets the connection, ends both sides with
/// a reset (no linger), so that the app can tell a cut-off answer from a finished one (review finding
/// 21). What the engine's listener still held for the app is discarded then, as a reset discards it.
async fn relay(mut app: TcpStream, mut upstream: Upstream, shared: &Arc<Shared>) {
    let _ = app.set_nodelay(true);
    let _ = upstream.stream.set_nodelay(true);
    let failed = {
        let (mut app_read, mut app_write) = app.split();
        let (mut up_read, mut up_write) = upstream.stream.split();
        let opened = upstream.opened;
        let bytes = upstream.bytes.as_ref();
        let up = async {
            let mut buffer = vec![0u8; 16 * 1024];
            let mut start = Some(Vec::new());
            loop {
                let n = match app_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return End::Failed,
                };
                if let Some(seen) = start.as_mut() {
                    seen.extend_from_slice(&buffer[..n]);
                    match tls::server_name(seen) {
                        ServerName::Found(hello) => {
                            shared.hello(opened, &hello, NamedBy::Tls);
                            start = None;
                        }
                        ServerName::None => start = None,
                        ServerName::Incomplete if seen.len() >= tls::MAX_HELLO => start = None,
                        ServerName::Incomplete => {}
                    }
                }
                if up_write.write_all(&buffer[..n]).await.is_err() {
                    return End::Failed;
                }
                Counters::add(&shared.counters.bytes_up, n as u64);
                if let Some(bytes) = bytes {
                    bytes.add_up(n);
                }
            }
            let _ = up_write.shutdown().await;
            End::Clean
        };
        let down = async {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                let n = match up_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return End::Failed,
                };
                if app_write.write_all(&buffer[..n]).await.is_err() {
                    return End::Failed;
                }
                Counters::add(&shared.counters.bytes_down, n as u64);
                if let Some(bytes) = bytes {
                    bytes.add_down(n);
                }
            }
            let _ = app_write.shutdown().await;
            End::Clean
        };
        tokio::pin!(up, down);
        let (mut up_end, mut down_end) = (None, None);
        loop {
            tokio::select! {
                end = &mut up, if up_end.is_none() => up_end = Some(end),
                end = &mut down, if down_end.is_none() => down_end = Some(end),
            }
            if up_end == Some(End::Failed) || down_end == Some(End::Failed) {
                break true;
            }
            if up_end.is_some() && down_end.is_some() {
                break false;
            }
        }
    };
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
