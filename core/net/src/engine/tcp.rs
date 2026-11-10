//! TCP through the tunnel (ADR 0012): the app's SYN held until its owner and the server are known, the
//! rewriting to the engine's listener, Android's own stack ending the connection, and the relay.

use super::logbook::FlowBytes;
use super::naming::Begun;
use super::upstream::{connect_tcp, owner};
use super::{
    CLOSE_LINGER, Counters, Ech, FAKE4, FAKE6, Flow, Loop, NamedBy, Opened, Outcome, Shared, TUN4,
    TUN6, is_unreachable, lock,
};
use crate::nat::{Lookup, Nat};
use crate::packet::{ACK, Packet, RST, SYN, TCP, Unreachable};
use crate::tls::ServerName;
use crate::tun::Tun;
use crate::{packet, tls};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
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
                let held = Held {
                    packet: packet.to_vec(),
                    parsed: *parsed,
                    port,
                    listener,
                };
                tokio::spawn(open(
                    held,
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

async fn open(
    mut held: Held,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
    pending: Pending,
) {
    let (app, destination) = (held.parsed.source, held.parsed.destination);
    let connect = async {
        match shared.target(destination) {
            Some(target) => connect_tcp(&shared, target).await,
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        }
    };
    let (uid, upstream) = tokio::join!(owner(&shared, TCP, app, destination), connect);
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
        let (fake, tun_ip) = if app.is_ipv4() {
            (IpAddr::V4(FAKE4), IpAddr::V4(TUN4))
        } else {
            (IpAddr::V6(FAKE6), IpAddr::V6(TUN6))
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
        lock(&nat).remove(held.port, Instant::now());
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
            tokio::time::sleep(CLOSE_LINGER).await;
            lock(&nat).remove_if(port, entry.app, entry.destination, Instant::now());
            shared.finish_closed(id);
        });
    }
}

/// Relays one connection both ways, counting the bytes as they pass, until both directions end; the
/// caller writes the flow's last segment once the tunnel is done with it. The app's first bytes are
/// read for a TLS hello (at most [`tls::MAX_HELLO`]), even when DNS named the flow, since only the
/// hello tells whether ECH hid the name; nothing is held back for that, so a protocol in which the
/// server speaks first is not delayed.
async fn relay(app: TcpStream, upstream: Upstream, shared: &Arc<Shared>) {
    let _ = app.set_nodelay(true);
    let _ = upstream.stream.set_nodelay(true);
    let (mut app_read, mut app_write) = app.into_split();
    let (mut up_read, mut up_write) = upstream.stream.into_split();
    let up = async {
        let mut buffer = vec![0u8; 16 * 1024];
        let mut start = Some(Vec::new());
        loop {
            let n = match app_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(seen) = start.as_mut() {
                seen.extend_from_slice(&buffer[..n]);
                match tls::server_name(seen) {
                    ServerName::Found(hello) => {
                        shared.hello(upstream.opened, &hello, NamedBy::Tls);
                        start = None;
                    }
                    ServerName::None => start = None,
                    ServerName::Incomplete if seen.len() >= tls::MAX_HELLO => start = None,
                    ServerName::Incomplete => {}
                }
            }
            if up_write.write_all(&buffer[..n]).await.is_err() {
                break;
            }
            Counters::add(&shared.counters.bytes_up, n as u64);
            if let Some(bytes) = &upstream.bytes {
                bytes.add_up(n);
            }
        }
        let _ = up_write.shutdown().await;
    };
    let down = async {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let n = match up_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if app_write.write_all(&buffer[..n]).await.is_err() {
                break;
            }
            Counters::add(&shared.counters.bytes_down, n as u64);
            if let Some(bytes) = &upstream.bytes {
                bytes.add_down(n);
            }
        }
        let _ = app_write.shutdown().await;
    };
    tokio::join!(up, down);
}
