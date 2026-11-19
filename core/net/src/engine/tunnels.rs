//! `WireGuard` upstreams in the engine (W7, ADR 0035): a table of tunnels, one for each configuration Watch
//! sets, each with its protocol core, its protected UDP socket, its timers and its state; and the flows
//! of the apps sent through them, forwarded by address swap (option 3).
//!
//! **Routes.** Each app has one route: directly, through the user's tool (W6), or through one tunnel.
//! The route is decided where W6 decides it, once Android has named the app: at the held SYN
//! (`tcp::upstream`) and the first datagram (`udp::open_mapped`, `udp::open_lookups`). Flows Android names
//! no app for, and ICMP echo, which Android cannot name, go through the default tunnel, the first
//! configuration set, while any app goes through any tunnel; never directly.
//!
//! **Forwarding.** A chosen app's packet takes the configuration's address as its source, its checksums
//! updated incrementally, and goes to the core; its port stays, since every app socket on the tunnel's
//! address has its own. Back from the tunnel, a packet passes only from inside the peer's `AllowedIPs`, to
//! the configuration's address, on a flow a local app started; it is swapped back and written to the
//! tunnel; anything else is dropped and counted (VPN.md, "No inbound path"). An ICMP error has its quote
//! swapped too (RFC 5508). A destination outside `AllowedIPs`, or of IPv6 where the configuration has no
//! IPv6 address, is refused with "administratively prohibited", which the app's kernel reads at once as a
//! failure, so that it falls back to IPv4 or gives up; nothing of it leaves directly.
//!
//! **DNS.** A chosen app's lookups to Watch's own DNS address go to its configuration's DNS server through
//! its tunnel, UDP rebuilt datagram by datagram, TCP by a second swap of the destination; the answers are
//! read for naming (W3) on the way back, kept in the tunnel's own cache, and reach the app with a time to
//! live of 0 (ADR 0035, question 4), so that Android's shared cache hands them to no other app.
//!
//! **MTU.** The tunnel keeps the TUN's MTU, which direct apps keep using whole: a tunnelled SYN's MSS, and
//! the server's SYN-ACK's, are clamped to the configuration's MTU, and a larger packet that may not be
//! fragmented is answered with "fragmentation needed" or "packet too big", as a router answers (ADR 0035,
//! "MTU", its second way; why in "How it is built").
//!
//! **Timers.** Each tunnel's task calls the core's timers once a second only while a session or a
//! handshake lives, or the configuration asks for keepalives, and before any packet that comes after a
//! pause of a second or more, since the core stamps every event with the time of the last call (the
//! spike). An idle tunnel costs no timer.
//!
//! **A tunnel that does not answer** holds its apps: packets wait in the core's bounded queue or are lost,
//! and the tunnel's state says it does not answer. No code path here leads to a direct socket.

use super::logbook::FlowBytes;
use super::upstream::protect;
use super::{Counters, Flow, Outcome, Shared, Via, lock, send_to_app};
use crate::dnscache::DnsCache;
use crate::packet::{self, ACK, Echo, FIN, Packet, RST, SYN, TCP, UDP, Unreachable};
use crate::tun::Tun;
use crate::wireguard::config::{Config, Endpoint};
use crate::wireguard::core::{Core, GotaTun, Received, Sent, Timers};
use crate::wireguard::swap::{self, Back};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

/// The timers' tick, and the pause after which they run before a packet (the spike, "Timers and the
/// clock").
pub const TICK: Duration = Duration::from_secs(1);
/// A handshake that did not complete this many times in a row makes the tunnel one that does not answer:
/// about ten seconds of initiations (`REKEY_TIMEOUT` is 5 s).
const UNANSWERED: u32 = 2;
/// After this many unanswered initiations, an endpoint given by name is resolved again, at most once in
/// [`RESOLVE_AGAIN`] (ADR 0035, question 9: "resolved again, bounded, when handshakes fail").
const RESOLVE_AFTER: u32 = 4;
const RESOLVE_AGAIN: Duration = Duration::from_secs(60);
/// How long a resolution of the endpoint's name may take, for each resolver address.
const RESOLVE_WAIT: Duration = Duration::from_secs(3);
/// At most this many datagrams wait for a tunnel's socket while it is made: a handshake initiation and a
/// few keepalives. The packets themselves wait in the core's queue.
const PENDING: usize = 8;
/// At most this many tunnelled TCP and UDP flows at once, for every tunnel together, and as many echo
/// identifiers: far above a phone's need, and a bound on what a flood of new flows can hold. A new flow
/// beyond it is dropped, as by a full queue, and counted.
pub const FLOWS: usize = 8_192;
/// A tunnelled TCP connection silent this long both ways is forgotten: RFC 5382's least for an
/// established connection, two hours and four minutes.
const TCP_IDLE: Duration = Duration::from_mins(124);
/// An echo identifier silent this long is forgotten.
const ECHO_IDLE: Duration = Duration::from_secs(30);
/// The largest datagram read from a tunnel's socket.
const LARGEST: usize = 65_535;

/// One configuration Watch sets, under the number Watch gave it.
#[derive(Clone, Debug)]
pub struct Configured {
    /// Its number, not 0, which the routes and the states name.
    pub id: u32,
    /// The configuration itself.
    pub config: Arc<Config>,
    /// "Local network directly": its chosen apps' private, link-local and unique-local destinations go
    /// directly while it is on (ADR 0035, question 8).
    pub local_network: bool,
}

/// What Watch sets on its tunnels: the configurations, in the order they were added, the first the
/// default; each app's tunnel by UID; and whether the destinations of the apps sent through them are
/// kept (W6's switch, "Log where these apps connect", `chain_log_destinations`).
#[derive(Clone, Debug, Default)]
pub struct TunnelSetting {
    /// The configurations, the default first.
    pub tunnels: Vec<Configured>,
    /// The apps sent through a tunnel, each with that tunnel's number.
    pub routes: HashMap<u32, u32>,
    /// Whether their flows' destinations go to the log and the live view.
    pub log_destinations: bool,
}

/// A tunnel's state, for the screens and the dump: no key, no address, no endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelState {
    /// Its number.
    pub id: u32,
    /// How long ago its session's handshake completed, if it has a session.
    pub handshake: Option<Duration>,
    /// How long ago the last datagram from its server passed the core, if one did.
    pub received: Option<Duration>,
    /// The last error, as a short word: of the socket (`network`, `refused`), of the endpoint's name
    /// (`resolve`), or of the core (`mac`, `aead`, `counter` and the like).
    pub error: Option<&'static str>,
    /// Whether its server does not answer: handshakes went out and none came back.
    pub not_answering: bool,
    /// Whether its endpoint's name could only be resolved over plain DNS, which the network beneath
    /// reads: it then learns which provider the user chose.
    pub plain_dns: bool,
    /// Whether it has a socket, its endpoint resolved.
    pub connected: bool,
    /// Its flows open now.
    pub flows: usize,
}

/// A tunnelled flow's key: protocol, the app's end, and the destination as the app sees it.
type FlowKey = (u8, SocketAddr, SocketAddr);
/// What the way back reads: the tunnel, protocol, where the flow went inside the tunnel, and the app's
/// port, which the configuration's address keeps.
type BackKey = (u32, u8, SocketAddr, u16);
/// An echo's key: the app's address, its identifier, and the address it pings.
type EchoKey = (IpAddr, u16, IpAddr);

/// A tunnelled TCP or UDP flow.
#[allow(clippy::struct_excessive_bools)]
struct Tflow {
    tunnel: u32,
    uid: Option<u32>,
    /// Its number in the log, 0 for lookups, which the log counts by app.
    id: u64,
    bytes: Option<Arc<FlowBytes>>,
    /// The configuration's address and the app's port.
    from: SocketAddr,
    /// Where it goes inside the tunnel: the destination, or for lookups the configuration's DNS server.
    to: SocketAddr,
    /// Lookups to Watch's own DNS address.
    lookups: bool,
    last: Instant,
    /// TCP: a FIN each way, or a reset, seen.
    fin_up: bool,
    fin_down: bool,
    reset: bool,
    /// When it closed, for the last segments' linger.
    closed: Option<Instant>,
}

/// An app's echo identifier sent through the default tunnel.
struct Eflow {
    tunnel: u32,
    last: Instant,
}

/// One tunnel.
#[allow(clippy::struct_excessive_bools)]
struct Tunnel {
    config: Arc<Config>,
    local_network: bool,
    core: Box<dyn Core>,
    socket: Option<Arc<UdpSocket>>,
    /// Grows when the tunnel is set anew or its task ends: a task of an older generation stops.
    generation: u64,
    /// Whether a task carries it now.
    carried: bool,
    /// Wakes its task: a handshake began, and the timers must run.
    wake: Arc<Notify>,
    pending: Vec<Vec<u8>>,
    last_timers: Instant,
    handshaking: bool,
    unanswered: u32,
    received: Option<Instant>,
    error: Option<&'static str>,
    plain_dns: bool,
    endpoint: Option<SocketAddr>,
    resolved_at: Option<Instant>,
    /// Its own cache of answers (ADR 0035, question 4: "a cache per route").
    answers: DnsCache,
}

impl Tunnel {
    fn new(configured: &Configured, generation: u64) -> Self {
        Self::with_core(
            configured,
            Box::new(GotaTun::new(&configured.config)),
            generation,
        )
    }

    fn with_core(configured: &Configured, core: Box<dyn Core>, generation: u64) -> Self {
        let endpoint = match configured.config.peer.endpoint {
            Endpoint::Address(address) => Some(address),
            Endpoint::Name(..) => None,
        };
        Self {
            config: Arc::clone(&configured.config),
            local_network: configured.local_network,
            core,
            socket: None,
            generation,
            carried: false,
            wake: Arc::new(Notify::new()),
            pending: Vec::new(),
            last_timers: Instant::now(),
            handshaking: false,
            unanswered: 0,
            received: None,
            error: None,
            plain_dns: false,
            endpoint,
            resolved_at: None,
            answers: DnsCache::default(),
        }
    }

    /// Whether the timers must run each second: a session or a handshake lives, or the configuration
    /// asks for keepalives.
    fn ticks(&self) -> bool {
        self.handshaking || self.core.keeps_alive() || self.core.session_age().is_some()
    }

    /// The timers, now: what they ask is sent.
    fn tick(&mut self, counters: &Counters) {
        self.last_timers = Instant::now();
        match self.core.timers() {
            Timers::Send(datagram) => self.out(datagram, counters),
            Timers::Expired(lost) => {
                self.handshaking = false;
                Counters::add(&counters.tunnel_lost, lost as u64);
            }
            Timers::Idle => {}
        }
    }

    /// The timers, if they have not run for [`TICK`]: before a packet either way after a pause, since the
    /// core stamps events with the time of their last run, which alone expires a session the server has
    /// dropped (the spike).
    fn catch_up(&mut self, counters: &Counters) {
        if self.last_timers.elapsed() >= TICK {
            self.tick(counters);
        }
    }

    /// Sends a datagram the core made, or keeps it for the socket being made.
    fn out(&mut self, datagram: Vec<u8>, counters: &Counters) {
        // WireGuard's message type 1 is a handshake initiation (the whitepaper, 5.4.2).
        if datagram.first() == Some(&1) {
            if !self.handshaking {
                self.wake.notify_one();
            }
            self.handshaking = true;
            self.unanswered = self.unanswered.saturating_add(1);
            Counters::add(&counters.tunnel_handshakes, 1);
        }
        match &self.socket {
            Some(socket) => {
                if socket.try_send(&datagram).is_err() {
                    Counters::add(&counters.tunnel_lost, 1);
                }
            }
            None if self.pending.len() < PENDING => self.pending.push(datagram),
            None => Counters::add(&counters.tunnel_lost, 1),
        }
    }

    /// An app's packet into the session.
    fn send(&mut self, packet: &[u8], counters: &Counters) {
        self.catch_up(counters);
        Counters::add(&counters.tunnel_up, 1);
        match self.core.send(packet) {
            Sent::Data(datagram) | Sent::Handshake(datagram) => self.out(datagram, counters),
            Sent::Queued => {}
            Sent::Dropped => Counters::add(&counters.tunnel_lost, 1),
        }
    }

    fn state(&self, id: u32, flows: usize) -> TunnelState {
        TunnelState {
            id,
            handshake: self.core.session_age(),
            received: self.received.map(|at| at.elapsed()),
            error: self.error,
            not_answering: self.unanswered >= UNANSWERED,
            plain_dns: self.plain_dns,
            connected: self.socket.is_some(),
            flows,
        }
    }
}

/// The table of tunnels and their flows.
#[derive(Default)]
struct Table {
    /// The tunnels' numbers in the order set: the first is the default.
    order: Vec<u32>,
    tunnels: HashMap<u32, Tunnel>,
    routes: HashMap<u32, u32>,
    log_destinations: bool,
    flows: HashMap<FlowKey, Tflow>,
    back: HashMap<BackKey, FlowKey>,
    echoes: HashMap<EchoKey, Eflow>,
    echo_back: HashMap<(u32, u16, IpAddr), EchoKey>,
    /// The number of the last generation handed out.
    generations: u64,
    /// The engine's tunnel, for the tasks the table starts, and the network's changes they follow.
    tun: Option<(Arc<Tun>, watch::Receiver<u64>)>,
}

/// The engine's tunnels: the table, and flags read on each packet and each new flow without its lock.
#[derive(Default)]
pub(super) struct Tunnels {
    table: Mutex<Table>,
    /// Whether any app is sent through any tunnel.
    any: AtomicBool,
    /// Whether any tunnelled flow or echo is open.
    carrying: AtomicBool,
    /// Woken when the setting changed, for the engine's loop to start what must start.
    pub(super) changed: Notify,
}

/// What a tunnelled packet from an app gave.
pub(super) enum Forwarded {
    /// Into the tunnel; with a tunnel whose task must start.
    Sent(Option<u32>),
    /// Answered for the app: an error, or a lookup from the tunnel's cache.
    Answer(Vec<u8>),
}

/// No room for a new tunnelled flow.
pub(super) struct Full;

/// Where a new tunnelled flow goes, once admitted: the configuration's address with the app's port, and
/// the destination inside the tunnel.
type Admitted = (SocketAddr, SocketAddr);

impl Tunnels {
    /// Sets the tunnels and the routes (`Engine::tunnels`). A tunnel whose configuration is the same as
    /// before keeps its core, its session and its flows; one set anew, or gone, loses them, and its flows
    /// end. An app whose tunnel changed has its UDP flows end, so that its next datagram takes its new
    /// route, as the chain's are (ADR 0044, decision 1); its TCP connections keep their way.
    pub(super) fn set(&self, setting: &TunnelSetting, shared: &Shared) {
        let ended = {
            let mut table = lock(&self.table);
            let mut tunnels = std::mem::take(&mut table.tunnels);
            let mut order = Vec::new();
            let mut replaced = Vec::new();
            for configured in &setting.tunnels {
                if configured.id == 0 || order.contains(&configured.id) {
                    continue;
                }
                order.push(configured.id);
                let kept = tunnels.remove(&configured.id).filter(|t| {
                    Arc::ptr_eq(&t.config, &configured.config) || *t.config == *configured.config
                });
                let tunnel = if let Some(mut tunnel) = kept {
                    tunnel.local_network = configured.local_network;
                    tunnel
                } else {
                    if table.order.contains(&configured.id) {
                        replaced.push(configured.id);
                    }
                    table.generations += 1;
                    Tunnel::new(configured, table.generations)
                };
                table.tunnels.insert(configured.id, tunnel);
            }
            // What is left is gone: its task stops when it sees that.
            drop(tunnels);
            table.order = order;
            let routes: HashMap<u32, u32> = setting
                .routes
                .iter()
                .filter(|(_, t)| table.tunnels.contains_key(t))
                .map(|(&uid, &t)| (uid, t))
                .collect();
            let moved: Vec<Option<u32>> = table
                .routes
                .iter()
                .filter(|(uid, t)| routes.get(uid) != Some(t))
                .map(|(&uid, _)| Some(uid))
                .chain(
                    routes
                        .keys()
                        .filter(|uid| !table.routes.contains_key(uid))
                        .map(|&uid| Some(uid)),
                )
                .collect();
            table.routes = routes;
            table.log_destinations = setting.log_destinations;
            self.any.store(!table.routes.is_empty(), Ordering::Release);
            // Flows of a tunnel gone or set anew end, whose source may no longer be the configuration's.
            table.end_where(|(_, flow, protocol)| {
                replaced.contains(&flow.tunnel) || (protocol == UDP && moved.contains(&flow.uid))
            })
        };
        for id in ended {
            shared.finish(id);
        }
        self.update_carrying();
        self.changed.notify_one();
    }

    /// The setting as it stands, for the next engine ([`super::Handover`]).
    pub(super) fn setting(&self) -> TunnelSetting {
        let table = lock(&self.table);
        TunnelSetting {
            tunnels: table
                .order
                .iter()
                .filter_map(|id| {
                    table.tunnels.get(id).map(|t| Configured {
                        id: *id,
                        config: Arc::clone(&t.config),
                        local_network: t.local_network,
                    })
                })
                .collect(),
            routes: table.routes.clone(),
            log_destinations: table.log_destinations,
        }
    }

    /// Whether any app is sent through any tunnel.
    pub(super) fn any(&self) -> bool {
        self.any.load(Ordering::Acquire)
    }

    /// Whether any tunnelled flow is open: the one check every packet makes.
    fn carrying(&self) -> bool {
        self.carrying.load(Ordering::Acquire)
    }

    fn update_carrying(&self) {
        let table = lock(&self.table);
        let carrying = !table.flows.is_empty() || !table.echoes.is_empty();
        self.carrying.store(carrying, Ordering::Release);
    }

    /// The tunnel the app `uid` is sent through, if one: its own, or for an app Android cannot name the
    /// default while any app is sent through one.
    pub(super) fn route_of(&self, uid: Option<u32>) -> Option<u32> {
        if !self.any() {
            return None;
        }
        let table = lock(&self.table);
        match uid {
            Some(uid) => table.routes.get(&uid).copied(),
            None => table.order.first().copied(),
        }
    }

    /// The default tunnel, while any app is sent through one: the way of ICMP echo.
    pub(super) fn default_tunnel(&self) -> Option<u32> {
        self.route_of(None)
    }

    /// Whether `destination` goes directly for an app of the tunnel `t`, by its "local network directly"
    /// (ADR 0035, question 8): a private, link-local, unique-local or multicast address, but not one of the
    /// configuration's own, its DNS servers', or Watch's own addresses, which go through the tunnel.
    pub(super) fn local_directly(&self, t: u32, destination: IpAddr, shared: &Shared) -> bool {
        let table = lock(&self.table);
        let Some(tunnel) = table.tunnels.get(&t) else {
            return false;
        };
        tunnel.local_network
            && is_local(destination)
            && !shared.is_tunnel_dns(destination)
            && !tunnel.config.dns.contains(&destination)
            && !tunnel.config.addresses.covers(destination)
            && !own_address(shared, destination)
    }

    /// Whether the destinations of tunnelled flows are kept.
    pub(super) fn logs_destinations(&self) -> bool {
        lock(&self.table).log_destinations
    }

    /// The engine's loop started on `tun`: the tasks the table starts write there, and follow `changes`.
    pub(super) fn attach(&self, tun: &Arc<Tun>, changes: &watch::Receiver<u64>) {
        lock(&self.table).tun = Some((Arc::clone(tun), changes.clone()));
    }

    /// Every tunnel's state, in the order set.
    pub(super) fn states(&self) -> Vec<TunnelState> {
        let table = lock(&self.table);
        table
            .order
            .iter()
            .filter_map(|id| {
                let flows = table.flows.values().filter(|f| f.tunnel == *id).count();
                table.tunnels.get(id).map(|t| t.state(*id, flows))
            })
            .collect()
    }

    /// Where a new flow of the app at `app` to `shown` goes through the tunnel `t`, if it may: inside the
    /// peer's `AllowedIPs`, of a version the configuration has an address of. Lookups to Watch's own DNS
    /// address go to the configuration's DNS server, of the same version where `same_version` asks (TCP
    /// and echo, whose packets keep their version), else of either.
    fn admit(
        &self,
        t: u32,
        app: SocketAddr,
        shown: SocketAddr,
        shared: &Shared,
        same_version: bool,
    ) -> Option<Admitted> {
        let table = lock(&self.table);
        admit(&table, t, app, shown, shared, same_version)
    }

    /// Notes a new tunnelled flow, admitted, and gives back the tunnel whose task must start, if one.
    /// [`Full`] when as many flows as allowed are open: the caller drops what it carries.
    fn open(&self, key: FlowKey, flow: Tflow) -> Result<Option<u32>, Full> {
        let mut table = lock(&self.table);
        if table.flows.len() >= FLOWS {
            return Err(Full);
        }
        let back = (flow.tunnel, key.0, flow.to, flow.from.port());
        // The same back key for another flow: two app sockets of the same port, IPv4 and IPv6, to the same
        // DNS server through the version they share. The second is refused.
        if table.back.get(&back).is_some_and(|other| *other != key) {
            return Err(Full);
        }
        let tunnel = flow.tunnel;
        table.back.insert(back, key);
        table.flows.insert(key, flow);
        drop(table);
        self.carrying.store(true, Ordering::Release);
        Ok(self.wanted(tunnel))
    }

    /// Whether the tunnel `t` needs its task started, which the caller starts: it has none.
    fn wanted(&self, t: u32) -> Option<u32> {
        let mut table = lock(&self.table);
        let tunnel = table.tunnels.get_mut(&t)?;
        (!tunnel.carried).then(|| {
            tunnel.carried = true;
            t
        })
    }
}

impl Table {
    /// Ends the flows `ended` says, and gives back their numbers in the log.
    fn end_where(&mut self, ended: impl Fn((&FlowKey, &Tflow, u8)) -> bool) -> Vec<u64> {
        let gone: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(key, flow)| {
                !self.tunnels.contains_key(&flow.tunnel) || ended((key, flow, key.0))
            })
            .map(|(key, _)| *key)
            .collect();
        let mut ids = Vec::new();
        for key in gone {
            if let Some(flow) = self.flows.remove(&key) {
                self.back
                    .remove(&(flow.tunnel, key.0, flow.to, flow.from.port()));
                if flow.id != 0 {
                    ids.push(flow.id);
                }
            }
        }
        let tunnels = &self.tunnels;
        self.echoes
            .retain(|_, echo| tunnels.contains_key(&echo.tunnel));
        let echoes = &self.echoes;
        self.echo_back.retain(|_, key| echoes.contains_key(key));
        ids
    }

    /// Forgets flows that ended, and those silent past their bound: a closed TCP connection after the
    /// linger of its last segments, a UDP flow silent `udp_idle`, an echo `ECHO_IDLE`.
    fn sweep(&mut self, now: Instant, shared: &Shared) -> Vec<u64> {
        let limits = shared.limits;
        let ids = self.end_where(|(_, flow, protocol)| {
            let silent = now.saturating_duration_since(flow.last);
            match protocol {
                TCP => {
                    flow.closed
                        .is_some_and(|at| now.saturating_duration_since(at) >= limits.close_linger)
                        || silent >= TCP_IDLE
                }
                _ => silent >= limits.udp_idle,
            }
        });
        self.echoes
            .retain(|_, echo| now.saturating_duration_since(echo.last) < ECHO_IDLE);
        let echoes = &self.echoes;
        self.echo_back.retain(|_, key| echoes.contains_key(key));
        ids
    }
}

fn admit(
    table: &Table,
    t: u32,
    app: SocketAddr,
    shown: SocketAddr,
    shared: &Shared,
    same_version: bool,
) -> Option<Admitted> {
    let config = &table.tunnels.get(&t)?.config;
    let to_ip = if shared.is_tunnel_dns(shown.ip()) {
        let dns = config.dns_like(shown.ip())?;
        if same_version && dns.is_ipv4() != shown.is_ipv4() {
            return None;
        }
        dns
    } else {
        shown.ip()
    };
    if !config.peer.allows(to_ip) {
        return None;
    }
    let from = config.addresses.like(to_ip)?;
    Some((
        SocketAddr::new(from, app.port()),
        SocketAddr::new(to_ip, shown.port()),
    ))
}

/// Whether `address` is on the local network as "local network directly" reads it: IPv4's private ranges
/// (RFC 1918), link-local (RFC 3927) and multicast, IPv6's link-local, unique-local (RFC 4193) and
/// multicast.
fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.is_multicast(),
        IpAddr::V6(a) => a.is_unicast_link_local() || a.is_unique_local() || a.is_multicast(),
    }
}

/// Whether `address` is one of Watch's own in the tunnel: its address, the fake peer, its DNS address.
fn own_address(shared: &Shared, address: IpAddr) -> bool {
    let at = shared.addresses;
    [
        IpAddr::V4(at.tun4),
        IpAddr::V4(at.fake4),
        IpAddr::V4(at.dns4),
        IpAddr::V6(at.tun6),
        IpAddr::V6(at.fake6),
        IpAddr::V6(at.dns6),
    ]
    .contains(&address)
}

/// The bytes a TCP segment carries.
fn tcp_payload(packet: &[u8], parsed: &Packet) -> usize {
    let offset = packet
        .get(parsed.transport + 12)
        .map_or(20, |b| usize::from(b >> 4) * 4);
    parsed.length.saturating_sub(parsed.transport + offset)
}

/// A packet into the tunnel `t` that is larger than its MTU and may not be fragmented gets the app an
/// error that says what passes, as from its destination, as a router would answer: IPv4's "fragmentation
/// needed", `ICMPv6`'s "packet too big". A datagram the engine put together from the app's own fragments
/// passes as it is, since it came fragmented and an error would only have it fragmented again.
fn too_big(
    packet: &[u8],
    (source, destination): (IpAddr, IpAddr),
    mtu: u16,
    reassembled: bool,
) -> Option<Vec<u8>> {
    if packet.len() <= usize::from(mtu) || reassembled || !swap::dont_fragment(packet) {
        return None;
    }
    packet::too_big(packet, destination, source, u32::from(mtu))
}

impl Shared {
    /// Counts a new tunnelled flow and keeps it for tests; for the log, as a chained one is: its
    /// destination stays out unless "Log where these apps connect" is on.
    pub(super) fn record_tunnelled(&self, mut flow: Flow, t: u32) -> Option<Arc<FlowBytes>> {
        flow.via = Via::Tunnel(t);
        self.record_via(flow, None)
    }
}

/// What the app's packet of an open tunnelled flow becomes: into the tunnel, answered, or not one.
fn forward(
    table: &mut Table,
    shared: &Shared,
    key: FlowKey,
    (packet, parsed): (&mut [u8], &Packet),
    reassembled: bool,
) -> Option<Forwarded> {
    let counters = &shared.counters;
    let now = Instant::now();
    let flow = table.flows.get_mut(&key)?;
    let t = flow.tunnel;
    if parsed.protocol == TCP {
        let flags = packet::tcp_flags(packet, parsed);
        // A new connection on the ends of one that closed: routed anew.
        if flags & SYN != 0 && flags & ACK == 0 && (flow.reset || (flow.fin_up && flow.fin_down)) {
            return None;
        }
        flow.fin_up |= flags & FIN != 0;
        flow.reset |= flags & RST != 0;
        if flow.closed.is_none() && (flow.reset || (flow.fin_up && flow.fin_down)) {
            flow.closed = Some(now);
        }
    }
    flow.last = now;
    let (from, to, lookups, uid, bytes) = (
        flow.from,
        flow.to,
        flow.lookups,
        flow.uid,
        flow.bytes.clone(),
    );
    let tunnel = table.tunnels.get_mut(&t)?;
    let mtu = tunnel.config.mtu();
    if lookups && parsed.protocol == UDP {
        // Watch's DNS address answers: from the tunnel's cache, or the query rebuilt toward its server.
        let payload = packet::udp_payload(packet, parsed)?.to_vec();
        shared.lookup(uid, packet.len());
        if let Some(mut answer) = tunnel.answers.answer(&payload, shared.clock.since_boot()) {
            crate::dns::uncache(&mut answer);
            let rebuilt = packet::udp(key.2, key.1, &answer)?;
            shared.lookup_answered(uid, rebuilt.len());
            return Some(Forwarded::Answer(rebuilt));
        }
        let rebuilt = packet::udp(from, to, &payload)?;
        tunnel.send(&rebuilt, counters);
        Counters::add(&counters.bytes_up, payload.len() as u64);
        return Some(Forwarded::Sent(restart(tunnel, t)));
    }
    // Quoted as the app sent it, before the swap, which changes no length.
    if let Some(error) = too_big(
        &packet[..parsed.length],
        (parsed.source.ip(), parsed.destination.ip()),
        mtu,
        reassembled,
    ) {
        Counters::add(&counters.tunnel_too_big, 1);
        return Some(Forwarded::Answer(error));
    }
    swap::swap(packet, parsed, from.ip(), to.ip())?;
    if parsed.protocol == TCP && packet::tcp_flags(packet, parsed) & SYN != 0 {
        swap::clamp_mss(packet, parsed, swap::largest_mss(mtu, to.is_ipv4()));
    }
    let sent = &packet[..parsed.length];
    tunnel.send(sent, counters);
    let start = restart(tunnel, t);
    let app_bytes = if parsed.protocol == TCP {
        tcp_payload(sent, parsed)
    } else {
        parsed.length.saturating_sub(parsed.transport + 8)
    };
    Counters::add(&counters.bytes_up, app_bytes as u64);
    if let Some(bytes) = bytes {
        bytes.up(shared, app_bytes, sent.len());
    }
    Some(Forwarded::Sent(start))
}

/// The tunnel `t` if its task must start again, as after its socket could not be made: marked carried.
fn restart(tunnel: &mut Tunnel, t: u32) -> Option<u32> {
    (!tunnel.carried).then(|| {
        tunnel.carried = true;
        t
    })
}

/// What the way back makes of a packet the tunnel `t` decrypted: the packet for the app, or nothing, the
/// drop counted.
#[allow(clippy::too_many_lines)]
fn back(table: &mut Table, shared: &Shared, t: u32, mut packet: Vec<u8>) -> Option<Vec<u8>> {
    let counters = &shared.counters;
    let config = Arc::clone(&table.tunnels.get(&t)?.config);
    let read = swap::read(&packet);
    let (source, destination) = match &read {
        Back::Transport(parsed) => (parsed.source.ip(), parsed.destination.ip()),
        Back::EchoReply(echo) => (echo.source, echo.destination),
        Back::Error(error) => (error.source, error.destination),
        Back::Other => {
            Counters::add(&counters.tunnel_unmatched, 1);
            return None;
        }
    };
    // From inside the peer's AllowedIPs, to this phone's address in the tunnel: nothing else comes in.
    if !config.peer.allows(source) || config.addresses.like(destination) != Some(destination) {
        Counters::add(&counters.tunnel_filtered, 1);
        return None;
    }
    let now = Instant::now();
    match read {
        Back::Transport(parsed) => {
            let Some(&key) =
                table
                    .back
                    .get(&(t, parsed.protocol, parsed.source, parsed.destination.port()))
            else {
                Counters::add(&counters.tunnel_unmatched, 1);
                return None;
            };
            let flow = table.flows.get_mut(&key)?;
            flow.last = now;
            let (app, shown, lookups, uid, bytes) =
                (key.1, key.2, flow.lookups, flow.uid, flow.bytes.clone());
            if parsed.protocol == UDP && lookups {
                let mut answer = packet::udp_payload(&packet, &parsed)?.to_vec();
                Counters::add(&counters.bytes_down, answer.len() as u64);
                shared.learn(&answer, None);
                if let Some(tunnel) = table.tunnels.get_mut(&t) {
                    tunnel.answers.insert(&answer, shared.clock.since_boot());
                }
                crate::dns::uncache(&mut answer);
                let rebuilt = packet::udp(shown, app, &answer)?;
                shared.lookup_answered(uid, rebuilt.len());
                Counters::add(&counters.tunnel_down, 1);
                return Some(rebuilt);
            }
            if parsed.protocol == TCP {
                let flags = packet::tcp_flags(&packet, &parsed);
                flow.fin_down |= flags & FIN != 0;
                flow.reset |= flags & RST != 0;
                if flow.closed.is_none() && (flow.reset || (flow.fin_up && flow.fin_down)) {
                    flow.closed = Some(now);
                }
                if flags & SYN != 0 {
                    swap::clamp_mss(
                        &mut packet,
                        &parsed,
                        swap::largest_mss(config.mtu(), parsed.source.is_ipv4()),
                    );
                }
                if lookups {
                    learn_tcp(shared, &packet, &parsed);
                }
            }
            swap::swap(&mut packet, &parsed, shown.ip(), app.ip())?;
            let app_bytes = if parsed.protocol == TCP {
                tcp_payload(&packet, &parsed)
            } else {
                parsed.length.saturating_sub(parsed.transport + 8)
            };
            Counters::add(&counters.bytes_down, app_bytes as u64);
            if let Some(bytes) = bytes {
                bytes.down(shared, app_bytes, packet.len());
            }
            Counters::add(&counters.tunnel_down, 1);
            Some(packet)
        }
        Back::EchoReply(echo) => {
            let Some(&key) = table.echo_back.get(&(t, echo.id, echo.source)) else {
                Counters::add(&counters.tunnel_unmatched, 1);
                return None;
            };
            let flow = table.echoes.get_mut(&key)?;
            flow.last = now;
            swap::swap_echo(&mut packet, &echo, key.2, key.0)?;
            Counters::add(&counters.echo_replies, 1);
            Counters::add(&counters.tunnel_down, 1);
            Some(packet)
        }
        Back::Error(error) => {
            if config.addresses.like(error.from.ip()) != Some(error.from.ip()) {
                Counters::add(&counters.tunnel_filtered, 1);
                return None;
            }
            let (app, shown) = match error.protocol {
                TCP | UDP => {
                    let key = table
                        .back
                        .get(&(t, error.protocol, error.to, error.from.port()));
                    let Some(&(_, app, shown)) = key else {
                        Counters::add(&counters.tunnel_unmatched, 1);
                        return None;
                    };
                    (app.ip(), shown.ip())
                }
                _ => {
                    let key = table.echo_back.get(&(t, error.from.port(), error.to.ip()));
                    let Some(&(app, _, shown)) = key else {
                        Counters::add(&counters.tunnel_unmatched, 1);
                        return None;
                    };
                    (app, shown)
                }
            };
            swap::swap_error(&mut packet, &error, app, (app, shown))?;
            Counters::add(&counters.tunnel_down, 1);
            Some(packet)
        }
        Back::Other => None,
    }
}

/// Learns the names of a DNS answer over TCP when the segment holds one whole, after its two bytes of
/// length: no stream is put together for it. Android's resolver asks over TCP only for an answer cut
/// short over UDP, which then also named the flow.
fn learn_tcp(shared: &Shared, packet: &[u8], parsed: &Packet) {
    let payload = tcp_payload(packet, parsed);
    let start = parsed.length.saturating_sub(payload);
    let Some(segment) = packet.get(start..parsed.length) else {
        return;
    };
    if let (Some(length), Some(message)) = (packet::u16_at(segment, 0), segment.get(2..))
        && usize::from(length) == message.len()
    {
        shared.learn(message, None);
    }
}

impl super::Loop {
    /// A packet of an open tunnelled TCP or UDP flow, which goes into its tunnel: whether it was one.
    pub(super) async fn tunnelled(
        &self,
        packet: &mut [u8],
        parsed: &Packet,
        reassembled: bool,
    ) -> bool {
        let tunnels = &self.shared.tunnels;
        if !tunnels.carrying() {
            return false;
        }
        let key = (parsed.protocol, parsed.source, parsed.destination);
        let forwarded = {
            let mut table = lock(&tunnels.table);
            forward(&mut table, &self.shared, key, (packet, parsed), reassembled)
        };
        match forwarded {
            None => false,
            Some(Forwarded::Sent(start)) => {
                if let Some(t) = start {
                    start_task(&self.shared, t);
                }
                true
            }
            Some(Forwarded::Answer(answer)) => {
                self.send(&answer).await;
                true
            }
        }
    }

    /// An app's echo request while any app goes through a tunnel: through the default tunnel, since
    /// Android cannot say whose it is (ADR 0035, question 7 as settled); refused where that tunnel cannot
    /// carry it. No record of it goes to the log, as for every echo.
    pub(super) async fn tunnel_echo(&self, packet: &mut [u8], request: &Echo) {
        let shared = &self.shared;
        let counters = &shared.counters;
        let refuse = || {
            Counters::add(&counters.echo_refused, 1);
            Counters::add(&counters.tunnel_refused, 1);
            packet::echo_refused(packet, request)
        };
        let Some(t) = shared.tunnels.default_tunnel() else {
            if let Some(error) = refuse() {
                self.send(&error).await;
            }
            return;
        };
        let shown = SocketAddr::new(request.destination, 0);
        let admitted = if crate::standins::is_stand_in(request.destination) {
            None
        } else {
            shared.tunnels.admit(
                t,
                SocketAddr::new(request.source, request.id),
                shown,
                shared,
                true,
            )
        };
        let Some((from, to)) = admitted else {
            if let Some(error) = refuse() {
                self.send(&error).await;
            }
            return;
        };
        let (start, answer) = {
            let mut table = lock(&shared.tunnels.table);
            let key = (request.source, request.id, request.destination);
            if !table.echoes.contains_key(&key) && table.echoes.len() >= FLOWS {
                Counters::add(&counters.echo_dropped, 1);
                return;
            }
            table.echoes.insert(
                key,
                Eflow {
                    tunnel: t,
                    last: Instant::now(),
                },
            );
            table.echo_back.insert((t, request.id, to.ip()), key);
            let Some(()) = swap::swap_echo(packet, request, from.ip(), to.ip()) else {
                return;
            };
            let Some(tunnel) = table.tunnels.get_mut(&t) else {
                return;
            };
            let mtu = tunnel.config.mtu();
            let sent = &packet[..request.length];
            if sent.len() > usize::from(mtu) {
                // Quoted as the app sent it.
                let _ = swap::swap_echo(packet, request, request.source, request.destination);
                Counters::add(&counters.tunnel_too_big, 1);
                (
                    None,
                    packet::too_big(
                        &packet[..request.length],
                        request.destination,
                        request.source,
                        u32::from(mtu),
                    ),
                )
            } else {
                tunnel.send(sent, counters);
                Counters::add(&counters.echo_carried, 1);
                Counters::add(&counters.bytes_up, (request.length - request.icmp) as u64);
                (restart(tunnel, t), None)
            }
        };
        shared.tunnels.carrying.store(true, Ordering::Release);
        if let Some(t) = start {
            start_task(shared, t);
        }
        if let Some(answer) = answer {
            self.send(&answer).await;
        }
    }

    /// The setting changed (`Engine::tunnels`): a tunnel whose configuration asks for keepalives starts at
    /// once, as `WireGuard`'s own implementations start such a peer, once an app is sent through it.
    pub(super) fn tunnels_changed(&self) {
        let shared = &self.shared;
        let start: Vec<u32> = {
            let mut table = lock(&shared.tunnels.table);
            let used: Vec<u32> = table.routes.values().copied().collect();
            table
                .tunnels
                .iter_mut()
                .filter(|(id, t)| !t.carried && t.core.keeps_alive() && used.contains(id))
                .map(|(id, t)| {
                    t.carried = true;
                    *id
                })
                .collect()
        };
        for t in start {
            start_task(shared, t);
        }
    }

    /// Forgets tunnelled flows that ended or fell silent; each ends in the log.
    pub(super) fn sweep_tunnels(&self) {
        let ids = lock(&self.shared.tunnels.table).sweep(Instant::now(), &self.shared);
        for id in ids {
            self.shared.finish_closed(id);
        }
        self.shared.tunnels.update_carrying();
    }
}

/// A held SYN of the app at `app` to `destination` whose app goes through the tunnel `t` (`tcp::open`):
/// the flow is noted and recorded, and its SYN goes into the tunnel, swapped. Gives what the app gets at
/// once, if anything: an error where the tunnel cannot carry it.
pub(super) fn open_tcp(
    shared: &Arc<Shared>,
    (uid, t): (Option<u32>, u32),
    (mut held, parsed): (Vec<u8>, Packet),
) -> Option<Vec<u8>> {
    let (app, destination) = (parsed.source, parsed.destination);
    let counters = &shared.counters;
    let mut flow = new_flow(shared, TCP, (app, destination), uid);
    let Some((from, to)) = shared.tunnels.admit(t, app, destination, shared, true) else {
        Counters::add(&counters.tunnel_refused, 1);
        flow.outcome = Outcome::Unreachable;
        shared.record_tunnelled(flow, t);
        return packet::unreachable(&held, &parsed, Unreachable::Prohibited);
    };
    let lookups = shared.is_tunnel_dns(destination.ip());
    // Counted as any flow; the log keeps none of Watch's own DNS address.
    let id = flow.id;
    let bytes = shared.record_tunnelled(flow, t);
    let now = Instant::now();
    let opened = shared.tunnels.open(
        (TCP, app, destination),
        Tflow {
            tunnel: t,
            uid,
            id,
            bytes,
            from,
            to,
            lookups,
            last: now,
            fin_up: false,
            fin_down: false,
            reset: false,
            closed: None,
        },
    );
    let Ok(start) = opened else {
        Counters::add(&counters.tcp_refused, 1);
        if id != 0 {
            shared.finish(id);
        }
        return None;
    };
    let answer = {
        let mut table = lock(&shared.tunnels.table);
        match forward(
            &mut table,
            shared,
            (TCP, app, destination),
            (&mut held, &parsed),
            false,
        ) {
            Some(Forwarded::Answer(answer)) => Some(answer),
            _ => None,
        }
    };
    if let Some(t) = start {
        start_task(shared, t);
    }
    answer
}

/// What is known of a new flow once Android named its app, as the direct path begins one.
fn new_flow(
    shared: &Shared,
    protocol: u8,
    (app, destination): (SocketAddr, SocketAddr),
    uid: Option<u32>,
) -> Flow {
    let super::naming::Begun {
        id,
        name,
        named_by,
        network,
        ..
    } = shared.begin(destination, uid);
    let by_dns = (named_by == super::NamedBy::Dns)
        .then_some(name.as_deref())
        .flatten();
    let (dns, resolver) = shared.dns_use(destination, by_dns);
    Flow {
        id,
        protocol,
        app,
        destination,
        uid,
        outcome: Outcome::Opened,
        name,
        named_by,
        dns_name: None,
        came_in: false,
        ech: super::Ech::Absent,
        dns,
        resolver,
        network,
        via: Via::Direct,
    }
}

/// The datagrams that waited for a new UDP destination whose app goes through the tunnel `t`
/// (`udp::open_mapped`, `udp::open_lookups`): the flow is noted, recorded unless it is lookups, which the
/// log counts by app, and each datagram goes into the tunnel. An error goes back to the app where the
/// tunnel cannot carry it.
pub(super) async fn open_udp(
    shared: &Arc<Shared>,
    tun: &Arc<Tun>,
    (key, uid, t): ((SocketAddr, SocketAddr), Option<u32>, u32),
    waiting: Vec<Vec<u8>>,
) {
    let (app, destination) = key;
    let counters = &shared.counters;
    let lookups = shared.is_tunnel_dns(destination.ip());
    let Some(first) = waiting.first() else {
        return;
    };
    let Some((from, to)) = shared.tunnels.admit(t, app, destination, shared, false) else {
        Counters::add(&counters.tunnel_refused, 1);
        let mut flow = new_flow(shared, UDP, key, uid);
        flow.outcome = Outcome::Unreachable;
        shared.record_tunnelled(flow, t);
        let error = packet::parse(first)
            .ok()
            .and_then(|parsed| packet::unreachable(first, &parsed, Unreachable::Prohibited));
        if let Some(error) = error {
            send_to_app(tun, shared, &error).await;
        }
        return;
    };
    let flow = new_flow(shared, UDP, key, uid);
    let id = flow.id;
    let bytes = shared.record_tunnelled(flow, t);
    let opened = shared.tunnels.open(
        (UDP, app, destination),
        Tflow {
            tunnel: t,
            uid,
            id,
            bytes,
            from,
            to,
            lookups,
            last: Instant::now(),
            fin_up: false,
            fin_down: false,
            reset: false,
            closed: None,
        },
    );
    let Ok(start) = opened else {
        Counters::add(&counters.udp_refused, waiting.len() as u64);
        if id != 0 {
            shared.finish(id);
        }
        return;
    };
    let mut answers = Vec::new();
    {
        let mut table = lock(&shared.tunnels.table);
        for mut packet in waiting {
            let Ok(parsed) = packet::parse(&packet) else {
                continue;
            };
            if let Some(Forwarded::Answer(answer)) = forward(
                &mut table,
                shared,
                (UDP, app, destination),
                (&mut packet, &parsed),
                false,
            ) {
                answers.push(answer);
            }
        }
    }
    if let Some(t) = start {
        start_task(shared, t);
    }
    for answer in answers {
        send_to_app(tun, shared, &answer).await;
    }
}

/// Starts the task of the tunnel `t`, which the caller marked as carried.
fn start_task(shared: &Arc<Shared>, t: u32) {
    let Some((tun, changes)) = lock(&shared.tunnels.table).tun.clone() else {
        return;
    };
    tokio::spawn(carry(Arc::clone(shared), tun, t, changes));
}

/// What a tunnel's task needs of it, read under the table's lock.
struct Ready {
    generation: u64,
    endpoint: Option<SocketAddr>,
    name: Option<(String, u16)>,
    wake: Arc<Notify>,
}

fn ready(shared: &Shared, t: u32) -> Option<Ready> {
    let table = lock(&shared.tunnels.table);
    let tunnel = table.tunnels.get(&t)?;
    let name = match &tunnel.config.peer.endpoint {
        Endpoint::Name(name, port) => Some((name.clone(), *port)),
        Endpoint::Address(_) => None,
    };
    Some(Ready {
        generation: tunnel.generation,
        endpoint: tunnel.endpoint,
        name,
        wake: Arc::clone(&tunnel.wake),
    })
}

/// The tunnel `t`, while it is still of `generation`.
fn current(table: &mut Table, t: u32, generation: u64) -> Option<&mut Tunnel> {
    table
        .tunnels
        .get_mut(&t)
        .filter(|tunnel| tunnel.generation == generation)
}

/// A tunnel's task: resolves its endpoint if it is a name, makes its protected socket, sends what waited
/// for it, then reads its server's datagrams, runs its timers while they must run, and on a network change
/// makes its socket anew and tells the server at once (ADR 0035, "Roaming"). It ends when the tunnel is
/// set anew or removed, or its socket cannot be made, which the next packet tries again.
async fn carry(shared: Arc<Shared>, tun: Arc<Tun>, t: u32, changes: watch::Receiver<u64>) {
    let Some(mut ready) = ready(&shared, t) else {
        return;
    };
    carry_while(&shared, &tun, t, changes, &mut ready).await;
    // Ended with the tunnel still in place, as when its socket failed: the next packet starts another.
    if let Some(tunnel) = current(&mut lock(&shared.tunnels.table), t, ready.generation) {
        tunnel.carried = false;
        tunnel.socket = None;
        tunnel.pending.clear();
    }
}

async fn carry_while(
    shared: &Arc<Shared>,
    tun: &Arc<Tun>,
    t: u32,
    mut changes: watch::Receiver<u64>,
    ready: &mut Ready,
) {
    changes.borrow_and_update();
    let Some(mut socket) = connect(shared, t, ready).await else {
        return;
    };
    let mut buffer = vec![0u8; LARGEST];
    loop {
        let (ticks, resolve) = {
            let mut table = lock(&shared.tunnels.table);
            let Some(tunnel) = current(&mut table, t, ready.generation) else {
                return;
            };
            let resolve = ready.name.is_some()
                && tunnel.unanswered >= RESOLVE_AFTER
                && tunnel
                    .resolved_at
                    .is_none_or(|at| at.elapsed() >= RESOLVE_AGAIN);
            (tunnel.ticks(), resolve)
        };
        if resolve {
            // Handshakes fail: the name may point elsewhere now.
            ready.endpoint = None;
            match connect(shared, t, ready).await {
                Some(again) => socket = again,
                None => continue,
            }
        }
        let wake = Arc::clone(&ready.wake);
        tokio::select! {
            moved = changes.changed() => {
                if moved.is_err() {
                    return;
                }
                if let Some(again) = connect(shared, t, ready).await {
                    socket = again;
                    roamed(shared, t, ready.generation);
                }
            }
            () = wake.notified() => {}
            () = tokio::time::sleep(TICK), if ticks => {
                let mut table = lock(&shared.tunnels.table);
                if let Some(tunnel) = current(&mut table, t, ready.generation) {
                    tunnel.tick(&shared.counters);
                }
            }
            readable = socket.readable() => {
                if readable.is_err() {
                    return;
                }
                let packets = receive(shared, t, ready.generation, &socket, &mut buffer);
                for packet in packets {
                    send_to_app(tun, shared, &packet).await;
                }
            }
        }
    }
}

/// Reads what the socket holds, at most a batch: each datagram through the core, the packets it
/// decrypted through the way back, for the app.
fn receive(
    shared: &Shared,
    t: u32,
    generation: u64,
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for _ in 0..super::BATCH {
        let n = match socket.try_recv(buffer) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => {
                if let Some(tunnel) = current(&mut lock(&shared.tunnels.table), t, generation) {
                    tunnel.error = Some(if error.kind() == io::ErrorKind::ConnectionRefused {
                        "refused"
                    } else {
                        "network"
                    });
                }
                break;
            }
        };
        let mut table = lock(&shared.tunnels.table);
        let Some(tunnel) = current(&mut table, t, generation) else {
            break;
        };
        tunnel.catch_up(&shared.counters);
        let from = tunnel
            .endpoint
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        match tunnel.core.receive(from, &buffer[..n]) {
            Received::Send {
                datagrams,
                established,
            } => {
                if established {
                    tunnel.handshaking = false;
                    tunnel.unanswered = 0;
                    tunnel.received = Some(Instant::now());
                    tunnel.error = None;
                }
                for datagram in datagrams {
                    tunnel.out(datagram, &shared.counters);
                }
            }
            Received::Keepalive => {
                tunnel.received = Some(Instant::now());
                tunnel.unanswered = 0;
            }
            Received::Packet(packet) => {
                tunnel.received = Some(Instant::now());
                tunnel.unanswered = 0;
                if let Some(packet) = back(&mut table, shared, t, packet) {
                    packets.push(packet);
                }
            }
            Received::Refused(why) => {
                tunnel.error = Some(why);
                Counters::add(&shared.counters.tunnel_rejected, 1);
            }
        }
    }
    packets
}

/// After a network change, the server learns the new address at once: a keepalive, or a handshake when the
/// session is old enough to be renewed (`REKEY_AFTER_TIME`, two minutes).
fn roamed(shared: &Shared, t: u32, generation: u64) {
    let mut table = lock(&shared.tunnels.table);
    let Some(tunnel) = current(&mut table, t, generation) else {
        return;
    };
    tunnel.catch_up(&shared.counters);
    let datagram = match tunnel.core.session_age() {
        Some(age) if age < Duration::from_secs(120) => tunnel.core.keepalive(),
        Some(_) => tunnel.core.handshake(),
        None => None,
    };
    if let Some(datagram) = datagram {
        tunnel.out(datagram, &shared.counters);
    }
}

/// Makes the tunnel's protected socket, connected to its endpoint, resolving a name first where it has
/// none, and puts it in place, sending what waited for it. `None` where it could not, the error noted.
async fn connect(shared: &Arc<Shared>, t: u32, ready: &mut Ready) -> Option<Arc<UdpSocket>> {
    let endpoint = match (ready.endpoint, &ready.name) {
        (Some(endpoint), _) => endpoint,
        (None, Some((name, port))) => {
            let resolved = resolve(shared, name, *port).await;
            let mut table = lock(&shared.tunnels.table);
            let tunnel = current(&mut table, t, ready.generation)?;
            tunnel.resolved_at = Some(Instant::now());
            // Watch has no encrypted resolver of its own before W8: the network's resolver it is, and the
            // state says so (ADR 0035, question 9).
            tunnel.plain_dns = true;
            let Some(endpoint) = resolved else {
                tunnel.error = Some("resolve");
                return None;
            };
            tunnel.endpoint = Some(endpoint);
            endpoint
        }
        (None, None) => return None,
    };
    ready.endpoint = Some(endpoint);
    let made = async {
        let socket = UdpSocket::bind(packet::unspecified_like(&endpoint)).await?;
        protect(shared, socket.as_fd()).await?;
        socket.connect(endpoint).await?;
        io::Result::Ok(socket)
    };
    let Ok(socket) = made.await.map(Arc::new) else {
        if let Some(tunnel) = current(&mut lock(&shared.tunnels.table), t, ready.generation) {
            tunnel.error = Some("network");
        }
        return None;
    };
    let _ = socket.writable().await;
    let mut table = lock(&shared.tunnels.table);
    let tunnel = current(&mut table, t, ready.generation)?;
    tunnel.socket = Some(Arc::clone(&socket));
    for datagram in std::mem::take(&mut tunnel.pending) {
        if socket.try_send(&datagram).is_err() {
            Counters::add(&shared.counters.tunnel_lost, 1);
        }
    }
    Some(socket)
}

/// The address of `name`, asked of the network's resolver over a protected socket: an IPv4 address, else
/// an IPv6 one.
async fn resolve(shared: &Arc<Shared>, name: &str, port: u16) -> Option<SocketAddr> {
    let resolver = (*lock(&shared.upstream_dns))?;
    for kind in [crate::answers::A, crate::answers::AAAA] {
        let Some(query) = query(name, kind) else {
            continue;
        };
        let asked = async {
            let socket =
                UdpSocket::bind(packet::unspecified_like(&SocketAddr::new(resolver, 53))).await?;
            protect(shared, socket.as_fd()).await?;
            socket.connect(SocketAddr::new(resolver, 53)).await?;
            socket.send(&query).await?;
            let mut answer = vec![0u8; 4_096];
            let n = socket.recv(&mut answer).await?;
            answer.truncate(n);
            io::Result::Ok(answer)
        };
        let Ok(Ok(answer)) = tokio::time::timeout(RESOLVE_WAIT, asked).await else {
            continue;
        };
        if answer.get(..2) != query.get(..2) {
            continue;
        }
        let address = crate::dns::response(&answer)?
            .addresses
            .into_iter()
            .map(|(address, _)| address)
            .find(|address| packet::unicast(*address) && !address.is_loopback());
        if let Some(address) = address {
            return Some(SocketAddr::new(address, port));
        }
    }
    None
}

/// A recursive query for `name`'s records of `kind`, under a random ID.
fn query(name: &str, kind: u16) -> Option<Vec<u8>> {
    let mut id = [0u8; 2];
    getrandom_id(&mut id);
    let mut out = id.to_vec();
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        out.push(
            u8::try_from(label.len())
                .ok()
                .filter(|&n| (1..=63).contains(&n))?,
        );
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Some(out)
}

/// A query ID an attacker on the network would have to guess, beside the socket's random port: from the
/// keys of the standard library's hasher, which it takes from the operating system's randomness.
fn getrandom_id(id: &mut [u8; 2]) {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(0);
    let [a, b, ..] = hasher.finish().to_le_bytes();
    *id = [a, b];
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A core that counts what it is asked, and answers as told.
    struct Fake {
        timers: Arc<AtomicUsize>,
        session: bool,
        keepalive: bool,
        /// Whether its queue is full: every packet lost.
        full: bool,
    }

    impl Core for Fake {
        fn send(&mut self, _: &[u8]) -> Sent {
            if self.full {
                Sent::Dropped
            } else {
                Sent::Data(vec![4; 32])
            }
        }
        fn receive(&mut self, _: SocketAddr, _: &[u8]) -> Received {
            Received::Keepalive
        }
        fn timers(&mut self) -> Timers {
            self.timers.fetch_add(1, Ordering::Relaxed);
            Timers::Idle
        }
        fn keepalive(&mut self) -> Option<Vec<u8>> {
            None
        }
        fn handshake(&mut self) -> Option<Vec<u8>> {
            None
        }
        fn session_age(&self) -> Option<Duration> {
            self.session.then_some(Duration::from_secs(1))
        }
        fn keeps_alive(&self) -> bool {
            self.keepalive
        }
    }

    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PEER: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn configured(id: u32, allowed: &str, local_network: bool) -> Configured {
        let text = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.77.0.2/24\nDNS = 10.77.0.1\n[Peer]\nPublicKey = {PEER}\n\
             AllowedIPs = {allowed}\nEndpoint = 192.0.2.1:51820\n"
        );
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        Configured {
            id,
            config: Arc::new(config),
            local_network,
        }
    }

    fn fake(session: bool, keepalive: bool) -> (Tunnel, Arc<AtomicUsize>) {
        let timers = Arc::new(AtomicUsize::new(0));
        let core = Fake {
            timers: Arc::clone(&timers),
            session,
            keepalive,
            full: false,
        };
        (
            Tunnel::with_core(&configured(1, "0.0.0.0/0", false), Box::new(core), 1),
            timers,
        )
    }

    /// The core stamps every event with the time of its timers' last run: a packet after a pause of a
    /// second or more runs them first, one within the second does not (the spike's rule).
    #[test]
    fn a_packet_after_a_pause_runs_the_timers_first() {
        let shared = shared();
        let (mut tunnel, timers) = fake(true, false);
        tunnel.send(&[0x45; 20], &shared.counters);
        assert_eq!(timers.load(Ordering::Relaxed), 0, "within the second");
        tunnel.last_timers = Instant::now()
            .checked_sub(TICK)
            .unwrap_or_else(Instant::now);
        tunnel.send(&[0x45; 20], &shared.counters);
        assert_eq!(timers.load(Ordering::Relaxed), 1, "after the pause");
        tunnel.send(&[0x45; 20], &shared.counters);
        assert_eq!(timers.load(Ordering::Relaxed), 1, "and not again at once");
    }

    /// An idle tunnel, with no session, no handshake and no keepalive asked, costs no timer; each of the
    /// three makes it tick.
    #[test]
    fn only_a_session_a_handshake_or_keepalives_make_the_timers_tick() {
        let shared = shared();
        let (mut idle, _) = fake(false, false);
        assert!(!idle.ticks());
        assert!(fake(true, false).0.ticks());
        assert!(fake(false, true).0.ticks());
        idle.out(vec![1; 148], &shared.counters);
        assert!(idle.ticks(), "a handshake initiation went out");
        assert_eq!(idle.unanswered, 1);
        assert_eq!(shared.counters.snapshot()[59], 1, "counted as a handshake");
        idle.out(vec![1; 148], &shared.counters);
        assert!(idle.state(1, 0).not_answering, "two unanswered");
        // A data message is no handshake.
        let (mut data, _) = fake(false, false);
        data.out(vec![4; 32], &shared.counters);
        assert!(!data.ticks());
    }

    /// A packet the core's full queue drops is counted as lost, and still as handed to the tunnel.
    #[test]
    fn a_packet_the_cores_queue_drops_is_counted_lost() {
        let shared = shared();
        let core = Fake {
            timers: Arc::new(AtomicUsize::new(0)),
            session: false,
            keepalive: false,
            full: true,
        };
        let mut tunnel = Tunnel::with_core(&configured(1, "0.0.0.0/0", false), Box::new(core), 1);
        tunnel.send(&[0x45; 20], &shared.counters);
        let counters = shared.counters.snapshot();
        assert_eq!((counters[52], counters[58]), (1, 1));
        assert_eq!(tunnel.pending.len(), 0);
    }

    /// Datagrams made before the socket wait for it, a few at most; past that they are lost and counted.
    #[test]
    fn datagrams_before_the_socket_wait_within_a_bound() {
        let shared = shared();
        let (mut tunnel, _) = fake(true, false);
        for _ in 0..PENDING + 2 {
            tunnel.out(vec![4; 32], &shared.counters);
        }
        assert_eq!(tunnel.pending.len(), PENDING);
        assert_eq!(shared.counters.snapshot()[58], 2, "lost");
    }

    fn setting(tunnels: Vec<Configured>, routes: &[(u32, u32)], log: bool) -> TunnelSetting {
        TunnelSetting {
            tunnels,
            routes: routes.iter().copied().collect(),
            log_destinations: log,
        }
    }

    /// Each app's route: its tunnel; an app Android cannot name takes the default, the first set, while
    /// any app goes through one; with none, W6's rule stands.
    #[test]
    fn routes_follow_the_setting_and_no_ones_flows_take_the_default() {
        use super::super::chain::Route;
        let shared = shared();
        let web = SocketAddr::from(([93, 184, 216, 34], 443));
        let is = |route: Route, t: Option<u32>| match (route, t) {
            (Route::Tunnel(a), Some(b)) => a == b,
            (Route::Direct, None) => true,
            _ => false,
        };
        assert!(is(shared.route(None, web), None), "nothing set");
        shared.tunnels.set(
            &setting(
                vec![
                    configured(2, "0.0.0.0/0", false),
                    configured(1, "0.0.0.0/0", false),
                ],
                &[],
                false,
            ),
            &shared,
        );
        assert!(!shared.tunnels.any());
        assert!(
            is(shared.route(None, web), None),
            "tunnels, but no app through one"
        );
        shared.tunnels.set(
            &setting(
                vec![
                    configured(2, "0.0.0.0/0", false),
                    configured(1, "0.0.0.0/0", false),
                ],
                &[(10_300, 1), (10_301, 9)],
                false,
            ),
            &shared,
        );
        assert!(shared.tunnels.any());
        assert!(is(shared.route(Some(10_300), web), Some(1)));
        assert!(
            is(shared.route(Some(10_301), web), None),
            "a route to a tunnel not set is none"
        );
        assert!(is(shared.route(Some(10_400), web), None));
        assert!(
            is(shared.route(None, web), Some(2)),
            "the first set is the default"
        );
        // A stand-in is the tool's alone.
        assert!(matches!(
            shared.route(Some(10_300), SocketAddr::from(([198, 18, 0, 1], 443))),
            Route::Refused
        ));
        // Destinations stay out of the log unless the switch says otherwise.
        assert!(shared.hides(Some(10_300), web));
        assert!(!shared.hides(Some(10_400), web));
        shared.tunnels.set(
            &setting(
                vec![configured(1, "0.0.0.0/0", false)],
                &[(10_300, 1)],
                true,
            ),
            &shared,
        );
        assert!(!shared.hides(Some(10_300), web));
    }

    /// "Local network directly", per configuration and off by default: a tunnelled app's private,
    /// link-local, unique-local and multicast destinations go directly, but not the configuration's own
    /// network, its DNS server, or Watch's addresses.
    #[test]
    fn local_network_directly_lets_only_the_local_network_go_directly() {
        use super::super::chain::Route;
        let shared = shared();
        let direct = |shared: &Shared, ip: IpAddr| {
            matches!(
                shared.route(Some(10_300), SocketAddr::new(ip, 80)),
                Route::Direct
            )
        };
        shared.tunnels.set(
            &setting(
                vec![configured(1, "0.0.0.0/0, ::/0", false)],
                &[(10_300, 1)],
                false,
            ),
            &shared,
        );
        assert!(
            !direct(&shared, IpAddr::from([192, 168, 1, 10])),
            "off by default"
        );
        shared.tunnels.set(
            &setting(
                vec![configured(1, "0.0.0.0/0, ::/0", true)],
                &[(10_300, 1)],
                false,
            ),
            &shared,
        );
        for local in [
            IpAddr::from([192, 168, 1, 10]),
            IpAddr::from([172, 16, 0, 9]),
            IpAddr::from([169, 254, 1, 1]),
            IpAddr::from([224, 0, 0, 251]),
            IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
            IpAddr::from([0xfd12, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            assert!(direct(&shared, local), "{local}");
        }
        let at = shared.addresses;
        for tunnelled in [
            IpAddr::from([93, 184, 216, 34]),
            IpAddr::from([10, 77, 0, 1]),
            IpAddr::from([10, 77, 0, 200]),
            IpAddr::V4(at.dns4),
            IpAddr::V4(at.tun4),
            IpAddr::V6(at.dns6),
        ] {
            assert!(!direct(&shared, tunnelled), "{tunnelled}");
        }
        // A provider's DNS server at a private address outside the interface's own /32, as Proton's
        // 10.2.0.1 beside 10.2.0.2/32: through the tunnel still.
        let text = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n[Peer]\nPublicKey = {PEER}\n\
             AllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"
        );
        let Ok(proton) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        let proton = Configured {
            id: 1,
            config: Arc::new(proton),
            local_network: true,
        };
        shared
            .tunnels
            .set(&setting(vec![proton], &[(10_300, 1)], false), &shared);
        assert!(
            !direct(&shared, IpAddr::from([10, 2, 0, 1])),
            "its DNS server"
        );
        assert!(
            direct(&shared, IpAddr::from([10, 2, 0, 9])),
            "beside it, the local network"
        );
    }

    /// A new flow is admitted inside `AllowedIPs`, of a version the configuration has an address of; a
    /// lookup to Watch's DNS address goes to the configuration's server.
    #[test]
    fn a_flow_is_admitted_only_where_the_tunnel_carries_it() {
        let shared = shared();
        shared.tunnels.set(
            &setting(
                vec![configured(1, "10.77.0.0/24, 93.184.216.0/24", false)],
                &[(10_300, 1)],
                false,
            ),
            &shared,
        );
        let app = SocketAddr::from((shared.addresses.tun4, 40_000));
        let admitted = shared.tunnels.admit(
            1,
            app,
            SocketAddr::from(([93, 184, 216, 34], 443)),
            &shared,
            true,
        );
        assert_eq!(
            admitted,
            Some((
                SocketAddr::from(([10, 77, 0, 2], 40_000)),
                SocketAddr::from(([93, 184, 216, 34], 443))
            ))
        );
        assert_eq!(
            shared
                .tunnels
                .admit(1, app, SocketAddr::from(([1, 1, 1, 1], 443)), &shared, true),
            None,
            "outside"
        );
        let app6 = SocketAddr::from((shared.addresses.tun6, 40_000));
        let six = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443));
        assert_eq!(
            shared.tunnels.admit(1, app6, six, &shared, true),
            None,
            "no IPv6 address"
        );
        let dns = SocketAddr::from((shared.addresses.dns4, 53));
        assert_eq!(
            shared
                .tunnels
                .admit(1, app, dns, &shared, true)
                .map(|(_, to)| to),
            Some(SocketAddr::from(([10, 77, 0, 1], 53)))
        );
        // A lookup to Watch's IPv6 DNS address reaches the IPv4 server, rebuilt; a TCP one cannot.
        let dns6 = SocketAddr::from((shared.addresses.dns6, 53));
        assert!(
            shared
                .tunnels
                .admit(1, app6, dns6, &shared, false)
                .is_some()
        );
        assert!(shared.tunnels.admit(1, app6, dns6, &shared, true).is_none());
        assert_eq!(
            shared.tunnels.admit(2, app, dns, &shared, true),
            None,
            "no such tunnel"
        );
    }

    /// A tunnel set again with the same configuration keeps its session; one set anew loses it, and its
    /// flows end.
    #[test]
    fn a_tunnel_set_again_unchanged_keeps_its_core() {
        let shared = shared();
        let first = configured(1, "0.0.0.0/0", false);
        shared.tunnels.set(
            &setting(vec![first.clone()], &[(10_300, 1)], false),
            &shared,
        );
        let generation = |shared: &Shared| {
            lock(&shared.tunnels.table)
                .tunnels
                .get(&1)
                .map(|t| t.generation)
        };
        let before = generation(&shared);
        shared
            .tunnels
            .set(&setting(vec![first], &[(10_300, 1)], false), &shared);
        assert_eq!(generation(&shared), before, "kept");
        shared.tunnels.set(
            &setting(
                vec![configured(1, "10.0.0.0/8", false)],
                &[(10_300, 1)],
                false,
            ),
            &shared,
        );
        assert_ne!(generation(&shared), before, "set anew");
        shared
            .tunnels
            .set(&setting(vec![], &[(10_300, 1)], false), &shared);
        assert!(!shared.tunnels.any(), "a route to a tunnel gone is none");
    }

    #[test]
    fn the_query_for_an_endpoint_is_a_recursive_one_for_its_name() {
        let Some(asked) = query("nl-free-1.example.net", crate::answers::A) else {
            unreachable!("no query")
        };
        assert_eq!(&asked[2..12], &[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        let Some(question) = crate::answers::question(&asked) else {
            unreachable!("unread")
        };
        assert_eq!(question.name, "nl-free-1.example.net");
        assert_eq!(question.kind, crate::answers::A);
        assert!(query("bad..name", crate::answers::A).is_none());
    }

    #[test]
    fn the_local_network_is_what_its_ranges_say() {
        assert!(is_local(IpAddr::from([10, 0, 0, 1])));
        assert!(is_local(IpAddr::from([192, 168, 0, 1])));
        assert!(
            !is_local(IpAddr::from([100, 64, 0, 1])),
            "carrier-grade NAT is not the local network"
        );
        assert!(!is_local(IpAddr::from([8, 8, 8, 8])));
        assert!(!is_local(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])));
    }
}
