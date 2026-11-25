//! The forwarder (ADR 0012): Android's own TCP stack terminates every app's connection, reached by
//! rewriting addresses, and the engine relays each one over a protected socket of its own to the
//! real destination. UDP is relayed in userspace, each destination a flow of its own in the log.
//!
//! A TCP packet from an app to `D:dp` is rewritten to come from the fake peer `FAKE:fp` and go to the
//! engine's listener on the tunnel's address. Android's TCP stack answers it, and the answer is
//! rewritten back to come from `D:dp`. The listener accepts the connection as if from `FAKE:fp`, the
//! table maps that to `D:dp`, and the engine connects there. The network part must be inside its own tunnel for
//! this, and protects each socket of its own (spike, finding 6).
//!
//! The app's first SYN is held until Android has named the app and the real server has accepted, so
//! that a connection closed at once still has an owner, and a refused or unreachable server looks so
//! to the app: it gets a reset or an ICMP error, as without a VPN.
//!
//! UDP leaves through one mapping for each app socket, whatever the destination (ADR 0044): on the
//! direct path one protected socket, through the user's tool one `UDP ASSOCIATE`. Either lets in only
//! what comes from addresses the app sent to.
//!
//! An app's ping leaves through a protected ping socket of the engine's own, and is refused while a
//! chain is on, since Android cannot name its app (ADR 0044, decision 5).
//!
//! The apps' fragments are put together again, and the "fragmentation needed" and "packet too big"
//! that routers beyond the first hop send the engine's sockets reach the apps, with their MTU. The
//! engine answers nothing as too large on its own: the tunnel's MTU is the first hop's, which the network part's
//! Kotlin side reads and sets, so the apps' own kernels meet it as they would without the network part (proposal for
//! decision 5 of 2026-11-15).
//!
//! The network part is not a hop (unit 11b): an app's datagram on the direct path and its ping leave with the
//! app's own hop limit, what comes back reaches the app with the hop limit it arrived with, and the
//! errors the path sends, a router's "time exceeded" and "destination unreachable" among them, reach
//! the app from the router or host that sent them, so that a traceroute through the network part sees the path.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc, watch};

use crate::dnscache::DnsCache;
use crate::fragments::{self, Reassembler, Taken};
use crate::log::Record;
use crate::messengers::Messengers;
use crate::names::Names;
use crate::nat::{self, Nat};
#[cfg(test)]
use crate::nat::{Listener, Lookup};
use crate::organisations::Organisations;
use crate::owners::{NetworkKind, Owners};
use crate::packet::{self, Skip, TCP};
use crate::resolvers::Resolvers;
use crate::standins::StandIns;
#[cfg(test)]
use crate::tls::Hello;
use crate::tun::Tun;

mod activity;
mod blocks;
mod budget;
mod chain;
mod clock;
mod echo;
mod errors;
mod hops;
mod kept;
mod logbook;
mod lookups;
#[cfg(test)]
mod model;
mod naming;
mod now;
pub mod resolver;
use resolver::{DnsConfig, Exchange, Exchanges};
mod proxied;
mod tcp;
mod tunnels;
mod udp;
mod upstream;
mod whose;

pub use blocks::{BlockSetting, Tally};
use budget::Budget;
pub use chain::Chain;
pub use clock::{Clock, SystemClock};
use echo::Echoes;
use logbook::{FlowBytes, Live, Lookups, logger};
#[cfg(test)]
use naming::Begun;
pub use proxied::{MAX_TRACKERS, Proxied, ProxySetting};
use tcp::{Listening, Pending, listen};
#[cfg(test)]
use tcp::{Upstream, accept};
pub use tunnels::{ASK_BOUND, AppRoute, Configured, MAX_TUNNELS, TunnelSetting, TunnelState};
use udp::UdpFlows;

/// The tunnel's addresses (ADR 0041, decision 3): its own address, a /32 or a /128 (ADR 0034: a wider
/// prefix would count as local network on Android 17), the fake peer the kernel sees for every rewritten
/// connection, outside it, and the DNS server Android is given inside the tunnel, whose queries the engine
/// passes on to the network's resolver. Any app can read the tunnel's address and prefix, so the network part takes
/// the ones other apps use and is not singled out by them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addresses {
    /// The tunnel's IPv4 address, a /32.
    pub tun4: Ipv4Addr,
    /// The IPv4 fake peer.
    pub fake4: Ipv4Addr,
    /// The IPv4 DNS server inside the tunnel.
    pub dns4: Ipv4Addr,
    /// The tunnel's IPv6 address, a /128.
    pub tun6: Ipv6Addr,
    /// The IPv6 fake peer.
    pub fake6: Ipv6Addr,
    /// The IPv6 DNS server inside the tunnel.
    pub dns6: Ipv6Addr,
}

impl Addresses {
    /// The tunnel addresses of `NetGuard`, `TrackerControl` and `InviZible` Pro, with the same /32 and /128:
    /// an app that reads them finds a local firewall, the kind of app the network part is, not the network part itself.
    /// Read from 32 apps' own source on 2026-11-12; the largest other group, 172.19.0.1, is that of proxy and
    /// circumvention clients, and its /30 does not fit Android 17.
    pub const COMMON: Self = Self {
        tun4: Ipv4Addr::new(10, 1, 10, 1),
        fake4: Ipv4Addr::new(10, 1, 10, 2),
        dns4: Ipv4Addr::new(10, 1, 10, 3),
        tun6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 1),
        fake6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 2),
        dns6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 3),
    };

    /// The network part's earlier addresses, for a network that uses the common ones itself: Comcast Business
    /// gateways answer at 10.1.10.1, and a tunnel that takes the router's address cuts the phone off
    /// from it. The network part picks this set when the network beneath clashes with [`Addresses::COMMON`].
    pub const SPARE: Self = Self {
        tun4: Ipv4Addr::new(10, 215, 173, 1),
        fake4: Ipv4Addr::new(10, 215, 173, 2),
        dns4: Ipv4Addr::new(10, 215, 173, 3),
        tun6: Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 1),
        fake6: Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 2),
        dns6: Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 3),
    };

    /// Whether `address` is the tunnel's own DNS address, which leads to the network's resolver.
    #[must_use]
    pub fn is_dns(&self, address: IpAddr) -> bool {
        address == IpAddr::V4(self.dns4) || address == IpAddr::V6(self.dns6)
    }
}

/// The most packets read after one wake-up before the engine waits again.
const BATCH: usize = 64;

/// How long the engine waits and keeps things, and which fake ports it hands out. The defaults are the
/// product's. Tests pass smaller ones, so that timing can be driven in seconds (review finding 21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// A UDP mapping with no datagram either way for this long ends (RFC 4787, REQ-5 and REQ-6), and
    /// so does a peer of a mapping silent as long, or a chained app's flow with no answer as long.
    pub udp_idle: Duration,
    /// At most this many datagrams to a new UDP destination wait for its way; more are dropped, as by
    /// a full queue. A lookup sends one, a QUIC handshake two or three.
    pub udp_waiting: usize,
    /// A UDP mapping's datagram to a destination it knows, or a lookup on a flow of lookups, asks Android
    /// again whose socket sent it when the app was silent this long, or when Android last named the app
    /// thirty times this long ago: Android may have handed the port to another app, which the log must
    /// name, and which the chain may send another way. Linux hands out a free port at random among about
    /// 28,000, so a port rarely comes back to another app within a second of its last datagram. An app
    /// that sends more often (calls, games, streams) is asked about every thirty seconds; one that pauses
    /// costs one question to Android, off the event loop, which holds that datagram for as long as the
    /// question takes: about 3 ms on the Galaxy A40, 11 ms in deep idle (the engine spike, 2026-11).
    pub udp_reask: Duration,
    /// For this long after the app first sends to a stand-in through the tool, while it waits for its
    /// first answer, an answer from an address another stand-in of the mapping was bound to, on that
    /// port, could be its own: it is dropped rather than given to the other name. After that, such
    /// answers go to the name bound to their address again, so that one unanswered name beside a
    /// working one on the same port cuts the working one for this long, not for as long as the app
    /// retries. A first answer through a tool comes within about a second; five leave room for a slow
    /// one. The stand-in still waits, as long as it lives, for a first answer from an address no other
    /// stand-in was bound to.
    pub udp_contest: Duration,
    /// How long a connection to a server, or a tool's handshake, may take before the app is told the
    /// server is unreachable.
    pub connect_timeout: Duration,
    /// How long a closed connection's rewriting stays, for the last FIN and ACK packets.
    pub close_linger: Duration,
    /// Stale TCP connections are swept at most this often, and only when packets come anyway: an idle
    /// tunnel must not wake the phone.
    pub sweep_every: Duration,
    /// A connection Android's stack never handed to the relay, silent this long, is forgotten
    /// ([`nat::TCP_IDLE`]).
    pub tcp_idle: Duration,
    /// A freed fake port is not handed out again for this long ([`nat::PORT_COOLING`]).
    pub port_cooling: Duration,
    /// At most this many TCP connections wait for their server at once, for every app together (ADR
    /// 0044, decision 3). A SYN beyond it is dropped, as by a full queue, and the app's stack sends it
    /// again; each waiting connection holds a socket and a fake port for up to `connect_timeout`.
    pub tcp_waiting: usize,
    /// At most this many of them are one app's, once Android has named it, or are of apps Android
    /// cannot name, which share one share: a quarter of `tcp_waiting`, at least 32. A SYN beyond it is
    /// dropped too, and its port freed.
    pub tcp_share: usize,
    /// At most this many UDP ways that hold a socket of their own are open at once, for every app
    /// together: mappings, on the direct path or through the tool, and flows of lookups to the
    /// tunnel's DNS address on the direct path (ADR 0044, decision 3). A new one beyond it makes room by
    /// ending a mapping, or its datagrams are dropped.
    pub udp_mappings: usize,
    /// At most this many of them are one app's, or of apps Android cannot name, which share one share:
    /// a quarter of `udp_mappings`, at least 64. An app at its share makes room among its own.
    pub udp_share: usize,
    /// A mapping that passed a datagram either way less than this long ago is never ended to make room,
    /// so that a call is never cut, unless it is an answered lookup, which carries nothing more.
    pub udp_quiet: Duration,
    /// At most this many associations of a stand-in's own are open at once, for every app together (ADR
    /// 0044, unit 9b): through the tool, each holds a socket and a connection to the tool, and a place
    /// in its app's share. They are for the rare app that asks several names at once on one port in a
    /// protocol without identifiers; beyond the cap, such a stand-in waits beside the others under unit
    /// 9's floor.
    pub udp_own_relays: usize,
    /// At most this many of them are one app's, or of apps Android cannot name, which share one share:
    /// a quarter of `udp_own_relays`, as decision 3 shares its caps (unit 9b, fix round 5, review I's
    /// I8: one app could hold them all, and every other app's stand-ins fell to unit 9's floor).
    pub udp_own_share: usize,
    /// At most this many names hold a stand-in at once (ADR 0038, [`crate::standins::CAPACITY`]); the
    /// least recently used gives way to a new one. The tests hold fewer.
    pub stand_ins: usize,
    /// At most this many ping sockets are open at once, for every app together (ADR 0044, decision
    /// 5): one for each app address, echo identifier and destination. A request that needs one more is
    /// dropped. Each holds a descriptor of its own, beside the budget of decision 3, so the decision
    /// caps them at 32.
    pub echo_sockets: usize,
    /// A ping socket through which no echo passed either way for this long ends. A ping sends a
    /// request every second, so a socket silent this long belongs to one that has stopped; an app that
    /// pings again later gets a socket anew.
    pub echo_idle: Duration,
    /// At the cap of ping sockets, one that has waited this long for an answer to its requests, with
    /// none coming meanwhile, may end to make room for a new one (ADR 0044, unit 11b): its target is
    /// silent, or its replies lost, even while its app sends on. Its app's next request, if any, gets a
    /// socket anew.
    pub echo_quiet: Duration,
    /// At the cap of ping sockets, one whose every request has had its reply or error, and through
    /// which nothing passed for longer than this, ends first to make room for a new one (ADR 0044, unit
    /// 11b, third round): a ping sends a request every second, so one still pinging sends its next
    /// before this, while a one-shot ping's socket, as a traceroute app leaves for each probe, never
    /// sends again.
    pub echo_interval: Duration,
    /// At most this many datagrams are put together from the apps' fragments at once (ADR 0044,
    /// the proposal for decision 5): for a fragment of one more, the oldest incomplete one gives way.
    pub fragment_datagrams: usize,
    /// At most this many bytes of fragments are held across them ([`crate::fragments::Bounds`]); past
    /// it, the oldest incomplete datagrams give way too.
    pub fragment_bytes: usize,
    /// A datagram whose last fragment has not come this long after its first is dropped. A sender
    /// sends a datagram's fragments one after another, within milliseconds.
    pub fragment_wait: Duration,
    /// A write to the tunnel that the tunnel refuses waits this long, off the event loop, for the
    /// tunnel set up again to take its place, and goes there (ADR 0044, unit 12b): Android resets the
    /// old interface before the network part hands the engine the new one, and a tun device whose interface is
    /// down refuses writes. The network part's Kotlin side hands it over as soon as `establish()` returns, within
    /// milliseconds; without a new tunnel by then, the packet is dropped, as before.
    pub tunnel_wait: Duration,
    /// The first of the fake ports handed out, `first_port..=last_port`.
    pub first_port: u16,
    /// The last of them.
    pub last_port: u16,
}

impl Limits {
    /// The product's limits for a process that may open `descriptors` files (its soft limit): a
    /// reserve of a sixteenth, at least 128, stays for the network part itself; waiting TCP connections may use an
    /// eighth of the rest, at most 4,096, and UDP mappings a quarter. Each app may use a quarter of
    /// each cap, at least 32 waiting connections and 64 mappings, and never more than the cap.
    #[must_use]
    pub fn for_descriptors(descriptors: usize) -> Self {
        let budget = descriptors.saturating_sub((descriptors / 16).max(128));
        let share = |cap: usize, floor: usize| (cap / 4).max(floor).min(cap);
        let tcp_waiting = (budget / 8).clamp(1, 4_096);
        let udp_mappings = (budget / 4).max(1);
        Self {
            tcp_waiting,
            tcp_share: share(tcp_waiting, 32),
            udp_mappings,
            udp_share: share(udp_mappings, 64),
            ..Self::default()
        }
    }

    /// The product's limits for this process, from its soft limit on open files in
    /// `/proc/self/limits`, or 1,024 where that cannot be read.
    #[must_use]
    pub fn for_this_process() -> Self {
        Self::for_descriptors(descriptor_limit().unwrap_or(1_024))
    }
}

/// The soft limit on open files, from `/proc/self/limits` ("Max open files  SOFT  HARD  files").
fn descriptor_limit() -> Option<usize> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

impl Default for Limits {
    /// Today's timings, with the caps of a process that may open 1,024 files.
    fn default() -> Self {
        Self {
            tcp_waiting: 112,
            tcp_share: 32,
            udp_mappings: 224,
            udp_share: 64,
            udp_quiet: Duration::from_secs(5),
            udp_idle: Duration::from_secs(120),
            udp_waiting: 32,
            udp_reask: Duration::from_secs(1),
            udp_contest: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(60),
            close_linger: Duration::from_secs(30),
            sweep_every: Duration::from_secs(60),
            tcp_idle: nat::TCP_IDLE,
            port_cooling: nat::PORT_COOLING,
            udp_own_relays: 32,
            udp_own_share: 8,
            stand_ins: crate::standins::CAPACITY,
            echo_sockets: 32,
            echo_idle: Duration::from_secs(10),
            echo_quiet: Duration::from_secs(2),
            echo_interval: Duration::from_millis(1_200),
            fragment_datagrams: 64,
            fragment_bytes: 1 << 20,
            fragment_wait: Duration::from_secs(5),
            tunnel_wait: Duration::from_millis(200),
            first_port: nat::FIRST_PORT,
            last_port: nat::LAST_PORT,
        }
    }
}
/// How long finished records gather before they go to the network part's log together (ADR 0037).
const LOG_DELAY: Duration = Duration::from_secs(30);

/// What the engine asks of Android, through the network part's Kotlin side, and the clock it reads.
pub trait Platform: Send + Sync + 'static {
    /// `ConnectivityManager.getConnectionOwnerUid`: the UID of the app with a socket from `local` to
    /// `remote`, or `None` when Android does not know.
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32>;

    /// `VpnService.protect`: keeps one of the engine's sockets out of the tunnel.
    fn protect(&self, fd: RawFd) -> bool;

    /// Hands a batch of records to the network part's connection log ([`crate::log::batch`]).
    fn log(&self, batch: &[u8]);

    /// The clock the engine reads for the log's times ([`Clock`]): the phone's own, unless a test hands
    /// in one it moves.
    fn clock(&self) -> Arc<dyn Clock> {
        Arc::new(SystemClock)
    }

    /// Whether the network part's Kotlin side tells the engine the apps' states ([`Engine::states`], ADR 0046,
    /// decision 1): then each second's bytes wait for their app's state, and the log's segments are cut
    /// where it changes. Without it, every segment is written at once in no state.
    fn tells_states(&self) -> bool {
        false
    }

    /// The engine would have the apps' states read: a flow opened, or bytes have waited for their state
    /// for five seconds. The network part's Kotlin side reads when its own rules allow (ADR 0046, decision 1), off
    /// the engine's thread: this must not block.
    fn wants_states(&self) {}

    /// The addresses of a `WireGuard` endpoint's host name (W7), from Android's own resolver on the network
    /// beneath the tunnel, which uses the user's Private DNS where it is on, and whether it did so encrypted
    /// (the maintainer's answer 4, 2026-11-19); called off the event loop. `None` where the platform has
    /// no resolver to offer: the engine then asks the network's resolver itself, over plain DNS.
    fn resolve(&self, _name: &str) -> Option<Resolution> {
        None
    }

    /// Where the app `uid` goes, which the network part did not name when it last handed its routes over
    /// ([`TunnelSetting::known`]): an app installed since, one installed again with a new UID among them. The network
    /// part reads the UID's packages from Android and answers the route its store gives them. Called off the event
    /// loop, on a thread of its own, at a held SYN or first datagram, which waits for it at most [`ASK_BOUND`];
    /// `None` where it cannot say, and the flow is refused, never sent directly (the maintainer, 2026-11-20).
    fn route_of_app(&self, _uid: u32) -> Option<AppRoute> {
        None
    }

    /// Carries the exchange `request` of the encrypted resolver (W8, part 1): over Android's own TLS, from a
    /// socket the network part protects and binds to the network beneath or through the user's tool, or by Android's
    /// resolver on the network beneath. Returns at once, from the engine's own thread, without blocking; the
    /// reply comes later, by [`Engine::exchanged`] with `ticket`. False where the platform carries none: then
    /// the network's resolver is asked from a protected socket, and no encrypted way answers.
    fn exchange(&self, _ticket: u64, _request: &Exchange) -> bool {
        false
    }

    /// The way direct apps' names go changed kind: an encrypted way, the fallback to the network's resolver,
    /// or failing in the strict setting ([`Engine::dns_status`]). Returns at once; the network screen and its
    /// notice read the state when they want it.
    fn dns_changed(&self) {}
}

/// What Android's resolver said of a host name ([`Platform::resolve`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// Its addresses, in the resolver's order; empty where the name does not resolve.
    pub addresses: Vec<IpAddr>,
    /// Whether the question went over encrypted DNS (Private DNS active on that network).
    pub encrypted: bool,
}

/// How a flow went, for the counters and the flows kept for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Connected (TCP) or sent (UDP).
    Opened,
    /// The server refused the connection: the app got a reset.
    Refused,
    /// No route, or no answer in time: the app got an ICMP error.
    Unreachable,
    /// The engine could not make or protect a socket.
    Failed,
    /// Tracker blocking refused it (W8, part 3a; ADR 0053): the app got a reset, or for QUIC an ICMP "port
    /// unreachable", and no byte of its payload went upstream.
    Blocked,
}

/// Where a flow's name came from. W3's order, written here and only here ([`NamedBy::yields_to`]): the
/// server name the connection itself sent, in its TLS or QUIC hello; then a DNS answer the network part passed to
/// the app for the destination's address; then the organisation of the address's network; then none.
///
/// The connection's own name comes first: the engine read it from the flow itself, while a DNS answer
/// is tied to the flow by its address alone, and on an address that serves many names another app's
/// lookup may have named it last (finding 20 of the independent review of 2026-11-09; ADR 0044, decision
/// 4). Either can be wrong, the connection's own when an app sends a front, so a DNS name it differs
/// from stays beside it ([`Flow::dns_name`]), while it is current: a stand-in's, tied to its address
/// alone, always; an answer's while the answer that named the flow is held in time since the phone
/// started, so that a name kept through a night does not show its age as a difference, while a later
/// answer for the address does not end it ([`Opened::dns_held_until`]). A stand-in's flow is named by its hello
/// too, one rule for every flow: the hello says which server the app spoke to at the address the tool
/// reached. A hello's name that is the public name of an ECH configuration the network part saw, in Android's
/// resolver's answers or the app's own, never names a flow ([`Ech::Hidden`]): a DNS name stays the
/// flow's then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedBy {
    /// The server name of the TLS connection.
    Tls,
    /// The server name of the QUIC connection's Initial packets.
    Quic,
    /// The destination the app asked its proxy for, read from the connection (W8, part 2a; ADR 0052): after
    /// the hello's name, which the connection inside the proxy's tunnel sends, and before a DNS answer for
    /// the proxy's address, which names the proxy, not the destination.
    Proxy,
    /// A DNS answer the network part passed to the app for the destination's address.
    Dns,
    /// The organisation whose network the address is in, from the offline table (ADR 0036).
    Organisation,
    /// Not named.
    Unknown,
}

impl NamedBy {
    /// Whether a name from this source gives way to one from `other`, by W3's order. TLS and QUIC share
    /// a place: a flow is one or the other, and keeps the name of its first hello.
    fn yields_to(self, other: Self) -> bool {
        let rank = |by: Self| match by {
            Self::Tls | Self::Quic => 0,
            Self::Proxy => 1,
            Self::Dns => 2,
            Self::Organisation => 3,
            Self::Unknown => 4,
        };
        rank(other) < rank(self)
    }
}

/// What the app's TLS or QUIC hello said about Encrypted Client Hello (ECH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ech {
    /// No ECH, or no hello read.
    Absent,
    /// ECH offered: a real one, or GREASE, which look the same by design. The server name in the hello
    /// names the flow.
    Offered,
    /// The hello's server name is the public name of an ECH configuration in a DNS answer the network part passed
    /// on: the real name is hidden, and the public name does not name the flow.
    Hidden,
}

/// Whether a flow carries an app's own DNS, past the network part's resolver (W3, ADR 0045, decision 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsUse {
    /// Not DNS, as far as the network part can tell, or the phone's own lookups through the network part's resolver.
    None,
    /// Plain DNS on port 53 to another server than the network part's: around the phone's DNS settings.
    Plain,
    /// DNS over TLS or QUIC (port 853), or DNS over HTTPS to a known resolver.
    Encrypted,
}

/// A flow the engine opened for an app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    /// A number of its own, counting from 1 since the engine started.
    pub id: u64,
    /// [`TCP`] or [`UDP`].
    pub protocol: u8,
    /// The app's end inside the tunnel.
    pub app: SocketAddr,
    /// Where the app sent it.
    pub destination: SocketAddr,
    /// The app's UID, if Android named it.
    pub uid: Option<u32>,
    /// How it went.
    pub outcome: Outcome,
    /// The destination's name, if the network part knows it.
    pub name: Option<String>,
    /// Where the name came from.
    pub named_by: NamedBy,
    /// The name a DNS answer gave the destination's address, where the connection's own name, which
    /// names the flow ([`NamedBy`]), differs from it: kept beside it, since either can be wrong.
    pub dns_name: Option<String>,
    /// Whether the flow came in: datagrams from another port of an address the app had sent to, which
    /// the app did not send to first (ADR 0044, decision 1).
    pub came_in: bool,
    /// Whether the hello hid the real name.
    pub ech: Ech,
    /// Whether the flow carries the app's own DNS.
    pub dns: DnsUse,
    /// The known resolver it goes to (`data/resolvers`), if it is one.
    pub resolver: Option<String>,
    /// The network of its address, when the organisation table named it.
    pub network: Option<Network>,
    /// The way it went: directly, through the user's tool, or through one `WireGuard` configuration.
    pub via: Via,
    /// The proxy the app reached it through, read from the connection or inferred (W8, part 2a; ADR 0052).
    pub proxy: Option<Box<Proxied>>,
    /// For a flow tracker blocking refused ([`Outcome::Blocked`]), the SDK of the graded table's row that blocked
    /// it, its Maven coordinate, which the log keeps whatever "Log where these apps connect" says, as it names
    /// a tracker and never a host (ADR 0053, decision 8).
    pub blocked: Option<Box<BlockedBy>>,
}

/// The graded table's row that blocked a flow (W8, part 3a; ADR 0053): its SDK's Maven coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedBy {
    /// The SDK, `group:artifact`.
    pub sdk: String,
}

/// The way a flow went (W6, W7): its route when it opened, which the log's records and the live view say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Via {
    /// Out on the network beneath, from a protected socket.
    #[default]
    Direct,
    /// Through the user's circumvention tool (W6).
    Tool,
    /// Through the `WireGuard` configuration of this number (W7, ADR 0035).
    Tunnel(u32),
}

/// The network a flow's address is in, when the organisation table named the flow (ADR 0036).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    /// Its AS number.
    pub asn: u32,
    /// Whether its owner is a known company, and whether that company hosts others' servers.
    pub kind: NetworkKind,
}

/// What the engine knew of a flow when it opened, for what the flow's hello may add.
#[derive(Clone, Copy, Debug)]
struct Opened {
    id: u64,
    port: u16,
    /// Where the app sent it.
    destination: SocketAddr,
    /// Whether its first bytes are read for a proxy (W8, part 2a): it went directly, and is not the user's
    /// tool's own (ADR 0046, decision 3).
    sniffs: bool,
    dns: DnsUse,
    /// The app's UID, if Android named it: whose ECH public names hide the hello's name.
    uid: Option<u32>,
    /// Until when, in time since the phone started, the answer that gave the flow its DNS name is held:
    /// while it is, that name stands beside a differing name its hello sends. The longest time there is
    /// for a stand-in's name, which names its address alone; nought for no DNS name.
    dns_held_until: Duration,
}

/// The engine's settings.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The tunnel's MTU, as given to `Builder.setMtu`.
    pub mtu: u16,
    /// How many of the latest flows to keep in memory for the network part's debug builds and tests; 0 keeps
    /// none. Release builds keep none: the connection log (W4) decides what is recorded.
    pub keep_flows: usize,
    /// The tunnel's addresses, as given to `Builder.addAddress` and `addDnsServer`.
    pub addresses: Addresses,
    /// How long the engine waits and keeps things; the product uses [`Limits::default`].
    pub limits: Limits,
}

/// How many counters [`Counters::snapshot`] gives.
pub const COUNTERS: usize = 71;

/// The counters, in the order of [`Counters::snapshot`].
#[derive(Debug, Default)]
pub struct Counters {
    tcp_flows: AtomicU64,
    udp_flows: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    owner_unknown: AtomicU64,
    refused: AtomicU64,
    unreachable: AtomicU64,
    failed: AtomicU64,
    skipped: AtomicU64,
    packets_in: AtomicU64,
    packets_out: AtomicU64,
    tls_names: AtomicU64,
    quic_names: AtomicU64,
    quic_unread: AtomicU64,
    ech_offered: AtomicU64,
    ech_hidden: AtomicU64,
    dns_plain: AtomicU64,
    dns_encrypted: AtomicU64,
    strangers: AtomicU64,
    fragments: AtomicU64,
    hellos_on_dns_names: AtomicU64,
    hello_names_differ: AtomicU64,
    resets: AtomicU64,
    tcp_refused: AtomicU64,
    udp_mappings: AtomicU64,
    udp_filtered: AtomicU64,
    udp_unmatched: AtomicU64,
    udp_came_in_capped: AtomicU64,
    udp_relay_elsewhere: AtomicU64,
    udp_ambiguous: AtomicU64,
    udp_late: AtomicU64,
    udp_refused: AtomicU64,
    udp_evicted: AtomicU64,
    echo_carried: AtomicU64,
    echo_replies: AtomicU64,
    echo_refused: AtomicU64,
    echo_unsupported: AtomicU64,
    echo_dropped: AtomicU64,
    reassembled: AtomicU64,
    too_big: AtomicU64,
    path_mtu: AtomicU64,
    time_exceeded: AtomicU64,
    path_unreachable: AtomicU64,
    echo_errors: AtomicU64,
    errors_dropped: AtomicU64,
    echo_evicted: AtomicU64,
    listener_recoveries: AtomicU64,
    udp_identified: AtomicU64,
    udp_unidentified: AtomicU64,
    udp_own_relays: AtomicU64,
    udp_own_refused: AtomicU64,
    told_late: AtomicU64,
    tunnel_up: AtomicU64,
    tunnel_down: AtomicU64,
    tunnel_filtered: AtomicU64,
    tunnel_unmatched: AtomicU64,
    tunnel_refused: AtomicU64,
    tunnel_too_big: AtomicU64,
    tunnel_lost: AtomicU64,
    tunnel_handshakes: AtomicU64,
    tunnel_rejected: AtomicU64,
    proxies_declared: AtomicU64,
    proxy_passwords: AtomicU64,
    proxies_inferred: AtomicU64,
    proxies_substituted: AtomicU64,
    proxies_taken_back: AtomicU64,
    covers_kept_out: AtomicU64,
    blocked_lookups: AtomicU64,
    blocked_connections: AtomicU64,
    blocked_addresses: AtomicU64,
    blocking_holds: AtomicU64,
}

impl Counters {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// Takes back `n` counted before, as a mark a flow loses; never below nought.
    fn take_back(counter: &AtomicU64, n: u64) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(n))
        });
    }

    /// TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused, unreachable,
    /// failed, packets skipped, packets in, packets out, server names read from TLS and from QUIC, QUIC
    /// flows whose name could not be read, hellos that offered ECH, hellos whose name was an ECH public
    /// name, flows of an app's own plain and encrypted DNS, connections to the engine's listener that
    /// did not come from the fake address, refused, the apps' IP fragments dropped (counted apart from
    /// the other skipped packets, review finding 21; since ADR 0044's unit 12, those the reassembler
    /// dropped: past a bound, overlapping, malformed, of a protocol the engine does not carry, or held by
    /// a datagram it gave up), and hellos read on flows a DNS answer had named, and of
    /// those, how many named another server (finding 20: how often a shared address gives a flow the
    /// wrong name), relayed connections that ended in an error and were reset on both sides (finding
    /// 21), SYNs dropped because as many connections as allowed were waiting for their servers, for
    /// every app together or for their app (finding 18), UDP mappings opened (finding 19: one for each
    /// app socket, on the direct path or through the tool), datagrams a mapping dropped because they
    /// came from an address its app had not sent to, and answers from the tool's relay that a mapping
    /// dropped because no one destination of its app could be told for them (ADR 0044, decision 2: a
    /// header that is not well formed, a fragment, or a port several stand-ins wait on), datagrams from
    /// another port of an address the app sent to that a mapping dropped because as many such ports had
    /// come in as it lets in, and relays a tool offered for UDP elsewhere than on the phone or at its
    /// proxy's own address, which the network part refused, and datagrams and lookups dropped because who sent
    /// them could not be told: the answers of Android's near them named different apps, and those
    /// dropped because they came too late for their app, which lost the socket before their way opened,
    /// or for any answer near them (ADR 0044, unit 9, "Whose a datagram is"), and datagrams and lookups
    /// dropped because their app's UDP way could have no socket: the cap for every app, or their app's
    /// share, was full (ADR 0044, decision 3), and UDP mappings ended to make room for a new way; then,
    /// for ICMP echo (decision 5), the apps' echo requests sent on to their destination, the echo
    /// replies handed to the apps, the requests refused with "administratively prohibited" because a
    /// chain was on, or because they went to a stand-in address, which only the tool reaches, the
    /// requests dropped because the kernel refused the engine's ping sockets of their IP version at its
    /// start, and those dropped because no ping socket could carry them: the cap was full, too many
    /// waited for their socket, or it could not be made, protected or sent on; then (decision 5 as
    /// amended) the datagrams put together from the apps' fragments, the datagrams the engine's kernel
    /// refused to send as too long (`EMSGSIZE`), which are dropped, and the "fragmentation needed" and
    /// "packet too big" routers sent the engine's sockets, passed on to the apps, for datagrams and,
    /// since unit 11b, echo requests; then (unit 11b) the "time exceeded" routers sent for them, passed
    /// on, the "destination unreachable" of every code routers or hosts sent for them, passed on, how
    /// many of the errors passed on, of those three kinds, answered echo requests, and the errors from
    /// the path dropped because they answered nothing the app sent that left: a destination its mapping
    /// or ping socket never sent to, a request it never sent, or a datagram or request the app was
    /// already told of once; or because no error to the app could be built for them; and the ping
    /// sockets ended at the cap to make room for a new one; then (unit 12b) the errors the engine's
    /// listeners met in accepting a connection, each recovered from: a listener that no longer
    /// listened, as after Android's netd destroyed the sockets on the tunnel's address, bound anew, or
    /// one that still did, as when the process was out of descriptors for a moment, accepting again
    /// after a pause; then (unit 9b) the answers from the tool's relay that a stand-in took by the
    /// identifier its app's datagram carried (a STUN transaction ID, a QUIC connection ID or the keys
    /// that derive from it, a DNS query's ID and question, an NTP request's timestamp) where the address
    /// alone could not tell: several stand-ins waited on the port, or the address was another peer's,
    /// and the answers dropped because only stand-ins with identifiers could take them and they carried
    /// none of theirs; and the associations of a stand-in's own opened for a stand-in whose answers the
    /// address alone could not have told from another's on its port, and those refused at a cap or for
    /// want of a place in the budget, which left it beside the other under unit 9's floor; then (W5's
    /// second part) the seconds, and segments with no count, placed in no state because their state was
    /// told too late: past a flow's window, past their app's share of what waits, or past the bound of
    /// all (ADR 0046, "How it is built"); then (W7, ADR 0035) the apps' packets handed to a `WireGuard` tunnel, and
    /// the packets from tunnels handed to the apps, those a tunnel decrypted that were dropped because they came
    /// from outside the peer's `AllowedIPs` or not to the configuration's address, and those dropped because no
    /// flow a local app started was theirs, the apps' packets refused because their tunnel could not carry them
    /// (outside `AllowedIPs`, or IPv6 without an IPv6 address), those answered as too big for the tunnel's MTU,
    /// those lost in a core's queue or for want of a socket, the handshake initiations sent, and the datagrams
    /// from a server that the core refused; then (W8, part 2a, ADR 0052) the proxy requests the apps' bytes
    /// declared, those of them that carried a password unencrypted, the flows named a messenger's inferred proxy,
    /// those not named so because the app connected to its maker directly in the window (substitution), the
    /// names taken back when it did so later, and the hellos whose name, a messenger's cover, named no flow; then
    /// (W8, part 3a, ADR 0053) the lookups tracker blocking answered empty, the connections it refused (TCP and
    /// QUIC, by name or by address), those of them refused by their address alone, and the connections whose first
    /// bytes were held while they read as an unfinished hello or request head. None
    /// names a destination: they can be read on any phone. New
    /// counters are only ever appended, so that scripts reading a column by its place keep reading the same one.
    #[must_use]
    pub fn snapshot(&self) -> [u64; COUNTERS] {
        self.each().map(|c| c.load(Ordering::Relaxed))
    }

    /// Counters that go on from `values`, as an engine started on a tunnel set up again goes on from
    /// the counts of the one before (re-review of unit 12, minor 3).
    fn going_on_from(values: &[u64; COUNTERS]) -> Self {
        let counters = Self::default();
        for (counter, &value) in counters.each().into_iter().zip(values) {
            counter.store(value, Ordering::Relaxed);
        }
        counters
    }

    /// Each counter, in the order of [`Counters::snapshot`].
    fn each(&self) -> [&AtomicU64; COUNTERS] {
        [
            &self.tcp_flows,
            &self.udp_flows,
            &self.bytes_up,
            &self.bytes_down,
            &self.owner_unknown,
            &self.refused,
            &self.unreachable,
            &self.failed,
            &self.skipped,
            &self.packets_in,
            &self.packets_out,
            &self.tls_names,
            &self.quic_names,
            &self.quic_unread,
            &self.ech_offered,
            &self.ech_hidden,
            &self.dns_plain,
            &self.dns_encrypted,
            &self.strangers,
            &self.fragments,
            &self.hellos_on_dns_names,
            &self.hello_names_differ,
            &self.resets,
            &self.tcp_refused,
            &self.udp_mappings,
            &self.udp_filtered,
            &self.udp_unmatched,
            &self.udp_came_in_capped,
            &self.udp_relay_elsewhere,
            &self.udp_ambiguous,
            &self.udp_late,
            &self.udp_refused,
            &self.udp_evicted,
            &self.echo_carried,
            &self.echo_replies,
            &self.echo_refused,
            &self.echo_unsupported,
            &self.echo_dropped,
            &self.reassembled,
            &self.too_big,
            &self.path_mtu,
            &self.time_exceeded,
            &self.path_unreachable,
            &self.echo_errors,
            &self.errors_dropped,
            &self.echo_evicted,
            &self.listener_recoveries,
            &self.udp_identified,
            &self.udp_unidentified,
            &self.udp_own_relays,
            &self.udp_own_refused,
            &self.told_late,
            &self.tunnel_up,
            &self.tunnel_down,
            &self.tunnel_filtered,
            &self.tunnel_unmatched,
            &self.tunnel_refused,
            &self.tunnel_too_big,
            &self.tunnel_lost,
            &self.tunnel_handshakes,
            &self.tunnel_rejected,
            &self.proxies_declared,
            &self.proxy_passwords,
            &self.proxies_inferred,
            &self.proxies_substituted,
            &self.proxies_taken_back,
            &self.covers_kept_out,
            &self.blocked_lookups,
            &self.blocked_connections,
            &self.blocked_addresses,
            &self.blocking_holds,
        ]
    }
}

/// What the network part last set on its engines from outside: the chain, and whether answers go uncached, which
/// goes with it ([`Engine::chain`]). The network part's native side keeps it whether or not an engine runs, so that
/// a chain set while none does, as in the moment of a swap, is the next engine's from its first packet
/// (fourth check of unit 12, minor 1); it wins over what the engine before handed over, which it may
/// be newer than.
#[derive(Clone, Debug)]
pub struct ChainSetting {
    /// The chain, or `None` for none.
    pub chain: Option<Chain>,
    /// Whether the answers of the tunnel's DNS address go to the apps with a time to live of 0.
    pub uncached_answers: bool,
    /// The `WireGuard` tunnels and the apps sent through them (W7), as set last ([`Engine::tunnels`]).
    pub tunnels: TunnelSetting,
    /// The encrypted resolver for direct apps' names (W8, part 1), as set last ([`Engine::dns`]); `None` keeps
    /// the network's resolver, as before W8.
    pub dns: Option<Arc<DnsConfig>>,
    /// The messengers' apps and Android's proxy setting (W8, part 2a), as set last ([`Engine::proxies`]).
    pub proxies: ProxySetting,
    /// Tracker blocking (W8, part 3a), as set last ([`Engine::blocking`]).
    pub blocking: BlockSetting,
}

/// What an engine hands the next when the tunnel is set up again (ADR 0044, the proposal for decision 5): what
/// was set on it from outside, the chain, the network's resolver and whether answers go uncached, and
/// what it learned that the apps' next flows need, the stand-in addresses chained apps were given and
/// the names DNS answers gave addresses; with its counters, which go on. So the new engine routes a
/// chained app's first packet through the tool, as the old one would have, rather than directly until
/// the chain is set again (re-review of unit 12, major 1). Its flows end with it. Since unit 12b this is
/// only for a tunnel with other addresses or on a new VPN network: one with the same addresses on the
/// same network goes to the running engine ([`Engine::swap_tunnel`]), which keeps its flows.
pub struct Handover {
    chain: Option<Arc<Chain>>,
    upstream_dns: Option<IpAddr>,
    uncached_answers: bool,
    stand_ins: StandIns,
    names: Names,
    counters: [u64; COUNTERS],
    /// The states told and the segments that wait for theirs (`activity`).
    activity: activity::Activity,
    /// The `WireGuard` tunnels and their routes, set anew in the next engine: its tunnels begin new sessions.
    tunnels: TunnelSetting,
    /// The encrypted resolver's setting; what it learned stays behind, with the network it learned on.
    dns: Option<Arc<DnsConfig>>,
    /// The messengers' apps and Android's proxy setting (W8, part 2a).
    proxies: ProxySetting,
    /// Each messenger app's last direct connection to its maker's network (the fix round of W8 part 2a, S-M2).
    direct: proxied::DirectInstants,
    /// Tracker blocking's setting (W8, part 3a); what it counted and tied stays behind.
    blocking: BlockSetting,
    /// The last flow number given: the next engine goes on from it, so that a number names one flow for the whole
    /// run. The segments handed over in `activity`, and the matches by number since unit A of the proxy record (a
    /// segment cut before its naming, a first hop held past its flow), would otherwise mistake an old flow for a new
    /// one of the same number (review A, engine, finding 4).
    next_id: u64,
    /// The flows taken back or substituted, whose records the log keeps left out while their apps' first hops are
    /// not kept: their segments waiting for their states cross with `activity`.
    taken_back: proxied::TakenBack,
}

/// What the engine's thread and its controller share.
struct Shared {
    platform: Arc<dyn Platform>,
    /// The tunnel's addresses for this run.
    addresses: Addresses,
    limits: Limits,
    /// The engine's listener on the tunnel's IPv4 address, the one the apps' connections are rewritten
    /// to: its port, 0 while none listens, and its generation. A listener that stopped listening is
    /// bound anew, on a new port, of a new generation (ADR 0044, unit 12b).
    listener4: Listening,
    /// The same on the tunnel's IPv6 address.
    listener6: Listening,
    /// TCP connections waiting for their servers now (`Limits::tcp_waiting`).
    tcp_waiting: AtomicUsize,
    /// Each app's share of them, once Android has named it (`Limits::tcp_share`).
    tcp_shares: Arc<Budget>,
    /// The UDP ways that hold a socket of their own, for every app together and for each
    /// (`Limits::udp_mappings`, `Limits::udp_share`).
    udp_budget: Arc<Budget>,
    /// The associations of a stand-in's own, opening or open, for every app together and for each
    /// (`Limits::udp_own_relays`, `Limits::udp_own_share`).
    own_relays: Arc<Budget>,
    counters: Counters,
    keep_flows: usize,
    flows: Mutex<VecDeque<Flow>>,
    /// The DNS server of the network beneath the tunnel.
    upstream_dns: Mutex<Option<IpAddr>>,
    /// Names from the DNS answers the network part passed on, by address.
    names: Mutex<Names>,
    /// The offline table from address to organisation, if the network part has one.
    organisations: Option<Organisations>,
    /// Well-known public DNS resolvers.
    resolvers: Resolvers,
    /// The companies behind well-known networks.
    owners: Owners,
    next_id: AtomicU64,
    /// The clock the log reads ([`Platform::clock`]).
    clock: Arc<dyn Clock>,
    /// The thread the engine runs on, once `run` starts: the log reads its clock only there, which is
    /// what leaves no race between a cut and a count (`logbook`'s comment), and debug builds check it.
    engine_thread: std::sync::OnceLock<std::thread::ThreadId>,
    /// The quarter hour of the wall clock (milliseconds since 1970 over [`logbook::SEGMENT_MS`]) that
    /// every open segment and each app's lookups are in, since the log's last cut ([`Shared::log_now`]).
    quarter: AtomicU64,
    /// The log's last reading of the wall clock, where a segment ends when the clock is set back.
    last_reading: AtomicU64,
    /// The flows open now, for the log.
    live: Mutex<HashMap<u64, Live>>,
    /// Lookups each app sent to the network part's own DNS address since the last segment.
    lookups: Mutex<HashMap<Option<u32>, Lookups>>,
    /// The bytes of open TCP flows by fake port, for the packets the tunnel carries.
    wire: Mutex<HashMap<u16, Arc<FlowBytes>>>,
    /// Records waiting to go to the network part's log.
    pending_log: Mutex<Vec<Record>>,
    /// Whether the network part's Kotlin side tells the apps' states ([`Platform::tells_states`]).
    tracks: bool,
    /// The seconds not placed in a state yet, of every flow and app's lookups together and of each app
    /// ([`activity::MARKS`], [`activity::MARKS_SHARE`]).
    waiting: Mutex<activity::Waiting>,
    /// The wall clock's second at which the engine last asked for the apps' states
    /// ([`activity::NO_SECOND`] for never).
    asked: AtomicU64,
    /// The states told, and the segments cut that wait for theirs (`activity`).
    activity: Mutex<activity::Activity>,
    /// Whether the engine stops to hand over to the next one ([`Engine::hand_over`]): the segments that
    /// wait for their states go with it, rather than being written in none.
    handing_over: AtomicBool,
    /// Woken when a record waits or a flow opens.
    log_ready: Notify,
    /// Who waits for a flush of the log ([`Shared::ask_flush`]), told once it is done, and whether a
    /// logger is there to make one.
    flushes: Mutex<logbook::Flushes>,
    /// Woken when a flush is asked.
    flush_wanted: Notify,
    /// Whether the answers of the network part's own DNS address go to the apps with a time to live of 0
    /// ([`crate::dns::uncache`]), so that Android's resolver keeps none of them.
    uncached_answers: AtomicBool,
    /// The user's tool and the apps sent through it, while a chain is on (W6).
    chain: Mutex<Option<Arc<Chain>>>,
    /// How many times the chain was set, on or off: a UDP mapping asks again whether its way still
    /// holds only when this changed.
    chains: AtomicU64,
    /// The stand-in addresses of the names chained apps looked up (ADR 0038).
    stand_ins: Mutex<StandIns>,
    /// The network resolver's answers, kept for the apps that go directly while a chain is on.
    direct_answers: Mutex<DnsCache>,
    /// The answers of chained apps' other questions, from the resolver through the tool (ADR 0038).
    tool_answers: Mutex<DnsCache>,
    /// The connections to those resolvers through the tool, kept open between questions.
    kept: Mutex<Vec<kept::Kept>>,
    /// The `WireGuard` tunnels, their routes and their flows (W7).
    tunnels: tunnels::Tunnels,
    /// The encrypted resolver for direct apps' names (W8, part 1).
    resolver: resolver::Resolver,
    /// The messengers whose proxies are inferred (W8, part 2a; ADR 0052): their apps' packages, Telegram's
    /// ranges and the names that tell their own connections.
    messengers: Messengers,
    /// What the inference and the declared proxies know: the messengers' apps, their direct connections,
    /// and Android's proxy setting.
    proxies: Mutex<proxied::State>,
    /// The records of flows named an inferred proxy, held back from the log for their window of take-back.
    held_back: Mutex<proxied::HeldBack>,
    /// Tracker blocking (W8, part 3a; ADR 0053): its setting, what it counted for "Now", and the addresses tied to
    /// blocked names.
    blocks: Mutex<blocks::Blocks>,
    /// How many times blocking was set: a relayed flow decides its row again when this changed.
    blocking_set: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A task of the engine's that carries no traffic, boxed: every such task shares this one type, so that tokio's code
/// for a task (its poll, shutdown and join handle, about 2 KB on x86-64 for each type of task) is in the library once,
/// not once per kind of task. The resolver's tasks first (W8), then the tasks that open a flow, ask Android, listen
/// and log (the cold paths' size pass, ADR 0053). It costs each task one allocation more, its future's box, and each
/// of its polls one indirect call: the tasks that relay traffic, a mapping's, a relay's, a tunnel's, an echo's, keep
/// their own types.
type Task = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Spawns `task` as a [`Task`].
#[track_caller]
fn spawn_task(
    task: impl std::future::Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let task: Task = Box::pin(task);
    tokio::spawn(task)
}

/// Runs `job` on the blocking pool, its answer if it ran to its end: as `tokio::task::spawn_blocking(job).await.ok()`,
/// but as one type of blocking task for every job, so that the pool's code for a task is in the library once, not
/// once per call to Android (the cold paths' size pass, ADR 0053). The job fills a slot of its own with its answer,
/// which the caller reads once the job has ended; a caller that stops waiting leaves the job to run on, as before,
/// and its answer goes with the slot.
async fn blocking<R: Send + 'static>(job: impl FnOnce() -> R + Send + 'static) -> Option<R> {
    let slot = Arc::new(Mutex::new(None));
    let filled = Arc::clone(&slot);
    let job: Box<dyn FnOnce() + Send> = Box::new(move || {
        let answer = job();
        *lock(&filled) = Some(answer);
    });
    tokio::task::spawn_blocking(job).await.ok()?;
    lock(&slot).take()
}

impl Shared {
    fn keep(&self, flow: Flow) {
        let counter = match flow.outcome {
            // A flow blocking refused is counted where it is refused (`Shared::count_block`).
            Outcome::Opened | Outcome::Blocked => None,
            Outcome::Refused => Some(&self.counters.refused),
            Outcome::Unreachable => Some(&self.counters.unreachable),
            Outcome::Failed => Some(&self.counters.failed),
        };
        Counters::add(
            if flow.protocol == TCP {
                &self.counters.tcp_flows
            } else {
                &self.counters.udp_flows
            },
            1,
        );
        if let Some(counter) = counter {
            Counters::add(counter, 1);
        }
        if flow.uid.is_none() {
            Counters::add(&self.counters.owner_unknown, 1);
        }
        match flow.dns {
            DnsUse::None => {}
            DnsUse::Plain => Counters::add(&self.counters.dns_plain, 1),
            DnsUse::Encrypted => Counters::add(&self.counters.dns_encrypted, 1),
        }
        if self.keep_flows > 0 {
            let mut flows = lock(&self.flows);
            if flows.len() == self.keep_flows {
                flows.pop_front();
            }
            flows.push_back(flow);
        }
    }
}

/// A new descriptor of the tunnel, for the engine's event loop, and where it says whether it took it
/// ([`Engine::swap_tunnel`]).
type Swap = (OwnedFd, std::sync::mpsc::SyncSender<io::Result<()>>);

/// The running engine. Dropping it stops the engine and closes the tunnel.
pub struct Engine {
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    network: watch::Sender<u64>,
    swaps: mpsc::UnboundedSender<Swap>,
    thread: Option<JoinHandle<()>>,
}

impl Engine {
    /// Starts the engine on its own thread, reading the tunnel `fd` until [`Engine::stop`].
    ///
    /// # Errors
    /// When the thread or its event loop cannot be made.
    pub fn start(
        fd: OwnedFd,
        config: Config,
        platform: Arc<dyn Platform>,
        organisations: Option<Organisations>,
    ) -> io::Result<Self> {
        Self::start_with(fd, config, platform, organisations, (None, None))
    }

    /// Starts as [`Engine::start`], on a tunnel set up again, with what the engine before it handed
    /// over ([`Engine::hand_over`]), and with the chain the network part last set, which wins over the one handed
    /// over: all of it is in place before the new engine's thread reads its first packet.
    ///
    /// # Errors
    /// When the thread or its event loop cannot be made.
    #[allow(clippy::too_many_lines)]
    pub fn start_with(
        fd: OwnedFd,
        config: Config,
        platform: Arc<dyn Platform>,
        organisations: Option<Organisations>,
        (handover, setting): (Option<Handover>, Option<ChainSetting>),
    ) -> io::Result<Self> {
        let tracks = platform.tells_states();
        let Handover {
            mut chain,
            upstream_dns,
            mut uncached_answers,
            stand_ins,
            names,
            counters,
            mut activity,
            mut tunnels,
            mut dns,
            mut proxies,
            direct,
            mut blocking,
            next_id,
            taken_back,
        } = handover.unwrap_or_else(|| Handover {
            chain: None,
            upstream_dns: None,
            uncached_answers: false,
            stand_ins: StandIns::with_capacity(config.limits.stand_ins),
            names: Names::default(),
            counters: [0; COUNTERS],
            activity: activity::Activity::new(tracks),
            tunnels: TunnelSetting::default(),
            dns: None,
            proxies: ProxySetting::default(),
            direct: Vec::new(),
            blocking: BlockSetting::default(),
            next_id: 0,
            taken_back: proxied::TakenBack::default(),
        });
        let waiting = activity::Waiting::of_held(&activity.held);
        if let Some(setting) = setting {
            chain = setting.chain.map(Arc::new);
            uncached_answers = setting.uncached_answers;
            tunnels = setting.tunnels;
            dns = setting.dns;
            proxies = setting.proxies;
            blocking = setting.blocking;
        }
        let clock = platform.clock();
        // The live view counts from now on; a handed-over view keeps the moment its first engine began.
        activity.counts.begin(clock.wall_ms());
        let quarter = clock.wall_ms() / logbook::SEGMENT_MS;
        let shared = Arc::new(Shared {
            platform,
            addresses: config.addresses,
            limits: config.limits,
            listener4: Listening::new(),
            listener6: Listening::new(),
            tcp_waiting: AtomicUsize::new(0),
            tcp_shares: Budget::new(config.limits.tcp_waiting, config.limits.tcp_share),
            udp_budget: Budget::new(config.limits.udp_mappings, config.limits.udp_share),
            own_relays: Budget::new(config.limits.udp_own_relays, config.limits.udp_own_share),
            counters: Counters::going_on_from(&counters),
            keep_flows: config.keep_flows,
            flows: Mutex::new(VecDeque::new()),
            upstream_dns: Mutex::new(upstream_dns),
            names: Mutex::new(names),
            organisations,
            resolvers: Resolvers::bundled(),
            owners: Owners::bundled(),
            next_id: AtomicU64::new(next_id),
            clock,
            engine_thread: std::sync::OnceLock::new(),
            quarter: AtomicU64::new(quarter),
            last_reading: AtomicU64::new(0),
            live: Mutex::default(),
            lookups: Mutex::default(),
            wire: Mutex::default(),
            pending_log: Mutex::default(),
            tracks,
            waiting: Mutex::new(waiting),
            asked: AtomicU64::new(activity::NO_SECOND),
            activity: Mutex::new(activity),
            handing_over: AtomicBool::new(false),
            log_ready: Notify::new(),
            flushes: Mutex::default(),
            flush_wanted: Notify::new(),
            uncached_answers: AtomicBool::new(uncached_answers),
            chain: Mutex::new(chain),
            chains: AtomicU64::new(0),
            stand_ins: Mutex::new(stand_ins),
            direct_answers: Mutex::default(),
            tool_answers: Mutex::default(),
            kept: Mutex::default(),
            tunnels: tunnels::Tunnels::default(),
            resolver: resolver::Resolver::default(),
            messengers: Messengers::bundled(),
            proxies: Mutex::default(),
            held_back: Mutex::new(proxied::HeldBack::carrying(taken_back)),
            blocks: Mutex::default(),
            blocking_set: AtomicU64::new(0),
        });
        // In place before the thread reads its first packet: no direct app's lookup goes to the network's
        // resolver while the encrypted one is set.
        shared.resolver.set(dns);
        // In place before the thread reads its first packet: a messenger's first flow is read as one, and
        // substitution goes on from the engine before.
        shared.set_proxies(proxies);
        lock(&shared.proxies).carry_direct(direct);
        // In place before the thread reads its first packet: no blocked name gets an answer from the new engine.
        shared.set_blocking(blocking);
        // In place before the thread reads its first packet: a tunnelled app's first SYN never goes directly.
        shared.tunnels.set(&tunnels);
        if shared.tunnels.any() {
            shared.uncached_answers.store(true, Ordering::Relaxed);
        }
        // What the engine before held may name chained apps' destinations that the chain set now leaves out.
        shared.hide_chained();
        let (stop, stopped) = watch::channel(false);
        let (network, changes) = watch::channel(0);
        let (swaps, swapped) = mpsc::unbounded_channel();
        // An engine that cannot start, or whose tunnel never comes, writes off at once what the engine before
        // handed over, segments waiting for their states among them (review b2 of W5's second part, fresh).
        let state = Arc::clone(&shared);
        let thread = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .and_then(|runtime| {
                std::thread::Builder::new()
                    .name("network-engine".into())
                    .spawn(move || {
                        runtime.block_on(async move {
                            if let Ok(tun) = Tun::waiting(fd, config.limits.tunnel_wait) {
                                run(tun, config.mtu, state, stopped, changes, swapped).await;
                            } else {
                                Counters::add(&state.counters.failed, 1);
                                state.write_off();
                            }
                        });
                    })
            })
            .inspect_err(|_| shared.write_off())?;
        Ok(Self {
            shared,
            stop,
            network,
            swaps,
            thread: Some(thread),
        })
    }

    /// Hands the running engine `fd`, the descriptor of the tunnel set up again with the same addresses
    /// on the same VPN network, which must be non-blocking (ADR 0044, unit 12b). The engine goes on with
    /// it in place of the tunnel it reads, keeping everything: its NAT, TCP connections and listeners,
    /// UDP mappings, ping sockets, fragments, chain, names, stand-ins, counters and log. It first handles
    /// what is still queued on the old tunnel, which it then closes. Waits until the engine's thread has
    /// done so.
    ///
    /// Only for the same addresses on the same network. The apps' connections are bound to the tunnel's
    /// addresses, and the engine's listeners and rewriting to them. And Android's netd marks each packet
    /// that comes in on the tunnel with its VPN network's netId, which the connections the engine's
    /// listener accepted keep (`tcp_fwmark_accept`): on a new network, which Android brings up when the
    /// apps of the tunnel change, they would route nowhere once the old one goes, where a new engine's
    /// connections reset at once. Either way a new engine starts, with what this one hands over
    /// ([`Engine::hand_over`]).
    ///
    /// # Errors
    /// When the engine has stopped, or tokio cannot register `fd`. `fd` is closed then, and an engine
    /// that runs goes on with the tunnel it had.
    pub fn swap_tunnel(&self, fd: OwnedFd) -> io::Result<()> {
        let (done, taken) = std::sync::mpsc::sync_channel(1);
        self.swaps
            .send((fd, done))
            .map_err(|_| io::Error::other("the engine has stopped"))?;
        taken
            .recv()
            .map_err(|_| io::Error::other("the engine stopped before it took the tunnel"))?
    }

    /// Stops the engine and waits for its thread: the tunnel's descriptor is closed, and with it the
    /// tunnel, and every connection relayed through it.
    pub fn stop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Stops the engine, as [`Engine::stop`], and hands over what the next engine, on a tunnel set up
    /// again, goes on with ([`Handover`]). Read once the thread has ended, so that nothing changes it
    /// after.
    #[must_use]
    pub fn hand_over(mut self) -> Handover {
        self.shared.handing_over.store(true, Ordering::Relaxed);
        self.stop();
        let shared = &self.shared;
        let tracks = shared.tracks;
        // Read before: a lock taken in the literal below would be held to its end.
        let (proxies, direct) = {
            let state = lock(&shared.proxies);
            (
                state.setting().clone(),
                state.direct_instants(shared.clock.since_boot()),
            )
        };
        let taken_back = lock(&shared.held_back).take_taken_back();
        Handover {
            chain: lock(&shared.chain).clone(),
            upstream_dns: *lock(&shared.upstream_dns),
            uncached_answers: shared.uncached_answers.load(Ordering::Relaxed),
            stand_ins: std::mem::replace(&mut *lock(&shared.stand_ins), StandIns::with_capacity(0)),
            names: std::mem::take(&mut *lock(&shared.names)),
            counters: shared.counters.snapshot(),
            activity: std::mem::replace(
                &mut *lock(&shared.activity),
                activity::Activity::new(tracks),
            ),
            tunnels: shared.tunnels.setting(),
            dns: shared.resolver.get(),
            proxies,
            direct,
            blocking: shared.blocking(),
            next_id: shared.next_id.load(Ordering::Relaxed),
            taken_back,
        }
    }

    /// The network beneath the tunnel, or its DNS server, changed. DNS goes to `dns` from now on. When
    /// the network itself is another one (`moved`), UDP mappings and flows are closed, so that their
    /// next datagram goes out on the new network; TCP connections on the old network end by
    /// themselves, as without a VPN. A change of the same network's properties closes nothing: Android
    /// reports several after each switch.
    pub fn network_changed(&self, dns: Option<IpAddr>, moved: bool) {
        *lock(&self.shared.upstream_dns) = dns;
        // Another resolver, or another network, may answer otherwise.
        lock(&self.shared.direct_answers).clear();
        if moved {
            self.shared.resolver.network_moved();
            self.network
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }

    /// Sets the encrypted resolver for the names of apps that go directly (W8, part 1, ADR 0042), or `None` for
    /// the network's resolver, as before W8. What the resolver learned and kept goes.
    pub fn dns(&self, config: Option<Arc<DnsConfig>>) {
        self.shared.resolver.set(config);
        self.shared.platform.dns_changed();
    }

    /// What Android says of the network beneath, for the encrypted resolver: whether it is validated (while it
    /// is not, as behind a captive portal, no failure counts) and its search domains (local names).
    pub fn dns_network(&self, validated: bool, domains: &str) {
        self.shared.resolver.network(validated, domains);
    }

    /// The encrypted resolver's state, one `key value` per line: `way` (`off`, `none`, the way that answered
    /// last, `fallback SECONDS`, `failing SECONDS`), `strict`, `validated`, `held`, and `answers` by way. It names
    /// no lookup.
    #[must_use]
    pub fn dns_status(&self) -> String {
        self.shared.resolver.status()
    }

    /// Forgets the durations of the exchanges the encrypted resolver kept, of every carry, so that the `latency`
    /// lines of [`Engine::dns_status`] read only those answered after it: debug builds' speed budget check, which
    /// times each way over its own lookups (ADR 0039).
    pub fn dns_times_clear(&self) {
        self.shared.resolver.clear_times();
    }

    /// The exchanges that wait for the network part's Kotlin side, which hands each reply to [`Exchanges::complete`].
    #[must_use]
    pub fn exchanges(&self) -> Arc<Exchanges> {
        Arc::clone(&self.shared.resolver.exchanges)
    }

    /// Turns chaining on with `chain`, or off with `None` (W6). New flows follow it, and TCP
    /// connections already open keep their way. A UDP mapping that it sends another way ends at its
    /// next datagram either way, so that the app's next one follows the new route (ADR 0044, decision
    /// 1); one through the same tool, reached the same way, stays. While a chain is on, every answer
    /// of the network part's DNS address reaches the apps with a time to live of 0 (ADR 0038).
    pub fn chain(&self, chain: Option<Chain>) {
        let on = chain.is_some() || self.shared.tunnels.any();
        *lock(&self.shared.chain) = chain.map(Arc::new);
        // After the chain itself: a mapping that reads the new count reads the new chain too.
        self.shared.chains.fetch_add(1, Ordering::Release);
        self.shared.uncached_answers.store(on, Ordering::Relaxed);
        lock(&self.shared.direct_answers).clear();
        lock(&self.shared.tool_answers).clear();
        // A kept connection goes through the tool it was opened through: those answer the questions
        // already sent, then end.
        lock(&self.shared.kept).clear();
        // What the new chain leaves out of the log leaves "Now" too, at once (ADR 0046, decision 6, item 5).
        self.shared.hide_chained();
    }

    /// Sets the `WireGuard` tunnels and the apps sent through them (W7, ADR 0035): each app's new flows follow
    /// its route from now on; an app whose tunnel changed has its UDP flows end at once, so that its next
    /// datagram takes its new route, and keeps its TCP connections' way, as the chain does. A tunnel whose
    /// configuration is the same keeps its session. While any app goes through a tunnel, every answer of
    /// the network part's DNS address reaches the apps with a time to live of 0 (ADR 0035, question 4).
    pub fn tunnels(&self, setting: &TunnelSetting) {
        self.shared.tunnels.set(setting);
        // As after a chain set anew: a UDP mapping or flow of lookups asks again whether its way still holds.
        self.shared.chains.fetch_add(1, Ordering::Release);
        let on = self.shared.tunnels.any() || self.shared.chain().is_some();
        self.shared.uncached_answers.store(on, Ordering::Relaxed);
        lock(&self.shared.direct_answers).clear();
        self.shared.hide_chained();
    }

    /// Sets the messengers' apps, by UID, and the proxies Android's setting names (W8, part 2a; ADR 0052): each
    /// app's new flows are read by them from now on, and the open ones keep how they were named.
    pub fn proxies(&self, setting: ProxySetting) {
        self.shared.set_proxies(setting);
    }

    /// Sets tracker blocking (W8, part 3a; ADR 0053), whole: every lookup and connection is decided by it from now
    /// on, and a relayed flow whose row it blocks now is reset at its next byte.
    pub fn blocking(&self, setting: BlockSetting) {
        self.shared.set_blocking(setting);
    }

    /// What tracker blocking counted in memory since the engine started or the live view was cleared: each app's
    /// rows, by the row's host, with the lookups answered empty and the connections refused apart (decision 7).
    #[must_use]
    pub fn blocked(&self) -> Vec<(u32, String, Tally)> {
        self.shared.blocked_tallies()
    }

    /// Whether the answers of the network part's own DNS address reach the apps with a time to live of 0 now: while a
    /// chain or a tunnel takes any app, or as set by [`Engine::uncache_answers`].
    #[must_use]
    pub fn answers_uncached(&self) -> bool {
        self.shared.uncached_answers.load(Ordering::Relaxed)
    }

    /// The network part's answers for the apps it did not name, by UID, `None` for a flow refused for want of one
    /// ([`Platform::route_of_app`]).
    #[must_use]
    pub fn app_answers(&self) -> Vec<(u32, Option<AppRoute>)> {
        self.shared.tunnels.answers()
    }

    /// Each tunnel's state, in the order set: no key, no address, no endpoint.
    #[must_use]
    pub fn tunnel_states(&self) -> Vec<TunnelState> {
        self.shared.tunnels.states(self.shared.clock.since_boot())
    }

    /// Whether the answers of the network part's own DNS address reach the apps with a time to live of 0, so that
    /// Android's resolver, which keeps one cache for all the apps of a network, keeps none of them:
    /// each app's lookup then reaches the network part with that app as its owner. Off by default.
    pub fn uncache_answers(&self, on: bool) {
        self.shared.uncached_answers.store(on, Ordering::Relaxed);
    }

    /// The release month of the organisation table the engine reads, if it has one.
    #[must_use]
    pub fn organisations(&self) -> Option<String> {
        self.shared
            .organisations
            .as_ref()
            .map(|table| table.month().to_owned())
    }

    /// The counters, as [`Counters::snapshot`] orders them.
    #[must_use]
    pub fn counters(&self) -> [u64; COUNTERS] {
        self.shared.counters.snapshot()
    }

    /// Hands the log every waiting record now, with a segment of each open flow up to now, as the
    /// quarter hour would: for the end-to-end test, which cannot wait. The engine's thread makes the
    /// flush, between its counts, and this waits until it has handed the records on, at most ten
    /// seconds; nothing is left to flush once the engine has stopped.
    pub fn flush_log(&self) {
        if self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
            let _ = self.shared.ask_flush(Duration::from_secs(10));
        }
    }

    /// What the live view "Now" draws (ADR 0046, decision 2 (d)), in the form of [`crate::snapshot`]:
    /// each app's bytes by state in the last 10 minutes, the last hour, since the screen came on and while
    /// it was off, those in no state by why, and its destinations. From memory only; cheap enough to read
    /// every second while the view is open.
    #[must_use]
    pub fn activity(&self) -> Vec<u8> {
        crate::snapshot::encode(&self.shared.now_view(self.shared.clock.wall_ms()))
    }

    /// Forgets everything the live view holds (ADR 0047, decision 3: under the profile for phones that may
    /// be searched, at each screen-off): every app's bytes in every window, its destinations, the window
    /// while the screen was off and the organisations looked up. Seconds before now that are placed later
    /// stay out of the view. It cannot clear the flows still open, which the engine needs to carry them,
    /// nor the seconds and segments that wait for their states, which are the log's and go to it as its
    /// retention says. A snapshot looks organisations up outside the engine's locks and keeps them after: a
    /// caller must not clear while one is taken, or the addresses it looked up stay (network-jni's `ENGINE`
    /// lock holds both calls apart; review c1 of W5's third part, engine, nit 5).
    pub fn clear_activity(&self) {
        let now = self.shared.clock.wall_ms();
        lock(&self.shared.activity).counts.clear(now);
        self.shared.clear_blocked();
    }

    /// Takes a reading of the apps' states from the network part's Kotlin side, a message of [`crate::states`]:
    /// every second held that it covers is placed, and the log's segments cut where an app's state
    /// changed. False for a message that is not one of its version, which changes nothing.
    #[must_use]
    pub fn states(&self, message: &[u8]) -> bool {
        match crate::states::read(message) {
            Some(told) => {
                self.shared.tell(&told);
                true
            }
            None => false,
        }
    }

    /// The latest flows kept, oldest first (only when [`Config::keep_flows`] is above 0).
    #[must_use]
    pub fn flows(&self) -> Vec<Flow> {
        lock(&self.shared.flows).iter().cloned().collect()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The engine's state inside its event loop.
struct Loop {
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
    pending: Pending,
    udp: UdpFlows,
    echoes: Echoes,
    /// The apps' fragments, put together again. Every app sends from the tunnel's one address, so
    /// the bounds are shared: one app that fills them makes the others' fragments dropped, as all
    /// were before. Accepted, since the bounds cap what they cost.
    fragments: Mutex<Reassembler>,
    changes: watch::Receiver<u64>,
}

async fn run(
    tun: Tun,
    mtu: u16,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
    changes: watch::Receiver<u64>,
    mut swaps: mpsc::UnboundedReceiver<Swap>,
) {
    let pending: Pending = Arc::default();
    let nat = Arc::new(Mutex::new(Nat::with_limits(&shared.limits)));
    let at = shared.addresses;
    listen(
        IpAddr::V4(at.tun4),
        IpAddr::V4(at.fake4),
        &pending,
        &shared,
        &nat,
    );
    listen(
        IpAddr::V6(at.tun6),
        IpAddr::V6(at.fake6),
        &pending,
        &shared,
        &nat,
    );
    let limits = shared.limits;
    let tun = Arc::new(tun);
    shared.tunnels.attach(&tun, &changes);
    let state = Loop {
        tun,
        shared,
        nat,
        pending,
        udp: Arc::default(),
        // At the engine's start: whether this kernel lets it make ping sockets at all.
        echoes: Echoes::probe(),
        fragments: Mutex::new(Reassembler::new(fragments::Bounds {
            datagrams: limits.fragment_datagrams,
            bytes: limits.fragment_bytes,
            wait: limits.fragment_wait,
        })),
        changes,
    };
    // Sized from the first tunnel's MTU, and never smaller than 1,500 bytes: a tunnel set up again and
    // handed over (`Engine::swap_tunnel`) keeps this buffer, which holds its packets too, since the network part
    // never gives the tunnel an MTU above 1,500 (ADR 0044, the proposal for decision 5).
    let mut buffer = vec![0u8; usize::from(mtu).max(1500) + 64];
    let mut swept = Instant::now();
    // Every task of the engine runs on this thread: the log reads its clock here alone.
    let _ = state.shared.engine_thread.set(std::thread::current().id());
    let (end_logging, logging_ends) = watch::channel(false);
    // From here a logger is there to answer a flush.
    lock(&state.shared.flushes).logging = true;
    let logging = spawn_task(logger(Arc::clone(&state.shared), logging_ends));
    // A tunnel that keeps itself alive starts at once.
    state.tunnels_changed();
    loop {
        // Polled in this order, not at random: a stop, then a new tunnel, which their callers wait for,
        // before another batch of reads. What is still queued on the old tunnel is then read by
        // `Loop::take_tunnel` before it closes; read here first, it would be handled the same.
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            Some(swap) = swaps.recv() => state.take_tunnel(swap, &mut buffer).await,
            () = state.shared.tunnels.changed.notified() => state.tunnels_changed(),
            read = state.tun.recv(&mut buffer) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                if swept.elapsed() > state.shared.limits.sweep_every {
                    state.sweep();
                    state.sweep_tunnels();
                    // An app's own tables of names, once every name in them has expired.
                    lock(&state.shared.names).forget_expired(Instant::now());
                    let dropped = lock(&state.fragments).sweep(Instant::now());
                    Counters::add(&state.shared.counters.fragments, dropped);
                    swept = Instant::now();
                }
                state.handle(&mut buffer[..n]).await;
                // What queued up meanwhile, before waiting again.
                for _ in 1..BATCH {
                    match state.tun.try_recv(&mut buffer) {
                        Ok(n) if n > 0 => state.handle(&mut buffer[..n]).await,
                        _ => break,
                    }
                }
            }
        }
    }
    // What is open ends with the tunnel; the log gets it before the engine's thread does, after any
    // batch the logger is handing over, so that the log gets them in order.
    let _ = end_logging.send(true);
    let _ = logging.await;
    state.shared.finish_all();
    if let Some(batch) = state.shared.take_log() {
        state.shared.platform.log(&batch);
    }
    // A flush asked meanwhile is answered by what was just handed on: only now is who waits let go.
    lock(&state.shared.flushes).waiting.clear();
}

impl Loop {
    /// Puts the tunnel set up again in the place of the old one, for reading and for every task that
    /// writes to the apps (ADR 0044, unit 12b). Android has moved the apps' routes to the new tunnel and
    /// reset the old one by then; what the apps sent before, still queued on the old tunnel, is read and
    /// handled first, and only then is the old tunnel closed, so that no packet in flight is lost. The
    /// buffer is the first tunnel's, which holds the new one's packets too (`run`).
    async fn take_tunnel(&self, (fd, done): Swap, buffer: &mut [u8]) {
        let old = match self.tun.replace(fd) {
            Ok(old) => old,
            Err(error) => {
                let _ = done.send(Err(error));
                return;
            }
        };
        // Nothing enters the old tunnel any more, so this ends once its queue is read.
        //
        // The order across the swap: `replace` has woken the writes refused in the gap, but this
        // thread runs them only when the loop next yields, at the latest once the drain is done, so
        // they reach the new tunnel among or after what the handling of the drained packets writes
        // itself, and before what those packets' own tasks, started later, write: a reset refused in
        // the gap comes before the answer to a SYN still queued here (the third round's check found
        // so). Tokio's order of running woken tasks is what holds it; nothing here orders them further.
        while let Ok(n) = old.try_recv(buffer) {
            if n == 0 {
                break;
            }
            self.handle(&mut buffer[..n]).await;
        }
        drop(old);
        let _ = done.send(Ok(()));
    }

    /// One packet from the tunnel. A fragment is held until its datagram is whole, which is then
    /// handled as any other packet, from a buffer of its own: the tunnel's read buffer holds one packet
    /// of the tunnel's MTU, and the next read overwrites it.
    async fn handle(&self, packet: &mut [u8]) {
        Counters::add(&self.shared.counters.packets_in, 1);
        match packet::parse(packet) {
            Err(Skip::Fragment) => {
                let Taken { whole, dropped } = lock(&self.fragments).take(packet, Instant::now());
                Counters::add(&self.shared.counters.fragments, dropped);
                if let Some(mut whole) = whole {
                    Counters::add(&self.shared.counters.reassembled, 1);
                    let parsed = packet::parse(&whole);
                    self.forward(&mut whole, parsed, true).await;
                }
            }
            parsed => self.forward(packet, parsed, false).await,
        }
    }

    /// One whole packet, as `parse` read it: TCP, UDP, an echo request, or skipped; `reassembled` when the
    /// engine put it together from the app's fragments. A packet of a tunnelled flow goes into its tunnel.
    async fn forward(
        &self,
        packet: &mut [u8],
        parsed: Result<packet::Packet, Skip>,
        reassembled: bool,
    ) {
        if let Ok(parsed) = &parsed
            && self
                .tunnelled(&mut packet[..parsed.length], parsed, reassembled)
                .await
        {
            return;
        }
        match parsed {
            Ok(parsed) if parsed.protocol == TCP => {
                self.tcp(&mut packet[..parsed.length], &parsed).await;
            }
            Ok(parsed) => self.udp(&packet[..parsed.length], &parsed).await,
            Err(Skip::Other(packet::ICMP | packet::ICMPV6)) => match packet::echo_request(packet) {
                Ok(request) if self.shared.tunnels.any() => {
                    self.tunnel_echo(&mut packet[..request.length], &request, reassembled)
                        .await;
                }
                Ok(request) => self.echo(&packet[..request.length], &request).await,
                // Any other ICMP an app sends, as its kernel's errors, stays skipped.
                Err(_) => Counters::add(&self.shared.counters.skipped, 1),
            },
            // A rebuilt packet is never a fragment (`fragments::Taken::whole`).
            Err(Skip::Fragment | Skip::Malformed | Skip::Other(_)) => {
                Counters::add(&self.shared.counters.skipped, 1);
            }
        }
    }

    /// Gives the app one packet through the tunnel, from the event loop. One the tunnel refuses as
    /// between Android's reset of the old interface and the swap (`tun::cured_by_another`) waits for the
    /// next tunnel in a task of its own (`Tun::send`), so that the loop reads on meanwhile; any other
    /// refusal drops it at once, as before.
    async fn send(&self, packet: &[u8]) {
        match self.tun.send_once(packet).await {
            Ok(_) => Counters::add(&self.shared.counters.packets_out, 1),
            Err(error) if self.tun.waits() && crate::tun::cured_by_another(&error) => {
                let (tun, shared) = (Arc::clone(&self.tun), Arc::clone(&self.shared));
                let packet = packet.to_vec();
                tokio::spawn(async move { send_to_app(&tun, &shared, &packet).await });
            }
            Err(_) => {}
        }
    }

    /// The tunnel's address and the fake peer, of one IP version.
    fn ends(&self, v4: bool) -> (IpAddr, IpAddr) {
        let at = self.shared.addresses;
        if v4 {
            (IpAddr::V4(at.tun4), IpAddr::V4(at.fake4))
        } else {
            (IpAddr::V6(at.tun6), IpAddr::V6(at.fake6))
        }
    }
}

/// Gives the app one packet through the tunnel, from a task: one the tunnel refuses waits for the
/// tunnel set up again, for `Limits::tunnel_wait` at most (`Tun::send`).
async fn send_to_app(tun: &Tun, shared: &Shared, packet: &[u8]) {
    if tun.send(packet).await.is_ok() {
        Counters::add(&shared.counters.packets_out, 1);
    }
}

impl Shared {
    /// Whether `address` is the tunnel's own DNS address, which leads to the network's resolver.
    fn is_tunnel_dns(&self, address: IpAddr) -> bool {
        self.addresses.is_dns(address)
    }

    /// The engine's listener of one IP version.
    fn listener(&self, v4: bool) -> &Listening {
        if v4 { &self.listener4 } else { &self.listener6 }
    }
}

/// The MTU the kernel keeps for the route of a connected socket (`IP_MTU`), or `None` when it says
/// nothing, as for a socket not connected. The network part's Kotlin side reads the first hop's MTU of the network
/// beneath with it, from a UDP socket bound to that network and connected toward an address only its
/// default route covers, and gives the tunnel that MTU (ADR 0044, the proposal for decision 5). On Linux
/// `IP_MTU` answers for an IPv6 socket too, with what router advertisements set.
#[must_use]
pub fn route_mtu(socket: &impl AsFd) -> Option<u32> {
    let mtu = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::IpMtu).ok()?;
    u32::try_from(mtu).ok().filter(|&mtu| mtu > 0)
}

fn is_unreachable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoPlatform;

    impl Platform for NoPlatform {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {}
    }

    /// One type of blocking task for every call to Android ([`blocking`], the cold paths' size pass): the job's answer
    /// once it ran, none for a job that panicked, and the pool still answers after one did.
    #[tokio::test(flavor = "current_thread")]
    async fn a_blocking_job_gives_its_answer_and_none_when_it_panics() {
        assert_eq!(blocking(|| 7u32).await, Some(7));
        let panicked: Option<u32> = blocking(|| unreachable!("a job that panics")).await;
        assert_eq!(panicked, None);
        assert_eq!(blocking(|| "after").await, Some("after"));
    }

    /// Android protects what Kotlin is handed while it runs: a duplicate of the socket's descriptor, owned by the job
    /// ([`upstream::protect`]), so that a caller that gives up and closes its socket leaves no bare number the kernel
    /// could hand another socket meanwhile. The duplicate still names the caller's socket after the caller closed it,
    /// and is closed once the job ends.
    #[tokio::test(flavor = "current_thread")]
    async fn a_socket_given_up_is_protected_through_its_own_duplicate() -> io::Result<()> {
        /// Protects only once let go, noting what the descriptor it got names.
        struct Holding {
            named: Mutex<Option<(RawFd, std::path::PathBuf)>>,
            go: Mutex<std::sync::mpsc::Receiver<()>>,
            done: Mutex<std::sync::mpsc::Sender<()>>,
        }
        impl Platform for Holding {
            fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
                None
            }

            fn protect(&self, fd: RawFd) -> bool {
                let _ = lock(&self.go).recv();
                *lock(&self.named) = std::fs::read_link(format!("/proc/self/fd/{fd}"))
                    .ok()
                    .map(|path| (fd, path));
                let _ = lock(&self.done).send(());
                true
            }

            fn log(&self, _: &[u8]) {}
        }
        let (go, going) = std::sync::mpsc::channel();
        let (done, ended) = std::sync::mpsc::channel();
        let platform = Arc::new(Holding {
            named: Mutex::new(None),
            go: Mutex::new(going),
            done: Mutex::new(done),
        });
        let shared = Arc::new(shared_with(Arc::clone(&platform) as Arc<dyn Platform>));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let original = std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&socket)
        ))?;
        let waited = tokio::time::timeout(
            Duration::from_millis(50),
            upstream::protect(&shared, socket.as_fd()),
        )
        .await;
        assert!(waited.is_err(), "the job waits to be let go");
        drop(socket);
        let _ = go.send(());
        let _ =
            tokio::task::spawn_blocking(move || ended.recv_timeout(Duration::from_secs(5))).await;
        let named = lock(&platform.named).clone();
        let Some((fd, path)) = named else {
            unreachable!("the job named its descriptor")
        };
        assert_eq!(
            path, original,
            "the duplicate names the socket the caller closed"
        );
        // Once the job has ended its duplicate is closed: the number names that socket no more.
        let mut closed = false;
        for _ in 0..100 {
            if std::fs::read_link(format!("/proc/self/fd/{fd}"))
                .ok()
                .as_ref()
                != Some(&original)
            {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(closed, "the duplicate is closed once the job ends");
        Ok(())
    }

    /// The tunnel's DNS server is the chosen set's, and the two sets share no address, so either can
    /// stand in for the other (ADR 0041).
    #[test]
    fn the_tunnels_dns_is_the_chosen_sets() {
        for (at, other) in [
            (Addresses::COMMON, Addresses::SPARE),
            (Addresses::SPARE, Addresses::COMMON),
        ] {
            let mut shared = shared();
            shared.addresses = at;
            assert!(shared.is_tunnel_dns(IpAddr::V4(at.dns4)));
            assert!(shared.is_tunnel_dns(IpAddr::V6(at.dns6)));
            assert!(!shared.is_tunnel_dns(IpAddr::V4(at.tun4)));
            assert!(!shared.is_tunnel_dns(IpAddr::V4(other.dns4)));
            assert!(!shared.is_tunnel_dns(IpAddr::V6(other.dns6)));
        }
        let (common, spare) = (Addresses::COMMON, Addresses::SPARE);
        for address in [common.tun4, common.fake4, common.dns4] {
            assert!(![spare.tun4, spare.fake4, spare.dns4].contains(&address));
        }
        for address in [common.tun6, common.fake6, common.dns6] {
            assert!(![spare.tun6, spare.fake6, spare.dns6].contains(&address));
        }
    }

    /// The kernel's MTU for a connected socket's route, of either IP version; none for a socket not
    /// connected.
    #[test]
    fn a_connected_socket_has_its_routes_mtu() -> io::Result<()> {
        let loopback = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        assert_eq!(route_mtu(&loopback), None);
        loopback.connect((Ipv4Addr::LOCALHOST, 9))?;
        assert!(route_mtu(&loopback).is_some_and(|mtu| mtu >= 1_280));
        if let Ok(loopback6) = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            && loopback6.connect((Ipv6Addr::LOCALHOST, 9)).is_ok()
        {
            assert!(route_mtu(&loopback6).is_some_and(|mtu| mtu >= 1_280));
        }
        Ok(())
    }

    /// The caps and shares follow the process's limit on open files (ADR 0044, decision 3): the
    /// defaults are those of a limit of 1,024; a share keeps its floor, but never passes its cap.
    #[test]
    fn the_caps_and_shares_follow_the_descriptor_limit() {
        assert_eq!(Limits::for_descriptors(1_024), Limits::default());
        let caps = |limits: Limits| {
            (
                limits.tcp_waiting,
                limits.tcp_share,
                limits.udp_mappings,
                limits.udp_share,
            )
        };
        assert_eq!(
            caps(Limits::for_descriptors(32_768)),
            (3_840, 960, 7_680, 1_920)
        );
        assert_eq!(
            caps(Limits::for_descriptors(100_000)),
            (4_096, 1_024, 23_437, 5_859)
        );
        assert_eq!(caps(Limits::for_descriptors(200)), (9, 9, 18, 18));
    }

    pub(super) fn shared() -> Shared {
        shared_with(Arc::new(NoPlatform))
    }

    pub(super) fn shared_with(platform: Arc<dyn Platform>) -> Shared {
        let tracks = platform.tells_states();
        let clock = platform.clock();
        Shared {
            platform,
            addresses: Addresses::COMMON,
            limits: Limits::default(),
            listener4: Listening::new(),
            listener6: Listening::new(),
            tcp_waiting: AtomicUsize::new(0),
            tcp_shares: Budget::new(Limits::default().tcp_waiting, Limits::default().tcp_share),
            udp_budget: Budget::new(Limits::default().udp_mappings, Limits::default().udp_share),
            own_relays: Budget::new(
                Limits::default().udp_own_relays,
                Limits::default().udp_own_share,
            ),
            counters: Counters::default(),
            keep_flows: 8,
            flows: Mutex::default(),
            upstream_dns: Mutex::default(),
            names: Mutex::default(),
            organisations: None,
            resolvers: Resolvers::parse(
                "sample\tSample\tSample DNS\tdoh.sample.example\t-\t192.0.2.53\t-\t-\n",
            ),
            owners: Owners::default(),
            next_id: AtomicU64::new(0),
            clock,
            engine_thread: std::sync::OnceLock::new(),
            quarter: AtomicU64::new(0),
            last_reading: AtomicU64::new(0),
            live: Mutex::default(),
            lookups: Mutex::default(),
            wire: Mutex::default(),
            pending_log: Mutex::default(),
            tracks,
            waiting: Mutex::default(),
            asked: AtomicU64::new(activity::NO_SECOND),
            activity: Mutex::new(activity::Activity::new(tracks)),
            handing_over: AtomicBool::new(false),
            log_ready: Notify::new(),
            flushes: Mutex::default(),
            flush_wanted: Notify::new(),
            uncached_answers: AtomicBool::new(false),
            chain: Mutex::new(None),
            chains: AtomicU64::new(0),
            stand_ins: Mutex::default(),
            direct_answers: Mutex::default(),
            tool_answers: Mutex::default(),
            kept: Mutex::default(),
            tunnels: tunnels::Tunnels::default(),
            resolver: resolver::Resolver::default(),
            messengers: crate::messengers::Messengers::bundled(),
            proxies: Mutex::default(),
            held_back: Mutex::default(),
            blocks: Mutex::default(),
            blocking_set: AtomicU64::new(0),
        }
    }

    const UID: u32 = 10_123;

    fn open_flow(shared: &Shared, destination: SocketAddr) -> Opened {
        open_flow_of(shared, destination, UID)
    }

    /// A flow of the app with `uid` to `destination`, opened and recorded as the engine does.
    fn open_flow_of(shared: &Shared, destination: SocketAddr, uid: u32) -> Opened {
        let Begun {
            id,
            name,
            named_by,
            network,
            held_until,
        } = shared.begin(destination, Some(uid));
        let by_dns = (named_by == NamedBy::Dns)
            .then_some(name.as_deref())
            .flatten();
        let (dns, resolver) = shared.dns_use(destination, by_dns);
        shared.record(Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination,
            uid: Some(uid),
            outcome: Outcome::Opened,
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
            blocked: None,
        });
        Opened {
            id,
            port: destination.port(),
            destination,
            sniffs: true,
            dns,
            uid: Some(uid),
            dns_held_until: held_until,
        }
    }

    fn hello(name: &str, ech: bool) -> Hello {
        Hello {
            name: name.into(),
            ech,
        }
    }

    #[test]
    fn hellos_on_dns_named_flows_are_counted_with_how_many_name_another_server() {
        let shared = shared();
        let now = Instant::now();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        lock(&shared.names).insert(
            asked.ip(),
            None,
            "www.example.com",
            60,
            (now, shared.clock.since_boot()),
        );
        lock(&shared.names).insert_public("cover.example", None, 60, now);
        let same = open_flow(&shared, asked);
        let other = open_flow(&shared, asked);
        let hidden = open_flow(&shared, asked);
        let unnamed = open_flow(&shared, SocketAddr::from(([203, 0, 113, 9], 443)));

        // Case and a trailing dot do not make another name.
        shared.hello(same, &hello("WWW.Example.com.", false), NamedBy::Tls);
        shared.hello(other, &hello("cdn-tenant.example", false), NamedBy::Tls);
        // An ECH public name differs by design: left out.
        shared.hello(hidden, &hello("cover.example", true), NamedBy::Tls);
        // A flow no DNS answer named is not counted.
        shared.hello(unnamed, &hello("quic.example", false), NamedBy::Quic);

        assert_eq!(shared.counters.snapshot()[20..22], [2, 1]);
    }

    /// Finding 20: the connection's own name names the flow, and a DNS name it differs from stays beside
    /// it, in the flow kept and in the log's; an ECH public name names nothing, and a DNS name stays the
    /// flow's then; a flow keeps its first hello's name.
    #[test]
    fn a_hello_names_a_flow_and_a_dns_name_it_differs_from_stays_beside_it() {
        let shared = shared();
        let now = Instant::now();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        lock(&shared.names).insert(
            asked.ip(),
            None,
            "www.example.com",
            60,
            (now, shared.clock.since_boot()),
        );
        lock(&shared.names).insert_public("cover.example", None, 60, now);
        let by_dns = open_flow(&shared, asked);
        let same = open_flow(&shared, asked);
        let by_quic = open_flow(&shared, SocketAddr::from(([203, 0, 113, 9], 443)));
        let hidden = open_flow(&shared, SocketAddr::from(([203, 0, 113, 10], 443)));
        let hidden_after_dns = open_flow(&shared, asked);

        // The connection's own name comes first; the DNS name it differs from stays beside it.
        shared.hello(by_dns, &hello("other.example", false), NamedBy::Tls);
        // A later hello does not rename it.
        shared.hello(by_dns, &hello("late.example", false), NamedBy::Quic);
        // The same name, in another case and with a trailing dot: nothing beside it, and the flow's name
        // written in lower case without the dot.
        shared.hello(same, &hello("WWW.Example.com.", false), NamedBy::Tls);
        // A QUIC name names a flow without one; ECH offered, perhaps GREASE, does not stop it.
        shared.hello(by_quic, &hello("quic.example", true), NamedBy::Quic);
        // A public name under ECH never names a flow, and the real name stays as DNS gave it.
        shared.hello(hidden, &hello("cover.example", true), NamedBy::Tls);
        shared.hello(
            hidden_after_dns,
            &hello("cover.example", true),
            NamedBy::Quic,
        );

        let expected = [
            (
                Some("other.example"),
                NamedBy::Tls,
                Some("www.example.com"),
                Ech::Absent,
            ),
            (Some("www.example.com"), NamedBy::Tls, None, Ech::Absent),
            (Some("quic.example"), NamedBy::Quic, None, Ech::Offered),
            (None, NamedBy::Unknown, None, Ech::Hidden),
            (Some("www.example.com"), NamedBy::Dns, None, Ech::Hidden),
        ];
        let seen = |flow: &Flow| {
            (
                flow.name.clone(),
                flow.named_by,
                flow.dns_name.clone(),
                flow.ech,
            )
        };
        let owned = |e: &(Option<&str>, NamedBy, Option<&str>, Ech)| {
            (e.0.map(str::to_owned), e.1, e.2.map(str::to_owned), e.3)
        };
        let expected: Vec<_> = expected.iter().map(owned).collect();
        let kept: Vec<_> = lock(&shared.flows).iter().map(seen).collect();
        assert_eq!(kept, expected);
        let live = lock(&shared.live);
        let logged: Vec<_> = (1..=5).map(|id| seen(&live[&id].flow)).collect();
        assert_eq!(logged, expected);
        drop(live);
        // TLS and QUIC names read, QUIC unread, ECH offered, ECH hidden.
        assert_eq!(shared.counters.snapshot()[11..16], [3, 3, 0, 3, 2]);
    }

    /// Review 1 of W5's first part, names, finding 1: an ECH public name never names a flow wherever the network part
    /// saw it in an ECH configuration. From Android's resolver it hides names in every app's flows; from
    /// an app's own plain resolver, past the network part's, in that app's flows only, so that no app hides another's
    /// names (ADR 0038): there another app's hello names its flow.
    #[test]
    fn an_ech_public_name_hides_the_name_in_the_flows_of_the_answers_scope() {
        const OTHER: u32 = 10_456;
        let answer = crate::dns::tests::with_https("cover.example");
        let address = SocketAddr::from(([93, 184, 216, 34], 443));
        for scope in [None, Some(UID)] {
            let shared = shared();
            shared.learn(&answer, scope);
            let own = open_flow(&shared, address);
            let other = open_flow_of(&shared, address, OTHER);
            shared.hello(own, &hello("cover.example", true), NamedBy::Tls);
            shared.hello(other, &hello("cover.example", true), NamedBy::Tls);
            let live = lock(&shared.live);
            let seen = |id: u64| {
                let flow = &live[&id].flow;
                (
                    flow.name.as_deref(),
                    flow.named_by,
                    flow.dns_name.as_deref(),
                    flow.ech,
                )
            };
            let hidden = (Some("www.example.com"), NamedBy::Dns, None, Ech::Hidden);
            assert_eq!(seen(own.id), hidden, "{scope:?}");
            let others = if scope.is_none() {
                hidden
            } else {
                (Some("cover.example"), NamedBy::Tls, None, Ech::Offered)
            };
            assert_eq!(seen(other.id), others, "{scope:?}");
        }
    }

    /// A DNS name stands beside the connection's own only while it is current (review 1 of W5's first
    /// part, engine finding 7, names finding 9): an answer's while it is held in time since the phone
    /// started, so that one kept through a night shows no difference that is only its age, though it
    /// still names a flow that sends no name; a stand-in's, which names that address alone, always.
    #[test]
    fn a_dns_name_stands_beside_the_connections_own_only_while_current() {
        let clock = clock::ManualClock::at(1_794_873_600_000);
        let mut shared = shared();
        shared.clock = clock.clone();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        let when = (Instant::now(), shared.clock.since_boot());
        lock(&shared.names).insert(asked.ip(), None, "www.example.com", 60, when);
        let stand_in = SocketAddr::from((lock(&shared.stand_ins).address("chained.example"), 443));
        let fresh = open_flow(&shared, asked);
        shared.hello(fresh, &hello("other.example", false), NamedBy::Tls);
        // A night's sleep: the monotonic clock stood still, the time since start did not.
        clock.pass(8 * 3_600_000);
        let after_the_night = open_flow(&shared, asked);
        let unnamed_after = open_flow(&shared, asked);
        let by_stand_in = open_flow(&shared, stand_in);
        shared.hello(
            after_the_night,
            &hello("other.example", false),
            NamedBy::Tls,
        );
        shared.hello(by_stand_in, &hello("other.example", false), NamedBy::Tls);
        let live = lock(&shared.live);
        let names = |id: u64| {
            let flow = &live[&id].flow;
            (
                flow.name.as_deref(),
                flow.named_by,
                flow.dns_name.as_deref(),
            )
        };
        assert_eq!(
            names(fresh.id),
            (Some("other.example"), NamedBy::Tls, Some("www.example.com"))
        );
        assert_eq!(
            names(after_the_night.id),
            (Some("other.example"), NamedBy::Tls, None)
        );
        assert_eq!(
            names(unnamed_after.id),
            (Some("www.example.com"), NamedBy::Dns, None)
        );
        assert_eq!(
            names(by_stand_in.id),
            (Some("other.example"), NamedBy::Tls, Some("chained.example"))
        );
    }

    /// The answer that named the flow decides whether its name stands beside the hello's (review 2 of W5's
    /// first part): another lookup that re-points the address to another name between the flow's start
    /// and its hello, as on an address that serves many names, does not drop it.
    #[test]
    fn a_later_answer_for_the_address_leaves_the_flows_dns_name_beside() {
        let shared = shared();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        let when = (Instant::now(), shared.clock.since_boot());
        lock(&shared.names).insert(asked.ip(), None, "www.example.com", 60, when);
        let opened = open_flow(&shared, asked);
        lock(&shared.names).insert(asked.ip(), None, "cdn-tenant.example", 60, when);
        shared.hello(opened, &hello("other.example", false), NamedBy::Tls);
        let live = lock(&shared.live);
        let flow = &live[&opened.id].flow;
        assert_eq!(
            (flow.name.as_deref(), flow.dns_name.as_deref()),
            (Some("other.example"), Some("www.example.com"))
        );
    }

    /// A hello's name is read without its trailing dot for ECH's public names and the known resolvers, as
    /// for the flow's name (review 2 of W5's first part, of the fixes, nit 5).
    #[test]
    fn a_hellos_name_with_a_trailing_dot_is_read_as_without() {
        let shared = shared();
        let now = Instant::now();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        let when = (now, shared.clock.since_boot());
        lock(&shared.names).insert(asked.ip(), None, "www.example.com", 60, when);
        lock(&shared.names).insert_public("cover.example", None, 60, now);
        let hidden = open_flow(&shared, asked);
        shared.hello(hidden, &hello("cover.example.", true), NamedBy::Tls);
        let doh = open_flow(&shared, SocketAddr::from(([198, 51, 100, 2], 443)));
        shared.hello(doh, &hello("doh.sample.example.", false), NamedBy::Tls);
        // A resolver's host that is also an ECH public name: the hello renames nothing, and marks it.
        lock(&shared.names).insert_public("doh.sample.example", None, 60, now);
        let hidden_doh = open_flow(&shared, SocketAddr::from(([198, 51, 100, 3], 443)));
        shared.hello(
            hidden_doh,
            &hello("doh.sample.example.", true),
            NamedBy::Tls,
        );
        let live = lock(&shared.live);
        let first = &live[&hidden.id].flow;
        assert_eq!(
            (first.name.as_deref(), first.ech),
            (Some("www.example.com"), Ech::Hidden)
        );
        for id in [doh.id, hidden_doh.id] {
            let flow = &live[&id].flow;
            assert_eq!(
                (flow.dns, flow.resolver.as_deref()),
                (DnsUse::Encrypted, Some("sample"))
            );
        }
        assert_eq!(live[&hidden_doh.id].flow.ech, Ech::Hidden);
    }

    /// The mark of an app's own encrypted DNS follows the name that names the flow (review 1 of W5's
    /// first part, names, finding 10): given by a resolver's host name in a DNS answer alone, it goes
    /// when the hello names another server, and the count with it; given by the resolver's address, it
    /// stays; and a hello naming a resolver's host gives it.
    #[test]
    fn the_mark_of_an_apps_own_dns_follows_the_name_that_names_the_flow() {
        let shared = shared();
        let when = (Instant::now(), shared.clock.since_boot());
        let elsewhere = SocketAddr::from(([198, 51, 100, 7], 443));
        let resolver = SocketAddr::from(([192, 0, 2, 53], 443));
        let web = SocketAddr::from(([198, 51, 100, 8], 443));
        for (address, name) in [
            (elsewhere, "doh.sample.example"),
            (resolver, "doh.sample.example"),
            (web, "www.example.com"),
        ] {
            lock(&shared.names).insert(address.ip(), None, name, 60, when);
        }
        let by_name = open_flow(&shared, elsewhere);
        let by_address = open_flow(&shared, resolver);
        let to_web = open_flow(&shared, web);
        assert_eq!(
            shared.counters.snapshot()[17],
            2,
            "two marked as they opened"
        );
        shared.hello(by_name, &hello("www.example.com", false), NamedBy::Tls);
        shared.hello(by_address, &hello("www.example.com", false), NamedBy::Tls);
        shared.hello(to_web, &hello("doh.sample.example", false), NamedBy::Tls);
        let live = lock(&shared.live);
        let marks: Vec<_> = [by_name, by_address, to_web]
            .iter()
            .map(|o| {
                let flow = &live[&o.id].flow;
                (flow.dns, flow.resolver.as_deref())
            })
            .collect();
        assert_eq!(
            marks,
            vec![
                (DnsUse::None, None),
                (DnsUse::Encrypted, Some("sample")),
                (DnsUse::Encrypted, Some("sample")),
            ]
        );
        assert_eq!(
            shared.counters.snapshot()[17],
            2,
            "one taken back, one given"
        );
    }

    #[test]
    fn an_apps_own_dns_is_recognised_by_port_address_or_name() {
        let shared = shared();
        let now = Instant::now();
        let at = |ip: [u8; 4], port| SocketAddr::from((ip, port));
        // A resolver of the app's own, by address: its answer names only this app's flows.
        let plain = open_flow(&shared, at([192, 0, 2, 53], 53));
        shared.learn(&dns_answer("own.example", [203, 0, 113, 20]), Some(UID));
        let named_by_own = open_flow(&shared, at([203, 0, 113, 20], 443));
        // Android's resolver through the network part: not the app's own.
        let tunnel = open_flow(
            &shared,
            SocketAddr::new(IpAddr::V4(Addresses::COMMON.dns4), 53),
        );
        // DNS over TLS anywhere, and DNS over HTTPS to a known address, or to a known name in the hello.
        let dot = open_flow(&shared, at([198, 51, 100, 1], 853));
        let doh = open_flow(&shared, at([192, 0, 2, 53], 443));
        let doh_by_name = open_flow(&shared, at([198, 51, 100, 2], 443));
        shared.hello(
            doh_by_name,
            &hello("doh.sample.example", false),
            NamedBy::Tls,
        );
        let web = open_flow(&shared, at([198, 51, 100, 3], 443));
        shared.hello(web, &hello("www.example.com", false), NamedBy::Tls);
        let _ = (plain, named_by_own, tunnel, dot, doh);

        let flows = lock(&shared.flows);
        let seen: Vec<_> = flows
            .iter()
            .map(|f| (f.destination.port(), f.dns, f.resolver.as_deref()))
            .collect();
        assert_eq!(
            seen,
            vec![
                (53, DnsUse::Plain, Some("sample")),
                (443, DnsUse::None, None),
                (53, DnsUse::None, None),
                (853, DnsUse::Encrypted, None),
                (443, DnsUse::Encrypted, Some("sample")),
                (443, DnsUse::Encrypted, Some("sample")),
                (443, DnsUse::None, None),
            ]
        );
        assert_eq!(flows[1].name.as_deref(), Some("own.example"));
        assert_eq!(flows[1].named_by, NamedBy::Dns);
        drop(flows);
        // Plain, encrypted.
        assert_eq!(shared.counters.snapshot()[16..18], [1, 3]);
        // Another app's flow to the same address is not named by that answer.
        assert_eq!(
            lock(&shared.names).get(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
                Some(10_456),
                now
            ),
            None
        );
    }

    #[test]
    fn the_log_gets_segments_of_open_flows_their_ends_and_lookups() {
        // 2026-11-17, 22:10 UTC.
        let clock = clock::ManualClock::at(1_794_873_600_000 + (22 * 60 + 10) * 60_000);
        let mut shared = shared();
        shared.clock = clock.clone();
        let flow = |id: u64, destination: SocketAddr, outcome| Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination,
            uid: Some(UID),
            outcome,
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
        };
        let server = SocketAddr::from(([198, 51, 100, 9], 443));
        let Some(bytes) = shared.record(flow(1, server, Outcome::Opened)) else {
            unreachable!("an open flow is live")
        };
        assert!(shared.record(flow(2, server, Outcome::Refused)).is_none());
        assert!(
            shared
                .record(flow(
                    3,
                    SocketAddr::new(IpAddr::V4(Addresses::COMMON.dns4), 53),
                    Outcome::Opened
                ))
                .is_none()
        );
        shared.lookup(Some(UID), 70);
        shared.lookup(Some(UID), 72);
        shared.lookup_answered(Some(UID), 300);
        bytes.up(&shared, 100, 140);
        bytes.down(&shared, 5_000, 5_200);
        // A quarter hour passes: the next count cuts the open flow's first segment, and the lookups.
        clock.pass(5 * 60_000);
        bytes.down(&shared, 700, 0);
        shared.finish(1);
        shared.finish(1);
        let records = std::mem::take(&mut *lock(&shared.pending_log));
        let segments: Vec<_> = records
            .iter()
            .map(|r| match r {
                Record::Segment {
                    flow,
                    bytes,
                    continues,
                    ..
                } => (flow.id, bytes[0], bytes[1], *continues),
                Record::Lookups {
                    count,
                    uid,
                    wire_up,
                    wire_down,
                    ..
                } if *wire_up == 142 && *wire_down == 300 => {
                    (u64::from(uid.unwrap_or(0)), 0, u64::from(*count), false)
                }
                Record::Lookups { .. } => (0, 0, 0, true),
            })
            .collect();
        assert_eq!(
            segments,
            vec![
                (2, 0, 0, false),
                (1, 100, 5_000, true),
                (u64::from(UID), 0, 2, false),
                (1, 0, 700, false),
            ]
        );
        let wire: Vec<_> = records
            .iter()
            .filter_map(|r| match r {
                Record::Segment { flow, bytes, .. } if flow.id == 1 => Some([bytes[2], bytes[3]]),
                _ => None,
            })
            .collect();
        assert_eq!(wire, vec![[140, 5_200], [0, 0]]);
        assert!(lock(&shared.live).is_empty());
        assert!(shared.take_log().is_none());
    }

    /// Android names the app of flows to one port only after `delay`, as in deep idle.
    struct SlowOwner {
        port: u16,
        delay: Duration,
    }

    impl Platform for SlowOwner {
        fn owner(&self, _: u8, _: SocketAddr, remote: SocketAddr) -> Option<u32> {
            if remote.port() == self.port {
                std::thread::sleep(self.delay);
            }
            Some(UID)
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {}
    }

    /// One packet from the fake tunnel's app side, as (source port, payload).
    async fn answer(app: &tokio::net::UnixDatagram) -> io::Result<(u16, Vec<u8>)> {
        let mut buffer = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(3), app.recv(&mut buffer))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let parsed =
            packet::parse(&buffer[..n]).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let payload =
            packet::udp_payload(&buffer[..n], &parsed).ok_or(io::ErrorKind::InvalidData)?;
        Ok((parsed.source.port(), payload.to_vec()))
    }

    /// A new UDP flow opens off the event loop: while Android takes half a second to name one flow's
    /// app, another flow's datagram goes out and its answer comes back at once, and the slow flow's
    /// datagrams wait for its socket, then leave in the order the app sent them.
    #[tokio::test(flavor = "current_thread")]
    async fn a_udp_flow_that_opens_slowly_holds_up_no_other() -> io::Result<()> {
        let slow = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let fast = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let (to_slow, to_fast) = (slow.local_addr()?, fast.local_addr()?);
        for server in [Arc::clone(&slow), Arc::clone(&fast)] {
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                    let _ = server.send_to(&buffer[..n], from).await;
                }
            });
        }
        let delay = Duration::from_millis(600);
        let shared = Arc::new(shared_with(Arc::new(SlowOwner {
            port: to_slow.port(),
            delay,
        })));
        // A pair of datagram sockets stands in for the tunnel: one read is one packet.
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

        let me = SocketAddr::from(([10, 215, 173, 1], 40_000));
        let other = SocketAddr::from(([10, 215, 173, 1], 40_001));
        let started = Instant::now();
        for (from, to, payload) in [
            (me, to_slow, &b"slow 1"[..]),
            (me, to_slow, b"slow 2"),
            (other, to_fast, b"fast"),
        ] {
            let Some(packet) = packet::udp(from, to, payload) else {
                unreachable!("a small datagram")
            };
            app.send(&packet).await?;
        }
        let (port, payload) = answer(&app).await?;
        assert_eq!((port, payload.as_slice()), (to_fast.port(), &b"fast"[..]));
        assert!(
            started.elapsed() < delay / 2,
            "the fast flow waited {:?}",
            started.elapsed()
        );
        let (_, first) = answer(&app).await?;
        let (_, second) = answer(&app).await?;
        assert_eq!(
            (first.as_slice(), second.as_slice()),
            (&b"slow 1"[..], &b"slow 2"[..])
        );
        assert!(started.elapsed() >= delay);
        Ok(())
    }

    /// A night's sleep on a UDP flow through the engine's loop and its mapping (finding 4): the evening's
    /// datagram and answer stay in their quarter hour, 22:00 to 22:15, when the morning's datagram from
    /// the app ends the sleep, or the server's answer does, and the morning's bytes go in the segment of
    /// 06:15. The app's datagram is counted by the loop as it leaves; the server's by the mapping's task,
    /// as it comes in.
    #[tokio::test(flavor = "current_thread")]
    async fn a_sleep_ended_by_a_udp_datagram_either_way_is_cut_before_it_is_counted()
    -> io::Result<()> {
        for apps_first in [true, false] {
            let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let to = server.local_addr()?;
            let evening = 1_794_873_600_000 + (22 * 60 + 10) * 60_000;
            let morning = evening + (8 * 60 + 6) * 60_000;
            let clock = clock::ManualClock::at(evening);
            let mut shared = shared();
            shared.clock = clock.clone();
            let shared = Arc::new(shared);
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
            let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
            let datagram =
                |payload: &[u8]| packet::udp(me, to, payload).ok_or(io::ErrorKind::InvalidData);
            let mut buffer = [0u8; 512];
            app.send(&datagram(b"evening")?).await?;
            let (_, mapping) = server.recv_from(&mut buffer).await?;
            server.send_to(b"answer", mapping).await?;
            answer(&app).await?;
            let Some(bytes) = lock(&shared.live)
                .values()
                .next()
                .map(|l| Arc::clone(&l.bytes))
            else {
                unreachable!("the flow is live")
            };
            let evening_counts = bytes.now();
            assert_eq!(evening_counts[..2], [7, 6]);

            clock.set(morning);
            let morning_counts = if apps_first {
                let sent = datagram(b"good morning")?;
                app.send(&sent).await?;
                server.recv_from(&mut buffer).await?;
                [12, 0, sent.len() as u64, 0]
            } else {
                server.send_to(b"push message", mapping).await?;
                let (_, payload) = answer(&app).await?;
                assert_eq!(payload, b"push message");
                [0, 12, 0, 12 + 28]
            };
            let written: Vec<_> = lock(&shared.pending_log)
                .iter()
                .map(|r| match r {
                    Record::Segment {
                        start, end, bytes, ..
                    } => (*start, *end, *bytes),
                    Record::Lookups { .. } => (0, 0, [0; 4]),
                })
                .collect();
            let quarter = |t: u64| t / logbook::SEGMENT_MS * logbook::SEGMENT_MS;
            assert_eq!(
                written,
                vec![(
                    evening,
                    quarter(evening) + logbook::SEGMENT_MS,
                    evening_counts
                )],
                "the app's first: {apps_first}"
            );
            let live = lock(&shared.live);
            let Some(open) = live.values().next() else {
                unreachable!("the flow is live")
            };
            assert_eq!(open.start, quarter(morning));
            assert_eq!(logbook::delta(open.bytes.now(), open.base), morning_counts);
        }
        Ok(())
    }

    /// The engine's sweep drops an app's own tables of names once every name in them has expired (review 4
    /// of W5's first part, nit 3): here the sweep runs at every read of the tunnel, and one datagram,
    /// whatever it holds, makes it run over a name learned three hours ago.
    #[tokio::test(flavor = "current_thread")]
    async fn the_sweep_drops_an_apps_tables_of_expired_names() -> io::Result<()> {
        let mut shared = shared();
        shared.limits.sweep_every = Duration::ZERO;
        let Some(then) = Instant::now().checked_sub(Duration::from_hours(3)) else {
            unreachable!("an instant three hours back")
        };
        let when = (then, shared.clock.since_boot());
        lock(&shared.names).insert(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            Some(UID),
            "own.example",
            60,
            when,
        );
        assert_eq!(lock(&shared.names).len(), 1);
        let shared = Arc::new(shared);
        let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
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
        app_end.send(b"not a packet")?;
        for _ in 0..200 {
            if lock(&shared.names).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(lock(&shared.names).is_empty(), "the expired table stayed");
        Ok(())
    }

    /// Unit 12b: a tunnel handed to the running engine takes the old one's place for reading and for
    /// the tasks that write to the apps, here a mapping's, which began before; a datagram still queued
    /// on the old tunnel when the new one comes is handled first, on the mapping it had, and its answer
    /// comes through the new one; and the old tunnel is closed. The engine's tasks run on this thread,
    /// so none of them runs between the datagram queued and the tunnel handed over: the event loop
    /// finds both at once, as when Android moved the routes while it was busy.
    #[tokio::test(flavor = "current_thread")]
    async fn a_new_tunnel_takes_over_after_what_is_queued_on_the_old_one() -> io::Result<()> {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let to = server.local_addr()?;
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                let _ = server.send_to(&buffer[..n], from).await;
            }
        });
        let shared = Arc::new(shared());
        // Two pairs of datagram sockets stand in for the old tunnel and the new one.
        let (old_engine, old_app) = std::os::unix::net::UnixDatagram::pair()?;
        let (new_engine, new_app) = std::os::unix::net::UnixDatagram::pair()?;
        for end in [&old_engine, &old_app, &new_engine, &new_app] {
            end.set_nonblocking(true)?;
        }
        let (_stop, stop) = watch::channel(false);
        let (_network, network) = watch::channel(0);
        let (swaps, swapped) = mpsc::unbounded_channel();
        tokio::spawn(run(
            Tun::new(OwnedFd::from(old_engine))?,
            1500,
            Arc::clone(&shared),
            stop,
            network,
            swapped,
        ));
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let datagram =
            |payload: &[u8]| packet::udp(me, to, payload).ok_or(io::ErrorKind::InvalidData);
        let old_app = tokio::net::UnixDatagram::from_std(old_app)?;
        let new_app = tokio::net::UnixDatagram::from_std(new_app)?;
        old_app.send(&datagram(b"before")?).await?;
        assert_eq!(answer(&old_app).await?, (to.port(), b"before".to_vec()));

        // No await between the two.
        old_app.try_send(&datagram(b"queued")?)?;
        let (done, taken) = std::sync::mpsc::sync_channel(1);
        swaps
            .send((OwnedFd::from(new_engine), done))
            .map_err(|_| io::Error::other("the engine ended"))?;
        assert_eq!(
            answer(&new_app).await?,
            (to.port(), b"queued".to_vec()),
            "the datagram queued on the old tunnel"
        );
        let mut said = taken.try_recv();
        for _ in 0..100 {
            if said.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
            said = taken.try_recv();
        }
        assert!(matches!(said, Ok(Ok(()))), "the engine said {said:?}");
        let late = old_app.try_send(&datagram(b"late")?).map_err(|e| e.kind());
        assert_eq!(
            late,
            Err(io::ErrorKind::ConnectionRefused),
            "the old tunnel is still open"
        );

        new_app.send(&datagram(b"after")?).await?;
        assert_eq!(answer(&new_app).await?, (to.port(), b"after".to_vec()));
        let counters = shared.counters.snapshot();
        assert_eq!(
            (counters[9], counters[24]),
            (3, 1),
            "packets in, and mappings"
        );
        Ok(())
    }

    /// A task's write waiting for the old tunnel to take a packet when the new one comes goes to the new
    /// one, and lets go of the old one, which closes. Here the app does not read the old tunnel, whose
    /// small buffer fills with a mapping's answers until the mapping's write waits; its answers from
    /// then on reach the app through the new tunnel, in order.
    #[tokio::test(flavor = "current_thread")]
    async fn a_write_waiting_on_the_old_tunnel_goes_to_the_new_one() -> io::Result<()> {
        const SENT: u8 = 32;
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let to = server.local_addr()?;
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                let _ = server.send_to(&buffer[..n], from).await;
            }
        });
        let shared = Arc::new(shared());
        let (old_engine, old_app) = std::os::unix::net::UnixDatagram::pair()?;
        let (new_engine, new_app) = std::os::unix::net::UnixDatagram::pair()?;
        for end in [&old_engine, &old_app, &new_engine, &new_app] {
            end.set_nonblocking(true)?;
        }
        // The kernel's smallest: a few answers the app does not read fill it.
        socket2::SockRef::from(&old_engine).set_send_buffer_size(1)?;
        let (_stop, stop) = watch::channel(false);
        let (_network, network) = watch::channel(0);
        let (swaps, swapped) = mpsc::unbounded_channel();
        tokio::spawn(run(
            Tun::new(OwnedFd::from(old_engine))?,
            1500,
            Arc::clone(&shared),
            stop,
            network,
            swapped,
        ));
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let datagram =
            |payload: &[u8]| packet::udp(me, to, payload).ok_or(io::ErrorKind::InvalidData);
        let old_app = tokio::net::UnixDatagram::from_std(old_app)?;
        let new_app = tokio::net::UnixDatagram::from_std(new_app)?;
        old_app.send(&datagram(&[0])?).await?;
        assert_eq!(answer(&old_app).await?, (to.port(), vec![0]));
        for n in 1..=SENT {
            old_app.send(&datagram(&[n])?).await?;
            tokio::task::yield_now().await;
        }
        // Until the answers stop coming: the mapping's write waits.
        let mut out = shared.counters.snapshot()[10];
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = shared.counters.snapshot()[10];
            if now == out {
                break;
            }
            out = now;
        }
        let taken = u8::try_from(out - 1).unwrap_or(SENT);
        assert!(
            taken < SENT,
            "the old tunnel took every answer: no write waited"
        );

        let (done, _taken) = std::sync::mpsc::sync_channel(1);
        swaps
            .send((OwnedFd::from(new_engine), done))
            .map_err(|_| io::Error::other("the engine ended"))?;
        for n in taken + 1..=SENT {
            assert_eq!(
                answer(&new_app).await?,
                (to.port(), vec![n]),
                "the answers after the old tunnel's {taken}"
            );
        }
        let late = old_app.try_send(&datagram(b"late")?).map_err(|e| e.kind());
        assert_eq!(
            late,
            Err(io::ErrorKind::ConnectionRefused),
            "the old tunnel is still open"
        );
        Ok(())
    }

    /// How the old tunnel refuses the engine's writes in a [`Gap`].
    #[derive(Clone, Copy)]
    enum Refusal {
        /// With `EIO`, as a tun device whose interface is down does, which only a new tunnel cures: a
        /// unit test cannot make a tun device, so the tunnel is told to refuse (`Tun::refuse_writes`).
        Down,
        /// With another error, which a new tunnel does not cure: here `EPIPE`, as the app's end has shut
        /// its reading, while the app can still send.
        Other,
    }

    /// What the gap between Android's reset of the old interface and the swap is made of here: an
    /// engine whose old tunnel refuses its writes, and waits up to `wait` for a new one; a server that
    /// echoes; the new tunnel's app end; and the swaps.
    struct Gap {
        to: SocketAddr,
        /// Written to directly: the app only sends through the old tunnel.
        old_app: std::os::unix::net::UnixDatagram,
        new_app: tokio::net::UnixDatagram,
        new_engine: Option<OwnedFd>,
        swaps: mpsc::UnboundedSender<Swap>,
        shared: Arc<Shared>,
        /// The loop's stop and the network's changes, which it runs as long as these live.
        _signals: (watch::Sender<bool>, watch::Sender<u64>),
    }

    impl Gap {
        async fn new(wait: Duration, refusal: Refusal) -> io::Result<Self> {
            let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let to = server.local_addr()?;
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                    let _ = server.send_to(&buffer[..n], from).await;
                }
            });
            let shared = Arc::new(shared());
            let (old_engine, old_app) = std::os::unix::net::UnixDatagram::pair()?;
            let (new_engine, new_app) = std::os::unix::net::UnixDatagram::pair()?;
            for end in [&old_engine, &old_app, &new_engine, &new_app] {
                end.set_nonblocking(true)?;
            }
            let tun = Tun::waiting(OwnedFd::from(old_engine), wait)?;
            match refusal {
                Refusal::Down => tun.refuse_writes(nix::libc::EIO),
                Refusal::Other => old_app.shutdown(std::net::Shutdown::Read)?,
            }
            let (stopping, stop) = watch::channel(false);
            let (moving, network) = watch::channel(0);
            let (swaps, swapped) = mpsc::unbounded_channel();
            tokio::spawn(run(tun, 1500, Arc::clone(&shared), stop, network, swapped));
            Ok(Self {
                to,
                old_app,
                new_app: tokio::net::UnixDatagram::from_std(new_app)?,
                new_engine: Some(OwnedFd::from(new_engine)),
                swaps,
                shared,
                _signals: (stopping, moving),
            })
        }

        /// Through the old tunnel: a SYN, which the engine's loop answers with a reset itself (no
        /// listener here), and a datagram, whose mapping's task writes the server's answer.
        fn send_both(&self) -> io::Result<()> {
            let mut syn = Vec::new();
            etherparse::PacketBuilder::ipv4([10, 1, 10, 1], [198, 51, 100, 9], 64)
                .tcp(40_001, 80, 1_000, 65_535)
                .syn()
                .write(&mut syn, &[])
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            self.old_app.send(&syn)?;
            let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
            let datagram =
                packet::udp(me, self.to, b"in the gap").ok_or(io::ErrorKind::InvalidData)?;
            self.old_app.send(&datagram)?;
            Ok(())
        }

        fn swap(&mut self) -> io::Result<()> {
            let (done, _taken) = std::sync::mpsc::sync_channel(1);
            let fd = self.new_engine.take().ok_or(io::ErrorKind::NotFound)?;
            self.swaps
                .send((fd, done))
                .map_err(|_| io::Error::other("the engine ended"))
        }

        /// What reaches the app through the new tunnel within `within`: a reset, and UDP payloads.
        async fn heard(&self, within: Duration) -> (bool, Vec<Vec<u8>>) {
            let (mut reset, mut payloads) = (false, Vec::new());
            let mut buffer = vec![0u8; 2048];
            while let Ok(Ok(n)) = tokio::time::timeout(within, self.new_app.recv(&mut buffer)).await
            {
                let Ok(parsed) = packet::parse(&buffer[..n]) else {
                    continue;
                };
                if parsed.protocol == TCP {
                    reset |= packet::tcp_flags(&buffer[..n], &parsed) & packet::RST != 0;
                } else if let Some(payload) = packet::udp_payload(&buffer[..n], &parsed) {
                    payloads.push(payload.to_vec());
                }
            }
            (reset, payloads)
        }
    }

    /// Unit 12b, writes in the gap: what the engine writes while the old tunnel refuses its writes, as
    /// once Android has reset the old interface and before the new tunnel is handed over, waits for the
    /// new one and goes there when it comes within `Limits::tunnel_wait`: the loop's own reset to a
    /// SYN, and a mapping's answer. The loop's write waits in a task of its own, so the loop reads the
    /// datagram after the SYN, and its mapping reaches the server, meanwhile.
    #[tokio::test(flavor = "current_thread")]
    async fn writes_refused_in_the_gap_go_to_the_tunnel_that_comes_within_the_wait()
    -> io::Result<()> {
        let mut gap = Gap::new(Duration::from_secs(2), Refusal::Down).await?;
        gap.send_both()?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            gap.shared.counters.snapshot()[9],
            2,
            "the loop read on while its reset waited"
        );
        gap.swap()?;
        let (reset, payloads) = gap.heard(Duration::from_millis(500)).await;
        assert!(reset, "the loop's reset to the SYN was lost");
        assert_eq!(
            payloads,
            vec![b"in the gap".to_vec()],
            "the mapping's answer"
        );
        assert_eq!(gap.shared.counters.snapshot()[10], 2, "packets out");
        Ok(())
    }

    /// The same, with no new tunnel within the wait: both writes are dropped once it ends, as before
    /// the wait, and a tunnel that comes later carries only what comes after.
    #[tokio::test(flavor = "current_thread")]
    async fn writes_refused_in_the_gap_are_dropped_when_no_tunnel_comes_within_the_wait()
    -> io::Result<()> {
        let mut gap = Gap::new(Duration::from_millis(100), Refusal::Down).await?;
        gap.send_both()?;
        tokio::time::sleep(Duration::from_millis(400)).await;
        gap.swap()?;
        let (reset, payloads) = gap.heard(Duration::from_millis(300)).await;
        assert!(
            !reset && payloads.is_empty(),
            "written after the wait: {reset}, {payloads:?}"
        );
        assert_eq!(gap.shared.counters.snapshot()[10], 0, "packets out");
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let after = packet::udp(me, gap.to, b"after").ok_or(io::ErrorKind::InvalidData)?;
        gap.new_app.send(&after).await?;
        assert_eq!(
            answer(&gap.new_app).await?,
            (gap.to.port(), b"after".to_vec())
        );
        Ok(())
    }

    /// A write the old tunnel refuses with an error a new tunnel does not cure, as `ENOMEM` or `ENOBUFS`
    /// under memory pressure, is dropped at once, as before the wait: here `EPIPE`, with a wait of 2 s
    /// and a new tunnel that comes within it, through which neither the loop's reset nor the mapping's
    /// answer comes. The loop reads on all the same.
    #[tokio::test(flavor = "current_thread")]
    async fn a_write_refused_with_another_error_is_dropped_at_once() -> io::Result<()> {
        let mut gap = Gap::new(Duration::from_secs(2), Refusal::Other).await?;
        gap.send_both()?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(gap.shared.counters.snapshot()[9], 2, "the loop read on");
        gap.swap()?;
        let (reset, payloads) = gap.heard(Duration::from_millis(500)).await;
        assert!(
            !reset && payloads.is_empty(),
            "a refusal a new tunnel does not cure waited for one: {reset}, {payloads:?}"
        );
        assert_eq!(gap.shared.counters.snapshot()[10], 0, "packets out");
        Ok(())
    }

    /// A descriptor tokio cannot register, here `/dev/null`, which epoll refuses, is refused, so that
    /// the network part's Kotlin side starts an engine instead; the engine goes on with the tunnel it had.
    #[tokio::test(flavor = "current_thread")]
    async fn a_tunnel_the_engine_cannot_take_leaves_the_old_one_in_place() -> io::Result<()> {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let to = server.local_addr()?;
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                let _ = server.send_to(&buffer[..n], from).await;
            }
        });
        let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        app_end.set_nonblocking(true)?;
        let (_stop, stop) = watch::channel(false);
        let (_network, network) = watch::channel(0);
        let (swaps, swapped) = mpsc::unbounded_channel();
        tokio::spawn(run(
            Tun::new(OwnedFd::from(engine_end))?,
            1500,
            Arc::new(shared()),
            stop,
            network,
            swapped,
        ));
        let (done, taken) = std::sync::mpsc::sync_channel(1);
        let null = OwnedFd::from(std::fs::File::open("/dev/null")?);
        swaps
            .send((null, done))
            .map_err(|_| io::Error::other("the engine ended"))?;
        let mut said = taken.try_recv();
        for _ in 0..100 {
            if said.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
            said = taken.try_recv();
        }
        assert!(matches!(said, Ok(Err(_))), "the engine said {said:?}");
        let app = tokio::net::UnixDatagram::from_std(app_end)?;
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let datagram = packet::udp(me, to, b"still").ok_or(io::ErrorKind::InvalidData)?;
        app.send(&datagram).await?;
        assert_eq!(answer(&app).await?, (to.port(), b"still".to_vec()));
        Ok(())
    }

    /// The listener hands a waiting upstream connection only to a connection from the fake address.
    /// Another app can reach the listener directly, from a port it picks: such a connection is closed
    /// at once and counted, and the upstream still waits for the rewritten one. A rewritten connection
    /// whose rewriting was forgotten meanwhile ends its flow in the log.
    #[tokio::test(flavor = "current_thread")]
    async fn the_listener_takes_only_connections_from_the_fake_address() -> io::Result<()> {
        let shared = Arc::new(shared());
        let pending: Pending = Arc::default();
        // In the test, the fake address is another local one.
        let fake = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));

        // A connection the engine rewrote, its upstream waiting under its fake port; and another app's
        // socket from that same port at the loopback address, which the kernel's choice of the port at
        // the fake address does not keep free there: another socket on the machine may hold it (unit 9b,
        // fix round 2: 8 runs in 256, 16 at once, failed with "address in use").
        let mut tries = 0;
        let (real, stranger, port) = loop {
            let real = TcpSocket::new_v4()?;
            real.bind(SocketAddr::new(fake, 0))?;
            let port = real.local_addr()?.port();
            let stranger = TcpSocket::new_v4()?;
            match stranger.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
                Ok(()) => break (real, stranger, port),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && tries < 64 => tries += 1,
                Err(error) => return Err(error),
            }
        };
        let nat = Arc::new(Mutex::new(Nat::with_ports(port, port)));
        let app = SocketAddr::from(([10, 215, 173, 1], 40_000));
        assert_eq!(
            lock(&nat).lookup(app, destination, true, Instant::now()),
            Lookup::New(port)
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        lock(&nat).open(
            port,
            Listener {
                port: address.port(),
                generation: 0,
            },
        );
        let upstream = TcpStream::connect(server.local_addr()?).await?;
        let (mut server_end, _) = server.accept().await?;
        let opened = open_flow(&shared, destination);
        lock(&pending).insert(
            port,
            Upstream {
                stream: upstream,
                opened,
                bytes: None,
            },
        );

        // A second one, whose rewriting is gone.
        let late = TcpSocket::new_v4()?;
        late.bind(SocketAddr::new(fake, 0))?;
        let late_port = late.local_addr()?.port();
        let late_opened = open_flow(&shared, destination);
        let late_upstream = TcpStream::connect(server.local_addr()?).await?;
        lock(&pending).insert(
            late_port,
            Upstream {
                stream: late_upstream,
                opened: late_opened,
                bytes: None,
            },
        );

        tokio::spawn(accept(
            Some(listener),
            (address.ip(), fake),
            Arc::clone(&pending),
            Arc::clone(&shared),
            Arc::clone(&nat),
        ));

        // Another app, straight to the listener, from the waiting connection's port.
        let mut stranger = stranger.connect(address).await?;
        let mut byte = [0u8; 1];
        assert_eq!(stranger.read(&mut byte).await?, 0, "closed at once");
        assert!(lock(&pending).contains_key(&port));
        assert_eq!(shared.counters.snapshot()[18], 1);

        // The rewritten connection gets its upstream.
        let mut real = real.connect(address).await?;
        real.write_all(b"hello").await?;
        let mut got = [0u8; 5];
        server_end.read_exact(&mut got).await?;
        assert_eq!(&got, b"hello");
        assert!(!lock(&pending).contains_key(&port));
        // The relay holds it now: no silence makes the sweep forget it.
        let hours = Instant::now() + Duration::from_hours(3);
        assert_eq!(lock(&nat).sweep(hours), Vec::<u16>::new());
        assert!(lock(&nat).by_fake(port, hours).is_some_and(|e| e.relayed));

        // The one whose rewriting is gone is closed, and its flow ends.
        let mut late = late.connect(address).await?;
        assert_eq!(late.read(&mut byte).await?, 0);
        assert!(lock(&pending).is_empty());
        assert!(!lock(&shared.live).contains_key(&late_opened.id));
        assert!(lock(&shared.live).contains_key(&opened.id));
        Ok(())
    }

    /// A connection the engine rewrote to its listener, from `fake`, with an upstream connection to
    /// `server` waiting for it under its fake port, as `tcp::open` leaves one; and the server's end.
    async fn waiting_connection(
        shared: &Shared,
        (nat, pending): (&Mutex<Nat>, &Pending),
        fake: IpAddr,
        (server, listener): (&TcpListener, Listener),
    ) -> io::Result<(TcpSocket, TcpStream)> {
        let real = TcpSocket::new_v4()?;
        real.bind(SocketAddr::new(fake, 0))?;
        let port = real.local_addr()?.port();
        // The fake port is the socket's own, which the kernel picked: the table hands out that one.
        *lock(nat) = Nat::with_ports(port, port);
        let app = SocketAddr::from(([10, 215, 173, 1], 40_000));
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        if lock(nat).lookup(app, destination, true, Instant::now()) != Lookup::New(port) {
            return Err(io::Error::other("no fake port"));
        }
        lock(nat).open(port, listener);
        let stream = TcpStream::connect(server.local_addr()?).await?;
        let (server_end, _) = server.accept().await?;
        lock(pending).insert(
            port,
            Upstream {
                stream,
                opened: open_flow(shared, destination),
                bytes: None,
            },
        );
        Ok((real, server_end))
    }

    /// Waits up to 3 s until the counter at `index` reaches `value`, letting the engine's tasks run.
    async fn until_counted(shared: &Shared, index: usize, value: u64) -> io::Result<()> {
        for _ in 0..300 {
            if shared.counters.snapshot()[index] >= value {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(io::Error::other(format!(
            "counter {index} stayed at {}",
            shared.counters.snapshot()[index]
        )))
    }

    /// The place of `listener_recoveries` in the counters.
    const LISTENER_RECOVERIES: usize = 46;

    /// The engine's listener and the accept loop on it, on the loopback, its port in `Shared`; and a
    /// second descriptor of the listener's socket, with which the test makes it stop listening, as
    /// Android's netd does when it destroys the sockets on the tunnel's address (ADR 0044, unit 12b).
    /// `shutdown(SHUT_RD)` on a listening socket stops its listening, as `SOCK_DESTROY` does, without
    /// the privilege `SOCK_DESTROY` needs: `accept` then answers `EINVAL`, and `SO_ACCEPTCONN` reads 0.
    async fn listening(
        shared: &Arc<Shared>,
        nat: &Arc<Mutex<Nat>>,
        pending: &Pending,
        fake: IpAddr,
    ) -> io::Result<(u16, socket2::Socket)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        shared.listener4.bound(address.port());
        let control = socket2::Socket::from(listener.as_fd().try_clone_to_owned()?);
        tokio::spawn(accept(
            Some(listener),
            (address.ip(), fake),
            Arc::clone(pending),
            Arc::clone(shared),
            Arc::clone(nat),
        ));
        Ok((address.port(), control))
    }

    /// Unit 12b: a listener that stops listening is bound anew, of a new generation and on a port the
    /// kernel picks, never on its old one (third round, nit 1), and the next connection rewritten to it
    /// gets its upstream connection. Here the old port is held, the moment no listener holds it, by a
    /// socket with `SO_REUSEADDR` that does not listen, as another app may hold it: a bind on the old port
    /// would have succeeded beside it, and that socket could connect from the listener's port. Before
    /// this unit, the accept loop ended at the first error, and every later connection was refused.
    #[tokio::test(flavor = "current_thread")]
    async fn a_listener_that_stops_listening_is_bound_anew_on_a_new_port() -> io::Result<()> {
        let shared = Arc::new(shared());
        let pending: Pending = Arc::default();
        let nat = Arc::new(Mutex::new(Nat::default()));
        let fake = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let (port, control) = listening(&shared, &nat, &pending, fake).await?;

        control.shutdown(std::net::Shutdown::Read)?;
        assert!(
            !nix::sys::socket::getsockopt(&control, nix::sys::socket::sockopt::AcceptConn)?,
            "still listening"
        );
        // Bound before the accept loop runs again: this test's thread runs it only when the test waits.
        let beside = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
        beside.set_reuse_address(true)?;
        beside.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)).into())?;
        until_counted(&shared, LISTENER_RECOVERIES, 1).await?;
        let now = shared.listener4.now();
        assert!(
            now.port != port && now.port != 0 && now.generation == 1,
            "the listener now: {now:?}, the old port {port}"
        );

        let (real, mut server_end) =
            waiting_connection(&shared, (&nat, &pending), fake, (&server, now)).await?;
        let mut real = real
            .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, now.port)))
            .await?;
        real.write_all(b"after").await?;
        let mut got = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), server_end.read_exact(&mut got)).await??;
        assert_eq!(&got, b"after");
        assert!(lock(&pending).is_empty());
        Ok(())
    }

    /// Unit 12b, second round (nit 2): an accept loop started with no listener, as when the first bind
    /// failed at the engine's start, binds one, on a port of its own, and accepts on it; before, no
    /// accept loop ran then, and the tunnel carried no TCP of that IP version for the whole run.
    #[tokio::test(flavor = "current_thread")]
    async fn an_accept_loop_with_no_listener_binds_one() -> io::Result<()> {
        let shared = Arc::new(shared());
        let pending: Pending = Arc::default();
        let nat = Arc::new(Mutex::new(Nat::default()));
        let fake = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        tokio::spawn(accept(
            None,
            (IpAddr::V4(Ipv4Addr::LOCALHOST), fake),
            Arc::clone(&pending),
            Arc::clone(&shared),
            Arc::clone(&nat),
        ));
        for _ in 0..300 {
            if shared.listener4.now().port != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let now = shared.listener4.now();
        assert!(now.port != 0, "no listener bound");
        let (real, mut server_end) =
            waiting_connection(&shared, (&nat, &pending), fake, (&server, now)).await?;
        let mut real = real
            .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, now.port)))
            .await?;
        real.write_all(b"first").await?;
        let mut got = [0u8; 5];
        tokio::time::timeout(Duration::from_secs(3), server_end.read_exact(&mut got)).await??;
        assert_eq!(&got, b"first");
        assert_eq!(shared.counters.snapshot()[LISTENER_RECOVERIES], 0);
        Ok(())
    }

    /// The event loop on a socket pair in place of the tunnel, with the engine's listener on `listener`
    /// as `Shared` says; the app's end of the pair, and the network's changes, which the loop holds.
    fn a_loop(listener: u16) -> io::Result<(Loop, tokio::net::UnixDatagram, watch::Sender<u64>)> {
        let shared = Arc::new(shared());
        shared.listener4.bound(listener);
        let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        app_end.set_nonblocking(true)?;
        let (moving, changes) = watch::channel(0);
        let limits = shared.limits;
        let state = Loop {
            tun: Arc::new(Tun::new(OwnedFd::from(engine_end))?),
            shared,
            nat: Arc::new(Mutex::new(Nat::default())),
            pending: Arc::default(),
            udp: Arc::default(),
            echoes: Echoes::probe(),
            fragments: Mutex::new(Reassembler::new(fragments::Bounds {
                datagrams: limits.fragment_datagrams,
                bytes: limits.fragment_bytes,
                wait: limits.fragment_wait,
            })),
            changes,
        };
        Ok((state, tokio::net::UnixDatagram::from_std(app_end)?, moving))
    }

    /// A TCP segment from `from` to `to` with `flags` (`packet::SYN`, `packet::RST`, `packet::ACK`),
    /// as the tunnel carries it; its sequence number is 7,000.
    fn segment(from: SocketAddr, to: SocketAddr, flags: u8) -> io::Result<Vec<u8>> {
        let (SocketAddr::V4(from), SocketAddr::V4(to)) = (from, to) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let mut builder = etherparse::PacketBuilder::ipv4(from.ip().octets(), to.ip().octets(), 64)
            .tcp(from.port(), to.port(), 7_000, 65_535);
        if flags & packet::ACK != 0 {
            builder = builder.ack(9_000);
        }
        if flags & packet::SYN != 0 {
            builder = builder.syn();
        }
        if flags & packet::RST != 0 {
            builder = builder.rst();
        }
        let mut bytes = Vec::new();
        builder
            .write(&mut bytes, &[])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(bytes)
    }

    /// Hands the loop one packet from the tunnel.
    async fn through(state: &Loop, mut bytes: Vec<u8>) -> io::Result<()> {
        let parsed =
            packet::parse(&bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        state.tcp(&mut bytes, &parsed).await;
        Ok(())
    }

    /// What the loop wrote to the app within half a second: the segment's ends and flags, if any.
    async fn written(app: &tokio::net::UnixDatagram) -> Option<(SocketAddr, SocketAddr, u8)> {
        let mut buffer = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_millis(500), app.recv(&mut buffer))
            .await
            .ok()?
            .ok()?;
        let parsed = packet::parse(&buffer[..n]).ok()?;
        Some((
            parsed.source,
            parsed.destination,
            packet::tcp_flags(&buffer[..n], &parsed),
        ))
    }

    /// A connection of the app at `app` to `destination` whose server accepted, rewritten to `listener`
    /// and waiting for it to be handed over, with its upstream connection to `server`, whose end comes
    /// back with its fake port; or, `relayed`, held by the relay.
    async fn rewritten_to(
        state: &Loop,
        (app, destination): (SocketAddr, SocketAddr),
        listener: Listener,
        server: Option<&TcpListener>,
    ) -> io::Result<(u16, Option<TcpStream>)> {
        let Lookup::New(port) = lock(&state.nat).lookup(app, destination, true, Instant::now())
        else {
            return Err(io::Error::other("no fake port"));
        };
        lock(&state.nat).open(port, listener);
        let Some(server) = server else {
            lock(&state.nat).relayed(port);
            return Ok((port, None));
        };
        let stream = TcpStream::connect(server.local_addr()?).await?;
        let (server_end, _) = server.accept().await?;
        let opened = open_flow(&state.shared, destination);
        lock(&state.pending).insert(
            port,
            Upstream {
                stream,
                opened,
                bytes: None,
            },
        );
        Ok((port, Some(server_end)))
    }

    /// Whether `end` reads a reset within 3 s.
    async fn reset_at(end: &mut TcpStream) -> bool {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), end.read(&mut byte)).await;
        matches!(read, Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset)
    }

    /// Unit 12b, second round: once the listener stopped listening and another was bound, here on
    /// another port, only a connection the relay holds keeps the old port, both ways, since the engine's
    /// own socket holds its ends there; a segment from the new port to it is dropped. One rewritten to
    /// the old listener and not yet relayed is the engine's no more, since another app may hold the old
    /// port now (`tcp::Listening`): what comes from that port for it is dropped, but a reset, which
    /// reaches the app; and the app's SYN sent again is refused with a reset, never rewritten to the old
    /// port, its upstream connection reset with it. The generation decides, not the port: the same
    /// holds after a listener bound anew on the old port.
    #[tokio::test(flavor = "current_thread")]
    async fn only_relayed_connections_keep_a_listener_that_stopped() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        let listening = &state.shared.listener4;
        let at = state.shared.addresses;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        let (held, waiting) = (
            SocketAddr::from((at.tun4, 40_000)),
            SocketAddr::from((at.tun4, 40_001)),
        );
        let old = listening.now();
        let (relayed, _) = rewritten_to(&state, (held, destination), old, None).await?;
        let (gone, server_end) =
            rewritten_to(&state, (waiting, destination), old, Some(&server)).await?;
        let mut server_end = server_end.ok_or(io::ErrorKind::NotFound)?;
        listening.lost();
        listening.bound(5_000);
        let (from_old, from_new) = (
            SocketAddr::from((at.tun4, 4_000)),
            SocketAddr::from((at.tun4, 5_000)),
        );

        let fake = SocketAddr::from((at.fake4, relayed));
        through(&state, segment(held, destination, packet::ACK)?).await?;
        assert_eq!(
            written(&app_end).await,
            Some((fake, from_old, packet::ACK)),
            "the relayed connection's segment"
        );
        through(&state, segment(from_old, fake, packet::ACK)?).await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, held, packet::ACK)),
            "Android's answer from the old port"
        );
        through(&state, segment(from_new, fake, packet::ACK)?).await?;
        assert_eq!(written(&app_end).await, None, "a segment from the new port");

        let fake = SocketAddr::from((at.fake4, gone));
        through(&state, segment(from_old, fake, packet::SYN | packet::ACK)?).await?;
        assert_eq!(written(&app_end).await, None, "a SYN-ACK from the old port");
        through(&state, segment(waiting, destination, packet::SYN)?).await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, waiting, packet::RST | packet::ACK)),
            "the SYN sent again was not refused"
        );
        assert!(
            lock(&state.pending).is_empty(),
            "the upstream connection is held"
        );
        assert_eq!(lock(&state.nat).by_fake(gone, Instant::now()), None);
        assert!(reset_at(&mut server_end).await, "the server's end");

        // A listener of a new generation on the same port number, which only the generation tells from
        // the one before: a connection rewritten to the one before is the engine's no more, and only a
        // reset from that port reaches the app.
        let now = listening.now();
        let (again, _end) =
            rewritten_to(&state, (waiting, destination), now, Some(&server)).await?;
        listening.lost();
        listening.bound(5_000);
        let fake = SocketAddr::from((at.fake4, again));
        through(&state, segment(from_new, fake, packet::ACK)?).await?;
        assert_eq!(
            written(&app_end).await,
            None,
            "an answer to a connection rewritten to the listener before"
        );
        through(&state, segment(from_new, fake, packet::RST | packet::ACK)?).await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, waiting, packet::RST | packet::ACK)),
            "the reset of a connection rewritten to the listener before"
        );
        assert!(lock(&state.pending).is_empty());
        Ok(())
    }

    /// The flow behind a fake port's waiting upstream connection.
    fn flow_of(state: &Loop, port: u16) -> io::Result<u64> {
        lock(&state.pending)
            .get(&port)
            .map(|upstream| upstream.opened.id)
            .ok_or_else(|| io::Error::other("no upstream connection waits"))
    }

    /// The outcome of flow `id` in its last segment in the log, and in the flows kept.
    fn outcome_of(shared: &Shared, id: u64) -> (Option<Outcome>, Option<Outcome>) {
        let logged = lock(&shared.pending_log)
            .iter()
            .rev()
            .find_map(|record| match record {
                Record::Segment { flow, .. } if flow.id == id => Some(flow.outcome),
                _ => None,
            });
        let kept = lock(&shared.flows)
            .iter()
            .find(|flow| flow.id == id)
            .map(|flow| flow.outcome);
        (logged, kept)
    }

    /// Unit 12b, third round (nit 2): a connection rewritten to a listener that stopped, which the
    /// engine resets itself when the app's segment comes, ends in the log, the counters and the flows
    /// kept as the app saw it end: refused, for its SYN sent again, else reset (`Failed`). Before, it
    /// ended as opened, with no bytes. One Android's stack resets ends as opened, as a relayed
    /// connection a peer resets does.
    #[tokio::test(flavor = "current_thread")]
    async fn the_log_has_what_the_app_saw_of_a_connection_the_engine_reset() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        let listening = &state.shared.listener4;
        let at = state.shared.addresses;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        let old = listening.now();
        let mut flows = Vec::new();
        let mut ends = Vec::new();
        for app in 40_000..40_003 {
            let app = SocketAddr::from((at.tun4, app));
            let (port, end) = rewritten_to(&state, (app, destination), old, Some(&server)).await?;
            flows.push((app, port, flow_of(&state, port)?));
            ends.push(end);
        }
        listening.lost();
        listening.bound(5_000);
        let [(syn, _, refused), (ack, _, reset), (_, android, opened)] = flows[..] else {
            unreachable!("three connections")
        };

        through(&state, segment(syn, destination, packet::SYN)?).await?;
        through(&state, segment(ack, destination, packet::ACK)?).await?;
        let from_old = SocketAddr::from((at.tun4, 4_000));
        let fake = SocketAddr::from((at.fake4, android));
        through(&state, segment(from_old, fake, packet::RST | packet::ACK)?).await?;
        for _ in 0..3 {
            assert!(written(&app_end).await.is_some(), "a reset to an app");
        }
        assert_eq!(
            outcome_of(&state.shared, refused),
            (Some(Outcome::Refused), Some(Outcome::Refused)),
            "the SYN sent again"
        );
        assert_eq!(
            outcome_of(&state.shared, reset),
            (Some(Outcome::Failed), Some(Outcome::Failed)),
            "the segment reset"
        );
        assert_eq!(
            outcome_of(&state.shared, opened),
            (Some(Outcome::Opened), Some(Outcome::Opened)),
            "Android's reset"
        );
        let counters = state.shared.counters.snapshot();
        assert_eq!((counters[5], counters[7]), (1, 1), "refused and failed");
        Ok(())
    }

    /// Unit 12b, third round (nit 3): a segment the engine drops, from the port of a listener that
    /// stopped to a connection not yet relayed, does not mark the connection as seen, so the sweep still
    /// forgets it, and its waiting upstream connection, once it was silent for `Limits::tcp_idle`. One
    /// that passes marks it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_answer_leaves_the_connection_to_the_sweep() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        let listening = &state.shared.listener4;
        let at = state.shared.addresses;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        let app = SocketAddr::from((at.tun4, 40_000));
        let (port, _end) =
            rewritten_to(&state, (app, destination), listening.now(), Some(&server)).await?;
        let seen = || {
            lock(&state.nat)
                .answered(port, 4_000)
                .map(|entry| entry.seen)
                .ok_or_else(|| io::Error::other("no connection"))
        };
        let (from_old, fake) = (
            SocketAddr::from((at.tun4, 4_000)),
            SocketAddr::from((at.fake4, port)),
        );
        let first = seen()?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        through(&state, segment(from_old, fake, packet::SYN | packet::ACK)?).await?;
        assert!(written(&app_end).await.is_some(), "the answer did not pass");
        let passed = seen()?;
        assert!(passed > first, "a segment that passed did not mark it");

        listening.lost();
        listening.bound(5_000);
        tokio::time::sleep(Duration::from_millis(20)).await;
        through(&state, segment(from_old, fake, packet::ACK)?).await?;
        assert_eq!(written(&app_end).await, None, "the answer passed");
        assert_eq!(seen()?, passed, "a segment dropped marked it as seen");
        let later = passed + nat::TCP_IDLE + Duration::from_millis(1);
        assert_eq!(lock(&state.nat).sweep(later), vec![port]);
        Ok(())
    }

    /// Unit 12b, third round (nit 1): a SYN without ACK from the tunnel's address to the fake peer,
    /// which no listener sends, is dropped and counted, also from the listener's port to a connection
    /// not yet relayed, as another app's socket bound beside the listener could send it. Android's
    /// SYN-ACK from there still passes.
    #[tokio::test(flavor = "current_thread")]
    async fn a_syn_from_the_tunnels_address_to_the_fake_peer_is_dropped() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        let at = state.shared.addresses;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        let app = SocketAddr::from((at.tun4, 40_000));
        let now = state.shared.listener4.now();
        let (port, _end) = rewritten_to(&state, (app, destination), now, Some(&server)).await?;
        let (from_listener, fake) = (
            SocketAddr::from((at.tun4, 4_000)),
            SocketAddr::from((at.fake4, port)),
        );
        through(&state, segment(from_listener, fake, packet::SYN)?).await?;
        assert_eq!(written(&app_end).await, None, "a SYN passed to the app");
        assert_eq!(state.shared.counters.snapshot()[8], 1, "skipped");
        assert!(lock(&state.pending).contains_key(&port));
        through(
            &state,
            segment(from_listener, fake, packet::SYN | packet::ACK)?,
        )
        .await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, app, packet::SYN | packet::ACK))
        );
        Ok(())
    }

    /// Unit 12b, second round: while no listener is bound (port 0), as when its port was taken and
    /// none can be bound, an app's SYN is refused at once, its fake port freed, nothing opened for it,
    /// and a listener wanted at once. Before, the engine rewrote it to the port of the listener that
    /// stopped, which another app may hold.
    #[tokio::test(flavor = "current_thread")]
    async fn with_no_listener_a_syn_is_refused_at_once() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        state.shared.listener4.lost();
        let app = SocketAddr::from((state.shared.addresses.tun4, 40_000));
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        through(&state, segment(app, destination, packet::SYN)?).await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, app, packet::RST | packet::ACK))
        );
        assert!(lock(&state.nat).is_empty() && lock(&state.pending).is_empty());
        let wanted = state.shared.listener4.wanted.notified();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wanted)
                .await
                .is_ok(),
            "no listener wanted"
        );
        Ok(())
    }

    /// Unit 12b, second round: a held SYN whose server accepted while the listener stopped listening,
    /// with none bound since, is refused, and the server's connection given up, rather than rewritten
    /// to the port of the listener that stopped, which another app may hold.
    #[tokio::test(flavor = "current_thread")]
    async fn a_held_syn_that_meets_no_listener_is_refused() -> io::Result<()> {
        let (state, app_end, _moving) = a_loop(4_000)?;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let destination = server.local_addr()?;
        let app = SocketAddr::from((state.shared.addresses.tun4, 40_000));
        // The SYN is held, its server asked in a task of its own, which runs once this test waits.
        through(&state, segment(app, destination, packet::SYN)?).await?;
        state.shared.listener4.lost();
        assert_eq!(
            written(&app_end).await,
            Some((destination, app, packet::RST | packet::ACK)),
            "the held SYN was not refused"
        );
        assert!(lock(&state.nat).is_empty() && lock(&state.pending).is_empty());
        // The log has it refused, as the app saw it, not opened (third round, nit 2).
        let kept = lock(&state.shared.flows)
            .back()
            .map(|flow| (flow.id, flow.outcome));
        let (id, outcome) = kept.ok_or(io::ErrorKind::NotFound)?;
        assert_eq!(outcome, Outcome::Refused, "the flow kept");
        assert_eq!(
            outcome_of(&state.shared, id).0,
            Some(Outcome::Refused),
            "the log"
        );
        assert_eq!(state.shared.counters.snapshot()[5], 1, "refused");
        let (mut server_end, _) = server.accept().await?;
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), server_end.read(&mut byte)).await?;
        assert!(matches!(read, Ok(0) | Err(_)), "the server's end: {read:?}");
        Ok(())
    }

    /// Unit 12b: Android's stack resets a connection its listener never handed to the relay, as when
    /// the listener it waited in stops listening. The app gets the reset, and the upstream connection
    /// waiting for the handover is reset too, its rewriting forgotten and its flow ended in the log,
    /// rather than held until the sweep, ten minutes on. A relayed connection's reset is the relay's to
    /// end, and its rewriting stays.
    #[tokio::test(flavor = "current_thread")]
    async fn androids_reset_before_the_relay_resets_the_server_too() -> io::Result<()> {
        let listener = 4_000;
        let (state, app_end, _moving) = a_loop(listener)?;
        let at = state.shared.addresses;
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let app = SocketAddr::from((at.tun4, 40_000));
        let destination = SocketAddr::from(([198, 51, 100, 9], 443));
        let Lookup::New(port) = lock(&state.nat).lookup(app, destination, true, Instant::now())
        else {
            return Err(io::Error::other("no fake port"));
        };
        lock(&state.nat).open(port, state.shared.listener4.now());
        let stream = TcpStream::connect(server.local_addr()?).await?;
        let (mut server_end, _) = server.accept().await?;
        let opened = open_flow(&state.shared, destination);
        lock(&state.pending).insert(
            port,
            Upstream {
                stream,
                opened,
                bytes: None,
            },
        );
        let fake = SocketAddr::from((at.fake4, port));
        let from_listener = SocketAddr::from((at.tun4, listener));

        through(
            &state,
            segment(from_listener, fake, packet::RST | packet::ACK)?,
        )
        .await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, app, packet::RST | packet::ACK)),
            "the reset to the app"
        );
        assert!(
            lock(&state.pending).is_empty(),
            "the upstream connection is held"
        );
        assert_eq!(lock(&state.nat).by_fake(port, Instant::now()), None);
        assert!(!lock(&state.shared.live).contains_key(&opened.id));
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), server_end.read(&mut byte)).await?;
        assert_eq!(
            read.map_err(|e| e.kind()),
            Err(io::ErrorKind::ConnectionReset),
            "the server's end"
        );

        // A relayed connection's reset passes, and leaves its rewriting to the relay.
        let other = SocketAddr::from((at.tun4, 40_001));
        let Lookup::New(relayed) =
            lock(&state.nat).lookup(other, destination, true, Instant::now())
        else {
            return Err(io::Error::other("no fake port"));
        };
        lock(&state.nat).open(relayed, state.shared.listener4.now());
        lock(&state.nat).relayed(relayed);
        let fake = SocketAddr::from((at.fake4, relayed));
        through(
            &state,
            segment(from_listener, fake, packet::RST | packet::ACK)?,
        )
        .await?;
        assert_eq!(
            written(&app_end).await,
            Some((destination, other, packet::RST | packet::ACK))
        );
        assert!(lock(&state.nat).by_fake(relayed, Instant::now()).is_some());
        Ok(())
    }

    /// What Android's stack sends after the relay ended (the rest of a download, the last FIN and ACK)
    /// reaches the flow's last segment, which ends at the last packet, not when the rewriting went.
    #[test]
    fn a_closed_flows_last_segment_holds_what_the_tunnel_carried_after_its_relay() {
        let clock = clock::ManualClock::at(1_794_873_600_000 + (22 * 60 + 10) * 60_000);
        let mut shared = shared();
        shared.clock = clock.clone();
        let Some(bytes) = shared.record(Flow {
            id: 1,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination: SocketAddr::from(([198, 51, 100, 9], 443)),
            uid: Some(UID),
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
        bytes.down(&shared, 2_000_000, 1_500_000);
        // The relay is done; the rest of the download is still on its way to the app.
        clock.pass(30);
        bytes.down(&shared, 0, 570_000);
        clock.pass(30);
        bytes.up(&shared, 0, 19_000);
        let last = bytes.last.load(Ordering::Relaxed);
        assert_eq!(last, clock.wall_ms());
        // The rewriting lingers on, silent, before it goes.
        clock.pass(5_000);
        shared.finish_closed(1);
        shared.finish_closed(1);
        let records = std::mem::take(&mut *lock(&shared.pending_log));
        let [
            Record::Segment {
                bytes,
                end,
                continues: false,
                ..
            },
        ] = records.as_slice()
        else {
            unreachable!("one last segment: {records:?}")
        };
        assert_eq!(*bytes, [0, 2_000_000, 19_000, 2_070_000]);
        assert_eq!(*end, last);
    }

    /// A DNS response for `name` with one A record, `address`.
    pub(super) fn dns_answer(name: &str, address: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(u8::try_from(label.len()).unwrap_or(0));
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
        m.extend_from_slice(&address);
        m
    }

    #[test]
    fn w3s_order_is_the_connections_own_name_then_dns_then_the_organisation() {
        use NamedBy::{Dns, Organisation, Quic, Tls, Unknown};
        let order: [&[NamedBy]; 4] = [&[Tls, Quic], &[Dns], &[Organisation], &[Unknown]];
        for (i, &place) in order.iter().enumerate() {
            for &better in place {
                for &worse in order[i + 1..].iter().flat_map(|p| p.iter()) {
                    assert!(worse.yields_to(better) && !better.yields_to(worse));
                }
                for &alike in place {
                    assert!(!alike.yields_to(better), "{alike:?} and {better:?}");
                }
            }
        }
    }
}
