//! The forwarder (ADR 0012): Android's own TCP stack terminates every app's connection, reached by
//! rewriting addresses, and the engine relays each one over a protected socket of its own to the
//! real destination. UDP is relayed in userspace, each destination a flow of its own in the log.
//!
//! A TCP packet from an app to `D:dp` is rewritten to come from the fake peer `FAKE:fp` and go to the
//! engine's listener on the tunnel's address. Android's TCP stack answers it, and the answer is
//! rewritten back to come from `D:dp`. The listener accepts the connection as if from `FAKE:fp`, the
//! table maps that to `D:dp`, and the engine connects there. Watch must be inside its own tunnel for
//! this, and protects each socket of its own (spike, finding 6).
//!
//! The app's first SYN is held until Android has named the app and the real server has accepted, so
//! that a connection closed at once still has an owner, and a refused or unreachable server looks so
//! to the app: it gets a reset or an ICMP error, as without a VPN.
//!
//! UDP leaves through one mapping for each app socket, whatever the destination (ADR 0044): on the
//! direct path one protected socket, through the user's tool one `UDP ASSOCIATE`. Either lets in only
//! what comes from addresses the app sent to.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Notify, watch};

use crate::dnscache::DnsCache;
use crate::log::Record;
use crate::names::Names;
#[cfg(test)]
use crate::nat::Lookup;
use crate::nat::{self, Nat};
use crate::organisations::Organisations;
use crate::owners::{NetworkKind, Owners};
use crate::packet::{self, Skip, TCP};
use crate::resolvers::Resolvers;
use crate::standins::StandIns;
#[cfg(test)]
use crate::tls::Hello;
use crate::tun::Tun;

mod chain;
mod errors;
mod kept;
mod logbook;
mod lookups;
mod naming;
mod tcp;
mod udp;
mod upstream;

pub use chain::Chain;
use logbook::{FlowBytes, Live, Lookups, logger, now_ms};
#[cfg(test)]
use naming::Begun;
use tcp::{Pending, listen};
#[cfg(test)]
use tcp::{Upstream, accept};
use udp::UdpFlows;

/// The tunnel's addresses (ADR 0041, decision 3): its own address, a /32 or a /128 (ADR 0034: a wider
/// prefix would count as local network on Android 17), the fake peer the kernel sees for every rewritten
/// connection, outside it, and the DNS server Android is given inside the tunnel, whose queries the engine
/// passes on to the network's resolver. Any app can read the tunnel's address and prefix, so Watch takes
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
    /// an app that reads them finds a local firewall, the kind of app Watch is, not Watch itself. Read
    /// from 32 apps' own source on 2026-11-12; the largest other group, 172.19.0.1, is that of proxy and
    /// circumvention clients, and its /30 does not fit Android 17.
    pub const COMMON: Self = Self {
        tun4: Ipv4Addr::new(10, 1, 10, 1),
        fake4: Ipv4Addr::new(10, 1, 10, 2),
        dns4: Ipv4Addr::new(10, 1, 10, 3),
        tun6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 1),
        fake6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 2),
        dns6: Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 3),
    };

    /// Watch's earlier addresses, for a network that uses the common ones itself: Comcast Business
    /// gateways answer at 10.1.10.1, and a tunnel that takes the router's address cuts the phone off
    /// from it. Watch picks this set when the network beneath clashes with [`Addresses::COMMON`].
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
    /// The first of the fake ports handed out, `first_port..=last_port`.
    pub first_port: u16,
    /// The last of them.
    pub last_port: u16,
}

impl Limits {
    /// The product's limits for a process that may open `descriptors` files (its soft limit): a
    /// reserve of a sixteenth, at least 128, stays for Watch itself; waiting TCP connections may use an
    /// eighth of the rest, at most 4,096.
    #[must_use]
    pub fn for_descriptors(descriptors: usize) -> Self {
        let budget = descriptors.saturating_sub((descriptors / 16).max(128));
        Self {
            tcp_waiting: (budget / 8).clamp(1, 4_096),
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
            udp_idle: Duration::from_secs(120),
            udp_waiting: 32,
            udp_reask: Duration::from_secs(1),
            udp_contest: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(60),
            close_linger: Duration::from_secs(30),
            sweep_every: Duration::from_secs(60),
            tcp_idle: nat::TCP_IDLE,
            port_cooling: nat::PORT_COOLING,
            first_port: nat::FIRST_PORT,
            last_port: nat::LAST_PORT,
        }
    }
}
/// How long finished records gather before they go to Watch's log together (ADR 0037).
const LOG_DELAY: Duration = Duration::from_secs(30);
/// A flow still open is written as a segment at every quarter of an hour, UTC. Every time zone is a
/// whole number of quarter hours from UTC, so no segment spans a local midnight.
const SEGMENT_MS: u64 = 15 * 60 * 1000;

/// What the engine asks of Android, through Watch's Kotlin side.
pub trait Platform: Send + Sync + 'static {
    /// `ConnectivityManager.getConnectionOwnerUid`: the UID of the app with a socket from `local` to
    /// `remote`, or `None` when Android does not know.
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32>;

    /// `VpnService.protect`: keeps one of the engine's sockets out of the tunnel.
    fn protect(&self, fd: RawFd) -> bool;

    /// Hands a batch of records to Watch's connection log ([`crate::log::batch`]).
    fn log(&self, batch: &[u8]);
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
}

/// Where a flow's name came from, in the order W3 prefers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedBy {
    /// A DNS answer Watch passed to the app for the destination's address.
    Dns,
    /// The server name of the TLS connection.
    Tls,
    /// The server name of the QUIC connection's Initial packets.
    Quic,
    /// The organisation whose network the address is in, from the offline table (ADR 0036).
    Organisation,
    /// Not named.
    Unknown,
}

impl NamedBy {
    /// Whether a name from this source gives way to one from `other`: W3's order is DNS, TLS, QUIC,
    /// then the organisation.
    fn yields_to(self, other: Self) -> bool {
        let rank = |by: Self| match by {
            Self::Dns => 0,
            Self::Tls => 1,
            Self::Quic => 2,
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
    /// The hello's server name is the public name of an ECH configuration in a DNS answer Watch passed
    /// on: the real name is hidden, and the public name does not name the flow.
    Hidden,
}

/// Whether a flow carries an app's own DNS, past Watch's resolver (W3, ADR 0029).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsUse {
    /// Not DNS, as far as Watch can tell, or the phone's own lookups through Watch's resolver.
    None,
    /// Plain DNS on port 53 to another server than Watch's: around the phone's DNS settings.
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
    /// The destination's name, if Watch knows it.
    pub name: Option<String>,
    /// Where the name came from.
    pub named_by: NamedBy,
    /// Whether the hello hid the real name.
    pub ech: Ech,
    /// Whether the flow carries the app's own DNS.
    pub dns: DnsUse,
    /// The known resolver it goes to (`data/resolvers`), if it is one.
    pub resolver: Option<String>,
    /// The network of its address, when the organisation table named it.
    pub network: Option<Network>,
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
    dns: DnsUse,
}

/// The engine's settings.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The tunnel's MTU, as given to `Builder.setMtu`.
    pub mtu: u16,
    /// How many of the latest flows to keep in memory for Watch's debug builds and tests; 0 keeps
    /// none. Release builds keep none: the connection log (W4) decides what is recorded.
    pub keep_flows: usize,
    /// The tunnel's addresses, as given to `Builder.addAddress` and `addDnsServer`.
    pub addresses: Addresses,
    /// How long the engine waits and keeps things; the product uses [`Limits::default`].
    pub limits: Limits,
}

/// How many counters [`Counters::snapshot`] gives.
pub const COUNTERS: usize = 29;

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
}

impl Counters {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused, unreachable,
    /// failed, packets skipped, packets in, packets out, server names read from TLS and from QUIC, QUIC
    /// flows whose name could not be read, hellos that offered ECH, hellos whose name was an ECH public
    /// name, flows of an app's own plain and encrypted DNS, connections to the engine's listener that
    /// did not come from the fake address, refused, IP fragments dropped (counted apart from the other
    /// skipped packets, review finding 21), and hellos read on flows a DNS answer had named, and of
    /// those, how many named another server (finding 20: how often a shared address gives a flow the
    /// wrong name), relayed connections that ended in an error and were reset on both sides (finding
    /// 21), SYNs dropped because as many connections as allowed were waiting for their servers
    /// (finding 18), UDP mappings opened (finding 19: one for each app socket, on the direct path or
    /// through the tool), datagrams a mapping dropped because they came from an address its app had not
    /// sent to, and answers from the tool's relay that a mapping dropped because no one destination of
    /// its app could be told for them (ADR 0044, decision 2: a header that is not well formed, a
    /// fragment, or a port several stand-ins wait on), datagrams from another port of an address the
    /// app sent to that a mapping dropped because as many such ports had come in as it lets in, and
    /// relays a tool offered for UDP elsewhere than on the phone or at its proxy's own address, which
    /// Watch refused. None names a destination: they can be read on any phone. New counters are only
    /// ever appended, so that scripts reading a column by its place keep reading the same one.
    #[must_use]
    pub fn snapshot(&self) -> [u64; COUNTERS] {
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
        ]
        .map(|c| c.load(Ordering::Relaxed))
    }
}

/// What the engine's thread and its controller share.
struct Shared {
    platform: Arc<dyn Platform>,
    /// The tunnel's addresses for this run.
    addresses: Addresses,
    limits: Limits,
    /// TCP connections waiting for their servers now (`Limits::tcp_waiting`).
    tcp_waiting: AtomicUsize,
    counters: Counters,
    keep_flows: usize,
    flows: Mutex<VecDeque<Flow>>,
    /// The DNS server of the network beneath the tunnel.
    upstream_dns: Mutex<Option<IpAddr>>,
    /// Names from the DNS answers Watch passed on, by address.
    names: Mutex<Names>,
    /// The offline table from address to organisation, if Watch has one.
    organisations: Option<Organisations>,
    /// Well-known public DNS resolvers.
    resolvers: Resolvers,
    /// The companies behind well-known networks.
    owners: Owners,
    next_id: AtomicU64,
    /// The flows open now, for the log.
    live: Mutex<HashMap<u64, Live>>,
    /// Lookups each app sent to Watch's own DNS address since the last segment.
    lookups: Mutex<HashMap<Option<u32>, Lookups>>,
    /// The bytes of open TCP flows by fake port, for the packets the tunnel carries.
    wire: Mutex<HashMap<u16, Arc<FlowBytes>>>,
    /// Records waiting to go to Watch's log.
    pending_log: Mutex<Vec<Record>>,
    /// Woken when a record waits or a flow opens.
    log_ready: Notify,
    /// Whether the answers of Watch's own DNS address go to the apps with a time to live of 0
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
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    fn keep(&self, flow: Flow) {
        let counter = match flow.outcome {
            Outcome::Opened => None,
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

/// The running engine. Dropping it stops the engine and closes the tunnel.
pub struct Engine {
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    network: watch::Sender<u64>,
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
        let shared = Arc::new(Shared {
            platform,
            addresses: config.addresses,
            limits: config.limits,
            tcp_waiting: AtomicUsize::new(0),
            counters: Counters::default(),
            keep_flows: config.keep_flows,
            flows: Mutex::new(VecDeque::new()),
            upstream_dns: Mutex::new(None),
            names: Mutex::new(Names::default()),
            organisations,
            resolvers: Resolvers::bundled(),
            owners: Owners::bundled(),
            next_id: AtomicU64::new(0),
            live: Mutex::default(),
            lookups: Mutex::default(),
            wire: Mutex::default(),
            pending_log: Mutex::default(),
            log_ready: Notify::new(),
            uncached_answers: AtomicBool::new(false),
            chain: Mutex::new(None),
            chains: AtomicU64::new(0),
            stand_ins: Mutex::default(),
            direct_answers: Mutex::default(),
            tool_answers: Mutex::default(),
            kept: Mutex::default(),
        });
        let (stop, stopped) = watch::channel(false);
        let (network, changes) = watch::channel(0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let state = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("watch-engine".into())
            .spawn(move || {
                runtime.block_on(async move {
                    match Tun::new(fd) {
                        Ok(tun) => run(tun, config.mtu, state, stopped, changes).await,
                        Err(_) => Counters::add(&state.counters.failed, 1),
                    }
                });
            })?;
        Ok(Self {
            shared,
            stop,
            network,
            thread: Some(thread),
        })
    }

    /// Stops the engine and waits for its thread: the tunnel's descriptor is closed, and with it the
    /// tunnel, and every connection relayed through it.
    pub fn stop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
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
            self.network
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }

    /// Turns chaining on with `chain`, or off with `None` (W6). New flows follow it, and TCP
    /// connections already open keep their way. A UDP mapping that it sends another way ends at its
    /// next datagram either way, so that the app's next one follows the new route (ADR 0044, decision
    /// 1); one through the same tool, reached the same way, stays. While a chain is on, every answer
    /// of Watch's DNS address reaches the apps with a time to live of 0 (ADR 0038).
    pub fn chain(&self, chain: Option<Chain>) {
        let on = chain.is_some();
        *lock(&self.shared.chain) = chain.map(Arc::new);
        // After the chain itself: a mapping that reads the new count reads the new chain too.
        self.shared.chains.fetch_add(1, Ordering::Release);
        self.shared.uncached_answers.store(on, Ordering::Relaxed);
        lock(&self.shared.direct_answers).clear();
        lock(&self.shared.tool_answers).clear();
        // A kept connection goes through the tool it was opened through: those answer the questions
        // already sent, then end.
        lock(&self.shared.kept).clear();
    }

    /// Whether the answers of Watch's own DNS address reach the apps with a time to live of 0, so that
    /// Android's resolver, which keeps one cache for all the apps of a network, keeps none of them:
    /// each app's lookup then reaches Watch with that app as its owner. Off by default.
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
    /// quarter hour would: for the end-to-end test, which cannot wait.
    pub fn flush_log(&self) {
        self.shared.checkpoint(now_ms());
        if let Some(batch) = self.shared.take_log() {
            self.shared.platform.log(&batch);
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
    listener4: u16,
    listener6: u16,
    changes: watch::Receiver<u64>,
}

async fn run(
    tun: Tun,
    mtu: u16,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
    changes: watch::Receiver<u64>,
) {
    let pending: Pending = Arc::default();
    let nat = Arc::new(Mutex::new(Nat::with_limits(&shared.limits)));
    let at = shared.addresses;
    let listener4 = listen(
        IpAddr::V4(at.tun4),
        IpAddr::V4(at.fake4),
        &pending,
        &shared,
        &nat,
    )
    .await;
    let listener6 = listen(
        IpAddr::V6(at.tun6),
        IpAddr::V6(at.fake6),
        &pending,
        &shared,
        &nat,
    )
    .await;
    let state = Loop {
        tun: Arc::new(tun),
        shared,
        nat,
        pending,
        udp: Arc::default(),
        listener4,
        listener6,
        changes,
    };
    let mut buffer = vec![0u8; usize::from(mtu).max(1500) + 64];
    let mut swept = Instant::now();
    let logging = tokio::spawn(logger(Arc::clone(&state.shared)));
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            read = state.tun.recv(&mut buffer) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                if swept.elapsed() > state.shared.limits.sweep_every {
                    state.sweep();
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
    // What is open ends with the tunnel; the log gets it before the engine's thread does.
    logging.abort();
    state.shared.finish_all();
    if let Some(batch) = state.shared.take_log() {
        state.shared.platform.log(&batch);
    }
}

impl Loop {
    /// One packet from the tunnel.
    async fn handle(&self, packet: &mut [u8]) {
        Counters::add(&self.shared.counters.packets_in, 1);
        match packet::parse(packet) {
            Ok(parsed) if parsed.protocol == TCP => {
                self.tcp(&mut packet[..parsed.length], &parsed).await;
            }
            Ok(parsed) => self.udp(&packet[..parsed.length], &parsed).await,
            Err(Skip::Fragment) => Counters::add(&self.shared.counters.fragments, 1),
            Err(Skip::Malformed | Skip::Other(_)) => {
                Counters::add(&self.shared.counters.skipped, 1);
            }
        }
    }

    async fn send(&self, packet: &[u8]) {
        if self.tun.send(packet).await.is_ok() {
            Counters::add(&self.shared.counters.packets_out, 1);
        }
    }

    fn ends(&self, v4: bool) -> (IpAddr, IpAddr, u16) {
        let at = self.shared.addresses;
        if v4 {
            (IpAddr::V4(at.tun4), IpAddr::V4(at.fake4), self.listener4)
        } else {
            (IpAddr::V6(at.tun6), IpAddr::V6(at.fake6), self.listener6)
        }
    }
}

/// Gives the app one packet through the tunnel.
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

    pub(super) fn shared() -> Shared {
        shared_with(Arc::new(NoPlatform))
    }

    fn shared_with(platform: Arc<dyn Platform>) -> Shared {
        Shared {
            platform,
            addresses: Addresses::COMMON,
            limits: Limits::default(),
            tcp_waiting: AtomicUsize::new(0),
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
            live: Mutex::default(),
            lookups: Mutex::default(),
            wire: Mutex::default(),
            pending_log: Mutex::default(),
            log_ready: Notify::new(),
            uncached_answers: AtomicBool::new(false),
            chain: Mutex::new(None),
            chains: AtomicU64::new(0),
            stand_ins: Mutex::default(),
            direct_answers: Mutex::default(),
            tool_answers: Mutex::default(),
            kept: Mutex::default(),
        }
    }

    const UID: u32 = 10_123;

    fn open_flow(shared: &Shared, destination: SocketAddr) -> Opened {
        let Begun {
            id,
            name,
            named_by,
            network,
        } = shared.begin(destination, Some(UID));
        let by_dns = (named_by == NamedBy::Dns)
            .then_some(name.as_deref())
            .flatten();
        let (dns, resolver) = shared.dns_use(destination, by_dns);
        shared.record(Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination,
            uid: Some(UID),
            outcome: Outcome::Opened,
            name,
            named_by,
            ech: Ech::Absent,
            dns,
            resolver,
            network,
        });
        Opened {
            id,
            port: destination.port(),
            dns,
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
        lock(&shared.names).insert(asked.ip(), None, "www.example.com", 60, now);
        lock(&shared.names).insert_public("cover.example", 60, now);
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

    #[test]
    fn a_hello_names_a_flow_in_w3s_order_unless_ech_hides_the_name() {
        let shared = shared();
        let now = Instant::now();
        let asked = SocketAddr::from(([93, 184, 216, 34], 443));
        lock(&shared.names).insert(asked.ip(), None, "www.example.com", 60, now);
        lock(&shared.names).insert_public("cover.example", 60, now);
        let by_dns = open_flow(&shared, asked);
        let by_quic = open_flow(&shared, SocketAddr::from(([203, 0, 113, 9], 443)));
        let hidden = open_flow(&shared, SocketAddr::from(([203, 0, 113, 10], 443)));
        let hidden_after_dns = open_flow(&shared, asked);

        // DNS comes first: a TLS name does not replace it.
        shared.hello(by_dns, &hello("other.example", false), NamedBy::Tls);
        // A QUIC name names a flow without one; ECH offered, perhaps GREASE, does not stop it.
        shared.hello(by_quic, &hello("quic.example", true), NamedBy::Quic);
        // A public name under ECH never names a flow, and the real name stays as DNS gave it.
        shared.hello(hidden, &hello("cover.example", true), NamedBy::Tls);
        shared.hello(
            hidden_after_dns,
            &hello("cover.example", true),
            NamedBy::Quic,
        );

        let flows = lock(&shared.flows);
        let seen: Vec<_> = flows
            .iter()
            .map(|f| (f.name.as_deref(), f.named_by, f.ech))
            .collect();
        assert_eq!(
            seen,
            vec![
                (Some("www.example.com"), NamedBy::Dns, Ech::Absent),
                (Some("quic.example"), NamedBy::Quic, Ech::Offered),
                (None, NamedBy::Unknown, Ech::Hidden),
                (Some("www.example.com"), NamedBy::Dns, Ech::Hidden),
            ]
        );
        // TLS and QUIC names read, QUIC unread, ECH offered, ECH hidden.
        assert_eq!(shared.counters.snapshot()[11..16], [2, 2, 0, 3, 2]);
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
        // Android's resolver through Watch: not the app's own.
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
        let shared = shared();
        let flow = |id: u64, destination: SocketAddr, outcome| Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination,
            uid: Some(UID),
            outcome,
            name: None,
            named_by: NamedBy::Unknown,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
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
        bytes.add_up(100);
        bytes.add_wire_up(140);
        bytes.add_down(5_000);
        bytes.add_wire_down(5_200);
        let started = lock(&shared.live)[&1].start;
        // A quarter hour passes: the open flow's first segment, and the lookups.
        shared.checkpoint(started + 1);
        bytes.add_down(700);
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
        tokio::spawn(run(
            Tun::new(OwnedFd::from(engine_end))?,
            1500,
            Arc::clone(&shared),
            stop,
            network,
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

        // A connection the engine rewrote, its upstream waiting under its fake port.
        let real = TcpSocket::new_v4()?;
        real.bind(SocketAddr::new(fake, 0))?;
        let port = real.local_addr()?.port();
        let nat = Arc::new(Mutex::new(Nat::with_ports(port, port)));
        let app = SocketAddr::from(([10, 215, 173, 1], 40_000));
        assert_eq!(
            lock(&nat).lookup(app, destination, true, Instant::now()),
            Lookup::New(port)
        );
        lock(&nat).open(port);
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

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        tokio::spawn(accept(
            listener,
            fake,
            Arc::clone(&pending),
            Arc::clone(&shared),
            Arc::clone(&nat),
        ));

        // Another app, straight to the listener, from the waiting connection's port.
        let stranger = TcpSocket::new_v4()?;
        stranger.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
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

    /// What Android's stack sends after the relay ended (the rest of a download, the last FIN and ACK)
    /// reaches the flow's last segment, which ends at the last packet, not when the rewriting went.
    #[test]
    fn a_closed_flows_last_segment_holds_what_the_tunnel_carried_after_its_relay() {
        let shared = shared();
        let Some(bytes) = shared.record(Flow {
            id: 1,
            protocol: TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination: SocketAddr::from(([198, 51, 100, 9], 443)),
            uid: Some(UID),
            outcome: Outcome::Opened,
            name: None,
            named_by: NamedBy::Unknown,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
        }) else {
            unreachable!("an open flow is live")
        };
        bytes.add_down(2_000_000);
        bytes.add_wire_down(1_500_000);
        // The relay is done; the rest of the download is still on its way to the app.
        bytes.add_wire_down(570_000);
        bytes.add_wire_up(19_000);
        let last = bytes.last.load(Ordering::Relaxed);
        assert!(last > 0);
        // The rewriting lingers on, silent, before it goes.
        std::thread::sleep(Duration::from_millis(20));
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
    fn dns_answer(name: &str, address: [u8; 4]) -> Vec<u8> {
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
    fn w3s_order_is_dns_tls_quic_then_the_organisation() {
        use NamedBy::{Dns, Organisation, Quic, Tls, Unknown};
        let order = [Dns, Tls, Quic, Organisation, Unknown];
        for (i, &better) in order.iter().enumerate() {
            for &worse in &order[i + 1..] {
                assert!(worse.yields_to(better) && !better.yields_to(worse));
            }
        }
    }
}
