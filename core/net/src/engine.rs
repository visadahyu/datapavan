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
//!
//! An app's ping leaves through a protected ping socket of the engine's own, and is refused while a
//! chain is on, since Android cannot name its app (ADR 0044, decision 5).
//!
//! The apps' fragments are put together again, and the "fragmentation needed" and "packet too big"
//! that routers beyond the first hop send the engine's sockets reach the apps, with their MTU. The
//! engine answers nothing as too large on its own: the tunnel's MTU is the first hop's, which Watch's
//! Kotlin side reads and sets, so the apps' own kernels meet it as they would without Watch (decision 5
//! as amended on 2026-11-15).

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

mod budget;
mod chain;
mod echo;
mod errors;
mod kept;
mod logbook;
mod lookups;
mod naming;
mod tcp;
mod udp;
mod upstream;
mod whose;

use budget::Budget;
pub use chain::Chain;
use echo::Echoes;
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
    /// At most this many datagrams are put together from the apps' fragments at once (ADR 0044,
    /// decision 5 as amended): for a fragment of one more, the oldest incomplete one gives way.
    pub fragment_datagrams: usize,
    /// At most this many bytes of fragments are held across them ([`crate::fragments::Bounds`]); past
    /// it, the oldest incomplete datagrams give way too.
    pub fragment_bytes: usize,
    /// A datagram whose last fragment has not come this long after its first is dropped. A sender
    /// sends a datagram's fragments one after another, within milliseconds.
    pub fragment_wait: Duration,
    /// A write to the tunnel that the tunnel refuses waits this long, off the event loop, for the
    /// tunnel set up again to take its place, and goes there (ADR 0044, unit 12b): Android resets the
    /// old interface before Watch hands the engine the new one, and a tun device whose interface is
    /// down refuses writes. Watch's Kotlin side hands it over as soon as `establish()` returns, within
    /// milliseconds; without a new tunnel by then, the packet is dropped, as before.
    pub tunnel_wait: Duration,
    /// The first of the fake ports handed out, `first_port..=last_port`.
    pub first_port: u16,
    /// The last of them.
    pub last_port: u16,
}

impl Limits {
    /// The product's limits for a process that may open `descriptors` files (its soft limit): a
    /// reserve of a sixteenth, at least 128, stays for Watch itself; waiting TCP connections may use an
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
            stand_ins: crate::standins::CAPACITY,
            echo_sockets: 32,
            echo_idle: Duration::from_secs(10),
            fragment_datagrams: 64,
            fragment_bytes: 1 << 20,
            fragment_wait: Duration::from_secs(5),
            tunnel_wait: Duration::from_millis(200),
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
pub const COUNTERS: usize = 41;

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
}

impl Counters {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
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
    /// proxy's own address, which Watch refused, and datagrams and lookups dropped because who sent
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
    /// "packet too big" routers sent the engine's sockets, passed on to the apps. None names a
    /// destination: they can be read on any phone. New counters are only ever appended, so that scripts
    /// reading a column by its place keep reading the same one.
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
        ]
    }
}

/// What Watch last set on its engines from outside: the chain, and whether answers go uncached, which
/// goes with it ([`Engine::chain`]). Watch's native side keeps it whether or not an engine runs, so that
/// a chain set while none does, as in the moment of a swap, is the next engine's from its first packet
/// (fourth check of unit 12, minor 1); it wins over what the engine before handed over, which it may
/// be newer than.
#[derive(Clone, Debug)]
pub struct ChainSetting {
    /// The chain, or `None` for none.
    pub chain: Option<Chain>,
    /// Whether the answers of the tunnel's DNS address go to the apps with a time to live of 0.
    pub uncached_answers: bool,
}

/// What an engine hands the next when the tunnel is set up again (ADR 0044, decision 5 as amended): what
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
}

/// What the engine's thread and its controller share.
struct Shared {
    platform: Arc<dyn Platform>,
    /// The tunnel's addresses for this run.
    addresses: Addresses,
    limits: Limits,
    /// TCP connections waiting for their servers now (`Limits::tcp_waiting`).
    tcp_waiting: AtomicUsize,
    /// Each app's share of them, once Android has named it (`Limits::tcp_share`).
    tcp_shares: Arc<Budget>,
    /// The UDP ways that hold a socket of their own, for every app together and for each
    /// (`Limits::udp_mappings`, `Limits::udp_share`).
    udp_budget: Arc<Budget>,
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
    /// over ([`Engine::hand_over`]), and with the chain Watch last set, which wins over the one handed
    /// over: all of it is in place before the new engine's thread reads its first packet.
    ///
    /// # Errors
    /// When the thread or its event loop cannot be made.
    pub fn start_with(
        fd: OwnedFd,
        config: Config,
        platform: Arc<dyn Platform>,
        organisations: Option<Organisations>,
        (handover, setting): (Option<Handover>, Option<ChainSetting>),
    ) -> io::Result<Self> {
        let Handover {
            mut chain,
            upstream_dns,
            mut uncached_answers,
            stand_ins,
            names,
            counters,
        } = handover.unwrap_or_else(|| Handover {
            chain: None,
            upstream_dns: None,
            uncached_answers: false,
            stand_ins: StandIns::with_capacity(config.limits.stand_ins),
            names: Names::default(),
            counters: [0; COUNTERS],
        });
        if let Some(setting) = setting {
            chain = setting.chain.map(Arc::new);
            uncached_answers = setting.uncached_answers;
        }
        let shared = Arc::new(Shared {
            platform,
            addresses: config.addresses,
            limits: config.limits,
            tcp_waiting: AtomicUsize::new(0),
            tcp_shares: Budget::new(config.limits.tcp_waiting, config.limits.tcp_share),
            udp_budget: Budget::new(config.limits.udp_mappings, config.limits.udp_share),
            counters: Counters::going_on_from(&counters),
            keep_flows: config.keep_flows,
            flows: Mutex::new(VecDeque::new()),
            upstream_dns: Mutex::new(upstream_dns),
            names: Mutex::new(names),
            organisations,
            resolvers: Resolvers::bundled(),
            owners: Owners::bundled(),
            next_id: AtomicU64::new(0),
            live: Mutex::default(),
            lookups: Mutex::default(),
            wire: Mutex::default(),
            pending_log: Mutex::default(),
            log_ready: Notify::new(),
            uncached_answers: AtomicBool::new(uncached_answers),
            chain: Mutex::new(chain),
            chains: AtomicU64::new(0),
            stand_ins: Mutex::new(stand_ins),
            direct_answers: Mutex::default(),
            tool_answers: Mutex::default(),
            kept: Mutex::default(),
        });
        let (stop, stopped) = watch::channel(false);
        let (network, changes) = watch::channel(0);
        let (swaps, swapped) = mpsc::unbounded_channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let state = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("watch-engine".into())
            .spawn(move || {
                runtime.block_on(async move {
                    match Tun::waiting(fd, config.limits.tunnel_wait) {
                        Ok(tun) => run(tun, config.mtu, state, stopped, changes, swapped).await,
                        Err(_) => Counters::add(&state.counters.failed, 1),
                    }
                });
            })?;
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
        self.stop();
        let shared = &self.shared;
        Handover {
            chain: lock(&shared.chain).clone(),
            upstream_dns: *lock(&shared.upstream_dns),
            uncached_answers: shared.uncached_answers.load(Ordering::Relaxed),
            stand_ins: std::mem::replace(&mut *lock(&shared.stand_ins), StandIns::with_capacity(0)),
            names: std::mem::take(&mut *lock(&shared.names)),
            counters: shared.counters.snapshot(),
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
    echoes: Echoes,
    /// The apps' fragments, put together again. Every app sends from the tunnel's one address, so
    /// the bounds are shared: one app that fills them makes the others' fragments dropped, as all
    /// were before. Accepted, since the bounds cap what they cost.
    fragments: Mutex<Reassembler>,
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
    mut swaps: mpsc::UnboundedReceiver<Swap>,
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
    let limits = shared.limits;
    let state = Loop {
        tun: Arc::new(tun),
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
        listener4,
        listener6,
        changes,
    };
    // Sized from the first tunnel's MTU, and never smaller than 1,500 bytes: a tunnel set up again and
    // handed over (`Engine::swap_tunnel`) keeps this buffer, which holds its packets too, since Watch
    // never gives the tunnel an MTU above 1,500 (ADR 0044, decision 5 as amended).
    let mut buffer = vec![0u8; usize::from(mtu).max(1500) + 64];
    let mut swept = Instant::now();
    let (end_logging, logging_ends) = watch::channel(false);
    let logging = tokio::spawn(logger(Arc::clone(&state.shared), logging_ends));
    loop {
        // Polled in this order, not at random: a stop, then a new tunnel, which their callers wait for,
        // before another batch of reads. What is still queued on the old tunnel is then read by
        // `Loop::take_tunnel` before it closes; read here first, it would be handled the same.
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            Some(swap) = swaps.recv() => state.take_tunnel(swap, &mut buffer).await,
            read = state.tun.recv(&mut buffer) => {
                let Ok(n) = read else { break };
                if n == 0 {
                    break;
                }
                if swept.elapsed() > state.shared.limits.sweep_every {
                    state.sweep();
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
                    self.forward(&mut whole, parsed).await;
                }
            }
            parsed => self.forward(packet, parsed).await,
        }
    }

    /// One whole packet, as `parse` read it: TCP, UDP, an echo request, or skipped.
    async fn forward(&self, packet: &mut [u8], parsed: Result<packet::Packet, Skip>) {
        match parsed {
            Ok(parsed) if parsed.protocol == TCP => {
                self.tcp(&mut packet[..parsed.length], &parsed).await;
            }
            Ok(parsed) => self.udp(&packet[..parsed.length], &parsed).await,
            Err(Skip::Other(packet::ICMP | packet::ICMPV6)) => match packet::echo_request(packet) {
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

    /// Gives the app one packet through the tunnel, from the event loop. One the tunnel refuses, as
    /// between Android's reset of the old interface and the swap, waits for the next tunnel in a task
    /// of its own (`Tun::send`), so that the loop reads on meanwhile.
    async fn send(&self, packet: &[u8]) {
        match self.tun.send_once(packet).await {
            Ok(_) => Counters::add(&self.shared.counters.packets_out, 1),
            Err(_) if self.tun.waits() => {
                let (tun, shared) = (Arc::clone(&self.tun), Arc::clone(&self.shared));
                let packet = packet.to_vec();
                tokio::spawn(async move { send_to_app(&tun, &shared, &packet).await });
            }
            Err(_) => {}
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
}

/// The MTU the kernel keeps for the route of a connected socket (`IP_MTU`), or `None` when it says
/// nothing, as for a socket not connected. Watch's Kotlin side reads the first hop's MTU of the network
/// beneath with it, from a UDP socket bound to that network and connected toward an address only its
/// default route covers, and gives the tunnel that MTU (ADR 0044, decision 5 as amended). On Linux
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

    fn shared_with(platform: Arc<dyn Platform>) -> Shared {
        Shared {
            platform,
            addresses: Addresses::COMMON,
            limits: Limits::default(),
            tcp_waiting: AtomicUsize::new(0),
            tcp_shares: Budget::new(Limits::default().tcp_waiting, Limits::default().tcp_share),
            udp_budget: Budget::new(Limits::default().udp_mappings, Limits::default().udp_share),
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

    /// What the gap between Android's reset of the old interface and the swap is made of here: an
    /// engine whose old tunnel refuses its writes, as a tun device whose interface is down does (the
    /// app's end has shut its reading, so the engine's writes fail, while the app can still send), and
    /// waits up to `wait` for a new one; a server that echoes; the new tunnel's app end; and the swaps.
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
        async fn new(wait: Duration) -> io::Result<Self> {
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
            old_app.shutdown(std::net::Shutdown::Read)?;
            let (stopping, stop) = watch::channel(false);
            let (moving, network) = watch::channel(0);
            let (swaps, swapped) = mpsc::unbounded_channel();
            tokio::spawn(run(
                Tun::waiting(OwnedFd::from(old_engine), wait)?,
                1500,
                Arc::clone(&shared),
                stop,
                network,
                swapped,
            ));
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
        let mut gap = Gap::new(Duration::from_secs(2)).await?;
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
        let mut gap = Gap::new(Duration::from_millis(100)).await?;
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

    /// A descriptor tokio cannot register, here `/dev/null`, which epoll refuses, is refused, so that
    /// Watch's Kotlin side starts an engine instead; the engine goes on with the tunnel it had.
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
