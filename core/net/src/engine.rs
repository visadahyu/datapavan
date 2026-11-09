//! The forwarder (ADR 0012): Android's own TCP stack terminates every app's connection, reached by
//! rewriting addresses, and the engine relays each one over a protected socket of its own to the
//! real destination. UDP is relayed in userspace through a table of flows.
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

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::dns;
use crate::names::Names;
use crate::nat::{Lookup, Nat};
use crate::organisations::Organisations;
use crate::owners::{NetworkKind, Owners};
use crate::packet::{self, ACK, Packet, RST, SYN, Skip, TCP, UDP, Unreachable};
use crate::quic;
use crate::resolvers::Resolvers;
use crate::tls::{self, Hello, ServerName};
use crate::tun::Tun;

/// The tunnel's IPv4 address, a /32 (ADR 0034: a wider prefix would count as local network on
/// Android 17 and fail without its permission).
pub const TUN4: Ipv4Addr = Ipv4Addr::new(10, 215, 173, 1);
/// The fake peer the kernel sees for every rewritten IPv4 connection, outside the /32.
pub const FAKE4: Ipv4Addr = Ipv4Addr::new(10, 215, 173, 2);
/// The DNS server Android is given inside the tunnel; the engine passes its queries to the DNS
/// server of the network beneath.
pub const DNS4: Ipv4Addr = Ipv4Addr::new(10, 215, 173, 3);
/// The tunnel's IPv6 address, a /128.
pub const TUN6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 1);
/// The IPv6 fake peer.
pub const FAKE6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 2);
/// The IPv6 DNS server inside the tunnel.
pub const DNS6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 3);

/// A UDP flow silent for this long is closed.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// How long a connection to a server may take before the app is told it is unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a closed connection's rewriting stays, for the last FIN and ACK packets.
const CLOSE_LINGER: Duration = Duration::from_secs(30);
/// The most packets read after one wake-up before the engine waits again.
const BATCH: usize = 64;
/// Stale TCP connections are swept at most this often, and only when packets come anyway: an idle
/// tunnel must not wake the phone.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// What the engine asks of Android, through Watch's Kotlin side.
pub trait Platform: Send + Sync + 'static {
    /// `ConnectivityManager.getConnectionOwnerUid`: the UID of the app with a socket from `local` to
    /// `remote`, or `None` when Android does not know.
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32>;

    /// `VpnService.protect`: keeps one of the engine's sockets out of the tunnel.
    fn protect(&self, fd: RawFd) -> bool;
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

/// A new flow's number and first name.
struct Begun {
    id: u64,
    name: Option<String>,
    named_by: NamedBy,
    network: Option<Network>,
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
}

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
}

impl Counters {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused, unreachable,
    /// failed, packets skipped, packets in, packets out, server names read from TLS and from QUIC, QUIC
    /// flows whose name could not be read, hellos that offered ECH, hellos whose name was an ECH public
    /// name, and flows of an app's own plain and encrypted DNS. None names a destination: they can be
    /// read on any phone.
    #[must_use]
    pub fn snapshot(&self) -> [u64; 18] {
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
        ]
        .map(|c| c.load(Ordering::Relaxed))
    }
}

/// What the engine's thread and its controller share.
struct Shared {
    platform: Arc<dyn Platform>,
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
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// A new flow's number and its first name: from the DNS answers the app was given, else from the
    /// organisation of the destination's network, as the company people know when the owners' table
    /// names it. A TLS or QUIC server name may come later.
    fn begin(&self, destination: SocketAddr, uid: Option<u32>) -> Begun {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(name) = lock(&self.names).get(destination.ip(), uid, Instant::now()) {
            return Begun {
                id,
                name: Some(name.to_owned()),
                named_by: NamedBy::Dns,
                network: None,
            };
        }
        match self
            .organisations
            .as_ref()
            .and_then(|table| table.lookup(destination.ip()))
        {
            Some(organisation) => {
                let owner = self.owners.of(organisation.asn);
                Begun {
                    id,
                    network: Some(Network {
                        asn: organisation.asn,
                        kind: owner.map_or(NetworkKind::Unlisted, |o| o.kind),
                    }),
                    name: Some(owner.map_or(organisation.name, |o| o.name.clone())),
                    named_by: NamedBy::Organisation,
                }
            }
            None => Begun {
                id,
                name: None,
                named_by: NamedBy::Unknown,
                network: None,
            },
        }
    }

    /// Whether a flow to `destination`, named `name` by DNS if at all, carries the app's own DNS, and
    /// to which known resolver: port 53 to another server than Watch's, port 853, or port 443 to a
    /// known resolver's address or host name.
    fn dns_use(&self, destination: SocketAddr, name: Option<&str>) -> (DnsUse, Option<String>) {
        let known = self
            .resolvers
            .at(destination.ip())
            .or_else(|| name.and_then(|n| self.resolvers.named(n)))
            .map(str::to_owned);
        match destination.port() {
            53 if !is_tunnel_dns(destination.ip()) => (DnsUse::Plain, known),
            853 => (DnsUse::Encrypted, known),
            443 if known.is_some() => (DnsUse::Encrypted, known),
            _ => (DnsUse::None, None),
        }
    }

    /// Notes what a flow's TLS or QUIC hello said: its server name names the flow by W3's order,
    /// unless it is the public name of an ECH configuration, behind which the real name is hidden. A
    /// known resolver's host name marks the flow as the app's own encrypted DNS.
    fn hello(&self, opened: Opened, hello: Hello, by: NamedBy) {
        let id = opened.id;
        let hidden = hello.ech && lock(&self.names).is_public(&hello.name, Instant::now());
        let resolver = matches!(opened.port, 443 | 853)
            .then(|| self.resolvers.named(&hello.name))
            .flatten()
            .map(str::to_owned);
        let counters = &self.counters;
        if resolver.is_some() && opened.dns == DnsUse::None {
            Counters::add(&counters.dns_encrypted, 1);
        }
        Counters::add(
            if by == NamedBy::Quic {
                &counters.quic_names
            } else {
                &counters.tls_names
            },
            1,
        );
        if hello.ech {
            Counters::add(&counters.ech_offered, 1);
        }
        if hidden {
            Counters::add(&counters.ech_hidden, 1);
        }
        if self.keep_flows == 0 {
            return;
        }
        if let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id) {
            flow.ech = match (hello.ech, hidden) {
                (_, true) => Ech::Hidden,
                (true, false) => Ech::Offered,
                (false, false) => Ech::Absent,
            };
            if let Some(resolver) = resolver {
                flow.dns = DnsUse::Encrypted;
                flow.resolver.get_or_insert(resolver);
            }
            if !hidden && flow.named_by.yields_to(by) {
                flow.name = Some(hello.name);
                flow.named_by = by;
            }
        }
    }

    /// Learns the names in a DNS answer passed back to an app: for every app's flows from Android's
    /// resolver, or for one app's flows from a resolver of its own. ECH public names are taken only
    /// from Android's: they hide names in every app's flows.
    fn learn(&self, answer: &[u8], scope: Option<u32>) {
        if let Some(response) = dns::response(answer) {
            let now = Instant::now();
            let mut names = lock(&self.names);
            for (address, ttl) in response.addresses {
                names.insert(address, scope, &response.question, ttl, now);
            }
            if scope.is_none() {
                for (public, ttl) in response.public_names {
                    names.insert_public(&public, ttl, now);
                }
            }
        }
    }

    fn record(&self, flow: Flow) {
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

    /// Where a flow to `destination` really goes: the network's DNS server for the tunnel's own DNS
    /// address, else the destination itself.
    fn target(&self, destination: SocketAddr) -> Option<SocketAddr> {
        if is_tunnel_dns(destination.ip()) {
            return lock(&self.upstream_dns).map(|dns| SocketAddr::new(dns, destination.port()));
        }
        Some(destination)
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
            counters: Counters::default(),
            keep_flows: config.keep_flows,
            flows: Mutex::new(VecDeque::new()),
            upstream_dns: Mutex::new(None),
            names: Mutex::new(Names::default()),
            organisations,
            resolvers: Resolvers::bundled(),
            owners: Owners::bundled(),
            next_id: AtomicU64::new(0),
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
    /// the network itself is another one (`moved`), UDP flows are closed, so that their next datagram
    /// goes out on the new network; TCP connections on the old network end by themselves, as without a
    /// VPN. A change of the same network's properties closes nothing: Android reports several after
    /// each switch.
    pub fn network_changed(&self, dns: Option<IpAddr>, moved: bool) {
        *lock(&self.shared.upstream_dns) = dns;
        if moved {
            self.network
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
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
    pub fn counters(&self) -> [u64; 18] {
        self.shared.counters.snapshot()
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

/// An upstream connection waiting for Android's TCP stack to hand over the app's end.
struct Upstream {
    stream: TcpStream,
    /// The flow, as it opened.
    opened: Opened,
}

type Pending = Arc<Mutex<HashMap<u16, Upstream>>>;
/// A UDP flow: the protected socket, and while its first datagrams may still name it, their QUIC
/// Initial packets read so far, with the flow's number.
struct UdpFlow {
    socket: Arc<UdpSocket>,
    quic: Option<(Opened, quic::Initial)>,
}

type UdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpFlow>>>;

/// A UDP flow's two ends and its app's UID, for the task that relays its answers.
struct UdpEnds {
    app: SocketAddr,
    destination: SocketAddr,
    uid: Option<u32>,
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
    let nat: Arc<Mutex<Nat>> = Arc::default();
    let listener4 = listen(IpAddr::V4(TUN4), &pending, &shared, &nat).await;
    let listener6 = listen(IpAddr::V6(TUN6), &pending, &shared, &nat).await;
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
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            read = state.tun.recv(&mut buffer) => {
                let Ok(n) = read else { return };
                if n == 0 {
                    return;
                }
                if swept.elapsed() > SWEEP_EVERY {
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
}

/// Binds the listener that terminates rewritten connections of one IP version and accepts them in
/// a task of its own; returns its port, or 0 when the tunnel has no address of that version.
async fn listen(
    address: IpAddr,
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
        Arc::clone(pending),
        Arc::clone(shared),
        Arc::clone(nat),
    ));
    port
}

impl Loop {
    /// Forgets connections that fell silent, and the upstream connections still waiting for them.
    fn sweep(&self) {
        let forgotten = lock(&self.nat).sweep(Instant::now());
        let mut pending = lock(&self.pending);
        for port in forgotten {
            pending.remove(&port);
        }
    }

    /// One packet from the tunnel.
    async fn handle(&self, packet: &mut [u8]) {
        Counters::add(&self.shared.counters.packets_in, 1);
        match packet::parse(packet) {
            Ok(parsed) if parsed.protocol == TCP => {
                self.tcp(&mut packet[..parsed.length], &parsed).await;
            }
            Ok(parsed) => self.udp(&packet[..parsed.length], &parsed).await,
            Err(Skip::Malformed | Skip::Fragment | Skip::Other(_)) => {
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
        if v4 {
            (IpAddr::V4(TUN4), IpAddr::V4(FAKE4), self.listener4)
        } else {
            (IpAddr::V6(TUN6), IpAddr::V6(FAKE6), self.listener6)
        }
    }

    async fn tcp(&self, packet: &mut [u8], parsed: &Packet) {
        let (tun, fake, listener) = self.ends(parsed.source.is_ipv4());
        let flags = packet::tcp_flags(packet, parsed);
        let now = Instant::now();
        if listener != 0
            && parsed.source == SocketAddr::new(tun, listener)
            && parsed.destination.ip() == fake
        {
            // Android's answer, back to the app as if from the real destination.
            let Some(entry) = lock(&self.nat).by_fake(parsed.destination.port(), now) else {
                return;
            };
            if packet::set_ends(packet, parsed, entry.destination, entry.app).is_some() {
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

    async fn udp(&self, packet: &[u8], parsed: &Packet) {
        let Some(payload) = packet::udp_payload(packet, parsed) else {
            Counters::add(&self.shared.counters.skipped, 1);
            return;
        };
        let key = (parsed.source, parsed.destination);
        let existing = lock(&self.udp)
            .get(&key)
            .map(|flow| Arc::clone(&flow.socket));
        let socket = if let Some(socket) = existing {
            socket
        } else {
            let Some(socket) = self.open_udp(packet, parsed).await else {
                return;
            };
            socket
        };
        self.read_quic(key, payload);
        match socket.send(payload).await {
            Ok(n) => Counters::add(&self.shared.counters.bytes_up, n as u64),
            Err(_) => {
                if let Some(error) = packet::unreachable(packet, parsed, Unreachable::Host) {
                    self.send(&error).await;
                }
            }
        }
    }

    /// Reads a datagram of a UDP flow that may still be named by its QUIC Initial packets.
    fn read_quic(&self, key: (SocketAddr, SocketAddr), payload: &[u8]) {
        let mut flows = lock(&self.udp);
        let Some(flow) = flows.get_mut(&key) else {
            return;
        };
        let Some((opened, initial)) = flow.quic.as_mut() else {
            return;
        };
        let opened = *opened;
        let read = initial.push(payload);
        if read == ServerName::Incomplete {
            return;
        }
        let was_quic = initial.is_quic();
        flow.quic = None;
        drop(flows);
        match read {
            ServerName::Found(hello) => self.shared.hello(opened, hello, NamedBy::Quic),
            _ if was_quic => Counters::add(&self.shared.counters.quic_unread, 1),
            _ => {}
        }
    }

    /// Opens a UDP flow's protected socket, asks Android whose the flow is, and starts relaying the
    /// answers. The app gets an ICMP error when the destination cannot be reached.
    async fn open_udp(&self, packet: &[u8], parsed: &Packet) -> Option<Arc<UdpSocket>> {
        let (app, destination) = (parsed.source, parsed.destination);
        let uid = owner(&self.shared, UDP, app, destination).await;
        let Begun {
            id,
            name,
            named_by,
            network,
        } = self.shared.begin(destination, uid);
        let by_dns = (named_by == NamedBy::Dns)
            .then_some(name.as_deref())
            .flatten();
        let (dns, resolver) = self.shared.dns_use(destination, by_dns);
        let opened = Opened {
            id,
            port: destination.port(),
            dns,
        };
        let mut flow = Flow {
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
        let Some(target) = self.shared.target(destination) else {
            flow.outcome = Outcome::Unreachable;
            self.shared.record(flow);
            if let Some(error) = packet::unreachable(packet, parsed, Unreachable::Host) {
                self.send(&error).await;
            }
            return None;
        };
        let socket = match connect_udp(&self.shared, target).await {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                flow.outcome = if is_unreachable(&error) {
                    Outcome::Unreachable
                } else {
                    Outcome::Failed
                };
                let unreachable = flow.outcome == Outcome::Unreachable;
                self.shared.record(flow);
                if unreachable
                    && let Some(error) = packet::unreachable(packet, parsed, Unreachable::Host)
                {
                    self.send(&error).await;
                }
                return None;
            }
        };
        self.shared.record(flow);
        // The tunnel's own DNS address is never QUIC.
        let quic = (!is_tunnel_dns(destination.ip())).then(|| (opened, quic::Initial::new()));
        lock(&self.udp).insert(
            (app, destination),
            UdpFlow {
                socket: Arc::clone(&socket),
                quic,
            },
        );
        tokio::spawn(answers(
            Arc::clone(&socket),
            UdpEnds {
                app,
                destination,
                uid,
            },
            Arc::clone(&self.tun),
            Arc::clone(&self.shared),
            Arc::clone(&self.udp),
            self.changes.clone(),
        ));
        Some(socket)
    }
}

/// Asks Android whose a flow is, off the event loop: the answer comes over Binder.
async fn owner(
    shared: &Arc<Shared>,
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u32> {
    let platform = Arc::clone(&shared.platform);
    tokio::task::spawn_blocking(move || platform.owner(protocol, local, remote))
        .await
        .ok()
        .flatten()
}

/// Protects a socket of the engine's own, off the event loop: the answer comes over Binder.
async fn protect(shared: &Arc<Shared>, fd: RawFd) -> io::Result<()> {
    let platform = Arc::clone(&shared.platform);
    if tokio::task::spawn_blocking(move || platform.protect(fd))
        .await
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(io::Error::other("protect() refused"))
    }
}

/// Whether `address` is the tunnel's own DNS address, which leads to the network's resolver.
fn is_tunnel_dns(address: IpAddr) -> bool {
    address == IpAddr::V4(DNS4) || address == IpAddr::V6(DNS6)
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

async fn connect_tcp(shared: &Arc<Shared>, target: SocketAddr) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(shared, socket.as_raw_fd()).await?;
    match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
        Ok(connected) => connected,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

async fn connect_udp(shared: &Arc<Shared>, target: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(packet::unspecified_like(&target)).await?;
    protect(shared, socket.as_raw_fd()).await?;
    socket.connect(target).await?;
    Ok(socket)
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
    shared.record(Flow {
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
        lock(&pending).insert(held.port, Upstream { stream, opened });
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
        lock(&nat).remove(held.port);
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
async fn accept(
    listener: TcpListener,
    pending: Pending,
    shared: Arc<Shared>,
    nat: Arc<Mutex<Nat>>,
) {
    while let Ok((app, peer)) = listener.accept().await {
        let port = peer.port();
        let Some(upstream) = lock(&pending).remove(&port) else {
            continue;
        };
        let Some(entry) = lock(&nat).by_fake(port, Instant::now()) else {
            continue;
        };
        let (shared, nat) = (Arc::clone(&shared), Arc::clone(&nat));
        tokio::spawn(async move {
            relay(app, upstream, &shared).await;
            // Android's last FIN and ACK still need rewriting for a while; then the port is free.
            tokio::time::sleep(CLOSE_LINGER).await;
            lock(&nat).remove_if(port, entry.app, entry.destination);
        });
    }
}

/// Relays one connection both ways, counting the bytes as they pass. The app's first bytes are read
/// for a TLS hello (at most [`tls::MAX_HELLO`]), even when DNS named the flow, since only the hello
/// tells whether ECH hid the name; nothing is held back for that, so a protocol in which the server
/// speaks first is not delayed.
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
                        shared.hello(upstream.opened, hello, NamedBy::Tls);
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
        }
        let _ = app_write.shutdown().await;
    };
    tokio::join!(up, down);
}

/// Wraps each answer of a UDP flow in an IP packet to the app, until the flow falls silent or the
/// network beneath changes.
async fn answers(
    socket: Arc<UdpSocket>,
    ends: UdpEnds,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
    let UdpEnds {
        app,
        destination,
        uid,
    } = ends;
    let mut buffer = vec![0u8; 65_535];
    // Only a change after the flow opened ends it: a clone starts with the loop's last-seen version.
    changes.borrow_and_update();
    loop {
        tokio::select! {
            _ = changes.changed() => break,
            received = tokio::time::timeout(UDP_IDLE, socket.recv(&mut buffer)) => {
                let Ok(received) = received else { break };
                let answer = match received {
                    Ok(n) => {
                        Counters::add(&shared.counters.bytes_down, n as u64);
                        // Android's resolver names every app's flows; an app's own, only its own.
                        if destination.port() == 53 {
                            if is_tunnel_dns(destination.ip()) {
                                shared.learn(&buffer[..n], None);
                            } else if uid.is_some() {
                                shared.learn(&buffer[..n], uid);
                            }
                        }
                        packet::udp(destination, app, &buffer[..n])
                    }
                    // The server's host answered that no one listens there.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        let quoted = packet::udp(app, destination, &[]);
                        quoted.and_then(|q| packet::parse(&q).ok().and_then(|p| packet::unreachable(&q, &p, Unreachable::Port)))
                    }
                    Err(_) => break,
                };
                if let Some(answer) = answer {
                    if tun.send(&answer).await.is_err() {
                        break;
                    }
                    Counters::add(&shared.counters.packets_out, 1);
                }
            }
        }
    }
    lock(&flows).remove(&(app, destination));
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
    }

    fn shared() -> Shared {
        Shared {
            platform: Arc::new(NoPlatform),
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
        shared.hello(by_dns, hello("other.example", false), NamedBy::Tls);
        // A QUIC name names a flow without one; ECH offered, perhaps GREASE, does not stop it.
        shared.hello(by_quic, hello("quic.example", true), NamedBy::Quic);
        // A public name under ECH never names a flow, and the real name stays as DNS gave it.
        shared.hello(hidden, hello("cover.example", true), NamedBy::Tls);
        shared.hello(
            hidden_after_dns,
            hello("cover.example", true),
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
        let tunnel = open_flow(&shared, SocketAddr::new(IpAddr::V4(DNS4), 53));
        // DNS over TLS anywhere, and DNS over HTTPS to a known address, or to a known name in the hello.
        let dot = open_flow(&shared, at([198, 51, 100, 1], 853));
        let doh = open_flow(&shared, at([192, 0, 2, 53], 443));
        let doh_by_name = open_flow(&shared, at([198, 51, 100, 2], 443));
        shared.hello(
            doh_by_name,
            hello("doh.sample.example", false),
            NamedBy::Tls,
        );
        let web = open_flow(&shared, at([198, 51, 100, 3], 443));
        shared.hello(web, hello("www.example.com", false), NamedBy::Tls);
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
        assert_eq!(shared.counters.snapshot()[16..], [1, 3]);
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
