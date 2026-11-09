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
use crate::packet::{self, ACK, Packet, RST, SYN, Skip, TCP, UDP, Unreachable};
use crate::tls::{self, ServerName};
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
            Self::Organisation => 3,
            Self::Unknown => 4,
        };
        rank(other) < rank(self)
    }
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
}

impl Counters {
    fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused, unreachable,
    /// failed, packets skipped, packets in, packets out.
    #[must_use]
    pub fn snapshot(&self) -> [u64; 11] {
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
    next_id: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// A new flow's number and its first name: from the DNS answers Watch passed on, else from the
    /// organisation of the destination's network. A TLS or QUIC server name may come later.
    fn begin(&self, destination: SocketAddr) -> (u64, Option<String>, NamedBy) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(name) = lock(&self.names).get(destination.ip(), Instant::now()) {
            return (id, Some(name.to_owned()), NamedBy::Dns);
        }
        match self
            .organisations
            .as_ref()
            .and_then(|table| table.lookup(destination.ip()))
        {
            Some(organisation) => (id, Some(organisation.name), NamedBy::Organisation),
            None => (id, None, NamedBy::Unknown),
        }
    }

    /// Gives a recorded flow a better name, by W3's order.
    fn name(&self, id: u64, name: String, named_by: NamedBy) {
        if self.keep_flows == 0 {
            return;
        }
        if let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
            && flow.named_by.yields_to(named_by)
        {
            flow.name = Some(name);
            flow.named_by = named_by;
        }
    }

    /// Learns the names in a DNS answer passed back to an app.
    fn learn(&self, answer: &[u8]) {
        if let Some(response) = dns::response(answer) {
            let now = Instant::now();
            let mut names = lock(&self.names);
            for (address, ttl) in response.addresses {
                names.insert(address, &response.question, ttl, now);
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
    pub fn counters(&self) -> [u64; 11] {
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
    /// The flow's number.
    id: u64,
    /// Whether the flow already has a name from DNS; else the relay looks for the TLS server name.
    named: bool,
}

type Pending = Arc<Mutex<HashMap<u16, Upstream>>>;
type UdpFlows = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpSocket>>>>;

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
        let existing = lock(&self.udp).get(&key).cloned();
        let socket = if let Some(socket) = existing {
            socket
        } else {
            let Some(socket) = self.open_udp(packet, parsed).await else {
                return;
            };
            socket
        };
        match socket.send(payload).await {
            Ok(n) => Counters::add(&self.shared.counters.bytes_up, n as u64),
            Err(_) => {
                if let Some(error) = packet::unreachable(packet, parsed, Unreachable::Host) {
                    self.send(&error).await;
                }
            }
        }
    }

    /// Opens a UDP flow's protected socket, asks Android whose the flow is, and starts relaying the
    /// answers. The app gets an ICMP error when the destination cannot be reached.
    async fn open_udp(&self, packet: &[u8], parsed: &Packet) -> Option<Arc<UdpSocket>> {
        let (app, destination) = (parsed.source, parsed.destination);
        let uid = owner(&self.shared, UDP, app, destination).await;
        let (id, name, named_by) = self.shared.begin(destination);
        let mut flow = Flow {
            id,
            protocol: UDP,
            app,
            destination,
            uid,
            outcome: Outcome::Opened,
            name,
            named_by,
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
        lock(&self.udp).insert((app, destination), Arc::clone(&socket));
        tokio::spawn(answers(
            Arc::clone(&socket),
            app,
            destination,
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
    let (id, name, named_by) = shared.begin(destination);
    let named = named_by == NamedBy::Dns;
    shared.record(Flow {
        id,
        protocol: TCP,
        app,
        destination,
        uid,
        outcome,
        name,
        named_by,
    });
    let answer = if let Ok(stream) = upstream {
        lock(&pending).insert(held.port, Upstream { stream, id, named });
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

/// Relays one connection both ways, counting the bytes as they pass. Until the flow has a name, the
/// app's first bytes are read for a TLS server name (at most [`tls::MAX_HELLO`]); nothing is held
/// back for that, so a protocol in which the server speaks first is not delayed.
async fn relay(app: TcpStream, upstream: Upstream, shared: &Arc<Shared>) {
    let _ = app.set_nodelay(true);
    let _ = upstream.stream.set_nodelay(true);
    let (mut app_read, mut app_write) = app.into_split();
    let (mut up_read, mut up_write) = upstream.stream.into_split();
    let up = async {
        let mut buffer = vec![0u8; 16 * 1024];
        let mut start = if upstream.named {
            None
        } else {
            Some(Vec::new())
        };
        loop {
            let n = match app_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(seen) = start.as_mut() {
                seen.extend_from_slice(&buffer[..n]);
                match tls::server_name(seen) {
                    ServerName::Found(name) => {
                        shared.name(upstream.id, name, NamedBy::Tls);
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
    app: SocketAddr,
    destination: SocketAddr,
    tun: Arc<Tun>,
    shared: Arc<Shared>,
    flows: UdpFlows,
    mut changes: watch::Receiver<u64>,
) {
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
                        if destination.port() == 53 && is_tunnel_dns(destination.ip()) {
                            shared.learn(&buffer[..n]);
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
