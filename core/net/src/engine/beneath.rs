//! The network beneath's own proxy, for direct apps (the proxy record's unit S2; S2-PLAN and its audit). Where the
//! network's settings name a direct HTTP proxy (its `LinkProperties.httpProxy`), Android gives it to the apps started
//! before the VPN, and inside the VPN to none: on a network that requires its proxy, an app started after Datapavan
//! lost the web. The engine now sends a direct app's TCP that a direct try cannot open through that proxy by
//! `CONNECT` ([`crate::connect`]), as Android would have given the app the proxy without the VPN.
//!
//! **The setting** ([`Beneath`]) is the network part's: the network's handle, the proxy's usable addresses (never the
//! loopback, by the maintainer's decision 3 of 2026-11-26, nor a link-local one, whose zone cannot be carried), its
//! exclusion list, whether the network has IPv6, and the user's choice "Send apps through this proxy" for that network
//! (decision 1). Only the network's own proxy, never the global one (audit M3), which Android already gives every app
//! inside the VPN. The order learned below lives in it, behind an `Arc`, so that it crosses to the next engine and
//! survives a new setting of the same proxy ([`Beneath::kept`]).
//!
//! **Which flows** ([`takes`]): only a direct route's (`Route::Direct`): a chained app's flows go to the tool, a
//! tunnelled app's into its tunnel, before any of this. Never through the proxy: loopback, link-local, multicast,
//! broadcast; a destination within the network's on-link prefixes ([`crate::local::OnLink::on_link`]), while a private
//! address on another subnet may need the proxy, as Android would send it there; a stand-in address and the tunnel's
//! own DNS address, which have paths of their own; the proxy's own addresses and any of Android's setting, so that a
//! proxy is never put in front of a proxy; a destination of a family the network has not, IPv4 or IPv6, as the
//! setting says (audit C2); and a destination the exclusion list names, by its DNS name from Android's resolver's
//! answers or by its address written out.
//!
//! **The order** (audit C2 and M6, decision 1): directly first, within `Limits::beneath_direct`. "No route of that
//! family" is the app's own error at once, and goes nowhere else: a family the setting says the network has not never
//! comes here ([`takes`]), and `EADDRNOTAVAIL`, no address of that family, ends here. Any other failure goes on to the
//! proxy, since a network that rejects is the case this is for: a server's own refusal, and `ENETUNREACH` too, which
//! Linux gives at once for an ICMP "network unreachable" or "prohibited", as a router with no route out answers and as
//! a network that lets out only its proxy may reject (S2's review, major 1). The
//! proxy comes first on the network only once `Limits::beneath_failures` distinct servers failed directly and opened
//! through the proxy within `Limits::beneath_window`, with no direct success between: a hostile proxy that answers
//! `200` to everything never captures a network that lets direct connections through, and a network that requires
//! its proxy learns it within its first few connections. A direct success ends "proxy first" at once. After
//! [`PREFERRED`], one connection, and only one, tries directly first again (the probe, given back however its flow
//! ends): its success brings the direct way back first, its failure keeps the proxy first for another [`PREFERRED`].
//! With the user's choice, the proxy always comes first, and is the only way.
//!
//! **The switch's hold** (S2's review, m2, the S-tier option taken as decision 1 says it): with the user's choice on
//! and no address of the proxy to use, the setting is a hold ([`Beneath::holds`]), which the network part hands while
//! it settles the proxy of a network whose switch is on (a new network's, before the lookup of a proxy given by name,
//! and when the network beneath is lost) and while no address it found can be used. A new direct flow it would carry
//! waits, its SYN unanswered, until a setting replaces it (looked at each [`HOLD_LOOK`]), and then goes as that setting
//! says: through the proxy that came, directly where none did or the switch is off. It fails, as a proxy that cannot be
//! reached fails it under the user's choice, once `Limits::beneath_direct` passed since the hold began: a flow then
//! waits no longer than the direct try that comes first without the switch, its app has sent its SYN at most twice
//! (Linux's first retransmissions, 1 s and 3 s), and a setting that cannot come, as for a name that does not resolve,
//! fails the flows at once from then on. The flows of a circumvention tool, and a tunnelled app's to its local network,
//! are not held: they go on as without the proxy, as chained and tunnelled apps' other flows never come here.
//!
//! **What the app sees** (M6): the proxy's `2xx` opens the flow through it. When both ways fail, the app sees the
//! direct way's outcome, a reset for a direct refusal, whatever the proxy answered. A direct try that ran out of its
//! share, or a proxy that came first and opened nothing, goes on to one more direct try: a proxy that gave no answer
//! hands it the rest of `Limits::connect_timeout`, so that a stale setting (a debugging proxy since switched off) never
//! costs a slow server its connection; a proxy that answered, by its policy or because it could not reach the server,
//! gives it `Limits::beneath_direct` alone, after which the app sees that answer, a reset for a refusal and an ICMP
//! error for a `5xx`, rather than a minute of silence on a network that drops (S2's review, minor 1).
//!
//! **By address, then by name** (C1, M1, decision 2): the authority is the address the app connected to. A request by
//! name follows, on a new connection, only after the proxy refused the address with a `4xx` other than `407`, and only
//! with the flow's own name: the address's sole name in Android's resolver's answers ([`crate::names::Names::sole`]),
//! the one that names the app's flow, and only where the app's own lookup was given it (S2's review, M2), never a name
//! whose answer carried an ECH configuration, nor one tracker blocking refuses for the app. While the proxy is held,
//! every answer reaches the apps with a time to live of 0, as while a chain is on, so that Android's resolver, which
//! keeps one cache for every app of a network, never answers an app's lookup without the engine noting the app. Never by name for a circumvention tool's flow (the chain's tool or any tool handed), and so for
//! what the tool carries for a chained app, nor for any flow of an app whose route is the tool or a tunnel ("Local
//! network directly"), nor for a flow whose app Android did not name, whatever any log switch says. Once a name opened
//! where its address was refused, names come first through that proxy while the setting holds.
//!
//! **The answer** is read with `peek` and then exactly what was peeked, the head's end looked for in what was read so
//! far with the peeked bytes after it (m1), so that nothing after the blank line is taken: a server that speaks first
//! reaches the app whole through the relay. The head is never kept or logged.
//!
//! **Bound to its network** (m5 of the audit): each socket to the proxy is protected and bound to the network whose
//! handle the setting holds ([`super::Platform::protect_on`]), refused once the network beneath is another, and
//! counted; no byte is written then. The proxy's second address is tried first once the first could not be reached,
//! as the resolver's `ResolverProxy` turns.
//!
//! The ways are `#[cold]`, out of line and boxed, so that a connection's future does not grow by the proxy's state,
//! and nothing of it is inlined into the packet path.

use super::chain::Route;
use super::forwarding::{self, Rescue};
use super::upstream::{connect_tcp, protect_on};
use super::{Counters, Limits, Shared, lock};
use crate::connect::{self, Answer};
use crate::socks5::Target;
use crate::standins::is_stand_in;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// How long the proxy comes first once learned, before one connection tries directly first again: as the resolver's
/// `ResolverProxy.PREFERRED_MS`.
pub const PREFERRED: Duration = Duration::from_secs(600);

/// The most addresses of a proxy kept, as `NetworkProxy.MAX_ADDRESSES`.
pub const MAX_ADDRESSES: usize = 2;

/// The most ports whose `CONNECT` a proxy refused are remembered for it ([`Beneath::refuses`]): a proxy that refuses
/// every port fills no more than this, and a flow to a port past it is still rescued after its own refusal.
const REFUSED_PORTS: usize = 16;

/// How often a flow the switch's hold keeps waiting looks at the setting again: the most its SYN waits once the setting
/// came.
pub const HOLD_LOOK: Duration = Duration::from_millis(25);

/// The network beneath's own proxy, as the network part settled it, and what the engines learned of it.
#[derive(Debug)]
pub struct Beneath {
    /// The network's handle (`Network.getNetworkHandle`), to which each socket to the proxy is bound.
    network: i64,
    /// The proxy's usable addresses, at most [`MAX_ADDRESSES`], in the order given.
    proxies: Vec<SocketAddr>,
    /// The exclusion list, comma-separated entries, whole, as the resolver's twin reads it on the Kotlin side: a list
    /// cut would send the hosts past the cut to the proxy (S2's review, minor 3).
    pub(super) exclusions: String,
    /// Whether the network has IPv4: without, an IPv4 destination never goes through the proxy (audit C2).
    ipv4: bool,
    /// Whether the network has IPv6: without, an IPv6 destination never goes through the proxy (audit C2).
    ipv6: bool,
    /// The user's choice "Send apps through this proxy" for this network (decision 1).
    pub(super) always: bool,
    /// What was learned: which way comes first, and whether names do.
    order: Mutex<Order>,
    /// Whether the proxy asked for a password (`407`): a fact a release build shows, naming no app or place (m2).
    password: AtomicBool,
    /// When the setting was made: the switch's hold lasts `Limits::beneath_direct` from here.
    since: Instant,
}

/// What the engine learned of the network's own proxy, for the network part's dump and "Now".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeneathState {
    /// Whether the proxy comes first now: learned, or the user's choice.
    pub proxy_first: bool,
    /// Whether names come first through it.
    pub names_first: bool,
    /// Whether it asked for a password (`407`) since it was set.
    pub password: bool,
}

impl Beneath {
    /// The proxy at `proxies`, of the network whose handle is `network`, with its exclusion list `exclusions` (comma
    /// separated), whether the network has IPv4 and IPv6, and whether the user chose to send every direct app through
    /// it.
    /// The addresses kept are at most [`MAX_ADDRESSES`], each once, none on the loopback, link-local, multicast,
    /// broadcast or unspecified, and none of port 0: `None` when none is left, but the switch's hold where the user
    /// chose the proxy (the module's comment).
    #[must_use]
    pub fn new(
        network: i64,
        proxies: &[SocketAddr],
        exclusions: &str,
        (ipv4, ipv6): (bool, bool),
        always: bool,
    ) -> Option<Self> {
        let mut kept: Vec<SocketAddr> = Vec::new();
        for proxy in proxies {
            let at = SocketAddr::new(proxy.ip().to_canonical(), proxy.port());
            if at.port() != 0 && reachable(at.ip()) && !kept.contains(&at) {
                kept.push(at);
            }
        }
        kept.truncate(MAX_ADDRESSES);
        if kept.is_empty() && !always {
            return None;
        }
        Some(Self {
            network,
            proxies: kept,
            exclusions: exclusions.to_owned(),
            ipv4,
            ipv6,
            always,
            order: Mutex::default(),
            password: AtomicBool::new(false),
            since: Instant::now(),
        })
    }

    /// Whether this setting is the switch's hold: the user's choice, and no address of the proxy to use (the module's
    /// comment).
    #[must_use]
    pub fn holds(&self) -> bool {
        self.proxies.is_empty()
    }

    /// This setting as the engines should hold it, beside `held`, the one held now: `held` itself when it is the same
    /// proxy (the same network, the same set of addresses, the same exclusions) and the same choice, so that what was
    /// learned of it stays; a new one with what was learned when only the user's choice or the network's families
    /// changed, the probe free in it, since a probe in flight gives it back to `held` alone (S2's review, minor 2); else
    /// this one.
    #[must_use]
    pub fn kept(self, held: Option<&Arc<Self>>) -> Arc<Self> {
        let Some(held) = held.filter(|held| held.same(&self)) else {
            return Arc::new(self);
        };
        if held.always == self.always && held.ipv4 == self.ipv4 && held.ipv6 == self.ipv6 {
            return Arc::clone(held);
        }
        Arc::new(Self {
            order: Mutex::new(Order {
                probing: false,
                ..lock(&held.order).clone()
            }),
            password: AtomicBool::new(held.password.load(Ordering::Relaxed)),
            ..self
        })
    }

    fn same(&self, other: &Self) -> bool {
        self.network == other.network
            && self.exclusions == other.exclusions
            && self.proxies.len() == other.proxies.len()
            && self.proxies.iter().all(|p| other.proxies.contains(p))
    }

    /// What was learned of the proxy at `now`, in time since the phone started: the proxy first as [`Order::start`]
    /// reads it, within [`PREFERRED`] of its learning or while a probe runs (S2's review, note 2).
    #[must_use]
    pub fn state(&self, now: Duration) -> BeneathState {
        let order = lock(&self.order);
        BeneathState {
            proxy_first: self.always
                || order
                    .proxy_since
                    .is_some_and(|since| now.saturating_sub(since) < PREFERRED || order.probing),
            names_first: order.names_first,
            password: self.password.load(Ordering::Relaxed),
        }
    }

    /// The proxy's address tried now.
    fn proxy(&self) -> SocketAddr {
        self.proxies[lock(&self.order).next % self.proxies.len()]
    }

    /// Whether the proxy refused a `CONNECT` to `port` while this setting holds: a flow the forwarder may carry goes to
    /// it at once ([`forwarding`]; the maintainer's decision of 2026-11-27).
    pub(super) fn refuses(&self, port: u16) -> bool {
        let order = lock(&self.order);
        order.refused[..order.refused_count].contains(&port)
    }

    /// The proxy refused a `CONNECT` to `port`: remembered, up to [`REFUSED_PORTS`] ports.
    fn refused(&self, port: u16) {
        let mut order = lock(&self.order);
        let count = order.refused_count;
        if !order.refused[..count].contains(&port) && count < REFUSED_PORTS {
            order.refused[count] = port;
            order.refused_count = count + 1;
        }
    }

    /// A direct connection opened after all: the direct way comes first again ([`Order::direct_opened`]).
    pub(super) fn direct_opened(&self) {
        lock(&self.order).direct_opened();
    }

    /// The proxy at `proxy` could not be reached: its other address is tried next, if it has one.
    fn unreachable(&self, proxy: SocketAddr) {
        let mut order = lock(&self.order);
        if self.proxies[order.next % self.proxies.len()] == proxy {
            order.next = order.next.wrapping_add(1);
        }
    }
}

/// Whether a proxy at `address` is one the engine may connect to: never the loopback (decision 3), link-local, whose
/// zone cannot be carried, multicast, broadcast or unspecified.
fn reachable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => {
            !(a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified())
        }
        IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_unicast_link_local()
                || a.is_multicast()
                || a.is_unspecified())
        }
    }
}

/// Which way comes first on the network, as learned (the module's comment).
#[derive(Clone, Debug, Default)]
struct Order {
    /// Since when, in time since the phone started, the proxy has come first: learned from a broad failure, or kept
    /// by a probe that failed directly.
    proxy_since: Option<Duration>,
    /// Whether a connection holds the probe now.
    probing: bool,
    /// The distinct servers that failed directly and then opened through the proxy since the last direct success,
    /// with when.
    failed: Vec<(IpAddr, Duration)>,
    /// Whether names come first: a name opened where its address was refused.
    names_first: bool,
    /// Which of the proxy's addresses is tried now, turned when one cannot be reached.
    next: usize,
    /// The ports whose `CONNECT` the proxy refused (a `4xx` other than `407`), at most [`REFUSED_PORTS`]: later flows
    /// the forwarder may carry go to it at once ([`Beneath::refuses`]); the first `refused_count`. A list of its own
    /// size, so that `Order` holds no second `Vec` to clone and drop (the forwarder's size pass).
    refused: [u16; REFUSED_PORTS],
    /// How many of `refused` are ports.
    refused_count: usize,
}

/// How a flow begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// Directly, as the default order.
    Direct,
    /// Directly, as the probe after [`PREFERRED`].
    Probe,
    /// Through the proxy.
    Proxy,
}

impl Order {
    /// How a new flow begins at `now`; `always` for the user's choice.
    fn start(&mut self, now: Duration, always: bool) -> Start {
        if always {
            return Start::Proxy;
        }
        match self.proxy_since {
            None => Start::Direct,
            Some(since) if now.saturating_sub(since) < PREFERRED || self.probing => Start::Proxy,
            Some(_) => {
                self.probing = true;
                Start::Probe
            }
        }
    }

    /// A direct connection opened: the direct way comes first again, at once, and what failed before counts no more.
    fn direct_opened(&mut self) {
        self.proxy_since = None;
        self.failed.clear();
    }

    /// The server at `server` failed directly, and the proxy then opened its tunnel, at `now`; `probe` when the flow
    /// held the probe. A clock that cannot be read (the longest time there is) teaches nothing.
    fn proxy_opened(&mut self, server: IpAddr, now: Duration, limits: &Limits, probe: bool) {
        if now == Duration::MAX {
            return;
        }
        if probe {
            self.proxy_since = Some(now);
            return;
        }
        if self.proxy_since.is_some() {
            return;
        }
        // The same server again, and those failed outside the window, count no more. A scan with `swap_remove`, not
        // `Vec::retain`'s generic code: the list holds a few servers, and their order does not matter.
        let mut i = 0;
        while let Some(&(at, when)) = self.failed.get(i) {
            if at == server || now.saturating_sub(when) >= limits.beneath_window {
                self.failed.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.failed.push((server, now));
        if self.failed.len() >= limits.beneath_failures.max(1) {
            self.proxy_since = Some(now);
            self.failed.clear();
        }
    }
}

/// The probe a flow holds, given back when the flow ends, however it ends (audit m8).
struct Probe(Arc<Beneath>);

impl Drop for Probe {
    fn drop(&mut self) {
        lock(&self.0.order).probing = false;
    }
}

impl Shared {
    /// Whether the network's own proxy is held now.
    pub(super) fn beneath_held(&self) -> bool {
        lock(&self.beneath).is_some()
    }

    /// The network's own proxy for a direct flow to `destination`, if one is set and may carry it ([`takes`]): one
    /// load of the setting while none is set.
    pub(super) fn beneath_for(&self, destination: SocketAddr) -> Option<Arc<Beneath>> {
        let beneath = lock(&self.beneath).clone()?;
        self.beneath_takes(&beneath, destination).then_some(beneath)
    }

    /// The facts [`takes`] reads, each lock taken alone.
    #[cold]
    #[inline(never)]
    fn beneath_takes(&self, beneath: &Beneath, destination: SocketAddr) -> bool {
        let address = destination.ip().to_canonical();
        if is_stand_in(address) || self.is_tunnel_dns(address) || self.android_setting(destination)
        {
            return false;
        }
        let on_link = lock(&self.proxies).setting().on_link.on_link(address);
        let name = lock(&self.names)
            .get(address, None, Instant::now())
            .map(str::to_owned);
        takes(beneath, address, on_link, name.as_deref())
    }
}

/// Whether the network's proxy `beneath` may carry a direct flow to `address`, `on_link` when the address is within the
/// network's on-link prefixes, `name` its DNS name from Android's resolver's answers: the module's comment, past the
/// facts the engine reads first (a stand-in, the tunnel's DNS address, Android's setting).
pub(super) fn takes(beneath: &Beneath, address: IpAddr, on_link: bool, name: Option<&str>) -> bool {
    let address = address.to_canonical();
    reachable(address)
        && !on_link
        && if address.is_ipv4() {
            beneath.ipv4
        } else {
            beneath.ipv6
        }
        && beneath.proxies.iter().all(|proxy| proxy.ip() != address)
        && !connect::excluded(&address.to_string(), &beneath.exclusions)
        && !name.is_some_and(|name| connect::excluded(name, &beneath.exclusions))
}

/// What a direct try gave a flow while the network's proxy is held ([`first`]).
pub(super) enum Tried {
    /// Its end: a stream, or the error the app sees.
    Done(io::Result<TcpStream>),
    /// The proxy's steps, still to come once Android named the app ([`finish`]).
    Onward(Box<Onward>),
}

/// What the proxy's steps start from.
pub(super) struct Onward {
    beneath: Arc<Beneath>,
    /// Where the direct way goes.
    target: SocketAddr,
    /// When the flow's first try began: its steps share `Limits::connect_timeout` from here.
    began: Instant,
    /// The direct try's error, where it came first, and whether it ran out of its share.
    direct: Option<(io::Error, bool)>,
    probe: Option<Probe>,
}

/// Why the proxy opened nothing.
#[derive(Debug)]
pub(super) enum Failure {
    /// No answer: it could not be reached, closed, sent no head in time, or not HTTP; or its socket could not be
    /// bound to the network.
    Silent(io::Error),
    /// An answer that opened nothing.
    Answered(Answer),
}

impl Failure {
    /// What the app sees where the proxy was its only way (the user's choice): a reset for a refusal, an ICMP error
    /// for a proxy that could not reach the destination, or the error itself.
    pub(super) fn error(self) -> io::Error {
        match self {
            Self::Silent(error) => error,
            Self::Answered(Answer::Unreachable) => io::ErrorKind::HostUnreachable.into(),
            Self::Answered(_) => io::ErrorKind::ConnectionRefused.into(),
        }
    }
}

/// Whether `error` says the phone has no address of the destination's family on the network, which goes nowhere else
/// and teaches nothing (audit C2). Not `ENETUNREACH`: for a flow [`takes`] let through, the network has that family,
/// and "network unreachable" is the network's rejection (the module's comment).
fn no_route(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
}

/// What a direct try that ended with `result`, or ran out of its share (`None`), leaves a flow: its end, a stream or
/// the app's own error where the phone has no address of that family ([`no_route`]); or the error the proxy's steps
/// start from, and whether it ran out.
fn direct_end<T>(result: Option<io::Result<T>>) -> Result<io::Result<T>, (io::Error, bool)> {
    match result {
        Some(Ok(stream)) => Ok(Ok(stream)),
        Some(Err(error)) if no_route(&error) => Ok(Err(error)),
        Some(Err(error)) => Err((error, false)),
        None => Err((io::ErrorKind::TimedOut.into(), true)),
    }
}

/// A direct flow's first way to `target` while `beneath` is held: directly first, within `Limits::beneath_direct`,
/// unless the proxy comes first. Boxed and out of line (the module's comment).
#[cold]
#[inline(never)]
pub(super) fn first(
    shared: &Arc<Shared>,
    beneath: Arc<Beneath>,
    target: SocketAddr,
) -> Pin<Box<dyn Future<Output = Tried> + Send + '_>> {
    Box::pin(async move {
        let began = Instant::now();
        let start = lock(&beneath.order).start(shared.clock.since_boot(), beneath.always);
        let probe = match start {
            Start::Proxy => {
                return Tried::Onward(Box::new(Onward {
                    beneath,
                    target,
                    began,
                    direct: None,
                    probe: None,
                }));
            }
            Start::Probe => Some(Probe(Arc::clone(&beneath))),
            Start::Direct => None,
        };
        let tried =
            tokio::time::timeout(shared.limits.beneath_direct, connect_tcp(shared, target)).await;
        let direct = match direct_end(tried.ok()) {
            Ok(Ok(stream)) => {
                lock(&beneath.order).direct_opened();
                return Tried::Done(Ok(stream));
            }
            Ok(Err(error)) => return Tried::Done(Err(error)),
            Err(direct) => direct,
        };
        Tried::Onward(Box::new(Onward {
            beneath,
            target,
            began,
            direct: Some(direct),
            probe,
        }))
    })
}

/// The flow's connection, once Android named its app `uid` (or did not): what the direct try gave, or the proxy's
/// steps from the app's end `app` to `destination` and then the direct way's last try; and whether it went through
/// the proxy.
pub(super) async fn finish(
    shared: &Arc<Shared>,
    tried: Tried,
    uid: Option<u32>,
    (app, destination): (SocketAddr, SocketAddr),
) -> (io::Result<TcpStream>, bool) {
    match tried {
        Tried::Done(result) => (result, false),
        Tried::Onward(onward) => onward_steps(shared, *onward, uid, (app, destination)).await,
    }
}

/// The proxy's steps, then the direct way with what is left where the module's comment says. Boxed and out of line.
#[cold]
#[inline(never)]
fn onward_steps(
    shared: &Arc<Shared>,
    onward: Onward,
    uid: Option<u32>,
    (app, destination): (SocketAddr, SocketAddr),
) -> Pin<Box<dyn Future<Output = (io::Result<TcpStream>, bool)> + Send + '_>> {
    Box::pin(async move {
        let Onward {
            beneath,
            target,
            began,
            direct,
            probe,
        } = onward;
        if beneath.holds() {
            return held(shared, &beneath, target, uid, (app, destination)).await;
        }
        let limits = shared.limits;
        // The forwarder (the maintainer's decision of 2026-11-27): a flow it may carry, to a port whose `CONNECT` the
        // proxy refused before, goes to it at once; one whose `CONNECT` it refuses now is rescued.
        let forwards = may_name(shared, uid);
        let remembered = forwards.is_some() && beneath.refuses(destination.port());
        let mut failure = if remembered {
            Counters::add(&shared.counters.beneath.remembered, 1);
            Failure::Answered(Answer::Refused)
        } else {
            match through(shared, &beneath, uid, destination, began).await {
                Ok(stream) => {
                    if direct.is_some() {
                        lock(&beneath.order).proxy_opened(
                            destination.ip().to_canonical(),
                            shared.clock.since_boot(),
                            &limits,
                            probe.is_some(),
                        );
                    }
                    return (Ok(stream), true);
                }
                Err(failure) => failure,
            }
        };
        if let Some(uid) = forwards
            && matches!(failure, Failure::Answered(Answer::Refused))
        {
            beneath.refused(destination.port());
            let rescue = Rescue {
                beneath: Arc::clone(&beneath),
                target,
                ends: (app, destination),
                uid,
                began,
                failed: direct
                    .as_ref()
                    .and_then(|(error, out)| (!out).then(|| error.kind())),
                remembered,
            };
            match forwarding::rescue(shared, rescue).await {
                Ok(stream) => return (Ok(stream), true),
                // Not reached: S2's tail, as for a proxy that gave no answer where none came this time.
                Err(error) if remembered => failure = Failure::Silent(error),
                Err(_) => {}
            }
        }
        if beneath.always {
            return (Err(failure.error()), false);
        }
        if let Some((error, false)) = direct {
            // Both ways failed: the app sees the direct way's own outcome (M6).
            return (Err(error), false);
        }
        let left = limits.connect_timeout.saturating_sub(began.elapsed());
        let answered = matches!(failure, Failure::Answered(_));
        let wait = if answered {
            limits.beneath_direct.min(left)
        } else {
            left
        };
        let result = match tokio::time::timeout(wait, connect_tcp(shared, target)).await {
            Ok(result) => result,
            Err(_) if answered => Err(failure.error()),
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        };
        if result.is_ok() {
            lock(&beneath.order).direct_opened();
        }
        drop(probe);
        (result, false)
    })
}

/// A flow of `uid` to `destination`, its direct way to `target`, that the switch's hold `hold` met (the module's
/// comment): it waits for the setting that replaces the hold and goes as that one says, or fails once the hold's time
/// passed; a circumvention tool's, a chained app's and a tunnelled app's go on at once, as without the proxy.
async fn held(
    shared: &Arc<Shared>,
    hold: &Beneath,
    target: SocketAddr,
    uid: Option<u32>,
    (app, destination): (SocketAddr, SocketAddr),
) -> (io::Result<TcpStream>, bool) {
    if shared.is_tool(uid) || matches!(shared.app_route(uid), Route::Tool(_) | Route::Tunnel(_)) {
        return (connect_tcp(shared, target).await, false);
    }
    Counters::add(&shared.counters.beneath.held, 1);
    let until = hold
        .since
        .checked_add(shared.limits.beneath_direct)
        .unwrap_or(hold.since);
    loop {
        match shared.beneath_for(destination) {
            None => return (connect_tcp(shared, target).await, false),
            Some(next) if !next.holds() => {
                let tried = first(shared, next, target).await;
                return finish(shared, tried, uid, (app, destination)).await;
            }
            Some(_) => {}
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (Err(io::ErrorKind::NetworkUnreachable.into()), false);
        }
        // A look at the setting each `HOLD_LOOK`, by the timer every flow's own times use: a wake-up shared with the
        // setter's side would be new code beside the packet path's (`Notify`'s polls, inlined anew into `Tun::send`).
        tokio::time::sleep(left.min(HOLD_LOOK)).await;
    }
}

/// Through the proxy to `destination`: by address, then by the flow's own name where the proxy refused the address,
/// or by name first once names came first.
pub(super) async fn through(
    shared: &Arc<Shared>,
    beneath: &Beneath,
    uid: Option<u32>,
    destination: SocketAddr,
    began: Instant,
) -> Result<TcpStream, Failure> {
    let names_first = lock(&beneath.order).names_first;
    if names_first && let Some(named) = own_name(shared, uid, destination) {
        Counters::add(&shared.counters.beneath.named, 1);
        return ask(shared, beneath, &named, began).await;
    }
    match ask(shared, beneath, &Target::Address(destination), began).await {
        Err(Failure::Answered(Answer::Refused)) if !names_first => {}
        other => return other,
    }
    let Some(named) = own_name(shared, uid, destination) else {
        return Err(Failure::Answered(Answer::Refused));
    };
    Counters::add(&shared.counters.beneath.named, 1);
    let opened = ask(shared, beneath, &named, began).await;
    if opened.is_ok() {
        lock(&beneath.order).names_first = true;
    }
    opened
}

/// The app `uid`, where the engine may name its flows to the proxy, by a `CONNECT` by name or by a forwarded `Host`: an
/// app Android named, no circumvention tool (the chain's or any handed one), its route direct (C1 of S2's audit).
pub(super) fn may_name(shared: &Shared, uid: Option<u32>) -> Option<u32> {
    let uid = uid?;
    (!shared.is_tool(Some(uid)) && matches!(shared.app_route(Some(uid)), Route::Direct))
        .then_some(uid)
}

/// The name a request may carry for the flow of `uid` to `destination` (the module's comment, C1, M1, decision 2).
fn own_name(shared: &Shared, uid: Option<u32>, destination: SocketAddr) -> Option<Target> {
    let uid = may_name(shared, uid)?;
    let address = destination.ip().to_canonical();
    let now = Instant::now();
    let name = {
        let names = lock(&shared.names);
        let sole = names.sole(address, uid, now)?;
        if names.get(address, Some(uid), now) != Some(sole) || names.is_hidden(sole, Some(uid), now)
        {
            return None;
        }
        sole.trim_end_matches('.').to_ascii_lowercase()
    };
    if shared
        .verdict(Some(uid), &name, super::blocks::Path::Connection)
        .is_some()
    {
        return None;
    }
    Target::name(&name, destination.port())
}

/// One `CONNECT` for `target` to the proxy, on a socket of its own bound to the network: the stream just past the
/// answer's head on a `2xx`.
async fn ask(
    shared: &Arc<Shared>,
    beneath: &Beneath,
    target: &Target,
    began: Instant,
) -> Result<TcpStream, Failure> {
    let limits = shared.limits;
    let left = || limits.connect_timeout.saturating_sub(began.elapsed());
    let mut stream = reach(shared, beneath, began).await?;
    Counters::add(&shared.counters.beneath.tries, 1);
    let status = match tokio::time::timeout(
        limits.beneath_answer.min(left()),
        answer(&mut stream, target),
    )
    .await
    {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => return Err(Failure::Silent(error)),
        Err(_) => return Err(Failure::Silent(io::ErrorKind::TimedOut.into())),
    };
    let answer = Answer::of(status);
    let counter = match answer {
        Answer::Opened => &shared.counters.beneath.opened,
        Answer::Password => {
            beneath.password.store(true, Ordering::Relaxed);
            &shared.counters.beneath.password
        }
        Answer::Unreachable => &shared.counters.beneath.unreachable,
        Answer::Refused | Answer::Unexpected => &shared.counters.beneath.refused,
    };
    Counters::add(counter, 1);
    if answer == Answer::Opened {
        Ok(stream)
    } else {
        Err(Failure::Answered(answer))
    }
}

/// A connection to the proxy on a socket of its own, protected and bound to the network, within
/// `Limits::beneath_direct` and the flow's time left from `began`: `ask`'s, and the forwarder's own (S2's steps, shared).
pub(super) async fn reach(
    shared: &Arc<Shared>,
    beneath: &Beneath,
    began: Instant,
) -> Result<TcpStream, Failure> {
    let limits = shared.limits;
    let proxy = beneath.proxy();
    let socket = if proxy.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(Failure::Silent)?;
    if let Err(error) = protect_on(shared, socket.as_fd(), beneath.network).await {
        Counters::add(&shared.counters.beneath.stale, 1);
        return Err(Failure::Silent(error));
    }
    socket.set_keepalive(true).map_err(Failure::Silent)?;
    // The proxy's other address comes first after this one refused, or ran out of the whole of its own share; not
    // after a timeout that only the flow's own time cut short (S2's review, note 3).
    let share = limits.connect_timeout.saturating_sub(began.elapsed());
    match tokio::time::timeout(limits.beneath_direct.min(share), socket.connect(proxy)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            beneath.unreachable(proxy);
            Err(Failure::Silent(error))
        }
        Err(_) => {
            if share >= limits.beneath_direct {
                beneath.unreachable(proxy);
            }
            Err(Failure::Silent(io::ErrorKind::TimedOut.into()))
        }
    }
}

/// Sends the request for `target` and reads the answer's head, to its end and no further: its status code.
async fn answer(stream: &mut TcpStream, target: &Target) -> io::Result<u16> {
    stream.write_all(&connect::request(target)).await?;
    let head = head(stream).await?;
    connect::status(&head).map_err(|_| io::ErrorKind::InvalidData.into())
}

/// The answer's head, read with `peek` and then exactly up to its end (the module's comment).
async fn head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut peeked = [0u8; 2_048];
    loop {
        let n = stream.peek(&mut peeked).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let before = head.len();
        head.extend_from_slice(&peeked[..n]);
        match connect::head_end_after(&head, before) {
            Ok(Some(end)) => {
                head.truncate(end);
                stream.read_exact(&mut peeked[..end - before]).await?;
                return Ok(head);
            }
            Ok(None) => {
                stream.read_exact(&mut peeked[..n]).await?;
            }
            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::clock::{Clock, ManualClock};
    use super::super::tests::shared_with;
    use super::super::{BlockSetting, Chain, Platform, ProxySetting, TunnelSetting};
    use super::*;
    use std::os::fd::RawFd;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;

    pub(in crate::engine) const UID: u32 = 10_123;
    const OTHER: u32 = 10_124;
    const NETWORK: i64 = 0x6d_0000_0001;

    /// Android, as each test needs it: whether a direct socket is protected (no direct try gets past a refusal), how
    /// long that takes (a direct try silent this long), and whether a socket to the proxy is bound to its network.
    #[derive(Default)]
    pub(in crate::engine) struct Lab {
        pub(in crate::engine) refuses: bool,
        pub(in crate::engine) slow: Duration,
        pub(in crate::engine) stale: bool,
        pub(in crate::engine) protects: AtomicUsize,
        pub(in crate::engine) bound: Mutex<Vec<i64>>,
    }

    impl Platform for Lab {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            Some(UID)
        }

        fn protect(&self, _: RawFd) -> bool {
            self.protects.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.slow);
            !self.refuses
        }

        fn protect_on(&self, _: RawFd, network: i64) -> bool {
            lock(&self.bound).push(network);
            !self.stale
        }

        fn log(&self, _: &[u8]) {}
    }

    /// How the test proxy answers a request, by its head.
    #[derive(Clone, Copy)]
    pub(in crate::engine) enum Reply {
        /// These bytes, then an echo of what the tunnel carries.
        Bytes(&'static [u8]),
        /// These bytes in two writes, cut at this byte, a pause between.
        Cut(&'static [u8], usize),
        /// `403` to a request by address, `200` and an echo to one by name.
        NamesOnly,
        /// Nothing, the connection held open.
        Silent,
        /// The connection closed at once.
        Closed,
        /// `403` to every `CONNECT`, as squid's default to port 80; each request in absolute form answered `200` with
        /// its request line as the body, the connection kept (the forwarder).
        Forward,
    }

    /// What the test proxy keeps: each request's head, and what the tunnel carried up past it.
    type Kept = (Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<u8>>>);

    /// A proxy on the loopback that records each request's head and answers as told.
    pub(in crate::engine) struct Proxy {
        pub(in crate::engine) at: SocketAddr,
        heads: Arc<Mutex<Vec<String>>>,
        /// What the tunnel carried up, past each head.
        after: Arc<Mutex<Vec<u8>>>,
    }

    impl Proxy {
        pub(in crate::engine) async fn new(reply: Reply) -> io::Result<Self> {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let at = listener.local_addr()?;
            let heads = Arc::new(Mutex::new(Vec::new()));
            let after = Arc::new(Mutex::new(Vec::new()));
            let kept = (Arc::clone(&heads), Arc::clone(&after));
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let kept = (Arc::clone(&kept.0), Arc::clone(&kept.1));
                    tokio::spawn(serve(stream, reply, kept));
                }
            });
            Ok(Self { at, heads, after })
        }

        pub(in crate::engine) fn heads(&self) -> Vec<String> {
            lock(&self.heads).clone()
        }

        pub(in crate::engine) fn after(&self) -> Vec<u8> {
            lock(&self.after).clone()
        }
    }

    async fn serve(mut stream: TcpStream, reply: Reply, (heads, after): Kept) {
        let _ = stream.set_nodelay(true);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        if matches!(reply, Reply::Forward) {
            return forward_mode(stream, head, &heads).await;
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let by_name = head.starts_with("CONNECT ")
            && !head.as_bytes()[8].is_ascii_digit()
            && head.as_bytes()[8] != b'[';
        lock(&heads).push(head);
        let bytes: &[u8] = match reply {
            Reply::Bytes(bytes) => bytes,
            Reply::Cut(bytes, at) => {
                let _ = stream.write_all(&bytes[..at]).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                &bytes[at..]
            }
            Reply::NamesOnly if by_name => b"HTTP/1.1 200 Connection established\r\n\r\n",
            Reply::NamesOnly => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            Reply::Silent => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            Reply::Closed | Reply::Forward => return,
        };
        if stream.write_all(bytes).await.is_err()
            || !bytes.starts_with(b"HTTP/1.1 200") && !bytes.starts_with(b"HTTP/1.0 200")
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
            return;
        }
        let mut buffer = [0u8; 1_024];
        while let Ok(n) = stream.read(&mut buffer).await {
            lock(&after).extend_from_slice(&buffer[..n]);
            if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                return;
            }
        }
    }

    /// [`Reply::Forward`]'s proxy, its first head read: each head recorded, a `CONNECT` refused, a request answered
    /// with its line, its body read by its length.
    async fn forward_mode(mut stream: TcpStream, mut head: Vec<u8>, heads: &Mutex<Vec<String>>) {
        loop {
            let text = String::from_utf8_lossy(&head).into_owned();
            lock(heads).push(text.clone());
            if text.starts_with("CONNECT ") {
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            }
            let length = text
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let line = text.lines().next().unwrap_or_default().to_owned();
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{line}",
                line.len()
            );
            if stream.write_all(answer.as_bytes()).await.is_err() {
                return;
            }
            head.clear();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte).await {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
        }
    }

    /// An echo server on the loopback, for the direct way.
    async fn echo_server() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let at = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1_024];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Ok(at)
    }

    /// A loopback port nothing listens on: a direct try there is refused.
    async fn closed_port() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        listener.local_addr()
    }

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap_or_else(|_| unreachable!("{text}"))
    }

    /// An engine's shared state over `lab`, with timings in milliseconds, the proxy at `proxy` set, and its clock, an
    /// hour after the phone started.
    fn engine_clocked(lab: Lab, proxy: SocketAddr) -> (Arc<Shared>, Arc<Lab>, Arc<ManualClock>) {
        let lab = Arc::new(lab);
        let mut shared = shared_with(Arc::clone(&lab) as Arc<dyn Platform>);
        let clock = ManualClock::at(1_794_873_600_000);
        shared.clock = clock.clone();
        shared.limits.beneath_direct = Duration::from_millis(300);
        shared.limits.beneath_answer = Duration::from_millis(300);
        shared.limits.connect_timeout = Duration::from_secs(3);
        let shared = Arc::new(shared);
        set(&shared, proxy, "");
        (shared, lab, clock)
    }

    pub(in crate::engine) fn engine(lab: Lab, proxy: SocketAddr) -> (Arc<Shared>, Arc<Lab>) {
        let (shared, lab, _) = engine_clocked(lab, proxy);
        (shared, lab)
    }

    /// Sets the proxy at `proxy`, its exclusion list `exclusions`: the test proxy is on the loopback, which the
    /// setting itself never keeps, so it is put in place by hand.
    fn set(shared: &Shared, proxy: SocketAddr, exclusions: &str) {
        set_with(shared, proxy, exclusions, false);
    }

    /// [`set`], with the user's choice `always`.
    pub(in crate::engine) fn set_with(
        shared: &Shared,
        proxy: SocketAddr,
        exclusions: &str,
        always: bool,
    ) {
        let Some(mut beneath) = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128")],
            exclusions,
            (true, true),
            always,
        ) else {
            unreachable!("a proxy kept")
        };
        beneath.proxies = vec![proxy];
        *lock(&shared.beneath) = Some(Arc::new(beneath));
    }

    pub(in crate::engine) fn held(shared: &Shared) -> Arc<Beneath> {
        lock(&shared.beneath)
            .clone()
            .unwrap_or_else(|| unreachable!("a proxy set"))
    }

    /// A flow of `uid` to `destination`, its direct way to `target`, as `tcp::upstream` will open it.
    async fn open(
        shared: &Arc<Shared>,
        uid: u32,
        destination: SocketAddr,
        target: SocketAddr,
    ) -> (io::Result<TcpStream>, bool) {
        let tried = first(shared, held(shared), target).await;
        finish(
            shared,
            tried,
            Some(uid),
            (at("10.0.0.2:40000"), destination),
        )
        .await
    }

    /// The stream carries bytes both ways: what is written comes back from the echo behind it.
    async fn echoes(stream: &mut TcpStream) -> io::Result<()> {
        stream.write_all(b"ping").await?;
        let mut got = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut got)).await??;
        assert_eq!(&got, b"ping");
        Ok(())
    }

    fn counters(shared: &Shared) -> [u64; 7] {
        let all = shared.counters.snapshot();
        let mut seven = [0; 7];
        seven.copy_from_slice(&all[73..80]);
        seven
    }

    pub(in crate::engine) const OPENED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

    /// Whether `stream` is a flow the forwarder rescued once the proxy refused its `CONNECT`: open, and reset at a first
    /// byte that starts no HTTP head (the forwarder; the maintainer's decision of 2026-11-27).
    pub(in crate::engine) async fn rescued(stream: io::Result<TcpStream>) -> bool {
        let Ok(mut stream) = stream else {
            return false;
        };
        if stream.write_all(b"\x16\x03\x01\x00\x05").await.is_err() {
            return true;
        }
        let mut byte = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
            Ok(Err(_) | Ok(0))
        )
    }

    /// A lookup of `name` by the app `uid` through Android's resolver, answered `address`: learned for every app's
    /// flows, and passed to that app, as the lookups' paths do.
    fn looked_up(shared: &Shared, uid: u32, name: &str, address: [u8; 4]) {
        let answer = super::super::tests::dns_answer(name, address);
        shared.learn(&answer, None);
        shared.passed(Some(uid), &answer);
    }

    /// A case of [`no_name_reaches_the_proxy_where_the_flows_name_is_not_its_own_to_give`]: what it is, what it sets,
    /// and the flow's app.
    type Case = (&'static str, fn(&Shared), Option<u32>);

    /// Section 2's cases: what the proxy never carries, and what it may.
    #[test]
    fn the_proxy_carries_no_local_special_excluded_or_proxy_destination() {
        let Some(beneath) = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128")],
            "*.intranet.example, 198.51.100.77,.lan",
            (true, false),
            false,
        ) else {
            unreachable!("a proxy kept")
        };
        let ip = |text: &str| {
            text.parse::<IpAddr>()
                .unwrap_or_else(|_| unreachable!("{text}"))
        };
        for (address, on_link, name, carried) in [
            ("198.51.100.7", false, None, true),
            ("10.20.0.5", false, None, true),
            ("192.168.1.20", true, None, false),
            ("127.0.0.1", false, None, false),
            ("169.254.1.1", false, None, false),
            ("224.0.0.251", false, None, false),
            ("255.255.255.255", false, None, false),
            ("0.0.0.0", false, None, false),
            ("203.0.113.80", false, None, false),
            ("198.51.100.77", false, None, false),
            ("198.51.100.7", false, Some("wiki.intranet.example"), false),
            ("198.51.100.7", false, Some("nas.lan"), false),
            ("198.51.100.7", false, Some("www.example.com"), true),
            ("::ffff:198.51.100.77", false, None, false),
            ("2001:db8::7", false, None, false),
        ] {
            assert_eq!(
                takes(&beneath, ip(address), on_link, name),
                carried,
                "{address} {name:?}"
            );
        }
        let Some(with_ipv6) =
            Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, true), false)
        else {
            unreachable!("a proxy kept")
        };
        assert!(takes(&with_ipv6, ip("2001:db8::7"), false, None));
        assert!(!takes(&with_ipv6, ip("fe80::1"), false, None));
        assert!(!takes(&with_ipv6, ip("ff02::1"), false, None));
        // A network with IPv6 alone (S2's review, major 1): its IPv4 destinations never go through the proxy.
        let Some(ipv6_only) = Beneath::new(
            NETWORK,
            &[at("[2001:db8::80]:3128")],
            "",
            (false, true),
            false,
        ) else {
            unreachable!("a proxy kept")
        };
        assert!(!takes(&ipv6_only, ip("198.51.100.7"), false, None));
        assert!(!takes(&ipv6_only, ip("::ffff:198.51.100.7"), false, None));
        assert!(takes(&ipv6_only, ip("2001:db8::7"), false, None));
    }

    /// The facts the engine reads first: a stand-in, the tunnel's DNS address, Android's setting, an on-link
    /// prefix, and the DNS name the exclusion list names.
    #[tokio::test(flavor = "current_thread")]
    async fn the_engines_facts_keep_their_destinations_from_the_proxy() {
        let (shared, _) = engine(Lab::default(), at("203.0.113.80:3128"));
        set(&shared, at("203.0.113.80:3128"), "*.corp.example");
        shared.apply_proxies(ProxySetting {
            android: vec![("198.51.100.90".into(), 8080)],
            on_link: crate::local::OnLink::new(
                [(IpAddr::from([10, 20, 30, 0]), 24)],
                crate::local::Transport::Wifi,
            ),
            ..ProxySetting::default()
        });
        shared.learn(
            &super::super::tests::dns_answer("git.corp.example", [198, 51, 100, 8]),
            None,
        );
        assert!(shared.beneath_for(at("198.51.100.7:443")).is_some());
        assert!(
            shared.beneath_for(at("10.20.31.5:443")).is_some(),
            "another subnet"
        );
        for (refused, why) in [
            ("10.20.30.5:443", "on link"),
            ("198.51.100.90:8080", "Android's setting"),
            ("198.51.100.8:443", "a name the exclusion list names"),
            ("10.1.10.3:53", "the tunnel's DNS address"),
            ("198.18.0.9:443", "a stand-in"),
        ] {
            assert!(shared.beneath_for(at(refused)).is_none(), "{why}");
        }
        *lock(&shared.beneath) = None;
        assert!(shared.beneath_for(at("198.51.100.7:443")).is_none());
    }

    /// The setting keeps usable addresses only, at most two, and a new setting of the same proxy keeps what was
    /// learned.
    #[test]
    fn a_setting_keeps_usable_addresses_and_what_was_learned_of_the_same_proxy() {
        let first = Beneath::new(
            NETWORK,
            &[
                at("127.0.0.1:3128"),
                at("[::1]:3128"),
                at("169.254.0.9:3128"),
                at("[fe80::9]:3128"),
                at("203.0.113.80:0"),
                at("[::ffff:203.0.113.80]:3128"),
                at("203.0.113.80:3128"),
                at("[2001:db8::80]:3128"),
                at("203.0.113.81:3128"),
            ],
            "a.example",
            (true, true),
            false,
        );
        let Some(first) = first else {
            unreachable!("a proxy kept")
        };
        assert_eq!(
            first.proxies,
            [at("203.0.113.80:3128"), at("[2001:db8::80]:3128")]
        );
        assert!(
            Beneath::new(NETWORK, &[at("127.0.0.1:8080")], "", (true, true), false).is_none(),
            "decision 3"
        );
        lock(&first.order).names_first = true;
        let held = first.kept(None);
        let again = |proxies: &[SocketAddr], exclusions: &str, network: i64, always: bool| {
            Beneath::new(network, proxies, exclusions, (true, true), always)
                .unwrap_or_else(|| unreachable!("a proxy kept"))
                .kept(Some(&held))
        };
        let same = again(
            &[at("[2001:db8::80]:3128"), at("203.0.113.80:3128")],
            "a.example",
            NETWORK,
            false,
        );
        assert!(Arc::ptr_eq(&same, &held));
        let chosen = again(
            &[at("203.0.113.80:3128"), at("[2001:db8::80]:3128")],
            "a.example",
            NETWORK,
            true,
        );
        assert!(!Arc::ptr_eq(&chosen, &held));
        let without_ipv4 = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128"), at("[2001:db8::80]:3128")],
            "a.example",
            (false, true),
            false,
        )
        .unwrap_or_else(|| unreachable!("a proxy kept"))
        .kept(Some(&held));
        assert!(!Arc::ptr_eq(&without_ipv4, &held) && !without_ipv4.ipv4);
        assert!(without_ipv4.state(Duration::ZERO).names_first);
        assert_eq!(
            chosen.state(Duration::ZERO),
            BeneathState {
                proxy_first: true,
                names_first: true,
                password: false
            }
        );
        for other in [
            again(&[at("203.0.113.80:3128")], "a.example", NETWORK, false),
            again(
                &[at("203.0.113.80:3128"), at("[2001:db8::80]:3128")],
                "b.example",
                NETWORK,
                false,
            ),
            again(
                &[at("203.0.113.80:3128"), at("[2001:db8::80]:3128")],
                "a.example",
                NETWORK + 1,
                false,
            ),
        ] {
            assert!(!other.state(Duration::ZERO).names_first);
        }
        // A list past 4 KiB is read whole, as the resolver's twin reads it: its last entry still keeps its host from
        // the proxy (S2's review, minor 3).
        let long = format!("{},last.example", "x.example,".repeat(500));
        let Some(whole) = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128")],
            &long,
            (true, true),
            false,
        ) else {
            unreachable!("a proxy kept")
        };
        assert!(long.len() > 4_096 && whole.exclusions == long);
        let ip = IpAddr::from([198, 51, 100, 7]);
        assert!(!takes(&whole, ip, false, Some("last.example")));
        assert!(takes(&whole, ip, false, Some("first.example")));
    }

    /// S2's review, minor 2: a setting kept beside one whose probe is in flight starts with the probe free, so that it
    /// probes again once [`PREFERRED`] ran out; and note 2, its state says the proxy comes first only within
    /// [`PREFERRED`] of its learning, or while a probe runs, as [`Order::start`] reads it.
    #[test]
    fn a_setting_kept_beside_a_probe_in_flight_probes_again() {
        let new = |ipv6| {
            Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, ipv6), false)
                .unwrap_or_else(|| unreachable!("a proxy kept"))
        };
        let held = new(true).kept(None);
        let since = Duration::from_secs(10);
        lock(&held.order).proxy_since = Some(since);
        assert!(
            held.state(since + PREFERRED.saturating_sub(Duration::from_secs(1)))
                .proxy_first
        );
        assert!(
            !held.state(since + PREFERRED).proxy_first,
            "PREFERRED ran out"
        );
        assert_eq!(
            lock(&held.order).start(since + PREFERRED, false),
            Start::Probe
        );
        assert!(
            held.state(since + PREFERRED).proxy_first,
            "while a probe runs"
        );
        let next = new(false).kept(Some(&held));
        assert!(!Arc::ptr_eq(&next, &held));
        // The probe's flow ends, and gives it back to the setting it started with.
        drop(Probe(Arc::clone(&held)));
        assert_eq!(
            lock(&next.order).start(since + PREFERRED * 3, false),
            Start::Probe
        );
    }

    /// C2: the order learns "proxy first" only from distinct servers that failed directly and opened through the
    /// proxy within the window, with no direct success between; a direct success ends it; the probe after
    /// [`PREFERRED`] is one connection's at a time, given back when dropped; the user's choice is always the proxy.
    #[test]
    fn the_order_is_learned_only_from_a_broad_failure() {
        let limits = Limits::default();
        let ip = |last: u8| IpAddr::from([198, 51, 100, last]);
        let s = Duration::from_secs;
        let mut order = Order::default();
        assert_eq!(order.start(s(100), false), Start::Direct);
        order.proxy_opened(ip(1), s(100), &limits, false);
        order.proxy_opened(ip(1), s(101), &limits, false);
        order.proxy_opened(ip(2), s(102), &limits, false);
        assert_eq!(
            order.start(s(103), false),
            Start::Direct,
            "two distinct servers"
        );
        order.direct_opened();
        order.proxy_opened(ip(3), s(104), &limits, false);
        order.proxy_opened(ip(4), s(105), &limits, false);
        assert_eq!(
            order.start(s(106), false),
            Start::Direct,
            "a direct success between"
        );
        order.proxy_opened(ip(5), s(200), &limits, false);
        assert_eq!(
            order.start(s(201), false),
            Start::Direct,
            "outside the window"
        );
        order.proxy_opened(ip(6), s(201), &limits, false);
        order.proxy_opened(ip(7), s(202), &limits, false);
        assert_eq!(
            order.start(s(203), false),
            Start::Proxy,
            "three within a minute"
        );
        assert_eq!(order.start(s(201) + PREFERRED, false), Start::Proxy);
        let later = s(202) + PREFERRED;
        assert_eq!(order.start(later, false), Start::Probe);
        assert_eq!(
            order.start(later, false),
            Start::Proxy,
            "one probe at a time"
        );
        order.probing = false;
        assert_eq!(
            order.start(later, false),
            Start::Probe,
            "the probe given back"
        );
        order.proxy_opened(ip(8), later, &limits, true);
        order.probing = false;
        assert_eq!(
            order.start(later + s(1), false),
            Start::Proxy,
            "renewed by the probe"
        );
        order.direct_opened();
        assert_eq!(order.start(later + s(2), false), Start::Direct);
        assert_eq!(
            order.start(later + s(2), true),
            Start::Proxy,
            "the user's choice"
        );
        for last in 9..12 {
            order.proxy_opened(ip(last), Duration::MAX, &limits, false);
        }
        assert!(
            order.failed.is_empty() && order.proxy_since.is_none(),
            "a clock that cannot be read teaches nothing"
        );
    }

    /// A direct way that answers leaves the proxy alone: it reads nothing, whatever it would answer.
    #[tokio::test(flavor = "current_thread")]
    async fn a_direct_answer_sends_the_proxy_nothing() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, _) = engine(Lab::default(), proxy.at);
        let server = echo_server().await?;
        for _ in 0..4 {
            let (stream, through) = open(&shared, UID, server, server).await;
            assert!(!through);
            echoes(&mut stream?).await?;
        }
        assert_eq!(proxy.heads(), Vec::<String>::new());
        assert_eq!(counters(&shared), [0; 7]);
        assert!(!held(&shared).state(Duration::ZERO).proxy_first);
        Ok(())
    }

    /// A direct refusal goes on to the proxy: one `CONNECT` by address, written as the bytes say, and the stream
    /// carries bytes both ways; the socket is bound to the setting's network.
    #[tokio::test(flavor = "current_thread")]
    async fn a_direct_refusal_goes_through_the_proxy_by_address() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, lab) = engine(Lab::default(), proxy.at);
        let closed = closed_port().await?;
        let (stream, through) = open(&shared, UID, closed, closed).await;
        assert!(through);
        echoes(&mut stream?).await?;
        assert_eq!(
            proxy.heads(),
            [format!(
                "CONNECT {closed} HTTP/1.1\r\nHost: {closed}\r\n\r\n"
            )]
        );
        assert_eq!(*lock(&lab.bound), [NETWORK]);
        assert_eq!(counters(&shared), [1, 1, 0, 0, 0, 0, 0]);
        Ok(())
    }

    /// A banner the server sends in the same segment as the proxy's `200`, and one after a head cut at any byte,
    /// reaches the app whole (m1).
    #[tokio::test(flavor = "current_thread")]
    async fn a_banner_after_the_head_reaches_the_app_whole() -> io::Result<()> {
        const BANNER: &[u8] = b"HTTP/1.0 200 OK\r\nVia: 1.1 p\r\n\r\n220 mail.example ESMTP\r\n";
        let banner = &BANNER[BANNER.len() - 24..];
        for cut in std::iter::once(None).chain((1..BANNER.len()).map(Some)) {
            let reply = cut.map_or(Reply::Bytes(BANNER), |at| Reply::Cut(BANNER, at));
            let proxy = Proxy::new(reply).await?;
            let (shared, _) = engine(
                Lab {
                    refuses: true,
                    ..Lab::default()
                },
                proxy.at,
            );
            let destination = at("198.51.100.25:25");
            let (stream, through) = open(&shared, UID, destination, destination).await;
            assert!(through, "cut at {cut:?}");
            let mut stream = stream?;
            let mut got = vec![0u8; banner.len()];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut got)).await??;
            assert_eq!(got, banner, "cut at {cut:?}");
        }
        Ok(())
    }

    /// A proxy that wants names: `403` to the address, then the flow's own name opens, and names come first after.
    #[tokio::test(flavor = "current_thread")]
    async fn a_refused_address_goes_by_the_flows_own_name_once_then_names_first() -> io::Result<()>
    {
        let proxy = Proxy::new(Reply::NamesOnly).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        looked_up(&shared, UID, "site.example", [198, 51, 100, 7]);
        let destination = at("198.51.100.7:443");
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(through);
        echoes(&mut stream?).await?;
        assert_eq!(
            proxy.heads(),
            [
                "CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n",
                "CONNECT site.example:443 HTTP/1.1\r\nHost: site.example:443\r\n\r\n",
            ]
        );
        assert!(held(&shared).state(Duration::ZERO).names_first);
        let (stream, _) = open(&shared, UID, destination, destination).await;
        echoes(&mut stream?).await?;
        assert_eq!(proxy.heads().len(), 3, "by name first");
        // A flow with no name still goes by address.
        let unnamed = at("198.51.100.8:443");
        let (stream, _) = open(&shared, UID, unnamed, unnamed).await;
        assert!(rescued(stream).await);
        assert!(proxy.heads()[3].starts_with("CONNECT 198.51.100.8:443 "));
        assert_eq!(counters(&shared), [4, 2, 2, 0, 0, 2, 0]);
        Ok(())
    }

    /// C1, M1 and decision 2: no name reaches a proxy that refuses addresses for a tool's flow (handed, or the
    /// chain's with the log switch on), a chained app's, a tunnelled app's local flow, an app Android did not name,
    /// a name tracker blocking refuses, an address of two names, or a name whose answer carried ECH, its mark still
    /// held or pushed out of its table.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)]
    async fn no_name_reaches_the_proxy_where_the_flows_name_is_not_its_own_to_give()
    -> io::Result<()> {
        let destination = at("198.51.100.7:443");
        let named = |shared: &Shared, name: &str| {
            looked_up(shared, UID, name, [198, 51, 100, 7]);
            looked_up(shared, OTHER, name, [198, 51, 100, 7]);
        };
        let cases: [Case; 10] = [
            (
                "a handed tool",
                |s| {
                    s.apply_proxies(ProxySetting {
                        tools: vec![UID],
                        ..ProxySetting::default()
                    });
                },
                Some(UID),
            ),
            (
                "the chain's tool, logged",
                |s| {
                    *lock(&s.chain) = Some(Arc::new(Chain {
                        proxy: at("127.0.0.1:10808"),
                        credentials: None,
                        tool: UID,
                        apps: Some([OTHER].into_iter().collect()),
                        udp: true,
                        log_destinations: true,
                    }));
                },
                Some(UID),
            ),
            (
                "a chained app",
                |s| {
                    *lock(&s.chain) = Some(Arc::new(Chain {
                        proxy: at("127.0.0.1:10808"),
                        credentials: None,
                        tool: OTHER,
                        apps: None,
                        udp: true,
                        log_destinations: true,
                    }));
                },
                Some(UID),
            ),
            (
                "a tunnelled app's local flow",
                |s| {
                    s.tunnels.set(&TunnelSetting {
                        tunnels: vec![super::super::tunnels::tests::configured(
                            1,
                            "0.0.0.0/0",
                            true,
                        )],
                        routes: [(UID, 1)].into_iter().collect(),
                        log_destinations: true,
                        ..TunnelSetting::default()
                    });
                },
                Some(UID),
            ),
            ("an app Android did not name", |_| {}, None),
            (
                "a blocked name",
                |s| {
                    s.set_blocking(BlockSetting {
                        on: true,
                        table: Some(Arc::new(crate::blocking::tests::table(&[(
                            "site.example",
                            "block",
                        )]))),
                        covered: vec![UID],
                        ..BlockSetting::default()
                    });
                },
                Some(UID),
            ),
            (
                "two names",
                |s| {
                    looked_up(s, UID, "ads.tracker.example", [198, 51, 100, 7]);
                },
                Some(UID),
            ),
            (
                "ECH",
                |s| {
                    lock(&s.names).insert_hidden("site.example", None, 300, Instant::now());
                },
                Some(UID),
            ),
            (
                "the app's own resolver naming the address otherwise (S2's review, minor 4)",
                |s| {
                    s.learn(
                        &super::super::tests::dns_answer("own.example", [198, 51, 100, 7]),
                        Some(UID),
                    );
                },
                Some(UID),
            ),
            (
                "ECH, its mark pushed out by as many ECH names as the table holds (S2's review, major 3)",
                |s| {
                    let mut table = lock(&s.names);
                    let now = Instant::now();
                    table.insert_hidden("site.example", None, 300, now);
                    for i in 0..crate::names::PUBLIC_CAPACITY {
                        table.insert_hidden(&format!("e{i}.example"), None, 300, now);
                    }
                },
                Some(UID),
            ),
        ];
        for (case, given, uid) in cases {
            let proxy = Proxy::new(Reply::NamesOnly).await?;
            let (shared, _) = engine(
                Lab {
                    refuses: true,
                    ..Lab::default()
                },
                proxy.at,
            );
            named(&shared, "site.example");
            given(&shared);
            let tried = first(&shared, held(&shared), destination).await;
            let (stream, through) =
                finish(&shared, tried, uid, (at("10.0.0.2:40000"), destination)).await;
            // A flow the forwarder may carry is rescued, and gets no name either; any other keeps S2's refusal (the
            // tool guard, m1 of the forwarder's audit).
            if may_name(&shared, uid).is_some() {
                assert!(through && rescued(stream).await, "{case}");
            } else {
                assert!(stream.is_err() && !through, "{case}");
            }
            assert_eq!(proxy.heads().len(), 1, "{case}");
            assert!(
                proxy.heads().iter().all(|h| !h.contains("site.example")),
                "{case}"
            );
        }
        // The same proxy for an ordinary app's flow: by name.
        let proxy = Proxy::new(Reply::NamesOnly).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        named(&shared, "site.example");
        let (stream, through) = open(&shared, OTHER, destination, destination).await;
        assert!(stream.is_ok() && through);
        Ok(())
    }

    /// S2's review, M2: an address that only another app's lookup named, as a hostile app's own server can answer
    /// with the address an app carries itself, gets no request by name for the app's flow; once the app's own lookup
    /// is given that name for the address, its flow goes by name.
    #[tokio::test(flavor = "current_thread")]
    async fn another_apps_lookup_never_names_a_flow() -> io::Result<()> {
        let proxy = Proxy::new(Reply::NamesOnly).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        let destination = at("198.51.100.7:443");
        looked_up(&shared, OTHER, "b.example", [198, 51, 100, 7]);
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(through && rescued(stream).await);
        assert_eq!(
            proxy.heads(),
            ["CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n"],
            "by address alone"
        );
        looked_up(&shared, UID, "b.example", [198, 51, 100, 7]);
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(through);
        echoes(&mut stream?).await?;
        assert!(proxy.heads()[2].starts_with("CONNECT b.example:443 "));
        // A lookup passed while no proxy is held notes no app.
        let (quiet, _) = engine(Lab::default(), proxy.at);
        *lock(&quiet.beneath) = None;
        looked_up(&quiet, UID, "c.example", [198, 51, 100, 9]);
        let now = Instant::now();
        assert_eq!(
            lock(&quiet.names).sole(IpAddr::from([198, 51, 100, 9]), UID, now),
            None
        );
        Ok(())
    }

    /// S2's review, M2: while the network's own proxy is held, every answer of the network part's DNS address reaches
    /// the apps with a time to live of 0, as while a chain is on, so that Android's resolver answers no app's lookup
    /// from its cache; set by the engine's setter and at its start, whatever else is set.
    #[test]
    fn while_the_networks_proxy_is_held_answers_go_uncached() -> io::Result<()> {
        let (engine_end, _app) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        let config = super::super::Config {
            mtu: 1_500,
            keep_flows: 0,
            addresses: super::super::Addresses::COMMON,
            limits: Limits::default(),
        };
        let setting = || {
            Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, true), false).map(Arc::new)
        };
        let mut engine = super::super::Engine::start(
            std::os::fd::OwnedFd::from(engine_end),
            config,
            Arc::new(Lab::default()),
            None,
        )?;
        assert!(!engine.answers_uncached());
        engine.beneath(setting());
        assert!(engine.answers_uncached(), "held");
        engine.chain(None);
        engine.tunnels(&TunnelSetting::default());
        assert!(engine.answers_uncached(), "held, with no chain nor tunnel");
        engine.beneath(None);
        assert!(!engine.answers_uncached(), "none held");
        engine.stop();
        let (engine_end, _app) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        let mut next = super::super::Engine::start_with(
            std::os::fd::OwnedFd::from(engine_end),
            config,
            Arc::new(Lab::default()),
            None,
            (
                None,
                Some(super::super::ChainSetting {
                    chain: None,
                    uncached_answers: false,
                    tunnels: TunnelSetting::default(),
                    dns: None,
                    proxies: ProxySetting::default(),
                    blocking: BlockSetting::default(),
                    beneath: setting(),
                }),
            ),
        )?;
        assert!(next.answers_uncached(), "held from the start");
        next.stop();
        Ok(())
    }

    /// S2's review, minor 1: once the proxy came first and answered, by its policy (`403`) or because it could not reach
    /// the server (`502`), the direct try after it has `Limits::beneath_direct` alone, and then the app sees that
    /// answer, a reset or an ICMP error, rather than the rest of `Limits::connect_timeout` of a direct way that drops.
    #[tokio::test(flavor = "current_thread")]
    async fn after_the_proxy_answered_the_direct_try_has_its_share_alone() -> io::Result<()> {
        for (reply, seen) in [
            (
                b"HTTP/1.1 403 Forbidden\r\n\r\n".as_slice(),
                io::ErrorKind::ConnectionRefused,
            ),
            (
                b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
                io::ErrorKind::HostUnreachable,
            ),
        ] {
            let proxy = Proxy::new(Reply::Bytes(reply)).await?;
            let lab = Lab {
                slow: Duration::from_millis(1_500),
                ..Lab::default()
            };
            let (shared, _) = engine(lab, proxy.at);
            lock(&held(&shared).order).proxy_since = Some(shared.clock.since_boot());
            let server = echo_server().await?;
            let began = Instant::now();
            let (stream, through) = open(&shared, UID, server, server).await;
            if seen == io::ErrorKind::ConnectionRefused {
                // Refused: the forwarder rescues the flow, with no direct try (the maintainer's decision of 2026-11-27).
                assert!(through && rescued(stream).await);
            } else {
                assert_eq!(stream.err().map(|e| e.kind()), Some(seen));
                assert!(!through);
            }
            assert!(
                began.elapsed() < Duration::from_secs(1),
                "{:?}",
                began.elapsed()
            );
        }
        Ok(())
    }

    /// S2's review, minor 4: a name whose answer carried an ECH configuration, learned from that answer as the lookups'
    /// paths learn it (an HTTPS record with `ech=`), never goes to the proxy, where the same answer without it does.
    #[tokio::test(flavor = "current_thread")]
    async fn a_name_learned_with_ech_from_its_answer_never_reaches_the_proxy() -> io::Result<()> {
        let destination = at("93.184.216.34:443");
        for (answer, by_name) in [
            (crate::dns::tests::with_https("cover.example"), false),
            (
                super::super::tests::dns_answer("www.example.com", [93, 184, 216, 34]),
                true,
            ),
        ] {
            let proxy = Proxy::new(Reply::NamesOnly).await?;
            let (shared, _) = engine(
                Lab {
                    refuses: true,
                    ..Lab::default()
                },
                proxy.at,
            );
            shared.learn(&answer, None);
            shared.passed(Some(UID), &answer);
            let (stream, through) = open(&shared, UID, destination, destination).await;
            // Refused by address with no name to give, the flow is rescued by the forwarder, which sends nothing yet.
            assert!(through && (by_name || rescued(stream).await));
            assert_eq!(proxy.heads().len(), if by_name { 2 } else { 1 });
            assert_eq!(
                proxy.heads().iter().any(|h| h.contains("www.example.com")),
                by_name
            );
        }
        Ok(())
    }

    /// S2's review, minor 4: a proxy that wants a password (`407`) gets no request by name after it, though the
    /// address has the flow's own sole name: one request alone.
    #[tokio::test(flavor = "current_thread")]
    async fn after_a_password_wanted_no_request_by_name_follows() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n",
        ))
        .await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        looked_up(&shared, UID, "site.example", [198, 51, 100, 7]);
        let destination = at("198.51.100.7:443");
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(stream.is_err() && !through);
        assert_eq!(proxy.heads().len(), 1);
        assert!(held(&shared).state(Duration::ZERO).password);
        Ok(())
    }

    /// The user's choice, with the proxy's two addresses, the first a closed port: [`ask`] turns to the other, so that
    /// the next flow opens through it (S2's review, minor 4); and it does not turn where the proxy only ran out of the
    /// time the flow had left, short of its own share (note 3), here a port whose queue is full.
    #[tokio::test(flavor = "current_thread")]
    async fn ask_turns_to_the_proxys_other_address_after_a_refusal_alone() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let closed = closed_port().await?;
        let (shared, _) = engine(Lab::default(), proxy.at);
        let two = |first: SocketAddr| {
            let mut beneath =
                Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, true), true)
                    .unwrap_or_else(|| unreachable!("a proxy kept"));
            beneath.proxies = vec![first, proxy.at];
            *lock(&shared.beneath) = Some(Arc::new(beneath));
        };
        two(closed);
        let destination = at("198.51.100.7:443");
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(stream.is_err() && !through, "the closed port");
        let (stream, through) = open(&shared, UID, destination, destination).await;
        assert!(through, "the other address");
        echoes(&mut stream?).await?;
        // A port that takes no more connections, its queue full: a connect there waits.
        let full = TcpSocket::new_v4()?;
        full.bind((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
        let full = full.listen(0)?;
        let waiting = full.local_addr()?;
        let mut queued = Vec::new();
        for _ in 0..2 {
            if let Ok(Ok(stream)) =
                tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(waiting)).await
            {
                queued.push(stream);
            }
        }
        let mut short = shared_with(Arc::new(Lab::default()) as Arc<dyn Platform>);
        short.limits.beneath_direct = Duration::from_millis(300);
        short.limits.beneath_answer = Duration::from_millis(300);
        short.limits.connect_timeout = Duration::from_millis(150);
        let short = Arc::new(short);
        *lock(&short.beneath) = lock(&shared.beneath).clone();
        let mut beneath = Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, true), true)
            .unwrap_or_else(|| unreachable!("a proxy kept"));
        beneath.proxies = vec![waiting, proxy.at];
        let beneath = Arc::new(beneath);
        *lock(&short.beneath) = Some(Arc::clone(&beneath));
        let (stream, _) = open(&short, UID, destination, destination).await;
        assert!(stream.is_err());
        assert_eq!(
            beneath.proxy(),
            waiting,
            "the flow's own time ran out, not the proxy's share"
        );
        drop((queued, full));
        Ok(())
    }

    /// M6: when both ways fail, the app sees the direct way's own outcome, whatever the proxy answered; `407` is
    /// counted and kept as a fact, `502` counted as unreachable; a proxy that closes or is silent gives no answer.
    #[tokio::test(flavor = "current_thread")]
    async fn when_both_ways_fail_the_app_sees_the_direct_ways_outcome() -> io::Result<()> {
        for (reply, counted) in [
            (Reply::Bytes(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n"), [1, 0, 0, 1, 0, 0, 0]),
            (Reply::Bytes(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"), [1, 0, 0, 0, 1, 0, 0]),
            (Reply::Bytes(b"HTTP/1.1 302 Found\r\nLocation: http://login.example/\r\n\r\n"), [1, 0, 1, 0, 0, 0, 0]),
            (Reply::Bytes(b"SSH-2.0-OpenSSH_9.6\r\n\r\n"), [1, 0, 0, 0, 0, 0, 0]),
            (Reply::Closed, [1, 0, 0, 0, 0, 0, 0]),
            (Reply::Silent, [1, 0, 0, 0, 0, 0, 0]),
        ] {
            let proxy = Proxy::new(reply).await?;
            let (shared, lab) = engine(Lab::default(), proxy.at);
            let closed = closed_port().await?;
            let (stream, through) = open(&shared, UID, closed, closed).await;
            let kind = stream.err().map(|e| e.kind());
            assert_eq!((kind, through), (Some(io::ErrorKind::ConnectionRefused), false));
            assert_eq!(lab.protects.load(Ordering::SeqCst), 1, "one direct try alone");
            assert_eq!(counters(&shared), counted);
            assert_eq!(held(&shared).state(Duration::ZERO).password, counted[3] == 1);
        }
        Ok(())
    }

    /// M6's stale setting: a direct try that ran out of its share, and a proxy that answers nothing, leave the rest
    /// of the time to a direct try, which opens; nothing is learned.
    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_server_behind_a_dead_proxy_still_opens_directly() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Silent).await?;
        let lab = Lab {
            slow: Duration::from_millis(400),
            ..Lab::default()
        };
        let (shared, lab) = engine(lab, proxy.at);
        let server = echo_server().await?;
        let (stream, through) = open(&shared, UID, server, server).await;
        assert!(!through);
        echoes(&mut stream?).await?;
        assert_eq!(lab.protects.load(Ordering::SeqCst), 2);
        assert_eq!(proxy.heads().len(), 1);
        assert!(!held(&shared).state(Duration::ZERO).proxy_first);
        Ok(())
    }

    /// m5: a socket to the proxy the network part will not bind, the network having changed, carries no byte, and is
    /// counted.
    #[tokio::test(flavor = "current_thread")]
    async fn a_proxy_of_another_network_gets_no_byte() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, _) = engine(
            Lab {
                stale: true,
                ..Lab::default()
            },
            proxy.at,
        );
        let closed = closed_port().await?;
        let (stream, through) = open(&shared, UID, closed, closed).await;
        assert_eq!(
            stream.err().map(|e| e.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert!(!through);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(proxy.heads(), Vec::<String>::new());
        assert_eq!(counters(&shared), [0, 0, 0, 0, 0, 0, 1]);
        Ok(())
    }

    /// C2 through the sockets: three distinct servers failing directly and opening through the proxy put it first,
    /// so that a fourth flow tries nothing directly; after [`PREFERRED`] on the manual clock one flow probes, and its
    /// direct success brings the direct way back first.
    #[tokio::test(flavor = "current_thread")]
    async fn three_servers_failing_directly_put_the_proxy_first_until_a_probe_answers()
    -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, lab, clock) = engine_clocked(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        for last in 1..=3 {
            let destination = SocketAddr::from(([198, 51, 100, last], 443));
            assert!(open(&shared, UID, destination, destination).await.1);
            assert_eq!(
                held(&shared).state(clock.since_boot()).proxy_first,
                last == 3
            );
        }
        let before = lab.protects.load(Ordering::SeqCst);
        let destination = at("198.51.100.4:443");
        assert!(open(&shared, UID, destination, destination).await.1);
        assert_eq!(lab.protects.load(Ordering::SeqCst), before, "no direct try");
        clock.pass(u64::try_from(PREFERRED.as_millis()).unwrap_or(u64::MAX));
        assert!(open(&shared, UID, destination, destination).await.1);
        assert_eq!(lab.protects.load(Ordering::SeqCst), before + 1, "the probe");
        assert!(
            held(&shared).state(clock.since_boot()).proxy_first,
            "renewed"
        );
        clock.pass(u64::try_from(PREFERRED.as_millis()).unwrap_or(u64::MAX));
        let server = echo_server().await?;
        let mut answering = shared_with(Arc::new(Lab::default()) as Arc<dyn Platform>);
        answering.clock = clock.clone();
        let answering = Arc::new(answering);
        *lock(&answering.beneath) = Some(held(&shared));
        let (stream, through) = open(&answering, UID, server, server).await;
        assert!(stream.is_ok() && !through);
        assert!(
            !held(&shared).state(clock.since_boot()).proxy_first,
            "the direct way first again"
        );
        Ok(())
    }

    /// A failure alone teaches nothing: three distinct servers failing directly and refused by the proxy too leave
    /// the direct way first.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failure_alone_teaches_nothing() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(b"HTTP/1.1 403 Forbidden\r\n\r\n")).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        for last in 1..=4 {
            let destination = SocketAddr::from(([198, 51, 100, last], 443));
            assert!(rescued(open(&shared, UID, destination, destination).await.0).await);
        }
        assert!(!held(&shared).state(Duration::ZERO).proxy_first);
        assert_eq!(proxy.heads().len(), 4);
        Ok(())
    }

    /// m8: the probe is given back when its flow is dropped before it ends, so that the next flow probes.
    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_flow_gives_the_probe_back() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let lab = Lab {
            slow: Duration::from_millis(200),
            ..Lab::default()
        };
        let (shared, _) = engine(lab, proxy.at);
        let beneath = held(&shared);
        let now = shared.clock.since_boot();
        lock(&beneath.order).proxy_since = Some(now.saturating_sub(PREFERRED));
        let destination = at("198.51.100.7:443");
        let dropped = tokio::time::timeout(
            Duration::from_millis(50),
            first(&shared, Arc::clone(&beneath), destination),
        )
        .await;
        assert!(dropped.is_err(), "still trying directly");
        assert!(!lock(&beneath.order).probing);
        assert_eq!(lock(&beneath.order).start(now, false), Start::Probe);
        Ok(())
    }

    /// A connection being opened keeps the setting it started with: replaced meanwhile, the old proxy carries it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_setting_replaced_during_a_try_keeps_its_snapshot() -> io::Result<()> {
        let old = Proxy::new(Reply::Cut(OPENED, 10)).await?;
        let new = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            old.at,
        );
        let destination = at("198.51.100.7:443");
        let tried = first(&shared, held(&shared), destination).await;
        set(&shared, new.at, "");
        let (stream, through) = finish(
            &shared,
            tried,
            Some(UID),
            (at("10.0.0.2:40000"), destination),
        )
        .await;
        assert!(stream.is_ok() && through);
        assert_eq!((old.heads().len(), new.heads().len()), (1, 0));
        Ok(())
    }

    /// The user's choice: the proxy is the only way, tried first, and its refusal is the flow's.
    #[tokio::test(flavor = "current_thread")]
    async fn with_the_users_choice_the_proxy_is_the_only_way() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(b"HTTP/1.1 403 Forbidden\r\n\r\n")).await?;
        let (shared, lab) = engine(Lab::default(), proxy.at);
        let Some(mut beneath) =
            Beneath::new(NETWORK, &[at("203.0.113.80:3128")], "", (true, true), true)
        else {
            unreachable!("a proxy kept")
        };
        beneath.proxies = vec![proxy.at];
        *lock(&shared.beneath) = Some(Arc::new(beneath));
        let server = echo_server().await?;
        let (stream, through) = open(&shared, UID, server, server).await;
        // Refused under the user's choice: the forwarder rescues the flow, never directly.
        assert!(through && rescued(stream).await);
        assert_eq!(lab.protects.load(Ordering::SeqCst), 0, "never directly");
        assert_eq!(proxy.heads().len(), 1);
        Ok(())
    }

    /// The switch's hold of [`NETWORK`] (S2's review, m2), set on `shared`: the user's choice, and no address yet.
    fn hold(shared: &Shared) {
        let Some(hold) = Beneath::new(NETWORK, &[], "", (true, true), true) else {
            unreachable!("the switch's hold")
        };
        assert!(hold.holds());
        *lock(&shared.beneath) = Some(Arc::new(hold));
    }

    /// The proxy at `proxy` with the user's choice `always`, as the network part's settle hands it after a hold.
    fn settled(proxy: SocketAddr, always: bool) -> Option<Arc<Beneath>> {
        let mut beneath = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128")],
            "",
            (true, true),
            always,
        )?;
        beneath.proxies = vec![proxy];
        Some(Arc::new(beneath))
    }

    /// How many flows the switch's hold kept waiting.
    fn held_flows(shared: &Shared) -> u64 {
        shared.counters.snapshot()[80]
    }

    /// S2's review, m2: under the switch's hold a direct app's flow waits, nothing of it sent, until the setting comes,
    /// and then goes through the proxy that came, never directly.
    #[tokio::test(flavor = "current_thread")]
    async fn the_switchs_hold_keeps_a_flow_until_the_proxy_comes() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, lab) = engine(Lab::default(), proxy.at);
        hold(&shared);
        let server = echo_server().await?;
        let began = Instant::now();
        let flow = open(&shared, UID, at("198.51.100.7:443"), server);
        let setting = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(proxy.heads().len(), 0, "nothing to the proxy while held");
            assert_eq!(lab.protects.load(Ordering::SeqCst), 0, "nothing directly");
            assert_eq!(held_flows(&shared), 1);
            *lock(&shared.beneath) = settled(proxy.at, true);
        };
        let ((stream, through), ()) = tokio::join!(flow, setting);
        assert!(through);
        // Within a look of the setting, long before the hold's bound (300 ms here).
        assert!(
            began.elapsed() < Duration::from_millis(250),
            "{:?}",
            began.elapsed()
        );
        echoes(&mut stream?).await?;
        assert_eq!(lab.protects.load(Ordering::SeqCst), 0, "never directly");
        assert_eq!(
            proxy.heads(),
            ["CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n"]
        );
        Ok(())
    }

    /// The hold's bound: a flow the setting never replaced fails once `Limits::beneath_direct` passed since the hold
    /// began, as a proxy that cannot be reached fails it under the user's choice, and a flow after that fails at once;
    /// neither sends anything anywhere.
    #[tokio::test(flavor = "current_thread")]
    async fn the_switchs_hold_fails_a_flow_once_its_time_passed() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, lab) = engine(Lab::default(), proxy.at);
        hold(&shared);
        let server = echo_server().await?;
        let destination = at("198.51.100.7:443");
        let began = Instant::now();
        let (stream, through) = open(&shared, UID, destination, server).await;
        let waited = began.elapsed();
        assert_eq!(
            stream.err().map(|e| e.kind()),
            Some(io::ErrorKind::NetworkUnreachable)
        );
        assert!(!through);
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(2),
            "{waited:?}"
        );
        let began = Instant::now();
        let (stream, _) = open(&shared, UID, destination, server).await;
        assert!(stream.is_err());
        assert!(began.elapsed() < Duration::from_millis(150), "at once");
        assert_eq!(lab.protects.load(Ordering::SeqCst), 0, "never directly");
        assert_eq!(proxy.heads().len(), 0);
        assert_eq!(held_flows(&shared), 2);
        Ok(())
    }

    /// With the switch off nothing is held: no address and no choice is no setting, and a hold replaced by the switch
    /// turned off, or by none, lets its flow try directly first, as before.
    #[tokio::test(flavor = "current_thread")]
    async fn the_switch_off_holds_nothing() -> io::Result<()> {
        assert!(Beneath::new(NETWORK, &[], "", (true, true), false).is_none());
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, lab) = engine(Lab::default(), proxy.at);
        let server = echo_server().await?;
        for (n, then) in [settled(proxy.at, false), None].into_iter().enumerate() {
            hold(&shared);
            let flow = open(&shared, UID, at("198.51.100.7:443"), server);
            let setting = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                *lock(&shared.beneath) = then;
            };
            let ((stream, through), ()) = tokio::join!(flow, setting);
            assert!(!through);
            echoes(&mut stream?).await?;
            assert_eq!(lab.protects.load(Ordering::SeqCst), n + 1, "directly");
        }
        assert_eq!(proxy.heads().len(), 0);
        Ok(())
    }

    /// A case of [`the_switchs_hold_keeps_no_tools_or_tunnelled_apps_flow`]: what it is, and what it sets.
    type Unheld = (&'static str, fn(&Shared));

    /// The hold keeps no circumvention tool's flow, handed or the chain's, nor a tunnelled app's to its local network:
    /// they go on at once, directly, as without the proxy.
    #[tokio::test(flavor = "current_thread")]
    async fn the_switchs_hold_keeps_no_tools_or_tunnelled_apps_flow() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let server = echo_server().await?;
        let cases: [Unheld; 3] = [
            ("a handed tool", |s| {
                s.apply_proxies(ProxySetting {
                    tools: vec![UID],
                    ..ProxySetting::default()
                });
            }),
            ("the chain's tool", |s| {
                *lock(&s.chain) = Some(Arc::new(Chain {
                    proxy: at("127.0.0.1:10808"),
                    credentials: None,
                    tool: UID,
                    apps: None,
                    udp: true,
                    log_destinations: false,
                }));
            }),
            ("a tunnelled app's local flow", |s| {
                s.tunnels.set(&TunnelSetting {
                    tunnels: vec![super::super::tunnels::tests::configured(
                        1,
                        "0.0.0.0/0",
                        true,
                    )],
                    routes: [(UID, 1)].into_iter().collect(),
                    ..TunnelSetting::default()
                });
            }),
        ];
        for (why, setting) in cases {
            let (shared, lab) = engine(Lab::default(), proxy.at);
            setting(&shared);
            hold(&shared);
            let began = Instant::now();
            let (stream, through) = open(&shared, UID, at("198.51.100.7:443"), server).await;
            assert!(!through, "{why}");
            echoes(&mut stream?).await?;
            assert!(
                began.elapsed() < Duration::from_millis(200),
                "{why}: not held"
            );
            assert_eq!(lab.protects.load(Ordering::SeqCst), 1, "{why}: directly");
            assert_eq!(held_flows(&shared), 0, "{why}");
        }
        assert_eq!(proxy.heads().len(), 0);
        Ok(())
    }

    /// S2's review, major 1: a direct try the kernel answers with "network unreachable" at once (as Linux answers an
    /// ICMP net unreachable, and a TCP connection to a multicast address) is the network's rejection where the setting
    /// says it has that family: it goes on to the proxy, which opens it, as after a reset.
    #[tokio::test(flavor = "current_thread")]
    async fn a_direct_try_the_network_answers_unreachable_goes_through_the_proxy() -> io::Result<()>
    {
        let proxy = Proxy::new(Reply::Bytes(OPENED)).await?;
        let (shared, _) = engine(Lab::default(), proxy.at);
        let destination = at("198.51.100.7:443");
        let (stream, through) = open(&shared, UID, destination, at("224.0.0.1:443")).await;
        assert!(through);
        echoes(&mut stream?).await?;
        assert_eq!(
            proxy.heads(),
            ["CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n"]
        );
        assert_eq!(counters(&shared), [1, 1, 0, 0, 0, 0, 0]);
        Ok(())
    }

    /// No address of the destination's family is the app's own error at once, and never goes to the proxy (C2); "network
    /// unreachable" goes on (S2's review, major 1).
    #[test]
    fn no_route_of_that_family_goes_nowhere_else() {
        assert!(no_route(&io::ErrorKind::AddrNotAvailable.into()));
        let kind = |end: Result<io::Result<()>, (io::Error, bool)>| match end {
            Ok(Ok(())) => (None, None),
            Ok(Err(error)) => (Some(error.kind()), None),
            Err((error, ran_out)) => (Some(error.kind()), Some(ran_out)),
        };
        assert_eq!(kind(direct_end(Some(Ok(())))), (None, None));
        assert_eq!(
            kind(direct_end(Some(
                Err(io::ErrorKind::AddrNotAvailable.into())
            ))),
            (Some(io::ErrorKind::AddrNotAvailable), None),
            "the app's own error, at once"
        );
        assert_eq!(
            kind(direct_end(Some(Err(
                io::ErrorKind::NetworkUnreachable.into()
            )))),
            (Some(io::ErrorKind::NetworkUnreachable), Some(false)),
            "on to the proxy"
        );
        assert_eq!(
            kind(direct_end::<()>(None)),
            (Some(io::ErrorKind::TimedOut), Some(true))
        );
        for kind in [
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(!no_route(&kind.into()), "{kind:?}");
        }
    }

    /// The proxy's second address is tried first once the first could not be reached.
    #[test]
    fn an_unreachable_proxy_address_turns_to_the_other() {
        let Some(beneath) = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128"), at("203.0.113.81:3128")],
            "",
            (true, true),
            false,
        ) else {
            unreachable!("a proxy kept")
        };
        assert_eq!(beneath.proxy(), at("203.0.113.80:3128"));
        beneath.unreachable(at("203.0.113.81:3128"));
        assert_eq!(
            beneath.proxy(),
            at("203.0.113.80:3128"),
            "not the one tried"
        );
        beneath.unreachable(at("203.0.113.80:3128"));
        assert_eq!(beneath.proxy(), at("203.0.113.81:3128"));
        beneath.unreachable(at("203.0.113.81:3128"));
        assert_eq!(beneath.proxy(), at("203.0.113.80:3128"));
    }

    /// A request through a rescued flow: `request` written, the proxy's answer read whole, its body the request line
    /// the proxy got.
    async fn asked(stream: &mut TcpStream, request: &[u8]) -> io::Result<String> {
        stream.write_all(request).await?;
        let mut answer = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut answer)).await??;
        let answer = String::from_utf8_lossy(&answer[..n]).into_owned();
        Ok(answer
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .to_owned())
    }

    /// The forwarder's places among the counters: forwarded, by `CONNECT` after all, reset, late, remembered.
    fn forwarder(shared: &Shared) -> [u64; 5] {
        let all = shared.counters.snapshot();
        let mut five = [0; 5];
        five.copy_from_slice(&all[81..86]);
        five
    }

    /// The forwarder (the maintainer's decision of 2026-11-27): a proxy that refuses `CONNECT` to port 80, as squid's
    /// default, has the flow rescued, its head forwarded in absolute form with every other byte as the app wrote it,
    /// two requests on one connection both rewritten; the refusal is remembered, so the next flow sends no `CONNECT`;
    /// a head written late is forwarded, never cut (M2), and counted.
    #[tokio::test]
    async fn a_refused_port_is_rescued_its_requests_forwarded_and_the_refusal_remembered()
    -> io::Result<()> {
        let proxy = Proxy::new(Reply::Forward).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        looked_up(&shared, UID, "example.test", [198, 51, 100, 9]);
        let destination = at("198.51.100.9:80");
        let (stream, through) = open(&shared, UID, destination, destination).await;
        let mut stream = stream?;
        assert!(through);
        let one = b"GET /p?q HTTP/1.1\r\nHost: example.test\r\nX-A: 1\r\n\r\n";
        assert_eq!(
            asked(&mut stream, one).await?,
            "GET http://example.test/p?q HTTP/1.1"
        );
        let two = b"POST /f HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(
            asked(&mut stream, two).await?,
            "POST http://example.test/f HTTP/1.1"
        );
        let heads = proxy.heads();
        assert_eq!(heads.len(), 4, "{heads:?}");
        assert!(
            heads[0].starts_with("CONNECT 198.51.100.9:80 ")
                && heads[1].starts_with("CONNECT example.test:80 ")
        );
        assert_eq!(
            heads[2],
            "GET http://example.test/p?q HTTP/1.1\r\nHost: example.test\r\nX-A: 1\r\n\r\n"
        );
        assert!(held(&shared).refuses(80));
        let (stream, _) = open(&shared, UID, destination, destination).await;
        let mut late = stream?;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            asked(&mut late, one).await?,
            "GET http://example.test/p?q HTTP/1.1"
        );
        assert_eq!(proxy.heads().len(), 5, "no CONNECT for a remembered port");
        assert_eq!(forwarder(&shared), [2, 0, 0, 1, 1]);
        Ok(())
    }

    /// What the forwarder never carries: a `Host` no answer of Datapavan's own resolvers gave the address (M3's
    /// binding), and on a forwarded connection a later head with another `Host`, after which the proxy holds only the
    /// first request.
    #[tokio::test]
    async fn an_unbound_host_or_a_later_other_host_is_reset() -> io::Result<()> {
        let proxy = Proxy::new(Reply::Forward).await?;
        let (shared, _) = engine(
            Lab {
                refuses: true,
                ..Lab::default()
            },
            proxy.at,
        );
        looked_up(&shared, UID, "example.test", [198, 51, 100, 9]);
        let destination = at("198.51.100.9:80");
        let (stream, _) = open(&shared, UID, destination, destination).await;
        let mut stream = stream?;
        let fake = b"GET / HTTP/1.1\r\nHost: popular.example\r\n\r\n";
        assert!(
            asked(&mut stream, fake)
                .await
                .map_or(true, |body| body.is_empty()),
            "reset"
        );
        assert_eq!(proxy.heads().len(), 2, "only the two CONNECTs");
        let (stream, _) = open(&shared, UID, destination, destination).await;
        let mut stream = stream?;
        let one = b"GET /1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert_eq!(
            asked(&mut stream, one).await?,
            "GET http://example.test/1 HTTP/1.1"
        );
        let other = b"GET /2 HTTP/1.1\r\nHost: other.example\r\n\r\n";
        assert!(
            asked(&mut stream, other)
                .await
                .map_or(true, |body| body.is_empty()),
            "reset"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(proxy.heads().len(), 3, "{:?}", proxy.heads());
        assert_eq!(forwarder(&shared), [1, 0, 2, 0, 1]);
        Ok(())
    }
}
