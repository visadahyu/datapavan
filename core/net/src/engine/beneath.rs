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
//! **What the app sees** (M6): the proxy's `2xx` opens the flow through it. When both ways fail, the app sees the
//! direct way's outcome, a reset for a direct refusal, whatever the proxy answered. A direct try that ran out of its
//! share, or a proxy that came first and opened nothing, hands the rest of `Limits::connect_timeout` to a direct try,
//! so that a stale setting (a debugging proxy since switched off) never costs a slow server its connection.
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

/// The longest exclusion list kept, in bytes: a longer one is cut after its last whole entry within it.
pub const MAX_EXCLUSIONS: usize = 4_096;

/// The network beneath's own proxy, as the network part settled it, and what the engines learned of it.
#[derive(Debug)]
pub struct Beneath {
    /// The network's handle (`Network.getNetworkHandle`), to which each socket to the proxy is bound.
    network: i64,
    /// The proxy's usable addresses, at most [`MAX_ADDRESSES`], in the order given.
    proxies: Vec<SocketAddr>,
    /// The exclusion list, comma-separated entries, at most [`MAX_EXCLUSIONS`] bytes.
    exclusions: String,
    /// Whether the network has IPv4: without, an IPv4 destination never goes through the proxy (audit C2).
    ipv4: bool,
    /// Whether the network has IPv6: without, an IPv6 destination never goes through the proxy (audit C2).
    ipv6: bool,
    /// The user's choice "Send apps through this proxy" for this network (decision 1).
    always: bool,
    /// What was learned: which way comes first, and whether names do.
    order: Mutex<Order>,
    /// Whether the proxy asked for a password (`407`): a fact a release build shows, naming no app or place (m2).
    password: AtomicBool,
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
    /// broadcast or unspecified, and none of port 0: `None` when none is left.
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
        if kept.is_empty() {
            return None;
        }
        let mut exclusions = exclusions;
        if exclusions.len() > MAX_EXCLUSIONS {
            let mut cut = MAX_EXCLUSIONS;
            while !exclusions.is_char_boundary(cut) {
                cut -= 1;
            }
            exclusions = exclusions[..cut]
                .rsplit_once(',')
                .map_or("", |(whole, _)| whole);
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
        })
    }

    /// This setting as the engines should hold it, beside `held`, the one held now: `held` itself when it is the same
    /// proxy (the same network, the same set of addresses, the same exclusions) and the same choice, so that what was
    /// learned of it stays; a new one with what was learned when only the user's choice changed; else this one.
    #[must_use]
    pub fn kept(self, held: Option<&Arc<Self>>) -> Arc<Self> {
        let Some(held) = held.filter(|held| held.same(&self)) else {
            return Arc::new(self);
        };
        if held.always == self.always && held.ipv4 == self.ipv4 && held.ipv6 == self.ipv6 {
            return Arc::clone(held);
        }
        Arc::new(Self {
            order: Mutex::new(lock(&held.order).clone()),
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

    /// What was learned of the proxy at `now`, in time since the phone started.
    #[must_use]
    pub fn state(&self, now: Duration) -> BeneathState {
        let order = lock(&self.order);
        BeneathState {
            proxy_first: self.always || order.proxy_since.is_some_and(|_| now != Duration::MAX),
            names_first: order.names_first,
            password: self.password.load(Ordering::Relaxed),
        }
    }

    /// The proxy's address tried now.
    fn proxy(&self) -> SocketAddr {
        self.proxies[lock(&self.order).next % self.proxies.len()]
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
enum Failure {
    /// No answer: it could not be reached, closed, sent no head in time, or not HTTP; or its socket could not be
    /// bound to the network.
    Silent(io::Error),
    /// An answer that opened nothing.
    Answered(Answer),
}

impl Failure {
    /// What the app sees where the proxy was its only way (the user's choice): a reset for a refusal, an ICMP error
    /// for a proxy that could not reach the destination, or the error itself.
    fn error(self) -> io::Error {
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
        let direct =
            match tokio::time::timeout(shared.limits.beneath_direct, connect_tcp(shared, target))
                .await
            {
                Ok(Ok(stream)) => {
                    lock(&beneath.order).direct_opened();
                    return Tried::Done(Ok(stream));
                }
                Ok(Err(error)) if no_route(&error) => return Tried::Done(Err(error)),
                Ok(Err(error)) => (error, false),
                Err(_) => (io::ErrorKind::TimedOut.into(), true),
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
/// steps to `destination` and then the direct way's last try; and whether it went through the proxy.
pub(super) async fn finish(
    shared: &Arc<Shared>,
    tried: Tried,
    uid: Option<u32>,
    destination: SocketAddr,
) -> (io::Result<TcpStream>, bool) {
    match tried {
        Tried::Done(result) => (result, false),
        Tried::Onward(onward) => onward_steps(shared, *onward, uid, destination).await,
    }
}

/// The proxy's steps, then the direct way with what is left where the module's comment says. Boxed and out of line.
#[cold]
#[inline(never)]
fn onward_steps(
    shared: &Arc<Shared>,
    onward: Onward,
    uid: Option<u32>,
    destination: SocketAddr,
) -> Pin<Box<dyn Future<Output = (io::Result<TcpStream>, bool)> + Send + '_>> {
    Box::pin(async move {
        let Onward {
            beneath,
            target,
            began,
            direct,
            probe,
        } = onward;
        let limits = shared.limits;
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
            Err(failure) if beneath.always => return (Err(failure.error()), false),
            Err(_) => {}
        }
        if let Some((error, false)) = direct {
            // Both ways failed: the app sees the direct way's own outcome (M6).
            return (Err(error), false);
        }
        let left = limits.connect_timeout.saturating_sub(began.elapsed());
        let result = match tokio::time::timeout(left, connect_tcp(shared, target)).await {
            Ok(result) => result,
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        };
        if result.is_ok() {
            lock(&beneath.order).direct_opened();
        }
        drop(probe);
        (result, false)
    })
}

/// Through the proxy to `destination`: by address, then by the flow's own name where the proxy refused the address,
/// or by name first once names came first.
async fn through(
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

/// The name a request may carry for the flow of `uid` to `destination` (the module's comment, C1, M1, decision 2).
fn own_name(shared: &Shared, uid: Option<u32>, destination: SocketAddr) -> Option<Target> {
    let uid = uid?;
    if shared.is_tool(Some(uid)) || !matches!(shared.app_route(Some(uid)), Route::Direct) {
        return None;
    }
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
    let mut stream = match tokio::time::timeout(
        limits.beneath_direct.min(left()),
        socket.connect(proxy),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        failed => {
            beneath.unreachable(proxy);
            return Err(Failure::Silent(match failed {
                Ok(Err(error)) => error,
                _ => io::ErrorKind::TimedOut.into(),
            }));
        }
    };
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
        match connect::head_end(&head) {
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
            Reply::Closed => return,
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
        finish(shared, tried, Some(uid), destination).await
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
        let long = format!("{},last.example", "x.example,".repeat(500));
        let Some(cut) = Beneath::new(
            NETWORK,
            &[at("203.0.113.80:3128")],
            &long,
            (true, true),
            false,
        ) else {
            unreachable!("a proxy kept")
        };
        assert!(cut.exclusions.len() <= MAX_EXCLUSIONS && cut.exclusions.ends_with("x.example"));
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
        assert!(stream.is_err());
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
        let cases: [Case; 9] = [
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
            let (stream, through) = finish(&shared, tried, uid, destination).await;
            assert!(stream.is_err() && !through, "{case}");
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
        assert!(stream.is_err() && !through);
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
            let (shared, _) = engine(Lab::default(), proxy.at);
            let closed = closed_port().await?;
            let (stream, through) = open(&shared, UID, closed, closed).await;
            let kind = stream.err().map(|e| e.kind());
            assert_eq!((kind, through), (Some(io::ErrorKind::ConnectionRefused), false));
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
            assert!(!open(&shared, UID, destination, destination).await.1);
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
        let (stream, through) = finish(&shared, tried, Some(UID), destination).await;
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
        assert_eq!(
            stream.err().map(|e| e.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert!(!through);
        assert_eq!(lab.protects.load(Ordering::SeqCst), 0, "never directly");
        assert_eq!(proxy.heads().len(), 1);
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
}
