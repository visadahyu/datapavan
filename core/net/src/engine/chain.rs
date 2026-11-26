//! Chaining (W6): the apps the user picks go through the local SOCKS5 proxy of the user's tool, and
//! nothing of theirs leaves directly (docs/VPN.md, "Coexistence with other VPNs"; ADR 0038).
//!
//! While a chain is on, a flow's route waits for Android to name its app: a chained app's connection
//! must not start on the network beneath and then be moved. The tool's own traffic goes directly, so
//! that it does not loop back into its proxy. A flow whose app Android cannot name goes nowhere while
//! a chain is on: directly it could be a chained app's, and through the tool it could be the tool's own.

use super::lookups::RESOLVERS;
use super::upstream::protect;
use super::{Shared, lock};
use crate::socks5::{self, Command, Credentials, Target};
use crate::standins::is_stand_in;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};

/// How long what the chain asked the tool for ties the chained tool's direct flows to it (R10, the proxy record's unit
/// D): ten seconds on the boot clock, sleep included.
pub(super) const CARRIED: Duration = Duration::from_secs(10);

/// The most requests [`Carried`] holds at once: past it, the oldest is forgotten, and a direct flow the tool opens for
/// it later counts as the tool's own (ADR 0052's limits, audit-D m5).
pub(super) const CARRIES: usize = 256;

/// What the chain asked the tool for within [`CARRIED`] (R10, the proxy record's unit D, option (c)): each request's
/// key, with when it was asked on the boot clock, in a fixed ring of [`CARRIES`]. A key is a 64-bit FNV-1a hash of the
/// request's address, in canonical form, or of its name, in lower case without a trailing dot, with its port: the ring
/// holds no name or address, and allocates nothing after it is made. Two requests whose keys meet tie more, never
/// less, and a chained app that crafted such a name could have asked the tool for the address itself. Only Datapavan's own facts: what it asked the tool for itself, never what an app or the tool sends. A flow of
/// the chained tool that one matches at its birth is what the tool opened directly for a chained app: "Now" shows it as
/// the tool's own, and the tool's own choice keeps its records out of the log. Entries are not used up: a dual-stack
/// dial or a retry opens two flows for one request. A leaf lock of its own (`Shared::carried`), taken alone; never
/// shown, never in a dump, not handed over; cleared only when the chain goes off or its tool changes (audit-D m4).
pub(super) struct Carried {
    asked: Vec<(u64, Option<Duration>)>,
    next: usize,
}

impl Default for Carried {
    fn default() -> Self {
        Self {
            asked: vec![(0, None); CARRIES],
            next: 0,
        }
    }
}

impl Carried {
    /// The key of a destination at `port`: its address's, canonical, or else its name's, told apart by a first byte.
    #[inline(never)]
    pub(super) fn key(address: Option<IpAddr>, name: &str, port: u16) -> u64 {
        let step =
            |hash: u64, byte: u8| (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        let mut hash = 0xcbf2_9ce4_8422_2325;
        match address.map(|address| address.to_canonical()) {
            Some(IpAddr::V4(address)) => {
                hash = address.octets().into_iter().fold(step(hash, 4), step);
            }
            Some(IpAddr::V6(address)) => {
                hash = address.octets().into_iter().fold(step(hash, 6), step);
            }
            None => {
                let name = name.trim_end_matches('.').bytes();
                hash = name.fold(step(hash, 0), |hash, byte| {
                    step(hash, byte.to_ascii_lowercase())
                });
            }
        }
        port.to_be_bytes().into_iter().fold(hash, step)
    }

    /// Whether a request of `key` was made within [`CARRIED`] before `now`.
    fn holds(&self, key: u64, now: Duration) -> bool {
        self.asked.iter().any(|&(asked, at)| {
            asked == key && at.is_some_and(|at| now.saturating_sub(at) < CARRIED)
        })
    }

    /// Whether `flow` goes where the chain asked the tool to within [`CARRIED`] before `now`: by its address and port,
    /// or by the DNS name its address was given (its name by DNS, or the one beside a hello's) at the same port.
    fn ties(&self, flow: &super::Flow, now: Duration) -> bool {
        let port = flow.destination.port();
        let address = Self::key(Some(flow.destination.ip()), "", port);
        let by_dns = (flow.named_by == super::NamedBy::Dns)
            .then_some(flow.name.as_deref())
            .flatten();
        let keys = [by_dns, flow.dns_name.as_deref()]
            .map(|name| name.map_or(address, |name| Self::key(None, name, port)));
        self.asked.iter().any(|&(key, at)| {
            at.is_some_and(|at| now.saturating_sub(at) < CARRIED)
                && (key == address || keys.contains(&key))
        })
    }

    /// Forgets every request: the chain went off, or its tool changed.
    pub(super) fn clear(&mut self) {
        self.asked.fill((0, None));
    }

    /// How many requests are held, of any age.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.asked.iter().filter(|(_, at)| at.is_some()).count()
    }
}

/// The user's tool and the apps sent through it.
#[derive(Clone, Debug)]
pub struct Chain {
    /// The address of the tool's local SOCKS5 proxy.
    pub proxy: SocketAddr,
    /// The username and password the tool asks for, if the user set one.
    pub credentials: Option<Credentials>,
    /// The tool's UID: its own traffic goes directly.
    pub tool: u32,
    /// The UIDs of the apps sent through the tool, or `None` for every app but the tool.
    pub apps: Option<HashSet<u32>>,
    /// Whether the tool carries UDP (`UDP ASSOCIATE`); without it, chained apps' UDP goes nowhere.
    pub udp: bool,
    /// Whether chained flows' destinations go to the connection log. Off unless the user turns it on:
    /// such a log is evidence in a phone search (docs/VPN.md, "Data path").
    pub log_destinations: bool,
}

impl Chain {
    /// Whether `other` is the same tool reached the same way: its UID, its proxy's address and the
    /// credentials it is given. A UDP relay asked of the one is the other's too.
    pub(super) fn same_tool(&self, other: &Self) -> bool {
        self.tool == other.tool
            && self.proxy == other.proxy
            && self.credentials == other.credentials
    }
}

/// Where a new flow goes.
#[derive(Clone, Debug)]
pub(super) enum Route {
    /// Out on the network beneath, from a protected socket.
    Direct,
    /// Through the tool's proxy.
    Tool(Arc<Chain>),
    /// Through the `WireGuard` tunnel of this number (W7).
    Tunnel(u32),
    /// Nowhere: the app gets a reset or an ICMP error.
    Refused,
}

impl Shared {
    /// The chain, if one is on.
    pub(super) fn chain(&self) -> Option<Arc<Chain>> {
        lock(&self.chain).clone()
    }

    /// Where a flow of the app `uid` to `destination` goes. A stand-in address is reached only through
    /// the tool: from any other app, it can only be one left over from a chain that ended.
    pub(super) fn route(&self, uid: Option<u32>, destination: SocketAddr) -> Route {
        match self.app_route(uid) {
            Route::Direct | Route::Tunnel(_) if is_stand_in(destination.ip()) => Route::Refused,
            // "Local network directly" (W7, ADR 0035, question 8): a tunnelled app's printer or NAS.
            Route::Tunnel(t) if self.tunnels.local_directly(t, destination.ip(), self) => {
                Route::Direct
            }
            route => route,
        }
    }

    /// Whether a chain is on that sends any app through the tool: every app but the tool, or a set of
    /// apps that is not empty. Android cannot say whose an ICMP echo is (`getConnectionOwnerUid` knows
    /// only TCP and UDP), so while this holds no echo leaves directly: it could be a chained app's (ADR
    /// 0044, decision 5). A chain of no app sends every app directly, so it refuses none.
    pub(super) fn chains_any_app(&self) -> bool {
        self.chain()
            .is_some_and(|chain| chain.apps.as_ref().is_none_or(|apps| !apps.is_empty()))
    }

    /// Where the flows of the app `uid` go, to any address but a stand-in. An app sent through a tunnel
    /// goes there, whatever the chain says (each app has one route, W7); and while any app goes through a
    /// tunnel, a flow whose app Android cannot name goes through the default one, never directly (ADR 0035,
    /// question 7 as settled).
    pub(super) fn app_route(&self, uid: Option<u32>) -> Route {
        // An app the network part did not name when it last handed its routes over, one installed since (with a new UID
        // when installed again), goes where the network part answered, asked at its first flow, and nowhere until then,
        // never on a default way: directly it could be an app the user sends through a tunnel or the tool (the
        // maintainer, 2026-11-20). This holds for the chain as for the tunnels.
        if let Some(uid) = uid {
            use super::tunnels::{AppRoute, Newcomer};
            match self.tunnels.newcomer(uid) {
                Newcomer::Named => {}
                Newcomer::Unanswered => return Route::Refused,
                Newcomer::Answered(AppRoute::Tunnel(t)) => return Route::Tunnel(t),
                Newcomer::Answered(AppRoute::Direct) => return Route::Direct,
                Newcomer::Answered(AppRoute::Tool) => {
                    return self.chain().map_or(Route::Refused, Route::Tool);
                }
            }
        }
        if let Some(t) = self.tunnels.route_of(uid) {
            return Route::Tunnel(t);
        }
        let Some(chain) = self.chain() else {
            return Route::Direct;
        };
        match uid {
            Some(uid) if uid == chain.tool => Route::Direct,
            Some(uid) if chain.apps.as_ref().is_none_or(|apps| apps.contains(&uid)) => {
                Route::Tool(chain)
            }
            Some(_) => Route::Direct,
            None => Route::Refused,
        }
    }

    /// Whether the log leaves out where a flow of `uid` to `destination` went, at once and in the live view too: a
    /// chained app's flow, unless the user asked for chained destinations. The flow is still counted, with its app
    /// and bytes. The tool's own flows are not hidden: "Now" shows them for their window, and the log keeps them
    /// stripped unless the switch or the tool's own choice says otherwise (R10, the proxy record's unit D,
    /// `proxied::strip_for_log`).
    pub(super) fn hides(&self, uid: Option<u32>, destination: SocketAddr) -> bool {
        match self.route(uid, destination) {
            Route::Tool(chain) => !chain.log_destinations,
            // A tunnelled app's, as a chained app's, and the switch is the same (ADR 0035, routes).
            Route::Tunnel(_) => !self.tunnels.logs_destinations(),
            // A flow that went directly is hidden as its app is: a tunnelled app's local network, which
            // "Local network directly" sends past its tunnel, as the live view hides that app's places
            // (W7's fix round, the engine reviewer's nit 13).
            Route::Direct | Route::Refused => self.hides_app(uid),
        }
    }

    /// Whether the app `uid` goes through the tool, or a tunnel, with its destinations left out: what the live view
    /// keeps of it is its bytes, with no destination (ADR 0046, decision 6, item 5).
    pub(super) fn hides_app(&self, uid: Option<u32>) -> bool {
        match self.app_route(uid) {
            Route::Tool(chain) => !chain.log_destinations,
            Route::Tunnel(_) => !self.tunnels.logs_destinations(),
            Route::Direct | Route::Refused => false,
        }
    }

    /// The chain asks the tool for `target` (R10): noted for [`CARRIED`], so that the direct flow the tool may open for
    /// it is told from its own. Out of line, once per request through the tool ([`Shared::tool_target`]).
    #[cold]
    #[inline(never)]
    fn carry(&self, target: &Target) {
        let key = match target {
            Target::Address(at) => Carried::key(Some(at.ip()), "", at.port()),
            Target::Name(name, port) => Carried::key(None, name, *port),
        };
        let now = self.clock.since_boot();
        let mut carried = lock(&self.carried);
        let next = carried.next;
        carried.asked[next] = (key, Some(now));
        carried.next = (next + 1) % CARRIES;
    }

    /// A flow of the chained tool is born (R10, option (c)): tied, whatever the switch (audit-D M2), if it goes where the
    /// chain asked the tool to within [`CARRIED`] ([`Carried`]). A tie never hides anything live; it only keeps the
    /// flow's records out of the log under the tool's own choice. The table is let go before `held_back` is taken, with
    /// no lock of the engine's order held, before `live`. Out of line.
    #[cold]
    #[inline(never)]
    pub(super) fn tie_carried(&self, flow: &super::Flow) -> bool {
        let now = self.clock.since_boot();
        let tied = lock(&self.carried).ties(flow, now);
        if tied {
            lock(&self.held_back).tie(flow.id);
        }
        tied
    }

    /// A circumvention tool's flow `opened` sent a hello that names `name`: the chained tool's may be tied by it, and any
    /// tool's has the trackers' rule decided for the name now, out of the engine's locks. Out of line.
    #[cold]
    #[inline(never)]
    pub(super) fn tool_hello(&self, opened: &super::Opened, name: &str) {
        if self
            .chain()
            .is_some_and(|chain| opened.uid == Some(chain.tool))
        {
            self.tie_at_hello(opened, name);
        }
        self.tool_marks(None, Some((name, opened.destination.port())));
    }

    /// The chained tool's flow `opened` sent a hello that names `name` (review-D-engine major 1): tied if the chain asked
    /// the tool for that name at the flow's port within [`CARRIED`], as a DNS name its address had at its birth would
    /// have tied it. The hello is the tool's to write, so under (c) it may only take from the user's choice, as the tool's
    /// own resolver's answers already can: nothing live changes, and the records of the flow already cut and waiting,
    /// held back or gathered for the next batch, are stripped as the tie says (audit-D m9). The table is let go before
    /// `held_back` is taken, then `pending_log`, in `to_log`'s order. Out of line.
    fn tie_at_hello(&self, opened: &super::Opened, name: &str) {
        let now = self.clock.since_boot();
        let key = Carried::key(None, name, opened.destination.port());
        let tied = lock(&self.carried).holds(key, now);
        if !tied {
            return;
        }
        // Its place and end give way before the tool's own from now on (review-D-engine major 2).
        if let Some(live) = lock(&self.live).get_mut(&opened.id) {
            live.tied = true;
        }
        let mut back = lock(&self.held_back);
        let mut pending = lock(&self.pending_log);
        let keeps = self.keeps_first_hops();
        back.tie_waiting(opened.id, &keeps, &mut pending);
    }

    /// What to ask the tool for: the name behind a stand-in address, or the address itself. `None` for
    /// a stand-in the map no longer holds. Each request through the tool, a TCP connection's (`connect_through`) or a
    /// UDP peer's (`udp::PeerWay::toward`), asks this once, which notes it ([`Shared::carry`], R10).
    pub(super) fn tool_target(&self, destination: SocketAddr) -> Option<Target> {
        // DNS over TCP to the network part's own address, which Android's resolver uses when an answer was cut
        // short, goes to the resolver of chained apps (ADR 0038). Its answers are not rebuilt.
        let target = if self.is_tunnel_dns(destination.ip()) {
            Target::Address(RESOLVERS[0])
        } else if !is_stand_in(destination.ip()) {
            Target::Address(destination)
        } else {
            let name = lock(&self.stand_ins).name(destination.ip())?;
            Target::name(&name, destination.port())?
        };
        self.carry(&target);
        Some(target)
    }
}

/// A TCP connection to the tool's proxy. One on the phone's loopback, which Android never routes into
/// a VPN, needs no protection; one elsewhere (on the local network) does, or it would loop back into
/// the tunnel. A proxy that does not answer means the tool stopped: the app is told its destination
/// cannot be reached, not that it refused.
pub(super) async fn connect_proxy(
    shared: &Arc<Shared>,
    proxy: SocketAddr,
) -> io::Result<TcpStream> {
    let socket = if proxy.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if !proxy.ip().is_loopback() {
        protect(shared, socket.as_fd()).await?;
    }
    socket
        .connect(proxy)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::HostUnreachable, e))
}

/// A TCP connection to `destination` through the tool.
pub(super) async fn connect_through(
    shared: &Arc<Shared>,
    chain: &Chain,
    destination: SocketAddr,
) -> io::Result<TcpStream> {
    let target = shared
        .tool_target(destination)
        .ok_or(io::ErrorKind::ConnectionRefused)?;
    let handshake = async {
        let mut stream = connect_proxy(shared, chain.proxy).await?;
        socks5::handshake(
            &mut stream,
            chain.credentials.as_ref(),
            Command::Connect,
            &target,
        )
        .await
        .map_err(io_error)?;
        Ok(stream)
    };
    match tokio::time::timeout(shared.limits.connect_timeout, handshake).await {
        Ok(connected) => connected,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// What the app is told of a failure through the tool: a refusal as a refusal, an unreachable
/// destination as unreachable, anything else, the tool stopped among it, as unreachable too: the app
/// waits and tries again, and nothing leaves directly.
pub(super) fn io_error(error: socks5::Error) -> io::Error {
    if error.is_refused() {
        io::ErrorKind::ConnectionRefused.into()
    } else {
        io::Error::new(io::ErrorKind::HostUnreachable, error)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;
    use std::net::Ipv4Addr;

    const TOOL: u32 = 10_200;
    const CHAINED: u32 = 10_300;
    const DIRECT: u32 = 10_400;

    fn chain(apps: Option<&[u32]>) -> Chain {
        Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: TOOL,
            apps: apps.map(|a| a.iter().copied().collect()),
            udp: true,
            log_destinations: false,
        }
    }

    fn is(route: &Route, tool: bool) -> bool {
        matches!(
            (route, tool),
            (Route::Tool(_), true) | (Route::Direct, false)
        )
    }

    #[test]
    fn routes_each_app_by_the_chain() {
        let shared = shared();
        let server = SocketAddr::from(([93, 184, 216, 34], 443));
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        assert!(is(&shared.route(Some(CHAINED), server), false), "no chain");
        assert!(matches!(
            shared.route(Some(CHAINED), stand_in),
            Route::Refused
        ));

        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        assert!(is(&shared.route(Some(CHAINED), server), true));
        assert!(is(&shared.route(Some(CHAINED), stand_in), true));
        assert!(is(&shared.route(Some(DIRECT), server), false));
        assert!(is(&shared.route(Some(TOOL), server), false));
        for uid in [Some(DIRECT), Some(TOOL)] {
            assert!(matches!(shared.route(uid, stand_in), Route::Refused));
        }
        assert!(matches!(shared.route(None, server), Route::Refused));

        *lock(&shared.chain) = Some(Arc::new(chain(None)));
        assert!(is(&shared.route(Some(DIRECT), server), true), "every app");
        assert!(is(&shared.route(Some(TOOL), server), false), "but the tool");
        assert!(matches!(shared.route(None, server), Route::Refused));
    }

    /// Echo is refused while a chain sends any app through the tool, whichever app pings, since
    /// Android cannot say which one does.
    #[test]
    fn echo_is_refused_while_any_app_is_chained() {
        let shared = shared();
        assert!(!shared.chains_any_app(), "no chain");
        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        assert!(shared.chains_any_app());
        *lock(&shared.chain) = Some(Arc::new(chain(None)));
        assert!(shared.chains_any_app(), "every app but the tool");
        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[]))));
        assert!(!shared.chains_any_app(), "a chain of no app");
        *lock(&shared.chain) = None;
        assert!(!shared.chains_any_app(), "the chain off again");
    }

    #[test]
    fn asks_the_tool_for_the_name_behind_a_stand_in() {
        let shared = shared();
        let address = lock(&shared.stand_ins).address("example.com");
        let stand_in = SocketAddr::from((address, 443));
        assert_eq!(
            shared.tool_target(stand_in),
            Target::name("example.com", 443)
        );
        let forgotten = SocketAddr::from((Ipv4Addr::new(198, 19, 0, 9), 443));
        assert_eq!(shared.tool_target(forgotten), None);
        let server = SocketAddr::from(([93, 184, 216, 34], 443));
        assert_eq!(shared.tool_target(server), Some(Target::Address(server)));
        let own_dns = SocketAddr::from((super::super::Addresses::COMMON.dns4, 53));
        assert_eq!(
            shared.tool_target(own_dns),
            Some(Target::Address(RESOLVERS[0]))
        );
    }

    #[test]
    fn the_log_gets_a_chained_flow_without_its_destination() {
        use super::super::{DnsUse, Ech, Flow, NamedBy, Outcome};
        let shared = shared();
        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        let server = SocketAddr::from(([93, 184, 216, 34], 443));
        let flow = |id, uid| Flow {
            id,
            protocol: crate::packet::TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination: server,
            uid: Some(uid),
            outcome: Outcome::Opened,
            name: Some("example.com".into()),
            named_by: NamedBy::Dns,
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
        assert!(shared.record(flow(1, CHAINED)).is_some(), "still counted");
        assert!(shared.record(flow(2, DIRECT)).is_some());
        let live = lock(&shared.live);
        let chained = &live[&1];
        assert!(chained.hidden);
        assert_eq!(
            chained.flow.destination,
            SocketAddr::from(([0, 0, 0, 0], 0))
        );
        assert_eq!(chained.flow.name, None);
        assert_eq!(chained.flow.uid, Some(CHAINED));
        assert!(!live[&2].hidden);
        assert_eq!(live[&2].flow.destination, server);
        drop(live);
        // Asked for, the destinations are kept.
        let mut kept = chain(Some(&[CHAINED]));
        kept.log_destinations = true;
        *lock(&shared.chain) = Some(Arc::new(kept));
        assert!(shared.record(flow(3, CHAINED)).is_some());
        assert_eq!(lock(&shared.live)[&3].flow.destination, server);
    }

    /// A chained app's flow, whose destination stays out of the log, takes no name from its hello: not
    /// the hello's, nor a DNS name beside it (review 1 of W5's first part, names, finding 2).
    #[test]
    fn a_chained_flows_hello_names_nothing_in_the_log() {
        use super::super::{DnsUse, Ech, Flow, NamedBy, Opened, Outcome};
        let shared = shared();
        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        let flow = |id, uid| Flow {
            id,
            protocol: crate::packet::TCP,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination: SocketAddr::from(([93, 184, 216, 34], 443)),
            uid: Some(uid),
            outcome: Outcome::Opened,
            name: Some("example.com".into()),
            named_by: NamedBy::Dns,
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
        let hello = crate::tls::Hello {
            name: "other.example".into(),
            ech: false,
        };
        let server = std::net::IpAddr::from([93, 184, 216, 34]);
        let when = (std::time::Instant::now(), shared.clock.since_boot());
        lock(&shared.names).insert(server, None, "example.com", 60, when);
        for (id, uid) in [(1, CHAINED), (2, DIRECT)] {
            assert!(shared.record(flow(id, uid)).is_some());
            let opened = Opened {
                id,
                port: 443,
                destination: std::net::SocketAddr::from(([192, 0, 2, 1], 443)),
                sniffs: false,
                dns: DnsUse::None,
                uid: Some(uid),
                // As the answer that named it gave it: held an hour.
                dns_held_until: when.1 + std::time::Duration::from_hours(1),
            };
            shared.hello(opened, &hello, NamedBy::Tls);
        }
        let live = lock(&shared.live);
        let named = |id: u64| {
            let flow = &live[&id].flow;
            (flow.name.as_deref(), flow.dns_name.as_deref())
        };
        assert_eq!(named(1), (None, None));
        assert_eq!(named(2), (Some("other.example"), Some("example.com")));
        drop(live);
        // The flows kept for debug builds and tests hold a chained app's destination, and its names, as
        // they always did.
        let kept: Vec<_> = lock(&shared.flows)
            .iter()
            .map(|f| (f.name.clone(), f.dns_name.clone()))
            .collect();
        let both = (
            Some("other.example".to_owned()),
            Some("example.com".to_owned()),
        );
        assert_eq!(kept, vec![both.clone(), both]);
    }

    /// A chained app's hello moves the counter of flows of an app's own encrypted DNS as in release
    /// builds, by the live flow, whose destination is hidden, and not by the flow kept for debug builds and
    /// tests (review 2 of W5's first part, of the fixes, nit 4): a flow to a resolver's host name, renamed
    /// by its hello, stays counted.
    #[test]
    fn a_chained_flows_hello_moves_no_counter_by_the_flow_kept_for_tests() {
        use super::super::{DnsUse, Ech, Flow, NamedBy, Opened, Outcome};
        let shared = shared();
        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        let destination = SocketAddr::from(([198, 51, 100, 7], 443));
        assert!(
            shared
                .record(Flow {
                    id: 1,
                    protocol: crate::packet::TCP,
                    app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
                    destination,
                    uid: Some(CHAINED),
                    outcome: Outcome::Opened,
                    name: Some("doh.sample.example".into()),
                    named_by: NamedBy::Dns,
                    dns_name: None,
                    came_in: false,
                    ech: Ech::Absent,
                    dns: DnsUse::Encrypted,
                    resolver: Some("sample".into()),
                    network: None,
                    via: crate::engine::Via::Direct,
                    proxy: None,
                    blocked: None,
                })
                .is_some()
        );
        assert_eq!(shared.counters.snapshot()[17], 1);
        let opened = Opened {
            id: 1,
            port: 443,
            destination: std::net::SocketAddr::from(([192, 0, 2, 1], 443)),
            sniffs: false,
            dns: DnsUse::Encrypted,
            uid: Some(CHAINED),
            dns_held_until: std::time::Duration::MAX,
        };
        let hello = crate::tls::Hello {
            name: "www.example.com".into(),
            ech: false,
        };
        shared.hello(opened, &hello, NamedBy::Tls);
        assert_eq!(shared.counters.snapshot()[17], 1, "counted as in release");
        // The flow kept for tests is renamed and loses its mark, as a direct app's would.
        let kept = lock(&shared.flows);
        assert_eq!(
            (kept[0].name.as_deref(), kept[0].dns),
            (Some("www.example.com"), DnsUse::None)
        );
    }

    #[test]
    fn tells_the_app_a_refusal_or_an_unreachable_destination() {
        assert_eq!(
            io_error(socks5::Error::Reply(5)).kind(),
            io::ErrorKind::ConnectionRefused
        );
        for error in [
            socks5::Error::Reply(4),
            socks5::Error::Reply(2),
            socks5::Error::NoAcceptableMethod,
            socks5::Error::Io(io::ErrorKind::ConnectionRefused),
        ] {
            assert_eq!(io_error(error).kind(), io::ErrorKind::HostUnreachable);
        }
    }

    /// The chained tool's flows the chain asked for (R10, the proxy record's unit D, option (c)).
    mod carried {
        use super::super::super::activity::tests::{T, flow, taken, telling_at};
        use super::super::super::clock::ManualClock;
        use super::super::super::{Flow, NamedBy, Shared, TunnelSetting};
        use super::*;

        /// A server of the chained app's, which the tool reaches directly for it by its own routing rules.
        const SITE: SocketAddr =
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)), 443);

        /// The engine's state with a chain of `CHAINED` through `TOOL`, "Log where these apps connect" as `log`
        /// says, in the chain and in the tunnels' table alike, as the network part hands it to both.
        fn chained(log: bool) -> (Shared, Arc<ManualClock>) {
            let (shared, clock, _) = telling_at(T);
            switch(&shared, log);
            (shared, clock)
        }

        /// The switch turned on or off, in the chain and the tunnels' table.
        fn switch(shared: &Shared, log: bool) {
            *lock(&shared.chain) = Some(Arc::new(Chain {
                log_destinations: log,
                ..chain(Some(&[CHAINED]))
            }));
            shared.tunnels.set(&TunnelSetting {
                log_destinations: log,
                ..TunnelSetting::default()
            });
            shared.hide_chained();
        }

        /// The flow `id` of `uid` to `destination`, named `name` by DNS, or by nothing.
        fn to(id: u64, uid: u32, destination: SocketAddr, name: Option<&str>) -> Flow {
            Flow {
                destination,
                name: name.map(str::to_owned),
                named_by: if name.is_some() {
                    NamedBy::Dns
                } else {
                    NamedBy::Unknown
                },
                ..flow(id, Some(uid))
            }
        }

        /// Records `flow`, as the engine does at its birth; whether it is live.
        fn born(shared: &Shared, flow: Flow) -> bool {
            shared.record(flow).is_some()
        }

        fn tied(shared: &Shared, id: u64) -> bool {
            lock(&shared.held_back).taken_back().tied(id)
        }

        /// The user's choice to log the tool `TOOL`'s own connections, the switch off (R10), with the tools `tools`.
        fn choose_tool(shared: &Shared, tools: &[u32]) {
            let mut setting = lock(&shared.proxies).setting().clone();
            setting.tools = tools.to_vec();
            setting.logged_tools = vec![TOOL];
            shared.apply_proxies(setting);
        }

        /// The flows `ids` ended, and the records of each gathered for the next batch: whether each keeps its
        /// destination.
        fn logged(shared: &Shared, ids: &[u64]) -> Vec<Option<bool>> {
            for &id in ids {
                shared.finish(id);
            }
            shared.flush();
            let records = taken(shared);
            ids.iter()
                .map(|&id| {
                    let of: Vec<_> = records
                        .iter()
                        .filter_map(|r| match r {
                            crate::log::Record::Segment { flow, .. } if flow.id == id => Some(flow),
                            _ => None,
                        })
                        .collect();
                    let kept = of.iter().all(|f| !f.destination.ip().is_unspecified());
                    let stripped = of
                        .iter()
                        .all(|f| f.destination.ip().is_unspecified() && f.name.is_none());
                    (!of.is_empty() && (kept || stripped)).then_some(kept)
                })
                .collect()
        }

        /// The live flow `id`: whether it is hidden, and its destination.
        fn live(shared: &Shared, id: u64) -> Option<(bool, SocketAddr)> {
            lock(&shared.live)
                .get(&id)
                .map(|l| (l.hidden, l.flow.destination))
        }

        /// D-PLAN test 6, rewritten to (c), and the audit's M2: the chain asks the tool for an address, and the tool's
        /// flow there within ten seconds is tied at its birth, whatever the switch; it is never hidden live, and "Now"
        /// shows its place as the tool's own. With the switch off its record keeps no address, as any of the tool's;
        /// with the switch on it is shown and logged, as chained destinations are.
        #[test]
        fn a_carried_flow_is_tied_at_its_birth_and_shown_live() {
            for log in [false, true] {
                let (shared, clock) = chained(log);
                shared.carry(&Target::Address(SITE));
                clock.pass(2_000);
                assert!(born(&shared, to(1, TOOL, SITE, None)));
                assert!(tied(&shared, 1), "tied, the switch {log}");
                assert_eq!(live(&shared, 1), Some((false, SITE)), "not hidden");
                if let Some(bytes) = lock(&shared.live).get(&1).map(|l| Arc::clone(&l.bytes)) {
                    clock.set(T + 2_500);
                    bytes.up(&shared, 10, 50);
                }
                let snapshot = shared.now_view(T + 3_000);
                let places: Vec<_> = snapshot
                    .apps
                    .iter()
                    .filter(|a| a.uid == Some(TOOL))
                    .flat_map(|a| a.places.iter().map(|p| (p.flow.destination, p.shown_only)))
                    .collect();
                assert_eq!(places, vec![(SITE, !log)], "the switch {log}");
                shared.finish(1);
                shared.flush();
                let records: Vec<_> = taken(&shared)
                    .into_iter()
                    .filter_map(|r| match r {
                        crate::log::Record::Segment { flow, .. } if flow.id == 1 => Some(flow),
                        _ => None,
                    })
                    .collect();
                assert!(!records.is_empty(), "the switch {log}: written");
                assert!(
                    records
                        .iter()
                        .all(|f| (f.destination == SITE) == log && f.uid == Some(TOOL)),
                    "the switch {log}: {records:?}"
                );
            }
            // The tool's own choice, the switch off: the tied flow stays out of the record, the tool's own is kept.
            let (shared, clock) = chained(false);
            choose_tool(&shared, &[TOOL]);
            shared.carry(&Target::Address(SITE));
            clock.pass(500);
            let own = SocketAddr::from(([203, 0, 113, 9], 443));
            assert!(born(&shared, to(1, TOOL, SITE, None)));
            assert!(born(&shared, to(2, TOOL, own, None)));
            assert_eq!(live(&shared, 1), Some((false, SITE)), "never hidden");
            assert_eq!(logged(&shared, &[1, 2]), vec![Some(false), Some(true)]);
        }

        /// D-PLAN test 7, rewritten to (c): at its birth, a request by name ties the tool's flow whose address
        /// Datapavan's names gave that name, at the same port, by its DNS name or the DNS name beside a hello's; not one
        /// named by its hello alone, which a hello the engine reads ties later (below), nor one at another port.
        #[test]
        fn carried_by_address_and_by_dns_name() {
            let (shared, clock) = chained(false);
            let Some(asked) = Target::name("Domestic.Example.", 443) else {
                unreachable!("a name")
            };
            shared.carry(&asked);
            shared.carry(&Target::Address(SITE));
            clock.pass(1_000);
            let other = SocketAddr::from(([192, 0, 2, 81], 443));
            assert!(born(&shared, to(1, TOOL, other, Some("domestic.example"))));
            let renamed = Flow {
                name: Some("cover.example".into()),
                named_by: NamedBy::Tls,
                dns_name: Some("domestic.example.".into()),
                ..to(2, TOOL, other, None)
            };
            assert!(born(&shared, renamed));
            let by_hello = Flow {
                name: Some("domestic.example".into()),
                named_by: NamedBy::Tls,
                ..to(3, TOOL, other, None)
            };
            assert!(born(&shared, by_hello));
            let port_80 = SocketAddr::from(([192, 0, 2, 81], 80));
            assert!(born(
                &shared,
                to(4, TOOL, port_80, Some("domestic.example"))
            ));
            let mapped = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 80).to_ipv6_mapped(), 443));
            assert!(born(&shared, to(5, TOOL, mapped, None)));
            let tied: Vec<bool> = (1..=5).map(|id| tied(&shared, id)).collect();
            assert_eq!(tied, vec![true, true, false, false, true]);
            // Under the tool's own choice: the tied flows stay out of the record, the others are kept as the tool's own.
            choose_tool(&shared, &[TOOL]);
            assert_eq!(
                logged(&shared, &[1, 2, 3, 4, 5]),
                vec![
                    Some(false),
                    Some(false),
                    Some(true),
                    Some(true),
                    Some(false)
                ]
            );
        }

        /// Review-D-engine major 1: the chained tool's flow whose hello names what the chain asked the tool for, by name
        /// at the flow's port, is tied at the hello, and its records already cut and waiting are stripped under the tool's
        /// choice; nothing live changes, and the hello names the flow as any does. A hello naming anything else, or the
        /// name at another port, ties nothing; nor does another app's hello.
        #[test]
        fn a_hello_naming_a_chained_request_ties_its_flow_and_strips_what_waits() {
            use super::super::super::{DnsUse, Opened};
            let (shared, clock) = chained(false);
            choose_tool(&shared, &[TOOL]);
            let Some(asked) = Target::name("news.domestic.example", 443) else {
                unreachable!("a name")
            };
            shared.carry(&asked);
            clock.pass(500);
            let at = |last: u8, port: u16| SocketAddr::from(([192, 0, 2, last], port));
            let flows = [
                (1, TOOL, at(81, 443), "News.Domestic.Example."),
                (2, TOOL, at(82, 443), "elsewhere.example"),
                (3, TOOL, at(83, 8443), "news.domestic.example"),
                (4, DIRECT, at(84, 443), "news.domestic.example"),
            ];
            for &(id, uid, destination, _) in &flows {
                assert!(born(&shared, to(id, uid, destination, None)));
                assert!(!tied(&shared, id), "{id}: nothing ties it at its birth");
            }
            // A segment of each, cut now, waits for the next batch, kept whole under the choice.
            for &(id, ..) in &flows {
                let bytes = lock(&shared.live).get(&id).map(|l| Arc::clone(&l.bytes));
                if let Some(bytes) = bytes {
                    clock.set(T + 1_000 + id);
                    bytes.up(&shared, 10, 50);
                }
            }
            shared.flush();
            let waiting = |id: u64| -> Vec<Flow> {
                lock(&shared.pending_log)
                    .iter()
                    .filter_map(|r| match r {
                        crate::log::Record::Segment { flow, .. } if flow.id == id => {
                            Some(flow.clone())
                        }
                        _ => None,
                    })
                    .collect()
            };
            assert!(
                flows.iter().all(|&(id, _, destination, _)| waiting(id)
                    .iter()
                    .any(|f| f.destination == destination)),
                "kept whole before the hello"
            );
            for &(id, uid, destination, name) in &flows {
                let opened = Opened {
                    id,
                    port: destination.port(),
                    destination,
                    sniffs: false,
                    dns: DnsUse::None,
                    uid: Some(uid),
                    dns_held_until: Duration::ZERO,
                };
                let hello = crate::tls::Hello {
                    name: name.into(),
                    ech: false,
                };
                shared.hello(opened, &hello, NamedBy::Tls);
            }
            let tied: Vec<bool> = flows.iter().map(|&(id, ..)| tied(&shared, id)).collect();
            assert_eq!(tied, vec![true, false, false, false]);
            assert!(
                lock(&shared.live).get(&1).is_some_and(|l| l.tied),
                "its place gives way before the tool's own from now on"
            );
            let stripped = waiting(1);
            assert!(
                !stripped.is_empty()
                    && stripped
                        .iter()
                        .all(|f| f.destination.ip().is_unspecified() && f.name.is_none()),
                "{stripped:?}"
            );
            for &(id, _, destination, _) in &flows[1..] {
                assert!(
                    waiting(id).iter().all(|f| f.destination == destination),
                    "{id}"
                );
            }
            let named = lock(&shared.live)
                .get(&1)
                .map(|l| (l.hidden, l.flow.destination, l.flow.name.clone()));
            assert_eq!(
                named,
                Some((false, at(81, 443), Some("news.domestic.example".to_owned()))),
                "nothing live changes"
            );
            taken(&shared);
            assert_eq!(
                logged(&shared, &[1, 2, 3, 4]),
                vec![Some(false), Some(true), Some(true), Some(true)]
            );
        }

        /// D-PLAN test 8: a request ties the tool's flows for ten seconds on the boot clock, and no longer.
        #[test]
        fn a_carried_match_ends_after_ten_seconds() {
            let (shared, clock) = chained(false);
            shared.carry(&Target::Address(SITE));
            clock.pass(9_999);
            assert!(born(&shared, to(1, TOOL, SITE, None)));
            assert!(tied(&shared, 1), "within ten seconds");
            assert!(born(&shared, to(2, TOOL, SITE, None)));
            assert!(tied(&shared, 2), "not used up");
            clock.pass(1_001);
            assert!(born(&shared, to(3, TOOL, SITE, None)));
            assert!(!tied(&shared, 3), "eleven seconds after: the tool's own");
        }

        /// D-PLAN test 9, rewritten to (c): a tie never hides anything live. A chained app that asks the tool for the
        /// tool's own server's address, while a server flow there is open, makes the tool's next flow there tied, and it
        /// stays shown in full, as the first is.
        #[test]
        fn a_tie_never_hides_anything_live() {
            let (shared, clock) = chained(false);
            let server = SocketAddr::from(([203, 0, 113, 9], 443));
            assert!(born(
                &shared,
                to(1, TOOL, server, Some("server.tool.example"))
            ));
            shared.carry(&Target::Address(server));
            clock.pass(500);
            assert!(born(
                &shared,
                to(2, TOOL, server, Some("server.tool.example"))
            ));
            assert!(tied(&shared, 2) && !tied(&shared, 1));
            for id in [1, 2] {
                assert_eq!(live(&shared, id), Some((false, server)), "{id}");
            }
            for (id, bytes) in [1, 2].map(|id| {
                (
                    id,
                    lock(&shared.live).get(&id).map(|l| Arc::clone(&l.bytes)),
                )
            }) {
                if let Some(bytes) = bytes {
                    clock.set(T + 1_000 + id);
                    bytes.up(&shared, 10, 50);
                }
            }
            let snapshot = shared.now_view(T + 2_000);
            let names: Vec<_> = snapshot
                .apps
                .iter()
                .filter(|a| a.uid == Some(TOOL))
                .flat_map(|a| {
                    a.places
                        .iter()
                        .map(|p| (p.flow.destination, p.flow.name.clone()))
                })
                .collect();
            assert_eq!(
                names,
                vec![(server, Some("server.tool.example".to_owned()))]
            );
        }

        /// D-PLAN test 10: only the chained tool's flows are tied: an unchained tool's, another app's, and any flow with
        /// no chain, to the address the chain asked for, are not.
        #[test]
        fn only_the_chained_tools_flows_are_carried() {
            let (shared, clock) = chained(false);
            let mut setting = lock(&shared.proxies).setting().clone();
            setting.tools = vec![TOOL, DIRECT];
            shared.apply_proxies(setting);
            shared.carry(&Target::Address(SITE));
            clock.pass(500);
            assert!(born(&shared, to(1, DIRECT, SITE, None)));
            assert!(born(&shared, to(2, DIRECT + 1, SITE, None)));
            *lock(&shared.chain) = None;
            assert!(born(&shared, to(3, TOOL, SITE, None)));
            assert!(
                (1..=3).all(|id| !tied(&shared, id)),
                "an unchained tool's, another app's, none without a chain"
            );
            // Under the choice of `TOOL`, and of `DIRECT` too: none is tied, so each is kept, the tools' as their own.
            let mut setting = lock(&shared.proxies).setting().clone();
            setting.logged_tools = vec![TOOL, DIRECT];
            shared.apply_proxies(setting);
            assert_eq!(logged(&shared, &[1, 2, 3]), vec![Some(true); 3]);
        }

        /// The audit's M2: a flow tied while the switch was on stays tied once it is turned off, so that under the
        /// tool's own choice its next records keep no destination, while "Now" still shows it, with no window.
        #[test]
        fn a_flow_tied_with_the_switch_on_stays_out_of_the_record_after_it() {
            let (shared, clock) = chained(true);
            shared.carry(&Target::Address(SITE));
            clock.pass(500);
            assert!(born(&shared, to(1, TOOL, SITE, None)));
            assert!(tied(&shared, 1), "tied whatever the switch");
            let bytes = lock(&shared.live).get(&1).map(|l| Arc::clone(&l.bytes));
            if let Some(bytes) = &bytes {
                clock.set(T + 1_000);
                bytes.up(&shared, 10, 50);
            }
            shared.flush();
            assert!(
                taken(&shared).iter().any(|r| matches!(
                    r,
                    crate::log::Record::Segment { flow, .. } if flow.id == 1 && flow.destination == SITE
                )),
                "logged in full while the switch is on"
            );
            switch(&shared, false);
            choose_tool(&shared, &[TOOL]);
            if let Some(bytes) = &bytes {
                clock.set(T + 2_000);
                bytes.up(&shared, 10, 50);
            }
            let snapshot = shared.now_view(T + 2_500);
            let places: Vec<_> = snapshot
                .apps
                .iter()
                .filter(|a| a.uid == Some(TOOL))
                .flat_map(|a| a.places.iter().map(|p| (p.flow.destination, p.shown_only)))
                .collect();
            assert_eq!(
                places,
                vec![(SITE, false)],
                "shown, with no window under the choice"
            );
            assert_eq!(logged(&shared, &[1]), vec![Some(false)], "the next batch");
        }

        /// The audit's m4: the table of what the chain asked goes when the chain goes off or its tool changes, not at
        /// each chain set anew with the same tool, as every change of an app's package sets it.
        #[test]
        fn the_table_is_cleared_only_when_the_chain_goes_off_or_its_tool_changes() {
            let (shared, _) = chained(false);
            let engine = crate::engine::Engine {
                shared: Arc::new(shared),
                stop: tokio::sync::watch::channel(false).0,
                network: tokio::sync::watch::channel(0).0,
                swaps: tokio::sync::mpsc::unbounded_channel().0,
                thread: None,
            };
            let held = |engine: &crate::engine::Engine| lock(&engine.shared.carried).held();
            engine.chain(Some(chain(Some(&[CHAINED]))));
            engine.shared.carry(&Target::Address(SITE));
            engine.chain(Some(Chain {
                log_destinations: true,
                ..chain(Some(&[CHAINED, DIRECT]))
            }));
            assert_eq!(held(&engine), 1, "the same tool, other apps, the switch on");
            engine.chain(Some(Chain {
                tool: TOOL + 1,
                ..chain(Some(&[CHAINED]))
            }));
            assert_eq!(held(&engine), 0, "another tool");
            engine.shared.carry(&Target::Address(SITE));
            engine.chain(Some(Chain {
                proxy: SocketAddr::from(([127, 0, 0, 1], 1_080)),
                tool: TOOL + 1,
                ..chain(Some(&[CHAINED]))
            }));
            assert_eq!(held(&engine), 0, "the tool reached another way");
            engine.shared.carry(&Target::Address(SITE));
            engine.chain(None);
            assert_eq!(held(&engine), 0, "the chain off");
        }

        /// The audit's m5: the table holds at most 256 requests, the oldest forgotten first, and a flow the tool opens
        /// for a forgotten one is the tool's own; the tied flows are at most 4,096, the oldest forgotten first.
        #[test]
        fn the_table_and_the_tied_flows_are_bounded() {
            let (shared, clock) = chained(false);
            let at = |n: u16| SocketAddr::from(([192, 0, 2, 90], 1_000 + n));
            for n in 0..=u16::try_from(CARRIES).unwrap_or(u16::MAX) {
                shared.carry(&Target::Address(at(n)));
            }
            assert_eq!(lock(&shared.carried).held(), CARRIES);
            clock.pass(100);
            assert!(born(&shared, to(1, TOOL, at(0), None)));
            assert!(born(&shared, to(2, TOOL, at(1), None)));
            assert!(!tied(&shared, 1) && tied(&shared, 2), "the oldest went");
            let mut held = super::super::super::proxied::HeldBack::default();
            for id in 0..=4_096 {
                held.tie(id);
            }
            let tied = held.taken_back();
            assert!(!tied.tied(0) && tied.tied(1) && tied.tied(4_096));
            // Past the bound an ended flow goes first: the open one stays.
            let mut held = super::super::super::proxied::HeldBack::default();
            held.tie(0);
            for id in 1..=4_097 {
                held.tie(id);
                held.tied_ended(id);
            }
            let tied = held.taken_back();
            assert!(
                tied.tied(0) && !tied.tied(1) && !tied.tied(2) && tied.tied(3) && tied.tied(4_097)
            );
        }

        /// Review-D-engine minor 1: a long-lived tied flow keeps its tie while thousands of others are tied and end, as
        /// each of theirs is forgotten once its last record leaves for the log; under the tool's choice its next record
        /// stays stripped.
        #[test]
        fn a_long_lived_tied_flow_keeps_its_tie_past_thousands_of_others() {
            let (shared, clock) = chained(false);
            choose_tool(&shared, &[TOOL]);
            shared.carry(&Target::Address(SITE));
            clock.pass(100);
            assert!(born(&shared, to(1, TOOL, SITE, None)));
            let mut id = 10;
            for round in 0..9u16 {
                for n in 0..512u16 {
                    let site = SocketAddr::from(([192, 0, 2, 90], 1_000 + n));
                    shared.carry(&Target::Address(site));
                    assert!(born(&shared, to(id, TOOL, site, None)));
                    shared.finish(id);
                    id += 1;
                }
                clock.pass(u64::from(round) + 1);
                shared.flush();
                let _ = shared.take_log();
            }
            assert!(id > 4_096 + 10);
            assert!(tied(&shared, 1), "still tied");
            assert!(
                lock(&shared.held_back).taken_back().tied_count() < 64,
                "the others forgotten as they were logged"
            );
            // Past the bound with none logged yet, those that ended give way first.
            for n in 0..4_100u16 {
                let site = SocketAddr::from(([192, 0, 2, 91], 1_000 + n % 512));
                shared.carry(&Target::Address(site));
                assert!(born(&shared, to(id, TOOL, site, None)));
                shared.finish(id);
                id += 1;
            }
            assert!(tied(&shared, 1), "still tied past the bound");
            assert_eq!(logged(&shared, &[1]), vec![Some(false)]);
        }
    }
}
