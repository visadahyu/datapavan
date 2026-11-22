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
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};

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
        // An app Watch did not name when it last handed its routes over, one installed since (with a new UID when
        // installed again), goes where Watch answered, asked at its first flow, and nowhere until then, never on a
        // default way: directly it could be an app the user sends through a tunnel or the tool (the maintainer,
        // 2026-11-20). This holds for the chain as for the tunnels.
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

    /// Whether the log leaves out where a flow of `uid` to `destination` went: a chained app's flow, and the
    /// tool's own, whose destinations are the user's servers (ADR 0046, decision 3, as decided on
    /// 2026-11-19), unless the user asked for chained destinations. The flow is still counted, with its app
    /// and bytes.
    pub(super) fn hides(&self, uid: Option<u32>, destination: SocketAddr) -> bool {
        match self.route(uid, destination) {
            Route::Tool(chain) => !chain.log_destinations || self.hides_tool(uid),
            // A tunnelled app's, as a chained app's, and the switch is the same (ADR 0035, routes).
            Route::Tunnel(_) => !self.tunnels.logs_destinations() || self.hides_tool(uid),
            // A flow that went directly is hidden as its app is: a tunnelled app's local network, which
            // "Local network directly" sends past its tunnel, as the live view hides that app's places
            // (W7's fix round, the engine reviewer's nit 13).
            Route::Direct | Route::Refused => self.hides_app(uid),
        }
    }

    /// Whether the app `uid` goes through the tool with its destinations left out, or is the tool itself
    /// with them left out: what the live view keeps of it is its bytes, with no destination (ADR 0046,
    /// decision 6, item 5, and decision 3's tool row).
    pub(super) fn hides_app(&self, uid: Option<u32>) -> bool {
        match self.app_route(uid) {
            Route::Tool(chain) => !chain.log_destinations || self.hides_tool(uid),
            Route::Tunnel(_) => !self.tunnels.logs_destinations() || self.hides_tool(uid),
            Route::Direct | Route::Refused => self.hides_tool(uid),
        }
    }

    /// Whether `uid` is the user's tool and "Log where these apps connect" is off: its own flows, to its
    /// servers, then keep no destination, in the log and the live view alike.
    fn hides_tool(&self, uid: Option<u32>) -> bool {
        self.chain()
            .is_some_and(|chain| uid == Some(chain.tool) && !chain.log_destinations)
    }

    /// What to ask the tool for: the name behind a stand-in address, or the address itself. `None` for
    /// a stand-in the map no longer holds.
    pub(super) fn tool_target(&self, destination: SocketAddr) -> Option<Target> {
        // DNS over TCP to Watch's own address, which Android's resolver uses when an answer was cut
        // short, goes to the resolver of chained apps (ADR 0038). Its answers are not rebuilt.
        if self.is_tunnel_dns(destination.ip()) {
            return Some(Target::Address(RESOLVERS[0]));
        }
        if !is_stand_in(destination.ip()) {
            return Some(Target::Address(destination));
        }
        let name = lock(&self.stand_ins).name(destination.ip())?;
        Target::name(&name, destination.port())
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
}
