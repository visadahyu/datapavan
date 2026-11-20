//! Apps' built-in proxies named (W8, part 2a; ADR 0052): a proxy the app's own bytes declare, read from the
//! connection, which then names the flow by the destination the app asked the proxy for; and a messenger's proxy
//! inferred from where and how it connects, named only when, in the same window, the app made no direct
//! connection to its maker's own network (substitution).
//!
//! What is read: the first bytes the app sends on a TCP flow that went directly, never on the user's tool's
//! own flows nor on a chained or tunnelled app's, which are the tool's (ADR 0046, decision 3). What is kept: the
//! proxy's kind, the destination asked for, whether Android's proxy setting names the proxy, whether a password
//! crossed the network unencrypted, the proxy's own name and its network's organisation, and for an inferred
//! proxy whether its address is outside the maker's network and the cover name its hello sent, which never names
//! the flow. Never a credential: `crate::proxies` skips them unread, and the bytes they passed through are zeroed
//! when dropped (`Sniff`). An app's own proxy is circumvention, as chaining is: its address and the destination
//! asked for are kept only while "Log where these apps connect" is on; otherwise its flows keep the kind alone.

use super::{Counters, Flow, NamedBy, Opened, Shared, lock};
use crate::messengers::{Family, Role};
use crate::proxies::{self, Asked, Declared, Kind, Request};
use crate::tls::{self, Hello, ServerName};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long after a messenger's last direct connection to its maker's network a connection elsewhere is not
/// named its proxy: the live view's shortest window. While one is open, none is.
pub(super) const SUBSTITUTION: Duration = Duration::from_mins(10);

/// The most messenger apps whose direct connections are remembered, and the most of their flows open at once.
const MESSENGER_APPS: usize = 64;
const OPEN_DIRECT: usize = 4096;

/// A flow's proxy (ADR 0052).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxied {
    /// SOCKS5, SOCKS4, an HTTP proxy, or a messenger's.
    pub kind: Kind,
    /// Whether Android's proxy setting, which every app that honours it shares, names this proxy.
    pub setting: bool,
    /// Whether a password for it crossed the network unencrypted (never the password).
    pub password: bool,
    /// For an inferred proxy: whether its address is outside the maker's own network (Telegram's published
    /// ranges, Meta's networks).
    pub outside_maker: bool,
    /// Where the app asked the proxy to go, and the port: a declared proxy's, while its destination is kept.
    pub asked: Option<(Asked, u16)>,
    /// The proxy's own name, the DNS name its address had, while its destination is kept.
    pub proxy_name: Option<String>,
    /// The organisation behind the proxy's network, from the organisation table, while it is kept.
    pub organisation: Option<String>,
    /// For a hello an inferred proxy sent with a name no DNS answer tied to its address: that name, a cover,
    /// which names nothing, while the destination is kept.
    pub cover: Option<String>,
}

impl Proxied {
    /// What a flow whose destination stays out keeps of its proxy: its kind and the facts that name nothing.
    #[must_use]
    pub fn without_destination(&self) -> Self {
        Self {
            asked: None,
            proxy_name: None,
            organisation: None,
            cover: None,
            ..self.clone()
        }
    }
}

/// What Watch tells the engine for the inference and the declared proxies: the messengers' apps, by UID, and
/// the proxies Android's setting names, by host (a name or an address as text) and port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxySetting {
    /// Each messenger's apps, by UID.
    pub messengers: Vec<(Family, u32)>,
    /// The proxies Android's setting names, by host and port.
    pub android: Vec<(String, u16)>,
}

/// A messenger app's direct connections to its maker's network: those open, and when the last one ended.
#[derive(Default)]
struct Direct {
    open: HashSet<u64>,
    last: Option<Instant>,
}

/// The engine's state of the inference.
#[derive(Default)]
pub(super) struct State {
    setting: ProxySetting,
    families: HashMap<u32, Family>,
    direct: HashMap<u32, Direct>,
    /// The open flows named an inferred proxy, by flow, with their app: a direct connection that opens takes
    /// their names back.
    inferred: HashMap<u64, u32>,
}

/// The shape of a messenger's first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shape {
    /// Telegram's obfuscated transport's header.
    Obfuscated,
    /// `WhatsApp`'s clear header.
    WhatsApp,
}

impl State {
    /// What Watch told last.
    pub(super) fn setting(&self) -> &ProxySetting {
        &self.setting
    }
}

impl Shared {
    /// Sets what Watch tells for the proxies ([`ProxySetting`]); the open flows keep how they were named.
    pub(super) fn set_proxies(&self, setting: ProxySetting) {
        let mut state = lock(&self.proxies);
        state.families = setting
            .messengers
            .iter()
            .map(|&(f, uid)| (uid, f))
            .collect();
        state.setting = setting;
    }

    /// The messenger an app is, if Watch named it one.
    pub(super) fn family(&self, uid: Option<u32>) -> Option<Family> {
        uid.and_then(|uid| lock(&self.proxies).families.get(&uid).copied())
    }

    /// Whether an app's own proxies keep their address and the destination asked for: "Log where these apps
    /// connect", which Watch hands with every route ([`super::TunnelSetting::log_destinations`]), off until it
    /// is told.
    pub(super) fn logs_own_proxies(&self) -> bool {
        self.tunnels.logs_destinations()
    }

    /// Whether `address` is in the maker's own network, for the messenger `family`: `Some(true)` or
    /// `Some(false)` where Watch can tell, by Telegram's ranges, or by the organisation table and the owners'
    /// table, or by a DNS name of the maker's (`dns_name`); `None` where it cannot.
    fn in_makers_network(
        &self,
        family: Family,
        address: IpAddr,
        dns_name: Option<&str>,
    ) -> Option<bool> {
        match family {
            Family::Telegram => Some(self.messengers.is_telegrams(address)),
            Family::Signal => None,
            Family::WhatsApp => {
                if dns_name.is_some_and(|n| self.messengers.role(family, n) == Some(Role::Own)) {
                    return Some(true);
                }
                // An address of the user's own network is no company's network: a proxy on it is outside Meta's.
                if is_local(address) {
                    return Some(false);
                }
                let asn = self.organisations.as_ref()?.lookup(address)?.asn;
                Some(
                    self.owners.of(asn).is_some_and(|owner| {
                        Some(owner.entity.as_str()) == family.network_entity()
                    }),
                )
            }
        }
    }

    /// A TCP flow opened directly (`tcp::open`): a messenger's connection to its maker's own network is noted
    /// for substitution, and its open flows named an inferred proxy lose that name.
    pub(super) fn proxies_opened(&self, opened: &Opened, dns_name: Option<&str>) {
        let (Some(uid), Some(family)) = (opened.uid, self.family(opened.uid)) else {
            return;
        };
        if self.in_makers_network(family, opened.destination.ip(), dns_name) == Some(true)
            || dns_name.is_some_and(|n| self.messengers.role(family, n) == Some(Role::Own))
        {
            self.went_directly(uid, opened.id);
        }
    }

    /// The messenger `uid` connected to its maker directly, on the flow `id`.
    fn went_directly(&self, uid: u32, id: u64) {
        let taken_back: Vec<u64> = {
            let mut state = lock(&self.proxies);
            if !state.direct.contains_key(&uid) && state.direct.len() >= MESSENGER_APPS {
                let oldest = state
                    .direct
                    .iter()
                    .filter(|(_, d)| d.open.is_empty())
                    .min_by_key(|(_, d)| d.last)
                    .map(|(&u, _)| u);
                if let Some(oldest) = oldest {
                    state.direct.remove(&oldest);
                }
            }
            let open: usize = state.direct.values().map(|d| d.open.len()).sum();
            let direct = state.direct.entry(uid).or_default();
            if open < OPEN_DIRECT {
                direct.open.insert(id);
            }
            direct.last = Some(Instant::now());
            let ids: Vec<u64> = state
                .inferred
                .iter()
                .filter(|&(_, &u)| u == uid)
                .map(|(&id, _)| id)
                .collect();
            for id in &ids {
                state.inferred.remove(id);
            }
            ids
        };
        for id in taken_back {
            Counters::add(&self.counters.proxies_taken_back, 1);
            self.change_flow(id, |flow| {
                if flow.proxy.as_ref().is_some_and(|p| !p.kind.declared()) {
                    flow.proxy = None;
                }
            });
        }
    }

    /// A flow ended: a direct connection's end starts the window of substitution.
    pub(super) fn proxies_ended(&self, id: u64) {
        let mut state = lock(&self.proxies);
        state.inferred.remove(&id);
        for direct in state.direct.values_mut() {
            if direct.open.remove(&id) {
                direct.last = Some(Instant::now());
            }
        }
    }

    /// Every flow ended, as when the engine stops.
    pub(super) fn proxies_all_ended(&self) {
        let mut state = lock(&self.proxies);
        state.inferred.clear();
        let now = Instant::now();
        for direct in state.direct.values_mut() {
            if !direct.open.is_empty() {
                direct.open.clear();
                direct.last = Some(now);
            }
        }
    }

    /// Whether the messenger `uid` connected to its maker directly within the window, or does now.
    fn went_directly_lately(&self, uid: u32) -> bool {
        lock(&self.proxies).direct.get(&uid).is_some_and(|d| {
            !d.open.is_empty() || d.last.is_some_and(|last| last.elapsed() < SUBSTITUTION)
        })
    }

    /// The app's bytes declared a proxy request: the flow is named by the destination asked for, its proxy kept
    /// beside it, or only the proxy's kind while "Log where these apps connect" is off.
    pub(super) fn declared(&self, opened: &Opened, request: &Request) {
        self.log_now();
        Counters::add(&self.counters.proxies_declared, 1);
        if request.password {
            Counters::add(&self.counters.proxy_passwords, 1);
        }
        let destination = opened.destination;
        let current = self.flow_of(opened.id);
        let proxy_name = current
            .as_ref()
            .filter(|f| f.named_by == NamedBy::Dns)
            .and_then(|f| f.name.clone());
        let setting = {
            let state = lock(&self.proxies);
            state.setting.android.iter().any(|(host, port)| {
                *port == destination.port()
                    && (host.parse::<IpAddr>().ok() == Some(destination.ip())
                        || proxy_name
                            .as_deref()
                            .is_some_and(|n| n.eq_ignore_ascii_case(host.trim_end_matches('.'))))
            })
        };
        let organisation = self.organisation(destination.ip());
        // The destination asked for names the flow: a name as it is, an address by the DNS answer it was
        // given for this app, if one is held, else by itself, which the screens show.
        let (name, named_by) = match &request.asked {
            Asked::Name(name) => (Some(name.clone()), NamedBy::Proxy),
            Asked::Address(address) => {
                match lock(&self.names).get(*address, opened.uid, Instant::now()) {
                    Some(name) => (Some(name.to_owned()), NamedBy::Proxy),
                    None => (None, NamedBy::Unknown),
                }
            }
        };
        let proxied = Proxied {
            kind: request.kind,
            setting,
            password: request.password,
            outside_maker: false,
            asked: Some((request.asked.clone(), request.port)),
            proxy_name,
            organisation: organisation.as_ref().map(|(_, n)| n.clone()),
            cover: None,
        };
        let network = organisation.map(|(network, _)| network);
        self.name_proxied(opened, current.as_ref(), |flow| {
            flow.name.clone_from(&name);
            flow.named_by = named_by;
            flow.dns_name = None;
            flow.network = network;
            flow.proxy = Some(Box::new(proxied.clone()));
        });
    }

    /// A messenger's first bytes had its proxy's shape, on a flow to an address outside its maker's network.
    pub(super) fn shaped(&self, opened: &Opened, shape: Shape) {
        let Some(family) = self.family(opened.uid).filter(|_| opened.sniffs) else {
            return;
        };
        let dns_name = self.dns_name_of(opened.id);
        let outside = self.in_makers_network(family, opened.destination.ip(), dns_name.as_deref())
            == Some(false);
        let fits = match (family, shape) {
            (Family::Telegram, Shape::Obfuscated) | (Family::WhatsApp, Shape::WhatsApp) => outside,
            _ => false,
        };
        if fits {
            self.infer(opened, family, None);
        }
    }

    /// A TLS hello read on a flow, outside a declared proxy's tunnel: for a messenger's flow, first whether it is
    /// its proxy's, and whether its name may name the flow. A Telegram or `WhatsApp` hello whose name no DNS answer
    /// Watch passed tied to an address outside the maker's network is a cover: it never names the flow
    /// ("Telegram → google.com" must not appear), and the flow is a candidate for the messenger's proxy. A Signal
    /// hello is decided by its name: Signal's own, its fronts and the third parties it reaches are not a proxy.
    pub(super) fn hello_read(&self, opened: Opened, hello: &Hello) {
        let Some(family) = self.family(opened.uid).filter(|_| opened.sniffs) else {
            return self.hello(opened, hello, NamedBy::Tls);
        };
        let address = opened.destination.ip();
        match family {
            Family::Telegram | Family::WhatsApp => {
                let dns_name = self.dns_name_of(opened.id);
                let outside =
                    self.in_makers_network(family, address, dns_name.as_deref()) == Some(false);
                let tied = !hello.name.is_empty()
                    && lock(&self.names)
                        .get(address, opened.uid, Instant::now())
                        .is_some_and(|n| {
                            n.trim_end_matches('.')
                                .eq_ignore_ascii_case(hello.name.trim_end_matches('.'))
                        });
                if outside && !tied {
                    Counters::add(&self.counters.covers_kept_out, 1);
                    let cover = (!hello.name.is_empty()).then(|| hello.name.clone());
                    self.infer(&opened, family, cover);
                    return;
                }
                self.hello(opened, hello, NamedBy::Tls);
            }
            Family::Signal => {
                let role = self.messengers.role(family, &hello.name);
                self.hello(opened, hello, NamedBy::Tls);
                match role {
                    Some(Role::Own) => {
                        if let Some(uid) = opened.uid {
                            self.went_directly(uid, opened.id);
                        }
                    }
                    // Signal's own circumvention, and the third parties it reaches itself, are no proxy.
                    Some(Role::Front | Role::Other) => {}
                    None => {
                        if !hello.name.is_empty() {
                            self.infer(&opened, family, None);
                        }
                    }
                }
            }
        }
    }

    /// Names the flow `opened` the messenger `family`'s proxy, inferred, unless the app connected to its maker
    /// directly in the window (substitution).
    fn infer(&self, opened: &Opened, family: Family, cover: Option<String>) {
        let Some(uid) = opened.uid else {
            return;
        };
        self.log_now();
        if self.went_directly_lately(uid) {
            Counters::add(&self.counters.proxies_substituted, 1);
            return;
        }
        Counters::add(&self.counters.proxies_inferred, 1);
        lock(&self.proxies).inferred.insert(opened.id, uid);
        let current = self.flow_of(opened.id);
        let proxy_name = current
            .as_ref()
            .filter(|f| f.named_by == NamedBy::Dns)
            .and_then(|f| f.name.clone());
        let organisation = self.organisation(opened.destination.ip());
        let proxied = Proxied {
            kind: family.kind(),
            setting: false,
            password: false,
            outside_maker: family != Family::Signal,
            asked: None,
            proxy_name,
            organisation: organisation.map(|(_, n)| n),
            cover,
        };
        self.name_proxied(opened, current.as_ref(), |flow| {
            flow.proxy = Some(Box::new(proxied.clone()));
        });
    }

    /// Applies `name` to the flow `opened`, live and kept, and, while "Log where these apps connect" is off,
    /// leaves its destination out at once: of its open segment, of the segments that wait for their states, and
    /// of the live view, where the place its first bytes were counted under goes ([`super::logbook`]).
    fn name_proxied(&self, opened: &Opened, before: Option<&Flow>, name: impl Fn(&mut Flow)) {
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows)
                .iter_mut()
                .rev()
                .find(|f| f.id == opened.id)
        {
            name(flow);
        }
        let hide = !self.logs_own_proxies();
        let mut live = lock(&self.live);
        let Some(live) = live.get_mut(&opened.id) else {
            return;
        };
        if live.hidden {
            return;
        }
        name(&mut live.flow);
        if hide {
            live.hidden = true;
            live.flow = super::logbook::without_destination(&live.flow);
        }
        let flow = live.flow.clone();
        let mut activity = lock(&self.activity);
        for piece in &mut activity.held {
            if let super::activity::Of::Flow {
                flow: held, hidden, ..
            } = &mut piece.of
                && held.id == opened.id
                && !*hidden
            {
                *held = flow.clone();
                *hidden = hide;
            }
        }
        if let Some(before) = before {
            activity.counts.forget_place(flow.uid, before);
        }
    }

    /// Changes the flow `id`, live and kept, as a later fact changes it.
    fn change_flow(&self, id: u64, change: impl Fn(&mut Flow)) {
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
        {
            change(flow);
        }
        if let Some(live) = lock(&self.live).get_mut(&id) {
            change(&mut live.flow);
        }
    }

    /// The flow `id` as it is now: the live one, else the one kept for debug builds and tests.
    fn flow_of(&self, id: u64) -> Option<Flow> {
        lock(&self.live)
            .get(&id)
            .filter(|l| !l.hidden)
            .map(|l| l.flow.clone())
            .or_else(|| lock(&self.flows).iter().rev().find(|f| f.id == id).cloned())
    }

    /// The DNS name the flow `id` was named by, if any.
    fn dns_name_of(&self, id: u64) -> Option<String> {
        self.flow_of(id)
            .filter(|f| f.named_by == NamedBy::Dns)
            .and_then(|f| f.name)
    }
}

/// Whether `address` is on the user's own network: private, link-local, or IPv6's unique local addresses.
fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => a.is_unique_local() || a.is_unicast_link_local(),
    }
}

/// What a TCP flow's first bytes are read for, as the relay passes them on: nothing is held back.
///
/// The bytes of a proxy request, which may carry credentials, are gathered only in `request`, whose capacity is
/// set once at [`proxies::MAX_REQUEST`] so that it never moves, and which is zeroed when dropped; the relay's own
/// buffer is zeroed too (`tcp::relay`). A TLS hello is gathered apart, as before W8 (at most [`tls::MAX_HELLO`]):
/// from the stream's start, or after a declared proxy's request, from the inner stream's.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct Sniff {
    /// Whether the flow's bytes are read for a proxy at all: it went directly, and is not the user's tool's.
    proxies: bool,
    /// Whether it is a messenger's flow, read for its proxy's shape.
    messenger: bool,
    request: Option<Zeroizing<Vec<u8>>>,
    hello: Option<Vec<u8>>,
    /// Whether the hello is the inner stream's, after a declared proxy's request.
    inner: bool,
    /// Whether the start is still read for a request or a shape.
    start: bool,
}

/// What the sniff found in the bytes fed to it, for the relay to tell the engine.
pub(super) enum Found {
    Hello(Hello, bool),
    Request(Request),
    Shape(Shape),
}

impl Sniff {
    /// A sniff for a flow: `proxies` whether its bytes are read for a proxy, `messenger` whether for a
    /// messenger's.
    pub(super) fn new(proxies: bool, messenger: bool) -> Self {
        Self {
            proxies,
            messenger: proxies && messenger,
            request: None,
            hello: None,
            inner: false,
            start: true,
        }
    }

    /// Whether anything is still read.
    pub(super) fn done(&self) -> bool {
        !self.start && self.hello.is_none()
    }

    /// Reads the next bytes the app sent; what they say, in the order found.
    pub(super) fn feed(&mut self, bytes: &[u8]) -> Vec<Found> {
        let mut found = Vec::new();
        if self.start {
            self.read_start(bytes, &mut found);
        } else if let Some(hello) = self.hello.as_mut() {
            hello.extend_from_slice(
                &bytes[..bytes.len().min(tls::MAX_HELLO.saturating_sub(hello.len()))],
            );
            self.read_hello(&mut found);
        }
        found
    }

    fn read_start(&mut self, bytes: &[u8], found: &mut Vec<Found>) {
        // A stream that starts as TLS is read for its hello alone, as before W8; any other, in a buffer that
        // never moves and is zeroed, for a request and a shape.
        let first = self
            .request
            .as_ref()
            .and_then(|r| r.first().copied())
            .or_else(|| bytes.first().copied());
        if first == Some(22) || !self.proxies {
            self.start = false;
            self.hello = Some(Vec::new());
            self.inner = false;
            found.extend(self.feed(bytes));
            return;
        }
        let request = self
            .request
            .get_or_insert_with(|| Zeroizing::new(Vec::with_capacity(proxies::MAX_REQUEST)));
        let room = proxies::MAX_REQUEST - request.len();
        let used = bytes.len().min(room);
        request.extend_from_slice(&bytes[..used]);
        let declared = proxies::declared(request);
        // A messenger's shape: found, none, or not known yet.
        let shape = if self.messenger {
            match (
                proxies::whatsapp_header(request),
                proxies::obfuscated2(request),
            ) {
                (Some(true), _) => Ok(Some(Shape::WhatsApp)),
                (_, Some(true)) => Ok(Some(Shape::Obfuscated)),
                (Some(false), Some(false)) => Ok(None),
                _ => Err(()),
            }
        } else {
            Ok(None)
        };
        match (declared, shape) {
            (Declared::Request(r), _) => {
                // The inner stream's start is read for its hello, from the bytes after the request: those
                // gathered, then those of this read past the bound, if it was reached.
                if let Some(from) = r.inner {
                    let mut hello = request.get(from..).unwrap_or_default().to_vec();
                    hello.extend_from_slice(&bytes[used..]);
                    hello.truncate(tls::MAX_HELLO);
                    self.hello = Some(hello);
                    self.inner = true;
                }
                found.push(Found::Request(r));
                self.end_start();
                self.read_hello(found);
            }
            (_, Ok(Some(shape))) => {
                found.push(Found::Shape(shape));
                self.end_start();
            }
            (Declared::Not, Ok(None)) => self.end_start(),
            // More bytes are needed for one or the other; past the bound, `declared` says none.
            (Declared::Incomplete, _) | (Declared::Not, Err(())) => {
                if request.len() >= proxies::MAX_REQUEST {
                    self.end_start();
                }
            }
        }
    }

    fn end_start(&mut self) {
        self.start = false;
        self.request = None;
    }

    fn read_hello(&mut self, found: &mut Vec<Found>) {
        let Some(hello) = self.hello.as_ref() else {
            return;
        };
        match tls::server_name(hello) {
            ServerName::Found(h) => {
                found.push(Found::Hello(h, self.inner));
                self.hello = None;
            }
            ServerName::None => self.hello = None,
            ServerName::Incomplete if hello.len() >= tls::MAX_HELLO => self.hello = None,
            ServerName::Incomplete => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::activity::tests::{T, UID, taken, telling_at};
    use super::super::{DnsUse, Ech, Outcome, TCP, TunnelSetting, Via};
    use super::*;
    use crate::log::Record;
    use crate::proxies::tests::SECRET;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// The engine's state with "Log where these apps connect" as `logs` says, the organisation table's sample
    /// (93.184.216.0/24 Example Net, 157.240.0.0/16 Meta) and the owners' table.
    fn engine(logs: bool) -> Shared {
        let (mut shared, _, _) = telling_at(T);
        shared.organisations = crate::organisations::Organisations::open(Box::new(
            crate::organisations::tests::sample(),
        ))
        .ok();
        shared.owners = crate::owners::Owners::bundled();
        shared.tunnels.set(&TunnelSetting {
            log_destinations: logs,
            ..TunnelSetting::default()
        });
        shared
    }

    /// Opens a TCP flow of `uid` to `destination` as `tcp::open` does, directly, its first bytes read.
    fn open(
        shared: &Shared,
        uid: u32,
        destination: SocketAddr,
    ) -> (Opened, Arc<super::super::logbook::FlowBytes>) {
        let begun = shared.begin(destination, Some(uid));
        let by_dns = (begun.named_by == NamedBy::Dns)
            .then(|| begun.name.clone())
            .flatten();
        let (dns, resolver) = shared.dns_use(destination, by_dns.as_deref());
        let opened = Opened {
            id: begun.id,
            port: destination.port(),
            destination,
            sniffs: true,
            dns,
            uid: Some(uid),
            dns_held_until: begun.held_until,
        };
        let Some(bytes) = shared.record(Flow {
            id: begun.id,
            protocol: TCP,
            app: SocketAddr::from(([10, 1, 10, 1], 40_000)),
            destination,
            uid: Some(uid),
            outcome: Outcome::Opened,
            name: begun.name,
            named_by: begun.named_by,
            dns_name: None,
            came_in: false,
            ech: Ech::Absent,
            dns,
            resolver,
            network: begun.network,
            via: Via::Direct,
            proxy: None,
        }) else {
            unreachable!("an open flow is live")
        };
        shared.proxies_opened(&opened, by_dns.as_deref());
        (opened, bytes)
    }

    /// Feeds `reads` to a sniff of the flow `opened` and tells the engine what they say, as `tcp::relay` does,
    /// each read's bytes counted after.
    fn relay(
        shared: &Shared,
        opened: Opened,
        bytes: &super::super::logbook::FlowBytes,
        reads: &[&[u8]],
    ) {
        let messenger = shared.family(opened.uid).is_some();
        let mut sniff = Sniff::new(opened.sniffs, messenger);
        for read in reads {
            for found in sniff.feed(read) {
                match found {
                    Found::Hello(hello, true) => shared.hello(opened, &hello, NamedBy::Tls),
                    Found::Hello(hello, false) => shared.hello_read(opened, &hello),
                    Found::Request(request) => shared.declared(&opened, &request),
                    Found::Shape(shape) => shared.shaped(&opened, shape),
                }
            }
            bytes.up(shared, read.len(), read.len() + 40);
        }
    }

    fn live(shared: &Shared, id: u64) -> Flow {
        lock(&shared.live)
            .get(&id)
            .map_or_else(|| unreachable!("the flow is live"), |l| l.flow.clone())
    }

    fn learn(shared: &Shared, address: &str, name: &str) {
        let address = address
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        lock(&shared.names).insert(
            address,
            None,
            name,
            600,
            (Instant::now(), shared.clock.since_boot()),
        );
    }

    fn at(address: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((address, port))
    }

    /// RFC 1929's sub-negotiation with the synthetic secret, then a `CONNECT` for `example.com:443`.
    fn socks5_reads() -> Vec<Vec<u8>> {
        let mut auth = vec![1, 4];
        auth.extend_from_slice(b"user");
        auth.push(u8::try_from(SECRET.len()).unwrap_or(0));
        auth.extend_from_slice(SECRET);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        vec![
            vec![5, 2, 0, 2],
            auth,
            request,
            crate::tls::tests::hello("example.com", 1000),
        ]
    }

    /// Whether `haystack` holds the synthetic secret anywhere.
    fn holds_secret(haystack: &[u8]) -> bool {
        haystack.windows(SECRET.len()).any(|w| w == SECRET)
    }

    #[test]
    fn a_socks5_proxy_names_the_flow_by_the_destination_asked_for_and_nothing_keeps_its_password() {
        let shared = engine(true);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay(&shared, opened, &bytes, &reads);
        let flow = live(&shared, opened.id);
        assert_eq!(flow.name.as_deref(), Some("example.com"));
        assert_eq!(
            flow.named_by,
            NamedBy::Tls,
            "the inner hello names it, after the request"
        );
        let proxy = flow
            .proxy
            .clone()
            .unwrap_or_else(|| unreachable!("named a proxy"));
        assert_eq!(proxy.kind, Kind::Socks5);
        assert!(proxy.password && !proxy.setting && !proxy.outside_maker);
        assert_eq!(proxy.asked, Some((Asked::Name("example.com".into()), 443)));
        assert_eq!(proxy.proxy_name.as_deref(), Some("proxy.example.net"));
        // The secret is nowhere: the flow, the kept flows, the live view, the log's records.
        assert!(!format!("{flow:?}{:?}", lock(&shared.flows)).contains("hunter2"));
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 1_000));
        assert!(!holds_secret(&snapshot));
        shared.finish(opened.id);
        shared.flush();
        let records = taken(&shared);
        assert!(
            records
                .iter()
                .any(|r| matches!(r, Record::Segment { flow, .. } if flow.proxy.is_some()))
        );
        assert!(!holds_secret(&crate::log::batch(&records)));
        assert_eq!(shared.counters.snapshot()[61..63], [1, 1]);
    }

    #[test]
    fn with_the_switch_off_an_apps_own_proxy_keeps_only_its_kind() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        // The greeting's bytes are counted under the proxy's own name first, before the request names it.
        relay(
            &shared,
            opened,
            &bytes,
            &[&reads[0], &reads[1], &reads[2], &reads[3]],
        );
        let flow = live(&shared, opened.id);
        assert!(flow.destination.ip().is_unspecified() && flow.name.is_none());
        let proxy = flow
            .proxy
            .clone()
            .unwrap_or_else(|| unreachable!("its kind is kept"));
        assert_eq!((proxy.kind, proxy.password), (Kind::Socks5, true));
        assert!(
            proxy.asked.is_none() && proxy.proxy_name.is_none() && proxy.organisation.is_none()
        );
        let view = shared.now_view(T + 1_000);
        let places: Vec<_> = view.apps.iter().flat_map(|a| a.places.iter()).collect();
        assert_eq!(places.len(), 1, "{places:?}");
        assert!(places[0].flow.name.is_none() && places[0].flow.proxy.is_some());
        let snapshot = crate::snapshot::encode(&view);
        for hidden in [&b"proxy.example.net"[..], b"example.com", &[203, 0, 113, 5]] {
            assert!(
                !snapshot.windows(hidden.len()).any(|w| w == hidden),
                "{hidden:?}"
            );
        }
        shared.finish(opened.id);
        shared.flush();
        let log = crate::log::batch(&taken(&shared));
        assert!(!log.windows(11).any(|w| w == b"example.com") && !holds_secret(&log));
    }

    #[test]
    fn turning_the_switch_off_leaves_an_open_proxied_flows_destination_out() {
        let shared = engine(true);
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 3128));
        relay(
            &shared,
            opened,
            &bytes,
            &[b"CONNECT example.org:443 HTTP/1.1\r\n\r\n"],
        );
        assert_eq!(
            live(&shared, opened.id).name.as_deref(),
            Some("example.org")
        );
        shared.tunnels.set(&TunnelSetting::default());
        shared.hide_chained();
        let flow = live(&shared, opened.id);
        assert!(flow.name.is_none() && flow.proxy.is_some_and(|p| p.asked.is_none()));
        assert!(shared.now_view(T + 1_000).apps.iter().all(|a| {
            a.places
                .iter()
                .all(|p| p.flow.destination.ip().is_unspecified())
        }));
    }

    #[test]
    fn androids_proxy_setting_is_told_from_an_apps_own() {
        let shared = engine(true);
        shared.set_proxies(ProxySetting {
            messengers: Vec::new(),
            android: vec![
                ("203.0.113.5".into(), 3128),
                ("proxy.example.net".into(), 8080),
            ],
        });
        let (own, bytes) = open(&shared, UID, at([203, 0, 113, 6], 3128));
        relay(
            &shared,
            own,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        let (set, bytes) = open(&shared, UID, at([203, 0, 113, 5], 3128));
        relay(
            &shared,
            set,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        learn(&shared, "203.0.113.7", "proxy.example.net");
        let (named, bytes) = open(&shared, UID, at([203, 0, 113, 7], 8080));
        relay(
            &shared,
            named,
            &bytes,
            &[b"CONNECT example.org:443 HTTP/1.1\r\n\r\n"],
        );
        let setting = |id| live(&shared, id).proxy.map(|p| (p.kind, p.setting));
        assert_eq!(setting(own.id), Some((Kind::Forward, false)));
        assert_eq!(setting(set.id), Some((Kind::Forward, true)));
        assert_eq!(setting(named.id), Some((Kind::Connect, true)));
    }

    #[test]
    fn a_flow_not_read_for_proxies_is_named_by_its_hello_alone() {
        let shared = engine(true);
        let (mut opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        opened.sniffs = false;
        let reads = socks5_reads();
        relay(&shared, opened, &bytes, &[&reads[0], &reads[1], &reads[2]]);
        assert!(live(&shared, opened.id).proxy.is_none());
    }

    fn telegram(shared: &Shared) {
        shared.set_proxies(ProxySetting {
            messengers: vec![(Family::Telegram, UID)],
            android: Vec::new(),
        });
    }

    /// 64 bytes of an obfuscated header: random-looking, none of the excluded prefixes.
    fn obfuscated() -> Vec<u8> {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut header: Vec<u8> = (0..64)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24).to_le_bytes()[0]
            })
            .collect();
        header[0] = 0x3c;
        header
    }

    #[test]
    fn telegrams_obfuscated_start_outside_its_ranges_is_its_proxy_unless_it_went_directly() {
        let shared = engine(true);
        telegram(&shared);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        let header = obfuscated();
        relay(&shared, proxy, &bytes, &[&header[..40], &header[40..]]);
        let named = live(&shared, proxy.id)
            .proxy
            .unwrap_or_else(|| unreachable!("inferred"));
        assert_eq!((named.kind, named.outside_maker), (Kind::MtProto, true));
        assert_eq!(named.organisation.as_deref(), Some("Example Net, Inc."));
        // A direct connection to Telegram's own ranges takes the name back.
        let (direct, bytes) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, direct, &bytes, &[&header]);
        assert!(live(&shared, proxy.id).proxy.is_none(), "taken back");
        assert!(live(&shared, direct.id).proxy.is_none());
        // While it goes directly, a CDN data centre outside the ranges is not its proxy.
        let (cdn, bytes) = open(&shared, UID, at([93, 184, 216, 35], 443));
        relay(&shared, cdn, &bytes, &[&header]);
        assert!(
            live(&shared, cdn.id).proxy.is_none(),
            "a CDN data centre reached directly"
        );
        // Ten minutes after its last direct connection ended, one is again.
        shared.finish(direct.id);
        if let Some(d) = lock(&shared.proxies).direct.get_mut(&UID) {
            d.last = Instant::now().checked_sub(SUBSTITUTION + Duration::from_secs(1));
        }
        let (later, bytes) = open(&shared, UID, at([93, 184, 216, 36], 443));
        relay(&shared, later, &bytes, &[&header]);
        assert!(live(&shared, later.id).proxy.is_some());
        assert_eq!(shared.counters.snapshot()[63..66], [2, 1, 1]);
    }

    #[test]
    fn another_apps_obfuscated_start_and_telegrams_tls_are_not_read_as_its_proxy() {
        let shared = engine(true);
        let (other, bytes) = open(&shared, UID + 1, at([93, 184, 216, 34], 443));
        relay(&shared, other, &bytes, &[&obfuscated()]);
        assert!(live(&shared, other.id).proxy.is_none());
        telegram(&shared);
        // An HTTP request is no obfuscated start.
        let (http, bytes) = open(&shared, UID, at([93, 184, 216, 34], 80));
        relay(
            &shared,
            http,
            &bytes,
            &[b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"],
        );
        assert!(live(&shared, http.id).proxy.is_none());
    }

    #[test]
    fn a_fake_tls_cover_never_names_telegrams_flow() {
        let shared = engine(true);
        telegram(&shared);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        let flow = live(&shared, proxy.id);
        assert_ne!(
            flow.name.as_deref(),
            Some("www.google.com"),
            "Telegram → google.com"
        );
        let named = flow.proxy.unwrap_or_else(|| unreachable!("inferred"));
        assert_eq!(
            (named.kind, named.cover.as_deref()),
            (Kind::MtProto, Some("www.google.com"))
        );
        // A name a DNS answer tied to the address names it, and is no cover.
        learn(&shared, "93.184.216.40", "updates.example.com");
        let (tied, bytes) = open(&shared, UID, at([93, 184, 216, 40], 443));
        relay(
            &shared,
            tied,
            &bytes,
            &[&crate::tls::tests::hello("updates.example.com", 1000)],
        );
        let flow = live(&shared, tied.id);
        assert_eq!(flow.name.as_deref(), Some("updates.example.com"));
        assert!(flow.proxy.is_none());
        assert_eq!(shared.counters.snapshot()[66], 1);
    }

    fn whatsapp(shared: &Shared) {
        shared.set_proxies(ProxySetting {
            messengers: vec![(Family::WhatsApp, UID)],
            android: Vec::new(),
        });
    }

    #[test]
    fn whatsapps_clear_header_outside_metas_network_is_its_proxy() {
        let shared = engine(true);
        whatsapp(&shared);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 5222));
        relay(&shared, proxy, &bytes, &[b"WA", b"\x06\x03\x00\x00\x24"]);
        let named = live(&shared, proxy.id)
            .proxy
            .unwrap_or_else(|| unreachable!("inferred"));
        assert_eq!((named.kind, named.outside_maker), (Kind::WhatsApp, true));
        // Its media through the proxy: a name of WhatsApp's that no answer tied to this address.
        let (media, bytes) = open(&shared, UID, at([93, 184, 216, 35], 587));
        relay(
            &shared,
            media,
            &bytes,
            &[&crate::tls::tests::hello("mmg.whatsapp.net", 1000)],
        );
        let flow = live(&shared, media.id);
        assert!(flow.proxy.is_some() && flow.name.as_deref() != Some("mmg.whatsapp.net"));
        // A proxy on the local network is outside Meta's network, table or not.
        let (local, bytes) = open(&shared, UID, at([192, 168, 1, 2], 5222));
        relay(&shared, local, &bytes, &[b"WA\x06\x03"]);
        assert!(live(&shared, local.id).proxy.is_some());
        // Without the organisation table nothing tells Meta's network: nothing is inferred.
        let mut bare = engine(true);
        bare.organisations = None;
        whatsapp(&bare);
        let (unknown, bytes) = open(&bare, UID, at([93, 184, 216, 34], 5222));
        relay(&bare, unknown, &bytes, &[b"WA\x06\x03"]);
        assert!(live(&bare, unknown.id).proxy.is_none());
    }

    #[test]
    fn whatsapps_link_previews_and_backups_are_not_its_proxy() {
        let shared = engine(true);
        whatsapp(&shared);
        // Its chat directly to Meta's network.
        let (chat, bytes) = open(&shared, UID, at([157, 240, 1, 35], 443));
        relay(
            &shared,
            chat,
            &bytes,
            &[b"ED\x00\x01\x00\x00\x02\x01\x02WA\x06\x03"],
        );
        assert!(live(&shared, chat.id).proxy.is_none());
        // A link preview, and a backup, to names a DNS answer tied to their addresses.
        learn(&shared, "93.184.216.34", "news.example.com");
        let (preview, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            preview,
            &bytes,
            &[&crate::tls::tests::hello("news.example.com", 1000)],
        );
        learn(&shared, "93.184.216.35", "www.googleapis.com");
        let (backup, bytes) = open(&shared, UID, at([93, 184, 216, 35], 443));
        relay(
            &shared,
            backup,
            &bytes,
            &[&crate::tls::tests::hello("www.googleapis.com", 1000)],
        );
        // Even a name no answer tied, while its chat goes directly: substitution.
        let (untied, bytes) = open(&shared, UID, at([93, 184, 216, 36], 443));
        relay(
            &shared,
            untied,
            &bytes,
            &[&crate::tls::tests::hello("cdn.example.net", 1000)],
        );
        for id in [preview.id, backup.id, untied.id] {
            assert!(live(&shared, id).proxy.is_none(), "flow {id}");
        }
        assert_eq!(
            live(&shared, preview.id).name.as_deref(),
            Some("news.example.com")
        );
    }

    fn signal(shared: &Shared) {
        shared.set_proxies(ProxySetting {
            messengers: vec![(Family::Signal, UID)],
            android: Vec::new(),
        });
    }

    #[test]
    fn signals_proxy_is_decided_by_names_and_its_fronting_and_captcha_are_not_one() {
        let shared = engine(true);
        signal(&shared);
        // Its own circumvention through Google's network, a captcha and a payment.
        for (i, name) in ["www.google.com", "js.hcaptcha.com", "api.stripe.com"]
            .into_iter()
            .enumerate()
        {
            let (flow, bytes) = open(
                &shared,
                UID,
                at([93, 184, 216, 34 + u8::try_from(i).unwrap_or(0)], 443),
            );
            relay(
                &shared,
                flow,
                &bytes,
                &[&crate::tls::tests::hello(name, 1000)],
            );
            assert!(live(&shared, flow.id).proxy.is_none(), "{name}");
        }
        // A proxy's own domain: Signal's proxy, named by it.
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 40], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("signal-proxy.example.org", 1000)],
        );
        let flow = live(&shared, proxy.id);
        assert_eq!(flow.name.as_deref(), Some("signal-proxy.example.org"));
        let named = flow.proxy.unwrap_or_else(|| unreachable!("inferred"));
        assert_eq!((named.kind, named.outside_maker), (Kind::Signal, false));
        // Its own service directly takes it back, and no other name is its proxy while it goes so.
        let (own, bytes) = open(&shared, UID, at([93, 184, 216, 41], 443));
        relay(
            &shared,
            own,
            &bytes,
            &[&crate::tls::tests::hello("chat.signal.org", 1000)],
        );
        assert!(live(&shared, proxy.id).proxy.is_none());
        let (after, bytes) = open(&shared, UID, at([93, 184, 216, 42], 443));
        relay(
            &shared,
            after,
            &bytes,
            &[&crate::tls::tests::hello("signal-proxy.example.org", 1000)],
        );
        assert!(live(&shared, after.id).proxy.is_none());
    }

    #[test]
    fn a_proxy_request_split_across_reads_and_past_the_bound_is_read_whole() {
        let mut sniff = Sniff::new(true, false);
        let mut request = b"CONNECT example.org:443 HTTP/1.1\r\n".to_vec();
        request.extend_from_slice(b"X-Pad: ");
        request.resize(proxies::MAX_REQUEST - 100, b'a');
        request.extend_from_slice(b"\r\n\r\n");
        let hello = crate::tls::tests::hello("inner.example", 1000);
        let mut found = Vec::new();
        for chunk in request.chunks(700) {
            found.extend(sniff.feed(chunk));
        }
        found.extend(sniff.feed(&hello));
        assert!(
            matches!(&found[..], [Found::Request(_), Found::Hello(h, true)] if h.name == "inner.example")
        );
        assert!(sniff.done());
        // Past the bound with no request, nothing more is read.
        let mut long = Sniff::new(true, false);
        assert!(long.feed(&vec![b'A'; proxies::MAX_REQUEST + 10]).is_empty());
        assert!(long.done());
        // A stream that starts as TLS is read for its hello alone, as before.
        let mut tls = Sniff::new(true, true);
        assert!(
            matches!(&tls.feed(&hello)[..], [Found::Hello(h, false)] if h.name == "inner.example")
        );
        let _ = DnsUse::None;
    }
}
