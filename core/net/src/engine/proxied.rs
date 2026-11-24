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
//! asked for are logged only while "Log where these apps connect" is on; otherwise the log keeps the kind alone,
//! "Now" shows the first hop, the proxy's own address and names, while the connection is open and for ten minutes
//! after it ends (`now::SHOWN`), and nothing the app sends names its flow by where it asked to go (C1).

use super::{Counters, Flow, NamedBy, Opened, Shared, lock};
use crate::messengers::{Family, Role};
use crate::proxies::{self, Asked, Declared, Kind, MAX_REPLY, Request};
use crate::tls::{self, Hello, ServerName};
use crate::trackers::NetworkSignatures;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long after a messenger's last direct connection to its maker's network a connection elsewhere is not
/// named its proxy: the live view's shortest window. While one is open, none is. It is read in time since the
/// phone started, sleep included (the fix round's S-n3): ten minutes of sleep are ten minutes. A flow named an
/// inferred proxy may be taken back by a direct connection for as long after its naming, and its records wait
/// that long before the log gets them ([`HeldBack`]).
pub(super) const SUBSTITUTION: Duration = Duration::from_mins(10);

/// The most records of inferred flows held back from the log at once, for their window of take-back: past it,
/// the oldest is written as it is (ADR 0052's accepted limits).
const HELD_BACK: usize = 1024;

/// The most inferred flows remembered for their window of take-back.
const INFERRED: usize = 4096;

/// The most messenger apps whose direct connections are remembered, and the most of their flows open at once.
const MESSENGER_APPS: usize = 64;
const OPEN_DIRECT: usize = 4096;

/// The most trackers a proxied flow keeps the marks of (the log's and the snapshot's proxy block).
pub const MAX_TRACKERS: usize = 8;

/// A flow's proxy (ADR 0052). Its facts are each a yes or a no, as the records write them: flags, not a state.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Where the app asked the proxy to go, and the port: a declared proxy's, only while "Log where these apps
    /// connect" is on, live and in the log alike (C1).
    pub asked: Option<(Asked, u16)>,
    /// The proxy's own name, the DNS name its address had: part of its first hop, which "Now" shows whatever the
    /// switch says, for its window while it is off, and the log keeps only while it is on.
    pub proxy_name: Option<String>,
    /// The organisation behind the proxy's network, from the organisation table: part of its first hop, as
    /// `proxy_name` is.
    pub organisation: Option<String>,
    /// For a hello an inferred proxy sent with a name no DNS answer tied to its address: that name, a cover,
    /// which names nothing: part of its first hop, as `proxy_name` is.
    pub cover: Option<String>,
    /// Whether the flow's own address and names were left out, as "Log where these apps connect" says (the
    /// fix round of W8 part 2a): a confirmed SOCKS or `CONNECT` proxy's flow, or an inferred one's.
    pub left_out: bool,
    /// The trackers matched on every name the flow carried before anything was left out (the address's DNS
    /// name, the hello's, the destination asked for, the address), by their εxodus ids, at most
    /// [`MAX_TRACKERS`]: kept whatever the switch says, as they name a tracker's company, never an address or a
    /// name (the fix round's S-M1).
    pub trackers: Vec<u32>,
}

impl Proxied {
    /// What a flow whose destination stays out keeps of its proxy: its kind, the facts that name nothing and
    /// its trackers' marks.
    #[must_use]
    pub fn without_destination(&self) -> Self {
        Self {
            asked: None,
            proxy_name: None,
            organisation: None,
            cover: None,
            left_out: true,
            ..self.clone()
        }
    }

    /// What a plain request's flow keeps of it while the switch is off: all but the destination asked for. Its
    /// own address and names stay, as for any flow: its request cannot be confirmed ([`proxies::confirmed`]).
    #[must_use]
    pub fn without_asked(&self) -> Self {
        Self {
            asked: None,
            ..self.clone()
        }
    }
}

/// What the network part tells the engine for the inference and the declared proxies: the messengers' apps, by UID, and
/// the proxies Android's setting names, by host (a name or an address as text) and port.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxySetting {
    /// Each messenger's apps, by UID.
    pub messengers: Vec<(Family, u32)>,
    /// The proxies Android's setting names, by host and port.
    pub android: Vec<(String, u16)>,
    /// The trackers' network signatures of the data pack the network part reads (`trackers`), for the marks a proxied
    /// flow keeps ([`Proxied::trackers`]); none until the network part hands them.
    pub trackers: Option<Arc<NetworkSignatures>>,
    /// Whether Private DNS is strict on the network beneath: Android's resolver then asks its provider over
    /// TLS, and the network part sees no app's lookups, so a hello no answer tied is no evidence (the fix round's
    /// S-M3).
    pub strict_dns: bool,
}

/// A messenger app's direct connections to its maker's network: those open, and when the last one ended, in
/// time since the phone started.
#[derive(Default)]
struct Direct {
    open: HashSet<u64>,
    last: Option<Duration>,
}

/// A flow named a messenger's inferred proxy, for its take-back: its app, what it was before, the hello whose
/// name was kept as a cover, and until when, in time since the phone started, a direct connection of the app
/// takes the name back.
struct Inferred {
    uid: u32,
    opened: Opened,
    before: Option<Flow>,
    hello: Option<Hello>,
    until: Duration,
}

/// The names a messenger app looked up through the network part, as keyed hashes, each until the names' shortest
/// lifetime ([`crate::names::MIN_KEEP`]) after, and its last lookup, in time since the phone started.
#[derive(Default)]
struct LookedUp {
    names: std::collections::VecDeque<(u64, Duration)>,
    last: Duration,
}

/// The engine's state of the inference.
#[derive(Default)]
pub(super) struct State {
    setting: ProxySetting,
    families: HashMap<u32, Family>,
    direct: HashMap<u32, Direct>,
    /// The flows named an inferred proxy within their window of take-back, open or ended, by flow.
    inferred: HashMap<u64, Inferred>,
    /// Each messenger app's lookups through the network part (the fix round's S-M3).
    looked_up: HashMap<u32, LookedUp>,
    /// When each Signal app last reached a third party of its own (a donation's, a debug log's): the pages
    /// it opens in its own web view after are not its proxy (the fix round's R-M5).
    third_party: HashMap<u32, Duration>,
    /// The key of the looked-up names' hashes.
    hasher: std::hash::RandomState,
}

/// The most names a messenger app's lookups are kept for.
const LOOKED_UP: usize = 512;

/// How long after Signal reached a third party of its own, a donation's or a debug log's, a name it reaches
/// is not its proxy: its web view loads the payment's pages from there, the card issuer's 3-D Secure among them,
/// whose names no list can hold. The live view's window, as substitution's.
const THIRD_PARTY: Duration = SUBSTITUTION;

/// Each messenger app's last direct connection to its maker's network, in time since the phone started, as an
/// engine hands it to the next (the fix round's S-M2): a flow of the next engine opened before the app's main
/// connection, as Telegram's CDN downloads after a hand-over, is not named its proxy.
pub(super) type DirectInstants = Vec<(u32, Duration)>;

/// The records of flows named an inferred proxy, held back from the log for their window of take-back, and
/// the flows they are of with when the window ends (the fix round's S-M2): a name taken back is corrected in
/// them before the log gets them, so that no record says what the engine took back. Bounded by [`HELD_BACK`].
#[derive(Default)]
pub(super) struct HeldBack {
    until: HashMap<u64, Duration>,
    records: std::collections::VecDeque<crate::log::Record>,
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
    /// What the network part told last.
    pub(super) fn setting(&self) -> &ProxySetting {
        &self.setting
    }

    /// Each messenger app's last direct connection, for the next engine: one open now counts as now.
    pub(super) fn direct_instants(&self, now: Duration) -> DirectInstants {
        self.direct
            .iter()
            .filter_map(|(&uid, d)| {
                let last = if d.open.is_empty() { d.last? } else { now };
                Some((uid, last))
            })
            .collect()
    }

    /// Takes the instants an engine before handed over.
    pub(super) fn carry_direct(&mut self, instants: DirectInstants) {
        for (uid, last) in instants.into_iter().take(MESSENGER_APPS) {
            self.direct.entry(uid).or_default().last = Some(last);
        }
    }
}

/// The flow id a record is of, if it is a flow's.
fn record_flow(record: &crate::log::Record) -> Option<u64> {
    match record {
        crate::log::Record::Segment { flow, .. } => Some(flow.id),
        crate::log::Record::Lookups { .. } => None,
    }
}

/// Whether `flow` went through an app's own proxy, whose first hop the switch decides for (ADR 0052): a SOCKS or
/// `CONNECT` proxy the server's reply confirmed, or a messenger's inferred one. A plain request in absolute form is
/// not one: nothing confirms it, so its flow keeps its own address and names as any flow does.
pub(super) fn own_proxy(flow: &Flow) -> bool {
    flow.proxy.as_ref().is_some_and(|p| p.kind != Kind::Forward)
}

/// Whether `flow` shows an app's own proxy's first hop: its address and names, not left out. "Now" guards such a
/// place against floods of other places (R8), whatever the switch, and shows it only within its window while its
/// app's first hops are not kept ([`strips`]).
pub(super) fn own_first_hop(flow: &Flow) -> bool {
    flow.proxy
        .as_ref()
        .is_some_and(|p| p.kind != Kind::Forward && !p.left_out)
}

/// Whether "Now" shows `flow`'s first hop for its window only, `keeps` saying whose apps' first hops are kept: an
/// own proxy's first hop of an app whose are not. The window, the table of ends, the sweep and the snapshot's
/// mark all ask this, never the proxy's fields, so that units B and D widen it here alone.
pub(super) fn strips(flow: &Flow, keeps: &dyn Fn(Option<u32>) -> bool) -> bool {
    own_first_hop(flow) && !keeps(flow.uid)
}

/// Whether `flow` holds where the app asked its proxy to go: a SOCKS, `CONNECT` or plain request's flow with what it
/// asked for. Only a declared proxy can: an inferred one is named by its own address and hello, the proxy's own.
pub(super) fn holds_destination(flow: &Flow) -> bool {
    flow.proxy
        .as_ref()
        .is_some_and(|p| p.kind.declared() && p.asked.is_some())
}

/// What the log may keep of `record`, `keeps` saying whose apps' first hops are kept (R1): unkept, an app's own
/// proxy's flow keeps its kind and the facts that name nothing (`logbook::without_destination`, the left-out
/// shape the log already reads), and a plain request keeps its own address and loses only where it asked to go.
pub(super) fn strip_for_log(record: &mut crate::log::Record, keeps: &dyn Fn(Option<u32>) -> bool) {
    let crate::log::Record::Segment { flow, .. } = record else {
        return;
    };
    if keeps(flow.uid) {
        return;
    }
    match flow.proxy.as_deref() {
        Some(proxy) if proxy.kind == Kind::Forward => {
            if proxy.asked.is_some() {
                let unasked = proxy.without_asked();
                flow.proxy = Some(Box::new(unasked));
            }
        }
        Some(proxy) if !proxy.left_out => *flow = super::logbook::without_destination(flow),
        _ => {}
    }
}

impl Shared {
    /// Sets what the network part tells for the proxies ([`ProxySetting`]); the open flows keep how they were named.
    pub(super) fn set_proxies(&self, setting: ProxySetting) {
        let mut state = lock(&self.proxies);
        state.families = setting
            .messengers
            .iter()
            .map(|&(f, uid)| (uid, f))
            .collect();
        state.setting = setting;
    }

    /// The messenger an app is, if the network part named it one.
    pub(super) fn family(&self, uid: Option<u32>) -> Option<Family> {
        uid.and_then(|uid| lock(&self.proxies).families.get(&uid).copied())
    }

    /// Whether an app's own proxies keep their address and the destination asked for: "Log where these apps
    /// connect", which the network part hands with every route ([`super::TunnelSetting::log_destinations`]), off until
    /// it is told.
    pub(super) fn logs_own_proxies(&self) -> bool {
        self.tunnels.logs_destinations()
    }

    /// Whose apps' own proxies keep their first hop and where they were asked to go, as the switch reads at this
    /// moment: every app's while "Log where these apps connect" is on. Each caller reads it once, under the lock
    /// that orders it against a change of the switch, and asks it for each flow's app; the one place a choice
    /// for single apps can join it (unit C's R3).
    pub(super) fn keeps_first_hops(&self) -> impl Fn(Option<u32>) -> bool + use<> {
        let all = self.logs_own_proxies();
        move |_| all
    }

    /// `flow` with only its first hop (audit-A 4): what was named by where the app asked its proxy to go gives way to
    /// the proxy's own names, as had the switch been off at its naming. Its name is the proxy's DNS name, else the
    /// organisation of its network, else none; its DNS mark is the proxy's address's, and no inner hello's ECH or
    /// resolver stays. A plain request loses only what it asked for; any flow that holds no destination, an
    /// inferred proxy's with its cover among them, is as it is. Not generic, for the library's size.
    pub(super) fn first_hop(&self, flow: &Flow) -> Flow {
        let Some(proxy) = flow.proxy.as_deref().filter(|_| holds_destination(flow)) else {
            return flow.clone();
        };
        let proxy = Box::new(proxy.without_asked());
        if proxy.kind == Kind::Forward {
            return Flow {
                proxy: Some(proxy),
                ..flow.clone()
            };
        }
        let (name, named_by) = match (&proxy.proxy_name, &proxy.organisation) {
            (Some(name), _) => (Some(name.clone()), NamedBy::Dns),
            (None, Some(organisation)) => (Some(organisation.clone()), NamedBy::Organisation),
            (None, None) => (None, NamedBy::Unknown),
        };
        let (dns, resolver) = self.dns_use(flow.destination, proxy.proxy_name.as_deref());
        Flow {
            name,
            named_by,
            dns_name: None,
            ech: super::Ech::Absent,
            dns,
            resolver,
            proxy: Some(proxy),
            ..flow.clone()
        }
    }

    /// Whether `address` is in the maker's own network, for the messenger `family`: `Some(true)` or
    /// `Some(false)` where the network part can tell, by Telegram's ranges, or by the organisation table and the
    /// owners' table, or by a DNS name of the maker's (`dns_name`); `None` where it cannot.
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

    /// The messenger `uid` connected to its maker directly, on the flow `id`: the flows it named an inferred
    /// proxy within their window are taken back.
    fn went_directly(&self, uid: u32, id: u64) {
        let now = self.clock.since_boot();
        let taken_back: Vec<Inferred> = {
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
            direct.last = Some(now);
            state.inferred.retain(|_, i| i.until > now);
            let ids: Vec<u64> = state
                .inferred
                .iter()
                .filter(|(_, i)| i.uid == uid)
                .map(|(&id, _)| id)
                .collect();
            ids.iter()
                .filter_map(|id| state.inferred.remove(id))
                .collect()
        };
        for inferred in taken_back {
            Counters::add(&self.counters.proxies_taken_back, 1);
            self.take_back(&inferred);
        }
    }

    /// Takes back the name of the flow `inferred`: it becomes what it would have been had the app's direct
    /// connection come first (the fix round's S-M2). Its name, address and place in "Now" come back, un-hidden
    /// where only the proxy left them out, and the hello kept as a cover names it as any hello does; the segments
    /// that wait for their states, and the records held back from the log, are rewritten so.
    fn take_back(&self, inferred: &Inferred) {
        let id = inferred.opened.id;
        let inferred_proxy = |flow: &Flow| flow.proxy.as_ref().is_some_and(|p| !p.kind.declared());
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
            && inferred_proxy(flow)
        {
            flow.proxy = None;
        }
        // What it would have been, from before its naming, where that is known.
        let restore = |current: &Flow| -> Flow {
            match &inferred.before {
                Some(before) if !self.hides(before.uid, before.destination) => Flow {
                    proxy: None,
                    blocked: current.blocked.clone(),
                    outcome: current.outcome,
                    came_in: current.came_in,
                    ..before.clone()
                },
                _ => Flow {
                    proxy: None,
                    ..current.clone()
                },
            }
        };
        let was = {
            let mut live = lock(&self.live);
            live.get_mut(&id)
                .filter(|l| inferred_proxy(&l.flow))
                .map(|l| {
                    let was = l.flow.clone();
                    let restored = restore(&l.flow);
                    l.hidden = l.hidden && self.hides(restored.uid, restored.destination);
                    // No proxy any more, so nothing was named without its destination.
                    l.unkept = false;
                    l.flow = restored;
                    was
                })
        };
        if was.is_some()
            && let Some(hello) = &inferred.hello
        {
            self.hello(inferred.opened, hello, NamedBy::Tls);
        }
        // The flow as it is now, once its hello named it; for an ended one, its record's facts.
        let now = lock(&self.live)
            .get(&id)
            .map(|l| (l.flow.clone(), l.hidden));
        let rewrite = |flow: &mut Flow, hidden: &mut bool| {
            if !inferred_proxy(flow) {
                return;
            }
            if let Some((restored, still_hidden)) = &now {
                *flow = Flow {
                    outcome: flow.outcome,
                    came_in: flow.came_in,
                    ..restored.clone()
                };
                *hidden = *still_hidden;
                return;
            }
            *flow = restore(flow);
            if let Some(hello) = &inferred.hello
                && flow.named_by.yields_to(NamedBy::Tls)
            {
                if flow.named_by == NamedBy::Dns {
                    flow.dns_name = flow.name.take();
                }
                flow.name = Some(hello.name.trim_end_matches('.').to_ascii_lowercase());
                flow.named_by = NamedBy::Tls;
            }
            *hidden = self.hides(flow.uid, flow.destination);
        };
        {
            let mut activity = lock(&self.activity);
            for piece in &mut activity.held {
                if let super::activity::Of::Flow { flow, hidden, .. } = &mut piece.of
                    && flow.id == id
                {
                    rewrite(flow, hidden);
                }
            }
            if let (Some(was), Some((restored, false))) = (&was, &now) {
                activity.counts.rename_place(restored.uid, was, restored);
            }
        }
        let mut back = lock(&self.held_back);
        back.until.remove(&id);
        for record in &mut back.records {
            let crate::log::Record::Segment { flow, .. } = record else {
                continue;
            };
            if flow.id == id {
                let mut hidden = false;
                rewrite(flow, &mut hidden);
                if hidden {
                    let stripped = super::logbook::without_destination(flow);
                    *flow = stripped;
                }
            }
        }
    }

    /// The records the log gets now: those of flows named an inferred proxy within their window of take-back
    /// are held back ([`HeldBack`]), and those whose window passed go first, in their order. Each is stripped as
    /// it enters, and again as it goes on from being held back ([`strip_for_log`]): what the log keeps of an app's
    /// own proxy follows the switch as the record reaches it, however long it waited.
    pub(super) fn to_log(&self, records: &mut Vec<crate::log::Record>) {
        let now = self.clock.since_boot();
        let mut back = lock(&self.held_back);
        let mut pending = lock(&self.pending_log);
        // Read once both are locked: a switch turned off before this is seen here, and one turned off after it
        // strips `pending_log` itself (`hide_chained`), so no record slips between the two (audit-A 2).
        let keeps = self.keeps_first_hops();
        back.until.retain(|_, until| *until > now);
        let HeldBack {
            until,
            records: held,
        } = &mut *back;
        let mut kept = std::collections::VecDeque::with_capacity(held.len());
        for mut record in held.drain(..) {
            if record_flow(&record).is_some_and(|id| until.contains_key(&id)) {
                kept.push_back(record);
            } else {
                strip_for_log(&mut record, &keeps);
                pending.push(record);
            }
        }
        for mut record in records.drain(..) {
            // Before it is held back too: a record made while the switch is off is never kept whole, even if the
            // switch is turned on before its window ends.
            strip_for_log(&mut record, &keeps);
            if record_flow(&record).is_some_and(|id| until.contains_key(&id)) {
                kept.push_back(record);
                if kept.len() > HELD_BACK
                    && let Some(mut oldest) = kept.pop_front()
                {
                    strip_for_log(&mut oldest, &keeps);
                    pending.push(oldest);
                }
            } else {
                pending.push(record);
            }
        }
        *held = kept;
    }

    /// Hands the log every record held back, as when the engine stops: no flow of it can be taken back after.
    /// Each is stripped as the switch says now, read once `pending_log` is locked, as in [`Shared::to_log`].
    pub(super) fn release_held_back(&self) {
        let mut back = lock(&self.held_back);
        back.until.clear();
        let mut pending = lock(&self.pending_log);
        let keeps = self.keeps_first_hops();
        for mut record in back.records.drain(..) {
            strip_for_log(&mut record, &keeps);
            pending.push(record);
        }
    }

    /// A flow ended: a direct connection's end starts the window of substitution. An inferred flow that ended
    /// stays within its window of take-back, for its records held back. The time since the phone started, as read
    /// for it, which also starts the window of an own proxy's first hop in "Now" (`logbook`): one reading for both.
    pub(super) fn proxies_ended(&self, id: u64) -> Duration {
        let now = self.clock.since_boot();
        let mut state = lock(&self.proxies);
        for direct in state.direct.values_mut() {
            if direct.open.remove(&id) {
                direct.last = Some(now);
            }
        }
        now
    }

    /// Every flow ended, as when the engine stops: none can be taken back after. The time since the phone started,
    /// as [`Shared::proxies_ended`] gives it, read once for every flow.
    pub(super) fn proxies_all_ended(&self) -> Duration {
        let now = self.clock.since_boot();
        let mut state = lock(&self.proxies);
        state.inferred.clear();
        for direct in state.direct.values_mut() {
            if !direct.open.is_empty() {
                direct.open.clear();
                direct.last = Some(now);
            }
        }
        now
    }

    /// Forgets the flows named an inferred proxy whose window of take-back ended at `now`, in time since the phone
    /// started. Each holds the flow as it was before its naming, its first hop with it, and the hello kept as a
    /// cover: memory then holds them no longer than "Now" shows them (audit-A 8). No take-back comes past the
    /// window ([`Shared::went_directly`] forgets them so first), so nothing else changes.
    pub(super) fn prune_inferred(&self, now: Duration) {
        lock(&self.proxies).inferred.retain(|_, i| i.until > now);
    }

    /// Whether the messenger `uid` connected to its maker directly within the window, or does now.
    fn went_directly_lately(&self, uid: u32) -> bool {
        let now = self.clock.since_boot();
        lock(&self.proxies).direct.get(&uid).is_some_and(|d| {
            !d.open.is_empty()
                || d.last
                    .is_some_and(|last| now.saturating_sub(last) < SUBSTITUTION)
        })
    }

    /// The trackers matched on `hosts` (a name or an address as text, each with its port), by their εxodus ids,
    /// sorted, at most [`MAX_TRACKERS`]; none before the network part handed the table.
    fn marks(&self, hosts: &[(String, u16)]) -> Vec<u32> {
        let Some(table) = lock(&self.proxies).setting.trackers.clone() else {
            return Vec::new();
        };
        let mut ids: Vec<u32> = hosts
            .iter()
            .flat_map(|(host, port)| table.matches(host, *port))
            .filter_map(|(i, _)| table.trackers().get(i).map(|t| t.id))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.truncate(MAX_TRACKERS);
        ids
    }

    /// Adds the trackers `name` at `port` matches to the proxied flow `id`'s, live and kept. The places its bytes
    /// were counted under take the new marks too: a place keys on the proxy, and one left behind would lose its
    /// flow's match, and so its first hop, while the flow is still open.
    pub(super) fn mark_proxied(&self, id: u64, name: &str, port: u16) {
        let found = self.marks(&[(name.to_owned(), port)]);
        if found.is_empty() {
            return;
        }
        let mark = |flow: &mut Flow| {
            if let Some(proxy) = flow.proxy.as_mut() {
                proxy.trackers.extend(&found);
                proxy.trackers.sort_unstable();
                proxy.trackers.dedup();
                proxy.trackers.truncate(MAX_TRACKERS);
            }
        };
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
        {
            mark(flow);
        }
        if let Some(live) = lock(&self.live).get_mut(&id) {
            let was = live.flow.clone();
            mark(&mut live.flow);
            if live.flow != was {
                lock(&self.activity)
                    .counts
                    .rename_place(was.uid, &was, &live.flow);
            }
        }
    }

    /// The names a flow carries, with its port, for its trackers' marks: its name where one names a host (not
    /// an organisation's), the DNS name beside it, and its address.
    fn hosts_of(flow: Option<&Flow>, destination: std::net::SocketAddr) -> Vec<(String, u16)> {
        let port = destination.port();
        let mut hosts = vec![(destination.ip().to_string(), port)];
        if let Some(flow) = flow {
            if flow.named_by != NamedBy::Organisation
                && let Some(name) = &flow.name
            {
                hosts.push((name.clone(), port));
            }
            if let Some(name) = &flow.dns_name {
                hosts.push((name.clone(), port));
            }
        }
        hosts
    }

    /// The app's bytes declared a proxy request, and for SOCKS or `CONNECT` the server's reply confirmed it
    /// ([`Handshake`]): the flow is named by the destination asked for, its proxy kept beside it; or, while "Log
    /// where these apps connect" is off, it keeps its own address and names, its first hop, and gains its proxy
    /// without what was asked (C1). A plain request goes to [`Shared::forwarded`].
    pub(super) fn declared(&self, opened: &Opened, request: &Request) {
        if request.kind == Kind::Forward {
            return self.forwarded(opened, request);
        }
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
        let setting = self.android_setting(destination, proxy_name.as_deref());
        let organisation = self.organisation(destination.ip());
        // The destination asked for names the flow: a name as it is, an address by the DNS answer it was
        // given for this app, if one is held, else by the address asked for itself, never by the proxy's (the
        // fix round's R-m2).
        let name = match &request.asked {
            Asked::Name(name) => name.clone(),
            Asked::Address(address) => lock(&self.names)
                .get(*address, opened.uid, Instant::now())
                .map_or_else(|| address.to_string(), str::to_owned),
        };
        let mut hosts = Self::hosts_of(current.as_ref(), destination);
        hosts.push((name.clone(), request.port));
        let proxied = Proxied {
            kind: request.kind,
            setting,
            password: request.password,
            outside_maker: false,
            asked: Some((request.asked.clone(), request.port)),
            proxy_name,
            organisation: organisation.as_ref().map(|(_, n)| n.clone()),
            cover: None,
            left_out: false,
            trackers: self.marks(&hosts),
        };
        let network = organisation.map(|(network, _)| network);
        self.name_proxied(opened, current.as_ref(), |flow, kept| {
            flow.network = network;
            if kept {
                flow.name = Some(name.clone());
                flow.named_by = NamedBy::Proxy;
                flow.dns_name = None;
                flow.proxy = Some(Box::new(proxied.clone()));
            } else {
                flow.proxy = Some(Box::new(proxied.without_asked()));
            }
        });
    }

    /// A plain request in absolute form: it cannot be confirmed, since origin servers accept that form too, so
    /// its flow keeps its own address and names, whatever the switch says; its proxy says what the request
    /// asked for, while "Log where these apps connect" is on (the fix round's S-M1).
    fn forwarded(&self, opened: &Opened, request: &Request) {
        self.log_now();
        Counters::add(&self.counters.proxies_declared, 1);
        if request.password {
            Counters::add(&self.counters.proxy_passwords, 1);
        }
        let destination = opened.destination;
        let current = self.flow_of(opened.id);
        let dns_name = current
            .as_ref()
            .filter(|f| f.named_by == NamedBy::Dns)
            .and_then(|f| f.name.clone());
        let mut hosts = Self::hosts_of(current.as_ref(), destination);
        hosts.push((
            match &request.asked {
                Asked::Name(name) => name.clone(),
                Asked::Address(address) => address.to_string(),
            },
            request.port,
        ));
        let proxied = Proxied {
            kind: Kind::Forward,
            setting: self.android_setting(destination, dns_name.as_deref()),
            password: request.password,
            outside_maker: false,
            asked: Some((request.asked.clone(), request.port)),
            proxy_name: None,
            organisation: None,
            cover: None,
            left_out: false,
            trackers: self.marks(&hosts),
        };
        self.name_proxied(opened, None, |flow, kept| {
            flow.proxy = Some(Box::new(if kept {
                proxied.clone()
            } else {
                proxied.without_asked()
            }));
        });
    }

    /// Whether Android's proxy setting names the proxy at `destination`, by its address or by `name`, the DNS
    /// name its address had.
    fn android_setting(&self, destination: std::net::SocketAddr, name: Option<&str>) -> bool {
        let state = lock(&self.proxies);
        state.setting.android.iter().any(|(host, port)| {
            *port == destination.port()
                && (host.parse::<IpAddr>().ok() == Some(destination.ip())
                    || name.is_some_and(|n| n.eq_ignore_ascii_case(host.trim_end_matches('.'))))
        })
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
    /// the network part passed tied to an address outside the maker's network is a cover: it never names the flow
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
                if outside
                    && !hello.name.is_empty()
                    && self.untied(&opened, &hello.name)
                    && self.infer(&opened, family, Some(hello))
                {
                    Counters::add(&self.counters.covers_kept_out, 1);
                    return;
                }
                // A hello that is no cover, or one while the app goes directly, names its flow as any does.
                self.hello(opened, hello, NamedBy::Tls);
            }
            Family::Signal => {
                let role = self.messengers.role(family, &hello.name);
                self.hello(opened, hello, NamedBy::Tls);
                let Some(uid) = opened.uid else {
                    return;
                };
                match role {
                    // Signal's own service, directly or through its own fronting, which a set proxy turns off
                    // (`SignalServiceNetworkAccess.kt`, `getConfiguration`, at the pinned commit): no proxy.
                    Some(Role::Own | Role::Front) => self.went_directly(uid, opened.id),
                    // A third party it reaches itself: what its web view opens next is not a proxy either.
                    Some(Role::Other) => {
                        lock(&self.proxies)
                            .third_party
                            .insert(uid, self.clock.since_boot());
                    }
                    None => {
                        if !hello.name.is_empty() && !self.after_third_party(uid) {
                            self.infer(&opened, family, None);
                        }
                    }
                }
            }
        }
    }

    /// Whether a messenger's hello named `name`, untied to its flow's address, and the network part can tell so (the
    /// fix round's S-M3): no answer the network part passed and still holds gave `name` this address, and the app did
    /// not look `name` up through the network part within the names' lifetime; and only where the network part sees the
    /// app's lookups, as Private DNS is not strict beneath and the app made one through the network part in the window.
    /// Otherwise an untied hello is no evidence. A fake-TLS proxy's cover is never looked up.
    fn untied(&self, opened: &Opened, name: &str) -> bool {
        let Some(uid) = opened.uid else {
            return false;
        };
        let now = self.clock.since_boot();
        let seen = {
            let state = lock(&self.proxies);
            let looked = state.looked_up.get(&uid);
            if state.setting.strict_dns
                || looked.is_none_or(|l| now.saturating_sub(l.last) >= SUBSTITUTION)
            {
                return false;
            }
            let hash = std::hash::BuildHasher::hash_one(
                &state.hasher,
                name.trim_end_matches('.').to_ascii_lowercase(),
            );
            looked.is_some_and(|l| l.names.iter().any(|(h, until)| *h == hash && *until > now))
        };
        !seen && !lock(&self.names).gave(opened.destination.ip(), opened.uid, name, Instant::now())
    }

    /// A DNS `answer` the network part passed to the app `uid`, from Android's resolver, the app's own or the network
    /// part's cache: for a messenger, its question is a name it looked up through the network part
    /// ([`Shared::untied`]).
    pub(super) fn looked_up(&self, uid: Option<u32>, answer: &[u8]) {
        let Some(uid) = uid.filter(|&u| {
            matches!(
                self.family(Some(u)),
                Some(Family::Telegram | Family::WhatsApp)
            )
        }) else {
            return;
        };
        let Some((_, question)) = crate::dns::answered(answer) else {
            return;
        };
        let now = self.clock.since_boot();
        let mut state = lock(&self.proxies);
        let hash = std::hash::BuildHasher::hash_one(
            &state.hasher,
            question.trim_end_matches('.').to_ascii_lowercase(),
        );
        if !state.looked_up.contains_key(&uid) && state.looked_up.len() >= MESSENGER_APPS {
            return;
        }
        let looked = state.looked_up.entry(uid).or_default();
        looked.last = now;
        looked.names.retain(|(h, _)| *h != hash);
        looked
            .names
            .push_back((hash, now.saturating_add(crate::names::MIN_KEEP)));
        while looked.names.len() > LOOKED_UP {
            looked.names.pop_front();
        }
    }

    /// Whether the Signal app `uid` reached a third party of its own within [`THIRD_PARTY`].
    fn after_third_party(&self, uid: u32) -> bool {
        let now = self.clock.since_boot();
        lock(&self.proxies)
            .third_party
            .get(&uid)
            .is_some_and(|at| now.saturating_sub(*at) < THIRD_PARTY)
    }

    /// Names the flow `opened` the messenger `family`'s proxy, inferred, unless the app connected to its maker
    /// directly in the window (substitution): whether it did. `hello` is the one whose name is kept as a cover.
    fn infer(&self, opened: &Opened, family: Family, hello: Option<&Hello>) -> bool {
        let Some(uid) = opened.uid else {
            return false;
        };
        self.log_now();
        if self.went_directly_lately(uid) {
            Counters::add(&self.counters.proxies_substituted, 1);
            return false;
        }
        Counters::add(&self.counters.proxies_inferred, 1);
        let cover = hello.filter(|h| !h.name.is_empty()).map(|h| h.name.clone());
        let current = self.flow_of(opened.id);
        let until = self.clock.since_boot().saturating_add(SUBSTITUTION);
        {
            let mut state = lock(&self.proxies);
            if state.inferred.len() >= INFERRED {
                let now = self.clock.since_boot();
                state.inferred.retain(|_, i| i.until > now);
            }
            if state.inferred.len() < INFERRED {
                state.inferred.insert(
                    opened.id,
                    Inferred {
                        uid,
                        opened: *opened,
                        before: current.clone(),
                        hello: hello.cloned(),
                        until,
                    },
                );
                lock(&self.held_back).until.insert(opened.id, until);
            }
        }
        let proxy_name = current
            .as_ref()
            .filter(|f| f.named_by == NamedBy::Dns)
            .and_then(|f| f.name.clone());
        let organisation = self.organisation(opened.destination.ip());
        let mut hosts = Self::hosts_of(current.as_ref(), opened.destination);
        if let Some(cover) = &cover {
            hosts.push((cover.clone(), opened.destination.port()));
        }
        let proxied = Proxied {
            kind: family.kind(),
            setting: false,
            password: false,
            outside_maker: family != Family::Signal,
            asked: None,
            proxy_name,
            organisation: organisation.map(|(_, n)| n),
            cover,
            left_out: false,
            trackers: self.marks(&hosts),
        };
        // An inferred proxy holds no destination: its flow is named by its own address and hello either way.
        self.name_proxied(opened, current.as_ref(), |flow, _| {
            flow.proxy = Some(Box::new(proxied.clone()));
        });
        true
    }

    /// Applies `name` to the flow `opened`, live and kept, with whether its app's first hops are kept, read once
    /// `live` is locked: a switch turned off after that is seen by the `hide_chained` that follows it, never
    /// between the two (audit-A 2). An own proxy named so is `unkept`, so that no hello names it later. The
    /// segments that wait for their states are named alike, and the place its first bytes were counted under,
    /// `before`, becomes its place. Unkept, the records already gathered for the log are stripped too: a segment a
    /// quarter hour cut between the request and a slow reply was written as an ordinary flow's (finding 27). One
    /// closure from each caller, so that this is built once for each (the library's size).
    fn name_proxied(&self, opened: &Opened, before: Option<&Flow>, name: impl Fn(&mut Flow, bool)) {
        let mut live = lock(&self.live);
        let kept = self.keeps_first_hops()(opened.uid);
        // The kept flows are locked after `live`, as `flow_of` locks them.
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows)
                .iter_mut()
                .rev()
                .find(|f| f.id == opened.id)
        {
            name(flow, kept);
        }
        let Some(live) = live.get_mut(&opened.id) else {
            return;
        };
        if live.hidden {
            return;
        }
        name(&mut live.flow, kept);
        let own = own_proxy(&live.flow);
        live.unkept |= own && !kept;
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
            }
        }
        if let Some(before) = before {
            activity.counts.rename_place(flow.uid, before, &flow);
        }
        if own && !kept {
            for record in lock(&self.pending_log).iter_mut() {
                if let crate::log::Record::Segment { flow: written, .. } = record
                    && written.id == opened.id
                {
                    // Given the named flow's proxy, so that the history says it went through one.
                    *written = super::logbook::without_destination(&Flow {
                        proxy: flow.proxy.clone(),
                        ..written.clone()
                    });
                }
            }
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
    /// How many bytes were copied into a hello's buffer, for the tests of what is copied.
    #[cfg(test)]
    copied: usize,
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
            #[cfg(test)]
            copied: 0,
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
            // A hello is gathered only from a stream that starts as TLS: no other first bytes are copied.
            if hello.is_empty() && bytes.first().is_some_and(|&b| b != 22) {
                self.hello = None;
                return found;
            }
            let take = bytes.len().min(tls::MAX_HELLO.saturating_sub(hello.len()));
            hello.extend_from_slice(&bytes[..take]);
            #[cfg(test)]
            {
                self.copied += take;
            }
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
        if first == Some(22) {
            self.start = false;
            self.hello = Some(Vec::new());
            self.inner = false;
            found.extend(self.feed(bytes));
            return;
        }
        // A stream not read for a proxy that does not start as TLS is read no further: no copy of its first
        // bytes is made, which may be a proxy's credentials, as the user's tool's own upstream's (the fix
        // round's S-m6).
        if !self.proxies {
            self.start = false;
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
                    // Only an inner stream that starts as TLS, or has not started yet, is copied.
                    let after = request.get(from..).unwrap_or_default();
                    let first = after.first().or_else(|| bytes.get(used)).copied();
                    if first.is_none_or(|b| b == 22) {
                        let mut hello = after.to_vec();
                        hello.extend_from_slice(&bytes[used..]);
                        hello.truncate(tls::MAX_HELLO);
                        #[cfg(test)]
                        {
                            self.copied += hello.len();
                        }
                        self.hello = Some(hello);
                        self.inner = true;
                    }
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

/// A declared SOCKS or `CONNECT` proxy's handshake, between the relay's two directions: the request the app's
/// bytes declared, and the server's first bytes ([`MAX_REPLY`] at most), which confirm it or not
/// ([`proxies::confirmed`]; the fix round's S-M1). Until they do, the flow keeps its own address and names, and
/// an inner hello read meanwhile waits; refused, or answered by another protocol, the request names nothing,
/// and that hello names the flow as its own. A server that never answers confirms nothing.
#[derive(Default)]
pub(super) struct Handshake {
    reply: [u8; MAX_REPLY],
    len: usize,
    step: Step,
}

#[derive(Default)]
enum Step {
    #[default]
    Idle,
    Waiting(Request, Option<Hello>),
    Confirmed,
    Refused,
}

/// What a handshake's next bytes settle, for the relay to tell the engine ([`Shared::handshake_settled`]).
pub(super) enum Settle {
    /// The request, confirmed, and the inner hello read before it was.
    Declared(Request, Option<Hello>),
    /// A hello: of the stream inside a confirmed proxy (`true`), or the flow's own.
    Hello(Hello, bool),
}

impl Handshake {
    /// The app's bytes declared `request`.
    fn ask(&mut self, request: Request) -> Option<Settle> {
        self.step = Step::Waiting(request, None);
        self.decide()
    }

    /// The sniff read a hello after a request.
    fn inner_hello(&mut self, hello: Hello) -> Option<Settle> {
        match &mut self.step {
            Step::Waiting(_, waiting) => {
                *waiting = Some(hello);
                None
            }
            Step::Confirmed => Some(Settle::Hello(hello, true)),
            Step::Idle | Step::Refused => Some(Settle::Hello(hello, false)),
        }
    }

    /// The server sent `bytes`: what they settle, and whether its next bytes are still wanted.
    fn server(&mut self, bytes: &[u8]) -> (Option<Settle>, bool) {
        let take = bytes.len().min(MAX_REPLY - self.len);
        self.reply[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
        let settled = self.decide();
        let wanted = self.len < MAX_REPLY && matches!(self.step, Step::Idle | Step::Waiting(..));
        (settled, wanted)
    }

    fn decide(&mut self) -> Option<Settle> {
        let Step::Waiting(request, _) = &self.step else {
            return None;
        };
        let reply = &self.reply[..self.len];
        let confirmed = match proxies::confirmed(request, reply) {
            Some(answer) => answer,
            // As many bytes as a confirmation takes came, and still none: not this protocol's.
            None if self.len >= MAX_REPLY => false,
            None => return None,
        };
        let Step::Waiting(request, hello) = std::mem::replace(
            &mut self.step,
            if confirmed {
                Step::Confirmed
            } else {
                Step::Refused
            },
        ) else {
            return None;
        };
        if confirmed {
            Some(Settle::Declared(request, hello))
        } else {
            hello.map(|hello| Settle::Hello(hello, false))
        }
    }
}

impl Shared {
    /// Tells the engine what a flow's sniff found ([`Sniff::feed`]), a declared SOCKS or `CONNECT` request
    /// through its `handshake`, which waits for the server's reply.
    pub(super) fn found(&self, opened: Opened, found: Found, handshake: &Mutex<Handshake>) {
        let settled = match found {
            Found::Hello(hello, false) => return self.hello_read(opened, &hello),
            Found::Hello(hello, true) => lock(handshake).inner_hello(hello),
            Found::Request(request) if request.kind == Kind::Forward => {
                return self.declared(&opened, &request);
            }
            Found::Request(request) => lock(handshake).ask(request),
            Found::Shape(shape) => return self.shaped(&opened, shape),
        };
        self.handshake_settled(opened, settled);
    }

    /// The server's first bytes on a flow that is read for a proxy: whether more are wanted.
    pub(super) fn replied(
        &self,
        opened: Opened,
        bytes: &[u8],
        handshake: &Mutex<Handshake>,
    ) -> bool {
        let (settled, wanted) = lock(handshake).server(bytes);
        self.handshake_settled(opened, settled);
        wanted
    }

    fn handshake_settled(&self, opened: Opened, settled: Option<Settle>) {
        match settled {
            Some(Settle::Declared(request, hello)) => {
                self.declared(&opened, &request);
                if let Some(hello) = hello {
                    self.hello(opened, &hello, NamedBy::Tls);
                }
            }
            Some(Settle::Hello(hello, true)) => self.hello(opened, &hello, NamedBy::Tls),
            Some(Settle::Hello(hello, false)) => self.hello_read(opened, &hello),
            None => {}
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
        engine_at(logs).0
    }

    /// [`engine`], with its clock.
    fn engine_at(logs: bool) -> (Shared, Arc<super::super::clock::ManualClock>) {
        let (mut shared, clock, _) = telling_at(T);
        shared.organisations = crate::organisations::Organisations::open(Box::new(
            crate::organisations::tests::sample(),
        ))
        .ok();
        shared.owners = crate::owners::Owners::bundled();
        shared.tunnels.set(&TunnelSetting {
            log_destinations: logs,
            ..TunnelSetting::default()
        });
        (shared, clock)
    }

    /// The app `uid` looked `name` up through the network part, and was given `address`: Android's resolver's answer,
    /// which names every app's flows.
    fn looked_up(shared: &Shared, uid: u32, name: &str, address: [u8; 4]) {
        let answer = super::super::tests::dns_answer(name, address);
        shared.learn(&answer, None);
        shared.looked_up(Some(uid), &answer);
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
            blocked: None,
        }) else {
            unreachable!("an open flow is live")
        };
        shared.proxies_opened(&opened, by_dns.as_deref());
        (opened, bytes)
    }

    /// Feeds `reads` to a sniff of the flow `opened` and tells the engine what they say, as `tcp::relay` does,
    /// each read's bytes counted after; the server sends nothing.
    fn relay(
        shared: &Shared,
        opened: Opened,
        bytes: &super::super::logbook::FlowBytes,
        reads: &[&[u8]],
    ) {
        relay_replied(shared, opened, bytes, reads, &[]);
    }

    /// As [`relay`], and then the server's `reply`, which may confirm a declared proxy's handshake.
    fn relay_replied(
        shared: &Shared,
        opened: Opened,
        bytes: &super::super::logbook::FlowBytes,
        reads: &[&[u8]],
        reply: &[u8],
    ) {
        let messenger = shared.family(opened.uid).is_some();
        let mut sniff = Sniff::new(opened.sniffs, messenger);
        let handshake = Mutex::new(Handshake::default());
        for read in reads {
            for found in sniff.feed(read) {
                shared.found(opened, found, &handshake);
            }
            bytes.up(shared, read.len(), read.len() + 40);
        }
        if !reply.is_empty() && opened.sniffs {
            shared.replied(opened, reply, &handshake);
        }
    }

    /// SOCKS5's replies to [`socks5_reads`]: RFC 1929 chosen, the password taken, the request done.
    const SOCKS5_REPLY: &[u8] = &[5, 2, 1, 0, 5, 0, 0, 1, 203, 0, 113, 5, 0x04, 0x38];

    /// An HTTP proxy's reply to `CONNECT`.
    const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

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
        relay_replied(&shared, opened, &bytes, &reads, SOCKS5_REPLY);
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

    /// Whether `haystack` holds `needle` anywhere.
    fn holds(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// SOCKS5's handshake with the synthetic secret, asking for `asked:443`, then a hello for `inner` inside.
    fn socks5_asking(asked: &str, inner: &str) -> Vec<Vec<u8>> {
        let mut reads = socks5_reads();
        let mut request = vec![5, 1, 0, 3, u8::try_from(asked.len()).unwrap_or(0)];
        request.extend_from_slice(asked.as_bytes());
        request.extend_from_slice(&443u16.to_be_bytes());
        reads[2] = request;
        reads[3] = crate::tls::tests::hello(inner, 1000);
        reads
    }

    /// A TLS record of a hello for `name` that offers ECH.
    fn ech_hello(name: &str) -> Vec<u8> {
        let handshake = crate::tls::tests::handshake(name, true);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Test 1: with the switch off, the log keeps of each own proxy's flow its kind, the facts that name nothing
    /// and its trackers' marks: of SOCKS5 with a password, of `CONNECT`, and of an inferred `MTProto` with a cover,
    /// written once its ten minutes passed. Nothing of the first hop, of what was asked or of an inner hello.
    #[test]
    fn with_the_switch_off_a_proxys_records_keep_its_kind_alone() {
        let messenger = UID + 2;
        let (shared, clock) = engine_at(false);
        shared.set_proxies(ProxySetting {
            messengers: vec![(Family::Telegram, messenger)],
            ..ProxySetting::default()
        });
        with_trackers(&shared);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (socks, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_asking("example.com", "inner.example");
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, socks, &bytes, &reads, SOCKS5_REPLY);
        let (connect, bytes) = open(&shared, UID, at([203, 0, 113, 7], 3128));
        relay_replied(
            &shared,
            connect,
            &bytes,
            &[b"CONNECT ads.tracker.example:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        looked_up(&shared, messenger, "web.example.org", [93, 184, 216, 99]);
        let (mtproto, bytes) = open(&shared, messenger, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            mtproto,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert_eq!(
            live(&shared, mtproto.id)
                .proxy
                .and_then(|p| p.cover)
                .as_deref(),
            Some("www.google.com")
        );
        for id in [socks.id, connect.id, mtproto.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let batch = crate::log::batch(&records);
        for hidden in [
            &b"proxy.example.net"[..],
            b"example.com",
            b"inner.example",
            b"www.google.com",
            b"tracker",
            &[203, 0, 113, 5],
            &[203, 0, 113, 7],
            &[93, 184, 216, 34],
        ] {
            assert!(!holds(&batch, hidden), "{hidden:?}");
        }
        assert!(!holds_secret(&batch));
        for (id, kind, password, trackers) in [
            (socks.id, Kind::Socks5, true, vec![]),
            (connect.id, Kind::Connect, false, vec![49]),
            (mtproto.id, Kind::MtProto, false, vec![]),
        ] {
            let written = of_flow(&records, id);
            assert!(
                !written.is_empty()
                    && written.iter().all(|f| left_out(f)
                        && f.proxy.as_ref().is_some_and(|p| {
                            p.kind == kind && p.password == password && p.trackers == trackers
                        })),
                "{kind:?} {written:?}"
            );
        }
    }

    /// Test 8: with the switch off, "Now" shows an app's own proxy's first hop in full: its address and port, the
    /// DNS name its address had and its network's organisation, with nothing asked and nothing left out; and a
    /// messenger's cover, which the log never gets.
    #[test]
    fn with_the_switch_off_now_shows_a_proxys_first_hop_in_full() {
        let shared = engine(false);
        learn(&shared, "93.184.216.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([93, 184, 216, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, opened, &bytes, &reads, SOCKS5_REPLY);
        let flow = live(&shared, opened.id);
        assert_eq!(flow.destination, at([93, 184, 216, 5], 1080));
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("proxy.example.net"), NamedBy::Dns)
        );
        let proxy = flow.proxy.unwrap_or_else(|| unreachable!("confirmed"));
        assert_eq!(proxy.proxy_name.as_deref(), Some("proxy.example.net"));
        assert_eq!(proxy.organisation.as_deref(), Some("Example Net, Inc."));
        assert!(proxy.asked.is_none() && !proxy.left_out && proxy.password);
        let view = shared.now_view(T + 1_000);
        let places: Vec<_> = view.apps.iter().flat_map(|a| a.places.iter()).collect();
        assert!(
            places.len() == 1 && places[0].shown_only,
            "shown here only: {places:?}"
        );
        let snapshot = crate::snapshot::encode(&view);
        assert!(holds(&snapshot, b"proxy.example.net") && holds(&snapshot, &[93, 184, 216, 5]));
        assert!(!holds(&snapshot, b"example.com") && !holds_secret(&snapshot));
        // A messenger's cover is shown live, and kept out of the log.
        let (shared, clock) = engine_at(false);
        telegram(&shared);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert_eq!(
            live(&shared, proxy.id)
                .proxy
                .and_then(|p| p.cover)
                .as_deref(),
            Some("www.google.com")
        );
        let view = shared.now_view(T + 1_000);
        assert!(
            view.apps
                .iter()
                .flat_map(|a| a.places.iter())
                .all(|p| p.shown_only)
        );
        let snapshot = crate::snapshot::encode(&view);
        assert!(holds(&snapshot, b"www.google.com") && holds(&snapshot, &[93, 184, 216, 34]));
        shared.finish(proxy.id);
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        assert_ne!(of_flow(&records, proxy.id).len(), 0);
        assert!(!holds(&crate::log::batch(&records), b"www.google.com"));
    }

    /// Test 9 (C1): with the switch off, neither the request nor the hello inside the proxy names the flow, live
    /// or kept, in "Now" or in the log: of SOCKS5 and `CONNECT` with an inner hello for `inner.example`, and of a
    /// `CONNECT` on port 443 whose inner hello names a known resolver and offers ECH. The flow keeps its own
    /// names, and the DNS mark, resolver and ECH of the proxy's own address; the trackers are marked. With the
    /// switch on, the inner hello names it, as before.
    #[test]
    fn neither_the_request_nor_the_inner_hello_names_the_flow_while_the_switch_is_off() {
        let shared = engine(false);
        with_trackers(&shared);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (socks, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_asking("example.com", "inner.example");
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, socks, &bytes, &reads, SOCKS5_REPLY);
        let (connect, bytes) = open(&shared, UID, at([203, 0, 113, 7], 3128));
        relay_replied(
            &shared,
            connect,
            &bytes,
            &[
                b"CONNECT ads.tracker.example:443 HTTP/1.1\r\n\r\n",
                &crate::tls::tests::hello("inner.example", 1000),
            ],
            CONNECTED,
        );
        let (resolver, bytes) = open(&shared, UID, at([203, 0, 113, 8], 443));
        relay_replied(
            &shared,
            resolver,
            &bytes,
            &[
                b"CONNECT doh.sample.example:443 HTTP/1.1\r\n\r\n",
                &ech_hello("doh.sample.example"),
            ],
            CONNECTED,
        );
        let named = [
            "inner.example",
            "example.com",
            "ads.tracker.example",
            "doh.sample.example",
        ];
        for (id, own) in [
            (socks.id, Some("proxy.example.net")),
            (connect.id, None),
            (resolver.id, None),
        ] {
            let kept = lock(&shared.flows)
                .iter()
                .rev()
                .find(|f| f.id == id)
                .cloned()
                .unwrap_or_else(|| unreachable!("kept"));
            for flow in [live(&shared, id), kept] {
                assert_eq!(flow.name.as_deref(), own, "{flow:?}");
                assert!(
                    !matches!(flow.named_by, NamedBy::Proxy | NamedBy::Tls),
                    "{flow:?}"
                );
                assert_eq!(
                    (flow.ech, flow.dns, flow.resolver.as_deref()),
                    (Ech::Absent, DnsUse::None, None),
                    "the proxy's own: {flow:?}"
                );
                assert!(flow.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
                assert!(
                    named.iter().all(|n| !format!("{flow:?}").contains(n)),
                    "{flow:?}"
                );
            }
        }
        assert_eq!(
            live(&shared, connect.id).proxy.map(|p| p.trackers),
            Some(vec![49]),
            "the destination asked for marks it"
        );
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 1_000));
        for id in [socks.id, connect.id, resolver.id] {
            shared.finish(id);
        }
        shared.flush();
        let batch = crate::log::batch(&taken(&shared));
        for name in named {
            assert!(
                !holds(&snapshot, name.as_bytes()) && !holds(&batch, name.as_bytes()),
                "{name}"
            );
        }
        // The switch on: the inner hello names the flow, as before unit A.
        let shared = engine(true);
        let (socks, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        relay_replied(&shared, socks, &bytes, &reads, SOCKS5_REPLY);
        let flow = live(&shared, socks.id);
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("inner.example"), NamedBy::Tls)
        );
        assert!(flow.proxy.is_some_and(|p| p.asked.is_some()));
    }

    /// Test 10 (R6f): a flow named without its destination stays so after the switch is turned on: the inner hello
    /// read after renames nothing, and its next record holds its first hop, with nothing asked.
    #[test]
    fn a_hello_after_the_switch_is_turned_on_does_not_name_an_unkept_flow() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let mut sniff = Sniff::new(true, false);
        let handshake = Mutex::new(Handshake::default());
        for read in &reads[..3] {
            for found in sniff.feed(read) {
                shared.found(opened, found, &handshake);
            }
        }
        shared.replied(opened, SOCKS5_REPLY, &handshake);
        switch(&shared, true);
        for found in sniff.feed(&reads[3]) {
            shared.found(opened, found, &handshake);
        }
        bytes.up(&shared, 100, 140);
        let flow = live(&shared, opened.id);
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("proxy.example.net"), NamedBy::Dns),
            "{flow:?}"
        );
        assert!(lock(&shared.live).get(&opened.id).is_some_and(|l| l.unkept));
        shared.finish(opened.id);
        shared.flush();
        let written = of_flow(&taken(&shared), opened.id);
        assert!(
            !written.is_empty()
                && written
                    .iter()
                    .all(|f| f.destination == at([203, 0, 113, 5], 1080)
                        && f.proxy.as_ref().is_some_and(|p| {
                            p.proxy_name.as_deref() == Some("proxy.example.net")
                                && p.asked.is_none()
                                && !p.left_out
                        })),
            "{written:?}"
        );
    }

    /// Test 7 (E6, finding 27): a quarter hour cuts a SOCKS5 flow's segment between its request and a slow reply,
    /// and the states are told, so that the record waits for the log as an ordinary flow's, with the proxy's
    /// address and name. The reply then confirms the proxy with the switch off: the record is stripped, with the
    /// proxy's kind.
    #[test]
    fn a_record_written_before_a_slow_reply_is_stripped_once_it_confirms_the_proxy() {
        let (shared, clock) = engine_at(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let mut sniff = Sniff::new(true, false);
        let handshake = Mutex::new(Handshake::default());
        for read in &socks5_reads() {
            for found in sniff.feed(read) {
                shared.found(opened, found, &handshake);
            }
            bytes.up(&shared, read.len(), read.len() + 40);
        }
        cut_and_tell(&shared, &clock);
        {
            let pending = lock(&shared.pending_log);
            let written = of_flow(&pending, opened.id);
            assert!(
                !written.is_empty()
                    && written.iter().all(
                        |f| f.proxy.is_none() && f.name.as_deref() == Some("proxy.example.net")
                    ),
                "{written:?}"
            );
        }
        shared.replied(opened, SOCKS5_REPLY, &handshake);
        let written = of_flow(&taken(&shared), opened.id);
        assert!(
            !written.is_empty()
                && written.iter().all(
                    |f| left_out(f) && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::Socks5)
                ),
            "{written:?}"
        );
    }
    /// Test 23 (R6a to R6d, R6g): turning the switch off sets every open flow, held segment and place of "Now" back to
    /// its first hop at once, with the proxy's own DNS mark, resolver and ECH; Signal's proxy keeps its name, its
    /// own; a place whose flow ended two minutes ago stays in full, and one twenty minutes ago is stripped, in
    /// memory before any view. Neither destination asked for is anywhere after, from the live flows to the log.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn turning_the_switch_off_sets_every_flow_back_to_its_first_hop() {
        let (shared, clock) = engine_at(true);
        let since = |from, until| {
            let mut reading = super::super::activity::tests::told(
                from,
                until,
                &[(from, until, crate::states::State::InUse)],
            );
            reading.screen = crate::states::Screen::On(Some(T));
            reading
        };
        // Two places whose flows end twenty and two minutes before the switch goes off.
        for (n, wait) in [(11u8, 18), (12, 2)] {
            use super::super::clock::Clock;
            let (flow, bytes) = open(&shared, UID, at([203, 0, 113, n], 3128));
            relay_replied(
                &shared,
                flow,
                &bytes,
                &[format!("CONNECT ended{n}.example:443 HTTP/1.1\r\n\r\n").as_bytes()],
                CONNECTED,
            );
            let now = clock.wall_ms();
            clock.pass(2_000);
            shared.tell(&since(now - 1_000, clock.wall_ms()));
            shared.finish(flow.id);
            clock.pass(wait * 60_000);
        }
        learn(&shared, "203.0.113.5", "socks.proxy.test");
        let (open_flow, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.org");
        request.extend_from_slice(&443u16.to_be_bytes());
        relay_replied(
            &shared,
            open_flow,
            &bytes,
            &[&request],
            &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        );
        let (held, bytes) = open(&shared, UID, at([203, 0, 113, 6], 3128));
        relay_replied(
            &shared,
            held,
            &bytes,
            &[b"CONNECT example.net:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        shared.finish(held.id);
        let (resolver, bytes) = open(&shared, UID, at([203, 0, 113, 8], 443));
        relay_replied(
            &shared,
            resolver,
            &bytes,
            &[
                b"CONNECT doh.sample.example:443 HTTP/1.1\r\n\r\n",
                &ech_hello("doh.sample.example"),
            ],
            CONNECTED,
        );
        let before = live(&shared, resolver.id);
        assert_eq!(
            (before.dns, before.resolver.as_deref(), before.ech),
            (DnsUse::Encrypted, Some("sample"), Ech::Offered),
            "named by its inner hello while the switch is on"
        );
        let messenger = UID + 3;
        let mut setting = lock(&shared.proxies).setting().clone();
        setting.messengers = vec![(Family::Signal, messenger)];
        shared.set_proxies(setting);
        let (signal, bytes) = open(&shared, messenger, at([93, 184, 216, 40], 443));
        relay(
            &shared,
            signal,
            &bytes,
            &[&crate::tls::tests::hello("relay.signal-proxy.test", 1000)],
        );
        assert_eq!(
            live(&shared, open_flow.id).name.as_deref(),
            Some("example.org")
        );
        switch(&shared, false);
        // The open flows hold their first hop, with the proxy's own marks.
        let flow = live(&shared, open_flow.id);
        assert_eq!(
            (flow.destination, flow.name.as_deref(), flow.named_by),
            (
                at([203, 0, 113, 5], 1080),
                Some("socks.proxy.test"),
                NamedBy::Dns
            )
        );
        assert!(
            lock(&shared.live)
                .get(&open_flow.id)
                .is_some_and(|l| l.unkept)
        );
        let flow = live(&shared, resolver.id);
        assert_eq!(
            (
                flow.name.as_deref(),
                flow.named_by,
                flow.dns,
                flow.resolver.as_deref(),
                flow.ech
            ),
            (None, NamedBy::Unknown, DnsUse::None, None, Ech::Absent),
            "{flow:?}"
        );
        assert!(flow.proxy.is_some_and(|p| p.asked.is_none()));
        let flow = live(&shared, signal.id);
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("relay.signal-proxy.test"), NamedBy::Tls),
            "Signal's proxy is named by its own hello"
        );
        // The segment held for its states.
        let pieces: Vec<Flow> = lock(&shared.activity)
            .held
            .iter()
            .filter_map(|p| match &p.of {
                super::super::activity::Of::Flow { flow, .. } if flow.id == held.id => {
                    Some(flow.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            !pieces.is_empty()
                && pieces.iter().all(|f| own_first_hop(f)
                    && !holds_destination(f)
                    && f.destination == at([203, 0, 113, 6], 3128)
                    && f.name.is_none()),
            "its first hop, in full for its window: {pieces:?}"
        );
        // The places, read in memory before any view sweeps: the recent one in full, the old one stripped.
        {
            let places = lock(&shared.activity).counts.places_of(Some(UID));
            let recent = places
                .iter()
                .find(|f| f.destination == at([203, 0, 113, 12], 3128))
                .unwrap_or_else(|| unreachable!("placed: {places:?}"));
            assert!(
                own_first_hop(recent) && !holds_destination(recent),
                "two minutes after its end: {recent:?}"
            );
            assert!(
                places
                    .iter()
                    .all(|f| f.destination != at([203, 0, 113, 11], 3128))
                    && places.iter().any(|f| f.destination.ip().is_unspecified()),
                "twenty minutes after its end, stripped: {places:?}"
            );
        }
        // Nowhere: the live flows, the segments held, "Now", the log.
        let gone = [&b"example.org"[..], b"example.net", b"ended11", b"ended12"];
        let seen = format!(
            "{:?}{pieces:?}",
            lock(&shared.live)
                .values()
                .map(|l| &l.flow)
                .collect::<Vec<_>>()
        );
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 1_000));
        for id in [open_flow.id, resolver.id, signal.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let batch = crate::log::batch(&taken(&shared));
        for name in gone {
            assert!(
                !holds(seen.as_bytes(), name) && !holds(&snapshot, name) && !holds(&batch, name),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    /// Test 24 (R6e): turning the switch on names no open flow anew: a first hop stays one, and its next record
    /// holds its address and the proxy's name, with nothing asked.
    #[test]
    fn turning_the_switch_on_names_no_open_flow_anew() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, opened, &bytes, &reads, SOCKS5_REPLY);
        switch(&shared, true);
        let flow = live(&shared, opened.id);
        assert_eq!(flow.name.as_deref(), Some("proxy.example.net"));
        assert!(flow.proxy.is_some_and(|p| p.asked.is_none()));
        bytes.up(&shared, 100, 140);
        shared.finish(opened.id);
        shared.flush();
        let written = of_flow(&taken(&shared), opened.id);
        assert!(
            !written.is_empty()
                && written
                    .iter()
                    .all(|f| f.destination == at([203, 0, 113, 5], 1080)
                        && f.proxy.as_ref().is_some_and(|p| {
                            p.proxy_name.as_deref() == Some("proxy.example.net")
                                && p.asked.is_none()
                        })),
            "{written:?}"
        );
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
            trackers: None,
            strict_dns: false,
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
        relay_replied(
            &shared,
            named,
            &bytes,
            &[b"CONNECT example.org:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        // Android's setting's host at another port is an app's own proxy.
        let (other_port, bytes) = open(&shared, UID, at([203, 0, 113, 5], 3129));
        relay(
            &shared,
            other_port,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        let setting = |id| live(&shared, id).proxy.map(|p| (p.kind, p.setting));
        assert_eq!(setting(other_port.id), Some((Kind::Forward, false)));
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
            trackers: None,
            strict_dns: false,
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
        let (shared, clock) = engine_at(true);
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
        // Its direct connection ended a moment ago: within the window, a connection elsewhere is still no proxy.
        shared.finish(direct.id);
        let (soon, bytes) = open(&shared, UID, at([93, 184, 216, 37], 443));
        relay(&shared, soon, &bytes, &[&header]);
        assert!(
            live(&shared, soon.id).proxy.is_none(),
            "within the window of substitution"
        );
        // Ten minutes after its last direct connection ended, in time since the phone started, one is again:
        // ten minutes of sleep count as ten minutes (S-n3).
        clock.pass(u64::try_from(SUBSTITUTION.as_millis()).unwrap_or(0) + 1_000);
        let (later, bytes) = open(&shared, UID, at([93, 184, 216, 36], 443));
        relay(&shared, later, &bytes, &[&header]);
        assert!(live(&shared, later.id).proxy.is_some());
        assert_eq!(shared.counters.snapshot()[63..66], [2, 2, 1]);
        // Past its window of take-back, a direct connection takes the name back no more.
        clock.pass(u64::try_from(SUBSTITUTION.as_millis()).unwrap_or(0) + 1_000);
        let (again, bytes) = open(&shared, UID, at([149, 154, 167, 52], 443));
        relay(&shared, again, &bytes, &[&header]);
        assert!(live(&shared, later.id).proxy.is_some(), "its window passed");
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
        // The network part sees Telegram's lookups: it looked a name up through it a moment ago.
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
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
            trackers: None,
            strict_dns: false,
        });
    }

    #[test]
    fn whatsapps_clear_header_outside_metas_network_is_its_proxy() {
        let shared = engine(true);
        whatsapp(&shared);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
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
            trackers: None,
            strict_dns: false,
        });
    }

    #[test]
    fn signals_proxy_is_decided_by_names_and_its_fronting_and_captcha_are_not_one() {
        let shared = engine(true);
        signal(&shared);
        // A proxy's own domain, with no direct connection: Signal's proxy, named by it.
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
        // Its own circumvention through Google's network, a captcha and a payment are none either.
        for (i, name) in ["www.google.com", "js.hcaptcha.com", "api.stripe.com"]
            .into_iter()
            .enumerate()
        {
            let (flow, bytes) = open(
                &shared,
                UID,
                at([93, 184, 216, 50 + u8::try_from(i).unwrap_or(0)], 443),
            );
            relay(
                &shared,
                flow,
                &bytes,
                &[&crate::tls::tests::hello(name, 1000)],
            );
            assert!(live(&shared, flow.id).proxy.is_none(), "{name}");
        }
    }

    /// Signal's fronting is its own service reached directly (R-M5): where it fronts, which a set proxy turns
    /// off, an unknown name after it is no proxy.
    #[test]
    fn signals_fronting_counts_as_going_directly() {
        let shared = engine(true);
        signal(&shared);
        let (front, bytes) = open(&shared, UID, at([93, 184, 216, 30], 443));
        relay(
            &shared,
            front,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com.eg", 1000)],
        );
        let (other, bytes) = open(&shared, UID, at([93, 184, 216, 31], 443));
        relay(
            &shared,
            other,
            &bytes,
            &[&crate::tls::tests::hello("maps.example.net", 1000)],
        );
        assert!(live(&shared, other.id).proxy.is_none());
        assert_eq!(shared.counters.snapshot()[63..65], [0, 1], "substituted");
    }

    /// A donation with no direct connection, as through a Signal proxy (R-M5): Stripe's API, then the pages its
    /// web view opens, the 3-D Secure page of a card issuer no list can hold among them, and `PayPal`'s approval
    /// and what it loads, are no proxy within the window after a third party of Signal's own; past it, an
    /// unknown name is again.
    #[test]
    fn a_donation_through_signals_web_view_is_no_proxy() {
        let (shared, clock) = engine_at(true);
        signal(&shared);
        for (i, name) in [
            "api.stripe.com",
            "hooks.stripe.com",
            "acs.issuer-bank.example",
            "signaldonations.org",
            "www.paypal.com",
            "www.paypalobjects.com",
            "debuglogs.org",
            "s3.upload.example.com",
            "node1.consensus.mob.production.namda.net",
            "fog.prod.mobilecoinww.com",
        ]
        .into_iter()
        .enumerate()
        {
            let (flow, bytes) = open(
                &shared,
                UID,
                at([93, 184, 216, 60 + u8::try_from(i).unwrap_or(0)], 443),
            );
            relay(
                &shared,
                flow,
                &bytes,
                &[&crate::tls::tests::hello(name, 1000)],
            );
            assert!(live(&shared, flow.id).proxy.is_none(), "{name}");
        }
        assert_eq!(shared.counters.snapshot()[63], 0);
        clock.pass(u64::try_from(THIRD_PARTY.as_millis()).unwrap_or(0) + 1_000);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 90], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("signal-proxy.example.org", 1000)],
        );
        assert!(live(&shared, proxy.id).proxy.is_some(), "past the window");
        // The third parties are in the data itself, each with its source.
        for name in [
            "signaldonations.org",
            "www.paypal.com",
            "debuglogs.org",
            "fog-rpt-prd.namda.net",
        ] {
            assert_eq!(
                shared.messengers.role(Family::Signal, name),
                Some(Role::Other),
                "{name}"
            );
        }
    }

    #[test]
    fn a_request_and_the_inner_hello_in_one_read_are_both_read() {
        let mut bytes = b"CONNECT example.org:443 HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(&crate::tls::tests::hello("inner.example", 1000));
        let found = Sniff::new(true, false).feed(&bytes);
        assert!(
            matches!(&found[..], [Found::Request(_), Found::Hello(h, true)] if h.name == "inner.example")
        );
    }

    /// Test 25 (N1, N2): the place a proxied flow's first bytes were counted under, by the proxy's own name with no
    /// proxy yet, becomes the named flow's once its request is confirmed, its bytes kept: with the switch off its
    /// first hop's, with the switch on the destination's; and a second flow's is merged into the first's.
    #[test]
    fn the_place_the_first_bytes_were_counted_under_becomes_the_named_flows() {
        for logs in [false, true] {
            let (shared, clock, _) = telling_at(T);
            shared.tunnels.set(&TunnelSetting {
                log_destinations: logs,
                ..TunnelSetting::default()
            });
            learn(&shared, "203.0.113.5", "proxy.example.net");
            let reads = socks5_reads();
            let greeting = reads[0].len() as u64;
            let places = |shared: &Shared| -> Vec<(Option<String>, bool, u64)> {
                shared
                    .now_view(T + 3_500)
                    .apps
                    .iter()
                    .flat_map(|a| a.places.iter())
                    .map(|p| (p.flow.name.clone(), p.flow.proxy.is_some(), p.bytes[2][0]))
                    .collect()
            };
            let name = if logs {
                "example.com"
            } else {
                "proxy.example.net"
            };
            for (k, at_ms) in [(1u64, 0u64), (2, 2_000)] {
                let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
                clock.set(T + at_ms);
                relay(&shared, opened, &bytes, &[&reads[0]]);
                clock.set(T + at_ms + 1_500);
                shared.tell(&super::super::activity::tests::told(
                    T,
                    T + at_ms + 1_000,
                    &[(T, T + at_ms + 1_000, crate::states::State::InUse)],
                ));
                let before = places(&shared);
                assert!(
                    before.contains(&(Some("proxy.example.net".to_owned()), false, greeting)),
                    "placed under the proxy's name: {before:?}"
                );
                // The rest of the handshake, in the same flow's sniff: a new one reads it from the start.
                let mut sniff = Sniff::new(true, false);
                for read in &reads {
                    for found in sniff.feed(read) {
                        if let Found::Request(request) = found {
                            shared.declared(&opened, &request);
                        }
                    }
                }
                assert_eq!(
                    places(&shared),
                    vec![(Some(name.to_owned()), true, greeting * k)],
                    "{logs} {k}"
                );
            }
        }
    }
    /// One destination reached directly and through a proxy is two places in "Now".
    #[test]
    fn a_destination_reached_through_a_proxy_is_a_place_apart() {
        let shared = engine(true);
        learn(&shared, "93.184.216.34", "example.com");
        let (direct, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            direct,
            &bytes,
            &[&crate::tls::tests::hello("example.com", 1000)],
        );
        let (proxied, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, proxied, &bytes, &reads, SOCKS5_REPLY);
        let view = shared.now_view(T + 1_000);
        let places: Vec<_> = view.apps.iter().flat_map(|a| a.places.iter()).collect();
        assert_eq!(places.len(), 2, "{places:?}");
        assert_eq!(places.iter().filter(|p| p.flow.proxy.is_some()).count(), 1);
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

    /// The trackers' table of the tests: one tracker whose signature is `tracker\.example`.
    fn with_trackers(shared: &Shared) {
        let table = crate::trackers::NetworkSignatures::parse(
            "49\tTracker Co\t\thttps://tracker.example/\t\ttracker\\.example\n",
        )
        .ok()
        .map(Arc::new);
        let mut setting = lock(&shared.proxies).setting().clone();
        setting.trackers = table;
        shared.set_proxies(setting);
    }

    /// An SDK's `CONNECT` to its own server, which ignores it: the request alone names nothing (the fix
    /// round's S-M1). With no reply, or a refusing one, or another protocol's, the flow keeps its name, its
    /// address and the DNS name its trackers' mark is read on; a hello after it names the flow as its own.
    #[test]
    fn a_proxy_request_the_server_does_not_confirm_names_nothing() {
        for (logs, reply) in [
            (false, &b""[..]),
            (true, b""),
            (false, b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            (false, &[0x16, 3, 3, 0, 0x5a, 2, 0, 0][..]),
        ] {
            let shared = engine(logs);
            with_trackers(&shared);
            learn(&shared, "203.0.113.9", "sdk.tracker.example");
            let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 9], 443));
            let mut fake = b"CONNECT www.google.com:443 HTTP/1.1\r\n\r\n".to_vec();
            fake.extend_from_slice(&crate::tls::tests::hello("sdk.tracker.example", 1000));
            relay_replied(&shared, opened, &bytes, &[&fake], reply);
            let flow = live(&shared, opened.id);
            assert!(flow.proxy.is_none(), "{logs} {reply:?}");
            assert_eq!(flow.destination, at([203, 0, 113, 9], 443));
            assert_eq!(
                flow.name.as_deref(),
                Some("sdk.tracker.example"),
                "{reply:?}"
            );
            assert_ne!(flow.named_by, NamedBy::Proxy);
            assert!(
                !lock(&shared.live)
                    .get(&opened.id)
                    .is_some_and(|l| l.hidden || l.unkept)
            );
        }
    }

    /// A proxy the server confirmed, with the switch off: its first hop is shown live, by the server's own name, and
    /// keeps its trackers' marks; the log keeps the marks as the company only, never a name or an address, and
    /// nothing the request asked for is anywhere.
    #[test]
    fn a_confirmed_proxy_with_the_switch_off_keeps_its_trackers_mark() {
        let shared = engine(false);
        with_trackers(&shared);
        learn(&shared, "203.0.113.9", "sdk.tracker.example");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 9], 443));
        relay_replied(
            &shared,
            opened,
            &bytes,
            &[b"CONNECT www.google.com:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        let flow = live(&shared, opened.id);
        assert_eq!(flow.destination, at([203, 0, 113, 9], 443));
        assert_eq!(flow.name.as_deref(), Some("sdk.tracker.example"));
        let proxy = flow.proxy.unwrap_or_else(|| unreachable!("confirmed"));
        assert!(!proxy.left_out && proxy.asked.is_none());
        assert_eq!(proxy.proxy_name.as_deref(), Some("sdk.tracker.example"));
        assert_eq!(proxy.trackers, vec![49]);
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 1_000));
        assert!(holds(&snapshot, b"sdk.tracker.example") && !holds(&snapshot, b"www.google.com"));
        shared.finish(opened.id);
        shared.flush();
        let records = taken(&shared);
        assert!(
            records
                .iter()
                .any(|r| matches!(r, Record::Segment { flow, .. }
            if flow.proxy.as_ref().is_some_and(|p| p.trackers == [49] && p.left_out)))
        );
        assert!(
            !crate::log::batch(&records)
                .windows(7)
                .any(|w| w == b"tracker")
                && !holds(&crate::log::batch(&records), b"www.google.com")
        );
        // The destination asked for marks it too, and the inner hello's name, though neither names it.
        let shared = engine(false);
        with_trackers(&shared);
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 10], 1080));
        let mut request = vec![5, 1, 0, 5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.org");
        request.extend_from_slice(&443u16.to_be_bytes());
        relay_replied(
            &shared,
            opened,
            &bytes,
            &[
                &request,
                &crate::tls::tests::hello("cdn.tracker.example", 1000),
            ],
            &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        );
        let proxy = live(&shared, opened.id)
            .proxy
            .unwrap_or_else(|| unreachable!("confirmed"));
        assert_eq!(proxy.trackers, vec![49], "the inner hello's name marks it");
        // The destination asked for alone marks it.
        let shared = engine(false);
        with_trackers(&shared);
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 11], 3128));
        relay_replied(
            &shared,
            opened,
            &bytes,
            &[b"CONNECT ads.tracker.example:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        let proxy = live(&shared, opened.id)
            .proxy
            .unwrap_or_else(|| unreachable!("confirmed"));
        assert_eq!(
            proxy.trackers,
            vec![49],
            "the destination asked for marks it"
        );
    }

    /// A plain request in absolute form cannot be confirmed: its flow keeps its own address and names whatever
    /// the switch says, and says what it asked for only while the switch is on.
    #[test]
    fn a_plain_request_keeps_its_flows_own_address_and_names() {
        for logs in [true, false] {
            let shared = engine(logs);
            learn(&shared, "203.0.113.5", "cache.example.net");
            let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 8080));
            relay(
                &shared,
                opened,
                &bytes,
                &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
            );
            // Its seconds placed in "Now" before the switch changes.
            shared.tell(&super::super::activity::tests::told(
                T,
                T + 1_000,
                &[(T, T + 1_000, crate::states::State::InUse)],
            ));
            let flow = live(&shared, opened.id);
            assert_eq!(flow.destination, at([203, 0, 113, 5], 8080));
            assert_eq!(
                (flow.name.as_deref(), flow.named_by),
                (Some("cache.example.net"), NamedBy::Dns)
            );
            let proxy = flow.proxy.unwrap_or_else(|| unreachable!("read"));
            assert_eq!(proxy.kind, Kind::Forward);
            assert!(!proxy.left_out);
            assert_eq!(proxy.asked.is_some(), logs);
            // Turning the switch off later leaves out only what it asked for.
            shared.tunnels.set(&TunnelSetting::default());
            shared.hide_chained();
            let flow = live(&shared, opened.id);
            assert_eq!(flow.name.as_deref(), Some("cache.example.net"));
            assert!(flow.proxy.is_some_and(|p| p.asked.is_none()));
            let view = shared.now_view(T + 1_000);
            assert!(view.apps.iter().any(|a| {
                a.places.iter().any(|p| {
                    p.flow.proxy.is_some() && p.flow.name.as_deref() == Some("cache.example.net")
                })
            }));
        }
    }

    /// A destination asked for by its address alone, with no DNS answer held for it, names the flow by that
    /// address, never by the proxy's (the fix round's R-m2).
    #[test]
    fn a_destination_asked_for_by_address_names_the_flow_by_it() {
        let shared = engine(true);
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        relay_replied(
            &shared,
            opened,
            &bytes,
            &[&[5, 1, 0, 5, 1, 0, 1, 198, 51, 100, 7, 1, 187]],
            &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        );
        let flow = live(&shared, opened.id);
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("198.51.100.7"), NamedBy::Proxy)
        );
    }

    /// Only a stream that starts as TLS is copied for its hello: a flow not read for proxies, as the user's
    /// tool's upstream with its password, and a proxy's inner stream that is not TLS, copy nothing (the fix
    /// round's S-m6).
    #[test]
    fn only_a_stream_that_starts_as_tls_is_copied() {
        let mut tool = Sniff::new(false, false);
        for read in socks5_reads() {
            tool.feed(&read);
        }
        assert_eq!(tool.copied, 0);
        assert!(tool.done());
        let mut inner = Sniff::new(true, false);
        let mut bytes = b"CONNECT example.org:80 HTTP/1.1\r\n\r\n".to_vec();
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\nAuthorization: Basic aHVudGVy\r\n\r\n");
        inner.feed(&bytes);
        inner.feed(b"more");
        assert_eq!(inner.copied, 0);
        // The request alone in one read, the inner stream's first bytes in the next.
        let mut later = Sniff::new(true, false);
        later.feed(b"CONNECT example.org:80 HTTP/1.1\r\n\r\n");
        later.feed(b"GET / HTTP/1.1\r\nAuthorization: Basic aHVudGVy\r\n\r\n");
        assert_eq!(later.copied, 0);
        let mut tls = Sniff::new(false, false);
        let hello = crate::tls::tests::hello("example.com", 1000);
        assert!(matches!(&tls.feed(&hello)[..], [Found::Hello(..)]));
        assert_eq!(tls.copied, hello.len());
    }

    /// Cuts the live view's quarter hour and has the states told, so that a flow's segment is written: the
    /// log's records then, held back or not.
    fn cut_and_tell(shared: &Shared, clock: &super::super::clock::ManualClock) {
        use super::super::clock::Clock;
        let now = clock.wall_ms();
        let next =
            (now / super::super::logbook::SEGMENT_MS + 1) * super::super::logbook::SEGMENT_MS;
        clock.pass(next - now + 1_000);
        shared.log_now();
        shared.tell(&super::super::activity::tests::told(
            T,
            clock.wall_ms(),
            &[(T, clock.wall_ms(), crate::states::State::InUse)],
        ));
    }

    /// A Telegram CDN flow opened before its main data centre, as after a hand-over, and taken back by it, with
    /// the switch on and off (S-M2): it is again what it would have been, live, in "Now", in the segment cut
    /// meanwhile, which the log got held back, and in the records after.
    #[test]
    fn a_name_taken_back_leaves_no_statement_of_it_anywhere() {
        use super::super::clock::Clock;
        for logs in [false, true] {
            let (shared, clock) = engine_at(logs);
            telegram(&shared);
            learn(&shared, "93.184.216.34", "cdn.example.net");
            let (cdn, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
            relay(&shared, cdn, &bytes, &[&obfuscated()]);
            assert!(live(&shared, cdn.id).proxy.is_some());
            assert!(
                !live(&shared, cdn.id).destination.ip().is_unspecified(),
                "its first hop, either way"
            );
            // A quarter hour cuts its segment, whose states are told: the log does not get it yet.
            cut_and_tell(&shared, &clock);
            bytes.up(&shared, 500, 540);
            assert!(
                !lock(&shared.pending_log)
                    .iter()
                    .any(|r| matches!(r, Record::Segment { flow, .. } if flow.id == cdn.id)),
                "held back for its window"
            );
            // The main data centre opens: the CDN flow's name is taken back.
            let (main, bytes2) = open(&shared, UID, at([149, 154, 167, 51], 443));
            relay(&shared, main, &bytes2, &[&obfuscated()]);
            let flow = live(&shared, cdn.id);
            assert!(flow.proxy.is_none(), "{logs}");
            assert_eq!(flow.destination, at([93, 184, 216, 34], 443));
            assert_eq!(flow.name.as_deref(), Some("cdn.example.net"));
            assert!(
                !lock(&shared.live)
                    .get(&cdn.id)
                    .is_some_and(|l| l.hidden || l.unkept)
            );
            let view = shared.now_view(clock.wall_ms());
            let places: Vec<_> = view.apps.iter().flat_map(|a| a.places.iter()).collect();
            assert!(places.iter().all(|p| p.flow.proxy.is_none()), "{places:?}");
            assert!(
                places
                    .iter()
                    .any(|p| p.flow.name.as_deref() == Some("cdn.example.net")),
                "{places:?}"
            );
            // Every record of it the log gets says what it is, and nothing of a proxy.
            shared.finish(cdn.id);
            shared.flush();
            let records = taken(&shared);
            let of_cdn: Vec<_> = records
                .iter()
                .filter_map(|r| match r {
                    Record::Segment { flow, .. } if flow.id == cdn.id => Some(flow),
                    _ => None,
                })
                .collect();
            assert!(of_cdn.len() >= 2, "{logs} {of_cdn:?}");
            assert!(
                of_cdn.iter().all(|f| f.proxy.is_none()
                    && f.name.as_deref() == Some("cdn.example.net")
                    && f.destination == at([93, 184, 216, 34], 443)),
                "{logs} {of_cdn:?}"
            );
        }
    }

    /// A take-back restores the name a cover hello would have given: the hello names the flow as any does.
    #[test]
    fn a_cover_taken_back_names_its_flow_as_any_hello_does() {
        let shared = engine(false);
        telegram(&shared);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&shared, flow.id).proxy.is_some());
        let (main, bytes) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, main, &bytes, &[&obfuscated()]);
        let flow = live(&shared, flow.id);
        assert!(flow.proxy.is_none());
        assert_eq!(
            (flow.name.as_deref(), flow.named_by),
            (Some("www.google.com"), NamedBy::Tls)
        );
    }

    /// The instants of a messenger's direct connections cross to the next engine (S-M2): a CDN flow opened
    /// before Telegram's main data centre right after a hand-over is not named its proxy.
    #[test]
    fn the_direct_instants_cross_the_hand_over() {
        use super::super::clock::Clock;
        let (before, clock) = engine_at(true);
        telegram(&before);
        let (main, bytes) = open(&before, UID, at([149, 154, 167, 51], 443));
        relay(&before, main, &bytes, &[&obfuscated()]);
        // A minute later it is still open: it counts as the moment of the hand-over, not of its opening.
        clock.pass(60_000);
        let instants = lock(&before.proxies).direct_instants(clock.since_boot());
        assert_eq!(
            instants,
            vec![(UID, clock.since_boot())],
            "an open one counts as now"
        );
        let after = engine(true);
        telegram(&after);
        lock(&after.proxies).carry_direct(instants);
        let (cdn, bytes) = open(&after, UID, at([93, 184, 216, 34], 443));
        relay(&after, cdn, &bytes, &[&obfuscated()]);
        assert!(live(&after, cdn.id).proxy.is_none());
        assert_eq!(after.counters.snapshot()[64], 1, "substituted");
    }

    /// "Tied" is tested from the name's side (S-M3): a Telegram hello for a name an answer gave this address,
    /// though a later answer re-pointed it to another name (`www.youtube.com`, then `i.ytimg.com`), names its
    /// flow and is no cover; so is one for a name the app looked up through the network part, whatever address it got.
    #[test]
    fn a_re_pointed_address_keeps_its_names_tied_for_telegram() {
        let shared = engine(true);
        telegram(&shared);
        looked_up(&shared, UID, "www.youtube.com", [93, 184, 216, 34]);
        // Another app's lookup gives the address to another name.
        learn(&shared, "93.184.216.34", "i.ytimg.com");
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.youtube.com", 1000)],
        );
        let flow = live(&shared, flow.id);
        assert!(flow.proxy.is_none(), "{flow:?}");
        assert_eq!(flow.name.as_deref(), Some("www.youtube.com"));
        // A name it looked up, reached at an address no answer gave it.
        looked_up(&shared, UID, "t.me", [93, 184, 216, 50]);
        let (other, bytes) = open(&shared, UID, at([93, 184, 216, 51], 443));
        relay(
            &shared,
            other,
            &bytes,
            &[&crate::tls::tests::hello("t.me", 1000)],
        );
        assert!(live(&shared, other.id).proxy.is_none());
        // A cover never looked up stays one.
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 52], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&shared, proxy.id).proxy.is_some());
    }

    /// The same for `WhatsApp` (S-M3): a link preview whose address was re-pointed, and the backup's
    /// `www.googleapis.com` and `oauth2.googleapis.com` on one address, are no cover.
    #[test]
    fn a_re_pointed_address_keeps_its_names_tied_for_whatsapp() {
        let shared = engine(true);
        whatsapp(&shared);
        looked_up(&shared, UID, "news.example.com", [93, 184, 216, 34]);
        learn(&shared, "93.184.216.34", "cdn.example.com");
        learn(&shared, "93.184.216.35", "www.googleapis.com");
        learn(&shared, "93.184.216.35", "oauth2.googleapis.com");
        for (address, name) in [
            ([93, 184, 216, 34], "news.example.com"),
            ([93, 184, 216, 35], "www.googleapis.com"),
            ([93, 184, 216, 35], "oauth2.googleapis.com"),
        ] {
            let (flow, bytes) = open(&shared, UID, at(address, 443));
            relay(
                &shared,
                flow,
                &bytes,
                &[&crate::tls::tests::hello(name, 1000)],
            );
            let flow = live(&shared, flow.id);
            assert!(flow.proxy.is_none(), "{name}");
            assert_eq!(flow.name.as_deref(), Some(name));
        }
    }

    /// Where the network part does not see the app's lookups, an untied hello is no evidence (S-M3): under strict
    /// Private DNS, or for an app whose lookups never passed through the network part in the window, the hello names
    /// its flow.
    #[test]
    fn an_untied_hello_counts_only_where_the_engine_sees_the_apps_lookups() {
        // Strict Private DNS, though the app looked a name up before.
        let shared = engine(true);
        let mut setting = ProxySetting {
            messengers: vec![(Family::Telegram, UID)],
            strict_dns: true,
            ..ProxySetting::default()
        };
        shared.set_proxies(setting.clone());
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&shared, flow.id).proxy.is_none());
        assert_eq!(
            live(&shared, flow.id).name.as_deref(),
            Some("www.google.com")
        );
        // Not strict: the same hello is a cover.
        setting.strict_dns = false;
        shared.set_proxies(setting);
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 35], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&shared, flow.id).proxy.is_some());
        // An app whose lookups never pass through the network part, as one with its own DNS over HTTPS.
        let (quiet, clock) = engine_at(true);
        telegram(&quiet);
        let (flow, bytes) = open(&quiet, UID, at([93, 184, 216, 34], 443));
        relay(
            &quiet,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&quiet, flow.id).proxy.is_none());
        // Its last lookup through the network part is older than the window: no evidence either.
        looked_up(&quiet, UID, "web.example.org", [93, 184, 216, 99]);
        clock.pass(u64::try_from(SUBSTITUTION.as_millis()).unwrap_or(0) + 1_000);
        let (flow, bytes) = open(&quiet, UID, at([93, 184, 216, 36], 443));
        relay(
            &quiet,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert!(live(&quiet, flow.id).proxy.is_none());
    }

    /// A hello is never lost (S-M3): while substitution holds, an untied hello names its flow as any does.
    #[test]
    fn a_hello_names_its_flow_while_substitution_holds() {
        let shared = engine(true);
        telegram(&shared);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (main, bytes) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, main, &bytes, &[&obfuscated()]);
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("embed.example.net", 1000)],
        );
        let flow = live(&shared, flow.id);
        assert!(flow.proxy.is_none());
        assert_eq!(flow.name.as_deref(), Some("embed.example.net"));
        assert_eq!(shared.counters.snapshot()[66], 0, "no cover kept out");
    }

    /// A take-back rewrites the segments that still wait for their states (S-M2): cut at a quarter hour while the
    /// flow was named a proxy and left out, they are written as the flow it was.
    #[test]
    fn a_take_back_rewrites_the_segments_that_wait_for_their_states() {
        use super::super::clock::Clock;
        let (shared, clock) = engine_at(false);
        telegram(&shared);
        learn(&shared, "93.184.216.34", "cdn.example.net");
        let (cdn, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(&shared, cdn, &bytes, &[&obfuscated()]);
        let now = clock.wall_ms();
        let next =
            (now / super::super::logbook::SEGMENT_MS + 1) * super::super::logbook::SEGMENT_MS;
        clock.pass(next - now + 1_000);
        shared.log_now();
        let held = |shared: &Shared| -> Vec<Flow> {
            lock(&shared.activity)
                .held
                .iter()
                .filter_map(|p| match &p.of {
                    super::super::activity::Of::Flow { flow, .. } if flow.id == cdn.id => {
                        Some(flow.clone())
                    }
                    _ => None,
                })
                .collect()
        };
        assert!(
            held(&shared).iter().any(|f| f.proxy.is_some()),
            "a segment waits"
        );
        let (main, bytes) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, main, &bytes, &[&obfuscated()]);
        let waiting = held(&shared);
        assert_ne!(waiting.len(), 0, "a segment still waits");
        assert!(
            waiting.iter().all(|f| f.proxy.is_none()
                && f.destination == at([93, 184, 216, 34], 443)
                && f.name.as_deref() == Some("cdn.example.net")),
            "{waiting:?}"
        );
    }

    /// The records of the flow `id` among `records`.
    fn of_flow(records: &[Record], id: u64) -> Vec<Flow> {
        records
            .iter()
            .filter_map(|r| match r {
                Record::Segment { flow, .. } if flow.id == id => Some(flow.clone()),
                _ => None,
            })
            .collect()
    }

    /// Whether a record's flow has the log's left-out shape: the proxy's kind and the facts that name nothing,
    /// with no address, port, name or network, and nothing of the proxy that names a place.
    fn left_out(flow: &Flow) -> bool {
        flow.destination.ip().is_unspecified()
            && flow.destination.port() == 0
            && flow.name.is_none()
            && flow.dns_name.is_none()
            && flow.network.is_none()
            && flow.proxy.as_ref().is_some_and(|p| {
                p.left_out
                    && p.asked.is_none()
                    && p.proxy_name.is_none()
                    && p.organisation.is_none()
                    && p.cover.is_none()
            })
    }

    /// The records held back for a take-back, of the flow `id`.
    fn held_back_of(shared: &Shared, id: u64) -> Vec<Flow> {
        of_flow(
            &lock(&shared.held_back)
                .records
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            id,
        )
    }

    /// Telegram's proxy inferred on a flow to Example Net's network, ended, and its records written: held back for
    /// their window of take-back.
    fn inferred_and_ended(shared: &Shared) -> u64 {
        telegram(shared);
        let (proxy, bytes) = open(shared, UID, at([93, 184, 216, 34], 443));
        relay(shared, proxy, &bytes, &[&obfuscated()]);
        shared.finish(proxy.id);
        shared.flush();
        assert!(
            of_flow(&taken(shared), proxy.id).is_empty(),
            "held back for the window"
        );
        assert_ne!(held_back_of(shared, proxy.id).len(), 0, "held back");
        proxy.id
    }

    /// Another app's flow, ended and written once the clock moved on: `to_log` runs, and lets go what waited.
    fn another_record(shared: &Shared) {
        let (other, bytes) = open(shared, UID + 1, at([198, 51, 100, 7], 443));
        bytes.up(shared, 10, 50);
        shared.finish(other.id);
        shared.flush();
    }

    fn switch(shared: &Shared, on: bool) {
        shared.tunnels.set(&TunnelSetting {
            log_destinations: on,
            ..TunnelSetting::default()
        });
        shared.hide_chained();
    }

    /// E1: with the switch off, an app's own proxy's records are stripped where they enter the log.
    #[test]
    fn with_the_switch_off_a_proxys_record_is_stripped_where_it_enters_the_log() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, opened, &bytes, &reads, SOCKS5_REPLY);
        shared.finish(opened.id);
        shared.flush();
        let written = of_flow(&taken(&shared), opened.id);
        assert!(
            !written.is_empty() && written.iter().all(left_out),
            "{written:?}"
        );
    }

    /// E2: records held back whole while the switch was on are stripped as `to_log` lets them go, once it is off.
    #[test]
    fn records_held_back_go_on_stripped_once_the_switch_is_off() {
        let (shared, clock) = engine_at(true);
        let id = inferred_and_ended(&shared);
        assert!(
            held_back_of(&shared, id).iter().all(|f| {
                f.destination == at([93, 184, 216, 34], 443)
                    && f.proxy.as_ref().is_some_and(|p| p.organisation.is_some())
            }),
            "held back whole while the switch is on"
        );
        switch(&shared, false);
        clock.pass(11 * 60_000);
        another_record(&shared);
        let written = of_flow(&taken(&shared), id);
        assert!(
            !written.is_empty() && written.iter().all(left_out),
            "{written:?}"
        );
    }

    /// E3: the same as the engine stops, whether it hands over or not: `release_held_back` strips too.
    #[test]
    fn records_held_back_are_stripped_when_the_engine_stops_once_the_switch_is_off() {
        for handing_over in [false, true] {
            let shared = engine(true);
            let id = inferred_and_ended(&shared);
            switch(&shared, false);
            shared
                .handing_over
                .store(handing_over, std::sync::atomic::Ordering::Relaxed);
            shared.finish_all();
            let written = of_flow(&taken(&shared), id);
            assert!(
                !written.is_empty() && written.iter().all(left_out),
                "{handing_over} {written:?}"
            );
        }
    }

    /// E5: a record made while the switch is off is held back already stripped, and turning the switch on before
    /// its window ends restores nothing.
    #[test]
    fn a_record_made_while_the_switch_is_off_stays_stripped_after_it_is_turned_on() {
        let (shared, clock) = engine_at(false);
        let id = inferred_and_ended(&shared);
        assert!(held_back_of(&shared, id).iter().all(left_out));
        switch(&shared, true);
        clock.pass(11 * 60_000);
        another_record(&shared);
        let written = of_flow(&taken(&shared), id);
        assert!(
            !written.is_empty() && written.iter().all(left_out),
            "{written:?}"
        );
    }

    /// E4 and F1: turning the switch off strips the records gathered for the next batch: an app's own proxy's to
    /// its kind, and a plain request's of where it asked to go.
    #[test]
    fn turning_the_switch_off_strips_the_batch_the_log_has_not_got_yet() {
        let shared = engine(true);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (socks, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(&shared, socks, &bytes, &reads, SOCKS5_REPLY);
        let (plain, bytes) = open(&shared, UID, at([203, 0, 113, 6], 8080));
        relay(
            &shared,
            plain,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        shared.finish(socks.id);
        shared.finish(plain.id);
        shared.flush();
        {
            let pending = lock(&shared.pending_log);
            let asked = |id| {
                of_flow(&pending, id)
                    .iter()
                    .all(|f| f.proxy.as_ref().is_some_and(|p| p.asked.is_some()))
            };
            assert!(asked(socks.id) && asked(plain.id), "{pending:?}");
        }
        switch(&shared, false);
        let records = taken(&shared);
        let socks = of_flow(&records, socks.id);
        assert!(!socks.is_empty() && socks.iter().all(left_out), "{socks:?}");
        let plain = of_flow(&records, plain.id);
        assert!(!plain.is_empty(), "{records:?}");
        assert!(
            plain
                .iter()
                .all(|f| f.destination == at([203, 0, 113, 6], 8080)
                    && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::Forward
                        && p.asked.is_none()
                        && !p.left_out)),
            "{plain:?}"
        );
    }

    /// Test 19 (W11): the inferred flows past their window of take-back leave memory at the next sweep, as a
    /// reading's: they hold the flow as it was before its naming, first hop and all.
    #[test]
    fn the_inferred_flows_past_their_window_leave_memory_at_a_sweep() {
        let (shared, clock) = engine_at(false);
        telegram(&shared);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(&shared, proxy, &bytes, &[&obfuscated()]);
        assert_eq!(lock(&shared.proxies).inferred.len(), 1);
        clock.pass(11 * 60_000);
        shared.tell(&super::super::activity::tests::told(T, T + 1_000, &[]));
        assert!(lock(&shared.proxies).inferred.is_empty());
    }

    /// A tracker the inner hello names marks the flow after its first seconds were placed: the place takes the mark
    /// with its flow, so that the open flow still matches it and its first hop stays in full.
    #[test]
    fn a_mark_from_the_inner_hello_keeps_the_place_with_its_flow() {
        use super::super::clock::Clock;
        let (shared, clock) = engine_at(false);
        with_trackers(&shared);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        let mut sniff = Sniff::new(true, false);
        let handshake = Mutex::new(Handshake::default());
        let reads = socks5_reads();
        for read in &reads[..3] {
            for found in sniff.feed(read) {
                shared.found(opened, found, &handshake);
            }
            bytes.up(&shared, read.len(), read.len() + 40);
        }
        shared.replied(opened, SOCKS5_REPLY, &handshake);
        clock.set(T + 1_500);
        shared.tell(&super::super::activity::tests::told(
            T,
            T + 1_000,
            &[(T, T + 1_000, crate::states::State::InUse)],
        ));
        for found in sniff.feed(&crate::tls::tests::hello("cdn.tracker.example", 1000)) {
            shared.found(opened, found, &handshake);
        }
        let view = shared.now_view(clock.wall_ms());
        let places: Vec<_> = view.apps.iter().flat_map(|a| a.places.iter()).collect();
        assert!(
            places.len() == 1
                && own_first_hop(&places[0].flow)
                && places[0]
                    .flow
                    .proxy
                    .as_ref()
                    .is_some_and(|p| p.trackers == [49]),
            "{places:?}"
        );
    }
}
