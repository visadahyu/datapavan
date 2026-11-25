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
use crate::proxies::{self, ASSOCIATE_REPLY, Asked, Declared, Kind, MAX_REPLY, Request};
use crate::socks5::Target;
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

/// The most flows remembered as taken back or substituted, for their records ([`TakenBack`]); past it the oldest is
/// forgotten, and a record of it that comes later still is written as it is.
const TAKEN_BACK: usize = 4096;

/// The most messenger apps whose direct connections are remembered, and the most of their flows open at once.
const MESSENGER_APPS: usize = 64;
const OPEN_DIRECT: usize = 4096;

/// The most trackers a proxied flow keeps the marks of (the log's and the snapshot's proxy block).
pub const MAX_TRACKERS: usize = 8;

/// The most `UDP ASSOCIATE`s of apps' own SOCKS5 proxies the engine ties relays to at once, and the most for each app
/// ([`Association`], audit-U M6): past an app's share, its own oldest is forgotten; past the whole, the oldest of the
/// app that holds the most, so that no app can push another's out.
const ASSOCIATIONS: usize = 256;
const ASSOCIATIONS_OF_APP: usize = 16;

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
    /// Whether the proxy's address is on the user's own network ([`crate::local`], R4): decided where the proxy is
    /// named, from the network beneath's on-link prefixes, and kept whatever the switch says, as a fact that names
    /// nothing (the proxy record's unit B).
    pub local: bool,
    /// Whether the engine could not tell this was a messenger's proxy: a flow it named one and took the name back from,
    /// or one it never named for substitution ([`TakenBack`]), left out as the proxy it was or would have been named.
    /// Set on records only, never on a live flow (the proxy record's unit B, the take-back's mark).
    pub unsure: bool,
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
    /// The network beneath's on-link prefixes and its transport, for the "local" fact ([`crate::local`]).
    pub on_link: crate::local::OnLink,
    /// The apps whose own proxies the user chose to log, by UID, as the network part hands them (R3, unit C).
    pub logged: Vec<u32>,
    /// The circumvention tools, by UID, as the network part tells them by signing key (unit B's B6): never chosen.
    pub tools: Vec<u32>,
    /// Android's PAC handler's UID, if one runs (unit B's B5): never chosen.
    pub pac_handler: Option<u32>,
}

/// The most apps whose own proxies the user can choose to log (R3): the live view's bound on apps.
const MAX_LOGGED: usize = 512;

/// R3, the proxy record's unit C: the application UIDs whose own proxies the user chose to log, sorted, never a tool's
/// nor Android's PAC handler's, at most [`MAX_LOGGED`]. A sorted slice and a binary search: it holds a few apps, and it
/// adds no map's code. The engine keeps it behind a leaf lock of its own (`Shared::kept_apps`), never under `proxies`,
/// whose holder `infer` takes `held_back` under it while the log's readers of this set hold `held_back`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct LoggedApps {
    apps: Box<[u32]>,
}

impl LoggedApps {
    /// The set the network part handed in `setting`: its application UIDs, but a tool's and the PAC handler's.
    fn of(setting: &ProxySetting) -> Self {
        let mut apps: Vec<u32> = setting
            .logged
            .iter()
            .copied()
            .filter(|&uid| {
                application(uid)
                    && !setting.tools.contains(&uid)
                    && setting.pac_handler != Some(uid)
            })
            .collect();
        apps.sort_unstable();
        apps.dedup();
        apps.truncate(MAX_LOGGED);
        Self {
            apps: apps.into_boxed_slice(),
        }
    }

    /// Whether the choice covers a flow of `uid` through `proxy`: its app was chosen (an SDK Runtime's follows its
    /// app), and the proxy is neither Android's setting nor on the user's own network, which no choice for one app
    /// covers. Both facts come from Android and the network part, never from the app's bytes (R8).
    fn covers(&self, uid: Option<u32>, proxy: &Proxied) -> bool {
        !proxy.setting
            && !proxy.local
            && uid.is_some_and(|uid| self.apps.binary_search(&app_of(uid)).is_ok())
    }

    /// Whether an app of this set is not in `after`: its choice was turned off, and what it kept goes (R6).
    fn lost(&self, after: &Self) -> bool {
        self.apps
            .iter()
            .any(|uid| after.apps.binary_search(uid).is_err())
    }
}

/// Whether `uid` is an application's, in any user's range of 100,000 (AOSP's `FIRST_APPLICATION_UID` to
/// `LAST_APPLICATION_UID`): Android's own UIDs, below, are shared by many parts and never chosen.
fn application(uid: u32) -> bool {
    (10_000..20_000).contains(&(uid % 100_000))
}

/// The app whose code a UID runs: an SDK Runtime sandbox's (AOSP's `FIRST_SDK_SANDBOX_UID` 20,000 to 29,999, ten
/// thousand above its app's, in each user's range), else the UID itself.
pub(super) fn app_of(uid: u32) -> u32 {
    if (20_000..30_000).contains(&(uid % 100_000)) {
        uid - 10_000
    } else {
        uid
    }
}

/// Whose own proxies keep their first hop and where they were asked to go, read once (`Shared::keeps_first_hops`):
/// every flow while "Log where these apps connect" is on, else the flows the user's choice for one app covers (R3).
/// A concrete type, not a closure, so that no `&dyn Fn` is built at each call.
#[derive(Clone, Debug, Default)]
pub(super) struct Keeps {
    all: bool,
    apps: Arc<LoggedApps>,
}

impl Keeps {
    /// Whether a flow of `uid` through `proxy` keeps its first hop and destination.
    pub(super) fn proxy(&self, uid: Option<u32>, proxy: Option<&Proxied>) -> bool {
        self.all || proxy.is_some_and(|p| self.apps.covers(uid, p))
    }

    /// [`Keeps::proxy`] for `flow`.
    pub(super) fn flow(&self, flow: &Flow) -> bool {
        self.proxy(flow.uid, flow.proxy.as_deref())
    }
}

/// A messenger app's direct connections to its maker's network: those open, and when the last one ended, in
/// time since the phone started.
struct Direct {
    open: HashSet<u64>,
    last: Option<Duration>,
}

impl Default for Direct {
    fn default() -> Self {
        Self {
            open: crate::set(),
            last: None,
        }
    }
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
    /// Its proxy as the log keeps it with the switch off, for its records once it is taken back ([`TakenBack`]).
    proxy: Proxied,
}

/// The names a messenger app looked up through the network part, as keyed hashes, each until the names' shortest
/// lifetime ([`crate::names::MIN_KEEP`]) after, and its last lookup, in time since the phone started.
#[derive(Default)]
struct LookedUp {
    names: std::collections::VecDeque<(u64, Duration)>,
    last: Duration,
}

/// A `UDP ASSOCIATE` an app's own SOCKS5 proxy confirmed, on its control flow (the proxy record's unit U): while that
/// flow is open, the app's UDP flows that go directly to the control flow's own server at the reply's `BND.PORT` are
/// that proxy's relay, and so its first hop. The tie is at the server the app's TCP flow reached and whose bytes
/// confirmed, never at the address the reply names (audit-U C1): a reply naming a third party's address ties nothing
/// there, so no app's server can make the app's plain UDP to anyone else read as a proxy's. It ends with its control
/// flow (RFC 1928, section 6), and is not handed over: a stop ends every flow first (audit-U M5).
struct Association {
    uid: u32,
    control: u64,
    server: IpAddr,
    port: u16,
    /// The control flow's facts that name nothing, which its relay's flows share.
    setting: bool,
    password: bool,
}

/// The engine's state of the inference.
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
    /// The `UDP ASSOCIATE`s whose relays are tied, oldest first, at most [`ASSOCIATIONS`].
    associations: Vec<Association>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            setting: ProxySetting::default(),
            families: crate::map(),
            direct: crate::map(),
            inferred: crate::map(),
            looked_up: crate::map(),
            third_party: crate::map(),
            hasher: crate::keys(),
            associations: Vec::new(),
        }
    }
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
pub(super) struct HeldBack {
    until: HashMap<u64, Duration>,
    records: std::collections::VecDeque<crate::log::Record>,
    taken_back: TakenBack,
}

impl Default for HeldBack {
    fn default() -> Self {
        Self {
            until: crate::map(),
            records: std::collections::VecDeque::new(),
            taken_back: TakenBack::default(),
        }
    }
}

impl HeldBack {
    /// None held back, with the flows taken back or substituted that an engine before handed over: their segments
    /// waiting for their states cross with them.
    pub(super) fn carrying(taken_back: TakenBack) -> Self {
        Self {
            taken_back,
            ..Self::default()
        }
    }

    /// The flows taken back or substituted, for the next engine.
    pub(super) fn take_taken_back(&mut self) -> TakenBack {
        std::mem::take(&mut self.taken_back)
    }

    /// The flows taken back or substituted.
    pub(super) fn taken_back(&self) -> &TakenBack {
        &self.taken_back
    }
}

/// The flows a messenger's direct connection took the name of its proxy back from, or that it never named for
/// substitution, by flow, each with the proxy it was or would have been named as the log keeps it with the switch off
/// (its kind, the facts that name nothing, the trackers' marks). While the app's first hops are not kept, their
/// records reach the log so, as every own proxy's: no proxy's address or cover in the history with the switch off
/// (the maintainer, 2026-11-24, review A's major 1; ADR 0052). The flow itself is shown in "Now" as it is. A mark
/// that the inference was taken back needs a flag of the log's next version (unit B). Bounded by [`TAKEN_BACK`],
/// the oldest forgotten first.
pub(super) struct TakenBack {
    proxies: HashMap<u64, Proxied>,
    order: std::collections::VecDeque<u64>,
}

impl Default for TakenBack {
    fn default() -> Self {
        Self {
            proxies: crate::map(),
            order: std::collections::VecDeque::new(),
        }
    }
}

impl TakenBack {
    fn insert(&mut self, id: u64, proxy: Proxied) {
        // Its records say that the engine could not tell (the take-back's mark, log version 7).
        let proxy = Proxied {
            unsure: true,
            ..proxy
        };
        if self.proxies.insert(id, proxy).is_none() {
            self.order.push_back(id);
            if self.order.len() > TAKEN_BACK
                && let Some(oldest) = self.order.pop_front()
            {
                self.proxies.remove(&oldest);
            }
        }
    }
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

    /// Notes `new`, within the bounds ([`ASSOCIATIONS`]): an app at its share forgets its own oldest; a full table, the
    /// oldest of the app that holds the most. Two of one relay are each kept, so that the tie goes only with the last.
    fn associate(&mut self, new: Association) {
        let mut held: HashMap<u32, usize> = crate::map();
        for a in &self.associations {
            *held.entry(a.uid).or_default() += 1;
        }
        let forgets = if held.get(&new.uid).copied().unwrap_or(0) >= ASSOCIATIONS_OF_APP {
            Some(new.uid)
        } else if self.associations.len() >= ASSOCIATIONS {
            held.iter().max_by_key(|&(_, &n)| n).map(|(&uid, _)| uid)
        } else {
            None
        };
        if let Some(uid) = forgets
            && let Some(oldest) = self.associations.iter().position(|a| a.uid == uid)
        {
            self.associations.remove(oldest);
        }
        self.associations.push(new);
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
/// not one, since nothing confirms it, and its flow keeps its own address and names as any flow does; except one to
/// Android's setting (R7, the proxy record's unit B), which is the user's shared proxy by its address or by a name
/// Android's resolver gave it, never by what the app wrote, and is left out as a confirmed proxy's.
pub(super) fn own_proxy(flow: &Flow) -> bool {
    flow.proxy
        .as_ref()
        .is_some_and(|p| p.kind != Kind::Forward || p.setting)
}

/// Whether `flow` shows an app's own proxy's first hop: its address and names, not left out. "Now" guards such a
/// place against floods of other places (R8), whatever the switch, and shows it only within its window while its
/// app's first hops are not kept ([`strips`]).
pub(super) fn own_first_hop(flow: &Flow) -> bool {
    own_proxy(flow) && flow.proxy.as_ref().is_some_and(|p| !p.left_out)
}

/// Whether "Now" shows `flow`'s first hop for its window only, `keeps` saying whose apps' first hops are kept: an
/// own proxy's first hop of an app whose are not. The window, the table of ends, the sweep and the snapshot's
/// mark all ask this, never the proxy's fields, so that units B and D widen it here alone.
pub(super) fn strips(flow: &Flow, keeps: &Keeps) -> bool {
    own_first_hop(flow) && !keeps.flow(flow)
}

/// Whether `flow` holds where the app asked its proxy to go: a SOCKS, `CONNECT` or plain request's flow with what it
/// asked for. Only a declared proxy can: an inferred one is named by its own address and hello, the proxy's own.
pub(super) fn holds_destination(flow: &Flow) -> bool {
    flow.proxy
        .as_ref()
        .is_some_and(|p| p.kind.declared() && p.asked.is_some())
}

/// Gives a record that names no proxy, written before its flow was named one, the log's left-out shape with `proxy`:
/// its kind and the facts that name nothing, so that the history says it went through one (finding 27). A segment cut
/// between a request and a slow reply is such a record, written as an ordinary flow's.
pub(super) fn strip_unnamed(record: &mut crate::log::Record, proxy: &Proxied) {
    if let crate::log::Record::Segment { flow, .. } = record
        && flow.proxy.is_none()
    {
        *flow = super::logbook::without_destination(&Flow {
            proxy: Some(Box::new(proxy.clone())),
            ..flow.clone()
        });
    }
}

/// What the log may keep of `record`, `keeps` saying whose apps' first hops are kept (R1): unkept, an app's own
/// proxy's flow keeps its kind and the facts that name nothing (`logbook::without_destination`, the left-out shape
/// the log already reads), a plain request keeps its own address and loses only where it asked to go, and a flow
/// taken back or substituted ([`TakenBack`]) keeps what it was or would have been named, as left out. `keeps` is
/// where unit C's choice for one app keeps such records whole.
pub(super) fn strip_for_log(
    record: &mut crate::log::Record,
    keeps: &Keeps,
    taken_back: &TakenBack,
) {
    let crate::log::Record::Segment { flow, .. } = record else {
        return;
    };
    // The take-back's mark, whatever the switch says now: a record stripped while it was off, and released after it
    // was turned on, keeps the left-out shape and must still say that the engine could not tell (review B-engine 1).
    mark_unsure(flow, taken_back);
    // A flow taken back has no proxy of its own: its would-be proxy's facts decide (unit C).
    let proxy = flow
        .proxy
        .as_deref()
        .or_else(|| taken_back.proxies.get(&flow.id));
    if keeps.proxy(flow.uid, proxy) {
        return;
    }
    match flow.proxy.as_deref() {
        Some(proxy) if proxy.kind == Kind::Forward && proxy.setting && !proxy.left_out => {
            *flow = super::logbook::without_destination(flow);
        }
        Some(proxy) if proxy.kind == Kind::Forward => {
            if proxy.asked.is_some() {
                let unasked = proxy.without_asked();
                flow.proxy = Some(Box::new(unasked));
            }
        }
        Some(proxy) if !proxy.left_out => *flow = super::logbook::without_destination(flow),
        Some(_) => {}
        None => {
            if let Some(proxy) = taken_back.proxies.get(&flow.id) {
                strip_unnamed(record, proxy);
            }
            return;
        }
    }
    mark_unsure(flow, taken_back);
}

/// Marks `flow`'s record unsure where it is left out as an inferred proxy and the flow was taken back or substituted
/// ([`TakenBack`]): also as it entered the log or while it was held back, the engine no longer holds that it was one
/// (the take-back's mark, audit-B 5).
fn mark_unsure(flow: &mut Flow, taken_back: &TakenBack) {
    if taken_back.proxies.contains_key(&flow.id)
        && let Some(proxy) = flow.proxy.as_deref_mut()
        && proxy.left_out
        && !proxy.kind.declared()
    {
        proxy.unsure = true;
    }
}

impl Shared {
    /// Sets what the network part tells for the proxies ([`ProxySetting`]); the open flows keep how they were named.
    /// The set of chosen apps is built before `proxies` is locked and swapped after it is let go, one lock after the
    /// other, never one inside the other (unit C, C2). Whether an app left that set, whose kept first hops and
    /// destinations must then go ([`super::Engine::proxies`]).
    /// [`Shared::set_proxies`], as the network part hands it (`Engine::proxies`): an app that left the user's choice
    /// loses at once what it kept (R6), as a switch turned off strips.
    pub(super) fn apply_proxies(&self, setting: ProxySetting) {
        if self.set_proxies(setting) {
            self.leave_out_first_hops();
        }
    }

    pub(super) fn set_proxies(&self, setting: ProxySetting) -> bool {
        let logged = Arc::new(LoggedApps::of(&setting));
        {
            let mut state = lock(&self.proxies);
            state.families = crate::map();
            state
                .families
                .extend(setting.messengers.iter().map(|&(f, uid)| (uid, f)));
            state.setting = setting;
        }
        let before = std::mem::replace(&mut *lock(&self.kept_apps), Arc::clone(&logged));
        before.lost(&logged)
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

    /// Whose own proxies keep their first hop and where they were asked to go, as the switch and the user's choice for
    /// single apps read at this moment ([`Keeps`]). Each caller reads it once, under the lock that orders it against a
    /// change of the switch, and asks it for each flow. Both are leaves: the tunnels' table and `kept_apps`.
    pub(super) fn keeps_first_hops(&self) -> Keeps {
        Keeps {
            all: self.logs_own_proxies(),
            apps: Arc::clone(&lock(&self.kept_apps)),
        }
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
                // An address of the user's own network is no company's network: a proxy on it is outside Meta's. So
                // is a private address off the link, as on a cellular network (review B-engine, minor 3): no company's
                // public network either.
                if self.local(address) || private_address(address) {
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
    /// that wait for their states, and the records held back from the log, are rewritten so. But the log keeps no
    /// proxy's address or cover of it with the switch off (the maintainer, 2026-11-24): a record stripped as it
    /// entered stays so, and the others reach the log left out as it was named while its app's first hops are not
    /// kept ([`TakenBack`]).
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
        self.taken_back(id, inferred.proxy.clone());
        let mut back = lock(&self.held_back);
        back.until.remove(&id);
        for record in &mut back.records {
            let crate::log::Record::Segment { flow, .. } = record else {
                continue;
            };
            // A record stripped as it entered the log stays so: what was not logged is not logged after a take-back
            // either (the maintainer, 2026-11-24).
            if flow.id == id && !flow.proxy.as_ref().is_some_and(|p| p.left_out) {
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
            taken_back,
        } = &mut *back;
        let mut kept = std::collections::VecDeque::with_capacity(held.len());
        for mut record in held.drain(..) {
            if record_flow(&record).is_some_and(|id| until.contains_key(&id)) {
                kept.push_back(record);
            } else {
                strip_for_log(&mut record, &keeps, taken_back);
                pending.push(record);
            }
        }
        for mut record in records.drain(..) {
            // Before it is held back too: a record made while the switch is off is never kept whole, even if the
            // switch is turned on before its window ends.
            strip_for_log(&mut record, &keeps, taken_back);
            if record_flow(&record).is_some_and(|id| until.contains_key(&id)) {
                kept.push_back(record);
                if kept.len() > HELD_BACK
                    && let Some(mut oldest) = kept.pop_front()
                {
                    strip_for_log(&mut oldest, &keeps, taken_back);
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
        let HeldBack {
            records,
            taken_back,
            ..
        } = &mut *back;
        for mut record in records.drain(..) {
            strip_for_log(&mut record, &keeps, taken_back);
            pending.push(record);
        }
    }

    /// The flow `id` was taken back, or never named its messenger's proxy for substitution: its records reach the log as
    /// `proxy`, left out, while its app's first hops are not kept ([`TakenBack`]), those already gathered for the next
    /// batch too.
    fn taken_back(&self, id: u64, proxy: Proxied) {
        let mut back = lock(&self.held_back);
        back.taken_back.insert(id, proxy);
        let mut pending = lock(&self.pending_log);
        let keeps = self.keeps_first_hops();
        for record in pending.iter_mut() {
            if record_flow(record) == Some(id) {
                strip_for_log(record, &keeps, &back.taken_back);
            }
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
        // A `UDP ASSOCIATE` ends with its control flow (RFC 1928, section 6).
        state.associations.retain(|a| a.control != id);
        now
    }

    /// Every flow ended, as when the engine stops: none can be taken back after. The time since the phone started,
    /// as [`Shared::proxies_ended`] gives it, read once for every flow.
    pub(super) fn proxies_all_ended(&self) -> Duration {
        let now = self.clock.since_boot();
        let mut state = lock(&self.proxies);
        state.inferred.clear();
        state.associations.clear();
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
                let mut activity = lock(&self.activity);
                activity.counts.rename_place(was.uid, &was, &live.flow);
                // The segments cut since its naming too, so that its end, which has the marks, matches them, and the
                // sweep does not strip them at once (review A, engine, note 11).
                for piece in &mut activity.held {
                    if let super::activity::Of::Flow {
                        flow,
                        hidden: false,
                        ..
                    } = &mut piece.of
                        && flow.id == id
                    {
                        mark(flow);
                    }
                }
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
        let setting = self.android_setting(destination);
        let organisation = self.organisation(destination.ip());
        // The destination asked for names the flow: a name as it is, an address by the DNS answer it was
        // given for this app, if one is held, else by the address asked for itself, never by the proxy's (the
        // fix round's R-m2). A `UDP ASSOCIATE` asks for none: its `DST` is the client's own source (audit-U M1), and
        // its control flow keeps its own server's names whatever the switch says.
        let name = (!request.associate).then(|| match &request.asked {
            Asked::Name(name) => name.clone(),
            Asked::Address(address) => lock(&self.names)
                .get(*address, opened.uid, Instant::now())
                .map_or_else(|| address.to_string(), str::to_owned),
        });
        let mut hosts = Self::hosts_of(current.as_ref(), destination);
        if let Some(name) = &name {
            hosts.push((name.clone(), request.port));
        }
        let proxied = Proxied {
            kind: request.kind,
            setting,
            password: request.password,
            outside_maker: false,
            asked: name
                .is_some()
                .then(|| (request.asked.clone(), request.port)),
            proxy_name,
            organisation: organisation.as_ref().map(|(_, n)| n.clone()),
            cover: None,
            left_out: false,
            trackers: self.marks(&hosts),
            local: self.local(destination.ip()),
            unsure: false,
        };
        let network = organisation.map(|(network, _)| network);
        self.name_proxied((opened, Some(&proxied)), current.as_ref(), |flow, kept| {
            flow.network = network;
            match &name {
                Some(name) if kept => {
                    flow.name = Some(name.clone());
                    flow.named_by = NamedBy::Proxy;
                    flow.dns_name = None;
                    flow.proxy = Some(Box::new(proxied.clone()));
                }
                _ => flow.proxy = Some(Box::new(proxied.without_asked())),
            }
        });
    }

    /// A `UDP ASSOCIATE` that the server of the flow `opened` confirmed named `bound` as its relay (unit U): the
    /// association is noted, for the app's UDP flows to its relay, before the reply reaches the app. Only on a flow
    /// read for proxies (it went directly, and is not the user's tool's) of an app Android named (audit-U m3), whose
    /// confirmed SOCKS5 proxy names it already. The relay is the control flow's own server at `BND.PORT`: a `BND.ADDR`
    /// elsewhere is counted, never tied there (audit-U C1), and a name there is tied by its port alone too.
    #[cold]
    #[inline(never)]
    fn associated(&self, opened: &Opened, bound: &Target) {
        let Some(uid) = opened.uid.filter(|_| opened.sniffs) else {
            return;
        };
        let Some(control) = self
            .flow_of(opened.id)
            .and_then(|f| f.proxy)
            .filter(|p| p.kind == Kind::Socks5)
        else {
            return;
        };
        let server = opened.destination.ip().to_canonical();
        let (elsewhere, port) = match bound {
            Target::Address(relay) => {
                let at = relay.ip().to_canonical();
                (!at.is_unspecified() && at != server, relay.port())
            }
            Target::Name(_, port) => (true, *port),
        };
        // A port of 0 names no relay: nothing is tied, and nothing counted.
        if port == 0 {
            return;
        }
        if elsewhere {
            Counters::add(&self.counters.proxy_relays_elsewhere, 1);
        }
        Counters::add(&self.counters.proxy_associations, 1);
        lock(&self.proxies).associate(Association {
            uid,
            control: opened.id,
            server,
            port,
            setting: control.setting,
            password: control.password,
        });
    }

    /// Gives `flow`, a new UDP flow that goes directly (`udp::begin_udp`'s callers), its app's own SOCKS5 proxy, when it
    /// goes to the relay of one of the app's open associations ([`Association`]), or comes in from that server on any
    /// port (audit-U m4): the proxy's kind and its first hop, the relay's own names and network, the facts that name
    /// nothing, and the trackers' marks on the relay's names (audit-U M4). No `asked` yet, which only the first
    /// datagram's header can give ([`Shared::relay_asked`]): "Now" shows the first hop, and the log keeps what an own
    /// proxy's flow keeps, as for any own proxy (`strips`, `strip_for_log`). The proxies' lock is taken alone, under
    /// the UDP table's, and let go before the other facts are read, which take it again themselves. Once recorded, the
    /// flow is [`Shared::relay_recorded`]. Whether one was given.
    pub(super) fn tie_relay(&self, flow: &mut Flow, came_in: bool) -> bool {
        let Some(uid) = flow.uid else {
            return false;
        };
        let address = flow.destination.ip().to_canonical();
        let port = flow.destination.port();
        let Some((setting, password)) = lock(&self.proxies)
            .associations
            .iter()
            .rev()
            .find(|a| a.uid == uid && a.server == address && (came_in || a.port == port))
            .map(|a| (a.setting, a.password))
        else {
            return false;
        };
        let proxy_name = (flow.named_by == NamedBy::Dns)
            .then(|| flow.name.clone())
            .flatten();
        let organisation = self.organisation(address).map(|(_, name)| name);
        let trackers = self.marks(&Self::hosts_of(Some(flow), flow.destination));
        flow.proxy = Some(Box::new(Proxied {
            kind: Kind::Socks5,
            setting,
            password,
            outside_maker: false,
            asked: None,
            proxy_name,
            organisation,
            cover: None,
            left_out: false,
            trackers,
            local: self.local(address),
            unsure: false,
        }));
        true
    }

    /// A flow tied to its app's proxy's relay ([`Shared::tie_relay`]) was recorded: no hello names it, whatever the
    /// switch says, so that a hello its app sends on it, as plain QUIC to the relay's port, only adds its trackers'
    /// marks, and the record keeps them (review U-engine M1). Only its first datagram's SOCKS5 header can name it, with
    /// the switch on ([`Shared::relay_asked`]).
    pub(super) fn relay_recorded(&self, id: u64) {
        if let Some(live) = lock(&self.live).get_mut(&id) {
            live.unkept = true;
        }
    }

    /// The first datagram an app sent on a flow tied to its proxy's relay ([`Shared::tie_relay`]) named `target` in its
    /// SOCKS5 header (`socks5::parse_datagram`, which drops a fragment): its trackers' marks join the flow's, and while
    /// "Log where these apps connect" is on, it is where the flow asked to go, which names it, as a `CONNECT`'s request
    /// does (audit-U M3). Through [`Shared::name_proxied`], which reads the switch under the flow's lock and keeps an
    /// unkept flow unkept. Only the first datagram is read: later ones to other destinations are not followed (n4).
    pub(super) fn relay_asked(&self, opened: &Opened, target: &Target) {
        let (asked, port) = match target {
            Target::Address(at) => (Asked::Address(at.ip()), at.port()),
            Target::Name(name, port) => match proxies::host_name(name.as_bytes()) {
                Some(name) => (name, *port),
                None => return,
            },
        };
        self.log_now();
        let name = match &asked {
            Asked::Name(name) => name.clone(),
            Asked::Address(address) => lock(&self.names)
                .get(*address, opened.uid, Instant::now())
                .map_or_else(|| address.to_string(), str::to_owned),
        };
        let found = self.marks(&[(name.clone(), port)]);
        let current = self.flow_of(opened.id);
        let tied = current.as_ref().and_then(|f| f.proxy.as_deref());
        self.name_proxied((opened, tied), current.as_ref(), |flow, kept| {
            let Some(proxy) = flow
                .proxy
                .as_deref_mut()
                .filter(|p| p.kind == Kind::Socks5 && p.asked.is_none())
            else {
                return;
            };
            proxy.trackers.extend(&found);
            proxy.trackers.sort_unstable();
            proxy.trackers.dedup();
            proxy.trackers.truncate(MAX_TRACKERS);
            if kept {
                proxy.asked = Some((asked.clone(), port));
                flow.name = Some(name.clone());
                flow.named_by = NamedBy::Proxy;
                flow.dns_name = None;
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
            setting: self.android_setting(destination),
            password: request.password,
            outside_maker: false,
            asked: Some((request.asked.clone(), request.port)),
            proxy_name: None,
            organisation: None,
            cover: None,
            left_out: false,
            trackers: self.marks(&hosts),
            local: self.local(destination.ip()),
            unsure: false,
        };
        self.name_proxied((opened, Some(&proxied)), None, |flow, kept| {
            flow.proxy = Some(Box::new(if kept {
                proxied.clone()
            } else {
                proxied.without_asked()
            }));
        });
    }

    /// Whether Android's proxy setting names the proxy at `destination`: by its address, or by a name of the setting
    /// that Android's resolver gave this address, the shared scope of the names, never an app's own resolver's answer
    /// (audit M5): otherwise an app's own resolver could make its own server read as the proxy in Android's settings.
    /// The setting's hosts are copied out before the names are asked, so that no lock is held under another.
    fn android_setting(&self, destination: std::net::SocketAddr) -> bool {
        let address = destination.ip().to_canonical();
        let hosts: Vec<String> = lock(&self.proxies)
            .setting
            .android
            .iter()
            .filter(|(_, port)| *port == destination.port())
            .map(|(host, _)| host.clone())
            .collect();
        if hosts
            .iter()
            .any(|host| host.parse::<IpAddr>().ok().map(|h| h.to_canonical()) == Some(address))
        {
            return true;
        }
        let names = lock(&self.names);
        hosts.iter().any(|host| {
            host.parse::<IpAddr>().is_err()
                && names.gave(address, None, host.trim_end_matches('.'), Instant::now())
        })
    }

    /// Whether the proxy at `address` is on the user's own network, by the network beneath's prefixes as told last.
    fn local(&self, address: IpAddr) -> bool {
        lock(&self.proxies).setting.on_link.is_local(address)
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
        let cover = hello.filter(|h| !h.name.is_empty()).map(|h| h.name.clone());
        let current = self.flow_of(opened.id);
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
            local: self.local(opened.destination.ip()),
            unsure: false,
        };
        if self.went_directly_lately(uid) {
            Counters::add(&self.counters.proxies_substituted, 1);
            // Named live as any flow is; logged as a flow taken back is (the maintainer, 2026-11-24).
            self.taken_back(opened.id, proxied.without_destination());
            return false;
        }
        Counters::add(&self.counters.proxies_inferred, 1);
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
                        proxy: proxied.without_destination(),
                    },
                );
                lock(&self.held_back).until.insert(opened.id, until);
            }
        }
        // An inferred proxy holds no destination: its flow is named by its own address and hello either way.
        self.name_proxied((opened, Some(&proxied)), current.as_ref(), |flow, _| {
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
    fn name_proxied(
        &self,
        (opened, proxy): (&Opened, Option<&Proxied>),
        before: Option<&Flow>,
        name: impl Fn(&mut Flow, bool),
    ) {
        let mut live = lock(&self.live);
        let kept = self.keeps_first_hops().proxy(opened.uid, proxy);
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
        if own
            && !kept
            && let Some(proxy) = flow.proxy.as_deref()
        {
            // Those held back for a take-back too: a messenger's segment cut before its inference can settle, and
            // be held back, between `infer`'s window and this naming (review A, engine, finding 3). In `to_log`'s
            // order: `held_back`, then `pending_log`.
            let mut back = lock(&self.held_back);
            let mut pending = lock(&self.pending_log);
            for record in back.records.iter_mut().chain(pending.iter_mut()) {
                if record_flow(record) == Some(opened.id) {
                    strip_unnamed(record, proxy);
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

/// Whether `address` is private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), whichever network it is on.
fn private_address(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(a) => a.is_private(),
        IpAddr::V6(a) => a.is_unique_local(),
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
/// and that hello names the flow as its own. A server that never answers confirms nothing. A confirmed `UDP
/// ASSOCIATE` is read on, across reads, until its reply's relay is whole ([`proxies::bound`], at most
/// [`ASSOCIATE_REPLY`] bytes; audit-U M2), in a buffer of its own on the heap ([`Binding`]): every TCP flow carries
/// this handshake in its relay, which keeps its 16 bytes.
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
    /// A `UDP ASSOCIATE` confirmed, its relay not read whole yet.
    Binding(Box<Binding>),
    Confirmed,
    Refused,
}

/// A confirmed `UDP ASSOCIATE`'s request, and its server's first bytes so far, at most [`ASSOCIATE_REPLY`].
struct Binding {
    request: Request,
    reply: Vec<u8>,
}

impl Binding {
    /// The step after `request`'s confirmation, by the server's first bytes `reply`.
    #[cold]
    #[inline(never)]
    fn start(request: &Request, reply: &[u8]) -> Step {
        let mut bytes = Vec::with_capacity(ASSOCIATE_REPLY);
        bytes.extend_from_slice(reply);
        Step::Binding(Box::new(Self {
            request: request.clone(),
            reply: bytes,
        }))
    }
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
            Step::Confirmed | Step::Binding(_) => Some(Settle::Hello(hello, true)),
            Step::Idle | Step::Refused => Some(Settle::Hello(hello, false)),
        }
    }

    /// The server sent `bytes`: what they settle, a confirmed `UDP ASSOCIATE`'s relay once its reply is whole, and
    /// whether its next bytes are still wanted.
    fn server(&mut self, bytes: &[u8]) -> (Option<Settle>, Option<Target>, bool) {
        let mut rest = bytes;
        let mut settled = None;
        if !matches!(self.step, Step::Binding(_)) {
            let take = bytes.len().min(MAX_REPLY - self.len);
            self.reply[self.len..self.len + take].copy_from_slice(&bytes[..take]);
            self.len += take;
            rest = &bytes[take..];
            settled = self.decide();
        }
        // Read only for a confirmed `UDP ASSOCIATE`, out of the relay's own code (the hot set, ADR 0053).
        let relay = if matches!(self.step, Step::Binding(_)) {
            self.bind(rest)
        } else {
            None
        };
        let wanted = match self.step {
            Step::Idle | Step::Waiting(..) => self.len < MAX_REPLY,
            Step::Binding(_) => true,
            Step::Confirmed | Step::Refused => false,
        };
        (settled, relay, wanted)
    }

    /// A confirmed `UDP ASSOCIATE`'s relay, `more` of the server's bytes read on: once the reply is whole, and then
    /// nothing more is read.
    #[cold]
    #[inline(never)]
    fn bind(&mut self, more: &[u8]) -> Option<Target> {
        let Step::Binding(binding) = &mut self.step else {
            return None;
        };
        let take = more
            .len()
            .min(ASSOCIATE_REPLY.saturating_sub(binding.reply.len()));
        binding.reply.extend_from_slice(&more[..take]);
        let relay = match proxies::bound(&binding.request, &binding.reply) {
            None if binding.reply.len() < ASSOCIATE_REPLY => return None,
            None => None,
            Some(relay) => relay,
        };
        self.step = Step::Confirmed;
        relay
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
            // Its control flow is named at once; its relay is read on.
            if request.associate {
                self.step = Binding::start(&request, &self.reply[..self.len]);
            }
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
        let (settled, relay, wanted) = lock(handshake).server(bytes);
        self.handshake_settled(opened, settled);
        if let Some(relay) = relay {
            self.associated(&opened, &relay);
        }
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
        // The flows a debug build keeps too (review A, engine, note 7).
        let seen = format!(
            "{:?}{pieces:?}{:?}",
            lock(&shared.live)
                .values()
                .map(|l| &l.flow)
                .collect::<Vec<_>>(),
            lock(&shared.flows)
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
            on_link: crate::local::OnLink::default(),
            logged: Vec::new(),
            tools: Vec::new(),
            pac_handler: None,
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

    /// The proxy record's unit B, M5: a name of Android's setting matches only by an answer of Android's resolver,
    /// never by one the app's own resolver gave, which would make the app's own server read as the setting; and a
    /// mapped address matches its IPv4 setting.
    #[test]
    fn an_apps_own_resolver_cannot_make_its_server_androids_setting() {
        let shared = engine(true);
        shared.set_proxies(ProxySetting {
            android: vec![
                ("proxy.example.net".into(), 8080),
                ("203.0.113.5".into(), 3128),
            ],
            ..ProxySetting::default()
        });
        // The app's own resolver says the setting's name is its own server.
        lock(&shared.names).insert(
            IpAddr::from([198, 51, 100, 9]),
            Some(UID),
            "proxy.example.net",
            600,
            (Instant::now(), shared.clock.since_boot()),
        );
        let (own, bytes) = open(&shared, UID, at([198, 51, 100, 9], 8080));
        relay_replied(
            &shared,
            own,
            &bytes,
            &[b"CONNECT example.org:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        assert_eq!(
            live(&shared, own.id).proxy.map(|p| (p.kind, p.setting)),
            Some((Kind::Connect, false))
        );
        // Android's resolver gives it to every app.
        learn(&shared, "198.51.100.10", "proxy.example.net");
        let (set, bytes) = open(&shared, UID, at([198, 51, 100, 10], 8080));
        relay_replied(
            &shared,
            set,
            &bytes,
            &[b"CONNECT example.org:443 HTTP/1.1\r\n\r\n"],
            CONNECTED,
        );
        assert_eq!(
            live(&shared, set.id).proxy.map(|p| (p.kind, p.setting)),
            Some((Kind::Connect, true))
        );
        let mapped = std::net::Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped();
        assert!(shared.android_setting(SocketAddr::from((mapped, 3128))));
        assert!(!shared.android_setting(SocketAddr::from((mapped, 3129))));
    }

    /// The proxy record's unit B, R4: "local" is decided where the proxy is named, by the network beneath's on-link
    /// prefixes and transport, and kept in the left-out record whatever the switch says.
    #[test]
    fn a_proxy_on_the_users_network_is_said_so_even_left_out() {
        use crate::local::{OnLink, Transport};
        let (shared, clock) = engine_at(false);
        shared.set_proxies(ProxySetting {
            on_link: OnLink::new([(IpAddr::from([100, 64, 7, 0]), 24)], Transport::Cellular),
            ..ProxySetting::default()
        });
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        let (on_link, bytes) = open(&shared, UID, at([100, 64, 7, 9], 1080));
        relay_replied(&shared, on_link, &bytes, &reads, SOCKS5_REPLY);
        // On a cellular network a private address off the link is not local.
        let (private, bytes) = open(&shared, UID, at([10, 0, 0, 9], 1080));
        relay_replied(&shared, private, &bytes, &reads, SOCKS5_REPLY);
        let (public, bytes) = open(&shared, UID, at([203, 0, 113, 5], 1080));
        relay_replied(&shared, public, &bytes, &reads, SOCKS5_REPLY);
        // A plain request and a messenger's inferred proxy on the link are local too (review B-engine, minor 2).
        let (plain, bytes) = open(&shared, UID, at([100, 64, 7, 10], 8080));
        relay(
            &shared,
            plain,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        let messenger = UID + 2;
        let mut setting = lock(&shared.proxies).setting().clone();
        setting.messengers = vec![(Family::Telegram, messenger)];
        shared.set_proxies(setting);
        let (inferred, bytes) = open(&shared, messenger, at([100, 64, 7, 11], 443));
        relay(&shared, inferred, &bytes, &[&obfuscated()]);
        let local = |id| live(&shared, id).proxy.map(|p| (p.kind, p.local));
        assert_eq!(
            (local(on_link.id), local(private.id), local(public.id)),
            (
                Some((Kind::Socks5, true)),
                Some((Kind::Socks5, false)),
                Some((Kind::Socks5, false))
            )
        );
        assert_eq!(
            (local(plain.id), local(inferred.id)),
            (Some((Kind::Forward, true)), Some((Kind::MtProto, true)))
        );
        for id in [on_link.id, private.id, public.id, plain.id, inferred.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let written = of_flow(&records, on_link.id);
        assert!(
            !written.is_empty()
                && written
                    .iter()
                    .all(|f| left_out(f) && f.proxy.as_ref().is_some_and(|p| p.local)),
            "{written:?}"
        );
        assert!(!holds(&crate::log::batch(&records), &[100, 64, 7, 9]));
    }

    /// The proxy record's unit B, R7: with the switch off, a plain request to Android's setting is left out of the
    /// record as a confirmed proxy's, while a plain request to another server keeps its own address.
    #[test]
    fn a_plain_request_to_androids_setting_is_left_out_of_the_record() {
        let (shared, clock) = engine_at(false);
        shared.set_proxies(ProxySetting {
            android: vec![("203.0.113.5".into(), 3128)],
            ..ProxySetting::default()
        });
        let (set, bytes) = open(&shared, UID, at([203, 0, 113, 5], 3128));
        relay(
            &shared,
            set,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        let (other, bytes) = open(&shared, UID, at([198, 51, 100, 7], 3128));
        relay(
            &shared,
            other,
            &bytes,
            &[b"GET http://example.org/a HTTP/1.1\r\n\r\n"],
        );
        // "Now" shows the setting's first hop in full, for its window.
        assert!(own_first_hop(&live(&shared, set.id)));
        assert!(!own_first_hop(&live(&shared, other.id)));
        for id in [set.id, other.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let batch = crate::log::batch(&records);
        assert!(!holds(&batch, &[203, 0, 113, 5]), "the setting's address");
        assert!(!holds(&batch, b"example.org"));
        let set_records = of_flow(&records, set.id);
        assert!(
            !set_records.is_empty()
                && set_records.iter().all(|f| left_out(f)
                    && f.proxy
                        .as_ref()
                        .is_some_and(|p| p.kind == Kind::Forward && p.setting)),
            "{set_records:?}"
        );
        let other_records = of_flow(&records, other.id);
        assert!(
            !other_records.is_empty()
                && other_records
                    .iter()
                    .all(|f| f.destination == at([198, 51, 100, 7], 3128)
                        && f.proxy
                            .as_ref()
                            .is_some_and(|p| !p.left_out && p.asked.is_none())),
            "{other_records:?}"
        );
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
        let _ = shared.set_proxies(ProxySetting {
            messengers: vec![(Family::Telegram, UID)],
            android: Vec::new(),
            trackers: None,
            strict_dns: false,
            on_link: crate::local::OnLink::default(),
            logged: Vec::new(),
            tools: Vec::new(),
            pac_handler: None,
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
            on_link: crate::local::OnLink::default(),
            logged: Vec::new(),
            tools: Vec::new(),
            pac_handler: None,
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
            on_link: crate::local::OnLink::default(),
            logged: Vec::new(),
            tools: Vec::new(),
            pac_handler: None,
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
            // With the switch on, every record of it the log gets says what it is, and nothing of a proxy. With it
            // off, every one keeps the kind and the facts it was inferred with, and no address or name (the
            // maintainer, 2026-11-24): what was not logged is not logged after a take-back either.
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
            if logs {
                assert!(
                    of_cdn.iter().all(|f| f.proxy.is_none()
                        && f.name.as_deref() == Some("cdn.example.net")
                        && f.destination == at([93, 184, 216, 34], 443)),
                    "{of_cdn:?}"
                );
            } else {
                // Every one, those cut before the take-back included, says that the engine could not tell
                // (audit-B 5).
                assert!(
                    of_cdn.iter().all(|f| left_out(f)
                        && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::MtProto
                            && p.outside_maker
                            && p.unsure)),
                    "{of_cdn:?}"
                );
            }
        }
    }

    /// Review B-engine, minor 1: R7's two strip points of a segment cut before the request: `name_proxied`'s strip of
    /// what waits for the log, with the switch off, and the switch-off pass's strip of such a segment, written while
    /// the switch was on. Neither leaves Android's setting's address in the log.
    #[test]
    fn a_segment_cut_before_a_plain_request_to_the_setting_is_left_out_too() {
        for switch_on_first in [false, true] {
            let (shared, clock) = engine_at(switch_on_first);
            shared.set_proxies(ProxySetting {
                android: vec![("203.0.113.5".into(), 3128)],
                ..ProxySetting::default()
            });
            let (opened, bytes) = open(&shared, UID, at([203, 0, 113, 5], 3128));
            bytes.up(&shared, 40, 80);
            cut_and_tell(&shared, &clock);
            let request: &[u8] = b"GET http://example.org/a HTTP/1.1\r\n\r\n";
            let mut sniff = Sniff::new(true, false);
            let handshake = Mutex::new(Handshake::default());
            for found in sniff.feed(request) {
                shared.found(opened, found, &handshake);
            }
            bytes.up(&shared, request.len(), request.len() + 40);
            if switch_on_first {
                switch(&shared, false);
            }
            shared.finish(opened.id);
            shared.flush();
            clock.pass(11 * 60_000);
            another_record(&shared);
            let records = taken(&shared);
            let written = of_flow(&records, opened.id);
            assert!(written.len() >= 2, "{switch_on_first}: {written:?}");
            assert!(
                written.iter().all(left_out),
                "{switch_on_first}: {written:?}"
            );
            assert!(!holds(&crate::log::batch(&records), &[203, 0, 113, 5]));
        }
    }

    /// Review B-engine 1: a record stripped while the switch was off keeps the take-back's mark when it reaches the log
    /// after the switch is turned on, whether the switch goes on before or after the take-back.
    #[test]
    fn a_record_stripped_before_the_switch_went_on_keeps_the_take_backs_mark() {
        for switch_first in [true, false] {
            let (shared, clock) = engine_at(false);
            telegram(&shared);
            learn(&shared, "93.184.216.34", "cdn.example.net");
            let (cdn, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
            relay(&shared, cdn, &bytes, &[&obfuscated()]);
            cut_and_tell(&shared, &clock);
            bytes.up(&shared, 500, 540);
            if switch_first {
                switch(&shared, true);
            }
            let (main, bytes2) = open(&shared, UID, at([149, 154, 167, 51], 443));
            relay(&shared, main, &bytes2, &[&obfuscated()]);
            if !switch_first {
                switch(&shared, true);
            }
            shared.finish(cdn.id);
            shared.flush();
            let records = taken(&shared);
            let stripped: Vec<_> = of_flow(&records, cdn.id)
                .into_iter()
                .filter(left_out)
                .collect();
            assert!(
                !stripped.is_empty(),
                "{switch_first}: a record stripped at entry"
            );
            assert!(
                stripped
                    .iter()
                    .all(|f| f.proxy.as_ref().is_some_and(|p| p.unsure)),
                "{switch_first}: {stripped:?}"
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
            on_link: crate::local::OnLink::default(),
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

    /// E7 (review A, engine, finding 2): a quarter hour cuts a SOCKS5 flow's segment before the server's reply, with the
    /// switch on, so that it waits for the log as an ordinary flow's; the reply confirms the proxy, kept; then the
    /// switch goes off before the batch is taken. The batch's record of it is stripped, with the proxy's kind.
    #[test]
    fn turning_the_switch_off_strips_a_segment_cut_before_its_naming() {
        let (shared, clock) = engine_at(true);
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
        shared.replied(opened, SOCKS5_REPLY, &handshake);
        assert!(
            of_flow(&lock(&shared.pending_log), opened.id)
                .iter()
                .any(|f| f.proxy.is_none() && f.name.as_deref() == Some("proxy.example.net")),
            "written as an ordinary flow's"
        );
        switch(&shared, false);
        let written = of_flow(&taken(&shared), opened.id);
        assert!(
            !written.is_empty()
                && written.iter().all(
                    |f| left_out(f) && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::Socks5)
                ),
            "{written:?}"
        );
    }

    /// Review A, engine, finding 3: a messenger's segment cut before its inference, held back for the take-back before
    /// the naming, is stripped by an unkept naming as the batch's are, with the proxy's kind.
    #[test]
    fn an_unkept_naming_strips_a_segment_held_back_before_it() {
        let shared = engine(false);
        telegram(&shared);
        learn(&shared, "93.184.216.34", "cdn.example.net");
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        // As if a reading had settled the segment, and `to_log` held it back, between `infer`'s window and its naming.
        lock(&shared.held_back).records.push_back(Record::Segment {
            flow: live(&shared, proxy.id),
            start: T,
            end: T + 1_000,
            bytes: [10, 0, 50, 0],
            continues: true,
            state: crate::states::Placed::Unknown(crate::states::Unknown::NotTold),
        });
        relay(&shared, proxy, &bytes, &[&obfuscated()]);
        let held = held_back_of(&shared, proxy.id);
        assert!(
            !held.is_empty()
                && held
                    .iter()
                    .all(|f| left_out(f)
                        && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::MtProto)),
            "{held:?}"
        );
    }

    /// The maintainer's decision of 2026-11-24 on review A's major 1: with the switch off, a fake-TLS proxy taken back
    /// by a direct connection is shown in "Now" as the flow it is, named by its hello, and the log gets no proxy's
    /// address and no cover of it: its records held back keep the kind they were stripped with, and its records after
    /// the take-back are left out as it would have been named. With the switch on, the log gets it whole, as before.
    #[test]
    fn a_take_back_writes_no_proxys_address_or_cover_with_the_switch_off() {
        for logs in [false, true] {
            let (shared, clock) = engine_at(logs);
            telegram(&shared);
            looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
            let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
            relay(
                &shared,
                proxy,
                &bytes,
                &[&crate::tls::tests::hello("www.google.com", 1000)],
            );
            cut_and_tell(&shared, &clock);
            let (main, direct) = open(&shared, UID, at([149, 154, 167, 51], 443));
            relay(&shared, main, &direct, &[&obfuscated()]);
            let flow = live(&shared, proxy.id);
            assert_eq!(
                (flow.proxy.is_none(), flow.name.as_deref()),
                (true, Some("www.google.com")),
                "shown as the flow it is"
            );
            bytes.up(&shared, 500, 540);
            shared.finish(proxy.id);
            shared.flush();
            let records = taken(&shared);
            let written = of_flow(&records, proxy.id);
            assert!(written.len() >= 2, "{logs} {written:?}");
            let batch = crate::log::batch(&records);
            if logs {
                assert!(
                    written
                        .iter()
                        .all(|f| f.proxy.is_none() && f.destination == at([93, 184, 216, 34], 443)),
                    "{written:?}"
                );
            } else {
                assert!(
                    written.iter().all(|f| left_out(f)
                        && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::MtProto)),
                    "{written:?}"
                );
                assert!(!holds(&batch, b"www.google.com") && !holds(&batch, &[93, 184, 216, 34]));
            }
        }
    }

    /// The same rule for substitution (the maintainer, 2026-11-24): with the switch off, a connection a messenger makes
    /// with its proxy's shape while it goes directly is named live as any flow is, by the name its hello sent, and the
    /// log gets it as it would have been named, left out: neither the address nor that name.
    #[test]
    fn a_substituted_flow_writes_no_address_or_cover_with_the_switch_off() {
        let shared = engine(false);
        telegram(&shared);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (main, direct) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, main, &direct, &[&obfuscated()]);
        let (flow, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            flow,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        let named = live(&shared, flow.id);
        assert_eq!(
            (named.proxy.is_none(), named.name.as_deref()),
            (true, Some("www.google.com")),
            "named live as any flow is"
        );
        assert_eq!(shared.counters.snapshot()[64], 1, "substituted");
        shared.finish(flow.id);
        shared.flush();
        let records = taken(&shared);
        let written = of_flow(&records, flow.id);
        assert!(
            !written.is_empty()
                && written.iter().all(|f| left_out(f)
                    && f.proxy
                        .as_ref()
                        .is_some_and(|p| p.kind == Kind::MtProto && p.outside_maker)),
            "{written:?}"
        );
        assert!(!holds(&crate::log::batch(&records), b"www.google.com"));
        // The direct connection itself is no proxy's, and is logged as it is.
        assert!(
            of_flow(&records, main.id)
                .iter()
                .all(|f| f.proxy.is_none() && !f.destination.ip().is_unspecified())
        );
    }

    /// A record stripped as it entered the log, held back for the take-back, stays stripped once it is taken back, even
    /// with the switch turned on before it goes on: it was made while the switch was off (E5, the maintainer's decision
    /// of 2026-11-24).
    #[test]
    fn a_take_back_leaves_a_record_stripped_as_it_entered() {
        let (shared, clock) = engine_at(false);
        let id = inferred_and_ended(&shared);
        switch(&shared, true);
        let (main, direct) = open(&shared, UID, at([149, 154, 167, 51], 443));
        relay(&shared, main, &direct, &[&obfuscated()]);
        clock.pass(11 * 60_000);
        another_record(&shared);
        let written = of_flow(&taken(&shared), id);
        assert!(
            !written.is_empty()
                && written
                    .iter()
                    .all(|f| left_out(f)
                        && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::MtProto)),
            "{written:?}"
        );
    }

    /// Review A, engine, note 11: a segment cut between the confirmation and the inner hello takes the marks the hello
    /// adds, as the live flow does, so that its end matches it.
    #[test]
    fn a_mark_from_the_inner_hello_reaches_the_segments_held() {
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
        // A quarter hour cuts the segment, whose states are not told yet: it is held.
        let now = clock.wall_ms();
        let next =
            (now / super::super::logbook::SEGMENT_MS + 1) * super::super::logbook::SEGMENT_MS;
        clock.pass(next - now + 1_000);
        shared.log_now();
        for found in sniff.feed(&crate::tls::tests::hello("cdn.tracker.example", 1000)) {
            shared.found(opened, found, &handshake);
        }
        let held: Vec<Flow> = lock(&shared.activity)
            .held
            .iter()
            .filter_map(|p| match &p.of {
                super::super::activity::Of::Flow { flow, .. } if flow.id == opened.id => {
                    Some(flow.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            !held.is_empty()
                && held
                    .iter()
                    .all(|f| f.proxy.as_ref().is_some_and(|p| p.trackers == [49])),
            "{held:?}"
        );
    }

    /// Review A, engine, note 10: an inner hello that names a known resolver moves no counter of the app's own
    /// encrypted DNS for a flow it does not name (C1).
    #[test]
    fn an_inner_hello_that_names_nothing_moves_no_dns_counter() {
        let shared = engine(false);
        let (resolver, bytes) = open(&shared, UID, at([203, 0, 113, 8], 443));
        let before = shared.counters.snapshot()[17];
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
        assert_eq!(live(&shared, resolver.id).dns, DnsUse::None);
        assert_eq!(
            shared.counters.snapshot()[17],
            before,
            "the flow's own DNS is as it was"
        );
    }

    /// A `UDP ASSOCIATE` asked of the SOCKS5 server at `server` by `uid`, its reply naming `bnd` (`ATYP` and on) as its
    /// relay, read as `tcp::relay` reads it: its control flow, left open.
    fn associate_at(shared: &Shared, uid: u32, server: SocketAddr, bnd: &[u8]) -> Opened {
        let (control, bytes) = open(shared, uid, server);
        let mut reply = vec![5, 0, 5, 0, 0];
        reply.extend_from_slice(bnd);
        relay_replied(
            shared,
            control,
            &bytes,
            &[&[5, 1, 0], &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]],
            &reply,
        );
        control
    }

    /// A UDP flow of `uid` to `destination` on the direct path, begun, tied and recorded as `udp::Peer::new` makes it:
    /// its opening, and the live flow.
    fn udp_flow(
        shared: &Shared,
        uid: u32,
        destination: SocketAddr,
        came_in: bool,
    ) -> (Opened, Flow) {
        let app = SocketAddr::from(([10, 1, 10, 1], 50_000));
        let (opened, mut flow) = super::super::udp::begin_udp(shared, app, destination, Some(uid));
        flow.came_in = came_in;
        let tied = shared.tie_relay(&mut flow, came_in);
        let _ = shared.record(flow);
        if tied {
            shared.relay_recorded(opened.id);
        }
        (opened, live(shared, opened.id))
    }

    /// Unit U (audit-U M1, M3, M4): a confirmed `UDP ASSOCIATE` names its control flow an own SOCKS5 proxy's, by its
    /// own server's names, its `DST` naming nothing, and ties the app's UDP flows to that server at the reply's port.
    /// With the switch off, "Now" shows the relay's first hop, the first datagram's destination names nothing, and the
    /// log keeps of both flows the proxy's kind and the facts that name nothing.
    #[test]
    fn a_udp_associate_ties_its_relays_flows_to_the_apps_own_proxy() {
        let (shared, clock) = engine_at(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let server = at([203, 0, 113, 5], 1080);
        let control = associate_at(&shared, UID, server, &[1, 0, 0, 0, 0, 0x9c, 0x40]);
        let named = live(&shared, control.id);
        assert!(
            named
                .proxy
                .as_ref()
                .is_some_and(|p| p.kind == Kind::Socks5 && p.asked.is_none() && !p.left_out),
            "{named:?}"
        );
        assert_eq!(named.name.as_deref(), Some("proxy.example.net"));
        let (relay, flow) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_000), false);
        assert!(
            flow.proxy.as_ref().is_some_and(|p| p.kind == Kind::Socks5
                && p.asked.is_none()
                && !p.left_out
                && p.proxy_name.as_deref() == Some("proxy.example.net")),
            "{flow:?}"
        );
        assert!(own_first_hop(&flow));
        shared.relay_asked(&relay, &Target::Name("example.com".into(), 443));
        let after = live(&shared, relay.id);
        assert!(after.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
        assert_eq!(after.name.as_deref(), Some("proxy.example.net"));
        assert!(lock(&shared.live).get(&relay.id).is_some_and(|l| l.unkept));
        for id in [control.id, relay.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let batch = crate::log::batch(&records);
        for hidden in [&b"proxy.example.net"[..], b"example.com", &[203, 0, 113, 5]] {
            assert!(!holds(&batch, hidden), "{hidden:?}");
        }
        for id in [control.id, relay.id] {
            let written = of_flow(&records, id);
            assert!(
                !written.is_empty()
                    && written
                        .iter()
                        .all(|f| left_out(f)
                            && f.proxy.as_ref().is_some_and(|p| p.kind == Kind::Socks5)),
                "{written:?}"
            );
        }
    }

    /// With the switch on, the first datagram's destination names the relay's flow, as a `CONNECT`'s request names
    /// its flow; turning the switch off sets it back to its first hop (audit-U M3).
    #[test]
    fn with_the_switch_on_a_relays_first_datagram_names_its_flow() {
        let shared = engine(true);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let control = associate_at(
            &shared,
            UID,
            at([203, 0, 113, 5], 1080),
            &[1, 0, 0, 0, 0, 0x9c, 0x40],
        );
        // Its `DST`, the client's own source, names nothing, the switch on too (audit-U M1).
        let named = live(&shared, control.id);
        assert_eq!(named.name.as_deref(), Some("proxy.example.net"));
        assert!(named.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
        let (relay, _) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_000), false);
        shared.relay_asked(&relay, &Target::Address(at([198, 51, 100, 9], 3478)));
        let named = live(&shared, relay.id);
        assert_eq!(
            (named.name.as_deref(), named.named_by),
            (Some("198.51.100.9"), NamedBy::Proxy)
        );
        let asked = Asked::Address(IpAddr::V4([198, 51, 100, 9].into()));
        assert!(
            named
                .proxy
                .as_ref()
                .is_some_and(|p| p.asked == Some((asked.clone(), 3478)))
        );
        switch(&shared, false);
        let back = live(&shared, relay.id);
        assert!(back.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
        assert_eq!(back.name.as_deref(), Some("proxy.example.net"));
    }

    /// Audit-U C1: a reply that names another address as its relay ties nothing there, so that no app's server can make
    /// the app's plain UDP to a third party read as a proxy's; the control flow's own server at that port is tied, and
    /// both the association and the relay elsewhere are counted.
    #[test]
    fn a_relay_named_elsewhere_ties_nothing_there() {
        let shared = engine(false);
        associate_at(
            &shared,
            UID,
            at([203, 0, 113, 5], 1080),
            &[1, 198, 51, 100, 20, 1, 187],
        );
        let (_, third) = udp_flow(&shared, UID, at([198, 51, 100, 20], 443), false);
        assert!(third.proxy.is_none(), "{third:?}");
        let (_, own) = udp_flow(&shared, UID, at([203, 0, 113, 5], 443), false);
        assert!(own.proxy.is_some());
        let counters = shared.counters.snapshot();
        assert_eq!(counters[super::super::COUNTERS - 2..], [1, 1]);
    }

    /// Audit-U m3 and m4: only the associating app's flows are tied, a flow of no app never is, one that comes in from
    /// the server is on any port, and a control flow not read for proxies (the user's tool's, a chained app's) notes no
    /// association.
    #[test]
    fn only_the_associating_apps_flows_are_tied() {
        let shared = engine(false);
        associate_at(
            &shared,
            UID,
            at([203, 0, 113, 5], 1080),
            &[1, 0, 0, 0, 0, 0x9c, 0x40],
        );
        let (_, other) = udp_flow(&shared, UID + 1, at([203, 0, 113, 5], 40_000), false);
        assert!(other.proxy.is_none());
        let (_, port) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_001), false);
        assert!(port.proxy.is_none(), "another port the app sent to");
        let (_, came_in) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_123), true);
        assert!(came_in.proxy.is_some(), "from the server, on any port");
        let app = SocketAddr::from(([10, 1, 10, 1], 50_001));
        let (_, mut nobody) =
            super::super::udp::begin_udp(&shared, app, at([203, 0, 113, 5], 40_000), None);
        assert!(!shared.tie_relay(&mut nobody, false));
        let (tool, bytes) = open(&shared, UID + 2, at([203, 0, 113, 6], 1080));
        let tool = Opened {
            sniffs: false,
            ..tool
        };
        let mut reply = vec![5, 0, 5, 0, 0];
        reply.extend_from_slice(&[1, 0, 0, 0, 0, 0x9c, 0x40]);
        relay_replied(
            &shared,
            tool,
            &bytes,
            &[&[5, 1, 0], &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]],
            &reply,
        );
        let (_, untied) = udp_flow(&shared, UID + 2, at([203, 0, 113, 6], 40_000), false);
        assert!(untied.proxy.is_none());
    }

    /// Audit-U M5: an association ends with its control flow, two on one relay port each count, so that the tie goes
    /// only with the last, and the engine's stop ends every one: none is handed over.
    #[test]
    fn an_association_ends_with_the_last_of_its_control_flows() {
        let shared = engine(false);
        let server = at([203, 0, 113, 5], 1080);
        // A server that relays on its TCP port, as shadowsocks-libev's local SOCKS5 server does.
        let bnd = [1, 0, 0, 0, 0, 0x04, 0x38];
        let first = associate_at(&shared, UID, server, &bnd);
        let second = associate_at(&shared, UID, server, &bnd);
        shared.finish(first.id);
        assert!(udp_flow(&shared, UID, server, false).1.proxy.is_some());
        shared.finish(second.id);
        assert!(udp_flow(&shared, UID, server, false).1.proxy.is_none());
        associate_at(&shared, UID, server, &bnd);
        assert!(udp_flow(&shared, UID, server, false).1.proxy.is_some());
        shared.proxies_all_ended();
        assert!(udp_flow(&shared, UID, server, false).1.proxy.is_none());
    }

    /// Audit-U M2: the relay is tied from a reply split at any byte, in IPv6, the server's bytes read on past the
    /// confirmation until its relay is whole, and no further.
    #[test]
    fn a_relay_is_tied_from_a_reply_split_anywhere_and_in_ipv6() {
        let server = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
            1080,
        );
        let mut reply = vec![5, 0, 5, 0, 0, 4];
        reply.extend_from_slice(&[0; 16]);
        reply.extend_from_slice(&[0x9c, 0x40]);
        for cut in 1..reply.len() {
            let shared = engine(false);
            let (control, _) = open(&shared, UID, server);
            let mut sniff = Sniff::new(true, false);
            let handshake = Mutex::new(Handshake::default());
            for read in [&[5, 1, 0][..], &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]] {
                for found in sniff.feed(read) {
                    shared.found(control, found, &handshake);
                }
            }
            assert!(
                shared.replied(control, &reply[..cut], &handshake),
                "at {cut}"
            );
            assert!(
                !shared.replied(control, &reply[cut..], &handshake),
                "at {cut}"
            );
            let (_, relay) = udp_flow(&shared, UID, SocketAddr::new(server.ip(), 40_000), false);
            assert!(relay.proxy.is_some(), "at {cut}");
        }
    }

    /// Audit-U M4: a relay's flow keeps the trackers' marks on the relay's names and on its first datagram's
    /// destination, whatever the switch says, as any own proxy's flow does.
    #[test]
    fn a_relays_flow_keeps_its_trackers_marks() {
        let (shared, clock) = engine_at(false);
        with_trackers(&shared);
        learn(&shared, "203.0.113.5", "relay.tracker.example");
        associate_at(
            &shared,
            UID,
            at([203, 0, 113, 5], 1080),
            &[1, 0, 0, 0, 0, 0x9c, 0x40],
        );
        let (by_relay, flow) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_000), false);
        assert_eq!(flow.proxy.map(|p| p.trackers), Some(vec![49]));
        associate_at(
            &shared,
            UID,
            at([203, 0, 113, 8], 1080),
            &[1, 0, 0, 0, 0, 0x9c, 0x40],
        );
        let (by_datagram, flow) = udp_flow(&shared, UID, at([203, 0, 113, 8], 40_000), false);
        assert_eq!(flow.proxy.map(|p| p.trackers), Some(vec![]));
        shared.relay_asked(
            &by_datagram,
            &Target::Name("sdk.tracker.example".into(), 443),
        );
        assert_eq!(
            live(&shared, by_datagram.id).proxy.map(|p| p.trackers),
            Some(vec![49])
        );
        for id in [by_relay.id, by_datagram.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        for id in [by_relay.id, by_datagram.id] {
            let written = of_flow(&records, id);
            assert!(
                !written.is_empty()
                    && written.iter().all(
                        |f| left_out(f) && f.proxy.as_ref().is_some_and(|p| p.trackers == [49])
                    ),
                "{written:?}"
            );
        }
    }

    /// Review U-engine M1: a hello its app sends on a relay's flow, as plain QUIC to the relay's port, names the flow
    /// nothing, the switch off or on, and its trackers' marks are kept, as they are for TCP.
    #[test]
    fn a_hello_on_a_relays_flow_names_nothing_and_keeps_its_mark() {
        for logs in [false, true] {
            let shared = engine(logs);
            with_trackers(&shared);
            associate_at(
                &shared,
                UID,
                at([203, 0, 113, 5], 1080),
                &[1, 0, 0, 0, 0, 0x9c, 0x40],
            );
            let (relay, before) = udp_flow(&shared, UID, at([203, 0, 113, 5], 40_000), false);
            let ServerName::Found(hello) =
                tls::server_name(&crate::tls::tests::hello("sdk.tracker.example", 1000))
            else {
                unreachable!("a hello")
            };
            shared.hello(relay, &hello, NamedBy::Quic);
            let after = live(&shared, relay.id);
            assert_eq!(
                (&after.name, after.named_by),
                (&before.name, before.named_by),
                "the switch {logs}"
            );
            assert_eq!(
                after.proxy.map(|p| p.trackers),
                Some(vec![49]),
                "the switch {logs}"
            );
        }
    }

    /// Audit-U M6: one app's flood of associations leaves another app's: an app at its share forgets its own oldest,
    /// and a full table the oldest of the app that holds the most.
    #[test]
    fn one_apps_flood_of_associations_leaves_another_apps() {
        let mut state = State::default();
        let entry = |uid, control| Association {
            uid,
            control,
            server: IpAddr::V4([203, 0, 113, 5].into()),
            port: 40_000,
            setting: false,
            password: false,
        };
        state.associate(entry(1, 0));
        for control in 1..=100 {
            state.associate(entry(2, control));
        }
        let of = |state: &State, uid| state.associations.iter().filter(|a| a.uid == uid).count();
        assert_eq!(of(&state, 2), ASSOCIATIONS_OF_APP);
        assert!(
            state
                .associations
                .iter()
                .filter(|a| a.uid == 2)
                .all(|a| a.control > 84)
        );
        let mut control = 1000;
        for uid in 3..40 {
            for _ in 0..ASSOCIATIONS_OF_APP {
                state.associate(entry(uid, control));
                control += 1;
            }
        }
        assert_eq!(state.associations.len(), ASSOCIATIONS);
        assert_eq!(of(&state, 1), 1, "the app with one keeps it");
    }

    /// The apps whose own proxies the user chose to log, the rest of the setting as it is (unit C's R3).
    fn choose(shared: &Shared, logged: &[u32]) {
        let mut setting = lock(&shared.proxies).setting().clone();
        setting.logged = logged.to_vec();
        let _ = shared.set_proxies(setting);
    }

    /// A SOCKS5 proxy at 203.0.113.5:1080 asked for `example.com` with an inner hello, by `uid`, confirmed: its flow.
    fn socks5_of(shared: &Shared, uid: u32, at_address: [u8; 4]) -> Opened {
        let (socks, bytes) = open(shared, uid, at(at_address, 1080));
        let reads = socks5_reads();
        let reads: Vec<&[u8]> = reads.iter().map(Vec::as_slice).collect();
        relay_replied(shared, socks, &bytes, &reads, SOCKS5_REPLY);
        socks
    }

    /// Unit C, test 1: with the switch off, a chosen app's own proxy keeps its first hop and destination, live and in
    /// the log, as with the switch on; another app's, at the same time, keeps its first hop alone.
    #[test]
    fn a_chosen_apps_proxy_keeps_its_first_hop_and_destination_with_the_switch_off() {
        let (shared, clock) = engine_at(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        choose(&shared, &[UID]);
        let chosen = socks5_of(&shared, UID, [203, 0, 113, 5]);
        let other = socks5_of(&shared, UID + 1, [203, 0, 113, 5]);
        let named = live(&shared, chosen.id);
        assert_eq!(named.name.as_deref(), Some("example.com"), "{named:?}");
        assert!(
            named
                .proxy
                .as_ref()
                .is_some_and(|p| p.asked.is_some() && !p.left_out)
        );
        assert!(!lock(&shared.live).get(&chosen.id).is_some_and(|l| l.unkept));
        let stripped = live(&shared, other.id);
        assert!(stripped.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
        assert!(lock(&shared.live).get(&other.id).is_some_and(|l| l.unkept));
        for id in [chosen.id, other.id] {
            shared.finish(id);
        }
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let kept = of_flow(&records, chosen.id);
        assert!(
            !kept.is_empty()
                && kept
                    .iter()
                    .all(|f| f.destination == at([203, 0, 113, 5], 1080)
                        && f.proxy
                            .as_ref()
                            .is_some_and(|p| p.asked.is_some() && !p.left_out)),
            "{kept:?}"
        );
        let left = of_flow(&records, other.id);
        assert!(!left.is_empty() && left.iter().all(left_out), "{left:?}");
    }

    /// Unit C, test 3: the choice never covers Android's setting, nor a proxy on the user's own network: for a chosen
    /// app, both keep only their first hop with the switch off.
    #[test]
    fn the_choice_never_covers_androids_setting_or_a_local_proxy() {
        use crate::local::{OnLink, Transport};
        let shared = engine(false);
        let _ = shared.set_proxies(ProxySetting {
            android: vec![("203.0.113.5".into(), 1080)],
            on_link: OnLink::new([(IpAddr::from([192, 168, 1, 0]), 24)], Transport::Wifi),
            logged: vec![UID],
            ..ProxySetting::default()
        });
        let setting = socks5_of(&shared, UID, [203, 0, 113, 5]);
        let local = socks5_of(&shared, UID, [192, 168, 1, 7]);
        for id in [setting.id, local.id] {
            let flow = live(&shared, id);
            assert!(
                flow.proxy.as_ref().is_some_and(|p| p.asked.is_none()),
                "{flow:?}"
            );
            assert!(lock(&shared.live).get(&id).is_some_and(|l| l.unkept));
        }
    }

    /// Unit C, test 4: a UID that is a tool, or Android's PAC handler, is never chosen, whatever the network part hands.
    #[test]
    fn the_choice_never_covers_a_tool_or_the_pac_handler() {
        for setting in [
            ProxySetting {
                logged: vec![UID],
                tools: vec![UID],
                ..ProxySetting::default()
            },
            ProxySetting {
                logged: vec![UID],
                pac_handler: Some(UID),
                ..ProxySetting::default()
            },
        ] {
            let shared = engine(false);
            let _ = shared.set_proxies(setting);
            let socks = socks5_of(&shared, UID, [203, 0, 113, 5]);
            assert!(
                live(&shared, socks.id)
                    .proxy
                    .is_some_and(|p| p.asked.is_none())
            );
        }
    }

    /// Unit C, test 5: an SDK Runtime's UID, ten thousand above its app's in each user's range, follows its app's
    /// choice, and a tool's sandbox never counts.
    #[test]
    fn an_apps_sdk_runtime_follows_its_choice() {
        assert_eq!(app_of(20_123), 10_123);
        assert_eq!(app_of(1_020_123), 1_010_123);
        assert_eq!(app_of(10_123), 10_123);
        assert_eq!(app_of(30_000), 30_000);
        let shared = engine(false);
        choose(&shared, &[UID]);
        let sandbox = socks5_of(&shared, UID + 10_000, [203, 0, 113, 5]);
        assert!(
            live(&shared, sandbox.id)
                .proxy
                .is_some_and(|p| p.asked.is_some())
        );
        let shared = engine(false);
        let _ = shared.set_proxies(ProxySetting {
            logged: vec![UID],
            tools: vec![UID],
            ..ProxySetting::default()
        });
        let sandbox = socks5_of(&shared, UID + 10_000, [203, 0, 113, 5]);
        assert!(
            live(&shared, sandbox.id)
                .proxy
                .is_some_and(|p| p.asked.is_none())
        );
    }

    /// Unit C, test 6 (audit 16): turning the choice off for an app strips what it kept at once, as the switch turned
    /// off does: its open flow goes back to its first hop and is unkept, and the record gathered for the next batch is
    /// stripped. Another chosen app's flow is untouched.
    #[test]
    fn turning_the_choice_off_strips_its_app_at_once() {
        let shared = &engine(false);
        learn(shared, "203.0.113.5", "proxy.example.net");
        choose(shared, &[UID, UID + 1]);
        let off = socks5_of(shared, UID, [203, 0, 113, 5]);
        let stays = socks5_of(shared, UID + 1, [203, 0, 113, 5]);
        assert_eq!(live(shared, off.id).name.as_deref(), Some("example.com"));
        let mut setting = lock(&shared.proxies).setting().clone();
        setting.logged = vec![UID + 1];
        shared.apply_proxies(setting);
        let back = live(shared, off.id);
        assert_eq!(back.name.as_deref(), Some("proxy.example.net"), "{back:?}");
        assert!(back.proxy.as_ref().is_some_and(|p| p.asked.is_none()));
        assert!(lock(&shared.live).get(&off.id).is_some_and(|l| l.unkept));
        assert_eq!(live(shared, stays.id).name.as_deref(), Some("example.com"));
        assert!(lock(&shared.pending_log).iter().all(|r| match r {
            Record::Segment { flow, .. } if flow.id == off.id =>
                flow.proxy.as_ref().is_some_and(|p| p.asked.is_none()),
            _ => true,
        }));
    }

    /// Unit C, test 7: turning the choice on names no open flow anew: an unkept flow's later hello does not name it.
    #[test]
    fn turning_the_choice_on_names_no_open_flow_anew() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        let socks = socks5_of(&shared, UID, [203, 0, 113, 5]);
        choose(&shared, &[UID]);
        let ServerName::Found(hello) =
            tls::server_name(&crate::tls::tests::hello("late.example", 1000))
        else {
            unreachable!("a hello")
        };
        shared.hello(socks, &hello, NamedBy::Tls);
        let flow = live(&shared, socks.id);
        assert_eq!(flow.name.as_deref(), Some("proxy.example.net"), "{flow:?}");
        assert!(flow.proxy.is_some_and(|p| p.asked.is_none()));
    }

    /// Unit C, test 9: a UID the choice no longer names is stripped from then on, as when its app was removed and
    /// its UID came to another app.
    #[test]
    fn a_uid_the_choice_no_longer_names_is_stripped_from_then_on() {
        let shared = engine(false);
        choose(&shared, &[UID]);
        choose(&shared, &[]);
        let socks = socks5_of(&shared, UID, [203, 0, 113, 5]);
        assert!(
            live(&shared, socks.id)
                .proxy
                .is_some_and(|p| p.asked.is_none())
        );
    }

    /// Unit C, test 11 (the lock-order mutant L1): the choice is read without the proxies' lock, nor `held_back`'s,
    /// so that a reading of the log's never waits on `infer`, which takes `held_back` under `proxies`.
    #[test]
    fn the_choice_is_read_without_the_proxies_lock() {
        let shared = engine(false);
        choose(&shared, &[UID]);
        for held in ["proxies", "held_back"] {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let _proxies = (held == "proxies").then(|| lock(&shared.proxies));
                let _held_back = (held == "held_back").then(|| lock(&shared.held_back));
                let reader = &shared;
                let tx = tx.clone();
                scope.spawn(move || {
                    let keeps = reader.keeps_first_hops();
                    let _ = tx.send(keeps.apps.apps.len());
                });
                assert_eq!(
                    rx.recv_timeout(Duration::from_secs(1)).ok(),
                    Some(1),
                    "the choice waited on {held}"
                );
            });
        }
    }

    /// Unit C, test 12: the set keeps application UIDs only, at most 512.
    #[test]
    fn the_choice_is_held_to_its_bounds() {
        let mut logged: Vec<u32> = (10_000..10_600).collect();
        logged.extend([0, 1000, 9_999, 30_000, 99_999]);
        let set = LoggedApps::of(&ProxySetting {
            logged,
            ..ProxySetting::default()
        });
        assert_eq!(set.apps.len(), MAX_LOGGED);
        assert!(set.apps.iter().all(|&uid| application(uid)));
    }

    /// Unit C, test 13: the rule matches the vectors the network part's Kotlin side reads too.
    #[test]
    fn the_cover_rule_matches_the_vectors() {
        let uids = |field: &str| -> Vec<u32> {
            if field == "-" {
                Vec::new()
            } else {
                field.split(',').filter_map(|u| u.parse().ok()).collect()
            }
        };
        let mut rows = 0;
        for line in include_str!("../../testdata/logged-apps.tsv").lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "{line}");
            let set = LoggedApps::of(&ProxySetting {
                logged: uids(fields[1]),
                tools: uids(fields[2]),
                pac_handler: uids(fields[3]).first().copied(),
                ..ProxySetting::default()
            });
            let proxy = Proxied {
                kind: Kind::Socks5,
                setting: fields[4] == "1",
                password: false,
                outside_maker: false,
                asked: None,
                proxy_name: None,
                organisation: None,
                cover: None,
                left_out: false,
                trackers: Vec::new(),
                local: fields[5] == "1",
                unsure: false,
            };
            let uid = fields[0].parse::<u32>().ok();
            assert_eq!(set.covers(uid, &proxy), fields[6] == "1", "{line}");
            rows += 1;
        }
        assert!(rows >= 13);
    }

    /// Unit C, the audit's minor 11: the window is decided per place, not per app. A chosen app's own proxy to
    /// Android's setting, or on the user's own network, leaves "Now" once its window ends, while its covered proxy
    /// stays in full.
    #[test]
    fn a_chosen_apps_places_the_choice_does_not_cover_keep_only_their_window() {
        use crate::local::{OnLink, Transport};
        let (shared, clock) = engine_at(false);
        let _ = shared.set_proxies(ProxySetting {
            android: vec![("203.0.113.5".into(), 1080)],
            on_link: OnLink::new([(IpAddr::from([192, 168, 1, 0]), 24)], Transport::Wifi),
            logged: vec![UID],
            ..ProxySetting::default()
        });
        let setting = socks5_of(&shared, UID, [203, 0, 113, 5]);
        let local = socks5_of(&shared, UID, [192, 168, 1, 7]);
        let covered = socks5_of(&shared, UID, [198, 51, 100, 7]);
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 1_000));
        for address in [[203, 0, 113, 5], [192, 168, 1, 7], [198, 51, 100, 7]] {
            assert!(holds(&snapshot, &address), "{address:?} shown while open");
        }
        for id in [setting.id, local.id, covered.id] {
            shared.finish(id);
        }
        clock.pass(11 * 60_000);
        let snapshot = crate::snapshot::encode(&shared.now_view(T + 11 * 60_000 + 2_000));
        assert!(
            !holds(&snapshot, &[203, 0, 113, 5]),
            "the setting's window ended"
        );
        assert!(
            !holds(&snapshot, &[192, 168, 1, 7]),
            "the local proxy's window ended"
        );
        assert!(
            holds(&snapshot, &[198, 51, 100, 7]),
            "the covered proxy stays"
        );
    }

    /// Unit C, the audit's minor 11: the switch turned on and off, and a chain set, while an app is chosen: each runs
    /// the pass that strips, and the chosen app keeps its destination through them, while another app's flow made with
    /// the switch on goes back to its first hop.
    #[test]
    fn a_chosen_app_keeps_its_destination_through_the_switch_and_a_chain() {
        let shared = engine(false);
        learn(&shared, "203.0.113.5", "proxy.example.net");
        choose(&shared, &[UID]);
        switch(&shared, true);
        let chosen = socks5_of(&shared, UID, [203, 0, 113, 5]);
        let other = socks5_of(&shared, UID + 1, [203, 0, 113, 5]);
        switch(&shared, false);
        shared.hide_chained();
        assert_eq!(
            live(&shared, chosen.id).name.as_deref(),
            Some("example.com")
        );
        assert!(
            live(&shared, chosen.id)
                .proxy
                .is_some_and(|p| p.asked.is_some())
        );
        let back = live(&shared, other.id);
        assert_eq!(back.name.as_deref(), Some("proxy.example.net"), "{back:?}");
        assert!(back.proxy.is_some_and(|p| p.asked.is_none()));
    }

    /// Unit C, test 2: a chosen messenger's inferred proxy, with the cover its hello sent, reaches the log whole after
    /// its window of take-back, as with the switch on.
    #[test]
    fn a_chosen_messengers_inferred_proxy_is_logged_whole_after_its_window() {
        let (shared, clock) = engine_at(false);
        telegram(&shared);
        choose(&shared, &[UID]);
        looked_up(&shared, UID, "web.example.org", [93, 184, 216, 99]);
        let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
        relay(
            &shared,
            proxy,
            &bytes,
            &[&crate::tls::tests::hello("www.google.com", 1000)],
        );
        assert_eq!(
            live(&shared, proxy.id).proxy.map(|p| p.kind),
            Some(Kind::MtProto)
        );
        shared.finish(proxy.id);
        shared.flush();
        clock.pass(11 * 60_000);
        another_record(&shared);
        let records = taken(&shared);
        let written = of_flow(&records, proxy.id);
        assert!(
            !written.is_empty()
                && written
                    .iter()
                    .all(|f| f.destination == at([93, 184, 216, 34], 443)
                        && f.proxy.as_ref().is_some_and(|p| !p.left_out)),
            "{written:?}"
        );
        assert!(holds(&crate::log::batch(&records), b"www.google.com"));
    }

    /// Unit C, test 10: a chosen messenger's flow never named its proxy for substitution is written with its own
    /// address, as with the switch on; at a local address it is left out, since no choice covers a local proxy.
    #[test]
    fn a_chosen_messengers_substituted_flow_is_logged_as_it_is_unless_local() {
        use crate::local::{OnLink, Transport};
        for local in [false, true] {
            let (shared, clock) = engine_at(false);
            let _ = shared.set_proxies(ProxySetting {
                messengers: vec![(Family::Telegram, UID)],
                logged: vec![UID],
                on_link: if local {
                    OnLink::new([(IpAddr::from([93, 184, 216, 0]), 24)], Transport::Wifi)
                } else {
                    OnLink::default()
                },
                ..ProxySetting::default()
            });
            let (direct, _) = open(&shared, UID, at([149, 154, 167, 51], 443));
            let (proxy, bytes) = open(&shared, UID, at([93, 184, 216, 34], 443));
            relay(&shared, proxy, &bytes, &[&obfuscated()]);
            for id in [proxy.id, direct.id] {
                shared.finish(id);
            }
            shared.flush();
            clock.pass(11 * 60_000);
            another_record(&shared);
            let written = of_flow(&taken(&shared), proxy.id);
            assert!(!written.is_empty(), "local {local}");
            if local {
                assert!(written.iter().all(left_out), "local: {written:?}");
            } else {
                assert!(
                    written
                        .iter()
                        .all(|f| f.destination == at([93, 184, 216, 34], 443)),
                    "{written:?}"
                );
            }
        }
    }
}
