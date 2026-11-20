//! Watch's encrypted resolver for the names of apps that go directly (W8, part 1, ADR 0042, "How it is built").
//!
//! A direct app's lookup to Watch's DNS address is answered here, never relayed to the network's resolver as
//! it was: from Watch's cache, else by the ways of the [`Ladder`] in their order of privacy (the user's own
//! resolver or Oblivious DoH through the pairs, then ODoH through the user's tool, the targets' operators' own
//! DoH, the presets that filter nothing), and only then, outside the strict setting, by the network's resolver,
//! which the screen shows while it lasts. In the strict setting a lookup no encrypted way answers gets "server
//! failure" at once. Local names (the network's search domains, `home.arpa`, the zones of RFC 6303 and 7793,
//! `ipv4only.arpa`, `resolver.arpa`, single labels) go to the network's resolver in either setting.
//!
//! The engine holds no TLS: each exchange is handed to Watch's Kotlin side ([`Platform::exchange`]), which
//! carries it over Android's own TLS from a socket it protects and binds to the network beneath, or through the
//! user's tool, and answers later with [`Exchanges::complete`]. The engine's loop never waits for it: each
//! lookup is a task of its own. ODoH's sealing and opening are the engine's ([`crate::odoh`]).
//!
//! What the resolver learns (holds, which pair answers best) lives in memory only, for the network Watch is on,
//! and goes with it; the answers it keeps go too.

use super::chain::Chain;
use super::upstream::protect;
use super::{Shared, lock};
use crate::catalogue::{Catalogue, Endpoint, Protocol, Url, dot_url};
use crate::dnscache::DnsCache;
use crate::hygiene::{self, Asked};
use crate::ladder::{Failure, Ladder, Now, Setup, Step};
use crate::odoh::{self, TargetKey};
use crate::packet;
use crate::socks5::Credentials;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

/// How long the engine waits for one exchange: Watch's Kotlin side gives up on its own after 3 s, with the
/// reason.
pub const EXCHANGE_WAIT: Duration = Duration::from_millis(3_500);
/// How long one lookup may try the encrypted ways in all, below the five seconds after which Android's
/// resolver asks again.
pub const LOOKUP_DEADLINE: Duration = Duration::from_millis(4_500);
/// How long the first pair has before the second is asked beside it, each attempt sealed afresh.
pub const HEDGE: Duration = Duration::from_millis(400);
/// How long past its time an answer is still served, stale, while a fresh one is asked (RFC 8767, bounded).
pub const STALE_WINDOW: Duration = Duration::from_hours(24);
/// How long the network's resolver has to answer.
pub const NETWORK_WAIT: Duration = Duration::from_secs(3);
/// How long a chained app's question may try the ways through the tool in all.
pub const TOOL_DEADLINE: Duration = Duration::from_secs(8);

/// How an exchange travels, as Watch's Kotlin side carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carry {
    /// A sealed query sent by POST to a relay (`application/oblivious-dns-message`).
    Odoh = 1,
    /// A query sent by POST to a DoH resolver (`application/dns-message`).
    Doh = 2,
    /// A query over a DoT connection.
    Dot = 3,
    /// A query to the network's resolver, by Android's own resolver on the network beneath (`DnsResolver`),
    /// which keeps the phone's Private DNS on "automatic" as it was.
    Network = 4,
    /// A GET of a target's `/.well-known/odohconfigs`.
    Fetch = 5,
}

/// The user's tool, for an exchange that goes through it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Through {
    /// The tool's SOCKS5 proxy.
    pub proxy: SocketAddr,
    /// The username and password it asks for, if any.
    pub credentials: Option<Credentials>,
}

/// One exchange for Watch's Kotlin side to carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// How.
    pub carry: Carry,
    /// The URL (ODoH: the relay's, with `targethost` and `targetpath`; DoH; the configurations' for a fetch);
    /// for DoT, `host:port`; empty for the network.
    pub url: String,
    /// The name the server's certificate must hold.
    pub host: String,
    /// Where the server is, so that its name is never looked up.
    pub addresses: Vec<IpAddr>,
    /// SPKI pins its certificate chain must match, if any.
    pub pins: Vec<String>,
    /// Through the user's tool, or directly on the network beneath.
    pub through: Option<Through>,
    /// What is sent: the DNS query, or the sealed one.
    pub body: Vec<u8>,
}

/// What came back of an exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The answer's bytes (HTTP 200, or a DoT or network answer).
    Answer(Vec<u8>),
    /// Another HTTP status.
    Status(u16),
    /// It failed, and how.
    Failed(Failure),
    /// The platform carries no exchanges (the engine's tests, a host without Watch's Kotlin side).
    Unsupported,
}

/// The exchanges handed to Watch's Kotlin side that wait for their reply.
#[derive(Debug, Default)]
pub struct Exchanges {
    /// By ticket: as many as lookups wait at once, a few dozen, so a list.
    pending: Mutex<Vec<(u64, oneshot::Sender<Reply>)>>,
}

/// Every exchange's number, never the same twice in the process, whichever engine handed it out.
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

impl Exchanges {
    /// Hands the reply of exchange `ticket` to the lookup that waits for it. False when none waits: it gave up,
    /// or the engine that asked is gone.
    pub fn complete(&self, ticket: u64, reply: Reply) -> bool {
        let waiting = {
            let mut pending = lock(&self.pending);
            let at = pending.iter().position(|(t, _)| *t == ticket);
            at.map(|at| pending.swap_remove(at).1)
        };
        waiting.is_some_and(|w| w.send(reply).is_ok())
    }

    /// How many wait.
    #[must_use]
    pub fn waiting(&self) -> usize {
        lock(&self.pending).len()
    }
}

/// Forgets a ticket whose lookup stopped waiting, as when the other pair answered first.
struct Ticket<'a>(&'a Exchanges, u64);

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        lock(&self.0.pending).retain(|(t, _)| *t != self.1);
    }
}

/// The user's choice of resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// None: Oblivious DoH through the pairs.
    Odoh,
    /// The preset of this index.
    Preset(usize),
    /// A DoH or DoT resolver the user gave.
    Custom(Endpoint),
}

/// What Watch set for the names of direct apps: the ways the pack holds, the user's choice, the pairs, strict.
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// The datasets.
    pub catalogue: Catalogue,
    /// The user's choice.
    pub choice: Choice,
    /// The pairs in use, the user's or the defaults, each allowed by the rule.
    pub pairs: Vec<(usize, usize)>,
    /// The strict setting.
    pub strict: bool,
}

impl DnsConfig {
    /// The setting `setting` (lines `strict 0|1`, `choice odoh`, `choice preset ID`, `choice doh URL ADDRS`,
    /// `choice dot HOST[:PORT] ADDRS`, `pairs default` or `pairs R>T,R>T`, addresses by commas) over
    /// `catalogue`. What does not read falls back to the default: ODoH, the default pairs, strict off. A pairs
    /// line that leaves no pair the rule allows keeps the defaults.
    #[must_use]
    pub fn read(catalogue: Catalogue, setting: &str) -> Self {
        let mut config = Self {
            pairs: catalogue.pairs.clone(),
            catalogue,
            choice: Choice::Odoh,
            strict: false,
        };
        for line in setting.lines() {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next(), words.next()) {
                (Some("strict"), Some(on), None, None) => config.strict = on == "1",
                (Some("choice"), Some("preset"), Some(id), None) => {
                    if let Some(i) = config.catalogue.presets.iter().position(|p| p.id == id) {
                        config.choice = Choice::Preset(i);
                    }
                }
                (Some("choice"), Some(protocol @ ("doh" | "dot")), Some(at), addresses) => {
                    let (protocol, url) = if protocol == "doh" {
                        (Protocol::Doh, Url::parse(at))
                    } else {
                        (Protocol::Dot, dot_url(at))
                    };
                    if let Some(url) = url {
                        let addresses = addresses
                            .unwrap_or("")
                            .split(',')
                            .filter_map(|a| a.parse().ok())
                            .take(16)
                            .collect();
                        config.choice = Choice::Custom(Endpoint {
                            protocol,
                            url,
                            addresses,
                            pins: Vec::new(),
                        });
                    }
                }
                (Some("pairs"), Some(spec), None, None) if spec != "default" => {
                    let pairs = config.catalogue.pairs_from(spec);
                    if !pairs.is_empty() {
                        config.pairs = pairs;
                    }
                }
                _ => {}
            }
        }
        config
    }

    /// The ladder's steps, with the tool on or not.
    fn setup(&self, tool: bool) -> Setup {
        let mut target_doh: Vec<usize> = Vec::new();
        for &(_, t) in &self.pairs {
            let url = self.catalogue.targets[t].doh.as_ref().map(|d| &d.url);
            if url.is_some()
                && !target_doh
                    .iter()
                    .any(|&o| self.catalogue.targets[o].doh.as_ref().map(|d| &d.url) == url)
            {
                target_doh.push(t);
            }
        }
        let chosen = match self.choice {
            Choice::Preset(i) => Some(i),
            _ => None,
        };
        let presets = (0..self.catalogue.presets.len())
            .filter(|&i| {
                let preset = &self.catalogue.presets[i];
                Some(i) != chosen
                    && preset.filtering == "none"
                    && !target_doh.iter().any(|&t| {
                        self.catalogue.targets[t].doh.as_ref().map(|d| &d.url.host)
                            == Some(&preset.endpoint.url.host)
                    })
            })
            .collect();
        Setup {
            choice: self.choice != Choice::Odoh,
            pairs: self.pairs.len(),
            tool,
            target_doh,
            presets,
            strict: self.strict,
        }
    }

    /// The endpoint of an ordinary step: the choice, a target's operator's DoH, a preset.
    fn endpoint(&self, step: Step) -> Option<&Endpoint> {
        match step {
            Step::Choice => match &self.choice {
                Choice::Odoh => None,
                Choice::Preset(i) => self.catalogue.presets.get(*i).map(|p| &p.endpoint),
                Choice::Custom(endpoint) => Some(endpoint),
            },
            Step::TargetDoh(t) => self.catalogue.targets.get(t)?.doh.as_ref(),
            Step::Preset(i) => self.catalogue.presets.get(i).map(|p| &p.endpoint),
            Step::Pair(_) | Step::PairThroughTool(_) => None,
        }
    }

    /// The step's name for the screen: `odoh RELAY TARGET`, `odoh-tool RELAY TARGET`, `choice`,
    /// `doh-target TARGET`, `preset ID`.
    fn name(&self, step: Step) -> String {
        let pair = |i: usize| {
            self.pairs.get(i).map_or_else(String::new, |&(r, t)| {
                format!(
                    "{} {}",
                    self.catalogue.relays[r].id, self.catalogue.targets[t].id
                )
            })
        };
        match step {
            Step::Choice => "choice".to_owned(),
            Step::Pair(i) => format!("odoh {}", pair(i)),
            Step::PairThroughTool(i) => format!("odoh-tool {}", pair(i)),
            Step::TargetDoh(t) => format!(
                "doh-target {}",
                self.catalogue.targets.get(t).map_or("", |x| x.id.as_str())
            ),
            Step::Preset(i) => format!(
                "preset {}",
                self.catalogue.presets.get(i).map_or("", |x| x.id.as_str())
            ),
        }
    }
}

/// How a TCP connection to Watch's DNS address is answered, by its app's route.
#[derive(Clone)]
pub(super) enum TcpLookups {
    /// A direct app's: by this resolver.
    Encrypted,
    /// A chained app's: as its UDP lookups are (ADR 0038).
    Tool(Arc<Chain>),
}

/// The resolver's state in the engine.
pub(super) struct Resolver {
    config: Mutex<Option<Arc<DnsConfig>>>,
    ladder: Mutex<Ladder>,
    /// Targets' keys fetched since the pack's, by target index.
    keys: Mutex<Vec<(usize, TargetKey)>>,
    /// Targets whose key is being fetched.
    refreshing: Mutex<Vec<usize>>,
    /// The encrypted ways' answers, kept for their time to live and a stale window.
    cache: Mutex<DnsCache>,
    /// The exchanges that wait for Watch's Kotlin side.
    pub(super) exchanges: Arc<Exchanges>,
    /// The network beneath's search domains.
    local: Mutex<Vec<String>>,
    /// The engine's own listener for DNS over TCP to Watch's address, on the loopback, once bound.
    pub(super) tcp: tokio::sync::OnceCell<SocketAddr>,
    /// The route of each connection to that listener, by its source port, until the listener takes it.
    pub(super) tcp_routes: Mutex<Vec<(u16, TcpLookups)>>,
    /// What answered, for the screen and the checks: by way, the network, failures, local names, stale.
    counts: Counts,
    /// How long the last answered exchanges of each carry took, in milliseconds, for the speed budget's check (ADR
    /// 0039): ODoH, DoH, DoT, the network's resolver. Durations only, never what was asked.
    times: Mutex<[Vec<u16>; 4]>,
}

/// How many durations are kept for each carry.
const TIMES_KEPT: usize = 256;

/// How many lookups each way answered.
#[derive(Default)]
struct Counts {
    odoh: AtomicU64,
    doh: AtomicU64,
    dot: AtomicU64,
    network: AtomicU64,
    failed: AtomicU64,
    local: AtomicU64,
    stale: AtomicU64,
    cached: AtomicU64,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            config: Mutex::default(),
            ladder: Mutex::default(),
            keys: Mutex::default(),
            refreshing: Mutex::default(),
            cache: Mutex::new(DnsCache::serving_stale(STALE_WINDOW)),
            exchanges: Arc::default(),
            local: Mutex::default(),
            tcp: tokio::sync::OnceCell::new(),
            tcp_routes: Mutex::default(),
            counts: Counts::default(),
            times: Mutex::default(),
        }
    }
}

impl Resolver {
    /// Whether Watch set the encrypted resolver: without it (the engine's own tests), direct apps' lookups go
    /// to the network's resolver as before W8.
    pub(super) fn on(&self) -> bool {
        lock(&self.config).is_some()
    }

    fn config(&self) -> Option<Arc<DnsConfig>> {
        lock(&self.config).clone()
    }

    /// Sets the resolver anew: what was learned and kept goes.
    pub(super) fn set(&self, config: Option<Arc<DnsConfig>>) {
        *lock(&self.config) = config;
        lock(&self.ladder).reset();
        lock(&self.keys).clear();
        lock(&self.cache).clear();
    }

    pub(super) fn get(&self) -> Option<Arc<DnsConfig>> {
        self.config()
    }

    /// The network beneath changed: holds, what was learned and the answers kept go.
    pub(super) fn network_moved(&self) {
        lock(&self.ladder).reset();
        lock(&self.cache).clear();
    }

    /// What Android says of the network beneath: validated or not, and its search domains.
    pub(super) fn network(&self, validated: bool, domains: &str) {
        lock(&self.ladder).set_validated(validated);
        *lock(&self.local) = domains
            .split([' ', ','])
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .take(16)
            .collect();
    }

    /// The state for Watch's screen and the checks, one `key value` per line.
    pub(super) fn status(&self) -> String {
        let config = self.config();
        let ladder = lock(&self.ladder);
        let now = Instant::now();
        let way = match (ladder.now(), &config) {
            (_, None) => "off".to_owned(),
            (Now::Unknown, _) => "none".to_owned(),
            (Now::Way(step), Some(config)) => config.name(step),
            (Now::Fallback(since), _) => {
                format!("fallback {}", now.duration_since(since).as_secs())
            }
            (Now::Failing(since), _) => format!("failing {}", now.duration_since(since).as_secs()),
        };
        let c = &self.counts;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let times = lock(&self.times);
        let mut latency = String::new();
        for (name, kept) in ["odoh", "doh", "dot", "network"].iter().zip(times.iter()) {
            let mut sorted = kept.clone();
            sorted.sort_unstable();
            let at = |p: usize| {
                sorted
                    .get((sorted.len() * p / 100).min(sorted.len().saturating_sub(1)))
                    .copied()
                    .unwrap_or(0)
            };
            let _ = writeln!(
                latency,
                "latency {name} {} {} {}",
                sorted.len(),
                at(50),
                at(95)
            );
        }
        format!(
            "way {way}\nstrict {}\nvalidated {}\nheld {}\nanswers odoh {} doh {} dot {} network {} failed {} local {} \
             stale {} cached {}\n{latency}",
            u8::from(config.as_ref().is_some_and(|c| c.strict)),
            u8::from(ladder.validated()),
            ladder.held(now),
            n(&c.odoh),
            n(&c.doh),
            n(&c.dot),
            n(&c.network),
            n(&c.failed),
            n(&c.local),
            n(&c.stale),
            n(&c.cached),
        )
    }

    /// Whether `name` is local: the network's to answer in either setting.
    fn is_local(&self, name: &str) -> bool {
        is_local(name, &lock(&self.local))
    }
}

/// The zones that are the network's own: special-use names (RFC 6761, 8375, 8880, 9462) and the reverse zones
/// of private and special addresses (RFC 6303, RFC 7793).
const LOCAL_ZONES: &[&str] = &[
    "home.arpa",
    "ipv4only.arpa",
    "resolver.arpa",
    "localhost",
    "local",
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "0.in-addr.arpa",
    "127.in-addr.arpa",
    "254.169.in-addr.arpa",
    "2.0.192.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "113.0.203.in-addr.arpa",
    "255.255.255.255.in-addr.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "8.b.d.0.1.0.0.2.ip6.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
];

/// Whether `name` (lower case, no final dot) is local: a single label, under a local zone, the second octets
/// 16 to 31 of 172 and 64 to 127 of 100 in reverse, or under one of the network's `search` domains.
#[must_use]
pub fn is_local(name: &str, search: &[String]) -> bool {
    let under = |zone: &str| name == zone || name.ends_with(&format!(".{zone}"));
    if !name.is_empty() && !name.contains('.') {
        return true;
    }
    if LOCAL_ZONES.iter().any(|z| under(z)) || search.iter().any(|z| under(z)) {
        return true;
    }
    // 172.16.0.0/12 and 100.64.0.0/10: their second octet's zones.
    let octet = |zone: &str, range: std::ops::RangeInclusive<u8>| {
        name.strip_suffix(zone)
            .and_then(|rest| rest.rsplit('.').next())
            .and_then(|o| o.parse::<u8>().ok())
            .is_some_and(|o| range.contains(&o))
    };
    octet(".172.in-addr.arpa", 16..=31) || octet(".100.in-addr.arpa", 64..=127)
}

/// A task of the resolver's, boxed: every one of them shares one type, so that the runtime's code for a task is
/// in the library once, not once per kind of task (W8 kept the native library within its 2 MB gate so, at no
/// cost in speed: one allocation per task, which the runtime makes anyway).
pub(super) type Task = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Spawns `task` as a [`Task`].
pub(super) fn spawn(task: impl std::future::Future<Output = ()> + Send + 'static) {
    let task: Task = Box::pin(task);
    tokio::spawn(task);
}

/// Asks Watch's Kotlin side to carry `request`, and waits for its reply at most [`EXCHANGE_WAIT`].
async fn ask(shared: &Shared, request: &Exchange) -> Reply {
    let exchanges = &shared.resolver.exchanges;
    let ticket = NEXT_TICKET.fetch_add(1, Ordering::Relaxed);
    let (sender, reply) = oneshot::channel();
    lock(&exchanges.pending).push((ticket, sender));
    let _forget = Ticket(exchanges, ticket);
    let asked = Instant::now();
    if !shared.platform.exchange(ticket, request) {
        return Reply::Unsupported;
    }
    let reply = match tokio::time::timeout(EXCHANGE_WAIT, reply).await {
        Ok(Ok(reply)) => reply,
        _ => Reply::Failed(Failure::Timeout),
    };
    let carry = match request.carry {
        Carry::Odoh => Some(0),
        Carry::Doh => Some(1),
        Carry::Dot => Some(2),
        Carry::Network => Some(3),
        Carry::Fetch => None,
    };
    if let (Some(carry), Reply::Answer(_)) = (carry, &reply) {
        let took = u16::try_from(asked.elapsed().as_millis()).unwrap_or(u16::MAX);
        let mut times = lock(&shared.resolver.times);
        let kept = &mut times[carry];
        if kept.len() == TIMES_KEPT {
            kept.remove(0);
        }
        kept.push(took);
    }
    reply
}

/// Tells Watch's Kotlin side when the way it shows changed kind: a way, the fallback, failing.
fn told<T>(shared: &Shared, change: impl FnOnce(&mut Ladder) -> T) -> T {
    let (before, after, out) = {
        let mut ladder = lock(&shared.resolver.ladder);
        let before = std::mem::discriminant(&ladder.now());
        let out = change(&mut ladder);
        (before, std::mem::discriminant(&ladder.now()), out)
    };
    if before != after {
        shared.platform.dns_changed();
    }
    out
}

/// The answer to a direct app's `query` to Watch's DNS address, made the app's: over TCP (`tcp`) whole, over
/// UDP cut to what the app takes. `None` only for bytes too short to be a query with an ID.
pub(super) async fn answer(shared: &Arc<Shared>, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
    let Some(asked) = hygiene::read(query) else {
        return crate::answers::failure(query);
    };
    let limit = (!tcp).then(|| asked.udp_limit());
    let mine = |upstream: &[u8]| {
        let mut out = asked.answer(upstream, limit)?;
        if shared.uncached_answers.load(Ordering::Relaxed) {
            crate::dns::uncache(&mut out);
        }
        Some(out)
    };
    let Some(config) = shared.resolver.config() else {
        return asked.failure();
    };
    let r = &shared.resolver;
    if shared.resolver.is_local(&asked.name) {
        Counters::add(&r.counts.local);
        return match network(shared, &asked).await {
            Some(answer) => {
                shared.learn(&answer, None);
                mine(&answer)
            }
            None => asked.failure(),
        };
    }
    let now = shared.clock.since_boot();
    let key = asked.as_query();
    let kept = lock(&r.cache).answer(&key, now);
    if let Some(kept) = kept {
        Counters::add(&r.counts.cached);
        return mine(&kept);
    }
    let stale = lock(&r.cache).stale(&key, now);
    if let Some(stale) = stale {
        Counters::add(&r.counts.stale);
        let (keeper, config, again) = (Arc::clone(shared), Arc::clone(&config), asked.clone());
        spawn(async move {
            if let Some((fresh, _)) = resolve(&keeper, &config, &again, None).await {
                keeper.learn(&fresh, None);
                lock(&keeper.resolver.cache).insert(&fresh, keeper.clock.since_boot());
            }
        });
        return mine(&stale);
    }
    if let Some((upstream, _)) = resolve(shared, &config, &asked, None).await {
        shared.learn(&upstream, None);
        lock(&r.cache).insert(&upstream, shared.clock.since_boot());
        return mine(&upstream);
    }
    if config.strict {
        told(shared, |l| l.failing(Instant::now()));
        Counters::add(&r.counts.failed);
        return asked.failure();
    }
    told(shared, |l| l.fell_back(Instant::now()));
    if let Some(answer) = network(shared, &asked).await {
        Counters::add(&r.counts.network);
        shared.learn(&answer, None);
        mine(&answer)
    } else {
        Counters::add(&r.counts.failed);
        asked.failure()
    }
}

/// The counters' one operation.
struct Counters;

impl Counters {
    fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Asks the encrypted ways for `asked` by the ladder, directly or (with `tool`) every step through the user's
/// tool: the resolver's answer (ID 0) and the step that gave it, or `None` when none answered by the deadline.
/// The two pairs of ODoH are hedged: the second is asked [`HEDGE`] after the first, unless the first failed
/// sooner. Any other step is asked once the one before it failed.
async fn resolve(
    shared: &Arc<Shared>,
    config: &Arc<DnsConfig>,
    asked: &Asked,
    tool: Option<&Arc<Chain>>,
) -> Option<(Vec<u8>, Step)> {
    // Through the tool: every step, in order, none held (the tool's network is not the network beneath).
    let plan = if tool.is_some() {
        config.setup(false).steps_through_tool()
    } else {
        let setup = config.setup(shared.chain().is_some());
        lock(&shared.resolver.ladder).plan(&setup, Instant::now())
    };
    let through = tool.map(|chain| Through {
        proxy: chain.proxy,
        credentials: chain.credentials.clone(),
    });
    let deadline = tokio::time::sleep(if tool.is_some() {
        TOOL_DEADLINE
    } else {
        LOOKUP_DEADLINE
    });
    tokio::pin!(deadline);
    let mut running = JoinSet::new();
    let mut next = 0;
    let start = |running: &mut JoinSet<_>, step: Step| {
        let (shared, config, asked) = (Arc::clone(shared), Arc::clone(config), asked.clone());
        let through = through.clone();
        running.spawn(async move {
            let got = attempt(&shared, &config, step, &asked, through).await;
            (step, got)
        });
    };
    if let Some(&first) = plan.first() {
        start(&mut running, first);
        next = 1;
    }
    while !running.is_empty() {
        let hedgeable = next < plan.len()
            && matches!(plan[next - 1], Step::Pair(_))
            && matches!(plan[next], Step::Pair(_))
            && running.len() == 1;
        let hedge = async {
            if hedgeable {
                tokio::time::sleep(HEDGE).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            () = &mut deadline => return None,
            () = hedge => {
                start(&mut running, plan[next]);
                next += 1;
            }
            Some(done) = running.join_next() => {
                let Ok((step, got)) = done else { continue };
                match got {
                    Ok(answer) => {
                        if tool.is_none() {
                            told(shared, |l| l.answered(step));
                        }
                        let counter = match step {
                            Step::Pair(_) | Step::PairThroughTool(_) => &shared.resolver.counts.odoh,
                            _ => match config.endpoint(step).map(|e| e.protocol) {
                                Some(Protocol::Dot) => &shared.resolver.counts.dot,
                                _ => &shared.resolver.counts.doh,
                            },
                        };
                        Counters::add(counter);
                        return Some((answer, step));
                    }
                    Err(failure) => {
                        if tool.is_none() {
                            lock(&shared.resolver.ladder).failed(step, failure, Instant::now());
                        }
                        if running.is_empty() && next < plan.len() {
                            start(&mut running, plan[next]);
                            next += 1;
                        }
                    }
                }
            }
        }
    }
    None
}

impl Setup {
    /// Every step, for a question through the tool: the choice or the pairs, then the targets' operators, then
    /// the presets, each reached through the tool.
    fn steps_through_tool(&self) -> Vec<Step> {
        let mut steps = Vec::new();
        if self.choice {
            steps.push(Step::Choice);
        }
        steps.extend((0..self.pairs).map(Step::PairThroughTool));
        steps.extend(self.target_doh.iter().copied().map(Step::TargetDoh));
        steps.extend(self.presets.iter().copied().map(Step::Preset));
        steps
    }
}

/// One step's attempt at `asked`: the resolver's answer to its question, or how it failed.
async fn attempt(
    shared: &Arc<Shared>,
    config: &Arc<DnsConfig>,
    step: Step,
    asked: &Asked,
    through: Option<Through>,
) -> Result<Vec<u8>, Failure> {
    let query = asked.upstream(true);
    let (pair, through) = match step {
        Step::Pair(i) => (Some(i), None),
        Step::PairThroughTool(i) => (Some(i), through),
        _ => (None, through),
    };
    let Some(pair) = pair else {
        let endpoint = config.endpoint(step).ok_or(Failure::Refused)?;
        let request = ordinary(endpoint, query, through);
        return checked(asked, ask(shared, &request).await);
    };
    let &(r, t) = config.pairs.get(pair).ok_or(Failure::Refused)?;
    let (relay, target) = (&config.catalogue.relays[r], &config.catalogue.targets[t]);
    let key = lock(&shared.resolver.keys)
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, key)| key.clone())
        .or_else(|| target.key.clone())
        .ok_or(Failure::Key)?;
    let sealed = odoh::seal(&key, &query, 0).ok_or(Failure::Refused)?;
    let request = Exchange {
        carry: Carry::Odoh,
        url: format!(
            "{}?targethost={}&targetpath={}",
            relay.url.text(),
            target.host,
            target.path
        ),
        host: relay.url.host.clone(),
        addresses: relay.addresses.clone(),
        pins: relay.pins.clone(),
        through,
        body: sealed.body.clone(),
    };
    match ask(shared, &request).await {
        Reply::Answer(body) => {
            let opened = odoh::open(&sealed, &body).ok_or(Failure::Refused)?;
            checked(asked, Reply::Answer(opened))
        }
        // RFC 9230 4.3: the target holds another key now.
        Reply::Status(401) => {
            refresh_key(shared, config, t);
            Err(Failure::Key)
        }
        other => checked(asked, other),
    }
}

/// An ordinary DoH or DoT exchange of `query` with `endpoint`.
fn ordinary(endpoint: &Endpoint, query: Vec<u8>, through: Option<Through>) -> Exchange {
    let (carry, url) = match endpoint.protocol {
        Protocol::Doh => (Carry::Doh, endpoint.url.text()),
        Protocol::Dot => (
            Carry::Dot,
            format!("{}:{}", endpoint.url.host, endpoint.url.port),
        ),
    };
    Exchange {
        carry,
        url,
        host: endpoint.url.host.clone(),
        addresses: endpoint.addresses.clone(),
        pins: endpoint.pins.clone(),
        through,
        body: query,
    }
}

/// A reply read as the answer to `asked`, or how the attempt failed: an answer to another question, or one
/// that is not an answer, counts as a refusal.
fn checked(asked: &Asked, reply: Reply) -> Result<Vec<u8>, Failure> {
    match reply {
        Reply::Answer(answer) if asked.answer(&answer, None).is_some() => Ok(answer),
        Reply::Answer(_) | Reply::Status(_) | Reply::Unsupported => Err(Failure::Refused),
        Reply::Failed(failure) => Err(failure),
    }
}

/// Fetches the key of the target `t` again, once at a time, after it answered 401: first from its HTTPS
/// record's `odohconfig` (RFC 9230 6), asked through two of the ladder's other ways, of different operators,
/// and taken only when both give the same; else from the target's `/.well-known/odohconfigs`, through the
/// user's tool while it is on, else directly over the network beneath, which shows the phone's address to
/// the target once (an accepted limit, ADR 0042).
fn refresh_key(shared: &Arc<Shared>, config: &Arc<DnsConfig>, t: usize) {
    {
        let mut refreshing = lock(&shared.resolver.refreshing);
        if refreshing.contains(&t) {
            return;
        }
        refreshing.push(t);
    }
    let (shared, config) = (Arc::clone(shared), Arc::clone(config));
    spawn(async move {
        let key = key_from_records(&shared, &config, t).await;
        let key = match key {
            Some(key) => Some(key),
            None => key_from_target(&shared, &config, t).await,
        };
        if let Some(key) = key {
            let mut keys = lock(&shared.resolver.keys);
            keys.retain(|(k, _)| *k != t);
            keys.push((t, key));
        }
        lock(&shared.resolver.refreshing).retain(|r| *r != t);
    });
}

/// The target's key from its HTTPS record, where two ways of different operators agree on it.
async fn key_from_records(
    shared: &Arc<Shared>,
    config: &Arc<DnsConfig>,
    t: usize,
) -> Option<TargetKey> {
    let target = config.catalogue.targets.get(t)?;
    let asked = hygiene::query_for(&target.host, crate::dns::TYPE_HTTPS)?;
    let setup = config.setup(false);
    let ways: Vec<Step> = setup
        .target_doh
        .iter()
        .copied()
        .filter(|&o| o != t)
        .map(Step::TargetDoh)
        .chain(setup.presets.iter().copied().map(Step::Preset))
        .collect();
    let mut found: Vec<(String, TargetKey)> = Vec::new();
    for step in ways {
        let operator = match step {
            Step::TargetDoh(o) => config.catalogue.targets[o].behind.operator.clone(),
            Step::Preset(p) => config.catalogue.presets[p].operator.clone(),
            _ => continue,
        };
        if found.iter().any(|(o, _)| *o == operator) {
            continue;
        }
        let Ok(answer) = attempt(shared, config, step, &asked, None).await else {
            continue;
        };
        let key =
            odoh::configs_in_https(&answer, &target.host).and_then(|c| TargetKey::parse(&c))?;
        found.push((operator, key));
        if found.len() == 2 {
            return (found[0].1 == found[1].1).then(|| found.swap_remove(0).1);
        }
    }
    None
}

/// The target's key from its `/.well-known/odohconfigs`.
async fn key_from_target(
    shared: &Arc<Shared>,
    config: &Arc<DnsConfig>,
    t: usize,
) -> Option<TargetKey> {
    let target = config.catalogue.targets.get(t)?;
    let addresses = target
        .doh
        .as_ref()
        .filter(|d| d.url.host == target.host)
        .map(|d| d.addresses.clone())
        .unwrap_or_default();
    let through = shared.chain().map(|chain| Through {
        proxy: chain.proxy,
        credentials: chain.credentials.clone(),
    });
    let port = target
        .doh
        .as_ref()
        .filter(|d| d.url.host == target.host)
        .map_or(443, |d| d.url.port);
    let host = if port == 443 {
        target.host.clone()
    } else {
        format!("{}:{port}", target.host)
    };
    let request = Exchange {
        carry: Carry::Fetch,
        url: format!("https://{host}/.well-known/odohconfigs"),
        host: target.host.clone(),
        addresses,
        pins: target.pins.clone(),
        through,
        body: Vec::new(),
    };
    match ask(shared, &request).await {
        Reply::Answer(configs) => TargetKey::parse(&configs),
        _ => None,
    }
}

/// The network's resolver's answer to `asked` (ID 0 asked, any back): through Android's resolver on the network
/// beneath where Watch's Kotlin side carries it, else from a protected socket to the network's DNS server.
async fn network(shared: &Arc<Shared>, asked: &Asked) -> Option<Vec<u8>> {
    let request = Exchange {
        carry: Carry::Network,
        url: String::new(),
        host: String::new(),
        addresses: Vec::new(),
        pins: Vec::new(),
        through: None,
        body: asked.upstream(false),
    };
    match ask(shared, &request).await {
        Reply::Answer(answer) => asked.answer(&answer, None).map(|_| answer),
        Reply::Unsupported => plain(shared, asked).await,
        _ => None,
    }
}

/// The network's resolver asked over plain DNS from a protected socket, under a random ID: the first datagram
/// with that ID that answers the question.
async fn plain(shared: &Arc<Shared>, asked: &Asked) -> Option<Vec<u8>> {
    let resolver = SocketAddr::new((*lock(&shared.upstream_dns))?, 53);
    let mut query = asked.upstream(false);
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).ok()?;
    query.get_mut(..2)?.copy_from_slice(&id);
    let exchange = async {
        let socket = UdpSocket::bind(packet::unspecified_like(&resolver))
            .await
            .ok()?;
        protect(shared, socket.as_fd()).await.ok()?;
        socket.connect(resolver).await.ok()?;
        socket.send(&query).await.ok()?;
        let mut buffer = vec![0u8; 4_096];
        loop {
            let n = socket.recv(&mut buffer).await.ok()?;
            let answer = buffer.get(..n)?;
            if answer.get(..2) == Some(&id[..]) && asked.answer(answer, None).is_some() {
                return Some(answer.to_vec());
            }
        }
    };
    tokio::time::timeout(NETWORK_WAIT, exchange)
        .await
        .ok()
        .flatten()
}

/// A chained app's question of another type than A and AAAA, through the tool by the encrypted ways (ADR 0038
/// gives this to W8): the resolver's answer (ID 0), or `None`, and the app's question then gets an empty answer.
pub(super) async fn through_tool(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    asked: &Asked,
) -> Option<Vec<u8>> {
    let config = shared.resolver.config()?;
    resolve(shared, &config, asked, Some(chain))
        .await
        .map(|(answer, _)| answer)
}

/// A `WireGuard` endpoint's addresses by the encrypted ways (W8 takes this over from W7): an IPv4 address
/// first, else an IPv6 one, never a loopback, multicast or unspecified one; and whether the name went
/// encrypted. Outside the strict setting, the network's resolver answers when no encrypted way does, and the
/// tunnel's state says so; in it, nothing does.
pub(super) async fn endpoint(shared: &Arc<Shared>, name: &str) -> Option<(IpAddr, bool)> {
    let config = shared.resolver.config()?;
    let usable = |address: &IpAddr| packet::unicast(*address) && !address.is_loopback();
    let mut fallback = None;
    for kind in [crate::answers::A, crate::answers::AAAA] {
        let asked = hygiene::query_for(name, kind)?;
        let found = resolve(shared, &config, &asked, None).await;
        let (answer, encrypted) = match found {
            Some((answer, _)) => (answer, true),
            None if config.strict => continue,
            None => {
                told(shared, |l| l.fell_back(Instant::now()));
                let Some(answer) = network(shared, &asked).await else {
                    continue;
                };
                (answer, false)
            }
        };
        let address = crate::dns::response(&answer)?
            .addresses
            .into_iter()
            .map(|(a, _)| a)
            .find(usable);
        match address {
            Some(address) if encrypted => return Some((address, true)),
            Some(address) => fallback = fallback.or(Some((address, false))),
            None => {}
        }
    }
    fallback
}

/// How long a connection of DNS over TCP to Watch's address may stay idle before Watch closes it (RFC 7766, 6.2.3:
/// the client opens another when it needs one).
pub const TCP_IDLE: Duration = Duration::from_secs(10);

/// A connection to the engine's own listener of DNS over TCP, which answers each query the app sends on it by its
/// `route`: what a TCP connection to Watch's DNS address at port 53 is relayed to (W8, part 1, point 9), so that
/// such a lookup goes the way its app's UDP lookups go, never to the network's resolver.
pub(super) async fn connect_lookups(
    shared: &Arc<Shared>,
    route: TcpLookups,
) -> std::io::Result<tokio::net::TcpStream> {
    let at = *shared
        .resolver
        .tcp
        .get_or_try_init(|| async {
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let at = listener.local_addr()?;
            spawn(serve_lookups(listener, Arc::clone(shared)));
            std::io::Result::Ok(at)
        })
        .await?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind((std::net::Ipv4Addr::LOCALHOST, 0).into())?;
    let port = socket.local_addr()?.port();
    lock(&shared.resolver.tcp_routes).push((port, route));
    let connected = socket.connect(at).await;
    if connected.is_err() {
        lock(&shared.resolver.tcp_routes).retain(|(p, _)| *p != port);
    }
    connected
}

/// The engine's listener of DNS over TCP: each connection from a port [`connect_lookups`] registered is served.
async fn serve_lookups(listener: tokio::net::TcpListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let route = {
            let mut routes = lock(&shared.resolver.tcp_routes);
            let at = routes.iter().position(|(p, _)| *p == peer.port());
            at.map(|at| routes.swap_remove(at).1)
        };
        if let Some(route) = route {
            spawn(serve_connection(stream, route, Arc::clone(&shared)));
        }
    }
}

/// Answers each query of one connection (two bytes of length, then the message, RFC 1035 4.2.2) in turn, until the
/// app closes it or it is idle for [`TCP_IDLE`]. Android's resolver asks over TCP only for an answer cut short over
/// UDP, one question at a time.
async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    route: TcpLookups,
    shared: Arc<Shared>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut length = [0u8; 2];
        if !matches!(
            tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut length)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
        if !matches!(
            tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut query)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let answer = match &route {
            TcpLookups::Encrypted => answer(&shared, &query, true).await,
            TcpLookups::Tool(chain) => super::lookups::answer(&shared, chain, &query).await,
        };
        let Some(answer) = answer else { continue };
        let Ok(length) = u16::try_from(answer.len()) else {
            continue;
        };
        let mut framed = length.to_be_bytes().to_vec();
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            break;
        }
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue;
    use crate::odoh::tests::{answer_as_target, target};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::OnceLock;

    fn config(setting: &str) -> DnsConfig {
        DnsConfig::read(catalogue::tests::shipped(), setting)
    }

    /// What the fake Kotlin side does with each kind of exchange.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Does {
        /// Answers: ODoH as the target would, DoH and DoT and the network with their own address.
        Answer,
        /// Fails so.
        Fail(Failure),
    }

    /// Watch's Kotlin side as the tests play it: records each exchange and answers by [`Does`], per carry.
    struct Fake {
        exchanges: OnceLock<Arc<Exchanges>>,
        seen: Mutex<Vec<Exchange>>,
        does: Mutex<HashMap<u8, Does>>,
        /// The relay that answers late, by host, and the target key pairs, by target host.
        keys: HashMap<String, odoh_rs::ObliviousDoHKeyPair>,
        late_relay: Mutex<Option<(String, u64)>>,
        changed: AtomicU64,
    }

    /// The fixed answer of each carry: 10.53.1.N for ODoH to the target of index N's host, 10.53.3.3 for DoH,
    /// 10.53.4.4 for DoT, 10.53.5.5 for the network's resolver.
    fn answer_with(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
        let asked = hygiene::read(query).unwrap_or_else(|| unreachable!("a query"));
        let mut out = asked.as_query();
        out[2] = 0x81;
        out[3] = 0x80;
        out[7] = 1;
        out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        out.extend_from_slice(&address.octets());
        out
    }

    impl Fake {
        fn new(targets: &[(&str, [u8; 32])]) -> Arc<Self> {
            Arc::new(Self {
                exchanges: OnceLock::new(),
                seen: Mutex::default(),
                does: Mutex::default(),
                keys: targets
                    .iter()
                    .map(|(host, ikm)| ((*host).to_owned(), target(ikm).0))
                    .collect(),
                late_relay: Mutex::default(),
                changed: AtomicU64::new(0),
            })
        }

        fn does(&self, carry: Carry, does: Does) {
            lock(&self.does).insert(carry as u8, does);
        }

        fn seen(&self, carry: Carry) -> Vec<Exchange> {
            lock(&self.seen)
                .iter()
                .filter(|e| e.carry == carry)
                .cloned()
                .collect()
        }

        fn reply(&self, request: &Exchange) -> Reply {
            let does = lock(&self.does)
                .get(&(request.carry as u8))
                .copied()
                .unwrap_or(Does::Answer);
            match does {
                Does::Fail(failure) => return Reply::Failed(failure),
                Does::Answer => {}
            }
            match request.carry {
                Carry::Odoh => {
                    let host = request
                        .url
                        .split("targethost=")
                        .nth(1)
                        .and_then(|r| r.split('&').next())
                        .unwrap_or("");
                    let Some(pair) = self.keys.get(host) else {
                        return Reply::Status(400);
                    };
                    let index =
                        u8::try_from(self.keys.keys().filter(|k| k.as_str() < host).count())
                            .unwrap_or(0);
                    let mut nonce = [0u8; 16];
                    nonce[0] = index;
                    let mut buffer = bytes::Bytes::copy_from_slice(&request.body);
                    let Ok(message) =
                        odoh_rs::parse::<odoh_rs::ObliviousDoHMessage, _>(&mut buffer)
                    else {
                        return Reply::Status(400);
                    };
                    let Ok((query, _)) = odoh_rs::decrypt_query(&message, pair) else {
                        return Reply::Status(401);
                    };
                    let dns = answer_with(&query.into_msg(), Ipv4Addr::new(10, 53, 1, index + 1));
                    answer_as_target(pair, &request.body, &dns, nonce)
                        .map_or(Reply::Status(400), |(_, sealed)| Reply::Answer(sealed))
                }
                Carry::Doh => {
                    Reply::Answer(answer_with(&request.body, Ipv4Addr::new(10, 53, 3, 3)))
                }
                Carry::Dot => {
                    Reply::Answer(answer_with(&request.body, Ipv4Addr::new(10, 53, 4, 4)))
                }
                Carry::Network => {
                    Reply::Answer(answer_with(&request.body, Ipv4Addr::new(10, 53, 5, 5)))
                }
                Carry::Fetch => {
                    let host = request.host.as_str();
                    self.keys.get(host).map_or(Reply::Status(404), |pair| {
                        let configs: odoh_rs::ObliviousDoHConfigs =
                            vec![odoh_rs::ObliviousDoHConfig::from(pair.public().clone())].into();
                        Reply::Answer(
                            odoh_rs::compose(&configs)
                                .map(|b| b.to_vec())
                                .unwrap_or_default(),
                        )
                    })
                }
            }
        }
    }

    impl super::super::Platform for Fake {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }
        fn protect(&self, _: std::os::fd::RawFd) -> bool {
            true
        }
        fn log(&self, _: &[u8]) {}
        fn exchange(&self, ticket: u64, request: &Exchange) -> bool {
            lock(&self.seen).push(request.clone());
            let Some(exchanges) = self.exchanges.get().cloned() else {
                return false;
            };
            let reply = self.reply(request);
            let late = lock(&self.late_relay)
                .clone()
                .filter(|(host, _)| *host == request.host)
                .map(|(_, ms)| ms);
            if let Some(ms) = late {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(ms));
                    exchanges.complete(ticket, reply);
                });
            } else {
                exchanges.complete(ticket, reply);
            }
            true
        }
        fn dns_changed(&self) {
            self.changed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The lab's tables of ways in miniature: two relays and three targets of distinct operators and
    /// jurisdictions, each target with a key of the test's and its own DoH, and two presets.
    fn tables() -> (String, String, String, String) {
        let hex = |ikm: &[u8; 32]| {
            target(ikm).1.iter().fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
        };
        let relays = "ra\thttps://relay-a.test/proxy\t192.0.2.1\t-\tRelay A\tPerson A\tXA\tAS64501\t-\t-\tlab\n\
                      rb\thttps://relay-b.test/proxy\t192.0.2.2\t-\tRelay B\tPerson B\tXB\tAS64502\t-\t-\tlab\n"
            .to_owned();
        let targets = format!(
            "ta\ttarget-a.test\t/dns-query\t-\t-\tTarget A\tPerson C\tXC\tAS64503\t-\tno\thttps://doh-a.test/dns-query\t192.0.2.3\t-\t-\t{}\tlab\n\
             tb\ttarget-b.test\t/dns-query\t-\t-\tTarget B\tPerson D\tXD\tAS64504\t-\tno\thttps://doh-b.test/dns-query\t192.0.2.4\t-\t-\t{}\tlab\n\
             tc\ttarget-c.test\t/dns-query\t-\t-\tTarget C\tPerson E\tXE\tAS64505\t-\tno\t-\t-\t-\t-\t{}\tlab\n",
            hex(&[1; 32]),
            hex(&[2; 32]),
            hex(&[3; 32])
        );
        let pairs = "ra\tta\nrb\ttb\n".to_owned();
        let presets = "pdoh\tP DoH\tPreset Co\tXF\tdoh\thttps://p.test/dns-query\t192.0.2.5\t-\tno logs\t-\tnone\thttps://p.test/policy\t-\t-\n\
                       pdot\tP DoT\tPreset Co\tXF\tdot\tp.test\t192.0.2.5\t-\tno logs\t-\tnone\thttps://p.test/policy\t-\t-\n"
            .to_owned();
        (relays, targets, pairs, presets)
    }

    fn lab_config(setting: &str) -> Arc<DnsConfig> {
        let (relays, targets, pairs, presets) = tables();
        Arc::new(DnsConfig::read(
            Catalogue::parse(&relays, &targets, &pairs, &presets),
            setting,
        ))
    }

    /// A shared engine state with the fake Kotlin side and the resolver set to `setting` over the lab's tables.
    fn resolving(setting: &str) -> (Arc<Shared>, Arc<Fake>) {
        let fake = Fake::new(&[
            ("target-a.test", [1; 32]),
            ("target-b.test", [2; 32]),
            ("target-c.test", [3; 32]),
        ]);
        let shared = Arc::new(super::super::tests::shared_with(
            Arc::clone(&fake) as Arc<dyn super::super::Platform>
        ));
        let _ = fake.exchanges.set(Arc::clone(&shared.resolver.exchanges));
        shared.resolver.set(Some(lab_config(setting)));
        (shared, fake)
    }

    fn app_query(name: &str, kind: u16) -> Vec<u8> {
        let mut q = vec![0x77, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap_or(0));
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        // EDNS with a client subnet, which must never leave.
        q.extend_from_slice(&[
            0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2,
        ]);
        q
    }

    /// The address an answer gives, and its RCODE.
    fn read(answer: Option<Vec<u8>>) -> (Option<IpAddr>, u8) {
        let answer = answer.unwrap_or_default();
        let rcode = answer.get(3).map_or(255, |f| f & 0x0f);
        let address = crate::dns::response(&answer).and_then(|r| r.addresses.first().map(|a| a.0));
        (address, rcode)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn the_setting_reads_choice_pairs_and_strict() {
        let c = config("strict 1\nchoice preset quad9-unsecured-doh\npairs numa>cloudflare");
        assert!(c.strict);
        assert_eq!(
            c.choice,
            Choice::Preset(
                c.catalogue
                    .presets
                    .iter()
                    .position(|p| p.id == "quad9-unsecured-doh")
                    .unwrap_or(99)
            )
        );
        assert_eq!(c.pairs.len(), 1);
        let custom = config("choice dot dns.example.net:8853 192.0.2.1,2001:db8::1");
        let Choice::Custom(endpoint) = custom.choice else {
            unreachable!("custom")
        };
        assert_eq!(endpoint.protocol, Protocol::Dot);
        assert_eq!(endpoint.url.port, 8853);
        assert_eq!(endpoint.addresses.len(), 2);
        // A pairs line the rule refuses whole keeps the defaults.
        assert_eq!(config("pairs numa>dnscry-pt-fra01").pairs.len(), 2);
        assert!(!config("nonsense\nstrict yes").strict);
    }

    #[test]
    fn the_ladder_holds_the_pairs_targets_and_unfiltered_presets_only() {
        let c = config("");
        let setup = c.setup(false);
        assert_eq!(setup.pairs, 2);
        let targets: Vec<&str> = setup
            .target_doh
            .iter()
            .map(|&t| c.catalogue.targets[t].id.as_str())
            .collect();
        assert_eq!(targets, ["cloudflare", "dnscry-pt-fra01"]);
        let presets: Vec<&str> = setup
            .presets
            .iter()
            .map(|&p| c.catalogue.presets[p].id.as_str())
            .collect();
        assert!(!presets.contains(&"quad9-doh"), "it filters malware");
        assert!(
            !presets.contains(&"cloudflare-doh"),
            "the same host as a target's operator's DoH"
        );
        assert!(presets.contains(&"quad9-unsecured-doh"));
        assert!(presets.contains(&"cloudflare-dot"));
        assert!(
            presets.iter().all(|p| !p.starts_with("dns4eu")),
            "court-ordered blocks are filtering"
        );
        let chosen = config("choice preset quad9-unsecured-dot").setup(true);
        assert!(chosen.choice && chosen.tool);
        assert!(
            !chosen
                .presets
                .iter()
                .any(|&p| c.catalogue.presets[p].id == "quad9-unsecured-dot"),
            "the choice is not a preset step too"
        );
    }

    #[test]
    fn local_names_are_the_networks() {
        let search = vec!["corp.example".to_owned()];
        for name in [
            "printer",
            "printer.home.arpa",
            "ipv4only.arpa",
            "_dns.resolver.arpa",
            "1.1.168.192.in-addr.arpa",
            "5.20.172.in-addr.arpa",
            "9.70.100.in-addr.arpa",
            "intranet.corp.example",
            "corp.example",
            "b.e.f.ip6.arpa",
        ] {
            assert!(is_local(name, &search), "{name}");
        }
        for name in [
            "example.com",
            "5.15.172.in-addr.arpa",
            "9.10.100.in-addr.arpa",
            "1.1.1.1.in-addr.arpa",
            "notcorp.example",
            "home.arpa.example.com",
        ] {
            assert!(!is_local(name, &search), "{name}");
        }
    }

    #[test]
    fn a_ticket_given_up_is_forgotten_and_its_reply_goes_nowhere() {
        let exchanges = Exchanges::default();
        let (sender, _reply) = oneshot::channel();
        lock(&exchanges.pending).push((7, sender));
        {
            let _ticket = Ticket(&exchanges, 7);
        }
        assert_eq!(exchanges.waiting(), 0);
        assert!(!exchanges.complete(7, Reply::Status(200)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_direct_apps_name_goes_by_odoh_padded_without_its_subnet_and_never_to_the_network() {
        let (shared, fake) = resolving("");
        let got = answer(&shared, &app_query("www.example.com", 1), false).await;
        let (address, rcode) = read(got.clone());
        assert_eq!(
            (address, rcode),
            (Some(v4(10, 53, 1, 1)), 0),
            "the first pair's target answered"
        );
        assert_eq!(
            got.as_deref().map(|a| a[..2].to_vec()),
            Some(vec![0x77, 0x01]),
            "the app's ID"
        );
        let odoh = fake.seen(Carry::Odoh);
        assert_eq!(odoh.len(), 1);
        assert_eq!(
            odoh[0].url,
            "https://relay-a.test/proxy?targethost=target-a.test&targetpath=/dns-query"
        );
        assert_eq!(
            odoh[0].addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
        assert!(odoh[0].through.is_none());
        assert!(
            fake.seen(Carry::Network).is_empty(),
            "nothing to the network's resolver"
        );
        assert!(shared.resolver.status().starts_with("way odoh ra ta\n"));
        // Kept: the same name again asks nothing.
        let again = answer(&shared, &app_query("www.example.com", 1), false).await;
        assert_eq!(read(again).0, Some(v4(10, 53, 1, 1)));
        assert_eq!(fake.seen(Carry::Odoh).len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn what_leaves_carries_no_client_subnet_and_is_padded() {
        let (shared, fake) = resolving("choice preset pdoh");
        let _ = answer(&shared, &app_query("www.example.com", 1), false).await;
        let doh = fake.seen(Carry::Doh);
        assert_eq!(doh.len(), 1);
        assert_eq!(doh[0].body.len() % hygiene::QUERY_BLOCK, 0);
        assert_eq!(doh[0].body[..2], [0, 0]);
        assert!(!doh[0].body.windows(4).any(|w| w == [0, 8, 0, 7]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strict_with_every_way_down_fails_at_once_and_sends_nothing_to_the_network() {
        let (shared, fake) = resolving("strict 1");
        for carry in [Carry::Odoh, Carry::Doh, Carry::Dot] {
            fake.does(carry, Does::Fail(Failure::Tampered));
        }
        let (address, rcode) = read(answer(&shared, &app_query("www.example.com", 1), false).await);
        assert_eq!((address, rcode), (None, 2), "server failure");
        assert_eq!(fake.seen(Carry::Network).len(), 0);
        assert!(shared.resolver.status().starts_with("way failing "));
        // Every step held now: the next lookup fails at once, without asking anything.
        let asked = lock(&fake.seen).len();
        let started = Instant::now();
        let (_, rcode) = read(answer(&shared, &app_query("other.example.com", 1), false).await);
        assert_eq!(rcode, 2);
        assert!(started.elapsed() < Duration::from_millis(100), "at once");
        assert_eq!(lock(&fake.seen).len(), asked, "nothing asked");
        assert_eq!(fake.seen(Carry::Network).len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_names_go_to_the_network_even_in_strict() {
        let (shared, fake) = resolving("strict 1");
        shared.resolver.network(true, "corp.example");
        let (address, _) = read(answer(&shared, &app_query("printer.home.arpa", 1), false).await);
        assert_eq!(address, Some(v4(10, 53, 5, 5)));
        let (address, _) = read(answer(&shared, &app_query("wiki.corp.example", 1), false).await);
        assert_eq!(address, Some(v4(10, 53, 5, 5)));
        assert!(
            fake.seen(Carry::Odoh).is_empty(),
            "no local name to a target"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outside_strict_the_fallback_shows_and_ends_when_a_way_answers() {
        let (shared, fake) = resolving("");
        for carry in [Carry::Odoh, Carry::Doh, Carry::Dot] {
            fake.does(carry, Does::Fail(Failure::Refused));
        }
        let (address, _) = read(answer(&shared, &app_query("a.example.com", 1), false).await);
        assert_eq!(address, Some(v4(10, 53, 5, 5)), "the network's resolver");
        assert!(shared.resolver.status().starts_with("way fallback "));
        assert!(fake.changed.load(Ordering::Relaxed) >= 1, "Kotlin told");
        // The ways come back; once their back-off ends, the next lookup climbs back up.
        for carry in [Carry::Odoh, Carry::Doh, Carry::Dot] {
            fake.does(carry, Does::Answer);
        }
        lock(&shared.resolver.ladder).reset();
        let (address, _) = read(answer(&shared, &app_query("b.example.com", 1), false).await);
        assert_eq!(address, Some(v4(10, 53, 1, 1)));
        assert!(shared.resolver.status().starts_with("way odoh ra ta\n"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_first_pair_is_hedged_by_the_second_sealed_afresh() {
        let (shared, fake) = resolving("");
        *lock(&fake.late_relay) = Some(("relay-a.test".into(), 2_000));
        let started = Instant::now();
        let (address, _) = read(answer(&shared, &app_query("www.example.com", 1), false).await);
        assert_eq!(
            address,
            Some(v4(10, 53, 1, 2)),
            "the second pair's target answered first"
        );
        assert!(started.elapsed() < Duration::from_millis(1_500));
        let odoh = fake.seen(Carry::Odoh);
        assert_eq!(odoh.len(), 2);
        assert_ne!(odoh[0].body, odoh[1].body, "each sealed afresh");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_401_fetches_the_key_again_and_the_next_lookup_uses_it() {
        // Target A's key in the table is not the one it holds: it answers 401.
        let fake = Fake::new(&[("target-a.test", [9; 32]), ("target-b.test", [2; 32])]);
        let shared = Arc::new(super::super::tests::shared_with(
            Arc::clone(&fake) as Arc<dyn super::super::Platform>
        ));
        let _ = fake.exchanges.set(Arc::clone(&shared.resolver.exchanges));
        shared.resolver.set(Some(lab_config("")));
        let (address, _) = read(answer(&shared, &app_query("one.example.com", 1), false).await);
        assert_eq!(
            address,
            Some(v4(10, 53, 1, 2)),
            "the second pair answered meanwhile"
        );
        // The refresh asks two operators' HTTPS records (none has one here), then fetches.
        for _ in 0..50 {
            if lock(&shared.resolver.keys).iter().any(|(t, _)| *t == 0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_ne!(fake.seen(Carry::Fetch).len(), 0);
        assert_eq!(
            fake.seen(Carry::Fetch)[0].url,
            "https://target-a.test/.well-known/odohconfigs"
        );
        // On another network, nothing learned: the first pair first, with the fetched key.
        shared.resolver.network_moved();
        let (address, _) = read(answer(&shared, &app_query("two.example.com", 1), false).await);
        assert_eq!(
            address,
            Some(v4(10, 53, 1, 1)),
            "the first pair again, with the fetched key"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_over_tcp_to_watchs_address_is_answered_by_the_resolver() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (shared, fake) = resolving("");
        let mut stream = connect_lookups(&shared, TcpLookups::Encrypted)
            .await
            .unwrap_or_else(|_| unreachable!("connects"));
        let query = app_query("tcp.example.com", 1);
        let mut framed = u16::try_from(query.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&query);
        stream
            .write_all(&framed)
            .await
            .unwrap_or_else(|_| unreachable!("written"));
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .unwrap_or_else(|_| unreachable!("read"));
        let mut got = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream
            .read_exact(&mut got)
            .await
            .unwrap_or_else(|_| unreachable!("read"));
        assert_eq!(read(Some(got)).0, Some(v4(10, 53, 1, 1)));
        assert_eq!(fake.seen(Carry::Odoh).len(), 1);
        assert_eq!(fake.seen(Carry::Network).len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_chained_apps_other_question_goes_encrypted_through_the_tool() {
        let (shared, fake) = resolving("");
        let chain = Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        });
        let asked = hygiene::read(&app_query("txt.example.com", 16))
            .unwrap_or_else(|| unreachable!("a query"));
        let got = through_tool(&shared, &chain, &asked).await;
        assert!(got.is_some());
        let odoh = fake.seen(Carry::Odoh);
        assert_eq!(odoh.len(), 1);
        assert_eq!(
            odoh[0].through.as_ref().map(|t| t.proxy),
            Some(SocketAddr::from(([127, 0, 0, 1], 10_808))),
            "through the tool"
        );
        assert_eq!(fake.seen(Carry::Network).len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_wireguard_endpoints_name_goes_the_encrypted_way() {
        let (shared, fake) = resolving("");
        let found = endpoint(&shared, "vpn.example.net").await;
        assert_eq!(found, Some((IpAddr::V4(Ipv4Addr::new(10, 53, 1, 1)), true)));
        assert_eq!(fake.seen(Carry::Network).len(), 0);
        // In strict with every way down: nothing, and nothing to the network.
        let (shared, fake) = resolving("strict 1");
        for carry in [Carry::Odoh, Carry::Doh, Carry::Dot] {
            fake.does(carry, Does::Fail(Failure::Timeout));
        }
        assert_eq!(endpoint(&shared, "vpn.example.net").await, None);
        assert_eq!(fake.seen(Carry::Network).len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn behind_a_captive_portal_failures_hold_nothing() {
        let (shared, fake) = resolving("");
        shared.resolver.network(false, "");
        for carry in [Carry::Odoh, Carry::Doh, Carry::Dot] {
            fake.does(carry, Does::Fail(Failure::Tampered));
        }
        let _ = answer(&shared, &app_query("portal.example.com", 1), false).await;
        assert!(shared.resolver.status().contains("held 0\n"));
    }
}
