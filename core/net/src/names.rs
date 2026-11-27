//! The names the network part saw in DNS answers, by address, so that a flow can be named after the name the app
//! asked for before it connected (W3).
//!
//! An entry lives at least [`MIN_KEEP`], however short the answer's TTL: apps keep addresses longer
//! than DNS says, and a flow named "unknown" because the TTL ran out a minute earlier tells the user
//! less than the name. The table holds at most [`CAPACITY`] addresses; the oldest go first.
//!
//! That time runs on the monotonic clock, which stands still while the phone sleeps: an app that
//! reconnects after a night to an address it got before it is named by the name it asked for. But a
//! name kept so through a night is old in real time, and set beside the name a connection itself sent
//! it would show as a difference what is only its age. So each entry also keeps when it ends in time
//! since the phone started, sleep included, which a flow named by it carries: only while that answer is
//! still held by that clock does its name stand beside a connection's own ([`Names::get_held`]; review 1
//! of W5's first part, engine, finding 7). A later answer for the address does not end it: on an address
//! that serves many names, another app's lookup re-points it often (review 2).
//!
//! The answers Android's resolver gave through the network part name every app's flows. The answers an app got
//! from a resolver of its own, past the network part's (plain DNS to another server), name only that app's flows:
//! an app chooses that resolver, and must not be able to rename other apps' connections through it.
//!
//! An address keeps the last name given for it, which names its flows, and up to [`NAMES_PER_ADDRESS`] names
//! given before it, each until its own answer ends, kept as keyed hashes: whether any answer still held gave
//! a name an address ([`Names::gave`]) tells a messenger's connection to a shared address from a proxy's cover
//! (the fix round of W8 part 2a, M3; ADR 0052).
//!
//! It also keeps the public names of the ECH configurations in the DNS answers, as long as the
//! addresses: a hello that offers ECH and names one of them hides the real name. They are scoped as the
//! addresses are: those in Android's resolver's answers hide names in every app's flows, those an app got
//! from a resolver of its own in that app's flows only, so that a public name never names a flow wherever
//! The network part saw its configuration, and no app can hide the names of another's (review 1 of W5's first part,
//! names, finding 1).
//!
//! Each scope has a table of its own, the oldest going first when it is full: Android's resolver's holds
//! [`CAPACITY`] addresses and [`PUBLIC_CAPACITY`] public names, and each app's own [`OWN_CAPACITY`] and
//! [`OWN_PUBLIC_CAPACITY`]. So an app's own resolver can push out only that app's names, never Android's
//! nor another app's (review 2 of W5's first part: in one table, an app's answers could push Android's
//! public names out, and the provider's cover name named every other app's flows again). At most
//! [`OWN_SCOPES`] apps keep tables of their own: past that, the app whose own resolver answered last the
//! longest ago loses its tables, and the engine's sweep drops an app's tables once every name in them has
//! expired (review 3, nit 3). ADR 0044's decision 4 gives the memory this takes.
//!
//! Beside them, scoped and bounded as the public names are, the names whose own answers carried an ECH configuration
//! (the proxy record's unit S2, the maintainer's decision 2 of 2026-11-26): the engine never hands such a name to the
//! network's proxy, so that the proxy learns no name ECH would hide. And [`Names::sole`], an address's one name in
//! Android's resolver's answers while no other name given it is still held (S2's audit, M1): the only name the engine
//! may send that proxy for a flow, never the last of several apps' lookups of a shared address.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hash, RandomState};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long an entry lives at least.
pub const MIN_KEEP: Duration = Duration::from_secs(3600);
/// How long an entry lives at most.
pub const MAX_KEEP: Duration = Duration::from_hours(24);
/// The most addresses kept from Android's resolver's answers.
pub const CAPACITY: usize = 8192;
/// The most addresses kept from one app's own resolver's answers.
pub const OWN_CAPACITY: usize = 512;
/// The most public names kept from Android's resolver's answers.
pub const PUBLIC_CAPACITY: usize = 256;
/// The most public names kept from one app's own resolver's answers.
pub const OWN_PUBLIC_CAPACITY: usize = 64;
/// The most apps that keep tables of their own.
pub const OWN_SCOPES: usize = 32;
/// The most names given before the last that an address keeps, for [`Names::gave`].
pub const NAMES_PER_ADDRESS: usize = 8;

/// Whose flows a name may name: every app's, or only the app with this UID.
pub type Scope = Option<u32>;

/// A name an answer gave an address, kept until `until` on the monotonic clock, to name flows, and until
/// `held_until` in time since the phone started, to stand beside a name a connection sent.
#[derive(Debug)]
struct Given {
    name: String,
    until: Instant,
    held_until: Duration,
    /// The names given the address before, as keyed hashes, each until its own answer ends.
    earlier: Vec<(u64, Instant)>,
}

/// The entries of one scope, the oldest first.
#[derive(Debug)]
struct Fifo<K, V> {
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> Default for Fifo<K, V> {
    fn default() -> Self {
        Self {
            entries: crate::map(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Hash + Eq + Clone, V> Fifo<K, V> {
    /// Keeps `value` for `key`, and at most `cap` entries, the oldest going first; the value it replaces.
    fn insert(&mut self, key: K, value: V, cap: usize) -> Option<V> {
        let old = self.entries.insert(key.clone(), value);
        if old.is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > cap {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        old
    }
}

/// Entries for every app's flows, and for each app's own, each scope in a table of its own.
#[derive(Debug)]
struct Scoped<K, V> {
    shared: Fifo<K, V>,
    /// Each app's table, with the number of the last write to it.
    own: HashMap<u32, (Fifo<K, V>, u64)>,
    /// How many writes to the apps' tables there were.
    writes: u64,
    /// The most entries of the shared table, and of each app's.
    caps: (usize, usize),
}

impl<K: Hash + Eq + Clone, V> Scoped<K, V> {
    fn new(caps: (usize, usize)) -> Self {
        Self {
            shared: Fifo::default(),
            own: crate::map(),
            writes: 0,
            caps,
        }
    }

    /// Keeps `value` for `key` in `scope`'s table, made from the value it replaces by `merge`.
    fn insert(&mut self, scope: Scope, key: K, value: V, merge: impl FnOnce(V, Option<&V>) -> V) {
        let Some(uid) = scope else {
            let value = merge(value, self.shared.entries.get(&key));
            self.shared.insert(key, value, self.caps.0);
            return;
        };
        // A table for one more app than may have one: the app written to the longest ago loses its own.
        if !self.own.contains_key(&uid)
            && self.own.len() >= OWN_SCOPES
            && let Some(oldest) = self
                .own
                .iter()
                .min_by_key(|(_, (_, written))| *written)
                .map(|(uid, _)| *uid)
        {
            self.own.remove(&oldest);
        }
        self.writes += 1;
        let (table, written) = self.own.entry(uid).or_insert_with(|| (Fifo::default(), 0));
        let value = merge(value, table.entries.get(&key));
        table.insert(key, value, self.caps.1);
        *written = self.writes;
    }

    /// Drops each app's table none of whose entries is `alive` any more.
    fn forget(&mut self, alive: impl Fn(&V) -> bool) {
        self.own
            .retain(|_, (table, _)| table.entries.values().any(&alive));
    }

    /// The entries for the flows of the app with `uid`: its own first, then every app's.
    fn for_app(&self, key: &K, uid: Option<u32>) -> impl Iterator<Item = &V> {
        let own = uid
            .and_then(|uid| self.own.get(&uid))
            .and_then(|(table, _)| table.entries.get(key));
        own.into_iter().chain(self.shared.entries.get(key))
    }

    fn clear(&mut self) {
        self.shared = Fifo::default();
        self.own.clear();
    }

    fn len(&self) -> usize {
        self.shared.entries.len()
            + self
                .own
                .values()
                .map(|(table, _)| table.entries.len())
                .sum::<usize>()
    }
}

/// Names by address.
#[derive(Debug)]
pub struct Names {
    addresses: Scoped<IpAddr, Given>,
    public: Scoped<String, Instant>,
    /// The names whose answers carried an ECH configuration, until when, scoped as the public names. Behind a pointer
    /// of its own (S2): inline, its 152 bytes moved the engine's state that follows the names past the reach of an
    /// arm64 `add` on the packet path.
    hidden: Box<Scoped<String, Instant>>,
    /// The key of the hashes of the names an address was given before its last, random for each table.
    hasher: RandomState,
}

impl Default for Names {
    fn default() -> Self {
        Self {
            addresses: Scoped::new((CAPACITY, OWN_CAPACITY)),
            public: Scoped::new((PUBLIC_CAPACITY, OWN_PUBLIC_CAPACITY)),
            hidden: Box::new(Scoped::new((PUBLIC_CAPACITY, OWN_PUBLIC_CAPACITY))),
            hasher: crate::keys(),
        }
    }
}

/// Keeps one entry of `earlier` for each name given again, its latest, and of those the latest
/// [`NAMES_PER_ADDRESS`], in the order they came. A scan of the entries kept, not a set: there are at most
/// `NAMES_PER_ADDRESS` + 1 (those an address kept, and the name given before the last), and a set took its keys and
/// its table for every answer to an address already held (the cold paths' second pass, ADR 0053).
fn latest_each(earlier: &mut Vec<(u64, Instant)>) {
    earlier.reverse();
    let mut kept = 0;
    for i in 0..earlier.len() {
        let hash = earlier[i].0;
        if earlier[..kept].iter().all(|(seen, _)| *seen != hash) {
            earlier.swap(kept, i);
            kept += 1;
        }
    }
    earlier.truncate(kept.min(NAMES_PER_ADDRESS));
    earlier.reverse();
}

/// Keeps `name` in `table` for the flows of `scope`, as long as an address: one function for the public names and the
/// hidden ones, so that one copy of the table's code serves both.
fn keep_until(
    table: &mut Scoped<String, Instant>,
    name: &str,
    scope: Scope,
    ttl: u32,
    now: Instant,
) {
    let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
    table.insert(scope, name.to_owned(), now + keep, |until, _| until);
}

/// A host name as names compare: in lower case, without a trailing dot.
fn compared(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl Names {
    /// Remembers that `address` was given for `name`, with the answer's `ttl` in seconds, for the flows
    /// of `scope`, at `now` on the monotonic clock and `boot` in time since the phone started.
    pub fn insert(
        &mut self,
        address: IpAddr,
        scope: Scope,
        name: &str,
        ttl: u32,
        (now, boot): (Instant, Duration),
    ) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        // A failed reading of the time since start (the longest time there is) holds the name for no time:
        // it names flows still, and stands beside none (review 2 of W5's first part).
        let held_until = if boot == Duration::MAX {
            Duration::ZERO
        } else {
            boot.saturating_add(keep)
        };
        let given = Given {
            name: name.to_owned(),
            until: now + keep,
            held_until,
            earlier: Vec::new(),
        };
        let hasher = &self.hasher;
        self.addresses
            .insert(scope, address, given, |mut given, old| {
                if let Some(old) = old {
                    let mut earlier: Vec<(u64, Instant)> = old
                        .earlier
                        .iter()
                        .copied()
                        .filter(|(_, until)| *until > now)
                        .collect();
                    if old.until > now && compared(&old.name) != compared(name) {
                        earlier.push((hasher.hash_one(compared(&old.name)), old.until));
                    }
                    let own = hasher.hash_one(compared(name));
                    earlier.retain(|(hash, _)| *hash != own);
                    latest_each(&mut earlier);
                    given.earlier = earlier;
                }
                given
            });
    }

    /// Whether an answer still kept for the flows of the app with `uid`, from its own resolver or from
    /// Android's, gave `name` the address `address`: the last name given, or one given before it.
    #[must_use]
    pub fn gave(&self, address: IpAddr, uid: Option<u32>, name: &str, now: Instant) -> bool {
        let wanted = compared(name);
        let hash = self.hasher.hash_one(&wanted);
        self.addresses.for_app(&address, uid).any(|given| {
            given.until > now && compared(&given.name) == wanted
                || given
                    .earlier
                    .iter()
                    .any(|(h, until)| *h == hash && *until > now)
        })
    }

    /// Remembers that a DNS answer gave an ECH configuration with the public name `name`, for the flows
    /// of `scope`.
    pub fn insert_public(&mut self, name: &str, scope: Scope, ttl: u32, now: Instant) {
        keep_until(&mut self.public, name, scope, ttl, now);
    }

    /// Remembers that a DNS answer for `name` carried an ECH configuration, for the flows of `scope`.
    pub fn insert_hidden(&mut self, name: &str, scope: Scope, ttl: u32, now: Instant) {
        keep_until(&mut self.hidden, &compared(name), scope, ttl, now);
    }

    /// Whether an answer for `name` still kept for the flows of the app with `uid`, from its own resolver or from
    /// Android's, carried an ECH configuration.
    #[must_use]
    pub fn is_hidden(&self, name: &str, uid: Option<u32>, now: Instant) -> bool {
        self.hidden
            .for_app(&compared(name), uid)
            .any(|until| *until > now)
    }

    /// The one name Android's resolver's answers still give `address`, if no other name given it before is still
    /// held: the shared scope alone, never an app's own resolver's.
    #[must_use]
    pub fn sole(&self, address: IpAddr, now: Instant) -> Option<&str> {
        let given = self.addresses.shared.entries.get(&address)?;
        (given.until > now && given.earlier.iter().all(|(_, until)| *until <= now))
            .then_some(given.name.as_str())
    }

    /// Whether `name` is the public name of an ECH configuration still kept for the flows of the app with
    /// `uid`: from Android's resolver, or from that app's own.
    #[must_use]
    pub fn is_public(&self, name: &str, uid: Option<u32>, now: Instant) -> bool {
        self.public
            .for_app(&name.to_owned(), uid)
            .any(|until| *until > now)
    }

    /// The name last given for `address` to the app with `uid`, if it is still kept: from that app's own
    /// resolver first, else from Android's.
    #[must_use]
    pub fn get(&self, address: IpAddr, uid: Option<u32>, now: Instant) -> Option<&str> {
        self.given(address, uid, now)
            .map(|given| given.name.as_str())
    }

    /// The name [`Names::get`] gives, and until when, in time since the phone started, its answer is
    /// held: while it is, the name may stand beside the name a connection sent, as a difference that is
    /// not only its age.
    #[must_use]
    pub fn get_held(
        &self,
        address: IpAddr,
        uid: Option<u32>,
        now: Instant,
    ) -> Option<(&str, Duration)> {
        self.given(address, uid, now)
            .map(|given| (given.name.as_str(), given.held_until))
    }

    fn given(&self, address: IpAddr, uid: Option<u32>, now: Instant) -> Option<&Given> {
        self.addresses
            .for_app(&address, uid)
            .find(|given| given.until > now)
    }

    /// Drops each app's own tables once every name in them has expired by `now`, as the engine's sweep
    /// does: an app that stopped asking its own resolver keeps nothing.
    pub fn forget_expired(&mut self, now: Instant) {
        self.addresses.forget(|given| given.until > now);
        self.public.forget(|until| *until > now);
        self.hidden.forget(|until| *until > now);
    }

    /// Forgets everything, as when the user wipes the log.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.public.clear();
        self.hidden.clear();
    }

    /// How many addresses are kept, of every scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether none is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// An hour after the phone started.
    const BOOT: Duration = Duration::from_hours(1);

    /// A name's answer is held for its keep in time since start, sleep included: after a night, though the
    /// monotonic clock moved a minute, it names flows still, held until a time long past; a failed
    /// reading of the time since start holds it for none.
    #[test]
    fn an_answer_is_held_for_its_keep_in_time_since_start() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "www.example.com", 60, (now, BOOT));
        let minute = now + Duration::from_mins(1);
        assert_eq!(
            names.get_held(a, Some(10_123), minute),
            Some(("www.example.com", BOOT + MIN_KEEP))
        );
        names.insert(a, None, "www.example.com", 60, (now, Duration::MAX));
        assert_eq!(
            names.get_held(a, None, minute),
            Some(("www.example.com", Duration::ZERO))
        );
    }

    #[test]
    fn keeps_a_name_at_least_an_hour_and_the_newest_ones() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "example.com", 30, (now, BOOT));
        assert_eq!(
            names.get(a, None, now + Duration::from_mins(30)),
            Some("example.com")
        );
        assert_eq!(
            names.get(a, None, now + MIN_KEEP + Duration::from_secs(1)),
            None
        );
        names.insert(a, None, "www.example.com", 30, (now, BOOT));
        assert_eq!(names.get(a, None, now), Some("www.example.com"));
        for i in 0..u32::try_from(CAPACITY).unwrap_or(0) {
            names.insert(
                IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
                None,
                "x",
                60,
                (now, BOOT),
            );
        }
        assert_eq!(names.len(), CAPACITY);
        assert_eq!(names.get(a, None, now), None, "the oldest went first");
    }

    #[test]
    fn an_apps_own_resolver_names_only_that_apps_flows() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        names.insert(a, Some(10_123), "own.example", 300, (now, BOOT));
        assert_eq!(names.get(a, Some(10_123), now), Some("own.example"));
        assert_eq!(names.get(a, Some(10_456), now), None);
        assert_eq!(names.get(a, None, now), None);
        names.insert(a, None, "shared.example", 300, (now, BOOT));
        assert_eq!(names.get(a, Some(10_123), now), Some("own.example"));
        assert_eq!(names.get(a, Some(10_456), now), Some("shared.example"));
    }

    #[test]
    fn keeps_public_names_for_a_while_and_the_newest_ones() {
        let mut names = Names::default();
        let now = Instant::now();
        names.insert_public("cover.example", None, 300, now);
        assert!(names.is_public("cover.example", Some(10_123), now));
        assert!(names.is_public("cover.example", None, now));
        assert!(!names.is_public("other.example", Some(10_123), now));
        assert!(!names.is_public(
            "cover.example",
            Some(10_123),
            now + MIN_KEEP + Duration::from_secs(1)
        ));
        for i in 0..PUBLIC_CAPACITY {
            names.insert_public(&format!("p{i}.example"), None, 300, now);
        }
        assert!(
            !names.is_public("cover.example", Some(10_123), now),
            "the oldest went first"
        );
        names.clear();
        assert!(!names.is_public("p1.example", None, now));
    }

    /// S2's audit, M1: an address's sole name is the one Android's resolver's answers gave it while no other name given
    /// it is still held; an app's own resolver's names never count, and an earlier name that ended leaves it sole
    /// again.
    #[test]
    fn an_address_has_a_sole_name_only_while_no_other_is_held() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert_eq!(names.sole(a, now), None);
        names.insert(a, Some(10_456), "own.example", 300, (now, BOOT));
        assert_eq!(names.sole(a, now), None, "an app's own resolver's");
        names.insert(a, None, "bank.example", 300, (now, BOOT));
        assert_eq!(names.sole(a, now), Some("bank.example"));
        names.insert(a, None, "BANK.example.", 300, (now, BOOT));
        assert_eq!(
            names.sole(a, now),
            Some("BANK.example."),
            "the same name again"
        );
        let later = now + Duration::from_secs(60);
        names.insert(a, None, "ads.tracker.example", 300, (later, BOOT));
        assert_eq!(names.sole(a, later), None, "two names held");
        let after = now + MIN_KEEP + Duration::from_secs(1);
        assert_eq!(names.sole(a, after), Some("ads.tracker.example"));
        assert_eq!(
            names.sole(a, later + MIN_KEEP + Duration::from_secs(1)),
            None
        );
    }

    /// S2, decision 2: a name whose answer carried an ECH configuration is kept as such for a while, scoped as the
    /// public names are, compared as names compare.
    #[test]
    fn a_name_whose_answer_carried_ech_is_known_for_its_scope() {
        let mut names = Names::default();
        let now = Instant::now();
        names.insert_hidden("Site.example.", None, 300, now);
        names.insert_hidden("mine.example", Some(10_123), 300, now);
        assert!(names.is_hidden("site.example", Some(10_456), now));
        assert!(names.is_hidden("site.example", None, now));
        assert!(names.is_hidden("mine.example", Some(10_123), now));
        assert!(!names.is_hidden("mine.example", Some(10_456), now));
        assert!(!names.is_hidden("mine.example", None, now));
        assert!(
            !names.is_public("site.example", None, now),
            "not a public name"
        );
        assert!(!names.is_hidden(
            "site.example",
            None,
            now + MIN_KEEP + Duration::from_secs(1)
        ));
        names.clear();
        assert!(!names.is_hidden("site.example", None, now));
    }

    /// Review 2 of W5's first part: one app's own resolver can push out only its own names, never
    /// Android's nor another app's, public names and addresses alike.
    #[test]
    fn an_apps_own_resolver_pushes_out_only_its_own_names() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert_public("cover.example", None, 300, now);
        names.insert_public("mine.example", Some(10_123), 300, now);
        names.insert(a, None, "www.example.com", 300, (now, BOOT));
        names.insert(a, Some(10_456), "own.example", 300, (now, BOOT));
        // More than Android's tables and the app's own hold: written as numbers, so that a capacity
        // changed by mistake fails here (review 3 of W5's first part, nit 4).
        for i in 0..320 {
            names.insert_public(&format!("p{i}.example"), Some(10_999), 300, now);
        }
        for i in 0..9_000 {
            let other = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            names.insert(other, Some(10_999), "x.example", 300, (now, BOOT));
        }
        assert!(names.is_public("cover.example", Some(10_456), now));
        assert!(names.is_public("mine.example", Some(10_123), now));
        assert_eq!(names.get(a, Some(10_123), now), Some("www.example.com"));
        assert_eq!(names.get(a, Some(10_456), now), Some("own.example"));
        // The flooding app's own tables keep only their newest: 64 public names and 512 addresses.
        assert!(!names.is_public("p0.example", Some(10_999), now));
        assert!(!names.is_public("p255.example", Some(10_999), now));
        assert!(names.is_public("p256.example", Some(10_999), now));
        assert!(names.is_public("p319.example", Some(10_999), now));
        assert_eq!(names.len(), 2 + 512);
    }

    /// An app's own tables go once every name in them has expired, at the engine's sweep; another app's,
    /// with one name expired beside one still kept, stay whole, and so do Android's (review 3 of W5's
    /// first part, nit 3; review 4, minor 1: a table that went at its first expired name passed before).
    #[test]
    fn an_apps_own_tables_go_once_every_name_in_them_has_expired() {
        let mut names = Names::default();
        let now = Instant::now();
        let later = now + Duration::from_hours(2);
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
        names.insert(a, None, "www.example.com", 60, (now, BOOT));
        names.insert(a, Some(10_123), "gone.example", 60, (now, BOOT));
        names.insert_public("gone.example", Some(10_123), 60, now);
        names.insert(b, Some(10_456), "expired.example", 60, (now, BOOT));
        names.insert(a, Some(10_456), "kept.example", 60, (later, BOOT));
        names.insert_public("expired-cover.example", Some(10_456), 60, now);
        names.insert_public("kept-cover.example", Some(10_456), 60, later);
        let after = now + MIN_KEEP + Duration::from_secs(1);
        names.forget_expired(after);
        assert!(!names.addresses.own.contains_key(&10_123));
        assert!(!names.public.own.contains_key(&10_123));
        assert!(names.addresses.own.contains_key(&10_456));
        assert!(names.public.own.contains_key(&10_456));
        assert_eq!(names.get(a, Some(10_456), after), Some("kept.example"));
        assert!(names.is_public("kept-cover.example", Some(10_456), after));
        assert_eq!(
            names.len(),
            3,
            "Android's and both of the app's, one expired"
        );
    }

    /// At most [`OWN_SCOPES`] apps keep tables of their own: one more takes the place of the app whose
    /// own resolver answered last the longest ago, which then falls back to Android's names.
    #[test]
    fn at_most_so_many_apps_keep_tables_of_their_own() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "www.example.com", 300, (now, BOOT));
        let apps: Vec<u32> = (0..=u32::try_from(OWN_SCOPES).unwrap_or(0))
            .map(|i| 10_100 + i)
            .collect();
        for &app in &apps[..OWN_SCOPES] {
            names.insert(a, Some(app), &format!("{app}.example"), 300, (now, BOOT));
        }
        // The first app answers itself again, so the second has answered last the longest ago.
        names.insert(a, Some(apps[0]), "again.example", 300, (now, BOOT));
        let newest = apps[OWN_SCOPES];
        names.insert(a, Some(newest), "newest.example", 300, (now, BOOT));
        assert_eq!(names.addresses.own.len(), 32);
        assert_eq!(names.get(a, Some(apps[1]), now), Some("www.example.com"));
        assert_eq!(names.get(a, Some(apps[0]), now), Some("again.example"));
        assert_eq!(names.get(a, Some(newest), now), Some("newest.example"));
    }

    /// An app's own resolver's public names hide names in that app's flows only.
    #[test]
    fn an_apps_own_resolvers_public_names_hide_only_in_its_flows() {
        let mut names = Names::default();
        let now = Instant::now();
        names.insert_public("cover.example", Some(10_123), 300, now);
        assert!(names.is_public("cover.example", Some(10_123), now));
        assert!(!names.is_public("cover.example", Some(10_456), now));
        assert!(!names.is_public("cover.example", None, now));
    }

    /// An address keeps the names given before its last (the fix round of W8 part 2a, M3): a shared address
    /// re-pointed by another app's lookup still ties the names it was given, each until its own answer ends,
    /// at most [`NAMES_PER_ADDRESS`] of them, in each scope as its answers came.
    #[test]
    fn an_address_keeps_the_names_it_was_given_before_its_last() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "www.youtube.com", 300, (now, BOOT));
        names.insert(a, None, "i.ytimg.com", 300, (now, BOOT));
        assert_eq!(
            names.get(a, None, now),
            Some("i.ytimg.com"),
            "the last names flows"
        );
        assert!(names.gave(a, None, "WWW.YouTube.com.", now));
        assert!(names.gave(a, Some(10_123), "i.ytimg.com", now));
        assert!(!names.gave(a, None, "www.google.com", now));
        // Each until its own answer ends.
        let later = now + MIN_KEEP + Duration::from_secs(1);
        names.insert(a, None, "yt3.ggpht.com", 86_400, (later, BOOT));
        assert!(!names.gave(a, None, "www.youtube.com", later));
        assert!(names.gave(a, None, "yt3.ggpht.com", later));
        // At most NAMES_PER_ADDRESS before the last, the latest kept; a name given again is one entry.
        for i in 0..NAMES_PER_ADDRESS + 3 {
            names.insert(a, None, &format!("n{i}.example"), 600, (later, BOOT));
        }
        names.insert(a, None, "n9.example", 600, (later, BOOT));
        names.insert(a, None, "last.example", 600, (later, BOOT));
        assert!(names.gave(a, None, "n10.example", later));
        assert!(names.gave(a, None, "n3.example", later));
        assert!(!names.gave(a, None, "n2.example", later), "past the bound");
        // An app's own resolver ties for that app alone.
        let b = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));
        names.insert(b, Some(10_123), "own.example", 600, (later, BOOT));
        names.insert(b, Some(10_123), "other.example", 600, (later, BOOT));
        assert!(names.gave(b, Some(10_123), "own.example", later));
        assert!(!names.gave(b, Some(10_456), "own.example", later));
    }

    /// The names given before an address's last keep one entry for each name given again, its latest, and of those
    /// the latest `NAMES_PER_ADDRESS`, in the order they came: the scan that took the place of a set (the cold
    /// paths' second pass) gives what the set gave, for every list tried of up to `NAMES_PER_ADDRESS` + 3 entries.
    #[test]
    fn the_names_given_before_keep_the_latest_of_each_in_their_order() {
        // The set's way, as `Names::insert` had it.
        let with_a_set = |mut earlier: Vec<(u64, Instant)>| {
            let mut seen = std::collections::HashSet::new();
            earlier.reverse();
            earlier.retain(|(hash, _)| seen.insert(*hash));
            earlier.truncate(NAMES_PER_ADDRESS);
            earlier.reverse();
            earlier
        };
        let now = Instant::now();
        let at = |seconds: u64| now + Duration::from_secs(seconds);
        let mut earlier = vec![
            (1, at(1)),
            (2, at(2)),
            (1, at(3)),
            (3, at(4)),
            (2, at(5)),
            (4, at(6)),
        ];
        let latest = vec![(1, at(3)), (3, at(4)), (2, at(5)), (4, at(6))];
        assert_eq!(with_a_set(earlier.clone()), latest);
        latest_each(&mut earlier);
        assert_eq!(earlier, latest, "the latest of each, in their order");
        // Past the bound, the latest are kept.
        let mut earlier: Vec<(u64, Instant)> = (0..10).map(|n| (n, at(n))).collect();
        latest_each(&mut earlier);
        assert_eq!(earlier, (2..10).map(|n| (n, at(n))).collect::<Vec<_>>());
        // Lists of up to NAMES_PER_ADDRESS + 3 entries among six names, many given again, as the set gave them.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for length in 0..=NAMES_PER_ADDRESS + 3 {
            for _ in 0..200 {
                let mut earlier = Vec::with_capacity(length);
                let mut when = now;
                for _ in 0..length {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    when += Duration::from_secs(1);
                    earlier.push((state % 6, when));
                }
                let expected = with_a_set(earlier.clone());
                latest_each(&mut earlier);
                assert_eq!(earlier, expected);
            }
        }
    }
}
