//! The names Watch saw in DNS answers, by address, so that a flow can be named after the name the app
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
//! since the phone started, sleep included, and only an entry still held by that clock stands beside a
//! connection's own name ([`Names::held`]; review 1 of W5's first part, engine, finding 7).
//!
//! The answers Android's resolver gave through Watch name every app's flows. The answers an app got
//! from a resolver of its own, past Watch's (plain DNS to another server), name only that app's flows:
//! an app chooses that resolver, and must not be able to rename other apps' connections through it.
//!
//! It also keeps the public names of the ECH configurations in the DNS answers, as long as the
//! addresses: a hello that offers ECH and names one of them hides the real name. They are scoped as the
//! addresses are: those in Android's resolver's answers hide names in every app's flows, those an app got
//! from a resolver of its own in that app's flows only, so that a public name never names a flow wherever
//! Watch saw its configuration, and no app can hide the names of another's (review 1 of W5's first part,
//! names, finding 1).
//!
//! Each scope has a table of its own, the oldest going first when it is full: Android's resolver's holds
//! [`CAPACITY`] addresses and [`PUBLIC_CAPACITY`] public names, and each app's own [`OWN_CAPACITY`] and
//! [`OWN_PUBLIC_CAPACITY`]. So an app's own resolver can push out only that app's names, never Android's
//! nor another app's (review 2 of W5's first part: in one table, an app's answers could push Android's
//! public names out, and the provider's cover name named every other app's flows again). The memory grows
//! with the apps that use a resolver of their own, by at most their own tables each.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long an entry lives at least.
pub const MIN_KEEP: Duration = Duration::from_secs(3600);
/// How long an entry lives at most.
pub const MAX_KEEP: Duration = Duration::from_hours(24);
/// The most addresses kept from Android's resolver's answers.
pub const CAPACITY: usize = 8192;
/// The most addresses kept from one app's own resolver's answers.
pub const OWN_CAPACITY: usize = 1024;
/// The most public names kept from Android's resolver's answers.
pub const PUBLIC_CAPACITY: usize = 256;
/// The most public names kept from one app's own resolver's answers.
pub const OWN_PUBLIC_CAPACITY: usize = 64;

/// Whose flows a name may name: every app's, or only the app with this UID.
pub type Scope = Option<u32>;

/// A name an answer gave an address, kept until `until` on the monotonic clock, to name flows, and until
/// `held_until` in time since the phone started, to stand beside a name a connection sent.
#[derive(Debug)]
struct Given {
    name: String,
    until: Instant,
    held_until: Duration,
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
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Hash + Eq + Clone, V> Fifo<K, V> {
    /// Keeps `value` for `key`, and at most `cap` entries, the oldest going first.
    fn insert(&mut self, key: K, value: V, cap: usize) {
        if self.entries.insert(key.clone(), value).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > cap {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

/// Entries for every app's flows, and for each app's own, each scope in a table of its own.
#[derive(Debug)]
struct Scoped<K, V> {
    shared: Fifo<K, V>,
    own: HashMap<u32, Fifo<K, V>>,
    /// The most entries of the shared table, and of each app's.
    caps: (usize, usize),
}

impl<K: Hash + Eq + Clone, V> Scoped<K, V> {
    fn new(caps: (usize, usize)) -> Self {
        Self {
            shared: Fifo::default(),
            own: HashMap::new(),
            caps,
        }
    }

    fn insert(&mut self, scope: Scope, key: K, value: V) {
        match scope {
            None => self.shared.insert(key, value, self.caps.0),
            Some(uid) => self
                .own
                .entry(uid)
                .or_default()
                .insert(key, value, self.caps.1),
        }
    }

    /// The entries for the flows of the app with `uid`: its own first, then every app's.
    fn for_app(&self, key: &K, uid: Option<u32>) -> impl Iterator<Item = &V> {
        let own = uid
            .and_then(|uid| self.own.get(&uid))
            .and_then(|table| table.entries.get(key));
        own.into_iter().chain(self.shared.entries.get(key))
    }

    fn clear(&mut self) {
        self.shared = Fifo::default();
        self.own.clear();
    }

    fn len(&self) -> usize {
        self.shared.entries.len() + self.own.values().map(|t| t.entries.len()).sum::<usize>()
    }
}

/// Names by address.
#[derive(Debug)]
pub struct Names {
    addresses: Scoped<IpAddr, Given>,
    public: Scoped<String, Instant>,
}

impl Default for Names {
    fn default() -> Self {
        Self {
            addresses: Scoped::new((CAPACITY, OWN_CAPACITY)),
            public: Scoped::new((PUBLIC_CAPACITY, OWN_PUBLIC_CAPACITY)),
        }
    }
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
        let given = Given {
            name: name.to_owned(),
            until: now + keep,
            held_until: boot.saturating_add(keep),
        };
        self.addresses.insert(scope, address, given);
    }

    /// Remembers that a DNS answer gave an ECH configuration with the public name `name`, for the flows
    /// of `scope`.
    pub fn insert_public(&mut self, name: &str, scope: Scope, ttl: u32, now: Instant) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        self.public.insert(scope, name.to_owned(), now + keep);
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

    /// Whether the name [`Names::get`] gives for `address` and the app with `uid` is `name`, and is
    /// still held in time since the phone started (`boot`), its sleep included: whether it may stand
    /// beside the name a connection sent, as a difference that is not only its age.
    #[must_use]
    pub fn held(
        &self,
        address: IpAddr,
        uid: Option<u32>,
        name: &str,
        (now, boot): (Instant, Duration),
    ) -> bool {
        self.given(address, uid, now)
            .is_some_and(|given| given.name == name && given.held_until > boot)
    }

    fn given(&self, address: IpAddr, uid: Option<u32>, now: Instant) -> Option<&Given> {
        self.addresses
            .for_app(&address, uid)
            .find(|given| given.until > now)
    }

    /// Forgets everything, as when the user wipes the log.
    pub fn clear(&mut self) {
        self.addresses.clear();
        self.public.clear();
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

    /// A name is held beside a connection's own for its keep in time since start, sleep included: after
    /// a night, though the monotonic clock moved a minute, it names flows still and is held no more; a
    /// name the address was not given is not held.
    #[test]
    fn a_name_kept_through_a_night_names_flows_but_stands_beside_none() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "www.example.com", 60, (now, BOOT));
        let minute = now + Duration::from_mins(1);
        assert!(names.held(
            a,
            Some(10_123),
            "www.example.com",
            (minute, BOOT + Duration::from_mins(59))
        ));
        assert!(!names.held(a, None, "other.example", (minute, BOOT)));
        // Held until its hold ends, not at its end.
        assert!(!names.held(a, None, "www.example.com", (minute, BOOT + MIN_KEEP)));
        let night = BOOT + Duration::from_hours(8);
        assert_eq!(names.get(a, None, minute), Some("www.example.com"));
        assert!(!names.held(a, None, "www.example.com", (minute, night)));
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
        for i in 0..PUBLIC_CAPACITY + OWN_PUBLIC_CAPACITY {
            names.insert_public(&format!("p{i}.example"), Some(10_999), 300, now);
        }
        for i in 0..u32::try_from(CAPACITY + OWN_CAPACITY).unwrap_or(0) {
            let other = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            names.insert(other, Some(10_999), "x.example", 300, (now, BOOT));
        }
        assert!(names.is_public("cover.example", Some(10_456), now));
        assert!(names.is_public("mine.example", Some(10_123), now));
        assert_eq!(names.get(a, Some(10_123), now), Some("www.example.com"));
        assert_eq!(names.get(a, Some(10_456), now), Some("own.example"));
        // The flooding app's own tables keep only their newest.
        assert!(!names.is_public("p0.example", Some(10_999), now));
        let last = PUBLIC_CAPACITY + OWN_PUBLIC_CAPACITY - 1;
        assert!(names.is_public(&format!("p{last}.example"), Some(10_999), now));
        assert_eq!(names.len(), 2 + OWN_CAPACITY);
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
}
