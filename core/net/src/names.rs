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
//! addresses, at most [`PUBLIC_CAPACITY`] of them: a hello that offers ECH and names one of them hides
//! the real name. They are scoped as the addresses are: those in Android's resolver's answers hide names
//! in every app's flows, those an app got from a resolver of its own in that app's flows only, so that
//! a public name never names a flow wherever Watch saw its configuration, and no app can hide the names
//! of another's (review 1 of W5's first part, names, finding 1).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long an entry lives at least.
pub const MIN_KEEP: Duration = Duration::from_secs(3600);
/// How long an entry lives at most.
pub const MAX_KEEP: Duration = Duration::from_hours(24);
/// The most addresses kept.
pub const CAPACITY: usize = 8192;
/// The most public names kept.
pub const PUBLIC_CAPACITY: usize = 256;

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

/// Names by address.
#[derive(Debug, Default)]
pub struct Names {
    by_address: HashMap<(IpAddr, Scope), Given>,
    order: VecDeque<(IpAddr, Scope)>,
    public: HashMap<(String, Scope), Instant>,
    public_order: VecDeque<(String, Scope)>,
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
        if self.by_address.insert((address, scope), given).is_none() {
            self.order.push_back((address, scope));
        }
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.by_address.remove(&oldest);
            }
        }
    }

    /// Remembers that a DNS answer gave an ECH configuration with the public name `name`, for the flows
    /// of `scope`.
    pub fn insert_public(&mut self, name: &str, scope: Scope, ttl: u32, now: Instant) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        let key = (name.to_owned(), scope);
        if self.public.insert(key.clone(), now + keep).is_none() {
            self.public_order.push_back(key);
        }
        while self.public_order.len() > PUBLIC_CAPACITY {
            if let Some(oldest) = self.public_order.pop_front() {
                self.public.remove(&oldest);
            }
        }
    }

    /// Whether `name` is the public name of an ECH configuration still kept for the flows of the app with
    /// `uid`: from Android's resolver, or from that app's own.
    #[must_use]
    pub fn is_public(&self, name: &str, uid: Option<u32>, now: Instant) -> bool {
        let live = |scope: Scope| {
            self.public
                .get(&(name.to_owned(), scope))
                .is_some_and(|until| *until > now)
        };
        live(None) || uid.is_some_and(|uid| live(Some(uid)))
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
        let own = uid.and_then(|uid| self.by_address.get(&(address, Some(uid))));
        own.into_iter()
            .chain(self.by_address.get(&(address, None)))
            .find(|given| given.until > now)
    }

    /// Forgets everything, as when the user wipes the log.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.order.clear();
        self.public.clear();
        self.public_order.clear();
    }

    /// How many addresses are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Whether none is kept.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
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
