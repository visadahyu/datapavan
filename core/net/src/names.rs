//! The names Watch saw in DNS answers, by address, so that a flow can be named after the name the app
//! asked for before it connected (W3).
//!
//! An entry lives at least [`MIN_KEEP`], however short the answer's TTL: apps keep addresses longer
//! than DNS says, and a flow named "unknown" because the TTL ran out a minute earlier tells the user
//! less than the name. The table holds at most [`CAPACITY`] addresses; the oldest go first.
//!
//! The answers Android's resolver gave through Watch name every app's flows. The answers an app got
//! from a resolver of its own, past Watch's (plain DNS to another server), name only that app's flows:
//! an app chooses that resolver, and must not be able to rename other apps' connections through it.
//!
//! It also keeps the public names of the ECH configurations in the DNS answers, as long as the
//! addresses, at most [`PUBLIC_CAPACITY`] of them: a hello that offers ECH and names one of them hides
//! the real name.

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

/// Names by address.
#[derive(Debug, Default)]
pub struct Names {
    by_address: HashMap<(IpAddr, Scope), (String, Instant)>,
    order: VecDeque<(IpAddr, Scope)>,
    public: HashMap<String, Instant>,
    public_order: VecDeque<String>,
}

impl Names {
    /// Remembers that `address` was given for `name`, with the answer's `ttl` in seconds, for the flows
    /// of `scope`.
    pub fn insert(&mut self, address: IpAddr, scope: Scope, name: &str, ttl: u32, now: Instant) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        if self
            .by_address
            .insert((address, scope), (name.to_owned(), now + keep))
            .is_none()
        {
            self.order.push_back((address, scope));
        }
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.by_address.remove(&oldest);
            }
        }
    }

    /// Remembers that a DNS answer gave an ECH configuration with the public name `name`.
    pub fn insert_public(&mut self, name: &str, ttl: u32, now: Instant) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        if self.public.insert(name.to_owned(), now + keep).is_none() {
            self.public_order.push_back(name.to_owned());
        }
        while self.public_order.len() > PUBLIC_CAPACITY {
            if let Some(oldest) = self.public_order.pop_front() {
                self.public.remove(&oldest);
            }
        }
    }

    /// Whether `name` is the public name of an ECH configuration still kept.
    #[must_use]
    pub fn is_public(&self, name: &str, now: Instant) -> bool {
        self.public.get(name).is_some_and(|until| *until > now)
    }

    /// The name last given for `address` to the app with `uid`, if it is still kept: from that app's own
    /// resolver first, else from Android's.
    #[must_use]
    pub fn get(&self, address: IpAddr, uid: Option<u32>, now: Instant) -> Option<&str> {
        let own = uid.and_then(|uid| self.by_address.get(&(address, Some(uid))));
        own.into_iter()
            .chain(self.by_address.get(&(address, None)))
            .find(|(_, until)| *until > now)
            .map(|(name, _)| name.as_str())
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

    #[test]
    fn keeps_a_name_at_least_an_hour_and_the_newest_ones() {
        let mut names = Names::default();
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        names.insert(a, None, "example.com", 30, now);
        assert_eq!(
            names.get(a, None, now + Duration::from_mins(30)),
            Some("example.com")
        );
        assert_eq!(
            names.get(a, None, now + MIN_KEEP + Duration::from_secs(1)),
            None
        );
        names.insert(a, None, "www.example.com", 30, now);
        assert_eq!(names.get(a, None, now), Some("www.example.com"));
        for i in 0..u32::try_from(CAPACITY).unwrap_or(0) {
            names.insert(
                IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
                None,
                "x",
                60,
                now,
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
        names.insert(a, Some(10_123), "own.example", 300, now);
        assert_eq!(names.get(a, Some(10_123), now), Some("own.example"));
        assert_eq!(names.get(a, Some(10_456), now), None);
        assert_eq!(names.get(a, None, now), None);
        names.insert(a, None, "shared.example", 300, now);
        assert_eq!(names.get(a, Some(10_123), now), Some("own.example"));
        assert_eq!(names.get(a, Some(10_456), now), Some("shared.example"));
    }

    #[test]
    fn keeps_public_names_for_a_while_and_the_newest_ones() {
        let mut names = Names::default();
        let now = Instant::now();
        names.insert_public("cover.example", 300, now);
        assert!(names.is_public("cover.example", now));
        assert!(!names.is_public("other.example", now));
        assert!(!names.is_public("cover.example", now + MIN_KEEP + Duration::from_secs(1)));
        for i in 0..PUBLIC_CAPACITY {
            names.insert_public(&format!("p{i}.example"), 300, now);
        }
        assert!(
            !names.is_public("cover.example", now),
            "the oldest went first"
        );
        names.clear();
        assert!(!names.is_public("p1.example", now));
    }
}
