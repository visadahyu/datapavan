//! The names Watch saw in DNS answers, by address, so that a flow can be named after the name the app
//! asked for before it connected (W3).
//!
//! An entry lives at least [`MIN_KEEP`], however short the answer's TTL: apps keep addresses longer
//! than DNS says, and a flow named "unknown" because the TTL ran out a minute earlier tells the user
//! less than the name. The table holds at most [`CAPACITY`] addresses; the oldest go first.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How long an entry lives at least.
pub const MIN_KEEP: Duration = Duration::from_secs(3600);
/// How long an entry lives at most.
pub const MAX_KEEP: Duration = Duration::from_hours(24);
/// The most addresses kept.
pub const CAPACITY: usize = 8192;

/// Names by address.
#[derive(Debug, Default)]
pub struct Names {
    by_address: HashMap<IpAddr, (String, Instant)>,
    order: VecDeque<IpAddr>,
}

impl Names {
    /// Remembers that `address` was given for `name`, with the answer's `ttl` in seconds.
    pub fn insert(&mut self, address: IpAddr, name: &str, ttl: u32, now: Instant) {
        let keep = Duration::from_secs(u64::from(ttl)).clamp(MIN_KEEP, MAX_KEEP);
        if self
            .by_address
            .insert(address, (name.to_owned(), now + keep))
            .is_none()
        {
            self.order.push_back(address);
        }
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.by_address.remove(&oldest);
            }
        }
    }

    /// The name last given for `address`, if it is still kept.
    #[must_use]
    pub fn get(&self, address: IpAddr, now: Instant) -> Option<&str> {
        self.by_address
            .get(&address)
            .filter(|(_, until)| *until > now)
            .map(|(name, _)| name.as_str())
    }

    /// Forgets everything, as when the user wipes the log.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.order.clear();
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
        names.insert(a, "example.com", 30, now);
        assert_eq!(
            names.get(a, now + Duration::from_mins(30)),
            Some("example.com")
        );
        assert_eq!(names.get(a, now + MIN_KEEP + Duration::from_secs(1)), None);
        names.insert(a, "www.example.com", 30, now);
        assert_eq!(names.get(a, now), Some("www.example.com"));
        for i in 0..u32::try_from(CAPACITY).unwrap_or(0) {
            names.insert(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), "x", 60, now);
        }
        assert_eq!(names.len(), CAPACITY);
        assert_eq!(names.get(a, now), None, "the oldest went first");
    }
}
