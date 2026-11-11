//! Stand-in addresses for the names that chained apps look up (ADR 0038, W6).
//!
//! A chained app asks Watch for a name's address; Watch answers with an address of its own from
//! 198.18.0.0/15 and remembers the name, and when the app connects to that address, the name goes to
//! the tool, which resolves it at its far end. Each name keeps its address for as long as it is used,
//! so that connections in parallel agree. At most [`CAPACITY`] names are held; when they are all in
//! use, the name used least recently gives up its address. New addresses are taken in turn around the
//! whole range, so that an address given up is not handed out again before 131,070 others: an app that
//! still holds it in a cache of its own meets "unknown" rather than another name.
//!
//! The map lives in memory only. It is the list of names the user opened through the tool, so Watch
//! never writes it down (ADR 0038).

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

/// The range's first address, 198.18.0.0 (RFC 2544).
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
/// The number of addresses in 198.18.0.0/15.
const SIZE: u32 = 1 << 17;
/// The most names held at once: about 2 MB at most, against Watch's memory budget of 48 MB.
pub const CAPACITY: usize = 16_384;

/// Whether `ip` is in the stand-ins' range.
#[must_use]
pub fn is_stand_in(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => u32::from(v4).wrapping_sub(BASE) < SIZE,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .is_some_and(|v4| is_stand_in(IpAddr::V4(v4))),
    }
}

/// Names and their stand-in addresses.
#[derive(Debug)]
pub struct StandIns {
    capacity: usize,
    by_name: HashMap<String, u32>,
    /// Each held offset into the range: its name, and when it was last used.
    by_offset: HashMap<u32, (String, u64)>,
    /// The held offsets by last use, oldest first.
    by_use: BTreeMap<u64, u32>,
    clock: u64,
    cursor: u32,
}

impl Default for StandIns {
    fn default() -> Self {
        Self::with_capacity(CAPACITY)
    }
}

impl StandIns {
    /// A map holding at most `capacity` names (at least 1; the tests use small ones).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.clamp(1, CAPACITY),
            by_name: HashMap::new(),
            by_offset: HashMap::new(),
            by_use: BTreeMap::new(),
            clock: 0,
            cursor: 0,
        }
    }

    /// The stand-in for `name` (lower case, without a final dot), given now if it has none.
    pub fn address(&mut self, name: &str) -> Ipv4Addr {
        if let Some(&offset) = self.by_name.get(name) {
            self.touch(offset);
            return Self::at(offset);
        }
        while self.by_offset.len() >= self.capacity {
            let Some((_, oldest)) = self.by_use.pop_first() else {
                break;
            };
            if let Some((old, _)) = self.by_offset.remove(&oldest) {
                self.by_name.remove(&old);
            }
        }
        let offset = self.next_free();
        self.clock += 1;
        self.by_name.insert(name.to_owned(), offset);
        self.by_offset.insert(offset, (name.to_owned(), self.clock));
        self.by_use.insert(self.clock, offset);
        Self::at(offset)
    }

    /// The name `ip` stands in for, if the map holds it.
    pub fn name(&mut self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else {
            return ip
                .to_canonical()
                .is_ipv4()
                .then(|| self.name(ip.to_canonical()))
                .flatten();
        };
        let offset = u32::from(v4).wrapping_sub(BASE);
        let name = self.by_offset.get(&offset)?.0.clone();
        self.touch(offset);
        Some(name)
    }

    /// How many names are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_offset.len()
    }

    /// Whether no name is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_offset.is_empty()
    }

    fn touch(&mut self, offset: u32) {
        if let Some((_, used)) = self.by_offset.get_mut(&offset) {
            self.by_use.remove(used);
            self.clock += 1;
            *used = self.clock;
            self.by_use.insert(self.clock, offset);
        }
    }

    /// The next offset in turn that holds no name, skipping the range's first and last addresses.
    /// Fewer names are held than the range has addresses, so one is always found.
    fn next_free(&mut self) -> u32 {
        loop {
            self.cursor = (self.cursor + 1) % SIZE;
            if self.cursor != 0
                && self.cursor != SIZE - 1
                && !self.by_offset.contains_key(&self.cursor)
            {
                return self.cursor;
            }
        }
    }

    fn at(offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(BASE + offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_each_name_one_address_and_names_it_back() {
        let mut map = StandIns::default();
        let a = map.address("example.com");
        let b = map.address("example.org");
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(b, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(map.address("example.com"), a);
        assert_eq!(map.name(IpAddr::V4(b)), Some("example.org".into()));
        let mapped = IpAddr::V6(a.to_ipv6_mapped());
        assert_eq!(map.name(mapped), Some("example.com".into()));
        assert_eq!(map.name(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9))), None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn the_name_used_least_recently_gives_up_its_address() {
        let mut map = StandIns::with_capacity(2);
        let a = map.address("a.example");
        let b = map.address("b.example");
        // Using a makes b the oldest.
        assert_eq!(map.name(IpAddr::V4(a)), Some("a.example".into()));
        let c = map.address("c.example");
        assert_eq!(map.name(IpAddr::V4(b)), None);
        assert_eq!(map.name(IpAddr::V4(a)), Some("a.example".into()));
        assert_eq!(map.name(IpAddr::V4(c)), Some("c.example".into()));
        // b's address is not handed out again at once.
        assert_ne!(map.address("b.example"), b);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn hands_out_the_whole_range_in_turn_and_skips_its_ends() {
        let mut map = StandIns::with_capacity(1);
        let mut last = Ipv4Addr::UNSPECIFIED;
        for i in 0..SIZE + 2 {
            last = map.address(&format!("n{i}.example"));
            assert!(is_stand_in(IpAddr::V4(last)));
            assert_ne!(last, Ipv4Addr::new(198, 18, 0, 0));
            assert_ne!(last, Ipv4Addr::new(198, 19, 255, 255));
        }
        // Around once (two ends skipped), and on to the fourth address.
        assert_eq!(last, Ipv4Addr::new(198, 18, 0, 4));
    }

    #[test]
    fn knows_the_range() {
        assert!(is_stand_in(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0))));
        assert!(is_stand_in(IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
        assert!(!is_stand_in(IpAddr::V4(Ipv4Addr::new(198, 20, 0, 0))));
        assert!(!is_stand_in(IpAddr::V4(Ipv4Addr::new(198, 17, 255, 255))));
        assert!(!is_stand_in(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }
}
