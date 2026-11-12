//! The table of rewritten TCP connections (ADR 0012): each connection an app opens through the
//! tunnel gets a fake port, so that Android's own TCP stack can terminate it at the engine's
//! listener as if it came from the fake peer `FAKE:port`, and the answers can be rewritten back.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The first fake port handed out by default.
pub const FIRST_PORT: u16 = 10_000;
/// The last fake port handed out by default.
pub const LAST_PORT: u16 = 60_000;

/// A connection that Android's stack never handed to the engine's relay, silent this long, is forgotten.
/// One it handed over is the relay's: only the relay forgets it, when the connection ends (an app's push
/// connection can be silent for half an hour, and RFC 5382 asks a NAT to keep an established one for
/// at least two hours and four minutes). The clock is time awake (`Instant`), as for every limit about
/// the network.
pub const TCP_IDLE: Duration = Duration::from_secs(600);

/// A fake port freed is not handed out again for this long: Android's stack may still hold the old
/// connection from it in `TIME_WAIT` (60 s on Linux), which a new SYN from the same port would meet.
pub const PORT_COOLING: Duration = Duration::from_secs(60);

/// Ports drawn at random before the table is searched in order: only a crowded table gets that far.
const DRAWS: usize = 32;

/// One rewritten TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The app's end of the connection.
    pub app: SocketAddr,
    /// Where the app connects to.
    pub destination: SocketAddr,
    /// When a packet of the connection last passed.
    pub seen: Instant,
    /// Whether the real server accepted. Until then the app's SYN is held: the app's socket must
    /// still exist when Android is asked whose it is, and a refused server must look refused.
    pub open: bool,
    /// Whether Android's stack handed the connection to the relay, which then alone forgets it.
    pub relayed: bool,
}

/// How a packet from an app fits the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A new connection: its fake port was just handed out, and its SYN must be held.
    New(u16),
    /// A known connection whose server has accepted.
    Open(u16),
    /// A known connection still waiting for its server: the app sent its SYN again.
    Waiting,
    /// Not a SYN, and not a known connection.
    Unknown,
    /// No fake port is free.
    Full,
}

/// The table, by fake port and by the app's side.
///
/// Fake ports are drawn at random, so that the next one cannot be guessed: an app that could guess it
/// might race the real connection to the engine's listener (which now also refuses any connection that
/// does not come from the fake address).
#[derive(Debug)]
pub struct Nat {
    by_fake: HashMap<u16, Entry>,
    by_app: HashMap<(SocketAddr, SocketAddr), u16>,
    /// The ports handed out, `first..=last`.
    first: u16,
    last: u16,
    /// Ports freed lately, oldest first, each with when it may be handed out again.
    cooling: VecDeque<(Instant, u16)>,
    cooling_set: HashSet<u16>,
    /// [`TCP_IDLE`] and [`PORT_COOLING`] unless the engine's limits say otherwise.
    idle: Duration,
    cooling_for: Duration,
    /// A keyed hash with keys drawn from the system, and how many draws it made.
    random: RandomState,
    draws: u64,
}

impl Default for Nat {
    fn default() -> Self {
        Self::with_ports(FIRST_PORT, LAST_PORT)
    }
}

impl Nat {
    /// A table with the engine's limits: its fake ports, how long an unrelayed connection may be
    /// silent, and how long a freed port cools.
    #[must_use]
    pub fn with_limits(limits: &crate::engine::Limits) -> Self {
        Self {
            idle: limits.tcp_idle,
            cooling_for: limits.port_cooling,
            ..Self::with_ports(limits.first_port, limits.last_port)
        }
    }

    /// A table that hands out the fake ports `first..=last`.
    #[must_use]
    pub fn with_ports(first: u16, last: u16) -> Self {
        Self {
            by_fake: HashMap::new(),
            by_app: HashMap::new(),
            first,
            last: last.max(first),
            cooling: VecDeque::new(),
            cooling_set: HashSet::new(),
            idle: TCP_IDLE,
            cooling_for: PORT_COOLING,
            random: RandomState::new(),
            draws: 0,
        }
    }

    /// Finds the connection of a packet from `app` to `destination`, or makes one for a SYN.
    pub fn lookup(
        &mut self,
        app: SocketAddr,
        destination: SocketAddr,
        syn: bool,
        now: Instant,
    ) -> Lookup {
        if let Some(&port) = self.by_app.get(&(app, destination)) {
            let Some(entry) = self.by_fake.get_mut(&port) else {
                return Lookup::Unknown;
            };
            entry.seen = now;
            return if entry.open {
                Lookup::Open(port)
            } else {
                Lookup::Waiting
            };
        }
        if !syn {
            return Lookup::Unknown;
        }
        self.cool(now);
        let span = u32::from(self.last - self.first) + 1;
        // Ports drawn at random; in a crowded table, then every port in order from the last one drawn.
        let mut start = 0;
        for _ in 0..DRAWS {
            start = self.draw() % span;
            if let Some(port) = self.free(start) {
                return self.hand_out(port, app, destination, now);
            }
        }
        for offset in 1..span {
            if let Some(port) = self.free((start + offset) % span) {
                return self.hand_out(port, app, destination, now);
            }
        }
        Lookup::Full
    }

    /// The port at `offset` from the first, if it is neither taken nor cooling.
    fn free(&self, offset: u32) -> Option<u16> {
        let port = self.first.checked_add(u16::try_from(offset).ok()?)?;
        (!self.by_fake.contains_key(&port) && !self.cooling_set.contains(&port)).then_some(port)
    }

    fn hand_out(
        &mut self,
        port: u16,
        app: SocketAddr,
        destination: SocketAddr,
        now: Instant,
    ) -> Lookup {
        self.by_fake.insert(
            port,
            Entry {
                app,
                destination,
                seen: now,
                open: false,
                relayed: false,
            },
        );
        self.by_app.insert((app, destination), port);
        Lookup::New(port)
    }

    /// A number no one outside the engine can foresee: the keyed hash of a counter.
    fn draw(&mut self) -> u32 {
        self.draws = self.draws.wrapping_add(1);
        u32::try_from(self.random.hash_one(self.draws) >> 32).unwrap_or(0)
    }

    /// Lets the ports whose cooling is over be handed out again.
    fn cool(&mut self, now: Instant) {
        while let Some(&(until, port)) = self.cooling.front() {
            if until > now {
                break;
            }
            self.cooling.pop_front();
            self.cooling_set.remove(&port);
        }
    }

    /// The connection behind a fake port, marking it as just seen.
    pub fn by_fake(&mut self, port: u16, now: Instant) -> Option<Entry> {
        let entry = self.by_fake.get_mut(&port)?;
        entry.seen = now;
        Some(*entry)
    }

    /// Marks a connection's server as having accepted.
    pub fn open(&mut self, port: u16) {
        if let Some(entry) = self.by_fake.get_mut(&port) {
            entry.open = true;
        }
    }

    /// Marks a connection as the relay's: the sweep leaves it alone from then on.
    pub fn relayed(&mut self, port: u16) {
        if let Some(entry) = self.by_fake.get_mut(&port) {
            entry.relayed = true;
        }
    }

    /// Forgets a connection; its port cools ([`PORT_COOLING`] by default) before it is handed out again.
    pub fn remove(&mut self, port: u16, now: Instant) {
        if let Some(entry) = self.by_fake.remove(&port) {
            self.by_app.remove(&(entry.app, entry.destination));
            self.cooling.push_back((now + self.cooling_for, port));
            self.cooling_set.insert(port);
        }
    }

    /// Forgets the connection behind `port` if it is still the one from `app` to `destination`.
    pub fn remove_if(&mut self, port: u16, app: SocketAddr, destination: SocketAddr, now: Instant) {
        if self
            .by_fake
            .get(&port)
            .is_some_and(|e| e.app == app && e.destination == destination)
        {
            self.remove(port, now);
        }
    }

    /// Forgets connections not yet relayed and silent for longer than [`TCP_IDLE`] (by default); returns their
    /// fake ports.
    pub fn sweep(&mut self, now: Instant) -> Vec<u16> {
        let stale: Vec<u16> = self
            .by_fake
            .iter()
            .filter(|(_, e)| !e.relayed && now.duration_since(e.seen) > self.idle)
            .map(|(&p, _)| p)
            .collect();
        for &port in &stale {
            self.remove(port, now);
        }
        stale
    }

    /// How many connections the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_fake.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_fake.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ends(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([10, 215, 173, 1], port)),
            SocketAddr::from(([93, 184, 216, 34], 443)),
        )
    }

    #[test]
    fn hands_out_a_port_per_connection_and_finds_it_again() {
        let mut nat = Nat::default();
        let now = Instant::now();
        let (app, server) = ends(40_000);
        assert_eq!(nat.lookup(app, server, false, now), Lookup::Unknown);
        let Lookup::New(port) = nat.lookup(app, server, true, now) else {
            unreachable!("no port")
        };
        assert_eq!(nat.lookup(app, server, true, now), Lookup::Waiting);
        nat.open(port);
        assert_eq!(nat.lookup(app, server, false, now), Lookup::Open(port));
        assert_eq!(
            nat.by_fake(port, now).map(|e| (e.app, e.destination)),
            Some((app, server))
        );
        let (other, _) = ends(40_001);
        assert!(matches!(nat.lookup(other, server, true, now), Lookup::New(p) if p != port));
        nat.remove(port, now);
        assert_eq!(nat.lookup(app, server, false, now), Lookup::Unknown);
    }

    /// The next port cannot be told from the last: of 200 ports handed out in a row, far fewer than
    /// half follow the one before (in order, all would).
    #[test]
    fn hands_out_ports_at_random() {
        let mut nat = Nat::default();
        let now = Instant::now();
        let server = ends(0).1;
        let ports: Vec<u16> = (0..200)
            .filter_map(
                |i| match nat.lookup(ends(30_000 + i).0, server, true, now) {
                    Lookup::New(port) => Some(port),
                    _ => None,
                },
            )
            .collect();
        assert_eq!(ports.len(), 200);
        assert!(ports.iter().all(|p| (FIRST_PORT..=LAST_PORT).contains(p)));
        let next = ports
            .windows(2)
            .filter(|w| w[1] == w[0].wrapping_add(1))
            .count();
        assert!(next < 10, "{next} of 199 ports followed the one before");
    }

    /// A freed port is not handed out again until it has cooled, so that a new SYN does not meet the
    /// old connection's `TIME_WAIT` in Android's stack.
    #[test]
    fn a_freed_port_cools_before_it_is_handed_out_again() {
        let mut nat = Nat::with_ports(20_000, 20_001);
        let then = Instant::now();
        let server = ends(0).1;
        let Lookup::New(first) = nat.lookup(ends(40_000).0, server, true, then) else {
            unreachable!("no port")
        };
        let Lookup::New(second) = nat.lookup(ends(40_001).0, server, true, then) else {
            unreachable!("no port")
        };
        assert_ne!(first, second);
        nat.remove(first, then);
        let soon = then + Duration::from_secs(1);
        assert_eq!(nat.lookup(ends(40_002).0, server, true, soon), Lookup::Full);
        let later = then + PORT_COOLING;
        assert_eq!(
            nat.lookup(ends(40_002).0, server, true, later),
            Lookup::New(first)
        );
    }

    /// A connection the relay holds outlives any silence: a push connection's next message, half an
    /// hour later, must still reach the app. One never relayed is forgotten after [`TCP_IDLE`].
    #[test]
    fn keeps_a_relayed_connection_through_silence() {
        let mut nat = Nat::default();
        let then = Instant::now();
        let server = ends(0).1;
        let Lookup::New(relayed) = nat.lookup(ends(40_000).0, server, true, then) else {
            unreachable!("no port")
        };
        let Lookup::New(waiting) = nat.lookup(ends(40_001).0, server, true, then) else {
            unreachable!("no port")
        };
        nat.open(relayed);
        nat.relayed(relayed);
        let hours = then + Duration::from_hours(3);
        assert_eq!(nat.sweep(hours), vec![waiting]);
        assert!(nat.by_fake(relayed, hours).is_some());
        nat.remove_if(relayed, ends(40_000).0, server, hours);
        assert!(nat.is_empty());
    }

    #[test]
    fn forgets_silent_connections() {
        let mut nat = Nat::default();
        let then = Instant::now();
        let (app, server) = ends(40_000);
        let Lookup::New(port) = nat.lookup(app, server, true, then) else {
            unreachable!("no port")
        };
        assert_eq!(nat.sweep(then + Duration::from_secs(1)), Vec::<u16>::new());
        assert_eq!(
            nat.sweep(then + TCP_IDLE + Duration::from_secs(1)),
            vec![port]
        );
        assert!(nat.is_empty());
    }

    /// Every port of the range is handed out, the last ones found in order once draws fail, and then
    /// the table says it is full.
    #[test]
    fn says_when_every_port_is_taken() {
        let mut nat = Nat::with_ports(30_000, 30_499);
        let now = Instant::now();
        let server = ends(0).1;
        let mut ports = HashSet::new();
        for i in 0..500 {
            let Lookup::New(port) = nat.lookup(ends(40_000 + i).0, server, true, now) else {
                unreachable!("connection {i} got no port")
            };
            ports.insert(port);
        }
        assert_eq!(ports.len(), 500);
        assert_eq!(
            nat.lookup(ends(1).0, SocketAddr::from(([1, 1, 1, 1], 443)), true, now),
            Lookup::Full
        );
    }
}
