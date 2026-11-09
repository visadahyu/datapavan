//! The table of rewritten TCP connections (ADR 0012): each connection an app opens through the
//! tunnel gets a fake port, so that Android's own TCP stack can terminate it at the engine's
//! listener as if it came from the fake peer `FAKE:port`, and the answers can be rewritten back.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The fake ports handed out.
const FIRST_PORT: u16 = 10_000;
const LAST_PORT: u16 = 60_000;

/// A connection silent for this long is forgotten. TCP keepalives from apps come far more often.
pub const TCP_IDLE: Duration = Duration::from_secs(600);

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
#[derive(Debug, Default)]
pub struct Nat {
    by_fake: HashMap<u16, Entry>,
    by_app: HashMap<(SocketAddr, SocketAddr), u16>,
    next: u16,
}

impl Nat {
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
        for _ in FIRST_PORT..=LAST_PORT {
            self.next = if (FIRST_PORT..LAST_PORT).contains(&self.next) {
                self.next + 1
            } else {
                FIRST_PORT
            };
            if let std::collections::hash_map::Entry::Vacant(free) = self.by_fake.entry(self.next) {
                free.insert(Entry {
                    app,
                    destination,
                    seen: now,
                    open: false,
                });
                self.by_app.insert((app, destination), self.next);
                return Lookup::New(self.next);
            }
        }
        Lookup::Full
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

    /// Forgets a connection.
    pub fn remove(&mut self, port: u16) {
        if let Some(entry) = self.by_fake.remove(&port) {
            self.by_app.remove(&(entry.app, entry.destination));
        }
    }

    /// Forgets the connection behind `port` if it is still the one from `app` to `destination`.
    pub fn remove_if(&mut self, port: u16, app: SocketAddr, destination: SocketAddr) {
        if self
            .by_fake
            .get(&port)
            .is_some_and(|e| e.app == app && e.destination == destination)
        {
            self.remove(port);
        }
    }

    /// Forgets connections silent for longer than [`TCP_IDLE`]; returns their fake ports.
    pub fn sweep(&mut self, now: Instant) -> Vec<u16> {
        let stale: Vec<u16> = self
            .by_fake
            .iter()
            .filter(|(_, e)| now.duration_since(e.seen) > TCP_IDLE)
            .map(|(&p, _)| p)
            .collect();
        for &port in &stale {
            self.remove(port);
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
        nat.remove(port);
        assert_eq!(nat.lookup(app, server, false, now), Lookup::Unknown);
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

    #[test]
    fn says_when_every_port_is_taken() {
        let mut nat = Nat::default();
        let now = Instant::now();
        let server = ends(0).1;
        let count = usize::from(LAST_PORT - FIRST_PORT) + 1;
        for i in 0..count {
            let app = SocketAddr::from(([10, 215, 173, 1], u16::try_from(i % 60_000).unwrap_or(0)));
            let app = SocketAddr::new(
                if i < 60_000 {
                    app.ip()
                } else {
                    [10, 215, 173, 3].into()
                },
                app.port(),
            );
            assert!(
                matches!(nat.lookup(app, server, true, now), Lookup::New(_)),
                "connection {i}"
            );
        }
        assert_eq!(
            nat.lookup(ends(1).0, SocketAddr::from(([1, 1, 1, 1], 443)), true, now),
            Lookup::Full
        );
    }
}
