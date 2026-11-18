//! The engine's clock (finding 4 of the independent review of 2026-11-09): the reading of time that
//! must follow the time the user lives in, handed to the engine with its platform
//! ([`super::Platform::clock`]), so that tests can move it: a sleep of hours, a jump back, a jump
//! forward.
//!
//! The engine's other timings, its NAT, UDP mappings, fragments, pings and waits, run on tokio's timers
//! and on [`std::time::Instant`], the monotonic clock, which stands still while the phone sleeps, as the
//! kernel's own timers and the apps' do: a connection idle across a night is still the apps' and the
//! kernel's, and so still the engine's.

use std::time::{SystemTime, UNIX_EPOCH};

/// The time, as the engine reads it for what follows the user's time.
pub trait Clock: Send + Sync {
    /// The wall clock: milliseconds since 1970, UTC, 0 before. It runs on while the phone sleeps, and
    /// the user or the network may set it, back or forward. The log's times and quarter hours follow it.
    fn wall_ms(&self) -> u64;
}

/// The phone's own clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that tests move by hand.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ManualClock {
    wall: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl ManualClock {
    /// A clock whose wall clock reads `wall_ms`.
    pub(crate) fn at(wall_ms: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            wall: wall_ms.into(),
        })
    }

    /// The phone sleeps, or runs, for `ms`: the wall clock moves on. The monotonic clock, which this one
    /// does not hold, stands still only in a sleep.
    pub(crate) fn pass(&self, ms: u64) {
        self.wall.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// The wall clock is set to `wall_ms`, back or forward, as by the user or the network.
    pub(crate) fn set(&self, wall_ms: u64) {
        self.wall
            .store(wall_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn wall_ms(&self) -> u64 {
        self.wall.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The phone's clock is past 2026.
    #[test]
    fn the_system_clock_reads_the_phones_clock() {
        assert!(SystemClock.wall_ms() > 1_767_225_600_000, "before 2026");
    }

    #[test]
    fn a_manual_clock_moves_as_told() {
        let clock = ManualClock::at(1_000);
        clock.pass(500);
        assert_eq!(clock.wall_ms(), 1_500);
        clock.set(200);
        assert_eq!(clock.wall_ms(), 200);
    }
}
