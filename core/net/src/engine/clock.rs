//! The engine's clock (finding 4 of the independent review of 2026-11-09): the two readings of time
//! that must follow the time the user lives in, handed to the engine with its platform
//! ([`super::Platform::clock`]), so that tests can move them: a sleep of hours, a jump back, a jump
//! forward.
//!
//! The engine's other timings, its NAT, UDP mappings, fragments, pings and waits, run on tokio's timers
//! and on [`std::time::Instant`], the monotonic clock, which stands still while the phone sleeps, as the
//! kernel's own timers and the apps' do: a connection idle across a night is still the apps' and the
//! kernel's, and so still the engine's. ADR 0044 lists every reading of time in the engine, what a sleep
//! or a jump of the wall clock does to it, and why it reads the clock it reads.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The time, as the engine reads it for what follows the user's time.
pub trait Clock: Send + Sync {
    /// The wall clock: milliseconds since 1970, UTC, 0 before. It runs on while the phone sleeps, and
    /// the user or the network may set it, back or forward. The log's times and quarter hours follow it.
    fn wall_ms(&self) -> u64;

    /// How long since the phone started, its sleep included (`CLOCK_BOOTTIME`): it never stands still
    /// and never jumps. The caches that keep DNS answers for their time to live follow it.
    fn since_boot(&self) -> Duration;
}

/// The phone's own clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn wall_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    /// `clock_gettime(CLOCK_BOOTTIME)`, through nix's safe function. It cannot fail on Linux since
    /// 2.6.39; were it to, the answer is the longest time there is, so that a cache keeps nothing rather
    /// than an answer for ever.
    fn since_boot(&self) -> Duration {
        use nix::time::{ClockId, clock_gettime};
        clock_gettime(ClockId::CLOCK_BOOTTIME).map_or(Duration::MAX, |t| {
            Duration::new(
                u64::try_from(t.tv_sec()).unwrap_or(0),
                u32::try_from(t.tv_nsec()).unwrap_or(0),
            )
        })
    }
}

/// A clock that tests move by hand.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ManualClock {
    wall: std::sync::atomic::AtomicU64,
    /// Milliseconds since the phone started.
    boot: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl ManualClock {
    /// A clock whose wall clock reads `wall_ms`, an hour after the phone started.
    pub(crate) fn at(wall_ms: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            wall: wall_ms.into(),
            boot: 3_600_000.into(),
        })
    }

    /// The phone sleeps, or runs, for `ms`: the wall clock and the time since start move on together.
    /// The monotonic clock, which this one does not hold, stands still only in a sleep.
    pub(crate) fn pass(&self, ms: u64) {
        use std::sync::atomic::Ordering::SeqCst;
        self.wall.fetch_add(ms, SeqCst);
        self.boot.fetch_add(ms, SeqCst);
    }

    /// The wall clock is set to `wall_ms`, back or forward, as by the user or the network; the time
    /// since start does not move.
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

    fn since_boot(&self) -> Duration {
        Duration::from_millis(self.boot.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The phone's clocks: the wall clock is past 2026, and the time since start runs on.
    #[test]
    fn the_system_clock_reads_the_phones_clocks() {
        assert!(SystemClock.wall_ms() > 1_767_225_600_000, "before 2026");
        let boot = SystemClock.since_boot();
        assert!(boot > Duration::ZERO && boot < Duration::MAX);
        assert!(SystemClock.since_boot() >= boot);
    }

    #[test]
    fn a_manual_clock_moves_as_told() {
        let clock = ManualClock::at(1_000);
        clock.pass(500);
        assert_eq!(
            (clock.wall_ms(), clock.since_boot()),
            (1_500, Duration::from_millis(3_600_500))
        );
        clock.set(200);
        assert_eq!(
            (clock.wall_ms(), clock.since_boot()),
            (200, Duration::from_millis(3_600_500))
        );
    }
}
