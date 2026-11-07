//! Counters every engine keeps, read by Kotlin as a `long[]` in the order of [`Stats::snapshot`].

use std::sync::atomic::{AtomicU64, Ordering};

/// What an engine counted since it started.
#[derive(Default)]
pub struct Stats {
    /// TCP flows accepted from the tunnel.
    pub tcp_flows: AtomicU64,
    /// UDP flows accepted from the tunnel.
    pub udp_flows: AtomicU64,
    /// Bytes from apps to the network, payload only.
    pub bytes_up: AtomicU64,
    /// Bytes from the network to apps, payload only.
    pub bytes_down: AtomicU64,
    /// Owner lookups made, one per new flow.
    pub owner_lookups: AtomicU64,
    /// Total time spent in owner lookups, in nanoseconds.
    pub owner_nanos: AtomicU64,
    /// Lookups that found no owner.
    pub owner_unknown: AtomicU64,
    /// Upstream connections that failed.
    pub connect_errors: AtomicU64,
    /// Packets read from the tunnel.
    pub packets_in: AtomicU64,
    /// Packets written to the tunnel.
    pub packets_out: AtomicU64,
}

impl Stats {
    /// Adds `n` to a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// The counters, in the order the Kotlin side reads them.
    #[must_use]
    pub fn snapshot(&self) -> [i64; 10] {
        let read = |c: &AtomicU64| i64::try_from(c.load(Ordering::Relaxed)).unwrap_or(i64::MAX);
        [
            read(&self.tcp_flows),
            read(&self.udp_flows),
            read(&self.bytes_up),
            read(&self.bytes_down),
            read(&self.owner_lookups),
            read(&self.owner_nanos),
            read(&self.owner_unknown),
            read(&self.connect_errors),
            read(&self.packets_in),
            read(&self.packets_out),
        ]
    }
}
