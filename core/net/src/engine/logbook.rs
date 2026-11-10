//! The connection log's bookkeeping inside the engine (ADR 0037): each open flow's bytes, the segments
//! of open flows at each quarter hour, each app's lookups, and the task that hands the records to Watch.

use super::{Flow, LOG_DELAY, Outcome, SEGMENT_MS, Shared, is_tunnel_dns, lock};
use crate::log;
use crate::log::Record;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The bytes of one open flow, counted as they pass: what the app sent and received, and the IP
/// packets the tunnel carried for it, headers included, which is what Android counts for the app.
#[derive(Debug, Default)]
pub(crate) struct FlowBytes {
    up: AtomicU64,
    down: AtomicU64,
    wire_up: AtomicU64,
    wire_down: AtomicU64,
    /// When the tunnel last carried a packet of the flow, in milliseconds since 1970; 0 for never.
    pub(super) last: AtomicU64,
}

impl FlowBytes {
    pub(super) fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub(super) fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub(super) fn add_wire_up(&self, n: usize) {
        self.wire_up.fetch_add(n as u64, Ordering::Relaxed);
        self.last.store(now_ms(), Ordering::Relaxed);
    }

    pub(super) fn add_wire_down(&self, n: usize) {
        self.wire_down.fetch_add(n as u64, Ordering::Relaxed);
        self.last.store(now_ms(), Ordering::Relaxed);
    }

    /// Up, down, and the tunnel's up and down.
    pub(super) fn now(&self) -> [u64; 4] {
        [&self.up, &self.down, &self.wire_up, &self.wire_down].map(|c| c.load(Ordering::Relaxed))
    }
}

/// A flow that is open, for the log: what is known of it, its bytes, and where its current segment
/// starts.
pub(super) struct Live {
    pub(super) flow: Flow,
    pub(super) bytes: Arc<FlowBytes>,
    pub(super) start: u64,
    /// The counts at the segment's start.
    pub(super) base: [u64; 4],
}

/// An app's lookups to Watch's own DNS address: since when, how many, and the tunnel's bytes for them.
#[derive(Debug, Clone, Copy)]
pub(super) struct Lookups {
    pub(super) start: u64,
    pub(super) count: u32,
    pub(super) wire_up: u64,
    pub(super) wire_down: u64,
}

impl Lookups {
    pub(super) fn record(self, uid: Option<u32>, end: u64) -> Record {
        Record::Lookups {
            uid,
            start: self.start,
            end: end.max(self.start),
            count: self.count,
            wire_up: self.wire_up,
            wire_down: self.wire_down,
        }
    }
}

/// Milliseconds since 1970, UTC.
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Shared {
    /// Counts a new flow and keeps it for tests. For the log, a flow that opened becomes live and gets
    /// its byte counts; one that did not is written at once. Lookups to Watch's own DNS address are
    /// counted per app instead.
    pub(super) fn record(&self, flow: Flow) -> Option<Arc<FlowBytes>> {
        let logged = self.log_flow(&flow);
        self.keep(flow);
        logged
    }

    pub(super) fn log_flow(&self, flow: &Flow) -> Option<Arc<FlowBytes>> {
        if is_tunnel_dns(flow.destination.ip()) {
            return None;
        }
        let now = now_ms();
        if flow.outcome != Outcome::Opened {
            self.write(Record::Segment {
                flow: flow.clone(),
                start: now,
                end: now,
                bytes: [0; 4],
                continues: false,
            });
            return None;
        }
        let bytes = Arc::new(FlowBytes::default());
        lock(&self.live).insert(
            flow.id,
            Live {
                flow: flow.clone(),
                bytes: Arc::clone(&bytes),
                start: now,
                base: [0; 4],
            },
        );
        self.log_ready.notify_one();
        Some(bytes)
    }

    /// Counts a lookup an app sent to Watch's own DNS address, `packet` bytes on the tunnel.
    pub(super) fn lookup(&self, uid: Option<u32>, packet: usize) {
        let mut lookups = lock(&self.lookups);
        let entry = lookups.entry(uid).or_insert(Lookups {
            start: now_ms(),
            count: 0,
            wire_up: 0,
            wire_down: 0,
        });
        entry.count += 1;
        entry.wire_up += packet as u64;
        drop(lookups);
        self.log_ready.notify_one();
    }

    /// Counts an answer to an app's lookup, `packet` bytes on the tunnel.
    pub(super) fn lookup_answered(&self, uid: Option<u32>, packet: usize) {
        if let Some(entry) = lock(&self.lookups).get_mut(&uid) {
            entry.wire_down += packet as u64;
        }
    }

    /// A live flow ended: its last segment is written.
    pub(super) fn finish(&self, id: u64) {
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let end = now_ms().max(live.start);
        self.write(segment(live, end, false));
    }

    /// A TCP flow whose rewriting is gone: its last segment holds every packet the tunnel carried for
    /// it, and ends at the last of them.
    pub(super) fn finish_closed(&self, id: u64) {
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let last = live.bytes.last.load(Ordering::Relaxed);
        let end = if last == 0 { now_ms() } else { last }.max(live.start);
        self.write(segment(live, end, false));
    }

    /// Writes every live flow's segment up to `boundary`, and the lookups counted so far.
    pub(super) fn checkpoint(&self, boundary: u64) {
        let mut records = Vec::new();
        for live in lock(&self.live).values_mut() {
            if live.start >= boundary {
                continue;
            }
            let now = live.bytes.now();
            records.push(Record::Segment {
                flow: live.flow.clone(),
                start: live.start,
                end: boundary,
                bytes: delta(now, live.base),
                continues: true,
            });
            live.start = boundary;
            live.base = now;
        }
        for (uid, lookups) in lock(&self.lookups).drain() {
            records.push(lookups.record(uid, boundary));
        }
        lock(&self.pending_log).extend(records);
    }

    /// Ends every live flow now, as when the engine stops.
    pub(super) fn finish_all(&self) {
        let now = now_ms();
        let live: Vec<Live> = lock(&self.live).drain().map(|(_, l)| l).collect();
        let mut records: Vec<Record> = live
            .into_iter()
            .map(|l| {
                let end = now.max(l.start);
                segment(l, end, false)
            })
            .collect();
        for (uid, lookups) in lock(&self.lookups).drain() {
            records.push(lookups.record(uid, now));
        }
        lock(&self.pending_log).extend(records);
    }

    pub(super) fn write(&self, record: Record) {
        lock(&self.pending_log).push(record);
        self.log_ready.notify_one();
    }

    /// The records waiting, as one batch, if there are any.
    pub(super) fn take_log(&self) -> Option<Vec<u8>> {
        let records = std::mem::take(&mut *lock(&self.pending_log));
        (!records.is_empty()).then(|| log::batch(&records))
    }
}

/// A live flow's segment from its start to `end`.
pub(super) fn segment(live: Live, end: u64, continues: bool) -> Record {
    Record::Segment {
        start: live.start,
        end,
        bytes: delta(live.bytes.now(), live.base),
        flow: live.flow,
        continues,
    }
}

pub(super) fn delta(now: [u64; 4], base: [u64; 4]) -> [u64; 4] {
    [0, 1, 2, 3].map(|i| now[i].saturating_sub(base[i]))
}

/// Hands finished records to Watch's log: gathered for [`LOG_DELAY`] after the first one, and at every
/// quarter hour the segments of the flows still open. With nothing open and nothing waiting it sleeps
/// without a timer, so an idle tunnel does not wake the phone.
pub(super) async fn logger(shared: Arc<Shared>) {
    let mut last = now_ms() / SEGMENT_MS * SEGMENT_MS;
    loop {
        let open = !lock(&shared.live).is_empty() || !lock(&shared.lookups).is_empty();
        let next = open.then(|| {
            let now = now_ms();
            Duration::from_millis(SEGMENT_MS - now % SEGMENT_MS)
        });
        tokio::select! {
            () = shared.log_ready.notified() => {
                tokio::time::sleep(next.map_or(LOG_DELAY, |n| n.min(LOG_DELAY))).await;
            }
            () = sleep_for(next) => {}
        }
        let boundary = now_ms() / SEGMENT_MS * SEGMENT_MS;
        if boundary > last {
            shared.checkpoint(boundary);
            last = boundary;
        }
        if let Some(batch) = shared.take_log() {
            let platform = Arc::clone(&shared.platform);
            let _ = tokio::task::spawn_blocking(move || platform.log(&batch)).await;
        }
    }
}

/// Sleeps for `duration`, or for ever when there is none.
async fn sleep_for(duration: Option<Duration>) {
    match duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending().await,
    }
}
