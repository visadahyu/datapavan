//! The connection log's bookkeeping inside the engine (ADR 0037): each open flow's bytes, the segments
//! of open flows at each quarter hour, each app's lookups, and the task that hands the records to Watch.
//!
//! **No byte in another quarter hour** (finding 4 of the independent review of 2026-11-09). The logger's
//! timer runs on the monotonic clock, which stands still while the phone sleeps: with the screen off, a
//! wait of a quarter hour can last a night, and a segment cut only by it would hold a night's bytes,
//! filed under the day it began. So the log reads the time in one place, [`Shared::log_now`], and every
//! path that counts a byte or a lookup, opens a flow or ends one reads it there first: it cuts each
//! segment at the quarter hours the wall clock passed since the last cut, back or forward, by one pure
//! function ([`cut`]). The timer then only cuts the flows no count has woken.
//!
//! **No race is left.** The engine's tasks share one thread, and a count reads the clock and adds its
//! bytes with no wait between, so no cut can come between the two. The one cut that came from another
//! thread, the debug builds' flush for the end-to-end test ([`super::Engine::flush_log`]), is now asked of
//! the logger, which makes it on the engine's thread ([`Shared::ask_flush`]). Made from the other thread,
//! it let a count that had read the clock before it add after it, in the next quarter hour's segment, and
//! a flow or an app's lookups begun on such a reading start in the quarter hour before, and take every
//! count until the next cut.
//!
//! What is counted twice is placed twice: the bytes a relay hands on are counted as it hands them, and
//! their packets as they cross the tunnel, each in the quarter hour it is counted in. A quarter hour that
//! passes between the two splits them, by what is in flight between the relay and the tunnel.

use super::{Counters, DnsUse, Ech, Flow, LOG_DELAY, NamedBy, Outcome, Shared, lock};
use crate::log;
use crate::log::Record;
use crate::packet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;

/// A flow still open is written as a segment at every quarter of an hour of the wall clock, UTC (ADR
/// 0037, decision 1). Every zone of tzdata (2026f, read on 2026-11-18) is a whole number of quarter hours
/// from UTC, and has been since 1979: the last two that were not, Africa/Monrovia at -0:44:30 and
/// Pacific/Kiritimati at -10:40, left those offsets in 1972 and 1979. So a local midnight is always a
/// quarter hour of UTC, Kathmandu's (+5:45), the Chatham Islands' (+12:45 and +13:45) and Eucla's (+8:45)
/// included, and no segment spans one. Watch's Kotlin side checks the zones it knows (`LogDaysTest`).
pub(super) const SEGMENT_MS: u64 = 15 * 60 * 1000;

/// Where an open segment ends, and where the next begins ([`cut`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cut {
    /// The end of the segment's own quarter hour.
    pub(super) end: u64,
    /// The start of the quarter hour the wall clock reads now.
    pub(super) next: u64,
}

/// Where an open segment that began at `start` is cut, now that the wall clock reads `now`: nowhere while
/// both are in one quarter hour. Otherwise the segment ends at the end of its own quarter hour and the
/// next begins at the start of now's, whichever way the clock moved: forward, as across a phone's sleep or
/// to a clock set ahead by days, or back past the segment's start. Every count cuts before it counts
/// ([`Shared::log_now`]), so the bytes a segment holds were all counted in its own quarter hour, and the
/// quarter hours a sleep passed had none. A segment's start is where the last cut left it, so no other
/// reading is needed.
#[must_use]
pub(super) fn cut(start: u64, now: u64) -> Option<Cut> {
    let (quarter, now_quarter) = (start / SEGMENT_MS, now / SEGMENT_MS);
    (quarter != now_quarter).then(|| Cut {
        end: quarter.saturating_add(1).saturating_mul(SEGMENT_MS),
        next: now_quarter * SEGMENT_MS,
    })
}

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
    /// Counts what the app sent: `app` bytes as the app sent them, and `wire` bytes of the tunnel's IP
    /// packets, 0 for none. The log reads the time first ([`Shared::log_now`]), which cuts the flow's
    /// segment at any quarter hour passed since: the bytes fall in the quarter hour they were counted in.
    pub(super) fn up(&self, log: &Shared, app: usize, wire: usize) {
        let now = log.log_now();
        self.up.fetch_add(app as u64, Ordering::Relaxed);
        self.wire(&self.wire_up, wire, now);
    }

    /// Counts what the app received, as [`FlowBytes::up`] counts what it sent.
    pub(super) fn down(&self, log: &Shared, app: usize, wire: usize) {
        let now = log.log_now();
        self.down.fetch_add(app as u64, Ordering::Relaxed);
        self.wire(&self.wire_down, wire, now);
    }

    fn wire(&self, counter: &AtomicU64, n: usize, now: u64) {
        if n > 0 {
            counter.fetch_add(n as u64, Ordering::Relaxed);
            self.last.store(now, Ordering::Relaxed);
        }
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
    /// Whether its destination stays out of the log (a chained app's flow, [`Shared::hides`]): its
    /// record holds no address, port or name, and no hello names it later.
    pub(super) hidden: bool,
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
    /// None yet, counted from `start`.
    fn since(start: u64) -> Self {
        Self {
            start,
            count: 0,
            wire_up: 0,
            wire_down: 0,
        }
    }

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

impl Shared {
    /// The wall clock now, for the log, once every open segment and each app's lookups are cut at the
    /// quarter hours it passed since the last cut, back or forward ([`cut`]). Every path that counts a
    /// byte or a lookup, opens a flow or ends one reads the time here first, so that nothing is counted
    /// in a segment of another quarter hour. One reading of the wall clock (a vDSO call) and one atomic
    /// load; the cut itself only when a quarter hour passed.
    pub(super) fn log_now(&self) -> u64 {
        let now = self.clock.wall_ms();
        if now / SEGMENT_MS != self.quarter.load(Ordering::Acquire) {
            self.cut_all(now);
        }
        now
    }

    /// Cuts every open segment and each app's lookups that are not in `now`'s quarter hour, and then
    /// says they all are. Only on the engine's thread, as every count, so nothing is counted meanwhile.
    fn cut_all(&self, now: u64) {
        let quarter = now / SEGMENT_MS;
        let mut records = Vec::new();
        {
            let mut live = lock(&self.live);
            for live in live.values_mut() {
                if let Some(Cut { end, next }) = cut(live.start, now) {
                    let counts = live.bytes.now();
                    records.push(Record::Segment {
                        flow: live.flow.clone(),
                        start: live.start,
                        end,
                        bytes: delta(counts, live.base),
                        continues: true,
                    });
                    live.start = next;
                    live.base = counts;
                }
            }
            lock(&self.lookups).retain(|&uid, lookups| match cut(lookups.start, now) {
                Some(Cut { end, .. }) => {
                    records.push(lookups.record(uid, end));
                    false
                }
                None => true,
            });
            self.quarter.store(quarter, Ordering::Release);
        }
        if !records.is_empty() {
            lock(&self.pending_log).extend(records);
            self.log_ready.notify_one();
        }
    }

    /// Counts a new flow and keeps it for tests. For the log, a flow that opened becomes live and gets
    /// its byte counts; one that did not is written at once. Lookups to Watch's own DNS address are
    /// counted per app instead.
    pub(super) fn record(&self, flow: Flow) -> Option<Arc<FlowBytes>> {
        let logged = self.log_flow(&flow);
        self.keep(flow);
        logged
    }

    pub(super) fn log_flow(&self, flow: &Flow) -> Option<Arc<FlowBytes>> {
        if self.is_tunnel_dns(flow.destination.ip()) {
            return None;
        }
        let hidden = self.hides(flow.uid, flow.destination);
        let without_destination;
        let flow = if hidden {
            without_destination = Flow {
                destination: packet::unspecified_like(&flow.destination),
                name: None,
                named_by: NamedBy::Unknown,
                ech: Ech::Absent,
                dns: DnsUse::None,
                resolver: None,
                network: None,
                ..flow.clone()
            };
            &without_destination
        } else {
            flow
        };
        let now = self.log_now();
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
                hidden,
            },
        );
        self.log_ready.notify_one();
        Some(bytes)
    }

    /// Counts a lookup an app sent to Watch's own DNS address, `packet` bytes on the tunnel.
    pub(super) fn lookup(&self, uid: Option<u32>, packet: usize) {
        let now = self.log_now();
        let mut lookups = lock(&self.lookups);
        let entry = lookups.entry(uid).or_insert(Lookups::since(now));
        entry.count += 1;
        entry.wire_up += packet as u64;
        drop(lookups);
        self.log_ready.notify_one();
    }

    /// Counts an answer to an app's lookup, `packet` bytes on the tunnel. An answer whose lookup was
    /// counted in a quarter hour already cut is counted in its own, with no lookup.
    pub(super) fn lookup_answered(&self, uid: Option<u32>, packet: usize) {
        let now = self.log_now();
        let mut lookups = lock(&self.lookups);
        let new = !lookups.contains_key(&uid);
        lookups.entry(uid).or_insert(Lookups::since(now)).wire_down += packet as u64;
        drop(lookups);
        if new {
            self.log_ready.notify_one();
        }
    }

    /// A live flow ended: its segment is cut at any quarter hour passed, as a count would cut it, and its
    /// last segment written.
    pub(super) fn finish(&self, id: u64) {
        let now = self.log_now();
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let end = now.max(live.start);
        self.write(segment(live, end, false));
    }

    /// A TCP flow the engine ended itself before its relay began, recorded as opened when its server
    /// accepted, which the app saw end otherwise (ADR 0044, unit 12b, third round): refused, or reset
    /// (`Outcome::Failed`). Its outcome becomes `outcome` in its last segment, the counters and the
    /// flows kept, and its last segment is written, as [`Shared::finish_closed`] writes it.
    pub(super) fn finish_as(&self, id: u64, outcome: Outcome) {
        match lock(&self.live).get_mut(&id) {
            Some(live) => live.flow.outcome = outcome,
            None => return,
        }
        if let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id) {
            flow.outcome = outcome;
        }
        let counter = match outcome {
            Outcome::Opened => None,
            Outcome::Refused => Some(&self.counters.refused),
            Outcome::Unreachable => Some(&self.counters.unreachable),
            Outcome::Failed => Some(&self.counters.failed),
        };
        if let Some(counter) = counter {
            Counters::add(counter, 1);
        }
        self.finish_closed(id);
    }

    /// A TCP flow whose rewriting is gone: its segment is cut as [`Shared::finish`] cuts it, and its last
    /// segment holds every packet the tunnel carried for it, and ends at the last of them, or at its
    /// start when the last passed before it, in a segment already written.
    pub(super) fn finish_closed(&self, id: u64) {
        let now = self.log_now();
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let last = live.bytes.last.load(Ordering::Relaxed);
        let end = if last == 0 {
            now.max(live.start)
        } else if last >= live.start && cut(live.start, last).is_none() {
            last
        } else {
            live.start
        };
        self.write(segment(live, end, false));
    }

    /// Asks the engine's thread to flush the log ([`Shared::flush`]) and hand its records on, and waits
    /// until it has, at most `wait`: from another thread, for the end-to-end test, which cannot wait
    /// ([`super::Engine::flush_log`]). The logger makes the flush between counts, on the thread that
    /// makes them (the module's comment). False if it did not in time, or the engine stopped first,
    /// after it handed its last records on.
    pub(super) fn ask_flush(&self, wait: Duration) -> bool {
        let (done, flushed) = std::sync::mpsc::sync_channel(1);
        lock(&self.flushes).push(done);
        self.flush_wanted.notify_one();
        flushed.recv_timeout(wait).is_ok()
    }

    /// Writes every live flow's segment up to now, as a quarter hour would, and the lookups counted so
    /// far.
    pub(super) fn flush(&self) {
        let now = self.log_now();
        let mut records = Vec::new();
        for live in lock(&self.live).values_mut() {
            if live.start >= now {
                continue;
            }
            let counts = live.bytes.now();
            records.push(Record::Segment {
                flow: live.flow.clone(),
                start: live.start,
                end: now,
                bytes: delta(counts, live.base),
                continues: true,
            });
            live.start = now;
            live.base = counts;
        }
        for (uid, lookups) in lock(&self.lookups).drain() {
            records.push(lookups.record(uid, now));
        }
        lock(&self.pending_log).extend(records);
    }

    /// Ends every live flow now, as when the engine stops, after the cut a count would make.
    pub(super) fn finish_all(&self) {
        let now = self.log_now();
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
/// quarter hour the segments of the flows still open, and at once when a flush is asked
/// ([`Shared::ask_flush`]). With nothing open and nothing waiting it sleeps without a timer, so an idle
/// tunnel does not wake the phone. Its timer stands still while the phone sleeps, and may wake hours
/// late: it then cuts at the quarter hours the wall clock passed, as a count would ([`Shared::log_now`]).
/// It returns once `end` says the engine stops, but never while it hands a batch to the log: the engine
/// then hands the last batch after it, so that the log gets them in order (fourth check of unit 12, a
/// nit).
pub(super) async fn logger(shared: Arc<Shared>, mut end: watch::Receiver<bool>) {
    loop {
        let open = !lock(&shared.live).is_empty() || !lock(&shared.lookups).is_empty();
        let next = open.then(|| {
            let now = shared.clock.wall_ms();
            Duration::from_millis(SEGMENT_MS - now % SEGMENT_MS)
        });
        tokio::select! {
            _ = end.changed() => return,
            () = shared.flush_wanted.notified() => {}
            () = shared.log_ready.notified() => {
                let gather = next.map_or(LOG_DELAY, |n| n.min(LOG_DELAY));
                tokio::select! {
                    _ = end.changed() => return,
                    () = shared.flush_wanted.notified() => {}
                    () = tokio::time::sleep(gather) => {}
                }
            }
            () = sleep_for(next) => {}
        }
        shared.log_now();
        let asked = std::mem::take(&mut *lock(&shared.flushes));
        if !asked.is_empty() {
            shared.flush();
        }
        if let Some(batch) = shared.take_log() {
            let platform = Arc::clone(&shared.platform);
            let _ = tokio::task::spawn_blocking(move || platform.log(&batch)).await;
        }
        for done in asked {
            let _ = done.send(());
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

#[cfg(test)]
mod tests {
    use super::super::clock::ManualClock;
    use super::super::tests::{shared, shared_with};
    use super::super::{Platform, TCP};
    use super::*;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::Mutex;

    /// 2026-11-17, 00:00 UTC.
    const DAY: u64 = 1_794_873_600_000;
    const MINUTE: u64 = 60_000;
    const HOUR: u64 = 60 * MINUTE;

    /// `hours` and `minutes` after 2026-11-17, 00:00 UTC; hours past 24 are the next days'.
    fn at(hours: u64, minutes: u64) -> u64 {
        DAY + hours * HOUR + minutes * MINUTE
    }

    fn flow(id: u64) -> Flow {
        Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 1, 10, 1], 40_000)),
            destination: SocketAddr::from(([198, 51, 100, 9], 443)),
            uid: Some(10_123),
            outcome: Outcome::Opened,
            name: None,
            named_by: NamedBy::Unknown,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
        }
    }

    /// A log whose wall clock reads `wall`, and the clock, to move.
    fn log_at(wall: u64) -> (Shared, Arc<ManualClock>) {
        let clock = ManualClock::at(wall);
        let mut shared = shared();
        shared.clock = clock.clone();
        (shared, clock)
    }

    /// A flow opened now, and its bytes.
    fn open(shared: &Shared, id: u64) -> Arc<FlowBytes> {
        let Some(bytes) = shared.record(flow(id)) else {
            unreachable!("an open flow is live")
        };
        bytes
    }

    /// The records written so far, taken.
    fn taken(shared: &Shared) -> Vec<Record> {
        std::mem::take(&mut *lock(&shared.pending_log))
    }

    /// A segment of flow `id`, as (flow, start, end, bytes, continues).
    type Seen = (u64, u64, u64, [u64; 4], bool);

    fn segments(records: &[Record]) -> Vec<Seen> {
        records
            .iter()
            .filter_map(|r| match r {
                Record::Segment {
                    flow,
                    start,
                    end,
                    bytes,
                    continues,
                } => Some((flow.id, *start, *end, *bytes, *continues)),
                Record::Lookups { .. } => None,
            })
            .collect()
    }

    /// Where flow `id`'s open segment starts, and what it holds so far.
    fn open_segment(shared: &Shared, id: u64) -> (u64, [u64; 4]) {
        let live = lock(&shared.live);
        (
            live[&id].start,
            delta(live[&id].bytes.now(), live[&id].base),
        )
    }

    #[test]
    fn a_segment_in_one_quarter_hour_is_not_cut() {
        assert_eq!(cut(at(22, 10), at(22, 15) - 1), None);
        // A segment that starts on a quarter hour is in it.
        assert_eq!(cut(at(22, 15), at(22, 29)), None);
        // A clock set back within the quarter hour moves nothing.
        assert_eq!(cut(at(22, 12), at(22, 10)), None);
    }

    #[test]
    fn one_quarter_hour_passed_cuts_there() {
        let at_22_15 = Some(Cut {
            end: at(22, 15),
            next: at(22, 15),
        });
        assert_eq!(cut(at(22, 10), at(22, 16)), at_22_15);
        // Exactly on it.
        assert_eq!(cut(at(22, 10), at(22, 15)), at_22_15);
        assert_eq!(
            cut(at(22, 15), at(22, 30)),
            Some(Cut {
                end: at(22, 30),
                next: at(22, 30),
            })
        );
    }

    /// The phone slept from 22:10 to 06:16 the next day: the segment carries its bytes to 22:15, the
    /// first quarter hour passed, and the next begins at 06:15, the last.
    #[test]
    fn several_quarter_hours_passed_cut_at_the_first_and_go_on_from_the_last() {
        assert_eq!(
            cut(at(22, 10), at(30, 16)),
            Some(Cut {
                end: at(22, 15),
                next: at(30, 15),
            })
        );
    }

    /// A wall clock set back, past the segment's start, cuts it at the end of its own quarter hour; the
    /// next begins in the quarter hour the clock reads.
    #[test]
    fn a_clock_set_back_before_the_segment_cuts_it_at_its_own_quarter_hour() {
        assert_eq!(
            cut(at(22, 10), at(21, 50)),
            Some(Cut {
                end: at(22, 15),
                next: at(21, 45),
            })
        );
        assert_eq!(
            cut(at(22, 10), 0),
            Some(Cut {
                end: at(22, 15),
                next: 0,
            })
        );
    }

    #[test]
    fn a_clock_set_forward_by_days_cuts_as_a_long_sleep() {
        let days = 40 * 24 * HOUR;
        assert_eq!(
            cut(at(22, 10), at(22, 10) + days),
            Some(Cut {
                end: at(22, 15),
                next: at(22, 0) + days,
            })
        );
        // The end of time does not overflow.
        assert_eq!(
            cut(u64::MAX - 1, 0),
            Some(Cut {
                end: u64::MAX,
                next: 0,
            })
        );
    }

    /// Kathmandu (+5:45), the Chatham Islands (+12:45, and +13:45 in their summer), Eucla (+8:45),
    /// Newfoundland (-3:30) and Lord Howe Island (+10:30): no segment the cut leaves holds a local
    /// midnight inside it, however the clock moved.
    #[test]
    fn no_segment_holds_a_midnight_of_a_zone_not_whole_hours_from_utc() {
        for offset in [345_i64, 765, 825, 525, -210, 630] {
            // Their midnight beginning 2026-11-18, in UTC.
            let Some(midnight) = (DAY + 24 * HOUR).checked_add_signed(-offset * 60_000) else {
                unreachable!("a midnight in 2026")
            };
            assert_eq!(midnight % SEGMENT_MS, 0, "{offset}");
            assert_eq!(
                cut(midnight - MINUTE, midnight + MINUTE),
                Some(Cut {
                    end: midnight,
                    next: midnight,
                })
            );
            for start in (midnight - 2 * HOUR..midnight + 2 * HOUR).step_by(60_000) {
                for now in [
                    start + MINUTE,
                    start + 7 * MINUTE,
                    start + 9 * HOUR,
                    start - HOUR,
                ] {
                    if let Some(Cut { end, next }) = cut(start, now) {
                        assert!(
                            !(start < midnight && midnight < end),
                            "{offset}: {start}..{end} holds {midnight}"
                        );
                        assert!(next <= now && now - next < SEGMENT_MS);
                    }
                }
            }
        }
    }

    /// The bytes before a night's sleep stay in their quarter hour when the app's packet ends it.
    #[test]
    fn a_sleep_ended_by_the_apps_packet_is_cut_before_it_is_counted() {
        let (shared, clock) = log_at(at(22, 10));
        let bytes = open(&shared, 1);
        bytes.up(&shared, 100, 140);
        clock.set(at(30, 16));
        bytes.up(&shared, 60, 100);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, at(22, 10), at(22, 15), [100, 0, 140, 0], true)]
        );
        assert_eq!(open_segment(&shared, 1), (at(30, 15), [60, 0, 100, 0]));
        assert_eq!(bytes.last.load(Ordering::Relaxed), at(30, 16));
    }

    /// The same when the server's packet ends it, as a push connection's does.
    #[test]
    fn a_sleep_ended_by_a_servers_packet_is_cut_before_it_is_counted() {
        let (shared, clock) = log_at(at(22, 10));
        let bytes = open(&shared, 1);
        bytes.down(&shared, 300, 340);
        clock.set(at(30, 16));
        bytes.down(&shared, 0, 52);
        bytes.down(&shared, 700, 0);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, at(22, 10), at(22, 15), [0, 300, 0, 340], true)]
        );
        assert_eq!(open_segment(&shared, 1), (at(30, 15), [0, 700, 0, 52]));
    }

    /// A clock set back, then running on: each count lands in the quarter hour the clock read. A flow
    /// opened after a sleep cuts the others, so that a clock set back then still finds them to cut.
    #[test]
    fn a_clock_set_back_cuts_and_each_count_falls_in_the_quarter_hour_it_read() {
        let (shared, clock) = log_at(at(22, 10));
        let bytes = open(&shared, 1);
        bytes.up(&shared, 10, 0);
        clock.set(at(21, 50));
        bytes.up(&shared, 20, 0);
        clock.set(at(22, 20));
        bytes.up(&shared, 30, 0);
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, at(22, 10), at(22, 15), [10, 0, 0, 0], true),
                (1, at(21, 45), at(22, 0), [20, 0, 0, 0], true),
            ]
        );
        assert_eq!(open_segment(&shared, 1), (at(22, 15), [30, 0, 0, 0]));

        // A night passes; a second flow opens; the clock is set back to the evening.
        clock.set(at(30, 16));
        let other = open(&shared, 2);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, at(22, 15), at(22, 30), [30, 0, 0, 0], true)]
        );
        clock.set(at(22, 40));
        other.up(&shared, 5, 0);
        assert_eq!(open_segment(&shared, 2), (at(22, 30), [5, 0, 0, 0]));
        assert_eq!(open_segment(&shared, 1).0, at(22, 30));
    }

    #[test]
    fn a_clock_set_forward_by_days_cuts_before_the_count() {
        let (shared, clock) = log_at(at(22, 10));
        let bytes = open(&shared, 1);
        bytes.down(&shared, 10, 0);
        clock.set(at(22, 10) + 40 * 24 * HOUR);
        bytes.down(&shared, 20, 0);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, at(22, 10), at(22, 15), [0, 10, 0, 0], true)]
        );
        assert_eq!(
            open_segment(&shared, 1),
            (at(22, 0) + 40 * 24 * HOUR, [0, 20, 0, 0])
        );
    }

    /// A flow that ends after a sleep: its bytes stay in their quarter hour, and its last segment begins
    /// in the quarter hour it ended in.
    #[test]
    fn a_flow_ended_after_a_sleep_keeps_its_bytes_in_their_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).up(&shared, 100, 140);
        clock.set(at(30, 16));
        shared.finish(1);
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, at(22, 10), at(22, 15), [100, 0, 140, 0], true),
                (1, at(30, 15), at(30, 16), [0; 4], false),
            ]
        );
    }

    /// The same for a TCP flow whose rewriting is gone: one that carried no packet ends when it ends; one
    /// whose last packet passed before the sleep ends where its last segment begins.
    #[test]
    fn a_closed_flow_ended_after_a_sleep_keeps_its_bytes_in_their_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).down(&shared, 300, 0);
        open(&shared, 2).down(&shared, 400, 440);
        clock.set(at(30, 16));
        shared.finish_closed(1);
        shared.finish_closed(2);
        let mut seen = segments(&taken(&shared));
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![
                (1, at(22, 10), at(22, 15), [0, 300, 0, 0], true),
                (1, at(30, 15), at(30, 16), [0; 4], false),
                (2, at(22, 10), at(22, 15), [0, 400, 0, 440], true),
                (2, at(30, 15), at(30, 15), [0; 4], false),
            ]
        );
    }

    /// A TCP flow the engine ended itself before its relay began, after a sleep: the same, with the
    /// outcome the app saw.
    #[test]
    fn a_flow_ended_as_refused_after_a_sleep_keeps_its_bytes_in_their_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).up(&shared, 0, 0);
        clock.set(at(30, 16));
        shared.finish_as(1, Outcome::Refused);
        let records = taken(&shared);
        assert_eq!(
            segments(&records),
            vec![
                (1, at(22, 10), at(22, 15), [0; 4], true),
                (1, at(30, 15), at(30, 16), [0; 4], false),
            ]
        );
        assert!(matches!(
            &records[1],
            Record::Segment { flow, .. } if flow.outcome == Outcome::Refused
        ));
    }

    /// The engine stops after a sleep: every flow's bytes and every app's lookups stay in their quarter
    /// hour.
    #[test]
    fn flows_and_lookups_ended_together_after_a_sleep_keep_their_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).up(&shared, 100, 140);
        shared.lookup(Some(10_123), 70);
        clock.set(at(30, 16));
        shared.finish_all();
        let records = taken(&shared);
        assert_eq!(
            segments(&records),
            vec![
                (1, at(22, 10), at(22, 15), [100, 0, 140, 0], true),
                (1, at(30, 15), at(30, 16), [0; 4], false),
            ]
        );
        let lookups: Vec<_> = records
            .iter()
            .filter(|r| matches!(r, Record::Lookups { .. }))
            .collect();
        assert_eq!(
            lookups,
            vec![&Record::Lookups {
                uid: Some(10_123),
                start: at(22, 10),
                end: at(22, 15),
                count: 1,
                wire_up: 70,
                wire_down: 0,
            }]
        );
    }

    /// An app's lookups and their answers each fall in the quarter hour they were counted in: an answer
    /// after a sleep is counted after its lookup's quarter hour is cut, and kept.
    #[test]
    fn lookups_and_answers_after_a_sleep_fall_in_their_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        shared.lookup(Some(10_123), 70);
        clock.set(at(30, 16));
        shared.lookup_answered(Some(10_123), 300);
        clock.set(at(30, 17));
        shared.lookup(Some(10_123), 72);
        clock.set(at(30, 31));
        shared.lookup(None, 60);
        assert_eq!(
            taken(&shared),
            vec![
                Record::Lookups {
                    uid: Some(10_123),
                    start: at(22, 10),
                    end: at(22, 15),
                    count: 1,
                    wire_up: 70,
                    wire_down: 0,
                },
                Record::Lookups {
                    uid: Some(10_123),
                    start: at(30, 16),
                    end: at(30, 30),
                    count: 1,
                    wire_up: 72,
                    wire_down: 300,
                },
            ]
        );
    }

    /// The end-to-end test's flush after a sleep: the quarter hour's cut first, then the flush.
    #[test]
    fn a_flush_after_a_sleep_cuts_at_the_quarter_hour_first() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).up(&shared, 100, 0);
        clock.set(at(30, 16));
        shared.flush();
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, at(22, 10), at(22, 15), [100, 0, 0, 0], true),
                (1, at(30, 15), at(30, 16), [0; 4], true),
            ]
        );
        assert_eq!(open_segment(&shared, 1), (at(30, 16), [0; 4]));
    }

    /// Watch's log, as the logger hands it batches.
    #[derive(Default)]
    struct Kept(Mutex<Vec<Vec<u8>>>);

    impl Platform for Kept {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, batch: &[u8]) {
            lock(&self.0).push(batch.to_vec());
        }
    }

    /// The logger's timer stands still while the phone sleeps (tokio's paused time stands for the
    /// monotonic clock here): it waits from 22:10 for 22:15, the phone sleeps until 06:16, and the timer
    /// wakes at last. The flow, which carried no packet since, is cut at 22:15 with its bytes, and goes
    /// on from 06:15.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_sleep_with_no_packet_is_cut_when_the_timer_wakes_late() {
        let platform = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 10));
        let mut shared = shared_with(platform.clone());
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let bytes = open(&shared, 1);
        bytes.down(&shared, 300, 340);
        let (_end, ending) = watch::channel(false);
        tokio::spawn(logger(Arc::clone(&shared), ending));
        // The new flow's records gather for 30 seconds; then the timer is set for 22:15.
        tokio::time::sleep(LOG_DELAY + Duration::from_secs(1)).await;
        assert!(lock(&platform.0).is_empty(), "nothing to hand over yet");
        // Asleep, the wall clock runs on to 06:16; awake, the timer's five minutes pass.
        clock.set(at(30, 16));
        tokio::time::sleep(Duration::from_mins(5)).await;
        for _ in 0..100 {
            if !lock(&platform.0).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let expected = Record::Segment {
            flow: lock(&shared.live)[&1].flow.clone(),
            start: at(22, 10),
            end: at(22, 15),
            bytes: [0, 300, 0, 340],
            continues: true,
        };
        assert_eq!(*lock(&platform.0), vec![log::batch(&[expected])]);
        assert_eq!(open_segment(&shared, 1), (at(30, 15), [0; 4]));
    }

    /// The segments in a batch the logger handed over, as (start, end, bytes up as the app sent them).
    fn segments_in(batch: &[u8]) -> Vec<(u64, u64, u64)> {
        let at = |b: &[u8], i: usize| {
            b.get(i..i + 8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map_or(0, u64::from_le_bytes)
        };
        let mut seen = Vec::new();
        let mut i = 4;
        while let Some(length) = batch.get(i..i + 2) {
            let length = usize::from(u16::from_le_bytes([length[0], length[1]]));
            let record = batch.get(i + 2..i + 2 + length).unwrap_or_default();
            if record.get(1) == Some(&1) {
                seen.push((at(record, 14), at(record, 22), at(record, 30)));
            }
            i += 2 + length;
        }
        seen
    }

    /// No race is left (the module's comment): a flush asked from another thread, here as the clock
    /// passes 22:15, is made on the engine's thread between its counts, so every byte falls in the
    /// quarter hour of the reading it was counted on, to the byte. The counts here stand for a relay's,
    /// one at each of its turns on the engine's thread.
    #[test]
    fn a_flush_asked_from_another_thread_is_made_between_the_engines_counts() -> std::io::Result<()>
    {
        const COUNTS: u64 = 4_000;
        let platform = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 15) - 50);
        let mut shared = shared_with(platform.clone());
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let bytes = open(&shared, 1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let engine = {
            let (shared, bytes) = (Arc::clone(&shared), Arc::clone(&bytes));
            std::thread::spawn(move || {
                runtime.block_on(async move {
                    let (end, ending) = watch::channel(false);
                    let logging = tokio::spawn(logger(Arc::clone(&shared), ending));
                    let mut early = 0;
                    for _ in 0..COUNTS {
                        bytes.up(&shared, 1, 1);
                        if bytes.last.load(Ordering::Relaxed) < at(22, 15) {
                            early += 1;
                        }
                        tokio::task::yield_now().await;
                    }
                    let _ = end.send(true);
                    let _ = logging.await;
                    shared.finish_all();
                    early
                })
            })
        };
        while bytes.now()[0] < COUNTS / 2 {
            std::thread::yield_now();
        }
        clock.set(at(22, 15) + 30);
        assert!(shared.ask_flush(Duration::from_secs(10)), "no flush");
        let Ok(early) = engine.join() else {
            unreachable!("the engine's thread panicked")
        };
        let mut seen: Vec<_> = lock(&platform.0)
            .iter()
            .flat_map(|b| segments_in(b))
            .collect();
        seen.extend(segments(&taken(&shared)).iter().map(|s| (s.1, s.2, s.3[0])));
        let held = |early: bool| -> u64 {
            seen.iter()
                .filter(|s| (s.0 < at(22, 15)) == early)
                .map(|s| s.2)
                .sum()
        };
        assert!((COUNTS / 2..COUNTS).contains(&early), "{early}");
        assert_eq!(
            (held(true), held(false)),
            (early, COUNTS - early),
            "{seen:?}"
        );
        // The flush cut at 22:15:00.030, after the quarter hour's cut at 22:15.
        assert!(seen.iter().any(|s| s.1 == at(22, 15) + 30), "{seen:?}");
        Ok(())
    }
}
