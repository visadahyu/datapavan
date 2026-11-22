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
//! count until the next cut. The engine notes its thread as its loop starts, and debug builds check that
//! the log's clock is read there alone ([`Shared::log_now`]).
//!
//! **What is counted when.** Each byte falls in the quarter hour of the reading it was counted on; what
//! that reading is stays the engine's choice, named here (review 1 of W5's first part, engine, finding 3):
//! - What is counted twice is placed twice: the bytes a relay hands on are counted as it hands them, and
//!   their packets as they cross the tunnel, each in the quarter hour it is counted in. A quarter hour that
//!   passes between the two splits them, by what is in flight between the relay and the tunnel.
//! - The packets the engine holds before a flow opens, a TCP SYN until its server accepts, datagrams and
//!   lookups until Android names their app, are counted when the flow opens, in its first segment: by at
//!   most the connect wait for TCP (60 seconds awake), and the owner question and the socket for UDP and
//!   lookups. Counting them at their arrival would need a segment before the flow's own start.
//! - A count costs one reading of the coarse wall clock (ADR 0044's cost note): one for each UDP datagram,
//!   and for TCP one for each read the relay hands on and one for each packet of the tunnel, about two
//!   for a small packet. The coarse clock lags the wall clock by less than two of the kernel's ticks,
//!   under 8 ms at 250 Hz, the default, under 20 ms at 100 Hz, the lowest, so a byte counted in that
//!   moment after a quarter hour falls in the quarter hour before.

use super::activity::{Force, Mark, NO_SECOND, Of, Piece};
use super::{Counters, DnsUse, Ech, Flow, LOG_DELAY, NamedBy, Outcome, Shared, lock};
use crate::log;
use crate::packet;
use crate::states::Placed;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

/// A flow still open is written as a segment at every quarter of an hour of the wall clock, UTC (ADR
/// 0037, decision 1), and every segment lies within one quarter hour. In every zone of tzdata (2026f, read
/// on 2026-11-18), every change of the local date since 2011 falls on a quarter hour of UTC, so no segment
/// spans one, Kathmandu's (+5:45), the Chatham Islands' (+12:45 and +13:45) and Eucla's (+8:45) included.
/// Both of what that takes hold: every offset is a whole number of quarter hours from UTC, which puts every
/// midnight on one (since 1979: Africa/Monrovia at -0:44:30 and Pacific/Kiritimati at -10:40 left theirs in
/// 1972 and 1979), and every change of offset that changes the date falls on one (since 2011:
/// Newfoundland, Goose Bay and Moncton changed theirs at 00:01 local time until 2010 and 2006, so that the
/// date changed at 02:31 or 03:01 UTC). Watch's Kotlin side checks it of the zones it knows, by their rules ahead
/// (`LogDaysTest`; review 1 of W5's first part, names, finding 5).
pub(super) const SEGMENT_MS: u64 = 15 * 60 * 1000;

/// Where an open segment ends, and where the next begins ([`cut`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cut {
    /// Where the segment ends, within its own quarter hour.
    pub(super) end: u64,
    /// Where the next begins, within the quarter hour the wall clock reads now.
    pub(super) next: u64,
}

/// Where an open segment that began at `start` is cut, now that the wall clock reads `now`, `last` being
/// the log's reading of it before: nowhere while `start` and `now` are in one quarter hour. Every count
/// cuts before it counts ([`Shared::log_now`]), so the bytes a segment holds were all counted in its own
/// quarter hour.
///
/// - The clock moved forward, as across a phone's sleep or to a clock set ahead by days: the segment
///   ends at the end of its quarter hour, and the next begins at the start of now's. The flow was open
///   across every quarter hour passed, and those a sleep passed had no count.
/// - The clock was set back past the segment's quarter hour: the segment ends at `last`, the old
///   clock's last reading, and the next begins at `now`, the new clock's first, so that neither claims a
///   time no clock read, and no segment begins before its flow opened by the new clock (review 1 of
///   W5's first part, engine, finding 6).
#[must_use]
pub(super) fn cut(start: u64, now: u64, last: u64) -> Option<Cut> {
    let (quarter, now_quarter) = (start / SEGMENT_MS, now / SEGMENT_MS);
    if quarter == now_quarter {
        return None;
    }
    let end_of_quarter = quarter.saturating_add(1).saturating_mul(SEGMENT_MS);
    Some(if now_quarter > quarter {
        Cut {
            end: end_of_quarter,
            next: now_quarter * SEGMENT_MS,
        }
    } else {
        Cut {
            end: last.max(start).min(end_of_quarter),
            next: now,
        }
    })
}

/// Whether two readings of the wall clock are in one quarter hour.
fn same_quarter(a: u64, b: u64) -> bool {
    a / SEGMENT_MS == b / SEGMENT_MS
}

/// The bytes of one open flow, counted as they pass: what the app sent and received, and the IP
/// packets the tunnel carried for it, headers included, which is what Android counts for the app.
#[derive(Debug)]
pub(crate) struct FlowBytes {
    up: AtomicU64,
    down: AtomicU64,
    wire_up: AtomicU64,
    wire_down: AtomicU64,
    /// When the tunnel last carried a packet of the flow, in milliseconds since 1970; 0 for never.
    pub(super) last: AtomicU64,
    /// The second of the wall clock of the flow's latest mark, [`NO_SECOND`] for none since its
    /// segment began (`activity`).
    second: AtomicU64,
    /// Its seconds not placed in a state yet: the first count of each, with the counts before it.
    pub(super) marks: Mutex<VecDeque<Mark>>,
    /// Whether the flow's segments are all cut and handed to the log: a count after, as of a packet the
    /// tunnel carries once the relay has ended, notes no mark.
    ended: AtomicBool,
    /// The flow's app, whose share of what waits its marks count in (`activity`).
    uid: Option<u32>,
}

impl Default for FlowBytes {
    fn default() -> Self {
        Self {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            wire_up: AtomicU64::new(0),
            wire_down: AtomicU64::new(0),
            last: AtomicU64::new(0),
            second: AtomicU64::new(NO_SECOND),
            marks: Mutex::default(),
            ended: AtomicBool::new(false),
            uid: None,
        }
    }
}

impl FlowBytes {
    /// Counts what the app sent: `app` bytes as the app sent them, and `wire` bytes of the tunnel's IP
    /// packets, 0 for none. The log reads the time first ([`Shared::log_now`]), which cuts the flow's
    /// segment at any quarter hour passed since: the bytes fall in the quarter hour they were counted in,
    /// and in the second, whose mark comes before them.
    pub(super) fn up(&self, log: &Shared, app: usize, wire: usize) {
        let now = log.log_now();
        self.mark(log, now, app + wire);
        Self::add(&self.up, app);
        self.wire(&self.wire_up, wire, now);
    }

    /// Counts what the app received, as [`FlowBytes::up`] counts what it sent.
    pub(super) fn down(&self, log: &Shared, app: usize, wire: usize) {
        let now = log.log_now();
        self.mark(log, now, app + wire);
        Self::add(&self.down, app);
        self.wire(&self.wire_down, wire, now);
    }

    /// Notes the first count of a second of the wall clock, `now` in milliseconds, before `bytes` are
    /// added: within a second, a division, a few comparisons and one atomic load.
    fn mark(&self, log: &Shared, now: u64, bytes: usize) {
        let second = now / 1000;
        if bytes > 0 && self.second.load(Ordering::Relaxed) != second && log.tracks {
            self.mark_anew(log, second);
        }
    }

    #[cold]
    fn mark_anew(&self, log: &Shared, second: u64) {
        if self.ended.load(Ordering::Relaxed) {
            return;
        }
        self.second.store(second, Ordering::Relaxed);
        let counts = self.now();
        let held = {
            let mut marks = lock(&self.marks);
            marks.push_back(Mark { second, counts });
            marks.len()
        };
        log.marked(self.uid, held, second);
    }

    /// The next count notes its second anew, even the second of the latest mark, as after a clock set back.
    pub(super) fn forget_second(&self) {
        self.second.store(NO_SECOND, Ordering::Relaxed);
    }

    /// Takes the marks of the segment cut now: the next count begins one anew, in whatever second. With
    /// `ended`, the flow notes none any more.
    fn take_marks(&self, ended: bool) -> VecDeque<Mark> {
        let mut marks = lock(&self.marks);
        if ended {
            self.ended.store(true, Ordering::Relaxed);
        }
        self.second.store(NO_SECOND, Ordering::Relaxed);
        std::mem::take(&mut *marks)
    }

    /// Adds `n` to `counter`; nothing for no bytes, as a tunnel packet's of the app's own (the fresh
    /// review 2 of W5's first part, nit 6).
    fn add(counter: &AtomicU64, n: usize) {
        if n > 0 {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
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
    /// The state of the segment's seconds placed so far (`activity`), and the second after the last of
    /// them, before which no cut falls.
    pub(super) state: Option<Placed>,
    pub(super) after: u64,
    /// Whether its destination stays out of the log (a chained app's flow, [`Shared::hides`]): its
    /// record holds no address, port or name, and no hello names it later.
    pub(super) hidden: bool,
    /// Whether it went directly, not through the user's tool, when it opened: a flow hidden by a chain
    /// set after it opened goes on directly (review b2 of W5's second part, N3).
    pub(super) direct: bool,
}

/// An app's lookups to Watch's own DNS address: since when, and since the first, how many and the
/// tunnel's bytes for them, as counts: lookups, nought, bytes up, bytes down.
#[derive(Debug)]
pub(super) struct Lookups {
    pub(super) start: u64,
    /// The counts where the part not written yet starts, and the state of its seconds placed so far.
    pub(super) base: [u64; 4],
    pub(super) state: Option<Placed>,
    pub(super) after: u64,
    pub(super) counts: [u64; 4],
    /// The second of the latest mark, and the seconds not placed yet (`activity`).
    second: u64,
    pub(super) marks: VecDeque<Mark>,
}

impl Lookups {
    /// None yet, counted from `start`.
    fn since(start: u64) -> Self {
        Self {
            start,
            base: [0; 4],
            state: None,
            after: 0,
            counts: [0; 4],
            second: NO_SECOND,
            marks: VecDeque::new(),
        }
    }

    /// Counts `count` lookups and their packets' bytes up and down, in the wall clock's second `second`:
    /// its mark first, if it is the first count in it. The marks held, when it noted one.
    fn count(&mut self, second: Option<u64>, [count, up, down]: [u64; 3]) -> Option<usize> {
        let marked = match second {
            Some(second) if second != self.second => {
                self.second = second;
                self.marks.push_back(Mark {
                    second,
                    counts: self.counts,
                });
                Some(self.marks.len())
            }
            _ => None,
        };
        self.counts[0] += count;
        self.counts[2] += up;
        self.counts[3] += down;
        marked
    }

    /// The next count notes its second anew, even the second of the latest mark.
    pub(super) fn forget_second(&mut self) {
        self.second = NO_SECOND;
    }

    /// Its segment, from its start to `end`, held for its state ([`Shared::hold`]).
    fn piece(self, uid: Option<u32>, end: u64) -> Piece {
        Piece {
            of: Of::Lookups,
            uid,
            start: self.start,
            base: self.base,
            state: self.state,
            after: self.after,
            end: end.max(self.start),
            last: self.counts,
            continues: false,
            marks: self.marks,
        }
    }
}

impl Shared {
    /// The wall clock now, for the log, once every open segment and each app's lookups are cut at the
    /// quarter hours it passed since the last cut, back or forward ([`cut`]). Every path that counts a
    /// byte or a lookup, opens a flow or ends one reads the time here first, so that nothing is counted
    /// in a segment of another quarter hour. One reading of the wall clock (a vDSO call) and one atomic
    /// load; the cut itself only when a quarter hour passed. A clock set back by a second or more first
    /// places every second held for its state (`activity`, [`Shared::clock_set_back`]), so that the
    /// seconds of two clocks never wait for one reading.
    pub(super) fn log_now(&self) -> u64 {
        debug_assert!(
            self.engine_thread
                .get()
                .is_none_or(|engine| *engine == std::thread::current().id()),
            "the log's clock was read off the engine's thread"
        );
        let now = self.clock.wall_ms();
        let last = self.last_reading.swap(now, Ordering::Relaxed);
        // The cut first: the segments it cuts are then held when a clock set back places what waits
        // (review b1 of W5's second part, engine, finding 6).
        if now / SEGMENT_MS != self.quarter.load(Ordering::Acquire) {
            self.cut_all(now, last);
        }
        if now.saturating_add(1000) <= last && self.tracks {
            self.clock_set_back(now);
        }
        now
    }

    /// Cuts every open segment and each app's lookups that are not in `now`'s quarter hour, and then
    /// says they all are. Only on the engine's thread, as every count, so nothing is counted meanwhile.
    /// Each segment cut waits for the states of its seconds ([`Shared::hold`]).
    fn cut_all(&self, now: u64, last: u64) {
        let quarter = now / SEGMENT_MS;
        let mut pieces = Vec::new();
        {
            let mut live = lock(&self.live);
            for live in live.values_mut() {
                if let Some(Cut { end, next }) = cut(live.start, now, last) {
                    let marks = live.bytes.take_marks(false);
                    let counts = live.bytes.now();
                    pieces.push(Piece {
                        of: Of::Flow {
                            flow: live.flow.clone(),
                            hidden: live.hidden,
                            direct: live.direct,
                        },
                        uid: live.flow.uid,
                        start: live.start,
                        base: live.base,
                        state: live.state.take(),
                        after: live.after,
                        end,
                        last: counts,
                        continues: true,
                        marks,
                    });
                    live.start = next;
                    live.base = counts;
                }
            }
            let mut lookups = lock(&self.lookups);
            let cuts: Vec<_> = lookups
                .iter()
                .filter_map(|(&uid, l)| cut(l.start, now, last).map(|Cut { end, .. }| (uid, end)))
                .collect();
            for (uid, end) in cuts {
                if let Some(entry) = lookups.remove(&uid) {
                    pieces.push(entry.piece(uid, end));
                }
            }
            self.quarter.store(quarter, Ordering::Release);
        }
        self.hold(pieces);
    }

    /// Counts a new flow and keeps it for tests. For the log, a flow that opened becomes live and gets
    /// its byte counts; one that did not is written once its moment's state is told. Lookups to Watch's
    /// own DNS address are counted per app instead.
    pub(super) fn record(&self, flow: Flow) -> Option<Arc<FlowBytes>> {
        let via = match self.route(flow.uid, flow.destination) {
            super::chain::Route::Tool(chain) => Some(chain),
            super::chain::Route::Direct
            | super::chain::Route::Tunnel(_)
            | super::chain::Route::Refused => None,
        };
        self.record_via(flow, via.as_deref())
    }

    /// Counts a new flow that went the way it was routed, `via` the chain whose tool it went through, or
    /// directly: a connection routed before a chain was set, or turned off, and recorded after, is shown
    /// the way it went (review b3 of W5's second part, R2).
    pub(super) fn record_via(
        &self,
        flow: Flow,
        via: Option<&super::Chain>,
    ) -> Option<Arc<FlowBytes>> {
        let mut flow = flow;
        if via.is_some() {
            flow.via = super::Via::Tool;
        }
        let logged = self.log_flow(&flow, via);
        self.keep(flow);
        logged
    }

    /// The log's part of [`Shared::record_via`]. Its destination stays out of the log when the chain it
    /// went through said so, or the chain now does: the switch is honoured either way.
    fn log_flow(&self, flow: &Flow, via: Option<&super::Chain>) -> Option<Arc<FlowBytes>> {
        if self.is_tunnel_dns(flow.destination.ip()) {
            return None;
        }
        let hidden = via.is_some_and(|chain| !chain.log_destinations)
            || self.hides(flow.uid, flow.destination);
        let direct = via.is_none();
        let stripped;
        let flow = if hidden {
            stripped = without_destination(flow);
            &stripped
        } else {
            flow
        };
        let now = self.log_now();
        // A flow opened, or tried: its app's state is wanted (ADR 0046, decision 1).
        self.ask(now / 1000);
        if flow.outcome != Outcome::Opened {
            self.hold(vec![Piece {
                of: Of::Flow {
                    flow: flow.clone(),
                    hidden,
                    direct,
                },
                uid: flow.uid,
                start: now,
                base: [0; 4],
                state: None,
                after: 0,
                end: now,
                last: [0; 4],
                continues: false,
                marks: VecDeque::new(),
            }]);
            return None;
        }
        let bytes = Arc::new(FlowBytes {
            uid: flow.uid,
            ..FlowBytes::default()
        });
        lock(&self.live).insert(
            flow.id,
            Live {
                flow: flow.clone(),
                bytes: Arc::clone(&bytes),
                start: now,
                base: [0; 4],
                state: None,
                after: 0,
                hidden,
                direct,
            },
        );
        self.log_ready.notify_one();
        Some(bytes)
    }

    /// Counts a lookup an app sent to Watch's own DNS address, `packet` bytes on the tunnel.
    pub(super) fn lookup(&self, uid: Option<u32>, packet: usize) {
        self.count_lookups(uid, [1, packet as u64, 0]);
        self.log_ready.notify_one();
    }

    /// Counts an answer to an app's lookup, `packet` bytes on the tunnel. An answer whose lookup was
    /// counted in a quarter hour already cut is counted in its own, with no lookup.
    pub(super) fn lookup_answered(&self, uid: Option<u32>, packet: usize) {
        if self.count_lookups(uid, [0, 0, packet as u64]) {
            self.log_ready.notify_one();
        }
    }

    /// Counts lookups and their packets' bytes up and down for the app `uid`, after the cut and the
    /// mark of the second: whether the app's count began anew.
    fn count_lookups(&self, uid: Option<u32>, counts: [u64; 3]) -> bool {
        let now = self.log_now();
        let second = (self.tracks && counts.iter().any(|&c| c > 0)).then_some(now / 1000);
        let mut lookups = lock(&self.lookups);
        let new = !lookups.contains_key(&uid);
        let marked = lookups
            .entry(uid)
            .or_insert_with(|| Lookups::since(now))
            .count(second, counts);
        drop(lookups);
        if let (Some(held), Some(second)) = (marked, second) {
            self.marked(uid, held, second);
        }
        new
    }

    /// A live flow ended: its segment is cut at any quarter hour passed, as a count would cut it, and its
    /// last segment written once its seconds' states are told.
    pub(super) fn finish(&self, id: u64) {
        let now = self.log_now();
        self.proxies_ended(id);
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let end = now.max(live.start);
        self.hold(vec![piece(live, end, false)]);
    }

    /// A TCP flow the engine ended itself before its relay began, recorded as opened when its server
    /// accepted, which the app saw end otherwise (ADR 0044, unit 12b, third round): refused, or reset
    /// (`Outcome::Failed`). Its outcome becomes `outcome` in its last segment, the counters and the
    /// flows kept, and its last segment is written, as [`Shared::finish_closed`] writes it. The cut
    /// comes first, so that a segment of a quarter hour before keeps the outcome the flow had then,
    /// whoever cuts it (review 1 of W5's first part, engine, finding 2).
    pub(super) fn finish_as(&self, id: u64, outcome: Outcome) {
        self.log_now();
        match lock(&self.live).get_mut(&id) {
            Some(live) => live.flow.outcome = outcome,
            None => return,
        }
        if let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id) {
            flow.outcome = outcome;
        }
        let counter = match outcome {
            // A flow blocking refused is counted where it is refused (`Shared::count_block`).
            Outcome::Opened | Outcome::Blocked => None,
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
        self.proxies_ended(id);
        let Some(live) = lock(&self.live).remove(&id) else {
            return;
        };
        let last = live.bytes.last.load(Ordering::Relaxed);
        let end = if last == 0 {
            now.max(live.start)
        } else if last >= live.start && same_quarter(live.start, last) {
            last
        } else {
            live.start
        };
        self.hold(vec![piece(live, end, false)]);
    }

    /// Asks the engine's thread to flush the log ([`Shared::flush`]) and hand its records on, and waits
    /// until it has, at most `wait`: from another thread, for the end-to-end test, which cannot wait
    /// ([`super::Engine::flush_log`]). The logger makes the flush between counts, on the thread that
    /// makes them (the module's comment). False if it did not in time, or the engine stopped first: then
    /// once the engine has handed its last records on.
    ///
    /// When no logger is there to make it, as before the engine's tunnel is up or once it has stopped,
    /// it waits for nothing (the fresh review 2 of W5's first part, nit 7: the debug flush held Watch's
    /// lock on the engine for the whole wait then). A waiter asked of a logger that then ends without its
    /// engine's loop, as only tests run it, waits out `wait`.
    pub(super) fn ask_flush(&self, wait: Duration) -> bool {
        let answer = {
            let mut asked = lock(&self.flushes);
            if !asked.logging {
                return false;
            }
            let (done, answer) = std::sync::mpsc::sync_channel(1);
            asked.waiting.push(done);
            answer
        };
        self.flush_wanted.notify_one();
        answer.recv_timeout(wait).is_ok()
    }

    /// Writes every live flow's segment up to now, as a quarter hour would, and the lookups counted so
    /// far, each second whose state was not told yet in no state, "not told".
    pub(super) fn flush(&self) {
        let now = self.log_now();
        let mut pieces = Vec::new();
        for live in lock(&self.live).values_mut() {
            if live.start >= now {
                continue;
            }
            let marks = live.bytes.take_marks(false);
            let counts = live.bytes.now();
            pieces.push(Piece {
                of: Of::Flow {
                    flow: live.flow.clone(),
                    hidden: live.hidden,
                    direct: live.direct,
                },
                uid: live.flow.uid,
                start: live.start,
                base: live.base,
                state: live.state.take(),
                after: live.after,
                end: now,
                last: counts,
                continues: true,
                marks,
            });
            live.start = now;
            live.base = counts;
        }
        for (uid, lookups) in lock(&self.lookups).drain() {
            pieces.push(lookups.piece(uid, now));
        }
        self.hold(pieces);
        self.settle(Some(Force::ALL));
    }

    /// Ends every live flow now, as when the engine stops, after the cut a count would make. Each second
    /// whose state was not told yet is written in no state, "not told", unless the engine hands what it
    /// holds to the next one, on a tunnel set up again ([`super::Engine::hand_over`]).
    pub(super) fn finish_all(&self) {
        let now = self.log_now();
        self.proxies_all_ended();
        let live: Vec<Live> = lock(&self.live).drain().map(|(_, l)| l).collect();
        let mut pieces: Vec<Piece> = live
            .into_iter()
            .map(|l| {
                let end = now.max(l.start);
                piece(l, end, false)
            })
            .collect();
        for (uid, lookups) in lock(&self.lookups).drain() {
            pieces.push(lookups.piece(uid, now));
        }
        self.hold(pieces);
        if !self.handing_over.load(Ordering::Relaxed) {
            self.settle(Some(Force::ALL));
        }
        // No flow of this engine can be taken back any more (ADR 0052).
        self.release_held_back();
    }

    /// The records waiting, as one batch, if there are any.
    pub(super) fn take_log(&self) -> Option<Vec<u8>> {
        let records = std::mem::take(&mut *lock(&self.pending_log));
        (!records.is_empty()).then(|| log::batch(&records))
    }

    /// Writes what waits for its states as not told, and hands it to the log at once: for an engine with
    /// no thread of its own to write it.
    pub(super) fn write_off(&self) {
        self.settle(Some(Force::ALL));
        if let Some(batch) = self.take_log() {
            self.platform.log(&batch);
        }
    }
}

/// A flow with its destination left out, as the log keeps a chained app's ([`Shared::hides`]): no
/// address, port, name or network.
pub(super) fn without_destination(flow: &Flow) -> Flow {
    Flow {
        destination: packet::unspecified_like(&flow.destination),
        name: None,
        named_by: NamedBy::Unknown,
        dns_name: None,
        ech: Ech::Absent,
        dns: DnsUse::None,
        resolver: None,
        network: None,
        // An app's own proxy keeps its kind, and the facts that name nothing (ADR 0052).
        proxy: flow
            .proxy
            .as_ref()
            .map(|p| Box::new(p.without_destination())),
        ..flow.clone()
    }
}

impl Shared {
    /// The chain was set anew (`Engine::chain`): the flows it now sends through the tool with their
    /// destinations left out, as when "Log where these apps connect" is turned off, lose them at once,
    /// in their open segments, in the segments that wait for their states, and in the live view, which
    /// keeps of such an app only its bytes, marked as through the tool (ADR 0046, decision 6, item 5).
    /// A flow opened while the switch was on adds no destination after. What the log already wrote stays,
    /// for the retention the user chose.
    pub(super) fn hide_chained(&self) {
        // An app's own proxy follows the same switch (ADR 0052): a confirmed or inferred one's flow is left out
        // whole; a plain request's keeps its own address and names, and loses only what it asked for.
        let own_proxies = !self.logs_own_proxies();
        let forwarded = |flow: &Flow| {
            flow.proxy
                .as_ref()
                .is_some_and(|p| p.kind == crate::proxies::Kind::Forward)
        };
        let hides = |flow: &Flow| {
            self.hides(flow.uid, flow.destination)
                || own_proxies && flow.proxy.is_some() && !forwarded(flow)
        };
        let strip_asked = |flow: &mut Flow| {
            if own_proxies && forwarded(flow) {
                flow.proxy = flow.proxy.as_ref().map(|p| Box::new(p.without_asked()));
            }
        };
        let mut live = lock(&self.live);
        for live in live.values_mut() {
            if !live.hidden && hides(&live.flow) {
                live.hidden = true;
                live.flow = without_destination(&live.flow);
            }
            strip_asked(&mut live.flow);
        }
        let mut activity = lock(&self.activity);
        for piece in &mut activity.held {
            if let Of::Flow { flow, hidden, .. } = &mut piece.of {
                if !*hidden && hides(flow) {
                    *hidden = true;
                    *flow = without_destination(flow);
                }
                strip_asked(flow);
            }
        }
        activity.counts.hide(|uid| self.hides_app(uid));
        if own_proxies {
            activity.counts.hide_proxies();
        }
    }
}

/// A live flow's last segment, from its start to `end`, held for its state ([`Shared::hold`]): it notes
/// no mark any more.
fn piece(live: Live, end: u64, continues: bool) -> Piece {
    let marks = live.bytes.take_marks(true);
    Piece {
        uid: live.flow.uid,
        start: live.start,
        base: live.base,
        state: live.state,
        after: live.after,
        end,
        last: live.bytes.now(),
        continues,
        marks,
        of: Of::Flow {
            flow: live.flow,
            hidden: live.hidden,
            direct: live.direct,
        },
    }
}

#[cfg(test)]
pub(super) fn delta(now: [u64; 4], base: [u64; 4]) -> [u64; 4] {
    [0, 1, 2, 3].map(|i| now[i].saturating_sub(base[i]))
}

/// Who waits for a flush of the log, and whether a logger is there to make one ([`Shared::ask_flush`]).
#[derive(Default)]
pub(super) struct Flushes {
    /// Whether a logger runs, or is about to, to answer.
    pub(super) logging: bool,
    /// Who waits, told once the flush is done.
    pub(super) waiting: Vec<std::sync::mpsc::SyncSender<()>>,
}

/// The logger's end, however it comes: no flush can be asked of it any more. Who waits already is let
/// go by the engine's loop once it has handed its last records on (`run`'s end), so that a flush asked
/// as the engine stops is answered by them (review 3 of W5's first part, finding 1: let go here, it was
/// answered before them).
struct Ended<'a>(&'a Shared);

impl Drop for Ended<'_> {
    fn drop(&mut self) {
        lock(&self.0.flushes).logging = false;
    }
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
    lock(&shared.flushes).logging = true;
    // However it returns, no flush is waited for any more: who waits is let go.
    let _ended = Ended(&shared);
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
        let now = shared.log_now();
        // Segments that wait for their states: asked for again, as traffic ran a moment ago.
        if !lock(&shared.activity).held.is_empty() {
            shared.ask(now / 1000);
        }
        let asked = std::mem::take(&mut lock(&shared.flushes).waiting);
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
    use crate::log::Record;
    use crate::states::Unknown;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::Mutex;

    /// Where a segment of a platform that tells no states is placed.
    const NOT_TOLD: Placed = Placed::Unknown(Unknown::NotTold);

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
            dns_name: None,
            came_in: false,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
            via: crate::engine::Via::Direct,
            proxy: None,
            blocked: None,
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
                    ..
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
        assert_eq!(cut(at(22, 10), at(22, 15) - 1, at(22, 11)), None);
        // A segment that starts on a quarter hour is in it.
        assert_eq!(cut(at(22, 15), at(22, 29), at(22, 20)), None);
        // A clock set back within the quarter hour moves nothing.
        assert_eq!(cut(at(22, 12), at(22, 10), at(22, 13)), None);
    }

    #[test]
    fn one_quarter_hour_passed_cuts_there() {
        let at_22_15 = Some(Cut {
            end: at(22, 15),
            next: at(22, 15),
        });
        assert_eq!(cut(at(22, 10), at(22, 16), at(22, 14)), at_22_15);
        // Exactly on it.
        assert_eq!(cut(at(22, 10), at(22, 15), at(22, 14)), at_22_15);
        assert_eq!(
            cut(at(22, 15), at(22, 30), at(22, 29)),
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
            cut(at(22, 10), at(30, 16), at(22, 12)),
            Some(Cut {
                end: at(22, 15),
                next: at(30, 15),
            })
        );
    }

    /// A wall clock set back, past the segment's quarter hour, ends the segment at the old clock's last
    /// reading and begins the next at the new clock's first: bounds no clock read, such as the end of
    /// the old quarter hour, or the start of the new one before the flow opened, are left out. A last
    /// reading before the segment, as no count has made, ends it at its start.
    #[test]
    fn a_clock_set_back_ends_the_segment_at_the_last_reading_and_begins_the_next_now() {
        assert_eq!(
            cut(at(22, 10), at(21, 50), at(22, 12)),
            Some(Cut {
                end: at(22, 12),
                next: at(21, 50),
            })
        );
        assert_eq!(
            cut(at(22, 10), 0, at(22, 10)),
            Some(Cut {
                end: at(22, 10),
                next: 0,
            })
        );
        assert_eq!(
            cut(at(22, 10), at(21, 50), 0),
            Some(Cut {
                end: at(22, 10),
                next: at(21, 50),
            })
        );
        assert_eq!(
            cut(at(22, 10), at(21, 50), at(23, 0)),
            Some(Cut {
                end: at(22, 15),
                next: at(21, 50),
            })
        );
    }

    #[test]
    fn a_clock_set_forward_by_days_cuts_as_a_long_sleep() {
        let days = 40 * 24 * HOUR;
        assert_eq!(
            cut(at(22, 10), at(22, 10) + days, at(22, 11)),
            Some(Cut {
                end: at(22, 15),
                next: at(22, 0) + days,
            })
        );
        // The end of time does not overflow.
        assert_eq!(
            cut(u64::MAX - 1, 0, u64::MAX),
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
                cut(midnight - MINUTE, midnight + MINUTE, midnight - MINUTE),
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
                    if let Some(Cut { end, next }) = cut(start, now, start) {
                        assert!(
                            !(start < midnight && midnight < end),
                            "{offset}: {start}..{end} holds {midnight}"
                        );
                        assert!(next <= now && now - next < SEGMENT_MS);
                        assert!(start <= end && (end == start || same_quarter(start, end - 1)));
                    }
                }
            }
        }
    }

    /// Where Watch's Kotlin side keeps the fixture its tests read (`LogTest`, `LogDaysTest`).
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/network/src/test/resources/org/visadahyu/datapavan/network/log/engine-records.hex"
    );

    /// The fixture's records: a segment of each kind the reader must tell apart, an app's lookups, and
    /// the segments the engine cuts around the midnights of Kathmandu (+5:45), the Chatham Islands (+13:45
    /// in their summer) and Eucla (+8:45), between 2026-11-17 and 2026-11-18, local time; with the states
    /// of version 3, each kind, and among those with none, no app, told too late and not told.
    fn fixture_records() -> Vec<Record> {
        use super::super::Network;
        use crate::owners::NetworkKind;
        let tls = Flow {
            id: 7,
            destination: SocketAddr::from(([93, 184, 216, 34], 443)),
            name: Some("other.example".into()),
            named_by: NamedBy::Tls,
            dns_name: Some("www.example.com".into()),
            ech: Ech::Offered,
            network: Some(Network {
                asn: 15_133,
                kind: NetworkKind::Hosting,
            }),
            ..flow(7)
        };
        let came_in = Flow {
            id: 8,
            protocol: crate::packet::UDP,
            app: SocketAddr::from((
                std::net::Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 1),
                40_001,
            )),
            destination: SocketAddr::from((
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53),
                853,
            )),
            uid: None,
            outcome: Outcome::Unreachable,
            name: Some("quic.example".into()),
            named_by: NamedBy::Quic,
            came_in: true,
            ech: Ech::Hidden,
            dns: DnsUse::Encrypted,
            resolver: Some("sample".into()),
            ..flow(8)
        };
        let organisation = Flow {
            id: 9,
            outcome: Outcome::Failed,
            name: Some("Société Générale".into()),
            named_by: NamedBy::Organisation,
            dns: DnsUse::Plain,
            network: Some(Network {
                asn: 29_084,
                kind: NetworkKind::Unlisted,
            }),
            ..flow(9)
        };
        let mut records = vec![
            Record::Segment {
                flow: tls,
                start: at(22, 10),
                end: at(22, 15),
                bytes: [300, 40_000, 820, 42_900],
                continues: true,
                state: Placed::Known(crate::states::State::InUse),
            },
            Record::Segment {
                flow: came_in,
                start: at(22, 16),
                end: at(22, 16),
                bytes: [0; 4],
                continues: false,
                state: Placed::Unknown(Unknown::NoApp),
            },
            Record::Segment {
                flow: organisation,
                start: at(22, 17),
                end: at(22, 17),
                bytes: [0; 4],
                continues: false,
                state: Placed::Known(crate::states::State::Background),
            },
            Record::Lookups {
                uid: Some(10_123),
                start: at(22, 10),
                end: at(22, 15),
                count: 3,
                wire_up: 210,
                wire_down: 540,
                state: Placed::Known(crate::states::State::Notification),
            },
        ];
        // Kathmandu's, the Chatham Islands' and Eucla's midnights, in UTC: a flow opened ten minutes
        // before, a count on each side, its end ten minutes after.
        for (id, midnight) in [(11, at(18, 15)), (12, at(10, 15)), (13, at(15, 15))] {
            let (shared, clock) = log_at(midnight - 10 * MINUTE);
            let bytes = open(&shared, id);
            bytes.up(&shared, 100, 140);
            clock.set(midnight + 10 * MINUTE);
            bytes.down(&shared, 200, 240);
            shared.finish(id);
            records.extend(taken(&shared));
        }
        records.push(fixture_codes());
        records.extend(fixture_proxies());
        records
    }

    /// The fixture's segments of an app's own proxies (version 5, ADR 0052): a SOCKS5 proxy its bytes declared,
    /// asked for a name, with a password unencrypted, named by Android's setting, its own name and its network's
    /// organisation kept; an HTTP proxy asked for an address; Telegram's `MTProto` proxy inferred, outside its maker's
    /// network, with the cover its hello sent; a SOCKS4 proxy with its destination left out, which keeps two
    /// trackers' marks; and a plain request with what it asked for left out, which keeps its own name and address
    /// (the fix round).
    #[allow(clippy::too_many_lines)]
    fn fixture_proxies() -> Vec<Record> {
        use super::super::{Network, Proxied};
        use crate::owners::NetworkKind;
        use crate::proxies::{Asked, Kind};
        let proxy = |kind| Proxied {
            kind,
            setting: false,
            password: false,
            outside_maker: false,
            asked: None,
            proxy_name: None,
            organisation: None,
            cover: None,
            left_out: false,
            trackers: Vec::new(),
        };
        let segment = |flow: Flow, minute| Record::Segment {
            flow,
            start: at(22, minute),
            end: at(22, minute),
            bytes: [10, 20, 30, 40],
            continues: false,
            state: Placed::Known(crate::states::State::InUse),
        };
        let network = Some(Network {
            asn: 24_940,
            kind: NetworkKind::Unlisted,
        });
        vec![
            segment(
                Flow {
                    id: 20,
                    destination: SocketAddr::from(([203, 0, 113, 5], 1080)),
                    name: Some("example.org".into()),
                    named_by: NamedBy::Proxy,
                    network,
                    proxy: Some(Box::new(Proxied {
                        setting: true,
                        password: true,
                        asked: Some((Asked::Name("example.org".into()), 443)),
                        proxy_name: Some("proxy.example.net".into()),
                        organisation: Some("Hetzner Online GmbH".into()),
                        ..proxy(Kind::Socks5)
                    })),
                    ..flow(20)
                },
                20,
            ),
            segment(
                Flow {
                    id: 21,
                    destination: SocketAddr::from(([192, 168, 1, 2], 3128)),
                    name: None,
                    named_by: NamedBy::Unknown,
                    proxy: Some(Box::new(Proxied {
                        asked: Some((
                            Asked::Address(
                                "2001:db8::7".parse().unwrap_or(std::net::IpAddr::V6(
                                    std::net::Ipv6Addr::UNSPECIFIED,
                                )),
                            ),
                            8443,
                        )),
                        ..proxy(Kind::Connect)
                    })),
                    ..flow(21)
                },
                21,
            ),
            segment(
                Flow {
                    id: 22,
                    destination: SocketAddr::from(([198, 51, 100, 9], 443)),
                    name: Some("Hetzner Online GmbH".into()),
                    named_by: NamedBy::Organisation,
                    network,
                    proxy: Some(Box::new(Proxied {
                        outside_maker: true,
                        organisation: Some("Hetzner Online GmbH".into()),
                        cover: Some("www.google.com".into()),
                        ..proxy(Kind::MtProto)
                    })),
                    ..flow(22)
                },
                22,
            ),
            segment(
                without_destination(&Flow {
                    id: 23,
                    proxy: Some(Box::new(Proxied {
                        trackers: vec![49, 312],
                        ..proxy(Kind::Socks4)
                    })),
                    ..flow(23)
                }),
                23,
            ),
            segment(
                Flow {
                    id: 24,
                    destination: SocketAddr::from(([198, 51, 100, 7], 8080)),
                    name: Some("cache.example.net".into()),
                    named_by: NamedBy::Dns,
                    proxy: Some(Box::new(Proxied {
                        password: true,
                        ..proxy(Kind::Forward)
                    })),
                    ..flow(24)
                },
                24,
            ),
        ]
    }

    /// The fixture's segment of the codes the others leave out (review 1 of W5's first part, names, finding
    /// 7): named by DNS, refused, a network of a known owner, both flags, and told too late.
    fn fixture_codes() -> Record {
        use super::super::Network;
        use crate::owners::NetworkKind;
        Record::Segment {
            flow: Flow {
                id: 10,
                outcome: Outcome::Refused,
                name: Some("www.example.com".into()),
                named_by: NamedBy::Dns,
                came_in: true,
                network: Some(Network {
                    asn: 32_934,
                    kind: NetworkKind::Own,
                }),
                // Through the WireGuard tunnel of number 7 (version 4).
                via: super::super::Via::Tunnel(7),
                ..flow(10)
            },
            start: at(22, 18),
            end: at(22, 19),
            bytes: [1, 2, 3, 4],
            continues: true,
            state: Placed::Unknown(Unknown::Late),
        }
    }

    /// The fixture Watch's Kotlin side reads is what the engine writes, byte for byte, so that the two
    /// cannot drift apart unseen: a change of the format fails here until the fixture is written anew
    /// (`DATAPAVAN_WRITE_FIXTURE=1`), and then the Kotlin tests read it. The engine's own cuts are in
    /// it: midnight in Kathmandu ends a segment there.
    #[test]
    fn the_kotlin_sides_fixture_is_what_the_engine_writes() -> std::io::Result<()> {
        let records = fixture_records();
        assert_eq!(
            segments(&records[4..6]),
            vec![
                (11, at(18, 5), at(18, 15), [100, 0, 140, 0], true),
                (11, at(18, 15), at(18, 25), [0, 200, 0, 240], false),
            ]
        );
        let mut text = String::from(
            "# Watch's connection log: one batch of records as the engine writes them (core/net/src/log.rs,\n\
             # version 6), in hex. Written by the engine's test the_kotlin_sides_fixture_is_what_the_engine_writes\n\
             # (core/net/src/engine/logbook.rs), which fails when the engine writes otherwise; run it with\n\
             # DATAPAVAN_WRITE_FIXTURE=1 to write it anew. Read by LogTest and LogDaysTest. Not edited by hand.\n",
        );
        for line in log::batch(&records).chunks(48) {
            text.extend(line.iter().map(|b| format!("{b:02x}")));
            text.push('\n');
        }
        if std::env::var_os("DATAPAVAN_WRITE_FIXTURE").is_some() {
            std::fs::write(FIXTURE, &text)?;
        }
        let kept = std::fs::read_to_string(FIXTURE)?;
        assert!(
            kept == text,
            "{FIXTURE} is not what the engine writes: run this test with DATAPAVAN_WRITE_FIXTURE=1, then \
             the Kotlin side's LogTest"
        );
        Ok(())
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
                (1, at(22, 10), at(22, 10), [10, 0, 0, 0], true),
                (1, at(21, 50), at(22, 0), [20, 0, 0, 0], true),
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
        let mut seen = segments(&taken(&shared));
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![
                (1, at(30, 15), at(30, 16), [0; 4], true),
                (2, at(30, 16), at(30, 16), [0; 4], true),
            ]
        );
        assert_eq!(open_segment(&shared, 2), (at(22, 40), [5, 0, 0, 0]));
        assert_eq!(open_segment(&shared, 1).0, at(22, 40));
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
        let outcomes: Vec<_> = records
            .iter()
            .filter_map(|r| match r {
                Record::Segment { flow, .. } => Some(flow.outcome),
                Record::Lookups { .. } => None,
            })
            .collect();
        assert_eq!(outcomes, vec![Outcome::Opened, Outcome::Refused]);
    }

    /// A hello read after a sleep names the flow from then on: the segment of the quarter hour before
    /// is cut first, with the name it had then, whether or not a count cuts it before the hello.
    #[test]
    fn a_hello_after_a_sleep_leaves_the_name_of_the_segment_before() {
        let (shared, clock) = log_at(at(22, 10));
        let Some(bytes) = shared.record(Flow {
            name: Some("www.example.com".into()),
            named_by: NamedBy::Dns,
            ..flow(1)
        }) else {
            unreachable!("an open flow is live")
        };
        bytes.up(&shared, 517, 557);
        clock.set(at(30, 16));
        let opened = super::super::Opened {
            id: 1,
            port: 443,
            destination: std::net::SocketAddr::from(([192, 0, 2, 1], 443)),
            sniffs: false,
            dns: DnsUse::None,
            uid: Some(10_123),
            dns_held_until: Duration::MAX,
        };
        let hello = crate::tls::Hello {
            name: "other.example".into(),
            ech: false,
        };
        shared.hello(opened, &hello, NamedBy::Tls);
        let named: Vec<_> = taken(&shared)
            .iter()
            .filter_map(|r| match r {
                Record::Segment { flow, start, .. } => Some((*start, flow.name.clone())),
                Record::Lookups { .. } => None,
            })
            .collect();
        assert_eq!(named, vec![(at(22, 10), Some("www.example.com".into()))]);
        assert_eq!(
            lock(&shared.live)[&1].flow.name.as_deref(),
            Some("other.example")
        );
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
                state: NOT_TOLD,
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
                    state: NOT_TOLD,
                },
                Record::Lookups {
                    uid: Some(10_123),
                    start: at(30, 16),
                    end: at(30, 30),
                    count: 1,
                    wire_up: 72,
                    wire_down: 300,
                    state: NOT_TOLD,
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

    /// A count within the quarter hour of the last cut takes no lock: one reading of the clock and one
    /// atomic load. The test holds the open flows' lock while another thread counts, which ends all
    /// the same.
    #[test]
    fn a_count_within_the_quarter_hour_takes_no_lock() {
        let (shared, clock) = log_at(at(22, 10));
        let shared = Arc::new(shared);
        let bytes = open(&shared, 1);
        clock.pass(MINUTE);
        let held = lock(&shared.live);
        let (done, counted) = std::sync::mpsc::channel();
        {
            let (shared, bytes) = (Arc::clone(&shared), Arc::clone(&bytes));
            std::thread::spawn(move || {
                bytes.up(&shared, 10, 0);
                let _ = done.send(());
            });
        }
        let quick = counted.recv_timeout(Duration::from_secs(5)).is_ok();
        drop(held);
        assert!(quick, "the count waited for the open flows' lock");
    }

    /// A closed flow's last segment ends within its own quarter hour: at its last packet where that
    /// passed in the segment, else at its start, as after a flush, which begins a segment after the last
    /// packet, or after a clock set back, which begins one in the quarter hour before.
    #[test]
    fn a_closed_flows_last_segment_ends_within_its_quarter_hour() {
        let (shared, clock) = log_at(at(22, 10));
        open(&shared, 1).down(&shared, 0, 52);
        clock.set(at(22, 12));
        shared.flush();
        clock.set(at(22, 13));
        shared.finish_closed(1);
        clock.set(at(22, 20));
        open(&shared, 2).down(&shared, 0, 52);
        clock.set(at(22, 5));
        shared.finish_closed(2);
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, at(22, 10), at(22, 12), [0, 0, 0, 52], true),
                (1, at(22, 12), at(22, 12), [0; 4], false),
                (2, at(22, 20), at(22, 20), [0, 0, 0, 52], true),
                (2, at(22, 5), at(22, 5), [0; 4], false),
            ]
        );
    }

    /// A second flush in the same millisecond writes nothing: no segment begins and ends at once.
    #[test]
    fn a_flush_in_the_same_millisecond_writes_nothing_more() {
        let (shared, _clock) = log_at(at(22, 10) + 1);
        open(&shared, 1).up(&shared, 10, 0);
        let _ = taken(&shared);
        shared.flush();
        assert_eq!(taken(&shared), vec![]);
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
            state: NOT_TOLD,
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

    /// A clock that notes the thread of every reading once the engine's thread has begun.
    struct Probe {
        clock: Arc<ManualClock>,
        on: std::sync::atomic::AtomicBool,
        threads: Mutex<std::collections::HashSet<std::thread::ThreadId>>,
    }

    impl super::super::Clock for Probe {
        fn wall_ms(&self) -> u64 {
            if self.on.load(Ordering::SeqCst) {
                lock(&self.threads).insert(std::thread::current().id());
            }
            self.clock.wall_ms()
        }

        fn since_boot(&self) -> Duration {
            self.clock.since_boot()
        }
    }

    /// No race is left (the module's comment), since the log reads its clock on the engine's thread
    /// alone: a flush asked from another thread, here as the clock passes 22:15, is made there between
    /// its counts. The clock notes the thread of each reading, which must be the engine's; and each byte
    /// falls in the quarter hour of the reading it was counted on, to the byte. The counts here stand
    /// for a relay's, one at each of its turns on the engine's thread.
    #[test]
    fn a_flush_asked_from_another_thread_is_made_between_the_engines_counts() -> std::io::Result<()>
    {
        /// The counts before the flush is asked, and after it is done.
        const COUNTS: u64 = 2_000;
        let platform = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 15) - 50);
        let probe = Arc::new(Probe {
            clock: clock.clone(),
            on: false.into(),
            threads: Mutex::default(),
        });
        let mut shared = shared_with(platform.clone());
        shared.clock = probe.clone();
        let shared = Arc::new(shared);
        let bytes = open(&shared, 1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        // The engine counts until the flush is done, then a fixed number more: however the threads are
        // scheduled, its logger is there to make the flush (the fresh review 2, finding 3: with a fixed
        // count, a thread descheduled until the logger had gone waited ten seconds for nothing).
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let engine = {
            let (shared, bytes, probe) = (Arc::clone(&shared), Arc::clone(&bytes), probe.clone());
            let flushed = Arc::clone(&flushed);
            std::thread::spawn(move || {
                let _ = shared.engine_thread.set(std::thread::current().id());
                probe.on.store(true, Ordering::SeqCst);
                runtime.block_on(async move {
                    let (end, ending) = watch::channel(false);
                    let logging = tokio::spawn(logger(Arc::clone(&shared), ending));
                    let (mut early, mut counted, mut after) = (0, 0, 0);
                    while after < COUNTS {
                        bytes.up(&shared, 1, 1);
                        counted += 1;
                        if bytes.last.load(Ordering::Relaxed) < at(22, 15) {
                            early += 1;
                        }
                        if flushed.load(Ordering::SeqCst) {
                            after += 1;
                        }
                        tokio::task::yield_now().await;
                    }
                    let _ = end.send(true);
                    let _ = logging.await;
                    shared.finish_all();
                    (early, counted)
                })
            })
        };
        let waited = std::time::Instant::now();
        while bytes.now()[0] < COUNTS {
            assert!(
                waited.elapsed() < Duration::from_secs(10),
                "the engine counts nothing"
            );
            std::thread::yield_now();
        }
        clock.set(at(22, 15) + 30);
        let asked = shared.ask_flush(Duration::from_secs(10));
        flushed.store(true, Ordering::SeqCst);
        assert!(asked, "no flush");
        // Handed over by the time the flush is said done.
        assert!(
            lock(&platform.0)
                .iter()
                .flat_map(|b| segments_in(b))
                .any(|s| s.1 == at(22, 15) + 30),
            "the flush's records were not handed over yet"
        );
        let Ok((early, counted)) = engine.join() else {
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
        assert!(
            early >= COUNTS && counted >= early + COUNTS,
            "{early} of {counted}"
        );
        assert_eq!(
            (held(true), held(false)),
            (early, counted - early),
            "{seen:?}"
        );
        // The flush cut at 22:15:00.030, after the quarter hour's cut at 22:15.
        assert!(seen.iter().any(|s| s.1 == at(22, 15) + 30), "{seen:?}");
        let engine_thread = shared.engine_thread.get().copied();
        assert_eq!(
            lock(&probe.threads)
                .iter()
                .copied()
                .map(Some)
                .collect::<Vec<_>>(),
            vec![engine_thread],
            "the log's clock read off the engine's thread"
        );
        Ok(())
    }

    /// What a count cuts after a sleep reaches the log within the 30 seconds records gather, not at the
    /// logger's own timer, which the sleep left minutes behind.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn what_a_count_cuts_reaches_the_log_within_the_gathering_wait() {
        let platform = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 10));
        let mut shared = shared_with(platform.clone());
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let bytes = open(&shared, 1);
        bytes.down(&shared, 300, 340);
        let (_end, ending) = watch::channel(false);
        tokio::spawn(logger(Arc::clone(&shared), ending));
        // The new flow's records gather; then the timer is set for 22:15, five minutes on.
        tokio::time::sleep(LOG_DELAY + Duration::from_secs(1)).await;
        clock.set(at(30, 16));
        bytes.down(&shared, 0, 52);
        tokio::time::sleep(LOG_DELAY + Duration::from_secs(1)).await;
        for _ in 0..100 {
            if !lock(&platform.0).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let seen: Vec<_> = lock(&platform.0)
            .iter()
            .flat_map(|b| segments_in(b))
            .collect();
        assert_eq!(seen, vec![(at(22, 10), at(22, 15), 0)]);
    }

    /// An answer that opens an app's count of lookups anew, its lookup's count gone out with a flush,
    /// wakes the logger, which then sets its timer and cuts the count at the quarter hour.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn an_answer_that_opens_a_count_wakes_the_logger() {
        let platform = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 10));
        let mut shared = shared_with(platform.clone());
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        shared.lookup(Some(10_123), 70);
        shared.flush();
        let (_end, ending) = watch::channel(false);
        tokio::spawn(logger(Arc::clone(&shared), ending));
        tokio::time::sleep(LOG_DELAY + Duration::from_secs(1)).await;
        clock.set(at(22, 11));
        shared.lookup_answered(Some(10_123), 300);
        tokio::time::sleep(LOG_DELAY + Duration::from_secs(1)).await;
        clock.set(at(22, 15));
        tokio::time::sleep(Duration::from_mins(4)).await;
        for _ in 0..100 {
            if lock(&platform.0).len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let answered = Record::Lookups {
            uid: Some(10_123),
            start: at(22, 11),
            end: at(22, 15),
            count: 0,
            wire_up: 0,
            wire_down: 300,
            state: NOT_TOLD,
        };
        assert_eq!(lock(&platform.0).get(1), Some(&log::batch(&[answered])));
    }

    /// The engine's flush, asked from another thread while the engine runs, hands each open flow's
    /// segment on before it returns; asked once the engine has stopped, it returns at once. The engine
    /// reads the clock its platform hands it.
    #[test]
    fn the_engines_flush_hands_the_records_on_while_it_runs() -> std::io::Result<()> {
        /// The log's platform, with a clock of the test's.
        struct Clocked(Arc<Kept>, Arc<ManualClock>);
        impl Platform for Clocked {
            fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
                Some(10_123)
            }
            fn protect(&self, _: RawFd) -> bool {
                true
            }
            fn log(&self, batch: &[u8]) {
                self.0.log(batch);
            }
            fn clock(&self) -> Arc<dyn super::super::Clock> {
                self.1.clone()
            }
        }
        let kept = Arc::new(Kept::default());
        let clock = ManualClock::at(at(22, 10));
        let server = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        server.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (engine_end, app) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        let config = super::super::Config {
            mtu: 1_500,
            keep_flows: 0,
            addresses: super::super::Addresses::COMMON,
            limits: super::super::Limits::default(),
        };
        let mut engine = super::super::Engine::start(
            std::os::fd::OwnedFd::from(engine_end),
            config,
            Arc::new(Clocked(Arc::clone(&kept), clock.clone())),
            None,
        )?;
        let me = SocketAddr::from((super::super::Addresses::COMMON.tun4, 40_000));
        let Some(datagram) = crate::packet::udp(me, server.local_addr()?, b"evening") else {
            unreachable!("a small datagram")
        };
        app.send(&datagram)?;
        let mut buffer = [0u8; 64];
        server.recv_from(&mut buffer)?;
        clock.set(at(22, 12));
        engine.flush_log();
        let seen: Vec<_> = lock(&kept.0).iter().flat_map(|b| segments_in(b)).collect();
        assert_eq!(seen, vec![(at(22, 10), at(22, 12), 7)]);
        engine.stop();
        let asked = std::time::Instant::now();
        engine.flush_log();
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "waited for a stopped engine"
        );
        Ok(())
    }

    /// A flush asked when no logger is there to make it, as before the engine's tunnel is up, waits for
    /// nothing (the fresh review 2 of W5's first part, nit 7); nor does one asked once the logger ended.
    #[tokio::test(flavor = "current_thread")]
    async fn a_flush_asked_with_no_logger_waits_for_nothing() {
        let shared = Arc::new(shared());
        let asked = std::time::Instant::now();
        assert!(!shared.ask_flush(Duration::from_secs(10)));
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "waited for no logger"
        );
        let (end, ending) = watch::channel(false);
        let logging = tokio::spawn(logger(Arc::clone(&shared), ending));
        tokio::task::yield_now().await;
        assert!(lock(&shared.flushes).logging);
        let _ = end.send(true);
        let _ = logging.await;
        let asked = std::time::Instant::now();
        assert!(!shared.ask_flush(Duration::from_secs(10)));
        assert!(
            asked.elapsed() < Duration::from_secs(1),
            "waited for an ended logger"
        );
    }

    /// The log, as it is handed its batches, noting at each whether a flush asked is still waited for.
    struct Observed {
        flushed: Mutex<std::sync::mpsc::Receiver<()>>,
        seen: Mutex<Vec<Result<(), std::sync::mpsc::TryRecvError>>>,
    }

    impl Platform for Observed {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {
            let state = lock(&self.flushed).try_recv();
            lock(&self.seen).push(state);
        }
    }

    /// A flush asked while the engine stops is answered by its last records: its loop lets every one
    /// who waits go once it has handed them on, and not before (review 3 of W5's first part, finding 1):
    /// at the last batch, the flush is still waited for.
    #[tokio::test(flavor = "current_thread")]
    async fn a_flush_asked_as_the_engine_stops_is_let_go() -> std::io::Result<()> {
        let (done, flushed) = std::sync::mpsc::sync_channel(1);
        let platform = Arc::new(Observed {
            flushed: Mutex::new(flushed),
            seen: Mutex::default(),
        });
        let shared = Arc::new(shared_with(platform.clone()));
        open(&shared, 1).up(&shared, 10, 0);
        lock(&shared.flushes).waiting.push(done);
        let (engine_end, _app) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        let (stop, stopped) = watch::channel(false);
        let (_network, network) = watch::channel(0);
        let (_swaps, swaps) = tokio::sync::mpsc::unbounded_channel();
        let running = tokio::spawn(super::super::run(
            crate::tun::Tun::new(std::os::fd::OwnedFd::from(engine_end))?,
            1_500,
            Arc::clone(&shared),
            stopped,
            network,
            swaps,
        ));
        tokio::task::yield_now().await;
        let _ = stop.send(true);
        let _ = running.await;
        assert_eq!(
            *lock(&platform.seen),
            vec![Err(std::sync::mpsc::TryRecvError::Empty)],
            "the last batch came after the flush was let go"
        );
        assert_eq!(
            lock(&platform.flushed).try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
        Ok(())
    }
}
