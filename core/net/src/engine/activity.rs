//! Each second's bytes held until its app's state is told, and the log's segments cut where the state
//! changes (ADR 0046, decision 1).
//!
//! **Each second is held until its state is told.** Every count of a flow's bytes reads the wall clock
//! first (`logbook`, the cut before the count), and the first count in each second of the clock notes a
//! *mark*: the second, and the flow's counts before it. The marks are the flow's one-second slots: the
//! bytes of a second are the counts from its mark to the next. An app's slots are its flows' marks, so
//! an app with no traffic holds none, and a count within a second takes no lock: a division, an
//! addition, a few comparisons and one atomic load more than before, and the lock of the flow's own marks
//! once a second (ADR 0044's cost note). An app's lookups to Watch's own DNS address are marked the same way, under the
//! lock they already take.
//!
//! **States come from Watch's Kotlin side** ([`crate::states`]): a reading of Android's usage events, as
//! the states each app had over a span of the wall clock, in use and with its notification, the
//! background elsewhere. A second is *placed* once a reading covers all of it: in the state its app had
//! in it, "in use" winning over "with its notification" and both over "in the background" within the
//! second, so that a second is in the background only when the app was so throughout; or in none, with
//! the reason, where the reading knew nothing (no usage access, no events before the first unlock), in a
//! gap between readings, or for a flow with no app. A reading that begins before the end of the last one
//! replaces what it covers; seconds already placed stay as they were.
//!
//! **A segment is cut where its app's state changes,** at the start of the first second of the new
//! state, back in time for as long as its marks reach ([`settle_marks`]). A segment cut at a quarter hour
//! or at the flow's end before its seconds are placed is held as a [`Piece`] until they are, and written
//! then, each part with its state. A segment with no count takes the state of its last moment.
//!
//! **The window.** Each flow, and each app's lookups, holds at most [`WINDOW`] seconds with counts not
//! placed yet, and all of them together at most [`MARKS`]; past either, the oldest are placed in no state,
//! "told too late". The engine asks for a reading once a second has waited [`ASK_EVERY`] seconds, and at
//! most that often; Watch's Kotlin side reads at most every 5 seconds with the screen on and every minute
//! with it off (ADR 0046, decision 1), so while traffic runs a second waits about a minute at most, and
//! the window holds twice that. A second never ages out by time: across a sleep it waits for the reading
//! the next traffic or the screen brings, and the logger asks again while segments wait.
//!
//! **A wall clock set back** by a second or more places every second held at once, by what was told of it
//! or in no state ("not told"), so that the seconds of two clocks never wait for one reading
//! ([`Shared::clock_set_back`]).
//!
//! **Without Watch's Kotlin side telling states** ([`super::Platform::tells_states`], as in tests that do
//! not), no mark is noted and every segment is written at once in no state, "not told".

use super::now::{Counts, Seen};
use super::{Flow, Shared, lock};
use crate::log::Record;
use crate::states::{Interval, Known, Placed, Screen, State, Told, Unknown};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;

/// At most this many seconds with counts, not placed yet, each flow and each app's lookups hold.
pub(super) const WINDOW: usize = 120;

/// At most this many seconds not placed yet all flows and lookups hold together: 2.5 MB of marks.
pub(super) const MARKS: usize = 65_536;

/// At most this many cut segments wait for their state; past it, the oldest is written with the seconds
/// not told yet as told too late.
pub(super) const HELD: usize = 4_096;

/// The engine asks for a reading once a second has waited this many seconds for its state, and at most
/// this often.
pub(super) const ASK_EVERY: u64 = 5;

/// A flow's second when it has no mark yet, as after a cut, or once it has ended.
pub(super) const NO_SECOND: u64 = u64::MAX;

/// At most this many spans of the timeline, and intervals of one app in it, are kept.
const SPANS: usize = 256;
const INTERVALS: usize = 256;

/// The first count of a second in a flow, or in an app's lookups: the second of the wall clock, and the
/// counts before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mark {
    pub(super) second: u64,
    pub(super) counts: [u64; 4],
}

/// Which seconds are placed now in no state, whatever was told: those before `before` not placed yet,
/// as `why`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Force {
    pub(super) before: u64,
    pub(super) why: Unknown,
}

impl Force {
    /// Every second, as when the log is flushed or Watch stops.
    pub(super) const ALL: Self = Self {
        before: u64::MAX,
        why: Unknown::NotTold,
    };
}

/// What a segment held for its state is: a flow's, or an app's lookups'.
pub(super) enum Of {
    /// A flow, as it was when cut, and whether its destination stays out of the log.
    Flow { flow: Flow, hidden: bool },
    /// An app's lookups to Watch's own DNS address: its counts are the lookups, nought, and their bytes
    /// up and down on the tunnel.
    Lookups,
}

/// A segment cut before all its seconds were placed.
pub(super) struct Piece {
    pub(super) of: Of,
    pub(super) uid: Option<u32>,
    /// Where the part not written yet starts, its counts there, and the state of its seconds placed.
    pub(super) start: u64,
    pub(super) base: [u64; 4],
    pub(super) state: Option<Placed>,
    /// Where the segment ends, its counts there, and whether the flow goes on after it.
    pub(super) end: u64,
    pub(super) last: [u64; 4],
    pub(super) continues: bool,
    /// Its seconds not placed yet.
    pub(super) marks: VecDeque<Mark>,
}

impl Piece {
    /// The second whose state a segment with no count takes: its last moment's.
    fn instant(&self) -> u64 {
        if self.end > self.start {
            (self.end - 1) / 1000
        } else {
            self.start / 1000
        }
    }

    /// The record of its part from `start` to `end`.
    fn record(
        &self,
        (start, end): (u64, u64),
        bytes: [u64; 4],
        continues: bool,
        state: Placed,
    ) -> Record {
        match &self.of {
            Of::Flow { flow, .. } => Record::Segment {
                flow: flow.clone(),
                start,
                end,
                bytes,
                continues,
                state,
            },
            Of::Lookups => lookups_record(self.uid, (start, end), bytes, state),
        }
    }
}

/// An app's lookups from `start` to `end`, their counts `bytes`.
pub(super) fn lookups_record(
    uid: Option<u32>,
    (start, end): (u64, u64),
    bytes: [u64; 4],
    state: Placed,
) -> Record {
    Record::Lookups {
        uid,
        start,
        end: end.max(start),
        count: u32::try_from(bytes[0]).unwrap_or(u32::MAX),
        wire_up: bytes[2],
        wire_down: bytes[3],
        state,
    }
}

/// Settles the marks at the front of `marks` that `place` places, oldest first: each second's bytes go
/// to `each`, and the segment that starts at `start` with the counts `base` is cut where the state
/// changes, at the start of the first second of the new state, no later than `end`, each part before
/// going to `cut` as its start, end, bytes and state. `now` holds the counts after the last mark. Stops
/// at the first second not placed yet. How many marks it settled.
fn settle_marks(
    place: &impl Fn(u64) -> Option<Placed>,
    (start, base, state): (&mut u64, &mut [u64; 4], &mut Option<Placed>),
    marks: &mut VecDeque<Mark>,
    (now, end): ([u64; 4], u64),
    mut each: impl FnMut(u64, [u64; 4], Placed),
    mut cut: impl FnMut(u64, u64, [u64; 4], Placed),
) -> usize {
    let mut settled = 0;
    while let Some(&mark) = marks.front() {
        let Some(placed) = place(mark.second) else {
            break;
        };
        let next = marks.get(1).map_or(now, |m| m.counts);
        each(mark.second, delta(next, mark.counts), placed);
        match *state {
            None => *state = Some(placed),
            Some(was) if was == placed => {}
            Some(was) => {
                let at = mark
                    .second
                    .saturating_mul(1000)
                    .clamp(*start, end.max(*start));
                cut(*start, at, delta(mark.counts, *base), was);
                *start = at;
                *base = mark.counts;
                *state = Some(placed);
            }
        }
        marks.pop_front();
        settled += 1;
    }
    settled
}

/// Gives back the room of marks settled: a flow that once held the window's 120 does not keep 5 KB for
/// the rest of its life, so that what all flows hold stays near what [`MARKS`] counts.
fn give_back(marks: &mut VecDeque<Mark>) {
    if marks.capacity() > 16 && marks.len() < marks.capacity() / 4 {
        marks.shrink_to(marks.len().max(8));
    }
}

fn delta(now: [u64; 4], base: [u64; 4]) -> [u64; 4] {
    [0, 1, 2, 3].map(|i| now[i].saturating_sub(base[i]))
}

/// One reading's span, as told.
#[derive(Clone, Copy, Debug)]
struct Span {
    from: u64,
    until: u64,
    known: Known,
}

/// The states told, by the wall clock: spans in order, none overlapping, and in the known ones the
/// intervals each app was in use or with its notification.
#[derive(Default)]
struct Timeline {
    spans: VecDeque<Span>,
    intervals: HashMap<u32, Vec<Interval>>,
}

impl Timeline {
    /// The end of what was told, 0 for nothing.
    fn until(&self) -> u64 {
        self.spans.back().map_or(0, |span| span.until)
    }

    /// Takes a reading: it replaces what it covers of the ones before. At most [`SPANS`] spans and
    /// [`INTERVALS`] intervals of an app are kept, the oldest giving way.
    fn tell(&mut self, told: &Told) {
        while let Some(last) = self.spans.back_mut() {
            if last.from >= told.from {
                self.spans.pop_back();
            } else {
                last.until = last.until.min(told.from);
                break;
            }
        }
        for list in self.intervals.values_mut() {
            list.retain_mut(|interval| {
                interval.until = interval.until.min(told.from);
                interval.from < interval.until
            });
        }
        if told.until > told.from {
            self.spans.push_back(Span {
                from: told.from,
                until: told.until,
                known: told.known,
            });
        }
        for interval in &told.intervals {
            let list = self.intervals.entry(interval.uid).or_default();
            if list.len() == INTERVALS {
                list.remove(0);
            }
            list.push(*interval);
        }
        if let Some(first) = self
            .spans
            .len()
            .checked_sub(SPANS)
            .and_then(|gone| self.spans.get(gone))
        {
            self.forget_before(first.from);
        }
        self.intervals.retain(|_, list| !list.is_empty());
    }

    /// Forgets what was told before `before`, in milliseconds since 1970, but the last span, by which
    /// the current state is read.
    fn forget_before(&mut self, before: u64) {
        while self.spans.len() > 1 && self.spans.front().is_some_and(|s| s.until <= before) {
            self.spans.pop_front();
        }
        let first = self
            .spans
            .front()
            .map_or(before, |span| span.from.min(before));
        for list in self.intervals.values_mut() {
            list.retain(|interval| interval.until > first);
        }
        self.intervals.retain(|_, list| !list.is_empty());
    }

    /// Where the second `second` of the app `uid` falls, or `None` while not all of it is told.
    fn place(&self, uid: u32, second: u64) -> Option<Placed> {
        let from = second.saturating_mul(1000);
        let until = from.saturating_add(1000);
        if until > self.until() {
            return None;
        }
        let mut covered = from;
        let mut nothing = None;
        for span in &self.spans {
            if span.until <= from {
                continue;
            }
            if span.from >= until {
                break;
            }
            if span.from > covered {
                return Some(Placed::Unknown(Unknown::NotTold));
            }
            match span.known {
                Known::States => {}
                Known::NoAccess => nothing = nothing.or(Some(Unknown::NoAccess)),
                Known::Locked => nothing = nothing.or(Some(Unknown::Locked)),
            }
            covered = covered.max(span.until);
        }
        if covered < until {
            return Some(Placed::Unknown(Unknown::NotTold));
        }
        if let Some(why) = nothing {
            return Some(Placed::Unknown(why));
        }
        let state = self
            .intervals
            .get(&uid)
            .into_iter()
            .flatten()
            .filter(|interval| interval.from < until && interval.until > from)
            .map(|interval| interval.state)
            .max_by_key(|state| state.rank())
            .unwrap_or(State::Background);
        Some(Placed::Known(state))
    }
}

/// The states told, the segments that wait for theirs, and each app's counts by state for the live
/// view ([`super::now`]).
pub(super) struct Activity {
    /// Whether Watch's Kotlin side tells the states ([`super::Platform::tells_states`]); without it
    /// every second is placed at once in no state, "not told".
    tracked: bool,
    timeline: Timeline,
    pub(super) held: VecDeque<Piece>,
    pub(super) counts: Counts,
    /// The screen, and what the latest reading knew, as last told.
    screen: Screen,
    known: Option<Known>,
}

impl Activity {
    pub(super) fn new(tracked: bool) -> Self {
        Self {
            tracked,
            timeline: Timeline::default(),
            held: VecDeque::new(),
            counts: Counts::default(),
            screen: Screen::Unknown,
            known: None,
        }
    }

    /// The screen as last told.
    pub(super) fn screen(&self) -> Screen {
        self.screen
    }

    /// What the latest reading knew, if one came.
    pub(super) fn known(&self) -> Option<Known> {
        self.known
    }

    /// The end of what was told.
    pub(super) fn told_until(&self) -> u64 {
        self.timeline.until()
    }

    /// The state of the app `uid` in the last second told, `None` while it does not place it.
    pub(super) fn now(&self, uid: Option<u32>) -> Option<Placed> {
        let until = self.timeline.until();
        if uid.is_some() && self.tracked && until < 1000 {
            return None;
        }
        self.place(uid, (until / 1000).saturating_sub(1), None)
    }

    /// How many marks the segments held keep, for the count of all marks.
    pub(super) fn held_marks(&self) -> usize {
        self.held.iter().map(|piece| piece.marks.len()).sum()
    }

    /// Takes a reading: the screen first, so that the seconds it places count since the screen came on
    /// where they do, then the states.
    fn tell(&mut self, told: &Told) {
        if let Screen::On(Some(since)) = told.screen {
            self.counts.screen_on(since);
        }
        self.screen = told.screen;
        self.known = Some(told.known);
        self.timeline.tell(told);
    }

    /// Where the second `second` of the app `uid` falls now: placed by what was told, by `force`, or not
    /// yet.
    fn place(&self, uid: Option<u32>, second: u64, force: Option<Force>) -> Option<Placed> {
        let Some(uid) = uid else {
            return Some(Placed::Unknown(Unknown::NoApp));
        };
        if !self.tracked {
            return Some(Placed::Unknown(Unknown::NotTold));
        }
        self.timeline.place(uid, second).or_else(|| {
            force
                .filter(|f| second < f.before)
                .map(|f| Placed::Unknown(f.why))
        })
    }

    /// Settles a live flow's, or an app's lookups', marks: each second to its app's counts, and its
    /// segment cut where the state changes, the parts before to `cut`. How many marks it settled.
    pub(super) fn settle_open(
        &mut self,
        (uid, seen): (Option<u32>, Seen<'_>),
        open: (&mut u64, &mut [u64; 4], &mut Option<Placed>),
        (marks, now): (&mut VecDeque<Mark>, [u64; 4]),
        force: Option<Force>,
        cut: impl FnMut(u64, u64, [u64; 4], Placed),
    ) -> usize {
        let mut seconds = Vec::new();
        let settled = {
            let place = |second| self.place(uid, second, force);
            settle_marks(
                &place,
                open,
                marks,
                (now, u64::MAX),
                |second, bytes, placed| seconds.push((second, bytes, placed)),
                cut,
            )
        };
        for (second, bytes, placed) in seconds {
            self.counts.count(uid, second, bytes, placed, seen);
        }
        settled
    }

    /// Settles the segments held: each whose seconds are all placed is written, cut where its state
    /// changed. How many marks it settled.
    pub(super) fn settle_held(&mut self, force: Option<Force>, records: &mut Vec<Record>) -> usize {
        let mut held = std::mem::take(&mut self.held);
        let mut settled = 0;
        held.retain_mut(|piece| {
            let (done, marks) = self.settle_piece(piece, force, records);
            settled += marks;
            !done
        });
        self.held = held;
        settled
    }

    /// Settles one segment cut before its seconds were placed: whether it is written, and how many marks
    /// it settled.
    pub(super) fn settle_piece(
        &mut self,
        piece: &mut Piece,
        force: Option<Force>,
        records: &mut Vec<Record>,
    ) -> (bool, usize) {
        let uid = piece.uid;
        let mut parts = Vec::new();
        let mut seconds = Vec::new();
        let settled = {
            let place = |second| self.place(uid, second, force);
            let Piece {
                start,
                base,
                state,
                marks,
                last,
                end,
                ..
            } = piece;
            settle_marks(
                &place,
                (start, base, state),
                marks,
                (*last, *end),
                |second, bytes, placed| seconds.push((second, bytes, placed)),
                |from, to, bytes, placed| parts.push((from, to, bytes, placed)),
            )
        };
        let seen = Seen::of(&piece.of);
        for (second, bytes, placed) in seconds {
            self.counts.count(uid, second, bytes, placed, seen);
        }
        // The parts before a change of state, each written with the flow as it was cut.
        for (from, to, bytes, placed) in parts {
            records.push(piece.record((from, to), bytes, true, placed));
        }
        if !piece.marks.is_empty() {
            return (false, settled);
        }
        let state = piece
            .state
            .or_else(|| self.place(uid, piece.instant(), force));
        let Some(state) = state else {
            return (false, settled);
        };
        records.push(piece.record(
            (piece.start, piece.end.max(piece.start)),
            delta(piece.last, piece.base),
            piece.continues,
            state,
        ));
        (true, settled)
    }

    /// Forgets what was told before the oldest second still waiting, in the flows' marks
    /// (`oldest_mark`) or the segments held.
    fn forget_told_before(&mut self, oldest_mark: Option<u64>) {
        let held = self
            .held
            .iter()
            .map(|piece| piece.marks.front().map_or(piece.instant(), |m| m.second))
            .min();
        let oldest = [oldest_mark, held].into_iter().flatten().min();
        self.timeline
            .forget_before(oldest.map_or(u64::MAX, |second| second.saturating_mul(1000)));
    }
}

impl Shared {
    /// A flow, or an app's lookups, noted a new second, `second`, whose seconds held now number `held`,
    /// the oldest `oldest`: counted with all marks, placed as told too late past the window or the bound
    /// of all marks, and a reading asked for once the oldest has waited [`ASK_EVERY`] seconds.
    #[cold]
    pub(super) fn marked(&self, held: usize, oldest: u64, second: u64) {
        let all = self.marks.fetch_add(1, Ordering::Relaxed) + 1;
        if held > WINDOW {
            self.settle(Some(Force {
                before: second.saturating_sub(WINDOW as u64 - 1),
                why: Unknown::Late,
            }));
        } else if all > MARKS {
            self.settle(Some(Force {
                before: second,
                why: Unknown::Late,
            }));
        }
        if second >= oldest.saturating_add(ASK_EVERY) {
            self.ask(second);
        }
    }

    /// Asks Watch's Kotlin side for a reading of the states, at most every [`ASK_EVERY`] seconds of the
    /// wall clock, whose second now is `second`: it reads when its own rules allow (ADR 0046, decision
    /// 1). A clock set back asks at once.
    pub(super) fn ask(&self, second: u64) {
        if !self.tracks {
            return;
        }
        let asked = self.asked.load(Ordering::Relaxed);
        if asked == NO_SECOND || second >= asked.saturating_add(ASK_EVERY) || second < asked {
            self.asked.store(second, Ordering::Relaxed);
            self.platform.wants_states();
        }
    }

    /// Takes a reading of the states, and places every second it covers.
    pub(super) fn tell(&self, told: &Told) {
        lock(&self.activity).tell(told);
        self.settle(None);
    }

    /// The wall clock was set back by a second or more (`logbook`'s `log_now`, before the count that
    /// read it): every second held is placed at once, by what was told of it or as not told, and what was
    /// told is forgotten, since its spans, of the old clock, may cover the seconds the new clock reads next;
    /// those wait for the readings of the new clock.
    #[cold]
    pub(super) fn clock_set_back(&self) {
        self.settle(Some(Force::ALL));
        lock(&self.activity).timeline = Timeline::default();
    }

    /// Places every second held that what was told places, or `force`: in the live flows, the apps'
    /// lookups and the segments held. The log gets the parts written.
    pub(super) fn settle(&self, force: Option<Force>) {
        let mut records = Vec::new();
        let mut settled = 0;
        {
            let mut live = lock(&self.live);
            let mut lookups = lock(&self.lookups);
            let mut activity = lock(&self.activity);
            let mut oldest: Option<u64> = None;
            for live in live.values_mut() {
                let mut marks = lock(&live.bytes.marks);
                if !marks.is_empty() {
                    let now = live.bytes.now();
                    let flow = &live.flow;
                    settled += activity.settle_open(
                        (flow.uid, Seen::live(flow, live.hidden)),
                        (&mut live.start, &mut live.base, &mut live.state),
                        (&mut marks, now),
                        force,
                        |start, end, bytes, state| {
                            records.push(Record::Segment {
                                flow: flow.clone(),
                                start,
                                end,
                                bytes,
                                continues: true,
                                state,
                            });
                        },
                    );
                }
                give_back(&mut marks);
                if let Some(mark) = marks.front() {
                    oldest = Some(oldest.map_or(mark.second, |o| o.min(mark.second)));
                }
            }
            for (&uid, entry) in lookups.iter_mut() {
                let counts = entry.counts;
                let super::Lookups {
                    start,
                    base,
                    state,
                    marks,
                    ..
                } = entry;
                settled += activity.settle_open(
                    (uid, Seen::Lookups),
                    (start, base, state),
                    (marks, counts),
                    force,
                    |start, end, bytes, state| {
                        records.push(lookups_record(uid, (start, end), bytes, state));
                    },
                );
                give_back(&mut entry.marks);
                if let Some(mark) = entry.marks.front() {
                    oldest = Some(oldest.map_or(mark.second, |o| o.min(mark.second)));
                }
            }
            settled += activity.settle_held(force, &mut records);
            activity.forget_told_before(oldest);
        }
        self.marks.fetch_sub(settled, Ordering::Relaxed);
        if !records.is_empty() {
            lock(&self.pending_log).extend(records);
            self.log_ready.notify_one();
        }
    }

    /// Holds cut segments until their seconds are placed, writing at once those whose are. Past
    /// [`HELD`] segments held, the oldest is written with the seconds not told yet as told too late.
    pub(super) fn hold(&self, pieces: Vec<Piece>) {
        if pieces.is_empty() {
            return;
        }
        let mut records = Vec::new();
        let mut settled = 0;
        let mut waiting = false;
        {
            let mut activity = lock(&self.activity);
            for mut piece in pieces {
                let (done, marks) = activity.settle_piece(&mut piece, None, &mut records);
                settled += marks;
                if !done {
                    activity.held.push_back(piece);
                    waiting = true;
                }
            }
            let late = Some(Force {
                before: u64::MAX,
                why: Unknown::Late,
            });
            while activity.held.len() > HELD {
                if let Some(mut oldest) = activity.held.pop_front() {
                    settled += activity.settle_piece(&mut oldest, late, &mut records).1;
                }
            }
        }
        self.marks.fetch_sub(settled, Ordering::Relaxed);
        let written = !records.is_empty();
        if written {
            lock(&self.pending_log).extend(records);
        }
        // The logger hands the records on, and asks again for the states of what waits.
        if written || waiting {
            self.log_ready.notify_one();
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::clock::ManualClock;
    use super::super::tests::shared_with;
    use super::super::{DnsUse, Ech, NamedBy, Outcome, Platform, TCP};
    use super::*;
    use crate::states::Screen;
    use std::net::SocketAddr;
    use std::os::fd::RawFd;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// 2026-11-17, 22:10 UTC: within a quarter hour, so that no quarter-hour cut comes into these tests
    /// unless they move the clock past 22:15.
    pub(crate) const T: u64 = 1_794_873_600_000 + 22 * 3_600_000 + 10 * 60_000;
    pub(crate) const UID: u32 = 10_123;
    pub(crate) const IN_USE: Placed = Placed::Known(State::InUse);
    pub(crate) const NOTIFICATION: Placed = Placed::Known(State::Notification);
    pub(crate) const BACKGROUND: Placed = Placed::Known(State::Background);
    pub(crate) const NOT_TOLD: Placed = Placed::Unknown(Unknown::NotTold);

    /// A platform whose Kotlin side tells the states, noting how often the engine asked for them.
    #[derive(Default)]
    pub(crate) struct Telling {
        pub(crate) asked: AtomicUsize,
    }

    impl Platform for Telling {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {}

        fn tells_states(&self) -> bool {
            true
        }

        fn wants_states(&self) {
            self.asked.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An engine's shared state whose platform tells the states, its clock at `wall`, and both.
    pub(crate) fn telling_at(wall: u64) -> (Shared, Arc<ManualClock>, Arc<Telling>) {
        let platform = Arc::new(Telling::default());
        let clock = ManualClock::at(wall);
        let mut shared = shared_with(platform.clone());
        shared.clock = clock.clone();
        shared.last_reading.store(wall, Ordering::Relaxed);
        shared
            .quarter
            .store(wall / super::super::logbook::SEGMENT_MS, Ordering::Relaxed);
        (shared, clock, platform)
    }

    pub(crate) fn flow(id: u64, uid: Option<u32>) -> Flow {
        Flow {
            id,
            protocol: TCP,
            app: SocketAddr::from(([10, 1, 10, 1], 40_000)),
            destination: SocketAddr::from(([198, 51, 100, 9], 443)),
            uid,
            outcome: Outcome::Opened,
            name: Some("www.example.com".into()),
            named_by: NamedBy::Dns,
            dns_name: None,
            came_in: false,
            ech: Ech::Absent,
            dns: DnsUse::None,
            resolver: None,
            network: None,
        }
    }

    pub(crate) fn open(shared: &Shared, id: u64) -> Arc<super::super::logbook::FlowBytes> {
        let Some(bytes) = shared.record(flow(id, Some(UID))) else {
            unreachable!("an open flow is live")
        };
        bytes
    }

    /// A reading from `from` to `until` that knows the states, with these intervals of [`UID`].
    pub(crate) fn told(from: u64, until: u64, intervals: &[(u64, u64, State)]) -> Told {
        Told {
            from,
            until,
            known: Known::States,
            screen: Screen::On(Some(from)),
            intervals: intervals
                .iter()
                .map(|&(from, until, state)| Interval {
                    uid: UID,
                    from,
                    until,
                    state,
                })
                .collect(),
        }
    }

    pub(crate) fn taken(shared: &Shared) -> Vec<Record> {
        std::mem::take(&mut *lock(&shared.pending_log))
    }

    /// The segments written, as (flow, start, end, bytes up as the app sent them, continues, state).
    fn segments(records: &[Record]) -> Vec<(u64, u64, u64, u64, bool, Placed)> {
        records
            .iter()
            .filter_map(|r| match r {
                Record::Segment {
                    flow,
                    start,
                    end,
                    bytes,
                    continues,
                    state,
                } => Some((flow.id, *start, *end, bytes[0], *continues, *state)),
                Record::Lookups { .. } => None,
            })
            .collect()
    }

    /// `n` bytes up at `at` milliseconds after [`T`].
    pub(crate) fn up_at(
        shared: &Shared,
        clock: &ManualClock,
        bytes: &super::super::logbook::FlowBytes,
        at: u64,
        n: usize,
    ) {
        clock.set(T + at);
        bytes.up(shared, n, n + 40);
    }

    #[test]
    fn a_second_is_placed_once_a_reading_covers_all_of_it() {
        let mut timeline = Timeline::default();
        assert_eq!(timeline.place(UID, T / 1000), None, "nothing told");
        timeline.tell(&told(
            T,
            T + 10_500,
            &[(T + 2_000, T + 4_000, State::InUse)],
        ));
        assert_eq!(timeline.place(UID, T / 1000), Some(BACKGROUND));
        assert_eq!(timeline.place(UID, T / 1000 + 2), Some(IN_USE));
        assert_eq!(timeline.place(UID, T / 1000 + 3), Some(IN_USE));
        assert_eq!(timeline.place(UID, T / 1000 + 4), Some(BACKGROUND));
        assert_eq!(timeline.place(UID, T / 1000 + 9), Some(BACKGROUND));
        assert_eq!(
            timeline.place(UID, T / 1000 + 10),
            None,
            "told to its middle"
        );
        assert_eq!(timeline.place(UID + 1, T / 1000 + 2), Some(BACKGROUND));
        assert_eq!(
            timeline.place(UID, T / 1000 - 1),
            Some(NOT_TOLD),
            "before the first reading"
        );
    }

    /// Within one second, in use wins over with its notification, and both over the background: a
    /// second is in the background only when the app was so throughout it.
    #[test]
    fn in_use_wins_within_a_second_and_the_background_needs_all_of_it() {
        let mut timeline = Timeline::default();
        timeline.tell(&told(
            T,
            T + 10_000,
            &[
                (T + 1_999, T + 2_001, State::InUse),
                (T + 1_000, T + 6_000, State::Notification),
                (T + 7_500, T + 7_501, State::InUse),
            ],
        ));
        assert_eq!(timeline.place(UID, T / 1000), Some(BACKGROUND));
        assert_eq!(
            timeline.place(UID, T / 1000 + 1),
            Some(IN_USE),
            "1.999 is in use"
        );
        assert_eq!(
            timeline.place(UID, T / 1000 + 2),
            Some(IN_USE),
            "2.000 is in use"
        );
        assert_eq!(timeline.place(UID, T / 1000 + 3), Some(NOTIFICATION));
        assert_eq!(timeline.place(UID, T / 1000 + 5), Some(NOTIFICATION));
        assert_eq!(
            timeline.place(UID, T / 1000 + 6),
            Some(BACKGROUND),
            "the service stopped at 6.000"
        );
        assert_eq!(
            timeline.place(UID, T / 1000 + 7),
            Some(IN_USE),
            "one millisecond is enough"
        );
    }

    /// A reading that knew nothing places its seconds in no state, with why; a gap between readings, or
    /// a second that only partly falls in a reading that knew, too.
    #[test]
    fn what_no_reading_knew_is_placed_in_no_state_with_why() {
        let mut timeline = Timeline::default();
        let nothing = |from, until, known| Told {
            known,
            intervals: Vec::new(),
            ..told(from, until, &[])
        };
        timeline.tell(&nothing(T, T + 2_000, Known::NoAccess));
        timeline.tell(&nothing(T + 2_000, T + 4_000, Known::Locked));
        timeline.tell(&told(T + 5_000, T + 7_500, &[]));
        timeline.tell(&told(T + 7_500, T + 9_000, &[]));
        assert_eq!(
            timeline.place(UID, T / 1000),
            Some(Placed::Unknown(Unknown::NoAccess))
        );
        assert_eq!(
            timeline.place(UID, T / 1000 + 3),
            Some(Placed::Unknown(Unknown::Locked))
        );
        // A span that ends where a second begins says nothing of it.
        assert_eq!(
            timeline.place(UID, T / 1000 + 2),
            Some(Placed::Unknown(Unknown::Locked))
        );
        assert_eq!(timeline.place(UID, T / 1000 + 4), Some(NOT_TOLD), "a gap");
        assert_eq!(timeline.place(UID, T / 1000 + 5), Some(BACKGROUND));
        assert_eq!(
            timeline.place(UID, T / 1000 + 7),
            Some(BACKGROUND),
            "two readings that meet"
        );
        // No access for half of a second, known for the other half: no state.
        timeline.tell(&nothing(T + 9_000, T + 9_500, Known::NoAccess));
        timeline.tell(&told(T + 9_500, T + 11_000, &[]));
        assert_eq!(
            timeline.place(UID, T / 1000 + 9),
            Some(Placed::Unknown(Unknown::NoAccess))
        );
        assert_eq!(timeline.place(UID, T / 1000 + 10), Some(BACKGROUND));
    }

    /// A later reading replaces what it covers of the earlier ones: their spans and intervals.
    #[test]
    fn a_later_reading_replaces_what_it_covers() {
        let mut timeline = Timeline::default();
        timeline.tell(&told(
            T,
            T + 10_000,
            &[(T + 4_000, T + 9_000, State::InUse)],
        ));
        timeline.tell(&told(
            T + 6_000,
            T + 12_000,
            &[(T + 10_000, T + 11_000, State::Notification)],
        ));
        assert_eq!(timeline.spans.len(), 2);
        // A reading from where another began replaces it whole, leaving no empty span.
        timeline.tell(&told(
            T + 6_000,
            T + 12_000,
            &[(T + 10_000, T + 11_000, State::Notification)],
        ));
        assert_eq!(timeline.spans.len(), 2);
        assert_eq!(timeline.place(UID, T / 1000 + 5), Some(IN_USE));
        assert_eq!(
            timeline.place(UID, T / 1000 + 7),
            Some(BACKGROUND),
            "replaced"
        );
        assert_eq!(timeline.place(UID, T / 1000 + 10), Some(NOTIFICATION));
        // A reading that begins before every span replaces them all.
        timeline.tell(&told(T - 1_000, T + 1_000, &[]));
        assert_eq!(timeline.until(), T + 1_000);
        assert_eq!(timeline.place(UID, T / 1000 + 5), None);
        assert!(timeline.intervals.is_empty());
    }

    /// The timeline forgets what no second held needs, but keeps its last span; and it keeps at most
    /// [`SPANS`] spans and [`INTERVALS`] intervals of an app.
    #[test]
    fn the_timeline_forgets_what_is_not_needed_and_stays_bounded() {
        let mut timeline = Timeline::default();
        for i in 0..10 {
            let from = T + i * 1_000;
            timeline.tell(&told(
                from,
                from + 1_000,
                &[(from, from + 500, State::InUse)],
            ));
        }
        timeline.forget_before(T + 5_000);
        assert_eq!(timeline.spans.len(), 5);
        assert_eq!(timeline.place(UID, T / 1000 + 5), Some(IN_USE));
        assert_eq!(timeline.place(UID, T / 1000 + 4), Some(NOT_TOLD));
        assert_eq!(timeline.intervals[&UID].len(), 5);
        timeline.forget_before(u64::MAX);
        assert_eq!(timeline.spans.len(), 1, "the last span stays");
        assert_eq!(timeline.place(UID, T / 1000 + 9), Some(IN_USE));
        for i in 0..(SPANS as u64 + 10) {
            let from = T + 20_000 + i * 1_000;
            timeline.tell(&told(
                from,
                from + 1_000,
                &[(from, from + 500, State::InUse)],
            ));
        }
        assert_eq!(timeline.spans.len(), SPANS);
        assert!(timeline.intervals[&UID].len() <= INTERVALS);
        let many: Vec<_> = (0..INTERVALS as u64 + 5)
            .map(|i| {
                (
                    T + 1_000_000 + 2 * i,
                    T + 1_000_000 + 2 * i + 1,
                    State::InUse,
                )
            })
            .collect();
        timeline.tell(&told(T + 1_000_000, T + 1_100_000, &many));
        assert_eq!(timeline.intervals[&UID].len(), INTERVALS);
    }

    /// A flow's bytes counted in the background, then in use, then in the background again, told only
    /// afterwards: the segment is cut back in time at the first second of each new state, each part with
    /// its bytes to the byte (ADR 0046, decision 1: the bytes an app sends after the user leaves it count
    /// as background, even on a connection opened while it was on screen).
    #[test]
    fn a_segment_is_cut_back_in_time_where_its_apps_state_changed() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 100, 10);
        up_at(&shared, &clock, &bytes, 1_200, 20);
        up_at(&shared, &clock, &bytes, 1_900, 30);
        up_at(&shared, &clock, &bytes, 3_500, 40);
        up_at(&shared, &clock, &bytes, 9_000, 50);
        up_at(&shared, &clock, &bytes, 9_999, 60);
        up_at(&shared, &clock, &bytes, 12_000, 70);
        assert_eq!(taken(&shared), vec![], "nothing before its state is told");
        shared.tell(&told(
            T,
            T + 11_000,
            &[(T + 1_500, T + 4_000, State::InUse)],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T, T + 1_000, 10, true, BACKGROUND),
                (1, T + 1_000, T + 9_000, 20 + 30 + 40, true, IN_USE),
            ]
        );
        {
            let live = &lock(&shared.live)[&1];
            assert_eq!(
                (live.start, live.base[0], live.state),
                (T + 9_000, 100, Some(BACKGROUND))
            );
            assert_eq!(lock(&live.bytes.marks).len(), 1, "12 s waits");
        }
        assert_eq!(shared.marks.load(Ordering::Relaxed), 1);
    }

    /// A flow that ended before its seconds were told is held, and written once they are, cut where
    /// its state changed; its last part keeps its end.
    #[test]
    fn a_flow_ended_before_its_state_was_told_is_written_once_it_is() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 100, 10);
        up_at(&shared, &clock, &bytes, 2_100, 20);
        clock.set(T + 2_500);
        shared.finish(1);
        assert_eq!(taken(&shared), vec![]);
        assert_eq!(lock(&shared.activity).held.len(), 1);
        shared.tell(&told(T, T + 2_000, &[(T, T + 1_500, State::InUse)]));
        assert_eq!(taken(&shared), vec![], "the last second is not told yet");
        shared.tell(&told(T + 2_000, T + 3_000, &[]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T, T + 2_000, 10, true, IN_USE),
                (1, T + 2_000, T + 2_500, 20, false, BACKGROUND),
            ]
        );
        assert!(lock(&shared.activity).held.is_empty());
        assert_eq!(shared.marks.load(Ordering::Relaxed), 0);
        // A count after the flow ended, as of a packet the tunnel carries after the relay, notes nothing.
        up_at(&shared, &clock, &bytes, 4_000, 5);
        assert!(lock(&bytes.marks).is_empty());
        assert_eq!(shared.marks.load(Ordering::Relaxed), 0);
    }

    /// A segment cut at a quarter hour before its seconds were told waits for them; the flow's next
    /// segment begins with marks of its own.
    #[test]
    fn a_segment_cut_at_a_quarter_hour_waits_for_its_state() {
        let quarter = T + 5 * 60_000;
        let (shared, clock, _) = telling_at(quarter - 2_000);
        let bytes = open(&shared, 1);
        bytes.up(&shared, 10, 50);
        clock.set(quarter - 500);
        bytes.up(&shared, 20, 60);
        clock.set(quarter + 300);
        bytes.up(&shared, 30, 70);
        assert_eq!(taken(&shared), vec![]);
        shared.tell(&told(
            quarter - 2_000,
            quarter + 1_000,
            &[(quarter - 1_000, quarter + 1_000, State::Notification)],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, quarter - 2_000, quarter - 1_000, 10, true, BACKGROUND),
                (1, quarter - 1_000, quarter, 20, true, NOTIFICATION),
            ]
        );
        let live = &lock(&shared.live)[&1];
        assert_eq!((live.start, live.state), (quarter, Some(NOTIFICATION)));
    }

    /// A segment with no count, as a refused connection's, takes the state of its last moment.
    #[test]
    fn a_segment_with_no_count_takes_the_state_of_its_last_moment() {
        let (shared, clock, _) = telling_at(T + 1_500);
        let refused = |id| Flow {
            outcome: Outcome::Refused,
            ..flow(id, Some(UID))
        };
        assert!(shared.record(refused(1)).is_none());
        assert_eq!(taken(&shared), vec![]);
        open(&shared, 2);
        // On a second's boundary: an instant is in the second it begins, a span in the second its end
        // closes.
        clock.set(T + 2_000);
        assert!(shared.record(refused(3)).is_none());
        clock.set(T + 4_000);
        shared.finish(2);
        shared.tell(&told(
            T,
            T + 5_000,
            &[
                (T + 1_000, T + 2_000, State::InUse),
                (T + 4_000, T + 4_500, State::InUse),
            ],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T + 1_500, T + 1_500, 0, false, IN_USE),
                (3, T + 2_000, T + 2_000, 0, false, BACKGROUND),
                (2, T + 1_500, T + 4_000, 0, false, BACKGROUND),
            ]
        );
    }

    /// A flow of no app is placed at once, in no state.
    #[test]
    fn a_flow_of_no_app_is_placed_at_once_in_no_state() {
        let (shared, clock, _) = telling_at(T);
        let Some(bytes) = shared.record(flow(1, None)) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &bytes, 1_000, 10);
        clock.set(T + 2_000);
        shared.finish(1);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 2_000, 10, false, Placed::Unknown(Unknown::NoApp))]
        );
    }

    /// An app's lookups to Watch's own DNS address are marked and cut where its state changes too.
    #[test]
    fn an_apps_lookups_are_cut_where_its_state_changes() {
        let (shared, clock, _) = telling_at(T);
        shared.lookup(Some(UID), 70);
        clock.set(T + 2_000);
        shared.lookup(Some(UID), 72);
        shared.lookup_answered(Some(UID), 300);
        clock.set(T + 3_000);
        shared.lookup_answered(Some(UID), 310);
        shared.tell(&told(T, T + 4_000, &[(T, T + 1_000, State::InUse)]));
        assert_eq!(
            taken(&shared),
            vec![lookups_record(
                Some(UID),
                (T, T + 2_000),
                [1, 0, 70, 0],
                IN_USE
            )]
        );
        clock.set(T + 4_500);
        shared.flush();
        assert_eq!(
            taken(&shared),
            vec![lookups_record(
                Some(UID),
                (T + 2_000, T + 4_500),
                [1, 0, 72, 610],
                BACKGROUND
            )]
        );
    }

    /// A flow that counts in more seconds than the window holds before any reading places the oldest in
    /// no state, told too late; the others wait.
    #[test]
    fn seconds_past_the_window_are_placed_as_told_too_late() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        for second in 0..=WINDOW as u64 {
            up_at(&shared, &clock, &bytes, second * 1_000, 1);
        }
        {
            let live = &lock(&shared.live)[&1];
            assert_eq!(lock(&live.bytes.marks).len(), WINDOW);
            assert_eq!(live.state, Some(Placed::Unknown(Unknown::Late)));
        }
        assert_eq!(shared.marks.load(Ordering::Relaxed), WINDOW);
        // Exactly the window's 120 seconds held, spread over more of the clock, are all kept.
        let (wide, clock_wide, _) = telling_at(T);
        let other = open(&wide, 2);
        for second in (0..=WINDOW as u64).filter(|&s| s != 1) {
            up_at(&wide, &clock_wide, &other, second * 1_000, 1);
        }
        assert_eq!(lock(&other.marks).len(), WINDOW);
        assert_eq!(lock(&wide.live)[&2].state, None, "none told too late");
        // Told now, the rest are placed as told, and the segment cut where told too late ends.
        shared.tell(&told(T, T + 200_000, &[]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 1_000, 1, true, Placed::Unknown(Unknown::Late))]
        );
    }

    /// A count of no bytes notes no second: it cuts no segment where its app's state changed.
    #[test]
    fn a_count_of_nothing_notes_no_second() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 10);
        clock.set(T + 5_000);
        bytes.up(&shared, 0, 0);
        bytes.down(&shared, 0, 0);
        assert_eq!(lock(&bytes.marks).len(), 1);
        clock.set(T + 6_000);
        shared.finish(1);
        shared.tell(&told(T, T + 7_000, &[(T + 1_000, T + 2_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 6_000, 10, false, IN_USE)]
        );
    }

    /// A segment cut in the middle of a second, as by a flush, leaves the next to begin its own mark in
    /// that second.
    #[test]
    fn a_cut_in_a_second_lets_the_next_segment_mark_it() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 10);
        clock.set(T + 1_500);
        shared.flush();
        up_at(&shared, &clock, &bytes, 1_700, 20);
        let marks = lock(&bytes.marks);
        assert_eq!(
            marks
                .iter()
                .map(|m| (m.second, m.counts[0]))
                .collect::<Vec<_>>(),
            vec![(T / 1000 + 1, 10)]
        );
    }

    /// The logger asks again for the states while cut segments wait for theirs, and not while none do.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_logger_asks_again_while_segments_wait() {
        let (shared, clock, platform) = telling_at(T);
        let shared = Arc::new(shared);
        let asked = || platform.asked.load(Ordering::Relaxed);
        let (_end, ending) = tokio::sync::watch::channel(false);
        tokio::spawn(super::super::logbook::logger(Arc::clone(&shared), ending));
        tokio::task::yield_now().await;
        // Nothing waits: the logger, woken by a flow, asks nothing of its own.
        let bytes = open(&shared, 1);
        assert_eq!(asked(), 1, "the flow's opening asked");
        clock.set(T + 10_000);
        tokio::time::sleep(super::super::LOG_DELAY + std::time::Duration::from_secs(1)).await;
        assert_eq!(asked(), 1);
        // A segment waits: woken, the logger asks.
        bytes.up(&shared, 10, 0);
        shared.finish(1);
        clock.set(T + 20_000);
        tokio::time::sleep(super::super::LOG_DELAY + std::time::Duration::from_secs(1)).await;
        assert_eq!(asked(), 2);
    }

    /// A flow's marks give their room back once settled.
    #[test]
    fn settled_marks_give_their_room_back() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        for second in 0..100 {
            up_at(&shared, &clock, &bytes, second * 1_000, 1);
        }
        assert!(lock(&bytes.marks).capacity() >= 100);
        shared.tell(&told(T, T + 99_000, &[]));
        let marks = lock(&bytes.marks);
        assert_eq!(marks.len(), 1);
        assert!(marks.capacity() <= 16, "{}", marks.capacity());
    }

    /// All flows together hold at most [`MARKS`] seconds not placed: past it, every one held is placed
    /// as told too late but the newest.
    #[test]
    fn seconds_past_the_bound_of_all_flows_are_placed_as_told_too_late() {
        let (shared, clock, _) = telling_at(T);
        let flows = MARKS / 100 + 1;
        let all: Vec<_> = (1..=flows as u64).map(|id| open(&shared, id)).collect();
        for second in 0..100 {
            clock.set(T + second * 1_000);
            for bytes in &all {
                bytes.up(&shared, 1, 0);
            }
        }
        assert!(shared.marks.load(Ordering::Relaxed) <= MARKS);
        let late = lock(&shared.live)
            .values()
            .filter(|live| live.state == Some(Placed::Unknown(Unknown::Late)))
            .count();
        assert!(late > 0, "none placed as told too late");
    }

    /// Exactly [`MARKS`] seconds held, by all flows together, are all kept.
    #[test]
    fn exactly_the_bound_of_all_flows_is_kept() {
        let (shared, clock, _) = telling_at(T);
        let flows: Vec<_> = (1..=656).map(|id| open(&shared, id)).collect();
        for second in 0..100u64 {
            clock.set(T + second * 1_000);
            for (i, bytes) in flows.iter().enumerate() {
                if i < 655 || second < 36 {
                    bytes.up(&shared, 1, 0);
                }
            }
        }
        assert_eq!(shared.marks.load(Ordering::Relaxed), MARKS);
        let late = lock(&shared.live)
            .values()
            .any(|live| live.state == Some(Placed::Unknown(Unknown::Late)));
        assert!(!late, "placed as told too late within the bound");
    }

    /// Past [`HELD`] segments waiting, the oldest is written, its seconds not told as told too late.
    #[test]
    fn segments_held_past_the_bound_are_written_as_told_too_late() {
        let (shared, clock, _) = telling_at(T);
        for id in 1..=HELD as u64 + 1 {
            let bytes = open(&shared, id);
            bytes.up(&shared, 1, 0);
            shared.finish(id);
        }
        clock.set(T + 1);
        assert_eq!(lock(&shared.activity).held.len(), HELD);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T, 1, false, Placed::Unknown(Unknown::Late))]
        );
        assert_eq!(shared.marks.load(Ordering::Relaxed), HELD);
    }

    /// A wall clock set back by a second or more places every second held at once, by what was told of
    /// it or as not told; less than a second moves nothing.
    #[test]
    fn a_clock_set_back_places_every_second_held_at_once() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 10);
        up_at(&shared, &clock, &bytes, 3_000, 19);
        shared.tell(&told(T, T + 2_000, &[(T, T + 2_000, State::InUse)]));
        assert_eq!(taken(&shared), vec![]);
        // Back by less than a second: nothing.
        up_at(&shared, &clock, &bytes, 3_500, 1);
        up_at(&shared, &clock, &bytes, 2_501, 0);
        assert_eq!(taken(&shared), vec![]);
        up_at(&shared, &clock, &bytes, 3_500, 0);
        up_at(&shared, &clock, &bytes, 2_600, 29);
        assert_eq!(taken(&shared), vec![]);
        // Back by exactly a second.
        up_at(&shared, &clock, &bytes, 1_600, 40);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 3_000, 10, true, IN_USE)]
        );
        {
            let live = &lock(&shared.live)[&1];
            assert_eq!(live.state, Some(NOT_TOLD));
            assert_eq!(lock(&live.bytes.marks).len(), 1, "the count after it waits");
        }
        // The reading of the old clock is forgotten: the count at 1.5 s, which it covered, is not placed by
        // it, in use, but waits for the new clock's, and one that begins after it leaves it not told.
        shared.tell(&told(T + 1_800, T + 2_500, &[]));
        assert_eq!(taken(&shared), vec![]);
        let live = &lock(&shared.live)[&1];
        assert_eq!(live.state, Some(NOT_TOLD));
        assert!(lock(&live.bytes.marks).is_empty());
    }

    /// The engine asks for the states when a flow opens and once a second has waited five seconds, at
    /// most every five seconds; and the logger asks again while segments wait.
    #[test]
    fn the_engine_asks_for_states_when_a_flow_opens_and_when_seconds_wait() {
        let (shared, clock, platform) = telling_at(T);
        let asked = || platform.asked.load(Ordering::Relaxed);
        let bytes = open(&shared, 1);
        assert_eq!(asked(), 1, "a flow opened");
        open(&shared, 2);
        assert_eq!(asked(), 1, "not again within five seconds");
        for second in 1..=4 {
            up_at(&shared, &clock, &bytes, second * 1_000, 1);
        }
        assert_eq!(asked(), 1);
        up_at(&shared, &clock, &bytes, 5_000, 1);
        assert_eq!(asked(), 1, "the oldest mark, at 1 s, waited four seconds");
        up_at(&shared, &clock, &bytes, 6_000, 1);
        assert_eq!(asked(), 2, "it waited five");
        up_at(&shared, &clock, &bytes, 7_000, 1);
        assert_eq!(asked(), 2, "not again within five seconds");
        up_at(&shared, &clock, &bytes, 11_000, 1);
        assert_eq!(asked(), 3);
        // A clock set back asks at once.
        shared.ask(T / 1000 + 5);
        assert_eq!(asked(), 4);
        // Without states told, the engine never asks.
        let counting = Arc::new(Untelling::default());
        let untold = shared_with(counting.clone());
        untold.ask(T / 1000);
        assert!(untold.record(flow(1, Some(UID))).is_some());
        assert_eq!(counting.asked.load(Ordering::Relaxed), 0);
    }

    /// A platform whose Kotlin side tells no states, noting whether the engine asked all the same.
    #[derive(Default)]
    struct Untelling {
        asked: AtomicUsize,
    }

    impl Platform for Untelling {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {}

        fn wants_states(&self) {
            self.asked.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Flushed, every second not told is written in no state, "not told", and nothing waits.
    #[test]
    fn a_flush_writes_every_second_not_told_as_not_told() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 500, 10);
        up_at(&shared, &clock, &bytes, 1_500, 20);
        shared.tell(&told(T, T + 1_000, &[]));
        assert_eq!(taken(&shared), vec![]);
        clock.set(T + 2_000);
        shared.flush();
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T, T + 1_000, 10, true, BACKGROUND),
                (1, T + 1_000, T + 2_000, 20, true, NOT_TOLD),
            ]
        );
        assert!(lock(&shared.activity).held.is_empty());
        assert_eq!(shared.marks.load(Ordering::Relaxed), 0);
    }

    /// Settling a segment's marks: each second's bytes, to the byte, with its state; parts cut at the
    /// start of each change; a second not placed stops it; and a cut never goes past the segment's end
    /// or before its start.
    #[test]
    fn settling_marks_cuts_at_each_change_and_stops_at_the_first_not_placed() {
        let marks = |seconds: &[(u64, u64)]| -> VecDeque<Mark> {
            seconds
                .iter()
                .map(|&(second, up)| Mark {
                    second,
                    counts: [up, 0, 0, 0],
                })
                .collect()
        };
        let states = [IN_USE, IN_USE, BACKGROUND, NOTIFICATION];
        let place = |second: u64| states.get(usize::try_from(second - 10).ok()?).copied();
        let mut held = marks(&[(10, 0), (11, 5), (12, 9), (13, 20), (14, 33)]);
        let (mut start, mut base, mut state) = (10_200, [0; 4], None);
        let (mut each, mut parts) = (Vec::new(), Vec::new());
        let settled = settle_marks(
            &place,
            (&mut start, &mut base, &mut state),
            &mut held,
            ([40, 0, 0, 0], 13_500),
            |second, bytes, placed| each.push((second, bytes[0], placed)),
            |from, to, bytes, placed| parts.push((from, to, bytes[0], placed)),
        );
        assert_eq!(settled, 4);
        assert_eq!(
            each,
            vec![
                (10, 5, IN_USE),
                (11, 4, IN_USE),
                (12, 11, BACKGROUND),
                (13, 13, NOTIFICATION)
            ]
        );
        assert_eq!(
            parts,
            vec![
                (10_200, 12_000, 9, IN_USE),
                (12_000, 13_000, 11, BACKGROUND)
            ]
        );
        assert_eq!((start, base[0], state), (13_000, 20, Some(NOTIFICATION)));
        assert_eq!(held, marks(&[(14, 33)]));
        // A change in the segment's first second, or past its end, cuts within it.
        let mut held = marks(&[(10, 0), (11, 5)]);
        let (mut start, mut base, mut state) = (11_400, [0; 4], Some(BACKGROUND));
        let mut parts = Vec::new();
        settle_marks(
            &place,
            (&mut start, &mut base, &mut state),
            &mut held,
            ([9, 0, 0, 0], 11_300),
            |_, _, _| {},
            |from, to, bytes, placed| parts.push((from, to, bytes[0], placed)),
        );
        assert_eq!(parts, vec![(11_400, 11_400, 0, BACKGROUND)]);
    }

    /// What a count costs, with states told and without, on the phone's own clock, and what a mark
    /// costs, the first count of a second: printed, for ADR 0044's cost note. Run it in a release
    /// build: `cargo test -p datapavan-net --release --lib -- --ignored --nocapture what_a_count_costs`.
    #[test]
    #[ignore = "a measurement, not a check: run it in a release build"]
    fn what_a_count_costs() {
        use std::time::Instant;
        const COUNTS: u32 = 20_000_000;
        let measure = |shared: &Shared| {
            let Some(bytes) = shared.record(flow(1, Some(UID))) else {
                unreachable!("an open flow is live")
            };
            let started = Instant::now();
            for _ in 0..COUNTS {
                bytes.up(shared, std::hint::black_box(100), 140);
            }
            started.elapsed().as_secs_f64() * 1e9 / f64::from(COUNTS)
        };
        let untold = super::super::tests::shared();
        let telling = shared_with(Arc::new(Telling::default()));
        let (before, after) = (measure(&untold), measure(&telling));
        println!("a count: {before:.1} ns without states told, {after:.1} ns with them");
        // A mark: the clock moves a second before each count, on 1,000 flows, told every 60 seconds.
        let (shared, clock, _) = telling_at(T);
        let flows: Vec<_> = (1..=1_000).map(|id| open(&shared, id)).collect();
        let started = Instant::now();
        let mut marks = 0u32;
        for second in 1..=120u64 {
            clock.set(T + second * 1_000);
            for bytes in &flows {
                bytes.up(&shared, 100, 140);
                marks += 1;
            }
            if second % 60 == 0 {
                shared.tell(&told(T, T + second * 1_000, &[]));
            }
        }
        let each = started.elapsed().as_secs_f64() * 1e9 / f64::from(marks);
        println!("a count that notes a mark, with a reading told every minute: {each:.1} ns");
    }

    /// A platform that tells states, with a clock of the test's, keeping the log's batches.
    struct Engined {
        clock: Arc<ManualClock>,
        batches: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl Platform for Engined {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            Some(UID)
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, batch: &[u8]) {
            lock(&self.batches).push(batch.to_vec());
        }

        fn clock(&self) -> Arc<dyn super::super::Clock> {
            self.clock.clone()
        }

        fn tells_states(&self) -> bool {
            true
        }
    }

    /// The states each segment in the log's batches was written with, in order.
    fn states_logged(platform: &Engined) -> Vec<Placed> {
        lock(&platform.batches)
            .iter()
            .flat_map(|batch| crate::log::states_in(batch))
            .collect()
    }

    /// An engine whose datagram reaches a local server, then stops. Handed over, the segment that waits
    /// for its state goes to the next engine, which writes it once told; stopped, it is written as not
    /// told.
    #[test]
    fn a_segment_waiting_for_its_state_goes_to_the_next_engine_or_is_written_as_not_told()
    -> std::io::Result<()> {
        use super::super::{Addresses, Config, Engine, Limits};
        let start = |platform: Arc<Engined>,
                     handover|
         -> std::io::Result<(Engine, std::os::unix::net::UnixDatagram)> {
            let (engine_end, app) = std::os::unix::net::UnixDatagram::pair()?;
            engine_end.set_nonblocking(true)?;
            let config = Config {
                mtu: 1_500,
                keep_flows: 0,
                addresses: Addresses::COMMON,
                limits: Limits::default(),
            };
            let engine = Engine::start_with(
                std::os::fd::OwnedFd::from(engine_end),
                config,
                platform,
                None,
                (handover, None),
            )?;
            Ok((engine, app))
        };
        let send = |app: &std::os::unix::net::UnixDatagram| -> std::io::Result<()> {
            let server = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            server.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
            let Some(datagram) = crate::packet::udp(me, server.local_addr()?, b"evening") else {
                unreachable!("a small datagram")
            };
            app.send(&datagram)?;
            server.recv_from(&mut [0u8; 64])?;
            Ok(())
        };
        let clock = ManualClock::at(T);
        let first = Arc::new(Engined {
            clock: clock.clone(),
            batches: std::sync::Mutex::default(),
        });
        let (engine, app) = start(first.clone(), None)?;
        send(&app)?;
        clock.set(T + 3_000);
        let handover = engine.hand_over();
        assert_eq!(states_logged(&first), vec![], "nothing written before told");
        let second = Arc::new(Engined {
            clock: clock.clone(),
            batches: std::sync::Mutex::default(),
        });
        let (mut engine, _app) = start(second.clone(), Some(handover))?;
        assert!(!engine.states(b"not a reading"));
        assert!(engine.states(&crate::states::write(&told(T, T + 4_000, &[]))));
        engine.flush_log();
        engine.stop();
        assert_eq!(states_logged(&second), vec![BACKGROUND]);

        // Stopped with nothing told, the segment is written as not told.
        let third = Arc::new(Engined {
            clock: clock.clone(),
            batches: std::sync::Mutex::default(),
        });
        let (mut engine, app) = start(third.clone(), None)?;
        send(&app)?;
        engine.stop();
        assert_eq!(states_logged(&third), vec![NOT_TOLD]);
        Ok(())
    }

    /// Without Watch's Kotlin side telling states, no mark is noted and every segment is written at
    /// once, not told.
    #[test]
    fn without_states_told_every_segment_is_written_at_once_as_not_told() {
        let shared = super::super::tests::shared();
        let Some(bytes) = shared.record(flow(1, Some(UID))) else {
            unreachable!("an open flow is live")
        };
        bytes.up(&shared, 10, 50);
        assert!(lock(&bytes.marks).is_empty());
        shared.finish(1);
        let records = taken(&shared);
        assert_eq!(records.len(), 1);
        assert!(matches!(
            records[0],
            Record::Segment {
                state: NOT_TOLD,
                ..
            }
        ));
    }
}
