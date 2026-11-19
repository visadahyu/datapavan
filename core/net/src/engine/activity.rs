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
//! **A segment is cut where its app's state changes,** back in time for as long as its marks reach
//! ([`settle_marks`]): where the timeline's state changed, so that quiet seconds after a change, up to
//! [`WINDOW`] of them, belong to the new part; never before a second already placed. A segment cut at a
//! quarter hour or at the flow's end before its seconds are placed is held as a [`Piece`] until they are,
//! and written then, each part with its state, before the live flows' parts of the same reading so that a
//! flow's records reach the log in time order. A segment with no count takes the state of its last moment,
//! and one that went quiet after its app's state changed ends with a part of no bytes in its end's state.
//!
//! **The window.** Each flow, and each app's lookups, holds at most [`WINDOW`] seconds with counts not
//! placed yet, and all of them together at most [`MARKS`], each app a quarter of it; past either, the
//! oldest are placed in no state, "told too late", of the app past its share or holding the most. The
//! engine asks for a reading at each new second counted, at most every [`ASK_EVERY`] seconds; Watch's
//! Kotlin side reads at most every 5 seconds with the screen on and every minute with it off (ADR 0046,
//! decision 1), making an ask in its turn, so a second waits about a minute at most, and the window holds
//! twice that. A second never ages out by time: in deep sleep it waits for the phone to wake.
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

/// At most this many of them are one app's (a quarter, as ADR 0044's decision 3 shares the engine's
/// other caps): an app past its share has its own oldest told too late, never another app's.
pub(super) const MARKS_SHARE: usize = MARKS / 4;

/// How far below a bound an app that passed it is brought back, by its oldest seconds: so that a busy
/// app gives way a little at a time, not a second at a time (review b2 of W5's second part, N1).
const GIVE_WAY: usize = MARKS_SHARE / 64;

/// At most this many cut segments wait for their state; past it, the oldest of the app that holds the
/// most is written with its seconds not told yet as told too late.
pub(super) const HELD: usize = 4_096;

/// At most this many of them are one app's; past it, the app's own oldest is written so.
pub(super) const HELD_SHARE: usize = HELD / 4;

/// A count by app, `None` for flows Android named no app for.
pub(super) type ByApp = HashMap<Option<u32>, usize>;

/// What all flows and lookups, and each app's, hold of seconds not placed yet ([`MARKS`],
/// [`MARKS_SHARE`]).
#[derive(Default)]
pub(super) struct Waiting {
    total: usize,
    by_app: ByApp,
}

impl Waiting {
    /// What the segments handed over from the engine before hold.
    pub(super) fn of_held(held: &VecDeque<Piece>) -> Self {
        let mut waiting = Self::default();
        for piece in held {
            *waiting.by_app.entry(piece.uid).or_default() += piece.marks.len();
            waiting.total += piece.marks.len();
        }
        waiting
    }

    /// One more of `uid`'s: what all hold now, and what the app holds.
    fn add(&mut self, uid: Option<u32>) -> (usize, usize) {
        self.total += 1;
        let mine = self.by_app.entry(uid).or_default();
        *mine += 1;
        (self.total, *mine)
    }

    /// Those placed, by app.
    fn sub(&mut self, settled: &ByApp) {
        for (uid, n) in settled {
            self.total = self.total.saturating_sub(*n);
            if let Some(mine) = self.by_app.get_mut(uid) {
                *mine = mine.saturating_sub(*n);
                if *mine == 0 {
                    self.by_app.remove(uid);
                }
            }
        }
    }

    /// The app that holds the most, and how many.
    fn heaviest(&self) -> Option<(Option<u32>, usize)> {
        self.by_app
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(uid, n)| (*uid, *n))
    }

    /// All of them.
    pub(super) fn total(&self) -> usize {
        self.total
    }
}

/// The engine asks for a reading at most this often, in seconds of the wall clock.
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
/// as `why`, of every app, or of the one app `of` names.
#[derive(Clone, Copy, Debug)]
pub(super) struct Force {
    pub(super) before: u64,
    pub(super) why: Unknown,
    pub(super) of: Whose,
}

/// Whose seconds a [`Force`] places: every app's, or one app's (`None` for flows of no app).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Whose {
    Every,
    App(Option<u32>),
}

impl Force {
    /// Every second, as when the log is flushed or Watch stops.
    pub(super) const ALL: Self = Self {
        before: u64::MAX,
        why: Unknown::NotTold,
        of: Whose::Every,
    };

    /// The seconds of the app `uid` before `before`, told too late.
    fn late(uid: Option<u32>, before: u64) -> Self {
        Self {
            before,
            why: Unknown::Late,
            of: Whose::App(uid),
        }
    }
}

/// What a segment held for its state is: a flow's, or an app's lookups'.
pub(super) enum Of {
    /// A flow, as it was when cut, whether its destination stays out of the log, and whether it went
    /// directly, not through the user's tool.
    Flow {
        flow: Flow,
        hidden: bool,
        direct: bool,
    },
    /// An app's lookups to Watch's own DNS address: its counts are the lookups, nought, and their bytes
    /// up and down on the tunnel.
    Lookups,
}

/// A segment cut before all its seconds were placed.
pub(super) struct Piece {
    pub(super) of: Of,
    pub(super) uid: Option<u32>,
    /// Where the part not written yet starts, its counts there, the state of its seconds placed, and the
    /// second after the last of them.
    pub(super) start: u64,
    pub(super) base: [u64; 4],
    pub(super) state: Option<Placed>,
    pub(super) after: u64,
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
/// changes, no later than `end`, each part before going to `cut` as its start, end, bytes and state.
/// The cut is where the timeline's state changed, not at the first second with bytes in the new state:
/// quiet seconds of the new state before it belong to the new part, up to [`WINDOW`] of them (review b1
/// of W5's second part, engine, nit 2). `now` holds the counts after the last mark. Stops at the first
/// second not placed yet. How many marks it settled.
fn settle_marks(
    place: &impl Fn(u64) -> Option<Placed>,
    (start, base, state, after): (&mut u64, &mut [u64; 4], &mut Option<Placed>, &mut u64),
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
                let at = change(place, mark.second, placed, (*start, *after))
                    .saturating_mul(1000)
                    .clamp(*start, end.max(*start));
                cut(*start, at, delta(mark.counts, *base), was);
                *start = at;
                *base = mark.counts;
                *state = Some(placed);
            }
        }
        *after = mark.second.saturating_add(1);
        marks.pop_front();
        settled += 1;
    }
    settled
}

/// The second the run of `placed` that holds `second` began: walking back over the seconds of the same
/// state, no further than [`WINDOW`] seconds, not before the first whole second from `start`, and not
/// before `after`, the second after the last placed in the segment (which a later reading may tell
/// otherwise than it was placed).
fn change(
    place: &impl Fn(u64) -> Option<Placed>,
    second: u64,
    placed: Placed,
    (start, after): (u64, u64),
) -> u64 {
    let first = start
        .div_ceil(1000)
        .max(after)
        .max(second.saturating_sub(WINDOW as u64));
    let mut at = second;
    while at > first && place(at - 1) == Some(placed) {
        at -= 1;
    }
    at
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
            // The one that ended first gives way: a reading lists an app's intervals by state, not by time,
            // so the first inserted may be the newest (review b3 of W5's second part, fresh, n3).
            if list.len() == INTERVALS
                && let Some(oldest) = (0..list.len()).min_by_key(|&k| list[k].until)
            {
                list.remove(oldest);
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
        let first = self.spans.partition_point(|span| span.until <= from);
        for span in self.spans.range(first..) {
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
    /// How many of the segments held are each app's ([`HELD_SHARE`]).
    held_by: ByApp,
    pub(super) counts: Counts,
    /// The screen, and what the latest reading knew, as last told.
    screen: Screen,
    known: Option<Known>,
    /// Seconds, and segments with no count, placed as told too late since the engine last took the
    /// count for its counters.
    late: u64,
}

impl Activity {
    pub(super) fn new(tracked: bool) -> Self {
        Self {
            tracked,
            timeline: Timeline::default(),
            held: VecDeque::new(),
            held_by: ByApp::new(),
            counts: Counts::default(),
            screen: Screen::Unknown,
            known: None,
            late: 0,
        }
    }

    /// The seconds and segments placed as told too late since the last call.
    fn take_late(&mut self) -> u64 {
        std::mem::take(&mut self.late)
    }

    /// Holds a segment for its state.
    fn push_held(&mut self, piece: Piece) {
        *self.held_by.entry(piece.uid).or_default() += 1;
        self.held.push_back(piece);
    }

    /// One segment held less of `uid`'s.
    fn unheld(&mut self, uid: Option<u32>) {
        if let Some(n) = self.held_by.get_mut(&uid) {
            *n -= 1;
            if *n == 0 {
                self.held_by.remove(&uid);
            }
        }
    }

    /// Writes the oldest segment `uid` holds, its seconds not told yet as told too late.
    fn evict(&mut self, uid: Option<u32>, records: &mut Vec<Record>, settled: &mut ByApp) {
        let Some(at) = self.held.iter().position(|piece| piece.uid == uid) else {
            return;
        };
        let Some(mut piece) = self.held.remove(at) else {
            return;
        };
        self.unheld(uid);
        let (_, marks) = self.settle_piece(&mut piece, Some(Force::late(uid, u64::MAX)), records);
        *settled.entry(uid).or_default() += marks;
    }

    /// The app that holds the most segments, and how many.
    fn heaviest_held(&self) -> Option<(Option<u32>, usize)> {
        self.held_by
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(uid, n)| (*uid, *n))
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

    /// Takes a reading: the screen first, so that the seconds it places count since the screen came on,
    /// and while it was off, where they do, then the states. When it went off comes before when it came
    /// on, which, for a screen on, is never earlier.
    fn tell(&mut self, told: &Told) {
        if let Some(off) = told.screen_off {
            self.counts.screen_off(off);
        }
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
                .filter(|f| {
                    second < f.before && (f.of == Whose::Every || f.of == Whose::App(Some(uid)))
                })
                .map(|f| Placed::Unknown(f.why))
        })
    }

    /// Settles a live flow's, or an app's lookups', marks: each second to its app's counts, and its
    /// segment cut where the state changes, the parts before to `cut`. A flow of no app is placed with no
    /// reading, so its seconds from `running` on, which may still be counted in, wait (review b1 of W5's
    /// second part, engine, finding 3: it lost the bytes counted after a placing in the same second); a
    /// second a reading told is over by the clock of the reading, two seconds before it ended. How many
    /// marks it settled.
    pub(super) fn settle_open(
        &mut self,
        (uid, seen): (Option<u32>, Seen<'_>),
        open: (&mut u64, &mut [u64; 4], &mut Option<Placed>, &mut u64),
        (marks, now, running): (&mut VecDeque<Mark>, [u64; 4], u64),
        force: Option<Force>,
        cut: impl FnMut(u64, u64, [u64; 4], Placed),
    ) -> usize {
        let mut seconds = Vec::new();
        let settled = {
            let place = |second| {
                if uid.is_none() && second >= running {
                    return None;
                }
                self.place(uid, second, force)
            };
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
            if placed == Placed::Unknown(Unknown::Late) {
                self.late += 1;
            }
            self.counts.count(uid, second, bytes, placed, seen);
        }
        settled
    }

    /// Settles the segments held: each whose seconds are all placed is written, cut where its state
    /// changed. The marks it settled go to `settled`, by app.
    pub(super) fn settle_held(
        &mut self,
        force: Option<Force>,
        records: &mut Vec<Record>,
        settled: &mut ByApp,
    ) {
        let mut held = std::mem::take(&mut self.held);
        held.retain_mut(|piece| {
            let (done, marks) = self.settle_piece(piece, force, records);
            *settled.entry(piece.uid).or_default() += marks;
            if done {
                self.unheld(piece.uid);
            }
            !done
        });
        self.held = held;
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
                after,
                marks,
                last,
                end,
                ..
            } = piece;
            settle_marks(
                &place,
                (start, base, state, after),
                marks,
                (*last, *end),
                |second, bytes, placed| seconds.push((second, bytes, placed)),
                |from, to, bytes, placed| parts.push((from, to, bytes, placed)),
            )
        };
        // A segment held gives back its marks' room as a live flow does (review b1, engine, nit 5).
        give_back(&mut piece.marks);
        let seen = Seen::of(&piece.of);
        for (second, bytes, placed) in seconds {
            if placed == Placed::Unknown(Unknown::Late) {
                self.late += 1;
            }
            self.counts.count(uid, second, bytes, placed, seen);
        }
        // The parts before a change of state, each written with the flow as it was cut.
        for (from, to, bytes, placed) in parts {
            records.push(piece.record((from, to), bytes, true, placed));
        }
        if !piece.marks.is_empty() {
            return (false, settled);
        }
        // The state of its last moment: the whole segment's when it has no bytes, and the end's part's
        // when the app's state changed after its last bytes (review b2 of W5's second part, fresh, m4:
        // the segment took its last bytes' state over its whole span).
        let instant = piece.instant();
        let Some(at_end) = self.place(uid, instant, force) else {
            return (false, settled);
        };
        let (start, end) = (piece.start, piece.end.max(piece.start));
        let state = piece.state.unwrap_or(at_end);
        if state == Placed::Unknown(Unknown::Late) {
            self.late += 1;
        }
        let bytes = delta(piece.last, piece.base);
        let cut = match at_end {
            Placed::Known(_) if at_end != state => {
                let place = |second| self.place(uid, second, force);
                let after = piece.after.max(start.div_ceil(1000));
                Some(change(&place, instant, at_end, (start, after)).saturating_mul(1000))
                    .filter(|&cut| cut > start && cut < end)
            }
            _ => None,
        };
        if let Some(cut) = cut {
            records.push(piece.record((start, cut), bytes, true, state));
            records.push(piece.record((cut, end), [0; 4], piece.continues, at_end));
        } else {
            records.push(piece.record((start, end), bytes, piece.continues, state));
        }
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
        // The seconds of the window before the oldest second still waiting, or before the end of what
        // was told, stay for the cuts ([`change`]).
        let oldest = [oldest_mark, held]
            .into_iter()
            .flatten()
            .min()
            .map_or(u64::MAX, |second| second.saturating_mul(1000));
        let keep = (WINDOW as u64).saturating_mul(1000);
        self.timeline
            .forget_before(oldest.min(self.timeline.until()).saturating_sub(keep));
    }
}

impl Shared {
    /// A flow, or an app's lookups, of the app `uid` noted a new second, `second`, whose seconds held
    /// now number `held`: counted with all marks and the app's. Past the flow's window, the app's seconds
    /// before the window are placed as told too late; past its share, only as many of its own oldest as
    /// bring it [`GIVE_WAY`] below it, and past the bound of all, as many of the oldest of the app that
    /// holds the most (review b2 of W5's second part, N1: all of them went before). One app's seconds
    /// never push another's out (review b1, engine, finding 2). A reading is asked for, at most every
    /// [`ASK_EVERY`] seconds, so that a lone burst waits no longer than one reading's period (review b2,
    /// fresh, m2).
    #[cold]
    pub(super) fn marked(&self, uid: Option<u32>, held: usize, second: u64) {
        let (all, mine) = lock(&self.waiting).add(uid);
        if held > WINDOW {
            self.settle(Some(Force::late(
                uid,
                second.saturating_sub(WINDOW as u64 - 1),
            )));
        } else if mine > MARKS_SHARE {
            self.give_way(uid, mine - (MARKS_SHARE - GIVE_WAY));
        } else if all > MARKS {
            let heaviest = lock(&self.waiting).heaviest();
            if let Some((heaviest, holds)) = heaviest {
                self.give_way(heaviest, (all - (MARKS - GIVE_WAY)).min(holds));
            }
        }
        self.ask(second);
    }

    /// Places as told too late at least `n` of the app `uid`'s seconds waiting, its oldest: every one of
    /// its seconds before the `n`-th oldest's, and that second's. On the cold path only, past a bound.
    fn give_way(&self, uid: Option<u32>, n: usize) {
        let mut seconds = Vec::new();
        {
            let live = lock(&self.live);
            let lookups = lock(&self.lookups);
            let activity = lock(&self.activity);
            for live in live.values().filter(|live| live.flow.uid == uid) {
                seconds.extend(lock(&live.bytes.marks).iter().map(|mark| mark.second));
            }
            if let Some(entry) = lookups.get(&uid) {
                seconds.extend(entry.marks.iter().map(|mark| mark.second));
            }
            for piece in activity.held.iter().filter(|piece| piece.uid == uid) {
                seconds.extend(piece.marks.iter().map(|mark| mark.second));
            }
        }
        let Some(nth) = n.min(seconds.len()).checked_sub(1) else {
            return;
        };
        let (_, &mut last, _) = seconds.select_nth_unstable(nth);
        self.settle(Some(Force::late(uid, last.saturating_add(1))));
    }

    /// How many seconds not placed yet all flows and lookups hold.
    #[cfg(test)]
    pub(super) fn waiting_marks(&self) -> usize {
        lock(&self.waiting).total()
    }

    /// Counts the seconds and segments the activity placed as told too late.
    fn count_late(&self, activity: &mut Activity) {
        let late = activity.take_late();
        if late > 0 {
            super::Counters::add(&self.counters.told_late, late);
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

    /// Takes a reading of the states, and places every second it covers. Seconds or segments it left
    /// waiting, as those of the moments after its end, ask for the next reading at once: Watch's Kotlin
    /// side makes it when its turn comes, so that they are placed within a reading's period even when no
    /// traffic asks again (review b1 of W5's second part, engine, on how long a record can wait).
    pub(super) fn tell(&self, told: &Told) {
        lock(&self.activity).tell(told);
        self.settle(None);
        // One lock at a time: `waiting` is not held while `activity` is waited for (review b2, N7).
        let marks = lock(&self.waiting).total();
        let waits = marks > 0 || !lock(&self.activity).held.is_empty();
        if waits && self.tracks {
            self.asked
                .store(self.clock.wall_ms() / 1000, Ordering::Relaxed);
            self.platform.wants_states();
        }
    }

    /// The wall clock was set back by a second or more, to `now` (`logbook`'s `log_now`, after the cut and
    /// before the count that read it): every second held is placed at once, by what was told of it or as
    /// not told, and what was told is forgotten, since its spans, of the old clock, may cover the seconds
    /// the new clock reads next; those wait for the readings of the new clock. Each flow and app's
    /// lookups notes its next second anew, even one it had noted on the old clock (review b1 of W5's
    /// second part, engine, finding 4), and the live view forgets the old clock's minutes later than the
    /// new clock's, and the moment the screen came on if that is later too (finding 5).
    #[cold]
    pub(super) fn clock_set_back(&self, now: u64) {
        self.settle(Some(Force::ALL));
        for live in lock(&self.live).values() {
            live.bytes.forget_second();
        }
        for entry in lock(&self.lookups).values_mut() {
            entry.forget_second();
        }
        let mut activity = lock(&self.activity);
        activity.timeline = Timeline::default();
        activity.counts.set_back(now);
    }

    /// Places every second held that what was told places, or `force`: in the live flows, the apps'
    /// lookups and the segments held. The log gets the parts written.
    pub(super) fn settle(&self, force: Option<Force>) {
        let mut records = Vec::new();
        let written;
        let mut settled = ByApp::new();
        // The second the clock reads, and the one before, which the engine's coarser clock may still be
        // counting in: not placed in live flows of no app, unless everything is.
        let running = if force.is_some_and(|f| f.before == u64::MAX) {
            u64::MAX
        } else {
            (self.clock.wall_ms() / 1000).saturating_sub(1)
        };
        {
            let mut live = lock(&self.live);
            let mut lookups = lock(&self.lookups);
            let mut activity = lock(&self.activity);
            let mut oldest: Option<u64> = None;
            // The segments held first: they are older than the live flows' parts, so that the log gets a
            // flow's records in time order (review b1 of W5's second part, engine, nit 1).
            activity.settle_held(force, &mut records, &mut settled);
            for live in live.values_mut() {
                let mut marks = lock(&live.bytes.marks);
                if !marks.is_empty() {
                    let now = live.bytes.now();
                    let flow = &live.flow;
                    *settled.entry(flow.uid).or_default() += activity.settle_open(
                        (flow.uid, Seen::live(flow, live.hidden, live.direct)),
                        (
                            &mut live.start,
                            &mut live.base,
                            &mut live.state,
                            &mut live.after,
                        ),
                        (&mut marks, now, running),
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
                    after,
                    marks,
                    ..
                } = entry;
                *settled.entry(uid).or_default() += activity.settle_open(
                    (uid, Seen::Lookups),
                    (start, base, state, after),
                    (marks, counts, running),
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
            activity.forget_told_before(oldest);
            self.count_late(&mut activity);
            written = !records.is_empty();
            // Handed to the log under the activity's lock, so that a segment that `hold` writes on the
            // engine's thread meanwhile does not reach it before the parts cut here (review b3 of W5's
            // second part, fresh, n1). Nothing takes the activity's lock while it holds the log's.
            if !records.is_empty() {
                lock(&self.pending_log).extend(records.drain(..));
            }
        }
        lock(&self.waiting).sub(&settled);
        if written {
            self.log_ready.notify_one();
        }
    }

    /// Holds cut segments until their seconds are placed, writing at once those whose are. Past its
    /// share of [`HELD`], an app's own oldest segment is written with its seconds not told yet as told
    /// too late; past [`HELD`] itself, the oldest of the app that holds the most.
    pub(super) fn hold(&self, pieces: Vec<Piece>) {
        if pieces.is_empty() {
            return;
        }
        let mut records = Vec::new();
        let mut settled = ByApp::new();
        let mut waiting = false;
        let written;
        {
            let mut activity = lock(&self.activity);
            for mut piece in pieces {
                let uid = piece.uid;
                let (done, marks) = activity.settle_piece(&mut piece, None, &mut records);
                *settled.entry(uid).or_default() += marks;
                if !done {
                    activity.push_held(piece);
                    waiting = true;
                    if activity.held_by.get(&uid).is_some_and(|n| *n > HELD_SHARE) {
                        activity.evict(uid, &mut records, &mut settled);
                    }
                }
            }
            while activity.held.len() > HELD {
                let Some((heaviest, _)) = activity.heaviest_held() else {
                    break;
                };
                activity.evict(heaviest, &mut records, &mut settled);
            }
            self.count_late(&mut activity);
            // Under the activity's lock, as `settle` does, for the log's order.
            written = !records.is_empty();
            if written {
                lock(&self.pending_log).extend(records.drain(..));
            }
        }
        lock(&self.waiting).sub(&settled);
        // The logger hands the records on; a segment that waits asks for its states now, not after the
        // logger's gathering (review b2 of W5's second part, fresh, m2).
        if waiting {
            self.ask(self.clock.wall_ms() / 1000);
        }
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
            screen_off: None,
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

    /// A reading of no span, as one told again at its own end, keeps no span: however many come, what was
    /// told before stays.
    #[test]
    fn a_reading_of_no_span_keeps_none() {
        let mut timeline = Timeline::default();
        timeline.tell(&told(T, T + 3_000, &[(T, T + 2_000, State::InUse)]));
        for _ in 0..=SPANS {
            timeline.tell(&Told {
                known: Known::NoAccess,
                intervals: Vec::new(),
                ..told(T + 3_000, T + 3_000, &[])
            });
        }
        assert_eq!(timeline.spans.len(), 1);
        assert_eq!(timeline.place(UID, T / 1000 + 1), Some(IN_USE));
    }

    /// Past [`INTERVALS`] intervals of one app, the one that ended first gives way, not the first a reading
    /// listed: a reading lists an app's intervals in use before those with its notification (review b3 of
    /// W5's second part, fresh, n3: the recent use went, and its second was told "in the background").
    #[test]
    fn past_the_bound_of_intervals_the_oldest_give_way() {
        let mut timeline = Timeline::default();
        let mut intervals = vec![(T + 600_000, T + 601_000, State::InUse)];
        for k in 0..INTERVALS as u64 {
            intervals.push((T + k * 2_000, T + k * 2_000 + 1_000, State::Notification));
        }
        timeline.tell(&told(T, T + 602_000, &intervals));
        assert_eq!(timeline.place(UID, T / 1000 + 600), Some(IN_USE));
        assert_eq!(
            timeline.place(UID, T / 1000),
            Some(BACKGROUND),
            "the oldest gave way"
        );
        assert_eq!(timeline.place(UID, T / 1000 + 2), Some(NOTIFICATION));
    }

    /// A reading that knew the states replaces the overlap of one before that knew nothing, as when
    /// usage access is granted between two readings (review b1 of W5's second part, engine, finding 8).
    #[test]
    fn a_reading_that_knows_replaces_the_overlap_of_one_that_did_not() {
        let mut timeline = Timeline::default();
        timeline.tell(&Told {
            known: Known::NoAccess,
            intervals: Vec::new(),
            ..told(T, T + 10_000, &[])
        });
        timeline.tell(&told(
            T + 5_000,
            T + 15_000,
            &[(T + 5_000, T + 12_000, State::InUse)],
        ));
        assert_eq!(
            timeline.place(UID, T / 1000 + 4),
            Some(Placed::Unknown(Unknown::NoAccess))
        );
        for second in 5..12 {
            assert_eq!(
                timeline.place(UID, T / 1000 + second),
                Some(IN_USE),
                "{second}"
            );
        }
        assert_eq!(timeline.place(UID, T / 1000 + 12), Some(BACKGROUND));
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
    /// afterwards: the segment is cut back in time where each new state began, each part with
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
                (1, T + 1_000, T + 4_000, 20 + 30 + 40, true, IN_USE),
            ]
        );
        {
            let live = &lock(&shared.live)[&1];
            assert_eq!(
                (live.start, live.base[0], live.state),
                (T + 4_000, 100, Some(BACKGROUND))
            );
            assert_eq!(lock(&live.bytes.marks).len(), 1, "12 s waits");
        }
        assert_eq!(shared.waiting_marks(), 1);
    }

    /// Bytes received as the first count of a second take that second's state: a download after the
    /// user left the app is not "in use" (review b1 of W5's second part, engine, finding 8).
    #[test]
    fn bytes_received_first_in_a_second_take_its_state() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 100, 10);
        clock.set(T + 3_500);
        bytes.down(&shared, 40, 80);
        shared.tell(&told(T, T + 5_000, &[(T, T + 3_000, State::InUse)]));
        let written: Vec<_> = taken(&shared)
            .into_iter()
            .filter_map(|r| match r {
                Record::Segment {
                    start,
                    end,
                    bytes,
                    state,
                    ..
                } => Some((start, end, bytes[0], bytes[1], state)),
                Record::Lookups { .. } => None,
            })
            .collect();
        assert_eq!(written, vec![(T, T + 3_000, 10, 0, IN_USE)]);
        let live = &lock(&shared.live)[&1];
        assert_eq!(
            (live.start, live.base[1], live.state),
            (T + 3_000, 0, Some(BACKGROUND))
        );
    }

    /// A segment is cut where its app's state changed by the timeline, not at the first second with
    /// bytes in the new state: quiet seconds after a change belong to the new part, up to the window's
    /// 120; and never before a second already placed, even when a later reading tells it otherwise
    /// (review b1 of W5's second part, engine, nit 2).
    #[test]
    fn a_segment_is_cut_where_the_timeline_changed_not_at_the_next_bytes() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 39_500, 10);
        up_at(&shared, &clock, &bytes, 50_000, 20);
        shared.tell(&told(T, T + 55_000, &[(T, T + 40_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 40_000, 10, true, IN_USE)]
        );
        // A second placed stays where it was: a later reading that ends the use earlier moves no cut
        // before it.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 39_500, 10);
        shared.tell(&told(T, T + 45_000, &[(T, T + 40_000, State::InUse)]));
        up_at(&shared, &clock, &bytes, 50_000, 20);
        shared.tell(&told(
            T + 35_000,
            T + 55_000,
            &[(T + 35_000, T + 38_000, State::InUse)],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 40_000, 10, true, IN_USE)]
        );
        // The timeline keeps what it was told of the window before its end: the quiet stretch, told by a
        // reading of its own, still finds the change in the one before.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 39_500, 10);
        shared.tell(&told(T, T + 41_000, &[(T, T + 40_000, State::InUse)]));
        shared.tell(&told(T + 41_000, T + 46_000, &[]));
        up_at(&shared, &clock, &bytes, 50_000, 20);
        shared.tell(&told(T + 46_000, T + 55_000, &[]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 40_000, 10, true, IN_USE)]
        );
        // A quiet stretch longer than the window: the cut is the window's 120 seconds before the bytes.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 10_000, 10);
        up_at(&shared, &clock, &bytes, 210_000, 20);
        shared.tell(&told(T, T + 215_000, &[(T, T + 11_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 90_000, 10, true, IN_USE)]
        );
    }

    /// One reading that places a flow's held segment and its live parts writes them in time order
    /// (review b1 of W5's second part, engine, nit 1).
    #[test]
    fn a_flows_records_reach_the_log_in_time_order() {
        let (shared, clock, _) = telling_at(T);
        clock.set(T + 295_000);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 296_000, 10);
        up_at(&shared, &clock, &bytes, 301_000, 20);
        up_at(&shared, &clock, &bytes, 305_000, 30);
        assert_eq!(
            lock(&shared.activity).held.len(),
            1,
            "the quarter's segment waits"
        );
        shared.tell(&told(
            T + 290_000,
            T + 310_000,
            &[(T + 290_000, T + 303_000, State::InUse)],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T + 295_000, T + 300_000, 10, true, IN_USE),
                (1, T + 300_000, T + 303_000, 20, true, IN_USE),
            ]
        );
    }

    /// A segment held gives back its marks' room once most of them are settled (review b1 of W5's second
    /// part, engine, nit 5).
    #[test]
    fn a_held_segment_gives_its_marks_room_back() {
        let (shared, clock, _) = telling_at(T);
        clock.set(T + 199_000);
        let bytes = open(&shared, 1);
        for second in 199..300 {
            up_at(&shared, &clock, &bytes, second * 1_000, 1);
        }
        up_at(&shared, &clock, &bytes, 300_500, 1);
        {
            let activity = lock(&shared.activity);
            assert!(activity.held[0].marks.capacity() >= 100);
        }
        shared.tell(&told(T + 190_000, T + 290_000, &[]));
        let activity = lock(&shared.activity);
        assert_eq!(activity.held[0].marks.len(), 10);
        assert!(
            activity.held[0].marks.capacity() <= 16,
            "{}",
            activity.held[0].marks.capacity()
        );
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
        assert_eq!(shared.waiting_marks(), 0);
        // A count after the flow ended, as of a packet the tunnel carries after the relay, notes nothing.
        up_at(&shared, &clock, &bytes, 4_000, 5);
        assert!(lock(&bytes.marks).is_empty());
        assert_eq!(shared.waiting_marks(), 0);
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

    /// A segment cut at a quarter hour takes its state with it: the next begins with none, and takes the
    /// state of its first second with bytes, with no empty record before it (review b1 of W5's second
    /// part, engine, finding 8).
    #[test]
    fn the_next_quarters_segment_begins_with_no_state() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 299_000, 10);
        shared.tell(&told(T, T + 300_000, &[(T, T + 300_000, State::InUse)]));
        assert_eq!(taken(&shared), vec![]);
        up_at(&shared, &clock, &bytes, 305_000, 20);
        shared.tell(&told(
            T + 300_000,
            T + 310_000,
            &[(T + 300_000, T + 302_000, State::InUse)],
        ));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 300_000, 10, true, IN_USE)]
        );
        let live = &lock(&shared.live)[&1];
        assert_eq!((live.start, live.state), (T + 300_000, Some(BACKGROUND)));
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
                (T, T + 1_000),
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
                (T + 1_000, T + 4_500),
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
        assert_eq!(shared.waiting_marks(), WINDOW);
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
        // The bytes' part in use; the quiet end, in the background, a part of its own with no bytes.
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T, T + 2_000, 10, true, IN_USE),
                (1, T + 2_000, T + 6_000, 0, false, BACKGROUND)
            ]
        );
    }

    /// A flow that goes quiet after its app's state changed and then ends, or is cut at a quarter hour,
    /// ends with a part of no bytes in the state of its end, cut where the state changed: the history
    /// does not draw the app in use after the user left it (review b2 of W5's second part, fresh, m4).
    #[test]
    fn a_quiet_end_after_a_change_has_a_part_of_its_own() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 10_000, 10);
        clock.set(T + 100_000);
        shared.finish(1);
        shared.tell(&told(T, T + 101_000, &[(T, T + 50_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![
                (1, T, T + 50_000, 10, true, IN_USE),
                (1, T + 50_000, T + 100_000, 0, false, BACKGROUND)
            ]
        );
        // Quiet in the same state to its end: one part.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 10_000, 10);
        clock.set(T + 40_000);
        shared.finish(1);
        shared.tell(&told(T, T + 41_000, &[(T, T + 50_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 40_000, 10, false, IN_USE)]
        );
        // Cut at a quarter hour, quiet after a change: the quarter's segment ends so too, and goes on.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 10_000, 10);
        up_at(&shared, &clock, &bytes, 301_000, 5);
        shared.tell(&told(T, T + 305_000, &[(T, T + 200_000, State::InUse)]));
        assert_eq!(
            segments(&taken(&shared))[..2],
            [
                (1, T, T + 200_000, 10, true, IN_USE),
                (1, T + 200_000, T + 300_000, 0, true, BACKGROUND)
            ]
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
        // A segment waits: its new second asked, and the logger asks again while it waits.
        bytes.up(&shared, 10, 0);
        shared.finish(1);
        assert_eq!(asked(), 2);
        clock.set(T + 20_000);
        tokio::time::sleep(super::super::LOG_DELAY + std::time::Duration::from_secs(1)).await;
        assert_eq!(asked(), 3);
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

    /// A flow of the app `uid`, opened now.
    fn open_of(shared: &Shared, id: u64, uid: u32) -> Arc<super::super::logbook::FlowBytes> {
        let Some(bytes) = shared.record(flow(id, Some(uid))) else {
            unreachable!("an open flow is live")
        };
        bytes
    }

    /// Whether any live flow of `uid` has seconds told too late.
    fn late_of(shared: &Shared, uid: u32) -> bool {
        lock(&shared.live).values().any(|live| {
            live.flow.uid == Some(uid) && live.state == Some(Placed::Unknown(Unknown::Late))
        })
    }

    /// An app past its share of [`MARKS`] has its own oldest seconds told too late, never another
    /// app's, and each is counted (review b1 of W5's second part, engine, finding 2).
    #[test]
    fn seconds_past_an_apps_share_are_its_own_told_too_late() {
        let (shared, clock, _) = telling_at(T);
        let other = open_of(&shared, 1, UID + 1);
        let flood: Vec<_> = (2..=201).map(|id| open_of(&shared, id, UID)).collect();
        for second in 0..100 {
            clock.set(T + second * 1_000);
            other.up(&shared, 1, 0);
            for bytes in &flood {
                bytes.up(&shared, 1, 0);
            }
        }
        assert!(
            late_of(&shared, UID),
            "the flooding app's own seconds were not told too late"
        );
        assert!(
            !late_of(&shared, UID + 1),
            "another app's seconds were told too late"
        );
        assert_eq!(lock(&other.marks).len(), 100);
        assert!(
            shared.counters.snapshot()[super::super::COUNTERS - 1] > 0,
            "not counted"
        );
    }

    /// Exactly an app's share is kept.
    #[test]
    fn exactly_an_apps_share_is_kept() {
        let (shared, clock, _) = telling_at(T);
        let flows: Vec<_> = (1..=164).map(|id| open_of(&shared, id, UID)).collect();
        for second in 0..100u64 {
            clock.set(T + second * 1_000);
            for (i, bytes) in flows.iter().enumerate() {
                if i < 163 || second < 84 {
                    bytes.up(&shared, 1, 0);
                }
            }
        }
        assert_eq!(shared.waiting_marks(), MARKS_SHARE);
        assert!(!late_of(&shared, UID), "told too late within the share");
    }

    /// A busy app with the screen off, read once a minute: past its share it gives up only as many of its
    /// oldest seconds as bring it back under, so most of its seconds keep their state (review b2 of W5's
    /// second part, N1, and the fresh review's m1: with 280 flows 97 % were told too late, with 300, 90 %).
    #[test]
    fn a_busy_app_with_the_screen_off_keeps_most_of_its_states() {
        for (flows, most) in [(250, 0.0), (280, 0.08), (300, 0.15)] {
            let (shared, clock, _) = telling_at(T);
            let bytes: Vec<_> = (0..flows)
                .map(|i| open_of(&shared, i + 1, UID + 1))
                .collect();
            let mut told_until = T;
            for second in 1..=600_u64 {
                clock.set(T + second * 1_000);
                for flow in &bytes {
                    flow.up(&shared, 1, 0);
                }
                if second % 60 == 0 {
                    let until = T + second * 1_000 - 2_000;
                    shared.tell(&told(told_until.saturating_sub(10_000).max(T), until, &[]));
                    told_until = until;
                }
            }
            let late = shared.counters.told_late.load(Ordering::Relaxed);
            #[allow(clippy::cast_precision_loss)]
            let part = late as f64 / (flows * 600) as f64;
            assert!(part <= most, "{flows} flows: {late} seconds told too late");
            assert!(shared.waiting_marks() <= MARKS_SHARE);
        }
    }

    /// Past its share, an app gives up its oldest seconds, and only enough to come [`GIVE_WAY`] under it.
    #[test]
    fn past_its_share_an_app_gives_up_only_its_oldest() {
        let (shared, clock, _) = telling_at(T);
        let bytes: Vec<_> = (0..164).map(|i| open_of(&shared, i + 1, UID + 1)).collect();
        for second in 0..100_u64 {
            clock.set(T + second * 1_000);
            for flow in &bytes {
                flow.up(&shared, 1, 0);
            }
        }
        // 16,400 seconds: 16 past the share. The oldest seconds go, all of their flows' at once.
        let late = shared.counters.told_late.load(Ordering::Relaxed);
        assert!(late > 0, "it gave way");
        assert!(late <= (GIVE_WAY + 2 * 164) as u64, "{late} told too late");
        for flow in &bytes {
            let marks = lock(&flow.marks);
            assert!(
                marks.back().is_some_and(|m| m.second == T / 1000 + 99),
                "the newest stay"
            );
        }
        assert!(shared.waiting_marks() <= MARKS_SHARE);
    }

    /// A flow's window places only its own app's seconds as told too late: another app's, as old, wait
    /// (review b2 of W5's second part, N6: widened to every app, the force survived the tests).
    #[test]
    fn a_flows_window_places_only_its_own_apps_seconds() {
        let (shared, clock, _) = telling_at(T);
        let other = open_of(&shared, 1, UID + 2);
        let busy = open_of(&shared, 2, UID + 1);
        for second in 0..=WINDOW as u64 {
            if second < 10 {
                up_at(&shared, &clock, &other, second * 1_000, 1);
            }
            up_at(&shared, &clock, &busy, second * 1_000, 1);
        }
        assert!(late_of(&shared, UID + 1), "the busy app's oldest");
        assert!(!late_of(&shared, UID + 2), "the other app's wait");
        assert_eq!(lock(&other.marks).len(), 10);
    }

    /// Past [`MARKS`] for all apps together, each within its share, the app that holds the most gives
    /// way, and none other.
    #[test]
    fn past_the_bound_of_all_seconds_the_heaviest_app_gives_way() {
        let (shared, clock, _) = telling_at(T);
        let mut flows = Vec::new();
        let mut id = 0;
        // Three apps of 16,000 seconds each, one of 16,300 and a fifth of 1,500: 65,800 in all.
        for (app, count) in [(1, 160), (2, 160), (3, 160), (4, 163), (5, 15)] {
            for _ in 0..count {
                id += 1;
                flows.push((app, open_of(&shared, id, UID + app)));
            }
        }
        for second in 0..100 {
            clock.set(T + second * 1_000);
            for (_, bytes) in &flows {
                bytes.up(&shared, 1, 0);
            }
        }
        assert!(shared.waiting_marks() <= MARKS);
        assert!(
            late_of(&shared, UID + 4),
            "the heaviest app did not give way"
        );
        for app in [1, 2, 3, 5] {
            assert!(!late_of(&shared, UID + app), "app {app} gave way");
        }
    }

    /// Exactly [`MARKS`] seconds held for all apps together are all kept; one more makes the heaviest
    /// app give way.
    #[test]
    fn exactly_the_bound_of_all_seconds_is_kept() {
        let (shared, clock, _) = telling_at(T);
        let mut flows = Vec::new();
        let mut id = 0;
        // Four apps of 16,000 seconds each and a fifth of 1,500: 65,500.
        for (app, count) in [(1, 160), (2, 160), (3, 160), (4, 160), (5, 15)] {
            for _ in 0..count {
                id += 1;
                flows.push(open_of(&shared, id, UID + app));
            }
        }
        for second in 0..100 {
            clock.set(T + second * 1_000);
            for bytes in &flows {
                bytes.up(&shared, 1, 0);
            }
        }
        let last = open_of(&shared, id + 1, UID + 5);
        for second in 100..136 {
            clock.set(T + second * 1_000);
            last.up(&shared, 1, 0);
        }
        assert_eq!(shared.waiting_marks(), MARKS);
        assert!(
            (1..=5).all(|app| !late_of(&shared, UID + app)),
            "none gave way"
        );
        clock.set(T + 136_000);
        last.up(&shared, 1, 0);
        assert!(shared.waiting_marks() <= MARKS);
        assert!(
            (1..=4).any(|app| late_of(&shared, UID + app)),
            "the heaviest gave way"
        );
        assert!(!late_of(&shared, UID + 5));
        // It gave up its oldest seconds, enough to come under the bound, not all of them (review b2 of W5's
        // second part, N1).
        let late = shared.counters.told_late.load(Ordering::Relaxed);
        assert!(
            (1..=(GIVE_WAY + 2 * 160) as u64).contains(&late),
            "{late} told too late"
        );
        assert!(shared.waiting_marks() >= MARKS - GIVE_WAY - 2 * 160);
    }

    /// Past its share of [`HELD`], an app's own oldest segment is written as told too late, never another
    /// app's: an app that ends short flows by the hundred while the screen is off does not blind Watch
    /// for others (review b1 of W5's second part, engine, finding 2).
    #[test]
    fn segments_past_an_apps_share_are_its_own_written_as_told_too_late() {
        let (shared, clock, _) = telling_at(T);
        let other = open_of(&shared, 1, UID + 1);
        other.up(&shared, 500, 0);
        shared.finish(1);
        let mut id = 1;
        for second in 0..23 {
            clock.set(T + second * 1_000);
            for _ in 0..200 {
                id += 1;
                open_of(&shared, id, UID).up(&shared, 1, 0);
                shared.finish(id);
            }
        }
        let held = lock(&shared.activity).held.len();
        assert_eq!(
            held,
            HELD_SHARE + 1,
            "the flooding app's share and the other's segment"
        );
        let written = segments(&taken(&shared));
        assert!(
            written.iter().all(|s| s.0 != 1),
            "another app's segment was pushed out"
        );
        assert!(
            written
                .iter()
                .all(|s| s.5 == Placed::Unknown(Unknown::Late))
        );
        // The minute's reading tells the other app's seconds: its record is in the background.
        let mut reading = told(T, T + 30_000, &[]);
        reading.intervals.clear();
        shared.tell(&reading);
        let other_record: Vec<_> = segments(&taken(&shared))
            .into_iter()
            .filter(|s| s.0 == 1)
            .collect();
        assert_eq!(other_record, vec![(1, T, T, 500, false, BACKGROUND)]);
    }

    /// Past [`HELD`] for all apps together, each within its share, the app that holds the most gives
    /// way, and none other.
    #[test]
    fn past_the_bound_of_all_segments_the_heaviest_app_gives_way() {
        let (shared, _, _) = telling_at(T);
        let mut id = 0;
        for (app, count) in [(1, 1_000), (2, 1_000), (3, 1_000), (4, 1_024), (5, 73)] {
            for _ in 0..count {
                id += 1;
                open_of(&shared, id, UID + app).up(&shared, 1, 0);
                shared.finish(id);
            }
        }
        assert_eq!(lock(&shared.activity).held.len(), HELD);
        let written = segments(&taken(&shared));
        assert_eq!(written.len(), 1, "{written:?}");
        let gone = written[0].0;
        assert!(
            (3_001..=4_024).contains(&gone),
            "flow {gone} of another app than the heaviest gave way"
        );
        assert_eq!(shared.waiting_marks(), HELD);
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
        // Back by exactly a second: the segment is cut where what was told ends.
        up_at(&shared, &clock, &bytes, 1_600, 40);
        assert_eq!(
            segments(&taken(&shared)),
            vec![(1, T, T + 2_000, 10, true, IN_USE)]
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

    /// A segment with no count cut by a clock set back across a quarter hour is written at once, as not
    /// told, rather than waiting for the new clock to reach its moment (review b1 of W5's second part,
    /// engine, finding 6).
    #[test]
    fn a_segment_cut_by_a_clock_set_back_is_written_at_once() {
        let (shared, clock, _) = telling_at(T);
        open(&shared, 1);
        let other = open(&shared, 2);
        let back = T - 2 * 3_600_000;
        clock.set(back);
        other.up(&shared, 10, 0);
        shared.finish(1);
        shared.finish(2);
        clock.set(back + 4_000);
        shared.tell(&told(back, back + 2_000, &[]));
        let written = segments(&taken(&shared));
        assert!(
            written.contains(&(1, T, T, 0, true, NOT_TOLD)),
            "{written:?}"
        );
        assert!(
            written.contains(&(2, T, T, 0, true, NOT_TOLD)),
            "{written:?}"
        );
        assert!(lock(&shared.activity).held.is_empty());
    }

    /// The engine asks for the states when a flow opens and at each new second counted, at most every
    /// five seconds; and the logger asks again while segments wait.
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
        assert_eq!(asked(), 1, "within five seconds of the last ask");
        up_at(&shared, &clock, &bytes, 5_000, 1);
        assert_eq!(asked(), 2, "five seconds after it");
        up_at(&shared, &clock, &bytes, 6_000, 1);
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

    /// A lone burst on a long connection asks for a reading, so that it waits no longer than one reading's
    /// period (review b2 of W5's second part, fresh, m2: it asked for nothing, and waited for other
    /// traffic or the screen).
    #[test]
    fn a_lone_burst_asks_for_a_reading() {
        let (shared, clock, platform) = telling_at(T);
        let asked = || platform.asked.load(Ordering::Relaxed);
        let bytes = open(&shared, 1);
        clock.set(T + 3_000);
        shared.tell(&told(T, T + 1_000, &[]));
        assert_eq!(asked(), 1, "the opening's");
        up_at(&shared, &clock, &bytes, 100_000, 5);
        up_at(&shared, &clock, &bytes, 100_500, 5);
        up_at(&shared, &clock, &bytes, 101_000, 5);
        assert_eq!(asked(), 2, "the burst's");
        clock.set(T + 104_000);
        shared.tell(&told(T + 1_000, T + 102_000, &[]));
        assert_eq!(shared.waiting_marks(), 0);
    }

    /// A segment held with all its seconds placed, waiting only for the state of its end, asks for a reading
    /// at once, not after the logger's gathering (review b3 of W5's second part, R5).
    #[test]
    fn a_segment_held_for_its_end_asks_at_once() {
        let (shared, clock, platform) = telling_at(T);
        let asked = || platform.asked.load(Ordering::Relaxed);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 10);
        clock.set(T + 4_000);
        shared.tell(&told(T, T + 3_000, &[]));
        assert_eq!(shared.waiting_marks(), 0);
        let before = asked();
        clock.set(T + 10_000);
        shared.finish(1);
        assert_eq!(
            lock(&shared.activity).held.len(),
            1,
            "it waits for the state of its end"
        );
        assert_eq!(asked(), before + 1);
    }

    /// A reading that leaves seconds or segments waiting asks for the next at once, even with no traffic
    /// after it, and one that leaves nothing waiting asks for none (review b1 of W5's second part, engine:
    /// with no traffic, what waited was placed only with the next traffic or the screen coming on).
    #[test]
    fn a_reading_that_leaves_seconds_waiting_asks_for_the_next() {
        let (shared, clock, platform) = telling_at(T);
        let asked = || platform.asked.load(Ordering::Relaxed);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 10);
        up_at(&shared, &clock, &bytes, 4_000, 10);
        assert_eq!(asked(), 1, "the flow's opening");
        clock.set(T + 6_000);
        shared.tell(&told(T, T + 4_000, &[]));
        assert_eq!(asked(), 2, "the second at 4 s waits");
        shared.tell(&told(T + 4_000, T + 5_000, &[]));
        assert_eq!(asked(), 2, "nothing waits");
        // A segment held for its state asks too.
        up_at(&shared, &clock, &bytes, 7_000, 10);
        clock.set(T + 8_000);
        shared.finish(1);
        shared.tell(&told(T + 5_000, T + 7_000, &[]));
        assert_eq!(asked(), 3, "the ended flow's last second waits");
        shared.tell(&told(T + 7_000, T + 9_000, &[]));
        assert_eq!(asked(), 3);
        assert!(lock(&shared.activity).held.is_empty());
    }

    /// An engine whose tunnel never comes, as one on a descriptor tokio cannot wait on, writes the segments
    /// the engine before handed it as not told, at once, rather than dropping them (review b2 of W5's
    /// second part, fresh, nit).
    #[test]
    fn an_engine_that_fails_to_start_writes_off_what_it_was_handed() -> std::io::Result<()> {
        use super::super::{Addresses, Config, Engine, Limits};
        let config = Config {
            mtu: 1_500,
            keep_flows: 0,
            addresses: Addresses::COMMON,
            limits: Limits::default(),
        };
        let clock = ManualClock::at(T);
        let first = Arc::new(Engined {
            clock: clock.clone(),
            batches: std::sync::Mutex::default(),
        });
        let (engine_end, app) = std::os::unix::net::UnixDatagram::pair()?;
        engine_end.set_nonblocking(true)?;
        let engine = Engine::start_with(
            std::os::fd::OwnedFd::from(engine_end),
            config,
            first.clone(),
            None,
            (None, None),
        )?;
        let server = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        server.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let Some(datagram) = crate::packet::udp(me, server.local_addr()?, b"evening") else {
            unreachable!("a small datagram")
        };
        app.send(&datagram)?;
        server.recv_from(&mut [0u8; 64])?;
        clock.set(T + 3_000);
        let handover = engine.hand_over();
        let second = Arc::new(Engined {
            clock: clock.clone(),
            batches: std::sync::Mutex::default(),
        });
        // A regular file: epoll refuses it, so the tunnel never comes.
        let file = std::fs::File::open(std::env::current_exe()?)?;
        let mut engine = Engine::start_with(
            std::os::fd::OwnedFd::from(file),
            config,
            second.clone(),
            None,
            (Some(handover), None),
        )?;
        for _ in 0..100 {
            if !states_logged(&second).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        engine.stop();
        assert_eq!(states_logged(&second), vec![NOT_TOLD]);
        Ok(())
    }

    /// An engine started with what the one before held, and a chain that leaves an app's destinations out
    /// of the log, shows none of them in "Now" (review b1 of W5's second part, engine, finding 1).
    #[test]
    fn a_chain_the_next_engine_starts_with_hides_what_the_last_held() -> std::io::Result<()> {
        use super::super::{Addresses, Chain, ChainSetting, Config, Engine, Handover, Limits};
        let start = |platform: Arc<Engined>,
                     handover: Option<Handover>,
                     setting: Option<ChainSetting>|
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
                (handover, setting),
            )?;
            Ok((engine, app))
        };
        let clock = ManualClock::at(T);
        let platform = || {
            Arc::new(Engined {
                clock: clock.clone(),
                batches: std::sync::Mutex::default(),
            })
        };
        let (engine, app) = start(platform(), None, None)?;
        let server = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        server.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let me = SocketAddr::from((Addresses::COMMON.tun4, 40_000));
        let Some(datagram) = crate::packet::udp(me, server.local_addr()?, b"evening") else {
            unreachable!("a small datagram")
        };
        app.send(&datagram)?;
        server.recv_from(&mut [0u8; 64])?;
        let places = |engine: &Engine| {
            let snapshot = engine.shared.now_view(T + 3_000);
            snapshot
                .apps
                .iter()
                .find(|a| a.uid == Some(UID))
                .map(|a| (a.places.len(), a.through_tool))
        };
        // The engine's thread counts the datagram as it passes it on: wait for the count to show.
        for _ in 0..100 {
            if places(&engine).is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(places(&engine), Some((1, false)));
        clock.set(T + 3_000);
        let handover = engine.hand_over();
        let setting = ChainSetting {
            chain: Some(Chain {
                proxy: SocketAddr::from(([127, 0, 0, 1], 9)),
                credentials: None,
                tool: 10_200,
                apps: Some(std::collections::HashSet::from([UID])),
                udp: true,
                log_destinations: false,
            }),
            uncached_answers: false,
        };
        let (mut engine, _app) = start(platform(), Some(handover), Some(setting))?;
        // No destination; and not through the tool, which that flow never went through (review b2, N3).
        assert_eq!(places(&engine), Some((0, false)));
        engine.stop();
        Ok(())
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
        assert_eq!(shared.waiting_marks(), 0);
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
        let (mut start, mut base, mut state, mut after) = (10_200, [0; 4], None, 0);
        let (mut each, mut parts) = (Vec::new(), Vec::new());
        let settled = settle_marks(
            &place,
            (&mut start, &mut base, &mut state, &mut after),
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
        assert_eq!(
            (start, base[0], state, after),
            (13_000, 20, Some(NOTIFICATION), 14)
        );
        assert_eq!(held, marks(&[(14, 33)]));
        // A change in the segment's first second, or past its end, cuts within it.
        let mut held = marks(&[(10, 0), (11, 5)]);
        let (mut start, mut base, mut state, mut after) = (11_400, [0; 4], Some(BACKGROUND), 0);
        let mut parts = Vec::new();
        settle_marks(
            &place,
            (&mut start, &mut base, &mut state, &mut after),
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
