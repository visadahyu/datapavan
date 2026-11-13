//! Whose an app socket's datagram is: the one rule by which the engine decides, from Android's answers
//! about the socket, which app sent a datagram or a lookup that came at a given instant (ADR 0044, unit
//! 9, "Whose a datagram is"). Every path of a UDP datagram goes through [`Record::whose`]: one that
//! passes by an open way, one that waits for its way while Android is asked, one that joins a question
//! out, one held when its way opens, and a lookup to the tunnel's DNS address alike.
//!
//! Android names a socket's app when asked, and may hand the port to another app at any moment. An
//! answer so tells who held the socket when it was asked, and Watch presumes the same app for what came
//! less than `Limits::udp_reask` before or after that: a port rarely comes back to another app so soon.
//! When answers near a datagram name different apps, a handover fell near it, and who sent it cannot be
//! told: it is dropped, never sent under either answer, and a later question could not tell either.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};
use std::time::{Duration, Instant};

/// What Android said of an app socket: the app it named, if it named one, and when it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Named {
    pub(super) uid: Option<u32>,
    pub(super) asked: Instant,
}

/// Whose a datagram is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The app that holds the socket now sent it, by Android's answers, or no app Android can name: it
    /// may leave by that app's way.
    Owner(Option<u32>),
    /// Answers near it name different apps, or the app they name holds the socket no more, or no answer
    /// near enough can be had: it is dropped and counted, never sent under any answer.
    Drop,
    /// No answer decides it yet; one asked now would.
    Unknown,
}

/// What a datagram that waits for its way does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// The answers decide it.
    Decided(Verdict),
    /// It waits for the answer to the question out, which can decide it.
    Join,
    /// It asks Android.
    Ask,
}

/// Datagrams that waited, sorted once their way is there: those that leave by it, those dropped, and
/// those, from the first that neither leaves nor drops, that wait on in order.
pub(super) struct Settled<T> {
    pub(super) leave: Vec<(Instant, T)>,
    pub(super) dropped: Vec<(Instant, T)>,
    pub(super) rest: Vec<(Instant, T)>,
}

/// The answers of Android's about one app socket that can still decide a datagram, and when a datagram
/// last left under the newest of them. It holds the newest answer, and the older ones less than
/// `udp_reask` from a datagram that still waits ([`Record::keep_from`]); it goes with the socket's last
/// way.
#[derive(Default)]
pub(super) struct Record {
    /// By when the question was asked and its number: the app named, if one was.
    answers: BTreeMap<(Instant, u64), Option<u32>>,
    /// The answers whose next answer, in the order asked, names another app: answers near a datagram
    /// agree when none of them but the last is here.
    changes: BTreeSet<(Instant, u64)>,
    /// When the last datagram that came after the newest question left under it.
    sent: Option<Instant>,
}

impl Record {
    /// The answer asked last.
    pub(super) fn newest(&self) -> Option<Named> {
        self.answers
            .last_key_value()
            .map(|(&(asked, _), &uid)| Named { uid, asked })
    }

    /// Notes the answer to question `id`: whether it is now the newest and names another app than the
    /// newest before it, so that the socket's ways, all of the app that held it, end.
    pub(super) fn note(&mut self, id: u64, named: Named) -> bool {
        let before = self.newest();
        let key = (named.asked, id);
        let earlier = self.answers.range(..key).next_back().map(|(&k, &u)| (k, u));
        let later = self
            .answers
            .range((Excluded(key), Unbounded))
            .next()
            .map(|(&k, &u)| (k, u));
        if let Some((earlier, uid)) = earlier {
            self.changes.remove(&earlier);
            if uid != named.uid {
                self.changes.insert(earlier);
            }
        }
        if later.is_some_and(|(_, uid)| uid != named.uid) {
            self.changes.insert(key);
        }
        self.answers.insert(key, named.uid);
        let changed = later.is_none() && before.is_none_or(|before| before.uid != named.uid);
        if changed {
            // What left under the app before was that app's: the stream it presumes is not the new
            // app's.
            self.sent = None;
        }
        changed
    }

    /// Whose a datagram that came at `came` is. `floor`, for a destination the app had no way to yet and
    /// for a lookup, is when its first datagram came: only an answer asked since may stand for it, so
    /// that it never takes an answer to a question asked before it came. `reask` is
    /// `Limits::udp_reask`.
    ///
    /// One that came after the newest question takes its answer, less than `reask` after it, or for as
    /// long as the app sends without a pause of `reask`, up to thirty times that: the window ADR 0044
    /// states. One that came before it takes the app named by every answer asked less than `reask` from
    /// it, before or after, one of them since `floor`, if that app still holds the socket; if they name
    /// different apps, a handover fell near it, and it is dropped.
    pub(super) fn whose(&self, came: Instant, floor: Option<Instant>, reask: Duration) -> Verdict {
        let Some(newest) = self.newest() else {
            return Verdict::Unknown;
        };
        let since_floor = |asked: Instant| floor.is_none_or(|floor| asked >= floor);
        if came >= newest.asked {
            if !since_floor(newest.asked) {
                return Verdict::Unknown;
            }
            let after = came.duration_since(newest.asked);
            let streaming = self.sent.is_some_and(|sent| {
                sent >= newest.asked && came.saturating_duration_since(sent) < reask
            });
            return if after < reask || (streaming && after < reask.saturating_mul(30)) {
                Verdict::Owner(newest.uid)
            } else {
                Verdict::Unknown
            };
        }
        let low = came
            .checked_sub(reask)
            .map_or(Unbounded, |low| Excluded((low, u64::MAX)));
        let high = Excluded((came + reask, 0));
        let mut near = self.answers.range((low, high));
        let (Some((&first, &uid)), last) = (near.next(), near.next_back()) else {
            return Verdict::Drop;
        };
        let last = last.map_or(first, |(&last, _)| last);
        let agree = self.changes.range(first..last).next().is_none();
        if agree && since_floor(last.0) && uid == newest.uid {
            Verdict::Owner(uid)
        } else {
            Verdict::Drop
        }
    }

    /// Whether a datagram that came `now` may pass by an open way of the app `uid`, as the newest
    /// answer, or the stream since it, says.
    pub(super) fn passes(&self, now: Instant, uid: Option<u32>, reask: Duration) -> bool {
        self.whose(now, None, reask) == Verdict::Owner(uid)
    }

    /// Whether a way of the app `uid` may open, or stay: the newest answer names that app.
    pub(super) fn keeps(&self, uid: Option<u32>) -> bool {
        self.newest().is_some_and(|newest| newest.uid == uid)
    }

    /// A datagram that came at `came` left under the newest answer: the app is presumed to send on.
    pub(super) fn left(&mut self, came: Instant) {
        if self.newest().is_some_and(|newest| came >= newest.asked) {
            self.sent = Some(self.sent.map_or(came, |sent| sent.max(came)));
        }
    }

    /// What a datagram that came at `came`, the first that waits for its way, does `now`: the answers
    /// decide it; it joins the question out, asked at `out`, if that can decide it; it asks, if a
    /// question asked now still could; else no answer near enough can be had, and it is dropped.
    pub(super) fn step(
        &self,
        (came, floor): (Instant, Option<Instant>),
        out: Option<Instant>,
        now: Instant,
        reask: Duration,
    ) -> Step {
        match self.whose(came, floor, reask) {
            Verdict::Unknown => {
                let decides = |asked: Instant| {
                    apart(asked, came) < reask && floor.is_none_or(|floor| asked >= floor)
                };
                if out.is_some_and(decides) {
                    Step::Join
                } else if decides(now) {
                    Step::Ask
                } else {
                    Step::Decided(Verdict::Drop)
                }
            }
            verdict => Step::Decided(verdict),
        }
    }

    /// Sorts datagrams that waited, in the order they came, once a way of the app `way` is there: each
    /// that app owns leaves, each dropped is dropped, and from the first of another app's, or
    /// undecided, all wait on.
    pub(super) fn settle<T>(
        &mut self,
        held: Vec<(Instant, T)>,
        floor: Option<Instant>,
        way: Option<u32>,
        reask: Duration,
    ) -> Settled<T> {
        let mut settled = Settled {
            leave: Vec::new(),
            dropped: Vec::new(),
            rest: Vec::new(),
        };
        let mut held = held.into_iter();
        for (came, item) in held.by_ref() {
            match self.whose(came, floor, reask) {
                Verdict::Owner(uid) if uid == way => {
                    self.left(came);
                    settled.leave.push((came, item));
                }
                Verdict::Drop => settled.dropped.push((came, item)),
                _ => {
                    settled.rest.push((came, item));
                    break;
                }
            }
        }
        settled.rest.extend(held);
        settled
    }

    /// Forgets the answers no datagram needs any more: all but the newest asked `reask` or more before
    /// `earliest`, the first datagram of the socket that still waits, or all but the newest when none
    /// waits.
    pub(super) fn keep_from(&mut self, earliest: Option<Instant>, reask: Duration) {
        while self.answers.len() > 1 {
            let Some((&key, _)) = self.answers.first_key_value() else {
                return;
            };
            if earliest.is_some_and(|earliest| apart(key.0, earliest) < reask || key.0 > earliest) {
                return;
            }
            self.answers.remove(&key);
            self.changes.remove(&key);
        }
    }

    /// How many answers it holds.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.answers.len()
    }
}

/// How far apart two instants are, either way.
fn apart(one: Instant, other: Instant) -> Duration {
    one.saturating_duration_since(other)
        .max(other.saturating_duration_since(one))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REASK: Duration = Duration::from_millis(100);
    const CHAINED: Option<u32> = Some(10_300);
    const DIRECT: Option<u32> = Some(10_400);

    /// `ms` milliseconds after `base`.
    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    fn named(uid: Option<u32>, asked: Instant) -> Named {
        Named { uid, asked }
    }

    /// The windows of the rule, to the nanosecond on both sides.
    #[test]
    fn the_windows_hold_to_the_nanosecond() {
        let base = Instant::now();
        let nano = Duration::from_nanos(1);
        let under = |window: Duration| base + window.saturating_sub(nano);
        let mut record = Record::default();
        record.note(1, named(CHAINED, base));
        // After the newest question: `udp_reask`.
        assert_eq!(
            record.whose(under(REASK), None, REASK),
            Verdict::Owner(CHAINED)
        );
        assert_eq!(record.whose(base + REASK, None, REASK), Verdict::Unknown);
        // Before it: `udp_reask`, from an answer only.
        let mut later = Record::default();
        later.note(1, named(CHAINED, base + REASK));
        let before = |gap: Duration| (base + REASK).checked_sub(gap);
        let just = before(REASK.saturating_sub(nano)).map(|came| later.whose(came, None, REASK));
        assert_eq!(just, Some(Verdict::Owner(CHAINED)));
        assert_eq!(later.whose(base, None, REASK), Verdict::Drop);
        // A stream that never pauses: until thirty times `udp_reask` after the question.
        let thirty = REASK * 30;
        record.left(under(thirty));
        assert_eq!(
            record.whose(under(thirty), None, REASK),
            Verdict::Owner(CHAINED)
        );
        record.left(base + thirty);
        assert_eq!(record.whose(base + thirty, None, REASK), Verdict::Unknown);
        // A pause of `udp_reask` in it ends it.
        let mut paused = Record::default();
        paused.note(1, named(CHAINED, base));
        paused.left(under(REASK));
        let after_pause = under(REASK) + REASK;
        assert_eq!(paused.whose(after_pause, None, REASK), Verdict::Unknown);
        let in_time = under(REASK) + REASK.saturating_sub(nano);
        assert_eq!(paused.whose(in_time, None, REASK), Verdict::Owner(CHAINED));
    }

    /// A datagram between two answers that name different apps, both less than `udp_reask` from it, is
    /// dropped: the handover fell near it (eighth review of unit 9, finding 1). One further from the
    /// older answer takes the newer, if that app still holds the socket.
    #[test]
    fn answers_near_a_datagram_that_disagree_drop_it() {
        let base = Instant::now();
        let mut record = Record::default();
        record.note(1, named(CHAINED, at(base, 1)));
        record.note(2, named(DIRECT, at(base, 51)));
        assert_eq!(record.whose(base, Some(base), REASK), Verdict::Drop);
        assert_eq!(record.whose(at(base, 40), None, REASK), Verdict::Drop);
        assert_eq!(
            record.whose(at(base, 120), None, REASK),
            Verdict::Owner(DIRECT)
        );
        // One that only the older answer can stand for is the old app's, which holds the socket no more.
        let mut old = Record::default();
        old.note(1, named(CHAINED, at(base, 1)));
        old.note(2, named(DIRECT, at(base, 500)));
        assert_eq!(old.whose(base, Some(base), REASK), Verdict::Drop);
        // No app named is an answer too.
        let mut none = Record::default();
        none.note(1, named(CHAINED, at(base, 1)));
        none.note(2, named(None, at(base, 51)));
        assert_eq!(none.whose(base, None, REASK), Verdict::Drop);
        assert_eq!(none.whose(at(base, 60), None, REASK), Verdict::Owner(None));
    }

    /// A late answer to an older question changes no newest answer, and neither ends nor opens a way.
    #[test]
    fn a_late_answer_changes_nothing_newer() {
        let base = Instant::now();
        let mut record = Record::default();
        assert!(record.note(2, named(DIRECT, at(base, 50))));
        assert!(!record.note(1, named(CHAINED, base)));
        assert_eq!(record.newest(), Some(named(DIRECT, at(base, 50))));
        assert!(record.keeps(DIRECT));
        assert!(!record.keeps(CHAINED));
        assert!(!record.note(3, named(DIRECT, at(base, 60))), "the same app");
    }

    /// An answer that comes late, asked before others already noted, is seen to disagree with the next
    /// one in the order asked.
    #[test]
    fn a_late_answer_before_others_is_seen_to_disagree_with_the_next() {
        let base = Instant::now();
        let mut record = Record::default();
        record.note(2, named(CHAINED, at(base, 100)));
        record.note(3, named(DIRECT, at(base, 300)));
        record.note(1, named(DIRECT, at(base, 50)));
        assert_eq!(record.whose(at(base, 120), None, REASK), Verdict::Drop);
    }

    /// What left under one app does not carry the stream on for the next: an answer naming another app,
    /// asked before the last datagram left but noted after, starts no stream of its own (found by the
    /// model, seed 406).
    #[test]
    fn a_stream_under_one_app_carries_no_other() {
        let base = Instant::now();
        let mut record = Record::default();
        record.note(1, named(CHAINED, base));
        record.left(at(base, 90));
        assert!(record.note(2, named(DIRECT, at(base, 60))));
        assert_eq!(record.whose(at(base, 170), None, REASK), Verdict::Unknown);
    }

    /// A destination the app had no way to takes no answer asked before its first datagram came: it
    /// asks, or joins only a question asked since.
    #[test]
    fn a_new_destination_takes_no_answer_asked_before_it_came() {
        let base = Instant::now();
        let mut record = Record::default();
        record.note(1, named(CHAINED, base));
        let came = at(base, 10);
        assert_eq!(record.whose(came, Some(came), REASK), Verdict::Unknown);
        assert_eq!(record.whose(came, None, REASK), Verdict::Owner(CHAINED));
        let now = at(base, 11);
        assert_eq!(
            record.step((came, Some(came)), Some(base), now, REASK),
            Step::Ask
        );
        let since = Some(at(base, 11));
        assert_eq!(
            record.step((came, Some(came)), since, now, REASK),
            Step::Join
        );
    }

    /// A datagram joins a question asked less than `udp_reask` from it, and asks when a question asked
    /// now still could decide it; else it is dropped.
    #[test]
    fn a_datagram_joins_or_asks_only_within_its_window() {
        let base = Instant::now();
        let record = Record::default();
        let nano = Duration::from_nanos(1);
        let came = base + REASK;
        let inside = came.checked_sub(REASK.saturating_sub(nano));
        let outside = Some(base);
        assert_eq!(record.step((came, None), inside, came, REASK), Step::Join);
        assert_eq!(record.step((came, None), outside, came, REASK), Step::Ask);
        let late = came + REASK;
        assert_eq!(
            record.step((came, None), None, late, REASK),
            Step::Decided(Verdict::Drop)
        );
        let in_time = came + REASK.saturating_sub(nano);
        assert_eq!(record.step((came, None), None, in_time, REASK), Step::Ask);
    }

    /// The record keeps the newest answer, and the older ones less than `udp_reask` from a datagram that
    /// still waits.
    #[test]
    fn the_record_keeps_what_a_waiting_datagram_needs() {
        let base = Instant::now();
        let mut record = Record::default();
        for (id, ms) in [(1, 0), (2, 300), (3, 450), (4, 900)] {
            record.note(id, named(CHAINED, at(base, ms)));
        }
        record.keep_from(Some(at(base, 500)), REASK);
        assert_eq!(record.len(), 2, "the one at 450, and the newest");
        record.keep_from(None, REASK);
        assert_eq!(record.len(), 1);
    }

    /// Settling waiting datagrams once a way is there: those the app owns leave, those dropped drop, and
    /// from the first undecided all wait on.
    #[test]
    fn settling_keeps_the_order_the_datagrams_came_in() {
        let base = Instant::now();
        let mut record = Record::default();
        record.note(1, named(CHAINED, at(base, 10)));
        record.note(2, named(DIRECT, at(base, 60)));
        let held = vec![
            (at(base, 5), 'a'),
            (at(base, 70), 'b'),
            (at(base, 300), 'c'),
            (at(base, 80), 'd'),
        ];
        let settled = record.settle(held, None, DIRECT, REASK);
        let names = |items: &[(Instant, char)]| items.iter().map(|(_, c)| *c).collect::<String>();
        assert_eq!(names(&settled.dropped), "a");
        assert_eq!(names(&settled.leave), "b");
        assert_eq!(names(&settled.rest), "cd");
    }

    /// A small seeded generator (xorshift64*), so that each schedule is the same on every run.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        /// A number in `0..n`.
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
    }

    /// The tunnel's DNS address, as the model's last destination: lookups always ask on their own.
    const LOOKUP: usize = 3;

    /// A datagram of the model: when it came, and which app truly sent it.
    #[derive(Clone, Copy, Debug)]
    struct Sent {
        came: u64,
        by: Option<u32>,
    }

    /// What happens next in a schedule, by the millisecond.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Event {
        Arrive(usize),
        Step(usize),
        Answer(u64),
        Opened(usize, Option<u32>),
    }

    /// A question of the model to Android: when it was asked and what it named.
    struct Question {
        asked: u64,
        uid: Option<u32>,
        waiters: Vec<usize>,
    }

    /// A destination's way in the model: none, or one of an app.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Way {
        Shut,
        Open(Option<u32>),
    }

    /// A destination's datagrams that wait for its way: the floor of the answers that may stand for
    /// them, the datagrams, and whether a step is under way for them.
    #[derive(Default)]
    struct Waiting {
        floor: Option<Instant>,
        held: Vec<(Instant, Sent)>,
        busy: bool,
    }

    /// One random schedule: who holds the port when, what it sends, and how slowly Android answers and
    /// ways open; run against the engine's own rule, checking every datagram that leaves.
    struct Schedule {
        base: Instant,
        rng: Rng,
        owners: Vec<(u64, Option<u32>)>,
        arrivals: Vec<(Sent, usize)>,
        record: Record,
        ways: [Way; 4],
        held: [Waiting; 4],
        questions: BTreeMap<u64, Question>,
        out: Option<u64>,
        answered: Vec<(u64, Option<u32>, u64)>,
        leaves: Vec<(u64, Option<u32>)>,
        queue: std::collections::BinaryHeap<std::cmp::Reverse<(u64, u64, Event)>>,
        order: u64,
        steps: usize,
    }

    impl Schedule {
        fn new(seed: u64) -> Self {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let apps = [CHAINED, DIRECT, None];
            let mut owners = vec![(0, apps[usize::try_from(rng.below(3)).unwrap_or(0)])];
            // A few handovers over three seconds; or, in one schedule of four, many over a few
            // `udp_reask`, so that answers near one datagram name three apps in turn.
            let (handovers, span) = if rng.below(4) == 0 {
                (5 + rng.below(15), 400)
            } else {
                (rng.below(5), 3_000)
            };
            for _ in 0..handovers {
                owners.push((
                    rng.below(span),
                    apps[usize::try_from(rng.below(3)).unwrap_or(0)],
                ));
            }
            owners.sort_unstable_by_key(|(at, _)| *at);
            let mut arrivals = Vec::new();
            let mut time = 0;
            // Bursts and pauses alike, around `udp_reask`; or, in one schedule of three, a stream that
            // never pauses for it, as a call's.
            let (count, gaps): (u64, &[u64]) = if rng.below(3) == 0 {
                (60 + rng.below(80), &[0, 1, 5, 30, 60, 90])
            } else {
                (10 + rng.below(50), &[0, 1, 5, 30, 90, 150, 400])
            };
            for _ in 0..count {
                time += gaps[usize::try_from(rng.below(gaps.len() as u64)).unwrap_or(0)];
                let destination = usize::try_from(rng.below(4)).unwrap_or(0);
                arrivals.push((
                    Sent {
                        came: time,
                        by: None,
                    },
                    destination,
                ));
            }
            let mut schedule = Self {
                base: Instant::now(),
                rng,
                owners,
                arrivals,
                record: Record::default(),
                ways: [Way::Shut; 4],
                held: Default::default(),
                questions: BTreeMap::new(),
                out: None,
                answered: Vec::new(),
                leaves: Vec::new(),
                queue: std::collections::BinaryHeap::new(),
                order: 0,
                steps: 0,
            };
            for index in 0..schedule.arrivals.len() {
                let came = schedule.arrivals[index].0.came;
                schedule.arrivals[index].0.by = schedule.owner(came);
                schedule.at(came, Event::Arrive(index));
            }
            schedule
        }

        /// Who held the port at `ms`.
        fn owner(&self, ms: u64) -> Option<u32> {
            self.owners
                .iter()
                .rev()
                .find(|(from, _)| *from <= ms)
                .and_then(|(_, uid)| *uid)
        }

        fn instant(&self, ms: u64) -> Instant {
            at(self.base, ms)
        }

        fn at(&mut self, ms: u64, event: Event) {
            self.order += 1;
            self.queue.push(std::cmp::Reverse((ms, self.order, event)));
        }

        /// A task's few hundred microseconds, at most a millisecond here.
        fn soon(&mut self, now: u64) -> u64 {
            now + self.rng.below(2)
        }

        fn run(&mut self) -> Result<(), String> {
            while let Some(std::cmp::Reverse((now, _, event))) = self.queue.pop() {
                self.steps += 1;
                if self.steps > 100_000 {
                    return Err("the schedule never settles".into());
                }
                match event {
                    Event::Arrive(index) => self.arrive(index, now)?,
                    Event::Step(destination) => self.step(destination, now)?,
                    Event::Answer(id) => self.answer(id, now),
                    Event::Opened(destination, uid) => self.opened(destination, uid, now)?,
                }
            }
            Ok(())
        }

        fn arrive(&mut self, index: usize, now: u64) -> Result<(), String> {
            let (sent, destination) = self.arrivals[index];
            let came = self.instant(sent.came);
            if let Way::Open(way) = self.ways[destination]
                && self.record.passes(came, way, REASK)
            {
                self.record.left(came);
                return self.leave(sent, way, now);
            }
            let known = self.ways[destination] != Way::Shut && destination != LOOKUP;
            let waiting = &mut self.held[destination];
            if waiting.held.is_empty() {
                waiting.floor = (!known).then_some(came);
            }
            waiting.held.push((came, sent));
            if !waiting.busy {
                waiting.busy = true;
                let when = self.soon(now);
                self.at(when, Event::Step(destination));
            }
            Ok(())
        }

        fn step(&mut self, destination: usize, now: u64) -> Result<(), String> {
            let floor = self.held[destination].floor;
            let Some(first) = self.held[destination].held.first().map(|(came, _)| *came) else {
                self.held[destination].busy = false;
                return Ok(());
            };
            let out = self
                .out
                .and_then(|id| self.questions.get(&id))
                .map(|question| self.instant(question.asked));
            match self
                .record
                .step((first, floor), out, self.instant(now), REASK)
            {
                Step::Join => {
                    if let Some(id) = self.out
                        && let Some(question) = self.questions.get_mut(&id)
                    {
                        question.waiters.push(destination);
                    }
                }
                Step::Ask => {
                    let id = u64::try_from(self.questions.len()).unwrap_or(0) + 1;
                    let uid = self.owner(now);
                    let latency =
                        [0, 2, 20, 80, 150, 300][usize::try_from(self.rng.below(6)).unwrap_or(0)];
                    let waiters = vec![destination];
                    self.questions.insert(
                        id,
                        Question {
                            asked: now,
                            uid,
                            waiters,
                        },
                    );
                    self.out = Some(id);
                    self.at(now + latency, Event::Answer(id));
                }
                Step::Decided(Verdict::Owner(Some(uid))) => {
                    if self.ways[destination] == Way::Open(Some(uid)) {
                        return self.flush(destination, Some(uid), now);
                    }
                    let delay =
                        [0, 1, 10, 60, 200][usize::try_from(self.rng.below(5)).unwrap_or(0)];
                    self.at(now + delay, Event::Opened(destination, Some(uid)));
                }
                Step::Decided(Verdict::Unknown) => return Err("an undecided step".into()),
                // No app Android can name goes nowhere while a chain is on.
                Step::Decided(Verdict::Owner(None)) => {
                    let waiting = &mut self.held[destination];
                    let held = std::mem::take(&mut waiting.held);
                    waiting.held = self.record.settle(held, waiting.floor, None, REASK).rest;
                    self.again(destination, now);
                }
                Step::Decided(Verdict::Drop) => {
                    self.held[destination].held.remove(0);
                    self.again(destination, now);
                }
            }
            Ok(())
        }

        fn answer(&mut self, id: u64, now: u64) {
            let Some(question) = self.questions.get_mut(&id) else {
                return;
            };
            let named = Named {
                uid: question.uid,
                asked: at(self.base, question.asked),
            };
            let waiters = std::mem::take(&mut question.waiters);
            self.answered.push((question.asked, question.uid, now));
            if self.record.note(id, named) {
                self.ways = [Way::Shut; 4];
            }
            let earliest = self
                .held
                .iter()
                .filter_map(|waiting| waiting.held.first())
                .map(|(came, _)| *came)
                .min();
            self.record.keep_from(earliest, REASK);
            if self.out == Some(id) {
                self.out = None;
            }
            for destination in waiters {
                let when = self.soon(now);
                self.at(when, Event::Step(destination));
            }
        }

        fn opened(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
            if !self.record.keeps(uid) {
                self.again(destination, now);
                return Ok(());
            }
            self.ways[destination] = Way::Open(uid);
            self.flush(destination, uid, now)
        }

        fn flush(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
            let waiting = &mut self.held[destination];
            let held = std::mem::take(&mut waiting.held);
            let settled = self.record.settle(held, waiting.floor, uid, REASK);
            waiting.held = settled.rest;
            for (_, sent) in settled.leave {
                self.leave(sent, uid, now)?;
            }
            self.again(destination, now);
            Ok(())
        }

        /// The destination's next step, if a datagram still waits for its way.
        fn again(&mut self, destination: usize, now: u64) {
            if self.held[destination].held.is_empty() {
                self.held[destination].busy = false;
            } else {
                self.at(now, Event::Step(destination));
            }
        }

        /// A datagram leaves under `uid` at `now`. It must be its sender's, or else lie within the window
        /// ADR 0044 states: every answer Android gave by then less than `udp_reask` from it names `uid`,
        /// and one does; or it came after an answer naming `uid`, less than thirty times `udp_reask` after
        /// it, with what left under `uid` since never pausing for `udp_reask`, and no answer since naming
        /// another app.
        fn leave(&mut self, sent: Sent, uid: Option<u32>, now: u64) -> Result<(), String> {
            let reask = u64::try_from(REASK.as_millis()).unwrap_or(100);
            if sent.by != uid {
                let known: Vec<_> = self
                    .answered
                    .iter()
                    .filter(|(_, _, at)| *at <= now)
                    .collect();
                let near: Vec<_> = known
                    .iter()
                    .filter(|(asked, _, _)| asked.abs_diff(sent.came) < reask)
                    .collect();
                let window = !near.is_empty() && near.iter().all(|(_, named, _)| *named == uid);
                let stream = known.iter().any(|(asked, named, _)| {
                    *named == uid
                        && *asked <= sent.came
                        && sent.came - asked < reask * 30
                        && !known.iter().any(|(other, by, _)| {
                            *other > *asked && *other <= sent.came && *by != uid
                        })
                        && {
                            let mut links: Vec<u64> = self
                                .leaves
                                .iter()
                                .filter(|(came, by)| {
                                    *by == uid && came > asked && *came < sent.came
                                })
                                .map(|(came, _)| *came)
                                .collect();
                            links.push(*asked);
                            links.push(sent.came);
                            links.sort_unstable();
                            links.windows(2).all(|pair| pair[1] - pair[0] < reask)
                        }
                });
                if !window && !stream {
                    return Err(format!(
                        "a datagram {} sent at {} ms left under {uid:?} at {now} ms; owners {:?}; answers \
                         (asked, named, answered) {:?}",
                        sent.by.map_or("of no app".into(), |by| format!("of {by}")),
                        sent.came,
                        self.owners,
                        self.answered
                    ));
                }
            }
            self.leaves.push((sent.came, uid));
            Ok(())
        }
    }

    /// The model: thousands of random schedules of handovers between a chained app, a direct app and no
    /// app, datagrams and lookups, Android answering with random latency and so out of order, and ways
    /// opening slowly, at simulated instants. Nothing any app sent leaves under another app beyond the
    /// window ADR 0044 states; in particular nothing a chained app sent leaves directly but within it
    /// (eighth review of unit 9, "the rule in one place"). The failing seed is printed.
    #[test]
    fn no_schedule_sends_a_datagram_under_an_app_that_did_not_send_it() -> Result<(), String> {
        let schedules = std::env::var("WHOSE_SCHEDULES")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(10_000u64);
        for seed in 1..=schedules {
            Schedule::new(seed)
                .run()
                .map_err(|why| format!("seed {seed}: {why}"))?;
        }
        Ok(())
    }
}
