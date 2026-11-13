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
    /// Answers near it name different apps, or one names none: a handover fell near it, and who sent it
    /// cannot be told. It is dropped and counted, never sent under any answer.
    Ambiguous,
    /// The answers near it agree on an app that holds the socket no more: its way would be another
    /// app's now. It is dropped and counted apart.
    Gone,
    /// No answer near it can be had any more: its question could not be asked less than `udp_reask`
    /// from it. It is dropped and counted apart.
    Late,
    /// No answer decides it yet; one asked now would.
    Unknown,
}

impl Verdict {
    /// Whether the datagram goes, never sent.
    pub(super) fn drops(self) -> bool {
        matches!(self, Self::Ambiguous | Self::Gone | Self::Late)
    }
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

/// A datagram that waits for its way, as the rule sees it: when it came, whose the answers said it was
/// then, if they said, and the datagram.
#[derive(Debug)]
pub(super) struct Waiter<T> {
    pub(super) came: Instant,
    pub(super) then: Option<Verdict>,
    pub(super) item: T,
}

/// Datagrams that waited, sorted once their way is there: those that leave by it, those dropped with
/// why, and those, from the first that neither leaves nor drops, that wait on in order.
pub(super) struct Settled<T> {
    pub(super) leave: Vec<Waiter<T>>,
    pub(super) dropped: Vec<(Waiter<T>, Verdict)>,
    pub(super) rest: Vec<Waiter<T>>,
}

impl<T> Settled<T> {
    /// How many were dropped as ambiguous, and how many for coming too late for their app or answer.
    pub(super) fn drops(&self) -> (u64, u64) {
        let ambiguous = self
            .dropped
            .iter()
            .filter(|(_, why)| *why == Verdict::Ambiguous)
            .count();
        let late = self.dropped.len() - ambiguous;
        (ambiguous as u64, late as u64)
    }
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
    /// different apps, a handover fell near it, and it is dropped as ambiguous. One whose answers agree
    /// on an app that has lost the socket since, or that no answer near it can decide, is dropped too,
    /// apart.
    pub(super) fn whose(&self, came: Instant, floor: Option<Instant>, reask: Duration) -> Verdict {
        let Some(newest) = self.newest() else {
            return Verdict::Unknown;
        };
        let since_floor = |asked: Instant| floor.is_none_or(|floor| asked >= floor);
        if came > newest.asked {
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
            return Verdict::Late;
        };
        let last = last.map_or(first, |(&last, _)| last);
        if self.changes.range(first..last).next().is_some() {
            Verdict::Ambiguous
        } else if !since_floor(last.0) {
            Verdict::Late
        } else if uid == newest.uid {
            Verdict::Owner(uid)
        } else {
            Verdict::Gone
        }
    }

    /// Whose a datagram that waits is, which came at `came`: as [`Record::whose`], but one the answers
    /// said was its app's when it came, by the newest answer or the stream since it, stays so for as long
    /// as no answer near it says otherwise, the last answer before it still names that app, and that app
    /// holds the socket, however many questions come after it while it waits (ninth review of unit 9,
    /// finding 4: the model found both).
    pub(super) fn whose_waiting(
        &self,
        (came, then): (Instant, Option<Verdict>),
        floor: Option<Instant>,
        reask: Duration,
    ) -> Verdict {
        match (self.whose(came, floor, reask), then) {
            (Verdict::Late, Some(Verdict::Owner(uid))) => {
                let before = self.answers.range(..=(came, u64::MAX)).next_back();
                if before.is_none_or(|(_, &named)| named != uid) {
                    Verdict::Late
                } else if self.keeps(uid) {
                    Verdict::Owner(uid)
                } else {
                    Verdict::Gone
                }
            }
            (verdict, _) => verdict,
        }
    }

    /// Whose the answers say a datagram that came `came`, and goes behind others that wait, is as it
    /// comes, if they say: it keeps that while it waits.
    pub(super) fn presume(
        &self,
        came: Instant,
        floor: Option<Instant>,
        reask: Duration,
    ) -> Option<Verdict> {
        let verdict = self.whose(came, floor, reask);
        matches!(verdict, Verdict::Owner(_)).then_some(verdict)
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

    /// What a datagram that came at `came` and waits for its way does `now`: the answers decide it; it
    /// joins the question out, asked at `out`, if that can decide it; it asks, if a question asked now
    /// still could; else no answer near enough can be had, and it is dropped as late. The engine asks
    /// this as each datagram comes, and again for the first that waits as answers come, so that a
    /// question is asked less than `reask` from each datagram no answer decides.
    pub(super) fn step(
        &self,
        (came, floor, then): (Instant, Option<Instant>, Option<Verdict>),
        out: Option<Instant>,
        now: Instant,
        reask: Duration,
    ) -> Step {
        match self.whose_waiting((came, then), floor, reask) {
            Verdict::Unknown => {
                let decides = |asked: Instant| {
                    apart(asked, came) < reask && floor.is_none_or(|floor| asked >= floor)
                };
                if out.is_some_and(decides) {
                    Step::Join
                } else if decides(now) {
                    Step::Ask
                } else {
                    Step::Decided(Verdict::Late)
                }
            }
            verdict => Step::Decided(verdict),
        }
    }

    /// Sorts datagrams that waited, in the order they came, once a way of the app `way` is there: each
    /// that app owns leaves, each the rule drops is dropped with why, and from the first of another
    /// app's, or undecided, all wait on.
    pub(super) fn settle<T>(
        &mut self,
        held: Vec<Waiter<T>>,
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
        for waiter in held.by_ref() {
            match self.whose_waiting((waiter.came, waiter.then), floor, reask) {
                Verdict::Owner(uid) if uid == way => {
                    self.left(waiter.came);
                    settled.leave.push(waiter);
                }
                why if why.drops() => settled.dropped.push((waiter, why)),
                _ => {
                    settled.rest.push(waiter);
                    break;
                }
            }
        }
        settled.rest.extend(held);
        settled
    }

    /// Forgets the answers no datagram needs any more. While a datagram of the socket waits, it keeps
    /// every answer asked since `reask` before the first that does, `earliest`, near a waiting datagram
    /// or not, since the later ones came later still; and the last answer before that, on which a
    /// waiting datagram may have been taken for an app. When none waits, it keeps the newest alone.
    pub(super) fn keep_from(&mut self, earliest: Option<Instant>, reask: Duration) {
        let cut = earliest.map(|earliest| earliest.checked_sub(reask).unwrap_or(earliest));
        while self.answers.len() > 1 {
            let mut first_two = self.answers.keys();
            let (Some(&first), Some(&second)) = (first_two.next(), first_two.next()) else {
                return;
            };
            if cut.is_some_and(|cut| second.0 > cut) {
                return;
            }
            self.answers.remove(&first);
            self.changes.remove(&first);
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
        assert_eq!(later.whose(base, None, REASK), Verdict::Late);
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
        assert_eq!(record.whose(base, Some(base), REASK), Verdict::Ambiguous);
        assert_eq!(record.whose(at(base, 40), None, REASK), Verdict::Ambiguous);
        assert_eq!(
            record.whose(at(base, 120), None, REASK),
            Verdict::Owner(DIRECT)
        );
        // One that only the older answer can stand for is the old app's, which holds the socket no more.
        let mut old = Record::default();
        old.note(1, named(CHAINED, at(base, 1)));
        old.note(2, named(DIRECT, at(base, 500)));
        assert_eq!(old.whose(base, Some(base), REASK), Verdict::Gone);
        // No app named is an answer too.
        let mut none = Record::default();
        none.note(1, named(CHAINED, at(base, 1)));
        none.note(2, named(None, at(base, 51)));
        assert_eq!(none.whose(base, None, REASK), Verdict::Ambiguous);
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
        assert_eq!(record.whose(at(base, 120), None, REASK), Verdict::Ambiguous);
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

    /// A datagram taken for its app as it came, by the stream since the newest answer, that waits on
    /// beyond `udp_reask` from every answer stays that app's while the last answer before it names that
    /// app and that app holds the socket. An answer asked before it, but given after it came, that
    /// names another app takes that away (found by the model, ninth review of unit 9).
    #[test]
    fn what_a_waiting_datagram_was_taken_for_holds_while_the_answer_before_it_agrees() {
        let base = Instant::now();
        let streaming = || {
            let mut record = Record::default();
            record.note(1, named(DIRECT, base));
            record.left(at(base, 90));
            record.left(at(base, 180));
            record
        };
        let came = at(base, 250);
        let then = streaming().presume(came, None, REASK);
        assert_eq!(then, Some(Verdict::Owner(DIRECT)));
        let mut agreeing = streaming();
        agreeing.note(3, named(DIRECT, at(base, 600)));
        assert_eq!(agreeing.whose(came, None, REASK), Verdict::Late);
        assert_eq!(
            agreeing.whose_waiting((came, then), None, REASK),
            Verdict::Owner(DIRECT)
        );
        let mut gone = streaming();
        gone.note(3, named(CHAINED, at(base, 600)));
        assert_eq!(gone.whose_waiting((came, then), None, REASK), Verdict::Gone);
        let mut contradicted = streaming();
        contradicted.note(2, named(None, at(base, 120)));
        contradicted.note(3, named(DIRECT, at(base, 600)));
        assert_eq!(
            contradicted.whose_waiting((came, then), None, REASK),
            Verdict::Late
        );
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
            record.step((came, Some(came), None), Some(base), now, REASK),
            Step::Ask
        );
        let since = Some(at(base, 11));
        assert_eq!(
            record.step((came, Some(came), None), since, now, REASK),
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
        assert_eq!(
            record.step((came, None, None), inside, came, REASK),
            Step::Join
        );
        assert_eq!(
            record.step((came, None, None), outside, came, REASK),
            Step::Ask
        );
        let late = came + REASK;
        assert_eq!(
            record.step((came, None, None), None, late, REASK),
            Step::Decided(Verdict::Late)
        );
        let in_time = came + REASK.saturating_sub(nano);
        assert_eq!(
            record.step((came, None, None), None, in_time, REASK),
            Step::Ask
        );
    }

    /// The record keeps the newest answer, and while a datagram waits, every answer since `udp_reask`
    /// before the first that does and the last one before that.
    #[test]
    fn the_record_keeps_what_a_waiting_datagram_needs() {
        let base = Instant::now();
        let mut record = Record::default();
        for (id, ms) in [(1, 0), (2, 300), (3, 450), (4, 900)] {
            record.note(id, named(CHAINED, at(base, ms)));
        }
        record.keep_from(Some(at(base, 500)), REASK);
        assert_eq!(
            record.len(),
            3,
            "the one at 300, the last before the window; the one at 450, and the newest"
        );
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
        let waiter = |ms, item| Waiter {
            came: at(base, ms),
            then: None,
            item,
        };
        let held = vec![
            waiter(5, 'a'),
            waiter(70, 'b'),
            waiter(300, 'c'),
            waiter(80, 'd'),
        ];
        let settled = record.settle(held, None, DIRECT, REASK);
        let names = |items: &[Waiter<char>]| items.iter().map(|w| w.item).collect::<String>();
        let dropped: Vec<_> = settled
            .dropped
            .iter()
            .map(|(w, why)| (w.item, *why))
            .collect();
        assert_eq!(dropped, [('a', Verdict::Ambiguous)]);
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

    /// The tunnel's DNS address, as the model's last destination: lookups always ask on their own, and
    /// a flow of lookups ends once answered.
    const LOOKUP: usize = 3;

    /// A datagram of the model: when it came, which app truly sent it, and the floor of the answers that
    /// may stand for it once it waited for its way.
    #[derive(Clone, Copy, Debug)]
    struct Sent {
        came: u64,
        by: Option<u32>,
        floor: Option<u64>,
    }

    /// What happens next in a schedule, by the millisecond.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Event {
        Arrive(usize),
        Step(usize),
        Answer(u64),
        Opened(usize, Option<u32>),
        Chain(bool),
        FlowEnds(usize),
    }

    /// A question of the model to Android: when it was asked, what it named, how long Android took, and
    /// the destinations that wait for it.
    struct Question {
        asked: u64,
        uid: Option<u32>,
        latency: u64,
        waiters: Vec<usize>,
    }

    /// A destination's way in the model: none, or one of an app.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Way {
        Shut,
        Open(Option<u32>),
    }

    /// A destination's datagrams that wait for its way, as the engine's `Holding`: the floor of the
    /// answers that may stand for them, the datagrams, and whether a step is under way for them.
    #[derive(Default)]
    struct Waiting {
        floor: Option<Instant>,
        held: Vec<Waiter<Sent>>,
        busy: bool,
    }

    /// One random schedule: who holds the port when, what it sends, whether the chain is on, and how
    /// slowly Android answers and ways open, or fail; run against the engine's own rule and steps,
    /// checking every datagram that leaves, and every one dropped.
    struct Schedule {
        base: Instant,
        rng: Rng,
        owners: Vec<(u64, Option<u32>)>,
        arrivals: Vec<(Sent, usize)>,
        chain: bool,
        /// Whether the socket has a way or a datagram that waits, as the engine's `Socket` does: the
        /// record goes with its last way.
        socket: bool,
        record: Record,
        ways: [Way; 4],
        held: [Waiting; 4],
        questions: BTreeMap<u64, Question>,
        out: Option<u64>,
        answered: Vec<(u64, Option<u32>, u64)>,
        /// How many of `answered` the record had when it was last forgotten: what the engine no
        /// longer knows.
        forgotten: usize,
        leaves: Vec<(u64, Option<u32>)>,
        queue: std::collections::BinaryHeap<std::cmp::Reverse<(u64, u64, Event)>>,
        order: u64,
        steps: usize,
    }

    /// A random pick among `choices`.
    fn pick<T: Copy>(rng: &mut Rng, choices: &[T]) -> T {
        choices[usize::try_from(rng.below(choices.len() as u64)).unwrap_or(0)]
    }

    impl Schedule {
        fn new(seed: u64) -> Self {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let apps = [CHAINED, DIRECT, None];
            let mut arrivals = Vec::new();
            let mut time = 0;
            // Bursts and pauses alike, around `udp_reask`; or, in one schedule of three, a stream that
            // never pauses for it, as a call's, at times for longer than thirty times `udp_reask`, and
            // in half of those to destinations it knows alone, with no lookups to ask anew.
            let (count, gaps, destinations): (u64, &[u64], u64) = if rng.below(3) == 0 {
                let destinations = if rng.below(2) == 0 { 3 } else { 4 };
                (60 + rng.below(240), &[0, 1, 5, 30, 60, 90], destinations)
            } else {
                (10 + rng.below(50), &[0, 1, 5, 30, 90, 150, 400], 4)
            };
            for _ in 0..count {
                time += pick(&mut rng, gaps);
                let destination = usize::try_from(rng.below(destinations)).unwrap_or(0);
                let sent = Sent {
                    came: time,
                    by: None,
                    floor: None,
                };
                arrivals.push((sent, destination));
            }
            let mut owners = vec![(0, pick(&mut rng, &apps))];
            // A few handovers while the app sends; or, in one schedule of four, many over a few
            // `udp_reask`, so that answers near one datagram name three apps in turn; or, in one of
            // five, none at all, where nothing may be dropped.
            let (handovers, span) = match rng.below(20) {
                0..5 => (5 + rng.below(15), 400),
                5..9 => (0, 1),
                _ => (rng.below(5), time.max(1)),
            };
            for _ in 0..handovers {
                owners.push((rng.below(span), pick(&mut rng, &apps)));
            }
            owners.sort_unstable_by_key(|(at, _)| *at);
            let mut schedule = Self {
                base: Instant::now(),
                rng,
                owners,
                arrivals,
                chain: true,
                socket: false,
                record: Record::default(),
                ways: [Way::Shut; 4],
                held: Default::default(),
                questions: BTreeMap::new(),
                out: None,
                answered: Vec::new(),
                forgotten: 0,
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
            // In one schedule of three, the chain goes off and on again.
            if schedule.rng.below(3) == 0 {
                let off = schedule.rng.below(time.max(1));
                let on = off + schedule.rng.below(1_000);
                schedule.at(off, Event::Chain(false));
                schedule.at(on, Event::Chain(true));
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

        fn ms(&self, instant: Instant) -> u64 {
            u64::try_from(instant.duration_since(self.base).as_millis()).unwrap_or(u64::MAX)
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
                    Event::Chain(on) => {
                        // A mapping ends when the chain sends its app another way, and a flow of
                        // lookups gives way.
                        self.chain = on;
                        self.ways = [Way::Shut; 4];
                        self.forget_if_idle();
                    }
                    Event::FlowEnds(destination) => {
                        self.ways[destination] = Way::Shut;
                        self.forget_if_idle();
                    }
                }
            }
            match self.held.iter().find_map(|waiting| waiting.held.first()) {
                Some(Waiter { item: sent, .. }) => Err(format!(
                    "a datagram sent at {} ms was never decided",
                    sent.came
                )),
                None => Ok(()),
            }
        }

        /// As the event loop: a datagram for a destination whose datagrams wait goes behind them, and
        /// asks Android as it comes if no answer and no question out can decide it; else it passes by
        /// an open way the rule lets it pass, or waits for its way.
        fn arrive(&mut self, index: usize, now: u64) -> Result<(), String> {
            let (mut sent, destination) = self.arrivals[index];
            let came = self.instant(sent.came);
            if !self.held[destination].held.is_empty() {
                let floor = self.held[destination].floor;
                sent.floor = floor.map(|floor| self.ms(floor));
                let then = self.record.presume(came, floor, REASK);
                let item = sent;
                self.held[destination]
                    .held
                    .push(Waiter { came, then, item });
                let out = self.out_asked();
                if self.record.step((came, floor, then), out, came, REASK) == Step::Ask {
                    self.ask(now, None);
                }
                return Ok(());
            }
            if let Way::Open(way) = self.ways[destination]
                && self.record.passes(came, way, REASK)
            {
                self.record.left(came);
                return self.leave(sent, way, now);
            }
            let known = self.ways[destination] != Way::Shut && destination != LOOKUP;
            let floor = (!known).then_some(came);
            sent.floor = (!known).then_some(sent.came);
            self.socket = true;
            let waiting = &mut self.held[destination];
            waiting.floor = floor;
            waiting.held.push(Waiter {
                came,
                then: None,
                item: sent,
            });
            if !waiting.busy {
                waiting.busy = true;
                let when = self.soon(now);
                self.at(when, Event::Step(destination));
            }
            Ok(())
        }

        /// When the question out was asked, if one is.
        fn out_asked(&self) -> Option<Instant> {
            self.out
                .and_then(|id| self.questions.get(&id))
                .map(|question| self.instant(question.asked))
        }

        /// Asks Android at `now`; Android reads the port's owner a moment later, and answers after a
        /// random latency, some longer than `udp_reask`.
        fn ask(&mut self, now: u64, waiter: Option<usize>) {
            let id = u64::try_from(self.questions.len()).unwrap_or(0) + 1;
            // Android looks the socket up a little after it was asked, never after it answers.
            let latency = pick(&mut self.rng, &[0, 2, 20, 80, 150, 300]);
            let read = now + self.rng.below(latency.min(2) + 1);
            let uid = self.owner(read);
            let waiters = waiter.into_iter().collect();
            let question = Question {
                asked: now,
                uid,
                latency,
                waiters,
            };
            self.questions.insert(id, question);
            self.out = Some(id);
            self.at(now + latency, Event::Answer(id));
        }

        /// As `decide` and `open_udp`: the first datagram that waits is decided, asks, or joins.
        fn step(&mut self, destination: usize, now: u64) -> Result<(), String> {
            let floor = self.held[destination].floor;
            let Some((first, then)) = self.held[destination]
                .held
                .first()
                .map(|waiter| (waiter.came, waiter.then))
            else {
                self.held[destination].busy = false;
                return Ok(());
            };
            let out = self.out_asked();
            match self
                .record
                .step((first, floor, then), out, self.instant(now), REASK)
            {
                Step::Join => {
                    if let Some(id) = self.out
                        && let Some(question) = self.questions.get_mut(&id)
                    {
                        question.waiters.push(destination);
                    }
                }
                Step::Ask => self.ask(now, Some(destination)),
                Step::Decided(Verdict::Unknown) => return Err("an undecided step".into()),
                // No app Android can name goes nowhere while a chain is on.
                Step::Decided(Verdict::Owner(None)) if self.chain => {
                    return self.fail(destination, None, now);
                }
                // As `open_mapped`: a way opens only for the app the newest answer names; for another,
                // what waits is decided again at once.
                Step::Decided(Verdict::Owner(uid)) if !self.record.keeps(uid) => {
                    self.again(destination, now);
                }
                Step::Decided(Verdict::Owner(uid)) => {
                    if self.ways[destination] == Way::Open(uid) {
                        return self.flush(destination, uid, now);
                    }
                    let delay = pick(&mut self.rng, &[0, 1, 10, 60, 200, 400]);
                    self.at(now + delay, Event::Opened(destination, uid));
                }
                Step::Decided(why) => {
                    let sent = self.held[destination].held.remove(0).item;
                    self.dropped(sent, why, now)?;
                    self.again(destination, now);
                }
            }
            Ok(())
        }

        /// As `answered`: the answer is noted if the socket is still known, and a new owner ends every
        /// way.
        fn answer(&mut self, id: u64, now: u64) {
            let Some(question) = self.questions.get_mut(&id) else {
                return;
            };
            let named = Named {
                uid: question.uid,
                asked: at(self.base, question.asked),
            };
            let waiters = std::mem::take(&mut question.waiters);
            if self.socket {
                self.answered.push((question.asked, question.uid, now));
                if self.record.note(id, named) {
                    self.ways = [Way::Shut; 4];
                }
                let earliest = self
                    .held
                    .iter()
                    .filter_map(|waiting| waiting.held.first())
                    .map(|waiter| waiter.came)
                    .min();
                self.record.keep_from(earliest, REASK);
            }
            if self.out == Some(id) {
                self.out = None;
            }
            for destination in waiters {
                let when = self.soon(now);
                self.at(when, Event::Step(destination));
            }
            self.forget_if_idle();
        }

        /// A way opens, or fails (`udp_failed`), or is found another app's than the newest answer's.
        fn opened(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
            // The chain may have come on while a way for no app opened: it goes nowhere then, as the
            // engine routes it again.
            if self.rng.below(10) == 0 || (uid.is_none() && self.chain) {
                return self.fail(destination, uid, now);
            }
            if !self.record.keeps(uid) {
                self.again(destination, now);
                return Ok(());
            }
            self.ways[destination] = Way::Open(uid);
            if destination == LOOKUP {
                let ends = now + pick(&mut self.rng, &[0, 20, 150, 400]);
                self.at(ends, Event::FlowEnds(destination));
            }
            self.flush(destination, uid, now)
        }

        /// As `udp_failed`: what the rule says `uid` sent fails with its way, or goes nowhere. It was still
        /// taken for that app's, so it is held to the same window as what leaves, and carries the app's
        /// stream on.
        fn fail(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
            let waiting = &mut self.held[destination];
            let held = std::mem::take(&mut waiting.held);
            let settled = self.record.settle(held, waiting.floor, uid, REASK);
            waiting.held = settled.rest;
            for waiter in settled.leave {
                self.leave(waiter.item, uid, now)?;
            }
            for (waiter, why) in settled.dropped {
                self.dropped(waiter.item, why, now)?;
            }
            self.again(destination, now);
            Ok(())
        }

        fn flush(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
            let waiting = &mut self.held[destination];
            let held = std::mem::take(&mut waiting.held);
            let settled = self.record.settle(held, waiting.floor, uid, REASK);
            waiting.held = settled.rest;
            for waiter in settled.leave {
                self.leave(waiter.item, uid, now)?;
            }
            for (waiter, why) in settled.dropped {
                self.dropped(waiter.item, why, now)?;
            }
            self.again(destination, now);
            Ok(())
        }

        /// The destination's next step, if a datagram still waits for its way.
        fn again(&mut self, destination: usize, now: u64) {
            if self.held[destination].held.is_empty() {
                self.held[destination].busy = false;
                self.forget_if_idle();
            } else {
                self.at(now, Event::Step(destination));
            }
        }

        /// As `forget`: the record goes with the socket's last way.
        fn forget_if_idle(&mut self) {
            let idle = self.ways.iter().all(|way| *way == Way::Shut)
                && self.held.iter().all(|waiting| waiting.held.is_empty());
            if idle {
                self.socket = false;
                self.record = Record::default();
                self.forgotten = self.answered.len();
            }
        }

        /// A datagram the rule drops: only where a handover lies less than `udp_reask` before it, or
        /// since the last answer before it, on which it may have been taken for an app, or since it
        /// came; or where a question asked since then took Android `udp_reask` or more to answer. Else
        /// the rule lost it for nothing.
        fn dropped(&mut self, sent: Sent, why: Verdict, now: u64) -> Result<(), String> {
            let reask = u64::try_from(REASK.as_millis()).unwrap_or(100);
            let before = self.answered[self.forgotten..]
                .iter()
                .filter(|(asked, _, at)| *asked <= sent.came && *at <= now)
                .map(|(asked, _, _)| *asked)
                .max();
            let from = sent
                .came
                .saturating_sub(reask)
                .min(before.unwrap_or(u64::MAX));
            let handover = self
                .owners
                .iter()
                .skip(1)
                .any(|(at, _)| *at >= from && *at <= now);
            let slow = self.questions.values().any(|question| {
                question.asked + reask > from && question.asked <= now && question.latency >= reask
            });
            if !handover && !slow {
                return Err(format!(
                    "a datagram sent at {} ms was dropped ({why:?}) at {now} ms with no handover near it, and \
                     Android answering in time; owners {:?}; answers (asked, named, answered) {:?}; \
                     questions (asked, latency) {:?}",
                    sent.came,
                    self.owners,
                    self.answered,
                    self.questions
                        .values()
                        .map(|question| (question.asked, question.latency))
                        .collect::<Vec<_>>()
                ));
            }
            Ok(())
        }

        /// A datagram leaves under `uid` at `now`. It must be its sender's, or else lie within the window
        /// ADR 0044 states, by the answers the engine still knows (the record goes with the socket's last
        /// way): every answer Android gave by then less than `udp_reask` from it names `uid`,
        /// and one of them asked since its floor does; or it came after an answer naming `uid` asked
        /// since its floor, less than thirty times `udp_reask` after it, with what left under `uid`
        /// since never pausing for `udp_reask`, and no answer since naming another app.
        fn leave(&mut self, sent: Sent, uid: Option<u32>, now: u64) -> Result<(), String> {
            let reask = u64::try_from(REASK.as_millis()).unwrap_or(100);
            let floor = sent.floor.unwrap_or(0);
            if sent.by != uid {
                let known: Vec<_> = self.answered[self.forgotten..]
                    .iter()
                    .filter(|(_, _, at)| *at <= now)
                    .collect();
                let near: Vec<_> = known
                    .iter()
                    .filter(|(asked, _, _)| asked.abs_diff(sent.came) < reask)
                    .collect();
                let window = near.iter().all(|(_, named, _)| *named == uid)
                    && near.iter().any(|(asked, _, _)| *asked >= floor);
                let stream = known.iter().any(|(asked, named, _)| {
                    *named == uid
                        && *asked < sent.came
                        && *asked >= floor
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
                         (asked, named, answered) {:?}, the first {} forgotten; what left (came, under) \
                         {:?}",
                        sent.by.map_or("of no app".into(), |by| format!("of {by}")),
                        sent.came,
                        self.owners,
                        self.answered,
                        self.forgotten,
                        self.leaves
                    ));
                }
            }
            self.leaves.push((sent.came, uid));
            Ok(())
        }
    }

    /// The model: thousands of random schedules of handovers between a chained app, a direct app and no
    /// app; datagrams and lookups, queued behind those that wait as the engine queues them; Android
    /// reading the owner a moment after it is asked and answering with random latency, so out of order;
    /// ways opening slowly, or failing; the chain going off and on; flows of lookups ending and the
    /// record going with the socket's last way; at simulated instants. Safety: nothing any app sent
    /// leaves under another app beyond the window ADR 0044 states, a destination's floor included; in
    /// particular nothing a chained app sent leaves directly but within it. Liveness: nothing is dropped
    /// unless a handover lies less than `udp_reask` before it or since, or a question Android took
    /// `udp_reask` or more to answer was asked then; and nothing waits for ever (eighth and ninth
    /// reviews of unit 9). The failing seed is printed.
    #[test]
    fn no_schedule_sends_a_datagram_under_an_app_that_did_not_send_it() -> Result<(), String> {
        let schedules = std::env::var("WHOSE_SCHEDULES")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(10_000u64);
        let only: Option<u64> = std::env::var("WHOSE_SEED")
            .ok()
            .and_then(|seed| seed.parse().ok());
        for seed in only.map_or(1..=schedules, |seed| seed..=seed) {
            Schedule::new(seed)
                .run()
                .map_err(|why| format!("seed {seed}: {why}"))?;
        }
        Ok(())
    }
}
