//! The owner rule's model: schedules of handovers, datagrams, lookups, questions to Android and ways,
//! run against the rule ([`Record`]) and the engine's steps around it as the engine takes them, with
//! every datagram that leaves, fails with its way, or is dropped checked against who truly sent it
//! (ADR 0044, unit 9, "The model").

use super::{Named, Record, Step, Verdict, Waiter};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const REASK: Duration = Duration::from_millis(100);
const CHAINED: Option<u32> = Some(10_300);
const DIRECT: Option<u32> = Some(10_400);

/// `ms` milliseconds after `base`.
fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
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
                    && !known
                        .iter()
                        .any(|(other, by, _)| *other > *asked && *other <= sent.came && *by != uid)
                    && {
                        let mut links: Vec<u64> = self
                            .leaves
                            .iter()
                            .filter(|(came, by)| *by == uid && came > asked && *came < sent.came)
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
