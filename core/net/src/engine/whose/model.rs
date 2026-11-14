//! The owner rule's model: schedules of handovers, datagrams, lookups, questions to Android and ways,
//! run against the rule ([`Record`]) and the engine's steps around it as the engine takes them, with
//! every datagram that leaves, fails with its way, or is dropped checked against who truly sent it
//! (ADR 0044, unit 9, "The model").
//!
//! The schedules come two ways. Random ones, from a seed, are long: streams of hundreds of datagrams
//! over seconds. The exhaustive search walks every schedule up to small bounds instead, on a grid of
//! time where `udp_reask` is two steps, so that every window's edge falls on a step and on either side
//! of it: each choice a schedule makes, whose the port is and when, when each datagram comes and where
//! to, how slowly Android answers and reads the socket, how slowly a way opens or whether it fails,
//! when the chain turns, and which of the events that fall on one instant runs first, is taken every
//! way, depth first.
//!
//! Beside its bounds ([`Bounds`]), the search takes as given what makes it finite: time moves in steps,
//! and each delay is one of the grid's; Android reads the socket at its question or a step after; the
//! port changes hands at a step before anything else that falls on it; the datagrams of one instant
//! come in the order of their destinations; and two paths that reach one state share what follows,
//! the state folded into 128 bits. Like the random schedules, it drives the model's own copy of the
//! engine's steps, not the engine, and puts no question for what only comes in.

use super::{Named, Record, Step, Verdict, Waiter};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CHAINED: Option<u32> = Some(10_300);
const DIRECT: Option<u32> = Some(10_400);

/// `ms` milliseconds after `base`: the model's steps of time are milliseconds.
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

/// The choices one path through the exhaustive search makes: each taken, out of how many. The search
/// replays a path from the start, and takes the first value of every choice beyond it.
#[derive(Clone, Default)]
struct Script {
    path: Vec<(u32, u32)>,
    /// How many of `path` this run has read.
    read: usize,
    /// How many of `path`, from the start, the search may not change: the part a worker was given.
    fixed: usize,
    /// How many choices a run may make before it stops, to split the search among workers.
    depth: Option<usize>,
    /// Whether this run needed a choice beyond `depth`.
    deep: bool,
}

impl Script {
    fn choose(&mut self, of: usize) -> usize {
        let of = u32::try_from(of).unwrap_or(u32::MAX);
        if of <= 1 {
            return 0;
        }
        if let Some(&(taken, was)) = self.path.get(self.read) {
            assert_eq!(was, of, "the model took another path on replay");
            self.read += 1;
            return taken as usize;
        }
        if self.depth.is_some_and(|depth| self.read >= depth) {
            self.deep = true;
            return 0;
        }
        self.path.push((0, of));
        self.read += 1;
        0
    }

    /// The next path, depth first: the last choice not yet at its last value takes the next, and every
    /// choice after it starts over. False once every path was walked.
    fn next(&mut self) -> bool {
        self.path.truncate(self.read);
        self.read = 0;
        self.deep = false;
        while self.path.len() > self.fixed {
            if let Some((taken, of)) = self.path.pop()
                && taken + 1 < of
            {
                self.path.push((taken + 1, of));
                return true;
            }
        }
        false
    }
}

/// Where a schedule's choices come from: a seeded generator, or the exhaustive search's script.
enum Choices {
    Random(Rng),
    Script(Script),
}

impl Choices {
    /// A number in `0..of`.
    fn choose(&mut self, of: usize) -> usize {
        match self {
            Self::Random(rng) => usize::try_from(rng.below(of as u64)).unwrap_or(0),
            Self::Script(script) => script.choose(of),
        }
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        from[self.choose(from.len())]
    }
}

/// The delays a schedule draws from, in the model's milliseconds, and what else differs between the
/// random schedules and the exhaustive search.
#[derive(Clone, Copy, Debug, Hash)]
struct Grid {
    /// `udp_reask`.
    reask: u64,
    /// How long Android takes to answer.
    latencies: &'static [u64],
    /// How long after a question Android may read the socket, at most, and never after it answers.
    read_gap: u64,
    /// How long a task may take to run, at most.
    soon: u64,
    /// How long a way takes to open, or to fail.
    delays: &'static [u64],
    /// One way in so many fails as it opens.
    fails_one_in: usize,
    /// How long a flow of lookups lives once open.
    flow_ends: &'static [u64],
    /// Whether events that fall on one instant run in every order: the exhaustive search's stand-in
    /// for what happens within one step of its grid.
    ties: bool,
    /// How many events a schedule may take before it is found never to settle.
    steps: usize,
}

/// The random schedules' delays: `udp_reask` of 100 ms, Android's answers and ways from at once to
/// three times that.
const RANDOM: Grid = Grid {
    reask: 100,
    latencies: &[0, 2, 20, 80, 150, 300],
    read_gap: 2,
    soon: 1,
    delays: &[0, 1, 10, 60, 200, 400],
    fails_one_in: 10,
    flow_ends: &[0, 20, 150, 400],
    ties: false,
    steps: 100_000,
};

/// The exhaustive search's grid: `udp_reask` is two steps, so that each window's edge, `udp_reask` and
/// thirty times it, lies on a step with a step on either side; every delay is at once, a step, the
/// window, or a step beyond it; a way fails or opens; tasks take no time, and events on one instant run
/// in every order instead.
const GRID: Grid = Grid {
    reask: 2,
    latencies: &[0, 1, 2, 3],
    read_gap: 1,
    soon: 0,
    delays: &[0, 1, 2, 3],
    fails_one_in: 2,
    flow_ends: &[0, 1, 2, 3],
    ties: true,
    steps: 10_000,
};

/// The coarse grid, for larger schedules: Android answers, and a way opens or fails, at once or a step
/// past `udp_reask`.
const COARSE: Grid = Grid {
    latencies: &[0, 3],
    delays: &[0, 3],
    flow_ends: &[0, 3],
    ..GRID
};

/// The bounds of an exhaustive search.
#[derive(Clone, Copy, Debug, Hash)]
struct Bounds {
    /// The grid: the fine one, [`GRID`], or [`COARSE`], either with slow ways ([`slow`]).
    grid: Grid,
    /// The last instant, in steps, at which a handover, a datagram or the chain's turn may fall.
    horizon: u64,
    /// Datagrams, besides a run's, that may come at one instant.
    together: usize,
    /// Handovers, each to another app than the one before: the chained app, the direct app, or none.
    handovers: usize,
    /// Datagrams, besides a run's.
    datagrams: usize,
    /// How many destinations they may go to, a run's included, the tunnel's DNS address apart.
    destinations: usize,
    /// Whether they may be lookups to the tunnel's DNS address too.
    lookups: bool,
    /// Questions to Android: a schedule that would ask one more is cut there.
    questions: usize,
    /// Whether the chain may turn, on or off, once.
    chain_turns: bool,
    /// A run: a datagram to the first destination at every step, from any instant, for at least and at
    /// most so many steps. A run never pauses, so it carries a stream: to thirty times `udp_reask`, or
    /// past an answer far enough back that only the stream decides what comes after.
    run: Option<(u64, u64)>,
}

/// Where a run stands.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Run {
    Before,
    Since(u64),
    Over,
}

/// The exhaustive search's world as it unfolds. At each step of the grid up to the horizon, before
/// what is queued for that instant runs, it chooses whether the port changes hands and to whom,
/// whether the chain turns, whether a run starts, goes on or stops, and how many datagrams come, and
/// where to. So schedules that begin alike share the search of their beginning.
#[derive(Clone, Copy, Debug, Hash)]
struct World {
    bounds: Bounds,
    /// The next step it acts at; none once it can do nothing more.
    tick: Option<u64>,
    /// What it may still do.
    handovers: usize,
    datagrams: usize,
    turn: bool,
    run: Run,
    /// How many destinations it has sent to, a run's first.
    used: usize,
    /// Whether an app has held the port yet: the chained and the direct app are alike to the rule, so
    /// the first app to hold it is the chained one.
    named: bool,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Event {
    Arrive(usize),
    Step(usize),
    Read(u64),
    Answer(u64),
    Opened(usize, Option<u32>),
    Chain(bool),
    FlowEnds(usize),
}

/// A question of the model to Android: when it was asked, what it named once Android read the socket,
/// how long Android took, and the destinations that wait for it.
struct Question {
    asked: u64,
    uid: Option<u32>,
    read: bool,
    latency: u64,
    waiters: Vec<usize>,
}

/// A destination's way in the model: none, or one of an app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    Shut,
    Open(Option<u32>),
}

/// A destination's datagrams that wait for their way, as the engine's `Holding`: the floor of the
/// answers that may stand for them, the datagrams, and whether a step is under way for them.
#[derive(Default)]
struct Waiting {
    floor: Option<Instant>,
    held: Vec<Waiter<Sent>>,
    busy: bool,
}

/// Why a path through a schedule stopped before its end: not at all, at the bound on questions, at a
/// state the search had walked on another path, at the depth that splits the search, or because the
/// world sent nothing at the start, which is a schedule that starts later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stopped {
    No,
    Cut,
    Seen,
    Deep,
    Redundant,
}

/// One schedule: who holds the port when, what it sends, whether the chain is on, and how slowly
/// Android answers and ways open, or fail; run against the engine's own rule and steps, checking every
/// datagram that leaves, and every one dropped.
struct Schedule {
    base: Instant,
    grid: Grid,
    reask: Duration,
    choices: Choices,
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
    /// How many questions the schedule may ask: one more cuts it there.
    most_questions: usize,
    /// Whether it stopped early, and why.
    stopped: Stopped,
    out: Option<u64>,
    answered: Vec<(u64, Option<u32>, u64)>,
    /// How many of `answered` the record had when it was last forgotten: what the engine no
    /// longer knows.
    forgotten: usize,
    leaves: Vec<(u64, Option<u32>)>,
    queue: BTreeSet<(u64, u64, Event)>,
    order: u64,
    steps: usize,
    /// The exhaustive search's world, which chooses who holds the port and what comes as it goes.
    world: Option<World>,
}

impl Schedule {
    fn empty(grid: Grid, choices: Choices) -> Self {
        Self {
            base: Instant::now(),
            grid,
            reask: Duration::from_millis(grid.reask),
            choices,
            owners: Vec::new(),
            arrivals: Vec::new(),
            chain: true,
            socket: false,
            record: Record::default(),
            ways: [Way::Shut; 4],
            held: Default::default(),
            questions: BTreeMap::new(),
            most_questions: usize::MAX,
            stopped: Stopped::No,
            out: None,
            answered: Vec::new(),
            forgotten: 0,
            leaves: Vec::new(),
            queue: BTreeSet::new(),
            order: 0,
            steps: 0,
            world: None,
        }
    }

    /// A random schedule, from `seed`.
    fn new(seed: u64) -> Self {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let apps = [CHAINED, DIRECT, None];
        let pick = |rng: &mut Rng, choices: &[u64]| {
            choices[usize::try_from(rng.below(choices.len() as u64)).unwrap_or(0)]
        };
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
        let first = apps[usize::try_from(rng.below(3)).unwrap_or(0)];
        let mut owners = vec![(0, first)];
        // A few handovers while the app sends; or, in one schedule of four, many over a few
        // `udp_reask`, so that answers near one datagram name three apps in turn; or, in one of
        // five, none at all, where nothing may be dropped.
        let (handovers, span) = match rng.below(20) {
            0..5 => (5 + rng.below(15), 400),
            5..9 => (0, 1),
            _ => (rng.below(5), time.max(1)),
        };
        for _ in 0..handovers {
            let at = rng.below(span);
            owners.push((at, apps[usize::try_from(rng.below(3)).unwrap_or(0)]));
        }
        owners.sort_unstable_by_key(|(at, _)| *at);
        let mut schedule = Self::empty(RANDOM, Choices::Random(rng));
        schedule.owners = owners;
        schedule.arrivals = arrivals;
        schedule.queue_arrivals();
        // In one schedule of three, the chain goes off and on again.
        if schedule.choices.choose(3) == 0 {
            let off = schedule.choose_below(time.max(1));
            let on = off + schedule.choose_below(1_000);
            schedule.at(off, Event::Chain(false));
            schedule.at(on, Event::Chain(true));
        }
        schedule
    }

    /// The schedule `script` takes within `bounds`, on their grid: who holds the port at the start, the
    /// chained app or none, and whether the chain is on, where that matters; the world does the rest
    /// as it goes ([`World`]).
    fn exhaustive(bounds: Bounds, script: Script) -> Self {
        assert!(bounds.destinations <= 3 && bounds.run.is_none_or(|(least, most)| least <= most));
        let mut schedule = Self::empty(bounds.grid, Choices::Script(script));
        schedule.most_questions = bounds.questions;
        let first = schedule.choices.pick(&[CHAINED, None]);
        schedule.owners = vec![(0, first)];
        // Whether the chain is on matters only for an app Android cannot name.
        schedule.chain =
            (first.is_some() && bounds.handovers == 0) || schedule.choices.choose(2) == 0;
        schedule.world = Some(World {
            bounds,
            tick: Some(0),
            handovers: bounds.handovers,
            datagrams: bounds.datagrams,
            turn: bounds.chain_turns,
            run: Run::Before,
            used: usize::from(bounds.run.is_some()),
            named: first.is_some(),
        });
        schedule
    }

    /// The world acts at the step `tick`: the port may change hands, the chain turn, a run start, go on
    /// or stop, and datagrams come, those of one instant in the order of their destinations. At the
    /// start, something comes.
    fn act(&mut self, tick: u64) {
        let Some(mut world) = self.world else {
            return;
        };
        let bounds = world.bounds;
        if world.handovers > 0 && tick > 0 {
            let before = self.owner(tick);
            let mut next = vec![None];
            next.extend(
                [CHAINED, DIRECT, None]
                    .into_iter()
                    .filter(|uid| *uid != before && (world.named || *uid != DIRECT))
                    .map(Some),
            );
            if let Some(uid) = self.choices.pick(&next) {
                self.owners.push((tick, uid));
                world.handovers -= 1;
                world.named |= uid.is_some();
            }
        }
        if world.turn && self.choices.choose(2) == 1 {
            world.turn = false;
            self.at(tick, Event::Chain(!self.chain));
        }
        let mut destinations = Vec::new();
        if let Some((least, most)) = bounds.run {
            match world.run {
                Run::Before if tick + least <= bounds.horizon => {
                    if self.choices.choose(2) == 1 {
                        world.run = Run::Since(tick);
                        destinations.push(0);
                    }
                }
                Run::Since(start) => {
                    let steps = tick - start;
                    let on = steps <= least || (steps <= most && self.choices.choose(2) == 0);
                    if on {
                        destinations.push(0);
                    } else {
                        world.run = Run::Over;
                    }
                }
                _ => {}
            }
        }
        let least = usize::from(tick == 0 && destinations.is_empty());
        let most = world.datagrams.min(bounds.together);
        if most < least {
            self.stopped = Stopped::Redundant;
            return;
        }
        let count = least + self.choices.choose(most - least + 1);
        let mut lowest = 0;
        for _ in 0..count {
            let mut options: Vec<usize> = (0..world.used).collect();
            if world.used < bounds.destinations {
                options.push(world.used);
            }
            if bounds.lookups {
                options.push(LOOKUP);
            }
            let at = lowest + self.choices.choose(options.len() - lowest);
            lowest = at;
            let destination = options[at];
            if destination == world.used {
                world.used += 1;
            }
            destinations.push(destination);
        }
        world.datagrams -= count;
        for destination in destinations {
            let sent = Sent {
                came: tick,
                by: self.owner(tick),
                floor: None,
            };
            self.arrivals.push((sent, destination));
            let index = self.arrivals.len() - 1;
            self.at(tick, Event::Arrive(index));
        }
        let more = world.handovers > 0
            || world.datagrams > 0
            || world.turn
            || matches!(world.run, Run::Since(_))
            || (world.run == Run::Before
                && bounds
                    .run
                    .is_some_and(|(least, _)| tick + 1 + least <= bounds.horizon));
        world.tick = (more && tick < bounds.horizon).then_some(tick + 1);
        self.world = Some(world);
    }

    /// Whether the schedule has made every choice its script replays, and makes new ones from here.
    fn past_the_script(&self) -> bool {
        match &self.choices {
            Choices::Script(script) => script.read >= script.path.len() && !script.deep,
            Choices::Random(_) => false,
        }
    }

    /// What the rest of the schedule depends on, its checks included, folded into 128 bits: what is
    /// queued, what the record holds, the ways, what waits, the questions, the world and who held the
    /// port, and what the checks look back at, the answers since the record was last forgotten and
    /// what left.
    fn state(&self) -> u128 {
        let ms = |instant: Instant| self.ms(instant);
        let verdict = |verdict: Option<Verdict>| match verdict {
            None => (0, None),
            Some(Verdict::Owner(uid)) => (1, uid),
            Some(Verdict::Ambiguous) => (2, None),
            Some(Verdict::Gone) => (3, None),
            Some(Verdict::Late) => (4, None),
            Some(Verdict::Unknown) => (5, None),
        };
        let mut queued: Vec<_> = self
            .queue
            .iter()
            .map(|&(at, _, event)| {
                let arrival = match event {
                    Event::Arrive(index) => self
                        .arrivals
                        .get(index)
                        .map(|(sent, to)| (sent.came, sent.by, *to)),
                    _ => None,
                };
                (at, event, arrival)
            })
            .collect();
        queued.sort_unstable();
        let answers: Vec<_> = self
            .record
            .answers
            .iter()
            .map(|(&(asked, id), &uid)| (ms(asked), id, uid))
            .collect();
        let changes: Vec<_> = self
            .record
            .changes
            .iter()
            .map(|&(asked, id)| (ms(asked), id))
            .collect();
        let held: Vec<_> = self
            .held
            .iter()
            .map(|waiting| {
                let waiters: Vec<_> = waiting
                    .held
                    .iter()
                    .map(|waiter| {
                        let sent = waiter.item;
                        (
                            ms(waiter.came),
                            verdict(waiter.then),
                            sent.came,
                            sent.by,
                            sent.floor,
                        )
                    })
                    .collect();
                (waiting.floor.map(ms), waiting.busy, waiters)
            })
            .collect();
        let questions: Vec<_> = self
            .questions
            .iter()
            .map(|(id, question)| {
                (
                    *id,
                    question.asked,
                    question.uid,
                    question.read,
                    question.latency,
                    question.waiters.clone(),
                )
            })
            .collect();
        let mut known = self.answered[self.forgotten..].to_vec();
        known.sort_unstable();
        let mut leaves = self.leaves.clone();
        leaves.sort_unstable();
        let ways: Vec<_> = self
            .ways
            .iter()
            .map(|way| match way {
                Way::Shut => (0, None),
                Way::Open(uid) => (1, *uid),
            })
            .collect();
        let fold = |salt: u8| {
            let mut hasher = DefaultHasher::new();
            salt.hash(&mut hasher);
            queued.hash(&mut hasher);
            answers.hash(&mut hasher);
            changes.hash(&mut hasher);
            self.record.sent.map(ms).hash(&mut hasher);
            held.hash(&mut hasher);
            questions.hash(&mut hasher);
            known.hash(&mut hasher);
            leaves.hash(&mut hasher);
            ways.hash(&mut hasher);
            (self.out, self.chain, self.socket).hash(&mut hasher);
            (self.world, &self.owners).hash(&mut hasher);
            hasher.finish()
        };
        u128::from(fold(1)) << 64 | u128::from(fold(2))
    }

    /// The script this schedule took, to take the next.
    fn script(self) -> Script {
        match self.choices {
            Choices::Script(script) => script,
            Choices::Random(_) => Script::default(),
        }
    }

    fn queue_arrivals(&mut self) {
        for index in 0..self.arrivals.len() {
            let came = self.arrivals[index].0.came;
            self.arrivals[index].0.by = self.owner(came);
            self.at(came, Event::Arrive(index));
        }
    }

    fn choose_below(&mut self, n: u64) -> u64 {
        self.choices
            .choose(usize::try_from(n).unwrap_or(usize::MAX)) as u64
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
        self.queue.insert((ms, self.order, event));
    }

    /// A task's few hundred microseconds, at most a millisecond in a random schedule.
    fn soon(&mut self, now: u64) -> u64 {
        now + self.choose_below(self.grid.soon + 1)
    }

    /// The next event: the earliest, or, where the grid says so, any of those that fall on that
    /// instant, but datagrams in the order they came, and the same event twice as one.
    fn next_event(&mut self) -> Option<(u64, Event)> {
        while let Some(tick) = self.world.and_then(|world| world.tick) {
            if self.queue.first().is_some_and(|&(at, _, _)| at < tick) {
                break;
            }
            self.act(tick);
            if self.stopped != Stopped::No {
                return None;
            }
        }
        let &(now, _, _) = self.queue.first()?;
        let mut tied: Vec<(u64, u64, Event)> = Vec::new();
        if self.grid.ties {
            let mut arrival = false;
            for &(time, order, event) in &self.queue {
                if time != now {
                    break;
                }
                // Android reading the socket comes out the same whatever runs beside it.
                if matches!(event, Event::Read(_)) {
                    tied = vec![(time, order, event)];
                    break;
                }
                if matches!(event, Event::Arrive(_)) {
                    if arrival {
                        continue;
                    }
                    arrival = true;
                }
                if !tied.iter().any(|(_, _, other)| *other == event) {
                    tied.push((time, order, event));
                }
            }
        }
        let chosen = match tied.len() {
            0 => *self.queue.first()?,
            n => tied[self.choices.choose(n)],
        };
        self.queue.remove(&chosen);
        Some((now, chosen.2))
    }

    fn run(&mut self) -> Result<(), String> {
        self.walk(None)
    }

    /// Runs the schedule. With `seen`, the states the search walked on other paths through it: once
    /// this path is past the choices it replays, a state seen before ends it, since what follows was
    /// walked from there already; a state seen before on this very path is a loop that never settles.
    fn walk(&mut self, seen: Option<&Seen>) -> Result<(), String> {
        let mut mine = HashSet::new();
        loop {
            if let Some(seen) = seen
                && self.past_the_script()
            {
                let state = self.state();
                if !mine.insert(state) {
                    return Err(format!("the schedule never settles; {}", self.story()));
                }
                if !seen.insert(state) {
                    self.stopped = Stopped::Seen;
                    return Ok(());
                }
            }
            let Some((now, event)) = self.next_event() else {
                break;
            };
            self.steps += 1;
            if self.steps > self.grid.steps {
                return Err("the schedule never settles".into());
            }
            match event {
                Event::Arrive(index) => self.arrive(index, now)?,
                Event::Step(destination) => self.step(destination, now)?,
                Event::Read(id) => self.read(id, now),
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
            if matches!(&self.choices, Choices::Script(script) if script.deep) {
                self.stopped = Stopped::Deep;
            }
            if self.stopped != Stopped::No {
                return Ok(());
            }
        }
        if self.stopped != Stopped::No {
            return Ok(());
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
        let reask = self.reask;
        if !self.held[destination].held.is_empty() {
            let floor = self.held[destination].floor;
            sent.floor = floor.map(|floor| self.ms(floor));
            let then = self.record.presume(came, floor, reask);
            let item = sent;
            self.held[destination]
                .held
                .push(Waiter { came, then, item });
            let out = self.out_asked();
            if self.record.step((came, floor, then), out, came, reask) == Step::Ask {
                self.ask(now, None);
            }
            return Ok(());
        }
        if let Way::Open(way) = self.ways[destination]
            && self.record.passes(came, way, reask)
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
    /// latency of the grid's, some longer than `udp_reask`. One question beyond the bounds cuts the
    /// schedule.
    fn ask(&mut self, now: u64, waiter: Option<usize>) {
        if self.questions.len() >= self.most_questions {
            self.stopped = Stopped::Cut;
            return;
        }
        let id = u64::try_from(self.questions.len()).unwrap_or(0) + 1;
        // Android looks the socket up a little after it was asked, never after it answers.
        let latency = self.choices.pick(self.grid.latencies);
        // Where the world can hand the port over no more, every reading names the same app.
        let still = self.world.is_some_and(|world| world.handovers == 0);
        let gap = if still {
            0
        } else {
            latency.min(self.grid.read_gap)
        };
        let read = now + self.choose_below(gap + 1);
        let waiters = waiter.into_iter().collect();
        let question = Question {
            asked: now,
            uid: None,
            read: false,
            latency,
            waiters,
        };
        self.questions.insert(id, question);
        self.out = Some(id);
        if read == now {
            self.read(id, now);
        } else {
            self.at(read, Event::Read(id));
        }
        self.at(now + latency, Event::Answer(id));
    }

    /// Android reads the socket's owner for the question `id`, once.
    fn read(&mut self, id: u64, now: u64) {
        let owner = self.owner(now);
        if let Some(question) = self.questions.get_mut(&id)
            && !question.read
        {
            question.uid = owner;
            question.read = true;
        }
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
            .step((first, floor, then), out, self.instant(now), self.reask)
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
                let delay = self.choices.pick(self.grid.delays);
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
        self.read(id, now);
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
            self.record.keep_from(earliest, self.reask);
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
        if self.choices.choose(self.grid.fails_one_in) == 0 || (uid.is_none() && self.chain) {
            return self.fail(destination, uid, now);
        }
        if !self.record.keeps(uid) {
            self.again(destination, now);
            return Ok(());
        }
        self.ways[destination] = Way::Open(uid);
        if destination == LOOKUP {
            let ends = now + self.choices.pick(self.grid.flow_ends);
            self.at(ends, Event::FlowEnds(destination));
        }
        self.flush(destination, uid, now)
    }

    /// As `udp_failed`: what the rule says `uid` sent fails with its way, or goes nowhere. It was still
    /// taken for that app's, so it is held to the same window as what leaves, and carries the app's
    /// stream on.
    fn fail(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
        self.flush(destination, uid, now)
    }

    /// What waits for `destination` is sorted once a way of `uid` is there: what leaves is checked
    /// against who sent it, what is dropped against the handovers, and what is counted against why.
    fn flush(&mut self, destination: usize, uid: Option<u32>, now: u64) -> Result<(), String> {
        let waiting = &mut self.held[destination];
        let held = std::mem::take(&mut waiting.held);
        let settled = self.record.settle(held, waiting.floor, uid, self.reask);
        let drops = settled.drops();
        waiting.held = settled.rest;
        let ambiguous = settled
            .dropped
            .iter()
            .filter(|(_, why)| *why == Verdict::Ambiguous)
            .count() as u64;
        let counted = (ambiguous, settled.dropped.len() as u64 - ambiguous);
        if drops != counted {
            return Err(format!(
                "drops counted as {drops:?}, by their verdicts {counted:?}"
            ));
        }
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
        let reask = self.grid.reask;
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
                 Android answering in time; {}",
                sent.came,
                self.story()
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
        let reask = self.grid.reask;
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
                    "a datagram {} sent at {} ms left under {uid:?} at {now} ms; {}",
                    sent.by.map_or("of no app".into(), |by| format!("of {by}")),
                    sent.came,
                    self.story()
                ));
            }
        }
        self.leaves.push((sent.came, uid));
        Ok(())
    }

    /// What happened, for a failure's message.
    fn story(&self) -> String {
        format!(
            "owners {:?}; datagrams (came, to) {:?}; questions (asked, latency) {:?}; answers (asked, \
             named, answered) {:?}, the first {} forgotten; what left (came, under) {:?}",
            self.owners,
            self.arrivals
                .iter()
                .map(|(sent, to)| (sent.came, *to))
                .collect::<Vec<_>>(),
            self.questions
                .values()
                .map(|question| (question.asked, question.latency))
                .collect::<Vec<_>>(),
            self.answered,
            self.forgotten,
            self.leaves
        )
    }
}

/// The states an exhaustive search has walked, shared by its workers, in shards so that they seldom
/// wait for each other.
struct Seen(Vec<Mutex<HashSet<u128>>>);

impl Seen {
    fn new() -> Self {
        Self((0..64).map(|_| Mutex::new(HashSet::new())).collect())
    }

    /// Notes `state`; false if it was noted before.
    fn insert(&self, state: u128) -> bool {
        let shard = usize::try_from(state % 64).unwrap_or(0);
        self.0[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(state)
    }

    fn len(&self) -> usize {
        self.0
            .iter()
            .map(|shard| shard.lock().map_or(0, |set| set.len()))
            .sum()
    }
}

/// What an exhaustive search walked: the paths that ran to their end, those the bound on questions
/// cut, those that reached a state walked before, and the states.
#[derive(Debug, Default)]
struct Tally {
    ended: u64,
    cut: u64,
    seen: u64,
    states: usize,
}

/// How many choices from the start split the search among its workers.
const SPLIT: usize = 8;

/// Walks every schedule within `bounds`, depth first, on up to `workers` threads: every way the first
/// [`SPLIT`] choices go is listed first, and each worker then takes one at a time and walks every path
/// that begins so. A state any worker walked before ends a path.
fn exhaust(bounds: Bounds, workers: usize) -> Result<Tally, String> {
    let mut starts = Vec::new();
    let mut script = Script {
        depth: Some(SPLIT),
        ..Script::default()
    };
    loop {
        let mut schedule = Schedule::exhaustive(bounds, script);
        let _ = schedule.walk(None);
        script = schedule.script();
        starts.push(script.path[..script.read].to_vec());
        if !script.next() {
            break;
        }
    }
    let seen = Seen::new();
    let next = AtomicUsize::new(0);
    let (ended, cut, again) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    let failure = Mutex::new(None::<String>);
    let workers = std::thread::available_parallelism().map_or(1, |cores| workers.min(cores.get()));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = starts.get(index) else {
                        return;
                    };
                    let mut script = Script {
                        path: path.clone(),
                        fixed: path.len(),
                        ..Script::default()
                    };
                    loop {
                        let mut schedule = Schedule::exhaustive(bounds, script);
                        let result = schedule.walk(Some(&seen));
                        match schedule.stopped {
                            Stopped::Cut => &cut,
                            Stopped::Seen => &again,
                            _ => &ended,
                        }
                        .fetch_add(1, Ordering::Relaxed);
                        script = schedule.script();
                        if let Err(why) = result {
                            failure
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .get_or_insert(format!(
                                    "{bounds:?}, path {:?}: {why}",
                                    &script.path[..script.read]
                                ));
                            next.store(usize::MAX / 2, Ordering::Relaxed);
                            return;
                        }
                        if !script.next() {
                            break;
                        }
                    }
                }
            });
        }
    });
    if let Some(why) = failure
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return Err(why);
    }
    Ok(Tally {
        ended: ended.into_inner(),
        cut: cut.into_inner(),
        seen: again.into_inner(),
        states: seen.len(),
    })
}

/// Runs the searches `sets`, each named and its bounds given as [`bounds`] reads them, on up to
/// `workers` threads, printing what each walked and how long it took.
fn exhaust_all(sets: &[(&str, &str)], workers: usize) -> Result<(), String> {
    for (name, given) in sets {
        let bounds = bounds(given).ok_or(format!(
            "{name}: bounds {given:?} not as `bounds` reads them"
        ))?;
        let started = std::time::Instant::now();
        let tally = exhaust(bounds, workers).map_err(|why| format!("{name}: {why}"))?;
        eprintln!(
            "{name} ({given}): {} states; {} paths to their end, {} cut at the bound on questions, \
             {} ending in a state walked before; in {:.1?}",
            tally.states,
            tally.ended,
            tally.cut,
            tally.seen,
            started.elapsed()
        );
    }
    Ok(())
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

/// Bounds as `horizon,handovers,datagrams,together,destinations,lookups,questions,chain,run,coarse`
/// and, if given, `slow`: the flags as 0 or 1, and the run as `shortest-longest` or `-`.
fn bounds(given: &str) -> Option<Bounds> {
    let parts: Vec<&str> = given.split(',').map(str::trim).collect();
    let number = |at: usize| parts.get(at).and_then(|part| part.parse::<u64>().ok());
    let count = |at: usize| number(at).and_then(|n| usize::try_from(n).ok());
    Some(Bounds {
        horizon: number(0)?,
        handovers: count(1)?,
        datagrams: count(2)?,
        together: count(3)?,
        destinations: count(4)?,
        lookups: number(5)? == 1,
        questions: count(6)?,
        chain_turns: number(7)? == 1,
        run: parts.get(8).and_then(|run| {
            let (shortest, longest) = run.split_once('-')?;
            Some((shortest.parse().ok()?, longest.parse().ok()?))
        }),
        grid: match (number(9)?, number(10).unwrap_or(0)) {
            (0, 0) => GRID,
            (1, 0) => COARSE,
            (coarse @ (0 | 1), 1) => slow(coarse == 1),
            _ => return None,
        },
    })
}

/// The fine grid, or the coarse one, where a way may also take three times `udp_reask` to open, or to
/// fail, as behind a slow `protect` or a tool's slow handshake: what waits behind it then outlives the
/// answers near it.
fn slow(coarse: bool) -> Grid {
    if coarse {
        Grid {
            delays: &[0, 3, 6],
            ..COARSE
        }
    } else {
        Grid {
            delays: &[0, 1, 2, 3, 6],
            ..GRID
        }
    }
}

/// The bounds every `cargo test` walks, on four threads, in a few seconds in a debug build: the fine
/// grid, a handover to the direct app or to none, the chained app's first, and two datagrams to new
/// destinations or lookups. It finds the bugs of the rule that a few datagrams show, each with a
/// schedule of two or three, and keeps the search itself working.
const SMALL: &[(&str, &str)] = &[("fine", "3,1,2,2,2,1,3,0,-,0")];

/// The larger bounds, walked on demand on every core, in about four minutes in a build with
/// optimisation: on the fine grid, more datagrams, two handovers, or the chain turning; on the coarse
/// grid, streams, with two handovers among them, behind slow ways, or past thirty times `udp_reask`.
const LARGE: &[(&str, &str)] = &[
    ("fine, two handovers", "4,2,2,2,2,1,3,0,-,0"),
    ("fine, the chain turning", "4,1,2,2,2,1,3,1,-,0"),
    ("fine, three datagrams", "4,1,3,2,2,1,3,0,-,0"),
    ("a stream with lookups", "3,1,3,2,2,1,3,0,3-3,1"),
    ("two handovers in a stream", "4,2,1,1,2,1,3,0,3-4,1"),
    ("two handovers in a longer stream", "4,2,2,1,2,1,3,0,2-4,1"),
    ("a stream behind slow ways", "5,0,3,1,1,1,3,0,3-3,1,1"),
    (
        "a stream behind slow ways, a handover",
        "5,1,3,1,2,1,3,0,3-3,1,1",
    ),
    (
        "a stream past thirty times udp_reask",
        "64,1,1,1,1,0,4,0,58-62,1",
    ),
];

/// Every schedule within small bounds ([`SMALL`]).
#[test]
fn every_schedule_within_small_bounds() -> Result<(), String> {
    exhaust_all(SMALL, 4)
}

/// Every schedule within the larger bounds ([`LARGE`]), or within those `WHOSE_BOUNDS` gives as
/// [`bounds`] reads them, to search further or less: minutes on every core, best in a build with
/// optimisation (`CARGO_PROFILE_DEV_OPT_LEVEL=3`).
#[test]
#[ignore = "minutes on every core; run with --ignored"]
fn every_schedule_within_larger_bounds() -> Result<(), String> {
    match std::env::var("WHOSE_BOUNDS") {
        Ok(given) => exhaust_all(&[("WHOSE_BOUNDS", &given)], usize::MAX),
        Err(_) => exhaust_all(LARGE, usize::MAX),
    }
}
