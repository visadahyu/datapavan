//! A model test of the states' placing (ADR 0046; review b1 of W5's second part, engine: "a stateful
//! target ... against a truth timeline"): random runs of two apps' flows and flows of no app, with counts,
//! ends, readings told from a true timeline of the apps' states in tenths of a second, quarter hours and,
//! in variants, a reading without usage access or clocks set back, checked against the records the
//! engine wrote, where it cut them, and what "Now" shows (review b2, N5). It runs in `cargo test`.

use super::activity::WINDOW;
use super::activity::tests::{T, flow, taken, telling_at};
use super::logbook::{FlowBytes, SEGMENT_MS};
use super::{Shared, lock};
use crate::log::Record;
use crate::states::{Interval, Known, Placed, Screen, State, Told, Unknown};
use std::collections::HashMap;
use std::sync::Arc;

/// The two apps; flows of no app are the third kind.
const APPS: [u32; 2] = [10_123, 10_124];

/// A run: from [`T`] (22:10) past the quarter hours of 22:15 and 22:30.
const LENGTH_MS: u64 = 1_300_000;

/// The tenths of a second of the truth, a little more than a run.
const TICKS: usize = 14_000;

/// A small deterministic generator (xorshift64*), so that a failing run can be run again by its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The truth: each app's state tenth of a second by tenth from [`T`], in runs from a tenth to 90
/// seconds, and the span a reading without usage access told, if one did.
struct Truth {
    ticks: HashMap<u32, Vec<State>>,
    no_access: Option<(u64, u64)>,
}

fn truth(rng: &mut Rng) -> Truth {
    let ticks = APPS
        .iter()
        .map(|&uid| {
            let mut states = Vec::with_capacity(TICKS + 900);
            while states.len() < TICKS {
                let state = match rng.below(3) {
                    0 => State::InUse,
                    1 => State::Notification,
                    _ => State::Background,
                };
                let run = if rng.below(4) == 0 {
                    1 + rng.below(20)
                } else {
                    10 + rng.below(890)
                };
                states.extend(std::iter::repeat_n(
                    state,
                    usize::try_from(run).unwrap_or(1),
                ));
            }
            (uid, states)
        })
        .collect();
    Truth {
        ticks,
        no_access: None,
    }
}

impl Truth {
    /// The true state of `uid` in the tenth of a second that holds `at`, in milliseconds since 1970.
    fn tick(&self, uid: u32, at: u64) -> State {
        let tick = usize::try_from(at.saturating_sub(T) / 100).unwrap_or(usize::MAX);
        self.ticks
            .get(&uid)
            .and_then(|states| states.get(tick))
            .copied()
            .unwrap_or(State::Background)
    }

    /// Where the second that holds `at` belongs, by the engine's rule: no state where a reading without
    /// usage access told any of it, else in use if the app was at any moment of it, else with its
    /// notification if it was so at any moment, else in the background.
    fn placed(&self, uid: Option<u32>, at: u64) -> Placed {
        let Some(uid) = uid else {
            return Placed::Unknown(Unknown::NoApp);
        };
        let from = at / 1000 * 1000;
        if self
            .no_access
            .is_some_and(|(a, b)| a < from + 1000 && from < b)
        {
            return Placed::Unknown(Unknown::NoAccess);
        }
        let state = (0..10)
            .map(|i| self.tick(uid, from + i * 100))
            .max_by_key(|state| state.rank())
            .unwrap_or(State::Background);
        Placed::Known(state)
    }

    /// A reading of the truth from `from` to `until`, as Watch's Kotlin side would tell it.
    fn reading(&self, from: u64, until: u64) -> Told {
        let mut intervals = Vec::new();
        for &uid in &APPS {
            let mut run: Option<(u64, State)> = None;
            let mut tick = from / 100 * 100;
            while tick < until {
                let state = self.tick(uid, tick);
                if run.is_none_or(|(_, was)| was != state) {
                    if let Some((start, was)) = run
                        && was != State::Background
                    {
                        intervals.push(Interval {
                            uid,
                            from: start.max(from),
                            until: tick.min(until),
                            state: was,
                        });
                    }
                    run = Some((tick, state));
                }
                tick += 100;
            }
            if let Some((start, was)) = run
                && was != State::Background
            {
                intervals.push(Interval {
                    uid,
                    from: start.max(from),
                    until,
                    state: was,
                });
            }
        }
        Told {
            from,
            until,
            known: Known::States,
            screen: Screen::On(Some(T)),
            screen_off: None,
            intervals,
        }
    }
}

/// A flow of the model: its app, its counts, and when it opened and ended.
struct Flowing {
    uid: Option<u32>,
    bytes: Arc<FlowBytes>,
    opened: u64,
    ended: Option<u64>,
    /// Each count: when, up and down.
    counts: Vec<(u64, u64, u64)>,
    /// How many of the first counts a clock set back took out of "Now"'s windows: those of minutes later
    /// than the new clock's.
    gone: Vec<bool>,
}

/// One run: what the engine wrote, the flows, the truth, and where the clock ended.
struct Run {
    shared: Shared,
    records: Vec<Record>,
    flows: HashMap<u64, Flowing>,
    truth: Truth,
    now: u64,
}

/// What a run adds to the plain one: a reading without usage access, or clocks set back now and then.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Plain,
    NoAccess,
    SetBack,
}

/// One step at `now`: a flow opens (always when none is open), one ends, or one counts bytes up and down.
fn act(
    rng: &mut Rng,
    shared: &Shared,
    flows: &mut HashMap<u64, Flowing>,
    next_id: &mut u64,
    now: u64,
) {
    let mut open: Vec<u64> = flows
        .iter()
        .filter(|(_, f)| f.ended.is_none())
        .map(|(&id, _)| id)
        .collect();
    open.sort_unstable();
    let action = rng.below(100);
    if action < 5 && open.len() < 12 || open.is_empty() {
        let uid = match rng.below(3) {
            0 => Some(APPS[0]),
            1 => Some(APPS[1]),
            _ => None,
        };
        let id = *next_id;
        *next_id += 1;
        if let Some(bytes) = shared.record(flow(id, uid)) {
            flows.insert(
                id,
                Flowing {
                    uid,
                    bytes,
                    opened: now,
                    ended: None,
                    counts: Vec::new(),
                    gone: Vec::new(),
                },
            );
        }
        return;
    }
    let id = open[usize::try_from(rng.below(open.len() as u64)).unwrap_or(0)];
    let Some(f) = flows.get_mut(&id) else {
        return;
    };
    if action < 9 {
        shared.finish(id);
        f.ended = Some(now);
    } else {
        let (up, down) = (rng.below(400), rng.below(400));
        let n = |x: u64| usize::try_from(x).unwrap_or(0);
        if up > 0 {
            f.bytes.up(shared, n(up), n(up) + 40);
        }
        if down > 0 {
            f.bytes.down(shared, n(down), n(down) + 40);
        }
        f.counts.push((now, up, down));
        f.gone.push(false);
    }
}

/// Runs the model with `seed` and `variant`. Without access, the reading after the 400th second tells
/// nothing is known, and the next tells from its end, as Watch's tracker does; with set backs, the clock
/// goes back by 1 to 5 seconds now and then.
fn run(seed: u64, variant: Variant) -> Run {
    let mut rng = Rng::new(seed);
    let mut truth = truth(&mut rng);
    let (shared, clock, _) = telling_at(T);
    let mut flows: HashMap<u64, Flowing> = HashMap::new();
    let mut records = Vec::new();
    let (mut now, mut told_until, mut next_reading, mut floor) = (T, T, T + 3_000, T);
    let mut next_id = 1;
    // Each reading reads again the last 10 seconds of the one before, but none before a clock set back
    // or after one without access.
    let tell = |shared: &Shared, truth: &Truth, from: u64, until: u64, floor: u64| {
        shared.tell(&truth.reading(from.saturating_sub(10_000).max(floor), until));
    };
    while now < T + LENGTH_MS {
        let last = now;
        now += 1 + rng.below(1_500);
        if variant == Variant::SetBack && rng.below(150) == 0 {
            now = now.saturating_sub(1_000 + rng.below(4_000)).max(T + 1_000);
            // Back by a second or more from the last moment the engine read, as the engine and the
            // tracker find it; less moves nothing.
            if now + 1_000 <= last {
                for f in flows.values_mut() {
                    for (i, &(at, _, _)) in f.counts.iter().enumerate() {
                        if at / 60_000 > now / 60_000 {
                            f.gone[i] = true;
                        }
                    }
                }
                // Watch's Kotlin side finds it at its next reading, and tells from the new clock on.
                told_until = now;
                floor = now;
            }
            clock.set(now);
        }
        clock.set(now);
        act(&mut rng, &shared, &mut flows, &mut next_id, now);
        if now >= next_reading {
            let until = now - 2_000;
            if until > told_until {
                if variant == Variant::NoAccess && truth.no_access.is_none() && now > T + 400_000 {
                    shared.tell(&Told {
                        known: Known::NoAccess,
                        intervals: Vec::new(),
                        ..truth.reading(told_until, until)
                    });
                    truth.no_access = Some((told_until, until));
                    floor = until;
                } else {
                    tell(&shared, &truth, told_until, until, floor);
                }
                told_until = until;
            }
            next_reading = now + 3_000 + rng.below(17_000);
        }
        records.extend(taken(&shared));
    }
    // Every flow ends; a last reading tells all, and a flush writes what still waits.
    now += 1;
    clock.set(now);
    for (&id, f) in &mut flows {
        if f.ended.is_none() {
            shared.finish(id);
            f.ended = Some(now);
        }
    }
    now += 5_000;
    clock.set(now);
    tell(&shared, &truth, told_until, now - 2_000, floor);
    shared.flush();
    records.extend(taken(&shared));
    Run {
        shared,
        records,
        flows,
        truth,
        now,
    }
}

/// A segment as the model reads it: start, end, bytes up and down, whether it goes on, and its state.
type Part = (u64, u64, u64, u64, bool, Placed);

/// Each flow's segments in the order written.
fn segments(records: &[Record]) -> HashMap<u64, Vec<Part>> {
    let mut by_flow: HashMap<u64, Vec<_>> = HashMap::new();
    for record in records {
        if let Record::Segment {
            flow,
            start,
            end,
            bytes,
            continues,
            state,
        } = record
        {
            by_flow
                .entry(flow.id)
                .or_default()
                .push((*start, *end, bytes[0], bytes[1], *continues, *state));
        }
    }
    by_flow
}

/// Where a cut between two parts of a flow may fall: at a quarter hour; else between parts of different
/// states, where the truth changes into the second part's state, or 120 seconds before the first second
/// of that part's that the engine walked back from (its first count, or the last moment of a part with
/// no bytes) over a longer quiet stretch, or at the first whole second of the part before.
fn cut_is_right(
    truth: &Truth,
    uid: Option<u32>,
    (a, b): (&Part, &Part),
    first: Option<u64>,
) -> bool {
    let cut = a.1;
    if cut % SEGMENT_MS == 0 {
        return true;
    }
    if a.5 == b.5 || cut % 1000 != 0 {
        return false;
    }
    let second = cut / 1000;
    let changed = truth.placed(uid, cut) == b.5 && truth.placed(uid, cut - 1000) != b.5;
    let from = first.unwrap_or_else(|| (b.1 - 1) / 1000);
    changed || second == from.saturating_sub(WINDOW as u64) || second == a.0.div_ceil(1000)
}

/// The checks of one flow's segments in [`the_engine_places_every_byte_in_its_true_state`].
fn check_flow(seed: u64, (id, f): (&u64, &Flowing), parts: &[Part], truth: &Truth) {
    let ended = f.ended.unwrap_or(u64::MAX);
    assert!(!parts.is_empty(), "seed {seed}, flow {id}: no record");
    assert_eq!(parts[0].0, f.opened, "seed {seed}, flow {id}: start");
    let last = parts[parts.len() - 1];
    assert_eq!(
        (last.1, last.4),
        (ended, false),
        "seed {seed}, flow {id}: end"
    );
    for pair in parts.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "seed {seed}, flow {id}: end to end");
        assert!(pair[0].4, "seed {seed}, flow {id}: one end");
        assert!(
            pair[0].0 < pair[1].0,
            "seed {seed}, flow {id}: in time order"
        );
        let first = f
            .counts
            .iter()
            .filter(|c| c.1 + c.2 > 0 && pair[1].0 <= c.0 && c.0 < pair[1].1)
            .map(|c| c.0 / 1000)
            .min();
        assert!(
            cut_is_right(truth, f.uid, (&pair[0], &pair[1]), first),
            "seed {seed}, flow {id}: a cut at {} between {:?} and {:?}",
            pair[0].1 - T,
            pair[0],
            pair[1]
        );
    }
    let sums = parts.iter().fold((0, 0), |(u, d), p| (u + p.2, d + p.3));
    let counted = f.counts.iter().fold((0, 0), |(u, d), c| (u + c.1, d + c.2));
    assert_eq!(sums, counted, "seed {seed}, flow {id}: bytes");
    for &(at, up, down) in &f.counts {
        if up + down == 0 {
            continue;
        }
        let part = parts.iter().find(|p| p.0 <= at && at < p.1);
        assert_eq!(
            part.map(|p| p.5),
            Some(truth.placed(f.uid, at)),
            "seed {seed}, flow {id}: the count at {}",
            at - T
        );
    }
    for part in parts.iter().filter(|p| p.2 + p.3 == 0 && p.1 > p.0) {
        assert_eq!(
            part.5,
            truth.placed(f.uid, part.1 - 1),
            "seed {seed}, flow {id}: {part:?}"
        );
    }
    // A segment's last part, at the flow's end or a quarter hour, is in the state of its last
    // moment where that state is known: a quiet end after a change has a part of its own (review
    // b2 of W5's second part, fresh, m4).
    for part in parts
        .iter()
        .filter(|p| p.1 > p.0 && (!p.4 || p.1 % SEGMENT_MS == 0))
    {
        let at_end = truth.placed(f.uid, part.1 - 1);
        if matches!(at_end, Placed::Known(_)) {
            assert_eq!(
                part.5, at_end,
                "seed {seed}, flow {id}: the end of {part:?}"
            );
        }
    }
}

/// Without a clock set back, and in a variant with a reading without usage access: each flow's segments
/// run end to end from its opening to its end, in time order, and add up to its counts; each cut falls
/// where [`cut_is_right`] allows; each byte is in a segment of its second's true state, of no app, or of
/// no access; a segment with no bytes has the state of its last moment; nothing waits after the last
/// reading; and "Now"'s hour holds each app's bytes in the columns of their states.
#[test]
fn the_engine_places_every_byte_in_its_true_state() {
    for seed in 0..240 {
        let variant = if seed % 6 == 5 {
            Variant::NoAccess
        } else {
            Variant::Plain
        };
        let run = run(seed, variant);
        let truth = &run.truth;
        let written = segments(&run.records);
        for (id, f) in &run.flows {
            let parts = written.get(id).map_or(&[][..], Vec::as_slice);
            check_flow(seed, (id, f), parts, truth);
        }
        assert_eq!(run.shared.waiting_marks(), 0, "seed {seed}");
        assert!(lock(&run.shared.activity).held.is_empty(), "seed {seed}");
        // "Now": the hour holds the whole run, each app's bytes by its state.
        let snapshot = run.shared.now_view(run.now);
        let mut expected: HashMap<Option<u32>, [[u64; 2]; 5]> = HashMap::new();
        for f in run.flows.values() {
            for &(at, up, down) in &f.counts {
                let column = match truth.placed(f.uid, at) {
                    Placed::Known(State::InUse) => 1,
                    Placed::Known(State::Notification) => 2,
                    Placed::Known(State::Background) => 3,
                    Placed::Unknown(_) => 0,
                };
                let ways = &mut expected.entry(f.uid).or_default()[column];
                ways[0] += up;
                ways[1] += down;
            }
        }
        for app in &snapshot.apps {
            assert_eq!(
                Some(&app.bytes[1]),
                expected.get(&app.uid),
                "seed {seed}, app {:?}",
                app.uid
            );
        }
        let shown = snapshot.apps.len();
        assert_eq!(shown, expected.len(), "seed {seed}: apps in \"Now\"");
        if variant == Variant::NoAccess {
            assert!(
                truth.no_access.is_some(),
                "seed {seed}: no reading without access"
            );
        }
    }
}

/// With clocks set back: each flow's records add up to its counts, it has one end, none is told too late,
/// and nothing waits after the last reading; "Now"'s hour holds every byte but those of minutes later than
/// a clock set back went to, which it forgets with them.
#[test]
fn a_clock_set_back_loses_no_byte() {
    for seed in 0..100 {
        let run = run(1_000 + seed, Variant::SetBack);
        let written = segments(&run.records);
        for (id, f) in &run.flows {
            let parts = written.get(id).map_or(&[][..], Vec::as_slice);
            assert_eq!(
                parts.iter().filter(|p| !p.4).count(),
                1,
                "seed {seed}, flow {id}: one end"
            );
            let sums = parts.iter().fold((0, 0), |(u, d), p| (u + p.2, d + p.3));
            let counted = f.counts.iter().fold((0, 0), |(u, d), c| (u + c.1, d + c.2));
            assert_eq!(sums, counted, "seed {seed}, flow {id}: bytes");
            assert!(
                parts.iter().all(|p| p.5 != Placed::Unknown(Unknown::Late)),
                "seed {seed}, flow {id}: told too late"
            );
        }
        assert_eq!(run.shared.waiting_marks(), 0, "seed {seed}");
        assert!(lock(&run.shared.activity).held.is_empty(), "seed {seed}");
        let snapshot = run.shared.now_view(run.now);
        let mut expected: HashMap<Option<u32>, [u64; 2]> = HashMap::new();
        for f in run.flows.values() {
            for (&(_, up, down), &gone) in f.counts.iter().zip(&f.gone) {
                if !gone {
                    let ways = expected.entry(f.uid).or_default();
                    ways[0] += up;
                    ways[1] += down;
                }
            }
        }
        for (uid, ways) in expected {
            let shown = snapshot
                .apps
                .iter()
                .find(|app| app.uid == uid)
                .map_or([0, 0], |app| {
                    app.bytes[1]
                        .iter()
                        .fold([0, 0], |[u, d], w| [u + w[0], d + w[1]])
                });
            assert_eq!(shown, ways, "seed {seed}, app {uid:?}: \"Now\"");
        }
    }
}
