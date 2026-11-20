//! The order in which Watch tries the encrypted ways for a direct app's name, and what it learns while it does
//! (W8, part 1, ADR 0042, "How it is built", points 6 and 7). Pure: the engine hands it the time and what each
//! attempt gave, and asks it what to try.
//!
//! **The order, by privacy.** The user's own resolver when there is one, else Oblivious DoH through the pairs;
//! then, while the user's tool is on, Oblivious DoH through the tool; then DoH directly to the targets' own
//! operators; then the presets that filter nothing; the network's resolver last, and never in the strict
//! setting. Watch learns only within a rung (which pair or endpoint answered last on this network, tried first
//! next), never across rungs, and climbs back up as soon as a higher rung answers: a rung below is used only
//! while every step above is held.
//!
//! **Holds.** A step that timed out, or was refused, or answered with an error, is held for a short back-off,
//! doubling from [`BACKOFF_FIRST`] to [`BACKOFF_MOST`]; one whose connection was reset or whose answer was
//! tampered with (a certificate that does not check) is held [`HOLD_TAMPERED`], as long as a measured censor
//! keeps blocking after it struck (FOCI 2025: up to 360 s). While Android says the network beneath is not
//! validated (a captive portal), no failure counts. A change of network clears every hold and everything
//! learned: what Watch learns lives in memory only, for the network it is on, and is never keyed by a network's
//! name (a list of networks where encrypted DNS failed would be evidence in a phone search).

use std::time::{Duration, Instant};

/// The first back-off after a timeout, a refusal or an error.
pub const BACKOFF_FIRST: Duration = Duration::from_secs(5);
/// The longest back-off.
pub const BACKOFF_MOST: Duration = Duration::from_secs(60);
/// How long a step whose connection was reset, or whose answer was tampered with, is held.
pub const HOLD_TAMPERED: Duration = Duration::from_secs(360);

/// One step of the ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The user's own resolver.
    Choice,
    /// Oblivious DoH through the pair of this index, directly.
    Pair(usize),
    /// Oblivious DoH through the pair of this index, through the user's tool.
    PairThroughTool(usize),
    /// DoH directly to the operator of the target of this index.
    TargetDoh(usize),
    /// The preset of this index.
    Preset(usize),
}

/// The rungs, highest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rung {
    /// The user's own resolver, or Oblivious DoH.
    First,
    /// Oblivious DoH through the user's tool.
    ThroughTool,
    /// DoH to the targets' own operators.
    TargetsDoh,
    /// The presets that filter nothing.
    Presets,
}

impl Step {
    /// The rung this step is on.
    #[must_use]
    pub fn rung(self) -> Rung {
        match self {
            Self::Choice | Self::Pair(_) => Rung::First,
            Self::PairThroughTool(_) => Rung::ThroughTool,
            Self::TargetDoh(_) => Rung::TargetsDoh,
            Self::Preset(_) => Rung::Presets,
        }
    }
}

/// What the ladder is made of now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Setup {
    /// Whether the user chose a resolver.
    pub choice: bool,
    /// How many pairs there are.
    pub pairs: usize,
    /// Whether the user's tool is on.
    pub tool: bool,
    /// The targets whose operator's own DoH is a step, in order.
    pub target_doh: Vec<usize>,
    /// The presets that are steps, in order.
    pub presets: Vec<usize>,
    /// The strict setting: never the network's resolver for a name of the internet.
    pub strict: bool,
}

impl Setup {
    /// Every step, in the order of privacy, before what was learned.
    fn steps(&self) -> Vec<Step> {
        let mut steps = Vec::new();
        if self.choice {
            steps.push(Step::Choice);
        } else {
            steps.extend((0..self.pairs).map(Step::Pair));
        }
        if self.tool {
            steps.extend((0..self.pairs).map(Step::PairThroughTool));
        }
        steps.extend(self.target_doh.iter().copied().map(Step::TargetDoh));
        steps.extend(self.presets.iter().copied().map(Step::Preset));
        steps
    }
}

/// How an attempt failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No answer in time, or no connection in time (dropped packets).
    Timeout,
    /// The connection was refused, or the server answered with an error or something that is not an answer.
    Refused,
    /// The connection was reset once the TLS hello was out, or the certificate did not check: what a censor
    /// does that blocks by server name, or one that answers in the server's place.
    Tampered,
    /// The target no longer holds the key the query was sealed to (HTTP 401): no hold, the key is fetched again.
    Key,
}

/// What a held step waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hold {
    until: Instant,
    backoff: Duration,
}

/// Which way answered last, for Watch's screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Now {
    /// Nothing asked yet on this network.
    Unknown,
    /// This step answered last.
    Way(Step),
    /// No encrypted way answered: the network's resolver did, outside the strict setting, since then.
    Fallback(Instant),
    /// No encrypted way answered, in the strict setting: the apps get "server failure", since then.
    Failing(Instant),
}

/// The ladder's state on the network Watch is on.
#[derive(Debug)]
pub struct Ladder {
    /// The steps held, each once: a few dozen at most, so a list (the native library's size counts, W8).
    holds: Vec<(Step, Hold)>,
    /// Within each rung, the step that answered last, by the rung's place.
    learned: [Option<Step>; 4],
    validated: bool,
    now: Now,
}

impl Default for Ladder {
    fn default() -> Self {
        Self {
            holds: Vec::new(),
            learned: [None; 4],
            validated: true,
            now: Now::Unknown,
        }
    }
}

impl Ladder {
    fn hold(&self, step: Step) -> Option<&Hold> {
        self.holds.iter().find(|(s, _)| *s == step).map(|(_, h)| h)
    }

    fn learned(&self, rung: Rung) -> Option<Step> {
        self.learned[rung as usize]
    }

    /// The steps to try now, in order: by rung, the one learned first within each, held ones left out.
    #[must_use]
    pub fn plan(&self, setup: &Setup, now: Instant) -> Vec<Step> {
        let open: Vec<Step> = setup
            .steps()
            .into_iter()
            .filter(|s| self.hold(*s).is_none_or(|h| h.until <= now))
            .collect();
        // The steps come in their rungs' order already: within each rung, the learned step first, the rest in
        // their order.
        let mut steps = Vec::with_capacity(open.len());
        for rung in [
            Rung::First,
            Rung::ThroughTool,
            Rung::TargetsDoh,
            Rung::Presets,
        ] {
            let learned = self.learned(rung).filter(|l| open.contains(l));
            steps.extend(learned);
            steps.extend(
                open.iter()
                    .filter(|s| s.rung() == rung && Some(**s) != learned),
            );
        }
        steps
    }

    /// Whether the network's resolver may answer a name of the internet now: outside the strict setting only.
    #[must_use]
    pub fn network_allowed(setup: &Setup) -> bool {
        !setup.strict
    }

    /// `step` failed by `failure` at `now`.
    pub fn failed(&mut self, step: Step, failure: Failure, now: Instant) {
        if !self.validated || failure == Failure::Key {
            return;
        }
        let before = self.hold(step).map(|h| h.backoff);
        let hold = if failure == Failure::Tampered {
            Hold {
                until: now + HOLD_TAMPERED,
                backoff: before.unwrap_or(BACKOFF_FIRST),
            }
        } else {
            let backoff = before.map_or(BACKOFF_FIRST, |b| (b * 2).min(BACKOFF_MOST));
            Hold {
                until: now + backoff,
                backoff,
            }
        };
        self.holds.retain(|(s, _)| *s != step);
        self.holds.push((step, hold));
        if self.learned(step.rung()) == Some(step) {
            self.learned[step.rung() as usize] = None;
        }
    }

    /// `step` answered: it is no longer held, it is tried first within its rung, and it is the way now.
    pub fn answered(&mut self, step: Step) {
        self.holds.retain(|(s, _)| *s != step);
        self.learned[step.rung() as usize] = Some(step);
        self.now = Now::Way(step);
    }

    /// No encrypted way answered, and the network's resolver was asked (outside strict).
    pub fn fell_back(&mut self, now: Instant) {
        if !matches!(self.now, Now::Fallback(_)) {
            self.now = Now::Fallback(now);
        }
    }

    /// No encrypted way answered, in the strict setting.
    pub fn failing(&mut self, now: Instant) {
        if !matches!(self.now, Now::Failing(_)) {
            self.now = Now::Failing(now);
        }
    }

    /// Android says whether the network beneath is validated; while it is not (a captive portal), no failure
    /// counts.
    pub fn set_validated(&mut self, validated: bool) {
        self.validated = validated;
    }

    /// Whether failures count now.
    #[must_use]
    pub fn validated(&self) -> bool {
        self.validated
    }

    /// The network beneath changed, or the ways themselves did: every hold and everything learned goes.
    pub fn reset(&mut self) {
        self.holds.clear();
        self.learned = [None; 4];
        self.now = Now::Unknown;
    }

    /// Which way answered last.
    #[must_use]
    pub fn now(&self) -> Now {
        self.now
    }

    /// How many steps are held at `now`.
    #[must_use]
    pub fn held(&self, now: Instant) -> usize {
        self.holds.iter().filter(|(_, h)| h.until > now).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Setup {
        Setup {
            choice: false,
            pairs: 2,
            tool: false,
            target_doh: vec![0, 1],
            presets: vec![3, 5],
            strict: false,
        }
    }

    #[test]
    fn the_order_is_odoh_then_targets_operators_then_presets() {
        let ladder = Ladder::default();
        let at = Instant::now();
        assert_eq!(
            ladder.plan(&setup(), at),
            [
                Step::Pair(0),
                Step::Pair(1),
                Step::TargetDoh(0),
                Step::TargetDoh(1),
                Step::Preset(3),
                Step::Preset(5)
            ]
        );
    }

    #[test]
    fn the_users_choice_comes_first_in_place_of_odoh_and_the_tool_after_it() {
        let ladder = Ladder::default();
        let s = Setup {
            choice: true,
            tool: true,
            ..setup()
        };
        assert_eq!(
            ladder.plan(&s, Instant::now())[..4],
            [
                Step::Choice,
                Step::PairThroughTool(0),
                Step::PairThroughTool(1),
                Step::TargetDoh(0)
            ]
        );
        let without_choice = Setup {
            tool: true,
            ..setup()
        };
        assert_eq!(
            ladder.plan(&without_choice, Instant::now())[..3],
            [Step::Pair(0), Step::Pair(1), Step::PairThroughTool(0)]
        );
    }

    #[test]
    fn a_timeout_backs_off_briefly_and_doubles_to_a_minute() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.failed(Step::Pair(0), Failure::Timeout, at);
        assert_eq!(ladder.plan(&setup(), at)[0], Step::Pair(1));
        assert_eq!(
            ladder.plan(&setup(), at + BACKOFF_FIRST)[0],
            Step::Pair(0),
            "back after 5 s"
        );
        let mut last = at;
        for i in 0..10 {
            last = at + Duration::from_secs(i);
            ladder.failed(Step::Pair(0), Failure::Timeout, last);
        }
        assert_ne!(
            ladder.plan(&setup(), last + Duration::from_secs(59))[0],
            Step::Pair(0)
        );
        assert_eq!(
            ladder.plan(&setup(), last + BACKOFF_MOST)[0],
            Step::Pair(0),
            "never past a minute"
        );
    }

    #[test]
    fn a_reset_holds_six_minutes() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.failed(Step::Pair(0), Failure::Tampered, at);
        assert_ne!(
            ladder.plan(&setup(), at + Duration::from_secs(359))[0],
            Step::Pair(0)
        );
        assert_eq!(ladder.plan(&setup(), at + HOLD_TAMPERED)[0], Step::Pair(0));
    }

    #[test]
    fn a_key_failure_holds_nothing() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.failed(Step::Pair(0), Failure::Key, at);
        assert_eq!(ladder.plan(&setup(), at)[0], Step::Pair(0));
    }

    #[test]
    fn behind_a_captive_portal_no_failure_counts() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.set_validated(false);
        ladder.failed(Step::Pair(0), Failure::Tampered, at);
        ladder.failed(Step::Pair(1), Failure::Timeout, at);
        assert_eq!(ladder.plan(&setup(), at)[0], Step::Pair(0));
        assert_eq!(ladder.held(at), 0);
        ladder.set_validated(true);
        ladder.failed(Step::Pair(0), Failure::Timeout, at);
        assert_eq!(ladder.held(at), 1);
    }

    #[test]
    fn it_learns_within_a_rung_and_never_across() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.answered(Step::Pair(1));
        assert_eq!(
            ladder.plan(&setup(), at)[..2],
            [Step::Pair(1), Step::Pair(0)]
        );
        // A preset that answered stays below the pairs.
        ladder.answered(Step::Preset(5));
        let plan = ladder.plan(&setup(), at);
        assert_eq!(plan[0], Step::Pair(1));
        assert_eq!(plan[4..], [Step::Preset(5), Step::Preset(3)]);
        // A failure forgets what was learned.
        ladder.failed(Step::Pair(1), Failure::Timeout, at);
        assert_eq!(
            ladder.plan(&setup(), at + BACKOFF_FIRST)[..2],
            [Step::Pair(0), Step::Pair(1)]
        );
    }

    #[test]
    fn it_climbs_back_as_soon_as_a_hold_ends() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        for step in [
            Step::Pair(0),
            Step::Pair(1),
            Step::TargetDoh(0),
            Step::TargetDoh(1),
        ] {
            ladder.failed(step, Failure::Timeout, at);
        }
        ladder.answered(Step::Preset(3));
        assert_eq!(ladder.plan(&setup(), at)[0], Step::Preset(3));
        assert_eq!(
            ladder.plan(&setup(), at + BACKOFF_FIRST)[0],
            Step::Pair(0),
            "the highest first again"
        );
    }

    #[test]
    fn a_change_of_network_clears_holds_and_learning() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.failed(Step::Pair(0), Failure::Tampered, at);
        ladder.answered(Step::Pair(1));
        ladder.fell_back(at);
        ladder.reset();
        assert_eq!(
            ladder.plan(&setup(), at)[..2],
            [Step::Pair(0), Step::Pair(1)]
        );
        assert_eq!(ladder.now(), Now::Unknown);
    }

    #[test]
    fn strict_never_allows_the_network_and_says_failing() {
        let strict = Setup {
            strict: true,
            ..setup()
        };
        assert!(!Ladder::network_allowed(&strict));
        assert!(Ladder::network_allowed(&setup()));
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.failing(at);
        ladder.failing(at + Duration::from_secs(3));
        assert_eq!(ladder.now(), Now::Failing(at), "since the first");
        ladder.answered(Step::Pair(0));
        assert_eq!(ladder.now(), Now::Way(Step::Pair(0)));
    }

    #[test]
    fn the_fallback_lasts_until_a_way_answers() {
        let mut ladder = Ladder::default();
        let at = Instant::now();
        ladder.fell_back(at);
        ladder.fell_back(at + Duration::from_secs(9));
        assert_eq!(ladder.now(), Now::Fallback(at));
        ladder.answered(Step::Preset(3));
        assert_eq!(ladder.now(), Now::Way(Step::Preset(3)));
    }
}
