//! What Watch's Kotlin side tells the engine of the apps' states (ADR 0046, decision 1): one reading of
//! Android's usage events, as the states each app had over a span of the wall clock. Version 1,
//! little-endian:
//!
//! - version (1), the span's start and end in milliseconds since 1970 (UTC), what is known over it (0:
//!   the states below; 1: nothing, Watch has no usage access; 2: nothing, Android gave no events, as
//!   before the first unlock after a restart), the screen at the span's end (0 off, 1 on, 2 not known)
//!   and when it last came on (0 for not known), then a count (u32) of intervals, each an app's UID (u32),
//!   its start and end, and its state in it (1 in use, 2 with its notification). An app with no interval
//!   in a known span was in the background throughout it; intervals of one app may overlap, and "in use"
//!   wins where they do.
//!
//! Nothing in it names a destination: UIDs, times and states only. The engine reads it with [`read`],
//! which takes any bytes and refuses what is not exactly one message of this version.

/// The version of the message.
pub const VERSION: u8 = 1;

/// The fixed part of a message: version, start, end, what is known, the screen, when it came on, the
/// count of intervals.
const HEAD: usize = 1 + 8 + 8 + 1 + 1 + 8 + 4;

/// One interval: UID, start, end, state.
const INTERVAL: usize = 4 + 8 + 8 + 1;

/// An app's state in a moment, by ADR 0046's decision 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// An activity of the app, or of a package sharing its UID, was resumed or visible, or the user
    /// interacted with it, then or within the grace before.
    InUse,
    /// The app ran a foreground service, which Android shows the user with its notification.
    Notification,
    /// Neither.
    Background,
}

impl State {
    /// Which state wins within one second that held several: in use, then with its notification, then
    /// in the background, so that a second is "in the background" only when the app was so throughout.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::InUse => 2,
            Self::Notification => 1,
            Self::Background => 0,
        }
    }
}

/// Why a second has no state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unknown {
    /// Watch has no usage access.
    NoAccess,
    /// Android gave no usage events, as before the first unlock after a restart.
    Locked,
    /// Its state was not told while the engine kept the second: past the window, or past the bound of
    /// what every flow keeps together.
    Late,
    /// Android did not name the flow's app.
    NoApp,
    /// Nothing was told for it: before Watch's first reading, in a gap a clock set back left, or when
    /// Watch stopped before a reading came.
    NotTold,
}

/// Where a second's bytes, or a segment, were placed: in a state, or in none, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Placed {
    /// The app's state.
    Known(State),
    /// No state, and why.
    Unknown(Unknown),
}

impl Placed {
    /// One byte, as the log's records (version 3) and the live view's snapshot carry it: the low four
    /// bits the state (0 none, 1 in use, 2 with its notification, 3 in the background), the high four
    /// why there is none (0 for a state; 1 no usage access, 2 no events, as before the first unlock, 3
    /// told too late, 4 no app, 5 not told).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Known(State::InUse) => 1,
            Self::Known(State::Notification) => 2,
            Self::Known(State::Background) => 3,
            Self::Unknown(why) => {
                (match why {
                    Unknown::NoAccess => 1,
                    Unknown::Locked => 2,
                    Unknown::Late => 3,
                    Unknown::NoApp => 4,
                    Unknown::NotTold => 5,
                }) << 4
            }
        }
    }

    /// Where the live view counts it: 0 no state, 1 in use, 2 with its notification, 3 in the
    /// background.
    #[must_use]
    pub fn column(self) -> usize {
        usize::from(self.code() & 0x0f)
    }
}

/// What a reading knows over its span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// The apps' states: the intervals, and the background elsewhere.
    States,
    /// Nothing: Watch has no usage access.
    NoAccess,
    /// Nothing: Android gave no events, as before the first unlock after a restart.
    Locked,
}

/// The screen at the end of a reading's span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Off, or not interactive (ambient display counts as off).
    Off,
    /// On, since the moment given if known, in milliseconds since 1970.
    On(Option<u64>),
    /// Not known.
    Unknown,
}

/// One interval of an app's state that is not "in the background".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// The app's UID.
    pub uid: u32,
    /// Its start, in milliseconds since 1970 (UTC).
    pub from: u64,
    /// Its end.
    pub until: u64,
    /// In use, or with its notification.
    pub state: State,
}

/// One reading, as told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Told {
    /// The span's start, in milliseconds since 1970 (UTC).
    pub from: u64,
    /// Its end: the states are known up to here.
    pub until: u64,
    /// What is known over it.
    pub known: Known,
    /// The screen at its end.
    pub screen: Screen,
    /// The apps' intervals in use and with their notification, within the span.
    pub intervals: Vec<Interval>,
}

/// Reads one message: `None` for anything that is not exactly one of this version, a span that ends
/// before it starts, an unknown code, an interval outside the span or empty, or intervals with a span
/// that knows nothing.
#[must_use]
pub fn read(bytes: &[u8]) -> Option<Told> {
    let head = bytes.get(..HEAD)?;
    if head[0] != VERSION {
        return None;
    }
    let from = u64_at(head, 1)?;
    let until = u64_at(head, 9)?;
    let known = match head[17] {
        0 => Known::States,
        1 => Known::NoAccess,
        2 => Known::Locked,
        _ => return None,
    };
    let since = u64_at(head, 19)?;
    let screen = match head[18] {
        0 => Screen::Off,
        1 => Screen::On((since != 0).then_some(since)),
        2 => Screen::Unknown,
        _ => return None,
    };
    let count = usize::try_from(u32::from_le_bytes(head[27..31].try_into().ok()?)).ok()?;
    let rest = &bytes[HEAD..];
    if from > until || rest.len() != count.checked_mul(INTERVAL)? {
        return None;
    }
    if known != Known::States && count > 0 {
        return None;
    }
    let mut intervals = Vec::with_capacity(count);
    for part in rest.as_chunks::<INTERVAL>().0 {
        let interval = Interval {
            uid: u32::from_le_bytes(part[..4].try_into().ok()?),
            from: u64_at(part, 4)?,
            until: u64_at(part, 12)?,
            state: match part[20] {
                1 => State::InUse,
                2 => State::Notification,
                _ => return None,
            },
        };
        if interval.from >= interval.until || interval.from < from || interval.until > until {
            return None;
        }
        intervals.push(interval);
    }
    Some(Told {
        from,
        until,
        known,
        screen,
        intervals,
    })
}

/// A message in its stored form: what Watch's Kotlin side writes, for the engine's tests and the
/// fixture both sides read.
#[must_use]
pub fn write(told: &Told) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD + told.intervals.len() * INTERVAL);
    out.push(VERSION);
    out.extend_from_slice(&told.from.to_le_bytes());
    out.extend_from_slice(&told.until.to_le_bytes());
    out.push(match told.known {
        Known::States => 0,
        Known::NoAccess => 1,
        Known::Locked => 2,
    });
    let (screen, since) = match told.screen {
        Screen::Off => (0, 0),
        Screen::On(since) => (1, since.unwrap_or(0)),
        Screen::Unknown => (2, 0),
    };
    out.push(screen);
    out.extend_from_slice(&since.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(told.intervals.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for interval in &told.intervals {
        out.extend_from_slice(&interval.uid.to_le_bytes());
        out.extend_from_slice(&interval.from.to_le_bytes());
        out.extend_from_slice(&interval.until.to_le_bytes());
        out.push(match interval.state {
            State::InUse => 1,
            State::Notification => 2,
            State::Background => 0,
        });
    }
    out
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn told() -> Told {
        Told {
            from: 1_000,
            until: 61_000,
            known: Known::States,
            screen: Screen::On(Some(500)),
            intervals: vec![
                Interval {
                    uid: 10_123,
                    from: 1_000,
                    until: 31_000,
                    state: State::InUse,
                },
                Interval {
                    uid: 10_124,
                    from: 2_000,
                    until: 61_000,
                    state: State::Notification,
                },
            ],
        }
    }

    #[test]
    fn a_message_reads_back_as_written() {
        let message = write(&told());
        assert_eq!(message.len(), HEAD + 2 * INTERVAL);
        assert_eq!(read(&message), Some(told()));
        for screen in [Screen::Off, Screen::On(None), Screen::Unknown] {
            let other = Told { screen, ..told() };
            assert_eq!(read(&write(&other)), Some(other));
        }
        for known in [Known::NoAccess, Known::Locked] {
            let nothing = Told {
                known,
                intervals: Vec::new(),
                ..told()
            };
            assert_eq!(read(&write(&nothing)), Some(nothing));
        }
    }

    /// Field by field, so that the Kotlin side's writer can be checked against the same bytes.
    #[test]
    fn a_message_is_laid_out_field_by_field() {
        let message = write(&told());
        let mut expected = vec![1];
        expected.extend_from_slice(&1_000u64.to_le_bytes());
        expected.extend_from_slice(&61_000u64.to_le_bytes());
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&500u64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&10_123u32.to_le_bytes());
        expected.extend_from_slice(&1_000u64.to_le_bytes());
        expected.extend_from_slice(&31_000u64.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&10_124u32.to_le_bytes());
        expected.extend_from_slice(&2_000u64.to_le_bytes());
        expected.extend_from_slice(&61_000u64.to_le_bytes());
        expected.push(2);
        assert_eq!(message, expected);
    }

    /// Every way a message can be wrong is refused, never read as something else.
    #[test]
    fn what_is_not_one_message_is_refused() {
        let good = write(&told());
        // Cut anywhere, or one byte too many.
        for end in 0..good.len() {
            assert_eq!(read(&good[..end]), None, "cut at {end}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(read(&longer), None);
        // Another version, an unknown kind or screen, an unknown state.
        for (at, value) in [(0, 2), (17, 3), (18, 3), (31 + 20, 0), (31 + 20, 3)] {
            let mut bad = good.clone();
            bad[at] = value;
            assert_eq!(read(&bad), None, "byte {at} = {value}");
        }
        // A count that says more or fewer intervals than there are, or more than memory holds.
        for count in [1u32, 3, u32::MAX] {
            let mut bad = good.clone();
            bad[27..31].copy_from_slice(&count.to_le_bytes());
            assert_eq!(read(&bad), None, "count {count}");
        }
        // A span that ends before it starts; an interval empty, backwards or outside the span.
        let bad = |told: Told| assert_eq!(read(&write(&told)), None, "{told:?}");
        bad(Told {
            from: 61_001,
            ..told()
        });
        for (from, until) in [
            (5_000, 5_000),
            (6_000, 5_000),
            (500, 2_000),
            (60_000, 61_001),
        ] {
            let mut wrong = told();
            wrong.intervals[0].from = from;
            wrong.intervals[0].until = until;
            bad(wrong);
        }
        // Intervals where nothing is known.
        bad(Told {
            known: Known::NoAccess,
            ..told()
        });
    }

    #[test]
    fn a_state_codes_in_one_byte_and_in_use_wins_within_a_second() {
        assert_eq!(Placed::Known(State::InUse).code(), 1);
        assert_eq!(Placed::Known(State::Notification).code(), 2);
        assert_eq!(Placed::Known(State::Background).code(), 3);
        assert_eq!(Placed::Unknown(Unknown::NoAccess).code(), 0x10);
        assert_eq!(Placed::Unknown(Unknown::Locked).code(), 0x20);
        assert_eq!(Placed::Unknown(Unknown::Late).code(), 0x30);
        assert_eq!(Placed::Unknown(Unknown::NoApp).code(), 0x40);
        assert_eq!(Placed::Unknown(Unknown::NotTold).code(), 0x50);
        assert_eq!(Placed::Unknown(Unknown::NotTold).column(), 0);
        assert_eq!(Placed::Known(State::Background).column(), 3);
        assert!(State::InUse.rank() > State::Notification.rank());
        assert!(State::Notification.rank() > State::Background.rank());
    }
}
