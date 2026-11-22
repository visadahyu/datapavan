//! What the network part's Kotlin side tells the engine of the apps' states (ADR 0046, decision 1): one reading of
//! Android's usage events, as the states each app had over a span of the wall clock. Version 2,
//! little-endian:
//!
//! - version (2), the span's start and end in milliseconds since 1970 (UTC), what is known over it (0:
//!   the states below; 1: nothing, the network part has no usage access; 2: nothing, Android gave no events, as
//!   before the first unlock after a restart), the screen at the span's end (0 off, 1 on, 2 not known),
//!   when it last came on (0 for not known, and always 0 for a screen not on) and when it last went off
//!   (0 for not known, always 0 for a screen not known or on since a moment not known, and for a screen on
//!   never after it came on), then
//!   a count (u32) of intervals, each an app's UID (u32), its start and end, and its state in it (1 in
//!   use, 2 with its notification). An app with no interval in a known span was in the background
//!   throughout it; intervals of one app may overlap, and "in use" wins where they do.
//!
//! Version 2 (W5's third part) added when the screen last went off, for the window "while the screen was
//! off" ([`crate::snapshot`]). Both sides ship in one build, so version 1 is refused.
//!
//! Nothing in it names a destination: UIDs, times and states only. The engine reads it with [`read`],
//! which takes any bytes and refuses what is not exactly one message of this version.

/// The version of the message.
pub const VERSION: u8 = 2;

/// The fixed part of a message: version, start, end, what is known, the screen, when it came on, when it
/// went off, the count of intervals.
const HEAD: usize = 1 + 8 + 8 + 1 + 1 + 8 + 8 + 4;

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
    /// The network part has no usage access.
    NoAccess,
    /// Android gave no usage events, as before the first unlock after a restart.
    Locked,
    /// Its state was not told while the engine kept the second: past the window, or past the bound of
    /// what every flow keeps together.
    Late,
    /// Android did not name the flow's app.
    NoApp,
    /// Nothing was told for it: before the network part's first reading, in a gap a clock set back left, or when
    /// the network part stopped before a reading came.
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

    /// The state a byte of [`Placed::code`] codes, `None` for a byte it never writes.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Known(State::InUse),
            2 => Self::Known(State::Notification),
            3 => Self::Known(State::Background),
            0x10 => Self::Unknown(Unknown::NoAccess),
            0x20 => Self::Unknown(Unknown::Locked),
            0x30 => Self::Unknown(Unknown::Late),
            0x40 => Self::Unknown(Unknown::NoApp),
            0x50 => Self::Unknown(Unknown::NotTold),
            _ => return None,
        })
    }

    /// Where the live view counts it: 0 no state, 1 in use, 2 with its notification, 3 in the
    /// background.
    #[must_use]
    pub fn column(self) -> usize {
        usize::from(self.code() & 0x0f)
    }

    /// Why it has no state, as the live view counts it apart: 0 no usage access, 1 no events, 2 told too
    /// late, 3 no app, 4 not told; `None` for a state.
    #[must_use]
    pub fn reason(self) -> Option<usize> {
        usize::from(self.code() >> 4).checked_sub(1)
    }
}

/// What a reading knows over its span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Known {
    /// The apps' states: the intervals, and the background elsewhere.
    States,
    /// Nothing: the network part has no usage access.
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
    /// When the screen last went off, in milliseconds since 1970, if known: the start of the window "while
    /// the screen was off". For a screen on, never after it came on.
    pub screen_off: Option<u64>,
    /// The apps' intervals in use and with their notification, within the span.
    pub intervals: Vec<Interval>,
}

/// Reads one message: `None` for anything that is not exactly one of this version, a span that ends
/// before it starts, an unknown code, a time the screen came on for a screen not on, a time it went off
/// for a screen not known or after it came on, an interval outside the span or empty, or intervals with
/// a span that knows nothing.
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
    // When the screen came on is told only for a screen that is on: anything else is not one message.
    let screen = match (head[18], since) {
        (0, 0) => Screen::Off,
        (1, since) => Screen::On((since != 0).then_some(since)),
        (2, 0) => Screen::Unknown,
        _ => return None,
    };
    // When it went off, for a screen whose state is known, and for one on, not after it came on.
    let off = u64_at(head, 27)?;
    let screen_off = match (screen, off) {
        (_, 0) => None,
        (Screen::Unknown | Screen::On(None), _) => return None,
        (Screen::On(Some(on)), off) if off > on => return None,
        (_, off) => Some(off),
    };
    let count = usize::try_from(u32::from_le_bytes(head[35..39].try_into().ok()?)).ok()?;
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
        screen_off,
        intervals,
    })
}

/// A message in its stored form: what the network part's Kotlin side writes, for the engine's tests and the
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
    out.extend_from_slice(&told.screen_off.unwrap_or(0).to_le_bytes());
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
            screen_off: Some(400),
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
        for (screen, screen_off) in [
            (Screen::Off, Some(900)),
            (Screen::Off, None),
            (Screen::On(None), None),
            (Screen::On(Some(500)), Some(500)),
            (Screen::On(Some(500)), None),
            (Screen::Unknown, None),
        ] {
            let other = Told {
                screen,
                screen_off,
                ..told()
            };
            assert_eq!(read(&write(&other)), Some(other));
        }
        // A span with no length, as a reading that tells nothing new, is one too.
        let empty = Told {
            until: 1_000,
            intervals: Vec::new(),
            ..told()
        };
        assert_eq!(read(&write(&empty)), Some(empty));
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
        let mut expected = vec![2];
        expected.extend_from_slice(&1_000u64.to_le_bytes());
        expected.extend_from_slice(&61_000u64.to_le_bytes());
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&500u64.to_le_bytes());
        expected.extend_from_slice(&400u64.to_le_bytes());
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
        let bad = |told: Told| assert_eq!(read(&write(&told)), None, "{told:?}");
        // Cut anywhere, or one byte too many.
        for end in 0..good.len() {
            assert_eq!(read(&good[..end]), None, "cut at {end}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(read(&longer), None);
        // When the screen came on, told for a screen off or not known (the fuzzer's first find).
        for screen in [0, 2] {
            let mut bad = write(&Told {
                screen: Screen::Off,
                screen_off: None,
                ..told()
            });
            bad[18] = screen;
            bad[19] = 1;
            assert_eq!(read(&bad), None, "screen {screen} with a time it came on");
        }
        // When it went off, told for a screen on since a moment not known (review c1 of W5's third part, engine,
        // nit 6: a window then opened that ran while the screen was on), for one not known, or after it came on.
        bad(Told {
            screen: Screen::On(None),
            screen_off: Some(400),
            ..told()
        });
        let mut unknown = write(&Told {
            screen: Screen::Unknown,
            screen_off: None,
            ..told()
        });
        unknown[27] = 1;
        assert_eq!(
            read(&unknown),
            None,
            "a screen not known with a time it went off"
        );
        bad(Told {
            screen_off: Some(501),
            ..told()
        });
        // Another version (the first included), an unknown kind or screen, an unknown state.
        for (at, value) in [(0, 1), (0, 3), (17, 3), (18, 3), (39 + 20, 0), (39 + 20, 3)] {
            let mut bad = good.clone();
            bad[at] = value;
            assert_eq!(read(&bad), None, "byte {at} = {value}");
        }
        // A count that says more or fewer intervals than there are, or more than memory holds.
        for count in [1u32, 3, u32::MAX] {
            let mut bad = good.clone();
            bad[35..39].copy_from_slice(&count.to_le_bytes());
            assert_eq!(read(&bad), None, "count {count}");
        }
        // A span that ends before it starts; an interval empty, backwards or outside the span.
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

    /// Where the network part's Kotlin side keeps the readings it writes (`StatesTest`), one a line in hex.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/network/src/test/resources/org/visadahyu/datapavan/network/activity/states.hex"
    );

    /// The engine reads what the network part's Kotlin side writes (`States.kt`), byte for byte: its test writes the
    /// fixture and fails when it writes otherwise, and this one reads it, so that the two cannot drift
    /// apart unseen.
    #[test]
    fn the_kotlin_sides_states_are_read_as_written() -> std::io::Result<()> {
        let text = std::fs::read_to_string(FIXTURE)?;
        let messages: Vec<Vec<u8>> = text
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| {
                (0..line.len() / 2)
                    .filter_map(|i| u8::from_str_radix(line.get(2 * i..2 * i + 2)?, 16).ok())
                    .collect()
            })
            .collect();
        let t = 1_794_953_400_000;
        let read: Vec<_> = messages.iter().map(|m| read(m)).collect();
        assert_eq!(
            read,
            vec![
                Some(Told {
                    from: t,
                    until: t + 60_000,
                    known: Known::States,
                    screen: Screen::On(Some(t - 5_000)),
                    screen_off: Some(t - 65_000),
                    intervals: vec![
                        Interval {
                            uid: 10_123,
                            from: t,
                            until: t + 30_000,
                            state: State::InUse,
                        },
                        Interval {
                            uid: 10_124,
                            from: t + 2_000,
                            until: t + 60_000,
                            state: State::Notification,
                        },
                    ],
                }),
                Some(Told {
                    from: t + 60_000,
                    until: t + 120_000,
                    known: Known::NoAccess,
                    screen: Screen::Off,
                    screen_off: Some(t + 61_000),
                    intervals: Vec::new(),
                }),
                Some(Told {
                    from: t + 120_000,
                    until: t + 180_000,
                    known: Known::Locked,
                    screen: Screen::Unknown,
                    screen_off: None,
                    intervals: Vec::new(),
                }),
            ]
        );
        Ok(())
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
        let reasons = [
            Unknown::NoAccess,
            Unknown::Locked,
            Unknown::Late,
            Unknown::NoApp,
            Unknown::NotTold,
        ]
        .map(|why| Placed::Unknown(why).reason());
        assert_eq!(reasons, [0, 1, 2, 3, 4].map(Some));
        for state in [State::InUse, State::Notification, State::Background] {
            assert_eq!(Placed::Known(state).reason(), None);
        }
        for code in 0..=u8::MAX {
            assert_eq!(
                Placed::from_code(code).map(Placed::code),
                Placed::from_code(code).map(|_| code)
            );
        }
        assert_eq!(Placed::from_code(0), None);
        assert_eq!(Placed::from_code(4), None);
        assert_eq!(Placed::Known(State::Background).column(), 3);
        assert!(State::InUse.rank() > State::Notification.rank());
        assert!(State::Notification.rank() > State::Background.rank());
    }
}
