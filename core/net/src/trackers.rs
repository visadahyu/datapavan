//! Tracker destinations, marked from the εxodus network signatures and from nothing else (ADR 0046,
//! decision 2 (d) and decision 4: "Trackers are named only from the εxodus network signatures").
//!
//! The table is `exodus/trackers.tsv` of the data pack the audit verifies (ADR 0015, `data/exodus`), the
//! current pack's, which Watch's Kotlin side reads and hands over: lines starting with `#` are comments,
//! every other line has six tab-separated columns, and the sixth is the network signature. εxodus writes
//! a signature as a Python regular expression and applies it as ETIP does, with `re.search`: an
//! alternative matches a name when it matches anywhere in it. The table uses a small subset of the
//! language, and this matches that subset exactly:
//!
//! - alternatives separated by `|` (the subset has no groups, so every `|` separates two);
//! - literal characters, `\.` and `\-` for a literal dot and hyphen;
//! - `.` for any one character but a line break, `.*` for any run of them, `[0-9]*` for a run of digits;
//! - one alternative with a port and a path (`54\.243\.73\.253:8080/SilverPush/`): its host part is
//!   matched as above against the destination's address or name, and its port against the
//!   destination's port. Watch never sees a path (it reads no content), so the path is not checked: such
//!   an alternative marks every flow to that address and port.
//!
//! Anything else (another escape such as the `\a` of `data.\altbeacon\.org`, which Python reads as the
//! bell character, a quantifier after a literal, a group, an anchor, another character class) lies
//! outside the subset: that alternative is refused and counted, never read as something else, and the
//! other alternatives of its signature still mark. Signatures of three characters or fewer are ignored,
//! as εxodus ignores such code signatures.
//!
//! Names are DNS names, which compare without regard to ASCII case (RFC 4343): a name is matched in
//! lower case, and the table's signatures are written in lower case but for the path above. The
//! matcher is a small automaton run over the name's characters, so a name costs at most its length
//! times the alternative's, and each alternative's longest literal run is looked for first.

use core::fmt;

/// One element of an alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Atom {
    /// This character.
    Char(char),
    /// `.`: any one character but a line break.
    Any,
    /// `.*`: any run of characters but line breaks, empty included.
    AnyRun,
    /// `[0-9]*`: any run of digits, empty included.
    Digits,
}

impl Atom {
    fn star(self) -> bool {
        matches!(self, Self::AnyRun | Self::Digits)
    }

    /// Whether this atom takes `c` as its one character, or as one of its run.
    fn takes(self, c: char) -> bool {
        match self {
            Self::Char(own) => own == c,
            Self::Any | Self::AnyRun => c != '\n',
            Self::Digits => c.is_ascii_digit(),
        }
    }
}

/// One alternative of a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    /// Index of its tracker in [`NetworkSignatures::trackers`].
    tracker: usize,
    /// The host part.
    atoms: Vec<Atom>,
    /// Its longest run of literal characters, looked for before the automaton runs.
    key: String,
    /// The port an alternative with a port and a path names.
    port: Option<u16>,
}

/// A tracker with a network signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tracker {
    /// Its id in the εxodus database.
    pub id: u32,
    /// Its name, for example "Google `AdMob`".
    pub name: String,
}

/// An alternative the matcher refused, as outside the subset it reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The line of the table it is on.
    pub line: usize,
    /// The alternative as written.
    pub alternative: String,
}

/// Why the table could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A line does not have the six tab-separated columns, or its id is not a number; the value is its
    /// line number.
    InvalidLine(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine(line) => write!(f, "invalid tracker line {line}"),
        }
    }
}

impl std::error::Error for Error {}

/// The network signatures of the table, ready for matching.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkSignatures {
    trackers: Vec<Tracker>,
    patterns: Vec<Pattern>,
    refused: Vec<Refused>,
}

impl NetworkSignatures {
    /// Reads `trackers.tsv` as `data/exodus/update.py` writes it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLine`] for a line that is not six columns with a numeric id. An alternative outside
    /// the subset is not an error: it is refused and counted ([`Self::refused`]).
    pub fn parse(tsv: &str) -> Result<Self, Error> {
        let mut table = Self::default();
        for (number, line) in tsv.lines().enumerate().map(|(i, line)| (i + 1, line)) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns: Vec<&str> = line.split('\t').collect();
            let [id, name, _, _, _, signature] = columns[..] else {
                return Err(Error::InvalidLine(number));
            };
            let id = id.parse().map_err(|_| Error::InvalidLine(number))?;
            if signature.chars().count() <= 3 {
                continue;
            }
            let tracker = table.trackers.len();
            table.trackers.push(Tracker {
                id,
                name: name.to_owned(),
            });
            for alternative in signature.split('|') {
                match Pattern::new(tracker, alternative) {
                    Some(pattern) => table.patterns.push(pattern),
                    None => table.refused.push(Refused {
                        line: number,
                        alternative: alternative.to_owned(),
                    }),
                }
            }
        }
        Ok(table)
    }

    /// The trackers with a network signature, in the order of the table.
    #[must_use]
    pub fn trackers(&self) -> &[Tracker] {
        &self.trackers
    }

    /// How many alternatives were read.
    #[must_use]
    pub fn alternatives(&self) -> usize {
        self.patterns.len()
    }

    /// The alternatives refused as outside the subset.
    #[must_use]
    pub fn refused(&self) -> &[Refused] {
        &self.refused
    }

    /// Indices into [`Self::trackers`] of the trackers one of whose alternatives matches the host
    /// `host` (a name, or an address as text) at the port `port`, in ascending order, each once.
    #[must_use]
    pub fn find(&self, host: &str, port: u16) -> Vec<usize> {
        let host: Vec<char> = host.chars().map(|c| c.to_ascii_lowercase()).collect();
        let text: String = host.iter().collect();
        let mut found: Vec<usize> = self
            .patterns
            .iter()
            .filter(|p| p.port.is_none_or(|own| own == port))
            .filter(|p| text.contains(p.key.as_str()) && search(&p.atoms, &host))
            .map(|p| p.tracker)
            .collect();
        found.dedup();
        found
    }
}

impl Pattern {
    /// Reads one alternative, or `None` for one outside the subset.
    fn new(tracker: usize, alternative: &str) -> Option<Self> {
        // The one form with a port and a path: HOST:PORT/PATH, PORT digits, the path anything.
        let (host, port) = match alternative.split_once(':') {
            Some((host, rest)) => {
                let (port, _path) = rest.split_once('/')?;
                // Digits only: Rust's own reading of a number takes a sign too.
                let digits = port.bytes().all(|b| b.is_ascii_digit());
                (host, Some(port.parse().ok().filter(|_| digits)?))
            }
            None => (alternative, None),
        };
        let atoms = atoms(host)?;
        if atoms.is_empty() {
            return None;
        }
        let mut key = String::new();
        let mut run = String::new();
        for atom in &atoms {
            if let Atom::Char(c) = atom {
                run.push(*c);
            } else {
                run.clear();
            }
            if run.len() > key.len() {
                key.clone_from(&run);
            }
        }
        Some(Self {
            tracker,
            atoms,
            key,
            port,
        })
    }
}

/// The atoms of a host part, or `None` where it lies outside the subset.
fn atoms(host: &str) -> Option<Vec<Atom>> {
    let mut atoms = Vec::new();
    let mut chars = host.chars().peekable();
    while let Some(c) = chars.next() {
        let atom = match c {
            '\\' => match chars.next()? {
                c @ ('.' | '-') => Atom::Char(c),
                _ => return None,
            },
            // A run is read only where the subset has one: `*`, `+`, `?` and `{` anywhere else are refused below,
            // as characters outside it.
            '.' if chars.peek() == Some(&'*') => {
                chars.next();
                Atom::AnyRun
            }
            '.' => Atom::Any,
            '[' => {
                let class: String = chars.by_ref().take(5).collect();
                if class != "0-9]*" {
                    return None;
                }
                Atom::Digits
            }
            c if c.is_ascii_alphanumeric() || c == '-' || c == '_' => {
                Atom::Char(c.to_ascii_lowercase())
            }
            _ => return None,
        };
        atoms.push(atom);
    }
    Some(atoms)
}

/// Whether `atoms` match anywhere in `text`, as Python's `re.search` does: the set of atoms matched so
/// far, carried over each character, with a new start at each.
fn search(atoms: &[Atom], text: &[char]) -> bool {
    let end = atoms.len();
    let mut now = vec![false; end + 1];
    now[0] = true;
    close(atoms, &mut now);
    if now[end] {
        return true;
    }
    for &c in text {
        let mut next = vec![false; end + 1];
        next[0] = true;
        for (i, atom) in atoms.iter().enumerate() {
            if now[i] && atom.takes(c) {
                // A run stays where it is; one character moves on.
                next[if atom.star() { i } else { i + 1 }] = true;
            }
        }
        close(atoms, &mut next);
        if next[end] {
            return true;
        }
        now = next;
    }
    false
}

/// A run may be empty: being before it is being after it too.
fn close(atoms: &[Atom], states: &mut [bool]) {
    for (i, atom) in atoms.iter().enumerate() {
        if states[i] && atom.star() {
            states[i + 1] = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(signatures: &[&str]) -> NetworkSignatures {
        let tsv = signatures
            .iter()
            .enumerate()
            .map(|(id, signature)| format!("{id}\tTracker {id}\t\t\t\t{signature}"))
            .collect::<Vec<_>>()
            .join("\n");
        NetworkSignatures::parse(&tsv).unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn marks(signature: &str, host: &str, port: u16) -> bool {
        !table(&[signature]).find(host, port).is_empty()
    }

    /// Each element of the subset, as Python's `re.search` reads it.
    #[test]
    fn the_subset_matches_as_python_searches() {
        // Literal labels with `\.`, anywhere in the name.
        assert!(marks(r"flurry\.com", "data.flurry.com", 443));
        assert!(marks(r"flurry\.com", "flurry.com.example.org", 443));
        assert!(!marks(r"flurry\.com", "flurryxcom", 443));
        assert!(!marks(r"flurry\.com", "flurry.co", 443));
        // A bare dot is any one character.
        assert!(marks("verify.uxcam.com", "verifyXuxcam-com", 443));
        assert!(marks(r".zapr\.in", "a.zapr.in", 443));
        assert!(
            !marks(r".zapr\.in", "zapr.in", 443),
            "a character before it"
        );
        // `.*`, empty or not, and `[0-9]*`, empty or digits only.
        assert!(marks(r".*\.estimote\.com", "cloud.estimote.com", 443));
        assert!(marks(r".*\.estimote\.com", ".estimote.com", 443));
        assert!(marks(r"adservice\.google\..*", "adservice.google.", 443));
        assert!(marks(r"mt[0-9]*\.google\.cn", "mt.google.cn", 443));
        assert!(marks(r"mt[0-9]*\.google\.cn", "mt12.google.cn", 443));
        assert!(!marks(r"mt[0-9]*\.google\.cn", "mtx.google.cn", 443));
        // `\-` is a hyphen; `|` separates alternatives.
        assert!(marks(
            r"usw\-lax\.adsrvr\.org|nothing\.here",
            "usw-lax.adsrvr.org",
            443
        ));
        assert!(marks(
            r"usw\-lax\.adsrvr\.org|nothing\.here",
            "x.nothing.here",
            443
        ));
        // Runs may be empty, also in an empty name, as Python's search finds.
        assert!(marks("[0-9]*", "", 443));
        assert!(marks(r"a[0-9]*\.b", "a.b", 443));
        // Case does not matter in a DNS name, nor in a signature.
        assert!(marks(r"flurry\.com", "DATA.Flurry.COM", 443));
        assert!(marks(r"Flurry\.com", "data.flurry.com", 443));
        // An underscore is a literal, as in a service's label.
        assert!(marks(r"_tcp\.ads\.example", "x._tcp.ads.example", 443));
        // A line break is not "any character".
        assert!(!marks("a.b", "a\nb", 443));
        assert!(!marks("a.*b", "a\nb", 443));
    }

    /// The one alternative with a port and a path matches its address at its port; the path, which Watch
    /// never sees, is not checked.
    #[test]
    fn a_port_and_a_path_match_by_address_and_port() {
        let signature = r"54\.243\.73\.253:8080/SilverPush/|silverpush\.co";
        assert!(marks(signature, "54.243.73.253", 8080));
        assert!(!marks(signature, "54.243.73.253", 443));
        assert!(!marks(signature, "54.243.73.25", 8080));
        assert!(
            marks(signature, "api.silverpush.co", 443),
            "its other alternative"
        );
    }

    /// What lies outside the subset is refused and counted, never read as something else; the other
    /// alternatives of its signature still mark.
    #[test]
    fn what_lies_outside_the_subset_is_refused_and_counted() {
        for outside in [
            r"data.\altbeacon\.org",
            r"a+\.com",
            r"ab?\.com",
            r"a{2}\.com",
            r"^ads\.com",
            r"ads\.com$",
            r"(ads)\.com",
            r"[a-z]*\.com",
            r"[0-9]\.com",
            r"x\d\.com",
            "a**b",
            "host:port/",
            "host:80",
            ":80/x",
            "host:99999/x",
            "host:+80/x",
            "a b",
            "",
            r"tail\",
        ] {
            let read = table(&[&format!("{outside}|kept\\.example")]);
            assert_eq!(
                read.refused(),
                &[Refused {
                    line: 1,
                    alternative: outside.to_owned()
                }],
                "{outside:?}"
            );
            assert_eq!(read.alternatives(), 1);
            assert_eq!(read.find("a.kept.example", 443), vec![0]);
        }
    }

    /// The table's other rules: comments and blank lines skipped, signatures of three characters or fewer
    /// ignored, a line that is not six columns refused, each tracker found once whichever alternatives
    /// match, in the order of the table.
    #[test]
    fn the_tables_lines() {
        let read = table(&["", "abc", r"one\.example|e\.example", r"two\.example"]);
        assert_eq!(
            read.trackers(),
            &[
                Tracker {
                    id: 2,
                    name: "Tracker 2".into()
                },
                Tracker {
                    id: 3,
                    name: "Tracker 3".into()
                }
            ]
        );
        assert_eq!(read.find("one.example", 443), vec![0]);
        assert_eq!(read.find("one.example.two.example", 443), vec![0, 1]);
        assert_eq!(read.find("abc", 443), Vec::<usize>::new());
        assert_eq!(
            NetworkSignatures::parse("# comment\n\n1\ta\tb\tc\td\n"),
            Err(Error::InvalidLine(3))
        );
        assert_eq!(
            NetworkSignatures::parse("x\ta\tb\tc\td\te\n"),
            Err(Error::InvalidLine(1))
        );
    }

    /// A name the alternative's atoms spell, with `filler` for a dot, a digit for a run of digits, and
    /// nothing for `.*`; and the same with every literal character changed, which it must not match.
    fn spelled(atoms: &[Atom], other: bool) -> String {
        atoms
            .iter()
            .map(|atom| match atom {
                Atom::Char(c) if other => {
                    if *c == '~' {
                        "^".into()
                    } else {
                        "~".into()
                    }
                }
                Atom::Char(c) => c.to_string(),
                Atom::Any => "q".into(),
                Atom::AnyRun => String::new(),
                Atom::Digits => "7".into(),
            })
            .collect()
    }

    /// Every alternative of the table the data pack carries matches a name it spells, at its port, and
    /// not the same name with its literal characters changed; what the table holds outside the subset is
    /// exactly what is known to lie there.
    #[test]
    fn every_signature_of_the_table_matches_a_name_it_should_and_not_one_it_should_not() {
        let tsv = include_str!("../../../data/exodus/trackers.tsv");
        let read = NetworkSignatures::parse(tsv).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(read.alternatives() > 600, "{}", read.alternatives());
        for pattern in &read.patterns {
            let port = pattern.port.unwrap_or(443);
            let yes = format!("a.{}.b", spelled(&pattern.atoms, false));
            let no = format!("a.{}.b", spelled(&pattern.atoms, true));
            assert!(
                search(&pattern.atoms, &yes.chars().collect::<Vec<_>>()),
                "{pattern:?} on {yes}"
            );
            assert!(
                read.find(&yes, port).contains(&pattern.tracker),
                "{pattern:?} on {yes}"
            );
            assert!(
                !search(&pattern.atoms, &no.chars().collect::<Vec<_>>()),
                "{pattern:?} on {no}"
            );
            if pattern.port.is_some() {
                assert!(
                    !read
                        .find(&yes, port.wrapping_add(1))
                        .contains(&pattern.tracker)
                );
            }
        }
        let refused: Vec<&str> = read
            .refused()
            .iter()
            .map(|r| r.alternative.as_str())
            .collect();
        assert_eq!(refused, vec![r"data.\altbeacon\.org"]);
    }
}
