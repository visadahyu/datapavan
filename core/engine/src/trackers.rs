//! Tracker signatures, and the matcher that finds them in an app's class names.
//!
//! The signatures come from the εxodus tracker database (`data/exodus`, ADR 0015), and they match
//! the way εxodus matches them: a signature is a list of alternatives separated by `|`, and an
//! alternative matches a class name when it occurs anywhere in it, with `.` standing for any one
//! character. εxodus writes them as regular expressions, but its converter rejects any syntax beyond
//! this, so this is the whole language. Signatures of three characters or fewer are ignored, as
//! εxodus does.
//!
//! An app has up to some hundred thousand classes and the database some six hundred alternatives,
//! so matching each alternative against each name would be too slow on a phone. Instead, one
//! Aho-Corasick automaton holds the longest literal run of every alternative; a single pass over
//! each name finds every place where an alternative can match, and only those are checked in full.

use core::fmt;
use std::collections::VecDeque;

/// One tracker from the database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tracker {
    /// The tracker's id in the εxodus database.
    pub id: u32,
    /// Its name, for example "Google Firebase Analytics".
    pub name: String,
    /// What it does, for example "Analytics" or "Advertisement".
    pub categories: Vec<String>,
    /// The company's website.
    pub website: String,
}

/// Why the signature data could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A line does not have the six tab-separated columns; the value is its line number.
    InvalidLine(usize),
    /// A code signature uses syntax the matcher does not support; the value is its line number.
    InvalidSignature(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLine(line) => write!(f, "invalid tracker line {line}"),
            Self::InvalidSignature(line) => write!(f, "unsupported code signature on line {line}"),
        }
    }
}

impl std::error::Error for Error {}

/// One alternative of a code signature.
struct Pattern {
    /// Index of its tracker in [`Signatures::trackers`].
    tracker: usize,
    /// The alternative's bytes; `.` matches any byte.
    bytes: Vec<u8>,
    /// Where its longest literal run, the key in the automaton, ends within `bytes`.
    key_end: usize,
}

/// The trackers found in one DEX file, by εxodus id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DexScan {
    /// Trackers whose classes the file defines: their code is in the app.
    pub embedded: Vec<u32>,
    /// Trackers whose classes the file refers to; includes the embedded ones.
    pub referenced: Vec<u32>,
}

/// The tracker database, ready for matching.
pub struct Signatures {
    trackers: Vec<Tracker>,
    patterns: Vec<Pattern>,
    automaton: Automaton,
}

impl Signatures {
    /// Reads `trackers.tsv` as `data/exodus/update.py` writes it: lines starting with `#` are
    /// comments, every other line has six tab-separated columns (id, name, categories separated by
    /// commas, website, code signature, network signature).
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] for a malformed line or an unsupported code signature.
    pub fn parse(tsv: &str) -> Result<Self, Error> {
        let mut trackers = Vec::new();
        let mut patterns = Vec::new();
        for (number, line) in tsv
            .lines()
            .enumerate()
            .map(|(index, line)| (index + 1, line))
        {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns: Vec<&str> = line.split('\t').collect();
            let [id, name, categories, website, signature, _network] = columns[..] else {
                return Err(Error::InvalidLine(number));
            };
            let tracker = trackers.len();
            trackers.push(Tracker {
                id: id.parse().map_err(|_| Error::InvalidLine(number))?,
                name: name.to_owned(),
                categories: categories
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned)
                    .collect(),
                website: website.to_owned(),
            });
            if signature.len() <= 3 {
                continue;
            }
            for alternative in signature.split('|') {
                patterns.push(
                    Pattern::new(tracker, alternative).ok_or(Error::InvalidSignature(number))?,
                );
            }
        }
        let automaton = Automaton::new(patterns.iter().map(Pattern::key));
        Ok(Self {
            trackers,
            patterns,
            automaton,
        })
    }

    /// Every tracker in the database, in the order of the data file.
    #[must_use]
    pub fn trackers(&self) -> &[Tracker] {
        &self.trackers
    }

    /// Indices into [`Self::trackers`] of the trackers whose signature matches at least one of the
    /// names, in ascending order.
    pub fn find<'a>(&self, names: impl IntoIterator<Item = &'a str>) -> Vec<usize> {
        let mut found = vec![false; self.trackers.len()];
        for name in names {
            let text = name.as_bytes();
            self.automaton.scan(text, |pattern_index, key_end_in_text| {
                let Some(pattern) = self.patterns.get(pattern_index) else {
                    return;
                };
                if found.get(pattern.tracker) == Some(&true) {
                    return;
                }
                if pattern.matches_at(text, key_end_in_text)
                    && let Some(slot) = found.get_mut(pattern.tracker)
                {
                    *slot = true;
                }
            });
        }
        found
            .iter()
            .enumerate()
            .filter_map(|(index, &hit)| hit.then_some(index))
            .collect()
    }
}

impl Signatures {
    /// Scans one DEX file. An app's result is the union over all its DEX files, in every APK it is
    /// installed from; a tracker that is referenced but embedded in none of them is referenced only.
    ///
    /// # Errors
    ///
    /// Returns the parser's error when the file is not a well-formed DEX file.
    pub fn scan_dex(&self, dex: &[u8]) -> Result<DexScan, crate::dex::Error> {
        let defined = crate::dex::defined_classes(dex)?;
        let referenced = crate::dex::referenced_classes(dex)?;
        let ids = |found: Vec<usize>| -> Vec<u32> {
            found
                .into_iter()
                .filter_map(|index| self.trackers.get(index).map(|t| t.id))
                .collect()
        };
        Ok(DexScan {
            embedded: ids(self.find(defined.iter().map(String::as_str))),
            referenced: ids(self.find(referenced.iter().map(String::as_str))),
        })
    }
}

impl Pattern {
    /// Accepts letters, digits, `_`, `-` and the wildcard `.`, with at least one literal byte.
    fn new(tracker: usize, alternative: &str) -> Option<Self> {
        let bytes = alternative.as_bytes().to_vec();
        if bytes.is_empty() || !bytes.iter().all(|&b| b == b'.' || symbol(b).is_some()) {
            return None;
        }
        // The longest run of literal bytes; on a tie the first.
        let (mut best_end, mut best_length, mut run) = (0, 0, 0);
        for (index, &byte) in bytes.iter().enumerate() {
            run = if byte == b'.' { 0 } else { run + 1 };
            if run > best_length {
                (best_end, best_length) = (index + 1, run);
            }
        }
        (best_length > 0).then_some(Self {
            tracker,
            bytes,
            key_end: best_end,
        })
    }

    fn key(&self) -> &[u8] {
        let start = self.bytes[..self.key_end]
            .iter()
            .rposition(|&b| b == b'.')
            .map_or(0, |dot| dot + 1);
        &self.bytes[start..self.key_end]
    }

    /// Whether the whole alternative matches `text` where its key ends just before `key_end_in_text`.
    fn matches_at(&self, text: &[u8], key_end_in_text: usize) -> bool {
        let Some(start) = key_end_in_text.checked_sub(self.key_end) else {
            return false;
        };
        text.get(start..start + self.bytes.len())
            .is_some_and(|window| {
                window
                    .iter()
                    .zip(&self.bytes)
                    .all(|(&t, &p)| p == b'.' || t == p)
            })
    }
}

/// Literal bytes of a signature: letters, digits, `_` and `-`, numbered from 0 to 63.
fn symbol(byte: u8) -> Option<usize> {
    match byte {
        b'a'..=b'z' => Some(usize::from(byte - b'a')),
        b'A'..=b'Z' => Some(usize::from(byte - b'A') + 26),
        b'0'..=b'9' => Some(usize::from(byte - b'0') + 52),
        b'_' => Some(62),
        b'-' => Some(63),
        _ => None,
    }
}

/// Any other byte of a class name; no key contains it.
const OTHER: usize = 64;
const ALPHABET: usize = 65;

/// An Aho-Corasick automaton over the keys, compiled to a full transition table.
struct Automaton {
    next: Vec<[u32; ALPHABET]>,
    /// For each state, the keys (by pattern index) that end there, including through suffixes.
    outputs: Vec<Vec<usize>>,
}

impl Automaton {
    fn new<'a>(keys: impl Iterator<Item = &'a [u8]>) -> Self {
        // The trie; 0 means "no child" until the transitions are completed below.
        let mut next: Vec<[u32; ALPHABET]> = vec![[0; ALPHABET]];
        let mut outputs: Vec<Vec<usize>> = vec![Vec::new()];
        for (pattern, key) in keys.enumerate() {
            let mut state = 0;
            for &byte in key {
                let symbol = symbol(byte).unwrap_or(OTHER);
                let child = next[state][symbol];
                state = if child == 0 {
                    let new = next.len();
                    next.push([0; ALPHABET]);
                    outputs.push(Vec::new());
                    next[state][symbol] = u32::try_from(new).unwrap_or(u32::MAX);
                    new
                } else {
                    usize_of(child)
                };
            }
            outputs[state].push(pattern);
        }

        // Breadth first, every state's failure state is shallower and already complete.
        let mut failure = vec![0_usize; next.len()];
        let mut queue: VecDeque<usize> = next[0]
            .iter()
            .filter(|&&c| c != 0)
            .map(|&c| usize_of(c))
            .collect();
        while let Some(state) = queue.pop_front() {
            let fallback = outputs[failure[state]].clone();
            outputs[state].extend(fallback);
            let fallback_row = next[failure[state]];
            for (symbol, &via_failure) in fallback_row.iter().enumerate() {
                let child = next[state][symbol];
                if child == 0 {
                    next[state][symbol] = via_failure;
                } else {
                    failure[usize_of(child)] = usize_of(via_failure);
                    queue.push_back(usize_of(child));
                }
            }
        }
        Self { next, outputs }
    }

    /// Calls `found(pattern, end)` for every key that ends at byte offset `end` (exclusive) of `text`.
    fn scan(&self, text: &[u8], mut found: impl FnMut(usize, usize)) {
        let mut state = 0;
        for (index, &byte) in text.iter().enumerate() {
            state = usize_of(self.next[state][symbol(byte).unwrap_or(OTHER)]);
            for &pattern in &self.outputs[state] {
                found(pattern, index + 1);
            }
        }
    }
}

fn usize_of(state: u32) -> usize {
    usize::try_from(state).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{DexScan, Error, Signatures};
    use std::fmt::Write as _;

    fn tsv(signatures: &[&str]) -> String {
        let mut out = String::from("# comment\n");
        for (id, signature) in signatures.iter().enumerate() {
            let _ = writeln!(
                out,
                "{id}\tTracker {id}\tAnalytics,Profiling\thttps://example.com\t{signature}\texample\\.com"
            );
        }
        out
    }

    /// Straightforward reference: every alternative at every position.
    fn naive(signatures: &[&str], names: &[&str]) -> Vec<usize> {
        let matches = |pattern: &[u8], text: &[u8]| {
            text.len() >= pattern.len()
                && (0..=text.len() - pattern.len()).any(|start| {
                    pattern
                        .iter()
                        .zip(&text[start..])
                        .all(|(&p, &t)| p == b'.' || p == t)
                })
        };
        signatures
            .iter()
            .enumerate()
            .filter(|(_, signature)| signature.len() > 3)
            .filter(|(_, signature)| {
                signature.split('|').any(|alternative| {
                    names
                        .iter()
                        .any(|name| matches(alternative.as_bytes(), name.as_bytes()))
                })
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn find(signatures: &[&str], names: &[&str]) -> Vec<usize> {
        Signatures::parse(&tsv(signatures))
            .map(|s| s.find(names.iter().copied()))
            .unwrap_or_default()
    }

    #[test]
    fn reads_the_tracker_columns() {
        let signatures = Signatures::parse(&tsv(&["com.example.", ""])).ok();
        let trackers = signatures
            .as_ref()
            .map(Signatures::trackers)
            .unwrap_or_default();
        assert_eq!(trackers.len(), 2);
        assert_eq!(trackers[0].id, 0);
        assert_eq!(trackers[0].name, "Tracker 0");
        assert_eq!(trackers[0].categories, ["Analytics", "Profiling"]);
        assert_eq!(trackers[0].website, "https://example.com");
    }

    #[test]
    fn matches_like_exodus() {
        let signatures = [
            "com.google.firebase.analytics.|com.google.android.gms.measurement",
            "com.facebook.ads",
            "io.sentry.",
            "abc",
            "",
        ];
        let names = [
            "com.google.android.gms.measurement.AppMeasurement",
            "shaded.io.sentry.Hub",
            "abc.Def",
        ];
        // Alternatives, a match anywhere in the name, and no match for signatures of 3 characters.
        assert_eq!(find(&signatures, &names), vec![0, 2]);
        // `.` is any character, as in the regular expression.
        assert_eq!(
            find(&["com.facebook.ads"], &["com/facebook/ads/AdView"]),
            vec![0]
        );
        assert_eq!(
            find(&["com.facebook.ads"], &["com.facebook.adx"]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn agrees_with_the_reference_on_overlapping_patterns() {
        // A small alphabet makes keys overlap and repeat, which exercises the automaton's suffix links.
        let alphabet = b"ab.";
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % u64::try_from(bound).unwrap_or(1)).unwrap_or(0)
        };
        for _ in 0..300 {
            let mut signatures = Vec::new();
            for _ in 0..=next(6) {
                let alternatives: Vec<String> = (0..=next(3))
                    .map(|_| {
                        let mut alternative: String = (0..=next(6))
                            .map(|_| char::from(alphabet[next(3)]))
                            .collect();
                        alternative.push('a');
                        alternative
                    })
                    .collect();
                signatures.push(alternatives.join("|"));
            }
            let names: Vec<String> = (0..=next(5))
                .map(|_| {
                    (0..next(12))
                        .map(|_| char::from(b"ab.$"[next(4)]))
                        .collect()
                })
                .collect();
            let signatures: Vec<&str> = signatures.iter().map(String::as_str).collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            assert_eq!(
                find(&signatures, &names),
                naive(&signatures, &names),
                "{signatures:?} {names:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_lines_and_unsupported_signatures() {
        assert_eq!(
            Signatures::parse("1\tonly three\tcolumns\n").err(),
            Some(Error::InvalidLine(1))
        );
        assert_eq!(
            Signatures::parse(&tsv(&["x"]).replace("0\t", "zero\t")).err(),
            Some(Error::InvalidLine(2))
        );
        for signature in [
            "com.example.(ads)",
            "com.example.*",
            "com.example|",
            "....|com.x",
        ] {
            assert_eq!(
                Signatures::parse(&tsv(&[signature])).err(),
                Some(Error::InvalidSignature(2)),
                "{signature}"
            );
        }
    }

    #[test]
    fn scans_a_real_dex_file() {
        let fixture = include_bytes!("../testdata/fixture.dex");
        let tsv = "7\tOwn\t\t\torg.visadahyu.datapavan.fixture.Fixture\t\n\
                   8\tPlatform\t\t\tandroid.net.VpnService\t\n\
                   9\tAbsent\t\t\tcom.example.absent\t\n";
        let scan = Signatures::parse(tsv).map(|s| s.scan_dex(fixture));
        assert_eq!(
            scan,
            Ok(Ok(DexScan {
                embedded: vec![7],
                referenced: vec![7, 8]
            }))
        );
        let broken = Signatures::parse(tsv).map(|s| s.scan_dex(&fixture[..100]).is_err());
        assert_eq!(broken, Ok(true));
    }

    #[test]
    fn reads_the_bundled_exodus_data() {
        let data = include_str!("../../../data/exodus/trackers.tsv");
        let signatures = Signatures::parse(data);
        assert!(signatures.is_ok());
        let signatures = signatures.ok();
        let trackers = signatures
            .as_ref()
            .map(Signatures::trackers)
            .unwrap_or_default();
        assert!(trackers.len() > 400);
        let firebase = signatures
            .as_ref()
            .map(|s| s.find(["com.google.firebase.analytics.FirebaseAnalytics"]))
            .unwrap_or_default();
        let names: Vec<&str> = firebase
            .iter()
            .map(|&i| trackers[i].name.as_str())
            .collect();
        assert!(names.contains(&"Google Firebase Analytics"), "{names:?}");
    }
}
