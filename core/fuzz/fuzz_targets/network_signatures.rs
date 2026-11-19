//! Differential fuzzing of Watch's matcher of the εxodus network signatures (`datapavan_net::trackers`,
//! ADR 0046, decision 2 (d)). The input is a table, as `trackers.tsv` or not, then a zero byte, then
//! names, one per line. Reading must never panic; every alternative of a signature kept is either read
//! or refused; and for every name, at ports 443 and 8080, the matcher must find exactly the trackers
//! that a plain backtracking search of the same subset finds, written here apart from it.
#![no_main]

use datapavan_net::trackers::NetworkSignatures;
use libfuzzer_sys::fuzz_target;

/// One element of the subset at the start of `p`: how many characters it takes, whether it is a run,
/// and the test of one character; `None` where `p` does not start with one.
fn element(p: &[char]) -> Option<(usize, bool, Box<dyn Fn(char) -> bool>)> {
    match p {
        ['\\', c @ ('.' | '-'), ..] => {
            let c = *c;
            Some((2, false, Box::new(move |t| t == c)))
        }
        ['.', '*', ..] => Some((2, true, Box::new(|t| t != '\n'))),
        ['.', ..] => Some((1, false, Box::new(|t| t != '\n'))),
        ['[', '0', '-', '9', ']', '*', ..] => Some((6, true, Box::new(|t: char| t.is_ascii_digit()))),
        [c, ..] if c.is_ascii_alphanumeric() || *c == '-' || *c == '_' => {
            let c = c.to_ascii_lowercase();
            Some((1, false, Box::new(move |t| t == c)))
        }
        _ => None,
    }
}

/// Whether the pattern `p` matches at the start of `t`, by trying every way.
fn at_start(p: &[char], t: &[char]) -> bool {
    let Some((taken, run, test)) = element(p) else {
        return p.is_empty();
    };
    let rest = &p[taken..];
    if run {
        let mut k = 0;
        loop {
            if at_start(rest, &t[k..]) {
                return true;
            }
            if k < t.len() && test(t[k]) {
                k += 1;
            } else {
                return false;
            }
        }
    }
    !t.is_empty() && test(t[0]) && at_start(rest, &t[1..])
}

fn search(p: &[char], t: &[char]) -> bool {
    (0..=t.len()).any(|start| at_start(p, &t[start..]))
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (tsv, names) = text.split_once('\0').unwrap_or((&text, ""));
    let Ok(read) = NetworkSignatures::parse(tsv) else {
        return;
    };
    // What a plain reading of the table keeps: each signature of more than three characters.
    let kept: Vec<&str> = tsv
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split('\t').nth(5))
        .filter(|signature| signature.chars().count() > 3)
        .collect();
    assert_eq!(kept.len(), read.trackers().len());
    let all: usize = kept.iter().map(|s| s.split('|').count()).sum();
    assert_eq!(read.alternatives() + read.refused().len(), all);
    // Backtracking costs a power of the runs: keep the comparison to small inputs.
    let runs = tsv.matches('*').count();
    if runs > 12 || names.len() > 512 {
        return;
    }
    for name in names.lines() {
        let host: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
        for port in [443u16, 8080] {
            let expected: Vec<usize> = kept
                .iter()
                .enumerate()
                .filter(|(_, signature)| {
                    signature.split('|').any(|alternative| {
                        if read.refused().iter().any(|r| r.alternative == alternative) {
                            return false;
                        }
                        let (pattern, own) = match alternative.split_once(':') {
                            Some((pattern, rest)) => {
                                let digits = rest.split_once('/').map_or("", |(d, _)| d);
                                (pattern, digits.parse::<u16>().ok())
                            }
                            None => (alternative, None),
                        };
                        own.is_none_or(|own| own == port)
                            && search(&pattern.chars().collect::<Vec<_>>(), &host)
                    })
                })
                .map(|(index, _)| index)
                .collect();
            assert_eq!(read.find(name, port), expected, "{name:?} at {port}");
        }
    }
});
