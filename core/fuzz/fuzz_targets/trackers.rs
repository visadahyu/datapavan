//! Differential fuzzing of the tracker matcher. The input is code signatures, one per line, then a
//! zero byte, then class names, one per line. The matcher's Aho-Corasick automaton must find exactly
//! what a plain search of every alternative at every position finds, and must never panic.
#![no_main]

use datapavan_engine::trackers::Signatures;
use libfuzzer_sys::fuzz_target;

fn matches(alternative: &[u8], name: &[u8]) -> bool {
    name.len() >= alternative.len()
        && (0..=name.len() - alternative.len()).any(|start| {
            alternative
                .iter()
                .zip(&name[start..])
                .all(|(&a, &n)| a == b'.' || a == n)
        })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (signatures, names) = text.split_once('\0').unwrap_or((&text, ""));
    let signatures: Vec<&str> = signatures.lines().collect();
    let names: Vec<&str> = names.lines().collect();
    let tsv: String = signatures
        .iter()
        .enumerate()
        .map(|(id, signature)| format!("{id}\tname\t\t\t{signature}\t\n"))
        .collect();
    let Ok(parsed) = Signatures::parse(&tsv) else {
        return;
    };
    let expected: Vec<usize> = signatures
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
        .collect();
    assert_eq!(parsed.find(names.iter().copied()), expected);
});
