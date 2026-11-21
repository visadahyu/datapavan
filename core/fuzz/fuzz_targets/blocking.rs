//! Fuzzing of tracker blocking's readers (`datapavan_net::blocking`, W8 part 3a, ADR 0053). The input is a graded
//! table, as `hosts.tsv` or not, then a zero byte, then names, one per line, and the bytes of a stream's start. The
//! table's reader must never panic, and refuses a table whole or reads every row; for every name, the row the
//! matcher finds must be the narrowest one a plain search of every row by label boundaries finds, written here apart
//! from it; and the reader of a plain request's `Host` must never panic, and never name a host its start does not
//! hold.
#![no_main]

use datapavan_net::blocking::{HttpHost, Table, http_host};
use libfuzzer_sys::fuzz_target;

/// The narrowest row's index whose host is `name` or a suffix of it after a dot, by a search of every row.
fn naive(table: &Table, name: &str) -> Option<usize> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 || name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    table
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, e)| name == e.host || name.ends_with(&format!(".{}", e.host)))
        .max_by_key(|(_, e)| e.host.len())
        .map(|(i, _)| i)
}

fuzz_target!(|data: &[u8]| {
    let (table, rest) = match data.iter().position(|&b| b == 0) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &[][..]),
    };
    let Ok(text) = std::str::from_utf8(table) else {
        return;
    };
    let read = Table::parse(text);
    let Ok(read) = read else {
        return;
    };
    let rows = text
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    assert_eq!(read.entries().len(), rows, "every row is read, or none");
    for (i, entry) in read.entries().iter().enumerate() {
        assert_eq!(read.index_of(&entry.host), Some(i));
    }
    if let Ok(names) = std::str::from_utf8(rest) {
        for name in names.lines() {
            assert_eq!(read.find(name), naive(&read, name), "{name:?}");
        }
    }
    if let HttpHost::Found(host) = http_host(rest) {
        let lower = String::from_utf8_lossy(rest).to_ascii_lowercase();
        assert!(lower.contains(&host), "{host:?} is not in the start");
    }
});
