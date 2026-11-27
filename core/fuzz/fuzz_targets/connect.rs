//! Fuzzing of the reader of a network proxy's answer to the engine's `CONNECT`, and of the exclusion list's rule
//! (`datapavan_net::connect`, the proxy record's unit S2): any bytes a proxy, or whatever holds its address, can send,
//! and any list a network's settings can name. The invariants:
//! - a head's end is within the bytes and within `MAX_HEAD`, and the bytes cut at any point give none, or the whole
//!   bytes' answer: what comes after the head never changes it;
//! - read on from a cut that held no end (`head_end_after`), the bytes give the whole bytes' answer;
//! - a status read from the whole bytes is the one read from the head alone;
//! - the exclusion rule ends for any host and list, and an empty entry adds nothing.
//!
//! The seeds are synthetic: squid's, tinyproxy's and nginx's answers written by hand, never captured.
#![no_main]

use datapavan_net::connect::{self, MAX_HEAD};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = connect::head_end(data);
    if let Ok(Some(end)) = whole {
        assert!(end <= data.len().min(MAX_HEAD));
        if let Ok(code) = connect::status(data) {
            assert_eq!(connect::status(&data[..end]), Ok(code));
        }
    }
    for cut in [
        data.len() / 2,
        data.len().saturating_sub(1),
        data.len().min(MAX_HEAD - 1),
    ] {
        match connect::head_end(&data[..cut]) {
            Ok(None) => assert_eq!(connect::head_end_after(data, cut), whole),
            part => assert_eq!(part, whole),
        }
    }
    if let Ok(code) = connect::status(data) {
        assert!(code <= 999);
        let _ = connect::Answer::of(code);
    }
    // A host, then a list: split at the first nought byte, or in the middle.
    let at = data.iter().position(|&b| b == 0).unwrap_or(data.len() / 2);
    let host = String::from_utf8_lossy(&data[..at]);
    let list = String::from_utf8_lossy(data.get(at + 1..).unwrap_or_default());
    let excluded = connect::excluded(&host, &list);
    assert_eq!(connect::excluded(&host, &format!("{list},")), excluded);
});
