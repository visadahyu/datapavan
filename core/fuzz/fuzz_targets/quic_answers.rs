//! Fuzzing of how a server's QUIC answers are told (`datapavan_net::quic`, ADR 0044, unit 9b), past what
//! `identifiers` reaches: random bytes never give an Initial whose tag checks, so this target builds an
//! app's Initial from connection IDs it chooses, then the server's answer: raw bytes, an Initial sealed
//! with the server's keys of those IDs, a Retry with its integrity tag, or a Version Negotiation, each in
//! either version, with one byte changed or not (from review B's probe of fix round 1). The input: a byte
//! for the versions, the app's destination and source IDs each after its length, a byte for how the
//! answer is made, a byte for the change, and the rest, the answer's frames, token or versions. Nothing
//! may panic; an answer built for the IDs and left whole must carry them, within the size and work an
//! answer may cost; one with a byte changed is not required to fail, since some bytes are not covered.
#![no_main]

use datapavan_net::{identifiers, quic};
use libfuzzer_sys::fuzz_target;

const V2: u32 = 0x6b33_43cf;

fn take(rest: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    let (&n, rest) = rest.split_first()?;
    let n = (usize::from(n) % (max + 1)).min(rest.len());
    Some(rest.split_at(n))
}

fuzz_target!(|data: &[u8]| {
    let Some((&versions, rest)) = data.split_first() else {
        return;
    };
    let asked_in = if versions & 1 == 0 { 1 } else { V2 };
    let answered_in = if versions & 2 == 0 { asked_in } else if asked_in == 1 { V2 } else { 1 };
    let Some((destination, rest)) = take(rest, 20) else {
        return;
    };
    let Some((source, rest)) = take(rest, 20) else {
        return;
    };
    let Some(client) = quic::client_initial(asked_in, (destination, source), (0, &[0x01]), 1200) else {
        return;
    };
    let asked = identifiers::of((40_000, 443), &client);
    assert_eq!(asked.len(), 1, "an Initial built here is always read");
    let Some((&how, rest)) = rest.split_first() else {
        return;
    };
    let Some((&change, rest)) = rest.split_first() else {
        return;
    };
    let server = [0x5a; 8];
    let mut answer = match how % 4 {
        0 => rest.to_vec(),
        1 => quic::server_initial(answered_in, destination, (source, &server), (0, rest))
            .unwrap_or_default(),
        2 => quic::retry(answered_in, destination, (source, &server), rest).unwrap_or_default(),
        _ => {
            let mut negotiation = vec![0x80, 0, 0, 0, 0, u8::try_from(source.len()).unwrap_or(0)];
            negotiation.extend_from_slice(source);
            negotiation.push(u8::try_from(destination.len()).unwrap_or(0));
            negotiation.extend_from_slice(destination);
            negotiation.extend_from_slice(rest);
            negotiation
        }
    };
    let changed = how & 4 != 0 && !answer.is_empty();
    if changed {
        let at = usize::from(change) % answer.len();
        answer[at] ^= 1 | (change >> 1);
    }
    let read = identifiers::Reading::new(&answer);
    let carried = read.carries(&asked);
    assert!(read.opened() <= quic::MOST_OPENED);
    if changed || answer.is_empty() || answer.len() > quic::LARGEST_ANSWER {
        return;
    }
    // Built for these IDs and whole: a Retry carries them, a Version Negotiation that lists whole
    // versions does, and an Initial does when its frames are ones an Initial may carry, as one PING.
    let whole_versions = !rest.is_empty() && rest.len() % 4 == 0;
    match how % 4 {
        2 => assert!(carried, "a Retry built for the IDs"),
        3 if whole_versions => assert!(carried, "a Version Negotiation built for the IDs"),
        1 if rest == [0x01; 4] => assert!(carried, "an Initial of PINGs built for the IDs"),
        _ => {}
    }
});
