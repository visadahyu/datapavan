//! Fuzzing of how a server's QUIC answers are told (`datapavan_net::quic`, ADR 0044, unit 9b), past what
//! `identifiers` reaches: random bytes never give an Initial whose tag checks, so this target builds an
//! app's Initial from connection IDs it chooses, then the server's answer: raw bytes; an Initial sealed
//! with the server's keys of those IDs, or of another destination ID; a Retry with its integrity tag, for
//! those IDs or another destination ID; or a Version Negotiation; each in either version, with one byte
//! changed or not (review B's probe of fix round 1, reviews D and F of fix rounds 2 and 3). The input: a
//! byte for the versions, the app's destination and source IDs each after its length, a byte for how the
//! answer is made (its low three bits the kind, six of them, and 8 for a byte changed), a byte for the
//! change, and the rest: for an Initial its frames, each byte one of the frames an Initial may carry (RFC
//! 9000 17.2.2), for a Retry its token, for a Version Negotiation its versions.
//!
//! Nothing may panic, nor open more packets than an answer may, and nothing carries the app's IDs that is
//! not sent to them: a packet to the app's source ID, or a Version Negotiation from its destination ID.
//! Built for the IDs and whole, an answer carries them exactly as a client would take it: an Initial of
//! frames, in either version (RFC 9368); a Retry with a token, in the app's version only (RFC 9369 4.1),
//! not from the app's own destination ID (RFC 9000 17.2.5.1); a Version Negotiation of whole versions,
//! not the app's among them (RFC 9000 6.2). Every byte of an Initial or a Retry is under its tag, which is
//! checked whatever the app's source ID (since fix round 3): one with any byte changed, or built for
//! another destination ID, never carries them, but where the change makes it a packet no tag covers, a
//! Version Negotiation, or a Handshake or 0-RTT packet, or one with a short header, which a source ID of
//! 4 bytes or more matches by itself.
#![no_main]

use datapavan_net::{identifiers, quic};
use libfuzzer_sys::fuzz_target;

const V2: u32 = 0x6b33_43cf;
/// The shortest source ID that tells a connection's packets apart by itself (`quic::TOLD_APART`).
const TELLS: usize = 4;

fn take(rest: &[u8], max: usize) -> Option<(&[u8], &[u8])> {
    let (&n, rest) = rest.split_first()?;
    let n = (usize::from(n) % (max + 1)).min(rest.len());
    Some(rest.split_at(n))
}

/// The frames `bytes` stand for, one each, of those an Initial may carry: PADDING, PING, ACK, ACK with
/// ECN counts, CRYPTO and `CONNECTION_CLOSE`, each whole.
fn frames(bytes: &[u8]) -> Vec<u8> {
    let mut frames = Vec::new();
    for &b in bytes.iter().take(64) {
        let x = b >> 3;
        match b % 6 {
            0 => frames.push(0x00),
            1 => frames.push(0x01),
            2 => frames.extend_from_slice(&[0x02, x, 0, 0, 0]),
            3 => frames.extend_from_slice(&[0x03, x, 0, 0, 0, 1, 2, 3]),
            4 => frames.extend_from_slice(&[0x06, 0, 1, x]),
            _ => frames.extend_from_slice(&[0x1c, 0, 0, 1, x]),
        }
    }
    frames
}

fuzz_target!(|data: &[u8]| {
    let Some((&versions, rest)) = data.split_first() else {
        return;
    };
    let asked_in = if versions & 1 == 0 { 1 } else { V2 };
    let answered_in = if versions & 2 == 0 {
        asked_in
    } else if asked_in == 1 {
        V2
    } else {
        1
    };
    let Some((destination, rest)) = take(rest, 20) else {
        return;
    };
    let Some((source, rest)) = take(rest, 20) else {
        return;
    };
    let Some(client) = quic::client_initial(asked_in, (destination, source), (0, &[0x01]), 1200)
    else {
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
    // Another destination ID than the app's, of the same length or of one byte.
    let mut other = destination.to_vec();
    match other.first_mut() {
        Some(first) => *first ^= 0x80,
        None => other.push(0),
    }
    let server = [0x5a; 8];
    let initial = |original: &[u8]| {
        quic::server_initial(answered_in, original, (source, &server), (0, &frames(rest)))
            .unwrap_or_default()
    };
    let retry = |original: &[u8]| {
        quic::retry(answered_in, original, (source, &server), rest).unwrap_or_default()
    };
    let kind = (how & 7) % 6;
    let mut answer = match kind {
        0 => rest.to_vec(),
        1 => initial(destination),
        2 => retry(destination),
        3 => {
            let mut negotiation = vec![0x80, 0, 0, 0, 0, u8::try_from(source.len()).unwrap_or(0)];
            negotiation.extend_from_slice(source);
            negotiation.push(u8::try_from(destination.len()).unwrap_or(0));
            negotiation.extend_from_slice(destination);
            negotiation.extend_from_slice(rest);
            negotiation
        }
        4 => initial(&other),
        _ => retry(&other),
    };
    let changed = how & 8 != 0 && !answer.is_empty();
    if changed {
        let at = usize::from(change) % answer.len();
        answer[at] ^= 1 | (change >> 1);
    }
    let read = identifiers::Reading::new(&answer);
    let carried = read.carries(&asked);
    assert!(read.opened() <= quic::MOST_OPENED);
    if carried {
        assert!(
            sent_to(&answer, destination, source),
            "an answer not sent to the app's IDs carries them"
        );
    }
    if answer.is_empty() || answer.len() > quic::LARGEST_DATAGRAM {
        return;
    }
    if matches!(kind, 1 | 2 | 4 | 5) && (changed || kind >= 4) && still_sealed(&answer) {
        assert!(!carried, "a sealed answer changed, or for another destination ID");
    }
    if changed {
        return;
    }
    match kind {
        1 => assert!(carried, "an Initial of frames built for the IDs"),
        2 => assert_eq!(
            carried,
            answered_in == asked_in && !rest.is_empty() && destination != server,
            "a Retry built for the IDs"
        ),
        3 => {
            let whole = !rest.is_empty() && rest.len() % 4 == 0;
            let own = rest.chunks_exact(4).any(|listed| listed == asked_in.to_be_bytes());
            assert_eq!(carried, whole && !own, "a Version Negotiation built for the IDs");
        }
        _ => {}
    }
});

/// Whether `answer` is sent to the app's IDs as an answer must be: a long header whose destination ID is
/// the app's `source`, or a Version Negotiation whose source ID is the app's `destination` as well; a
/// short header that begins with the app's source ID, where that is long enough to tell.
fn sent_to(answer: &[u8], destination: &[u8], source: &[u8]) -> bool {
    let Some(&first) = answer.first() else {
        return false;
    };
    if first & 0x80 == 0 {
        return source.len() >= TELLS && answer.get(1..1 + source.len()) == Some(source);
    }
    let id = |at: usize| -> Option<(&[u8], usize)> {
        let length = usize::from(*answer.get(at)?);
        Some((answer.get(at + 1..at + 1 + length)?, at + 1 + length))
    };
    let Some((to, after)) = id(5) else {
        return false;
    };
    if answer.get(1..5) == Some(&[0; 4]) {
        return to == source && id(after).is_some_and(|(from, _)| from == destination);
    }
    to == source
}

/// Whether `answer` still reads as an Initial or a Retry of a version this engine reads, which only its
/// tag lets carry the app's IDs: a change may have made it another kind of packet.
fn still_sealed(answer: &[u8]) -> bool {
    let (Some(&first), Some(version)) = (answer.first(), answer.get(1..5)) else {
        return false;
    };
    let kind = (first >> 4) & 3;
    first & 0x80 != 0
        && match version {
            [0, 0, 0, 1] => kind == 0 || kind == 3,
            [0x6b, 0x33, 0x43, 0xcf] => kind == 1 || kind == 0,
            _ => false,
        }
}
