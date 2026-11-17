//! Fuzzing of what tells a stand-in's answers apart (`datapavan_net::identifiers`, ADR 0044, unit 9b):
//! any datagram an app sends a stand-in, and any answer anyone sends back through the tool. The input
//! is a port in two bytes, a datagram after its length in two bytes, and an answer, the rest; the
//! datagram is read as sent from an app's port and from that port itself, strictly (`of`) and from the
//! headers alone (`named`, which every datagram through the tool to a settled peer goes through since fix
//! round 3), and the answer for what it answers in the clear (`Reading::answers`). Nothing may panic; a
//! STUN request, a DNS query or an NTP request never carries what it asked itself: an app's own datagram
//! echoed back binds no stand-in; `named` reads whatever `of` reads, and of other protocols than QUIC
//! the same (review H of fix round 3); what an answer names in the clear is what it tells it answers
//! (review J of fix round 4): `answers` names an identifier only where `tells` finds it, and that very
//! one wherever `tells` finds a STUN or DNS identifier (a STUN response's cookie reads as 0x2112
//! questions, so it never reads as DNS too), and something wherever it finds an NTP one (a reply may
//! read as DNS, which is read first; review L of fix round 5); and an answer whose first packet, a short
//! header's, begins with a QUIC source ID of 4 bytes or more the app sent is addressed to it
//! (`Reading::addressed`, fix round 6).
#![no_main]

use datapavan_net::identifiers::{self, Asked};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_at_checked(4) else {
        return;
    };
    let port = u16::from_be_bytes([head[0], head[1]]);
    let length = usize::from(u16::from_be_bytes([head[2], head[3]])).min(rest.len());
    let (datagram, answer) = rest.split_at(length);
    // From an app's port, and from the destination's own port, as a Multicast DNS querier sends.
    let read = identifiers::Reading::new(answer);
    let answers = read.answers(port);
    let addressed = read.addressed(port);
    assert!(addressed.len() <= 17, "more IDs than lengths a source ID may have");
    for from in [40_000, port] {
        let asked = identifiers::of((from, port), datagram);
        let named = identifiers::named((from, port), datagram);
        for one in &asked {
            assert!(named.contains(one), "of reads what named does not: {one:?}");
        }
        if !asked.is_empty() || named.iter().any(|one| !matches!(one, Asked::Quic(_))) {
            assert_eq!(named, asked, "named reads otherwise what of reads");
        }
        let _ = identifiers::carries(&asked, answer);
        for one in &asked {
            if !matches!(one, Asked::Quic(_)) {
                assert!(!identifiers::carries(std::slice::from_ref(one), datagram));
            }
            let named = answers == Some(identifiers::fingerprint(port, one));
            let told = read.tells(one) == Some(true);
            assert!(!named || told, "answers names what tells does not find: {one:?}");
            match one {
                Asked::Quic(ids) => {
                    assert!(!named, "answers named a QUIC identifier");
                    if let Some(source) = ids.telling_source()
                        && answer.first().is_some_and(|&first| first & 0x80 == 0)
                        && answer.get(1..=source.len()) == Some(source)
                    {
                        let fingerprint = identifiers::source_fingerprint(port, source);
                        assert!(addressed.contains(&fingerprint), "not addressed: {one:?}");
                    }
                }
                Asked::Stun { .. } | Asked::Dns { .. } => {
                    assert_eq!(named, told, "a STUN or DNS response: {one:?}");
                }
                Asked::Ntp(_) => assert!(!told || answers.is_some(), "answers names nothing: {one:?}"),
            }
        }
    }
    let _ = read.dns_response();
});
