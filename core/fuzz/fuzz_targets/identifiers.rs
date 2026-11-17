//! Fuzzing of what tells a stand-in's answers apart (`datapavan_net::identifiers`, ADR 0044, unit 9b):
//! any datagram an app sends a stand-in, and any answer anyone sends back through the tool. The input
//! is a port in two bytes, a datagram after its length in two bytes, and an answer, the rest; the
//! datagram is read as sent from an app's port and from that port itself, strictly (`of`) and from the
//! headers alone (`named`, which every datagram through the tool to a settled peer goes through since fix
//! round 3), and the answer for what it answers in the clear (`Reading::answers`). Nothing may panic; a
//! STUN request, a DNS query or an NTP request never carries what it asked itself: an app's own datagram
//! echoed back binds no stand-in; `named` reads whatever `of` reads, and of other protocols than QUIC
//! the same (review H of fix round 3); and what an answer names in the clear is what it tells it
//! answers (review J of fix round 4): `answers` names an identifier only where `tells` finds it, and
//! names one wherever `tells` finds a STUN, DNS or NTP identifier, that very one for STUN, which it
//! reads first.
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
                Asked::Quic(_) => assert!(!named, "answers named a QUIC identifier"),
                Asked::Stun { .. } => assert_eq!(named, told, "a STUN response: {one:?}"),
                Asked::Dns { .. } | Asked::Ntp(_) => {
                    assert!(!told || answers.is_some(), "answers names nothing: {one:?}");
                }
            }
        }
    }
    let _ = read.dns_response();
});
