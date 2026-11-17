//! Fuzzing of what tells a stand-in's answers apart (`datapavan_net::identifiers`, ADR 0044, unit 9b):
//! any datagram an app sends a stand-in, and any answer anyone sends back through the tool. The input
//! is a port in two bytes, a datagram after its length in two bytes, and an answer, the rest; the
//! datagram is read as sent from an app's port and from that port itself. Nothing
//! may panic, and a STUN request, a DNS query or an NTP request never carries what it asked itself: an
//! app's own datagram echoed back binds no stand-in.
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
    for from in [40_000, port] {
        let asked = identifiers::of((from, port), datagram);
        let _ = identifiers::carries(&asked, answer);
        for one in &asked {
            if !matches!(one, Asked::Quic(_)) {
                assert!(!identifiers::carries(std::slice::from_ref(one), datagram));
            }
        }
    }
});
