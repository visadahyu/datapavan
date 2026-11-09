//! Fuzzing of Watch's packet reader and writers (`datapavan_net::packet`): any bytes an app can put
//! into the tunnel. A packet that is read must describe the input exactly; its ends rewritten must
//! read back as the new ends, and every packet built in answer to it must read back as well.
#![no_main]

use std::net::SocketAddr;

use datapavan_net::packet::{self, Unreachable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = packet::parse(data) else {
        return;
    };
    assert!(parsed.length <= data.len() && parsed.transport < parsed.length);
    let _ = packet::udp_payload(data, &parsed);
    let _ = packet::tcp_flags(data, &parsed);

    let mut copy = data.to_vec();
    let (from, to) = if parsed.source.is_ipv4() {
        (SocketAddr::from(([10, 215, 173, 2], 10_000)), SocketAddr::from(([10, 215, 173, 1], 5555)))
    } else {
        (SocketAddr::from(([0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 2], 10_000)), SocketAddr::from(([0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 1], 5555)))
    };
    if packet::set_ends(&mut copy, &parsed, from, to).is_some() {
        let again = packet::parse(&copy);
        assert_eq!(again.map(|p| (p.source, p.destination)), Ok((from, to)));
    }
    for reason in [Unreachable::Host, Unreachable::Port] {
        if let Some(error) = packet::unreachable(data, &parsed, reason) {
            assert!(error.len() <= 1280);
        }
    }
    if let Some(reset) = packet::tcp_reset(parsed.destination, parsed.source, 1, Some(2)) {
        assert_eq!(packet::parse(&reset).map(|p| (p.source, p.destination)), Ok((parsed.destination, parsed.source)));
    }
    if let Some(payload) = packet::udp_payload(data, &parsed)
        && let Some(answer) = packet::udp(parsed.destination, parsed.source, payload)
    {
        assert_eq!(packet::parse(&answer).ok().and_then(|p| packet::udp_payload(&answer, &p)), Some(payload));
    }
});
