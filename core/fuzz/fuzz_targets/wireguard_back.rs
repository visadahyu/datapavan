//! Fuzzing of what W7's back path reads (`datapavan_net::wireguard::swap`): any packet a `WireGuard` server,
//! or anyone behind it, can have the tunnel decrypt, and any packet an app sends into it. What is read lies
//! inside the input; a swap that is made reads back with the addresses it was given, its ports or echo
//! identifier kept, and an error's quote reads back with the addresses given for it. An MSS clamped is never
//! above its bound, and nothing is read or written past the packet.
#![no_main]

use datapavan_net::packet;
use datapavan_net::wireguard::swap::{self, Back};
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fn tun(v4: bool) -> IpAddr {
    if v4 {
        IpAddr::from([10, 1, 10, 1])
    } else {
        IpAddr::from([0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 1])
    }
}

fuzz_target!(|data: &[u8]| {
    let mut copy = data.to_vec();
    match swap::read(data) {
        Back::Transport(parsed) => {
            assert!(parsed.length <= data.len());
            let v4 = parsed.source.is_ipv4();
            if swap::swap(&mut copy, &parsed, parsed.source.ip(), tun(v4)).is_some() {
                let again = packet::parse(&copy);
                assert_eq!(
                    again.map(|p| (p.source.port(), p.destination)),
                    Ok((
                        parsed.source.port(),
                        std::net::SocketAddr::new(tun(v4), parsed.destination.port())
                    ))
                );
            }
            if parsed.protocol == packet::TCP {
                let mut clamped = data.to_vec();
                if swap::clamp_mss(&mut clamped, &parsed, 1_000) {
                    assert_eq!(clamped.len(), data.len());
                }
            }
        }
        Back::EchoReply(echo) => {
            assert!(echo.length <= data.len() && echo.icmp < echo.length);
            let v4 = echo.source.is_ipv4();
            if swap::swap_echo(&mut copy, &echo, echo.source, tun(v4)).is_some() {
                assert!(
                    matches!(swap::read(&copy), Back::EchoReply(e) if e.id == echo.id && e.destination == tun(v4))
                );
            }
        }
        Back::Error(error) => {
            assert!(error.length <= data.len() && error.inner_transport < error.length);
            let v4 = error.source.is_ipv4();
            if swap::swap_error(&mut copy, &error, tun(v4), (tun(v4), error.to.ip())).is_some() {
                match swap::read(&copy) {
                    Back::Error(again) => {
                        assert_eq!(
                            (again.destination, again.from.ip(), again.to.ip()),
                            (tun(v4), tun(v4), error.to.ip())
                        );
                        assert_eq!(
                            (again.from.port(), again.to.port()),
                            (error.from.port(), error.to.port())
                        );
                    }
                    other => panic!("an error swapped reads as {other:?}"),
                }
            }
        }
        Back::Other => {}
    }
    let _ = swap::dont_fragment(data);
});
