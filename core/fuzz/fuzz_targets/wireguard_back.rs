//! Fuzzing of what W7's back path reads (`datapavan_net::wireguard::swap`): any packet a `WireGuard` server,
//! or anyone behind it, can have the tunnel decrypt, and any packet an app sends into it. What is read lies
//! inside the input; a swap that is made reads back with the addresses it was given, its ports or echo
//! identifier kept, and an error's quote reads back with the addresses given for it. An MSS clamped reads back
//! no larger than its bound, with the segment's checksum still right where it was right, and nothing is read or
//! written past the packet.
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

/// The MSS option of the TCP segment at `transport` in `packet`, if it has one.
fn mss(packet: &[u8], transport: usize) -> Option<u16> {
    let offset = usize::from(packet.get(transport + 12)? >> 4) * 4;
    let mut at = transport + 20;
    let end = transport + offset;
    while at < end {
        match *packet.get(at)? {
            0 => return None,
            1 => at += 1,
            kind => {
                let length = usize::from(*packet.get(at + 1)?);
                if kind == 2 && length == 4 {
                    return Some(u16::from_be_bytes([*packet.get(at + 2)?, *packet.get(at + 3)?]));
                }
                at += length.max(2);
            }
        }
    }
    None
}

/// Whether the TCP segment's checksum is right, over its pseudo-header, IPv4's or IPv6's.
fn checksum_right(packet: &[u8], parsed: &packet::Packet) -> bool {
    let Some(segment) = packet.get(parsed.transport..parsed.length) else {
        return false;
    };
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    };
    match (parsed.source.ip(), parsed.destination.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            add(&s.octets());
            add(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            add(&s.octets());
            add(&d.octets());
        }
        _ => return false,
    }
    let length = u32::try_from(segment.len()).unwrap_or(u32::MAX);
    add(&length.to_be_bytes());
    add(&[0, 0, 0, packet::TCP]);
    add(segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
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
                let right = checksum_right(data, &parsed);
                if swap::clamp_mss(&mut clamped, &parsed, 1_000) {
                    assert_eq!(clamped.len(), data.len());
                    assert!(mss(&clamped, parsed.transport).is_some_and(|n| n <= 1_000));
                    assert!(!right || checksum_right(&clamped, &parsed), "the checksum went wrong");
                } else {
                    assert_eq!(clamped, data, "an MSS not clamped changes nothing");
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
