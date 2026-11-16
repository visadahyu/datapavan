//! Fuzzing of Watch's packet reader and writers (`datapavan_net::packet`): any bytes an app can put
//! into the tunnel. A packet that is read must describe the input exactly; its ends rewritten must
//! read back as the new ends, and every packet built in answer to it must read back as well. An echo
//! request that is read lies inside the input, and the reply and refusal built for it fit, as do the
//! request rebuilt for a router's error and that error, quoting it or any bytes. A hop limit set on any
//! bytes changes nothing else a read gives. Read as a sequence of fragments, the input never takes the
//! reassembler past its bounds, and what it rebuilds is a whole packet by its own header.
#![no_main]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use datapavan_net::fragments::{Bounds, Reassembler};
use datapavan_net::packet::{self, Skip, Unreachable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    echo(data);
    fragments(data);
    hops(data);
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

/// An echo request read from `data`, and the reply and the refusal built for it: each with every
/// checksum right, by a sum made here; the refusal quoting the request, which reads back the same
/// when it was quoted whole.
fn echo(data: &[u8]) {
    let Ok(echo) = packet::echo_request(data) else {
        return;
    };
    assert!(echo.icmp + 8 <= echo.length && echo.length <= data.len());
    let message = &data[echo.icmp + 8..echo.length];
    let ip = if echo.source.is_ipv4() { 20 } else { 40 };
    if let Some(reply) = packet::echo_reply(echo.destination, echo.source, echo.id, echo.sequence, message) {
        assert_eq!(reply.len(), ip + 8 + message.len());
        assert!(checks_out(&reply));
        assert!(packet::echo_request(&reply).is_err());
    }
    if let Some(error) = packet::echo_refused(data, &echo) {
        assert!(error.len() <= 1280);
        assert!(checks_out(&error));
        let quoted = &error[ip + 8..];
        if quoted.len() == echo.length {
            assert_eq!(packet::echo_request(quoted), Ok(echo));
        }
    }
    // The request as an error from the path quotes it, rebuilt with the app's identifier, and a router's
    // "time exceeded" quoting it, or the whole input, from the address pinged.
    if let Some(request) = packet::echo_request_of(echo.source, echo.destination, echo.id, echo.sequence, message) {
        assert!(checks_out(&request));
        let read = packet::echo_request(&request).map(|r| (r.source, r.destination, r.id, r.sequence));
        assert_eq!(read, Ok((echo.source, echo.destination, echo.id, echo.sequence)));
        let kind = if echo.source.is_ipv4() { (11, 0) } else { (3, 0) };
        for quoted in [&request[..], data] {
            if let Some(error) = packet::path_error(quoted, (echo.destination, echo.source), kind, [0; 4]) {
                assert!(error.len() <= 1280);
                assert!(checks_out(&error));
            }
        }
    }
}

/// A hop limit set on any bytes, as on a packet the engine built: what reads as a packet still reads
/// the same, but for its hop limit.
fn hops(data: &[u8]) {
    let mut copy = data.to_vec();
    packet::set_hops(&mut copy, 7);
    if let Ok(parsed) = packet::parse(data) {
        assert_eq!(packet::parse(&copy), Ok(packet::Packet { hops: 7, ..parsed }));
    }
    if let Ok(echo) = packet::echo_request(data) {
        assert_eq!(packet::echo_request(&copy), Ok(packet::Echo { hops: 7, ..echo }));
    }
}

/// The input as fragments, each a two-byte length and that many bytes (or what is left), 10 ms apart,
/// taken in by a reassembler with small bounds: whatever they hold, it never holds more datagrams or
/// bytes than its bounds, and each packet it rebuilds is whole by its own IP header's length, no longer
/// than IP allows, and no fragment.
fn fragments(data: &[u8]) {
    let bounds = Bounds { datagrams: 4, bytes: 16 * 1024, wait: Duration::from_millis(50) };
    let mut reassembler = Reassembler::new(bounds);
    let start = Instant::now();
    let mut rest = data;
    let mut at = start;
    while let [high, low, tail @ ..] = rest {
        let (fragment, after) = tail.split_at(usize::from(u16::from_be_bytes([*high, *low])).min(tail.len()));
        rest = after;
        at += Duration::from_millis(10);
        let taken = reassembler.take(fragment, at);
        assert!(reassembler.datagrams() <= bounds.datagrams && reassembler.bytes() <= bounds.bytes);
        if let Some(whole) = taken.whole {
            assert!(!matches!(packet::parse(&whole), Err(Skip::Fragment)));
            let length = if whole[0] >> 4 == 4 {
                usize::from(u16::from_be_bytes([whole[2], whole[3]]))
            } else {
                40 + usize::from(u16::from_be_bytes([whole[4], whole[5]]))
            };
            assert_eq!(length, whole.len());
        }
    }
    reassembler.sweep(at + bounds.wait);
    assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
}

/// The one's-complement sum of `bytes` as 16-bit words, the last byte alone padded.
fn sum(bytes: &[u8]) -> u32 {
    bytes.chunks(2).map(|word| u32::from(word[0]) << 8 | u32::from(*word.get(1).unwrap_or(&0))).sum()
}

fn folds_to_ones(mut total: u32) -> bool {
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    total == 0xffff
}

/// Whether an ICMP or ICMPv6 packet the engine built, with no options or extension headers, has its
/// checksums right: IPv4's header and ICMP's message, or ICMPv6's over its pseudo-header.
fn checks_out(packet: &[u8]) -> bool {
    if packet[0] >> 4 == 4 {
        folds_to_ones(sum(&packet[..20])) && folds_to_ones(sum(&packet[20..]))
    } else {
        let length = u32::try_from(packet.len() - 40).unwrap_or(u32::MAX);
        let pseudo = sum(&packet[8..40]) + (length >> 16) + (length & 0xffff) + u32::from(packet[6]);
        folds_to_ones(pseudo + sum(&packet[40..]))
    }
}
