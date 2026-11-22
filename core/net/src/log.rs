//! The records the network part's connection log stores (W4, ADR 0037), in the form the engine hands them to
//! The network part's Kotlin side, which seals each one under the day's key. Version 5, little-endian:
//!
//! - a flow segment: version, kind 1, the flow's number, the app's UID (`u32::MAX` unknown), start and
//!   end in milliseconds since 1970 (UTC), bytes up and down as the app sent and received them, bytes
//!   up and down as IP packets on the tunnel (what Android counts), protocol, outcome, where the name came
//!   from, ECH, the app's own DNS, flags (bit 0: the flow continues; bit 1: it came in), the
//!   destination's address (length 4 or 16, then the bytes) and port, the AS number (0 none) and what its
//!   owner is, then the name, the resolver and the DNS name where it differs from the name, each a length
//!   byte and UTF-8, then the state of its app over the segment ([`Placed::code`]): its bytes' seconds', or,
//!   for a part with no bytes, its end's (ADR 0046, "How it is built"); and last its route: one byte (0
//!   directly, 1 through the user's tool, 2 through a `WireGuard` tunnel) and the tunnel's number (u32, 0 for
//!   none); and since version 5 its proxy ([`push_proxy`]): a byte 0 for none; and since version 6 the SDK of the
//!   graded table's row that blocked it, a length byte and UTF-8, empty for a flow not blocked.
//! - lookups an app sent to the network part's own DNS address: version, kind 2, the UID, start and end, their
//!   count, their packets' bytes up and down on the tunnel, and last the app's state over them, as a segment's.
//!
//! A batch is a count (u32), then each record after its length (u16).
//!
//! Version 2 (2026-11-18, W5's first part, ADR 0044's decision 4) added the DNS name and the flag of a
//! flow that came in; version 1 had neither, and was never in a release. A DNS name is written only where
//! it differs from the name, so a flag for that would say the same twice. Version 3 (W5's second part,
//! ADR 0046's decision 1) added the state, one byte at the end of each kind: the low four bits the state
//! (0 none, 1 in use, 2 with its notification, 3 in the background), the high four why there is none.
//! Version 4 (W7, part 1, ADR 0035) added a segment's route after its state, so that the history says which
//! flows went through which tunnel, or the tool; a lookups record is as in version 3. Version 5 (W8, part 2a, ADR
//! 0052) added a segment's proxy after its route, and the code 5 of where a name came from: the destination the
//! app asked its proxy for. Version 6 (W8, part 3a, ADR 0053) added the outcome 4, a flow tracker blocking refused,
//! and after the proxy the SDK (its Maven coordinate) of the row that blocked it, which names a tracker, never a
//! host, so it is kept whatever "Log where these apps connect" says.

use std::net::{IpAddr, SocketAddr};

use crate::engine::{DnsUse, Ech, Flow, NamedBy, Network, Outcome, Proxied, Via};
use crate::owners::NetworkKind;
use crate::proxies::{Asked, Kind};
use crate::states::Placed;

/// The version of the record format.
pub const VERSION: u8 = 6;

/// One record of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A flow, or a part of it: the whole flow when it ended within the segment, else what passed
    /// from `start` to `end`.
    Segment {
        /// What the engine knows of the flow.
        flow: Flow,
        /// The segment's start, in milliseconds since 1970 (UTC).
        start: u64,
        /// The segment's end.
        end: u64,
        /// The bytes the app sent and received in the segment, then the tunnel's IP bytes up and down.
        bytes: [u64; 4],
        /// Whether the flow was still open at the segment's end.
        continues: bool,
        /// The state of its app over the segment, or why it has none (ADR 0046, decision 1): its bytes'
        /// seconds', or for a part with no bytes its end's.
        state: Placed,
    },
    /// Lookups an app sent to the network part's own DNS address between `start` and `end`.
    Lookups {
        /// The app's UID, if Android named it.
        uid: Option<u32>,
        /// The first lookup counted, in milliseconds since 1970 (UTC).
        start: u64,
        /// The end of the count.
        end: u64,
        /// How many lookups.
        count: u32,
        /// Their packets' bytes on the tunnel, up.
        wire_up: u64,
        /// The answers' bytes on the tunnel.
        wire_down: u64,
        /// The state of the app over them, as a segment's, or why it has none.
        state: Placed,
    },
}

impl Record {
    /// The record in its stored form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        match self {
            Self::Segment {
                flow,
                start,
                end,
                bytes,
                continues,
                state,
            } => {
                out.push(1);
                out.extend_from_slice(&flow.id.to_le_bytes());
                out.extend_from_slice(&flow.uid.unwrap_or(u32::MAX).to_le_bytes());
                for value in [*start, *end].iter().chain(bytes) {
                    out.extend_from_slice(&value.to_le_bytes());
                }
                out.push(flow.protocol);
                out.push(match flow.outcome {
                    Outcome::Opened => 0,
                    Outcome::Refused => 1,
                    Outcome::Unreachable => 2,
                    Outcome::Failed => 3,
                    Outcome::Blocked => 4,
                });
                out.push(named_by_code(flow.named_by));
                out.push(ech_code(flow.ech));
                out.push(dns_code(flow.dns));
                out.push(u8::from(*continues) | u8::from(flow.came_in) << 1);
                push_address(&mut out, flow.destination);
                push_network(&mut out, flow.network);
                push_text(&mut out, flow.name.as_deref());
                push_text(&mut out, flow.resolver.as_deref());
                push_text(&mut out, flow.dns_name.as_deref());
                out.push(state.code());
                push_via(&mut out, flow.via);
                push_proxy(&mut out, flow.proxy.as_deref());
                push_text(&mut out, flow.blocked.as_ref().map(|b| b.sdk.as_str()));
            }
            Self::Lookups {
                uid,
                start,
                end,
                count,
                wire_up,
                wire_down,
                state,
            } => {
                out.push(2);
                out.extend_from_slice(&uid.unwrap_or(u32::MAX).to_le_bytes());
                out.extend_from_slice(&start.to_le_bytes());
                out.extend_from_slice(&end.to_le_bytes());
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&wire_up.to_le_bytes());
                out.extend_from_slice(&wire_down.to_le_bytes());
                out.push(state.code());
            }
        }
        out
    }
}

/// A flow's route, as the log and the live view's snapshot write it: a byte (0 directly, 1 through the
/// tool, 2 through a tunnel), then the tunnel's number, 0 for none.
pub(crate) fn push_via(out: &mut Vec<u8>, via: Via) {
    let (code, tunnel) = match via {
        Via::Direct => (0, 0),
        Via::Tool => (1, 0),
        Via::Tunnel(t) => (2, t),
    };
    out.push(code);
    out.extend_from_slice(&tunnel.to_le_bytes());
}

/// Where a flow's name came from, as the log and the live view's snapshot write it.
pub(crate) fn named_by_code(named_by: NamedBy) -> u8 {
    match named_by {
        NamedBy::Dns => 0,
        NamedBy::Tls => 1,
        NamedBy::Quic => 2,
        NamedBy::Organisation => 3,
        NamedBy::Unknown => 4,
        NamedBy::Proxy => 5,
    }
}

/// A flow's proxy (W8, part 2a; ADR 0052), as the log and the live view's snapshot write it: its kind, one byte
/// (0 none, 1 SOCKS5, 2 SOCKS4, 3 an HTTP `CONNECT`, 4 a plain request to an HTTP proxy, 5 Telegram's `MTProto`,
/// 6 `WhatsApp`'s, 7 Signal's); for a proxy, then flags (bit 0: Android's proxy setting names it; bit 1: a password
/// crossed the network unencrypted; bit 2: its address is outside the maker's network; bit 3: the destination
/// asked for follows; bit 4: the flow's own address and names were left out, as "Log where these apps connect"
/// said), the destination asked for where bit 3 says (its address, length 0, 4 or 16 and the bytes, then its
/// name, a length byte and UTF-8, then its port, u16), the proxy's own name, the organisation behind its network
/// and the cover name its hello sent, each a length byte and UTF-8, empty for none, and last the trackers matched
/// on its names before anything was left out: a count byte (at most 8) and each one's εxodus id (u32). No
/// credential is ever written: none is kept. Bit 4 and the trackers came in the fix round of W8 part 2a, before
/// any release wrote version 5.
pub(crate) fn push_proxy(out: &mut Vec<u8>, proxy: Option<&Proxied>) {
    let Some(proxy) = proxy else {
        out.push(0);
        return;
    };
    out.push(match proxy.kind {
        Kind::Socks5 => 1,
        Kind::Socks4 => 2,
        Kind::Connect => 3,
        Kind::Forward => 4,
        Kind::MtProto => 5,
        Kind::WhatsApp => 6,
        Kind::Signal => 7,
    });
    out.push(
        u8::from(proxy.setting)
            | u8::from(proxy.password) << 1
            | u8::from(proxy.outside_maker) << 2
            | u8::from(proxy.asked.is_some()) << 3
            | u8::from(proxy.left_out) << 4,
    );
    if let Some((asked, port)) = &proxy.asked {
        match asked {
            Asked::Address(IpAddr::V4(ip)) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
                push_text(out, None);
            }
            Asked::Address(IpAddr::V6(ip)) => {
                out.push(16);
                out.extend_from_slice(&ip.octets());
                push_text(out, None);
            }
            Asked::Name(name) => {
                out.push(0);
                push_text(out, Some(name));
            }
        }
        out.extend_from_slice(&port.to_le_bytes());
    }
    push_text(out, proxy.proxy_name.as_deref());
    push_text(out, proxy.organisation.as_deref());
    push_text(out, proxy.cover.as_deref());
    let trackers = &proxy.trackers[..proxy.trackers.len().min(crate::engine::MAX_TRACKERS)];
    out.push(u8::try_from(trackers.len()).unwrap_or(0));
    for id in trackers {
        out.extend_from_slice(&id.to_le_bytes());
    }
}

/// What a flow's hello said of ECH, as the log and the snapshot write it.
pub(crate) fn ech_code(ech: Ech) -> u8 {
    match ech {
        Ech::Absent => 0,
        Ech::Offered => 1,
        Ech::Hidden => 2,
    }
}

/// Whether a flow carries the app's own DNS, as the log and the snapshot write it.
pub(crate) fn dns_code(dns: DnsUse) -> u8 {
    match dns {
        DnsUse::None => 0,
        DnsUse::Plain => 1,
        DnsUse::Encrypted => 2,
    }
}

/// A network's AS number (0 for none) and what its owner is (0 none, 1 a company's own, 2 hosting, 3
/// not listed).
pub(crate) fn push_network(out: &mut Vec<u8>, network: Option<Network>) {
    let (asn, kind) = network.map_or((0, 0), |n| {
        (
            n.asn,
            match n.kind {
                NetworkKind::Own => 1,
                NetworkKind::Hosting => 2,
                NetworkKind::Unlisted => 3,
            },
        )
    });
    out.extend_from_slice(&asn.to_le_bytes());
    out.push(kind);
}

/// An address: its length (4 or 16), its bytes, and the port.
pub(crate) fn push_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(16);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port().to_le_bytes());
}

/// A length byte and at most 255 bytes of UTF-8, cut at a character boundary.
pub(crate) fn push_text(out: &mut Vec<u8>, text: Option<&str>) {
    let text = text.unwrap_or("");
    let mut end = text.len().min(255);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    out.push(u8::try_from(end).unwrap_or(u8::MAX));
    out.extend_from_slice(&text.as_bytes()[..end]);
}

/// A batch of records in their stored form.
#[must_use]
pub fn batch(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(records.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for record in records {
        let encoded = record.encode();
        out.extend_from_slice(
            &u16::try_from(encoded.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&encoded);
    }
    out
}

/// A segment's state, read past its fixed fields, its address, network and three texts; before its route and
/// its proxy.
#[cfg(test)]
fn segment_state(record: &[u8]) -> Option<Placed> {
    // Version, kind, number, UID, six counts, six codes.
    let mut at = 1 + 1 + 8 + 4 + 6 * 8 + 6;
    at += 1 + usize::from(*record.get(at)?) + 2;
    at += 4 + 1;
    for _ in 0..3 {
        at += 1 + usize::from(*record.get(at)?);
    }
    record.get(at).copied().and_then(Placed::from_code)
}

/// The state of each segment in a batch, in order, for the engine's tests.
#[cfg(test)]
pub(crate) fn states_in(batch: &[u8]) -> Vec<Placed> {
    let mut states = Vec::new();
    let mut at = 4;
    while let Some(length) = batch.get(at..at + 2) {
        let length = usize::from(u16::from_le_bytes([length[0], length[1]]));
        if let Some(record) = batch.get(at + 2..at + 2 + length)
            && record.get(1) == Some(&1)
            && let Some(state) = segment_state(record)
        {
            states.push(state);
        }
        at += 2 + length;
    }
    states
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::states::Unknown;
    use std::net::Ipv4Addr;

    const NOT_TOLD: Placed = Placed::Unknown(Unknown::NotTold);

    fn flow() -> Flow {
        Flow {
            id: 7,
            protocol: 6,
            app: SocketAddr::from(([10, 215, 173, 1], 40_000)),
            destination: SocketAddr::from(([157, 240, 1, 35], 443)),
            uid: Some(10_123),
            outcome: Outcome::Opened,
            name: Some("Meta Platforms, Inc.".into()),
            named_by: NamedBy::Organisation,
            dns_name: None,
            came_in: false,
            ech: Ech::Offered,
            dns: DnsUse::None,
            resolver: None,
            network: Some(Network {
                asn: 32934,
                kind: NetworkKind::Own,
            }),
            via: crate::engine::Via::Direct,
            proxy: None,
            blocked: None,
        }
    }

    #[test]
    fn encodes_a_segment_field_by_field() {
        let record = Record::Segment {
            flow: flow(),
            start: 1_000,
            end: 2_000,
            bytes: [300, 40_000, 820, 42_900],
            continues: true,
            state: NOT_TOLD,
        };
        let bytes = record.encode();
        let mut expected = vec![6, 1];
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&10_123u32.to_le_bytes());
        for v in [1_000u64, 2_000, 300, 40_000, 820, 42_900] {
            expected.extend_from_slice(&v.to_le_bytes());
        }
        expected.extend_from_slice(&[6, 0, 3, 1, 0, 1, 4, 157, 240, 1, 35]);
        expected.extend_from_slice(&443u16.to_le_bytes());
        expected.extend_from_slice(&32934u32.to_le_bytes());
        expected.push(1);
        expected.push(20);
        expected.extend_from_slice(b"Meta Platforms, Inc.");
        expected.extend_from_slice(&[0, 0]);
        expected.push(0x50);
        expected.extend_from_slice(&[0, 0, 0, 0, 0]);
        // No proxy, and blocked by no row.
        expected.extend_from_slice(&[0, 0]);
        assert_eq!(bytes, expected);
    }

    /// Version 6's addition (W8, part 3a; ADR 0053): the outcome 4 of a flow tracker blocking refused, and the SDK
    /// of the row that blocked it last, kept with its destination left out as with it.
    #[test]
    fn encodes_a_blocked_flow_and_its_rows_sdk_last() {
        let blocked = Flow {
            outcome: Outcome::Blocked,
            blocked: Some(Box::new(crate::engine::BlockedBy {
                sdk: "com.google.firebase:firebase-analytics".into(),
            })),
            ..flow()
        };
        let segment = |flow| Record::Segment {
            flow,
            start: 1_000,
            end: 2_000,
            bytes: [0; 4],
            continues: false,
            state: NOT_TOLD,
        };
        let bytes = segment(blocked.clone()).encode();
        let outcome = 1 + 1 + 8 + 4 + 6 * 8 + 1;
        assert_eq!((bytes[0], bytes[outcome]), (6, 4));
        assert!(bytes.ends_with(b"\x00\x26com.google.firebase:firebase-analytics"));
        let not = segment(flow()).encode();
        assert_eq!((not[outcome], not.last().copied()), (0, Some(0)));
    }

    /// Version 4's addition: a segment's route after its state, each kind, with its tunnel's number.
    #[test]
    fn encodes_a_segments_route_after_its_state() {
        for (via, end) in [
            (Via::Direct, [0, 0, 0, 0, 0]),
            (Via::Tool, [1, 0, 0, 0, 0]),
            (Via::Tunnel(0x0102_0304), [2, 4, 3, 2, 1]),
        ] {
            let segment = Record::Segment {
                flow: Flow { via, ..flow() },
                start: 1_000,
                end: 2_000,
                bytes: [1, 2, 3, 4],
                continues: false,
                state: NOT_TOLD,
            };
            let bytes = segment.encode();
            assert_eq!(
                &bytes[bytes.len() - 8..],
                &[&[NOT_TOLD.code()][..], &end, &[0, 0]].concat()[..]
            );
        }
    }

    /// Version 3's addition: the state, the last byte of a lookups record and of a segment before its route,
    /// every code the engine writes.
    #[test]
    fn encodes_the_state_last_in_each_kind() {
        use crate::states::State;
        for state in [
            Placed::Known(State::InUse),
            Placed::Known(State::Notification),
            Placed::Known(State::Background),
            Placed::Unknown(Unknown::NoAccess),
            Placed::Unknown(Unknown::Locked),
            Placed::Unknown(Unknown::Late),
            Placed::Unknown(Unknown::NoApp),
            NOT_TOLD,
        ] {
            let segment = Record::Segment {
                flow: flow(),
                start: 1_000,
                end: 2_000,
                bytes: [1, 2, 3, 4],
                continues: false,
                state,
            };
            let lookups = Record::Lookups {
                uid: None,
                start: 5,
                end: 6,
                count: 1,
                wire_up: 2,
                wire_down: 3,
                state,
            };
            let (segment, lookups) = (segment.encode(), lookups.encode());
            assert_eq!((segment[0], segment[segment.len() - 8]), (6, state.code()));
            assert_eq!(
                (lookups[0], lookups.last().copied()),
                (6, Some(state.code()))
            );
            assert_eq!(Placed::from_code(state.code()), Some(state));
        }
        let lookups = Record::Lookups {
            uid: Some(10_123),
            start: 5,
            end: 6,
            count: 3,
            wire_up: 210,
            wire_down: 540,
            state: Placed::Known(State::Background),
        };
        assert_eq!(lookups.encode().len(), 1 + 1 + 4 + 8 + 8 + 4 + 8 + 8 + 1);
    }

    /// Version 2's additions: the flag of a flow that came in, beside the one of a flow that continues,
    /// and the DNS name last.
    #[test]
    fn encodes_the_dns_name_and_a_flow_that_came_in() {
        let mut both = flow();
        both.name = Some("other.example".into());
        both.named_by = NamedBy::Tls;
        both.dns_name = Some("www.example.com".into());
        both.came_in = true;
        let record = |continues| Record::Segment {
            flow: both.clone(),
            start: 1_000,
            end: 2_000,
            bytes: [0; 4],
            continues,
            state: NOT_TOLD,
        };
        let bytes = record(false).encode();
        // Version, kind, number, UID, six times; protocol, outcome, named by, ECH, DNS, flags.
        let flags = 1 + 1 + 8 + 4 + 6 * 8 + 5;
        assert_eq!((bytes[0], bytes[flags]), (6, 0b10));
        assert_eq!(record(true).encode()[flags], 0b11);
        assert!(bytes.ends_with(b"\x0dother.example\x00\x0fwww.example.com\x50\0\0\0\0\0\0\0"));
    }

    #[test]
    fn cuts_long_names_at_a_character_and_batches_with_lengths() {
        let mut long = flow();
        long.name = Some("é".repeat(200));
        long.network = None;
        long.uid = None;
        long.destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let record = Record::Segment {
            flow: long,
            start: 0,
            end: 0,
            bytes: [0; 4],
            continues: false,
            state: NOT_TOLD,
        };
        let bytes = record.encode();
        // The name, then an empty resolver, no DNS name, the state, the route, no proxy and no row.
        let name_at = bytes.len() - 1 - 1 - 5 - 1 - 1 - 1 - 254 - 1;
        assert_eq!(bytes[name_at], 254, "127 two-byte characters");
        let lookups = Record::Lookups {
            uid: Some(10_123),
            start: 5,
            end: 6,
            count: 3,
            wire_up: 210,
            wire_down: 540,
            state: NOT_TOLD,
        };
        let all = batch(&[record.clone(), lookups.clone()]);
        assert_eq!(all[..4], 2u32.to_le_bytes());
        let first = usize::from(u16::from_le_bytes([all[4], all[5]]));
        assert_eq!(all[6..6 + first], record.encode()[..]);
        assert_eq!(all[6 + first + 2..], lookups.encode()[..]);
    }
}
