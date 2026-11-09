//! The records Watch's connection log stores (W4, ADR 0037), in the form the engine hands them to
//! Watch's Kotlin side, which seals each one under the day's key. Version 1, little-endian:
//!
//! - a flow segment: version, kind 1, the flow's number, the app's UID (`u32::MAX` unknown), start and
//!   end in milliseconds since 1970 (UTC), bytes up and down as the app sent and received them, bytes
//!   up and down as IP packets on the tunnel (what Android counts), protocol, outcome, where the name came
//!   from, ECH, the app's own DNS, flags (bit 0: the flow continues), the destination's address
//!   (length 4 or 16, then the bytes) and port, the AS number (0 none) and what its owner is, then the
//!   name and the resolver, each a length byte and UTF-8.
//! - lookups an app sent to Watch's own DNS address: version, kind 2, the UID, start and end, their
//!   count, and their packets' bytes up and down on the tunnel.
//!
//! A batch is a count (u32), then each record after its length (u16).

use std::net::{IpAddr, SocketAddr};

use crate::engine::{DnsUse, Ech, Flow, NamedBy, Outcome};
use crate::owners::NetworkKind;

/// The version of the record format.
pub const VERSION: u8 = 1;

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
    },
    /// Lookups an app sent to Watch's own DNS address between `start` and `end`.
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
                });
                out.push(match flow.named_by {
                    NamedBy::Dns => 0,
                    NamedBy::Tls => 1,
                    NamedBy::Quic => 2,
                    NamedBy::Organisation => 3,
                    NamedBy::Unknown => 4,
                });
                out.push(match flow.ech {
                    Ech::Absent => 0,
                    Ech::Offered => 1,
                    Ech::Hidden => 2,
                });
                out.push(match flow.dns {
                    DnsUse::None => 0,
                    DnsUse::Plain => 1,
                    DnsUse::Encrypted => 2,
                });
                out.push(u8::from(*continues));
                push_address(&mut out, flow.destination);
                let (asn, kind) = flow.network.map_or((0, 0), |n| {
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
                push_text(&mut out, flow.name.as_deref());
                push_text(&mut out, flow.resolver.as_deref());
            }
            Self::Lookups {
                uid,
                start,
                end,
                count,
                wire_up,
                wire_down,
            } => {
                out.push(2);
                out.extend_from_slice(&uid.unwrap_or(u32::MAX).to_le_bytes());
                out.extend_from_slice(&start.to_le_bytes());
                out.extend_from_slice(&end.to_le_bytes());
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&wire_up.to_le_bytes());
                out.extend_from_slice(&wire_down.to_le_bytes());
            }
        }
        out
    }
}

fn push_address(out: &mut Vec<u8>, address: SocketAddr) {
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
fn push_text(out: &mut Vec<u8>, text: Option<&str>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Network;
    use std::net::Ipv4Addr;

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
            ech: Ech::Offered,
            dns: DnsUse::None,
            resolver: None,
            network: Some(Network {
                asn: 32934,
                kind: NetworkKind::Own,
            }),
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
        };
        let bytes = record.encode();
        let mut expected = vec![1, 1];
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
        expected.push(0);
        assert_eq!(bytes, expected);
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
        };
        let bytes = record.encode();
        let name_at = bytes.len() - 1 - 254 - 1;
        assert_eq!(bytes[name_at], 254, "127 two-byte characters");
        let lookups = Record::Lookups {
            uid: Some(10_123),
            start: 5,
            end: 6,
            count: 3,
            wire_up: 210,
            wire_down: 540,
        };
        let all = batch(&[record.clone(), lookups.clone()]);
        assert_eq!(all[..4], 2u32.to_le_bytes());
        let first = usize::from(u16::from_le_bytes([all[4], all[5]]));
        assert_eq!(all[6..6 + first], record.encode()[..]);
        assert_eq!(all[6 + first + 2..], lookups.encode()[..]);
    }
}
