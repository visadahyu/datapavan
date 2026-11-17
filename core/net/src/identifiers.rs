//! What an app's datagram to a stand-in asks, and whether an answer carries it (ADR 0044, unit 9b).
//!
//! The tool's relay answers a stand-in from the address the tool reached, which the app never saw, so
//! the address alone cannot say which stand-in an answer is for, nor whether it is the server's or a
//! stranger's that reached the relay first. Where the protocol itself carries an identifier from the
//! app's datagram into its answer, that tells them: a STUN transaction ID, a QUIC connection ID or the
//! Initial keys that derive from it ([`crate::quic`]), a DNS query's ID and question, an NTP request's
//! transmit timestamp.
//!
//! Each parse of the app's datagram is strict, so that a datagram of another protocol passes it only by
//! a vanishing chance: a stand-in found to have identifiers takes only an answer that carries one, and a
//! false reading would leave its real answers unmatched. Classic STUN (RFC 3489), with a 128-bit ID and
//! no magic cookie, is not read: without the cookie, which RFC 5389 brought in to tell STUN from the
//! protocols that share its ports (RFC 7983), its parse would pass datagrams of other protocols far more
//! often. Its clients still work, as stand-ins without identifiers. A STUN indication is read as STUN but
//! gives no identifier: no one answers it (RFC 8489 6.3), so waiting for an answer that carries its ID
//! would wait for ever.
//!
//! Port 53 is not read here: the engine keeps its queries as before, by their ID and question, read as
//! loosely as unit 9 reads them. On other ports a protocol that looks like DNS is read as DNS only where
//! its answer repeats the query's ID and question (ADR 0044, unit 9b, fix round 1): LLMNR on 5355 does
//! (RFC 4795 2.1.1), and so does a Multicast DNS responder to a query from any port but 5353, a "legacy
//! unicast" one (RFC 6762 6.7). the `NetBIOS` name service on 137 does not, its responses holding no
//! question (RFC 1002 4.2.13), nor Multicast DNS between two queriers on 5353, whose responses hold none
//! and an ID of zero (RFC 6762 6, 18.1): such datagrams ask nothing, and their stand-ins are bound as
//! stand-ins without identifiers are.
//!
//! An answer is read once ([`Reading`]), whatever the number of stand-ins it is checked for, and opens
//! at most [`quic::MOST_OPENED`] QUIC packets in all.
//!
//! The bytes come from any app and any sender, so nothing here may panic or read outside a slice
//! (`fuzz_targets/identifiers.rs`, `fuzz_targets/quic_answers.rs`).

use std::cell::OnceCell;

use crate::{answers, dns, quic};

/// STUN's magic cookie (RFC 8489 5).
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
/// NTP's port (RFC 5905 7.2): only datagrams to it are read as NTP, whose parse is otherwise weak.
const NTP: u16 = 123;
/// The size of an NTP packet without extension fields or a MAC (RFC 5905 7.3).
const NTP_SIZE: usize = 48;
/// The `NetBIOS` name service (RFC 1002 4.2): DNS's header, but responses without the question.
const NETBIOS: u16 = 137;
/// Multicast DNS's port (RFC 6762): from it, a querier's responses hold no question.
const MDNS: u16 = 5353;

/// One thing an app's datagram asked, which an answer to it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    /// A STUN request (RFC 8489, RFC 5389): its method and 96-bit transaction ID, which a success or
    /// error response to it carries.
    Stun {
        /// The request's method, which its response repeats.
        method: u16,
        /// Its transaction ID.
        transaction: [u8; 12],
    },
    /// A QUIC Initial packet's IDs (RFC 9000 17.2, RFC 9001 5, RFC 9369).
    Quic(quic::Ids),
    /// A DNS query on a port other than 53: its ID and its question, in lower case.
    Dns {
        /// The query's ID.
        id: u16,
        /// The name asked for.
        question: Box<str>,
    },
    /// An NTP client request's transmit timestamp, which the server's reply carries as its origin
    /// timestamp (RFC 5905 8).
    Ntp(u64),
}

/// What `payload`, an app's datagram from its port `from` to `to`, asks an answer to carry: nothing when
/// it is of no protocol read here, or does not read strictly as one.
#[must_use]
pub fn of((from, to): (u16, u16), payload: &[u8]) -> Vec<Asked> {
    if let Some((0, method, transaction)) = stun(payload) {
        return vec![Asked::Stun {
            method,
            transaction,
        }];
    }
    if to != NETBIOS
        && !(to == MDNS && from == MDNS)
        && let Some(query) = dns_query(payload)
    {
        return vec![query];
    }
    if to == NTP
        && let Some(transmit) = ntp(payload, 3, 40)
        && transmit != 0
    {
        return vec![Asked::Ntp(transmit)];
    }
    quic::asked(payload).into_iter().map(Asked::Quic).collect()
}

/// Whether `answer` carries one of `asked` (see [`Reading::carries`]), for one check alone.
#[must_use]
pub fn carries(asked: &[Asked], answer: &[u8]) -> bool {
    Reading::new(answer).carries(asked)
}

/// A datagram that came back, read once for whatever stand-ins it is checked for: each protocol's fields
/// parsed the first time one is needed, and its QUIC packets opened [`quic::MOST_OPENED`] times at most
/// in all (ADR 0044, unit 9b, fix round 1).
pub struct Reading<'a> {
    answer: &'a [u8],
    stun: OnceCell<Option<(u16, [u8; 12])>>,
    dns: OnceCell<Option<(u16, String)>>,
    ntp: OnceCell<Option<u64>>,
    quic: Option<quic::Answer<'a>>,
}

impl<'a> Reading<'a> {
    /// `answer`, not read yet.
    #[must_use]
    pub fn new(answer: &'a [u8]) -> Self {
        Self {
            answer,
            stun: OnceCell::new(),
            dns: OnceCell::new(),
            ntp: OnceCell::new(),
            quic: quic::Answer::read(answer),
        }
    }

    /// Whether it carries one of `asked`, the latest asked first: a STUN success or error response with a
    /// request's method and transaction ID; a QUIC server's answer to an Initial packet
    /// ([`quic::Answer::carries`]); a DNS response with a query's ID and question; an NTP server reply
    /// whose origin timestamp is a request's transmit timestamp.
    #[must_use]
    pub fn carries(&self, asked: &[Asked]) -> bool {
        asked.iter().rev().any(|one| match one {
            Asked::Stun {
                method,
                transaction,
            } => {
                *self.stun.get_or_init(|| {
                    stun(self.answer)
                        .filter(|&(class, ..)| class >= 2)
                        .map(|(_, method, transaction)| (method, transaction))
                }) == Some((*method, *transaction))
            }
            Asked::Quic(ids) => self.quic.as_ref().is_some_and(|read| read.carries(ids)),
            Asked::Dns { id, question } => self
                .dns_response()
                .is_some_and(|(answered, of)| answered == *id && of == &**question),
            Asked::Ntp(transmit) => {
                *self.ntp.get_or_init(|| ntp(self.answer, 4, 24)) == Some(*transmit)
            }
        })
    }

    /// Its ID and question, when it is a DNS response with one question.
    #[must_use]
    pub fn dns_response(&self) -> Option<(u16, &str)> {
        self.dns
            .get_or_init(|| {
                Some((
                    dns::u16_at(self.answer, 0)?,
                    dns::response(self.answer)?.question,
                ))
            })
            .as_ref()
            .map(|(id, question)| (*id, question.as_str()))
    }

    /// How many QUIC packets it opened so far.
    #[must_use]
    pub fn opened(&self) -> usize {
        self.quic.as_ref().map_or(0, quic::Answer::opened)
    }
}

/// The class of a STUN message: 0 a request, 1 an indication, 2 a success response, 3 an error
/// response (RFC 8489 5); 0 for what is too short to have one.
fn stun_class(message: &[u8]) -> u8 {
    let kind = dns::u16_at(message, 0).unwrap_or(0);
    u8::try_from(((kind >> 7) & 2) | ((kind >> 4) & 1)).unwrap_or(0)
}

/// A STUN message of RFC 5389 or 8489 (5 and 14): its class, method and transaction ID. The top two
/// bits zero, the magic cookie, a length that is a multiple of 4 and the message's own, and attributes
/// that each fit, padded to 4 bytes, to its end.
fn stun(message: &[u8]) -> Option<(u8, u16, [u8; 12])> {
    let kind = dns::u16_at(message, 0)?;
    let length = usize::from(dns::u16_at(message, 2)?);
    if kind & 0xc000 != 0 || !length.is_multiple_of(4) || message.len() != 20 + length {
        return None;
    }
    if message.get(4..8)? != COOKIE {
        return None;
    }
    let mut at = 20;
    while at < message.len() {
        let value = usize::from(dns::u16_at(message, at + 2)?);
        at += 4 + value.next_multiple_of(4);
    }
    if at != message.len() {
        return None;
    }
    let method = (kind & 0x000f) | ((kind >> 1) & 0x0070) | ((kind >> 2) & 0x0f80);
    let transaction = message.get(8..20)?.try_into().ok()?;
    Some((stun_class(message), method, transaction))
}

/// A DNS query that reads strictly as one: a standard query (QR 0, opcode 0) with one question, no
/// answer or authority records, and nothing after the question but one OPT record (RFC 6891), to the
/// datagram's end.
fn dns_query(message: &[u8]) -> Option<Asked> {
    let question = answers::question(message)?;
    let (answered, authorities, additional) = (
        dns::u16_at(message, 6)?,
        dns::u16_at(message, 8)?,
        dns::u16_at(message, 10)?,
    );
    if answered != 0 || authorities != 0 || additional > 1 {
        return None;
    }
    let end = if additional == 0 {
        question.end
    } else {
        // The OPT record: the root name, its type, then a class, flags and the data's length.
        let at = question.end;
        if *message.get(at)? != 0 || dns::u16_at(message, at + 1)? != dns::TYPE_OPT {
            return None;
        }
        at + 11 + usize::from(dns::u16_at(message, at + 9)?)
    };
    (end == message.len()).then(|| Asked::Dns {
        id: dns::u16_at(message, 0).unwrap_or(0),
        question: question.name.into_boxed_str(),
    })
}

/// The 64-bit timestamp at `at` of an NTP packet of `mode` (RFC 5905 7.3): versions 1 to 4, and 48 bytes
/// or more in whole words, as extension fields and a MAC make it.
fn ntp(packet: &[u8], mode: u8, at: usize) -> Option<u64> {
    let first = *packet.first()?;
    let version = (first >> 3) & 7;
    if first & 7 != mode || !(1..=4).contains(&version) {
        return None;
    }
    if packet.len() < NTP_SIZE || !packet.len().is_multiple_of(4) {
        return None;
    }
    Some(u64::from_be_bytes(packet.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing asked.
    const NOTHING: [Asked; 0] = [];
    /// The app's port, as an engine's tests have it.
    const APP: u16 = 40_000;

    /// A STUN message of `kind` with `transaction` and one attribute of `value`, padded.
    fn stun_message(kind: u16, transaction: [u8; 12], value: &[u8]) -> Vec<u8> {
        let padded = value.len().next_multiple_of(4);
        let mut message = kind.to_be_bytes().to_vec();
        message.extend_from_slice(&u16::try_from(4 + padded).unwrap_or(0).to_be_bytes());
        message.extend_from_slice(&COOKIE);
        message.extend_from_slice(&transaction);
        // SOFTWARE (0x8022).
        message.extend_from_slice(&[0x80, 0x22]);
        message.extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
        message.extend_from_slice(value);
        message.resize(20 + 4 + padded, 0);
        message
    }

    const ID: [u8; 12] = [7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    /// A Binding request asks for its transaction ID: its success and error responses carry it, under
    /// the same method; a response with another ID, another method, an indication, or the request
    /// itself do not, nor does anything that misses the cookie, the length or its attributes.
    #[test]
    fn a_stun_request_is_answered_by_its_transaction_id() {
        let request = stun_message(0x0001, ID, b"app");
        let asked = of((APP, 3_478), &request);
        assert_eq!(
            asked,
            [Asked::Stun {
                method: 1,
                transaction: ID
            }]
        );
        assert!(carries(&asked, &stun_message(0x0101, ID, b"server")));
        assert!(carries(&asked, &stun_message(0x0111, ID, b"error")));
        let mut other = ID;
        other[11] ^= 1;
        assert!(!carries(&asked, &stun_message(0x0101, other, b"server")));
        // An Allocate success response (TURN's method 3) to a Binding request's ID.
        assert!(!carries(&asked, &stun_message(0x0103, ID, b"server")));
        assert!(!carries(&asked, &stun_message(0x0011, ID, b"indication")));
        assert!(!carries(&asked, &request));
        // An indication asks for nothing: no one answers it.
        assert_eq!(of((APP, 3_478), &stun_message(0x0011, ID, b"app")), NOTHING);
        let mut no_cookie = request.clone();
        no_cookie[4] ^= 1;
        assert_eq!(of((APP, 3_478), &no_cookie), NOTHING);
        let mut longer = request.clone();
        longer.push(0);
        assert_eq!(of((APP, 3_478), &longer), NOTHING);
        let mut cut_attribute = request.clone();
        cut_attribute[23] = 40;
        assert_eq!(of((APP, 3_478), &cut_attribute), NOTHING);
        let mut top_bits = request;
        top_bits[0] |= 0x40;
        assert_eq!(of((APP, 3_478), &top_bits), NOTHING);
        // Classic STUN, without the cookie, is not read.
        let mut classic = stun_message(0x0001, ID, b"app");
        classic[4..8].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(of((APP, 3_478), &classic), NOTHING);
    }

    /// A standard query for the A record of `name`, with an OPT record when `opt`.
    fn query(id: u16, name: &[u8], opt: bool) -> Vec<u8> {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(opt)]);
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        if opt {
            query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        }
        query
    }

    /// The answer to `query` under `id`, with no records.
    fn response(query: &[u8], id: u16) -> Vec<u8> {
        let mut response = query.to_vec();
        response[..2].copy_from_slice(&id.to_be_bytes());
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response
    }

    /// On a port other than 53, a query that reads strictly asks for its ID and question; what has
    /// records, more than an OPT record, or bytes after it asks nothing.
    #[test]
    fn a_strict_query_is_answered_by_its_id_and_question() {
        for opt in [false, true] {
            let asked_query = query(0x1234, b"\x07example\x03com\x00", opt);
            let asked = of((APP, 5_353), &asked_query);
            assert_eq!(
                asked,
                [Asked::Dns {
                    id: 0x1234,
                    question: "example.com".into()
                }]
            );
            assert!(carries(&asked, &response(&asked_query, 0x1234)));
            assert!(!carries(&asked, &response(&asked_query, 0x1235)));
            let other = query(0x1234, b"\x07example\x03org\x00", opt);
            assert!(!carries(&asked, &response(&other, 0x1234)));
            assert!(!carries(&asked, &asked_query), "the query itself");
            let mut after = asked_query.clone();
            after.push(0);
            assert_eq!(of((APP, 5_353), &after), NOTHING);
        }
        let mut with_answer = query(0x1234, b"\x07example\x03com\x00", false);
        with_answer[7] = 1;
        assert_eq!(of((APP, 5_353), &with_answer), NOTHING);
        let mut two_additional = query(0x1234, b"\x07example\x03com\x00", true);
        two_additional[11] = 2;
        assert_eq!(of((APP, 5_353), &two_additional), NOTHING);
        let mut not_opt = query(0x1234, b"\x07example\x03com\x00", true);
        let at = not_opt.len() - 9;
        not_opt[at] = 1;
        assert_eq!(of((APP, 5_353), &not_opt), NOTHING);
    }

    /// An NTP packet of `mode` with `origin` and `transmit`.
    fn ntp_packet(mode: u8, origin: u64, transmit: u64) -> Vec<u8> {
        let mut packet = vec![0u8; NTP_SIZE];
        packet[0] = (4 << 3) | mode;
        packet[24..32].copy_from_slice(&origin.to_be_bytes());
        packet[40..48].copy_from_slice(&transmit.to_be_bytes());
        packet
    }

    /// To port 123, a client request asks for its transmit timestamp, which the server's reply carries
    /// as its origin; elsewhere, or with no timestamp, it asks nothing.
    #[test]
    fn an_ntp_request_is_answered_by_its_transmit_timestamp() {
        let transmit = 0xe9a1_2b3c_4d5e_6f70;
        let request = ntp_packet(3, 0, transmit);
        let asked = of((APP, NTP), &request);
        assert_eq!(asked, [Asked::Ntp(transmit)]);
        assert!(carries(&asked, &ntp_packet(4, transmit, 1)));
        assert!(!carries(&asked, &ntp_packet(4, transmit + 1, 1)));
        assert!(!carries(&asked, &ntp_packet(3, transmit, 1)), "a client's");
        assert!(!carries(&asked, &request));
        assert_eq!(of((APP, 4_123), &request), NOTHING, "not to NTP's port");
        assert_eq!(
            of((APP, NTP), &ntp_packet(3, 0, 0)),
            NOTHING,
            "no timestamp"
        );
        let mut odd = request.clone();
        odd.push(0);
        assert_eq!(of((APP, NTP), &odd), NOTHING);
        let mut version = request;
        version[0] = (7 << 3) | 3;
        assert_eq!(of((APP, NTP), &version), NOTHING);
    }

    /// A QUIC Initial asks for its IDs, which the server's Initial built with their keys carries; one
    /// of another connection's keys does not, nor does a datagram of another protocol.
    #[test]
    fn a_quic_initial_is_answered_through_its_keys() {
        let hello = crate::tls::tests::handshake("watch.test", false);
        let destination = [0x11; 8];
        let Some(initial) = quic::client_initial(
            1,
            (&destination, &[]),
            (0, &crate::quic::tests::crypto(0, &hello)),
            1200,
        ) else {
            unreachable!("an Initial packet")
        };
        let asked = of((APP, 443), &initial);
        assert_eq!(asked.len(), 1);
        let answer = |keys: &[u8]| {
            quic::server_initial(1, keys, (&[], &[0x22; 8]), (0, &[0x01, 0x00, 0x00]))
                .unwrap_or_default()
        };
        assert!(carries(&asked, &answer(&destination)));
        assert!(!carries(&asked, &answer(&[0x12; 8])));
        assert!(!carries(&asked, &stun_message(0x0101, ID, b"server")));
        assert_eq!(of((APP, 443), b"\x12\x34 an ordinary datagram"), NOTHING);
    }

    /// The parse's checks that mutants survived (review B): a STUN length field that is not the
    /// message's own though its attributes still fit; a DNS query with an authority record, or whose OPT
    /// record's owner is not the root; an NTP request or reply shorter than 48 bytes.
    #[test]
    fn each_check_of_the_parse_refuses_what_it_is_for() {
        let mut wrong_length = stun_message(0x0001, ID, b"app");
        wrong_length[3] = 4;
        assert_eq!(of((APP, 3_478), &wrong_length), NOTHING);
        let mut authority = query(0x1234, b"\x07example\x03com\x00", false);
        authority[9] = 1;
        assert_eq!(of((APP, 5_353), &authority), NOTHING);
        let mut owner = query(0x1234, b"\x07example\x03com\x00", true);
        let at = owner.len() - 11;
        owner[at] = 1;
        assert_eq!(of((APP, 5_353), &owner), NOTHING);
        let transmit = 0xe9a1_2b3c_4d5e_6f70;
        let short_request = ntp_packet(3, 0, transmit)[..44].to_vec();
        assert_eq!(of((APP, NTP), &short_request), NOTHING);
        let asked = of((APP, NTP), &ntp_packet(3, 0, transmit));
        assert!(!carries(&asked, &ntp_packet(4, transmit, 1)[..44]));
    }

    /// The protocols that look like DNS on other ports (unit 9b, fix round 1; review B): LLMNR (RFC 4795)
    /// and a legacy unicast query to Multicast DNS (RFC 6762 6.7) ask their ID and question; the `NetBIOS` name
    /// service (RFC 1002), whose responses hold no question, and Multicast DNS from its own port, whose
    /// responses hold none either, ask nothing.
    #[test]
    fn dns_shaped_protocols_ask_only_where_their_answers_repeat_the_question() {
        let asked = query(0x1234, b"\x07example\x03com\x00", false);
        for (from, to, reads) in [
            (APP, 5_355, true),
            (APP, MDNS, true),
            (MDNS, MDNS, false),
            (APP, NETBIOS, false),
            (NETBIOS, NETBIOS, false),
        ] {
            assert_eq!(
                of((from, to), &asked).len(),
                usize::from(reads),
                "{from} to {to}"
            );
        }
    }

    /// The most an identifier holds in place, beside a DNS question's name on the heap (at most 253
    /// bytes): what ADR 0044's note on unit 9b states for 64 of them.
    #[test]
    fn an_identifier_holds_64_bytes_in_place() {
        assert_eq!(std::mem::size_of::<Asked>(), 64);
    }
}
