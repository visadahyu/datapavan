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
//! unicast" one (RFC 6762 6.7). The `NetBIOS` name service on 137 does not, its responses holding no
//! question (RFC 1002 4.2.13), nor Multicast DNS between two queriers on 5353, whose responses hold none
//! and an ID of zero (RFC 6762 6, 18.1): such datagrams ask nothing, and their stand-ins are bound as
//! stand-ins without identifiers are.
//!
//! An answer is read once ([`Reading`]), whatever the number of stand-ins it is checked for, and opens
//! at most [`quic::MOST_OPENED`] QUIC packets in all. What costs no packet opened is told first
//! ([`Reading::tells`]); the engine spends the opens on what is left ([`Reading::opens_for`]).
//!
//! What the app asked of every peer is also kept as a fingerprint ([`fingerprint`]), so that an identifier
//! it sent to two peers is known for one that tells neither apart (ADR 0044, unit 9b, fix round 2).
//!
//! The bytes come from any app and any sender, so nothing here may panic or read outside a slice
//! (`fuzz_targets/identifiers.rs`, `fuzz_targets/quic_answers.rs`).

use std::cell::OnceCell;
use std::hash::{BuildHasher, Hash, Hasher, RandomState};
use std::sync::LazyLock;

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
/// Of a STUN message, the bytes over which its attributes are walked ([`stun`]): Watch's tunnel's largest
/// MTU, [`quic::LARGEST_DATAGRAM`] (ADR 0044, unit 9b, fix rounds 4 and 5).
const WALKED: usize = quic::LARGEST_DATAGRAM;

/// The keys of this run's fingerprints ([`fingerprint`]): random, so that no one can choose identifiers
/// whose fingerprints meet.
static KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);

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

impl Hash for Asked {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Stun {
                method,
                transaction,
            } => (0u8, method, transaction).hash(state),
            Self::Quic(ids) => (1u8, ids).hash(state),
            Self::Dns { id, question } => dns_hash(*id, question, state),
            Self::Ntp(transmit) => (3u8, transmit).hash(state),
        }
    }
}

/// A DNS query's ID and question as [`Asked::Dns`] hashes them, whatever port it went to.
fn dns_hash<H: Hasher>(id: u16, question: &str, state: &mut H) {
    (2u8, id, question).hash(state);
}

/// The fingerprint of `asked` sent to `port`: 64 bits of the hash of Rust's `RandomState`, keyed at random
/// for each run (an algorithm Rust leaves unspecified, `SipHash-1-3` today) (ADR 0044,
/// unit 9b, fix round 2). Two equal identifiers to one port have one; two different ones meet by a chance
/// of 2^-64.
#[must_use]
pub fn fingerprint(port: u16, asked: &Asked) -> u64 {
    let mut state = KEYS.build_hasher();
    port.hash(&mut state);
    asked.hash(&mut state);
    state.finish()
}

/// The fingerprint of a DNS query with `id` for `question` sent to `port`, as [`fingerprint`] gives it for
/// [`Asked::Dns`]: on port 53, where the engine reads a query loosely, without making one.
#[must_use]
pub fn dns_fingerprint(port: u16, id: u16, question: &str) -> u64 {
    let mut state = KEYS.build_hasher();
    port.hash(&mut state);
    dns_hash(id, question, &mut state);
    state.finish()
}

/// What `payload`, an app's datagram from its port `from` to `to`, asks an answer to carry: nothing when
/// it is of no protocol read here, or does not read strictly as one. A QUIC Initial is opened and its tag
/// checked ([`quic::asked`]), in a datagram of [`quic::LARGEST_DATAGRAM`] bytes at most.
#[must_use]
pub fn of(ports: (u16, u16), payload: &[u8]) -> Vec<Asked> {
    read(ports, payload, quic::asked)
}

/// What [`of`] reads, with a QUIC Initial's IDs read from its headers alone, none opened
/// ([`quic::named`]): for what the app is remembered to have sent a peer (ADR 0044, unit 9b, fix round
/// 3), on every datagram through the tool, at a cost a datagram's parse bounds without AEAD.
#[must_use]
pub fn named(ports: (u16, u16), payload: &[u8]) -> Vec<Asked> {
    read(ports, payload, quic::named)
}

/// What [`of`] and [`named`] read, QUIC's by `quic`.
fn read((from, to): (u16, u16), payload: &[u8], quic: fn(&[u8]) -> Vec<quic::Ids>) -> Vec<Asked> {
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
    quic(payload).into_iter().map(Asked::Quic).collect()
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

    /// Whether it carries one of `asked`: each told where that costs no packet opened, then those only
    /// an opened packet tells, the latest asked first, while it may open more.
    #[must_use]
    pub fn carries(&self, asked: &[Asked]) -> bool {
        let mut costly = false;
        for one in asked {
            match self.tells(one) {
                Some(true) => return true,
                Some(false) => {}
                None => costly = true,
            }
        }
        costly
            && asked
                .iter()
                .rev()
                .any(|one| self.tells(one).is_none() && self.opens_for(one))
    }

    /// Whether it carries `one` where that costs no QUIC packet opened: a STUN success or error response
    /// with a request's method and transaction ID; a QUIC server's answer that its IDs or its kind tell
    /// ([`quic::Answer::tells`]); a DNS response with a query's ID and question; an NTP server reply whose
    /// origin timestamp is a request's transmit timestamp. `None` for a QUIC identifier only an opened
    /// packet tells ([`Reading::opens_for`]).
    #[must_use]
    pub fn tells(&self, one: &Asked) -> Option<bool> {
        Some(match one {
            Asked::Stun {
                method,
                transaction,
            } => self.stun_response() == Some((*method, *transaction)),
            Asked::Quic(ids) => {
                return self
                    .quic
                    .as_ref()
                    .map_or(Some(false), |read| read.tells(ids));
            }
            Asked::Dns { id, question } => self
                .dns_response()
                .is_some_and(|(answered, of)| answered == *id && of == &**question),
            Asked::Ntp(transmit) => {
                *self.ntp.get_or_init(|| ntp(self.answer, 4, 24)) == Some(*transmit)
            }
        })
    }

    /// Whether it carries `one`, a QUIC identifier [`Reading::tells`] left to an opened packet, by
    /// opening one ([`quic::Answer::opens_for`]); `false` once it may open no more.
    #[must_use]
    pub fn opens_for(&self, one: &Asked) -> bool {
        match (one, &self.quic) {
            (Asked::Quic(ids), Some(read)) => read.opens_for(ids),
            _ => false,
        }
    }

    /// How many more QUIC packets it may open.
    #[must_use]
    pub fn opens_left(&self) -> usize {
        self.quic.as_ref().map_or(0, quic::Answer::opens_left)
    }

    /// Its ID and question, when it is a DNS response with one question, the root among them
    /// ([`dns::answered`]: since fix round 3, as a query's is read, so that a query for the root binds by
    /// its answer).
    #[must_use]
    pub fn dns_response(&self) -> Option<(u16, &str)> {
        self.dns
            .get_or_init(|| dns::answered(self.answer))
            .as_ref()
            .map(|(id, question)| (*id, question.as_str()))
    }

    /// The fingerprint ([`fingerprint`]) of what it answers where it names that in the clear, as an answer
    /// on `port`: a STUN success or error response's method and transaction ID; a DNS response's ID and
    /// question; on port 123, an NTP server reply's origin timestamp. `None` for anything else, a QUIC
    /// packet among them, whose answer names nothing of the app's but under keys. So an answer under a
    /// relay's name is told to be another peer's, though no stand-in may take it (ADR 0044, unit 9b, fix
    /// round 3).
    #[must_use]
    pub fn answers(&self, port: u16) -> Option<u64> {
        if let Some((method, transaction)) = self.stun_response() {
            return Some(fingerprint(
                port,
                &Asked::Stun {
                    method,
                    transaction,
                },
            ));
        }
        if let Some((id, question)) = self.dns_response() {
            return Some(dns_fingerprint(port, id, question));
        }
        if port == NTP
            && let Some(origin) = *self.ntp.get_or_init(|| ntp(self.answer, 4, 24))
        {
            return Some(fingerprint(port, &Asked::Ntp(origin)));
        }
        None
    }

    /// Its method and transaction ID, when it is a STUN success or error response.
    fn stun_response(&self) -> Option<(u16, [u8; 12])> {
        *self.stun.get_or_init(|| {
            stun(self.answer)
                .filter(|&(class, ..)| class >= 2)
                .map(|(_, method, transaction)| (method, transaction))
        })
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
/// that each fit, padded to 4 bytes, to its end, walked over its first [`WALKED`] bytes.
///
/// A STUN message over UDP SHOULD be smaller than the path's MTU (RFC 8489 6.1), at most 1,500 bytes
/// through Watch's tunnel, but need not be: the rule is a SHOULD so that STUN may probe the MTU (RFC
/// 5780), whose PADDING makes a response as large as the server's outgoing MTU (5780 6.1, 7.6), larger
/// than the request where the server's path is. So a larger message is read, its header and its
/// transaction ID, which tell its answer apart, as any other's; its attributes past the first 1,500
/// bytes are taken to fit, so that walking them costs no more than 1,500 bytes' worth (fix round 4,
/// review G's G6: 65,500 bytes of empty attributes cost 36 us; fix round 5, review J's minor 2: the
/// round's bound refused such a message whole, a padded response among them).
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
    // Past the walk's end, `at` is at the message's end or, for a larger message, at an attribute's
    // start beyond the walked bytes; past its end only where an attribute walked overruns it.
    while at < message.len().min(WALKED) {
        let value = usize::from(dns::u16_at(message, at + 2)?);
        at += 4 + value.next_multiple_of(4);
    }
    if at > message.len() {
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

    /// A STUN request's method is read in all its twelve bits (RFC 8489 5): a response of another method
    /// that differs from it only in the high bits does not carry it (review D's surviving mutant).
    #[test]
    fn a_stun_methods_high_bits_tell_it() {
        // Method 0x080: M7, bit 9 of the type.
        let asked = of((APP, 3_478), &stun_message(0x0200, ID, b"app"));
        assert_eq!(
            asked,
            [Asked::Stun {
                method: 0x080,
                transaction: ID
            }]
        );
        assert!(carries(&asked, &stun_message(0x0300, ID, b"server")));
        assert!(
            !carries(&asked, &stun_message(0x0100, ID, b"server")),
            "method 0"
        );
    }

    /// Of many QUIC identifiers only opened packets tell, the latest asked is tried first, within the
    /// packets an answer may open (review D's surviving mutant).
    #[test]
    fn the_latest_quic_identifier_is_tried_first() {
        let asked: Vec<Asked> = (0..20u8)
            .flat_map(|n| {
                let initial = quic::client_initial(1, (&[n; 8], &[]), (0, &[0x01]), 1200);
                of((APP, 443), &initial.unwrap_or_default())
            })
            .collect();
        assert_eq!(asked.len(), 20);
        let answer = |n: u8| {
            quic::server_initial(1, &[n; 8], (&[], &[0x5a; 8]), (0, &[0x02, 0, 0, 0, 0]))
                .unwrap_or_default()
        };
        assert!(carries(&asked, &answer(19)));
        assert!(
            !carries(&asked, &answer(0)),
            "beyond the packets an answer opens"
        );
    }

    /// A fingerprint is the identifier's and its port's: the same on both ways a DNS query's is taken,
    /// another for another port or identifier (fix round 2).
    #[test]
    fn a_fingerprint_is_an_identifiers_on_its_port() {
        let query = Asked::Dns {
            id: 0x5151,
            question: "x.test".into(),
        };
        assert_eq!(
            fingerprint(53, &query),
            dns_fingerprint(53, 0x5151, "x.test")
        );
        assert_ne!(fingerprint(53, &query), fingerprint(5_353, &query));
        assert_ne!(
            fingerprint(53, &query),
            dns_fingerprint(53, 0x5152, "x.test")
        );
        assert_ne!(
            fingerprint(123, &Asked::Ntp(1)),
            fingerprint(123, &Asked::Ntp(2))
        );
        // QUIC's IDs, the source among them (review F's surviving mutant F22).
        let quic = |source: &[u8]| {
            let initial = quic::client_initial(1, (&[7; 8], source), (0, &[0x01]), 1200);
            of((APP, 443), &initial.unwrap_or_default()).remove(0)
        };
        assert_ne!(
            fingerprint(443, &quic(&[1, 2, 3, 4])),
            fingerprint(443, &quic(&[1, 2, 3, 5]))
        );
        assert_eq!(
            fingerprint(123, &Asked::Ntp(1)),
            fingerprint(123, &Asked::Ntp(1))
        );
    }

    /// A query for the root name, as a resolver primes itself with, off port 53 asks its ID and the empty
    /// question, and its response carries them (fix round 3, review F: the response's reader took no root
    /// question, so the stand-in, strict by the query, was answered by nothing).
    #[test]
    fn a_query_for_the_root_is_answered_by_its_response() {
        let mut root = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        root.extend_from_slice(&[0, 0, 2, 0, 1]);
        let asked = of((APP, 5_355), &root);
        assert_eq!(
            asked,
            [Asked::Dns {
                id: 0x1234,
                question: "".into()
            }]
        );
        assert!(carries(&asked, &response(&root, 0x1234)));
        assert!(!carries(&asked, &response(&root, 0x1235)));
        assert_eq!(
            Reading::new(&response(&root, 0x1234)).dns_response(),
            Some((0x1234, ""))
        );
    }

    /// What an answer answers, where it names it in the clear, has the fingerprint of what was asked: a
    /// STUN response's, a DNS response's, an NTP reply's on port 123, none for a QUIC packet (fix round 3).
    #[test]
    fn an_answer_names_what_it_answers() {
        let stun = Asked::Stun {
            method: 1,
            transaction: ID,
        };
        assert_eq!(
            Reading::new(&stun_message(0x0101, ID, b"server")).answers(3_478),
            Some(fingerprint(3_478, &stun))
        );
        let query = query(0x1234, b"\x07example\x03com\x00", false);
        let dns = &of((APP, 5_353), &query)[0];
        assert_eq!(
            Reading::new(&response(&query, 0x1234)).answers(5_353),
            Some(fingerprint(5_353, dns))
        );
        assert_eq!(
            Reading::new(&response(&query, 0x1234)).answers(53),
            Some(dns_fingerprint(53, 0x1234, "example.com"))
        );
        assert_eq!(
            Reading::new(&ntp_packet(4, 77, 1)).answers(NTP),
            Some(fingerprint(NTP, &Asked::Ntp(77)))
        );
        assert_eq!(Reading::new(&ntp_packet(4, 77, 1)).answers(4_123), None);
        let initial = quic::server_initial(1, &[7; 8], (&[], &[0x5a; 8]), (0, &[0x02, 0, 0, 0, 0]))
            .unwrap_or_default();
        assert_eq!(Reading::new(&initial).answers(443), None);
    }

    /// A STUN message larger than 1,500 bytes is read, its attributes walked over its first 1,500
    /// bytes (fix round 5, review J's minor 2; fix round 4, review G's G6, refused it whole): a request
    /// of 1,504 bytes, and a Binding response padded to a server's outgoing MTU (RFC 5780 7.6), which
    /// answers its request. An attribute walked that overruns the message still refuses it, also in a
    /// larger one.
    #[test]
    fn a_stun_messages_attributes_are_walked_over_1_500_bytes() {
        let sized = |kind: u16, size: usize| {
            let mut message = stun_message(kind, ID, &[]);
            message.resize(size, 0);
            let attributes = u16::try_from(size - 20).unwrap_or(0).to_be_bytes();
            message[2..4].copy_from_slice(&attributes);
            message
        };
        for size in [1_500, 1_504, 65_500] {
            assert_eq!(
                of((APP, 3_478), &sized(0x0001, size)).len(),
                1,
                "{size} bytes"
            );
        }
        // A Binding success response padded to 1,524 bytes: PADDING (0x0026) after SOFTWARE.
        let mut padded = stun_message(0x0101, ID, &[]);
        padded.extend_from_slice(&[0x00, 0x26]);
        padded.extend_from_slice(&1_496u16.to_be_bytes());
        padded.resize(padded.len() + 1_496, 0);
        let attributes = u16::try_from(padded.len() - 20).unwrap_or(0).to_be_bytes();
        padded[2..4].copy_from_slice(&attributes);
        assert_eq!(padded.len(), 1_524);
        let asked = of((APP, 3_478), &stun_message(0x0001, ID, &[]));
        assert!(
            carries(&asked, &padded),
            "a padded response answers its request"
        );
        assert_eq!(
            Reading::new(&padded).answers(3_478),
            Some(fingerprint(3_478, &asked[0]))
        );
        // An attribute that overruns its message, at its start and at the walk's last bytes.
        for (size, at) in [(1_500, 20), (2_000, 20), (2_000, 1_496)] {
            let mut overrun = sized(0x0001, size);
            overrun[at + 2..at + 4].copy_from_slice(&4_000u16.to_be_bytes());
            assert!(
                of((APP, 3_478), &overrun).is_empty(),
                "{size} bytes, at {at}"
            );
        }
        // Past the first 1,500 bytes nothing is walked: an attribute there that overruns the message is
        // not seen, so that 65,500 bytes cost no more to read than 1,500.
        let mut past = sized(0x0001, 65_500);
        past[1_502..1_504].copy_from_slice(&0xfffcu16.to_be_bytes());
        assert_eq!(
            of((APP, 3_478), &past).len(),
            1,
            "an attribute past the walk was walked"
        );
    }

    /// The most an identifier holds in place, beside a DNS question's name on the heap (at most 253
    /// bytes): what ADR 0044's note on unit 9b states for 64 of them.
    #[test]
    fn an_identifier_holds_64_bytes_in_place() {
        assert_eq!(std::mem::size_of::<Asked>(), 64);
    }
}
