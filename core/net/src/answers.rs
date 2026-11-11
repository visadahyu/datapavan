//! The DNS answers Watch gives chained apps (ADR 0038, W6): a stand-in address for an A question, no
//! data for AAAA, the name for a reverse lookup of a stand-in, and for any other question the answer of
//! the resolver reached through the tool, rebuilt without the address hints of HTTPS and SVCB records.
//! Every record of these answers has a time to live of 0, so that Android's resolver, which keeps one
//! cache for all the apps of the tunnel, keeps none of them.
//!
//! [`rebuilt`] writes the resolver's answer out again with every name in full: dropping a hint changes
//! a record's length, which would break the compression pointers after it. Only the record types of
//! RFC 1035 may hold compressed names in their data (RFC 3597); the current ones are read, the obsolete
//! ones dropped, and every other type is copied as it is.

use crate::dns::{
    CLASS_IN, MAX_JUMPS, TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_OPT, TYPE_SVCB, read_name, u16_at,
};
use std::net::Ipv4Addr;

/// A reverse lookup (PTR).
pub const TYPE_PTR: u16 = 12;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MX: u16 = 15;
/// Obsolete types of RFC 1035 whose data may hold compressed names: MD, MF, MB, MG, MR, MINFO.
const OBSOLETE: [u16; 6] = [3, 4, 7, 8, 9, 14];
const KEY_MANDATORY: u16 = 0;
const KEY_IPV4_HINT: u16 = 4;
const KEY_IPV6_HINT: u16 = 6;
const SERVER_FAILURE: u8 = 2;
/// The longest name in wire form.
const MAX_WIRE_NAME: usize = 255;

/// An address question.
pub const A: u16 = TYPE_A;
/// An IPv6 address question.
pub const AAAA: u16 = TYPE_AAAA;

/// The one question of an app's query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// The name asked for, in lower case, without a final dot.
    pub name: String,
    /// Its type: [`A`], [`AAAA`], [`TYPE_PTR`] or another.
    pub kind: u16,
    /// Its class; 1 is the internet's.
    pub class: u16,
    /// Where the question ends in the query.
    end: usize,
}

/// The question of a standard query with one question, or `None`.
#[must_use]
pub fn question(query: &[u8]) -> Option<Question> {
    let flags = u16_at(query, 2)?;
    // QR clear: a query; opcode 0: a standard one.
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || u16_at(query, 4)? != 1 {
        return None;
    }
    let (name, after) = read_name(query, 12)?;
    let kind = u16_at(query, after)?;
    let class = u16_at(query, after + 2)?;
    Some(Question {
        name,
        kind,
        class,
        end: after + 4,
    })
}

/// Whether Watch answers this question itself: A, AAAA, and a reverse lookup, of the internet class.
#[must_use]
pub fn answered_here(question: &Question) -> bool {
    question.class == CLASS_IN && matches!(question.kind, TYPE_A | TYPE_AAAA | TYPE_PTR)
}

/// The header of an answer to `query`: its ID and recursion flag, "recursion available", `rcode`, the
/// question, and `answers` records to follow.
fn header(query: &[u8], question: Option<&Question>, rcode: u8, answers: u16) -> Option<Vec<u8>> {
    let id = query.get(..2)?;
    let recursion = query.get(2)? & 1;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(id);
    out.extend_from_slice(&[0x80 | recursion, 0x80 | rcode]);
    out.extend_from_slice(&[0, u8::from(question.is_some()), 0, 0, 0, 0, 0, 0]);
    out[7] = u8::try_from(answers).unwrap_or(0);
    out[6] = u8::try_from(answers >> 8).unwrap_or(0);
    if let Some(question) = question {
        // The question as the app wrote it, the case of its letters included.
        out.extend_from_slice(query.get(12..question.end)?);
    }
    Some(out)
}

/// One answer record for the question (a pointer to its name), with a time to live of 0.
fn record(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&[0xc0, 12]);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(data);
}

/// The answer to an A question: the stand-in `address`.
#[must_use]
pub fn address(query: &[u8], question: &Question, address: Ipv4Addr) -> Option<Vec<u8>> {
    let mut out = header(query, Some(question), 0, 1)?;
    record(&mut out, TYPE_A, &address.octets());
    Some(out)
}

/// An answer with no records and no error: the name exists, but not with this type ("no data"). Without
/// an SOA record, no resolver keeps it.
#[must_use]
pub fn no_data(query: &[u8], question: &Question) -> Option<Vec<u8>> {
    header(query, Some(question), 0, 0)
}

/// The answer to a reverse lookup: `name`, if it can be written.
#[must_use]
pub fn name(query: &[u8], question: &Question, name: &str) -> Option<Vec<u8>> {
    let data = wire(name)?;
    let mut out = header(query, Some(question), 0, 1)?;
    record(&mut out, TYPE_PTR, &data);
    Some(out)
}

/// "Server failure" for `query`, with its question when it has one Watch can read, so that the app's
/// resolver stops waiting. `None` for a query too short to have an ID.
#[must_use]
pub fn failure(query: &[u8]) -> Option<Vec<u8>> {
    header(query, question(query).as_ref(), SERVER_FAILURE, 0)
}

/// The IPv4 address of a reverse lookup's name (`d.c.b.a.in-addr.arpa`), if it is one.
#[must_use]
pub fn reverse_v4(name: &str) -> Option<Ipv4Addr> {
    let octets = name.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<u8> = octets
        .split('.')
        .map(|p| {
            (!p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
                .then(|| p.parse().ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    let [d, c, b, a] = parts[..] else {
        return None;
    };
    Some(Ipv4Addr::new(a, b, c, d))
}

/// A name in wire form, uncompressed, if every label is 1 to 63 bytes and the whole at most 255.
fn wire(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))?;
        out.push(length);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    (out.len() <= MAX_WIRE_NAME).then_some(out)
}

/// The name at `at` in wire form, uncompressed, with its labels' bytes as they are, and where the
/// record continues after it. `None` for a malformed name, a loop, or a pointer that does not point back.
fn wire_name(message: &[u8], mut at: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(at)?;
        match length >> 6 {
            0 if length == 0 => {
                out.push(0);
                return (out.len() <= MAX_WIRE_NAME).then(|| (out, end.unwrap_or(at + 1)));
            }
            0 => {
                let label = message.get(at..at + 1 + usize::from(length))?;
                out.extend_from_slice(label);
                if out.len() >= MAX_WIRE_NAME {
                    return None;
                }
                at += label.len();
            }
            3 => {
                jumps += 1;
                let pointer = usize::from(u16_at(message, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                if jumps > MAX_JUMPS || pointer >= at {
                    return None;
                }
                at = pointer;
            }
            _ => return None,
        }
    }
}

/// The data of an SVCB or HTTPS record without its address hints, or `None` when the record says the
/// hints are mandatory (then it is dropped) or is malformed.
fn without_hints(data: &[u8]) -> Option<Vec<u8>> {
    // Priority 0 is alias mode: a target name, no parameters.
    if u16_at(data, 0)? == 0 {
        return Some(data.to_vec());
    }
    let mut at = 2;
    loop {
        let length = usize::from(*data.get(at)?);
        if length > 63 {
            return None;
        }
        at += 1 + length;
        if length == 0 {
            break;
        }
    }
    let mut out = data.get(..at)?.to_vec();
    while at < data.len() {
        let key = u16_at(data, at)?;
        let length = usize::from(u16_at(data, at + 2)?);
        let parameter = data.get(at..at + 4 + length)?;
        at += parameter.len();
        if key == KEY_MANDATORY
            && parameter[4..]
                .chunks(2)
                .any(|k| matches!(u16_at(k, 0), Some(KEY_IPV4_HINT | KEY_IPV6_HINT)))
        {
            return None;
        }
        if key != KEY_IPV4_HINT && key != KEY_IPV6_HINT {
            out.extend_from_slice(parameter);
        }
    }
    Some(out)
}

/// The data of a record of `kind` at `data_at`, `length` bytes long, written out with its names in
/// full; `None` drops the record.
fn record_data(message: &[u8], kind: u16, data_at: usize, length: usize) -> Option<Vec<u8>> {
    let end = data_at.checked_add(length)?;
    let data = message.get(data_at..end)?;
    let names = |mut at: usize, count: usize, rest: usize| -> Option<Vec<u8>> {
        let mut out = message.get(data_at..at)?.to_vec();
        for _ in 0..count {
            let (name, next) = wire_name(message, at)?;
            out.extend_from_slice(&name);
            at = next;
        }
        (at + rest == end).then_some(())?;
        out.extend_from_slice(message.get(at..end)?);
        Some(out)
    };
    match kind {
        TYPE_NS | TYPE_CNAME | TYPE_PTR => names(data_at, 1, 0),
        TYPE_MX => names(data_at + 2, 1, 0),
        TYPE_SOA => names(data_at, 2, 20),
        TYPE_SVCB | TYPE_HTTPS => without_hints(data),
        kind if OBSOLETE.contains(&kind) => None,
        _ => Some(data.to_vec()),
    }
}

/// The resolver's `answer`, written out again for a chained app: every name in full, the address hints
/// of HTTPS and SVCB records removed (ADR 0038), and every time to live 0 but the OPT record's flags.
/// `None` for anything but a well-formed response with one question.
#[must_use]
pub fn rebuilt(answer: &[u8]) -> Option<Vec<u8>> {
    let flags = u16_at(answer, 2)?;
    if flags & 0x8000 == 0 || u16_at(answer, 4)? != 1 {
        return None;
    }
    let mut out = answer.get(..12)?.to_vec();
    let (name, after) = wire_name(answer, 12)?;
    out.extend_from_slice(&name);
    out.extend_from_slice(answer.get(after..after + 4)?);
    let mut at = after + 4;
    for count_at in [6, 8, 10] {
        let mut kept: u16 = 0;
        for _ in 0..u16_at(answer, count_at)? {
            let (owner, after) = wire_name(answer, at)?;
            let kind = u16_at(answer, after)?;
            let length = usize::from(u16_at(answer, after + 8)?);
            let header = answer.get(after..after + 8)?;
            at = after + 10 + length;
            let Some(data) = record_data(answer, kind, after + 10, length) else {
                continue;
            };
            out.extend_from_slice(&owner);
            out.extend_from_slice(&header[..4]);
            if kind == TYPE_OPT {
                out.extend_from_slice(&header[4..8]);
            } else {
                out.extend_from_slice(&[0, 0, 0, 0]);
            }
            out.extend_from_slice(&u16::try_from(data.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&data);
            kept += 1;
        }
        out[count_at..count_at + 2].copy_from_slice(&kept.to_be_bytes());
    }
    (at == answer.len() && u16::try_from(out.len()).is_ok()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;

    fn query(name: &[u8], kind: u16) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(name);
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn answers_a_with_the_stand_in_and_aaaa_with_no_data() {
        let q = query(b"\x03www\x07Example\x03com\x00", A);
        let Some(question) = question(&q) else {
            unreachable!("a query")
        };
        assert_eq!(question.name, "www.example.com");
        assert!(answered_here(&question));
        let Some(answer) = address(&q, &question, Ipv4Addr::new(198, 18, 0, 7)) else {
            unreachable!("an answer")
        };
        assert_eq!(answer[..4], [0xab, 0xcd, 0x81, 0x80]);
        assert_eq!(
            answer[12..q.len()],
            q[12..],
            "the question as the app wrote it"
        );
        let Some(read) = dns::response(&answer) else {
            unreachable!("a response")
        };
        assert_eq!(
            read.addresses,
            vec![(Ipv4Addr::new(198, 18, 0, 7).into(), 0)]
        );
        let aaaa = query(b"\x03www\x07example\x03com\x00", AAAA);
        let Some(question) = super::question(&aaaa) else {
            unreachable!("a query")
        };
        let Some(empty) = no_data(&aaaa, &question) else {
            unreachable!("an answer")
        };
        assert_eq!(empty[4..12], [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(empty[3] & 0x0f, 0, "no error");
    }

    #[test]
    fn answers_a_reverse_lookup_and_fails_politely() {
        assert_eq!(
            reverse_v4("7.0.18.198.in-addr.arpa"),
            Some(Ipv4Addr::new(198, 18, 0, 7))
        );
        assert_eq!(reverse_v4("7.0.18.in-addr.arpa"), None);
        assert_eq!(reverse_v4("256.0.18.198.in-addr.arpa"), None);
        assert_eq!(reverse_v4("x.0.18.198.in-addr.arpa"), None);
        let q = query(b"\x017\x010\x0218\x03198\x07in-addr\x04arpa\x00", TYPE_PTR);
        let Some(question) = question(&q) else {
            unreachable!("a query")
        };
        let Some(answer) = name(&q, &question, "example.com") else {
            unreachable!("an answer")
        };
        assert!(answer.ends_with(b"\x07example\x03com\x00"));
        assert_eq!(answer[6..8], [0, 1]);
        let Some(failed) = failure(&q) else {
            unreachable!("an answer")
        };
        assert_eq!(failed[3] & 0x0f, 2);
        assert_eq!(failure(&[1]), None);
        let mut response = q.clone();
        response[2] |= 0x80;
        assert_eq!(super::question(&response), None, "an answer is no query");
    }

    /// An answer to an HTTPS question for `example.com`: a CNAME to `edge.example.net` by pointer, then
    /// the HTTPS record of the target, by pointer, with alpn, ipv4hint, ech and ipv6hint, then OPT.
    fn https_answer(mandatory_hint: bool) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 1];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x41\x00\x01");
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 0, 0, 7]);
        let target = m.len();
        m.extend_from_slice(b"\x04edge\xc0\x0c");
        let mut data = vec![0, 1, 0];
        if mandatory_hint {
            data.extend_from_slice(&[0, 0, 0, 2, 0, 4]);
        }
        data.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'2']);
        data.extend_from_slice(&[0, 4, 0, 4, 192, 0, 2, 1]);
        data.extend_from_slice(&[0, 5, 0, 3, 0xaa, 0xbb, 0xcc]);
        data.extend_from_slice(&[0, 6, 0, 16]);
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        m.extend_from_slice(&[
            0xc0,
            u8::try_from(target).unwrap_or(0),
            0,
            65,
            0,
            1,
            0,
            0,
            2,
            0,
        ]);
        m.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(&data);
        m.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        m
    }

    #[test]
    fn rebuilds_an_https_answer_without_hints_keeping_ech() {
        let Some(out) = rebuilt(&https_answer(false)) else {
            unreachable!("a rebuilt answer")
        };
        assert_eq!(out[6..12], [0, 2, 0, 0, 0, 1]);
        // The CNAME's target in full, then the HTTPS record under that name.
        let cname = b"\x07example\x03com\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x12\x04edge\x07example\x03com\x00";
        assert!(out.windows(cname.len()).any(|w| w == cname), "{out:?}");
        let https = b"\x04edge\x07example\x03com\x00\x00\x41\x00\x01\x00\x00\x00\x00";
        assert!(out.windows(https.len()).any(|w| w == https));
        // alpn and ech stay, the hints go.
        assert!(out.windows(7).any(|w| w == [0, 1, 0, 3, 2, b'h', b'2']));
        assert!(out.windows(7).any(|w| w == [0, 5, 0, 3, 0xaa, 0xbb, 0xcc]));
        assert!(!out.windows(4).any(|w| w == [0, 4, 0, 4]));
        assert!(!out.windows(4).any(|w| w == [0, 6, 0, 16]));
        // The OPT record keeps its flags.
        assert!(out.ends_with(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]));
        assert_eq!(
            rebuilt(&out),
            Some(out.clone()),
            "rebuilding twice changes nothing"
        );
        let mut cached = out.clone();
        assert!(dns::uncache(&mut cached));
        assert_eq!(cached, out, "every time to live is 0 already");
    }

    #[test]
    fn drops_a_record_whose_hints_are_mandatory_and_refuses_broken_answers() {
        let Some(out) = rebuilt(&https_answer(true)) else {
            unreachable!("a rebuilt answer")
        };
        assert_eq!(out[6..8], [0, 1], "only the CNAME is left");
        let answer = https_answer(false);
        for cut in 0..answer.len() {
            assert_eq!(rebuilt(&answer[..cut]), None, "cut at {cut}");
        }
        let mut query = answer.clone();
        query[2] &= 0x7f;
        assert_eq!(rebuilt(&query), None);
        // A pointer forward, to itself.
        let mut looped = answer;
        let at = 12 + 13 + 4;
        looped[at + 1] = u8::try_from(at).unwrap_or(0);
        assert_eq!(rebuilt(&looped), None);
    }
}
