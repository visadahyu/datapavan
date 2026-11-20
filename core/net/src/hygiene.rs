//! What a direct app's query becomes on its way to an encrypted resolver, and the resolver's answer on its way
//! back (W8, part 1, ADR 0042, "How it is built", point 8).
//!
//! On the way out, the query keeps only its one question and the app's DNSSEC flags (RD, CD, and DO where the app
//! asked with EDNS): its ID becomes 0, as RFC 8484 4.1 asks of DoH; every EDNS option the app sent is dropped,
//! the client subnet (RFC 7871) among them, so that no app can hand a resolver its address or a cookie of its own;
//! and an EDNS(0) padding option (RFC 7830) brings the message to a multiple of 128 bytes (RFC 8467, 4.1), which
//! also asks the resolver to pad its answer. On the way back, the answer must be one to that very question; it
//! gets the app's ID and the app's question as the app wrote it (its letters' case), loses the resolver's OPT
//! record, its padding and options, which a bare one of the app's own size replaces where the app spoke EDNS, and
//! is cut to a truncated answer where it is longer than the app takes over UDP (512 bytes without EDNS), so that
//! the app asks again over TCP.
//!
//! Every function takes bytes an app or a resolver can choose, so none may panic (`fuzz_targets/hygiene.rs`).

use crate::dns::{read_name, u16_at};

/// The block the query is padded to (RFC 8467, 4.1, "Recommended Strategy: Block-Length Padding").
pub const QUERY_BLOCK: usize = 128;
/// The OPT pseudo-record (RFC 6891).
const TYPE_OPT: u16 = 41;
/// The padding option (RFC 7830).
const OPTION_PADDING: u16 = 12;
/// The UDP size Watch's queries announce upstream: the DNS Flag Day 2020 value.
const UPSTREAM_UDP: u16 = 1232;
/// The most a client without EDNS takes over UDP (RFC 1035 4.2.1).
const PLAIN_UDP: usize = PLAIN_UDP_SIZE as usize;
/// The same, as EDNS's size field holds it.
const PLAIN_UDP_SIZE: u16 = 512;
/// The header's flags a query keeps: RD and CD.
const KEPT_FLAGS: u16 = 0x0100 | 0x0010;
/// DNSSEC OK, in the OPT record's flags.
const DO_BIT: u32 = 0x0000_8000;

/// An app's query as Watch read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    /// Its ID, which the answer gets back.
    pub id: u16,
    /// Its question's name, in lower case, without the final dot (empty for the root).
    pub name: String,
    /// Its question's type.
    pub kind: u16,
    /// Its question's class.
    pub class: u16,
    /// The question as the app wrote it, from its name to its class.
    question: Vec<u8>,
    /// The header's RD and CD flags.
    flags: u16,
    /// The UDP size the app announced with EDNS, `None` when it sent no OPT record.
    edns: Option<u16>,
    /// Whether it asked for DNSSEC records (DO).
    dnssec_ok: bool,
}

/// Reads an app's query: a standard query (QR 0, opcode 0) with one question, no answer or authority records,
/// and in its additional section at most an OPT record (whose options are dropped) and records that are dropped.
/// `None` for anything else, which Watch answers with "server failure" where it has an ID.
#[must_use]
pub fn read(query: &[u8]) -> Option<Asked> {
    let id = u16_at(query, 0)?;
    let flags = u16_at(query, 2)?;
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 {
        return None;
    }
    if u16_at(query, 4)? != 1 || u16_at(query, 6)? != 0 || u16_at(query, 8)? != 0 {
        return None;
    }
    let additional = u16_at(query, 10)?;
    let (name, after) = read_name(query, 12)?;
    // The question's name must be written in full: a query has nothing earlier to point to.
    let mut label = 12;
    loop {
        let length = *query.get(label)?;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        label += 1 + usize::from(length);
    }
    let kind = u16_at(query, after)?;
    let class = u16_at(query, after + 2)?;
    let question = query.get(12..after + 4)?.to_vec();
    let mut at = after + 4;
    let mut edns = None;
    let mut dnssec_ok = false;
    for _ in 0..additional {
        let (_, data) = skip_record_name(query, at)?;
        let rtype = u16_at(query, data)?;
        let rclass = u16_at(query, data + 2)?;
        let ttl = crate::dns::u32_at(query, data + 4)?;
        let length = usize::from(u16_at(query, data + 8)?);
        let end = data.checked_add(10 + length)?;
        query.get(data..end)?;
        if rtype == TYPE_OPT && edns.is_none() {
            edns = Some(rclass.max(PLAIN_UDP_SIZE));
            dnssec_ok = ttl & DO_BIT != 0;
        }
        at = end;
    }
    Some(Asked {
        id,
        name,
        kind,
        class,
        question,
        flags: flags & KEPT_FLAGS,
        edns,
        dnssec_ok,
    })
}

/// Where a record continues after the name at `at`: the name's own bytes and where its type is.
fn skip_record_name(message: &[u8], mut at: usize) -> Option<(usize, usize)> {
    let start = at;
    loop {
        let length = *message.get(at)?;
        match length >> 6 {
            0 if length == 0 => return Some((start, at + 1)),
            0 => at = at.checked_add(1 + usize::from(length))?,
            3 => {
                message.get(at + 1)?;
                return Some((start, at + 2));
            }
            _ => return None,
        }
    }
}

impl Asked {
    /// The query to send upstream: ID 0, the app's question and RD and CD flags, and an OPT record with the
    /// app's DO flag and, when `pad`, a padding option that brings the message to a multiple of
    /// [`QUERY_BLOCK`] bytes. Nothing else of the app's.
    #[must_use]
    pub fn upstream(&self, pad: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(QUERY_BLOCK);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
        out.extend_from_slice(&self.question);
        // The OPT record: root name, type, UDP size, extended RCODE 0, version 0, flags, then its data.
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&UPSTREAM_UDP.to_be_bytes());
        let flags: u32 = if self.dnssec_ok { DO_BIT } else { 0 };
        out.extend_from_slice(&flags.to_be_bytes());
        if pad {
            // The option's own four bytes count: the whole message ends on a block.
            let without = out.len() + 2 + 4;
            let padding = (QUERY_BLOCK - without % QUERY_BLOCK) % QUERY_BLOCK;
            let data = 4 + padding;
            out.extend_from_slice(&u16::try_from(data).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&OPTION_PADDING.to_be_bytes());
            out.extend_from_slice(&u16::try_from(padding).unwrap_or(0).to_be_bytes());
            out.resize(out.len() + padding, 0);
        } else {
            out.extend_from_slice(&[0, 0]);
        }
        out
    }

    /// The longest answer the app takes over UDP: what it announced with EDNS, else 512 bytes.
    #[must_use]
    pub fn udp_limit(&self) -> usize {
        self.edns.map_or(PLAIN_UDP, usize::from)
    }

    /// The resolver's `answer` made the app's: `None` unless it is a response to this very question (its type,
    /// class and name, the name's case aside) with an RCODE of its own. It gets the app's ID and question, the
    /// resolver's OPT record is replaced (where the app spoke EDNS) or removed, and where it is longer than
    /// `limit` (the app's UDP size, or `None` over TCP) it becomes a truncated answer with no records.
    #[must_use]
    pub fn answer(&self, answer: &[u8], limit: Option<usize>) -> Option<Vec<u8>> {
        let flags = u16_at(answer, 2)?;
        if flags & 0x8000 == 0 || flags & 0x7800 != 0 || u16_at(answer, 4)? != 1 {
            return None;
        }
        let (name, after) = read_name(answer, 12)?;
        if name != self.name
            || u16_at(answer, after)? != self.kind
            || u16_at(answer, after + 2)? != self.class
        {
            return None;
        }
        let records = [u16_at(answer, 6)?, u16_at(answer, 8)?, u16_at(answer, 10)?];
        // Walk every record, to find the OPT record and to be sure the message is whole.
        let mut at = after + 4;
        let mut opt: Option<(usize, u32)> = None;
        let mut kept_additional = 0u16;
        let total = u32::from(records[0]) + u32::from(records[1]) + u32::from(records[2]);
        for index in 0..total {
            let (_, data) = skip_record_name(answer, at)?;
            let rtype = u16_at(answer, data)?;
            let ttl = crate::dns::u32_at(answer, data + 4)?;
            let length = usize::from(u16_at(answer, data + 8)?);
            let end = data.checked_add(10 + length)?;
            answer.get(data..end)?;
            let additional = index >= u32::from(records[0]) + u32::from(records[1]);
            if additional && opt.is_none() {
                if rtype == TYPE_OPT {
                    opt = Some((at, ttl));
                } else {
                    kept_additional += 1;
                }
            }
            at = end;
        }
        // Everything from the OPT record on goes: a name after it may point into what is cut, and the
        // additional section is advice.
        let cut = opt.map_or(at, |(start, _)| start);
        let mut out = answer.get(..cut)?.to_vec();
        out.get_mut(..2)?.copy_from_slice(&self.id.to_be_bytes());
        // The app's question as it wrote it: the same name, so the same length.
        if after + 4 - 12 == self.question.len() {
            out.get_mut(12..after + 4)?.copy_from_slice(&self.question);
        }
        let mut additional = kept_additional;
        if let Some(size) = self.edns {
            // The resolver's extended RCODE, version and DO flag; the app's size; no options.
            let ttl = opt.map_or(0, |(_, ttl)| ttl);
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
            additional += 1;
        } else if opt.is_some_and(|(_, ttl)| ttl >> 24 != 0) {
            // An extended RCODE the app cannot read: it gets "server failure".
            return self.failure();
        }
        out.get_mut(10..12)?
            .copy_from_slice(&additional.to_be_bytes());
        match limit {
            Some(limit) if out.len() > limit => Some(self.truncated(&out)),
            _ => Some(out),
        }
    }

    /// A truncated answer to this question, with `full`'s header flags and RCODE and no records, so that the
    /// app asks again over TCP.
    fn truncated(&self, full: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.question.len() + 11);
        out.extend_from_slice(&self.id.to_be_bytes());
        let flags = u16_at(full, 2).unwrap_or(0x8180) | 0x0200;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&self.question);
        if let Some(size) = self.edns {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            out[11] = 1;
        }
        out
    }

    /// "Server failure" (RCODE 2) for this question, with the app's ID: the answer while no way answers in the
    /// strict setting, so that the app's resolver stops waiting at once.
    #[must_use]
    pub fn failure(&self) -> Option<Vec<u8>> {
        Some(self.header_only(2))
    }

    /// An answer with no records and `rcode`.
    fn header_only(&self, rcode: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.question.len() + 11);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&(0x8080 | self.flags & 0x0100 | rcode).to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&self.question);
        if let Some(size) = self.edns {
            out.push(0);
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            out[11] = 1;
        }
        out
    }

    /// The query that asks this question, as the cache reads one: the app's ID and question, no records.
    #[must_use]
    pub fn as_query(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.question.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&self.question);
        out
    }
}

/// A query for `name` of type `kind` in class IN with ID 0, as Watch asks for itself (a `WireGuard` endpoint's
/// name, a target's HTTPS record): `None` for a name that cannot be written.
#[must_use]
pub fn query_for(name: &str, kind: u16) -> Option<Asked> {
    let mut query = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        query.push(u8::try_from(bytes.len()).ok()?);
        query.extend_from_slice(bytes);
    }
    if query.len() > 12 + 255 {
        return None;
    }
    query.push(0);
    query.extend_from_slice(&kind.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
    read(&query)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An app's query for `www.Example.com` A, with an OPT record that carries a client subnet and a cookie.
    fn app_query() -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1];
        q.extend_from_slice(b"\x03www\x07Example\x03com\x00\x00\x01\x00\x01");
        // OPT: size 4096, DO set; options: ECS (8) for 192.0.2.0/24, cookie (10) of 8 bytes.
        q.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0x00]);
        let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2];
        let cookie = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let length = u16::try_from(ecs.len() + cookie.len()).unwrap_or(0);
        q.extend_from_slice(&length.to_be_bytes());
        q.extend_from_slice(&ecs);
        q.extend_from_slice(&cookie);
        q
    }

    /// A resolver's answer to `upstream` with one A record, padded with an OPT record of `opt_ttl`.
    fn resolver_answer(upstream: &[u8], name_case: &[u8], opt_ttl: u32) -> Vec<u8> {
        let mut a = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1];
        a.extend_from_slice(name_case);
        a.extend_from_slice(&[0, 1, 0, 1]);
        a.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34]);
        a.extend_from_slice(&[0, 0, 41, 0x04, 0xd0]);
        a.extend_from_slice(&opt_ttl.to_be_bytes());
        // A padding option of 400 bytes.
        a.extend_from_slice(&[0x01, 0x94, 0, 12, 0x01, 0x90]);
        a.resize(a.len() + 400, 0);
        assert!(upstream.len().is_multiple_of(QUERY_BLOCK));
        a
    }

    #[test]
    fn the_upstream_query_has_id_0_no_app_option_and_ends_on_a_block() {
        let Some(asked) = read(&app_query()) else {
            unreachable!("read")
        };
        assert_eq!(asked.id, 0xabcd);
        assert_eq!(asked.name, "www.example.com");
        let up = asked.upstream(true);
        assert_eq!(up.len() % QUERY_BLOCK, 0, "padded to a block");
        assert_eq!(up.len(), QUERY_BLOCK);
        assert_eq!(up[..2], [0, 0], "ID 0");
        assert_eq!(up[2..4], [0x01, 0x00], "RD kept, AD dropped");
        // No client subnet (option 8) and no cookie (10) anywhere: only the padding option.
        let opt_at = 12 + 17 + 4;
        assert_eq!(up[opt_at..opt_at + 3], [0, 0, 41]);
        assert_eq!(
            up[opt_at + 5..opt_at + 9],
            [0, 0, 0x80, 0],
            "the app's DO flag"
        );
        let options = &up[opt_at + 11..];
        assert_eq!(options[..2], [0, 12], "the one option is padding");
        assert!(options[4..].iter().all(|&b| b == 0));
        assert!(
            !up.windows(4).any(|w| w == [0, 8, 0, 7]),
            "no client subnet"
        );
        let unpadded = asked.upstream(false);
        assert_eq!(unpadded.len(), opt_at + 11);
    }

    #[test]
    fn every_length_of_name_pads_to_a_block() {
        for n in 1..=63 {
            let name = format!("{}.test", "a".repeat(n));
            let Some(asked) = query_for(&name, 1) else {
                unreachable!("a query")
            };
            assert_eq!(asked.upstream(true).len() % QUERY_BLOCK, 0, "{n}");
        }
    }

    #[test]
    fn the_answer_gets_the_apps_id_and_question_and_a_bare_opt() {
        let Some(asked) = read(&app_query()) else {
            unreachable!("read")
        };
        let answer = resolver_answer(
            &asked.upstream(true),
            b"\x03www\x07example\x03com\x00",
            0x8000,
        );
        let Some(mine) = asked.answer(&answer, Some(asked.udp_limit())) else {
            unreachable!("an answer")
        };
        assert_eq!(mine[..2], [0xab, 0xcd]);
        assert_eq!(
            &mine[12..29],
            b"\x03www\x07Example\x03com\x00",
            "the app's case"
        );
        assert_eq!(mine[10..12], [0, 1], "one additional record, the OPT");
        let opt = &mine[mine.len() - 11..];
        assert_eq!(
            opt,
            [0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0],
            "the app's size, no options"
        );
        assert!(mine.len() < 80, "no padding");
    }

    #[test]
    fn an_app_without_edns_gets_no_opt_and_at_most_512_bytes() {
        let mut q = vec![0x01, 0x02, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x04long\x04test\x00\x00\x10\x00\x01");
        let Some(asked) = read(&q) else {
            unreachable!("read")
        };
        assert_eq!(asked.udp_limit(), 512);
        // A TXT answer of 600 bytes.
        let mut a = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1];
        a.extend_from_slice(b"\x04long\x04test\x00\x00\x10\x00\x01");
        a.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0x02, 0x58]);
        for _ in 0..3 {
            a.push(199);
            a.resize(a.len() + 199, b'x');
        }
        a.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let Some(udp) = asked.answer(&a, Some(asked.udp_limit())) else {
            unreachable!("an answer")
        };
        assert_eq!(udp[2] & 0x02, 0x02, "truncated");
        assert_eq!(udp[6..12], [0, 0, 0, 0, 0, 0], "no records, no OPT");
        let Some(tcp) = asked.answer(&a, None) else {
            unreachable!("an answer")
        };
        assert_eq!(tcp[2] & 0x02, 0, "whole over TCP");
        assert_eq!(tcp[10..12], [0, 0], "the OPT removed");
        assert!(tcp.len() > 600);
    }

    #[test]
    fn an_answer_to_another_question_is_refused() {
        let Some(asked) = read(&app_query()) else {
            unreachable!("read")
        };
        let other = resolver_answer(&asked.upstream(true), b"\x03www\x07example\x03net\x00", 0);
        assert!(asked.answer(&other, None).is_none());
        let mut query_not_answer = other.clone();
        query_not_answer[2] &= 0x7f;
        assert!(asked.answer(&query_not_answer, None).is_none());
        let good = resolver_answer(&asked.upstream(true), b"\x03www\x07example\x03com\x00", 0);
        assert!(
            asked.answer(&good[..good.len() - 1], None).is_none(),
            "cut short"
        );
    }

    #[test]
    fn queries_that_are_not_are_refused() {
        assert!(read(&[]).is_none());
        let mut response = app_query();
        response[2] |= 0x80;
        assert!(read(&response).is_none());
        let mut two = app_query();
        two[5] = 2;
        assert!(read(&two).is_none());
        let mut notify = app_query();
        notify[2] |= 0x20;
        assert!(read(&notify).is_none(), "opcode 4");
    }

    #[test]
    fn failure_says_server_failure_for_the_question() {
        let Some(asked) = read(&app_query()) else {
            unreachable!("read")
        };
        let Some(failed) = asked.failure() else {
            unreachable!("a failure")
        };
        assert_eq!(failed[..2], [0xab, 0xcd]);
        assert_eq!(failed[3] & 0x0f, 2);
        assert_eq!(failed[2] & 0x80, 0x80);
    }
}
