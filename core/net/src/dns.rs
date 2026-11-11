//! DNS answers as they pass from the network's resolver back to an app (RFC 1035): which name the app
//! asked for, and which addresses it was given, so that a later flow to one of those addresses can be
//! named after what the app asked (W3).
//!
//! The name the app asked for is kept, not the end of a CNAME chain: an app that asks for
//! `graph.instagram.com` and is sent on to a CDN's name connects to Instagram, as far as it knows.
//! The ECH configurations in HTTPS and SVCB records (RFC 9460) are read for their public names: an
//! app whose TLS or QUIC hello then names one of them hides the real name behind it ([`crate::tls`]).
//!
//! Every function takes bytes a resolver on the network can choose, so none may panic or loop without
//! end (`fuzz_targets/dns.rs`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::tls;

/// The longest name DNS allows, in its text form.
const MAX_NAME: usize = 253;
/// Compression pointers followed in one name before it is refused.
pub(crate) const MAX_JUMPS: usize = 32;
/// Answers read from one message.
const MAX_ANSWERS: usize = 64;

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_SVCB: u16 = 64;
pub(crate) const TYPE_HTTPS: u16 = 65;
/// The `ech` parameter of an SVCB or HTTPS record (RFC 9460 14.3.2).
const KEY_ECH: u16 = 5;
/// The version of an `ECHConfig` the public name is read from (`draft-ietf-tls-esni`, RFC 9849).
const ECH_VERSION: u16 = 0xfe0d;
/// Public names read from one message.
const MAX_PUBLIC_NAMES: usize = 8;
pub(crate) const CLASS_IN: u16 = 1;
/// The OPT pseudo-record of EDNS (RFC 6891), whose TTL field holds flags, not a time.
pub(crate) const TYPE_OPT: u16 = 41;

/// What one DNS response says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The name the app asked for, in lower case.
    pub question: String,
    /// The addresses given for it, each with its time to live in seconds.
    pub addresses: Vec<(IpAddr, u32)>,
    /// The public names of the ECH configurations given for it, each with its time to live.
    pub public_names: Vec<(String, u32)>,
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at.checked_add(1)?)?,
    ]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads the name at `at`, following compression pointers. Returns the name in lower case and where
/// the record continues after it, or `None` for a name that is malformed, too long, loops, or holds
/// bytes outside printable ASCII (an app's log must not carry control characters).
pub(crate) fn read_name(message: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(at)?;
        match length >> 6 {
            0 if length == 0 => {
                let next = end.unwrap_or(at + 1);
                return Some((name, next));
            }
            0 => {
                let label = message.get(at + 1..at + 1 + usize::from(length))?;
                if !label.iter().all(u8::is_ascii_graphic) {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                if name.len() > MAX_NAME {
                    return None;
                }
                at += 1 + usize::from(length);
            }
            3 => {
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                let pointer = usize::from(u16_at(message, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                // A pointer must point back, so that a name cannot point into itself.
                if pointer >= at {
                    return None;
                }
                at = pointer;
            }
            _ => return None,
        }
    }
}

/// Reads a DNS response: its first question and the A and AAAA records of the answer section. Records
/// whose owner is not the question or a name a CNAME of the answer led to are left out, so that a
/// resolver cannot name an address after a name the app never asked for. Returns `None` for anything
/// that is not a well-formed response with one question.
#[must_use]
pub fn response(message: &[u8]) -> Option<Response> {
    let flags = u16_at(message, 2)?;
    // QR set: a response; opcode 0: a standard query.
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return None;
    }
    let questions = u16_at(message, 4)?;
    let answers = u16_at(message, 6)?;
    if questions != 1 {
        return None;
    }
    let (question, mut at) = read_name(message, 12)?;
    if question.is_empty() {
        return None;
    }
    at = at.checked_add(4)?;
    if at > message.len() {
        return None;
    }
    // The question and every name a CNAME in the answer led to.
    let mut owners = vec![question.clone()];
    let mut addresses = Vec::new();
    let mut public_names = Vec::new();
    for _ in 0..answers.min(u16::try_from(MAX_ANSWERS).unwrap_or(u16::MAX)) {
        let (owner, after) = read_name(message, at)?;
        let kind = u16_at(message, after)?;
        let class = u16_at(message, after + 2)?;
        let ttl = u32_at(message, after + 4)?;
        let length = usize::from(u16_at(message, after + 8)?);
        let data = after + 10;
        let record = message.get(data..data.checked_add(length)?)?;
        at = data + length;
        if class != CLASS_IN || !owners.contains(&owner) {
            continue;
        }
        match (kind, record.len()) {
            (TYPE_A, 4) => addresses.push((
                IpAddr::V4(Ipv4Addr::new(record[0], record[1], record[2], record[3])),
                ttl,
            )),
            (TYPE_AAAA, 16) => {
                let octets: [u8; 16] = record.try_into().ok()?;
                addresses.push((IpAddr::V6(Ipv6Addr::from(octets)), ttl));
            }
            // A CNAME: the name it leads to may own the addresses that follow.
            (5, _) => {
                if let Some((target, _)) = read_name(message, data)
                    && owners.len() < MAX_ANSWERS
                {
                    owners.push(target);
                }
            }
            (TYPE_SVCB | TYPE_HTTPS, _) => {
                let mut names = Vec::new();
                // A malformed record gives no names; the rest of the answer still counts.
                let _ = ech_public_names(record, &mut names);
                for name in names {
                    if public_names.len() < MAX_PUBLIC_NAMES {
                        public_names.push((name, ttl));
                    }
                }
            }
            _ => {}
        }
    }
    Some(Response {
        question,
        addresses,
        public_names,
    })
}

/// Sets the time to live of every record of a DNS response to 0, the OPT record's flags left alone,
/// so that Android's resolver, which keeps one cache for all the apps of a network, keeps none of it:
/// each app's next lookup of the name then reaches Watch again, with that app as its owner. Negative
/// answers are covered too, since Android keeps them for the SOA record's TTL at most (RFC 2308).
/// Returns `false`, the message left as it was, when it is not a well-formed response.
pub fn uncache(message: &mut [u8]) -> bool {
    let Some(offsets) = ttl_offsets(message) else {
        return false;
    };
    for at in offsets {
        message[at..at + 4].fill(0);
    }
    true
}

/// Where the TTL of each record of a response is, OPT records left out; `None` when the response is
/// not well formed. Names are skipped, not read, so a name of any bytes still counts.
fn ttl_offsets(message: &[u8]) -> Option<Vec<usize>> {
    if u16_at(message, 2)? & 0x8000 == 0 {
        return None;
    }
    let questions = u16_at(message, 4)?;
    let records = [6, 8, 10]
        .iter()
        .map(|&at| u16_at(message, at).map(usize::from))
        .sum::<Option<usize>>()?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(message, at)?.checked_add(4)?;
    }
    if at > message.len() {
        return None;
    }
    let mut offsets = Vec::new();
    for _ in 0..records {
        let after = skip_name(message, at)?;
        let kind = u16_at(message, after)?;
        let length = usize::from(u16_at(message, after.checked_add(8)?)?);
        let end = after.checked_add(10)?.checked_add(length)?;
        if end > message.len() {
            return None;
        }
        if kind != TYPE_OPT {
            offsets.push(after + 4);
        }
        at = end;
    }
    Some(offsets)
}

/// Where a record continues after the name at `at`, which ends with a zero length or a compression
/// pointer; `None` past the message's end or for a label type that does not exist.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *message.get(at)?;
        match length >> 6 {
            0 if length == 0 => return Some(at + 1),
            0 => at = at.checked_add(1 + usize::from(length))?,
            3 => {
                message.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}

/// Adds the public names of the `ECHConfig`s in an SVCB or HTTPS record's data to `names`: the record's
/// priority, its target name (never compressed, RFC 9460 2.2), then its parameters, whose `ech` value
/// is an `ECHConfigList`.
fn ech_public_names(record: &[u8], names: &mut Vec<String>) -> Option<()> {
    // Priority 0 is alias mode, which has no parameters.
    if u16_at(record, 0)? == 0 {
        return Some(());
    }
    let mut at = 2;
    loop {
        let length = usize::from(*record.get(at)?);
        if length > 63 {
            return None;
        }
        at += 1 + length;
        if length == 0 {
            break;
        }
    }
    while at < record.len() {
        let key = u16_at(record, at)?;
        let length = usize::from(u16_at(record, at + 2)?);
        let value = record.get(at + 4..at + 4 + length)?;
        at += 4 + length;
        if key != KEY_ECH {
            continue;
        }
        let list = value.get(2..2 + usize::from(u16_at(value, 0)?))?;
        let mut config = 0;
        while config + 4 <= list.len() {
            let version = u16_at(list, config)?;
            let length = usize::from(u16_at(list, config + 2)?);
            let contents = list.get(config + 4..config + 4 + length)?;
            config += 4 + length;
            if version != ECH_VERSION {
                continue;
            }
            // config_id, kem_id, public_key, cipher_suites, maximum_name_length, then public_name.
            let mut p = 3;
            p += 2 + usize::from(u16_at(contents, p)?);
            p += 2 + usize::from(u16_at(contents, p)?);
            p += 1;
            let name_length = usize::from(*contents.get(p)?);
            if let Some(name) = tls::valid_name(contents.get(p + 1..p + 1 + name_length)?) {
                names.push(name);
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response for `www.Example.com`: a CNAME to `edge.cdn.net`, its A and AAAA records, and an A
    /// record for a name nobody asked for.
    fn sample() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 4, 0, 0, 0, 0];
        m.extend_from_slice(b"\x03www\x07Example\x03com\x00\x00\x01\x00\x01");
        // CNAME, owner: pointer to the question at 12.
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 14]);
        let target = m.len();
        m.extend_from_slice(b"\x04edge\x03cdn\x03net\x00");
        // A of the target, by pointer.
        m.extend_from_slice(&[
            0xc0,
            u8::try_from(target).unwrap_or(0),
            0,
            1,
            0,
            1,
            0,
            0,
            1,
            44,
            0,
            4,
            93,
            184,
            216,
            34,
        ]);
        // AAAA of the target.
        m.extend_from_slice(&[
            0xc0,
            u8::try_from(target).unwrap_or(0),
            0,
            28,
            0,
            1,
            0,
            0,
            0,
            30,
            0,
            16,
        ]);
        m.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        // An A record of an unrelated name.
        m.extend_from_slice(
            b"\x05other\x03net\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04",
        );
        m
    }

    #[test]
    fn names_the_addresses_after_the_question_through_a_cname() {
        let parsed = response(&sample());
        assert_eq!(
            parsed,
            Some(Response {
                question: "www.example.com".into(),
                addresses: vec![
                    (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 300),
                    (
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                        30
                    ),
                ],
                public_names: vec![],
            })
        );
    }

    /// [`sample`] with an HTTPS record for the question after the others, whose `ech` parameter holds
    /// an `ECHConfig` with the public name `public`, after an `alpn` parameter.
    fn with_https(public: &str) -> Vec<u8> {
        let mut config = vec![7, 0, 0x20, 0, 32];
        config.extend_from_slice(&[9; 32]);
        config.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0]);
        config.push(u8::try_from(public.len()).unwrap_or(0));
        config.extend_from_slice(public.as_bytes());
        config.extend_from_slice(&[0, 0]);
        let mut list = vec![0xfe, 0x0d];
        list.extend_from_slice(&u16::try_from(config.len()).unwrap_or(0).to_be_bytes());
        list.extend_from_slice(&config);
        let mut data = vec![0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2', 0, 5];
        data.extend_from_slice(&u16::try_from(list.len() + 2).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&u16::try_from(list.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&list);
        let mut m = sample();
        m[7] += 1;
        m.extend_from_slice(&[0xc0, 12, 0, 65, 0, 1, 0, 0, 2, 0x58]);
        m.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        m.extend_from_slice(&data);
        m
    }

    #[test]
    fn reads_the_public_names_of_ech_configurations() {
        let Some(parsed) = response(&with_https("Cover.Example")) else {
            unreachable!("a response")
        };
        assert_eq!(parsed.public_names, vec![("cover.example".into(), 600)]);
        assert_eq!(parsed.addresses.len(), 2);
        // An ECHConfig whose public key runs past its end gives no names; the addresses still count.
        let mut cut = with_https("cover.example");
        let at = cut.len() - 60 + 3;
        assert_eq!(cut[at..at + 2], [0, 32], "the public key's length");
        cut[at] = 0xff;
        let Some(parsed) = response(&cut) else {
            unreachable!("a response")
        };
        assert_eq!(parsed.public_names, Vec::<(String, u32)>::new());
        assert_eq!(parsed.addresses.len(), 2);
    }

    #[test]
    fn refuses_queries_loops_and_strange_bytes() {
        let mut query = sample();
        query[2] = 0x01;
        assert_eq!(response(&query), None);

        // A pointer that points to itself.
        let mut looped = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1,
        ];
        assert_eq!(response(&looped), None);
        looped[13] = 0;
        assert_eq!(response(&looped), None);

        let mut control = sample();
        control[13] = b'\n';
        assert_eq!(response(&control), None);

        let message = sample();
        for cut in 0..40 {
            assert_eq!(response(&message[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn uncache_sets_every_time_to_live_to_zero_but_the_opt_flags() {
        let mut message = sample();
        // An OPT record in the additional section, its TTL field holding the DO flag.
        message[11] = 1;
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        assert!(uncache(&mut message));
        let Some(parsed) = response(&message) else {
            unreachable!("a response")
        };
        assert!(parsed.addresses.iter().all(|&(_, ttl)| ttl == 0));
        assert_eq!(
            message[message.len() - 6..message.len() - 2],
            [0, 0, 0x80, 0],
            "the OPT flags"
        );
        let Some(offsets) = ttl_offsets(&message) else {
            unreachable!("well formed")
        };
        assert_eq!(
            offsets.len(),
            4,
            "CNAME, A, AAAA and the unrelated A; not OPT"
        );
        assert!(offsets.iter().all(|&at| message[at..at + 4] == [0; 4]));

        // A name of bytes the reader refuses is still skipped, and its record still uncached.
        let mut strange = sample();
        strange[13] = b'\n';
        assert!(uncache(&mut strange));
        assert_eq!(strange[strange.len() - 10..strange.len() - 6], [0; 4]);
    }

    #[test]
    fn uncache_leaves_a_query_or_a_cut_response_as_it_was() {
        let mut query = sample();
        query[2] = 0x01;
        let before = query.clone();
        assert!(!uncache(&mut query));
        assert_eq!(query, before);
        let message = sample();
        for cut in 0..message.len() {
            let mut part = message[..cut].to_vec();
            assert!(!uncache(&mut part), "cut at {cut}");
            assert_eq!(part, message[..cut], "cut at {cut}");
        }
    }
}
