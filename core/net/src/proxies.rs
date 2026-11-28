//! What the first bytes an app sends on a TCP flow say about a proxy (W8, part 2a; ADR 0052): a proxy the
//! app's own bytes declare, read from the connection, and the shapes from which a messenger's proxy is
//! inferred.
//!
//! **Declared.** SOCKS5 (RFC 1928, with RFC 1929's user name and password), SOCKS4 and `SOCKS4a`, an HTTP
//! `CONNECT` (RFC 9110, 9.3.6), and a plain HTTP request sent to a proxy, whose target is in absolute form
//! (RFC 9112, 3.2.2): each names the destination the app asked the proxy for in clear bytes. Only the
//! destination is taken, and of a plain request only its authority, never its path or query.
//!
//! **Never kept.** RFC 1929's user name and password, SOCKS4's user ID, a `Proxy-Authorization` header's value
//! and the user information of a URL are skipped by their lengths or delimiters and never copied: nothing here
//! returns them, and the only thing said of them is whether a password crossed the network unencrypted (RFC
//! 1929's, or HTTP's `Basic` scheme). The caller's buffer is its own to zero (`engine::tcp`).
//!
//! **Confirmed by the reply** (fix round of W8 part 2a; ADR 0052): a request alone is only what the app wrote,
//! which a server of its own may ignore. A SOCKS or `CONNECT` request names its flow only once the server's
//! first bytes confirm the handshake ([`confirmed`]): SOCKS5's choice of the method the app then used, RFC 1929's
//! success where it was used, and the request's success, `05 00 00`; SOCKS4's `00 5a`; a `2xx` status line for
//! `CONNECT`. A plain request in absolute form cannot be confirmed so, since origin servers accept that form
//! too.
//!
//! **Shapes.** The 64 bytes that start Telegram's obfuscated transport, by the rules its documentation gives
//! the client for them (core.telegram.org/mtproto/mtproto-transports, read 2026-11-20): the first byte is not
//! `0xef`, the first four are none of `HEAD`, `POST`, `GET `, `OPTI`, `16 03 01 02`, `dd dd dd dd` and `ee ee ee
//! ee`, bytes 4 to 8 are not all zero; and, as the header is random: its bits set average between 3 and 5 a
//! byte (a random header's mean is 4, with a standard deviation of 0.18 over 64 bytes), 16 to 48 of its bytes
//! have the high bit set (a random header misses that once in 41,043: 2.4 in 100,000, computed from the
//! binomial distribution), and the 64 bytes are not UTF-8 text, which random bytes are with a chance below 2
//! in 10^16 (bounded by counting UTF-8's lead and continuation bytes). Text, ASCII or not, so never passes:
//! `PUT`, `PATCH`, `SSH-2.0` and Persian alike. And `WhatsApp`'s clear
//! header, `W` `A` and two bytes, or `E` `D` `0` `1`, a 3-byte length, the routing data and then `W` `A`, as
//! two open-source clients write it (whatsmeow's `WAConnHeader`, Baileys's `noise-handler.ts`, read
//! 2026-11-20).
//!
//! Everything is bounded: a request is looked for in the first [`MAX_REQUEST`] bytes, and nothing here may
//! panic or read outside the slice (`fuzz_targets/proxies.rs`).

use crate::Number;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most bytes a proxy request is looked for in: a SOCKS5 greeting, RFC 1929's sub-negotiation and the
/// request fit in 1,036; an HTTP request line and its headers, as clients send them to a proxy, in far less.
pub const MAX_REQUEST: usize = 4096;

/// The bytes the obfuscated transport's header takes.
pub const OBFUSCATED_HEADER: usize = 64;

/// The kind of a proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// SOCKS5 (RFC 1928).
    Socks5,
    /// SOCKS4, or `SOCKS4a` with a host name.
    Socks4,
    /// An HTTP proxy asked with `CONNECT` for a tunnel.
    Connect,
    /// An HTTP proxy sent a plain request in absolute form.
    Forward,
    /// Telegram's `MTProto` proxy, inferred.
    MtProto,
    /// `WhatsApp`'s proxy, inferred.
    WhatsApp,
    /// Signal's proxy, inferred.
    Signal,
}

impl Kind {
    /// Whether the kind is read from the connection, not inferred.
    #[must_use]
    pub fn declared(self) -> bool {
        matches!(
            self,
            Self::Socks5 | Self::Socks4 | Self::Connect | Self::Forward
        )
    }
}

/// The destination an app asked its proxy for: a host name, in lower case and without a trailing dot, or
/// an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
    /// A host name.
    Name(String),
    /// An address.
    Address(IpAddr),
}

/// A request the app's bytes declare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Of a declared kind: SOCKS5, SOCKS4, `CONNECT` or a plain request.
    pub kind: Kind,
    /// Where it asked to go.
    pub asked: Asked,
    /// The port asked for.
    pub port: u16,
    /// Whether a password crossed the network unencrypted on the way: RFC 1929's, or HTTP's `Basic`. The
    /// password itself is never read into anything.
    pub password: bool,
    /// Where the stream the proxy carries starts in the bytes read, for a kind that opens a tunnel (SOCKS,
    /// `CONNECT`): its TLS hello, if any, is read from there. `None` for a plain request, which is itself
    /// what the proxy carries.
    pub inner: Option<usize>,
    /// For SOCKS5, the method the app then used (0 none, 2 RFC 1929's), which the server's choice must be.
    pub method: u8,
    /// Whether it is SOCKS5's `UDP ASSOCIATE` (command 3), not a `CONNECT` (the proxy record's unit U). Its `DST` is
    /// the client's own source (RFC 1928, section 6), never where it wants to go, so it is skipped unread: `asked` is
    /// then the unspecified address and `port` 0, which nothing names a flow by, and there is no inner stream. The
    /// destinations are in each datagram's header (section 7), and the relay in the reply ([`bound`]).
    pub associate: bool,
}

/// What the start of a stream says about a proxy request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declared {
    /// A request, read.
    Request(Request),
    /// No proxy request: another protocol, or one that does not parse.
    Not,
    /// More bytes are needed to tell.
    Incomplete,
}

/// Reads a proxy request from the start of a stream, which may be incomplete: past [`MAX_REQUEST`] bytes
/// without one, it is none.
#[must_use]
pub fn declared(start: &[u8]) -> Declared {
    let start = &start[..start.len().min(MAX_REQUEST)];
    let read = match start.first() {
        None => Some(Err(Need)),
        Some(5) => Some(socks5(start)),
        Some(4) => Some(socks4(start)),
        Some(b'A'..=b'Z') => Some(http(start)),
        Some(_) => None,
    };
    match read {
        Some(Ok(Some(request))) => Declared::Request(request),
        Some(Err(Need)) if start.len() < MAX_REQUEST => Declared::Incomplete,
        _ => Declared::Not,
    }
}

/// More bytes are needed.
struct Need;

/// A reading: `Err(Need)` for more bytes, `Ok(None)` for none.
type Read = Result<Option<Request>, Need>;

fn at(bytes: &[u8], i: usize) -> Result<u8, Need> {
    bytes.get(i).copied().ok_or(Need)
}

fn port_at(bytes: &[u8], i: usize) -> Result<u16, Need> {
    Ok(u16::from_be_bytes([at(bytes, i)?, at(bytes, i + 1)?]))
}

/// RFC 1928: the greeting, RFC 1929's sub-negotiation where the greeting offered it, then a `CONNECT`.
fn socks5(b: &[u8]) -> Read {
    let methods = usize::from(at(b, 1)?);
    // A plausible list: 1 to 10 methods, each one IANA assigned (0 to 9), none twice (the fix round's S-m1).
    if methods == 0 || methods > 10 {
        return Ok(None);
    }
    let offered = b.get(2..2 + methods).ok_or(Need)?;
    if offered
        .iter()
        .enumerate()
        .any(|(n, &m)| m > 9 || offered[..n].contains(&m))
    {
        return Ok(None);
    }
    let mut i = 2 + methods;
    let first = at(b, i)?;
    let mut password = false;
    let method = if first == 1 { 2 } else { 0 };
    if !offered.contains(&method) {
        return Ok(None);
    }
    if first == 1 {
        // RFC 1929: version 1, ULEN, UNAME, PLEN, PASSWD; offered only with method 2. Skipped by length.
        let user = usize::from(at(b, i + 1)?);
        let pass = usize::from(at(b, i + 2 + user)?);
        if user == 0 {
            return Ok(None);
        }
        password = pass > 0;
        i += 3 + user + pass;
    } else if first != 5 {
        return Ok(None);
    }
    // The request: version 5, CONNECT (1) or UDP ASSOCIATE (3), reserved 0, the address's type.
    let associate = match at(b, i + 1)? {
        1 => false,
        3 => true,
        _ => return Ok(None),
    };
    if at(b, i)? != 5 || at(b, i + 2)? != 0 {
        return Ok(None);
    }
    let (asked, after) = match at(b, i + 3)? {
        1 => (Asked::Address(IpAddr::V4(v4_at(b, i + 4)?)), i + 8),
        4 => (Asked::Address(IpAddr::V6(v6_at(b, i + 4)?)), i + 20),
        3 => {
            let length = usize::from(at(b, i + 4)?);
            let name = b.get(i + 5..i + 5 + length).ok_or(Need)?;
            // An associate's `DST` is the client's own, skipped by its length.
            let name = if associate {
                Some(Asked::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
            } else {
                host_name(name)
            };
            let Some(name) = name else {
                return Ok(None);
            };
            (name, i + 5 + length)
        }
        _ => return Ok(None),
    };
    let port = port_at(b, after)?;
    if associate {
        return Ok(Some(Request {
            kind: Kind::Socks5,
            asked: Asked::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 0,
            password,
            inner: None,
            method,
            associate,
        }));
    }
    Ok(Some(Request {
        kind: Kind::Socks5,
        asked,
        port,
        password,
        inner: Some(after + 2),
        method,
        associate,
    }))
}

/// SOCKS4: version 4, `CONNECT` (1), the port, the address, the user ID ending in a zero; `SOCKS4a`, with an
/// address 0.0.0.x (x not 0), adds the host name ending in a zero. The user ID is skipped, but must be
/// printable ASCII, as clients write it: random bytes rarely are (the fix round's S-m1).
fn socks4(b: &[u8]) -> Read {
    if at(b, 1)? != 1 {
        return Ok(None);
    }
    let port = port_at(b, 2)?;
    let address = v4_at(b, 4)?;
    let user = b.get(8..).ok_or(Need)?;
    let user_end = match user
        .iter()
        .position(|&c| c == 0 || !(b' '..=b'~').contains(&c))
    {
        Some(end) if user[end] == 0 => 8 + end,
        Some(_) => return Ok(None),
        None => return Err(Need),
    };
    let [a, b0, c, d] = address.octets();
    let (asked, after) = if a == 0 && b0 == 0 && c == 0 && d != 0 {
        let from = user_end + 1;
        let rest = b.get(from..).ok_or(Need)?;
        let length = rest.iter().position(|&c| c == 0).ok_or(Need)?;
        let Some(name) = host_name(&rest[..length]) else {
            return Ok(None);
        };
        (name, from + length + 1)
    } else {
        if address.is_unspecified() {
            return Ok(None);
        }
        (Asked::Address(IpAddr::V4(address)), user_end + 1)
    };
    Ok(Some(Request {
        kind: Kind::Socks4,
        asked,
        port,
        password: false,
        inner: Some(after),
        method: 0,
        associate: false,
    }))
}

/// An HTTP request to a proxy: `CONNECT host:port HTTP/1.x`, or a plain request whose target is an absolute
/// `http://` URL, then its headers up to the empty line. Of a plain request only the authority is read, and
/// its user information skipped; of the headers only whether `Proxy-Authorization` uses `Basic`.
fn http(b: &[u8]) -> Read {
    // The method: 1 to 20 upper-case letters, then a space.
    let space = match b.iter().take(21).position(|&c| !c.is_ascii_uppercase()) {
        Some(space) if space > 0 && b[space] == b' ' => space,
        None if b.len() < 21 => return Err(Need),
        Some(_) | None => return Ok(None),
    };
    let method = &b[..space];
    let target = &b[space + 1..];
    let connect = method == b"CONNECT";
    let (asked, port, after_target) = if connect {
        let end = match target
            .iter()
            .position(|&c| c == b' ' || c == b'\r' || c == b'\n')
        {
            Some(end) => end,
            None if target.len() < 262 => return Err(Need),
            None => return Ok(None),
        };
        let Some((asked, port)) = authority(&target[..end], None) else {
            return Ok(None);
        };
        (asked, port, end)
    } else {
        const SCHEME: &[u8] = b"http://";
        let shown = target.len().min(SCHEME.len());
        if !target[..shown].eq_ignore_ascii_case(&SCHEME[..shown]) {
            return Ok(None);
        }
        if target.len() < SCHEME.len() {
            return Err(Need);
        }
        let rest = &target[SCHEME.len()..];
        let end = match rest
            .iter()
            .position(|&c| matches!(c, b'/' | b'?' | b'#' | b' ' | b'\r' | b'\n'))
        {
            Some(end) => end,
            None if rest.len() < 262 + 256 => return Err(Need),
            None => return Ok(None),
        };
        // The user information before an `@` is skipped, never read. An `@` after the authority ends, before
        // the target does, is refused: `http://alice:1234/x@host/` would otherwise give a user name as the
        // destination, and a target written so is not one a client sends (the fix round's S-n1).
        let target_end = rest
            .iter()
            .position(|&c| matches!(c, b' ' | b'\r' | b'\n'))
            .unwrap_or(rest.len());
        if rest[end..target_end].contains(&b'@') {
            return Ok(None);
        }
        let host = &rest[..end];
        let host = match host.iter().rposition(|&c| c == b'@') {
            Some(at) => &host[at + 1..],
            None => host,
        };
        let Some((asked, port)) = authority(host, Some(80)) else {
            return Ok(None);
        };
        (asked, port, SCHEME.len() + end)
    };
    // The rest of the request line, then the headers, up to the empty line. A plain request's line may be
    // long (its path and query, never read): past the bound, it is taken without its headers.
    let line_from = space + 1 + after_target;
    let Some(line_end) = find(&b[line_from..], b"\n").map(|n| line_from + n + 1) else {
        if !connect && b.len() >= MAX_REQUEST {
            return Ok(Some(request(Kind::Forward, asked, port, false, None)));
        }
        return Err(Need);
    };
    let line = &b[line_from..line_end];
    if find(line, b" HTTP/1.").is_none() {
        return Ok(None);
    }
    let mut password = false;
    let mut i = line_end;
    loop {
        let Some(n) = find(&b[i..], b"\n") else {
            if !connect && b.len() >= MAX_REQUEST {
                return Ok(Some(request(Kind::Forward, asked, port, password, None)));
            }
            return Err(Need);
        };
        let header = &b[i..i + n];
        let header = header.strip_suffix(b"\r").unwrap_or(header);
        i += n + 1;
        if header.is_empty() {
            break;
        }
        password |= basic_proxy_authorization(header);
    }
    Ok(Some(if connect {
        request(Kind::Connect, asked, port, password, Some(i))
    } else {
        request(Kind::Forward, asked, port, password, None)
    }))
}

fn request(kind: Kind, asked: Asked, port: u16, password: bool, inner: Option<usize>) -> Request {
    Request {
        kind,
        asked,
        port,
        password,
        inner,
        method: 0,
        associate: false,
    }
}

/// The most of a server's first bytes [`confirmed`] reads: SOCKS5's choice, RFC 1929's success and the
/// request's success, 7 bytes; an HTTP status line's version and code, 12.
pub const MAX_REPLY: usize = 16;

/// Whether the server's first bytes, `reply`, confirm the handshake `request` declared: `Some(true)` once they
/// do, `Some(false)` once they refuse it or are not its protocol's, `None` while too few came. A plain request
/// is never confirmed (`Some(false)`): an origin server accepts the absolute form too (RFC 9112, 3.2.2).
#[must_use]
pub fn confirmed(request: &Request, reply: &[u8]) -> Option<bool> {
    let has = |i: usize, byte: u8| reply.get(i).map(|&b| b == byte);
    let all = |checks: &[Option<bool>]| -> Option<bool> {
        for check in checks {
            match check {
                Some(true) => {}
                Some(false) => return Some(false),
                None => return None,
            }
        }
        Some(true)
    };
    match request.kind {
        Kind::Socks5 => {
            // The method chosen, the sub-negotiation's success where it was used, then version 5, success, RSV.
            let i = if request.method == 2 { 4 } else { 2 };
            let mut checks = vec![has(0, 5), has(1, request.method)];
            if request.method == 2 {
                checks.extend([has(2, 1), has(3, 0)]);
            }
            checks.extend([has(i, 5), has(i + 1, 0), has(i + 2, 0)]);
            all(&checks)
        }
        Kind::Socks4 => all(&[has(0, 0), has(1, 0x5a)]),
        Kind::Connect => {
            // `HTTP/1.x 2xx`: the version, a space, a code of three digits starting with 2.
            let line = b"HTTP/1.";
            let mut checks: Vec<Option<bool>> =
                line.iter().enumerate().map(|(i, &c)| has(i, c)).collect();
            let digit = |i: usize| reply.get(i).map(u8::is_ascii_digit);
            checks.extend([digit(7), has(8, b' '), has(9, b'2'), digit(10), digit(11)]);
            all(&checks)
        }
        _ => Some(false),
    }
}

/// The most of a server's first bytes [`bound`] reads for a `UDP ASSOCIATE`: SOCKS5's choice and RFC 1929's success,
/// then the reply whole, whose longest form names a host of 255 bytes ([`crate::socks5::MAX_REPLY`]).
pub const ASSOCIATE_REPLY: usize = 4 + crate::socks5::MAX_REPLY;

/// Where a confirmed `UDP ASSOCIATE` says its relay is (the proxy record's unit U): the reply's `BND.ADDR` and
/// `BND.PORT`, read only once [`confirmed`] says `Some(true)`, by the parsers of the engine's own SOCKS5 client
/// (`socks5::reply_length`, `socks5::reply`), which are fuzzed. `None` while more bytes are needed, `Some(None)` for no
/// relay: not an associate, not confirmed, or a reply that does not parse. Read from the reply's own length, never past
/// it, so that a reply cut at any byte gives none or the same as the whole (`fuzz_targets/proxies.rs`). The caller
/// decides what the address means: the engine ties the relay at the control connection's own server, whatever
/// `BND.ADDR` names (`engine::proxied`).
#[must_use]
pub fn bound(request: &Request, reply: &[u8]) -> Option<Option<crate::socks5::Target>> {
    if !request.associate || request.kind != Kind::Socks5 {
        return Some(None);
    }
    if !confirmed(request, reply)? {
        return Some(None);
    }
    // The reply's header follows the choice, and RFC 1929's success where it was used.
    let rest = reply.get(if request.method == 2 { 4 } else { 2 }..)?;
    let head: [u8; 5] = rest.get(..5)?.try_into().ok()?;
    let Ok(length) = crate::socks5::reply_length(head) else {
        return Some(None);
    };
    Some(crate::socks5::reply(rest.get(..length)?).ok())
}

/// Whether a header line is `Proxy-Authorization` with the `Basic` scheme, whose credentials are only
/// base64. The credentials after the scheme are not looked at.
fn basic_proxy_authorization(header: &[u8]) -> bool {
    const NAME: &[u8] = b"proxy-authorization:";
    if header.len() < NAME.len() || !header[..NAME.len()].eq_ignore_ascii_case(NAME) {
        return false;
    }
    let value = &header[NAME.len()..];
    let value = &value[value
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(value.len())..];
    value.len() > 5 && value[..5].eq_ignore_ascii_case(b"basic") && matches!(value[5], b' ' | b'\t')
}

/// `host:port`, the host a name, an IPv4 address or an IPv6 address in brackets; the port required unless a
/// default is given.
fn authority(text: &[u8], default: Option<u16>) -> Option<(Asked, u16)> {
    let (host, port) = if let Some(rest) = text.strip_prefix(b"[") {
        let close = rest.iter().position(|&c| c == b']')?;
        let after = &rest[close + 1..];
        let port = match after {
            [] => None,
            [b':', digits @ ..] => Some(digits),
            _ => return None,
        };
        let address: Ipv6Addr = std::str::from_utf8(&rest[..close]).ok()?.parse().ok()?;
        (Asked::Address(IpAddr::V6(address)), port)
    } else {
        let (host, port) = match text.iter().rposition(|&c| c == b':') {
            Some(colon) => (&text[..colon], Some(&text[colon + 1..])),
            None => (text, None),
        };
        let host = match std::str::from_utf8(host)
            .ok()
            .and_then(|h| h.parse::<Ipv4Addr>().ok())
        {
            Some(address) => Asked::Address(IpAddr::V4(address)),
            None => host_name(host)?,
        };
        (host, port)
    };
    let port = match port {
        None => default?,
        Some(digits)
            if !digits.is_empty() && digits.len() <= 5 && digits.iter().all(u8::is_ascii_digit) =>
        {
            std::str::from_utf8(digits).ok()?.number::<u16>().ok()?
        }
        Some(_) => return None,
    };
    (port != 0).then_some((host, port))
}

/// A host name as a flow keeps it, from bytes an app sent: letters, digits, `-`, `_` and dots, 1 to 253
/// bytes once a trailing dot is dropped, in lower case.
pub(crate) fn host_name(bytes: &[u8]) -> Option<Asked> {
    let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
    let fits = !bytes.is_empty()
        && bytes.len() <= 253
        && bytes
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && !bytes.starts_with(b".")
        && !bytes.windows(2).any(|w| w == b"..");
    fits.then(|| Asked::Name(String::from_utf8_lossy(bytes).to_ascii_lowercase()))
}

fn v4_at(b: &[u8], i: usize) -> Result<Ipv4Addr, Need> {
    let octets: [u8; 4] = b.get(i..i + 4).ok_or(Need)?.try_into().map_err(|_| Need)?;
    Ok(Ipv4Addr::from(octets))
}

fn v6_at(b: &[u8], i: usize) -> Result<Ipv6Addr, Need> {
    let octets: [u8; 16] = b.get(i..i + 16).ok_or(Need)?.try_into().map_err(|_| Need)?;
    Ok(Ipv6Addr::from(octets))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether the start of a stream is the header of Telegram's obfuscated transport, by its documented
/// rules and its randomness (module comment); `None` until [`OBFUSCATED_HEADER`] bytes came. A stream that
/// starts as TLS, HTTP or `WhatsApp`'s header is not.
#[must_use]
pub fn obfuscated2(start: &[u8]) -> Option<bool> {
    const EXCLUDED: [[u8; 4]; 7] = [
        *b"HEAD",
        *b"POST",
        *b"GET ",
        *b"OPTI",
        [0x16, 0x03, 0x01, 0x02],
        [0xdd; 4],
        [0xee; 4],
    ];
    let header = start.get(..OBFUSCATED_HEADER)?;
    if header[0] == 0xef || EXCLUDED.iter().any(|e| header[..4] == e[..]) || header[4..8] == [0; 4]
    {
        return Some(false);
    }
    if whatsapp_header(header) == Some(true) {
        return Some(false);
    }
    // Between 3 and 5 bits set a byte, on average: 192 to 320 over the 64 bytes; 16 to 48 bytes with the high
    // bit set; and not UTF-8 text, a character cut at the end included (module comment).
    let bits: u32 = header.iter().map(|b| b.count_ones()).sum();
    let high = header.iter().filter(|&&b| b >= 0x80).count();
    let text = match std::str::from_utf8(header) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none(),
    };
    Some((192..=320).contains(&bits) && (16..=48).contains(&high) && !text)
}

/// Whether the start of a stream is `WhatsApp`'s clear header (module comment); `None` while too few bytes
/// came to tell.
#[must_use]
pub fn whatsapp_header(start: &[u8]) -> Option<bool> {
    const ROUTED: &[u8] = &[b'E', b'D', 0, 1];
    if let [b'W', b'A', _, _, ..] = start {
        return Some(true);
    }
    if let [b'E', b'D', 0, 1, a, b, c, ..] = start {
        let length = usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c);
        return match start.get(7 + length..7 + length + 2) {
            Some(wa) => Some(wa == b"WA"),
            None if 7 + length + 2 <= MAX_REQUEST => None,
            None => Some(false),
        };
    }
    // A start of either header, shorter than its first four bytes, or of the routed one's seven.
    let short = start.len() < 4 && b"WA"[..start.len().min(2)] == start[..start.len().min(2)]
        || start.len() < 7 && ROUTED[..start.len().min(4)] == start[..start.len().min(4)];
    if short { None } else { Some(false) }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    fn ip6(text: &str) -> Ipv6Addr {
        text.parse().unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// A synthetic secret the tests look for wherever they must not find it.
    pub(crate) const SECRET: &[u8] = b"hunter2-synthetic-secret";

    fn socks5_with_password(name: &[u8]) -> Vec<u8> {
        let mut b = vec![5, 2, 0, 2, 1, 4];
        b.extend_from_slice(b"user");
        b.push(u8::try_from(SECRET.len()).unwrap_or(0));
        b.extend_from_slice(SECRET);
        b.extend_from_slice(&[5, 1, 0, 3, u8::try_from(name.len()).unwrap_or(0)]);
        b.extend_from_slice(name);
        b.extend_from_slice(&443u16.to_be_bytes());
        b
    }

    #[test]
    fn a_socks5_request_names_its_destination_and_says_only_that_a_password_crossed() {
        let mut b = socks5_with_password(b"Example.COM.");
        let inner = b.len();
        b.extend_from_slice(&[0x16, 0x03, 0x01]);
        let Declared::Request(request) = declared(&b) else {
            unreachable!("not read");
        };
        assert_eq!(request.kind, Kind::Socks5);
        assert_eq!(request.asked, Asked::Name("example.com".into()));
        assert_eq!(request.port, 443);
        assert!(request.password);
        assert_eq!(request.inner, Some(inner));
        // Nothing of the secret is in what is returned, in any form.
        let shown = format!("{request:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        // Every prefix is incomplete until the port came.
        for cut in 0..inner {
            assert_eq!(declared(&b[..cut]), Declared::Incomplete, "at {cut}");
        }
    }

    #[test]
    fn socks5_without_a_password_and_by_address() {
        let mut b = vec![5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 5, 0, 80];
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert_eq!(r.asked, Asked::Address(ip("203.0.113.5")));
        assert_eq!((r.port, r.password, r.inner), (80, false, Some(13)));
        b = vec![5, 1, 0, 5, 1, 0, 4];
        b.extend_from_slice(&ip6("2001:db8::1").octets());
        b.extend_from_slice(&[1, 187]);
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert_eq!(r.asked, Asked::Address(ip("2001:db8::1")));
        assert_eq!(r.port, 443);
    }

    /// SOCKS5's `UDP ASSOCIATE` (unit U, audit M1 and m2): its `DST`, zeros, an address or a name, is the client's own
    /// source, never read as a destination, and it carries no inner stream.
    #[test]
    fn a_udp_associate_names_no_destination_and_no_inner_stream() {
        let unasked = Asked::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let mut by_name = vec![5, 1, 0, 5, 3, 0, 3, 9];
        by_name.extend_from_slice(b"phone.lan");
        by_name.extend_from_slice(&[0x9c, 0x40]);
        let mut by_v6 = vec![5, 1, 0, 5, 3, 0, 4];
        by_v6.extend_from_slice(&ip6("2001:db8::7").octets());
        by_v6.extend_from_slice(&[0x9c, 0x40]);
        for b in [
            vec![5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
            vec![5, 1, 0, 5, 3, 0, 1, 10, 215, 173, 1, 0x9c, 0x40],
            by_name,
            by_v6,
        ] {
            let Declared::Request(r) = declared(&b) else {
                unreachable!("not read: {b:?}");
            };
            assert!(r.associate, "{b:?}");
            assert_eq!(r.kind, Kind::Socks5);
            assert_eq!((&r.asked, r.port, r.inner), (&unasked, 0, None), "{b:?}");
            for cut in 0..b.len() {
                assert_eq!(declared(&b[..cut]), Declared::Incomplete, "at {cut}");
            }
        }
        // With RFC 1929, the password is said to have crossed, as for a `CONNECT`.
        let mut b = vec![5, 1, 2, 1, 4];
        b.extend_from_slice(b"user");
        b.push(4);
        b.extend_from_slice(b"pass");
        b.extend_from_slice(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert!(r.associate && r.password);
        assert_eq!(r.method, 2);
        // A `CONNECT` is no associate.
        let Declared::Request(r) = declared(&[5, 1, 0, 5, 1, 0, 1, 203, 0, 113, 5, 0, 80]) else {
            unreachable!("not read");
        };
        assert!(!r.associate);
    }

    fn associate(method: u8) -> Request {
        Request {
            kind: Kind::Socks5,
            asked: Asked::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 0,
            password: method == 2,
            inner: None,
            method,
            associate: true,
        }
    }

    /// The relay a confirmed `UDP ASSOCIATE` names (unit U, audit M2): in IPv4, IPv6 and name forms, zeros included,
    /// after RFC 1929's success too, and from a reply cut at any byte, none until it is whole and then the same.
    #[test]
    fn a_confirmed_associates_relay_is_read_whole_in_every_form() {
        use crate::socks5::Target;
        let v4 = |a: [u8; 4], port: u16| Target::Address(SocketAddr::from((a, port)));
        let mut v6_reply = vec![5, 0, 5, 0, 0, 4];
        v6_reply.extend_from_slice(&ip6("2001:db8::53").octets());
        v6_reply.extend_from_slice(&[0x1f, 0x90]);
        let mut name_reply = vec![5, 0, 5, 0, 0, 3, 11];
        name_reply.extend_from_slice(b"relay.local");
        name_reply.extend_from_slice(&[0x1f, 0x90]);
        let mut password_v6 = vec![5, 2, 1, 0];
        password_v6.extend_from_slice(&v6_reply[2..]);
        let cases: Vec<(Request, Vec<u8>, Target)> = vec![
            (
                associate(0),
                vec![5, 0, 5, 0, 0, 1, 203, 0, 113, 9, 0x1f, 0x90],
                v4([203, 0, 113, 9], 8080),
            ),
            (
                associate(0),
                vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0x1f, 0x90],
                v4([0, 0, 0, 0], 8080),
            ),
            (
                associate(0),
                v6_reply,
                Target::Address(SocketAddr::new(ip("2001:db8::53"), 8080)),
            ),
            (
                associate(0),
                name_reply,
                Target::Name("relay.local".into(), 8080),
            ),
            (
                associate(2),
                password_v6,
                Target::Address(SocketAddr::new(ip("2001:db8::53"), 8080)),
            ),
        ];
        for (request, reply, relay) in cases {
            assert_eq!(
                bound(&request, &reply),
                Some(Some(relay.clone())),
                "{reply:?}"
            );
            for cut in 0..reply.len() {
                assert_eq!(
                    bound(&request, &reply[..cut]),
                    None,
                    "at {cut} of {reply:?}"
                );
            }
            // Bytes past the reply's own length are the relay's or the tunnel's, never read.
            let mut more = reply.clone();
            more.extend_from_slice(&[0xde, 0xad]);
            assert_eq!(bound(&request, &more), Some(Some(relay)), "{reply:?}");
        }
        // Refused, by another protocol, a malformed reply, or no associate: no relay.
        assert_eq!(bound(&associate(0), &[5, 0, 5, 1, 0]), Some(None));
        assert_eq!(bound(&associate(0), b"HTTP/1.1 200 OK"), Some(None));
        assert_eq!(
            bound(&associate(0), &[5, 0, 5, 0, 0, 9, 1, 2, 3]),
            Some(None)
        );
        assert_eq!(bound(&associate(2), &[5, 0, 5, 0, 0, 1]), Some(None));
        let connect = Request {
            associate: false,
            ..associate(0)
        };
        assert_eq!(
            bound(&connect, &[5, 0, 5, 0, 0, 1, 203, 0, 113, 9, 0x1f, 0x90]),
            Some(None)
        );
    }

    #[test]
    fn what_is_not_a_socks5_connect_or_associate_is_none() {
        // BIND names no destination of this flow, and no other command is read.
        assert_eq!(
            declared(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]),
            Declared::Not
        );
        assert_eq!(
            declared(&[5, 1, 0, 5, 4, 0, 1, 1, 2, 3, 4, 0, 80]),
            Declared::Not
        );
        // No methods; a sub-negotiation not offered; a name with a space.
        assert_eq!(declared(&[5, 0, 5]), Declared::Not);
        assert_eq!(declared(&[5, 1, 0, 1, 1, b'u', 1, b'p']), Declared::Not);
        assert_eq!(
            declared(&[5, 1, 0, 5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80]),
            Declared::Not
        );
        // A port of 0 is read as asked: SOCKS carries it.
        assert!(matches!(
            declared(&[5, 1, 0, 5, 1, 0, 3, 1, b'a', 0, 0]),
            Declared::Request(_)
        ));
    }

    #[test]
    fn socks4_and_4a_skip_the_user_id() {
        let mut b = vec![4, 1, 1, 187, 198, 51, 100, 7];
        b.extend_from_slice(SECRET);
        b.push(0);
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert_eq!(r.kind, Kind::Socks4);
        assert_eq!(r.asked, Asked::Address(ip("198.51.100.7")));
        assert!(!r.password && r.inner == Some(b.len()));
        assert!(!format!("{r:?}").contains("hunter2"));
        let mut a = vec![4, 1, 0, 80, 0, 0, 0, 9];
        a.extend_from_slice(b"id\0example.org\0");
        let Declared::Request(r) = declared(&a) else {
            unreachable!("not read");
        };
        assert_eq!(r.asked, Asked::Name("example.org".into()));
        assert_eq!(r.inner, Some(a.len()));
        assert_eq!(declared(&a[..a.len() - 1]), Declared::Incomplete);
        // BIND, and 0.0.0.0.
        assert_eq!(declared(&[4, 2, 0, 80, 1, 2, 3, 4, 0]), Declared::Not);
        assert_eq!(declared(&[4, 1, 0, 80, 0, 0, 0, 0, 0]), Declared::Not);
    }

    #[test]
    fn an_http_connect_names_its_authority_and_tells_basic_from_other_schemes() {
        let text = "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\nProxy-Authorization: Basic aHVudGVyMg==\r\n\r\n";
        let mut b = text.as_bytes().to_vec();
        b.extend_from_slice(&[0x16, 3, 1]);
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert_eq!(r.kind, Kind::Connect);
        assert_eq!(
            (r.asked.clone(), r.port, r.password),
            (Asked::Name("example.net".into()), 443, true)
        );
        assert_eq!(r.inner, Some(text.len()));
        assert!(!format!("{r:?}").contains("aHVudGVy"));
        let digest = "CONNECT [2001:db8::5]:8443 HTTP/1.1\nproxy-authorization: Digest x\n\n";
        let Declared::Request(r) = declared(digest.as_bytes()) else {
            unreachable!("not read");
        };
        assert_eq!(r.asked, Asked::Address(ip("2001:db8::5")));
        assert!(!r.password);
        assert_eq!(
            declared(&text.as_bytes()[..text.len() - 1]),
            Declared::Incomplete
        );
        // No port; not HTTP/1.
        assert_eq!(
            declared(b"CONNECT example.net HTTP/1.1\r\n\r\n"),
            Declared::Not
        );
        assert_eq!(
            declared(b"CONNECT example.net:443 HTTP/2\r\n\r\n"),
            Declared::Not
        );
    }

    #[test]
    fn a_plain_request_to_a_proxy_gives_its_authority_only() {
        let text = "GET http://user:hunter2@Example.org:8080/private/path?q=secret HTTP/1.1\r\nProxy-Authorization: basic x\r\n\r\n";
        let Declared::Request(r) = declared(text.as_bytes()) else {
            unreachable!("not read");
        };
        assert_eq!(r.kind, Kind::Forward);
        assert_eq!(
            (r.asked.clone(), r.port, r.password, r.inner),
            (Asked::Name("example.org".into()), 8080, true, None)
        );
        let shown = format!("{r:?}");
        for hidden in ["hunter2", "private", "secret", "user"] {
            assert!(!shown.contains(hidden), "{shown}");
        }
        let Declared::Request(r) = declared(b"POST HTTP://192.0.2.4?x HTTP/1.0\r\n\r\n") else {
            unreachable!("not read");
        };
        assert_eq!((r.asked, r.port), (Asked::Address(ip("192.0.2.4")), 80));
        // An origin-form request, as to a server itself, and HTTPS's absolute form, are not to a proxy.
        assert_eq!(
            declared(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Declared::Not
        );
        assert_eq!(
            declared(b"GET https://example.org/ HTTP/1.1\r\n\r\n"),
            Declared::Not
        );
        assert_eq!(
            declared(b"get http://example.org/ HTTP/1.1\r\n\r\n"),
            Declared::Not
        );
        // A long line is taken without its headers once the bound is reached.
        let mut long = b"GET http://example.org/".to_vec();
        long.resize(MAX_REQUEST + 10, b'a');
        assert!(matches!(
            declared(&long),
            Declared::Request(Request {
                password: false,
                ..
            })
        ));
        assert_eq!(declared(&long[..100]), Declared::Incomplete);
    }

    #[test]
    fn other_protocols_are_no_request_at_once() {
        assert_eq!(declared(&[0x16, 3, 1, 0, 5]), Declared::Not);
        assert_eq!(declared(b"\x00\x01"), Declared::Not);
        assert_eq!(declared(b"SSH-2.0-OpenSSH"), Declared::Not);
        assert_eq!(declared(b""), Declared::Incomplete);
        assert_eq!(declared(&vec![b'A'; MAX_REQUEST]), Declared::Not);
    }

    /// 64 bytes of a fixed pseudo-random header.
    fn random_header(seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..64)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24).to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn the_obfuscated_header_follows_telegrams_rules() {
        let mut h = random_header(7);
        h[0] = 0x12;
        assert_eq!(obfuscated2(&h[..63]), None);
        assert_eq!(obfuscated2(&h), Some(true));
        for prefix in [
            &b"HEAD"[..],
            b"POST",
            b"GET ",
            b"OPTI",
            &[0x16, 3, 1, 2],
            &[0xdd; 4],
            &[0xee; 4],
        ] {
            let mut x = h.clone();
            x[..4].copy_from_slice(prefix);
            assert_eq!(obfuscated2(&x), Some(false), "{prefix:?}");
        }
        let mut x = h.clone();
        x[0] = 0xef;
        assert_eq!(obfuscated2(&x), Some(false));
        let mut x = h.clone();
        x[4..8].copy_from_slice(&[0; 4]);
        assert_eq!(obfuscated2(&x), Some(false));
        // Mostly zeros, or WhatsApp's header, is not random.
        let mut z = vec![0x41; 64];
        z[4] = 1;
        assert_eq!(obfuscated2(&z), Some(false));
        let mut w = h;
        w[..4].copy_from_slice(b"WA\x06\x03");
        assert_eq!(obfuscated2(&w), Some(false));
    }

    #[test]
    fn socks_requests_need_a_plausible_method_list_and_a_printable_user_id() {
        // SOCKS5: a method outside IANA's 0 to 9, one offered twice, more than ten, or the method used not offered.
        for greeting in [
            &[5, 1, 0x80][..],
            &[5, 2, 0, 0x80],
            &[5, 2, 0, 0],
            &[5, 11, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 9],
            &[5, 1, 2],
        ] {
            let mut b = greeting.to_vec();
            b.extend_from_slice(&[5, 1, 0, 1, 203, 0, 113, 5, 0, 80]);
            assert_eq!(declared(&b), Declared::Not, "{greeting:?}");
        }
        let Declared::Request(r) = declared(&[5, 3, 2, 1, 0, 5, 1, 0, 1, 203, 0, 113, 5, 0, 80])
        else {
            unreachable!("not read");
        };
        assert_eq!(r.method, 0);
        assert_eq!(socks5_request_method(), 2);
        // SOCKS4: a user ID of anything but printable ASCII.
        let mut b = vec![4, 1, 0, 80, 198, 51, 100, 7, b'i', 0x01, b'd', 0];
        assert_eq!(declared(&b), Declared::Not);
        b[9] = b'~';
        assert!(matches!(declared(&b), Declared::Request(_)));
    }

    fn socks5_request_method() -> u8 {
        match declared(&socks5_with_password(b"example.com")) {
            Declared::Request(r) => r.method,
            _ => 0xff,
        }
    }

    #[test]
    fn only_the_servers_reply_confirms_a_proxy_handshake() {
        let socks5 = |method| Request {
            kind: Kind::Socks5,
            asked: Asked::Name("example.org".into()),
            port: 443,
            password: method == 2,
            inner: None,
            method,
            associate: false,
        };
        let plain = socks5(0);
        assert_eq!(
            confirmed(&plain, &[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
            Some(true)
        );
        for cut in 0..5 {
            assert_eq!(confirmed(&plain, &[5, 0, 5, 0, 0][..cut]), None, "at {cut}");
        }
        // Refused: no acceptable method, or the request refused (general failure, 1).
        assert_eq!(confirmed(&plain, &[5, 0xff]), Some(false));
        assert_eq!(confirmed(&plain, &[5, 0, 5, 1, 0]), Some(false));
        // Another server's bytes: a TLS server's first record, an HTTP answer.
        assert_eq!(confirmed(&plain, &[0x16, 3, 3]), Some(false));
        assert_eq!(confirmed(&plain, b"HTTP/1.1 400"), Some(false));
        let password = socks5(2);
        assert_eq!(confirmed(&password, &[5, 2, 1, 0, 5, 0, 0]), Some(true));
        assert_eq!(
            confirmed(&password, &[5, 0, 5, 0, 0]),
            Some(false),
            "not the method used"
        );
        assert_eq!(
            confirmed(&password, &[5, 2, 1, 1]),
            Some(false),
            "the password refused"
        );
        let socks4 = Request {
            kind: Kind::Socks4,
            ..plain.clone()
        };
        assert_eq!(
            confirmed(&socks4, &[0, 0x5a, 0, 80, 1, 2, 3, 4]),
            Some(true)
        );
        assert_eq!(confirmed(&socks4, &[0, 0x5b]), Some(false));
        assert_eq!(confirmed(&socks4, &[0]), None);
        let connect = Request {
            kind: Kind::Connect,
            ..plain.clone()
        };
        assert_eq!(
            confirmed(&connect, b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(true)
        );
        assert_eq!(confirmed(&connect, b"HTTP/1.0 204 x"), Some(true));
        assert_eq!(
            confirmed(&connect, b"HTTP/1.1 407 Proxy Authentication Required"),
            Some(false)
        );
        assert_eq!(confirmed(&connect, b"HTTP/1.1 2"), None);
        assert_eq!(confirmed(&connect, b"SSH-2.0-OpenSSH_9.6"), Some(false));
        assert_eq!(confirmed(&connect, b"HTTP/2 200 "), Some(false));
        // A plain request is never confirmed by its reply: origin servers take the absolute form too.
        let forward = Request {
            kind: Kind::Forward,
            ..plain
        };
        assert_eq!(confirmed(&forward, b"HTTP/1.1 200 OK\r\n"), Some(false));
    }

    /// An empty RFC 1929 password crossed nothing; a `Proxy-Authorization` of another scheme of five letters is
    /// not `Basic`.
    #[test]
    fn only_a_password_sent_is_said_to_have_crossed() {
        let mut b = vec![5, 1, 2, 1, 4];
        b.extend_from_slice(b"user");
        b.push(0);
        b.extend_from_slice(&[5, 1, 0, 1, 203, 0, 113, 5, 0, 80]);
        let Declared::Request(r) = declared(&b) else {
            unreachable!("not read");
        };
        assert!(!r.password);
        let Declared::Request(r) =
            declared(b"CONNECT example.net:443 HTTP/1.1\r\nProxy-Authorization: Token abc\r\n\r\n")
        else {
            unreachable!("not read");
        };
        assert!(!r.password);
    }

    #[test]
    fn an_at_sign_after_the_authority_is_refused() {
        assert_eq!(
            declared(b"GET http://alice:1234/x@host/ HTTP/1.1\r\n\r\n"),
            Declared::Not
        );
        assert_eq!(
            declared(b"GET http://example.org/?q=a@b HTTP/1.1\r\n\r\n"),
            Declared::Not
        );
        assert!(matches!(
            declared(b"GET http://user@example.org/x HTTP/1.1\r\n\r\n"),
            Declared::Request(Request { asked: Asked::Name(ref n), .. }) if n == "example.org"
        ));
    }

    /// A fast generator of bytes for the measurements below (xorshift64*).
    struct Bytes(u64);

    impl Bytes {
        fn next(&mut self) -> u8 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes()[7]
        }
    }

    /// The false rate of the declared kinds on random starts, as the review measured it (36 SOCKS4 requests in
    /// 2,000,000 random 600-byte starts before the fix round): none now. A start whose first byte rules every kind
    /// out at once (all but 4, 5 and the letters) is decided by that byte alone, so only the others are drawn whole.
    #[test]
    fn random_starts_are_no_proxy_request() {
        let mut random = Bytes(0x9e37_79b9_7f4a_7c15);
        let mut start = vec![0u8; 600];
        let mut found = 0;
        for _ in 0..2_000_000 {
            start[0] = random.next();
            if !matches!(start[0], 4 | 5 | b'A'..=b'Z') {
                continue;
            }
            for byte in &mut start[1..] {
                *byte = random.next();
            }
            if matches!(declared(&start), Declared::Request(_)) {
                found += 1;
            }
        }
        assert_eq!(found, 0);
    }

    /// A random header passes the obfuscated transport's rules but for 2.4 in 100,000 (module comment): fewer
    /// than 1 in 10,000, measured on 1,000,000 random headers.
    #[test]
    fn random_headers_are_read_as_obfuscated_but_rarely() {
        let mut random = Bytes(0x2545_f491_4f6c_dd1d);
        let mut header = [0u8; 64];
        let mut missed = 0;
        for _ in 0..1_000_000 {
            for byte in &mut header {
                *byte = random.next();
            }
            // The documented excluded starts are the client's to avoid; a header holding one is drawn again.
            header[0] = if header[0] == 0xef { 0x12 } else { header[0] };
            if obfuscated2(&header) == Some(false) {
                missed += 1;
            }
        }
        assert!(missed < 100, "{missed} in 1,000,000");
    }

    #[test]
    fn text_is_no_obfuscated_header() {
        let persian = "سلام، این یک پیام آزمایشی است که به زبان فارسی نوشته شده است و بیشتر از شصت و چهار بایت دارد.";
        let mixed =
            "Hello, سلام! This line mixes English and فارسی words to make sixty-four bytes or more.";
        for text in [
            &b"PUT /upload/part?id=1234567890 HTTP/1.1\r\nHost: upload.example.com\r\nContent-Length: 1\r\n"[..],
            b"PATCH /v1/items/42 HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n",
            b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n\x00\x00\x05\xdc\x07\x14abcdefghijklmnopqrstuv",
            persian.as_bytes(),
            mixed.as_bytes(),
        ] {
            assert_eq!(obfuscated2(text), Some(false), "{}", String::from_utf8_lossy(&text[..16]));
        }
        // The high bit's bound alone: random low bits, with the high bit set on exactly `k` of the 64 bytes (a
        // permutation of their places), pass at 16 and 48 and not at 15 or 49.
        let with_high = |k: usize| -> Vec<u8> {
            let mut h = random_header(11);
            for (i, byte) in h.iter_mut().enumerate() {
                *byte = if (i * 37) % 64 < k {
                    *byte | 0x80
                } else {
                    *byte & 0x7f
                };
            }
            h
        };
        for (k, passes) in [(15, false), (16, true), (48, true), (49, false)] {
            assert_eq!(
                obfuscated2(&with_high(k)),
                Some(passes),
                "{k} bytes with the high bit"
            );
        }
        // The bits' average alone: half the bytes with the high bit, one bit each, 64 bits in all, is not random.
        let sparse: Vec<u8> = (0..64)
            .map(|i| if i % 2 == 0 { 0x80 } else { 0x01 })
            .collect();
        assert_eq!(obfuscated2(&sparse), Some(false));
    }

    #[test]
    fn whatsapps_header_with_and_without_routing() {
        assert_eq!(whatsapp_header(b"WA\x06\x03\x00\x00"), Some(true));
        assert_eq!(whatsapp_header(b"WA\x06"), None);
        let mut routed = vec![b'E', b'D', 0, 1, 0, 0, 3, 9, 9, 9];
        assert_eq!(whatsapp_header(&routed), None);
        routed.extend_from_slice(b"WA\x06\x03");
        assert_eq!(whatsapp_header(&routed), Some(true));
        routed[10] = b'X';
        assert_eq!(whatsapp_header(&routed), Some(false));
        assert_eq!(whatsapp_header(&[0x16, 3]), Some(false));
        assert_eq!(whatsapp_header(b"EX"), Some(false));
        // A routing length past the bound is no header.
        assert_eq!(
            whatsapp_header(&[b'E', b'D', 0, 1, 0xff, 0xff, 0xff]),
            Some(false)
        );
    }
}
