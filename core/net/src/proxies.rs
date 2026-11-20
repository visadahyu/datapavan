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
//! **Shapes.** The 64 bytes that start Telegram's obfuscated transport, by the rules its documentation gives
//! the client for them (core.telegram.org/mtproto/mtproto-transports, read 2026-11-20): the first byte is not
//! `0xef`, the first four are none of `HEAD`, `POST`, `GET `, `OPTI`, `16 03 01 02`, `dd dd dd dd` and `ee ee ee
//! ee`, bytes 4 to 8 are not all zero; and, as the header is random, its bits set average between 3 and 5 a
//! byte (a random header's mean is 4, with a standard deviation of 0.18 over 64 bytes). And `WhatsApp`'s clear
//! header, `W` `A` and two bytes, or `E` `D` `0` `1`, a 3-byte length, the routing data and then `W` `A`, as
//! two open-source clients write it (whatsmeow's `WAConnHeader`, Baileys's `noise-handler.ts`, read
//! 2026-11-20).
//!
//! Everything is bounded: a request is looked for in the first [`MAX_REQUEST`] bytes, and nothing here may
//! panic or read outside the slice (`fuzz_targets/proxies.rs`).

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
    if methods == 0 {
        return Ok(None);
    }
    let offered = b.get(2..2 + methods);
    let mut i = 2 + methods;
    let first = at(b, i)?;
    let mut password = false;
    if first == 1 {
        // RFC 1929: version 1, ULEN, UNAME, PLEN, PASSWD; offered only with method 2. Skipped by length.
        let Some(offered) = offered else {
            return Err(Need);
        };
        if !offered.contains(&2) {
            return Ok(None);
        }
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
    // The request: version 5, CONNECT (1), reserved 0, the address's type.
    if at(b, i)? != 5 || at(b, i + 1)? != 1 || at(b, i + 2)? != 0 {
        return Ok(None);
    }
    let (asked, after) = match at(b, i + 3)? {
        1 => (Asked::Address(IpAddr::V4(v4_at(b, i + 4)?)), i + 8),
        4 => (Asked::Address(IpAddr::V6(v6_at(b, i + 4)?)), i + 20),
        3 => {
            let length = usize::from(at(b, i + 4)?);
            let name = b.get(i + 5..i + 5 + length).ok_or(Need)?;
            let Some(name) = host_name(name) else {
                return Ok(None);
            };
            (name, i + 5 + length)
        }
        _ => return Ok(None),
    };
    let port = port_at(b, after)?;
    Ok(Some(Request {
        kind: Kind::Socks5,
        asked,
        port,
        password,
        inner: Some(after + 2),
    }))
}

/// SOCKS4: version 4, `CONNECT` (1), the port, the address, the user ID ending in a zero; `SOCKS4a`, with an
/// address 0.0.0.x (x not 0), adds the host name ending in a zero. The user ID is skipped.
fn socks4(b: &[u8]) -> Read {
    if at(b, 1)? != 1 {
        return Ok(None);
    }
    let port = port_at(b, 2)?;
    let address = v4_at(b, 4)?;
    let user_end = 8 + b
        .get(8..)
        .ok_or(Need)?
        .iter()
        .position(|&c| c == 0)
        .ok_or(Need)?;
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
        // The user information before an `@` is skipped, never read.
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
    }
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
            std::str::from_utf8(digits).ok()?.parse::<u16>().ok()?
        }
        Some(_) => return None,
    };
    (port != 0).then_some((host, port))
}

/// A host name as a flow keeps it, from bytes an app sent: letters, digits, `-`, `_` and dots, 1 to 253
/// bytes once a trailing dot is dropped, in lower case.
fn host_name(bytes: &[u8]) -> Option<Asked> {
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
    // Between 3 and 5 bits set a byte, on average: 192 to 320 over the 64 bytes.
    let bits: u32 = header.iter().map(|b| b.count_ones()).sum();
    Some((192..=320).contains(&bits))
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

    #[test]
    fn what_is_not_a_socks5_connect_is_none() {
        // UDP ASSOCIATE and BIND name no destination of this flow.
        assert_eq!(
            declared(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]),
            Declared::Not
        );
        assert_eq!(
            declared(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80]),
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
