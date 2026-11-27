//! An HTTP `CONNECT` client's bytes (RFC 9110, 9.3.6; RFC 9112, 3.2.3), for the network's own proxy (the proxy
//! record's unit S2): where the network beneath names a direct HTTP proxy in its settings, the engine sends a direct
//! app's TCP through it where a direct connection fails, as Android would have given that app the proxy without the
//! VPN (`engine::beneath`).
//!
//! **The request** is `CONNECT <authority> HTTP/1.1`, a `Host` header of the same authority and a blank line, as the
//! resolver's `ProxySocket` writes it on the Kotlin side. The authority always gives the port: an IPv4 address, an
//! IPv6 address in brackets and never with a zone, or a host name. No other header is written: no `User-Agent`,
//! `Proxy-Connection`, `Connection` or `Proxy-Authorization`, so that nothing names the engine, and Android keeps no
//! credentials for a network's proxy to send.
//!
//! **The answer's head** ends at its first blank line, `\r\n\r\n` or `\n\n`, within [`MAX_HEAD`] bytes, as
//! `ProxySocket.MAX_HEAD`; [`head_end`] says where, so that the engine reads exactly the head and nothing of the
//! tunnel after it, which a server that speaks first (an SMTP banner) may send in the same segment. [`status`] reads
//! the status line's code, `HTTP/1.x` and three digits, the reason phrase optional; [`Answer::of`] tells what a code
//! means for the flow. A `Content-Length` or `Transfer-Encoding` on a `2xx` means nothing: the content is the tunnel
//! (RFC 9110, 9.3.6). An interim `1xx` is not skipped (RFC 9110, 15.2): no proxy sends one to a `CONNECT` without an
//! `Expect`, and the engine takes it, as a `3xx` (a login page's redirect), for a refusal. The head is never kept or
//! logged: it may carry a `Proxy-Authenticate` realm, which names the network's operator.
//!
//! **The exclusion list** ([`excluded`]) is the Rust twin of the Kotlin side's `NetworkProxy.excluded`, both read
//! against one table, `core/net/testdata/proxy-exclusions.tsv`: comma-separated entries, case-insensitive, a trailing
//! dot dropped; `*` matches any run, so `*.example.com` takes the subdomains of `example.com` and `10.*` the addresses
//! that start so; a leading `.` takes the subdomains; any other entry takes that host itself; an IPv6 host's brackets
//! are dropped. It is wider than Android's own selector, libcore's, which matches case-sensitively and reads no
//! leading dot as the subdomains (Chromium does): the safe direction, since more goes directly. CIDR entries, which
//! Chromium reads, are not read. `*` here matches any run of bytes, where the Kotlin side's regular expression stops
//! at a line break, which no host holds. Letters are folded in ASCII alone, on both sides, as the table holds: a host
//! the engine asks about is a DNS name or an address, ASCII both, and Unicode's folding would make the Kelvin sign a
//! `k`. The host and each entry are trimmed of the code points up to U+0020 alone, the controls and the space, on both
//! sides, as Java's `String.trim` does: Rust's `str::trim` takes Unicode's white space (U+0085 and U+00A0 among it)
//! and Kotlin's `trim` Java's (U+001C to U+001F among it): each alone would read a rare list otherwise than the other.
//! Hand-written, with no regular expression crate and no Unicode case tables, for size.
//!
//! Everything here is pure, with no IO, so that it can be fuzzed with any bytes a proxy can send
//! (`fuzz_targets/connect.rs`); nothing may panic or read outside the slice.

use crate::socks5::Target;
use std::net::IpAddr;

/// The most bytes of a proxy's answer read for its head: a status line and a few headers, as `ProxySocket.MAX_HEAD`.
pub const MAX_HEAD: usize = 8_192;

/// Why a proxy's answer is no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No blank line within [`MAX_HEAD`] bytes.
    TooLong,
    /// The head does not start with an `HTTP/1.x` status line and a code of three digits.
    NotHttp,
}

/// What a proxy's status code means for the flow it was asked to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `2xx`: the tunnel is open; what follows the head is the destination's.
    Opened,
    /// A `4xx` other than `407`: refused, as a proxy that filters by name answers a bare address (often `403`), so a
    /// request by name may follow.
    Refused,
    /// `407`: the proxy wants a password, which Android does not keep for a network.
    Password,
    /// `5xx`: the proxy could not reach the destination (`502`, `503`, `504`).
    Unreachable,
    /// Any other code: an interim `1xx`, a `3xx` redirect, or none of HTTP's classes. Taken for a refusal, with no
    /// request by name after it.
    Unexpected,
}

impl Answer {
    /// The meaning of the status code `status`.
    #[must_use]
    pub fn of(status: u16) -> Self {
        match status {
            200..=299 => Self::Opened,
            407 => Self::Password,
            400..=499 => Self::Refused,
            500..=599 => Self::Unreachable,
            _ => Self::Unexpected,
        }
    }
}

/// The request that asks a proxy for a tunnel to `target`: `CONNECT`, the authority, `Host` and a blank line, nothing
/// else.
#[must_use]
pub fn request(target: &Target) -> Vec<u8> {
    let authority = match target {
        Target::Address(at) => match at.ip().to_canonical() {
            IpAddr::V4(ip) => format!("{ip}:{}", at.port()),
            // An address's own form, never its zone: `SocketAddrV6`'s would write one.
            IpAddr::V6(ip) => format!("[{ip}]:{}", at.port()),
        },
        Target::Name(name, port) => format!("{name}:{port}"),
    };
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

/// Where the head of a proxy's answer ends in `bytes`, its first bytes: just past its first blank line (`\r\n\r\n` or
/// `\n\n`), `None` while none is in them, an error once [`MAX_HEAD`] bytes hold none. Only the first [`MAX_HEAD`]
/// bytes are read.
///
/// # Errors
///
/// [`Error::TooLong`] when the first [`MAX_HEAD`] bytes hold no blank line.
pub fn head_end(bytes: &[u8]) -> Result<Option<usize>, Error> {
    let head = &bytes[..bytes.len().min(MAX_HEAD)];
    for (i, &b) in head.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        let lf = i >= 1 && head[i - 1] == b'\n';
        let crlf = i >= 3 && head[i - 3..i] == *b"\r\n\r";
        if lf || crlf {
            return Ok(Some(i + 1));
        }
    }
    if head.len() == MAX_HEAD {
        Err(Error::TooLong)
    } else {
        Ok(None)
    }
}

/// The code of the status line that starts `head`: `HTTP/1.` and a digit, a space, three digits, then a space, the
/// line's end or the head's. Read byte by byte, as `proxies::confirmed` reads an app's proxy's reply.
///
/// # Errors
///
/// [`Error::NotHttp`] for any other first line: `HTTP/2`, a lone code, a code of other than three digits, garbage.
pub fn status(head: &[u8]) -> Result<u16, Error> {
    let version = head.get(..7) == Some(b"HTTP/1.".as_slice())
        && head.get(7).is_some_and(u8::is_ascii_digit)
        && head.get(8) == Some(&b' ');
    let code = head
        .get(9..12)
        .filter(|code| code.iter().all(u8::is_ascii_digit));
    let ends = head
        .get(12)
        .is_none_or(|b| matches!(b, b' ' | b'\r' | b'\n'));
    match code {
        Some(&[a, b, c]) if version && ends => {
            Ok(u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'))
        }
        _ => Err(Error::NotHttp),
    }
}

/// Whether `host`, a host name or an address written out, is in `exclusions`, a proxy's exclusion list of
/// comma-separated entries, by the rules of the module's comment.
#[must_use]
pub fn excluded(host: &str, exclusions: &str) -> bool {
    let host = trimmed(host).trim_end_matches('.');
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    exclusions.split(',').any(|raw| {
        let entry = trimmed(raw).trim_end_matches('.').to_ascii_lowercase();
        if entry.is_empty() {
            false
        } else if entry.contains('*') {
            glob(entry.as_bytes(), host.as_bytes())
        } else if entry.starts_with('.') {
            host.ends_with(&entry)
        } else {
            host == entry
        }
    })
}

/// `text` without the code points up to U+0020 at either end, the controls and the space, as Java's `String.trim` and
/// the Kotlin side's `NetworkProxy.trimmed` (the module's comment).
fn trimmed(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// Whether `pattern`, whose `*` matches any run of bytes, matches the whole of `text`. The usual scan with one point to
/// go back to, the last `*`: at most `pattern.len()` times `text.len()` steps, whatever the bytes.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                back = Some((p, t));
                p += 1;
            }
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match back {
                // The last `*` takes one byte more.
                Some((star, from)) => {
                    p = star + 1;
                    t = from + 1;
                    back = Some((star, from + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p.min(pattern.len())..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxies::{self, Asked, Declared, Kind};
    use std::net::SocketAddr;

    fn address(text: &str) -> Target {
        Target::Address(
            text.parse::<SocketAddr>()
                .unwrap_or_else(|_| unreachable!("{text}")),
        )
    }

    /// The request for each kind of authority, byte for byte: an IPv6 address in brackets, its zone never written, an
    /// IPv4-mapped one as IPv4, a name; no header but `Host`.
    #[test]
    fn a_request_names_its_authority_twice_and_nothing_else() {
        let zoned = Target::Address(SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap_or_else(|_| unreachable!()),
            443,
            0,
            7,
        )));
        for (target, authority) in [
            (address("198.51.100.9:443"), "198.51.100.9:443"),
            (address("[2001:db8::9]:443"), "[2001:db8::9]:443"),
            (zoned, "[fe80::1]:443"),
            (address("[::ffff:198.51.100.9]:993"), "198.51.100.9:993"),
            (
                Target::name("name.example", 80).unwrap_or_else(|| unreachable!()),
                "name.example:80",
            ),
        ] {
            let bytes = request(&target);
            assert_eq!(
                String::from_utf8_lossy(&bytes),
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
            );
            let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
            for header in [
                "user-agent",
                "proxy-connection",
                "connection:",
                "proxy-authorization",
                "%",
            ] {
                assert!(!text.contains(header), "{header} in {text}");
            }
        }
    }

    /// Each request reads back, by the engine's own reader of apps' proxies, as a `CONNECT` to the same destination
    /// and port, its head whole.
    #[test]
    fn each_request_reads_back_as_the_same_connect() {
        for (target, asked, port) in [
            (
                address("198.51.100.9:443"),
                Asked::Address("198.51.100.9".parse().unwrap_or_else(|_| unreachable!())),
                443,
            ),
            (
                address("[2001:db8::9]:8443"),
                Asked::Address("2001:db8::9".parse().unwrap_or_else(|_| unreachable!())),
                8443,
            ),
            (
                Target::name("mail.example", 993).unwrap_or_else(|| unreachable!()),
                Asked::Name("mail.example".into()),
                993,
            ),
        ] {
            let bytes = request(&target);
            let Declared::Request(read) = proxies::declared(&bytes) else {
                unreachable!("not read: {target:?}");
            };
            assert_eq!(
                (read.kind, read.asked, read.port, read.password, read.inner),
                (Kind::Connect, asked, port, false, Some(bytes.len()))
            );
        }
    }

    /// The head's end with CRLF and with LF, at every cut: none until the blank line is whole, then the same end;
    /// bytes after it never counted.
    #[test]
    fn a_heads_end_is_found_at_its_first_blank_line_however_the_bytes_are_cut() {
        for (head, after) in [
            (
                &b"HTTP/1.1 200 Connection established\r\n\r\n"[..],
                &b"220 mail.example ESMTP\r\n"[..],
            ),
            (
                b"HTTP/1.0 200 OK\nVia: 1.1 proxy\n\n",
                b"\n\nSSH-2.0-x\r\n\r\n",
            ),
            (b"HTTP/1.1 200\r\nProxy-Agent: x\r\n\r\n", b""),
        ] {
            let whole = [head, after].concat();
            for cut in 0..=whole.len() {
                let expected = (cut >= head.len()).then_some(head.len());
                assert_eq!(head_end(&whole[..cut]), Ok(expected), "cut at {cut}");
            }
        }
        // A lone CR between the lines is no blank line, nor a line feed after a CR alone.
        assert_eq!(head_end(b"HTTP/1.1 200\r\r\n"), Ok(None));
        assert_eq!(head_end(b"HTTP/1.1 200\n\r\n"), Ok(None));
        assert_eq!(head_end(b"\n\n"), Ok(Some(2)));
    }

    /// A head of [`MAX_HEAD`] bytes ending in its blank line is read; one byte more with none is an error, and so are
    /// [`MAX_HEAD`] bytes with none, however many follow.
    #[test]
    fn a_head_past_its_bound_is_no_answer() {
        let mut fits = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        fits.resize(MAX_HEAD - 4, b'a');
        fits.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head_end(&fits), Ok(Some(MAX_HEAD)));
        let mut long = fits[..MAX_HEAD - 4].to_vec();
        long.resize(MAX_HEAD, b'a');
        assert_eq!(head_end(&long), Err(Error::TooLong));
        long.extend_from_slice(b"\r\n\r\n");
        assert_eq!(head_end(&long), Err(Error::TooLong));
        assert_eq!(head_end(&long[..MAX_HEAD - 1]), Ok(None));
    }

    /// The codes squid, tinyproxy and nginx answer with, written by hand, and what is not a status line.
    #[test]
    fn a_status_line_gives_its_code_and_anything_else_none() {
        for (line, code) in [
            (&b"HTTP/1.1 200 Connection established\r\n\r\n"[..], 200),
            (b"HTTP/1.0 200\r\n\r\n", 200),
            (b"HTTP/1.1 200\n\n", 200),
            (b"HTTP/1.1 204 No Content\r\n\r\n", 204),
            (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 403),
            (b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n", 407),
            (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", 502),
            (b"HTTP/1.0 504 Gateway Time-out\r\n\r\n", 504),
            (b"HTTP/1.1 100 Continue\r\n\r\n", 100),
            (b"HTTP/1.1 302", 302),
        ] {
            assert_eq!(status(line), Ok(code), "{}", String::from_utf8_lossy(line));
        }
        for line in [
            &b"HTTP/2 200\r\n\r\n"[..],
            b"200 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 20\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"HTTP/1.x 200 OK\r\n\r\n",
            b"http/1.1 200 OK\r\n\r\n",
            b"HTTP/1.1 2a0 OK\r\n\r\n",
            b"SSH-2.0-OpenSSH_9.6\r\n",
            b"\x16\x03\x01\x02\x00",
            b"",
        ] {
            assert_eq!(
                status(line),
                Err(Error::NotHttp),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// Each class of code, and `407` apart from the other refusals.
    #[test]
    fn each_class_of_code_means_one_thing() {
        for (code, answer) in [
            (200, Answer::Opened),
            (204, Answer::Opened),
            (299, Answer::Opened),
            (400, Answer::Refused),
            (403, Answer::Refused),
            (405, Answer::Refused),
            (407, Answer::Password),
            (499, Answer::Refused),
            (500, Answer::Unreachable),
            (502, Answer::Unreachable),
            (504, Answer::Unreachable),
            (100, Answer::Unexpected),
            (101, Answer::Unexpected),
            (302, Answer::Unexpected),
            (600, Answer::Unexpected),
            (0, Answer::Unexpected),
        ] {
            assert_eq!(Answer::of(code), answer, "{code}");
        }
    }

    /// A cell of the shared table with each `\u{XXXX}` read as that code point, so that the table can name a tab, a
    /// line break or a control without holding it.
    fn unescaped(cell: &str) -> String {
        let mut out = String::new();
        let mut rest = cell;
        while let Some(at) = rest.find("\\u{") {
            out.push_str(&rest[..at]);
            let after = &rest[at + 3..];
            let end = after
                .find('}')
                .unwrap_or_else(|| unreachable!("an open escape: {cell}"));
            let code = u32::from_str_radix(&after[..end], 16)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or_else(|| unreachable!("no code point: {cell}"));
            out.push(code);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// The table both sides hold (`core/net/testdata/proxy-exclusions.tsv`): the host, the exclusion list (`-` for
    /// none), and whether it is excluded.
    #[test]
    fn the_exclusion_list_follows_the_shared_table() {
        let mut rows = 0;
        for line in include_str!("../testdata/proxy-exclusions.tsv").lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let [host, list, expected] = fields[..] else {
                unreachable!("a row of three fields: {line}");
            };
            let list = if list == "-" { "" } else { list };
            assert_eq!(
                excluded(&unescaped(host), &unescaped(list)),
                expected == "1",
                "{line}"
            );
            rows += 1;
        }
        assert!(rows >= 30, "{rows} rows");
    }

    /// The scan stays linear in the pattern's stars: a long run of them against a long host that never matches ends.
    #[test]
    fn a_pattern_of_many_stars_ends() {
        let pattern = format!("{}b", "*a".repeat(200));
        let host = "a".repeat(4_000);
        assert!(!excluded(&host, &pattern));
        assert!(excluded(&format!("{host}b"), &pattern));
    }
}
