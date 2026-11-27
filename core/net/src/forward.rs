//! Plain HTTP to the network's own proxy in absolute form (RFC 9112, 3.2.2), where that proxy refused a `CONNECT` to
//! the flow's port (the proxy record's forwarder; F-PLAN, section 3, and its audit). Pure: the strict reader of a
//! request's head, the authority, the rewrite of the request line, and the framer of every request on a kept-alive
//! connection. The engine's stage that uses it is `engine::forwarding`.
//!
//! **Only the request target changes.** `GET /p?q HTTP/1.1` becomes `GET http://<Host>/p?q HTTP/1.1`, the `Host` value
//! copied byte for byte (its optional white space trimmed); `OPTIONS *` becomes `OPTIONS http://<Host>` (RFC 9112,
//! 3.2.4); an HTTP/1.0 head without `Host` takes the destination address written out. Every other byte, the version,
//! the field lines and the bodies, goes on as the app wrote it: no `Via`, no `X-Forwarded-For`, nothing added.
//!
//! **Strict, so that two parsers cannot disagree** about where a request ends (request smuggling): CRLF only, no
//! `obs-fold`, no white space before a colon, a token for each field name, no control byte but HTAB in a value; one
//! `Host` (required in 1.1), one `Content-Length` of 1 to 19 digits or one `Transfer-Encoding` that is exactly
//! `chunked`, never both, never `Transfer-Encoding` in 1.0, no body on `GET` or `HEAD`; chunk sizes of 1 to 16 hex
//! digits with no extension, each chunk's data followed by CRLF, trailers read as field lines and none of the framing
//! or meaning fields among them. Refused too, by exact name: `Upgrade` (a WebSocket goes by `CONNECT`, RFC 6455, 4.1),
//! `Proxy-Authorization` (the app's credential is never handed to the network's proxy), and a `Connection` field that
//! names `Host`, `Content-Length` or `Transfer-Encoding` (the hop-by-hop abuse). `Upgrade-Insecure-Requests` is another
//! name and goes on. `Expect` goes on too: the proxy lab sent squid 6.13 and tinyproxy 1.11.2 a body holding a whole
//! request behind an `Expect` each refused early (`403`, `417`), and neither read that request (the audit's m6).
//!
//! **The authority** must be the flow's own: the `Host` port, or 80 without one, equal to the destination's; a literal
//! equal to the destination's address; a name of letters, digits, `-`, `_` and `.`, 1 to 253 bytes with at most one
//! trailing dot, no empty label, not ending in a number, and read by the tracker gate's own reader
//! ([`crate::blocking::http_host`]) as the same name within its 8 KiB. Whether DNS gave the name this address is the
//! engine's to check ([`First::name`]).
//!
//! **One `Host` per connection:** every later head must carry the first one's value byte for byte (or none, for
//! HTTP/1.0 without one), so that the gate's one decision on the first holds for all.
//!
//! **Copies:** every buffer that may hold a head is `Zeroizing`, and grows only by replacement ([`reserve`]): a `Vec`
//! that grows in place frees its old allocation unzeroed (the audit's m3).

use crate::blocking::{HttpHost, http_host_again};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::Zeroizing;

/// The most bytes of a request's head: squid's own default for a request's headers (`request_header_max_size`).
pub const MAX_HEAD: usize = 64 * 1024;

/// Why a head, or a byte of a body's framing, is not forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The first bytes cannot start an HTTP/1.x request line: a TLS record, a binary protocol.
    NotHttp,
    /// A bare CR or LF, or a request line that is not three parts.
    Line,
    /// Absolute form, authority form, `CONNECT`, `*` with a method other than `OPTIONS`, a byte outside `0x21` to
    /// `0x7E`, a `#`, or an `@` or `\\` that a URL's lenient reader could take for the end of the authority.
    Target,
    /// A version other than `HTTP/1.0` and `HTTP/1.1`.
    Version,
    /// A field line with no colon, white space before it, a name that is not a token, a control byte, or `obs-fold`.
    Field,
    /// `Host` missing in 1.1, more than once, empty or invalid, or read otherwise by the gate's reader.
    Host,
    /// A `Host` port other than the flow's, or not 1 to 5 digits without a leading zero.
    Port,
    /// A literal of another address than the flow's.
    Address,
    /// `Content-Length` and `Transfer-Encoding` together, either twice, a length that is not 1 to 19 digits, a coding
    /// other than `chunked`, `Transfer-Encoding` in HTTP/1.0, or a body on `GET` or `HEAD`.
    Framing,
    /// A chunk size line, or a chunk's end, not as the grammar says.
    Chunk,
    /// `Upgrade`, `Proxy-Authorization`, or a `Connection` field naming `Host` or the framing.
    Meaning,
    /// A head past [`MAX_HEAD`].
    TooLong,
    /// A later head whose `Host` is not the first one's.
    OtherHost,
    /// A name no answer of Datapavan's own resolvers gave the address (the engine's check).
    Unbound,
    /// A name the proxy's exclusion list names (the engine's check).
    Excluded,
    /// A name tracker blocking refuses for the app (the engine's check).
    Blocked,
}

/// Grows `buffer` to hold `more` bytes past its length, by a new allocation the old one is copied into and dropped,
/// zeroed, so that no copy of a head is left in freed memory.
pub fn reserve(buffer: &mut Zeroizing<Vec<u8>>, more: usize) {
    let wanted = buffer.len() + more;
    if wanted <= buffer.capacity() {
        return;
    }
    let mut grown = Zeroizing::new(Vec::with_capacity(
        wanted.max(2 * buffer.capacity()).max(256),
    ));
    grown.extend_from_slice(buffer);
    *buffer = grown;
}

/// `bytes` written at the end of `out`, grown by [`reserve`].
fn put(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    reserve(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Where the line section that started at `bytes[0]` ends, past its blank line, read on from `from` (where an earlier
/// call stopped): `None` while it has not ended. A bare CR or LF is refused at once.
fn section_end(bytes: &[u8], from: usize) -> Result<Option<usize>, Why> {
    for i in from.saturating_sub(3)..bytes.len() {
        match bytes[i] {
            b'\n' if i == 0 || bytes[i - 1] != b'\r' => return Err(Why::Line),
            b'\n' if i >= 3 && &bytes[i - 3..i] == b"\r\n\r" => return Ok(Some(i + 1)),
            b'\r' if bytes.get(i + 1).is_some_and(|&b| b != b'\n') => return Err(Why::Line),
            _ => {}
        }
    }
    Ok(None)
}

/// Where a request's head that starts `bytes` ends, past its blank line, read on from `from`: `None` while it has
/// not; refused at once where the start cannot be a request line (1 to 20 upper-case letters and a space, the gate's
/// own test) or a bare CR or LF came.
///
/// # Errors
/// [`Why::NotHttp`] or [`Why::Line`].
pub fn head_end(bytes: &[u8], from: usize) -> Result<Option<usize>, Why> {
    let start = &bytes[..bytes.len().min(21)];
    match start.iter().position(|b| !b.is_ascii_uppercase()) {
        Some(space) if space > 0 && start[space] == b' ' => {}
        None if start.len() < 21 => {}
        _ => return Err(Why::NotHttp),
    }
    section_end(bytes, from)
}

/// Whether `b` is a `tchar` (RFC 9110, 5.6.2).
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// `bytes` without the optional white space at either end.
fn trimmed(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// A request's framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    None,
    Length(u64),
    Chunked,
}

/// The facts of a field section that matter here.
#[derive(Default)]
struct Fields<'a> {
    hosts: usize,
    host: &'a [u8],
    lengths: usize,
    length: u64,
    codings: usize,
}

/// The field names the reader acts on, compared without case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Name {
    Host,
    Length,
    Coding,
    Connection,
    Upgrade,
    ProxyAuthorization,
}

/// Each of [`Name`] in lower case: the three that frame or route first.
const NAMES: [(&[u8], Name); 6] = [
    (b"host", Name::Host),
    (b"content-length", Name::Length),
    (b"transfer-encoding", Name::Coding),
    (b"connection", Name::Connection),
    (b"upgrade", Name::Upgrade),
    (b"proxy-authorization", Name::ProxyAuthorization),
];

/// Whether `bytes` is `lower`, an ASCII lower-case word, in any case: as `eq_ignore_ascii_case`, written here so that
/// the tracker gate's copy of that, in the relay's task, keeps its one caller (the forwarder's size pass).
fn lower_eq(bytes: &[u8], lower: &[u8]) -> bool {
    bytes.len() == lower.len()
        && bytes
            .iter()
            .zip(lower)
            .all(|(b, l)| b.to_ascii_lowercase() == *l)
}

/// Which of [`NAMES`] `name` is, if any.
fn known(name: &[u8]) -> Option<Name> {
    NAMES
        .iter()
        .find(|(lower, _)| lower_eq(name, lower))
        .map(|&(_, known)| known)
}

/// Reads the field lines of `section` (each ending in CRLF, the blank line left out) into `fields`; `trailers` refuses
/// every field that frames, routes or changes the meaning, which has no place in a trailer.
fn fields<'a>(section: &'a [u8], fields: &mut Fields<'a>, trailers: bool) -> Result<(), Why> {
    for line in section.split(|&b| b == b'\n') {
        let Some(line) = line.strip_suffix(b"\r") else {
            continue;
        };
        let colon = line.iter().position(|&b| b == b':').ok_or(Why::Field)?;
        let (name, value) = (&line[..colon], trimmed(&line[colon + 1..]));
        if name.is_empty() || !name.iter().all(|&b| tchar(b)) {
            return Err(Why::Field);
        }
        if !value
            .iter()
            .all(|&b| b == b'\t' || b == b' ' || (0x21..=0x7e).contains(&b) || b >= 0x80)
        {
            return Err(Why::Field);
        }
        let name = known(name);
        let framing = matches!(name, Some(Name::Host | Name::Length | Name::Coding));
        if matches!(name, Some(Name::Upgrade | Name::ProxyAuthorization)) || (trailers && framing) {
            return Err(Why::Meaning);
        }
        match name {
            Some(Name::Connection) => {
                for option in value.split(|&b| b == b',') {
                    if matches!(
                        known(trimmed(option)),
                        Some(Name::Host | Name::Length | Name::Coding)
                    ) {
                        return Err(Why::Meaning);
                    }
                }
            }
            Some(Name::Host) => {
                fields.hosts += 1;
                fields.host = value;
            }
            Some(Name::Length) => {
                fields.lengths += 1;
                if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
                    return Err(Why::Framing);
                }
                fields.length = value.iter().fold(0, |n, &d| n * 10 + u64::from(d - b'0'));
            }
            Some(Name::Coding) => {
                fields.codings += 1;
                if !lower_eq(value, b"chunked") {
                    return Err(Why::Framing);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A head read: where its target is, its `Host` value, its version's minor digit and its framing.
struct Head<'a> {
    method: &'a [u8],
    target: &'a [u8],
    /// Where the request line goes on past the target: its space before the version.
    after_target: usize,
    host: Option<&'a [u8]>,
    body: Body,
}

/// Reads `head`, a whole head with its blank line and no bare CR or LF ([`head_end`]).
fn read(head: &[u8]) -> Result<Head<'_>, Why> {
    let line_end = head.iter().position(|&b| b == b'\r').ok_or(Why::Line)?;
    let line = &head[..line_end];
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Why::Line);
    };
    if method.is_empty() || method.len() > 20 || !method.iter().all(u8::is_ascii_uppercase) {
        return Err(Why::NotHttp);
    }
    let minor = match version {
        b"HTTP/1.1" => 1,
        b"HTTP/1.0" => 0,
        _ => return Err(Why::Version),
    };
    let origin = target.first() == Some(&b'/');
    let star = target == b"*" && method == b"OPTIONS";
    if method == b"CONNECT"
        || !(origin || star)
        || !target
            .iter()
            .all(|&b| (0x21..=0x7e).contains(&b) && !matches!(b, b'#' | b'@' | b'\\'))
    {
        return Err(Why::Target);
    }
    let mut found = Fields::default();
    fields(&head[line_end + 2..head.len() - 2], &mut found, false)?;
    let body = match (found.lengths, found.codings) {
        (0, 0) => Body::None,
        (1, 0) => Body::Length(found.length),
        (0, 1) if minor == 1 => Body::Chunked,
        _ => return Err(Why::Framing),
    };
    if (method == b"GET" || method == b"HEAD") && !matches!(body, Body::None | Body::Length(0)) {
        return Err(Why::Framing);
    }
    let host = match found.hosts {
        0 if minor == 0 => None,
        1 if !found.host.is_empty() => Some(found.host),
        _ => return Err(Why::Host),
    };
    Ok(Head {
        method,
        target,
        after_target: method.len() + 1 + target.len(),
        host,
        body,
    })
}

/// What a `Host` value names, once its port is the flow's: a name, in the form names compare (lower case, no trailing
/// dot), or `None` for a literal of the flow's own address; and the host the gate's reader must find for it.
fn authority(host: &[u8], destination: SocketAddr) -> Result<(Option<String>, String), Why> {
    let (name, port) = if let Some(rest) = host.strip_prefix(b"[") {
        let close = rest.iter().position(|&b| b == b']').ok_or(Why::Host)?;
        (&rest[..close], &rest[close + 1..])
    } else {
        match host.iter().rposition(|&b| b == b':') {
            Some(colon) => (&host[..colon], &host[colon..]),
            None => (host, &b""[..]),
        }
    };
    let port = match port {
        b"" => 80,
        [b':', digits @ ..]
            if (1..=5).contains(&digits.len())
                && digits[0] != b'0'
                && digits.iter().all(u8::is_ascii_digit) =>
        {
            digits
                .iter()
                .fold(0u32, |n, &d| n * 10 + u32::from(d - b'0'))
        }
        _ => return Err(Why::Port),
    };
    if port != u32::from(destination.port()) {
        return Err(Why::Port);
    }
    let text = std::str::from_utf8(name).map_err(|_| Why::Host)?;
    let own = destination.ip().to_canonical();
    if host.first() == Some(&b'[') {
        let address: Ipv6Addr = text.parse().map_err(|_| Why::Host)?;
        return if IpAddr::V6(address).to_canonical() == own {
            Ok((None, text.to_ascii_lowercase()))
        } else {
            Err(Why::Address)
        };
    }
    let bare = text.strip_suffix('.').unwrap_or(text);
    let last = bare.rsplit('.').next().unwrap_or(bare);
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") || last.starts_with("0X")
    {
        // A name that ends in a number is an address to a URL's reader (WHATWG's "ends in a number"): only the
        // canonical dotted quad of the flow's own address is taken.
        let address: Ipv4Addr = text.parse().map_err(|_| Why::Host)?;
        return if IpAddr::V4(address) == own {
            Ok((None, text.to_owned()))
        } else {
            Err(Why::Address)
        };
    }
    let fine = !bare.is_empty()
        && bare.len() <= 253
        && bare.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !fine {
        return Err(Why::Host);
    }
    let name = bare.to_ascii_lowercase();
    Ok((Some(name.clone()), name))
}

/// The request line of `head`, read as `read` gave it, rewritten into `out` with `authority`: the method, a space,
/// `http://`, the authority, the target (none for `*`), then every byte after the target as it came.
fn rewrite(head: &[u8], read: &Head<'_>, authority: &[u8], out: &mut Zeroizing<Vec<u8>>) {
    reserve(out, head.len() + authority.len() + 8);
    out.extend_from_slice(read.method);
    out.extend_from_slice(b" http://");
    out.extend_from_slice(authority);
    if read.target != b"*" {
        out.extend_from_slice(read.target);
    }
    out.extend_from_slice(&head[read.after_target..]);
}

/// Where the framer is in the requests after the first head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// A head, held in `held` until it ends.
    Head,
    /// So many bytes of a body by its length.
    Length(u64),
    /// A chunk's size line, held in `held`.
    Size,
    /// So many bytes of a chunk's data.
    Data(u64),
    /// The CRLF after a chunk's data: how many of its bytes came.
    DataEnd(u8),
    /// The trailers after the last chunk, held in `held` behind a CRLF of their own.
    Trailers,
}

/// A forwarded connection's up direction after its first head: each later head checked and rewritten, each body framed
/// and copied unread.
pub struct Forward {
    authority: Box<[u8]>,
    host: Option<Box<[u8]>>,
    state: State,
    held: Zeroizing<Vec<u8>>,
}

/// A first head that may be forwarded: the framer for the rest of the connection, and the name the engine must still
/// find bound to the flow's address (`None` for a literal or no `Host`).
pub struct First {
    /// The framer for what follows the first head.
    pub forward: Forward,
    /// The `Host`'s name, in the form names compare, for the engine's binding; `None` for a literal or no `Host`.
    pub name: Option<String>,
}

/// The state after a head of framing `body`.
fn after(body: Body) -> State {
    match body {
        Body::None | Body::Length(0) => State::Head,
        Body::Length(n) => State::Length(n),
        Body::Chunked => State::Size,
    }
}

/// The first head of a flow to `destination`, `head` whole with its blank line: checked, and rewritten into `out`.
///
/// # Errors
/// Why the head may not be forwarded.
pub fn first(
    head: &[u8],
    destination: SocketAddr,
    out: &mut Zeroizing<Vec<u8>>,
) -> Result<First, Why> {
    if head.len() > MAX_HEAD {
        return Err(Why::TooLong);
    }
    if head_end(head, 0)? != Some(head.len()) {
        return Err(Why::Line);
    }
    let read = read(head)?;
    let (authority, name) = if let Some(host) = read.host {
        let (name, gate) = authority(host, destination)?;
        // The gate decides by what its own reader finds within its 8 KiB: the same host, or nothing goes (m2). Matched,
        // not compared: `HttpHost`'s `==` in the library moves the gate's machine code in the relay's task (measured).
        if !matches!(http_host_again(head), HttpHost::Found(found) if found == gate) {
            return Err(Why::Host);
        }
        (Box::<[u8]>::from(host), name)
    } else {
        let mut written = match destination.ip().to_canonical() {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => format!("[{a}]"),
        };
        if destination.port() != 80 {
            written.push(':');
            written.push_str(&destination.port().to_string());
        }
        (Box::<[u8]>::from(written.as_bytes()), None)
    };
    rewrite(head, &read, &authority, out);
    Ok(First {
        forward: Forward {
            host: read.host.map(Box::from),
            authority,
            state: after(read.body),
            held: Zeroizing::new(Vec::new()),
        },
        name,
    })
}

impl Forward {
    /// The app's next bytes `input`, framed: what goes to the proxy written into `out`, a head only once whole and
    /// checked, a body's bytes as they come.
    ///
    /// # Errors
    /// Why the connection must be reset: what was written into `out` before goes on first.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Zeroizing<Vec<u8>>) -> Result<(), Why> {
        while !input.is_empty() {
            match self.state {
                State::Head | State::Trailers => {
                    // The trailers are held behind a CRLF of their own, which counts for nothing.
                    let bound = MAX_HEAD + if self.state == State::Head { 0 } else { 2 };
                    let before = self.held.len();
                    let room = (bound + 1).saturating_sub(before).min(input.len());
                    put(&mut self.held, &input[..room]);
                    let ended = if self.state == State::Head {
                        head_end(&self.held, before)?
                    } else {
                        section_end(&self.held, before)?
                    };
                    match ended {
                        Some(end) if end <= bound => {}
                        None if self.held.len() <= bound => return Ok(()),
                        _ => return Err(Why::TooLong),
                    }
                    let end = ended.unwrap_or_default();
                    input = &input[end - before..];
                    if self.state == State::Head {
                        self.head(end, out)?;
                    } else {
                        // The CRLF put before the trailers is the last chunk line's, written already.
                        let section = &self.held[2..end];
                        if section.len() > 2 {
                            fields(&section[..section.len() - 2], &mut Fields::default(), true)?;
                        }
                        put(out, section);
                        self.state = State::Head;
                    }
                    self.held.clear();
                }
                State::Length(left) | State::Data(left) => {
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(input.len());
                    put(out, &input[..n]);
                    input = &input[n..];
                    let left = left - n as u64;
                    self.state = match self.state {
                        State::Length(_) if left == 0 => State::Head,
                        State::Length(_) => State::Length(left),
                        _ if left == 0 => State::DataEnd(0),
                        _ => State::Data(left),
                    };
                }
                State::DataEnd(seen) => {
                    let wanted = if seen == 0 { b'\r' } else { b'\n' };
                    if input[0] != wanted {
                        return Err(Why::Chunk);
                    }
                    put(out, &input[..1]);
                    input = &input[1..];
                    self.state = if seen == 0 {
                        State::DataEnd(1)
                    } else {
                        State::Size
                    };
                }
                State::Size => {
                    let b = input[0];
                    input = &input[1..];
                    let (last, len) = (self.held.last().copied(), self.held.len());
                    match (last, b) {
                        (Some(b'\r'), b'\n') => {
                            put(out, &self.held);
                            put(out, b"\n");
                            let digits = &self.held[..self.held.len() - 1];
                            let size = digits.iter().fold(0u64, |n, &d| {
                                n * 16 + u64::from((d as char).to_digit(16).unwrap_or(0))
                            });
                            self.held.clear();
                            self.state = if size == 0 {
                                put(&mut self.held, b"\r\n");
                                State::Trailers
                            } else {
                                State::Data(size)
                            };
                        }
                        (Some(b'\r'), _) => return Err(Why::Chunk),
                        (_, b'\r') if len > 0 => put(&mut self.held, b"\r"),
                        (_, d) if d.is_ascii_hexdigit() && len < 16 => put(&mut self.held, &[d]),
                        _ => return Err(Why::Chunk),
                    }
                }
            }
        }
        Ok(())
    }

    /// The held head, `held[..end]`, of a later request: checked, its `Host` the first one's, and rewritten.
    fn head(&mut self, end: usize, out: &mut Zeroizing<Vec<u8>>) -> Result<(), Why> {
        let head = &self.held[..end];
        let read = read(head)?;
        if read.host != self.host.as_deref() {
            return Err(Why::OtherHost);
        }
        rewrite(head, &read, &self.authority, out);
        self.state = after(read.body);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
