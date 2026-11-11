//! A SOCKS5 client (RFC 1928, with RFC 1929's username and password) for W6: Watch carries the
//! traffic of the apps the user chains through the local proxy of the user's circumvention tool
//! (docs/VPN.md, "Coexistence with other VPNs"). It sends only `CONNECT` and `UDP ASSOCIATE`; `BIND`,
//! which would let the tool's network open a connection to the phone, has no command here.
//!
//! The encoders and parsers hold no state and do no IO, so that the parsers can be fuzzed with any
//! bytes a local proxy can send; [`handshake`] runs them over a stream. A password never appears in
//! a `Debug` output.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 5;
/// The version of RFC 1929's sub-negotiation.
const PASSWORD_VERSION: u8 = 1;
const NO_AUTHENTICATION: u8 = 0;
const PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;
const UDP_ASSOCIATE: u8 = 3;
const IPV4: u8 = 1;
const NAME: u8 = 3;
const IPV6: u8 = 4;
/// The longest name a request can carry: its length is one byte.
const MAX_NAME: usize = 255;
/// The longest reply: a header, a name of [`MAX_NAME`] bytes after its length, and a port.
const MAX_REPLY: usize = 4 + 1 + MAX_NAME + 2;

/// Where a request or a datagram goes, or where the proxy bound: an address, or a name the proxy
/// resolves itself, so that the name never reaches the network beneath the tool.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// An IPv4 or IPv6 address and a port.
    Address(SocketAddr),
    /// A host name and a port.
    Name(String, u16),
}

impl Target {
    /// A name target, if the proxy can be sent `name`: 1 to 255 bytes of ASCII letters, digits, `-`,
    /// `_` and `.`, as host names are.
    #[must_use]
    pub fn name(name: &str, port: u16) -> Option<Self> {
        valid_name(name.as_bytes()).then(|| Self::Name(name.to_owned(), port))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Address(SocketAddr::V4(address)) => {
                out.push(IPV4);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
            Self::Address(SocketAddr::V6(address)) => {
                out.push(IPV6);
                out.extend_from_slice(&address.ip().octets());
                out.extend_from_slice(&address.port().to_be_bytes());
            }
            Self::Name(name, port) => {
                out.push(NAME);
                // A name is at most 255 bytes: Target::name and decode check it.
                out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Reads a target (`ATYP`, address, port) from the start of `bytes`: the target and its length in
    /// bytes, or `None` when it is cut short, of an unknown type, or a name that is not one.
    fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let (address, at) = match *bytes.first()? {
            IPV4 => {
                let octets: [u8; 4] = bytes.get(1..5)?.try_into().ok()?;
                (Address::Ip(IpAddr::V4(Ipv4Addr::from(octets))), 5)
            }
            IPV6 => {
                let octets: [u8; 16] = bytes.get(1..17)?.try_into().ok()?;
                (Address::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 17)
            }
            NAME => {
                let length = usize::from(*bytes.get(1)?);
                let name = bytes.get(2..2 + length)?;
                if !valid_name(name) {
                    return None;
                }
                (
                    Address::Name(String::from_utf8_lossy(name).into_owned()),
                    2 + length,
                )
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
        let target = match address {
            Address::Ip(ip) => Self::Address(SocketAddr::new(ip, port)),
            Address::Name(name) => Self::Name(name, port),
        };
        Some((target, at + 2))
    }
}

enum Address {
    Ip(IpAddr),
    Name(String),
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// What Watch asks the proxy to do. `BIND` has no variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// A TCP connection to the target.
    Connect,
    /// A UDP relay, for as long as the request's TCP connection stays open.
    UdpAssociate,
}

/// A username and a password for the proxy (RFC 1929), each 1 to 255 bytes. Neither is ever shown by
/// `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: Vec<u8>,
    password: Vec<u8>,
}

impl Credentials {
    /// Credentials, if each part is 1 to 255 bytes.
    #[must_use]
    pub fn new(user: &[u8], password: &[u8]) -> Option<Self> {
        let fits = |part: &[u8]| (1..=255).contains(&part.len());
        (fits(user) && fits(password)).then(|| Self {
            user: user.to_vec(),
            password: password.to_vec(),
        })
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(..)")
    }
}

/// Why a request through the proxy failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The other end is not a SOCKS5 proxy, or broke the protocol.
    Protocol,
    /// The proxy accepts none of the methods offered: it wants a password Watch was not given.
    NoAcceptableMethod,
    /// The proxy refused the username and password.
    PasswordRefused,
    /// The proxy answered the request with this reply code (RFC 1928, section 6).
    Reply(u8),
    /// The connection to the proxy failed, closed or timed out.
    Io(io::ErrorKind),
}

impl Error {
    /// The target refused the connection (`REP` 5): the app gets a reset, as without the proxy.
    #[must_use]
    pub fn is_refused(self) -> bool {
        self == Self::Reply(5)
    }

    /// The target could not be reached (network or host unreachable, TTL expired): the app gets an
    /// ICMP error, as without the proxy.
    #[must_use]
    pub fn is_unreachable(self) -> bool {
        matches!(self, Self::Reply(3 | 4 | 6))
    }

    /// The proxy does not carry this command (`REP` 7): for `UDP ASSOCIATE`, a tool without UDP.
    #[must_use]
    pub fn is_unsupported(self) -> bool {
        self == Self::Reply(7)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => f.write_str("not a SOCKS5 proxy, or it broke the protocol"),
            Self::NoAcceptableMethod => {
                f.write_str("the proxy accepts none of the methods offered")
            }
            Self::PasswordRefused => f.write_str("the proxy refused the username and password"),
            Self::Reply(code) => write!(f, "the proxy answered with reply code {code}"),
            Self::Io(kind) => write!(f, "the connection to the proxy failed: {kind}"),
        }
    }
}

impl std::error::Error for Error {}

/// The greeting: no authentication, and the password method too when Watch has credentials, so that
/// the proxy chooses; a tool that cannot take a password still answers.
#[must_use]
pub fn greeting(credentials: Option<&Credentials>) -> Vec<u8> {
    match credentials {
        Some(_) => vec![VERSION, 2, NO_AUTHENTICATION, PASSWORD],
        None => vec![VERSION, 1, NO_AUTHENTICATION],
    }
}

/// The method the proxy chose: `true` for the password, `false` for none. A method Watch did not
/// offer is a protocol error.
///
/// # Errors
/// [`Error::NoAcceptableMethod`] when the proxy accepts none, [`Error::Protocol`] otherwise.
pub fn chosen_method(reply: [u8; 2], offered_password: bool) -> Result<bool, Error> {
    match reply {
        [VERSION, NO_AUTHENTICATION] => Ok(false),
        [VERSION, PASSWORD] if offered_password => Ok(true),
        [VERSION, NO_ACCEPTABLE_METHOD] => Err(Error::NoAcceptableMethod),
        _ => Err(Error::Protocol),
    }
}

/// RFC 1929's request: the username and the password.
#[must_use]
pub fn password_request(credentials: &Credentials) -> Vec<u8> {
    let mut out = vec![PASSWORD_VERSION];
    for part in [&credentials.user, &credentials.password] {
        out.push(u8::try_from(part.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(part);
    }
    out
}

/// RFC 1929's answer.
///
/// # Errors
/// [`Error::PasswordRefused`] for any status but 0; [`Error::Protocol`] for another version. Some
/// proxies answer with version 5, which is accepted.
pub fn password_status(reply: [u8; 2]) -> Result<(), Error> {
    match reply {
        [PASSWORD_VERSION | VERSION, 0] => Ok(()),
        [PASSWORD_VERSION | VERSION, _] => Err(Error::PasswordRefused),
        _ => Err(Error::Protocol),
    }
}

/// A request for `command` to `target`.
#[must_use]
pub fn request(command: Command, target: &Target) -> Vec<u8> {
    let code = match command {
        Command::Connect => CONNECT,
        Command::UdpAssociate => UDP_ASSOCIATE,
    };
    let mut out = vec![VERSION, code, 0];
    target.encode(&mut out);
    out
}

/// The length of a reply whose first five bytes are `head`: four bytes of header, the address with
/// its type's length, and the port.
///
/// # Errors
/// [`Error::Protocol`] for another version or an unknown address type.
pub fn reply_length(head: [u8; 5]) -> Result<usize, Error> {
    if head[0] != VERSION {
        return Err(Error::Protocol);
    }
    match head[3] {
        IPV4 => Ok(4 + 4 + 2),
        IPV6 => Ok(4 + 16 + 2),
        NAME => Ok(4 + 1 + usize::from(head[4]) + 2),
        _ => Err(Error::Protocol),
    }
}

/// A whole reply: the address the proxy bound, which for `UDP ASSOCIATE` is where datagrams go.
///
/// # Errors
/// [`Error::Reply`] for a failure the proxy reports, [`Error::Protocol`] for a malformed reply.
pub fn reply(bytes: &[u8]) -> Result<Target, Error> {
    let head: [u8; 4] = bytes
        .get(..4)
        .and_then(|h| h.try_into().ok())
        .ok_or(Error::Protocol)?;
    if head[0] != VERSION {
        return Err(Error::Protocol);
    }
    if head[1] != 0 {
        return Err(Error::Reply(head[1]));
    }
    match Target::decode(&bytes[3..]) {
        Some((bound, length)) if 3 + length == bytes.len() => Ok(bound),
        _ => Err(Error::Protocol),
    }
}

/// Where to send datagrams for a `UDP ASSOCIATE` whose reply named `bound`: that address, or the
/// proxy's own address with its port when the proxy answered with an unspecified one, as many do.
/// `None` when the proxy named a host instead of an address.
#[must_use]
pub fn relay_address(bound: &Target, proxy: SocketAddr) -> Option<SocketAddr> {
    match bound {
        Target::Address(address) if address.ip().is_unspecified() => {
            Some(SocketAddr::new(proxy.ip(), address.port()))
        }
        Target::Address(address) => Some(*address),
        Target::Name(..) => None,
    }
}

/// A datagram for the relay: a header naming `target`, then `payload`. Never fragmented.
#[must_use]
pub fn datagram(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    target.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

/// A datagram from the relay: the target it came from and its payload. `None` for a fragment, which
/// Watch drops as RFC 1928 allows, or for a malformed header.
#[must_use]
pub fn parse_datagram(bytes: &[u8]) -> Option<(Target, &[u8])> {
    if *bytes.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (target, length) = Target::decode(&bytes[3..])?;
    Some((target, &bytes[3 + length..]))
}

/// Asks the proxy at the other end of `stream` to carry `command` to `target`: the greeting, the
/// password when the proxy asks for it, then the request. Returns the address the proxy bound. For
/// `CONNECT`, `stream` then carries the connection; for `UDP ASSOCIATE`, it must stay open for as long
/// as the relay is used.
///
/// # Errors
/// See [`Error`]; the caller times the whole handshake out.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credentials: Option<&Credentials>,
    command: Command,
    target: &Target,
) -> Result<Target, Error> {
    stream.write_all(&greeting(credentials)).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    if chosen_method(method, credentials.is_some())? {
        let credentials = credentials.ok_or(Error::Protocol)?;
        stream.write_all(&password_request(credentials)).await?;
        let mut status = [0; 2];
        stream.read_exact(&mut status).await?;
        password_status(status)?;
    }
    stream.write_all(&request(command, target)).await?;
    let mut answer = [0; MAX_REPLY];
    stream.read_exact(&mut answer[..5]).await?;
    // A failure may come with a short or zero address; its code is what counts.
    if answer[0] == VERSION && answer[1] != 0 {
        return Err(Error::Reply(answer[1]));
    }
    let length = reply_length([answer[0], answer[1], answer[2], answer[3], answer[4]])?;
    stream.read_exact(&mut answer[5..length]).await?;
    reply(&answer[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4], port: u16) -> Target {
        Target::Address(SocketAddr::from((a, port)))
    }

    #[test]
    fn encodes_requests_of_each_address_type() {
        assert_eq!(
            request(Command::Connect, &v4([93, 184, 216, 34], 443)),
            [5, 1, 0, 1, 93, 184, 216, 34, 1, 187]
        );
        let v6 = Target::Address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53));
        let mut expected = vec![5, 3, 0, 4];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&[0, 53]);
        assert_eq!(request(Command::UdpAssociate, &v6), expected);
        let Some(name) = Target::name("example.com", 80) else {
            unreachable!("a valid name")
        };
        let mut expected = vec![5, 1, 0, 3, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[0, 80]);
        assert_eq!(request(Command::Connect, &name), expected);
    }

    #[test]
    fn refuses_names_a_request_cannot_carry() {
        assert_eq!(Target::name("", 80), None);
        assert_eq!(Target::name("a b", 80), None);
        assert_eq!(Target::name("ex\u{e4}mple.com", 80), None);
        assert_eq!(Target::name(&"a".repeat(256), 80), None);
        assert!(Target::name(&"a".repeat(255), 80).is_some());
    }

    #[test]
    fn greets_with_the_password_method_only_when_it_has_credentials() {
        let Some(credentials) = Credentials::new(b"watch", b"secret") else {
            unreachable!("valid credentials")
        };
        assert_eq!(greeting(None), [5, 1, 0]);
        assert_eq!(greeting(Some(&credentials)), [5, 2, 0, 2]);
        assert_eq!(chosen_method([5, 0], true), Ok(false));
        assert_eq!(chosen_method([5, 2], true), Ok(true));
        assert_eq!(chosen_method([5, 2], false), Err(Error::Protocol));
        assert_eq!(
            chosen_method([5, 0xff], false),
            Err(Error::NoAcceptableMethod)
        );
        assert_eq!(chosen_method([4, 0], false), Err(Error::Protocol));
        assert_eq!(
            password_request(&credentials),
            [
                1, 5, b'w', b'a', b't', b'c', b'h', 6, b's', b'e', b'c', b'r', b'e', b't'
            ]
        );
        assert_eq!(password_status([1, 0]), Ok(()));
        assert_eq!(password_status([5, 0]), Ok(()));
        assert_eq!(password_status([1, 1]), Err(Error::PasswordRefused));
        assert_eq!(password_status([2, 0]), Err(Error::Protocol));
        assert_eq!(format!("{credentials:?}"), "Credentials(..)");
        assert_eq!(Credentials::new(b"", b"x"), None);
        assert_eq!(Credentials::new(b"x", &[0; 256]), None);
    }

    #[test]
    fn reads_replies_and_their_failures() {
        let ok = [5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90];
        assert_eq!(reply_length([5, 0, 0, 1, 127]), Ok(10));
        assert_eq!(reply(&ok), Ok(v4([127, 0, 0, 1], 8080)));
        assert_eq!(reply(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]), Err(Error::Reply(5)));
        assert!(Error::Reply(5).is_refused());
        assert!(Error::Reply(4).is_unreachable() && Error::Reply(3).is_unreachable());
        assert!(Error::Reply(7).is_unsupported());
        assert!(!Error::Reply(1).is_refused() && !Error::Reply(1).is_unreachable());
        assert_eq!(reply(&ok[..9]), Err(Error::Protocol));
        let mut long = ok.to_vec();
        long.push(0);
        assert_eq!(reply(&long), Err(Error::Protocol));
        assert_eq!(reply_length([5, 0, 0, 9, 0]), Err(Error::Protocol));
        assert_eq!(reply_length([5, 0, 0, 3, 7]), Ok(4 + 1 + 7 + 2));
        assert_eq!(reply_length([4, 0, 0, 1, 0]), Err(Error::Protocol));
    }

    #[test]
    fn sends_datagrams_to_the_proxy_or_its_bound_address() {
        let proxy = SocketAddr::from(([127, 0, 0, 1], 10808));
        assert_eq!(
            relay_address(&v4([0, 0, 0, 0], 40000), proxy),
            Some(SocketAddr::from(([127, 0, 0, 1], 40000)))
        );
        assert_eq!(
            relay_address(&v4([127, 0, 0, 2], 40000), proxy),
            Some(SocketAddr::from(([127, 0, 0, 2], 40000)))
        );
        assert_eq!(relay_address(&Target::Name("relay".into(), 1), proxy), None);
    }

    #[test]
    fn wraps_and_unwraps_datagrams_and_drops_fragments() {
        let Some(target) = Target::name("dns.example", 53) else {
            unreachable!("a valid name")
        };
        let wrapped = datagram(&target, b"query");
        assert_eq!(parse_datagram(&wrapped), Some((target, &b"query"[..])));
        let from = v4([192, 0, 2, 1], 443);
        let wrapped = datagram(&from, b"");
        assert_eq!(parse_datagram(&wrapped), Some((from, &b""[..])));
        let mut fragment = wrapped.clone();
        fragment[2] = 1;
        assert_eq!(parse_datagram(&fragment), None);
        for cut in 0..wrapped.len() {
            assert_eq!(parse_datagram(&wrapped[..cut]), None, "cut at {cut}");
        }
    }
}
