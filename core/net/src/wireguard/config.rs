//! A `WireGuard` configuration in `wg-quick`'s format, as providers hand it out (ADR 0035, question 9 as
//! settled on 2026-11-19): one `[Interface]` with `PrivateKey`, `Address` (IPv4, IPv6 or both), `DNS`,
//! which W7 requires, and `MTU`; one `[Peer]` with `PublicKey`, `PresharedKey`, `Endpoint` (an address or
//! a host name, with its port), `AllowedIPs` and `PersistentKeepalive`. Anything else is refused with a
//! [`Refusal`] the screens can show: several peers, `PostUp`, `Table`, `SaveConfig`, a key it does not
//! know, a value it cannot read.
//!
//! The parser holds no state and does no IO, so that it can be fuzzed with any bytes (`core/fuzz`). The
//! keys are [`Secret`]s: zeroed when dropped, never in a `Debug` output, a refusal, a log line or the
//! dump. A refusal names a line and a key, never a value.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::Zeroize;

/// The longest configuration read: providers' files are a few hundred bytes.
pub const MAX_TEXT: usize = 16 * 1024;
/// At most this many networks in `AllowedIPs`: a provider's "everything" is one or two, and a file that
/// leaves out private ranges by hand a few dozen.
pub const MAX_ALLOWED: usize = 256;
/// At most this many DNS servers.
pub const MAX_DNS: usize = 8;
/// The smallest and largest MTU accepted: IPv4's least (RFC 791) and the tunnel's own, which Watch never
/// sets above 1,500 bytes (ADR 0044, decision 5 as amended). With an IPv6 address, at least 1,280 (RFC
/// 8200 5).
pub const MTU_RANGE: std::ops::RangeInclusive<u16> = 576..=1_500;
/// The MTU inside the tunnel when the configuration gives none: 1,280, as `WireGuard`'s own app uses
/// (ADR 0035, "MTU"), which every IPv6 path carries.
pub const DEFAULT_MTU: u16 = 1_280;

/// A key that must stay secret: the private key or the preshared key. Zeroed when dropped; its `Debug`
/// shows no byte of it, and two are compared in constant time.
#[derive(Clone)]
pub struct Secret([u8; 32]);

impl PartialEq for Secret {
    /// Every byte looked at, whatever differs first (the engine's review, nit 16).
    fn eq(&self, other: &Self) -> bool {
        let differ = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |differ, (a, b)| differ | (a ^ b));
        std::hint::black_box(differ) == 0
    }
}

impl Eq for Secret {}

impl Secret {
    /// The key's bytes, for the protocol core alone.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A secret of these bytes, for tests and the protocol core's own types.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Secret {
    /// Writes nought over the key, as dropping it does.
    fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// An IP network, as `Address` and `AllowedIPs` give it: an address and the length of its prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Network {
    /// The network's address, with the bits past the prefix cleared (`AllowedIPs`), or the interface's
    /// own address (`Address`).
    pub address: IpAddr,
    /// The prefix's length: at most 32 for IPv4, 128 for IPv6.
    pub prefix: u8,
}

impl Network {
    /// Whether `address` is inside the network.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_bits_equal(
                u128::from(net.to_bits()),
                u128::from(ip.to_bits()),
                32,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_bits_equal(net.to_bits(), ip.to_bits(), 128, self.prefix)
            }
            _ => false,
        }
    }

    /// The network with the bits past its prefix cleared.
    #[must_use]
    pub fn masked(self) -> Self {
        let address = match self.address {
            IpAddr::V4(a) => {
                let kept = mask(32, self.prefix);
                IpAddr::V4(Ipv4Addr::from_bits(
                    u32::try_from(u128::from(a.to_bits()) & kept).unwrap_or(0),
                ))
            }
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from_bits(a.to_bits() & mask(128, self.prefix))),
        };
        Self { address, ..self }
    }
}

/// The bits a prefix of `prefix` keeps of an address of `width` bits.
fn mask(width: u32, prefix: u8) -> u128 {
    let prefix = u32::from(prefix).min(width);
    if prefix == 0 {
        return 0;
    }
    let all = if width == 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    // A whole prefix keeps every bit; shifting by the width would overflow (found by fuzzing).
    if prefix == width {
        return all;
    }
    all & !(all >> prefix)
}

fn prefix_bits_equal(a: u128, b: u128, width: u32, prefix: u8) -> bool {
    (a ^ b) & mask(width, prefix) == 0
}

/// Where the peer is: an address, or a host name resolved before the tunnel (ADR 0035, question 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// An IPv4 or IPv6 address and its port.
    Address(SocketAddr),
    /// A host name, lower case and without a trailing dot, and the port.
    Name(String, u16),
}

/// The interface's own addresses: at most one of each version, which a chosen app's packets take as
/// their source (ADR 0035, option 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Addresses {
    /// The IPv4 address, with its prefix.
    pub v4: Option<(Ipv4Addr, u8)>,
    /// The IPv6 address, with its prefix.
    pub v6: Option<(Ipv6Addr, u8)>,
}

impl Addresses {
    /// The address of `address`'s version, if the configuration has one.
    #[must_use]
    pub fn like(&self, address: IpAddr) -> Option<IpAddr> {
        match address {
            IpAddr::V4(_) => self.v4.map(|(a, _)| IpAddr::V4(a)),
            IpAddr::V6(_) => self.v6.map(|(a, _)| IpAddr::V6(a)),
        }
    }

    /// Whether `address` is inside the interface's own networks, by their prefixes.
    #[must_use]
    pub fn covers(&self, address: IpAddr) -> bool {
        let v4 = self.v4.map(|(a, prefix)| Network {
            address: IpAddr::V4(a),
            prefix,
        });
        let v6 = self.v6.map(|(a, prefix)| Network {
            address: IpAddr::V6(a),
            prefix,
        });
        v4.into_iter().chain(v6).any(|n| n.contains(address))
    }
}

/// The one peer.
#[derive(Clone, PartialEq, Eq)]
pub struct Peer {
    /// Its public key.
    pub public_key: [u8; 32],
    /// The preshared key, where the provider gives one.
    pub preshared_key: Option<Secret>,
    /// Where it is.
    pub endpoint: Endpoint,
    /// The networks it may send from, and to which the chosen apps' packets may go; the rest is refused,
    /// never sent directly (ADR 0035, question 9).
    pub allowed_ips: Vec<Network>,
    /// The seconds between keepalives, if the configuration asks for them.
    pub persistent_keepalive: Option<u16>,
}

impl fmt::Debug for Peer {
    /// No key, and no endpoint: the dump and the log name neither (ADR 0035, "logging").
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("preshared_key", &self.preshared_key.is_some())
            .field("allowed_ips", &self.allowed_ips.len())
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish_non_exhaustive()
    }
}

impl Peer {
    /// Whether `address` is inside the peer's `AllowedIPs`.
    #[must_use]
    pub fn allows(&self, address: IpAddr) -> bool {
        self.allowed_ips.iter().any(|n| n.contains(address))
    }
}

/// A configuration Watch accepts.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// The interface's private key.
    pub private_key: Secret,
    /// Its addresses.
    pub addresses: Addresses,
    /// Its DNS servers, in order, at least one of a version it has an address of.
    pub dns: Vec<IpAddr>,
    /// Its MTU, if given.
    pub mtu: Option<u16>,
    /// The peer.
    pub peer: Peer,
    /// The apps `WireGuard`'s own app exports with a configuration (`IncludedApplications`,
    /// `ExcludedApplications`): kept for the import to offer as the choice of apps, for the user to
    /// confirm (the maintainer's answer 2, 2026-11-19). Watch routes by its own choice of apps alone.
    pub applications: Applications,
}

/// The apps a configuration names for its tunnel, as `WireGuard`'s app exports them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Applications {
    /// It names none.
    #[default]
    Unnamed,
    /// Only these packages (`IncludedApplications`).
    Only(Vec<String>),
    /// Every package but these (`ExcludedApplications`).
    Except(Vec<String>),
}

impl fmt::Debug for Config {
    /// The shape alone: no key, no address, no endpoint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("v4", &self.addresses.v4.is_some())
            .field("v6", &self.addresses.v6.is_some())
            .field("dns", &self.dns.len())
            .field("mtu", &self.mtu)
            .field("peer", &self.peer)
            .field("applications", &self.applications)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// The MTU inside the tunnel: the configuration's, or [`DEFAULT_MTU`].
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_MTU)
    }

    /// The first DNS server of `address`'s version, if the configuration has an address of that version
    /// to reach it from; else the first it can reach from either.
    #[must_use]
    pub fn dns_like(&self, address: IpAddr) -> Option<IpAddr> {
        let reachable = |dns: &&IpAddr| self.reaches(**dns);
        self.dns
            .iter()
            .filter(reachable)
            .find(|dns| dns.is_ipv4() == address.is_ipv4())
            .or_else(|| self.dns.iter().find(reachable))
            .copied()
    }

    /// Whether a DNS server at `dns` can be reached through the tunnel: the configuration has an address of
    /// its version, and it is inside the peer's `AllowedIPs`, so that its answers pass the back path.
    #[must_use]
    pub fn reaches(&self, dns: IpAddr) -> bool {
        self.addresses.like(dns).is_some() && self.peer.allows(dns)
    }

    /// Reads a configuration from `text`.
    ///
    /// # Errors
    /// The [`Refusal`] that says why the configuration is not one Watch accepts.
    pub fn parse(text: &[u8]) -> Result<Self, Refusal> {
        parse(text)
    }

    /// Whether the peer's `AllowedIPs` carry every destination of each IP version the configuration has an
    /// address of: `0.0.0.0/0`, or networks that add up to it, such as `0.0.0.0/1, 128.0.0.0/1`. Where they do
    /// not, only those destinations go through the tunnel, and the chosen apps' others are refused, never sent
    /// directly (ADR 0035, question 9). A version the configuration has no address of is refused either way.
    #[must_use]
    pub fn carries_everything(&self) -> bool {
        let whole = |v6: bool| {
            let (width, top) = if v6 {
                (128, u128::MAX)
            } else {
                (32, u128::from(u32::MAX))
            };
            let mut ranges: Vec<(u128, u128)> = self
                .peer
                .allowed_ips
                .iter()
                .filter(|n| n.address.is_ipv6() == v6)
                .map(|n| {
                    let start = match n.address {
                        IpAddr::V4(a) => u128::from(a.to_bits()),
                        IpAddr::V6(a) => a.to_bits(),
                    } & mask(width, n.prefix);
                    (start, start | (!mask(width, n.prefix) & top))
                })
                .collect();
            ranges.sort_unstable();
            // The first address not covered yet.
            let mut next = 0u128;
            for (start, end) in ranges {
                if start > next {
                    return false;
                }
                if end >= top {
                    return true;
                }
                next = next.max(end + 1);
            }
            false
        };
        (self.addresses.v4.is_none() || whole(false))
            && (self.addresses.v6.is_none() || whole(true))
    }

    /// What the import shows the user before anything is saved (W7, part 2): what the configuration does,
    /// never a key. One line each, a word and its value: `endpoint HOST PORT`, `address A/P` for each address,
    /// `dns A` for each server, `allowed A/P` for each network of `AllowedIPs`, `everything 1` or `0`
    /// ([`Self::carries_everything`]), `preshared 1` or `0` (whether a `PresharedKey` is set), `mtu N` (the
    /// tunnel's, given or [`DEFAULT_MTU`]), `keepalive N` where the configuration asks for keepalives, and last
    /// `only PACKAGE` or `except PACKAGE` for each app `WireGuard`'s app named with it ([`Applications`]). The
    /// endpoint is the user's to see on the screen; Watch's dump and log never print it.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut lines = Vec::new();
        lines.push(match &self.peer.endpoint {
            Endpoint::Address(address) => format!("endpoint {} {}", address.ip(), address.port()),
            Endpoint::Name(name, port) => format!("endpoint {name} {port}"),
        });
        if let Some((address, prefix)) = self.addresses.v4 {
            lines.push(format!("address {address}/{prefix}"));
        }
        if let Some((address, prefix)) = self.addresses.v6 {
            lines.push(format!("address {address}/{prefix}"));
        }
        lines.extend(self.dns.iter().map(|dns| format!("dns {dns}")));
        lines.extend(
            self.peer
                .allowed_ips
                .iter()
                .map(|n| format!("allowed {}/{}", n.address, n.prefix)),
        );
        lines.push(format!(
            "everything {}",
            u8::from(self.carries_everything())
        ));
        lines.push(format!(
            "preshared {}",
            u8::from(self.peer.preshared_key.is_some())
        ));
        lines.push(format!("mtu {}", self.mtu()));
        if let Some(seconds) = self.peer.persistent_keepalive {
            lines.push(format!("keepalive {seconds}"));
        }
        let (word, names) = match &self.applications {
            Applications::Unnamed => ("", &[][..]),
            Applications::Only(names) => ("only", &names[..]),
            Applications::Except(names) => ("except", &names[..]),
        };
        lines.extend(names.iter().map(|name| format!("{word} {name}")));
        lines.join("\n")
    }
}

/// Why a configuration is refused. Each names what the screens can tell the user, a line where there is
/// one, and never a value: a refused line may hold a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Longer than [`MAX_TEXT`].
    TooLong,
    /// Not UTF-8 text.
    NotText,
    /// A line that is neither a section, a `key = value`, a comment nor empty.
    Unreadable {
        /// The line, counting from 1.
        line: usize,
    },
    /// A `key = value` before any section.
    OutsideSection {
        /// The line, counting from 1.
        line: usize,
    },
    /// A section other than `[Interface]` and `[Peer]`.
    UnknownSection {
        /// The line, counting from 1.
        line: usize,
    },
    /// A second `[Interface]`.
    SeveralInterfaces {
        /// The line, counting from 1.
        line: usize,
    },
    /// A second `[Peer]`: W7 takes one.
    SeveralPeers {
        /// The line, counting from 1.
        line: usize,
    },
    /// A key Watch does not carry out, named when it is a plain word: `PostUp`, `Table`, `SaveConfig`,
    /// `PreUp`, `PostDown` and the like, or one it does not know. `ListenPort` and `FwMark` are read and
    /// ignored, and `IncludedApplications` and `ExcludedApplications` kept ([`Applications`]).
    Unsupported {
        /// The line, counting from 1.
        line: usize,
        /// The key.
        key: Option<String>,
    },
    /// A key given twice where it takes one value.
    Repeated {
        /// The line, counting from 1.
        line: usize,
        /// The key.
        key: &'static str,
    },
    /// A value that cannot be read for its key.
    BadValue {
        /// The line, counting from 1.
        line: usize,
        /// The key.
        key: &'static str,
    },
    /// Two addresses of one version: Watch gives a chosen app's packets one.
    SeveralAddresses {
        /// The line, counting from 1.
        line: usize,
    },
    /// A search domain in `DNS`, which Watch cannot apply.
    SearchDomain {
        /// The line, counting from 1.
        line: usize,
    },
    /// No `[Interface]`.
    NoInterface,
    /// No `[Peer]`.
    NoPeer,
    /// No `PrivateKey`.
    NoPrivateKey,
    /// No `Address`.
    NoAddress,
    /// No `DNS`: its names would have nowhere private to go (ADR 0035, question 9; W8 routes them to the
    /// user's own encrypted resolver instead).
    NoDns,
    /// No DNS server the tunnel reaches: none of a version the configuration has an address of and inside
    /// the peer's `AllowedIPs`, whose answers alone pass the way back.
    DnsUnreachable,
    /// No `PublicKey`.
    NoPublicKey,
    /// No `Endpoint`: Watch must reach the server first.
    NoEndpoint,
    /// No `AllowedIPs`, or none of a version the configuration has an address of.
    NoAllowedIps,
    /// An `MTU` outside [`MTU_RANGE`], or below 1,280 with an IPv6 address.
    BadMtu,
    /// Both `IncludedApplications` and `ExcludedApplications`, which `WireGuard`'s app refuses too.
    BothApplicationLists {
        /// The line, counting from 1.
        line: usize,
    },
}

impl Refusal {
    /// A short code for the screens to say why, in the user's language.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLong => "too-long",
            Self::NotText => "not-text",
            Self::Unreadable { .. } => "unreadable",
            Self::OutsideSection { .. } => "outside-section",
            Self::UnknownSection { .. } => "unknown-section",
            Self::SeveralInterfaces { .. } => "several-interfaces",
            Self::SeveralPeers { .. } => "several-peers",
            Self::Unsupported { .. } => "unsupported",
            Self::Repeated { .. } => "repeated",
            Self::BadValue { .. } => "bad-value",
            Self::SeveralAddresses { .. } => "several-addresses",
            Self::SearchDomain { .. } => "search-domain",
            Self::NoInterface => "no-interface",
            Self::NoPeer => "no-peer",
            Self::NoPrivateKey => "no-private-key",
            Self::NoAddress => "no-address",
            Self::NoDns => "no-dns",
            Self::DnsUnreachable => "dns-unreachable",
            Self::NoPublicKey => "no-public-key",
            Self::NoEndpoint => "no-endpoint",
            Self::NoAllowedIps => "no-allowed-ips",
            Self::BadMtu => "bad-mtu",
            Self::BothApplicationLists { .. } => "both-application-lists",
        }
    }

    /// The line it is about, counting from 1, where there is one.
    #[must_use]
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::Unreadable { line }
            | Self::OutsideSection { line }
            | Self::UnknownSection { line }
            | Self::SeveralInterfaces { line }
            | Self::SeveralPeers { line }
            | Self::Unsupported { line, .. }
            | Self::Repeated { line, .. }
            | Self::BadValue { line, .. }
            | Self::SeveralAddresses { line }
            | Self::SearchDomain { line }
            | Self::BothApplicationLists { line } => Some(*line),
            _ => None,
        }
    }

    /// The key it is about, where it names one: one of `wg-quick`'s, or a plain word from the file.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        match self {
            Self::Unsupported { key, .. } => key.as_deref(),
            Self::Repeated { key, .. } | Self::BadValue { key, .. } => Some(key),
            _ => None,
        }
    }
}

impl fmt::Display for Refusal {
    /// `code`, then the line and the key where there are: `bad-value line 3 Endpoint`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())?;
        if let Some(line) = self.line() {
            write!(f, " line {line}")?;
        }
        if let Some(key) = self.key() {
            write!(f, " {key}")?;
        }
        Ok(())
    }
}

/// Which section a line is in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// What has been read so far.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
struct Read {
    interface: bool,
    peer: bool,
    private_key: Option<Secret>,
    addresses: Addresses,
    address_seen: bool,
    dns: Vec<IpAddr>,
    dns_seen: bool,
    mtu: Option<u16>,
    public_key: Option<[u8; 32]>,
    preshared_key: Option<Secret>,
    endpoint: Option<Endpoint>,
    allowed_ips: Vec<Network>,
    allowed_seen: bool,
    keepalive_seen: bool,
    keepalive: Option<u16>,
    applications: Applications,
    listen_port_seen: bool,
    fwmark_seen: bool,
}

fn parse(text: &[u8]) -> Result<Config, Refusal> {
    if text.len() > MAX_TEXT {
        return Err(Refusal::TooLong);
    }
    let text = std::str::from_utf8(text).map_err(|_| Refusal::NotText)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut read = Read::default();
    let mut section = Section::None;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        // `wg-quick` cuts a comment at its first `#`; base64 has none.
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        if let Some(inner) = content.strip_prefix('[') {
            let name = inner
                .strip_suffix(']')
                .ok_or(Refusal::Unreadable { line })?
                .trim();
            section = if name.eq_ignore_ascii_case("interface") {
                if read.interface {
                    return Err(Refusal::SeveralInterfaces { line });
                }
                read.interface = true;
                Section::Interface
            } else if name.eq_ignore_ascii_case("peer") {
                if read.peer {
                    return Err(Refusal::SeveralPeers { line });
                }
                read.peer = true;
                Section::Peer
            } else {
                return Err(Refusal::UnknownSection { line });
            };
            continue;
        }
        let (key, value) = content
            .split_once('=')
            .ok_or(Refusal::Unreadable { line })?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() {
            return Err(Refusal::Unreadable { line });
        }
        match section {
            Section::None => return Err(Refusal::OutsideSection { line }),
            Section::Interface => interface(&mut read, line, key, value)?,
            Section::Peer => peer(&mut read, line, key, value)?,
        }
    }
    finish(read)
}

/// A key of `[Interface]`.
#[allow(clippy::too_many_lines)]
fn interface(read: &mut Read, line: usize, key: &str, value: &str) -> Result<(), Refusal> {
    match key.to_ascii_lowercase().as_str() {
        "privatekey" => {
            let key = "PrivateKey";
            if read.private_key.is_some() {
                return Err(Refusal::Repeated { line, key });
            }
            let secret = decode_key(value).ok_or(Refusal::BadValue { line, key })?;
            read.private_key = Some(secret);
        }
        "address" => {
            read.address_seen = true;
            for item in list(value) {
                let network = network(item, false).ok_or(Refusal::BadValue {
                    line,
                    key: "Address",
                })?;
                match network.address {
                    IpAddr::V4(a) if read.addresses.v4.is_none() => {
                        read.addresses.v4 = Some((a, network.prefix));
                    }
                    IpAddr::V6(a) if read.addresses.v6.is_none() => {
                        read.addresses.v6 = Some((a, network.prefix));
                    }
                    _ => return Err(Refusal::SeveralAddresses { line }),
                }
            }
        }
        "dns" => {
            read.dns_seen = true;
            for item in list(value) {
                let Ok(address) = item.parse::<IpAddr>() else {
                    return Err(if host_name(item).is_some() {
                        Refusal::SearchDomain { line }
                    } else {
                        Refusal::BadValue { line, key: "DNS" }
                    });
                };
                if !usable_server(address) || read.dns.len() == MAX_DNS {
                    return Err(Refusal::BadValue { line, key: "DNS" });
                }
                if !read.dns.contains(&address) {
                    read.dns.push(address);
                }
            }
        }
        "mtu" => {
            let key = "MTU";
            if read.mtu.is_some() {
                return Err(Refusal::Repeated { line, key });
            }
            let mtu = number(value).ok_or(Refusal::BadValue { line, key })?;
            read.mtu = Some(mtu);
        }
        // Read and ignored (the maintainer's answer 2): Watch picks its own socket, and marks nothing.
        "listenport" => {
            let key = "ListenPort";
            if std::mem::replace(&mut read.listen_port_seen, true) {
                return Err(Refusal::Repeated { line, key });
            }
            number(value).ok_or(Refusal::BadValue { line, key })?;
        }
        "fwmark" => {
            let key = "FwMark";
            if std::mem::replace(&mut read.fwmark_seen, true) {
                return Err(Refusal::Repeated { line, key });
            }
            if !value.eq_ignore_ascii_case("off") && fwmark(value).is_none() {
                return Err(Refusal::BadValue { line, key });
            }
        }
        "includedapplications" | "excludedapplications" => {
            let included = key.eq_ignore_ascii_case("includedapplications");
            let key = if included {
                "IncludedApplications"
            } else {
                "ExcludedApplications"
            };
            let mut names = match std::mem::take(&mut read.applications) {
                Applications::Unnamed => Vec::new(),
                Applications::Only(names) if included => names,
                Applications::Except(names) if !included => names,
                Applications::Only(_) | Applications::Except(_) => {
                    return Err(Refusal::BothApplicationLists { line });
                }
            };
            for item in list(value) {
                if !package_name(item) || names.len() == MAX_APPLICATIONS {
                    return Err(Refusal::BadValue { line, key });
                }
                if !names.iter().any(|n| n == item) {
                    names.push(item.to_owned());
                }
            }
            read.applications = if included {
                Applications::Only(names)
            } else {
                Applications::Except(names)
            };
        }
        _ => return Err(unsupported(line, key)),
    }
    Ok(())
}

/// A key of `[Peer]`.
fn peer(read: &mut Read, line: usize, key: &str, value: &str) -> Result<(), Refusal> {
    match key.to_ascii_lowercase().as_str() {
        "publickey" => {
            let key = "PublicKey";
            if read.public_key.is_some() {
                return Err(Refusal::Repeated { line, key });
            }
            let decoded = decode_key(value).ok_or(Refusal::BadValue { line, key })?;
            read.public_key = Some(*decoded.bytes());
        }
        "presharedkey" => {
            let key = "PresharedKey";
            if read.preshared_key.is_some() {
                return Err(Refusal::Repeated { line, key });
            }
            read.preshared_key = Some(decode_key(value).ok_or(Refusal::BadValue { line, key })?);
        }
        "endpoint" => {
            let key = "Endpoint";
            if read.endpoint.is_some() {
                return Err(Refusal::Repeated { line, key });
            }
            read.endpoint = Some(endpoint(value).ok_or(Refusal::BadValue { line, key })?);
        }
        "allowedips" => {
            read.allowed_seen = true;
            for item in list(value) {
                let network = network(item, true).ok_or(Refusal::BadValue {
                    line,
                    key: "AllowedIPs",
                })?;
                if read.allowed_ips.len() == MAX_ALLOWED {
                    return Err(Refusal::BadValue {
                        line,
                        key: "AllowedIPs",
                    });
                }
                if !read.allowed_ips.contains(&network) {
                    read.allowed_ips.push(network);
                }
            }
        }
        "persistentkeepalive" => {
            let key = "PersistentKeepalive";
            if read.keepalive_seen {
                return Err(Refusal::Repeated { line, key });
            }
            read.keepalive_seen = true;
            let seconds = if value.eq_ignore_ascii_case("off") {
                None
            } else {
                Some(number(value).ok_or(Refusal::BadValue { line, key })?)
            };
            read.keepalive = seconds.filter(|&s| s > 0);
        }
        _ => return Err(unsupported(line, key)),
    }
    Ok(())
}

/// The configuration, once every line was read: what W7 needs is there.
fn finish(read: Read) -> Result<Config, Refusal> {
    if !read.interface {
        return Err(Refusal::NoInterface);
    }
    if !read.peer {
        return Err(Refusal::NoPeer);
    }
    let private_key = read.private_key.ok_or(Refusal::NoPrivateKey)?;
    let addresses = read.addresses;
    if addresses.v4.is_none() && addresses.v6.is_none() {
        return Err(Refusal::NoAddress);
    }
    if read.dns.is_empty() {
        return Err(Refusal::NoDns);
    }
    if let Some(mtu) = read.mtu
        && (!MTU_RANGE.contains(&mtu) || (addresses.v6.is_some() && mtu < 1_280))
    {
        return Err(Refusal::BadMtu);
    }
    let public_key = read.public_key.ok_or(Refusal::NoPublicKey)?;
    let endpoint = read.endpoint.ok_or(Refusal::NoEndpoint)?;
    if !read
        .allowed_ips
        .iter()
        .any(|n| addresses.like(n.address).is_some())
    {
        return Err(Refusal::NoAllowedIps);
    }
    // Its names go through the tunnel, and their answers come back only from inside `AllowedIPs`.
    let reachable = |dns: &IpAddr| {
        addresses.like(*dns).is_some() && read.allowed_ips.iter().any(|n| n.contains(*dns))
    };
    if !read.dns.iter().any(reachable) {
        return Err(Refusal::DnsUnreachable);
    }
    Ok(Config {
        private_key,
        addresses,
        dns: read.dns,
        mtu: read.mtu,
        peer: Peer {
            public_key,
            preshared_key: read.preshared_key,
            endpoint,
            allowed_ips: read.allowed_ips,
            persistent_keepalive: read.keepalive,
        },
        applications: read.applications,
    })
}

/// A refusal of the key `key`, named only when it is a plain word, which no key's base64 is short
/// enough to be mistaken for.
fn unsupported(line: usize, key: &str) -> Refusal {
    let plain = (1..=24).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphabetic());
    Refusal::Unsupported {
        line,
        key: plain.then(|| key.to_owned()),
    }
}

/// The items of a comma-separated value, trimmed; empty ones are skipped, as `wg-quick` skips them.
fn list(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

/// A decimal number of at most five digits that fits 16 bits.
fn number(value: &str) -> Option<u16> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// A DNS server Watch can send to: unicast, not the unspecified or a loopback address.
fn usable_server(address: IpAddr) -> bool {
    crate::packet::unicast(address) && !address.is_loopback()
}

/// An address with its prefix, `10.2.0.2/32` or `fd00::2/128`, or a bare address, which is a host's
/// whole prefix. For `AllowedIPs` (`masked`), the bits past the prefix are cleared, as `wg` clears them.
fn network(item: &str, masked: bool) -> Option<Network> {
    let (address, prefix) = match item.split_once('/') {
        Some((address, prefix)) => (address.trim(), Some(prefix.trim())),
        None => (item, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => width,
        Some(digits) => {
            if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            digits.parse::<u8>().ok().filter(|&p| p <= width)?
        }
    };
    let network = Network { address, prefix };
    if masked {
        Some(network.masked())
    } else {
        // An interface's address must be one a packet can come from.
        crate::packet::unicast(address)
            .then_some(network)
            .filter(|_| !address.is_loopback())
    }
}

/// `host:port`, `v4:port` or `[v6]:port`. An address must be one a server can have: unicast, and in IPv6
/// not link-local, which would need a scope this format has no room for (the engine's review, nit 12). The
/// loopback stays allowed: a local relay that wraps `WireGuard` to pass a network that blocks it (wstunnel,
/// udp2raw) listens there, and Watch's own socket reaches it outside the tunnel.
fn endpoint(value: &str) -> Option<Endpoint> {
    let server = |address: IpAddr| {
        crate::packet::unicast(address)
            && !matches!(address, IpAddr::V6(a) if a.is_unicast_link_local())
    };
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        let address = IpAddr::V6(host.parse::<Ipv6Addr>().ok()?);
        return port_of(port)
            .filter(|_| server(address))
            .map(|port| Endpoint::Address(SocketAddr::new(address, port)));
    } else {
        value.rsplit_once(':')?
    };
    let port = port_of(port)?;
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        let address = IpAddr::V4(address);
        return server(address).then_some(Endpoint::Address(SocketAddr::new(address, port)));
    }
    host_name(host).map(|name| Endpoint::Name(name, port))
}

/// At most this many packages in `IncludedApplications` or `ExcludedApplications`.
pub const MAX_APPLICATIONS: usize = 512;

/// An Android package name: at least two segments of ASCII letters, digits and underscores, separated by
/// dots, each beginning with a letter; at most 255 bytes.
fn package_name(name: &str) -> bool {
    let segment = |s: &str| {
        s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    name.len() <= 255 && name.contains('.') && name.split('.').all(segment)
}

/// `FwMark`'s value as `wg` reads it: decimal, or hexadecimal after `0x`, of 32 bits.
fn fwmark(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return (!hex.is_empty() && hex.len() <= 8)
            .then(|| u32::from_str_radix(hex, 16).ok())
            .flatten();
    }
    let digits =
        !value.is_empty() && value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit());
    digits.then(|| value.parse().ok()).flatten()
}

fn port_of(port: &str) -> Option<u16> {
    number(port).filter(|&p| p != 0)
}

/// A host name as DNS has them: labels of letters, digits and hyphens, none starting or ending with a
/// hyphen, each 1 to 63 bytes, at most 253 in all, and not all digits (that would be an address). In
/// lower case, without the trailing dot.
fn host_name(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if !host.split('.').all(valid_label) || host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// A key in base64: 44 characters, the last `=`, for 32 bytes; the all-zero key, which `wg` reads as no
/// key, is refused. The bytes pass through no buffer that is not zeroed.
fn decode_key(value: &str) -> Option<Secret> {
    let text = value.as_bytes();
    if text.len() != 44 || text[43] != b'=' || text[42] == b'=' {
        return None;
    }
    let mut out = Secret([0; 32]);
    let mut bits: u32 = 0;
    let mut held = 0u32;
    let mut at = 0usize;
    for &c in &text[..43] {
        let Some(sextet) = sextet(c) else {
            bits.zeroize();
            return None;
        };
        bits = (bits << 6) | u32::from(sextet);
        held += 6;
        if held >= 8 {
            held -= 8;
            let byte = u8::try_from((bits >> held) & 0xff).unwrap_or(0);
            if let Some(slot) = out.0.get_mut(at) {
                *slot = byte;
            }
            at += 1;
            bits &= (1 << held) - 1;
        }
    }
    // 43 characters carry 258 bits: 32 bytes and two bits, which a canonical key leaves at nought.
    let canonical = at == 32 && held == 2 && bits == 0;
    bits.zeroize();
    (canonical && out.0 != [0; 32]).then_some(out)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key `wg genkey` wrote, for tests only.
    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    fn proton_like() -> String {
        format!(
            "[Interface]\n# Key for test\nPrivateKey = {PRIVATE}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n\
             [Peer]\n# NL#1\nPublicKey = {PUBLIC}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.7:51820\n"
        )
    }

    fn refusal(text: &str) -> Refusal {
        match Config::parse(text.as_bytes()) {
            Ok(_) => unreachable!("accepted: {text}"),
            Err(refusal) => refusal,
        }
    }

    #[test]
    fn a_providers_file_is_read() {
        let Ok(config) = Config::parse(proton_like().as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(config.addresses.v4, Some((Ipv4Addr::new(10, 2, 0, 2), 32)));
        assert_eq!(config.addresses.v6, None);
        assert_eq!(config.dns, vec![IpAddr::from([10, 2, 0, 1])]);
        assert_eq!(config.mtu(), DEFAULT_MTU);
        assert_eq!(
            config.peer.endpoint,
            Endpoint::Address(SocketAddr::from(([198, 51, 100, 7], 51_820)))
        );
        assert!(config.peer.allows(IpAddr::from([93, 184, 216, 34])));
        assert!(
            !config
                .peer
                .allows(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]))
        );
        assert_eq!(config.peer.persistent_keepalive, None);
        assert!(config.peer.preshared_key.is_none());
    }

    /// W7, part 2: the import's description says what the configuration does, in a line each, and never a key.
    #[test]
    fn the_description_says_what_it_does_and_no_key() {
        let text = format!(
            "[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.64.0.2/32, fc00:bbbb::2/128\nDNS = 10.64.0.1, fc00:bbbb::1\n\
             MTU = 1420\nIncludedApplications = org.example.one, org.example.two\n[Peer]\nPublicKey = {PUBLIC}\n\
             PresharedKey = {PSK}\nEndpoint = vpn.Example.net:443\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/0\n\
             PersistentKeepalive = 25\n"
        );
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.describe(),
            "endpoint vpn.example.net 443\naddress 10.64.0.2/32\naddress fc00:bbbb::2/128\ndns 10.64.0.1\n\
             dns fc00:bbbb::1\nallowed 0.0.0.0/1\nallowed 128.0.0.0/1\nallowed ::/0\neverything 1\npreshared 1\n\
             mtu 1420\nkeepalive 25\nonly org.example.one\nonly org.example.two"
        );
        let shown = config.describe();
        for key in [PRIVATE, PSK] {
            assert!(!shown.contains(key), "{shown}");
        }
        let Ok(proton) = Config::parse(proton_like().as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            proton.describe(),
            "endpoint 198.51.100.7 51820\naddress 10.2.0.2/32\ndns 10.2.0.1\nallowed 0.0.0.0/0\neverything 1\n\
             preshared 0\nmtu 1280"
        );
    }

    /// `everything` adds up the networks of each version the configuration has an address of.
    #[test]
    fn everything_is_every_destination_of_each_version_it_has() {
        let with = |allowed: &str, address: &str| {
            let text = proton_like()
                .replace("0.0.0.0/0", allowed)
                .replace("10.2.0.2/32", address)
                .replace("DNS = 10.2.0.1", "DNS = 10.2.0.1, fd00::1");
            match Config::parse(text.as_bytes()) {
                Ok(config) => config.carries_everything(),
                Err(refusal) => unreachable!("{refusal} for {allowed}"),
            }
        };
        assert!(
            with("0.0.0.0/0", "10.2.0.2/32"),
            "IPv4 alone, all of it: an IPv4 configuration needs no IPv6 network"
        );
        assert!(with("0.0.0.0/1, 128.0.0.0/1", "10.2.0.2/32"), "two halves");
        assert!(
            with("128.0.0.0/1, 0.0.0.0/2, 64.0.0.0/2", "10.2.0.2/32"),
            "out of order"
        );
        assert!(
            !with("0.0.0.0/1, 192.0.0.0/2", "10.2.0.2/32"),
            "a quarter missing"
        );
        assert!(
            !with("10.0.0.0/8", "10.2.0.2/32"),
            "a company's network alone"
        );
        assert!(
            !with("0.0.0.0/0", "10.2.0.2/32, fd00::2/128"),
            "IPv6 refused"
        );
        assert!(with(
            "0.0.0.0/0, ::/1, 8000::/1",
            "10.2.0.2/32, fd00::2/128"
        ));
        assert!(!with("0.0.0.0/0, ::/1", "10.2.0.2/32, fd00::2/128"));
        assert!(
            with("::/0, 0.0.0.0/0, 10.0.0.0/8", "fd00::2/128"),
            "overlapping"
        );
    }

    #[test]
    fn every_key_wg_quick_writes_for_a_client_is_read() {
        let text = format!(
            "\u{feff}[interface]\r\nprivatekey={PRIVATE}\r\nADDRESS = 10.64.0.2/32, fc00:bbbb::2/128\r\n\
             DNS = 10.64.0.1, fc00:bbbb::1 , \r\nMTU = 1420\r\n[PEER]\r\nPublicKey = {PUBLIC}\r\n\
             PresharedKey = {PSK}\r\nEndpoint = [2001:db8::7]:51820\r\nAllowedIPs = 0.0.0.0/0\r\n\
             AllowedIPs = ::/0\r\nPersistentKeepalive = 25 # every 25 s\r\n"
        );
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(config.addresses.v6.map(|(_, p)| p), Some(128));
        assert_eq!(config.dns.len(), 2);
        assert_eq!(config.mtu(), 1_420);
        assert!(config.peer.preshared_key.is_some());
        assert_eq!(config.peer.allowed_ips.len(), 2);
        assert_eq!(config.peer.persistent_keepalive, Some(25));
        assert!(matches!(
            config.peer.endpoint,
            Endpoint::Address(SocketAddr::V6(_))
        ));
    }

    #[test]
    fn a_host_name_endpoint_is_kept_in_lower_case() {
        let text = proton_like().replace("198.51.100.7:51820", "NL-FREE-1.Example.NET.:443");
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.peer.endpoint,
            Endpoint::Name("nl-free-1.example.net".into(), 443)
        );
    }

    #[test]
    fn allowed_ips_are_masked_and_a_narrower_set_is_kept() {
        let text = proton_like()
            .replace("0.0.0.0/0", "10.77.0.9/24, 192.0.2.1")
            .replace("DNS = 10.2.0.1", "DNS = 10.77.0.1");
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.peer.allowed_ips,
            vec![
                Network {
                    address: IpAddr::from([10, 77, 0, 0]),
                    prefix: 24
                },
                Network {
                    address: IpAddr::from([192, 0, 2, 1]),
                    prefix: 32
                },
            ]
        );
        assert!(config.peer.allows(IpAddr::from([10, 77, 0, 200])));
        assert!(!config.peer.allows(IpAddr::from([10, 77, 1, 1])));
        assert!(!config.peer.allows(IpAddr::from([192, 0, 2, 2])));
    }

    /// Every refusal, with what it names.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_refusal_says_why() {
        let base = proton_like();
        let cases: Vec<(String, Refusal)> = vec![
            (" ".repeat(MAX_TEXT + 1), Refusal::TooLong),
            ("x".to_owned(), Refusal::Unreadable { line: 1 }),
            (
                format!("PrivateKey = {PRIVATE}\n{base}"),
                Refusal::OutsideSection { line: 1 },
            ),
            (
                format!("{base}[Wat]\n"),
                Refusal::UnknownSection { line: 12 },
            ),
            (
                format!("{base}[Interface\n"),
                Refusal::Unreadable { line: 12 },
            ),
            (
                format!("{base}[Interface]\n"),
                Refusal::SeveralInterfaces { line: 12 },
            ),
            (
                format!("{base}[Peer]\nPublicKey = {PUBLIC}\n"),
                Refusal::SeveralPeers { line: 12 },
            ),
            (
                base.replace("DNS = 10.2.0.1", "PostUp = iptables -A FORWARD"),
                Refusal::Unsupported {
                    line: 5,
                    key: Some("PostUp".into()),
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nTable = off"),
                Refusal::Unsupported {
                    line: 6,
                    key: Some("Table".into()),
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nListenPort = x"),
                Refusal::BadValue {
                    line: 6,
                    key: "ListenPort",
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nFwMark = 0xzz"),
                Refusal::BadValue {
                    line: 6,
                    key: "FwMark",
                },
            ),
            (
                base.replace(
                    "DNS = 10.2.0.1",
                    "DNS = 10.2.0.1\nIncludedApplications = org.a.b\nExcludedApplications = org.c.d",
                ),
                Refusal::BothApplicationLists { line: 7 },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nIncludedApplications = org.a.b, 1bad.name"),
                Refusal::BadValue {
                    line: 6,
                    key: "IncludedApplications",
                },
            ),
            (
                format!("{base}{PRIVATE} = 1\n"),
                Refusal::Unsupported {
                    line: 12,
                    key: None,
                },
            ),
            (
                base.replace(
                    "Address = 10.2.0.2/32",
                    &format!("Address = 10.2.0.2/32\nPrivateKey = {PRIVATE}"),
                ),
                Refusal::Repeated {
                    line: 5,
                    key: "PrivateKey",
                },
            ),
            (
                base.replace(PRIVATE, "c2hvcnQ="),
                Refusal::BadValue {
                    line: 3,
                    key: "PrivateKey",
                },
            ),
            (
                base.replace(PRIVATE, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                Refusal::BadValue {
                    line: 3,
                    key: "PrivateKey",
                },
            ),
            (
                base.replace("10.2.0.2/32", "10.2.0.2/33"),
                Refusal::BadValue {
                    line: 4,
                    key: "Address",
                },
            ),
            (
                base.replace("10.2.0.2/32", "10.2.0.2/32, 10.2.0.3/32"),
                Refusal::SeveralAddresses { line: 4 },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1, corp.example"),
                Refusal::SearchDomain { line: 5 },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1, 1.1.1"),
                Refusal::BadValue {
                    line: 5,
                    key: "DNS",
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 127.0.0.1"),
                Refusal::BadValue {
                    line: 5,
                    key: "DNS",
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 1420\nMTU = 1420"),
                Refusal::Repeated {
                    line: 7,
                    key: "MTU",
                },
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 1e3"),
                Refusal::BadValue {
                    line: 6,
                    key: "MTU",
                },
            ),
            (
                base.replace(
                    &format!("PublicKey = {PUBLIC}"),
                    &format!("PublicKey = {PUBLIC}\nPublicKey = {PUBLIC}"),
                ),
                Refusal::Repeated {
                    line: 10,
                    key: "PublicKey",
                },
            ),
            (
                base.replace(PUBLIC, "not a key"),
                Refusal::BadValue {
                    line: 9,
                    key: "PublicKey",
                },
            ),
            (
                base.replace(
                    "AllowedIPs",
                    &format!("PresharedKey = {PSK}\nPresharedKey = {PSK}\nAllowedIPs"),
                ),
                Refusal::Repeated {
                    line: 11,
                    key: "PresharedKey",
                },
            ),
            (
                base.replace("AllowedIPs", "PresharedKey = x\nAllowedIPs"),
                Refusal::BadValue {
                    line: 10,
                    key: "PresharedKey",
                },
            ),
            (
                base.replace(
                    "198.51.100.7:51820",
                    "198.51.100.7:51820\nEndpoint = 198.51.100.8:51820",
                ),
                Refusal::Repeated {
                    line: 12,
                    key: "Endpoint",
                },
            ),
            (
                base.replace(":51820", ":0"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace(":51820", ""),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "[2001:db8::7"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "-bad-.example"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "255.255.255.255"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "[::]"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "[fe80::1]"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("198.51.100.7", "[ff02::1]"),
                Refusal::BadValue {
                    line: 11,
                    key: "Endpoint",
                },
            ),
            (
                base.replace("0.0.0.0/0", "0.0.0.0/x"),
                Refusal::BadValue {
                    line: 10,
                    key: "AllowedIPs",
                },
            ),
            (
                base.replace(
                    "Endpoint",
                    "PersistentKeepalive = 25\nPersistentKeepalive = 25\nEndpoint",
                ),
                Refusal::Repeated {
                    line: 12,
                    key: "PersistentKeepalive",
                },
            ),
            (
                base.replace("Endpoint", "PersistentKeepalive = 99999\nEndpoint"),
                Refusal::BadValue {
                    line: 11,
                    key: "PersistentKeepalive",
                },
            ),
            ("[Peer]\n".to_owned(), Refusal::NoInterface),
            (
                base.split("[Peer]").next().unwrap_or("").to_owned(),
                Refusal::NoPeer,
            ),
            (
                base.replace(&format!("PrivateKey = {PRIVATE}"), ""),
                Refusal::NoPrivateKey,
            ),
            (
                base.replace("Address = 10.2.0.2/32", ""),
                Refusal::NoAddress,
            ),
            (base.replace("DNS = 10.2.0.1", ""), Refusal::NoDns),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 2001:db8::53"),
                Refusal::DnsUnreachable,
            ),
            (
                base.replace("0.0.0.0/0", "192.0.2.0/24"),
                Refusal::DnsUnreachable,
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 575"),
                Refusal::BadMtu,
            ),
            (
                base.replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 1501"),
                Refusal::BadMtu,
            ),
            (
                base.replace("10.2.0.2/32", "10.2.0.2/32, fd00::2/128")
                    .replace("DNS = 10.2.0.1", "DNS = 10.2.0.1\nMTU = 1279"),
                Refusal::BadMtu,
            ),
            (
                base.replace(&format!("PublicKey = {PUBLIC}"), ""),
                Refusal::NoPublicKey,
            ),
            (
                base.replace("Endpoint = 198.51.100.7:51820", ""),
                Refusal::NoEndpoint,
            ),
            (
                base.replace("AllowedIPs = 0.0.0.0/0", ""),
                Refusal::NoAllowedIps,
            ),
            (base.replace("0.0.0.0/0", "::/0"), Refusal::NoAllowedIps),
        ];
        for (text, expected) in cases {
            assert_eq!(refusal(&text), expected, "{text}");
        }
        assert_eq!(Config::parse(&[0xff, 0xfe]), Err(Refusal::NotText));
    }

    /// A refusal names a line and a key, never what the line held.
    #[test]
    fn a_refusal_shows_no_value() {
        let text = proton_like().replace("PrivateKey", "PrivatKey");
        let shown = refusal(&text).to_string();
        assert_eq!(shown, "unsupported line 3 PrivatKey");
        assert!(!shown.contains(&PRIVATE[..8]));
        let unreadable =
            refusal(&proton_like().replace(&format!("PrivateKey = {PRIVATE}"), PRIVATE));
        // A line of the key alone reads as a key that is no plain word: named by its line alone.
        assert_eq!(unreadable.to_string(), "unsupported line 3");
    }

    /// `ListenPort` and `FwMark` are read and ignored; the application lists of `WireGuard`'s app are kept,
    /// for the import to offer (the maintainer's answer 2, 2026-11-19).
    #[test]
    fn listen_port_and_fwmark_are_ignored_and_the_application_lists_kept() {
        let base = proton_like();
        let text = base.replace(
            "DNS = 10.2.0.1",
            "DNS = 10.2.0.1\nListenPort = 51820\nFwMark = 0xca6c\n\
             ExcludedApplications = org.example.bank, com.example.game, org.example.bank",
        );
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.applications,
            Applications::Except(vec!["org.example.bank".into(), "com.example.game".into()])
        );
        let text = base.replace(
            "DNS = 10.2.0.1",
            "DNS = 10.2.0.1\nIncludedApplications = org.example.browser\nFwMark = off",
        );
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.applications,
            Applications::Only(vec!["org.example.browser".into()])
        );
        let Ok(plain) = Config::parse(base.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(plain.applications, Applications::Unnamed);
        assert!(fwmark("4294967296").is_none() && fwmark("0x100000000").is_none());
        assert_eq!(
            (fwmark("51820"), fwmark("0xCA6C")),
            (Some(51_820), Some(0xca6c))
        );
    }

    /// Two secrets compare by every byte.
    #[test]
    fn secrets_compare_by_every_byte() {
        let (a, mut b) = (Secret([7; 32]), [7; 32]);
        assert_eq!(a, Secret(b));
        b[31] = 8;
        assert_ne!(a, Secret(b));
        b[31] = 7;
        b[0] = 0;
        assert_ne!(a, Secret(b));
    }

    /// No key reaches a `Debug` output.
    #[test]
    fn debug_shows_no_key_and_no_endpoint() {
        let text =
            proton_like().replace("AllowedIPs", &format!("PresharedKey = {PSK}\nAllowedIPs"));
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        let shown = format!("{config:?}");
        for hidden in [
            &PRIVATE[..10],
            &PUBLIC[..10],
            &PSK[..10],
            "198.51",
            "10.2.0",
        ] {
            assert!(!shown.contains(hidden), "{shown}");
        }
        assert_eq!(format!("{:?}", config.private_key), "Secret(..)");
        // Neither do the key's bytes, in any form.
        let bytes = format!("{:?}", config.private_key.bytes());
        assert!(!shown.contains(&bytes));
    }

    /// A key reads to the bytes `wg` writes it from, and only a canonical one is taken.
    #[test]
    fn keys_decode_as_wg_writes_them() {
        let Some(key) = decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=") else {
            unreachable!("refused")
        };
        let expected: Vec<u8> = (1..=32).collect();
        assert_eq!(key.bytes().as_slice(), expected.as_slice());
        // The two bits past the last byte set: not the canonical form.
        assert!(decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB=").is_none());
        // `E` leaves those two bits at nought: another key, canonical.
        assert!(decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyE=").is_some());
        assert!(decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHy==").is_none());
        assert!(decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eH*A=").is_none());
        assert!(decode_key("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA").is_none());
    }

    /// What `Drop` runs writes nought over the key. That `Drop` runs it cannot be seen from safe code,
    /// once the secret is gone.
    #[test]
    fn a_wiped_secret_is_nought() {
        let mut secret = Secret([7; 32]);
        secret.wipe();
        assert_eq!(secret.0, [0; 32]);
    }

    #[test]
    fn the_dns_server_is_the_one_of_the_querys_version_where_there_is_one() {
        let text = proton_like()
            .replace("10.2.0.2/32", "10.2.0.2/32, fd00::2/128")
            .replace("DNS = 10.2.0.1", "DNS = 2001:db8::53, 10.2.0.1, 192.0.2.53")
            .replace("0.0.0.0/0", "0.0.0.0/0, ::/0");
        let Ok(config) = Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        assert_eq!(
            config.dns_like(IpAddr::from([10, 1, 10, 3])),
            Some(IpAddr::from([10, 2, 0, 1]))
        );
        assert_eq!(
            config.dns_like(IpAddr::from([0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 3])),
            Some(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53]))
        );
        // Without an IPv6 address, an IPv6 server cannot be reached: the IPv4 one answers both.
        let Ok(v4only) = Config::parse(
            proton_like()
                .replace("DNS = 10.2.0.1", "DNS = 2001:db8::53, 10.2.0.1")
                .as_bytes(),
        ) else {
            unreachable!("refused")
        };
        assert_eq!(
            v4only.dns_like(IpAddr::from([0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 3])),
            Some(IpAddr::from([10, 2, 0, 1]))
        );
    }

    #[test]
    fn a_network_contains_what_its_prefix_says() {
        let net = |a: [u8; 4], prefix| Network {
            address: IpAddr::from(a),
            prefix,
        };
        assert!(net([0, 0, 0, 0], 0).contains(IpAddr::from([255, 1, 2, 3])));
        assert!(net([10, 0, 0, 0], 8).contains(IpAddr::from([10, 255, 0, 1])));
        assert!(!net([10, 0, 0, 0], 8).contains(IpAddr::from([11, 0, 0, 1])));
        assert!(net([10, 0, 0, 1], 32).contains(IpAddr::from([10, 0, 0, 1])));
        assert!(!net([10, 0, 0, 1], 32).contains(IpAddr::from([10, 0, 0, 2])));
        assert!(!net([0, 0, 0, 0], 0).contains(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
        let six = Network {
            address: IpAddr::from([0xfd77, 0, 0, 0, 0, 0, 0, 0]),
            prefix: 64,
        };
        assert!(six.contains(IpAddr::from([0xfd77, 0, 0, 0, 1, 2, 3, 4])));
        assert!(!six.contains(IpAddr::from([0xfd77, 0, 0, 1, 0, 0, 0, 0])));
        assert_eq!(net([10, 77, 0, 9], 24).masked(), net([10, 77, 0, 0], 24));
        assert_eq!(net([10, 77, 0, 9], 0).masked(), net([0, 0, 0, 0], 0));
        // Whole prefixes, which the fuzzer found shifted past their width.
        let host6 = Network {
            address: IpAddr::from([0xfd77, 0, 0, 0, 0, 0, 0, 2]),
            prefix: 128,
        };
        assert_eq!(host6.masked(), host6);
        assert!(host6.contains(IpAddr::from([0xfd77, 0, 0, 0, 0, 0, 0, 2])));
        assert!(!host6.contains(IpAddr::from([0xfd77, 0, 0, 0, 0, 0, 0, 3])));
        assert_eq!(net([10, 77, 0, 9], 32).masked(), net([10, 77, 0, 9], 32));
    }
}
