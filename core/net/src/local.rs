//! Whether an address is on the user's own network (the proxy record's unit B, R4; ADR 0052): one definition for the
//! engine's facts, decided where a proxy is named, so that a record left out for the switch still says so (its address
//! is all zeros there).
//!
//! The rule, from the network beneath's own prefixes, which the network part reads from its `LinkProperties`:
//! 1. link-local (`169.254/16`, `fe80::/10`) is local;
//! 2. an address within one of the network's on-link prefixes is local, global IPv6 included: on Wi-Fi and Ethernet the
//!    routes without a gateway and the link addresses' own prefixes, on a cellular network only the link addresses'
//!    (a data call is point to point, and a modem may report its default route with no gateway), IPv4 from `/24` there,
//!    so that other subscribers are not local; never a prefix of length 0, and none wider than `/16` for IPv4 or `/48`
//!    for IPv6 ([`OnLink::new`] leaves them out);
//! 3. private addresses (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) are local on Wi-Fi and Ethernet; on another
//!    network only by rule 2;
//! 4. CGNAT (`100.64/10`) and the deprecated `fec0::/10` (RFC 3879) only by rule 2;
//! 5. with no network told yet, rules 1 and 3, as if on Wi-Fi.
//!
//! An IPv4-mapped IPv6 address is read as its IPv4 address. The unspecified addresses are never local.
use std::net::IpAddr;

/// The most on-link prefixes kept of one network.
pub const MAX_PREFIXES: usize = 64;

/// The narrowest an IPv4 on-link prefix may be counted wide: a wider one is left out.
pub const MIN_V4: u8 = 16;

/// The same for IPv6.
pub const MIN_V6: u8 = 48;

/// The same for IPv4 on a cellular network, where a data call's link prefix wider than this would take in other
/// subscribers (review B-engine, minor 5): `/32` and `/30` are the usual ones, and the emulator's radio has a `/24`.
pub const MIN_V4_CELLULAR: u8 = 24;

/// What the network beneath is, as far as rule 3 goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// No network told yet: rule 5.
    #[default]
    Unknown,
    /// Wi-Fi.
    Wifi,
    /// Ethernet.
    Ethernet,
    /// A cellular data call.
    Cellular,
    /// Anything else: Bluetooth, USB, a satellite link.
    Other,
}

impl Transport {
    /// From the network part's code: 0 unknown, 1 Wi-Fi, 2 Ethernet, 3 cellular, anything else other.
    #[must_use]
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Unknown,
            1 => Self::Wifi,
            2 => Self::Ethernet,
            3 => Self::Cellular,
            _ => Self::Other,
        }
    }

    fn private_is_local(self) -> bool {
        matches!(self, Self::Unknown | Self::Wifi | Self::Ethernet)
    }
}

/// The network beneath's on-link prefixes and its transport, as the network part last told them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OnLink {
    prefixes: Vec<(IpAddr, u8)>,
    transport: Transport,
}

impl OnLink {
    /// The prefixes kept of `prefixes`, at most [`MAX_PREFIXES`]: each of a length its family allows, none of length 0
    /// and none wider than [`MIN_V4`] or [`MIN_V6`]. On a cellular network the network part hands only its link
    /// addresses' own prefixes (rule 2).
    #[must_use]
    pub fn new(prefixes: impl IntoIterator<Item = (IpAddr, u8)>, transport: Transport) -> Self {
        let prefixes = prefixes
            .into_iter()
            .map(|(address, length)| (address.to_canonical(), length))
            .filter(|&(address, length)| match address {
                IpAddr::V4(_) if transport == Transport::Cellular => {
                    (MIN_V4_CELLULAR..=32).contains(&length)
                }
                IpAddr::V4(_) => (MIN_V4..=32).contains(&length),
                IpAddr::V6(_) => (MIN_V6..=128).contains(&length),
            })
            .take(MAX_PREFIXES)
            .collect();
        Self {
            prefixes,
            transport,
        }
    }

    /// The prefixes kept, for the debug dump.
    #[must_use]
    pub fn prefixes(&self) -> &[(IpAddr, u8)] {
        &self.prefixes
    }

    /// The transport told.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Whether `address` is on the user's own network, by the rule above.
    #[must_use]
    pub fn is_local(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        if address.is_unspecified() {
            return false;
        }
        let link_local = match address {
            IpAddr::V4(a) => a.is_link_local(),
            IpAddr::V6(a) => a.is_unicast_link_local(),
        };
        if link_local || self.prefixes.iter().any(|&(p, l)| within(address, p, l)) {
            return true;
        }
        let private = match address {
            IpAddr::V4(a) => a.is_private(),
            IpAddr::V6(a) => a.is_unique_local(),
        };
        private && self.transport.private_is_local()
    }
}

/// Whether `address` is within `prefix`/`length`, both of one family.
fn within(address: IpAddr, prefix: IpAddr, length: u8) -> bool {
    match (address, prefix) {
        (IpAddr::V4(a), IpAddr::V4(p)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            u32::from(a) & mask == u32::from(p) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(p)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            u128::from(a) & mask == u128::from(p) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table both sides hold (`core/net/testdata/local-addresses.tsv`): the address, the prefixes as
    /// `address/length` by commas or `-` for none, the transport, and whether it is local.
    const VECTORS: &str = include_str!("../testdata/local-addresses.tsv");

    fn transport(word: &str) -> Transport {
        match word {
            "unknown" => Transport::Unknown,
            "wifi" => Transport::Wifi,
            "ethernet" => Transport::Ethernet,
            "cellular" => Transport::Cellular,
            "other" => Transport::Other,
            _ => unreachable!("no transport {word}"),
        }
    }

    #[test]
    fn every_vector_of_the_shared_table_holds() {
        let mut rows = 0;
        for line in VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "{line}");
            let address: IpAddr = fields[0].parse().unwrap_or_else(|_| unreachable!("{line}"));
            let prefixes = fields[1]
                .split(',')
                .filter(|p| *p != "-")
                .map(|p| {
                    let (a, l) = p.split_once('/').unwrap_or_else(|| unreachable!("{line}"));
                    (
                        a.parse().unwrap_or_else(|_| unreachable!("{line}")),
                        l.parse().unwrap_or_else(|_| unreachable!("{line}")),
                    )
                })
                .collect::<Vec<_>>();
            let on_link = OnLink::new(prefixes, transport(fields[2]));
            assert_eq!(on_link.is_local(address), fields[3] == "local", "{line}");
            rows += 1;
        }
        assert!(rows >= 20, "the table has {rows} rows");
    }

    #[test]
    fn a_prefix_of_length_zero_or_too_wide_is_never_kept() {
        let on_link = OnLink::new(
            [
                ("0.0.0.0".parse().unwrap_or(IpAddr::from([0, 0, 0, 0])), 0),
                ("::".parse().unwrap_or(IpAddr::from([0u16; 8])), 0),
                (IpAddr::from([10, 0, 0, 0]), 8),
                (IpAddr::from([192, 168, 1, 0]), 24),
                (IpAddr::from([192, 168, 1, 0]), 33),
            ],
            Transport::Cellular,
        );
        assert_eq!(on_link.prefixes(), &[(IpAddr::from([192, 168, 1, 0]), 24)]);
        let many = (0..200u8).map(|i| (IpAddr::from([10, 1, i, 0]), 24));
        assert_eq!(
            OnLink::new(many, Transport::Wifi).prefixes().len(),
            MAX_PREFIXES
        );
    }
}
