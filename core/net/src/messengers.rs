//! The three messengers whose built-in proxies the network part infers (W8, part 2a; ADR 0052), from `data/messengers`:
//! their makers' own Android packages (`clients.tsv`), Telegram's published address ranges
//! (`telegram-cidr.txt`, byte for byte as Telegram serves it, each fetch recorded in `SOURCE`), and the server
//! names that tell a messenger's own connections, its own circumvention and the third parties it reaches from
//! those of a proxy (`names.tsv`).
//!
//! The tables are compiled into the engine and kept out of the data pack, as the resolvers are: they are the network
//! part's alone, and an update of any of them needs an app release (ADR 0052's accepted limits, corrected in the fix
//! round, S-n4). They are deflated (`build.rs`) and inflated where they are read. Rows that do not parse are skipped,
//! never fatal: the tables are data, checked by `scripts/check.sh`. A table that does not inflate stops the engine
//! (`crate::bundled`): that is a damaged library, not data.

use std::net::IpAddr;

const CIDR: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/messengers-telegram-cidr.txt.deflate"
));
const CLIENTS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/messengers-clients.tsv.deflate"));
const NAMES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/messengers-names.tsv.deflate"));

/// A messenger whose proxy is inferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// Telegram's clients, whose proxy is `MTProto`.
    Telegram,
    /// `WhatsApp`'s.
    WhatsApp,
    /// Signal's.
    Signal,
}

impl Family {
    /// Its code in the tables and in the network part's calls: `telegram`, `whatsapp`, `signal`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Telegram => "telegram",
            Self::WhatsApp => "whatsapp",
            Self::Signal => "signal",
        }
    }

    /// The family of a code.
    #[must_use]
    pub fn of_code(code: &str) -> Option<Self> {
        match code {
            "telegram" => Some(Self::Telegram),
            "whatsapp" => Some(Self::WhatsApp),
            "signal" => Some(Self::Signal),
            _ => None,
        }
    }

    /// The kind of its proxy.
    #[must_use]
    pub fn kind(self) -> crate::proxies::Kind {
        match self {
            Self::Telegram => crate::proxies::Kind::MtProto,
            Self::WhatsApp => crate::proxies::Kind::WhatsApp,
            Self::Signal => crate::proxies::Kind::Signal,
        }
    }

    /// The entity of `data/owners` whose own networks are the maker's, where its networks are told by the
    /// owners' table: Meta's for `WhatsApp`, which Meta's peering page names (AS32934, AS63293). Telegram's are
    /// its published ranges; Signal has no network of its own.
    #[must_use]
    pub fn network_entity(self) -> Option<&'static str> {
        match self {
            Self::WhatsApp => Some("meta"),
            Self::Telegram | Self::Signal => None,
        }
    }
}

/// What a server name is to a messenger (`names.tsv`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The maker's own service.
    Own,
    /// A name the app sends to reach its own service through another network: its own circumvention.
    Front,
    /// A third party the app reaches itself.
    Other,
}

/// The tables.
#[derive(Debug, Default)]
pub struct Messengers {
    telegram: Vec<(IpAddr, u8)>,
    clients: Vec<(Family, String)>,
    names: Vec<(Family, Role, String)>,
}

impl Messengers {
    /// The tables compiled into the engine.
    #[must_use]
    pub fn bundled() -> Self {
        Self::parse(
            &crate::bundled(CIDR),
            &crate::bundled(CLIENTS),
            &crate::bundled(NAMES),
        )
    }

    /// Reads the three tables: one network in CIDR form a line; then `#` comments and tab-separated rows of
    /// family and package; of family, role and name.
    #[must_use]
    pub fn parse(cidr: &str, clients: &str, names: &str) -> Self {
        let telegram = cidr
            .lines()
            .filter_map(|line| {
                let (address, length) = line.trim().split_once('/')?;
                let address: IpAddr = address.parse().ok()?;
                let length: u8 = length.parse().ok()?;
                let most = if address.is_ipv4() { 32 } else { 128 };
                (length <= most).then_some((address, length))
            })
            .collect();
        let rows = |table: &'_ str| -> Vec<Vec<String>> {
            table
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .map(|l| l.split('\t').map(str::to_owned).collect())
                .collect()
        };
        let clients = rows(clients)
            .into_iter()
            .filter_map(|c| Some((Family::of_code(c.first()?)?, c.get(1)?.clone())))
            .collect();
        let names = rows(names)
            .into_iter()
            .filter_map(|c| {
                let role = match c.get(1)?.as_str() {
                    "own" => Role::Own,
                    "front" => Role::Front,
                    "other" => Role::Other,
                    _ => return None,
                };
                Some((
                    Family::of_code(c.first()?)?,
                    role,
                    c.get(2)?.to_ascii_lowercase(),
                ))
            })
            .collect();
        Self {
            telegram,
            clients,
            names,
        }
    }

    /// Whether `address` is in Telegram's published ranges.
    #[must_use]
    pub fn is_telegrams(&self, address: IpAddr) -> bool {
        self.telegram
            .iter()
            .any(|&(network, length)| within(address, network, length))
    }

    /// What `name` is to `family`'s messenger, if `names.tsv` says: the row's name or a name under it.
    #[must_use]
    pub fn role(&self, family: Family, name: &str) -> Option<Role> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.names
            .iter()
            .find(|(f, _, row)| {
                *f == family
                    && (name == *row
                        || name
                            .strip_suffix(row.as_str())
                            .is_some_and(|head| head.ends_with('.')))
            })
            .map(|&(_, role, _)| role)
    }

    /// Each client package and its family.
    pub fn clients(&self) -> impl Iterator<Item = (Family, &str)> {
        self.clients.iter().map(|(f, p)| (*f, p.as_str()))
    }

    /// How many ranges, packages and names the tables hold.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.telegram.len(), self.clients.len(), self.names.len())
    }
}

/// Whether `address` is in `network`/`length`, of one IP version.
fn within(address: IpAddr, network: IpAddr, length: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    #[test]
    fn the_deflated_tables_inflate_to_the_files() {
        let files = [
            (
                CIDR,
                include_str!("../../../data/messengers/telegram-cidr.txt"),
            ),
            (
                CLIENTS,
                include_str!("../../../data/messengers/clients.tsv"),
            ),
            (NAMES, include_str!("../../../data/messengers/names.tsv")),
        ];
        for (blob, text) in files {
            assert_eq!(crate::bundled(blob), text);
        }
    }

    #[test]
    fn the_bundled_tables_read_whole() {
        let m = Messengers::bundled();
        assert_eq!(m.counts(), (14, 7, 26));
        assert!(m.is_telegrams(ip("149.154.167.51")));
        assert!(m.is_telegrams(ip("91.108.56.130")));
        assert!(m.is_telegrams(ip("2001:67c:4e8:f004::a")));
        assert!(!m.is_telegrams(ip("149.154.176.1")));
        assert!(!m.is_telegrams(ip("203.0.113.5")));
        assert!(
            m.clients()
                .any(|(f, p)| f == Family::Telegram && p == "org.telegram.messenger")
        );
        assert!(
            m.clients()
                .any(|(f, p)| f == Family::Signal && p == "org.thoughtcrime.securesms")
        );
    }

    #[test]
    fn a_name_matches_its_row_or_a_name_under_it() {
        let m = Messengers::bundled();
        assert_eq!(m.role(Family::Signal, "chat.signal.org"), Some(Role::Own));
        assert_eq!(m.role(Family::Signal, "Signal.org."), Some(Role::Own));
        assert_eq!(m.role(Family::Signal, "notsignal.org"), None);
        assert_eq!(m.role(Family::Signal, "www.google.com"), Some(Role::Front));
        assert_eq!(m.role(Family::Signal, "js.hcaptcha.com"), Some(Role::Other));
        assert_eq!(m.role(Family::WhatsApp, "g.whatsapp.net"), Some(Role::Own));
        assert_eq!(m.role(Family::WhatsApp, "signal.org"), None);
    }

    #[test]
    fn a_network_of_length_0_holds_every_address_of_its_version() {
        let m = Messengers::parse("0.0.0.0/0\n::/129\nnot\n", "", "");
        assert!(m.is_telegrams(ip("8.8.8.8")));
        assert!(!m.is_telegrams(ip("::1")));
        assert_eq!(m.counts(), (1, 0, 0));
    }
}
