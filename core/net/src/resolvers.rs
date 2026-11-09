//! Well-known public DNS resolvers, from `data/resolvers/resolvers.tsv` (CC0, each value with its
//! operator's own page in `sources.tsv`), so that Watch can say when an app sends its own DNS to one of
//! them, past the phone's settings (W3, ADR 0029): plain DNS to one of its addresses, or DNS over HTTPS
//! to one of its host names or addresses.
//!
//! The table is compiled into the engine. Rows that do not parse are skipped, never fatal: the table
//! is data, checked by `scripts/check.sh`.

use std::collections::HashMap;
use std::net::IpAddr;

/// The table as the build found it.
const BUNDLED: &str = include_str!("../../../data/resolvers/resolvers.tsv");

/// Resolvers by address and by host name, each giving the resolver's id (`google`, `quad9`).
#[derive(Debug, Default)]
pub struct Resolvers {
    by_address: HashMap<IpAddr, String>,
    by_host: HashMap<String, String>,
}

impl Resolvers {
    /// The table compiled into the engine.
    #[must_use]
    pub fn bundled() -> Self {
        Self::parse(BUNDLED)
    }

    /// Reads a table: `#` comments, then one row per resolver of tab-separated columns id, operator,
    /// service, DNS-over-HTTPS hosts, DNS-over-TLS hosts, IPv4 addresses, IPv6 addresses, note.
    /// Lists are comma separated, and `-` is none.
    #[must_use]
    pub fn parse(table: &str) -> Self {
        let mut resolvers = Self::default();
        for line in table
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let columns: Vec<&str> = line.split('\t').collect();
            let [id, _operator, _service, doh, dot, v4, v6, ..] = columns[..] else {
                continue;
            };
            let values = |column: &'_ str| -> Vec<String> {
                column
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty() && *v != "-")
                    .map(str::to_ascii_lowercase)
                    .collect()
            };
            for host in values(doh).into_iter().chain(values(dot)) {
                share(&mut resolvers.by_host, host, id);
            }
            for address in values(v4).into_iter().chain(values(v6)) {
                if let Ok(address) = address.parse::<IpAddr>() {
                    share(&mut resolvers.by_address, address, id);
                }
            }
        }
        resolvers
    }

    /// The resolver at `address`, if it is one. Where several services of one operator share a value
    /// (one DNS-over-HTTPS host with a path for each filter), it names their common start, as
    /// `controld` for `controld-malware` and `controld-family`.
    #[must_use]
    pub fn at(&self, address: IpAddr) -> Option<&str> {
        self.by_address.get(&address).map(String::as_str)
    }

    /// The resolver with the host name `host` (lower case), if it is one.
    #[must_use]
    pub fn named(&self, host: &str) -> Option<&str> {
        self.by_host.get(host).map(String::as_str)
    }

    /// How many addresses and host names the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len() + self.by_host.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Gives `key` the id `id`, or the part before a dash that it shares with the id it already has.
fn share<K: std::hash::Hash + Eq>(map: &mut HashMap<K, String>, key: K, id: &str) {
    let shared = match map.get(&key) {
        None => id.to_owned(),
        Some(old) if old == id => return,
        Some(old) => {
            let common: Vec<&str> = old
                .split('-')
                .zip(id.split('-'))
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect();
            if common.is_empty() {
                old.clone()
            } else {
                common.join("-")
            }
        }
    };
    map.insert(key, shared);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn reads_hosts_and_addresses_and_skips_what_does_not_parse() {
        let table = "# a comment\n\
            sample\tSample Inc.\tSample DNS\tdns.Sample.example\t-\t192.0.2.53, 192.0.2.54\t2001:db8::53\t-\n\
            broken\tonly three\tcolumns\n\
            other\tOther\tOther DNS\t-\tdot.other.example\tnot-an-address\t-\tnote\n";
        let resolvers = Resolvers::parse(table);
        assert_eq!(resolvers.named("dns.sample.example"), Some("sample"));
        assert_eq!(resolvers.named("dot.other.example"), Some("other"));
        assert_eq!(
            resolvers.at(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54))),
            Some("sample")
        );
        assert_eq!(
            resolvers.at(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53
            ))),
            Some("sample")
        );
        assert_eq!(resolvers.named("columns"), None);
        assert_eq!(resolvers.len(), 5);
    }

    #[test]
    fn a_value_shared_by_one_operators_services_names_the_operator() {
        let table = "op-a\tOp\tA\tdoh.op.example\t-\t-\t-\t-\n\
            op-b\tOp\tB\tdoh.op.example\t-\t192.0.2.1\t-\t-\n\
            other\tOther\tO\t-\t-\t192.0.2.1\t-\t-\n";
        let resolvers = Resolvers::parse(table);
        assert_eq!(resolvers.named("doh.op.example"), Some("op"));
        assert_eq!(
            resolvers.at(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some("op-b")
        );
    }

    #[test]
    fn the_bundled_table_parses_every_row() {
        let rows = BUNDLED
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        let resolvers = Resolvers::bundled();
        assert!(rows == 0 || !resolvers.is_empty());
        for line in BUNDLED
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            assert_eq!(
                line.split('\t').count(),
                8,
                "a row of eight columns: {line}"
            );
        }
    }
}
