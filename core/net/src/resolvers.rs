//! Well-known public DNS resolvers, from `data/resolvers/resolvers.tsv` (CC0, each value with its
//! operator's own page in `sources.tsv`), so that the network part can say when an app sends its own DNS to one of
//! them, past the phone's settings (W3, ADR 0045, decision 11): plain DNS to one of its addresses, or DNS over HTTPS
//! to one of its host names or addresses.
//!
//! The table is compiled into the engine, deflated (`build.rs`), and inflated where it is read. Rows that do not parse
//! are skipped, never fatal: the table is data, checked by `scripts/check.sh`. A table that does not inflate stops the
//! engine (`crate::bundled`): that is a damaged library, not data.

use std::collections::HashMap;
use std::net::IpAddr;

/// The table as the build found it, deflated (`build.rs`).
const BUNDLED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/resolvers-resolvers.tsv.deflate"));

/// Resolvers by address and by host name, each giving the resolver's id (`google`, `quad9`).
#[derive(Debug)]
pub struct Resolvers {
    by_address: HashMap<IpAddr, String>,
    by_host: HashMap<String, String>,
}

impl Default for Resolvers {
    fn default() -> Self {
        Self {
            by_address: crate::map(),
            by_host: crate::map(),
        }
    }
}

impl Resolvers {
    /// The table compiled into the engine.
    #[must_use]
    pub fn bundled() -> Self {
        Self::parse(&crate::bundled(BUNDLED))
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
    if let Some(shared) = shared_id(map.get(&key).map(String::as_str), id) {
        map.insert(key, shared);
    }
}

/// The id [`share`] gives a key whose id is `old`, or `None` where the key keeps it: `id` for a key with none; the part
/// before a dash that `old` and `id` share; nothing new where `old` is `id` or shares no part with it. Out of line and
/// not generic, so that the map of host names and that of addresses share one copy of it, where each built its own
/// (the cold paths' fourth pass, ADR 0053).
#[inline(never)]
fn shared_id(old: Option<&str>, id: &str) -> Option<String> {
    let Some(old) = old else {
        return Some(id.to_owned());
    };
    if old == id {
        return None;
    }
    let common: Vec<&str> = old
        .split('-')
        .zip(id.split('-'))
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    (!common.is_empty()).then(|| common.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The table's text, as the build found it (`build.rs` deflates it).
    const TEXT: &str = include_str!("../../../data/resolvers/resolvers.tsv");

    #[test]
    fn the_deflated_table_inflates_to_the_file() {
        assert_eq!(crate::bundled(BUNDLED), TEXT);
    }

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

    /// `share` as it was before its body went out of line (the cold paths' fourth pass).
    fn share_before<K: std::hash::Hash + Eq>(map: &mut HashMap<K, String>, key: K, id: &str) {
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

    /// `share` leaves the map its old body left: every id of one to four dash-separated parts of `a`, `b` and `ab`
    /// (120) given to a key after every other, in both orders, and every three of the 30 ids of `a` and `b` in turn.
    #[test]
    fn a_shared_id_is_the_old_share_s() {
        let mut ids: Vec<String> = vec![String::new()];
        let mut all = Vec::new();
        for _ in 0..4 {
            ids = ids
                .iter()
                .flat_map(|id| {
                    ["a", "b", "ab"].map(|part| {
                        if id.is_empty() {
                            part.to_owned()
                        } else {
                            format!("{id}-{part}")
                        }
                    })
                })
                .collect();
            all.extend(ids.iter().cloned());
        }
        assert_eq!(all.len(), 120);
        let check = |given: &[&String]| {
            let (mut before, mut after) = (HashMap::new(), HashMap::new());
            for id in given {
                share_before(&mut before, 7u8, id);
                share(&mut after, 7u8, id);
                assert_eq!(after, before, "{given:?}");
            }
        };
        for x in &all {
            for y in &all {
                check(&[x, y]);
            }
        }
        let short: Vec<&String> = all.iter().filter(|id| !id.contains("ab")).collect();
        assert_eq!(short.len(), 30);
        for x in &short {
            for y in &short {
                for z in &short {
                    check(&[x, y, z]);
                }
            }
        }
    }

    #[test]
    fn the_bundled_table_parses_every_row() {
        let rows = TEXT
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        let resolvers = Resolvers::bundled();
        assert!(rows == 0 || !resolvers.is_empty());
        for line in TEXT
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
