//! The companies behind well-known networks, from `data/owners/asns.tsv` and `entities.tsv` (CC0, each row
//! with its evidence; ADR 0036, decision 4), so that a flow named by its network's organisation shows the
//! company people know rather than the registry's name ("Meta Platforms, Inc.", not "Facebook, Inc."),
//! and says whether that network also hosts other companies' servers: then the network is named, not
//! the service the app used.
//!
//! The tables are compiled into the engine. Rows that do not parse are skipped, never fatal: the tables
//! are data, checked by `scripts/check.sh`.

use std::collections::HashMap;

const ENTITIES: &str = include_str!("../../../data/owners/entities.tsv");
const ASNS: &str = include_str!("../../../data/owners/asns.tsv");

/// What Watch knows of a network's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    /// A company's own network: it sells no hosting, so its servers are its own.
    Own,
    /// A company that sells cloud, CDN or hosting services: a server there may be another company's.
    Hosting,
    /// Not in the table: only the registry's name is known.
    Unlisted,
}

/// A network's owner, as the table names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    /// The company's name, from `entities.tsv`.
    pub name: String,
    /// Whether it hosts other companies' servers.
    pub kind: NetworkKind,
}

/// Owners by AS number.
#[derive(Debug, Default)]
pub struct Owners {
    by_asn: HashMap<u32, Owner>,
}

impl Owners {
    /// The tables compiled into the engine.
    #[must_use]
    pub fn bundled() -> Self {
        Self::parse(ENTITIES, ASNS)
    }

    /// Reads `entities.tsv` (entity, name, ...) and `asns.tsv` (asn, entity, hosting, ...): `#`
    /// comments, then tab-separated rows. An AS whose entity is unknown is skipped.
    #[must_use]
    pub fn parse(entities: &str, asns: &str) -> Self {
        let names: HashMap<&str, &str> = rows_of(entities)
            .filter_map(|columns| Some((*columns.first()?, *columns.get(1)?)))
            .collect();
        let mut by_asn = HashMap::new();
        for columns in rows_of(asns) {
            let (Some(asn), Some(entity), Some(hosting)) =
                (columns.first(), columns.get(1), columns.get(2))
            else {
                continue;
            };
            let (Ok(asn), Some(name)) = (asn.parse::<u32>(), names.get(entity)) else {
                continue;
            };
            let kind = match *hosting {
                "no" => NetworkKind::Own,
                _ => NetworkKind::Hosting,
            };
            by_asn.insert(
                asn,
                Owner {
                    name: (*name).to_owned(),
                    kind,
                },
            );
        }
        Self { by_asn }
    }

    /// The owner of AS `asn`, if the table names one.
    #[must_use]
    pub fn of(&self, asn: u32) -> Option<&Owner> {
        self.by_asn.get(&asn)
    }

    /// How many AS numbers the table names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_asn.len()
    }

    /// Whether the table names none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_asn.is_empty()
    }
}

/// The rows of a table: `#` comments and blank lines left out, each row split at tabs.
fn rows_of(table: &str) -> impl Iterator<Item = Vec<&str>> {
    table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_company_and_whether_it_hosts_others() {
        let entities = "# entity\tname\n\
            sample\tSample Platforms, Inc.\tQ1\t-\n\
            cloudy\tCloudy Corp.\tQ2\t-\n";
        let asns = "# asn\tentity\thosting\n\
            64500\tsample\tno\tSAMPLE / Sample, Inc.\n\
            64501\tcloudy\tyes\tCLOUDY / Cloudy\n\
            64502\tnobody\tno\tunknown entity\n\
            not-a-number\tsample\tno\n";
        let owners = Owners::parse(entities, asns);
        assert_eq!(
            owners.of(64500),
            Some(&Owner {
                name: "Sample Platforms, Inc.".into(),
                kind: NetworkKind::Own,
            })
        );
        assert_eq!(owners.of(64501).map(|o| o.kind), Some(NetworkKind::Hosting));
        assert_eq!(owners.of(64502), None);
        assert_eq!(owners.len(), 2);
    }

    #[test]
    fn the_bundled_tables_name_every_listed_network() {
        let listed = rows_of(ASNS).count();
        assert_eq!(
            Owners::bundled().len(),
            listed,
            "an AS row names an unknown entity"
        );
    }
}
