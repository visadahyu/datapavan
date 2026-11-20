//! The encrypted ways Watch knows for the names of apps that go directly (W8, part 1, ADR 0042), from the signed
//! data pack: the Oblivious DoH relays and targets of `data/odoh` with the default pairs, and the DoH and DoT
//! resolvers of `data/dns-presets` that the user may choose. Watch's Kotlin side reads the pack and hands the
//! files' text over; this module reads it, so that one parser, fuzzed, decides what the engine uses.
//!
//! **The pair rule** (ADR 0042, "How it is built", point 4): a relay and a target form a pair only when they share
//! no operator, no person behind them, no jurisdiction, and no hosting network or CDN, read from the dataset's
//! fields, never from domain names. An entry whose person or jurisdictions the dataset does not know never pairs.
//!
//! Rows that do not parse are skipped, never fatal: the files are data, checked by `scripts/check.sh` and by the
//! tests below against the files as committed. Every function takes text a pack may carry, so none may panic
//! (`fuzz_targets/catalogue.rs`).

use crate::odoh::TargetKey;
use std::net::IpAddr;

/// An https URL as a way's endpoint names it: host, port and path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// The host, in lower case.
    pub host: String,
    /// The port, 443 unless the URL names one.
    pub port: u16,
    /// The path, `/` at least, without a query.
    pub path: String,
}

impl Url {
    /// Reads `https://host[:port][/path]`; `None` for any other scheme, a query or fragment, user information, a
    /// host that is not a name of letters, digits, hyphens and dots or an IPv4 address, or a path of other
    /// characters than RFC 3986's unreserved ones and `/` (W8's fix round, review S-m4: a target's path goes into
    /// the relay's URL as it is, and no path may add a parameter to it). Watch's screen checks the same.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("https://")?;
        let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
        if !plain_path(path) {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port.parse().ok()?),
            _ => (authority, 443),
        };
        if !valid_host(host) || port == 0 {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_owned(),
        })
    }

    /// The URL as text.
    #[must_use]
    pub fn text(&self) -> String {
        if self.port == 443 {
            format!("https://{}{}", self.host, self.path)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path)
        }
    }
}

/// Whether `path` starts with `/` and holds only RFC 3986's unreserved characters and `/`.
fn plain_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
}

/// Whether `host` is a name of letters, digits, hyphens and dots, at most 253 long.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Who stands behind a relay or a target, as the pair rule reads it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Behind {
    /// The operator, as it names itself.
    pub operator: String,
    /// The person or body behind it; empty where the dataset does not know.
    pub person: String,
    /// Jurisdictions (ISO 3166-1 alpha-2): its seat, its hosting company's, its CDN's.
    pub jurisdictions: Vec<String>,
    /// The hosting networks' AS numbers.
    pub hosting: Vec<u32>,
    /// The CDN's AS numbers in front, if any.
    pub cdn: Vec<u32>,
}

/// Why a relay and a target do not form a pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clash {
    /// One operator runs both.
    Operator,
    /// One person or body stands behind both.
    Person,
    /// Both fall under this jurisdiction.
    Jurisdiction(String),
    /// Both are hosted on, or behind, this network.
    Network(u32),
    /// The dataset does not know who stands behind one of them.
    Unknown,
}

impl Behind {
    /// Why `self` (a relay) and `target` cannot pair, or `None` when they can (the pair rule).
    #[must_use]
    pub fn clash(&self, target: &Self) -> Option<Clash> {
        if self.person.is_empty()
            || target.person.is_empty()
            || self.jurisdictions.is_empty()
            || target.jurisdictions.is_empty()
            || self.hosting.is_empty()
            || target.hosting.is_empty()
        {
            return Some(Clash::Unknown);
        }
        if self.operator.eq_ignore_ascii_case(&target.operator) {
            return Some(Clash::Operator);
        }
        if self.person.eq_ignore_ascii_case(&target.person) {
            return Some(Clash::Person);
        }
        if let Some(shared) = self
            .jurisdictions
            .iter()
            .find(|j| target.jurisdictions.contains(j))
        {
            return Some(Clash::Jurisdiction(shared.clone()));
        }
        let mine = self.hosting.iter().chain(&self.cdn);
        let theirs: Vec<u32> = target.hosting.iter().chain(&target.cdn).copied().collect();
        mine.into_iter()
            .find(|n| theirs.contains(n))
            .map(|n| Clash::Network(*n))
    }
}

/// An ODoH relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    /// Its id in the dataset.
    pub id: String,
    /// Its URL, which takes `targethost` and `targetpath` in its query.
    pub url: Url,
    /// Its addresses, so that it is reached without a lookup.
    pub addresses: Vec<IpAddr>,
    /// Who stands behind it.
    pub behind: Behind,
    /// SPKI pins (`sha256/…`) its certificate chain must match, if the dataset gives any.
    pub pins: Vec<String>,
}

/// An ODoH target.
#[derive(Clone, Debug)]
pub struct Target {
    /// Its id in the dataset.
    pub id: String,
    /// Its host, as `targethost` names it.
    pub host: String,
    /// Its path, as `targetpath` names it.
    pub path: String,
    /// Its own addresses, so that its configurations can be fetched without a lookup.
    pub addresses: Vec<IpAddr>,
    /// Who stands behind it.
    pub behind: Behind,
    /// Whether it filters answers (not offered by default).
    pub filters: bool,
    /// Its operator's own DoH, for asking that operator directly.
    pub doh: Option<Endpoint>,
    /// SPKI pins.
    pub pins: Vec<String>,
    /// Its key as the pack holds it, to begin with.
    pub key: Option<TargetKey>,
}

/// An ordinary encrypted resolver: DoH or DoT, at an endpoint reached by its addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// DoH or DoT.
    pub protocol: Protocol,
    /// The DoH URL; for DoT, `https://host[:port]/` holds its name and port (853 unless named).
    pub url: Url,
    /// Its addresses.
    pub addresses: Vec<IpAddr>,
    /// SPKI pins.
    pub pins: Vec<String>,
}

/// The protocol of an [`Endpoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// DNS over HTTPS (RFC 8484).
    Doh,
    /// DNS over TLS (RFC 7858).
    Dot,
}

/// A resolver the user may choose, with its card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    /// Its id in the dataset.
    pub id: String,
    /// The service's name.
    pub name: String,
    /// Its operator.
    pub operator: String,
    /// The operator's seat.
    pub country: String,
    /// Where and how it is reached.
    pub endpoint: Endpoint,
    /// What the operator says it logs.
    pub logging: String,
    /// Who examined that, and when; empty for no one.
    pub audit: String,
    /// What it filters; `none` for nothing.
    pub filtering: String,
    /// Its privacy policy's URL.
    pub policy: String,
}

/// Everything the datasets hold.
#[derive(Clone, Debug, Default)]
pub struct Catalogue {
    /// The relays.
    pub relays: Vec<Relay>,
    /// The targets.
    pub targets: Vec<Target>,
    /// The default pairs, as indices into `relays` and `targets`, in order; only pairs the rule allows.
    pub pairs: Vec<(usize, usize)>,
    /// The presets.
    pub presets: Vec<Preset>,
}

/// The rows of a table: `#` comments and blank lines left out, columns split at tabs.
fn rows(table: &str) -> impl Iterator<Item = Vec<&str>> {
    table
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').map(str::trim).collect())
}

/// A comma list, `-` for none.
fn list(column: &str) -> Vec<&str> {
    column
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "-")
        .collect()
}

/// A column that may be `-`: empty then.
fn text(column: &str) -> String {
    if column == "-" {
        String::new()
    } else {
        column.to_owned()
    }
}

fn addresses(v4: &str, v6: &str) -> Vec<IpAddr> {
    list(v4)
        .into_iter()
        .chain(list(v6))
        .filter_map(|a| a.parse().ok())
        .take(16)
        .collect()
}

fn asns(column: &str) -> Option<Vec<u32>> {
    list(column)
        .into_iter()
        .map(|a| a.strip_prefix("AS").and_then(|n| n.parse().ok()))
        .collect()
}

fn behind(
    operator: &str,
    person: &str,
    jurisdictions: &str,
    hosting: &str,
    cdn: &str,
) -> Option<Behind> {
    let jurisdictions: Vec<String> = list(jurisdictions)
        .into_iter()
        .map(str::to_ascii_uppercase)
        .collect();
    if jurisdictions
        .iter()
        .any(|j| j.len() != 2 || !j.bytes().all(|b| b.is_ascii_uppercase()))
    {
        return None;
    }
    Some(Behind {
        operator: text(operator),
        person: text(person),
        jurisdictions,
        hosting: asns(hosting)?,
        cdn: asns(cdn)?,
    })
}

fn pins(column: &str) -> Vec<String> {
    list(column)
        .into_iter()
        .filter(|p| p.starts_with("sha256/"))
        .map(str::to_owned)
        .collect()
}

/// Lower-case hex, as `configs` is written.
fn hex(column: &str) -> Option<Vec<u8>> {
    if !column.len().is_multiple_of(2) {
        return None;
    }
    (0..column.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(column.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The relays of `relays.tsv`, each id once.
fn read_relays(table: &str) -> Vec<Relay> {
    let mut relays: Vec<Relay> = Vec::new();
    for row in rows(table) {
        let [
            id,
            url,
            v4,
            v6,
            operator,
            person,
            jurisdictions,
            hosting,
            cdn,
            pin,
            ..,
        ] = row[..]
        else {
            continue;
        };
        let (Some(url), Some(behind)) = (
            Url::parse(url),
            behind(operator, person, jurisdictions, hosting, cdn),
        ) else {
            continue;
        };
        if relays.iter().any(|r| r.id == id) {
            continue;
        }
        relays.push(Relay {
            id: id.to_owned(),
            url,
            addresses: addresses(v4, v6),
            behind,
            pins: pins(pin),
        });
    }
    relays
}

/// The targets of `targets.tsv`, each id once.
fn read_targets(table: &str) -> Vec<Target> {
    let mut targets: Vec<Target> = Vec::new();
    for row in rows(table) {
        let [
            id,
            host,
            path,
            v4,
            v6,
            operator,
            person,
            jurisdictions,
            hosting,
            cdn,
            filtering,
            doh,
            doh4,
            doh6,
            pin,
            configs,
            ..,
        ] = row[..]
        else {
            continue;
        };
        let Some(behind) = behind(operator, person, jurisdictions, hosting, cdn) else {
            continue;
        };
        if !valid_host(host) || !plain_path(path) || targets.iter().any(|t| t.id == id) {
            continue;
        }
        let doh = Url::parse(doh).map(|url| Endpoint {
            protocol: Protocol::Doh,
            url,
            addresses: addresses(doh4, doh6),
            pins: pins(pin),
        });
        targets.push(Target {
            id: id.to_owned(),
            host: host.to_ascii_lowercase(),
            path: path.to_owned(),
            addresses: addresses(v4, v6),
            behind,
            filters: filtering != "no",
            doh,
            pins: pins(pin),
            key: hex(configs).and_then(|c| TargetKey::parse(&c)),
        });
    }
    targets
}

/// The presets of `presets.tsv`, each id once.
fn read_presets(table: &str) -> Vec<Preset> {
    let mut presets: Vec<Preset> = Vec::new();
    for row in rows(table) {
        let [
            id,
            name,
            operator,
            country,
            protocol,
            endpoint,
            v4,
            v6,
            logging,
            audit,
            filtering,
            policy,
            pin,
            ..,
        ] = row[..]
        else {
            continue;
        };
        let protocol = match protocol {
            "doh" => Protocol::Doh,
            "dot" => Protocol::Dot,
            _ => continue,
        };
        let url = match protocol {
            Protocol::Doh => Url::parse(endpoint),
            Protocol::Dot => dot_url(endpoint),
        };
        let Some(url) = url else { continue };
        if presets.iter().any(|p| p.id == id) {
            continue;
        }
        presets.push(Preset {
            id: id.to_owned(),
            name: name.to_owned(),
            operator: operator.to_owned(),
            country: country.to_owned(),
            endpoint: Endpoint {
                protocol,
                url,
                addresses: addresses(v4, v6),
                pins: pins(pin),
            },
            logging: text(logging),
            audit: text(audit),
            filtering: text(filtering),
            policy: text(policy),
        });
    }
    presets
}

impl Catalogue {
    /// Reads the four tables (`relays.tsv`, `targets.tsv`, `pairs.tsv` of `data/odoh`, `presets.tsv` of
    /// `data/dns-presets`). A pair the rule refuses, or that names an entry the tables lack, is left out.
    #[must_use]
    pub fn parse(relays: &str, targets: &str, pairs: &str, presets: &str) -> Self {
        let mut catalogue = Self {
            relays: read_relays(relays),
            targets: read_targets(targets),
            pairs: Vec::new(),
            presets: read_presets(presets),
        };
        catalogue.pairs =
            catalogue.pairs_of(pairs.lines().filter(|l| !l.starts_with('#')).map(|l| {
                let mut columns = l.split('\t').map(str::trim);
                (columns.next().unwrap_or(""), columns.next().unwrap_or(""))
            }));
        catalogue
    }

    /// The pairs named by ids, as indices, in order: each only once, and only where both are known, the target
    /// filters nothing and the rule allows them (W8's fix round, review S-m4: "unfiltered only" held here, not
    /// only on the screen).
    pub fn pairs_of<'a>(
        &self,
        named: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        for (relay, target) in named {
            let (Some(r), Some(t)) = (
                self.relays.iter().position(|x| x.id == relay),
                self.targets.iter().position(|x| x.id == target),
            ) else {
                continue;
            };
            if !self.targets[t].filters
                && self.relays[r]
                    .behind
                    .clash(&self.targets[t].behind)
                    .is_none()
                && !pairs.contains(&(r, t))
            {
                pairs.push((r, t));
            }
        }
        pairs
    }

    /// The pairs the user set, `relay>target` by commas, in place of the defaults: only those the rule allows.
    #[must_use]
    pub fn pairs_from(&self, spec: &str) -> Vec<(usize, usize)> {
        self.pairs_of(spec.split(',').filter_map(|p| p.trim().split_once('>')))
    }
}

/// A DoT endpoint, `host` or `host:port`, as a URL that holds its name and port.
#[must_use]
pub fn dot_url(endpoint: &str) -> Option<Url> {
    let (host, port) = match endpoint.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (endpoint, 853),
    };
    if !valid_host(host) || port == 0 {
        return None;
    }
    Some(Url {
        host: host.to_ascii_lowercase(),
        port,
        path: "/".to_owned(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const RELAYS: &str = include_str!("../../../data/odoh/relays.tsv");
    const TARGETS: &str = include_str!("../../../data/odoh/targets.tsv");
    const PAIRS: &str = include_str!("../../../data/odoh/pairs.tsv");
    const PRESETS: &str = include_str!("../../../data/dns-presets/presets.tsv");

    pub(crate) fn shipped() -> Catalogue {
        Catalogue::parse(RELAYS, TARGETS, PAIRS, PRESETS)
    }

    fn who(
        operator: &str,
        person: &str,
        jurisdictions: &[&str],
        hosting: &[u32],
        cdn: &[u32],
    ) -> Behind {
        Behind {
            operator: operator.into(),
            person: person.into(),
            jurisdictions: jurisdictions.iter().map(|j| (*j).to_owned()).collect(),
            hosting: hosting.to_vec(),
            cdn: cdn.to_vec(),
        }
    }

    #[test]
    fn the_shipped_tables_read_whole_and_both_default_pairs_pass_the_rule() {
        let c = shipped();
        assert_eq!(c.relays.len(), 2);
        assert_eq!(c.targets.len(), 6);
        assert!(
            c.targets.iter().all(|t| t.key.is_some()),
            "every target's key reads"
        );
        assert_eq!(c.presets.len(), 12);
        let named: Vec<(&str, &str)> = c
            .pairs
            .iter()
            .map(|&(r, t)| (c.relays[r].id.as_str(), c.targets[t].id.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                ("numa", "cloudflare"),
                ("crypto-sx-fastly", "dnscry-pt-fra01")
            ]
        );
    }

    /// Review S-m4: a target that filters never pairs, whoever names the pair; nor one whose path would add a
    /// parameter to the relay's URL.
    #[test]
    fn a_filtering_target_or_a_path_with_a_parameter_never_pairs() {
        // The shipped tables with one field of fra01's row changed.
        let changed = |field: usize, value: &str| {
            let rows: Vec<String> = TARGETS
                .lines()
                .map(|line| {
                    if !line.starts_with("dnscry-pt-fra01\t") {
                        return line.to_owned();
                    }
                    let mut fields: Vec<&str> = line.split('\t').collect();
                    fields[field] = value;
                    fields.join("\t")
                })
                .collect();
            Catalogue::parse(RELAYS, &rows.join("\n"), PAIRS, PRESETS)
        };
        assert_eq!(
            shipped()
                .pairs_from("crypto-sx-fastly>dnscry-pt-fra01")
                .len(),
            1
        );
        let filtering = changed(10, "malware");
        assert!(filtering.targets.iter().any(|t| t.id == "dnscry-pt-fra01"));
        assert_eq!(filtering.pairs_from("crypto-sx-fastly>dnscry-pt-fra01"), []);
        let other = changed(2, "/dns-query&targethost=other.test");
        assert!(other.targets.iter().all(|t| t.id != "dnscry-pt-fra01"));
    }

    #[test]
    fn the_rule_refuses_one_operator_person_jurisdiction_network_or_cdn() {
        let relay = who("Relay Co", "A Person", &["DE"], &[24940], &[]);
        let fine = who("Target Co", "B Person", &["US"], &[13335], &[13335]);
        assert_eq!(relay.clash(&fine), None);
        assert_eq!(
            relay.clash(&who("relay co", "B", &["US"], &[1], &[])),
            Some(Clash::Operator)
        );
        assert_eq!(
            relay.clash(&who("T", "a person", &["US"], &[1], &[])),
            Some(Clash::Person)
        );
        assert_eq!(
            relay.clash(&who("T", "B", &["US", "DE"], &[1], &[])),
            Some(Clash::Jurisdiction("DE".into()))
        );
        assert_eq!(
            relay.clash(&who("T", "B", &["US"], &[24940], &[])),
            Some(Clash::Network(24940))
        );
        // A relay on a CDN's network and a target behind the same CDN.
        let fastly = who("R", "P", &["FR", "US"], &[54113], &[54113]);
        assert_eq!(
            fastly.clash(&who("T", "B", &["NO"], &[2], &[54113])),
            Some(Clash::Network(54113))
        );
        // Both behind one CDN, though hosted apart.
        let fronted = who("R", "P", &["FR"], &[1], &[13335]);
        assert_eq!(
            fronted.clash(&who("T", "B", &["NO"], &[2], &[13335])),
            Some(Clash::Network(13335))
        );
        assert_eq!(
            relay.clash(&who("T", "", &["US"], &[1], &[])),
            Some(Clash::Unknown)
        );
        let fine = who("T", "B", &["US"], &[1], &[]);
        assert_eq!(
            who("R", "", &["DE"], &[2], &[]).clash(&fine),
            Some(Clash::Unknown),
            "the relay's side too"
        );
        assert_eq!(
            relay.clash(&who("T", "B", &[], &[1], &[])),
            Some(Clash::Unknown)
        );
        assert_eq!(
            relay.clash(&who("T", "B", &["US"], &[], &[])),
            Some(Clash::Unknown)
        );
    }

    #[test]
    fn the_rule_reads_fields_not_names() {
        // Two endpoints under one registrable domain but different operators pass; a check by domain would not.
        let c = shipped();
        let numa = c.relays.iter().position(|r| r.id == "numa");
        let fra = c.targets.iter().position(|t| t.id == "dnscry-pt-fra01");
        let (Some(numa), Some(fra)) = (numa, fra) else {
            unreachable!("in the tables")
        };
        // Numa and dnscry.pt are both in Germany: refused by jurisdiction.
        assert_eq!(
            c.relays[numa].behind.clash(&c.targets[fra].behind),
            Some(Clash::Jurisdiction("DE".into()))
        );
        assert_eq!(c.pairs_from("numa>dnscry-pt-fra01"), vec![]);
        assert_eq!(
            c.pairs_from("numa>cloudflare, numa>nowhere"),
            vec![(numa, 0)]
        );
    }

    #[test]
    fn urls_read_and_refuse() {
        assert_eq!(
            Url::parse("https://relay.dnslab.test:18440/proxy"),
            Some(Url {
                host: "relay.dnslab.test".into(),
                port: 18440,
                path: "/proxy".into()
            })
        );
        assert_eq!(Url::parse("https://a.b").map(|u| u.path), Some("/".into()));
        assert!(Url::parse("http://a.b/").is_none());
        assert!(Url::parse("https://a.b/x?y=1").is_none());
        assert!(Url::parse("https://user@a.b/").is_none());
        assert!(Url::parse("https://a..b/").is_none());
        // Review S-m4 and the screen's nit: nothing but unreserved characters in a path, no IPv6 literal.
        for refused in [
            "https://a.b/dns-query&targethost=other.test",
            "https://a.b/dns-query\nchoice odoh",
            "https://a.b/x y",
            "https://a.b/%2e",
            "https://[2001:db8::1]/dns-query",
            "https://a.b/x#y",
        ] {
            assert!(Url::parse(refused).is_none(), "{refused:?}");
        }
        assert!(Url::parse("https://dns.example/dns-query/ab_1.2~c-d").is_some());
        assert_eq!(dot_url("dns.quad9.net").map(|u| u.port), Some(853));
        assert_eq!(
            dot_url("dot.dnslab.test:18444").map(|u| u.port),
            Some(18444)
        );
    }
}
