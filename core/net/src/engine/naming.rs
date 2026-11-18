//! What names a flow: the DNS answers Watch passed on, the TLS or QUIC server name of its first bytes,
//! the organisation behind the destination's network, and whether it is an app's own DNS.

use super::{Counters, DnsUse, Ech, Flow, NamedBy, Network, Opened, Shared, lock};
use crate::dns;
use crate::owners::NetworkKind;
use crate::standins::is_stand_in;
use crate::tls::Hello;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// A new flow's number and first name.
pub(super) struct Begun {
    pub(super) id: u64,
    pub(super) name: Option<String>,
    pub(super) named_by: NamedBy,
    pub(super) network: Option<Network>,
}

impl Shared {
    /// A new flow's number and its first name: from the DNS answers the app was given, else from the
    /// organisation of the destination's network, as the company people know when the owners' table
    /// names it. A TLS or QUIC server name read later names it instead ([`NamedBy`]).
    pub(super) fn begin(&self, destination: SocketAddr, uid: Option<u32>) -> Begun {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        // A stand-in is named by the lookup it answered (ADR 0038), and has no network of its own.
        if is_stand_in(destination.ip()) {
            let name = lock(&self.stand_ins).name(destination.ip());
            let named_by = if name.is_some() {
                NamedBy::Dns
            } else {
                NamedBy::Unknown
            };
            return Begun {
                id,
                name,
                named_by,
                network: None,
            };
        }
        if let Some(name) = lock(&self.names).get(destination.ip(), uid, Instant::now()) {
            return Begun {
                id,
                name: Some(name.to_owned()),
                named_by: NamedBy::Dns,
                network: None,
            };
        }
        match self
            .organisations
            .as_ref()
            .and_then(|table| table.lookup(destination.ip()))
        {
            Some(organisation) => {
                let owner = self.owners.of(organisation.asn);
                Begun {
                    id,
                    network: Some(Network {
                        asn: organisation.asn,
                        kind: owner.map_or(NetworkKind::Unlisted, |o| o.kind),
                    }),
                    name: Some(owner.map_or(organisation.name, |o| o.name.clone())),
                    named_by: NamedBy::Organisation,
                }
            }
            None => Begun {
                id,
                name: None,
                named_by: NamedBy::Unknown,
                network: None,
            },
        }
    }

    /// Whether a flow to `destination`, named `name` by DNS if at all, carries the app's own DNS, and
    /// to which known resolver: port 53 to another server than Watch's, port 853, or port 443 to a
    /// known resolver's address or host name.
    pub(super) fn dns_use(
        &self,
        destination: SocketAddr,
        name: Option<&str>,
    ) -> (DnsUse, Option<String>) {
        let known = self
            .resolvers
            .at(destination.ip())
            .or_else(|| name.and_then(|n| self.resolvers.named(n)))
            .map(str::to_owned);
        match destination.port() {
            53 if !self.is_tunnel_dns(destination.ip()) => (DnsUse::Plain, known),
            853 => (DnsUse::Encrypted, known),
            443 if known.is_some() => (DnsUse::Encrypted, known),
            _ => (DnsUse::None, None),
        }
    }

    /// Notes what a flow's TLS or QUIC hello said: its server name names the flow by W3's order
    /// ([`NamedBy`]), and a DNS name it differs from stays beside it, unless it is the public name of
    /// an ECH configuration, behind which the real name is hidden: a DNS name stays the flow's then. A
    /// flow the organisation table named, or none, takes the hello's name too: its network, the AS
    /// number and what its owner is, stays in the flow and its records, while the organisation's name,
    /// which names who runs the network rather than the server, gives way, as before. A chained app's
    /// flow, whose destination stays out of the log, takes no name in it. A known resolver's host name
    /// marks the flow as the app's own encrypted DNS.
    ///
    /// The log's segments are cut first, at any quarter hour passed, so that a segment of a quarter hour
    /// before keeps the name the flow had then, whoever cuts it.
    pub(super) fn hello(&self, opened: Opened, hello: &Hello, by: NamedBy) {
        self.log_now();
        let id = opened.id;
        let hidden =
            hello.ech && lock(&self.names).is_public(&hello.name, opened.uid, Instant::now());
        let resolver = matches!(opened.port, 443 | 853)
            .then(|| self.resolvers.named(&hello.name))
            .flatten()
            .map(str::to_owned);
        let counters = &self.counters;
        if resolver.is_some() && opened.dns == DnsUse::None {
            Counters::add(&counters.dns_encrypted, 1);
        }
        Counters::add(
            if by == NamedBy::Quic {
                &counters.quic_names
            } else {
                &counters.tls_names
            },
            1,
        );
        if hello.ech {
            Counters::add(&counters.ech_offered, 1);
        }
        if hidden {
            Counters::add(&counters.ech_hidden, 1);
        }
        // Finding 20's first step: how often the name a DNS answer gave the flow's address differs from
        // the one the connection itself sent. Only counted, never logged: it names no destination. An
        // ECH public name differs by design and is left out.
        if !hidden
            && let Some(live) = lock(&self.live).get(&id)
            && live.flow.named_by == NamedBy::Dns
            && let Some(dns) = &live.flow.name
        {
            Counters::add(&counters.hellos_on_dns_names, 1);
            if !same_name(dns, &hello.name) {
                Counters::add(&counters.hello_names_differ, 1);
            }
        }
        let apply = |flow: &mut Flow| {
            flow.ech = match (hello.ech, hidden) {
                (_, true) => Ech::Hidden,
                (true, false) => Ech::Offered,
                (false, false) => Ech::Absent,
            };
            if let Some(resolver) = &resolver {
                flow.dns = DnsUse::Encrypted;
                flow.resolver.get_or_insert_with(|| resolver.clone());
            }
            if !hidden && flow.named_by.yields_to(by) {
                // Finding 20: a DNS name the connection's own differs from stays beside it.
                if flow.named_by == NamedBy::Dns
                    && let Some(dns) = flow.name.take()
                    && !same_name(&dns, &hello.name)
                {
                    flow.dns_name = Some(dns);
                }
                flow.name = Some(written(&hello.name));
                flow.named_by = by;
            }
        };
        if let Some(live) = lock(&self.live).get_mut(&id)
            && !live.hidden
        {
            apply(&mut live.flow);
        }
        if self.keep_flows > 0
            && let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
        {
            apply(flow);
        }
    }

    /// Learns the names in a DNS answer passed back to an app, and the public names of its ECH
    /// configurations: for every app's flows from Android's resolver, or for one app's flows from a
    /// resolver of its own, so that no app can rename or hide another's flows (ADR 0038).
    pub(super) fn learn(&self, answer: &[u8], scope: Option<u32>) {
        if let Some(response) = dns::response(answer) {
            let now = Instant::now();
            let mut names = lock(&self.names);
            for (address, ttl) in response.addresses {
                names.insert(address, scope, &response.question, ttl, now);
            }
            for (public, ttl) in response.public_names {
                names.insert_public(&public, scope, ttl, now);
            }
        }
    }
}

/// A host name as a flow keeps it: in lower case, without the trailing dot that only marks it as fully
/// qualified, so that one server is one name in the log, however the app spelled it (review 1 of W5's
/// first part, names, finding 11). A name of dots alone stays as it is.
fn written(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() { name } else { trimmed }.to_ascii_lowercase()
}

/// Whether two host names are the same name: DNS names ignore case, and a trailing dot only marks a name
/// as fully qualified.
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flow_keeps_a_host_name_in_lower_case_without_its_trailing_dot() {
        assert_eq!(written("WWW.Example.COM."), "www.example.com");
        assert_eq!(written("cdn.example.net"), "cdn.example.net");
        assert_eq!(written("."), ".");
        assert!(same_name("WWW.Example.COM.", "www.example.com"));
    }
}
