//! What names a flow: the DNS answers the network part passed on, the TLS or QUIC server name of its first bytes,
//! the organisation behind the destination's network, and whether it is an app's own DNS.

use super::{Counters, DnsUse, Ech, Flow, NamedBy, Network, Opened, Shared, lock};
use crate::dns;
use crate::owners::NetworkKind;
use crate::standins::is_stand_in;
use crate::tls::Hello;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// A new flow's number and first name.
pub(super) struct Begun {
    pub(super) id: u64,
    pub(super) name: Option<String>,
    pub(super) named_by: NamedBy,
    pub(super) network: Option<Network>,
    /// Until when, in time since the phone started, the DNS name is held ([`Opened::dns_held_until`]).
    pub(super) held_until: Duration,
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
                held_until: Duration::MAX,
            };
        }
        if let Some((name, held_until)) =
            lock(&self.names).get_held(destination.ip(), uid, Instant::now())
        {
            return Begun {
                id,
                name: Some(name.to_owned()),
                named_by: NamedBy::Dns,
                network: None,
                held_until,
            };
        }
        match self.organisation(destination.ip()) {
            Some((network, name)) => Begun {
                id,
                network: Some(network),
                name: Some(name),
                named_by: NamedBy::Organisation,
                held_until: Duration::ZERO,
            },
            None => Begun {
                id,
                name: None,
                named_by: NamedBy::Unknown,
                network: None,
                held_until: Duration::ZERO,
            },
        }
    }

    /// The network of `address` and the organisation behind it, as the company people know where the
    /// owners' table names it, if the network part has the organisation table and it names the address.
    pub(super) fn organisation(&self, address: IpAddr) -> Option<(Network, String)> {
        let organisation = self
            .organisations
            .as_ref()
            .and_then(|table| table.lookup(address))?;
        let owner = self.owners.of(organisation.asn);
        Some((
            Network {
                asn: organisation.asn,
                kind: owner.map_or(NetworkKind::Unlisted, |o| o.kind),
            },
            owner.map_or(organisation.name, |o| o.name.clone()),
        ))
    }

    /// Whether a flow to `destination`, named `name` by DNS if at all, carries the app's own DNS, and
    /// to which known resolver: port 53 to another server than the network part's, port 853, or port 443 to a
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
    /// flow, whose destination stays out of the log, takes no name in it.
    ///
    /// A DNS name stands beside the connection's own only while the answer that named the flow is held,
    /// in time since the phone started, as the flow carries it from its start
    /// ([`Opened::dns_held_until`]): a stand-in's always. A name kept through a night on the monotonic
    /// clock still names a flow that sends no name of its own, but beside another it would show its age as
    /// a difference (review 1 of W5's first part, engine, finding 7); a later answer for the address
    /// does not end it (review 2).
    ///
    /// The mark of the app's own DNS follows the name that names the flow: renamed by its hello, the flow
    /// is marked again from its port, its address and the hello's name, so that a mark its DNS name alone
    /// gave goes with that name; a flow the hello does not rename may gain a mark from the hello's name
    /// (review 1 of W5's first part, names, finding 10).
    ///
    /// The counter of flows of an app's own encrypted DNS moves by what the hello does to the live flow,
    /// as in release builds, never by the flows kept for debug builds and tests (review 2 of W5's first
    /// part, of the fixes, nit 4).
    ///
    /// The hello's name is read written as a flow keeps it, without a trailing dot, for every use: the
    /// flow's name, ECH's public names and the known resolvers (review 2, of the fixes, nit 5).
    ///
    /// The log's segments are cut first, at any quarter hour passed, so that a segment of a quarter hour
    /// before keeps the name the flow had then, whoever cuts it.
    pub(super) fn hello(&self, opened: Opened, hello: &Hello, by: NamedBy) {
        self.log_now();
        // R10's tie at the hello (review-D-engine major 1): a flow of the chained tool whose hello names what the chain
        // asked the tool for. It only strips the flow's records under the tool's choice. The cheap test first.
        if self
            .chain()
            .is_some_and(|chain| opened.uid == Some(chain.tool))
        {
            self.tie_at_hello(&opened, &hello.name);
        }
        let id = opened.id;
        let own = written(&hello.name);
        let hidden = hello.ech && lock(&self.names).is_public(&own, opened.uid, Instant::now());
        let resolver = matches!(opened.port, 443 | 853)
            .then(|| self.resolvers.named(&own))
            .flatten()
            .map(str::to_owned);
        let Renaming {
            renames,
            beside,
            mark,
            live,
        } = self.renaming(&opened, hello, by, hidden, &own);
        let counters = &self.counters;
        let encrypted = match &mark {
            Some((dns, _)) if live => *dns == DnsUse::Encrypted,
            _ => resolver.is_some() || opened.dns == DnsUse::Encrypted,
        };
        // A hello that names nothing (C1, below) moves no flow's mark, so not the counter of them either (review A,
        // engine, note 10).
        let unkept = lock(&self.live).get(&id).is_some_and(|l| l.unkept);
        match (opened.dns == DnsUse::Encrypted, encrypted) {
            (false, true) if !unkept => Counters::add(&counters.dns_encrypted, 1),
            (true, false) if !unkept => Counters::take_back(&counters.dns_encrypted, 1),
            _ => {}
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
            && !live.unkept
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
            match &mark {
                Some((dns, known)) => (flow.dns, flow.resolver) = (*dns, known.clone()),
                None => {
                    if let Some(resolver) = &resolver {
                        flow.dns = DnsUse::Encrypted;
                        flow.resolver.get_or_insert_with(|| resolver.clone());
                    }
                }
            }
            if renames && flow.named_by.yields_to(by) {
                // Finding 20: a current DNS name the connection's own differs from stays beside it.
                if flow.named_by == NamedBy::Dns {
                    flow.dns_name.clone_from(&beside);
                }
                flow.name = Some(own.clone());
                flow.named_by = by;
            }
        };
        let (mut hidden_proxy, mut unkept) = (false, false);
        if let Some(live) = lock(&self.live).get_mut(&id) {
            if live.hidden {
                hidden_proxy = live.flow.proxy.is_some();
            } else if live.unkept {
                // C1: an app's own proxy named without where it was asked to go is named by no hello after, the
                // inner one included, live or kept. Read under the lock that names, so that a switch turned off
                // in between cannot let the hello name it.
                unkept = true;
            } else {
                apply(&mut live.flow);
            }
        }
        // A proxied flow left out for "Log where these apps connect" takes no name, but the trackers its hello
        // names still mark it, as its company only (ADR 0052, the fix round's S-M1).
        if hidden_proxy || unkept {
            self.mark_proxied(id, &own, opened.port);
        }
        if !unkept
            && self.keep_flows > 0
            && let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id)
        {
            apply(flow);
        }
    }

    /// What a hello does to the names of the flow `opened` ([`Shared::hello`]), its own name written
    /// `own`, from the flow as it is: the live one, or the one kept for debug builds and tests where the
    /// live one hides its destination or is none, which says so (`live` false).
    fn renaming(
        &self,
        opened: &Opened,
        hello: &Hello,
        by: NamedBy,
        hidden: bool,
        own: &str,
    ) -> Renaming {
        let from_live = lock(&self.live)
            .get(&opened.id)
            .filter(|live| !live.hidden)
            .map(|live| {
                (
                    live.flow.destination,
                    live.flow.named_by,
                    live.flow.name.clone(),
                )
            });
        let live = from_live.is_some();
        let state = from_live.or_else(|| {
            lock(&self.flows)
                .iter()
                .rev()
                .find(|flow| flow.id == opened.id)
                .map(|flow| (flow.destination, flow.named_by, flow.name.clone()))
        });
        let renames = !hidden
            && state
                .as_ref()
                .is_some_and(|(_, named_by, _)| named_by.yields_to(by));
        let beside = match &state {
            Some((_, NamedBy::Dns, Some(dns)))
                if renames
                    && !same_name(dns, &hello.name)
                    && opened.dns_held_until > self.clock.since_boot() =>
            {
                Some(dns.clone())
            }
            _ => None,
        };
        let mark = match &state {
            Some((destination, ..)) if renames => Some(self.dns_use(*destination, Some(own))),
            _ => None,
        };
        Renaming {
            renames,
            beside,
            mark,
            live,
        }
    }

    /// Learns the names in a DNS answer passed back to an app, and the public names of its ECH
    /// configurations: for every app's flows from Android's resolver, or for one app's flows from a
    /// resolver of its own, so that no app can rename or hide another's flows (ADR 0038).
    pub(super) fn learn(&self, answer: &[u8], scope: Option<u32>) {
        if let Some(response) = dns::response(answer) {
            let now = Instant::now();
            let boot = self.clock.since_boot();
            let mut names = lock(&self.names);
            for &(address, ttl) in &response.addresses {
                names.insert(address, scope, &response.question, ttl, (now, boot));
            }
            for (public, ttl) in response.public_names {
                names.insert_public(&public, scope, ttl, now);
            }
            drop(names);
            // Tracker blocking ties an address to the names Android's resolver gave it (W8, part 3a; ADR 0053).
            if scope.is_none()
                && let Some(chain) = dns::chain(answer)
            {
                self.tie(&chain, &response.addresses);
            }
        }
    }
}

/// What a hello does to a flow's names: whether its name names the flow, the DNS name it leaves
/// beside it, and, for a flow it renames, the mark of the app's own DNS read again.
struct Renaming {
    renames: bool,
    beside: Option<String>,
    mark: Option<(DnsUse, Option<String>)>,
    /// Whether it is read from the live flow, by which alone the counters move.
    live: bool,
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
