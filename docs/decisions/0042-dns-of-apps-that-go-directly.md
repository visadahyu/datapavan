# 0042. DNS of apps that go directly: Oblivious DoH, several jurisdictions

- Status: Accepted (by the maintainer on 2026-11-12), with open questions
- Date: 2026-11-12

## Context

Apps that Watch sends through the user's tool have their names resolved by the tool
([ADR 0038](0038-dns-of-chained-apps.md)). Every other app goes directly. For those, Watch's resolver answers
inside the tunnel and asks upstream, today as plain DNS from a protected socket to the network's resolver
([VPN.md](../VPN.md), DESIGN.md §13.2, W3). So by default the network sees every name a direct app looks up,
unless the user set Private DNS. The plan for W8 adds a DoH or DoT resolver of the user's choice and a strict
setting that never falls back to the network.

Encrypting the questions to one resolver hides them from the network, but hands all of them, with the user's
address, to that resolver's operator. Oblivious DoH (ODoH, RFC 9230) splits the two:
- **A relay** sees the user's address but not the question.
- **A target** sees the question but not the address.

In filtered networks, though, DoH and its relays are often blocked, and a resolver that cannot be reached
leaves every direct app without names.

## Decision

1. **ODoH is the default** upstream for the names of apps that go directly, once W8 is built. No single server
   sees both who asks and what.
2. **Several jurisdictions.** Relays and targets are chosen from more than one operator and jurisdiction, and the
   user can see and change them.
3. **The network's resolver is a fallback only,** outside the strict setting. Watch uses it only when no
   encrypted path answers, and says so on its screen while it does. With the strict setting, it is never used.
4. **The user's own choice stays.** A DoH or DoT resolver of the user's choice, and the strict setting, remain as
   W8 planned.

## Open questions

- **Which relays and targets.** Few public ODoH relays exist. Their operators and terms, and whether the
  project should run or sponsor one, are read before W8.
- **Fallbacks in filtered networks.** How Watch keeps names working where DoH and ODoH are blocked, without
  falling back silently to a resolver the censor controls, is research at the frontier.
- **The cost.** ODoH adds a hop to each uncached name. Its latency is measured against Watch's speed budget
  (ADR 0039).

## Consequences

- **VPN.md's default changes.** VPN.md's DNS row and DESIGN.md's W3 and W8 rows now point here. The network's
  resolver stops being the default for direct apps once W8 lands. Until then, the screen says that direct apps'
  names go to the network's resolver.
- **ADR 0034's requirement narrows.** Upstream queries to the network's resolver through `DnsResolver` matter
  only for the fallback.
- **The engine needs a TLS client and HPKE** for DoH and ODoH. Both are new code that parses hostile input, so
  they are fuzzed and fall within the outside review (ADR 0039).
