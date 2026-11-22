# 0055. An Oblivious DoH relay of the project's own, and a bounded exception to ADR 0016

- Status: Proposed (the direction approved by the maintainer on 2026-11-21; the details wait for the maintainer's
  word)
- Date: 2026-11-22
- Decided by: the direction by the maintainer, 2026-11-21 («همه تایید شد», to the coordinator's six
  recommendations). This record was drafted by the coordinator with AI help.
- Builds on:
  - [0016](0016-no-user-data.md), whose decision 5 requires a new ADR before any change to it;
  - [0042](0042-dns-of-apps-that-go-directly.md), the pairs and the ladder;
  - [0051](0051-two-lanes-and-an-analysis-machine.md).

## Context
- **What Watch uses today.** By default, Watch sends the names that direct apps look up through Oblivious DoH: a
  relay sees the phone's address but not the question, and a target sees the question but not the address (ADR
  0042).
- **Who runs the relays.** The default pairs use relays run by volunteers: Numa's, and crypto.sx's on Fastly. Their
  targets are Cloudflare's and dnscry.pt's. One person runs dnscry.pt, and few public ODoH relays exist at all. A
  volunteer's relay can stop at any time, and the default way would go with it.
- **What the maintainer asked, on 2026-11-21:** why the project depends on volunteers rather than running
  everything itself.
- **The answer has two parts:**
  - **No target of its own beside its relay.** ODoH protects only while relay and target do not collude, so one
    party must never run both halves of a pair. A target of the project's own beside its relay would let the
    project see who asked what.
  - **A relay is possible.** The project may run a relay, paired only with targets of other operators.

  The maintainer approved that direction.
- **Why ADR 0016 must change.** Today no part of Datapavan contacts a server of the project's own by itself:
  - **Basic** has no INTERNET permission;
  - **Watch** connects only to what the user's apps and tools reach, to the resolvers the user or the data names,
    and to the ODoH relays and targets of other operators.

  A relay of the project's own would be the first server of the project that phones contact by themselves, and it
  would see their addresses. ADR 0016 decision 1 says the project collects no data from users. Its decision 5
  requires a new ADR, a legal review and a published threat assessment before that changes.

## Decision
1. **A relay only, never a target.**
   - **What it runs:** Datapavan runs an ODoH relay (RFC 9230's Oblivious Proxy), and no ODoH target or DNS resolver
     of any kind.
   - **What it pairs with:** only targets whose operator, people, jurisdictions and hosting network differ from the
     relay's, by ADR 0042's own pair rule in `catalogue.rs`, with the project as the relay's operator.
   - **A change to this** needs a new ADR.
2. **A bounded exception to ADR 0016's decision 1.**
   - **What the relay may handle, for the life of one request:**
     - the phone's address and port;
     - the TLS session;
     - the size and timing of the request;
     - the target it names.
   - **One counter, for abuse only:** a per-address count of requests, kept in memory for at most 10 minutes, is the
     only state that outlives a request.
   - **Nothing is written:** no access log, no error log with an address, no metrics by address, no sampling, no
     analytics, no backups of any of these.
   - **What may be counted:** totals that carry no address (requests per minute, errors by kind), in memory, only to
     keep the service running.
   - **Anything wider** needs a new ADR. Every other part of ADR 0016 stands.
3. **Not an open proxy.**
   - **Allowed targets:** the relay forwards only to the targets in `data/odoh/targets.tsv` whose pairing with it
     passes the pair rule, by host and path, and only HTTPS POSTs of `application/oblivious-dns-message` within the
     RFC's sizes.
   - **Refused:** any other target, method or type gets a 4xx without contacting anything.
   - **Why:** a relay that forwards anywhere would be a tool for attacking others and a reason to block it.
4. **Its configuration and code are published.**
   - **What is published:** the relay's code, its configuration (the web server's site block with logging off, the
     service unit, the allowlist) and how it is deployed, in this repository.
   - **The code:** a small relay of the project's own in Rust, with the engine's HTTP stack where it fits. The
     reason is that an existing server would bring its own logging and features to remove. Its tests prove the
     allowlist, the absence of addresses in anything written, and the counter's expiry.
5. **Where it runs.**
   - **The server:** the project's netcup server, which already serves datapavan.org. That costs nothing new, as
     the memory of 2026-11-05 asks.
   - **The location:** the jurisdiction and hosting network are those of the server's address, read from its RIPE
     and RDAP records when it is built and recorded in `data/odoh` with their sources, like every other relay's.
   - **The operator** is the project, seated where the maintainer is.
   - **Who deploys:** root changes on the server (the service unit, the web server's site block) are the
     maintainer's to type, since agents there have no sudo.
6. **Its place among the pairs.**
   - **Kept:** the volunteers' pairs stay.
   - **The project's pair:** the project's relay joins with Cloudflare's target, since dnscry.pt shares the server's
     jurisdiction if the server is in Germany. The pair rule decides on the recorded values, not this record.
   - **The order of the pairs** is set by measurement, not here: each pair's warm p50 and p95 from at least two
     networks, and how often each fails over a week.
   - **The volunteers** are still asked before a release ships their endpoints (ADR 0042's release gate).
7. **The threat assessment, published with the relay.** Decision 5 of ADR 0016 asks for it. It covers what follows,
   and every point is a fact about the design, not a promise:
   - **The network sees who uses Datapavan.** A network observer sees connections to the relay's address. The relay
     serves only Datapavan, so that address marks a phone as running Datapavan's Watch more strongly than a
     volunteer's relay, which others' clients use too.
     - **Mitigations within this decision:**
       - lookups go through the user's tool while it is on, as ADR 0042 already does for some fetches;
       - ECH on the relay's name where the web server and DNS support it;
       - the volunteers' pairs stay, so a user can leave the project's out. Watch's DNS screen must offer that.
     - **Fronting the relay with a large CDN** would hide it among other sites but add a party that sees addresses.
       It is left to a later decision.
   - **What the relay sees.** If the relay is breached or compelled to log, it learns addresses, times and sizes,
     and which target was asked. It never learns the question, which is sealed to the target. A breach or a
     compelled log is a risk this server has met before: `homediyet.com` was found hacked on it before its
     reinstall of 2026-11-06.
     - **What limits it:** the server is hardened and the relay runs as its own user.
     - **What the relay keeps:** nothing. A compelled log can cover only the time after the order.
   - **Blocking.** A censor that blocks the relay's address takes only that pair away. The ladder moves to the next
     pair, then to the tool, then to the other ways (ADR 0042).
   - **Abuse.** The allowlist and the counter limit it. A flood against the relay also hits the website, which is on
     the same server: measure it, and move the relay to its own address or server if it costs the website.
8. **What gates its release.**
   - **The reviews:** the legal review that ADR 0016 decision 5 requires, of the relay's handling of addresses under
     the server's jurisdiction and the operator's, and the threat assessment, published.
   - **The checks:**
     - the relay's tests;
     - a week of the measurements in point 6;
     - CI's DNS lab, with a lab relay in the project's own code beside the current ones.
   - **Until all of these pass,** the relay ships in no release as a default. It may be tried in debug builds.

## Consequences
- **Under the project's own control.** The default way no longer depends only on volunteers, and the project can
  keep one pair working on its own.
- **First contact by phones.** For the first time, phones contact a server of the project's own by themselves. The
  privacy policy's one sentence, that nothing leaves the phone unless the user sends it, becomes untrue for Watch's
  ODoH relay. PRIVACY.md and its page must say exactly what the relay handles and keeps, before the release that
  ships it.
- **A Datapavan-only address.** A network observer can tell Datapavan's users from others more easily than with
  volunteers' relays alone. The user must be able to leave the project's pair out.
- **Running a service.** The project must keep it up, patch it and watch it, without logs. That is a running cost
  in time, and later perhaps in money.
- **No collusion by design.** Running only a relay keeps ODoH's split. The project can never see a question tied to
  an address, whatever it is compelled to do, as long as it runs no target in the pairs.
