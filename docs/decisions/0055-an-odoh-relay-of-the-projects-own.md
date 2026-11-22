# 0055. An Oblivious DoH relay of the project's own, and a bounded exception to ADR 0016

- Status: Proposed (the direction approved by the maintainer on 2026-11-21; the details wait for the maintainer's
  word)
- Date: 2026-11-22
- Decided by: the direction by the maintainer, 2026-11-21 («همه تایید شد», to the coordinator's six
  recommendations). This record was drafted by the coordinator with AI help, and revised the same day after the
  server was read and after one security review round (strategy repository,
  `research/2026-11-w8/review-odoh-relay.md`).
- Builds on:
  - [0016](0016-no-user-data.md), whose decision 5 requires a new ADR before any change to it;
  - [0042](0042-dns-of-apps-that-go-directly.md), the pairs and the ladder;
  - [0051](0051-two-lanes-and-an-analysis-machine.md).

## Context
- **What Advanced's network part uses today.** By default, it sends the names that direct apps look up
  through Oblivious DoH. A relay sees the phone's address but not the question, and a target sees the question but
  not the address (ADR 0042).
- **Who runs the relays.** The default pairs use relays run by volunteers: Numa's, and crypto.sx's on Fastly.
  - **Their targets:** Cloudflare's and dnscry.pt's.
  - **The risk:** one person runs dnscry.pt, and few public ODoH relays exist at all. A volunteer's relay can
    stop at any time, and the default way would go with it.
- **What the maintainer asked, on 2026-11-21:** why the project depends on volunteers rather than running
  everything itself.
- **The answer has two parts:**
  - **No target of its own beside its relay.** ODoH protects only while relay and target do not collude, so one
    party must never run both halves of a pair. A target of the project's own beside its relay would let the
    project see who asked what.
  - **A relay is possible.** The project may run a relay, paired only with targets of other operators.

  The maintainer approved that direction.
- **What the server already is.** The project's server is a netcup VPS running Debian 13. It is the one that
  serves datapavan.org (strategy repository, `server/`).
  - **Its front:** Caddy holds port 443 for the website, its redirects, and `mail.datapavan.org` in front of
    Stalwart. Caddy is Debian's 2.6.2, sandboxed under systemd, with its admin API off and no access log.
  - **Its firewall:** the firewall already lets Caddy's user reach DNS and port 443.
  - **What follows:** Caddy can be the relay with configuration alone.
- **Why ADR 0016 must change.** Today no part of Datapavan contacts a server of the project's own by itself:
  - **Basic** has no INTERNET permission;
  - **Advanced's network part** connects only to what the user's apps and tools reach, to the resolvers the
    user or the data names, and to the ODoH relays and targets of other operators.

  A relay of the project's own would be the first server of the project that phones contact by themselves, and it
  would see their addresses. ADR 0016 decision 1 says the project collects no data from users. Its decision 5
  requires a new ADR, a legal review and a published threat assessment before that changes.
- **What this record does not follow of ADR 0016, said plainly.** ADR 0016's decision 5 asks for a new ADR that
  supersedes it, after the legal review and the published threat assessment.
  - **This record revisits it in part,** which that decision does not provide for. On acceptance, ADR 0016's
    decision 5 is amended to allow it, or ADR 0016 is superseded: the maintainer's choice.
  - **The server goes first.** This record's gates (point 8) hold only the app's release. The relay on the
    server is live and public as soon as the maintainer runs the install script. It then serves any ODoH client,
    and its URL is in public data. That can come before the legal review, by the maintainer's word alone.
  - **From that moment,** ADR 0016's consequence "There is no server to subpoena, breach or compel" is untrue for
    the relay.
  - **The other order** is to hold the install until the review. It is the maintainer's to choose.

## Decision
1. **A relay only, never a target.**
   - **What it runs:** Datapavan runs an ODoH relay (RFC 9230's Oblivious Proxy), and no ODoH target or DNS resolver
     of any kind.
   - **What it pairs with:** only targets whose operator, people, jurisdictions and hosting network differ from the
     relay's, by ADR 0042's own pair rule in `catalogue.rs`, with the project as the relay's operator.
   - **A change to this** needs a new ADR.
2. **A bounded exception to ADR 0016's decision 1.**
   - **What the relay may handle:**
     - the phone's address and port;
     - the TLS session;
     - the size and timing of the request;
     - the target it names.
   - **For how long:** one request's data lives for that request. The connection does not: one HTTP/2
     connection, with its address, carries many requests, and Caddy keeps it open while idle for up to five
     minutes.
   - **The TLS session:** its resumption tickets could let the relay link one phone's connections across
     addresses. Advanced's network part keeps one TLS session cache per network beneath (ADR 0042), so it
     does not resume across a change of network. Other clients may. Turning Caddy's session tickets off, for the
     website too, is left to a later decision.
   - **No count per address,** not even for abuse. Caddy's core has none, and none is better than one kept for ten
     minutes.
   - **Nothing is written:** no access log, no log line with an address, no metrics by address, no sampling, no
     analytics, no backups of any of these.
     - **Caddy's error log,** which would carry the whole request when a target is down, has its request fields
       deleted for every site on the server.
     - **Go's error text,** which names both ends of a connection (a client that resets mid-response over
       HTTP/1.1), has every address in it masked.
     - **A message** cannot be filtered in Caddy 2.6.2. Its error log's message names only an upstream, and Go's
       own messages, which name the client, come at the debug level. The log level therefore stays at info.
     - **No access log:** the install script and the test fail when a site turns one on.
     - **The firewall's log** of dropped packets names their source, five a minute. A relay client that tried QUIC
       on UDP 443 would be logged. None tries today: Caddy offers no HTTP/3, the site has no HTTPS record, and the
       app does not use QUIC.
   - **The abuse limit is what the relay forwards:**
     - at most one POST of at most 65,604 bytes per request;
     - only once the whole body is in, so that a slow client holds no request open at a target;
     - only to the two targets of point 6, at one fixed path each.

     It cannot be pointed at anyone else.
   - **What it does not bound:** time and concurrency at Caddy itself. Caddy 2.6.2 sets no read timeout, so slow
     clients can hold as many connections as the server's memory allows, shared with the website and the mail
     proxy, as they already could against the website.
   - **The targets' limits:** an abuser can spend the server's bandwidth, and can make the targets rate-limit the
     relay's one address. That fails the relay for every user of it. Both targets sit on Cloudflare's network
     (AS13335; crypto.sx's behind Cloudflare's CDN), so one rate limit or bot decision there fails both of the
     relay's pairs at once. The ladder then moves on (point 7).
   - **A later option:** a kernel rate limit per source address in `nftables`, which keeps its counts in the
     kernel for seconds. It needs the maintainer's word, and is not part of this decision.
   - **Anything wider** needs a new ADR. Every other part of ADR 0016 stands.
3. **Not an open proxy.**
   - **What it forwards:** the relay answers one path, `/odoh/proxy`. It forwards a request there only when it is
     a POST of `application/oblivious-dns-message` whose length is within RFC 9230's sizes, and whose whole query
     names exactly one allowed target by its host and path.
     - **The path** may be written plain or with `/` as `%2F`.
     - **Refused:** a duplicated or encoded `targethost`, an extra parameter, and any other order or path.
   - **The forwarded request** carries the body, ODoH's `Content-Type` and `Accept`, and the target's `Host`.
     - **Never sent:** none of the client's headers, and none that the proxy adds by itself (`X-Forwarded-*`, Go's
       `User-Agent`). The names of trailers a client declares reach the target, never their values.
     - **The response:** the target's status and body come back with ODoH's type and none of the target's headers
       (no cookie, `Server`, CORS, `Clear-Site-Data`, reporting or `Location` under datapavan.org's origin).
   - **The path:** `/odoh/proxy`, and what Caddy's path matcher takes as equal to it (case, doubled slashes,
     escapes). The target and its path stay fixed whatever the spelling.
   - **Refused:** any other method, type, size, query or path gets a 4xx without contacting anything.
   - **Why:** a relay that forwards anywhere would be a tool for attacking others and a reason to block it.
4. **Caddy's configuration, published, instead of a relay program.**
   - **What is published:** the configuration in this repository's `server/`:
     - `log.caddy`: the global log filter;
     - `odoh-relay.caddy`: the relay's rules;
     - `odoh-pairs.caddy`: the allowed targets.

     The maintainer's install script (strategy repository, `server/odoh-relay.sh`) carries copies of these
     files, and the relay's test checks that the copies match.
   - **Why Caddy and not a program of the project's own,** such as a small relay in Rust, though an
     existing server brings its own logging and features to remove:
     - **The attack surface:** the program that faces the internet stays the one already there, already exposed
       and already sandboxed. A relay program would add a second listener and a second parser behind it.
     - **Already hardened:** Caddy runs as its own user under a systemd sandbox, behind a firewall that limits
       where it may connect. A new program would need all of that again.
     - **Nothing new to patch,** with a limit: Debian's security updates, which the server installs by itself,
       fix some of Caddy's flaws, and leave others. In Debian 13, as the review read Debian's tracker on 2026-11-22:
       - CVE-2026-77281 (a rewrite that ends in `?` re-expands its placeholders) is marked no-dsa;
       - CVE-2026-55458 (the 101 path skips the cleanup of hop-by-hop headers) is still vulnerable;
       - two more are undetermined.

       The configuration avoids each construct: the rewrite's path is a literal, no target can answer 101 over
       HTTP/2, the request body is never a placeholder, and no site uses `hide`. A program of the project's own
       would still be one more thing to watch for flaws and rebuild.
     - **Caddy's logging** is removed and masked by configuration, and the test proves it for each kind of line
       above.
   - **The test:** `scripts/relaylab.sh` runs Debian 13's own Caddy package with these files, beside stand-ins
     for the targets that record what they receive. It tests:
     - every rule of point 3, over HTTP/1.1 and HTTP/2;
     - the log, with a target down, with clients that reset mid-response and mid-body, and with failed handshakes;
     - slow bodies, which reach no target;
     - a control run without the filter, which shows that the checks would catch an address.
   - **Where it runs:**
     - **CI** runs it on the `dns` shard, with a Caddyfile of its own around the published files.
     - **Its server mode** rebuilds the server's Caddyfile from the strategy repository's scripts and runs the
       install script on it, with a failed restart and a target that does not answer. That repository is
       private, so this mode runs on the maintainer's computer only.
   - **Caddy 2.6.2's limits,** written around and tested:
     - a lone `*` in a header deletion crashes the request;
     - the proxy's own deletions run after its settings.

     The client's headers are therefore deleted before the proxy, and every header of the target's after it, with
     `**`. ODoH's type is set as the response is written.
5. **Where it runs.**
   - **The server and the name:** the project's netcup server, at `https://datapavan.org/odoh/proxy`. This needs no
     new DNS record, certificate or firewall rule, and costs nothing new, as the memory of 2026-11-05 asks.
   - **The location,** read from the address of datapavan.org on 2026-11-22 (`data/odoh/sources.tsv`):
     - **The hosting network:** AS197540, netcup GmbH, Karlsruhe, Germany, by RIPEstat and RIPE's RDAP.
     - **DE:** the hosting company's seat, the IPv4 /22's country, and where RIPEstat's GeoLite data places both
       addresses (Nuremberg).
     - **AT:** netcup's parent, Anexia Holding GmbH of Klagenfurt, holds the IPv4 /16 (country AT) and maintains
       the /22. RIPE names the IPv6 /40 `DE-NETCUP-KVM-VIE`, after Vienna.
     - **TR:** the operator's seat.
     - **The data centre itself** is for the maintainer to read in netcup's control panel, and the data to cite.
     - **Under the pair rule,** AT changes no pair today.
   - **The operator** is the project, seated where the maintainer resides, Türkiye.
   - **Who deploys:** the change to the server's Caddyfile is the maintainer's to run with sudo, since agents
     there have no root: `server/odoh-relay.sh` in the strategy repository.
     - **What it does:** it backs the Caddyfile up and writes the three parts between markers, so a second run
       never adds them twice. It then validates the configuration, restarts Caddy, and checks the site, the log
       and the relay from the server.
     - **If any step after the write fails** (the validation, the restart, a check of the site or the relay), it
       puts the Caddyfile before it back and restarts Caddy on it. It checks the website and says what it did, or
       which commands to run if even that Caddy does not start. A failed relay check therefore rolls the relay
       back. `--remove` takes the relay out.
     - **`site.sh`** refuses to write the Caddyfile over the relay, whose log filter protects every site.
6. **Its place among the pairs.**
   - **Kept:** the volunteers' pairs stay.
   - **The project's pairs:** by the rule, on the recorded values, the relay pairs with:
     - Cloudflare's target (US, CR; AS13335);
     - crypto.sx's target (FR, US; AS13335, AS12876).

     It does not pair with dnscry.pt's targets, which share Germany (and vie01 Austria). The engine's tests hold
     this.
   - **Offered on debuggable builds alone,** until point 8's gates pass:
     - `relays.tsv` has a `status` column, and the relay's row says `debug`.
     - A release build of Advanced's network part keeps a row only when its status is `-`, and leaves every
       other row out of its tables before the engine or the screen reads them (`DnsSettings.forBuild`, by
       Android's debuggable flag). It fails closed: a misspelling, a new value, a moved column or a missing one
       keeps the row out.
     - `pairs.tsv` does not name the relay, so no build uses it by default. A debug build offers its pairs on the
       DNS screen.
     - **Its release** takes a pack with the status `-`, and then a pair in `pairs.tsv` if it is to be a default.
   - **The order of the pairs** is set by measurement, not here: each pair's warm p50 and p95 from at least two
     networks, and how often each fails over a week.
   - **The volunteers** are still asked before a release ships their endpoints (ADR 0042's release gate).
7. **The threat assessment, published with the relay.** Decision 5 of ADR 0016 asks for it. It covers what follows,
   and every point is a fact about the design, not a promise:
   - **The network sees a connection to datapavan.org.**
     - **The address and name:** the relay shares the website's address and its name. A network observer sees
       `datapavan.org` in the TLS handshake and cannot tell the relay's path from a visit to the site by name.
     - **What it can still read:** the pattern is not a visit's. There are small POSTs at the rate of the
       phone's lookups, over hours. Contact with datapavan.org already marks a phone as near Datapavan, and the
       pattern marks it as running Advanced's network part more strongly than a volunteer's relay, which
       others' clients use too.
     - **Mitigations within this decision:**
       - lookups go through the user's tool while it is on, as ADR 0042 already does for some fetches;
       - the volunteers' pairs stay, so a user can leave the project's pair out. Advanced's DNS screen
         must offer that.
     - **ECH is not available:** Caddy 2.6.2 cannot serve ECH, and Android offers it to apps only from Android 17.
       It would hide the name, not the address.
     - **Fronting the relay with a large CDN** would hide it among other sites but add a party that sees addresses.
       It is left to a later decision.
   - **What the relay sees.** If the server is breached or compelled to log, it learns addresses, times and sizes,
     and which target was asked. It never learns the question, which is sealed to the target.
   - **What the hosting network sees.** netcup and its parent Anexia carry every client's packets to the server.
     They see each client's address and timing, and can keep flow records, outside the project's control and
     whatever Caddy writes.
     - **A risk this server has met before:** `homediyet.com` was found hacked on it before its reinstall of
       2026-11-06.
     - **What limits it:** the server is hardened, and the relay is the website's own Caddy, under its user and its
       sandbox. No new program faces the internet. A flaw in Caddy now reaches the relay as well as the website
       and the mail proxy, as it already reached both.
     - **What the relay keeps:** nothing. A compelled log can cover only the time after the order.
   - **Blocking.** A censor that blocks the relay's address takes that pair away, and with it the website, since
     both share one address. The ladder moves to the next pair, then to the tool, then to the other ways (ADR 0042).
   - **Abuse.** The allowlist and the size limit bound what an abuser gets (point 2).
     - **Shared fate:** a flood against the relay is a flood against the website and the mail proxy, which run in
       the same Caddy. Measure it.
     - **If it costs the website:** move the relay to its own address, or its own server, with its own record.
8. **What gates its release.**
   - **The reviews:** the legal review that ADR 0016 decision 5 requires, of the relay's handling of addresses under
     the server's jurisdiction and the operator's, and the threat assessment, published.
   - **The checks:**
     - the relay's test (`scripts/relaylab.sh`), on CI;
     - the DNS lab's ODoH steps through it on an emulator (`DNSLAB_RELAY=caddy DNSLAB_ONLY=odoh
       scripts/verify-dns.sh`);
     - the install script's own checks on the server, from the server;
     - a week of the measurements in point 6.
   - **Until all of these pass,** the relay ships in no release (point 6's status column). It may be tried in
     debug builds.

## Consequences
- **Under the project's own control.** The default way no longer depends only on volunteers, and the project can
  keep pairs working on its own.
- **First contact by phones.** For the first time, phones contact a server of the project's own by themselves.
  - **The privacy policy:** its one sentence, that nothing leaves the phone unless the user sends it, becomes
    untrue for Advanced's ODoH relay.
  - **Before the release that ships it:** PRIVACY.md and its page must say exactly what the relay handles and
    keeps.
- **A Datapavan-only pattern.** A network observer can tell Datapavan's users from others more easily than with
  volunteers' relays alone, though it sees only the website's name. The user must be able to leave the project's
  pair out.
- **The website and the relay share a fate:** one address to block, one Caddy to breach, one link to flood.
- **Running a service.** The project must keep it up and watch it, without logs, and keep the pairs in the
  configuration in step with the data. That is a running cost in time. Caddy's patches come with Debian's.
- **No collusion by design.** Running only a relay keeps ODoH's split. The project can never see a question tied to
  an address on its own, whatever it is compelled to do, as long as it runs no target in the pairs. A compelled log
  of the relay joined with a compelled log of a target would link them.
