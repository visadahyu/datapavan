# 0052. Apps' built-in proxies named: read from the connection, or inferred with substitution

- Status: Accepted, with the proxy record's unit C (2026-11-25), as the maintainer approved its plan on 2026-11-24
  («تایید شد», "approved"), which named this ADR's acceptance in that unit; decision 8 rests on the maintainer's
  middle way of 2026-11-22 («تایید شد», "approved"); decision 11 on the maintainer's decisions of 2026-11-26 on the
  proxy record's unit S2 («همه تایید», "all approved"). Built on `watch-w8b`, W8 part 2a, 2026-11-20; its fix round on
  `watch-w8b-fix`, 2026-11-21.
- Date: 2026-11-20, fix round 2026-11-21; the proxy record's units A to C, 2026-11-24 and 2026-11-25; unit S2,
  2026-11-27
- Decided by: drafted by the builder of W8 part 2a with AI help, under the session's grant (go on by the roadmap at
  the S-tier bar), from a brief audited once before the build; the proxy record's units A to C built with AI help, each
  from a plan audited once, under the maintainer's approvals of 2026-11-22 and 2026-11-24 that decision 8 quotes.
- Builds on: ADR [0025](0025-guided-check-and-traffic-facts.md) (decisions 4 and 5: facts, never alarms; the words),
  [0036](0036-ip-to-organisation-dataset.md) (decision 4: an address's organisation hosts, it does not run),
  [0037](0037-connection-log-storage.md), [0038](0038-dns-of-chained-apps.md),
  [0046](0046-live-activity.md) (decision 3: the tool's own row; "Log where these apps connect"),
  [0047](0047-profile-for-phones-that-may-be-searched.md) and [0015](0015-dataset-licences.md).

## Context

DESIGN.md's W8 row: "Apps' built-in proxies are named, with their operator when it is not the app's maker, Telegram's
MTProto and SOCKS5 proxies first." Many apps carry a proxy setting of their own: browsers, games, download managers,
and above all messengers in restricted regions (Telegram's MTProto and SOCKS5 proxies, WhatsApp's since January
2023, Signal's since 2021). Advanced sees every app's packets and already names each flow by its app, its TLS or QUIC
server name, the DNS answer for its address and the address's organisation. A flow through an app's own proxy is
then named after the proxy, and where the proxy is reached by its address alone, after the proxy's hosting company:
the user learns nothing of where the app really went, nor that it used a proxy.

What the field does (research of 2026-11-20, in the private strategy repository): nDPI, and PCAPdroid on top of it,
label SOCKS and HTTP `CONNECT`, but name neither the destination asked for nor the proxy's place; nDPI's Telegram
label is an address match, so a flow to an MTProto proxy gets none; no tool found says "this app uses a proxy of its
own, here, for this destination". No peer-reviewed method for MTProto proxies exists; the material is implementers'
documentation. The brief's audit (one round, 2026-11-20) found that inferences resting on one feature misname
Telegram's CDN data centres, WhatsApp's link previews and backups, and Signal's own fronting, and asked for
substitution; that "the operator" is not what the data gives; and that an app's own proxy is circumvention, as
chaining is, and must follow the same switch.

## Decision

1. **Proxies the app's own bytes declare are read from the connection.** The first bytes an app sends on a TCP flow
   that went directly are read for SOCKS5 (RFC 1928, with RFC 1929's user name and password), SOCKS4 and 4a, an HTTP
   `CONNECT`, and a plain HTTP request sent to a proxy (its target in absolute form), within 4,096 bytes
   (`core/net/src/proxies.rs`, fuzzed). **The app declares the proxy, not Datapavan** (decision F1): a request alone
   is only what the app wrote, so a SOCKS or `CONNECT` request names its flow only once the server's first bytes
   confirm the handshake (`proxies::confirmed`: SOCKS5's choice of the method the app then used, RFC 1929's success
   where it was used, then `05 00 00`; SOCKS4's `00 5a`; an `HTTP/1.x 2xx` status line for `CONNECT`). Until then, and
   for good when the server refuses, never answers or answers in another protocol, the flow keeps its own address,
   names and trackers' marks, and a hello read after the request names it as its own. Confirmed, the flow is named by
   the destination the app asked the proxy for, a source of names after the hello's and before a DNS answer's (which
   names the proxy's address, not the destination), by the address asked for where no answer names it, never by the
   proxy's; the inner TLS hello is read too, and names the flow as any hello does. A plain request in absolute form
   cannot be confirmed so, since origin servers accept that form too (RFC 9112, 3.2.2): its flow keeps its own address
   and names whatever the switch says, and its row says what the request asked for, never that the server is a proxy.
   **The exception (the proxy record's unit B, R7):** a plain request to the proxy in Android's settings, which is
   known by the setting's address or a name Android's resolver gave it, never by the app's bytes. Its row calls it by
   that setting's name, as Android does, and its record is left out as a confirmed proxy's (decisions 4 and 8).
   Of a plain request only the authority is taken, never its path or query, and a target with an `@` after its
   authority is refused. SOCKS5 needs a plausible method list (one to ten, each IANA assigned, none twice, the method
   used among them) and SOCKS4 a printable user ID: 0 of 2,000,000 random 600-byte starts parse as a request (36
   without these two rules). The screens word it "Asked the SOCKS5 proxy at ADDRESS for DESTINATION. Read from the
   connection."
2. **Never kept, logged, shown or held past the parse:** RFC 1929's user name and password, SOCKS4's user ID, a
   `Proxy-Authorization` header's value, a URL's user information. The parser skips them by their lengths and
   delimiters and copies nothing of them; the bytes they passed through in the relay, the sniff buffer (its capacity
   set once, so that it never moves) and the relay's own buffer, are zeroed when dropped, and a hello's buffer is
   started only for a stream whose first byte is TLS's `0x16`, so no other first bytes are copied (S-m6).
   The packet path before the relay is not zeroed: the tunnel's packet buffer, the fragment reassembler and a held TCP
   Fast Open SYN's payload (an accepted limit below). The one fact said is that a password for
   this proxy crossed the network unencrypted (RFC 1929's, or HTTP's `Basic`), never the password. Tests prove that
   none of them reaches a flow, the log, the live view, the debug dump, logcat or the crash buffer; the fuzz seeds are
   synthetic.
3. **Skipped:** the chained circumvention tool's own flows, and the apps Advanced chains through it or sends through a
   WireGuard tunnel: what they carry is the tool's (ADR 0046, decision 3), and a tool whose upstream is plain SOCKS5
   or HTTP would otherwise show every chained destination under its row. A tool that is not chained is read as any
   app is, and its proxy rows say that the proxy is a circumvention tool's (unit B's B6); where it can carry traffic
   inside the VPN, its own connections follow R10 (decision 8, the other units), and a tool that runs only as a VPN is
   an ordinary app there.
4. **Android's proxy setting** is told apart from an app's own: the network part hands the engine the hosts and ports of
   the global proxy and of each network's own at each start and change, and a declared proxy at one of them says "This
   is the proxy in Android's settings, which other apps can use too." Corrected by measurements 7.1 and 7.2 (the
   proxy record's unit B, 2026-11-25; the strategy repository's `research/2026-11-proxy-record/measurements-7.md`):
   - **The global proxy** reaches every app inside the VPN that follows Android's setting.
   - **A network's own proxy** reaches into the tunnel only through apps that were running before the VPN started,
     Google Play services among them, and through the apps the user left out, outside it. Apps that start inside the
     VPN connect directly, and on a network that requires its proxy they reached nothing until the engine carried them
     through it itself (decision 11, unit S2). Its address stays in the list, so that those apps' flows are named so.
   - **A PAC file** is not a proxy's address: Android reports it as its handler on `localhost`, which is never handed
     to the engine. Most apps connect to the proxies the file names themselves, under their own UIDs. Android's PAC
     handler, `com.android.proxyhandler`, connects for the others, left-out apps included, under its own UID inside the
     tunnel, and its rows say so: "This is Android's PAC proxy, which connects for other apps, including apps you left
     out."
   - **Matched by address, or by a name Android's resolver gave the address,** never by an answer of the app's own
     resolver, which would let an app make its own server read as the setting (the brief audit's M5). Under strict
     Private DNS, which hides the apps' lookups, the network part looks the setting's names up itself, through
     Android's resolver and so the same encrypted way; otherwise it never does, so no proxy name goes out in plain DNS.
   - **A plain request to the setting** is the user's shared proxy, by its address or that name, never by what the app
     wrote: with the switch off it is left out of the record as a confirmed proxy's and shown live by R2 (R7). It is
     the one plain request a row calls by a proxy's name, since Android names it so (decision 1's exception).
   - **"Now" shows Android's own setting** in one line while any is set (the brief audit's note 24): the global proxy
     first, then this network's own, or a PAC file, each with what it does inside the VPN. A global proxy set over adb
     or by a device owner shows in none of Android's own Wi-Fi screens.
5. **Messengers' proxies are inferred, each with substitution,** and worded "Through a KIND at ADDRESS. Inferred from
   where and how it connects.", followed by a sentence that where it goes from there is encrypted and cannot be seen.
   The clients are their makers' own packages (`data/messengers/clients.tsv`). A proxy is named only while, in the
   same window (the live view's ten minutes in time since the phone started, sleep included, or while one is open),
   the app made no TCP connection to its maker's own network. A direct connection within ten minutes after a naming
   takes the name back (F2): the flow becomes what it would have been, its name, address and place in "Now",
   un-hidden, the hello kept as a cover naming it, the segments that wait for their states rewritten; the log's
   records of an inferred flow are held back for those ten minutes (at most 1,024 at once) and rewritten on a
   take-back, so that no record says what the engine took back. The instants of the direct connections cross to the
   next engine at a hand-over, so a CDN flow opened right after it is not named.
   - **Telegram's MTProto:** a flow to an address outside Telegram's published ranges (`data/messengers`, its
     `cidr.txt` byte for byte, each fetch recorded with its date, SHA-256 and the ranges added and removed) whose
     first 64 bytes pass the obfuscated transport's rules (the excluded prefixes and bytes 4 to 8, not a length; and
     random-looking: 3 to 5 bits set a byte on average, 16 to 48 of the 64 bytes with the high bit set, and not UTF-8
     text: a random header misses that 2.4 times in 100,000, measured 26 in 1,000,000), or whose TLS hello's server
     name is untied to this address (fake TLS, below). Any TCP flow of the app to its ranges, even one refused, is a
     direct connection; a call's UDP to a relay is not one (an accepted limit below). A CDN data centre reached while
     the app goes directly is therefore no proxy.
   - **When a hello is untied** (F3): no answer the engine passed and still holds gave the name this address (an
     address keeps up to eight names given before its last, each until its own answer ends), and the app, or Android's
     resolver for it, did not look the name up through the tunnel within the names' lifetime: mtg's cover is never
     looked up. The rule counts only where the engine sees the app's lookups: Private DNS not strict on the tunnel's
     network, and a lookup of the app through the tunnel in the window. Otherwise an untied hello is no evidence, and
     only the byte rules and substitution decide. A hello that is no cover, and one while substitution holds, names
     its flow as any does.
   - **The cover name never names the flow.** For Telegram's and WhatsApp's clients, a hello whose name no DNS answer
     the engine passed tied to an address outside the maker's network, while the rule above counts and the flow is
     named the proxy, does not rename the flow: "Telegram → google.com" never appears under its proxy. The name is
     kept as the cover it is ("Its connection sent the name NAME.", followed by a sentence that no DNS answer passed
     through the tunnel gave that name this address), with, where the owners' tables name both, the company behind the
     name and the network's: the owner test supports, never decides (mtg advises a cover hosted with the proxy's own
     provider).
   - **WhatsApp's proxy:** WhatsApp's clear header (`W` `A` and two bytes, or `E` `D` `0` `1` with its routing data,
     as whatsmeow and Baileys write it) to an address outside Meta's networks, on any port (5222 and 80 by default; the
     client lets the user set others), or a TLS hello whose name no DNS answer tied to such an address (the proxy's 443
     and its media ports, 587 and 7777, which carry `*.whatsapp.net` names). Meta's networks are AS32934 and AS63293,
     which Meta's peering page names, through the organisation table, or a DNS name of WhatsApp's; an address of the
     user's own network is no company's. Without the organisation table nothing is inferred elsewhere. A link preview
     or a backup reaches a name a DNS answer tied to its address: not a candidate, and substitution besides.
   - **Signal's proxy:** decided by names. A TLS hello of a Signal client whose name is not Signal's own
     (`signal.org`, `signalcaptchas.org`), not one of Signal's fronts (the names its source sends to reach Signal
     through Google's and Fastly's networks), and not a third party it reaches itself (Stripe, hCaptcha, its donations'
     `signaldonations.org` and PayPal, `debuglogs.org`, MobileCoin's hosts), nor a name it reaches within ten minutes
     after such a third party: its web view opens the payment's pages from there, a card issuer's 3-D Secure page among
     them, whose names no list can hold (F7). Signal's fronting is its own circumvention and counts as a
     direct connection to Signal: a set proxy turns it off (`SignalServiceNetworkAccess.kt`, `getConfiguration`, at
     the pinned commit `aa38b25`), so a front seen means no proxy. Signal has no network of its own, so nothing is said
     of its maker's network.
6. **Who runs it is never said.** "An address in the network of ORGANISATION. Who runs it is not known." or "On your
   local network. Who runs it is not known." Where Datapavan can tell that the network is not the app maker's, it says
   so: for Telegram (outside its ranges) and WhatsApp (outside Meta's networks) always, the network unknown or the row
   left out included; for a declared proxy only where the owners' tables name both the network's company group and the
   app's (ADR 0020) and they differ. Never "the operator".
7. **The confidence, in words,** shown whether or not the switch is on (F5): "Read from the connection" for a declared
   proxy; "Inferred from where and how it connects" for a messenger's. What Datapavan never knows is said, in "What
   this view cannot see": who runs a proxy, where an inferred proxy sends the traffic on, and whether the user or the
   app chose it.
8. **An app's own proxy is seen live in full, and kept in the log only by the user's choice** (the maintainer,
   2026-11-22). This replaces the rule of 2026-11-21, under which the switch left the proxy out of "Now" too. The
   maintainer's principle that day: «چیزی نباید به هیچ دلیلی از زیر چتر نظارتی داتاپاوان در بره حتی با این استدلال
   که ممکنه گوشی کاربر بازرسی بشه», "nothing should, for any reason, slip out from under Datapavan's monitoring
   umbrella, even on the argument that the user's phone might be searched". The coordinator's proposal that followed,
   built from an independent design study (rules R1 to R10, in the private strategy repository), was approved the
   same day («تایید شد», "approved"). On 2026-11-24 the maintainer approved its split into four units and the plan's
   four proposals («تایید شد», "approved"). Unit A, "seen live in full", builds what follows; unit C, the choice for
   one app (R3), is below; the other units are named at the end.
   - **The words.** An *own proxy flow* is a SOCKS or `CONNECT` flow the server's reply confirmed, or a messenger's
     inferred proxy (decisions 1 and 5), and a plain request to Android's setting (decision 1's exception, unit B). Any
     other plain request in absolute form is not one. Its *first hop* is the flow's own
     address and port, the DNS name its address had, its network and organisation, and an inferred proxy's cover name.
     Its *destination* is what the app asked the proxy for, and every name that gives it: the name or address asked
     for, the DNS name of an address asked for, and the inner hello's name, ECH state and resolver mark. Only a
     declared SOCKS or `CONNECT` flow can hold one; an inferred flow never does (Signal's is named by its outer hello,
     the proxy's own name). *The switch* is "Log where apps connect through your tool, WireGuard or a proxy" (W6's
     switch, F6), off by default. *With the switch off*, below, means for a flow that the user's choice for its app
     does not cover (R3, unit C): a flow it covers is kept as with the switch on.
   - **R1, the record.** With the switch off, each record of an own proxy flow is stripped as it enters the log
     (`logbook::without_destination`). It keeps the kind, the facts that name nothing (Android's setting, a password
     unencrypted, outside the maker's network), the trackers' εxodus ids, the bytes, times, states and route, and a
     blocked flow's SDK. It keeps nothing of the first hop or the destination, at an address of zeros with flag bit 4
     set, the shape the log already had for a flow left out. A plain request's record keeps its own address and loses
     what it asked for, except one to Android's setting, which is left out as above. With the switch on, records keep
     the first hop and the destination, as before.
     - *When it is decided.* The switch is read under the log's lock at two points: as a record enters the log's
       queue, before it is held back or pushed, and as a held-back record goes on to the next batch. A messenger's
       records enter the queue as they are made, so those made while the switch was off are held back already
       stripped, and turning the switch on during their ten minutes restores nothing.
     - *What waits, stated as it is.* A held-back record made while the switch was on keeps its first hop until it
       goes on to the batch: ten minutes or more. A segment that waits for its app's state keeps it until it is
       written, where it is stripped. If the switch goes off and on again in that time, both are written as they were
       made. A segment cut seconds before the switch was turned on, and still waiting, is written with its first hop:
       that is the user's new choice.
     - *A cut before the reply.* A quarter hour's cut can fall between a request and a slow reply, and the cut segment
       is then an ordinary flow's, with the proxy's address and name. When the reply confirms the proxy with the switch
       off, that flow's records still in the batch are stripped too, each given the proxy's kind, so that the history
       says it was a proxy. The batch waits at least 30 s, so this closes nearly every case (a limit below). Turning
       the switch off strips such a record of a flow already named, and so does a naming of a segment held back for
       a messenger's take-back before it.
     - *A take-back, and substitution* (the maintainer, 2026-11-24, after unit A's review, engine, major 1:
       «تایید شد», "approved"). A flow named a messenger's proxy and taken back (F2), or never named so for
       substitution, is shown in "Now" as the flow it is. While the switch is off, the log keeps of it what it keeps of an own proxy
       flow: a record stripped as it entered stays so, and its other records are stripped as it was, or would have
       been, named. No proxy's address and no cover reaches the history with the switch off. The record keeps the
       kind, the time, the bytes and the trackers, and, from log version 7 (unit B), the mark that the engine could
       not tell it was the messenger's proxy, on every record of the flow, those held back before the take-back
       included. Unit C's choice for one app keeps such records whole where the user picks it.
   - **R2, live.** With the switch off, "Now" shows the first hop of every own proxy flow: its address and port, DNS
     name, organisation and network, and for an inferred proxy its cover line. The flow is placed under the proxy
     server's own name. The destination is never live while the switch is off: live flows never hold it (C1), and the
     kept flows, which only debug builds keep, follow the same rule. The trackers' marks are matched in the engine on
     every name the flow carried before anything was left out (its address's DNS name, the outer hello's, the
     destination asked for, an inner hello's) and kept by εxodus id alone, which names a tracker's company, never an
     address or a name (F1). A release build's dump prints no place.
     - *The window.* A place shows its first hop in full while a live flow of its app matches it, and until ten minutes
       after the latest end of the flows that matched it. A quiet flow is full while it is open, however quiet, and for
       ten minutes after it ends.
     - *The clock.* The time since the phone started (`CLOCK_BOOTTIME`, `Clock::since_boot`), which counts sleep and is
       never set: ten minutes asleep are ten minutes. It is read once when a flow ends and once per sweep, never on the
       packet path. A wall clock set back or forward changes nothing in the window. A failed reading strips rather
       than keeps: an end read so is not recorded, a sweep that reads so strips everything due, and the window's
       arithmetic saturates.
     - *The table of ends.* For each own proxy flow that ended: its app, its first hop and when it ended. Two ends of
       the same place are kept as one, the later. At most 128 entries per app and 2,048 in all; past them, the oldest
       of the app goes, and then the oldest of the app that holds the most. It is pruned at each sweep, cleared with
       the counts and handed to the next engine with them.
     - *After the window.* A place is stripped as a record is, merged into the app's stripped place of the same kind
       and facts with its bytes added, and its address's organisation leaves the view's cache. A stripped place never
       becomes full again. A segment that waits for its app's state, whose flow is no longer live and which no unexpired
       end matches, is stripped too, so the view's "not told yet" places never show it full.
     - *The sweep.* At each view, at each reading of the apps' states (at most every 5 s with the screen on and every
       minute with it off) and at each change of the switch. It reads the switch and the clock once. As a backstop
       while first hops are not kept, it sets back to its first hop any own proxy flow or place that still holds a
       destination. It also prunes the messengers' inferred flows past their window.
     - *The view's bounds.* A guarded place, an own proxy place not left out, gives way only after every other place
       of its app (128) or of all apps (2,048): stripped and ordinary places go first, oldest first. While the view is
       built, first hops have a cap of their own of 128, so that neither kind of flood pushes the other out.
     - *The snapshot's bit.* "Shown here only" tells the screens that a first hop is shown in "Now" and not logged.
       The engine alone sets it, as it builds the view, so the screens repeat no decision.
     - With the switch on, nothing expires, and the history keeps it all.
   - **C1, the inner hello and the request.** The switch is read inside the flow's lock, at naming. While first hops
     are not kept, a confirmed request leaves the flow's name, its origin and its DNS name as they are, and adds only
     the proxy, without what was asked, and its network. The flow is marked as named without its destination
     (`Live.unkept`), and an inner hello, read in the same handshake or after it, changes nothing of the flow and adds
     only the trackers its name matches. The mark is cleared only by a take-back (F2): turning the switch on does not
     clear it. With the switch on at naming, both the request and the inner hello name the flow, as before.
   - **R6, the switch.** Every change of it, and the engine's start, run the same pass. Turned off, at once: every live
     flow, waiting segment and "Now" place that holds a destination goes back to its first hop, and a place that comes
     to equal another is merged into it; the own proxy records gathered for the log's next batch are stripped, and
     plain requests' records lose what they asked for; first hops in "Now" outside the window are stripped by the
     sweep that follows, and those inside stay until it ends. Held-back records and waiting segments are as R1 says.
     Turned on: an open flow gains no destination it never held, its later records carry its first hop, and places
     stay as they are.
   - **R8, no app makes Datapavan keep less.** The server's confirmation is still needed (F1). The live flow always
     keeps its own address: the request and the inner hello cannot rename it (C1), and a flood of other destinations
     cannot push its first hop out of "Now" early (one limit below). Nothing an app sends turns the switch, or the
     choice for one app (R3), on or off: each is set only from the screens and from the debug-only dump command. A PanicKit trigger from an app the user has
     not connected no longer clears the live view (ADR 0047, decision 7).
   - **R9, the profile.** Under ADR 0047's profile, no proxy kind, flag or counter is recorded, and "Now" shows a
     first hop within the screen-on session only, behind Advanced's lock. The screen-off clear
     (`Engine::clear_activity`) already forgets every place, full or not, and the table of ends, as a test shows. That
     the clear also resets the proxy counters the switch's drawing reads (`LogSwitch.proxiesSeen`) and the
     substitution's memory is W9's work, a must in DESIGN.md's W9 row: no engine path reads the profile yet. The
     choice for one app (R3) shows a chosen app's destinations within that session too, and is kept in memory only.
   - **Kept from before.** The switch is drawn wherever anything is left out for it, and every left-out row links to
     it. A release's dump writes the proxy counters as `-`, eight since unit U. The substitution's state is a few instants and name
     hashes per messenger, in memory. Nothing reaches a summary, the widget or the tile (ADR 0046, decision 3).
   - **R3, the choice for one app** (unit C, 2026-11-25). "Log where APP connects through a proxy", on the app's page
     and on its rows in "Now" and the history, keeps that app's own proxy flows as the switch on does, the switch
     staying off.
     - *The rule, per flow.* Wherever the engine read the switch, it reads one predicate of the flow and its proxy
       (`Keeps`): every flow while the switch is on, else a flow the choice covers (`LoggedApps::covers`). A covered
       flow is named by its destination at naming (C1 does not apply), its records keep the first hop and the
       destination at both entry points of the log, "Now" shows it in full with no window and no "shown here only"
       bit, and a plain request keeps what it asked for. A flow taken back is decided by its would-be proxy's facts,
       so a chosen messenger's taken-back records are written whole, as with the switch on.
     - *Not covered, and where.* Android's proxy setting (the flow's `setting` fact, set at naming by an address or
       a name Android's resolver gave, never the app's) and a proxy on the user's own network (the `local` fact, from
       Android's link properties): in the engine, per flow, as far as those facts reach. They miss a PAC file's
       proxies and, at times, a setting given by name, so a chosen app's flows to those can be covered; the limits
       for the choice say when, and the confirmation says so (review C-engine, major 1). A circumvention tool known by
       its signing key, the chain's tool and the three named rows (unit B's B6), and Android's PAC handler: the
       network part never offers or hands them, and the engine drops them from the set. The chain's tool is dropped
       from the chain's own settings at each hand-over, before the tools are read again (review C-rest 8). Android's own UIDs, below 10,000 in each user's range:
       the engine keeps only application UIDs. An SDK Runtime UID (AOSP's 20,000 to 29,999 in each user's range)
       follows its app (`app_of`). An exclusion only removes the choice's extra logging; it never goes below R1.
       Chained and tunnelled apps' flows are not read for proxies (decision 3), so the choice changes nothing for
       them, and its confirmation says so.
     - *Shared UIDs.* The choice is made for the UID, and its confirmation names every package that holds it. A UID
       is handed only while every package that holds it now was chosen: a package that joins it later ends the
       choice, the safe direction, and the app's rows say so in the run that saw it.
     - *R6 for the choice.* Turned off for an app, at once, as the switch turned off: that app's live flows, waiting
       segments and "Now" places that hold a destination go back to their first hop, its own proxy records gathered
       for the next batch are stripped, and its first hops in "Now" outside their window are stripped by the sweep
       that follows (`Shared::apply_proxies` runs the pass whenever an app left the set, for whatever reason).
       Held-back records and waiting segments are as R1 says. What the log already holds stays for the retention, and
       the screens say so. Turned on: an open flow gains no destination it never held, and places stay as they are; a
       place left out while its proxy was not logged says so.
     - *R8 for the choice.* It is written only by the network part's screens, which are not exported, and by the
       debug builds' dump command `proxy-log`, which takes only this project's own packages. Every fact that excludes
       a flow comes from Android or from the network part's own reading, never from an app's bytes.
     - *The store* (`proxy/LoggedApps.kt`, the preferences `logged_proxies` of the network process): one line per
       package, with its kind (unit D's tools a kind of their own) and its first install time, never a UID, and
       nothing of any flow. Android gives a removed app's UID to another after a reboot, and a package name can be
       installed again by anyone: an entry whose package is gone, or whose first install time changed, is dropped at
       the next hand-over and never comes back; an update keeps the first install time, and the choice. The app's rows
       say that a reinstall ended it, whether the network part saw the new first install time or the package gone and
       then back, the second kept in the network process's memory alone while it lives (review C-rest 1). The yes of
       the confirmation chooses only the packages it named (review C-rest 9). The network part hands the engine the
       chosen UIDs, with the tools' and the PAC handler's, at each hand-over of the proxies (`nativeProxies`), and none
       before the tools were read once in that run, so that a known tool is never covered in the seconds after a
       start. Under strict Private DNS, where the engine tells the setting by the addresses handed alone, the addresses
       of the network part's last lookup of the setting's names go with them at each hand-over until the names change,
       and no chosen UID is handed while the names have none yet (review C-engine, major 1 (a)). Under the switch, its
       note gives how many apps are chosen (the maintainer, 2026-11-25); their list is W9's, behind Advanced's lock.
     - *The profile (R9).* Nothing is recorded under ADR 0047's profile, so there the choice changes only what "Now"
       shows. The store then keeps it in memory only; W9's screen-off and a wipe clear it, and turning the profile off
       restores nothing and writes nothing (ADR 0047, decisions 3, 4 and 7). Each of these has the running network
       part hand the choice to the engine again, and each runs in the network process, which alone holds the session
       and the service it asks (review C-rest 5); the profile's and the wipe's writes reach the disk before they
       return. The confirmation's words under the profile are W9's.
     - *A leaf lock of its own.* The engine's set sits behind its own lock (`Shared::kept_apps`), taken only to clone
       or swap it, with nothing taken under it. Under the `proxies` lock it would deadlock: `infer` holds `proxies`
       and takes `held_back`, while the log's readers of the set hold `held_back`. The setting and the set are swapped
       one after the other, never one inside the other, which is safe while network-jni serialises every call that
       hands them.
   - **The other units.** R4, the facts said whatever the switch, with R7, plain requests to Android's setting: unit
     B, built (decisions 4 and 9). A plain request to a local address keeps its own address, as before (the brief audit's
     finding 15). SOCKS5's `UDP ASSOCIATE`: unit U, built (decision 10). R10, the tool's own row: unit D, built
     (ADR 0046, decision 3, the tool's own row):
     - *Who is a tool:* a UID the network part hands as a tool, known by its signing key and narrowed to the rows that
       can carry traffic inside the VPN (a proxy mode, Tor Browser, its alpha and Briar), or the chain's tool, which
       the engine counts from the chain itself from the first packet. A package name alone gives nothing.
     - *Live:* every flow of a tool shows in full for R2's window, the chained tool's included, whatever the switch
       and whatever the flow carries. The window, the table of ends, the sweep, the flood guard and the snapshot's
       "shown here only" bit read the predicates beside `own_first_hop` in `proxied.rs`, never the proxy's fields. A
       tool the user sends through a WireGuard tunnel, or chains as an app through another tool, is a tunnelled or
       chained app first, hidden live while the switch is off. After its window a
       tool's plain place goes and its bytes stay; the snapshot's bit 2 of the app says so.
     - *The record:* a tool's flow keeps its address only with the switch on, or with the user's choice for that tool
       ("Log where TOOL connects for itself", kept in the same store as R3's, a kind of its own). The choice keeps
       the first hop of a tool's own proxy flow, never what it asked for.
     - *The tie:* the engine keeps for ten seconds what the chain asked the tool for, by address and by name, and
       ties the chained tool's flows opened to those, at their birth and at their hello, whatever the switch. A tie never hides anything
       live; it only keeps a tied flow out of the log under the tool's choice. Since a tie can only take away from the
       user's choice, never below R1, it may read any name the engine gave the flow, the tool's own resolver's
       included, and the hello the tool wrote.
     - *Kept in full:* a tool's flow whose names match a tracker, record and place, with no window; a blocked flow's
       SDK (ADR 0053, decision 8).
     - *R6:* turning the switch or a tool's choice off, and a UID becoming a tool, run the pass that strips what is
       gathered for the next batch and leaves places to their window. A tool known late, after its first flows,
       has its waiting records stripped and its ended places given an end at that moment.
     - *R8:* nothing an app or a tool sends turns the switch, the choice or the profile on, or hides a tool's
       connection from "Now"; the choice is written only by the network part's screens and a debug-only command that
       takes this project's own packages.
9. **The records.** The log's records are version 7 (unit B; version 6 was [ADR 0053](0053-tracker-blocking.md)'s,
   which added the blocked outcome and the row's SDK); the live view's snapshot is version 6. Each has a proxy block
   after the route (`log::push_proxy`): the kind, the flags (bit 4: the flow left out; bit 5, from version 7: the
   proxy's address is on the user's own network; bit 6, from version 7: the engine could not tell it was a messenger's
   proxy, only on an inferred kind's record left out), the destination asked for, the proxy's own name, its network's
   organisation, the cover and the trackers' ids (at most eight); six counters are appended (declared, with a password,
   inferred, substituted, taken back, covers kept out). Version 5 of the snapshot added one bit, bit 1 of the
   destination's flags: the first hop is shown here only; version 6 carries the log's version 7 block, its bit 6 never
   set. The network part's Kotlin side reads the log's versions 1 to 7, bits 5 and 6 only from version 7. The choice
   for one app (R3, unit C) changes neither format: a covered flow's record has the shape of one kept with the switch
   on, and no bit says why it was kept, so a searcher learns nothing more from a record; the screens tell which rows
   the choice could cover from the facts both formats already carry and the UIDs the network part knows, by the
   engine's own vectors (`core/net/testdata/logged-apps.tsv`). Unit S2 (decision 11) took the log to version 8 and
   the snapshot to version 7, each in the shape before it: only the route 3 is new, read from those versions on.
   - **"On your local network"** is one rule (`core/net/src/local.rs`, with a table of vectors both sides hold),
     decided where the proxy is named from the network beneath's on-link prefixes, which the network part hands over
     with its transport, and kept whatever the switch says, since it names nothing: link-local; an on-link prefix,
     global IPv6 included, never of length 0 nor wider than `/16` or `/48`, and on a cellular network only the link
     addresses' own, IPv4 from `/24`, since a data call may report its default route with no gateway and a wider
     prefix there would take in other subscribers; private addresses on Wi-Fi and
     Ethernet only; CGNAT and `fec0::/10` only by a prefix.
10. **SOCKS5's `UDP ASSOCIATE`** (the proxy record's unit U, 2026-11-25, after its plan's audit): an app that sends its
    UDP through its own SOCKS5 proxy, as Telegram's calls through a proxy may, keeps that proxy's address out of the
    history with the switch off, as for its TCP (R1).
    - **The request.** Command 3 is read beside `CONNECT`. Its `DST` is the client's own source (RFC 1928, section 6),
      never a destination: it names nothing, the switch on or off, and the control flow keeps its own server's names.
    - **The reply.** Once the server confirms, as for `CONNECT`, its bytes are read on, across reads, until the reply's
      `BND` is whole, by the engine's own fuzzed SOCKS5 parsers: at most 266 of the server's bytes, its choice of method
      and RFC 1929's success included. The relay is tied before the read that completes `BND` reaches the app, which
      cannot send to the relay before it knows the port.
    - **The tie.** While the control flow is open, the app's UDP flows that go directly to that flow's own server at
      `BND.PORT`, and those that come in from that server on any port, are the app's own proxy's, with its first hop.
      The tie is at the server that confirmed with its own bytes, never at `BND.ADDR`: otherwise an app's server could
      answer with a third party's address and make the app's plain UDP to it read as a proxy's (R8). `BND.ADDR`
      elsewhere is counted. Only an app Android named, on a flow read for proxies, ties; never the user's tool's flows
      nor a chained or tunnelled app's. Apps that share a UID share its associations, as they share everything Android
      tells of a flow; an SDK Runtime's sandbox has a UID of its own, so its UDP is never tied to its app's proxy.
    - **The relay's flow.** At its birth it gets the proxy's kind, the relay's names and network, the control flow's
      setting and password facts, its trackers' marks on the relay's names, and whether it is local. On a flow its app
      began, the first datagram's SOCKS5 header adds the marks on the destination it names and, with the switch on,
      that destination, which then names the flow, through the same naming under the flow's lock as a `CONNECT`'s
      request; a fragment, or a header that does not parse, gives none. No hello ever names a relay's flow, the switch
      on or off: a hello the app sends on it, as plain QUIC to the relay's port, only adds its trackers' marks (the
      unit's review, engine M1).
    - **Lifetime and bounds.** An association ends with its control flow (RFC 1928, section 6); two on one relay port
      each count, so that the tie goes only with the last; none is handed over, as a stop ends every flow first. At
      most 16 for each app and 256 in all, so that one app's flood forgets only its own: a full table, which takes
      sixteen apps at their share, forgets the oldest of the app that holds the most.
    - **Records.** No format changes: the relay's flow is an own proxy's flow of kind SOCKS5. Two counters are appended,
      each written as `-` in a release's dump, as the six before them are: the associations tied, and among them the
      replies whose relay named another address or a name.
11. **The network's own proxy carries direct apps where they cannot connect directly** (the proxy record's unit S2,
    2026-11-27, after its plan's audit and the maintainer's decisions of 2026-11-26). Decision 4 found that a network's
    own proxy reaches no app started inside the VPN: on a network that requires its proxy, such an app reached
    nothing, while the resolver went through the proxy ([ADR 0042](0042-dns-of-apps-that-go-directly.md), "Android's
    proxy"). The engine now sends a direct app's TCP through that proxy by HTTP `CONNECT` where a direct try fails, as
    Android would have given the app the proxy without the VPN (`core/net/src/connect.rs`, the protocol, pure;
    `engine/beneath.rs`, the setting and the ways). The VPN's own link still gets no proxy (`setHttpProxy` is not
    called), so every app's flow still reaches the engine, tracker blocking still reads it, and chained and tunnelled
    apps are unchanged.
    - **Which proxy.** The one the resolver settles, in one settle for both (ADR 0042, "Android's proxy", point 8): the
      network's own direct proxy (`LinkProperties.httpProxy`), at most two addresses, each with its port. Never
      Android's global proxy (the reason `global`), which Android already gives every app inside the VPN (the plan
      audit's M3); never a PAC file (`pac`); never a proxy on the loopback (`loopback`, the maintainer's decision 3), on
      a link-local address (`link-local`) or on one of the phone's own addresses (`own`); none for a proxy's name the
      network beneath did not resolve (`unresolved`). On Android 17 a proxy on the local network is used whether or not
      Datapavan holds the local-network grant, since the engine's and the resolver's connections to one reached it
      without the grant when measured ([ADR 0034](0034-network-permissions.md), decision 5); "Now" advises the grant
      beside it (S2's review, M2). The settle is one pure function, `NetworkProxy.settle`, and the hand-over a class of
      its own, `BeneathHand`, each held by JVM tests (S2's review, m5). A proxy on the phone at a port
      that a circumvention tool installed is known to use is named in "Now" as that tool's, with a button to the chain,
      which is how Datapavan sends apps through a tool.
    - **Which flows** (`beneath::takes`). Only a direct route's: a chained app's flows go to the tool, and a tunnelled
      app's into its tunnel, before any of this. Never through the proxy: loopback, link-local, multicast and broadcast
      destinations; one within the network's on-link prefixes (`OnLink::on_link`), while a private address on another
      subnet may go through it, as Android would send it; a stand-in and the tunnel's DNS address; the proxy's own
      addresses and any of Android's setting, so that a proxy is never put in front of a proxy; a destination of a family
      the network has not, from the setting (IPv4: an IPv4 address of its own, not link-local, and an IPv4 default
      route; IPv6: a `2000::/3` address and an IPv6 default route); and a destination the proxy's exclusion
      list names, by its address written out or by its name from Android's resolver's answers. UDP never: no HTTP proxy
      carries it.
    - **The exclusion list** is read by Android's rules in twins, `connect::excluded` and `NetworkProxy.excluded`, held
      to one table (`core/net/testdata/proxy-exclusions.tsv`): comma-separated entries, `*` matching any run, a leading
      `.` taking the subdomains, ASCII letters alone folded, and only the code points up to U+0020 trimmed, alike on
      both sides, so that the resolver and the engine never send one server two ways. Both read the list whole, as
      Android gives it (the engine's cut at 4 KiB is gone since S2's review).
    - **The order** (the maintainer's decision 1; the plan audit's C2 and M6). Directly first, within
      `Limits::beneath_direct` (3 s). No address of that family (`EADDRNOTAVAIL`) is the app's error at once and goes
      nowhere else; "network unreachable" (`ENETUNREACH`), which a network that lets out only its proxy may answer by
      ICMP, goes on to the proxy, as any other failure does, a server's own refusal among them (S2's review of the
      engine, M1). The proxy
      comes first only once `Limits::beneath_failures` (3) distinct servers failed directly and opened through it
      within `Limits::beneath_window` (60 s), with no direct success between, so that a hostile proxy that answers
      `200` to everything never captures a network that lets direct connections through. A direct success ends it at
      once; after ten minutes one connection, and only one, tries directly first again. The proxy's connect is bounded
      by the direct share, its answer by `Limits::beneath_answer` (10 s). When both ways fail, the app sees the direct
      way's own outcome; a direct try that ran out of its share, or a proxy that came first and opened nothing, hands
      the rest of the connection's 60 s to a direct try.
    - **"Send apps through this proxy"** (decision 1): a switch under the network's proxy line in "Now", off unless the
      user turns it on, for a user who set that proxy up as a privacy proxy of their own. It is kept by the network's
      transport and the proxy's host and port (`ThroughProxy`), not by the network's name, which Android gives no app
      without the location permission. With it on, the proxy is the only way for every flow `takes` allows; its
      refusal is a reset, and its `5xx` or its silence an ICMP error. **It never fails open** (S2's review, m2, its
      S-tier option, taken as decision 1 says it: every direct app's TCP goes through the proxy, as Android would send
      it): where Datapavan has no address of the proxy yet, or none it can use, the network part hands the engine the
      switch's hold (`Beneath::holds`: the user's choice and no address) in place of none. It is handed at a new
      network whose switch is on, before the lookup of a proxy given by name (`BeneathHand.settling`), never none
      first; at a lost network whose switch was on, as the hold of no network, kept until a network's own settle
      (`BeneathHand.none`); when the switch is turned on, while the name is looked up; and by the settle while no
      address can be used (unresolved, link-local, the phone's own), never for a proxy on the phone itself, which the
      engine never uses (decision 3) and whose line has no switch. A new direct flow that `takes` allows waits, its SYN
      unanswered, looking at the setting each 25 ms (`HOLD_LOOK`, by tokio's timer: a `Notify` for it changed the
      packet path's code), until a setting replaces the hold, and goes as that one says: through the proxy that came,
      directly where none did or the switch went off. It fails as an unreachable network (an ICMP error) once
      `Limits::beneath_direct` (3 s) passed since the hold began: no longer than the direct try that comes first
      without the switch, and the app has sent its SYN at most twice (Linux's retransmissions at 1 s and 3 s); a literal
      proxy settles at once and a name in one lookup, while a setting that cannot come fails each flow at once from
      then on. A circumvention tool's flows, handed or the chain's, and a tunnelled app's to its local network are not
      held; chained and tunnelled apps' other flows never reach the network beneath. Nothing changes with the switch
      off. "Now" then says, in a line of its own with the switch, that the connections it would send through the proxy
      fail, and how to let them go directly. What stays open is Android's own lag: a flow in the moment between Android
      moving its default network and its callback reaching the network part goes on the previous setting (the one
      before's switch holds it; with none before, directly), as an app that follows the setting without the VPN reads
      it only from Android's broadcast. A choice whose setting was not seen at any settle for 90 days is forgotten, with
      its key (S2's review, m3).
    - **The bytes.** `CONNECT <address>:<port> HTTP/1.1`, `Host` and a blank line, as the resolver's `ProxySocket`
      writes it, an IPv6 address in brackets with no zone. No `User-Agent`, `Proxy-Connection`, `Connection` or
      `Proxy-Authorization`. The answer is read with `peek` and then exactly what was peeked, up to its head's end
      within 8 KiB, so that a server that speaks first reaches the app whole; the head is never kept or logged. A `2xx`
      opens the flow; a `407` is refused, counted and said in "Now", in a line of its own after the network's line and
      its switch, as some connections refused (S2's review, M1), since Android keeps no password for a network's proxy; another `4xx` is refused, and a request by name may follow; a `1xx` or `3xx` is refused with none; a `5xx`
      is unreachable.
    - **By name** (the maintainer's decision 2; the plan audit's C1 and M1). Only after the proxy refused the address
      with a `4xx` other than `407`, on a new connection, and only with the flow's own name: the address's sole name in
      Android's resolver's answers (`Names::sole`), the one that names the app's flow, and only where that app's own
      lookup was given it (S2's review of the engine, M2): the name keeps the UIDs of the latest four apps it was given
      to, so that an app that connects by an address it carries, or got from a resolver the engine cannot read, goes by
      address alone; never a name whose answer carried an ECH configuration, nor one tracker blocking refuses for the
      app. While the proxy is held, the network part's DNS answers go to the apps with a time to live of 0, as while a
      chain or a tunnel is on, so that Android's one cache for a network never answers an app the engine did not see. Never by name for a circumvention
      tool's flow (the chain's tool or any tool handed), nor for any flow of an app whose route is the tool or a
      tunnel, nor for a flow whose app Android did not name, whatever any log switch says. Once a name opened where its
      address was refused, names come first through that proxy while the setting holds.
    - **Bound to its network** (the plan audit's m5). Each socket to the proxy goes through `Platform::protect_on`,
      which protects it and binds it to the network whose handle the setting holds, and refuses, counted, once the
      network beneath is another: nothing is written then. The proxy's second address is tried first once the first
      could not be reached. What was learned lives with the setting, behind an `Arc`, so that it crosses to the next
      engine and survives a new setting of the same proxy.
    - **The record.** A flow through the proxy is the app's own flow to its destination, named as a direct one is, with
      the route `Via::NetworkProxy`: route 3 in the log's version 8 and in the live view's snapshot version 7. The
      proxy's address is not kept per flow, nor why the proxy was taken; "Now" shows the address on its own line. A
      flow whose destination is hidden keeps route 3 and no destination; the history counts route 3 among the direct
      flows, and says it went through the network's proxy. Eight counters follow the 73 (tries, opened, refused,
      password, unreachable, by name, `protect_on` refused, and the flows the switch's hold kept waiting), in a debug
      build's dump only, beside its line `beneath-proxy ADDRESSES WHY first=direct|proxy names=0|1 password=0|1
      always=0|1 no-grant=0|1`, `hold` in place of the addresses for the switch's hold.
    - **"Now"** shows the network's line beside the whole phone's while both are set, since the engine uses the
      network's proxy whatever the global setting is. Where the engine has the proxy, the line says that an app that
      cannot connect directly is connected through it, as Android would, and that the proxy then sees where it
      connects; otherwise why not: the phone itself, or a known tool's port, or no address Datapavan can use. The line
      and its switch stay whatever the proxy answered: a password asked for, and on Android 17 the local network without
      the grant (advice, with a button that asks for it), are lines of their own after them (S2's review, M1 and M2). A
      proxy is on the local network by its range or within the network's own prefixes (m9). A row of "Now" says when a
      connection went through the network's proxy, and the history says it in the past tense, as the proxy of the
      network the connection was on (m1).
    - **Blocking first** ([ADR 0053](0053-tracker-blocking.md), decision 4 (h)): a lookup, an address or a hello that
      blocking refuses gives the proxy nothing of the app's but, for a hello, the `CONNECT` by address and an empty
      tunnel.
    - **Measured** on the emulator (Android 15 with root, 17 without, part of 10; measurements 7, "After the engine's
      network proxy", against `adcdd7f9`): on a network that lets out only its proxy, an app started inside the VPN
      that was refused before reached public servers through it, by address, with no `User-Agent`, in 0.3 to 0.6 s; on
      a network that allows both, the engine went directly and the proxy saw nothing of the fixture unless the switch
      was on; a `407`, a refusal by address followed by the flow's own name, an exclusion, blocking and a chained app
      each did as above.
12. **Plain HTTP where the network's proxy refuses `CONNECT` to its port: the forwarder** (the proxy record's
    forwarder, 2026-11-28, after its plan's audit and the maintainer's decisions of 2026-11-27, «بله، تایید», "yes,
    approved", on the plan, and «بله، اول CONNECT», "yes, CONNECT first", on the audit's M1). squid's shipped
    configuration refuses a `CONNECT` to every port but 443 (`http_access deny CONNECT !SSL_ports`, measured in the
    proxy lab), so under decision 11 an app's plain HTTP behind such a proxy got nothing.
    - **`CONNECT` first.** Every flow through the network's proxy goes as decision 11 says. Only where the proxy refuses
      the `CONNECT` (a `4xx` other than `407`, by address and then by the flow's own name) is a flow that decision 11
      may name to the proxy rescued (an app Android named, no circumvention tool, its route direct): its SYN is
      answered once a connection of the forwarder's own reached the proxy, so that a proxy gone hands the flow back to
      decision 11's tail; its first request is awaited with no cut but the flow's connection time (the audit's M2:
      `HttpURLConnection`, Chromium and WebView write late); and it goes to the proxy in absolute form (RFC 9112,
      3.2.2), as Android's HTTP clients send it to a proxy without the VPN. The refusal is kept per proxy and port as the
      port's policy, not a site's (the forwarder's review, M1): a port is learned only once the proxy refused two
      distinct names there at both of decision 11's steps for flows whose first request was then forwarded, within ten
      minutes of each other, so that a flow with no name of its own, a TLS flow (port 443 is never learned) or one
      site's `403` teaches nothing. A learned port sends later flows to the forwarder at once for ten minutes from its
      last confirmation, after which it is tried by `CONNECT` again; a `CONNECT` to it that opens, for any flow,
      forgets it (at most 16 ports, the oldest giving way), and a flow sent at once whose bytes are no request it can
      forward goes by `CONNECT` on the forwarder's own connection. Where the proxy carries `CONNECT` to the port, plain
      HTTP is tunnelled as before: the proxy is asked only for the destination and parses nothing, though it carries
      the request in clear and can read it, as any network on the way can (PRIVACY.md: the proxy sees what apps send
      unencrypted).
    - **The rewrite** (`core/net/src/forward.rs`, pure): only the request target changes (`GET /p HTTP/1.1` becomes
      `GET http://<Host>/p HTTP/1.1`, the `Host` value copied; `OPTIONS *` becomes `OPTIONS http://<Host>`, RFC 9112,
      3.2.4; an HTTP/1.0 request with no `Host` takes the destination's address), and a `Transfer-Encoding` read as
      `chunked` in another case or with white space is written `chunked`, since tinyproxy 1.11.2 matches it in lower
      case alone and otherwise sends no body (measured). Nothing is added: no `Via`, no `X-Forwarded-For`. The reader
      is strict, so that two parsers cannot disagree on where a request ends: CRLF only, one `Host`, one
      `Content-Length` or one `chunked` coding, never both, chunk sizes with no extension, no trailer (tinyproxy knows
      none, and a proxy that does not could read one as the next request), field names compared exactly. Refused:
      `Upgrade` (a WebSocket goes by `CONNECT`, RFC 6455, 4.1), `Proxy-Authorization` (the app's credential is never
      the network's proxy's), and a `Connection` field that names `Host`, `Content-Length` or `Transfer-Encoding`.
      `Expect` goes on: neither squid 6.13 nor tinyproxy 1.11.2 read a request out of an `Expect` request whose body
      held a whole one (the audit's m6). squid refused each early (`403` to port 81, outside its
      `Safe_ports`; `417` for an expectation it does not know); tinyproxy ignores `Expect`, forwarding the request
      whole with its body as a body (`204` for `Expect: x-lab`) or failing to reach the origin (`500`, port 81 having
      no listener in the lab), and closes after one answer. Every request on a kept-alive connection is framed and
      rewritten, and must name the first one's `Host`; the proxy's answers and its close pass through unread (tinyproxy
      answers one request per connection).
    - **The name** (the audit's M3): the `Host` must be a name Datapavan's own resolvers gave the flow's address, and
      the flow is then named by it; tracker blocking's verdict is read for it again, and a blocked `Host` is reset and
      recorded blocked; an excluded `Host` goes directly where the direct way had not failed and the user did not
      choose the proxy (m16), else it is reset. A first request that cannot be forwarded goes by `CONNECT` where one
      may still be tried, else it is reset; a later one is reset after the requests before it.
    - **A stage behind the relay** (the audit's M4, its option a; `core/net/src/engine/forwarding.rs`): the relay's
      upstream is one end of a loopback TCP pair, and the forwarder's task holds the other end and the connection to
      the proxy, so the relay, `accept`'s task and the packet loop are decision 11's, and the sniff, the gate and the
      byte counts see the app's own bytes. Two descriptors and a copy per byte more, for plain HTTP through a refusing
      proxy only. Every buffer that holds the app's bytes is `Zeroizing` and grows only by replacement (m3).
    - **The record:** no format change: route 3 in the log's version 8, the flow under its first `Host`, never a path
      or a query (an end-to-end row of the network lab checks the log, the kept flows and the live view's snapshot).
      Five debug-only counters, 81 to 85 (forwarded, by `CONNECT` after all, reset, a first byte later than 250 ms,
      sent at once by a refusal kept), written as `-` in a release's dump.
    - **Limits:** a server-first protocol on a port whose refusal is kept waits for a request that never comes and is
      reset at the flow's connection time, though `CONNECT` there might have worked for another name than the one the
      proxy refused; through both lab proxies `OPTIONS *` reaches the origin as `OPTIONS /`; a `Host` port with leading
      zeros (`:080`) is refused, though both proxies read it as 80; a WebSocket over `ws://` behind such a proxy fails,
      as without the VPN; through tinyproxy, requests pipelined after the first are dropped with the connection, as
      without the VPN, and clients retry them.
    - **Checked** by 134 shared vectors (`core/net/testdata/forward-requests.tsv`, read by forward.rs's tests whole,
      cut at every byte and byte by byte, and by the proxy lab, which holds what squid and tinyproxy sent the origin
      for each to two measured columns), a fuzz target compared with httparse, 25 hand mutants each killed, the
      network lab behind a proxy that behaves as squid's default and one that tunnels every port (95 rows: late
      writers, two names on one address, a 60 KiB head, a WebSocket after a kept-alive request, a blocked `Host`
      reset before the stage passes a byte), the proxy lab (squid 6.13 and tinyproxy 1.11.2 as Debian ships them, 144
      rows, which the `proxies` shard runs before its emulator rows, so that a changed pin, a changed proxy or a vector
      row added without measuring fails CI), and the emulator's `proxies` shard, whose row of decision 11 now includes
      a plain request behind a proxy that refuses `CONNECT` but to 443 (under its `Host`, with the app's `Host` and
      `User-Agent` and no field a proxy adds, after a refused `CONNECT` to that site's port 80).
    - **Measured** on the emulator (Android 15, `scripts/measure-proxy-settings.sh` pass 11, the recorder refusing
      `CONNECT` but to 443): the recorder, as the proxy, answered `http://example.com/fwd` in 407 ms after the
      `CONNECT` by address and by name were refused, the request reaching it in absolute form with the app's own
      fields alone (`User-Agent,Host,Connection,Accept-Encoding`); the next request to port 80 in 203 ms with no
      `CONNECT`; port 8080 likewise; a WebView's page; HTTPS by `CONNECT` as before; no first byte later than 250 ms.
      Its blocked plain-HTTP name is stopped at its lookup, before any flow, so tracker blocking's DNS answer comes
      first there and the forwarder never sees that `Host`. A blocked `Host` on a forwarded flow is held by the network
      lab's row above (the tracker gate resets it before the stage passes a byte), and the stage's own re-check by
      `beneath::a_blocked_host_the_gate_let_go_unread_is_reset_at_the_stage`, not by the emulator.
    - **Size:** against `main` at `47bc14d6`, both built with the size passes' `ndkbuild3.sh` (the `/c` remap, then
      `llvm-strip --strip-unneeded`), the forwarder's tip `31cef934` takes 26,960 bytes more on x86_64 (2,067,656 to
      2,094,616), 24,592 on arm64-v8a (1,854,832 to 1,879,424) and 17,576 on armeabi-v7a (1,368,760 to 1,386,336), where
      its plan expected 16 KB on x86_64 (ADR 0053, the third pass). By Gradle, against `main`'s gate build of 2,067,768
      bytes on x86_64, 26,960 to 27,024 more (the tip's steps' figure with Gradle's offset of 112 bytes at `main`
      or of 176 at the fourth pass's tip, since only that tip was built by Gradle): about 2,094,760 bytes, some 2,400
      under the gate and 5,800 past the 8 KiB stop line the record's plans keep under it. As that stop asks, the
      forwarder lands on `main` only with the cold paths' fourth pass (ADR 0053), which frees 32,104, 31,592 and 30,000
      bytes: Gradle's gate build of the two gives 2,062,688 bytes on x86_64, 1,846,736 on arm64-v8a and 1,356,528 on
      armeabi-v7a, x86_64 34,464 bytes under the gate and 26,272 above the stop. The forwarder's fix round (its review's
      M1 and minors) adds 4,760 bytes on x86_64 by the steps' build: Gradle's gate build of the tip that lands
      (`fb37710d`) gives 2,067,448, 1,850,984 and 1,359,904 bytes, x86_64 29,704 under the gate and 21,512 above the
      stop, 320 bytes below `main`'s.

## Consequences

- Advanced says, for the first time in the field as far as the research found, where an app went through its own
  proxy and where that proxy is, for the declared kinds with no guess at all.
- **Accepted limits**, each with its reason:
  - Proxies inside TLS or QUIC (HTTPS proxies, Signal's own inner TLS, QUIC-based proxies): their request is encrypted.
    Signal's and WhatsApp's are inferred instead; others are not seen as proxies.
  - Apps pointed at a proxy on the phone itself (Orbot's SOCKS port): loopback never enters the tunnel, so their traffic
    shows as the proxy app's, as chaining's tool. Android's PAC handler is the exception: its connections for other
    apps come into the tunnel under its own UID (decision 4).
  - **Under a PAC file,** an app's connection to the proxy the file names is shown as the app's own proxy, since the
    network part has the file's proxies only through the app's own bytes. A check per flow through `ProxySelector` would
    tell a global PAC's apart; it is left for the unit that measures a PAC on a VPN's link.
  - **A browser engine inside an app** may use Android's PAC proxy, which is then shown as Android's, or may not use
    Android's setting at all inside the VPN (WebView 124 went through the handler; WebView 145 ignored both the global
    proxy and the global PAC inside the VPN, in measurements 7).
  - **Android's setting by name** matches only where Android's resolver gave the name: a fronted proxy whose address
    also serves others strips every app's plain requests to it at that port; a `CONNECT` to the setting that it refuses,
    a 407 for example, is unconfirmed and keeps its address; a link-local host with a zone never matches.
  - **"Local"** follows the prefixes the network part last handed over: until the first change of the link properties
    after a start, the rule is the one for no network; a proxy on the user's own laptop behind the phone's hotspot is
    not local; on Wi-Fi from another phone's hotspot, the carrier's private addresses beyond it count as local. A
    history row says "local" only from log version 7 on, or by its kept address before.
  - **The PAC handler** is known by its UID, only a system app's with an application UID of its own; a history row of
    that UID cannot say whether a PAC was set then.
  - Only the first request on a connection is read: a plain HTTP proxy's later requests on a kept-alive connection to
    other hosts are counted under the first.
  - An inferred proxy's destination beyond it is encrypted: Advanced shows the proxy, not where it leads.
  - A WhatsApp proxy given by a name that Android's resolver answered, reached over TLS on 443, sends a name a DNS
    answer tied to its address: it looks like a link preview, and is not named (the same proxy on 5222 or 80 is).
  - Substitution reads ten minutes: a user who turns a proxy on within ten minutes of a direct connection sees it named
    only after them; one who turns it off sees it taken back at the first direct connection.
  - Forks of the three clients are not recognised until a row of `clients.tsv` names them. The list, as Telegram's
    ranges and the names, is compiled into the engine and kept out of the data pack, as the resolvers are (the network
    part's data alone): an update of any of them needs an app release (S-n4).
  - **An app that runs a proxy-shaped server of its own** (F1): a server that answers a SOCKS or `CONNECT`
    request as a proxy does confirms it, so the app can leave its destination out while the switch is off. Its first
    hop, the server's own address and name, is still shown in "Now" (decision 8, R2); only the history lacks it. Its
    bytes, its states and its trackers' marks stay, and turning the switch on keeps the rest. The app, not Datapavan,
    declares a flow proxied.
  - **A hello's tie needs the app's lookups** (F3): under strict Private DNS, or for an app whose lookups do not pass
    through the tunnel (its own DNS over HTTPS), a fake-TLS proxy is not inferred from its hello; Telegram's obfuscated
    start and WhatsApp's header still are.
  - **A Telegram fake-TLS proxy whose cover resolves to it** (S-m4): the engine passed that answer, so the name is
    tied and the flow is named by it with no proxy, as for WhatsApp's below. The open research is Telegram's hello
    template.
  - **Substitution counts TCP connections alone** (R-m5): with "use proxy for calls" off, Telegram's calls reach its
    relays over UDP directly while its chats go through the proxy; those datagrams do not cancel the proxy's naming,
    which is right for the chats. That Telegram makes no TCP connection to its ranges while a proxy is set is read
    from its behaviour, not from its documentation: where it did, its proxy would not be named (a false negative).
  - **The take-back's window** (F2): ten minutes after a naming; a direct connection later, as when the user turns the
    proxy off, takes nothing back, as the proxy was real until then. Past 1,024 held-back records, the oldest is
    written as it is. Past 4,096 flows taken back or substituted, the oldest is forgotten, and a record of it that
    comes later still is written as it is. A taken-back flow's records say, left out, what it was inferred to be, with
    the mark that the engine could not tell (log version 7); a batch already handed to the logger keeps no mark.
  - **Signal's window after a third party** (F7): ten minutes; a 3-D Secure challenge longer than that, or a page
    Signal opens without a listed host before it, is named its proxy while Signal goes through one.
  - **The packet path is not zeroed** (S-m6): the tunnel's packet buffer, the fragment reassembler and a held Fast Open
    SYN carry a credential's bytes before the relay; zeroing them would cost every packet a write.
  - **A proxy connection kept open** (decision 8, R2): a messenger that keeps its proxy connection open, as Telegram
    does while it runs, keeps its first hop in "Now" all that time, hours included. Someone who unlocks the phone and
    opens "Now" within it, or within ten minutes after, sees the first hop. The words say "while the connection is
    open".
  - **Memory past the window** (unit A's plan audit, finding 8). Open flows hold their first hop while they are open.
    Waiting segments, places and the table of ends hold it until the first sweep after their window: at the next
    reading of the apps' states, so at most a minute with the screen off, and while the phone sleeps, until it wakes
    and the first reading or view comes, about 5 s after the screen comes on. Held-back records made while the switch
    was on hold it until they go on to the batch. The view's cache of an address's organisation can hold a first hop's
    address past its place, until the next change of the switch, an overflow of the cache or a clear (unit A's
    review, engine, note 8). A dump of the process's memory in that time holds it. Stripped strings are not zeroed:
    the engine zeroes only credentials.
  - **A batch already handed on** (decision 8, R1): a segment cut between a request and a slow reply, in a batch the
    logger already handed to the network part before the reply confirmed the proxy, stays as written, with the proxy's
    address and name.
  - **129 names** (unit A's plan audit, finding 21): a named first hop is one place per name, so an app whose one
    server has 129 DNS names can push its own real first hop out of "Now" with first hops of its own, each of them
    shown.
  - **SOCKS5's `UDP ASSOCIATE`** (decision 10, unit U):
    - *A relay elsewhere.* A reply whose `BND.ADDR` names another address than the control connection's own server
      ties nothing there: the app's UDP to that address keeps its address in the log with the switch off, as before
      unit U, and the reply is counted. By default Dante, 3proxy, shadowsocks-libev, Xray, sing-box and gost answer
      with the address the control connection reached, and shadowsocks-rust with its listening address, zeros when it
      listens on every address, so their relays are tied; a public address configured apart (3proxy's `-Ni`, Xray's
      `address`, gost's `publicAddr`) or shadowsocks-rust listening on another address or a name is elsewhere (read
      from their source, 2026-11-25).
    - *The first datagram only.* A relay flow's later datagrams to other destinations are neither named nor matched
      for trackers, which keeps the send path, read for every datagram, as it is: an SDK can avoid its mark after its
      first datagram, and with the switch on the history names only the first destination.
    - *Before the reply, and across a restart.* A UDP flow the app begins before its server's reply, as a client that
      knows a same-port server's relay in advance can, is never tied, since a flow is tied once, at its birth. An
      association ends with its control connection and is not handed to the next engine: after the tunnel is set up
      again, the app's UDP to the relay is an ordinary flow until it associates again.
    - *The bounds.* At most 16 associations for each app and 256 in all are tied at once; past them the oldest of the
      same app goes, or of the app that holds the most, and its relay's new flows are ordinary flows.
    - *An address, not a service.* The tie is the app's UDP to the server's address at `BND.PORT`, and from it on any
      port. Where that address serves others too, as a cloud's load balancer may, the app's own UDP there to another
      service on that port loses its address with the switch off, which is wider than TCP's residual of the one flow
      that confirmed; it is still only the app's own flows, to a server that confirmed SOCKS5 to it.
    - *NAT64.* An app that reached its proxy by an address of the NAT64 prefix, while the reply names the server's IPv4
      address, has its relay elsewhere: not tied.
    - *No emulator check.* microsocks, the proxy lab's SOCKS5 server, answers every command but `CONNECT` with code 7,
      and the fixture sends no UDP: the network lab's test through the whole engine is unit U's check.
  - **The choice for one app** (decision 8, R3, unit C):
    - *Android's setting and a local proxy.* A chosen app that sends through Android's setting, or through a proxy on
      the user's own network, keeps its destination out with the switch off: those proxies carry other apps'
      connections too. That holds where the engine's facts say so (review C-engine, major 1), and the confirmation
      says that a PAC file's proxy, or the setting given by its name, may be logged as the app's own:
      - *A PAC file's proxies.* An app reaches a proxy a PAC file names under its own UID (decision 4), which the engine
        reads as the app's own: a chosen app's flows to it are covered, unless it is on the user's own network.
      - *The setting given by name.* Outside strict Private DNS the engine tells it by Android's answers for the name,
        which its names table holds among at most 8,192 addresses, the oldest going first: after a day's browsing the
        entry can go, and until Android's resolver answers the name again where the network part sees it, a chosen
        app's flows to the setting's proxy are covered. Under strict Private DNS the network part looks the names up itself, hands the
        addresses with the names from then on, and hands no chosen app while it has none, a lookup that finds none
        included; an address the app's own lookup got and the network part's did not, as a name that answers by asker
        can give, is covered all the same.
      - *A change of the setting or the network.* The facts are set when a flow is named; the engine reads them again
        for a chosen app's open flows when the setting or the network's prefixes change, and a flow that became the
        setting's or local goes back to its first hop. A fact never goes from true to false, so nothing is named anew.
      - *A private address beyond the link.* On Wi-Fi and Ethernet every private address counts as local, so a chosen
        app's proxy at one that is routed beyond the link (a hotel's or a company's `10/8`) is not covered: the safe
        direction (the study's 4.2).
    - *Connections opened before the choice is handed.* After each start no app is handed before the tools are read,
      nor, under strict Private DNS, before the setting's names are looked up: a chosen app's connection opened before
      then, as a messenger's to its proxy as soon as the VPN is up, keeps its first hop alone for its whole life, as
      one opened before the choice does, and its row says so (review C-rest 13).
    - *A reinstall, or a package that joins the UID,* ends the choice; the app's rows say so while the network process
      that saw it lives, a removal it saw and the package back after it included, and nothing of it is kept on disk.
      A restart of the network process between the removal it saw and the new install ends the choice silently.
    - *An archived app.* An app that Android or its store archives for disuse, on Android 15 and later, reads as
      removed: its choice ends, and the user chooses again once it is restored.
    - *The SDK Runtime's rule* rests on AOSP's numbering, which Android's own call confirms only from API 35 (the
      emulator's check compares them); on Android 13 and 14 it is the same numbering, with nothing to compare. A
      chosen app's isolated and app-zygote processes (90,000 to 99,999 in each user's range) run under UIDs of their
      own, which the choice does not cover: the safe direction.
    - *A choice made by mistake* logs one app's proxy from then on, and its confirmation says so; an app that carries
      other apps' connections has theirs logged as its own.
    - *Who opens the app's page* sees its choice, until W9's lock; the count of apps chosen is under the switch.
    - *A tool whose key Datapavan has not recorded yet* is an ordinary app (unit B's B6), so the choice covers it if
      the user picks it, until it becomes the chain's tool, which ends the choice at the next hand-over.
    - *Another user's copy of an app* (a vendor's dual app, Android's clone profile) is not offered the choice in this
      user, whose package it would name.
    - *The store at rest* is plain preferences of the network process, as the chain's list of apps is, with each chosen
      app's first install time: an app removed while the tunnel was off stays in it until the network part runs again.
  - **The tool's own row** (decision 8, R10, unit D):
    - *What the tie misses.* The tool's direct connection for a chained app is tied only when it opens within ten
      seconds of the request: to the address asked, to a name the engine gave its address, or with a TLS or QUIC hello
      naming what was asked, each at the same port. A name the tool resolved privately (its own DoH, or through its
      server) for a connection with no readable hello (plain HTTP, or ECH, whose outer name is not the one asked), a
      connection to another port or opened later, a chained app's UDP peer the tool opens again after its idle mapping
      ended, and the tool's connections to the chained apps' resolver (ADR 0038), which the ring does not hold, are the
      tool's own: shown in "Now" for their window and, under the tool's choice, logged with their addresses. The
      choice's words say so. An unchained tool has no chain to tie to: all its flows are its own. A tie made at the
      hello strips the flow's records still held back or gathered for the next batch; a batch already handed on stays
      as written. The hello is the tool's to write, so a tool can name a chained request as its own cover and keep its
      own records out of the log under the choice: that only takes from the choice, never below R1.
    - *The bounds.* The ring of what the chain asked holds 256 requests of the last ten seconds, the oldest forgotten
      first, and starts empty after a hand-over. The tied flows are those open, held for their states or waiting in
      the next batch, each forgotten once its last record leaves; past 4,096 of them an ended one goes first, else the
      oldest. Past either bound, a flow the tool opened for a chained app is the tool's own under the choice. The ring
      holds 64-bit keys, not names or addresses: two that meet only tie more.
    - *A tied flow under the choice* shows in "Now" as the tool's own, with no window and no "shown here only" mark,
      while its record stays stripped: the tie is the log's, and the live view's rule does not read it.
    - *A tool's own SOCKS or `CONNECT` upstream under the choice* shows in "Now" with no window, and its record keeps
      the first hop, never what it asked for (the request's naming stays unit C's). One to Android's setting, or to a
      proxy on the user's own network, is never covered by the tool's choice, as by unit C's: it keeps its window and
      mark, and its record keeps only its kind.
    - *Trackers win.* A tool's flow whose names the trackers' signatures match is kept in full, tied or not. The
      signatures are read at the flow's birth and at its hello, and the answer kept for 512 hosts, the oldest read
      again past that, all of them anew when new signatures arrive: a record cut before a hello named a tracker may
      still be stripped, and before the signatures arrive the rule does nothing.
    - *Through a tool's open local proxy* (the plan's audit, M4): an app that sends through a tool's proxy port on the
      phone, which the tool's rules then send directly, keeps its destinations out of the history under the tool's row,
      shown in "Now" for their window. Datapavan cannot see the app's side of the loopback. The network screen's line
      about an open proxy port, and that what goes through it is not logged under the app, is drawn for the tool the
      network part found, chained or not; other tools' open ports are not named.
    - *Who is a tool* rests on the signing key, but the chain's tool counts whatever its key, as the user chose it: a
      modified copy reinstalled under the chosen package gets the lean record. A chained tool that is not `Genuine`
      leaves the set when the chain is turned off, and its open connection's next records are then logged in full.
      Briar's contacts on the local network count as its own, the protective direction.
    - *Late tools.* The tools reach the engine a second or two after a start. A tool known late has every place and
      held segment in its window for ten minutes from that moment, and its waiting records stripped; a batch already
      handed on before then stays as written. A tool that leaves the set and comes back gets ten minutes again.
    - *129 places* (unit A's limit): past 128 places of one app the oldest gives way. A tool's places tied to what
      the chain asked are not guarded and go first, but its untied places share the 128: its own other places, and the
      chained apps' destinations the tie misses, can push out its oldest before its window ends. A place first made
      for a tied flow stays unguarded if the tool's own flow reaches it later. Tied places compete by age with other
      apps' places in the 2,048 of all apps.
    - *A plain request held past its window,* of a tool's own `Forward` flow, settles as an empty place of its kind
      (unit A's risk 7, unchanged).
  - **The network's own proxy** (decision 11, unit S2):
    - *A PAC file in the network's settings* is not followed: where the network requires it, apps started inside the
      VPN still reach nothing, and "Now" says that they do not use it.
    - *A proxy that asks for a password:* the connection is refused, since Android keeps no password for a network's
      proxy and the engine has none to give. A proxy may ask for some destinations only, so "Now" says that some
      connections were refused, after the network's line and its switch; with the switch on it adds that those
      connections cannot connect at all, since no direct try is made. Apps already running, and those left out, still
      use the proxy themselves.
    - *A proxy on the loopback* is never used: apps started inside the VPN go directly, and "Now" says so, naming the
      tool where the port is a known tool's.
    - *A name only the proxy can resolve.* Without a VPN, an app that follows the proxy looks no name up and hands the
      proxy the name. Inside Datapavan, its lookup goes to Datapavan's resolver first, and a name that neither the
      encrypted ways nor the network's resolver answer fails before any connection, as the measurement's lab names did.
      Public names resolve there, since the resolver reaches its servers through the same proxy. Stand-in answers for
      such names, as the chain gives, wait for a real network that needs them.
    - *Plain HTTP through a proxy that refuses `CONNECT` to its port.* Plain HTTP goes by `CONNECT` too, and a proxy
      that refuses a `CONNECT` to port 80 refuses it: squid's documented default (`http_access deny CONNECT
      !SSL_ports`, with 443 alone) does; tinyproxy 1.11.2 does only as configured (with `ConnectPort 443` it answers
      `403 Access violation`, and its Debian configuration, those lines commented out, carries it). Other ports a proxy
      refuses for `CONNECT` were refused likewise. Decision 12, the forwarder, now sends such a flow's plain HTTP to
      the proxy in absolute form (RFC 9112, 3.2.2), as Android's HTTP clients send it to the proxy without the VPN.
    - *UDP* never goes through the proxy. On a network that requires it, an app's UDP gets no answer, or an ICMP error
      where the network rejects, as without Datapavan; browsers fall back from QUIC to TCP, which goes through the
      proxy, and calls over UDP fail unless their service falls back to TCP. A WireGuard tunnel's UDP fails there too.
    - *A network that allows both:* apps started inside the VPN go directly while direct connections work, even where
      the network's owner wants the proxy used, unless the user turns "Send apps through this proxy" on.
    - *A network that drops* costs each of the first few servers the 3 s direct share before the proxy comes first
      (measured: 3.6 to 3.9 s for each, then 0.75 to 0.89 s).
    - *One app can turn the order.* The three servers that teach "proxy first" may all be one app's, in one burst, and
      the order then holds for every app on that network until a direct success ends it.
    - *The exclusion list by name* is checked against the address's latest name in Android's resolver's answers alone:
      an address that answers for several names, one of them excluded, may go through the proxy under another.
    - *By name fails closed under an ECH flood* (S2's review of the engine, M3). An app on the phone whose own
      resolver answers with many ECH configurations pushes names out of the table of names that carried one; once a
      live name is pushed out, the guard closes until that name's hold would have ended, and meanwhile no flow of any
      app goes to the proxy by name, only by address.
    - *Memory:* the apps a name was given to add 16 bytes to each address entry of Android's resolver's table, 128
      KiB at most ([ADR 0044](0044-udp-mapping-and-budgets.md)'s figure for the names).
    - *Android 17's local-network grant.* On Android 17's emulator (`dp-api37-16k`), with Datapavan's grant revoked and
      the VPN restarted, the engine's connection to the Wi-Fi proxy at 10.0.2.2 and the resolver's both opened (S2's
      review, M2; measurements 7, its fix round), so neither way withholds a proxy on the local network for want of the
      grant, and "Now" only advises it. Where another build or maker's Android holds Datapavan's protected sockets to
      the grant, each try there times out instead: the engine's within the 3 s direct share, the resolver's within
      1.2 s, and with the switch on the connection fails; "Now"'s advice and its button are the way out.
    - *Not measured:* the switch on Android 15 (that run tapped its words, not the switch); a tunnelled app with a
      Wi-Fi proxy set; a proxy given by a name only the network's resolver knows; the network that requires its proxy
      on Android 10, where Wi-Fi did not reconnect after the setting was cleared.
  - The false positives that need a maker's own network (a Telegram CDN data centre beside its ranges, WhatsApp's link
    previews and backups) are checked in the engine's tests and its network lab, not on the emulator, which must reach
    no outside server.
- **Checks:** unit tests for each parser and rule, fuzzing of the parser (`fuzz_targets/proxies.rs`, synthetic seeds),
  two network-lab tests through the whole engine on Linux's TCP stack (an address of Telegram's ranges on the lab's own
  loopback) and unit U's on its UDP too, with a SOCKS5 relay that answers, the proxy lab (`scripts/proxylab.sh`: microsocks, tinyproxy, mtg built from v2.3.0 at a pinned commit, on
  a network with no way out), and the emulator's `proxies` shard (`scripts/verify-proxies.sh`), which CI runs and in
  which a skip fails: the project's own fixture under package names of its own, which only debug builds add to a
  messenger's clients.
- **Size:** the network part's native library grew by 45,520 bytes on arm64-v8a, 32,832 on armeabi-v7a and 49,232 on
  x86_64 in part 2a (built alike from `main` and from it before part 1: 1,707,608, 1,465,644 and 1,981,256 bytes
  before; 1,753,128, 1,498,476 and 2,030,488 after). After the fix round, rebased onto `main` with part 1 (whose fix
  round measured 1,695,200, 1,256,752 and 1,933,072 bytes, stripped, inside `core`), the library in Advanced's release
  APK 1,772,296 bytes on arm64-v8a, 1,312,792 on armeabi-v7a and 2,017,976 on x86_64, under the 2 MiB gate (2,097,152
  bytes) of each ABI, which is unchanged: x86_64 79,176 bytes under it. Against part 1's figures, built otherwise,
  this part with its fix round adds about 77, 56 and 85 KB. Unit U, against `main` at `5c5dc487` (2,039,896 bytes on
  x86_64): 2,051,208 bytes on x86_64, 1,826,872 on arm64-v8a and 1,356,752 on armeabi-v7a, 11,312 bytes more on
  x86_64 and 45,944 under the gate; the packet path's machine code compared function by function with the size
  pass's tool, every relay's poll inline as before. Unit D, against unit C's tree with D's hand-over (2,060,176 bytes
  on x86_64): 2,068,288 bytes on x86_64, 1,842,672 on arm64-v8a and 1,368,832 on armeabi-v7a, 8,112 bytes more on
  x86_64 and 28,864 under the gate; after its review round, 2,073,752 bytes on x86_64, 1,847,944 on arm64-v8a and
  1,372,304 on armeabi-v7a, 13,576 bytes more on x86_64 than before the unit and 23,400 under the gate. Compared the
  same way, only the live view's count grew, by its tool mark and the tied places' arm. The cold paths' second pass
  (ADR 0053), against `d9b44fb7`, whose engine is that tree's: 2,064,648 bytes on x86_64, 1,844,664 on arm64-v8a and
  1,368,784 on armeabi-v7a, 9,104, 3,280 and 3,520 bytes less, x86_64 32,504 bytes under the gate. In its steps' builds
  (`ndkbuild.sh`, stripped) its last step, one JNI entry per return type, grew arm64-v8a's library by 512 bytes, the
  unwind entries of the functions it adds, within that pass's limit of 1 KiB for arm64; x86_64 shrank at each step and
  armeabi-v7a with each of the pass's two items. Unit S2 (decision 11), built with the size pass's `ndkbuild.sh` and
  stripped, against `adcdd7f9` (2,064,472 bytes on x86_64, 1,845,760 on arm64-v8a): x86_64 2,086,088 bytes once the
  engine sends flows through the proxy (`6119ff5f`), and 2,087,816 with the network part's side and the JNI
  (`4ed82450`), 23,344 bytes more; arm64-v8a 1,869,616, 23,856 more. That is over the plan's estimate of 7 to 15 KB.
  `connect::excluded` folds ASCII letters alone, since Unicode's case tables would have cost 9,632 bytes, and the
  JNI's setting, written out in five places, became one function, which saved about what the network part's side
  cost. The x86_64 library Gradle builds is then about 2,087,992 bytes: 9,160 under the gate, and 968 above the 8 KiB
  that the unit's plan set as its stop line. No armeabi-v7a figure is recorded for the unit. The hot set, compared
  function by function with the size pass's tool against `adcdd7f9`: on x86_64 the packet path moves by offsets only.
  On arm64-v8a the engine's state had grown 264 bytes ahead of its tunnels' table, past the 4,095 an `add` takes as an
  immediate, so the proxy's seven counters and the table of names whose answers carried ECH moved behind pointers of
  their own; then `forward`, `handle`, `send`, the relay's poll, `relayed_receive`, `mapped_receive` and
  `tunnels::forward` are the same, and the tunnels' `carry` poll keeps its 1,537 instructions, differing only where the
  linker writes two addresses of one constant as `adrp` and `add` instead of `nop` and `adr`: the unit's code before
  that constant moved it out of `adr`'s 1 MiB reach, which no layout of the state changes (four of tokio's small
  functions for the carry task likewise, at the same count). On both ABIs `Shared::learn` differs, its public names'
  insertion now out of line, shared with the names whose answers carried ECH and called only for an answer with an ECH
  configuration; and so does `Engine::start_with`'s loop, whose sweep calls hashbrown's `erase` for the names' tables
  out of line, a third table of that type being there now. The fix round of the unit's review (`a9b9459b`), built and
  stripped the same way: x86_64 2,091,184 bytes against `99a09d27`'s 2,088,136 (3,048 more; 26,712 more than
  `adcdd7f9`), arm64-v8a 1,872,872 against 1,870,000 (2,872 more; 27,112 more than `adcdd7f9`). The x86_64 library
  Gradle builds is then about 2,091,360 bytes, 5,792 under the 2 MiB gate and so below the plan's 8 KiB stop line:
  unit S2 is therefore pushed together with the third size pass, which frees about 26.6 to 31.8 KB, as the plan's
  stop says. The hot set against `99a09d27`: `Loop::forward` differs by one call only (`looked_up` becomes `passed`),
  the event loop by offsets on x86_64, and arm64's `tunnels::carry` poll by `adrp` and `add` for a panic path's
  constant; `Shared::learn` and `Names::insert`'s merge differ, as the fix round's names (the askers and the closed
  ECH guard) need. The switch's hold (S2's review, m2; `9cc3a838`), built and stripped the same way: x86_64 2,093,216
  bytes, arm64-v8a 1,874,632, 2,032 and 1,760 more than the fix round's and 5,080 and 4,632 more than `99a09d27`'s;
  Gradle's release library is 2,093,392 bytes on x86_64, 3,760 under the gate, 1,873,472 on arm64-v8a and 1,388,336
  on armeabi-v7a. Its hot set against `99a09d27` is the fix round's, function by function. A `Notify` for the hold's
  wake-up had made it otherwise: with a second caller of its poll's inner part, `Notified::poll` was inlined anew into
  `Tun::send`, `Tun::send_once` and the polls of `mapped`, `own_relayed`, `tunnels::carry` and `echo::carry`, so the
  hold looks at the setting by the timer instead. The cold paths' third pass (ADR 0053), against `32b5f261`, S2's tree,
  whose library Gradle builds at 2,088,312 bytes on x86_64, 1,868,840 on arm64-v8a and 1,385,696 on armeabi-v7a (x86_64
  8,840 under the gate): 2,062,752, 1,849,040 and 1,366,440 bytes, 25,560, 19,800 and 19,256 less, x86_64 34,400 bytes
  under the gate; its sorts and the bridge's one attach take 19,928, 14,232 and 13,688 bytes of that in its steps'
  builds, and crates.io's sources named `/c` in the panic locations the rest. S2's last tip (`2510dfa2`: the R8 keep
  rule and the hold's emulator row after the hold, no native change) keeps the hold's figures: Gradle's release library
  2,093,392 bytes on x86_64, 3,760 under the gate and so below the plan's 8 KiB stop, which is why S2 lands on `main`
  only together with the third pass. With both on `main` (`fb4bd403`), Gradle's gate build (`scripts/check.sh android`'s
  native budget) gives 2,067,768 bytes on x86_64, 1,853,736 on arm64-v8a and 1,369,080 on armeabi-v7a, 25,624, 19,736
  and 19,256 less than S2's tip: x86_64 29,384 bytes under the gate (S2's fix round and hold took 5,080 of the 34,400
  the pass's own base had; the pass frees 64 more here), 13,000 once the forwarder takes its planned 16 KB and 4,808
  above the 8 KiB stop. The forwarder (decision 12) took about 27 KB instead, and lands with the cold paths' fourth
  pass: Gradle's gate build of the two gives 2,062,688 bytes on x86_64, 1,846,736 on arm64-v8a and 1,356,528 on
  armeabi-v7a, x86_64 34,464 bytes under the gate and 26,272 above the 8 KiB stop (decision 12, "Size").
- **Frontier research, open:** Telegram's fake-TLS hello across versions, told from the device without a JA4 database;
  encapsulated handshakes seen from the device (Xue et al., USENIX Security 2024) for Signal and WhatsApp; and how
  people read "read from the connection" against "inferred", with real users.

## How it is built (W8, part 2a)

- `core/net/src/proxies.rs` (the parsers), `messengers.rs` (the data), `engine/proxied.rs` (the rules, substitution,
  the sniff and its zeroing), `engine/tcp.rs` (the relay reads through the sniff), `log.rs` and `snapshot.rs` (the
  formats); `core/network-jni` (`nativeProxies`, `nativeMessengerClients`, `nativeFlowProxies`).
- The network part (`android/network`): `NetworkVpnService.applyProxies` (the messengers' UIDs, Android's proxy
  setting, again at package and proxy changes), `activity/ProxyFacts.kt` (what a row says, a pure function), the
  screens "Now" and the history, the strings in `strings.xml` and its translations (ADR 0030), and those the proxy
  record's unit A added in `strings_untranslated.xml` until ADR 0030's next round, all held to ADR 0025's words by a
  test.
- Data: `data/messengers` (CC0 for the project's lists; Telegram's `cidr.txt` states no licence, ADR 0015's record).
- **The proxy record's unit C** (2026-11-25, decision 8's R3): in the engine, `Keeps`, `LoggedApps` and `app_of` in
  `engine/proxied.rs`, with the leaf lock `Shared::kept_apps` and `Shared::apply_proxies`, and `ProxySetting`'s
  `logged`, `tools` and `pac_handler`, which `nativeProxies` hands; the shared vectors
  `core/net/testdata/logged-apps.tsv`, read by the engine's tests and the network part's (`proxy/ProxyChoice.kt`). In
  the network part, `proxy/LoggedApps.kt` (the store, memory only under the profile, and the hand-over's rule),
  `NetworkVpnService.applyProxies` (the UIDs, the tools and the PAC handler, again once the tools are read and at
  `ACTION_APPLY_PROXIES`, with the setting's addresses under strict Private DNS), `ui/AppProxyChoice.kt` (the
  confirmation and the page's switch), the rows of `ui/NowScreen.kt` and `ui/HistoryScreen.kt`, the count under the
  switch, and the debug builds' `proxy-log`, `proxy-logged`, `proxy-sandbox`, `proxy-handed`, `proxy-ended` and
  `packages-handed`. The emulator's `proxies` shard checks it end to end at a TEST-NET address that a rooted
  emulator's own rule sends to the proxy lab, so that the first hop is not local (`scripts/verify-proxies.sh`), and
  checks an update, a reinstall the network part follows and one it learns of by the first install time alone, each
  after the hand-over that follows it. Its review round (2026-11-25, two reviewers, the engine and the rest) found no
  critical; its findings are taken in as the sections above say, each with the review's number.

- **The proxy record's unit S2** (2026-11-27, decision 11): in the engine, `core/net/src/connect.rs` (the request, the
  head's end, the status, the answer and the exclusion list, with no IO; fuzzed by `fuzz_targets/connect.rs`, seeded
  with squid's, tinyproxy's and nginx's answers written by hand), `engine/beneath.rs` (`Beneath`, `takes`, the order
  and the ways, `#[cold]`, out of line and boxed, so that a connection's future does not grow by the proxy's state and
  nothing of it is inlined into the packet path), `engine/tcp.rs` (`upstream` and `open`, `Via::NetworkProxy`),
  `upstream::protect_on`, and route 3 in `log.rs` and `snapshot.rs`; the JNI's `nativeBeneathProxy` and
  `nativeBeneathState`, the setting kept beside the chain's. In the network part,
  `NetworkVpnService.settleResolverProxy` (one settle for the resolver and the engine, and `protectSocket` bound to the
  network's handle),
  `dns/NetworkProxy.kt` (`forEngine`, `withoutGrant`, `excluded`), `proxy/ThroughProxy.kt`, `ProxyContext.State`, and
  the lines and rows of `ui/NowScreen.kt` and `ui/HistoryScreen.kt`, in `strings_untranslated.xml` until ADR 0030's
  next round. Checked by the engine's unit tests (20 in `beneath.rs`) with hand mutants, the shared vectors of the
  exclusion list and of the request (`core/net/testdata/connect-requests.tsv`, which the proxy lab also sends
  tinyproxy 1.11.2 byte for byte), nine network-lab tests through the whole engine with an HTTP `CONNECT` proxy of the
  lab's own on a network that lets out only it (`scripts/netlab-enter.py --require-proxy`), the measurement on the
  emulator (`scripts/measure-proxy-settings.sh`), and row 7 of the `proxies` shard (`scripts/verify-proxies.sh`), which
  CI runs: a device owner sets the Wi-Fi network's proxy to the recorder, everything else is rejected, and a fresh
  fixture's request to a public name must answer through it, with a `CONNECT` to its address carrying no
  `User-Agent` and none for the on-link target.

## Fix round (2026-11-21)

One review round ran with two independent reviewers (security and engine; screens, words and checks), read only, on
`5885669..da15d69`. The decisions below were taken by **the coordinator, under the maintainer's word of 2026-11-21**,
for the maintainer to confirm when this ADR is accepted; the builder of the fix round wrote them in, each with its
reason.

- **F1. The reply confirms, the app declares** (security M1). A request of about 40 bytes, ignored by an SDK's own
  server, turned any flow into `0.0.0.0:0` with no name and stripped its trackers' marks. Reason: only the server's
  answer shows that a proxy took the request; a plain request cannot be confirmed so, so its flow is never hidden for
  it. The marks are taken in the engine from every name the flow carries before anything is stripped, and kept as the
  company only while the switch is off, so that what a proxy hides never hides a tracker. The residual limit is stated
  above: an app that runs a proxy-shaped server of its own.
- **F2. A take-back is complete** (security M2, screens m1). Reason: a name taken back that stayed hidden made the
  history say "Sent through your circumvention tool" of a flow that was not. Of the two ways the brief allowed, the
  records of an inferred flow are held back for the window of take-back and rewritten on one, rather than a correction
  record the readers apply: it changes no format, reader or day file, and keeps the log's bounds (at most 1,024
  records held, ten minutes each). The history now tells a flow left out for a proxy, by its recorded kind, from one
  sent through the tool, by its recorded route.
- **F3. "Tied" is tested from the name's side** (security M3, screens M1). Reason: one name per address made a
  re-pointed shared address (Telegram's `www.youtube.com` and `i.ytimg.com`; WhatsApp's backup on `www.googleapis.com`
  and `oauth2.googleapis.com`) a cover, on every hello of a user on a real MTProxy. Where the engine cannot see the
  app's lookups the rule is no evidence at all, rather than a guess.
- **F4. The cover line states facts only** (screens M2): ADR 0025 decision 4 bans words that imply intent; the word
  test also refuses "look like", "disguise", "pretend", "fake" and "hide".
- **F5. Confidence words always, "own" dropped** (screens M3): with the switch off, an inferred proxy was stated as a
  fact, and Android's setting was called the app's "own".
- **F6. The switch the screen points to is always there** (screens M4), one switch as the maintainer settled for the
  tool's row (ADR 0046): reworded to cover apps' own proxies, drawn in the tool's section, the WireGuard section, or on
  its own once an app's own proxy is seen since the engine started, and linked from every left-out row.
- **F7. Signal's own connections and its third parties** (screens M5, security m3): fronting counts as direct (a set
  proxy turns it off, verified at the pinned commit), the third parties are read from that commit (and PayPal's
  approval host from PayPal's own API specification, as Signal gets the URL from its server), and the 3-D Secure pages,
  which open in Signal's own web view (`Stripe3DSDialogFragment`, `PayPalConfirmationDialogFragment`), fall in the
  window after a third party.
- **Open, for the maintainer, now resolved.** One alternative was weighed and left open: for an app that is not a
  messenger and does not use Android's setting or a proxy on the local network, its own proxy's connection could show
  as any flow's does, with only the destination asked for following the switch. That would close F1's residual limit,
  but departs from the maintainer's rule of 2026-11-19 for the tool's own row (ADR 0046): the servers follow the
  switch. The maintainer's decision of 2026-11-22 resolved it (decision 8): every app's own proxy is shown in "Now"
  with its first hop in full, whatever the switch, while the connection is open and for ten minutes after it ends;
  the destination asked for, and the first hop in the log, follow it.

The minors and nits, as done: SOCKS4's printable user ID and SOCKS5's plausible methods (security m1); obfuscated2's
high-bit bound and text rule (m2); the fake-TLS cover that resolves to its proxy, an accepted limit (m4); the profile's
promise made W9's must, and the six counters gated on a debuggable build (m5, screens m4); the zeroing claim corrected
and the hello buffer started on `0x16` alone (m6); a destination asked for by address names its flow (screens m2); the
maker fact where the network is unknown (screens m3); Telegram's UDP calls stated as a limit and tested (screens m5);
PRIVACY.md and its page (screens m6); a random SOCKS user name searched for on the emulator (screens m7); the hand
mutants recorded below (screens m8); an `@` after the authority refused (n1); `update.py`'s bounds (n2); substitution
on the time since the phone started (n3); the client list's place corrected above (n4); the snapshot's comment (n5);
the credit for Signal's fronting given to names, and the history's address parsed once (screens' nits).

**Checks of the fix round.** Each fix has a test that fails when the fix is reverted (the hand mutants below are those
reverts and more). The engine's unit tests, the network lab's proxy tests (four, a hand-over among them), the network
part's JVM tests (`ProxyRowTest`, `LogSwitchTest`, `HistoryTest`, `ProxyFactsTest`, `TrackerMarksTest`), the proxy lab
and the emulator's `proxies` shard.

**Hand mutants**, in cargo-mutants' manner, on the code as it is after the fix round (part 2a's first 27 were not
recorded one by one, so they were run again in this set rather than recovered):
66 in all, 63 killed and 3 argued equivalent.
- *The parsers* (`proxies.rs`, 18): SOCKS5's list of more than ten methods (equivalent: more than ten methods, each 0 to
  9, none twice, cannot be, and the rule of none twice refuses them), a method outside 0 to 9, one offered twice, the
  method used not offered; SOCKS4's user ID of any bytes; the reply's method, RFC 1929's refusal, SOCKS4's refusal,
  `CONNECT`'s `407`, a plain request confirmed; an `@` after the authority; the high bit's bound, the text rule, the
  bits' average, an excluded prefix, bytes 4 to 8 zero; an empty password said to cross; a scheme not `Basic`.
- *The rules* (`proxied.rs`, `names.rs`, `naming.rs`, `logbook.rs`, `now.rs`, `log.rs`, 33): a request named before
  its reply; too few bytes taken as a confirmation (equivalent: `confirmed` reads at most 12 bytes, so it never
  answers "not yet" at 16); a plain request left out whole, its place dropped from "Now", hidden when the switch turns
  off; no trackers' marks on a confirmed proxy, none from an inner hello, none from the destination asked for; an
  address asked for naming nothing; a take-back leaving the flow hidden, its place's proxy, the segments that wait,
  the records held back; nothing held back; a take-back past its window; the instants not carried, an open direct
  connection not handed as now; strict Private DNS ignored, no lookup needed, a looked-up name not tied, only the last
  name of an address tied; a hello lost under substitution; Signal's fronting not direct, no window after a third
  party; a stream not read for proxies copied (equivalent: the hello buffer is dropped before any byte when the stream
  does not start with `0x16`, which the copy counter shows), an inner stream not TLS copied, a hello buffer started on
  any byte; the left-out bit and the trackers not written; the setting's port, a proxy on the local network, the
  substitution's window, a cover not kept as one.
- *The network part's Kotlin side* (15, all killed by its JVM tests): `ProxyFacts` (kept read from the address, a
  plain request called an HTTP proxy, the maker said where the companies agree, a cover of the network's own company,
  the dump's counters in a release), `proxyRow`'s branches (the confidence line, Android's setting, the password while
  left out, a plain request's link, the maker where the network is unknown, the cover line), `LogSwitch` (the switch
  alone), `History` (a direct segment said through the tool), `TrackerMarks.byId` (the name's column) and `LogRecord`
  (the left-out bit).
Twelve survived the first run, one did not build and two did not apply as written: tests were added for each that was
not equivalent (the parsers' plausible methods with 0 offered, the bits' average alone, an empty password, a five-letter
scheme; the destination asked for alone marking a proxy, the held segments of a take-back, an open direct connection a
minute later at a hand-over, a request alone in a read before its inner stream, a plain request's place placed in "Now"
before the switch turns off), and each was run again and killed, as were the other three, written anew.
