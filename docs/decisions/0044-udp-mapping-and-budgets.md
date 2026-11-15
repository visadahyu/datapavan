# 0044. UDP mapping, budgets for each app, and the engine's smaller gaps

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12

## Context

The independent review of 2026-11-09 rated the engine's design and parsers above the field, and its forwarding
path at the field's standard. Its findings 18 to 21 say why. The maintainer made them gates of Watch 0.2.0, with
an ADR (D25).
- **18. No app has a budget.** A UDP flow costs:
  - a task;
  - a socket;
  - a 64 KiB buffer for 60 seconds, even for one DNS answer.

  A waiting TCP connection holds a socket and a fake port for up to 60 seconds. Nothing caps either. One app that
  sends to tens of thousands of ports, or to addresses that never answer, uses up the process's descriptors or
  the ports, and then no app can connect. Without a VPN the kernel charges each app for its own sockets, so this
  weakness comes with the tunnel.
- **19. One socket per destination.** ADR 0012 chose one connected UDP socket per flow, keyed by the app's
  address and the destination. An app's one socket that asks a STUN server for its address and then talks to a
  peer leaves through two sockets with two ports. The peer's packets, sent to the port STUN saw, reach nothing. RFC
  4787 (REQ-1) asks the opposite of a NAT: the same mapping whatever the destination. Calls and peer-to-peer apps
  still work through relays, but lose their direct path.
- **20. One name per flow.** A name learned from a DNS answer, tied to the flow only by its address, outranks the
  server name the connection itself sent. On addresses that serve many names, a flow can be logged under a name
  another lookup asked for. Either name can be wrong: a server name can be a front.
- **21. Smaller gaps:**
  - a server's reset reaches the app as a clean close;
  - ping and other ICMP echo are dropped;
  - fragments are counted with malformed packets;
  - a datagram too large for the network beneath becomes "host unreachable";
  - `nativeStop` held a lock while joining the engine's thread;
  - no test can drive the forwarding path's timing.

## Decision

1. **UDP: one mapping per app socket.**
   - **Mapping:** a datagram from an app's address and port leaves through one upstream socket, whatever its
     destination: endpoint-independent mapping, RFC 4787 REQ-1. The socket is protected and not connected.
   - **Filtering:** an answer comes in only from an address the app has already sent to from that socket:
     address-dependent filtering. An answer from another port of such an address is let in and logged as a flow
     that came in.
   - **Logging:** each destination stays its own flow in the log, with its own name, organisation, bytes and
     QUIC reading.
   - **Lifetime:** a mapping ends after 120 seconds with no datagram either way (REQ-5 and REQ-6; today 60
     seconds, refreshed only by answers), when its app's owner changes, or when the network or the chain
     changes.
   - **What stays as it is:** lookups to the tunnel's DNS address keep one connected socket per flow.
   - **ICMP errors are kept.** A connected socket learns of an ICMP error such as "port unreachable" by itself;
     an unconnected one only with `IP_RECVERR` (and `IPV6_RECVERR`), which queues each error with the datagram's
     destination. The mapped sockets turn it on. The engine reads each error from the socket's error queue and
     tells the app, from that destination, as it does today. Most userspace NATs lose these errors, and apps then
     wait for their own timeouts.
   - **Through a safe library only (ADR 0006).** rustix 1.1.4, already in the lockfile, offers neither the option
     nor the extended error. nix (MIT) offers both, `sockopt::Ipv4RecvErr` and `Ipv6RecvErr` and the
     `Ipv4RecvErr` and `Ipv6RecvErr` control messages, behind safe functions. It comes in with this unit, if its
     review for size, licence and advisories passes. If it does not, the errors are lost for mapped sockets, and
     this ADR says so in its amendment.
2. **Chained UDP: one UDP ASSOCIATE per mapping,** not per destination.
   - Each answer is matched to its destination by its SOCKS5 header. Today that header is thrown away, so anything
     the relay sends on an association reaches the app as if from the flow's destination.
   - A stand-in name is bound to the first answer from the port the app asked.
   - Chained apps get the same address-dependent filtering. W6's done-when, "nothing comes in that a local app did
     not start", becomes "nothing comes in from an address a local app did not send to".
   - Whether the tool itself keeps one upstream socket per association is the tool's own choice. Watch cannot
     change it.
3. **A budget for the engine and for each app.**
   - **The caps:** they come from the process's descriptor limit N, read from `/proc/self/limits`, less a
     reserve of max(128, N/16) for Watch itself (B). UDP mappings are capped at B/4. Waiting TCP connections are
     capped at min(B/8, 4,096).
   - **The share:** each app may use a quarter of each cap, with at least 64 mappings and 32 waiting connections.
     Flows whose app Android cannot name share one share. So four apps must misbehave before any other is
     touched; for TCP, where Android answers late, two and a half (as unit 10 builds it, below).
   - **At the TCP cap:** a SYN is dropped, as by a full queue, so the app's own stack tries again. Its fake port is
     freed at once, since it never reached Android's stack.
   - **At the UDP cap, what makes room, in order:**
     1. an answered lookup;
     2. the requesting app's least recently active mapping idle at least 5 seconds;
     3. any app's.

     A mapping with traffic in the last 5 seconds is never evicted, so a call is never cut; an answered lookup,
     which carries nothing more, ends however recent its answer (as unit 10 builds it, below). If nothing
     qualifies, the datagram is dropped.
   - **What each part costs:** one 64 KiB receive buffer per engine thread replaces one per flow. A lookup to the
     tunnel's DNS address ends with its answer.
   - **Counters:** each refusal and eviction is counted. None of them names a destination.
4. **Two names.**
   - The name the connection itself sent (TLS or QUIC) names the flow. The DNS name is kept beside it when the two
     differ.
   - An ECH public name keeps today's rule: it never names a flow.
   - The log's record format moves to version 2, with a flag where the names differ, a flag for a flow that came
     in, and the DNS name. Watch's Kotlin side reads versions 1 and 2, so sealed records stay readable.
   - ADR 0037 is amended to match. Counters measure how often the names differ before the format changes.
5. **The smaller gaps:**
   - **Resets:** an upstream that ends in an error ends the other side with a reset (linger zero), both ways.
   - **ICMP echo:** carried through unprivileged ICMP sockets, protected, at most 32. Its owner cannot be asked of
     Android, so pings are refused while a chain is on. Where Android refuses such sockets, echo is dropped as
     today, and counted.
   - **Fragments:** counted apart. They are reassembled only if the count shows a need. (Amended on 2026-11-15,
     below: they are reassembled.)
   - **Too large:** a datagram larger than the network beneath can carry is answered with ICMP "fragmentation
     needed" or "packet too big", with the network's MTU, which Kotlin passes from `LinkProperties`. The app's
     "do not fragment" bit is not copied onto the engine's sockets. (Amended on 2026-11-15, below: the tunnel's
     MTU follows the network beneath, and the engine passes on only what routers answer.)
   - **The lock:** Watch's native side never holds the engine's lock while joining its thread.
6. **Tests that drive time.**
   - The engine takes its limits and timings from its `Config`, so tests can use seconds.
   - On Linux, a harness runs it in an unprivileged user and network namespace with a real tun device. Kernel
     TCP, resets, ICMP sockets, caps and timeouts are then tested in an ordinary `cargo test`, on every change,
     without an emulator.
   - Where namespaces are not available, those tests say plainly that they did not run. They never pass silently.
   - CI allows the namespaces.

**Amendment of decision 5, fragments and the MTU (2026-11-15, unit 12; proposed, revised after review).**
- **Why.** Two things were measured in Linux namespaces on 2026-11-15:
  - **Apps' kernels fragment.** A default UDP socket, IPv4 or IPv6, whose path MTU is smaller than its datagram
    sends it as fragments. Only a socket set to "do not fragment" gets `EMSGSIZE`. An engine that drops fragments
    cuts such an app off as soon as its path is narrower than its datagrams.
  - **"Too large" from the engine is not what the app meets without Watch.** A first version of this unit
    answered datagrams larger than the network beneath, as a router would. The second review showed what that
    does to apps whose own link would have handled them:
    - a connected default socket fails its next call with `EMSGSIZE`, and that datagram is lost;
    - an IPv6 socket set to `IPV6_PMTUDISC_OMIT` ignores the answer, so every datagram is lost;
    - `PROBE` and `INTERFACE` sockets lose datagrams silently.

    Without Watch, the app's own kernel fragments those datagrams, or refuses them at once.
- **The tunnel's MTU follows the network beneath.**
  - Watch sets the tunnel's MTU to its first hop's, as the kernel reports it. A UDP socket of each IP version,
    bound to the network beneath, is connected toward an address only the default route covers, and `IP_MTU` is
    read from it. On Linux `IP_MTU` answers for an IPv6 socket too, and the IPv6 value includes what router
    advertisements set.
  - The tunnel takes the smaller of the two values, never below 1280 or above 1500. It takes 1500 when neither
    socket answers.
  - When a network change brings another value, the tunnel is set up again, as for an address clash (ADR 0041),
    and make-before-break: the new tunnel is established while the old engine still runs, so that nothing leaves
    outside the tunnel meanwhile, and the new engine goes on with the one before's chain from its first packet.
    Within one network a lower value is taken at once and a higher one only 10 minutes after the last setup, so
    that a flapping route cannot set the tunnel up again and again.
  - Android's `Builder` takes one MTU for both IP versions, so the wider version meets the narrower one's MTU.
  - The app's own kernel then meets the first hop as it would without Watch: it fragments the datagram or refuses
    it, by its socket's own setting. `LinkProperties.getMtu()` is 0 on most networks, so it is not used.
- **Fragments are reassembled.**
  - An app's IPv4 and IPv6 fragments are put together, and the whole datagram is handled as any other.
  - The cost is bounded in datagrams, bytes and time. When a bound is reached, the oldest incomplete datagram gives
    way, since an honest one is complete within milliseconds.
  - Overlapping fragments drop the whole datagram, and its later fragments until its wait ends (RFC 5722). A first
    fragment without the whole transport header drops it too (RFC 1858, RFC 7112).
- **Beyond the first hop.** The "fragmentation needed" and "packet too big" that routers send to the engine's
  sockets (read through `IP_RECVERR`) are passed on to the app with their MTU, as they would reach it without Watch.
  The engine answers nothing on its own. A datagram larger than the path is sent: the engine's kernel fragments it,
  or a router answers.
- **What stays as it is.** A datagram the engine's kernel refuses as too large is dropped and counted, never
  answered "host unreachable". The chain, lookups to the tunnel's DNS address, and TCP are unchanged.

## Consequences

- **Calls and peer-to-peer apps keep their direct paths,** as without Watch. Port scanning by one app no longer
  costs other apps their connections.
- **The maintainer's questions on the bar (2026-11-12):** budgets for each app, two names and the namespace
  harness are above the open tools; endpoint-independent mapping by default, also through the chain, is at the
  top of the field; resets, echo and the MTU are the field's standard; keeping ICMP errors with unconnected
  sockets is above most userspace NATs. Building it needs no frontier research. Measuring it does need lab work:
  - descriptor limits and ICMP sockets across phone makers;
  - each tool's relay;
  - how often names differ.

  An outside review of the engine (WATCH-07) is still needed before 0.2.0 is called stable.
- **nix's review (2026-11-12):** nix 0.31.3 (MIT), with the features `net` and `uio`, passed `cargo deny` and
  builds for the three Android targets. It brings memoffset, cfg_aliases, bitflags and autocfg (build only). With
  the new UDP code, the arm64 library grew from 775,976 to 812,312 bytes, about 2.8 KB of it nix's own.
- **Two filters differ by design:** address-dependent for answers, endpoint-independent for mappings. These are
  the defaults RFC 4787 recommends, and what most home routers do.
- **ADR 0012's "one socket per flow" for UDP is superseded** by decision 1. W6's done-when changes its wording,
  not its meaning: an answer still needs a datagram the app sent first.
- **The log format changes once,** before W5 reads it.
- **This is a set of units:** each lands on its own, with its tests. The harness comes first, so the later units
  are tested by it.

## How it is built

**Unit 9, the chain's mappings (2026-11-13, decision 2).**
- **One `UDP ASSOCIATE` per mapping.** A chained app socket sends to every destination over one relay of the tool,
  each datagram with a header naming its destination: the address, or the name behind a stand-in. Destinations
  that open at once wait for the first to open the mapping, so that a burst, as of an app asking several servers,
  asks the tool for one relay, not one each.
- **Each answer goes to the destination its header names,** with the direct path's filter, in this order:
  - from a destination's own address, to its flow;
  - from the address a stand-in was bound to, to that stand-in, unless another stand-in that the app asked
    within the last 5 s (`Limits::udp_contest`) still waits on that port: the tool may have resolved both names
    to that one address, so the answer is then dropped;
  - from another port of an address the app sent to, to a new flow, never as a stand-in's first answer. It is
    shown from the address the app sent to itself, else from the stand-in bound to that address; the app's
    replies to a flow shown as a stand-in go to the tool by that stand-in's name, at the flow's port, as the
    stand-in's own datagrams do. Such a port is no destination the app knew: the app's first datagram to it
    asks Android whose socket this is, as a new destination's does, since the app that held the socket when
    the port came in may be gone. That is one question for each such port the app answers. When that same
    stand-in, alone, waits on that port, the one name asked on a second port, the answer binds it there too;
  - from an address the app never saw, to a stand-in that waits on that port, as below;
  - from anywhere else, nowhere, counted in `udp_filtered`.
- **At most 64 flows that came in** for each mapping, on the direct path too. A STUN server's tests of the mapping
  and a peer's new NAT bindings bring a few such ports, and 64 is the floor decision 3 gives each app's mappings.
  More are dropped and counted, so that neither a sender at such an address nor a tool that forges headers can
  grow the table without end. One counts for as long as it lives, even once the app answers it: an app that
  answers whoever reaches it, as a DHT node or a QUIC listener does, would otherwise lift the cap.
- **Stand-ins.** The relay answers from the address the tool reached, which the app never saw:
  - A stand-in still waiting for its first answer is bound to the first answer from its port, from an address the
    app never saw, when no other stand-in of the mapping could take it. Later answers from that address reach the
    app from the stand-in. Only a stand-in the app sent to waits: a flow that came in, as another port of a name
    a relay gave back, never does, since the app asked it nothing.
  - **A bounded cut.** A second name asked on a bound name's port contests the bound address's answers for
    `Limits::udp_contest`, 5 s after the app first asked it, and they are dropped meanwhile: one unanswered
    datagram to a silent STUN name beside a working TURN server on 3478 cuts the TURN server for those seconds,
    not for minutes. A first answer through a tool comes within about a second; five leave room for a slow one.
    The trade-off: if the second name does resolve to the bound name's very address and port, its later answers
    reach the app under the first name, and the log counts them there. The second name still waits, as long as
    it lives, for a first answer from an address no other stand-in was bound to.
  - On port 53, that answer must also be a DNS response to a query the app sent that stand-in, by its ID and its
    question. A sender that guesses neither cannot take the stand-in, nor feed Watch the names it learns.
  - **The risk left until unit 9b:** on other ports, whoever reaches the tool's relay first, from the port the app
    asked and an address the app never saw, takes a waiting stand-in, and the real answer is then dropped. Such a
    sender must know where the tool's relay sends from, and when; the tool's own filtering, if it has any, comes
    first. A destination the app sent to, or a stand-in already bound, never takes another stand-in this way.
  - When several wait on one port, the answer could be any of their names'. It is dropped rather than handed to
    one, for as long as more than one waits. An app that asks several names on one port at once, as some ask
    several STUN servers, gets no answer from them through the tool.
  - **The maintainer's decision (2026-11-13):** dropping is the safe floor, since handing an answer to the wrong
    name would make the log wrong without a word. It is not the best the field allows, so unit 9b, before
    Advanced's first release, removes the loss without guessing: an answer is told apart by the protocol's own
    identifier where it has one (a STUN transaction ID, a QUIC connection ID, a DNS query ID), and a stand-in that
    shares a waiting port in a protocol with none gets an association of its own. The lab first checks what real
    tools' relays put in the header (gate 4's check R, table B10): where they give back the name, nothing is
    ambiguous.
  - A relay that gives back the name it was asked for is matched by that name, and the stand-in then waits no
    more for a first answer from an address, which a stranger could otherwise send it later. A second stand-in
    still waiting on that port is then the only one that could take an answer from an address there, and the
    first such answer binds it. That is right under the rule that a relay naming one answer names the next; a
    relay that names some answers and not others could give the first stand-in's answer to the second.
  - A stand-in on port 53 keeps the last 64 queries the app sent it while it waits, so that a burst before the
    first answer (retries, A and AAAA, several names) still binds it; at most about 17 KB, only while it waits.
    Once bound, or answered by name, it drops them and keeps none after.
  - A stand-in's name can give way in the stand-in map (16,384 names, `Limits::stand_ins`) to newer names while
    the app still sends to it, since the mapping's own datagrams do not keep it in use there. A live peer then
    keeps the way it had, also when a pause makes its way anew, for its own app only: another app that took
    the socket's port gets no name from the old app's peers. A peer made with such a way is logged under the
    name its way names.
- **Names learned:** from a flow the app started, as before; from a flow that came in, only from a DNS response to
  a query the app sent it, by ID and question, even once the app has sent to it. A sender at port 53 of an
  address the app sent to cannot name the app's later flows.
- **Android is asked again.** Android may hand a closed socket's port to another app, which the log must name
  (decision 1: a mapping ends when its app's owner changes) and the chain may send another way. So, with or
  without a chain, a mapping's datagram to a destination it knows, or a lookup on a flow of lookups to the
  tunnel's DNS address, asks Android again whose socket sent it when the app was silent for a second
  (`Limits::udp_reask`), or thirty seconds after Android last named it. The datagram waits for the answer, off the
  event loop: about 3 ms on the Galaxy A40, 11 ms in deep idle (the engine spike of 2026-11). Linux hands out a
  free port at random among about 28,000, so a port rarely comes back to another app within a second. The cost is
  one Binder call for each pause of an app socket, and one every thirty seconds for one that never pauses: a socket
  that keeps a connection alive every 30 s adds about 1,400 a night, beside the 984 lookups of a whole night in
  that spike. Lookups cost more: one takes no answer asked before it came (below), so a lookup that finds no flow
  of lookups open on its socket asks once, and a socket's lookups one after another, each after the last one's
  answer, cost one question each (ten for ten, 200 ms apart, in the ninth review's probe). Keeping the answers
  between them would save nothing, for that reason; no lookup costs more than one. What only comes in to a mapping,
  from its peers, asks too once the app has sent nothing for `udp_reask` and Android has not named it since: at
  most one question each `udp_reask` of such traffic, and none while a question out can say. An answer that names
  another app, or none, ends the mapping.
- **Whose a datagram is: the rule, in one place.** Every path of a UDP datagram asks one function,
  `Record::whose` in `core/net/src/engine/whose.rs`: one passing by a mapping, a lookup by its flow, one held while
  Android is asked, one joining a question out, one sorted when its way opens or is found stale. For each app
  socket with a way, opening or open, the table keeps the answers of Android's that can still decide a datagram:
  the app each named, or none, and when it was asked. For a datagram that came at `t`:
  - if it came after the newest question, it is the app that answer names: less than `udp_reask` after it, or for
    as long as the app sends without a pause of `udp_reask`, up to thirty times that after the question;
  - if it came before, or at the very instant Android was asked, it is the app named by every answer whose
    question lies less than `udp_reask` from `t`, before or after, if that app still holds the socket; one whose
    app holds it no more is dropped, and counted as late. If two such answers name different apps, or one names
    none, a handover fell near it, and who sent it cannot be told: it is dropped and counted as ambiguous, never
    sent under either answer, and never asked about again, since a later question could not tell either;
  - a destination the app had no way to, and a lookup to the tunnel's DNS address, take only an answer asked since
    their first datagram came: they never take an answer to a question asked before them;
  - otherwise no answer decides it yet, and it asks Android as it comes, also when it goes behind others that wait
    for their way, or waits for the question out about its socket when that can decide it: one asked less than
    `udp_reask` from it, and, for a new destination or a lookup, since it came. So a pause costs one question
    however many destinations the socket knows, and a burst of new destinations shares the questions asked since
    they came. One that no question could decide any more, its own having taken Android `udp_reask` or more to
    answer, is dropped, and counted as late;
  - a datagram that waits keeps whose the answers said it was as it came, by the newest answer or the stream since
    it: it stays that app's while it waits, however many questions come after it, as long as no answer near it
    says otherwise, the last answer before it still names that app, and that app holds the socket. An answer near
    it that names another app disagrees with it: a handover fell near it, and it is dropped, never sent under
    that answer (tenth review, minor 1). It is counted as ambiguous; if by then a newer answer names yet another
    app, or the first again, the socket has changed hands since, and it is counted as late (eleventh review).
  A way, mapping or flow of lookups, opens only for the app the newest answer names, and an answer that names
  another app ends every way of the socket; a flow that ends so still hands the app the answers it owes. An
  answer looks at the socket's ways only then, since they are all of the newest answer's app, so a socket's many
  flows of lookups cost an answer naming their own app nothing. A late answer to an older question changes no
  newest answer. What left under one app carries no stream on for the next. The record keeps the newest answer
  and, while a datagram of the socket waits, every answer from `udp_reask` before the first that does, and the
  last one before that; it goes with the socket's last way. A destination that waits for another of its socket to
  open the mapping waits only for one of its own app. The datagram dropped is the one the rule decided, found by
  when it came.
  - **The cost.** A datagram that came less than `udp_reask` from answers that disagree is lost: the first
    datagrams of each app after a handover, the old app's last ones and the new app's first, for up to `udp_reask`
    around the questions, and one taken for the old app as it came, by the stream since its answer, that waits
    behind others until an answer near it names the new app. At the Galaxy A40's 3 ms an answer is asked within
    milliseconds of the datagram that needs it, so this is the handover's own second. A datagram whose own question
    Android answers `udp_reask` or more after it was asked, with no other answer near it, is dropped. A way that
    opens slowly, a tool's slow handshake or a slow `protect`, drops nothing while the port stays with one app:
    each datagram behind it asked as it came.
  - **The windows**, each pinned to the nanosecond on both sides by the engine's own tests: `udp_reask` after the
    newest question, and before or after any answer for one that came before it; thirty times `udp_reask` for a
    stream; `udp_contest` for a waiting stand-in.
  - **The model.** A test in `whose/model.rs` drives the rule through 10,000 seeded random schedules at
    simulated instants, in 1.6 s; 1,000,000 pass in 30 s with optimisation. It drives handovers between a
    chained app, a direct app and no app, many within a few `udp_reask` or none at all; datagrams and lookups,
    queued as the engine queues them, and streams that never pause for longer than thirty times `udp_reask`;
    Android reading the socket a moment after it is asked and answering after random delays, so out of order;
    ways opening slowly, or failing, and a way for no app refused once the chain is on; the chain going off and
    on; flows of lookups ending, and the record going with the socket's last way. It checks every datagram that
    leaves, or fails with its way, against who held the port when it was sent. One sent by another app than the
    one it is taken for must lie within the windows above, by the answers given by then: every answer less than
    `udp_reask` from it names that app, and one of them was asked since its floor; or it came after an answer
    naming that app, asked since its floor, less than thirty times `udp_reask` after it, with what left under
    that app since never pausing for `udp_reask`, and no answer since naming another app. Nor may one that
    waited behind others leave under another app than the one the stream took it for as it came (tenth review,
    minor 1). It checks liveness too: nothing is dropped unless a handover fell near it, from `udp_reask` before
    it, or the answer before it, then or as it came, if earlier, until it was dropped, or a question asked then
    took Android `udp_reask` or more to answer; and nothing waits for ever. It fails, naming its seed, with each
    of fifteen bugs of the rule put back by mutation, those the eighth and ninth reviews found among them. A
    sixteenth, a datagram that keeps whose it was taken for though the answer before it names another app, it
    finds only beyond 10,000 schedules; a test of its own holds it.
  - **The bounded search.** The model also walks every schedule within small bounds, depth first, with the same
    checks, on a grid of time where `udp_reask` is two steps, so that each window's edge falls on a step: who
    holds the port and when, when each datagram or lookup comes and where to, how slowly Android answers and
    reads the socket, how slowly each way opens or whether it fails, when the chain turns, and the order of what
    falls on one instant; paths that reach one state share what follows. Every `cargo test` walks one set, a
    handover and two datagrams or lookups, in 3.7 s; nine larger ones, with two handovers, the chain turning,
    streams behind ways three times `udp_reask` slow, or a stream past thirty times it, walk 263 million states
    in three minutes on 24 cores with optimisation (`--ignored`; `WHOSE_BOUNDS` sets others); unit 10 adds one
    set to the first and two to the larger, with the mapping ended to make room (below). Of 24 mutations of
    the rule, it finds 15, each with a schedule of two to seven datagrams, among them the tenth review's minor 1
    put back, in 3 s; the random schedules find 14 of those within 10,000 seeds, but one, the presumption put
    over every verdict, only at seed 626,780. It does not reach what needs long streams, slow answers among
    them, or several answers kept while a datagram waits: four mutations the random schedules find, three of
    them only beyond 10,000 seeds (a join that takes an answer from before the floor, the presumption without
    the answer before it, and the near window's lower edge taken in), lie beyond its bounds; and five survive
    both: three the tenth review judged harmless, and two that drop more only where a handover lies near, which
    the liveness check allows. It takes the port to change hands before what else falls on its step, Android to
    read the socket at its question or a step after, and each delay to be one of the grid's; like the random
    schedules, it drives the model's copy of the engine's steps, not the engine, and puts no question for what
    only comes in.
- **No guess.** An app Android cannot name is unknown, in the log (decision 3's shared bucket) and to the chain,
  even when Android named that socket's app before: the old app is never taken for it. While a chain is on, it goes
  nowhere. A socket Android fails to name for a moment so gets a new mapping, and so another port.
- **Flows of lookups** to the tunnel's DNS address end once each lookup they carried has its answer: a direct one
  when the network's resolver answers, a chained app's when Watch has answered it, within a few seconds. Each
  lookup is kept by its ID and question, and an answer settles only the lookup it answers, so a repeated answer
  does not end the flow before a later lookup has its own; at most 256 wait on one flow. One that gives way to a
  new flow, when Android is asked again or the chain changes, still hands the app every answer it owes.
- **Counters, appended:**
  - `udp_unmatched`, the 27th: answers that no one destination could be told for, such as one on a port several
    stand-ins wait on, a malformed header or a fragment. It measures how often the rule above costs an answer;
  - `udp_came_in_capped`, the 28th: what the cap of 64 dropped;
  - `udp_relay_elsewhere`, the 29th: relays a tool offered elsewhere than on the phone or at its proxy's own
    address. Such a relay would take the app's datagrams, each naming its destination, across the network
    beneath, outside the tool, so that tool's UDP is refused, as a tool's without UDP. On the phone means on its
    loopback or at any address it holds, as a tool that shares its proxy on the local network announces its
    Wi-Fi address: a UDP socket connected to the relay, which sends nothing, then sends from that very address. A
    broadcast address refuses such a socket, though Linux lets one bind it;
  - `udp_ambiguous`, the 30th: datagrams and lookups dropped because answers near them name different apps, or
    one names another app than a waiting one was taken for as it came while that answer's app still holds the
    socket, by the rule above, so that who sent them could not be told;
  - `udp_late`, the 31st: datagrams and lookups the rule dropped otherwise, their app having lost the socket
    before their way opened, or no answer near them to be had. Both count what is dropped as a way fails too.
- **The chain changes:** a mapping ends at its next datagram either way when the chain is set again and sends its
  app another way: another tool, proxy address, user name or password, UDP turned off, or the chain off. The same
  tool set again keeps it. This holds for the direct path's mappings too, which until now kept their way. A chained
  mapping also ends when the tool closes its relay. When the chain changes while a destination's way opens, the
  destination is routed again before anything that waited leaves. Lookups to the tunnel's DNS address follow
  too: a flow of lookups that the chain sends another way gives way at the app's next lookup, and lookups that
  waited while it opened are routed again. Nor does anything come in on a direct mapping once the chain takes
  its app, ICMP errors included. So nothing an app sends once the chain takes it leaves directly, but for the
  port handed over below.
- **Known limits:**
  - A bound stand-in keeps sending by name, so that the tool's own routing by name still applies. When the tool
    resolves the name again to another address, the answers from that address are dropped, or, on a port another
    stand-in waits on, taken by that one. When that new address is already bound to another stand-in, or is a
    destination the app sent to itself, the answers go to that other peer, under its name, without a word: the
    address alone cannot tell them apart.
  - A port that Android hands to another app less than a second (`udp_reask`) after the last answer naming the
    old app, or at any time while the old app's datagrams have never paused for a second since that answer, up
    to thirty times `udp_reask` after it: what the new app sends to a destination the old app also sent to
    leaves the old app's way, and is logged under it, until Android is next asked. That is at the new app's
    first silence of a second, at most thirty seconds after Android last named the old app, or at any answer
    about the socket, which then names the new app. In the ninth review's probe, with `udp_reask` at 100 ms, a
    handover 2 s into such a stream sent 47 of the new app's next 71 datagrams directly. It is accepted because
    such a handover needs the old app to close its socket and the new app to be given that very port, one of
    about 28,000 handed out at random, within a second of the old app's last datagram; and the only way to
    narrow it, asking Android for every datagram, costs a Binder call each, about 3 ms on the Galaxy A40: fifty a
    second for a call's 20 ms packets. Likewise a datagram that no answer took for its app as it came, whose only
    answers near it all came after a handover that fell between it and them: no answer can tell it. One that
    waits, taken for its app as it came, by the newest answer or the stream since it, is told by that, and
    dropped (tenth review, minor 1).
  - What a mapping's peers send reaches the port's next app, if it took the port without sending, until Android
    is next asked about what comes in: at most `udp_reask` after the old app last sent or was named, and then
    for as long as Android takes to answer.
  - The re-check just before what waited leaves covers the moment between opening the mapping and sending. No test
    reaches that moment without a hook in the engine; the check made as the mapping opens is tested.
- **Unchanged:** chained apps' TCP, the tool's own traffic, a stopped tool, and a tool without UDP.
- **Tests:** ninety-two in `core/net/tests/chain.rs`, twenty-seven in the engine's own tests (the rule in
  `whose.rs` and its model in `whose/model.rs`, the larger bounded search run on demand; the windows, at
  simulated instants a nanosecond before their end and at it, `udp_contest`'s among them; what a stand-in keeps
  of its queries, which only memory shows; what waits sorted by the rule; how many ways an answer looks at; and
  the record released with the socket's last way), and three in the network lab with a real tun. Each was made
  to fail by breaking the code it guards, or, for the ten independent reviews' findings, by the engine before
  their fixes. Those that time a
  handover count from when the test's Android was asked, which the engine did no later, so that load cannot
  narrow their margins. Those that need port 53
  use the test proxy's remapping, or any port of the tunnel's DNS address, which leads to the same port of the
  network's resolver, so they run in every `cargo test`. ICMP errors on a direct mapping once the chain takes its
  app have no test: they answer a datagram sent before, and arrive at once on a test's loopback.
- **Still open:** what real tools' relays put in the header, and whether they keep one upstream socket per
  association. The test tool and the lab's proxy name the real sender; v2rayNG and NekoBox are not yet checked.

**Unit 10, the budget for the engine and for each app (2026-11-14, decision 3).**
- **What came before.** Unit 7 capped the TCP connections waiting for their servers for every app together
  (`Limits::tcp_waiting`): a SYN beyond the cap is dropped, its fake port freed at once (`Nat::release`), and
  counted (`tcp_refused`, the 24th counter). Unit 8 brought one receive buffer for each engine thread, lookups that
  end with their answer, and the two-minute timer refreshed both ways. This unit builds the rest of decision 3.
  Unit 9's two leftovers for it, a reused app port reaching a destination its mapping knew with no question to
  Android, and an app Android could not name taken for the mapping's old app, were settled within unit 9 ("Android
  is asked again", "No guess").
- **The caps and the shares,** in `Limits::for_descriptors`, from the soft limit on open files N in
  `/proc/self/limits` (1,024 where it cannot be read), less Watch's reserve of max(128, N/16), B: waiting TCP
  connections min(B/8, 4,096) (`tcp_waiting`), UDP ways B/4 (`udp_mappings`); each app a quarter of each cap, at
  least 32 connections (`tcp_share`) and 64 ways (`udp_share`), never more than the cap. At N = 1,024, the
  defaults: 112 and 32, 224 and 64; at 32,768: 3,840 and 960, 7,680 and 1,920. The apps Android cannot name are one
  app here, and share one share. So four apps must use their whole UDP share before any other is touched, or three
  and a half where a floor lifts the share above a quarter of its cap, as at 1,024. For TCP, where Android answers
  late, an app may hold up to twice its share, as the next point says, by one share at most for every app
  together, and for at most `connect_timeout`: then two and a half apps can fill the TCP cap at 1,024 files (in a
  probe of the review of unit 10, with a cap of 6 and a share of 2, one app held 4, another 2, and a third was
  refused). An app whose sockets Android names at times and not at others holds its own share and, beside it,
  places in the share of the apps Android cannot name, which every such app shares: at 1,024 files up to 128 of
  the 224 UDP ways, so that with one other app at its share, and half another's, it fills the UDP cap; and 64 of
  the 112 waiting connections, or 96 while Android answers late, half another app's share then filling the TCP
  cap.
- **TCP.** A connection waiting for its server holds a place in its app's share from when Android names the app
  until the server answers or fails. Through the chain, to a stand-in, and whenever more than a share's worth of
  connections wait for their servers in all (`tcp_share`, this one counted), Android is asked first and the place
  taken before anything leaves the phone: an app that holds its whole share then has the SYN dropped, as at the
  cap, its port freed at once, nothing sent to the server, no flow logged, and `tcp_refused` counting it. While at
  most a share's worth wait in all, no app can hold its whole share yet, so the server is asked at once beside
  Android, as before the shares, which spares each connection the time a question takes, about 3 ms. Such a
  connection takes its place when Android answers, beyond the share if the app's later connections took places
  first, and is never dropped: whatever leaves the phone is logged under its app (independent review of unit 10,
  major: such a connection was dropped once its SYN had left, and never logged). Only connections begun so lift an
  app above its share, never past twice it, by one share at most for every app together, since each began while at
  most a share's worth waited in all, and only while they wait, for at most `connect_timeout`; one whose server
  answered before Android takes no place. So a question asked first costs its 3 ms only under pressure: past 32
  waiting connections at 1,024 files, 960 at 32,768.
- **What takes a UDP place:** every UDP way that holds a socket of its own. A mapping, on the direct path or
  through the tool, holds its place until it ends; a flow of lookups to the tunnel's DNS address on the direct
  path, until each lookup it carried has its answer, or 10 s pass with none. A chained app's lookups, which Watch
  answers itself, hold none. The place is taken before the socket is made, and before the destination becomes the
  one its socket's other destinations wait for, so that none of them waits on a way refused.
- **At the cap or the share, a mapping ends to make room,** the first there is of:
  1. an answered lookup: a mapping of one destination on port 53 to which the app sent DNS queries only, each with
     its answer by its ID. Since unit 8 a lookup to the tunnel's DNS address ends with its answer, so what this
     finds is an app's own resolver, which sends each query from a socket of its own and leaves a mapping behind
     each answer. It carries nothing more, so it ends however recent its answer: the five seconds below guard what
     may still carry traffic. One the app sent anything else, or more than 64 queries waiting at once, is no
     lookup; nor is one that came in;
  2. the app's own least recently active mapping that passed nothing either way for `Limits::udp_quiet` (5 s);
  3. any app's.

  An app at its share makes room among its own only, steps 1 and 2, since another app's mapping would free nothing
  of its share. A mapping with traffic in the last five seconds never ends so, nor does a flow of lookups, which
  waits for its answer. Each mapping ended so is counted. It ends as one the chain ends: its flows end in the log,
  and its app's next datagram asks Android again and opens a mapping anew, from another port.
- **If nothing may end,** the way is refused: what the rule says its app sent is dropped, as by a full queue, with
  nothing sent back, no flow logged, and counted; what another app sent waits on, as when a way fails. The app
  sends again, as after a lost datagram.
- **What it costs.** Nothing for each datagram. The table ranks the mappings by when it last saw each active, for
  every app and for each, and a search for one to end puts a mapping active since in its place anew, once for all
  its datagrams since: a search costs at most a step for each mapping active since the ranks last placed it, and
  one more. An answered lookup is noted as its answer comes, and dropped from the note once a search finds it sent
  on since. Both go with the mapping.
- **Whose a datagram is** stays the one rule above. A refused way is one that fails at once: what waits is sorted
  by the rule, and only what it says the app sent is dropped. A mapping ended to make room is a way that ends, as
  when the chain changes, and what the app sends next asks Android as a new destination's does. The model drives
  both: a way that fails at a delay of nothing stands for a refused one; and the mapping ends at any instant,
  beside a flow of lookups that stays, in 10,000 random schedules of their own, each with the handovers, datagrams
  and chain turns of the first test's schedule of the same seed, and in the bounded search, on the coarse grid in
  every `cargo test` (110,764 states, about a second) and on the fine grid and in a stream with lookups among the
  larger sets (1.6 and 56.8 million states, in 2 s and 95 s on eight cores with optimisation; the eleven larger
  sets, 321 million states, in eight and a half minutes). Neither finds a fault; both find an eviction that forgets
  the socket's record while a datagram of it still waits, put in by hand.
- **Counters, appended:**
  - `udp_refused`, the 32nd: datagrams and lookups dropped because their UDP way could have no socket, the cap or
    their app's share being full with nothing that could end;
  - `udp_evicted`, the 33rd: mappings ended to make room;
  - `tcp_refused`, the 24th, counts too the SYNs dropped for their app's share.
- **Tests:** nine in `core/net/tests/budget.rs`, with two apps named by their ports: an app at its share gets no
  new mapping while another app does; the cap refuses whoever's way once full; the apps Android cannot name share
  one share; a lookup holds a place until its answer; an app at its share ends its own quiet mapping, not a busy
  one nor another app's, and is refused once only busy ones are left; at the cap, the app's own quiet mapping ends
  before another app's, an app with none ends another app's, an answered lookup through the tool ends first, and
  one that sent on after its answer does not. In the network lab: each app holds only its share of waiting
  connections, so another app's first SYN finds room; a SYN dropped for its share never left the phone, and every
  connection the engine began is logged under its app, counted from the namespace's own `ActiveOpens`, also where
  Android answers slowly; and an answered lookup on the direct path ends first. Unit tests hold the caps to the
  descriptor limit, the budget's places, and the ranks. Each fails when what it guards is broken, on a copy of the
  code.
- **Known limits:**
  - Destinations that wait for their way, before Android names their app or while a tool's handshake takes its
    time, hold no place: each holds up to `udp_waiting` datagrams and a task, for as long as that takes, up to
    `connect_timeout`. Their number is not capped.
  - The destinations an app sends to from one socket are each a flow of its mapping, in memory, and not capped;
    only those that came in are (64).
  - The budget bounds what waits for a server and what UDP holds, as decision 3 says, not every descriptor: a
    relayed TCP connection holds two for as long as it lives, and a mapping through the tool two (its socket and
    its request's connection) for one place.
  - A mapping silent for five seconds may end under pressure, as a call on hold might be; it opens again from
    another port at its next datagram.
  - Left for a later unit, older than this one (found by the review of unit 10): TCP to the tunnel's DNS address,
    as DNS over TCP to the network's resolver, is neither logged as a flow, since the log leaves out every flow to
    that address (`Shared::log_flow`), nor counted as a lookup, as UDP's lookups are.
  - A mapping that ends gives back its place at once, so that room is made under the table's lock, in one step,
    while its socket, and through the tool its request's connection, close a moment later, as its task next runs,
    and as a datagram that was leaving by it is sent. For that moment the engine holds one or two descriptors
    more than the cap counts for each mapping so ended.

**Unit 11, ping (2026-11-15, decision 5).**
- **What is carried.** An app's echo request (ICMP type 8, ICMPv6 type 128) leaves through an unprivileged ping
  socket of Watch's own (a datagram socket of the ICMP protocol, which Android lets every app make), one for each
  app address, echo id and destination, protected before its first send. At most 32 exist (`Limits::echo_sockets`,
  sockets still being made included), and up to 8 requests wait while one is made. A socket ends after 10 s with no
  request (`Limits::echo_idle`), when the network moves, or when a chain comes on. A reply is taken only from the
  address pinged and is rebuilt with the app's own id, its sequence and data, and a hop limit of 64; the kernel's
  id on Watch's socket never reaches the app. A ping to the tunnel's DNS address goes to the network's resolver,
  as lookups do, and is dropped when that resolver is of the other IP version. Echo writes no record to the log.
- **While a chain is on,** every echo is refused, since Android cannot say whose a ping is: a unicast destination
  is answered at once with "administratively prohibited" (ICMP type 3 code 13, ICMPv6 type 1 code 1), a multicast,
  broadcast or unspecified one with nothing (RFC 1812 4.3.2.7, RFC 4443 2.4(e)). The engine's tasks share one
  thread, so only an await lets another run: a socket is waited for until it can be written, and only then are the
  chain checked and the waiting requests sent, with no await between. What is left is a chain set from Android's
  side between a check and its send, which can let out the requests already decided, as for UDP.
- **Where Android refuses ping sockets,** a probe at start finds it for each IP version, and echo is dropped and
  counted, as before this unit.
- **Counters 34 to 38:** echo requests carried, replies, refused, unsupported, dropped.
- **Tests:** unit tests of the packets (checksums, the ICMPv6 pseudo-header, padding, the rebuilt reply, the
  refusal and when none is sent), the cap and the idle end; in netlab, 12 of the engine's 32 tests: ping in IPv4
  and IPv6 with its own id, several ids at once, the cap and the idle end, a forged reply, the probe, the refusal
  with sockets already open (the namespace's kernel received no request, `InEchos`), a reply after a chain came on,
  a request waiting for its socket when a chain comes on, the network moving, and the IPv6 refusal. Each was shown
  to fail without its part of the code. `verify-watch.sh` pings through the tunnel: on the Android 15 emulator,
  Watch's own ping socket carried it and the replies came back (2026-11-15).
- **Reviews.** An independent review found no fault in safety and two majors: requests that waited for a new socket
  could leave after a chain came on, since a first send on a new socket awaited, and the safety claims that matter
  most had no test. Both were fixed, with the minors (the resolver's IP version, no error for multicast or
  broadcast, tests that waited a fixed time, the fuzz target's checksums); a narrow review of the fixes found no
  critical or major fault left.
- **Not done, stated:**
  - errors from the network beneath (unreachable, time exceeded) and the arriving hop limit are not passed on:
    the app sees a timeout, and a traceroute through Watch shows the destination at every hop. A later change that
    sets `IP_RECVERR` on the ping sockets must read their error queue, as `errors::queued` does, so that a pending
    error does not end the socket;
  - echo's bytes are not in the engine's byte counters, while Android counts them to Watch;
  - with no owner there is no share for each app: one app can take all 32 sockets for as long as it pings.
    Accepted: a ping is small and brief, and no other traffic waits on these sockets;
  - phones of other makers, whose SELinux rules for ICMP sockets may differ, are not measured yet (the Galaxy A40
    next).

**Unit 12, fragments and the MTU (2026-11-15, decision 5 as amended and revised).**
- **The first version answered "too large" itself, and was taken back.** Built from the amendment as first written, it
  read the first hop's MTU in the engine and answered a datagram larger than it, as a router would. The second review
  showed what that did to apps whose own link would have carried the datagram: a connected default socket failed its
  next call with `EMSGSIZE` and lost that datagram, an IPv6 socket set to `IPV6_PMTUDISC_OMIT` lost every one, and
  `PROBE` and `INTERFACE` sockets lost them silently. The amendment was revised, and the engine's answer, its probe,
  its table of learned MTUs and their limits went (the `engine/mtu.rs` module, `Config::mtu_probe`, `MtuProbe`,
  `Engine::first_hop_mtus`, `Limits::mtu_learned` and `mtu_expires`).
- **The tunnel's MTU follows the network beneath** (Kotlin, `TunnelMtu`, `WatchVpnService`).
  - A UDP socket of each IP version is bound to the network beneath (`Network.bindSocket`, or `protect` where that is
    refused or before any network is followed), connected toward an address only a default route covers, port 9
    (connecting sends nothing), and its `IP_MTU` read. The address is drawn anew at each measure, from 192.0.2.2 to
    192.0.2.254 and from 2001:db8::/32 outside 2001:db8::/40, where the checks send: one address used every time
    could have a path MTU of its own in the kernel, which an app that sends there and a host that forges a "too big"
    for it could set, and so steer the tunnel's (re-review, minor 4).
  - `android.system.Os` offers apps no `getsockoptInt` (only `getsockoptTimeval`, whose size check refuses an int),
    so the read is Rust's: `datapavan_net::engine::route_mtu`, through nix's safe `sockopt::IpMtu`, behind a new JNI
    export, `Engine.nativeRouteMtu(fd)`, which borrows Kotlin's socket for the call. No existing JNI signature changed.
  - `TunnelMtu.choose` takes the smaller value, within 1,280 and 1,500, and 1,500 when neither socket answers.
    Android's `Builder.setMtu` takes one MTU for both IP versions, so on a network whose IPv4 and IPv6 first hops
    differ, the wider version meets the narrower MTU in the tunnel, not its own hop's: its datagrams between the two
    are fragmented or refused by the app's kernel where without Watch they would pass whole (re-review, minor 2).
  - The tunnel starts with it, measured off the main thread first, since StrictMode counts a UDP connect as network
    access; a stop that comes while a start waits for its measure wins, and so does the service's end (minor 5). Each
    change of the followed network's properties measures again. Within one network the MTU goes down at once, and up
    only once ten minutes have passed since the tunnel was last set up (`TunnelMtu.next`): a reading low for a moment,
    as while a network's IPv6 or its CLAT comes up, does not keep the tunnel narrow for the network's life, and a
    route that flaps sets the tunnel up again at most once in ten minutes for each rise, and once for the fall after
    it (narrow check of the second round, minor 4). A rise held back is measured again once it may be taken, by a
    measure posted for then on the main handler, which `close()` drops, so that a network whose properties do not
    change still gets it (fourth check, minor 2). A new network takes its own value. A new value sets the tunnel up
    again.
  - Watch's dump prints `mtu <chosen> first-hop <IPv4> <IPv6>`. Kotlin no longer reports the network's MTU to the
    engine, which has no use for it.
- **The tunnel is set up again make-before-break** (re-review, major 1). Until then, a new MTU, an address clash (ADR
  0041) and a change of the apps left out each closed the engine and the tunnel before `establish()`: Android tore
  the VPN network down, and the apps, chained ones included, went out directly until the new one was up, against
  W6's "nothing of a chained app goes out directly", or lost their traffic under "block connections without VPN".
  Now each of them, and the debug `addresses-force`, calls `setUpAgain`:
  - the new tunnel is built and established while the old engine still runs on the old one;
  - only then does `nativeStart` stop the old engine, which closes the old tunnel, and start one on the new tunnel;
    the network callbacks stay registered, and the Builder names the followed network as the tunnel's underlying
    one, as the callback did after a start;
  - the old engine hands the new one, before the new one reads a packet, what it goes on with (`Engine::hand_over`,
    `Engine::start_with`, narrow check of the second round, major 1): the chain as Watch last set it, the network's
    resolver, whether answers go uncached, the stand-ins chained apps were given, the names DNS answers gave, and the
    counters, which go on rather than drop (its minor 3). Until then the new engine started with no chain and read
    the new tunnel at once, while Kotlin's `applyChain` came after: a chained app's packets in between went
    directly, and a connection opened then stayed direct for its life. Kotlin sets nothing again after the swap, so
    that no chain read from settings older than the one just applied replaces it (its minor 6). A chain Watch sets
    while no engine runs, as during the swap, is not lost: Watch's native side keeps the chain last set, with whether
    answers go uncached, whatever runs, holds it from reading it until the new engine is in place, and the new engine
    takes it over the one handed over (`ChainSetting`, fourth check, minor 1); stopping the tunnel forgets it;
  - the engine's flows begin anew, as before; unit 12b will hand the new tunnel to the running engine, keeping them;
  - the debug list of apps the end-to-end test sends through the tunnel now holds for every setup of a run.
  - **Why no window is left, and what that rests on.** Read in AOSP's `Vpn.java` (main, 2026-11-15): `establish()`
    called while a VPN interface is up keeps the VPN network and updates its link properties in place when
    `allowBypass` and the allowed and disallowed apps are unchanged, as for a new MTU or new addresses
    (`updateLinkPropertiesInPlaceIfPossible`); otherwise, as when the apps left out change, it connects a new network
    agent before it disconnects the old one ("to prevent the data leakage", `startNewNetworkAgent`); and it resets the
    old interface only after, and only when the new one has another name. So the apps always have a VPN network, and
    what they send between `establish()` and the new engine's start waits in the new tunnel, unread, rather than
    leaving outside it; and the new engine routes them as the old one did, from its first. The narrow check of the
    second round read `android10-release` and `android11-release` too, with the same handover and three differences,
    none harmful here: Android 10's `makeLinkProperties` sets no MTU, while the new tun still takes it from
    `jniCreate(config.mtu)`; on 10 and 11 the Builder's underlying networks are applied at the next update of the
    network's capabilities, not at once; and Android 10's failed `establish()` reports the old network disconnected
    in every case, where Watch stops at any failure anyway. Not measured on a device; the emulator's `verify-watch.sh`
    runs the clash both ways. If `establish()` fails, as when the user withdrew Watch's consent, the tunnel stops, as
    at any start.
- **Fragments are put together** (`core/net/src/fragments.rs`, pure): the apps' IPv4 fragments (the "more
  fragments" flag or an offset) and IPv6 ones (a fragment header with an offset or M), by source, destination and
  identification, and IPv4's protocol. An IPv6 atomic fragment is read whole, as before (RFC 6946).
  - **What drops a whole datagram,** with no ICMP error (RFC 8200 4.5): a fragment not a multiple of 8 but the last,
    or an empty one; a datagram past 65,535 bytes; a first fragment without the whole upper-layer header (UDP's 8
    bytes, TCP's to its data offset, ICMP's 8) or, in IPv6, without every extension header before it (RFC 1858,
    RFC 7112); an overlap with a held fragment (RFC 5722); a fragment past the datagram's end, or a second end. An
    exact duplicate, the same place and the same bytes, is dropped alone. A protocol the engine does not carry is
    dropped as its fragments come (IPv4) or as its first fragment does (IPv6).
  - **After an overlap,** or a fragment past the end or a second end, a marker stays in the datagram's place until its
    wait ends, and its later fragments are dropped as they come, "including those not yet received" (RFC 5722). A
    marker costs one place (32 bytes) and counts toward the bounds. A malformed fragment drops its datagram without a
    marker.
  - **The rebuilt packet:** in IPv4, the first fragment's header with the flag and the offset cleared, the total
    length and the checksum made anew; in IPv6, the headers before the fragment header, which goes, the Next Header
    that named it naming what it named, and the payload length set. It is handled as any packet, from a buffer of its
    own. One that `parse` still calls a fragment, with a fragment header inside the first, is dropped.
  - **Bounds** (`Limits`, Android's defaults): 64 datagrams at once, markers included (`fragment_datagrams`), 1 MiB
    held (`fragment_bytes`), and 5 s from a datagram's first fragment to its last (`fragment_wait`). The bound on bytes
    counts what each buffer reserves, its header, and 32 bytes for each fragment's place, so that a datagram cut into
    8-byte fragments holds no more memory than counted. A buffer doubles as a vector does, so that fragments in order
    do not each move it, and never passes 64 KiB. When a fragment would pass a bound, the incomplete datagram or
    marker that took a fragment longest ago gives way, then the next, until there is room (re-review, minor 3): an
    honest datagram's fragments come one after another, so one that stopped taking them is the likeliest never to be
    whole, and a long one still arriving is not given up for the many that came after its first fragment, as it was
    when the one whose first fragment came first gave way. Each datagram keeps its place in the order of fragments
    taken, a count rather than a time, so that fragments of one instant still have an order; a marker's is its
    marking. A fragment no room could take, larger than the bound with its own datagram, is dropped with it, and
    nothing gives way for it. Expired datagrams go at the next fragment and in the engine's sweep.
  - **Shared by every app.** Every app sends from the tunnel's one address, so the bounds are not kept for each app:
    one app that keeps them full makes the others' datagrams give way, as every fragment was dropped before. Accepted,
    since the bounds cap what fragments cost, for at most the wait.
- **Beyond the first hop.** `errors::told` passes on "fragmentation needed" (type 3 code 4) and "packet too big"
  (type 2) with the MTU the kernel gives in `ee_info`, to the app at once, as if from the destination, as an
  unreachable port is passed on; an MTU of 0, from a router older than RFC 1191, is left out. The engine keeps
  nothing of them: its own kernel keeps the path's MTU for its sockets. What a mapping read as the network beneath
  moved is not passed on after the move, nor counted, and the mapping ends (second review, minor 4b), whichever way
  its read ended, the mapping gone or its socket failing among them (re-review, minor 6).
- **What stays as it is.** A send the engine's kernel refuses as too long (`EMSGSIZE`) is dropped and counted, never
  answered "host unreachable". A datagram larger than the path leaves: the engine's kernel fragments it, or a router
  answers. The chain, lookups to the tunnel's DNS address and TCP are unchanged; writes to the tunnel larger than its
  MTU, the answers the engine's kernel put together, are taken by Linux in the network lab (phones in unit 11b).
- **Counters:** `fragments`, the 20th, now counts the fragments dropped, those of a datagram given up included.
  Appended: `reassembled`, the 39th, datagrams put together; `too_big`, the 40th, datagrams the engine's kernel
  refused as too long, dropped; `path_mtu`, the 41st, routers' "fragmentation needed" and "packet too big" passed on.
  `COUNTERS` is 41.
- **The network lab.**
  - A narrow network (`scripts/netlab-enter.py`): a server at 198.51.100.20 and 2001:db8:1::20 on `far`, one end of a
    veth pair whose other end, `near`, is in the same namespace, its own MTU and its routes' 1,280. What the namespace
    itself sends there takes `near`, by a rule for packets made locally, while the apps' packets still go into the
    tunnel first. An app of the namespace's own addresses so meets the narrow network as an app meets its link without
    Watch.
  - An app of every path MTU discovery mode (`scripts/netlab-app.py`): `dont`, `want`, `do`, `probe`, `interface` and
    `omit`, unconnected and connected, and IPv6's `IPV6_DONTFRAG`. nix sets none of them on Linux and the workspace
    forbids unsafe code; Python's socket module takes the option numbers.
- **Tests.**
  - In the engine: 14 of the reassembler (in and out of order, both versions, IPv4 options and IPv6 headers before the
    fragment header, overlap and its marker, exact duplicate, a first fragment without its header, what is malformed or
    too long, a datagram giving way at each bound with the costs counted, the one heard from longest ago giving way
    rather than the one that began first, and the re-review's race, a 10-fragment datagram whole among 32 new
    datagrams after each of its fragments, or 8 far ones of 64 KiB; the wait to the nanosecond, the rebuilt headers
    byte for byte); one of what routers say (`errors::told`); three of the mappings (an error read as the network
    moves is not passed on, and one read before passes on with its MTU; a move since a mapping opened, not one before,
    and the engine stopping, as its watch shows them; `EMSGSIZE` dropped and counted); one of `route_mtu`. The fuzz
    target feeds the reassembler a sequence of fragments and holds it to its bounds.
  - In the network lab, 5: across a swap, as `nativeStart` makes it, a chained app's first datagram and first TCP
    connection go through the tool and nothing of them reaches the server directly, a direct app's lookup reaches the
    resolver handed over and comes back uncached, a flow is named by a name learned before, and the counters go on;
    a 3,000-byte datagram both ways in IPv4 and IPv6; at the tunnel's 1,500 with the network
    at 1,280, as in the moment before Watch sets the tunnel up again, every mode's datagram reaches the server whole,
    with no error on a connected default socket and nothing lost by `omit` (the second review's R1 and R3, now
    passing); with tun0 at 1,280, as Watch sets it, each mode fragments or is refused with `EMSGSIZE` exactly as the
    same app does on the narrow network without Watch, and the 24 datagrams fragmented are put together; a router's
    "fragmentation needed" and "packet too big" reach the app with their MTU, and a connected default socket then
    sees `EMSGSIZE` once, as without Watch. In `chain.rs`, a stand-in given before a swap names its name after, and a
    chain set during the swap wins over the one handed over; in watch-jni, a chain set while no engine runs, between
    the hand-over and the next start as `nativeStart` has them, is the next engine's, and a stop forgets it.
  - In Kotlin, JVM tests of `TunnelMtu`: the choice, the MTU's rise within a network only ten minutes after a setup,
    to the millisecond, how long a rise held back waits to be measured again, and the probe's
    addresses drawn from their ranges, never where checks send. `scripts/verify-watch.sh` checks that the tunnel's
    interface carries the MTU Watch chose (1,500 on the emulator), where the shell can read it, and pings with 2,000
    bytes, which must be put together on an emulator, its reply reported, not required. On the Android 15 emulator
    both passed (the maintainer's session, before the tunnel was set up make-before-break).
  - Each was made to fail by a mutation of the code it guards: 71 mutations of the code as it stands, each caught.
    No test reaches the service's lifecycle, which is Android's: setting the tunnel up again, a start or a stop while
    a measure runs, and the measure posted for a rise; nor `nativeStart`'s own hand-over, two lines that call what the
    swap test calls; nor the order of the native side's two locks against a `nativeChain` that lands mid-swap, nor
    the logger's last batch after one it was handing over (fourth check, a nit, fixed), both races; nor an
    early end of a mapping's read after it built errors, which needs the mapping to end
    between two reads; nor the order in which echo counts a reply and writes it, which is a race with the reader
    (re-review, minor 7: it counts first now).
- **Not done, stated:**
  - phones, what `IP_MTU` says on Wi-Fi and mobile networks and whether their kernels take writes to the tunnel
    larger than its MTU, are measured in unit 11b; the make-before-break setup has not run on an emulator yet;
  - the first start keeps its order, older than this unit: the engine reads the tunnel from `nativeStart` on, and
    `applyChain` comes after, so a chained app's first packets can still go directly at a start, as they did before
    Watch ran. The native side now keeps a chain set before any engine runs and starts the first engine with it, so
    calling `applyChain` before `nativeStart` would close this; that reorder, with unit 12b's holding of a chained
    app's new flows until the chain is set, is left to unit 12b;
  - setting the tunnel up again ends the engine's flows, as before: connections through the tunnel start anew. Within
    a network that happens only when its MTU goes down; unit 12b keeps the flows;
  - a network whose IPv4 and IPv6 first hops differ gives the wider version the narrower MTU (above);
  - the ping sockets still set no `IP_RECVERR` (unit 11), so a router's "fragmentation needed" for an echo request is
    not passed on, and a request whose send fails with `EMSGSIZE` is counted as dropped echo;
  - the errors passed on are not rate-limited (RFC 4443 2.4 (f)): they reach only the phone's own apps;
  - an app's TCP fragments are put together too and handled as any segment; Android's stack sizes its segments to
    the tunnel, so they are rare.
