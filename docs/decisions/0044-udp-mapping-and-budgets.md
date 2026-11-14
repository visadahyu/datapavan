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
     touched.
   - **At the TCP cap:** a SYN is dropped, as by a full queue, so the app's own stack tries again. Its fake port is
     freed at once, since it never reached Android's stack.
   - **At the UDP cap, what makes room, in order:**
     1. an answered lookup;
     2. the requesting app's least recently active mapping idle at least 5 seconds;
     3. any app's.

     A mapping with traffic in the last 5 seconds is never evicted, so a call is never cut. If nothing qualifies,
     the datagram is dropped.
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
   - **Fragments:** counted apart. They are reassembled only if the count shows a need.
   - **Too large:** a datagram larger than the network beneath can carry is answered with ICMP "fragmentation
     needed" or "packet too big", with the network's MTU, which Kotlin passes from `LinkProperties`. The app's
     "do not fragment" bit is not copied onto the engine's sockets.
   - **The lock:** Watch's native side never holds the engine's lock while joining its thread.
6. **Tests that drive time.**
   - The engine takes its limits and timings from its `Config`, so tests can use seconds.
   - On Linux, a harness runs it in an unprivileged user and network namespace with a real tun device. Kernel
     TCP, resets, ICMP sockets, caps and timeouts are then tested in an ordinary `cargo test`, on every change,
     without an emulator.
   - Where namespaces are not available, those tests say plainly that they did not run. They never pass silently.
   - CI allows the namespaces.

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
    in three minutes on 24 cores with optimisation (`--ignored`; `WHOSE_BOUNDS` sets others). Of 24 mutations of
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
