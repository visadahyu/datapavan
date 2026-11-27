# 0044. UDP mapping, budgets for each app, and the engine's smaller gaps

- Status: Accepted (by the maintainer on 2026-11-12)
- Date: 2026-11-12

## Context

The independent review of 2026-11-09 rated the engine's design and parsers above the field, and its forwarding
path at the field's standard. Its findings 18 to 21 say why. The maintainer made them gates of Datapavan Advanced
0.2.0, its first release, with an ADR (D25).
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
   - **Lifetime:** a mapping ends after 120 seconds with no datagram either way (REQ-5 and REQ-6), when its
     app's owner changes, or when the network or the chain changes.
   - **What stays as it is:** lookups to the tunnel's DNS address keep one connected socket per flow.
   - **ICMP errors are kept.** A connected socket learns of an ICMP error such as "port unreachable" by itself;
     an unconnected one only with `IP_RECVERR` (and `IPV6_RECVERR`), which queues each error with the datagram's
     destination. The mapped sockets turn it on. The engine reads each error from the socket's error queue and
     tells the app: from the router or host the kernel names as its sender, else from that destination (unit
     11b, below). Most userspace NATs lose these errors, and apps then
     wait for their own timeouts.
   - **Through a safe library only (ADR 0006).** rustix 1.1.4, already in the lockfile, offers neither the option
     nor the extended error. nix (MIT) offers both, `sockopt::Ipv4RecvErr` and `Ipv6RecvErr` and the
     `Ipv4RecvErr` and `Ipv6RecvErr` control messages, behind safe functions. It is used, its review for size,
     licence and advisories having passed (under "Consequences").
2. **Chained UDP: one UDP ASSOCIATE per mapping,** not per destination.
   - Each answer is matched to its destination by its SOCKS5 header, so that nothing the relay sends on an
     association reaches the app as if from the flow's destination.
   - A stand-in name is bound to the first answer from the port the app asked.
   - Chained apps get the same address-dependent filtering. W6's done-when reads "nothing comes in from an
     address a local app did not send to".
   - Whether the tool itself keeps one upstream socket per association is the tool's own choice. Advanced cannot
     change it.
3. **A budget for the engine and for each app.**
   - **The caps:** they come from the process's descriptor limit N, read from `/proc/self/limits`, less a reserve of
     max(128, N/16) for the network part's own use (B). UDP mappings are capped at B/4. Waiting TCP connections are
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
   - **What each part costs:** one 64 KiB receive buffer per engine thread, not one per flow. A lookup to the
     tunnel's DNS address ends with its answer.
   - **Counters:** each refusal and eviction is counted. None of them names a destination.
4. **Two names.**
   - The name the connection itself sent (TLS or QUIC) names the flow. The DNS name is kept beside it when the two
     differ.
   - An ECH public name never names a flow.
   - The log's record format is version 2. The DNS name is written only where the names differ, so its presence
     is the flag that they differ, and no bit of its own says it twice; a flow that came in is bit 1 of the
     record's flags. The order of names is written once, in the engine's `NamedBy`. The network part's Kotlin
     side reads versions 1 and 2, so sealed records stay readable.
   - ADR 0037 states the record's format to match. Counters measure how often the names differ.
   - The names' finer rules (W5's first part and its fix rounds, 2026-11-18, after review 1 of that part):
     - ECH public names in the answers of an app's own plain resolver are kept as its addresses are, for that app's
       flows only, so a public name names no flow wherever the engine saw its configuration, and no app hides
       another's names (names, finding 1). Each scope has a table of its own, Android's resolver's of 8,192 addresses
       and 256 public names, so an app's own resolver pushes out only that app's names (review 2: in one table it
       could push Android's out). Each app's holds 512 addresses and 64 public names, at most 32 apps keep tables of
       their own (one more takes the place of the app whose own resolver answered last the longest ago), and the
       engine's sweep, every minute with traffic, drops an app's tables once every name in them has expired (review 3,
       nit 3). The names are the app's to choose, up to 253 bytes each, and the bound is given with them at their
       longest: by what the tables ask of the allocator, an app's full tables take up to about 270 KB, so 32 apps
       about 8.5 MB, beside Android's about 3.7 MB, or about half that with names of 15 bytes (115 KB, 3.6 MB and 1.7
       MB; review 4, nit 4). An app that sends no plain DNS of its own, past the tunnel's resolver, takes nothing.
     - A DNS name stands beside the connection's own only while it is current: a name from an answer is kept, to name
       flows, on the monotonic clock, and through a night it would show W5's users a difference that is only its age,
       so it stands beside another only while the answer that named the flow when it started is held in time since the
       phone started, with the same hold (at least an hour, at most a day). The flow carries that hold from its start,
       so a later answer for the address, as another app's lookup of a name on the same CDN address, does not end it.
       The answer's own time to live would hide a real difference after a minute, since apps keep addresses longer
       than DNS says (engine, finding 7). A failed reading of the time since start holds a name for no time.
     - A stand-in's name is the name the tool was asked to reach, tied to that address alone, so it is current while
       the stand-in lives and stands beside the hello's name; the hello's name names the flow, one rule for every
       flow, since the hello says which server the app spoke to at the address the tool reached, and both names are
       kept (names, finding 9).
     - The mark of an app's own encrypted DNS follows the name that names the flow: a hello that renames a flow
       marks it again from its port, its address and the hello's name, so a mark that only its DNS name gave goes
       with that name, and the counter of such flows takes it back (names, finding 10).
5. **The smaller gaps:**
   - **Resets:** an upstream that ends in an error ends the other side with a reset (linger zero), both ways.
   - **ICMP echo:** carried through unprivileged ICMP sockets, protected, at most 32. Its owner cannot be asked of
     Android, so pings are refused while a chain is on. Where Android refuses such sockets, echo is dropped and
     counted.
   - **Fragments:** counted apart. They are reassembled only if the count shows a need. (Proposed on 2026-11-15,
     below, "Proposed for decision 5": they are reassembled, within bounds.)
   - **Too large:** a datagram larger than the network beneath can carry is answered with ICMP "fragmentation
     needed" or "packet too big", with the network's MTU, which Kotlin passes from `LinkProperties`. The app's
     "do not fragment" bit is not copied onto the engine's sockets. (Proposed on 2026-11-15, below, "Proposed for
     decision 5": the tunnel's MTU follows the network beneath, and the engine passes on only what routers answer.)
   - **The lock:** the native side (`core/network-jni`) never holds the engine's lock while joining its thread.
6. **Tests that drive time.**
   - The engine takes its limits and timings from its `Config`, so tests can use seconds.
   - On Linux, a harness runs it in an unprivileged user and network namespace with a real tun device. Kernel
     TCP, resets, ICMP sockets, caps and timeouts are then tested in an ordinary `cargo test`, on every change,
     without an emulator.
   - Where namespaces are not available, those tests say plainly that they did not run. They never pass silently.
   - CI allows the namespaces.

**Proposed for decision 5: fragments and the MTU (2026-11-15, unit 12, which builds it; no acceptance by the
maintainer is recorded).**
- **Why.** Two things were measured in Linux namespaces on 2026-11-15:
  - **Apps' kernels fragment.** A default UDP socket, IPv4 or IPv6, whose path MTU is smaller than its datagram
    sends it as fragments. Only a socket set to "do not fragment" gets `EMSGSIZE`. An engine that drops fragments
    cuts such an app off as soon as its path is narrower than its datagrams.
  - **"Too large" from the engine is not what the app meets without the VPN.** An engine that answers datagrams
    larger than the network beneath, as a router would, harms apps whose own link would have handled them, as
    unit 12's second review showed:
    - a connected default socket fails its next call with `EMSGSIZE`, and that datagram is lost;
    - an IPv6 socket set to `IPV6_PMTUDISC_OMIT` ignores the answer, so every datagram is lost;
    - `PROBE` and `INTERFACE` sockets lose datagrams silently.

    Without the VPN, the app's own kernel fragments those datagrams, or refuses them at once.
- **The tunnel's MTU follows the network beneath.**
  - Advanced sets the tunnel's MTU to its first hop's, as the kernel reports it. A UDP socket of each IP version,
    bound to the network beneath, is connected toward an address only the default route covers, and `IP_MTU` is
    read from it. On Linux `IP_MTU` answers for an IPv6 socket too, and the IPv6 value includes what router
    advertisements set.
  - The tunnel takes the smaller of the two values, never below 1280 or above 1500. It takes 1500 when neither
    socket answers.
  - When a network change brings another value, the tunnel is set up again, as for an address clash (ADR 0041), and
    make-before-break: the new tunnel is established while the engine still runs, so that nothing leaves outside the
    tunnel meanwhile. Where its addresses stay and Android keeps the same VPN network (the apps the service hands its
    `Builder` are the same, in the same order), the running engine goes on with the new tunnel and keeps its flows,
    chain and all (unit 12b); a setup with other addresses or on a new VPN network starts a new engine, which goes on
    with the one before's chain from its first packet. Within one network a lower value is taken at once and a higher
    one only 10 minutes after the last setup, so that a flapping route cannot set the tunnel up again and again.
  - Android's `Builder` takes one MTU for both IP versions, so the wider version meets the narrower one's MTU.
  - The app's own kernel then meets the first hop as it would without the VPN: it fragments the datagram or refuses
    it, by its socket's own setting. `LinkProperties.getMtu()` is 0 on most networks, so it is not used.
- **Fragments are reassembled.**
  - An app's IPv4 and IPv6 fragments are put together, and the whole datagram is handled as any other.
  - The cost is bounded in datagrams, bytes and time. When a bound is reached, the oldest incomplete datagram gives
    way, since an honest one is complete within milliseconds.
  - Overlapping fragments drop the whole datagram, and its later fragments until its wait ends (RFC 5722). A first
    fragment without the whole transport header drops it too (RFC 1858, RFC 7112).
- **Beyond the first hop.** The "fragmentation needed" and "packet too big" that routers send to the engine's
  sockets (read through `IP_RECVERR`) are passed on to the app with their MTU, as they would reach it without the VPN.
  The engine answers nothing on its own. A datagram larger than the path is sent: the engine's kernel fragments it,
  or a router answers.
- **What stays as it is.** A datagram the engine's kernel refuses as too large is dropped and counted, never
  answered "host unreachable". The chain, lookups to the tunnel's DNS address, and TCP are unchanged.

## Consequences

- **Calls and peer-to-peer apps keep their direct paths,** as without the VPN. Port scanning by one app does not
  cost other apps their connections.
- **The maintainer's questions on the bar (2026-11-12):** budgets for each app, two names and the namespace
  harness are above the open tools; endpoint-independent mapping by default, also through the chain, is at the
  top of the field; resets, echo and the MTU are the field's standard; keeping ICMP errors with unconnected
  sockets is above most userspace NATs. Building it needs no frontier research. Measuring it does need lab work:
  - descriptor limits and ICMP sockets across phone makers;
  - each tool's relay;
  - how often names differ.

  An outside review of the engine (D28) is still needed before 0.2.0 is called stable.
- **nix's review (2026-11-12):** nix 0.31.3 (MIT), with the features `net` and `uio`, passed `cargo deny` and
  builds for the three Android targets. It brings memoffset, cfg_aliases, bitflags and autocfg (build only). With
  the new UDP code, the arm64 library grew from 775,976 to 812,312 bytes, about 2.8 KB of it nix's own.
- **aes-gcm's review (2026-11-17, unit 9b, fix round 1):** the maintainer's rule, vetted libraries over cryptography
  of our own, replaced unit 9b's GHASH written out by hand with RustCrypto's `aes-gcm` 0.11.1 (Apache-2.0 OR MIT,
  published by the RustCrypto developers, repository RustCrypto/AEADs), without its default features (no allocator, no
  random numbers), on the `aes` 0.9.4 and `cipher` 0.5.2 already in both lockfiles. It brings seven more crates, all
  RustCrypto's and under the same licences: `aead` 0.6.1, `ctr` 0.10.1, `ghash` 0.6.0, `polyval` 0.7.3,
  `universal-hash` 0.6.1, `ctutils` 0.4.8 and `cmov` 0.5.4; `cargo deny` passes, both lockfiles hold them, and the
  three Android targets build. **Audit:** the crate's README cites one review by NCC Group, read here in the report
  itself ("RustCrypto AES/GCM and ChaCha20+Poly1305 Implementation Review", version 1.0 of 2020-02-13, by Gérald
  Doussot and Thomas Pornin, for MobileCoin, five person-days): it covered `aes-gcm`, `aes`, `ghash`, `polyval`,
  `aead` and `universal-hash` at their commits of December 2019 and found no vulnerability; in its words, "a few
  cosmetic remarks, mostly related to potential performance improvements", and one on GCM's size limits: `aes-gcm`'s
  checks of the largest plaintext, ciphertext and associated data were slightly off GCM's own (2^36 bytes against
  2^36 - 32, the tag left out of the ciphertext's, and associated data held to 2^36 bytes where GCM allows 2^61 - 1),
  which the report found no risk in, the checks being failsafes and 2^36 bytes about 69 GB; this engine's packets are at
  most 64 KB. The code reviewed is that of nearly seven years ago, not 0.11's, whose ARMv8 backends, those a phone
  uses, came later and have no audit. **Advisories:** RUSTSEC-2023-0096 (a failed tag left the decrypted text in the
  caller's buffer, 0.10.0 to 0.10.2, patched in 0.10.3); 0.11.1 checks the tag before it decrypts, and the engine
  never reads a buffer whose tag failed. Two more in RustSec's database for crates it brings, read in fix round 2:
  RUSTSEC-2026-0003 (`cmov` before 0.4.4 made code on 32-bit ARM that branched on the values it was to move in
  constant time) and RUSTSEC-2026-0385 (`ctutils` before 0.4.4, masks built with a branch, and `u128` comparisons
  branching on 32-bit targets); the lockfiles hold `cmov` 0.5.4 and `ctutils` 0.4.8, both after the fixes, which
  matters since 32-bit ARM (`armv7-linux-androideabi`) is one of the engine's targets. The arm64 library grew from
  1,040,152 to 1,050,160 bytes. The hello's reader, which removed an Initial's protection without its tag, now checks
  it too: with the library it costs one GHASH for each of a flow's first few datagrams, and a packet damaged on its
  way, or bytes that only look like an Initial, then name no flow rather than one by frames that happened to parse.
- **hkdf's review (2026-11-17, unit 9b, fix round 2):** the same rule replaced the HMAC-SHA-256 and TLS 1.3's
  `HKDF-Expand-Label` written in `quic.rs` since W3 with RustCrypto's `hkdf` 0.13.0 (MIT OR Apache-2.0, published by
  the RustCrypto developers, repository RustCrypto/KDFs), which brings `hmac` 0.13.0 (the same, repository
  RustCrypto/MACs); both are built on `digest` 0.11, as the `sha2` 0.11.1 already in both lockfiles is, both
  forbid unsafe code, neither is used with a default feature (`hkdf`'s `kdf`, off by default, is not taken), and
  `digest` gains its `mac` feature. No newer release of either exists than these, `hmac` 0.13.0 of 2026-03-29 and
  `hkdf` 0.13.0 of 2026-03-30, the first stable ones on `digest` 0.11; RustSec's
  database (read 2026-11-17) has no advisory for either. Neither is
  covered by NCC's review above, nor by any audit their repositories cite: HKDF and HMAC are a few dozen lines over
  SHA-256, checked here against RFC 5869 A.1 (the PRK, and all 42 bytes of the expand step) and RFC 9001 A.1 (each
  secret and key, step by step), as the code they replace was, and against every RFC sample packet the sealer
  reproduces. `cargo deny` passes, both lockfiles hold them, and the three Android targets build. Initial keys are
  no secret, so a fault in either would misread packets, not leak anything.
- **Two filters differ by design:** address-dependent for answers, endpoint-independent for mappings. These are
  the defaults RFC 4787 recommends, and what most home routers do.
- **For UDP, decision 1 takes the place of ADR 0012's "one socket per flow".** W6's done-when keeps its meaning
  in decision 2's words: an answer still needs a datagram the app sent first.
- **The log's format has one change,** to version 2 (decision 4), made before W5 read the log.

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
    app never saw, when no other stand-in of the mapping could take it (one whose datagrams carried an identifier
    only by an answer that carries it: unit 9b, below). Later answers from that address reach the
    app from the stand-in. Only a stand-in the app sent to waits: a flow that came in, as another port of a name
    a relay gave back, never does, since the app asked it nothing.
  - **A bounded cut** (only for a second name whose datagrams carry no identifier, unit 9b; one that carries
    one takes from the bound address only the answers that carry it, and the rest go to the bound name at once). A
    second name asked on a bound name's port contests the bound address's answers for
    `Limits::udp_contest`, 5 s after the app first asked it, and they are dropped meanwhile: one unanswered
    datagram to a silent STUN name beside a working TURN server on 3478 cuts the TURN server for those seconds,
    not for minutes. A first answer through a tool comes within about a second; five leave room for a slow one.
    The trade-off: if the second name does resolve to the bound name's very address and port, its later answers
    reach the app under the first name, and the log counts them there. The second name still waits, as long as
    it lives, for a first answer from an address no other stand-in was bound to.
  - On port 53, that answer must also be a DNS response to a query the app sent that stand-in, by its ID and its
    question. A sender that guesses neither cannot take the stand-in, nor feed the engine the names it learns.
  - **The risk where no identifier tells:** a stand-in whose datagrams carried a STUN transaction ID, a QUIC
    connection ID, a DNS query's ID and question or an NTP request's timestamp is bound only by an answer that
    carries it, also when it waits alone (unit 9b, below): a sender can take it only with what the app sent it.
    For a protocol that carries none, on other ports, whoever reaches the tool's relay first, from the port the
    app asked and an address the app never saw, takes a waiting stand-in, and the real answer is then dropped.
    Such a sender must know where the tool's relay sends from, and when; the tool's own filtering, if it has any,
    comes first. No relay read for unit 9b filters its answers by their source, so an association of a
    stand-in's own does not narrow it. A destination the app sent to, or a stand-in already bound, never takes
    another stand-in this way; its address binds a waiting stand-in, beside the peer that holds it, by an answer
    that carries that stand-in's identifier, and only so.
  - When several wait on one port, an answer from an address the app never saw goes to the one stand-in whose
    identifier it carries, and is dropped, as carrying none, when it carries none of theirs (unit 9b). A stand-in
    without identifiers is never left beside another on one association, but leaves by one of its own. Only beyond
    the caps on those, or with no place in the budget, does the floor apply: there the answer could be any of
    their names', and it is dropped rather than handed to one, for as long as more than one waits, so that an app
    that asks several names on one port at once, as some ask several STUN servers, gets no answer from them
    through the tool.
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
  when the network's resolver answers, a chained app's when the engine has answered it, within a few seconds. Each
  lookup is kept by its ID and question, and an answer settles only the lookup it answers, so a repeated answer
  does not end the flow before a later lookup has its own; at most 256 wait on one flow. One that gives way to a
  new flow, when Android is asked again or the chain changes, still hands the app every answer it owes.
- **Counters, appended:**
  - `udp_unmatched`, the 27th: answers that no one destination could be told for, such as one on a port several
    stand-ins wait on, a malformed header or a fragment. It measures how often the rule above costs an answer
    (what it counts is listed in unit 9b's note);
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
  tool set again keeps it. This holds for the direct path's mappings too. A chained
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
- **What earlier units built.** Unit 7 capped the TCP connections waiting for their servers for every app together
  (`Limits::tcp_waiting`): a SYN beyond the cap is dropped, its fake port freed at once (`Nat::release`), and
  counted (`tcp_refused`, the 24th counter). Unit 8 brought one receive buffer for each engine thread, lookups that
  end with their answer, and the two-minute timer refreshed both ways. This unit builds the rest of decision 3.
  A reused app port reaching a destination its mapping knew, and an app Android cannot name, are unit 9's
  ("Android is asked again", "No guess").
- **The caps and the shares,** in `Limits::for_descriptors`, from the soft limit on open files N in
  `/proc/self/limits` (1,024 where it cannot be read), less the process's own reserve of max(128, N/16), B: waiting TCP
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
  Android, which spares each connection the time a question takes, about 3 ms. Such a
  connection takes its place when Android answers, beyond the share if the app's later connections took places
  first, and is never dropped: whatever leaves the phone is logged under its app (independent review of unit 10,
  major: dropped once its SYN had left, such a connection would never be logged). Only connections begun so lift an
  app above its share, never past twice it, by one share at most for every app together, since each began while at
  most a share's worth waited in all, and only while they wait, for at most `connect_timeout`; one whose server
  answered before Android takes no place. So a question asked first costs its 3 ms only under pressure: past 32
  waiting connections at 1,024 files, 960 at 32,768.
- **What takes a UDP place:** every UDP way that holds a socket of its own. A mapping, on the direct path or
  through the tool, holds its place until it ends; a flow of lookups to the tunnel's DNS address on the direct
  path, until each lookup it carried has its answer, or 10 s pass with none. A chained app's lookups, which the
  engine answers itself, hold none. The place is taken before the socket is made, and before the destination becomes the
  one its socket's other destinations wait for, so that none of them waits on a way refused.
- **At the cap or the share, a mapping ends to make room,** the first there is of:
  1. an answered lookup: a mapping of one destination on port 53 to which the app sent DNS queries only, each with
     its answer by its ID. A lookup to the tunnel's DNS address ends with its answer (unit 8), so what this
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
  socket of the engine's own (a datagram socket of the ICMP protocol, which Android lets every app make), one for each
  app address, echo id and destination, protected before its first send. At most 32 exist (`Limits::echo_sockets`,
  sockets still being made included), and up to 8 requests wait while one is made. A socket ends after 10 s with no
  request (`Limits::echo_idle`), when the network moves, when a chain comes on, or at the cap, to make room for a
  new one (unit 11b, below). A reply is taken only from the address pinged and is rebuilt with the app's own id,
  its sequence and data, and the hop limit it arrived with (unit 11b); the kernel's id on the engine's socket never
  reaches the app. A ping to the tunnel's DNS address goes to the network's resolver,
  as lookups do, and is dropped when that resolver is of the other IP version. Echo writes no record to the log.
- **While a chain is on,** every echo is refused, since Android cannot say whose a ping is: a unicast destination
  is answered at once with "administratively prohibited" (ICMP type 3 code 13, ICMPv6 type 1 code 1), a multicast,
  broadcast or unspecified one with nothing (RFC 1812 4.3.2.7, RFC 4443 2.4(e)). The engine's tasks share one
  thread, so only an await lets another run: a socket is waited for until it can be written, and only then are the
  chain checked and the waiting requests sent, with no await between. What is left is a chain set from Android's
  side between a check and its send, which can let out the requests already decided, as for UDP.
- **Where Android refuses ping sockets,** a probe at start finds it for each IP version, and echo is dropped and
  counted.
- **Counters 34 to 38:** echo requests carried, replies, refused, unsupported, dropped.
- **Tests:** unit tests of the packets (checksums, the ICMPv6 pseudo-header, padding, the rebuilt reply, the
  refusal and when none is sent), the cap and the idle end; in netlab, 12 of the engine's 32 tests: ping in IPv4
  and IPv6 with its own id, several ids at once, the cap and the idle end, a forged reply, the probe, the refusal
  with sockets already open (the namespace's kernel received no request, `InEchos`), a reply after a chain came on,
  a request waiting for its socket when a chain comes on, the network moving, and the IPv6 refusal. Each was shown
  to fail without its part of the code. `verify-network.sh` pings through the tunnel: on the Android 15 emulator,
  the engine's own ping socket carried it and the replies came back (2026-11-15).
- **Reviews.** An independent review found no fault in safety and two majors: requests that waited for a new socket
  could leave after a chain came on, since a first send on a new socket awaited, and the safety claims that matter
  most had no test. Both were fixed, with the minors (the resolver's IP version, no error for multicast or
  broadcast, tests that waited a fixed time, the fuzz target's checksums); a narrow review of the fixes found no
  critical or major fault left.
- **Not done, stated:**
  - errors from the network beneath (unreachable, time exceeded), the arriving hop limit and echo's bytes are
    unit 11b's (below): it sets `IP_RECVERR` on the ping sockets and reads their error queue, as `errors::queued`
    does, so that a pending error does not end the socket;
  - with no owner there is no share for each app: one app can take all 32 sockets for as long as it pings.
    Accepted: a ping is small and brief, and no other traffic waits on these sockets;
  - phones of other makers, whose SELinux rules for ICMP sockets may differ, are not measured yet (the Galaxy
    A40's run is in unit 11b).

**Unit 12, fragments and the MTU (2026-11-15, the proposal for decision 5).**
- **The engine answers no "too large" itself.** Answered by the engine, as a router would, a datagram larger than
  the first hop's MTU harms apps whose own link would have carried it, as the second review showed: a connected
  default socket fails its next call with `EMSGSIZE` and loses that datagram, an IPv6 socket set to
  `IPV6_PMTUDISC_OMIT` loses every one, and `PROBE` and `INTERFACE` sockets lose them silently. The engine keeps no
  probe of the first hop and no table of learned MTUs.
- **The tunnel's MTU follows the network beneath** (Kotlin, `TunnelMtu`, `NetworkVpnService`).
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
    are fragmented or refused by the app's kernel where without the VPN they would pass whole (re-review, minor 2).
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
  - The service's dump prints `mtu <chosen> first-hop <IPv4> <IPv6>`. Kotlin does not report the network's MTU to
    the engine, which has no use for it.
- **The tunnel is set up again make-before-break** (re-review, major 1). Were the engine and the tunnel closed
  before `establish()`, Android would tear the VPN network down, and the apps, chained ones included, would go out
  directly until the new one was up, against W6's "nothing of a chained app goes out directly", or lose their
  traffic under "block connections without VPN". A new MTU, an address clash (ADR 0041), a change of the apps left
  out and the debug `addresses-force` each call `setUpAgain`:
  - the new tunnel is built and established while the old engine still runs on the old one;
  - only then does `nativeStart` stop the old engine, which closes the old tunnel, and start one on the new tunnel;
    the network callbacks stay registered, and the Builder names the followed network as the tunnel's underlying
    one, as the callback did after a start;
  - the old engine hands the new one, before the new one reads a packet, what it goes on with (`Engine::hand_over`,
    `Engine::start_with`, narrow check of the second round, major 1): the chain as the service last set it, the
    network's resolver, whether answers go uncached, the stand-ins chained apps were given, the names DNS answers
    gave, and the counters, which go on rather than drop (its minor 3). A new engine that started with no chain and
    read the new tunnel at once, before Kotlin's `applyChain`, would send a chained app's packets in between
    directly, and a connection opened then would stay direct for its life. Kotlin sets nothing again after the
    swap, so that no chain read from settings older than the one just applied replaces it (its minor 6). A chain
    the service sets while no engine runs, as during the swap, is not lost: the native side keeps the chain last
    set, with whether
    answers go uncached, whatever runs, holds it from reading it until the new engine is in place, and the new engine
    takes it over the one handed over (`ChainSetting`, fourth check, minor 1); stopping the tunnel forgets it;
  - with other addresses or on a new VPN network the engine's flows begin anew; otherwise unit 12b hands the new
    tunnel to the running engine, which keeps them;
  - the debug list of apps the end-to-end test sends through the tunnel holds for every setup of a run.
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
    in every case, where the service stops at any failure anyway. Not measured on a device; the emulator's
    `verify-network.sh` runs the clash both ways. If `establish()` fails, as when the user withdrew the VPN
    consent, the tunnel stops, as at any start.
- **Fragments are put together** (`core/net/src/fragments.rs`, pure): the apps' IPv4 fragments (the "more
  fragments" flag or an offset) and IPv6 ones (a fragment header with an offset or M), by source, destination and
  identification, and IPv4's protocol. An IPv6 atomic fragment is read whole (RFC 6946).
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
    whole, and a long one still arriving is not given up for the many that came after its first fragment. Each
    datagram keeps its place in the order of fragments
    taken, a count rather than a time, so that fragments of one instant still have an order; a marker's is its
    marking. A fragment no room could take, larger than the bound with its own datagram, is dropped with it, and
    nothing gives way for it. Expired datagrams go at the next fragment and in the engine's sweep.
  - **Shared by every app.** Every app sends from the tunnel's one address, so the bounds are not kept for each app:
    one app that keeps them full makes the others' datagrams give way, which costs them no more than dropping every
    fragment would. Accepted, since the bounds cap what fragments cost, for at most the wait.
- **Beyond the first hop.** `errors::told` passes on "fragmentation needed" (type 3 code 4) and "packet too big" (type
  2) with the MTU the kernel gives in `ee_info`, to the app at once, from the router that sent it (unit 11b, below),
  as an unreachable port is passed on; an MTU of 0, from a router older than RFC 1191, is left out. The engine keeps
  nothing of them: its own kernel keeps the path's MTU for its sockets. What a mapping read as the network beneath
  moved is not passed on after the move, nor counted, and the mapping ends (second review, minor 4b), whichever way
  its read ended, the mapping gone or its socket failing among them (re-review, minor 6).
- **What stays as it is.** A send the engine's kernel refuses as too long (`EMSGSIZE`) is dropped and counted, never
  answered "host unreachable". A datagram larger than the path leaves: the engine's kernel fragments it, or a router
  answers. The chain, lookups to the tunnel's DNS address and TCP are unchanged; writes to the tunnel larger than its
  MTU, the answers the engine's kernel put together, are taken by Linux in the network lab (phones in unit 11b).
- **Counters:** `fragments`, the 20th, counts the fragments dropped, those of a datagram given up included.
  Appended: `reassembled`, the 39th, datagrams put together; `too_big`, the 40th, datagrams the engine's kernel
  refused as too long, dropped; `path_mtu`, the 41st, routers' "fragmentation needed" and "packet too big" passed on.
  `COUNTERS` is 41.
- **The network lab.**
  - A narrow network (`scripts/netlab-enter.py`): a server at 198.51.100.20 and 2001:db8:1::20 on `far`, one end of a
    veth pair whose other end, `near`, is in the same namespace, its own MTU and its routes' 1,280. What the namespace
    itself sends there takes `near`, by a rule for packets made locally, while the apps' packets still go into the
    tunnel first. An app of the namespace's own addresses so meets the narrow network as an app meets its link without
    the VPN.
  - An app of every path MTU discovery mode (`scripts/netlab-app.py`): `dont`, `want`, `do`, `probe`, `interface` and
    `omit`, unconnected and connected, and IPv6's `IPV6_DONTFRAG`. nix sets none of them on Linux and the workspace
    forbids unsafe code; Python's socket module takes the option numbers.
- **Tests.**
  - In the engine: 14 of the reassembler (in and out of order, both versions, IPv4 options and IPv6 headers before the
    fragment header, overlap and its marker, exact duplicate, a first fragment without its header, what is malformed
    or too long, a datagram giving way at each bound with the costs counted, the one heard from longest ago giving way
    rather than the one that began first, and the re-review's race, a 10-fragment datagram whole among 32 new
    datagrams after each of its fragments, or 8 far ones of 64 KiB; the wait to the nanosecond, the rebuilt headers
    byte for byte); one of what routers say (`errors::told`); three of the mappings (an error read as the network
    moves is not passed on, and one read before passes on with its MTU; a move since a mapping opened, not one before,
    and the engine stopping, as its `watch` channel shows them; `EMSGSIZE` dropped and counted); one of `route_mtu`.
    The fuzz target feeds the reassembler a sequence of fragments and holds it to its bounds.
  - In the network lab, 5: across a swap, as `nativeStart` makes it, a chained app's first datagram and first TCP
    connection go through the tool and nothing of them reaches the server directly, a direct app's lookup reaches the
    resolver handed over and comes back uncached, a flow is named by a name learned before, and the counters go on;
    a 3,000-byte datagram both ways in IPv4 and IPv6; at the tunnel's 1,500 with the network
    at 1,280, as in the moment before the service sets the tunnel up again, every mode's datagram reaches the server
    whole, with no error on a connected default socket and nothing lost by `omit` (the second review's R1 and R3);
    with tun0 at 1,280, as the service sets it, each mode fragments or is refused with `EMSGSIZE` exactly as the
    same app does on the narrow network without the VPN, and the 24 datagrams fragmented are put together; a
    router's "fragmentation needed" and "packet too big" reach the app with their MTU, and a connected default
    socket then sees `EMSGSIZE` once, as without the VPN. In `chain.rs`, a stand-in given before a swap names its
    name after, and a chain set during the swap wins over the one handed over; in network-jni, a chain set while no
    engine runs, between
    the hand-over and the next start as `nativeStart` has them, is the next engine's, and a stop forgets it.
  - In Kotlin, JVM tests of `TunnelMtu`: the choice, the MTU's rise within a network only ten minutes after a setup,
    to the millisecond, how long a rise held back waits to be measured again, and the probe's addresses drawn from
    their ranges, never where checks send. `scripts/verify-network.sh` checks that the tunnel's interface carries the
    MTU the service chose (1,500 on the emulator), where the shell can read it, and pings with 2,000 bytes, which must
    be put together on an emulator, its reply reported, not required. On the Android 15 emulator both passed (the
    maintainer's session, before the tunnel was set up make-before-break).
  - Each was made to fail by a mutation of the code it guards: 71 mutations of the code as it stands, each caught.
    No test reaches the service's lifecycle, which is Android's: setting the tunnel up again, a start or a stop while
    a measure runs, and the measure posted for a rise; nor `nativeStart`'s own hand-over, two lines that call what the
    swap test calls; nor the order of the native side's two locks against a `nativeChain` that lands mid-swap, nor
    the logger's last batch after one it was handing over (fourth check, a nit, fixed), both races; nor an
    early end of a mapping's read after it built errors, which needs the mapping to end
    between two reads; nor the order in which echo counts a reply and writes it, which is a race with the reader
    (re-review, minor 7: it counts first).
- **Not done, stated:**
  - phones, what `IP_MTU` says on Wi-Fi and mobile networks and whether their kernels take writes to the tunnel
    larger than its MTU, are measured in unit 11b; the make-before-break setup ran on the emulator in unit 12b;
  - setting the tunnel up again with other addresses or on a new VPN network ends the engine's flows: connections
    through the tunnel start anew. Otherwise unit 12b keeps the flows;
  - a network whose IPv4 and IPv6 first hops differ gives the wider version the narrower MTU (above);
  - a router's "fragmentation needed" for an echo request, and a request whose send takes a pending error, are
    unit 11b's: it passes the first on and sends the second again;
  - the errors passed on are not rate-limited (RFC 4443 2.4 (f)): they reach only the phone's own apps, at most one
    for each datagram or request the app sent (unit 11b);

  - an app's TCP fragments are put together too and handled as any segment; Android's stack sizes its segments to
    the tunnel, so they are rare.

**Unit 12b, the engine keeps its flows when the tunnel is set up again (2026-11-16).**
- **A tunnel set up again with the same addresses, on the VPN network Android kept, goes to the running engine,** as
  for a new MTU. The engine goes on with the new tunnel, and no TCP connection or UDP mapping of any app ends with the
  setup: it keeps everything, its NAT, TCP connections and listeners, UDP mappings, ping sockets, the reassembler,
  chain, names, stand-ins, counters and log.
  - `Tun` holds its descriptor behind a lock, and each read and each write takes the one in place, so that a new one
    replaces the old for the event loop's reads and for every task that writes to the apps, the relays, mappings and
    ping sockets that began before among them (`Tun::replace`). A write waiting for the old one to take a packet
    when it is replaced is woken, goes to the new one and lets go of the old one: the old interface is down by then,
    and refuses writes.
  - **Writes in the gap** (third round). Android resets the old interface inside `establish()`, before the service
    can hand the engine the new tunnel, and a tun device whose interface is down refuses writes (`EIO`). A write the
    tunnel refuses waits up to `Limits::tunnel_wait`, 200 ms, for the new one, and goes there; with none by then it
    is dropped (`Tun::send`). A task's write waits where it is; the event loop's own writes, a reset or a
    rewritten segment, hand a refused packet to a task of their own (`Loop::send`), so that the loop reads on. Only
    the refusals a new tunnel cures wait (`tun::cured_by_another`): `EIO`, from a tun device whose interface is
    down, and `EBADFD`, from one whose file is no longer attached to a device. The others are dropped at once (the
    third round's check): on a Linux tun they are in practice `ENOMEM` or `ENOBUFS` under memory pressure, where
    each mapping's task would wait 200 ms an answer and the loop would start a task for each packet it read. The
    network part's Kotlin side hands the new tunnel over as soon as `establish()` returns, within milliseconds.
  - **The order across the swap.** `replace` wakes the writes refused in the gap, and the engine's thread runs them
    when its loop next yields, at the latest once the drain is done: they reach the new tunnel among or after what
    the drained packets' handling writes itself, and before what those packets' own tasks, started later, write. The
    third round's check found a reset refused in the gap still before the answer to a SYN queued on the old tunnel.
    It is tokio's order of running woken tasks that holds it, as the code says where the drain is; nothing orders
    them further.
  - `Engine::swap_tunnel` hands the new `OwnedFd` to the engine's thread through a channel into its event loop,
    beside the stop and the network's changes, and waits for its answer. The loop polls them in order, a stop, a new
    tunnel, then a read (a biased `select!`), registers the descriptor with tokio and puts it in place, then reads
    what is still queued on the old tunnel until "would block" and handles it, so that a packet the apps sent before
    their routes moved is not lost, and only then closes the old one, once, since it owns it. A descriptor tokio
    refuses is answered so, and the old tunnel stays.
  - The read buffer is the first tunnel's, `mtu.max(1500) + 64` bytes: the tunnel's MTU never goes above 1,500 (unit
    12), so it holds the new tunnel's packets too.
  - network-jni exports `Engine.nativeSwapTunnel(fd): Boolean`, which takes ownership of `fd` as
    `nativeStart` does, and returns false, with `fd` closed, when no engine runs or the engine could not take it. It
    holds the native side's engine lock while the engine's thread takes the tunnel, so that a chain set meanwhile
    reaches the engine after. The rule that makes this safe: that thread never takes the lock, and the Kotlin code it
    reaches, `ownerUid`, `protectSocket` and `logRecords`, from tokio's blocking threads or, for `logRecords`, from
    the engine's own thread as its loop ends, never calls a native method of `Engine` (second review, minor 4). No
    existing signature changed.
  - Kotlin's `setUpAgain` hands the engine a duplicate of the new tunnel's descriptor only when Android kept the VPN
    network and the addresses are the same (below), keeps its own for `nativeStart` should the swap fail, and closes
    its own once the engine took it.
- **Only on the VPN network Android kept** (second review, major 1, and the emulator's `verify-chain.sh`). When the
  apps left out change, Android brings up a new network, though the addresses stay: it keeps the network and
  updates it in place only when `allowBypass` and the allowed and disallowed apps
  are unchanged, the apps compared as ordered lists (AOSP's `updateLinkPropertiesInPlaceIfPossible`); otherwise a
  new network agent, with a new netId, connects before the old one goes. netd marks each packet that comes in on a
  VPN interface with its network's netId (`RouteController::modifyIncomingPacketMark`), and Android sets
  `tcp_fwmark_accept`, so the connections the engine's listener accepted carry the old netId, and once the old
  network goes their packets route nowhere: kept connections would hang for minutes, where with a new engine they
  reset at once and the apps open new ones. The review modelled it in the network lab with iptables marks,
  `tcp_fwmark_accept` and a rule for each netId: the same netId with a swap carried 3 of 3, a new netId with a swap
  gave no answer within 5 s in 3 of 3, and a new netId with a new engine was reset at once; on the emulator, after an
  app was left out and taken back, its new connection failed too. It also found that the list can differ when the
  apps have not: handed to the Builder in the order of `getStringSet`'s `HashSet`, a list in another order brings a
  new network even for a new MTU. AOSP's `Builder.verifyApp`, in `android10-release` and `main`, ignores a package
  that is not installed, so its name stays in Android's list; only a maker's `Builder` might refuse it, and
  `TunnelSetup` records what the `Builder` took either way (the narrow check of the second round). The narrow
  check also read `updateLinkPropertiesInPlaceIfPossible` in `android10-release`, `android11-release` and `main`:
  each compares only `allowBypass` and the two ordered lists, so the service's condition, which compares the
  addresses too, is the same or stricter.
  - The service hands the Builder its apps in sorted order and keeps the list it took, with the addresses, as the
    tunnel's setup (`TunnelSetup`); it never calls `allowBypass`. `TunnelSetup.canSwap` decides: a setup whose
    lists and addresses are the same as the last one's goes to the running engine; any other, and the first, starts
    a new engine, unit 12's path, with what the old one hands over: when the apps left out change, the apps'
    connections through the tunnel begin anew. The decision is a function of its own, tested on the JVM, since the
    third round's check found that narrowing it back to the addresses inside `setUpAgain` failed no test but the
    emulator's.
- **Other addresses still start a new engine.** For ADR 0041's clash and the debug `addresses-force`, the apps'
  connections are bound to the old addresses, as are the engine's listeners and its rewriting, and cannot go on:
  `nativeStart` stops the old engine, which hands the new one what unit 12 hands over, and the flows begin anew, as
  they do when a swap fails.
- **The first start sets the chain before the tunnel and the engine.** `start()` calls `applyChain()` before
  `establish()` and `startEngine()`. With no engine running, the native side keeps the chain (unit 12) and the
  first engine starts with it, so a chained app's first packet goes through the tool, where an engine that read the
  tunnel before its chain was set could let its first packets leave directly. Called between `establish()` and
  `startEngine()`, it would keep the apps' packets waiting in the tunnel, or dropped once it held 500, while the
  main thread read the tool table and perhaps the Keystore (second review, minor 3); it needs no tunnel.
  `nativeChain` says false while no engine runs, which `applyChain` does not read; the screen shows the chain's
  settings and whether the tunnel runs, neither of which this changes; and a start that fails, at `establish()` or
  after, stops, which forgets the chain.
- **A debug trigger.** The dump argument `setup-again` calls `setUpAgain()` with nothing changed, as `addresses-force`
  does for the clash, so that the emulator can show a setup that keeps the network and the addresses.
- **The network lab.** Rust makes a tun device only with unsafe ioctls, and a descriptor inherited by its number
  becomes an owned one only with unsafe code too, so the brief's inherited descriptor could not be used: the test
  opens `/dev/net/tun` itself and `scripts/netlab-enter.py --tunnel tun2`, run with that file as its standard input,
  names the device on it (TUNSETIFF acts on the open file, which both share) and brings it up as tun0.
  `netlab-enter.py --move tun0 tun2` then plays Android's in-place update: the tunnel's addresses, IPv4 and IPv6, and
  the routes into the tunnel go to tun2, and only then are tun0's addresses taken away and tun0 brought down, as
  Android resets the old interface. Linux refuses writes to a tun device that is down (`EIO`), as the lab showed,
  and goes on answering reads with "would block", so the engine runs on, on the old tunnel, until it is handed the
  new one; what it writes to the old one meanwhile waits for the new one (above).
  - **Android's marks** (third round, from the second review's model). `netlab-enter.py --marks 100 tun0` sets them
    as netd does, in IPv4: what comes in on tun0 is marked, in mangle `INPUT`, with netId 100, explicitlySelected and
    protectedFromVpn (`RouteController::modifyIncomingPacketMark`); `tcp_fwmark_accept` is 1; a rule sends what
    bears netId 100 and explicitlySelected to the network's own table, into its interface; the apps' rule into the
    tunnel takes only what is not protectedFromVpn, as the secure VPN's rule does; and the last rule is unreachable.
    `--marks-move` moves the network to tun2, as an in-place update does; `--marks-new-network` brings up netId 101
    on tun2 and then takes netId 100 away, its rule and its mark with it, as a new network agent does. It needs
    iptables in the namespace, and its kernel modules, which a namespace cannot load: nf_tables, and nft_compat and
    xt_mark where iptables-nft encodes `-j MARK` through the xtables compatibility layer. The iptables 1.8.13 here
    encodes it natively; Ubuntu 24.04's 1.8.10 may not, so CI loads all three and warns, loudly, of any it cannot
    load. Without iptables the mode says so and fails, and with it the test, which never passes without the marks.
- **Tests.**
  - In the engine, 6, with the engine's event loop on the test's own thread, so that what it finds at once can be
    made to be there at once: a datagram queued on the old tunnel when the new one comes is handled on the mapping it
    had, whose writer began before, and its answer comes through the new tunnel, the old one closed and a datagram on
    the new one carried; a mapping's write waiting for the old tunnel to take a packet, its small buffer full of
    answers the app did not read, goes to the new one when it comes, with every answer after it, in order, and the
    old one closes; a descriptor tokio refuses (`/dev/null`) is answered so, the old tunnel carrying on; with an old
    tunnel that refuses the engine's writes with `EIO`, as a tun device that is down does, the loop's reset to a SYN
    and a mapping's answer, refused there, reach the app through the new tunnel when it comes within the wait, while
    the loop reads on meanwhile, and both are dropped, as before, when none comes within it; and refused with another
    error (`EPIPE`, a socket pair's), both are dropped at once though a new tunnel comes within the wait. A unit test
    cannot make a tun device, so the old tunnel there is told to refuse with `EIO` (`Tun::refuse_writes`, built for
    tests only); the network lab's test below shows a real tun device's `EIO`.
  - In network-jni: `nativeSwapTunnel`'s function with no engine running returns false and closes the descriptor; with
    one running, one the engine cannot take returns false and the old tunnel stays, and one it can take is kept open
    and the old one closed. The test of unit 12's `SET` now also starts a first engine with a chain set before it, as
    `start()` does. The tests that use the process's engine and chain take a lock, so that they do not run at once.
  - In Kotlin, JVM tests of `TunnelSetup`: the same apps go to the Builder in the same order whatever order the set
    gives them in; the list kept is the one the Builder took, also from a maker's Builder that refuses an app no
    longer installed; and `canSwap` lets the running engine take the tunnel for the same setup only: not for other
    addresses, other allowed or disallowed apps, the same apps in another order, or with no setup before.
  - In the network lab, 7. With traffic flowing, Android's in-place update played, then the new tunnel handed over:
    the same TCP connection carries bytes both ways after, and the server accepted no other; the app socket's mapping
    leaves through the same port, and a peer it sent to before gets in unasked; the app's ping goes through the same
    ping socket of the engine's; the counters go on, with no TCP flow or mapping begun anew; and the engine's
    descriptor of tun0 is closed, counted from `/proc/self/fdinfo`, whose `iff` line names the device, while the
    test's own stays. With a chain on (a chain refuses every ping, so the ping is the first test's only): a chained
    app's connection and UDP association go on through the tool, its new connection and datagram after the swap go
    through it too, and the server accepted only the tool's connections (two `CONNECT`s, one `UDP ASSOCIATE`). Through
    IPv6, an app's TCP connection goes on across the swap, the server accepting no other. A datagram a peer sends the
    app's mapping once tun0 is down, before the swap, is refused with `EIO` and reaches the app through tun2 when it
    comes 200 ms later. And with Android's marks: on the same network, a kept connection goes on across the swap; on a
    new network, a swap leaves it hanging (no answer in 3 s) while a new connection passes, which is why the service
    starts a new engine there; and a new engine on the new network resets it at once, so that the app opens another.
  - The brief asked the lab to show a packet queued on the old tunnel at the swap handled too. On a real tun device the
    engine reads each packet as it comes, on a thread of its own, so a test cannot make one wait there at the swap
    but by a race; the engine's own test above makes it so on one thread, deterministically.
  - `scripts/verify-network.sh` keeps a connection to the test server open through the tunnel, one nc sending a request,
    then a second only once a marker file is there (Android 15's shell may not make a FIFO in `/data/local/tmp`),
    sets the tunnel up again with `setup-again`, waits until the old interface is gone, checks that the connection
    still has one answer, and requires the second request answered on the same connection and the MTU the service chose
    unchanged. `scripts/verify-chain.sh`'s step that leaves an app out and takes it back counts only flows new since
    before, by protocol, the app's end and the destination, whichever way the setup went. On a fresh Android 15
    emulator, in the maintainer's session, the whole network shard passed with the second round: the swap kept the
    connection, an app left out reached the server unseen, and taken back it passed through the tunnel again.
  - Each was made to fail by a mutation of the code it guards: the old tunnel's queue left unread, the old tunnel
    never closed, a refused descriptor answered as taken, `swap_tunnel` not waiting for the answer or taking
    nothing, a waiting write not woken by the replacement, writes kept on the first descriptor, a descriptor kept
    open with no engine running, the apps handed to the Builder unsorted; in the third round, a task's refused write
    not waiting, the loop's not handed to a task, the loop waiting itself, and the wait with no bound; and, in the
    lab, the in-place move leaving IPv6 behind, the marks left on the old interface by an in-place update, and a new
    network that keeps the old netId; in the fourth round, `canSwap` narrowed to the addresses, any refusal waiting,
    and `EIO` not waiting.
  - No test reaches: the `select!`'s order, without which a packet queued on the old tunnel is handled the same, by
    the read that comes first, and a stop waits at most one more batch; the order across the swap, which is tokio's;
    the few lines by which the service asks `canSwap`, its fallback, the duplicate it hands over, and `start()`'s
    order, which are the service's lifecycle, Android's; `EBADFD`, which a test would need a tun file detached from
    its device for;
    `nativeSwapTunnel`'s JNI shell, a few lines around the function tested; Android's own marks, which the lab
    models after netd's code and the emulator showed; and what Android does on a phone.
- **Not done, stated:**
  - the swap has not run on a phone: the Galaxy A40 run is the maintainer's, next; other phones in unit 11b;
  - a setup with other addresses, on a new VPN network, or a swap that fails, ends the engine's flows: for other
    addresses it must, and on a new network a new engine resets the connections at once, which
    the swap could not keep;
  - a setup with the same addresses on the same network can still lose the TCP connections, when Android's netd
    destroys the sockets on the tunnel's address; the engine's listener, which it destroys with them, recovers
    (the next note).

**Unit 12b, when netd destroys the sockets on the tunnel's address: the listener recovers (2026-11-16).**
- **What the emulator showed.** On a one-core Android 15 emulator, the tunnel set up again with the same addresses,
  over and over: after the 7th swap, the connection kept open got no answer, and every later TCP connection through
  the tunnel was refused. Android's log at that swap: `Netd: Destroyed 5 sockets on 10.1.10.1` right after
  `Vpn: Established ... on tun1`; `/proc/net/tcp` then held no listening socket of the engine's on 10.1.10.1. CI's run
  43876121769 failed the same way at the kept connection (`docs/ci-flakes.md`).
- **What netd does.** netd destroys every TCP socket on an address it believes was removed (`SOCK_DESTROY`),
  listening ones among them. Here it believed so although tun1 held the address: Android's in-place update gives the
  new interface the address before the old interface's reset takes it from the old one, and netd's bookkeeping of
  which interfaces hold the address raced that update, as far as the log shows.
- **What a setup with the same addresses can lose.** Then every TCP connection on the tunnel's address ends: the apps'
  own sockets, which netd destroys with the rest and which fail at once in the apps (`ECONNABORTED`), and the engine's
  ends of them. No VPN can keep those; the swap keeps what netd leaves, and UDP mappings and pings, whose sockets are
  not on the tunnel's address, are not touched.
- **The listener recovers.** An accept loop that ends at its first error (`while let Ok(..) =
  listener.accept().await`) drops the listener, and Android's stack then answers every SYN the engine rewrites to it
  with a reset, for the rest of the run, whatever the error, `EMFILE` among them. The loop never ends while the
  engine runs (`tcp::accept`):
  - a listener that no longer listens, as `accept`'s `EINVAL` or `SO_ACCEPTCONN` at 0 says after `SOCK_DESTROY`, is
    closed and another bound on the tunnel's address (`tcp::bind_anew`), on a port the kernel picks, never on its old
    one, which another app may hold by then (the second and third rounds, below).
    The listener the engine rewrites to is `Shared::listener4` and `listener6` (`tcp::Listening`), read where
    packets are rewritten: its port, 0 while none listens, and its
    generation, which grows each time a listener stops listening. The old listener is closed first. An attempt that fails, as without descriptors or with the address gone, is made again after a pause, from 10 ms
    doubling up to 64 s, or after 10 ms when an app's SYN finds no listener, and a listener bound anew that stops
    listening before it accepted anything is bound anew again only after a pause, so that nothing turns in a tight
    loop. A first bind that fails at the engine's start leaves the accept loop binding one the same way (the second
    round, nit 2);
  - a listener that still listens accepts again: at once after an error of one connection, which took that connection
    off its queue (`ECONNABORTED`, `EPROTO`, `ENETDOWN`, `EHOSTUNREACH` and the like), and after a pause after a lack
    of descriptors or memory (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`), the connections in its queue waiting there
    meanwhile. That pause is 10 ms, doubling up to a second, and 10 ms again once a connection is accepted (the
    second round's nit 1);
  - `listener_recoveries`, the 47th counter, counts each accept error recovered from, either way; `COUNTERS` is 47.
- **Only a relayed connection keeps a listener that stopped.** Each NAT entry keeps the listener its SYN was rewritten
  to, port and generation (`nat::Entry::listener`). A connection the relay holds goes on through its port, both ways,
  whatever listener the engine has now: the engine's own accepted socket holds its four ends there, so no other socket
  can. One not yet relayed is the engine's only while that listener is the one now, by generation, the port alone not
  telling a listener bound anew on the same port from the one before: once another app may hold the port, a segment
  from it is that app's as likely as Android's (the second round, below). A segment from the tunnel's address to a
  fake port is taken for Android's answer only from the entry's port (`Nat::answered`); one from the listener now to
  a connection the engine forgot is dropped.
- **Nothing is left holding a connection that ended.** A relayed connection whose engine end netd destroyed ends as any
  connection that fails: Android's stack resets it as it destroys it, the reset reaches the app through the rewriting,
  the relay reads the error and resets the server's end, and the rewriting goes after `close_linger`. A connection the
  listener never handed over, in its queue when it was destroyed or whose SYN came while no listener was there, is
  reset by Android's stack too, and its upstream connection would wait for the handover until the sweep, ten minutes
  on; so Android's reset of a connection not yet relayed resets the upstream connection, forgets the rewriting and ends
  the flow in the log (`Loop::reset_before_the_relay`); one the accept loop has taken already is the relay's to end.
- **`verify-network.sh`.** When the kept connection carries no second answer, a new connection through the tunnel must
  pass right after, and Android's log since the setup (`adb logcat -d -T`) tells a destroy by netd on the tunnel's
  address, which is reported, as a warning on a CI run, and passes, from a stall, which fails. A destroy passes only
  if the running engine took the tunnel at that setup, the service's dump's `setups kept N` one more and `anew M` the
  same, so that the fallback to a new engine, which ends the connections itself, cannot hide behind a destroy (the
  second round).
- **Tests.**
  - In the network lab, 6, with iproute2's `ss -K` run in the namespace, where `SOCK_DESTROY` works for an unprivileged
    user: the listener destroyed alone (`state listening src` the tunnel's address), IPv4 and IPv6: it is bound anew
    (on another port), a new connection passes, and one kept open goes on; every TCP socket on the tunnel's address destroyed, as
    netd does (`state all src` the address), IPv4 and IPv6: the app's connection ends at once with an error, the
    server's end with a reset, no connection to the server is left open, the listener is bound anew, and a new
    connection passes; only the engine's end destroyed (`src` the address `dst` the fake peer): the app reads a
    reset through the engine, the server's end a reset; and the process out of descriptors as a connection reaches the
    listener: the lab sets the test's soft limit on open files to 256 (`NETLAB_NOFILE`) and the test takes the rest
    with `/dev/null` while the lab's Android takes 300 ms to name the app, so that `accept` fails with `EMFILE`; the
    connection waits in the queue and is accepted and relayed, by the same listener, once the descriptors are given
    back. `ss -K` passes over a socket the kernel will not destroy without a word (a kernel without
    `CONFIG_INET_DIAG_DESTROY` answers `EOPNOTSUPP`), so each of these tests first destroys a listener of its own, and
    fails, saying that it did not run, where that listener still listens or `ss` is missing. CI's ubuntu-24.04 image
    has iproute2, and CI now loads `inet_diag` and `tcp_diag` with the lab's other modules; that Ubuntu's kernels set
    `CONFIG_INET_DIAG_DESTROY` is what a Red Hat bug report (2230213) says, not checked on the runner.
  - In the engine, 4: a listener made to stop listening with `shutdown(SHUT_RD)`, which stops a listening socket as
    `SOCK_DESTROY` does, without its privilege, is bound anew on a new port, its old port taken meanwhile, which
    `Shared` then holds, and the next rewritten connection gets its upstream connection there; after that, a connection the old listener took goes on through the old port both ways, and a segment
    from the new port to its fake port is dropped; and Android's reset of a connection not yet relayed reaches the app
    and resets the server's end, with nothing of it left in the pending connections, the NAT or the live flows, while a
    relayed connection's reset leaves its rewriting to the relay. `nat`'s test checks `answered` too.
  - Each failed once without its fix: the accept loop ending at its first error, with the count kept (the lab's new
    connections refused, `ECONNREFUSED`, as on the emulator; the connection queued under `EMFILE` reset; the engine's
    two listener tests); the listener bound anew on its own port only (the taken port's test); an error while still
    listening taken as no longer listening (the connection in the queue reset); the app's segments rewritten to the
    port now rather than the entry's, and Android's answers taken from any port; and no reset before the relay (the
    upstream connection held). The test of the engine's end alone guards the relay's reset of finding 21: an error read
    from the app's side taken as a clean end fails it, and the netd test too, the server's end closed rather than reset.
    With an `ss` that does nothing, the lab's tests fail and say that they did not run.
  - No test reaches: netd and its race, which the lab plays with `ss -K`; `ENFILE`, `ENOBUFS`, `ENOMEM` and
    `ECONNABORTED` from `accept`, which take the way `EMFILE` takes; the pause before a listener bound anew is bound
    again, and a bind that fails for a moment; a SYN that comes in the moment between the destroy and the new bind,
    whose reset by Android's stack the engine's reset test plays; and what netd does on a phone.
- **On the emulator (the maintainer's run, 2026-11-16).** On a one-core Android 15 emulator, 40 swaps with this
  unit's first round: netd destroyed the sockets on the tunnel's address in 11 of them, the kept connection lost each
  time, and in all 11 a new connection right after passed; `listener_recoveries` reached 32. Before the fix, the first
  destroy left every later TCP connection refused.
- **The second round (2026-11-16).** The independent review found no critical or major fault; its findings, and what
  was done for each:
  - **Another app could take the listener's port once it stopped listening (minor, a local hardening).** Once the
    engine's listener no longer listens, its port is free to any app that binds it with `SO_REUSEADDR`, which Linux
    allows whatever the app's UID, and listens there; the engine's bind on the old port then fails, and the first
    round bound another, taking that for harmless. It was not: a connection whose SYN the engine rewrote before it
    stored the new port, or that was rewritten to the old port and not yet relayed, its SYN sent again among it, went to
    that app's listener, and what that app sent back from the old port reached the app as if from the real server; and
    while no listener could be bound, every new connection was rewritten to the old port. Now:
    - each listener has a generation (`tcp::Listening`), and a connection not yet relayed is the engine's only while
      the listener it was rewritten to is the one now. For one rewritten to a listener that stopped, a segment from the
      old port is dropped, but a reset, which reaches the app, as Android's stack resets what the old listener held
      when it stops listening; and the app's segment, a SYN sent again among them, is never rewritten to the old port
      again: the engine resets the app, a SYN with a reset that refuses it, and the upstream connection with it
      (`Loop::reset_before_the_relay`). A relayed connection keeps its port, above;
    - while no listener is bound, the port the engine rewrites to is 0: an app's SYN is refused at once, its fake port
      freed and a listener wanted, and a held SYN whose server accepted meanwhile is refused, its upstream connection
      reset, rather than rewritten to a port another app may hold.
  - **`verify-network.sh` could hide a fallback behind a destroy (minor).** It now requires the swap, above.
  - **Nits.** Only a lack of descriptors or memory pauses the accept loop, above; and a first bind that fails at the
    engine's start no longer leaves the version without a listener for the whole run, above.
  - **Tests, and their mutations.** In the network lab, 1 more: an app's connection is rewritten to the listener and
    held there by a policy rule that drops what the tunnel carries to the listener's port (`ip rule ... dport P
    blackhole`), so that it is not yet relayed; then `netlab-enter.py --interloper` stops the test's process, so that
    the engine cannot bind the port again first, destroys the engine's listener with `ss -K`, binds the port with
    `SO_REUSEADDR` and listens, takes the rule away and lets the process go on. The engine binds another port; the
    waiting connection's SYN, sent again a second after the first, is refused; a new connection goes to the engine's
    new listener; a relayed connection goes on through the old port; and the interloper accepted nothing. If the
    interloper takes longer than the app's stack waits before it sends its SYN again, the test fails and says it did
    not run. In the engine, 5 more, and the first round's test of a connection the old listener took replaced: only a
    relayed connection keeps a listener that stopped, both ways, a connection not yet relayed rewritten to it getting
    only a reset from its port and a reset for its SYN sent again, also when the listener was bound anew on the same
    port; a SYN with no listener refused at once and a listener
    wanted; a held SYN that meets no listener refused and its server's connection given up; an accept loop with no
    listener binding one; the pause only for a lack; and the listener's port and generation read together. They
    failed: with connections rewritten to a listener that stopped trusted (the lab's waiting connection connected, to
    the interloper; the engine's test, a SYN-ACK from the old port passed); with no other port bound when the old one
    is taken (the lab's listener never recovered); with no new generation when a listener
    stops (a connection rewritten to the listener before, on the same port, got its answer); and with a SYN rewritten
    while no listener is bound, from the loop and from the held SYN's task (both rewritten to port 0).
  - **What no test reaches, beside the above:** the moment between the listener's destroy and the engine's accept loop
    seeing it, at most a turn of the engine's loop, in which a connection rewritten and answered from the old port
    still passes until the new generation; the pause up to 64 s and its cut by an app's SYN, which the engine's test of
    a SYN with no listener shows only as the want; an interloper on the IPv6 listener's port, which takes the same
    code; and Android's own apps, which the lab plays with one socket.
- **On the emulator, with the second round (2026-11-16).** The review showed its interloper test failing on the first
  round's engine and passing on the second's, 12 of 12, and the Android 15 emulator's whole network shard passed.
- **The third round (2026-11-16).** A narrow check found no critical, major or minor fault; its three nits, and what
  was done for each:
  - **A listener bound anew on its old port, and SYNs to the fake peer (nit 1).** With generations, a listener bound
    anew on its old port number kept nothing valid, and left one opening: another app may bind the old port with
    `SO_REUSEADDR`, without listening, in the moment no listener holds it; the engine's bind on that port then
    succeeds beside it, and that app's socket can connect from the listener's port, its SYN to the fake peer passing
    for Android's answer to a connection not yet relayed in the moment before the kernel makes the listener's own
    request socket for it. A listener is now always bound anew on a port the kernel picks, which is never one another
    socket holds; and a SYN without ACK from the tunnel's address to the fake peer, which no listener sends, is
    dropped and counted as skipped, before anything else is read of it.
  - **The log's outcome (nit 2).** A held SYN refused because no listener was bound, and a connection rewritten to a
    listener that stopped, which the engine resets itself, were recorded as opened, when the server accepted, and
    ended in the log as opened with no bytes, though the app saw "refused" or a reset. The held SYN is now recorded
    as refused, the outcome the app saw; the other ends, in its last segment, the counters and the flows kept,
    refused when the engine refused its SYN sent again, else failed, the log's outcome for a connection that ended in
    an error (`Shared::finish_as`). The record format needed no change: these outcomes are in it since version 1.
 A connection
    not yet relayed that Android's stack resets still ends as opened, as a relayed connection a peer resets does.
  - **What a dropped segment marked (nit 3).** `Nat::answered` marked a connection as just seen for every segment from
    its listener's port, also for those the caller then dropped, so that segments from an old listener's port kept a
    connection not yet relayed, and its waiting upstream connection, from the sweep. It no longer marks; a segment
    that passes does (`Nat::seen`).
  - **Tests, and their mutations.** In the engine, 3 more, and the two first-round tests of a listener bound anew
    merged into one: a listener that stops listening is bound anew on a new port, its old port held meanwhile by a
    socket with `SO_REUSEADDR` that does not listen; a SYN from the listener's port to a connection not yet relayed is
    dropped and counted, Android's SYN-ACK from there passing; the log, the counters and the flows kept have the
    engine's resets as refused and failed, and Android's as opened; the held SYN that met no listener is refused in the
    log too; and a segment dropped from an old listener's port leaves the connection to the sweep, while one that
    passes marks it. In the lab, the tests of a listener destroyed now check that it is bound anew, on a new port where
    a kept connection holds the old one. They failed: with the old port bound first (the new port's test, the old port
    again), with the SYN let through (it reached the app), with the held SYN recorded as opened, with the engine's
    resets ended as opened, and with every segment from a listener's port marking the connection. The mutations ran in
    a target directory of their own.
- **Not done, stated:** the second round had not run on a phone, and the third has run neither on the emulator nor on
  a phone; the Galaxy A40 run is the maintainer's, as above.

**Unit 11b, traceroute through the tunnel: hop limits, errors from the path, echo's bytes (2026-11-16, decision 5).**
- **The tunnel is not a hop.** An app's echo request, and its UDP datagram on the direct path, leave with the time to
  live (IPv4) or hop limit (IPv6) the app sent them with, copied, not lowered: with the engine's own 64, a
  traceroute through the tunnel would show the destination at every hop.
  - The parser reads the value into `Packet::hops` and `Echo::hops`.
  - A mapping's datagram carries it in its `sendmsg`'s ancillary data, `IP_TTL` or `IPV6_HOPLIMIT`
    (`engine/hops.rs`, through nix's safe `ControlMessage::Ipv4Ttl` and `Ipv6HopLimit`), so that one socket's
    datagrams of different hop limits, as a traceroute's probes are, need no socket option between them. An IPv4
    echo request carries it the same way.
  - An IPv6 echo request takes it as its ping socket's option, `IPV6_UNICAST_HOPS`, set only when it differs from
    the one last set on that socket. Linux's IPv6 ping sockets read no ancillary data before 5.18
    (`ping_v6_sendmsg`), and most phones run older kernels, where the request would leave with the default without
    a word. A ping socket serves one app socket and address pinged, whose hop limit changes only when the app
    changes it; the engine's tasks share one thread, so no other request comes between the option and its send.
  - IPv4 takes a time to live of 1 to 255 in ancillary data: a packet that came with 0, which no socket could have
    sent, leaves with the socket's own.
  - Never through the chain, whose relay carries the datagram with its own, and never for lookups to the tunnel's
    DNS address, which Android's resolver sends whatever the app's socket says.
- **What comes back keeps the hop limit it arrived with.** Mapping and ping sockets ask for it (`IP_RECVTTL`,
  `IPV6_RECVHOPLIMIT`) and read with `recvmsg`, and `packet::set_hops` gives the rebuilt answer, echo reply or error
  that value, IPv4's header checksum made anew; 64 stays where the kernel gives none, and for what the tool's relay
  hands back, which crossed only the phone. Once a socket asks for hop limits, an error read off its queue carries
  one too, before the error itself: the room for the error's ancillary data grows by it, or IPv6's error would be
  cut off (the router's "too big" test failed so).
- **Errors from the path.** The ping sockets now queue theirs (`IP_RECVERR`, `IPV6_RECVERR`) and read them off their
  queue on `Interest::ERROR`, before the replies, as the mappings do; a read or a send that takes a pending error
  goes on (`errors::from_icmp`, which now takes `EREMOTEIO` too, a ping socket's own for a source quench or a
  redirect), and a send is made again. For both, the app is told:
  - "time exceeded in transit" (ICMP 11/0, ICMPv6 3/0), what a traceroute asks each hop for;
  - "destination unreachable" with the code it came with, where before every one but the port's was "host
    unreachable";
  - "fragmentation needed" and "packet too big" with their MTU, as unit 12 does for mappings, now for echo too.
  "Parameter problem", a fragment's reassembly that timed out (11/1, 3/1), and errors of local origin, as the
  engine's kernel's own "message too long", are left out.
  - **From whom.** Each comes from the router or host the kernel names as its sender (`SO_EE_OFFENDER`), as it would
    without the VPN; from the destination where the kernel names none, where the sender is the very address
    the engine sent to, which the app may know by another (a ping to the tunnel's DNS address reaches the network's
    resolver), where it is no address an error may come from, or where it is one of the phone's own (`errors::sender`).
    The engine's own kernel sends an error from the phone's address on the network beneath when it answers itself, as
    "host unreachable" when a neighbour does not answer. In IPv4, from that address, the app's kernel would drop it on
    the tunnel as a martian source (Linux's `fib_validate_source`, under Android's rules), and the app wait for its
    timeout. Linux's IPv6 input drops only loopback, multicast and
    IPv4-mapped sources (`ip6_rcv_core`), so there the substitution is a harmless choice, kept for one rule in both
    versions (second review, minor 2). Whether an address is the phone's is asked as for the tool's relay
    (`on_the_phone`): a UDP socket connected to it, which sends nothing, sends from it only if the phone holds it.
  - **Quoting.** An echo error quotes the app's own request: an echo request from the app's address to the address
    it pinged, with the app's identifier, the sequence number read from the payload the error queue returns (the
    request's ICMP header as the router quoted it) and the data the router quoted. The app's kernel finds its ping
    socket by that identifier, and `ping` its request by the sequence number. A mapping's error quotes the datagram's
    header as before, which the app's kernel matches by the ports.
  - **One at most for each request or datagram the app sent.** A ping socket keeps the sequence numbers of its last
    64 requests that no error answered yet (`echo::ASKED`), and each peer of a mapping one owed error for each
    datagram the app sent it, at most 64 (`udp::OWED_ERRORS`). An error for another destination than the socket's or
    a peer's, for a sequence number never sent, or a second for one request or datagram, is dropped and counted: the
    engine's kernel queues an error for an unconnected socket whatever destination it quotes, so a forged one would
    otherwise reach the app. A sender that forges errors for a peer the app sends to without pause passes on at most
    one for each of the app's last 64 datagrams there; the app's own kernel, without the VPN, takes as many.
  - **A network that moved.** What a ping socket read as the network beneath moved is not passed on, and the socket
    ends with the move, as unit 12 has it for mappings (`udp::network_moved`).
- **Echo's bytes are counted** in `bytes_up` and `bytes_down`: what the ping socket sends and reads, the ICMP message,
  header and data, as UDP's counters hold what its sockets carry, without IP headers. Android counts them to Advanced.
  Echo still writes no record to the connection log.
- **Counters, appended:** `time_exceeded`, the 42nd, and `path_unreachable`, the 43rd, passed on for datagrams and
  echo both, as `path_mtu`, the 41st, now counts echo's "too big" too; `echo_errors`, the 44th, how many of those three
  kinds answered echo requests, counted apart so that a phone's dump says how much of what the path answered was a
  ping's or a traceroute's; and `errors_dropped`, the 45th, the errors
  dropped as answering nothing the app sent that left, or once more, or as no error to the app could be built for
  them. `COUNTERS` is 45; the second round appends a 46th, below.
- **Not changed:** TCP, which the engine's kernel terminates: a traceroute over TCP sees its probes answered by the
  engine's listener, and is out of scope. The chain: echo is still refused while a chain is on, and chained UDP keeps
  the relay's hop limit. Lookups to the tunnel's DNS address. ADR 0044's other decisions.
- **Tests.**
  - In the network lab, 5, each in IPv4 and IPv6: an app sending with 3, by UDP and by ping, reaches the server's
    socket (`IP_RECVTTL`, `IPV6_RECVHOPLIMIT`) and a raw socket of the namespace with 3, while its lookup to the
    tunnel's DNS address leaves with 64; a server answering with 7, and the namespace's kernel echoing with 7, reach
    the app's sockets with 7; a router's "time exceeded" for a datagram and for an echo request, from 192.0.2.1 or
    2001:db8:2::1, addresses the namespace does not hold, as a router on a phone's path is none of the phone's, sent by
    a raw socket with its own IP header (`IP_HDRINCL`, `IPV6_HDRINCL`), reaches the app's UDP and ping sockets
    (`IP_RECVERR`) from that router, with its hop limit, about the destination they sent to, the ping's quoting its
    own identifier, sequence and data, then an unreachable with its code too, while errors forged for another
    destination, for a sequence never sent, and a second for one datagram or request are dropped and counted, and the
    ping socket goes on to the next reply through the same engine socket; and two pings of 20 bytes of data add 28
    bytes each way to the byte counters each. A sixth, IPv4 only, sends an error from the namespace's 198.51.100.10,
    standing for the phone's own address: the app hears it from the destination. The lab's IPv6 holds no address of
    its own beside the destination that its rules route as local.
  - In the engine, 6, 4 of them new: what a mapping reads off its error queue before and after a move, from whom,
    with what hop limit, and one for each datagram; echo's quoting and its rule of one for each request; whom an
    error comes from; the kinds the app is told of; and the packets built, a hop limit set, and path errors and the
    quoted request, checked against etherparse. The fuzz target builds the quoted request and errors from any input, quoting it or any bytes,
    and sets hop limits on any bytes (6.8 million runs, no fault).
  - Each was made to fail by a mutation of the code it guards: no ancillary data on a send (64 in IPv4, and alone in
    IPv6), the IPv4 ping without it, the IPv6 ping without its option, a lookup sent with the app's 3; the answer's
    hop limit not set, a mapping not asking for it, IPv6 not asking, the reply's not set, the error queue's old room;
    time exceeded left out, every error from the destination, the error's hop limit not set, unreachables as host
    unreachable, no rule of one for each datagram or for each request, an error for any destination of a mapping or
    of a ping socket, any sequence number, ping sockets keeping no errors, the request quoted with the engine's
    identifier, an error from the phone's own address passed on from it; and either byte count taken away.
  - `scripts/verify-network.sh`, after the ping checks, pings 1.1.1.1 from the shell with a time to live of 1: where
    the network beneath answers "time to live exceeded", the shell must see it from an address other than 1.1.1.1;
    where it answers none, as an emulator's NAT may not, it is reported, with the 42nd counter (made stricter in the
    second round, below).
- **What no test reaches:** a read or a send that takes a pending error, which needs an error to come between the
  error queue's read and a reply's read, or before a send: tokio does not try a read on a wake for an error alone,
  so the lab cannot make one wait there but by a race (the test shows the socket going on after errors); the check
  against a network that moved for a ping socket, which needs a move between its read and the check; the IPv6 ping
  socket's option on a kernel older than 5.18 (the lab's is newer, where ancillary data would have done too); the
  hop limit of the relay's leg through the chain; an error from one of the phone's own IPv6 addresses; and what
  phones' kernels do, among them whether Android drops an error from the phone's own address as this note says.
- **Not done, stated:**
  - phones: the time exceeded, the hop limits and echo's bytes on the emulator and the Galaxy A40 are the
    maintainer's run, as are unit 12's measures of `IP_MTU` and writes larger than the tunnel's MTU on phones;
  - "parameter problem" and a fragment's reassembly that timed out are not passed on;
  - an error passed on for a datagram quotes only its headers, not its payload: a tool that reads its own probe back
    from the error finds none of it there;
  - a traceroute over TCP sees the engine's listener at every hop.
- **On devices (the maintainer's run, 2026-11-16).** The Android 15 emulator's network shard passed; its NAT answers a
  ping with a time to live of 1 itself (ttl=255 from 1.1.1.1), so the check reported "not seen". The Galaxy A40
  (Android 11, home Wi-Fi) passed every check, the time-to-live one with "told its time ran out by the first router,
  192.168.1.1, as without Watch (counted: 0, then 1)". The independent review built a lab with a real forwarding
  router and a server behind it: `ping -t 1` and `-t 2`, and Linux traceroute in its UDP, `-U` and `-I` modes, IPv4
  and IPv6, matched what they show without the VPN.
- **The second round (2026-11-16).** The independent review found no critical or security fault; its findings, and
  what was done for each:
  - **One-shot pings used up the cap (major 1).** Android's traceroute apps run `/system/bin/ping -c 1 -t N` once for
    each probe, often several at once, since Java and Kotlin cannot read a ping socket's error queue: each is a socket
    and an identifier of its own that never pings again, so 40 such pings found the cap of 32 full for 10 s from the
    33rd on, and a traceroute lost its answers after about ten hops. At the cap, a new socket now makes room
    (`Table::make_room`) by ending another, in the order the third round set (below). A socket still being made is
    never ended. The ended socket's task is woken to close it, and its app's next request, if any, gets a socket anew.
    `echo_evicted`, the 46th counter, counts them; `COUNTERS` is 46. (This round's first order, an answered socket
    first however recent, then one through which nothing passed for `Limits::echo_quiet`, took a ping that runs between
    its requests: the third round's finding 1.)
  - **The check passed when the feature was broken (major 2).** A reply to the time-to-live-1 ping, what the engine
    before this unit gave, printed "not seen". On a phone, a reply now fails the check, since no path reaches 1.1.1.1
    in one hop, and a "time to live exceeded" must also have grown the 42nd counter; the emulator, whose NAT answers
    ICMP itself, still reports. No baseline with the VPN stopped: stopping the VPN in the middle of the check would mean
    setting its tunnel up again for the steps after.
  - **A full send buffer spun the event loop (outside the diff, on its send path).** A datagram to a known peer waited
    in the event loop for room in its mapping's socket, every app's packets behind it, and once an ICMP error had come
    for the socket the wait spun: epoll's `EPOLLERR` beside `EPOLLOUT` marks the socket closed for writing in mio, a
    state tokio keeps for good, so the wait never waited (the lab measured 2 s of CPU time in 2 s). Mappings have had
    `IP_RECVERR` since unit 8, and connected sockets take an error the same way. A UDP datagram now never waits: one that
    finds the buffer full is dropped and counted as skipped, as a full queue drops it. A bounded backoff would still
    hold the event loop, for every app, for its length; UDP is free to drop.
  - **Errors for a ping to the tunnel's DNS address, and the caps, untested (minor 1).** Now tested: in the lab, a
    router's error for a ping to the tunnel's DNS address, whose socket's target is the network's resolver, reaches the
    app from the router about the address it pinged, and the resolver's own error comes from that address; unit tests
    bound `echo::ASKED` and `udp::OWED_ERRORS` from both sides.
  - **The ADR's older notes (minor 2)** state what this unit changed, and the martian-source reason is said to hold
    for IPv4 only (above).
  - **The quote (minor 3).** An error passed on quoted the engine's own IPv4 header (identification 0, "do not
    fragment", time to live 64), where a router quotes the app's, which Paris traceroute and mtr read. `packet::Sent`
    keeps what a router would quote of an app's packet, the first eight bytes of its IP header, its hop limit and the
    first eight of its transport header, and `packet::quoted` builds the quote from it: the app's own fields, the hop
    limit the router found (1 for "time exceeded", else the one the app sent with, which a router further on finds
    lower, unknown to the engine), and the transport header as sent, an echo request's checksum among it, then what
    the router quoted after it. A ping socket keeps it with each request, a mapping's peer with the app's last
    datagram to it, which an error for an earlier datagram to that peer quotes too: Paris traceroute and mtr, which
    match an error to its probe by the IP identification or the checksum, may then miss it where they send several
    probes to one port, while Linux traceroute and tracepath use a socket or a port for each probe. IPv4 options and
    IPv6 extension headers are not quoted.
  - **Accounting (minor 4).** A request or datagram is noted as one an error may answer only once it left: a mapping's
    datagram to a known peer is sent under the table's lock, which the send that no longer waits allows. An error used
    up for which no error to the app can be built, as for a multicast destination that named no sender, is counted
    among the dropped, and the counter is renamed `errors_dropped`.
  - **Tests, and their mutations.** In the lab, 4 more: 40 one-shot pings each get their reply, 8 sockets ended and
    the engine holding 32; two sockets waiting on an address that never answers hold the cap until both are quiet for
    `echo_quiet`; a full send buffer, after an ICMP error, drops and holds no one up (tc's token bucket on the way to
    an address that never answers, `sch_tbf`, which CI now loads); and the errors for a ping to the tunnel's DNS
    address, IPv4 and IPv6. The cap's test of unit 11 now pings that silent address, whose sockets wait on their
    replies. In the engine, 3 more, and 3 changed: the order of what makes room, the two caps, and the quote's fields.
    They failed with no room made, without the answered rule or the quiet rule, the ended socket not woken (40 sockets
    held), replies not noted; the send that waits (no answer in 2 s, the thread spinning); the error's destination
    compared to the address pinged rather than the target, the resolver's error shown from the resolver; `ASKED` 1 or
    unbounded, `OWED_ERRORS` unbounded or 1; an unbuilt error not counted; the quote with the engine's own fields, and
    with an expiry quoted at the hop limit sent. `verify-network.sh` was checked against a stand-in for adb, seven
    outputs. The fuzz target builds quotes of what it reads.
  - **What no test reaches, beside the above:** a request or datagram whose send fails, which is not noted: the lab
    cannot make a ping socket's send fail at will, and a full mapping's peer owes at most 64 errors either way, so the
    table's own test shows it; a lookup to the tunnel's DNS address that finds its socket's buffer full, dropped as a
    mapping's datagram is.
- **On devices, with the second round (the maintainer's run, 2026-11-16).** The Android 15 emulator's network shard
  passed, the time-to-live check reporting the emulator's NAT, as designed. In the review's real-router lab, the 40
  one-shot pings that failed in the first round all got their "time exceeded".
- **The third round (2026-11-16).** A narrow check found no critical or major fault, and two minors:
  - **A ping that runs could be pushed out between its requests (finding 1).** The second round's order ended first
    any socket whose every request had had its answer, however recent: a ping that runs, answered between its
    requests, was the first taken, and beside another app's pings of an address that never answers, neither answered
    nor quiet, it was then refused for good. At the cap the order is now:
    1. a socket whose every request has had its reply or error, through which nothing passed for longer than a ping
       interval (`Limits::echo_interval`, 1.2 s): a ping that stopped, or a one-shot ping's;
    2. the socket that has waited longest, `Limits::echo_quiet` at least, for an answer that has not come: its target
       is silent, or its replies lost, even while its app sends on (`echo_quiet` now means that wait, from the first
       request no answer followed, where it meant no traffic either way);
    3. the least recently active socket whose one request has had its answer, as a burst of one-shot pings leaves
       within a ping interval.
    A ping that runs looks like a one-shot ping until its second request, and may be taken so once, in the third step;
    its socket then carries a second request, or its key, kept among the last 64 ended (`echo::ENDED`), comes back
    with its next request, and the third step never takes it again; the first step takes it only once it has stopped
    for a ping interval, the second only once it has waited two seconds for an answer. In the review's scenario, at a
    cap of two beside two pings of a silent address, the ping that runs is taken once, refused at its next two
    requests, back at the third, once one of the silent pings has waited two seconds, and answered every second after;
    before, it was refused for good. Keeping it from its first second on would mean refusing one-shot pings for a ping
    interval, which a burst of a traceroute app's would meet.
  - **A drop by the network's queue was told as "host unreachable" (finding 2).** A mapping's socket asks for its ICMP
    errors, so the kernel fails a send whose packet the network beneath's queue drops with `ENOBUFS`, which was told to
    the app as "host unreachable"; an app socket that asks for its errors too then failed its next send with
    `EHOSTUNREACH`. `ENOBUFS` is now what a full socket buffer is: the datagram is dropped and counted as skipped.
  - **Noted, unchanged:** a UDP error quotes the peer's last datagram (above); and the stricter time-to-live check of
    `verify-network.sh` fails on a phone whose network's gateway answers ICMP itself, as a captive portal may, which its
    message names.
  - **Tests.** In the engine, the review's scenario as above, and the order of what makes room; they failed with the
    second round's order, without the exemption of a key that came back or of a second request, and with the wait
    counted from the last request rather than from an answer. In the lab, a way to an address that never answers holding
    3,000 bytes: an app socket with `IP_RECVERR` sends forty datagrams of 1,400 bytes there, none of its sends fails, no
    error reaches it, and the drops are counted; before, its sends failed with `EHOSTUNREACH`. The lab's 40 one-shot
    pings, quiet socket and cap tests pass as before.

**Unit 9b, a stand-in's answers told apart by the protocol's own identifier (2026-11-17, decision 2).**
- **What it removes.** Unit 9 left three losses, which the maintainer's decision of 2026-11-13 (above) set for this
  unit, before Advanced's first release, "without guessing": on ports other than 53, whoever reached the tool's relay
  first from the port the app asked took a waiting stand-in; while several stand-ins waited on one port, every
  answer from an address the app never saw was dropped; and a bound stand-in's address was cut for `udp_contest` on
  a port where another name waited. Each is now settled by what the app's own datagram asked the answer to carry,
  where the protocol carries one, and by an association of its own where it carries none.
- **The identifiers** (`core/net/src/identifiers.rs`, with QUIC's in `core/net/src/quic.rs`). Each is read from the
  app's datagrams to a stand-in by a parse that a datagram of another protocol passes only by a vanishing chance,
  since a stand-in found to have one takes only an answer that carries it:
  - **STUN** (RFC 8489, RFC 5389): a request, its top two bits zero, the magic cookie, a length that is the
    message's own and a multiple of 4, and attributes that fit to its end (walked over its first
    1,500 bytes, those past taken to fit: see the accepted limits below): its method and 96-bit transaction ID. A
    success or error response with that method and ID carries it. An indication is read as STUN but gives none: no
    one answers it (RFC 8489 6.3), so a stand-in that waited for an answer carrying its ID would wait for ever.
    Classic STUN (RFC 3489), with a 128-bit ID and no cookie, is not read: the cookie is what RFC 5389 brought in to
    tell STUN from the protocols that share its ports (RFC 7983), and without it the parse would pass datagrams of
    other protocols far more often. Its clients still work, as stand-ins without identifiers.
  - **QUIC** (RFC 9000 17.2, RFC 9001 5, RFC 9369), versions 1 and 2: a datagram whose Initial packets each give,
    with the client's keys, a tag that checks and frames that parse to the end gives the destination and source
    connection IDs of each of its long-header packets. An answer carries them when it is a Version Negotiation
    packet whose source ID is the app's destination ID and whose destination ID is the app's source ID, the
    versions after them whole, the app's own not among them (RFC 9000 6.2); a Retry with a token
    whose integrity tag checks with the app's destination ID, the only trace of
    that ID a Retry holds (RFC 9001 5.8); an Initial to the app's source ID that the server's keys of the app's
    destination ID open, its tag checked and its frames parsed to the end; or any packet whose destination ID is
    the app's source ID, where that has 4 bytes or more. A shorter one would be matched by a stranger's packet by
    a chance up to one in 256, and is not used alone. A client that sends no source ID, as Chromium's, so Cronet's,
    does, is told only by its Initial keys: by the server's first answer. The Initial may be of either version,
    keyed by its own (RFC 9368's compatible negotiation, below); the Retry only of the app's (RFC 9369 4.1 has the
    client ignore one in another version).
  - **The AEAD tag is checked** for both, by RustCrypto's `aes-gcm` (its review is under "Consequences"): checked
    against GCM's test cases 1 to 4 and RFC 9001's and RFC 9369's sample packets A.2 to A.4, which the tests' sealer
    reproduces byte for byte (the Retry's four unused bits set as the samples set them). It protects
    nothing against a sender who saw the app's packet, who can compute the keys and the tag as well, as the tool and
    anyone on its path can. On that path, keys and tag, a chance match is 2^-128, where frames alone would be
    matched by random bytes at about 2^-24 (a CRYPTO frame whose length runs exactly to the end), by this unit's
    estimate; a packet matched by the app's source ID alone is matched at the chance that ID's length gives, 2^-32 for
    4 bytes; and a Version Negotiation packet, which has no tag, by the two IDs it echoes. The hello's reader checks
    the tag too.
  - **DNS:** port 53 as before, unit 9's queries by their ID and question, read as loosely as then. On another port,
    a datagram that reads strictly as one standard query, one question, no answer or authority records, and
    nothing after but one OPT record, gives its ID and question; a response with both carries them. Such answers
    teach the engine no names: only port 53's do. Only where the answer repeats the question: LLMNR on
    5355 does (RFC 4795 2.1.1), and a Multicast DNS responder to a query from another port than 5353 (RFC 6762
    6.7); the NetBIOS name service on 137 does not (RFC 1002 4.2.13), nor Multicast DNS between two queriers on
    5353 (RFC 6762 6, 18.1), and those ask nothing.
  - **NTP** (RFC 5905): to port 123 only, a client request (mode 3, versions 1 to 4, 48 bytes or more in whole
    words) with a transmit timestamp other than zero; a server reply (mode 4) whose origin timestamp is that value
    carries it. Elsewhere its parse would be weak, a sixteenth of any 48-byte datagram, and it costs nothing more
    than those few lines: kept.
- **What is kept.** Each stand-in keeps them as unit 9 keeps port 53's queries: the last 64 (`ASKED`), each once, as a
  STUN or QUIC client sends one again, only while it waits for its first answer or is bound beside another peer
  (below), and none once it is bound alone or answered by name. Each takes 64 bytes in place, a
  DNS question's name at most 253 more, and each of at most 8 QUIC ones (`QUIC_ASKED`) the server's keys in two
  versions once an answer needed them, 864 bytes each on x86-64: at most 64 x 64 + 56 x 253 + 8 x 2 x 864 =
  32,088 bytes, and the vector's 24. That is for each stand-in peer, an address and a port
  the app sent to: an app that asks one name on many ports makes one for each, and pays for its own; a stranger
  makes none.
- **A stand-in with identifiers is bound only by an answer that carries one of them,** also when it waits alone on
  its port: a sender that reaches the tool's relay first, from its port, takes it only with what the app sent it.
  Port 53 had this since unit 9. One without identifiers is bound by the first answer from its port when it alone
  waits there, as unit 9 has it (but not by one that names in the clear what the app sent another peer, which it
  cannot have asked).
  - **Which stand-ins have them.** One whose app's datagrams carried one. A stand-in that had one keeps that, also
    when a later datagram carries none: the answer to the one it sent carries it still, as clients send their
    request or Initial again until it is answered; an answer to the later one that comes first is dropped and
    counted. One that had none takes them on from its first datagram that carries one, and from then on is bound
    only by an answer that carries one: an answer to its first datagrams that comes after that is dropped and
    counted too. It stays on the association it was given, also once Android was asked again.
- **Several stand-ins on one port.** An answer from an address the app never saw goes to the one stand-in whose
  identifiers it carries; one that carries none of theirs is dropped and counted (`udp_unidentified`); one that
  carries several stand-ins' at once is dropped as unmatched. For STUN that needs two of the app's requests with one
  96-bit random ID (2^-96), for QUIC one random destination ID of 8 bytes or more sent to two names (2^-64, and an
  Initial that two IDs' keys open with their tags, 2^-128 more): negligible. For DNS it is not: a client that sends
  one query with one ID to several servers at once, as some stub resolvers do, makes every answer carry both; so
  does an NTP client that sends one timestamp to two servers, as a clock of a millisecond's resolution may. Such a
  stand-in gets an association of its own as it is placed, on port 53 too, so that the association tells their
  answers apart; only identifiers that come to be another's later, once both are placed, still make an answer
  several stand-ins', dropped and counted as unmatched, which a test holds. An identifier the app sent any peer of
  the association on the port counts, a server known by its address and a bound stand-in among them (below, fix
  round 2's "Identifiers the app sent two peers").
- **The contest.** An answer from a bound stand-in's address, or a destination's own, that carries the identifier
  of a stand-in waiting on that port goes to the waiting one, which is bound by it beside the peer that held the
  address first; one that carries none of the waiting ones' goes to that peer, with no cut. `udp_contest`'s cut
  stays only where the waiting stand-in has no identifiers (`an_unanswered_name_cuts_a_bound_one_only_for_a_while`
  still holds it). Another port of an address a stand-in was bound to, on a port where a stand-in whose name the
  tool resolved to that address waits, binds it by its identifier.
- **Once both are bound.** The tool resolved both names to one address and port: the address alone cannot tell them. A
  stand-in bound beside another peer keeps the identifiers of what the app sends it, as a waiting one does, and what
  comes from that address goes to the one bound beside whose identifiers it carries, and otherwise to the peer that
  held it first. So STUN is told apart by every response's ID, a QUIC client with a source ID of 4 bytes or more by
  it, DNS on another port by its ID and question, NTP by its timestamp, at a cost paid only in this case: up to 64
  identifiers for each stand-in bound beside, and a parse of each answer from such an address. **Known limit** (in the
  list below): what carries no identifier still goes to the first: after its first answer, a QUIC client that sends no
  source ID has its server's packets from that address reach the app under the first name, as unit 9 states for every
  protocol, and its own stack drops them. When the first peer ends, the one bound beside it holds the address alone
  and lets its identifiers go.
- **A stand-in that would share a waiting port where the address alone could not tell gets an association of its
  own** (the maintainer's decision). On one association, a port where a stand-in without identifiers waits has no
  other stand-in waiting: when the app's first datagram to a stand-in would break that, a stand-in without
  identifiers beside any other, or one with them beside one without, that stand-in's datagrams leave through a
  `UDP ASSOCIATE` of its own, opened as `associate()` opens a mapping's, with the same request: Xray drops
  everything on an association whose request names another port, and zeros make it use the client's address. Only
  that stand-in leaves by it, and only it and the flows that come in through it take what comes back on it: each
  association has its own record of where answers come from (`Scope`). A peer's association is the peer's, also
  after Android was asked again, and for the app's replies to a flow that came in through one (fix round 1). Port
  53 needs one only for identifiers another stand-in there has too (fix round 1).
  - **What it costs, and the caps.** Each holds a TCP connection to the tool and a socket, two descriptors, as a
    mapping through the tool does, and takes one place in its app's share of the budget (decision 3), made room for as
    a mapping is, never by ending its own mapping, not even as an answered lookup (review E). At most 32 for the
    engine (`Limits::udp_own_relays`), and each app, and the apps Android cannot name together, a quarter of that
    (`Limits::udp_own_share`, 8, more names than an app asks at once on one port without identifiers), as decision
    3 shares its caps: the pattern is rare, and a tool's connections are not to be spent on it without bound (fix
    rounds 5 and 6).
  - **Beyond the caps, or with no place in the budget,** the stand-in waits beside the other on the mapping's
    association, under unit 9's floor: an answer from an address the app never saw on that port that carries no
    waiting stand-in's identifier is dropped and counted as unmatched, for as long as more than one waits; one
    that carries one goes to its stand-in. Counted in `udp_own_refused`. Never a guess.
  - **What waits for it.** While it opens, the stand-in's datagrams wait as a new destination's wait for its
    mapping, at most `udp_waiting`; nothing else of the mapping waits. One that cannot open (the tool refuses it, does
    not answer within `connect_timeout`, or offers a relay elsewhere, refused and counted as for a mapping) fails
    that stand-in's datagrams as a mapping's failing association fails a destination's: its flow is recorded, the app
    told it cannot be reached, and nothing leaves directly. Its next datagram tries again.
  - **How it ends:** with the last flow that leaves by it, its stand-in's or one that came in through it, silent for
    `udp_idle` (fix round 2); with
    its mapping, whatever ends that: the chain set again another way, the network moving, an answer of
    Android's naming another app, the budget; and when the tool closes it, which ends its stand-in's flow, so that the
    app's next datagram to the stand-in is decided anew. Its place goes back with it.
  - **What unit 9 holds for a mapping's association holds for it:** it opens only for a chained mapping, and is
    checked against the chain when it is used and as it opens; a stopped tool closes it; a relay elsewhere is
    refused; its socket is connected to the relay, so nothing of the app leaves directly; and what comes in through it
    asks Android again as what comes in through the mapping's does.
  - **What it does not do.** Every relay read for this unit (Xray, sing-box, mihomo, shadowsocks-rust, Hysteria 2,
    in the coordinator's notes of 2026-11-17) keeps one upstream socket for each association and filters no answer by
    its source: whoever learns that socket's port can send into the association with its own address. An
    association of its own separates stand-ins from each other, not from strangers: for a protocol without
    identifiers, unit 9's residual stays as unit 9 states it, the first answer from its port taking the stand-in.
    Xray and sing-box give back the name only for answers from the address the association's first destination
    resolved to: a stand-in alone on its own association is that first destination, and its answers then come by
    name, which matches them as before.
- **Counters, appended:** `udp_identified`, the 48th: answers a stand-in took by its identifier where the address
  alone could not tell, several stand-ins waiting on the port, or the address being another peer's, and an answer
  under a relay's name that a peer other than the label's holder took by an identifier the app sent it, a settled peer
  among them; `udp_unidentified`, the 49th: answers that only stand-ins with identifiers could have taken, and that
  carried none of theirs, a stranger's on port 53 among them; `udp_own_relays`, the 50th: associations of a stand-in's
  own opened; `udp_own_refused`, the 51st: those refused at a cap or for want of a place. `COUNTERS` is 51.
  `udp_unmatched`, the 27th, counts what still could not be told: a header that is not well formed, a fragment, an
  answer that carries several stand-ins' identifiers, an answer on a port where a stand-in without identifiers waits
  beside another (beyond the caps only), the cut of `udp_contest` for a stand-in without identifiers, an answer under
  a name for a stand-in, or one of its ports, that leaves by another association, and an answer from another port of
  an address the app knows already by that very address and port; an answer under a name that names in the clear what
  several peers were sent, the label's holder not among them, and one under a label held by the stand-in bound beside
  it while a stand-in without identifiers contests the port; the same under a label the name's own stand-in holds, and
  an answer from an address the app never saw that names in the clear what a peer was sent, where a lone stand-in
  without identifiers waits on the port.
- **Not changed:** the direct path; a relay that gives back the name, matched by it (unless the answer carries
  another stand-in's identifier); chained TCP; lookups to the tunnel's DNS address; `whose.rs`, the
  one rule of whose a datagram is; the budget's other places.
- **Found on the way.** A socket of a stand-in's own association, like the mapping's, must first be known to tokio
  as writable before the datagrams that waited for it leave without waiting: sent at once, they are dropped by
  tokio as "would block". Which of two stand-ins asked at once on one port leaves by the mapping's
  association, and which by its own, is whichever's datagrams leave first once the mapping opens: both wait for
  it, so either may.
- **Tests.**
  - In `core/net/src/quic.rs`, 5 new: GCM's tag against its first two test cases; RFC 9369's server Initial sealed
    byte for byte and told by its destination ID only; both RFCs' Retry samples told by their tag; what an app's
    Initial asks, once however often it is sent, and nothing from a tag or frames that fail; a Version Negotiation
    with the IDs crossed, and a packet to a source ID of 4 bytes or more. In `core/net/src/identifiers.rs`, 5: STUN,
    DNS on another port, NTP and QUIC, each asked and answered, and what each refuses; and the 64 bytes an
    identifier takes. The fuzz target `identifiers` holds that nothing panics and that a request never
    carries what it asked itself (12.9 million runs in 60 s of `cargo fuzz run identifiers` with no seeds, no fault).
    Random bytes reach its QUIC answers only up to their tags: fix round 1 adds seeds that start past them, and a
    target, `quic_answers`, that builds the answers.
  - In `core/net/tests/chain.rs`, 11 new and 4 of unit 9's changed, most through the scripted relay so that each
    answer comes from the address and in the order the test chooses, in IPv4 and in IPv6 (the engine's stand-ins are
    IPv4; the address the tool reached is either): two STUN stand-ins on one port answered in crossed order, each its
    own; a STUN response with another ID before the real one, taking no stand-in waiting alone or beside another; two
    QUIC stand-ins whose clients send no source ID, told by their Initial keys alone, both of version 1, with a
    datagram of no QUIC dropped and counted; a Version Negotiation and a Retry, each to its own stand-in (the Retry
    told by its tag alone, neither client sending a source ID); DNS on port 5353 and NTP, crossed; the contest settled
    by an identifier, then each STUN transaction's response from the shared address reaching the stand-in that sent
    it; a stand-in without identifiers beside a waiting one: a second `UDP ASSOCIATE` at the test proxy, each stand-in
    answered, and the second association closed once its stand-in was silent for `udp_idle` while the first went on; a
    stand-in with identifiers beside one without gets its own, two with identifiers share; the app's share and the
    engine's cap (`udp_own_relays`), beyond which the floor drops and counts; no place in the budget, the same, the
    mapping never ended to make room though quiet for `udp_quiet`; an association of its own whose relay names the
    name; and its end with its mapping when the chain is set again. Unit 9's two tests that held the floor now hold
    the answers each stand-in gets (the first of them is the second association's test above), and its two tests of
    port 53 the new counter. In the engine, 1: what a stand-in keeps, at most 64, each once, only while it waits or is
    bound beside, none once bound alone or answered by name, and none once the peer it was bound beside ends.
  - Each failed once without what it guards, on a copy of the code restored after: stand-ins never strict; the contest
    without identifiers; a stand-in bound beside keeping none; a lone stand-in with identifiers bound by any answer; the
    counter not counted; no bound of 64, identifiers kept once bound or after the first peer ended, recorded while
    settled; the Initial's and the Retry's tags not checked, a Version Negotiation not crossed, any source ID taken as
    telling, an app's Initial read without its frames; STUN's method not compared, indications answered, its attributes
    not read to the end, DNS with records read, NTP on any port; no association of its own, one beside stand-ins with
    identifiers too, either cap taken away, no end with its stand-in or with its mapping, one record of answers for
    every association, the mapping's socket for every peer, an association never refused for want of a place, and the
    mapping's own end to make room for it.
  - `scripts/verify-chain.sh`, with the picked app's UDP allowed, has it send STUN Binding requests from one socket to
    two names on one port at once (`scripts/workload-app`, extra `stun`). The test tool resolves them to 127.0.0.1 and
    127.0.0.2 on the phone, where it runs, beside its proxy, a STUN server on that port at each (`scripts/test-tool`,
    extra `stun`), so that both stand-ins wait on one port when the answers come back through its relay; both answers
    must reach the app, each with its own transaction ID from its own stand-in, and the 48th counter is printed. Not
    run by this unit's builder: the emulator is the coordinator's. It passed on Android 15's emulator after fix
    rounds 2 to 5, the 48th counter rising from 0 to 1 at the first sending.
- **What no test reaches:** the tool closing a stand-in's own association while its mapping's stays open, which the
  test proxy, closing all its relays at once, cannot do alone, and an association of its own that fails to open,
  which the same code as a mapping's failure handles; NTP and DNS answers that carry several stand-ins' identifiers,
  which the identifiers' own tests and the STUN path's logic cover; a client Initial whose datagram also coalesces
  0-RTT or Handshake packets, whose IDs are read the same way; real tools' relays, which the coordinator's static
  reading covers and the lab's gate 4 (table B10) will measure.
- **Accepted limits, gathered** (fix round 6, review L). Each is a limit
  this unit and its fix rounds accept, with its reason and the round that set it; the notes below point here.
  - **Classic STUN** (RFC 3489), without the magic cookie, is not read (unit 9b): without the cookie its parse would
    pass datagrams of other protocols far more often. Its clients work as stand-ins without identifiers.
  - **A protocol without identifiers** keeps unit 9's residual risk (unit 9, unit 9b): a stranger who learns where
    the tool's relay sends from can answer such a stand-in first, as none of the relays read filters by sender; an
    association of its own separates stand-ins from each other, not from strangers.
  - **Past an app's share or the engine's cap** of associations of a stand-in's own, or with no place in the budget,
    a stand-in without identifiers waits beside the other on the mapping's association under unit 9's floor: an
    answer from an address the app never saw on that port that carries no waiting stand-in's identifier is dropped,
    as either's, while more than one waits (unit 9b; the share, fix round 5): a tool's connections are not to
    be spent without bound, and the alternative is a guess.
  - **Once two stand-ins are bound to one address,** what carries no identifier goes to the first (unit 9b): a QUIC
    client that sends no source ID has its server's packets from there reach the app under the first name, and its
    own stack drops them. Nothing in them tells otherwise.
  - **Under a relay's name** (fix rounds 1 and 4), the label read as the address it stands for: what carries no
    identifier goes to the label's holder; a QUIC answer goes by its keys among the stand-ins that wait or are bound
    beside on its port, else by the label; a stand-in without identifiers whose name the tool resolved to the first
    destination's address, on another port, has its answers come under the first's name, as a flow of its other
    port; a name no peer has binds no stand-in without identifiers, as a name nobody asked for is dropped (unit 9's
    M21) and one whose peers ended cannot be told from it; and a flow of the name that came in on a port before a
    stand-in was bound beside under it there holds the label, as a peer holds its own address. Each is the rule of an
    address, whose address here the engine does not know.
  - **The contest** (fix rounds 5 and 6): a QUIC answer to a holder whose client's source ID is shorter than 4
    bytes, empty in Chromium and Cronet, is cut for `udp_contest` while a stand-in without identifiers asked
    meanwhile waits on the port: once settled, the holder keeps no keys, and nothing else in the answer tells it is
    the holder's. The cut lasts 5 s from the other stand-in's first datagram, within which QUIC sends again.
  - **QUIC's sizes** (fix rounds 1 and 4): a server's Initial or Retry larger than 1,500 bytes binds nothing, and an
    app's datagram larger than that, which came in IP fragments from a stack that cannot set "don't fragment", asks
    nothing and names no flow: through the tunnel no QUIC path carries more. A stand-in with more distinct
    destination IDs than the 16 packets an answer may open has its oldest tried last: a client outside what the
    RFCs' connections do.
  - **A STUN message larger than 1,500 bytes** (fix rounds 5 and 6) is read with its attributes walked over its
    first 1,500 bytes, so that one whose attributes past there are malformed is read as well formed: what tells its
    answer is its method, class, cookie, exact length and 96-bit transaction ID, which anyone who knows the ID could
    put in a well-formed message as well; its client discards a malformed one and sends its request again; and a
    full walk would cost 36 us for 64 KB under the table's lock.
  - **What is remembered** (fix rounds 2 and 3): an identifier the app sent a peer more than 64 identifiers earlier
    is forgotten for it, so that sent again to a new name at that distance it is no retry of the same request; and
    peers are not capped, so that the engine's memory grows with the destinations an app reaches within `udp_idle`,
    at most by 83.4 bytes for each identifier it sends them (5,339 for one peer): a cap would
    refuse a peer-to-peer app's destinations, which no NAT's mapping refuses.
  - **Port 53** (fix round 3): a stand-in there is bound by a response's ID and question alone, so that one whose
    answer section is cut or malformed binds it; the app's own resolver reads and refuses that section, as it would
    without the VPN, and the engine learns names only from a response it reads whole.
- **Not done, stated:** what no test reaches (above). The emulator step is the coordinator's; it passed after fix
  rounds 2 to 5 (above).

**Unit 9b, fix round 1 (2026-11-17).** Two independent reviews and the emulator's first run of the new step, after
which the maintainer's rule, given on reading them: every finding gets the best-in-class fix, or an accepted
limit with its reason here.
- **A peer's association is the peer's** (review A, major 1). After Android was asked again, a stand-in's
  datagram waited, went through `open_peer`, and left by the mapping's association though the stand-in had one of
  its own; its answer then came back on the mapping's association, to another name, or bound a stand-in waiting
  there. So did the app's first reply to a flow that came in through an association of a stand-in's own; and a
  peer made by an answer while an association of its own opened stayed the mapping's while its datagrams left by
  the new one. `leave_by` now sends a destination that is already a peer by the association it has, and closes
  whatever was opened for it meanwhile; one whose association is gone is gone with it (`Mapping::end_own`) and
  is decided again as a new one.
- **Identifiers outrank a relay's name** (review A, major 2). The relays read for this unit (Xray's `freedom`, and an
  Xray server behind VLESS or VMess with XUDP; sing-box by default) give the asked name only to answers from the
  address the association's first destination resolved to, and to every answer from there, whatever port: on one
  association whose names the tool resolved to one address, as `stun.x` and `turn.x` on one coturn server, the
  second's answers come under the first's name. An answer under a name that carries the identifier of exactly one
  other stand-in on its port, waiting or bound beside another, now goes to that one, which a waiting one is bound
  beside the named one by, keeping its identifiers; one that carries several is unmatched; otherwise the name decides,
  as before. **Known limit** (in unit 9b's list of accepted limits, above): a stand-in without identifiers whose name
  the tool resolved to the first destination's address, on another port, has its answers come under the first's name,
  as another port of it, a flow that came in; nothing in them tells otherwise. mihomo, shadowsocks-rust and Hysteria 2
  always give the address, and so never meet this.
- **The fuzz target had no seeds** (review B), so `scripts/fuzz.sh`, which stops at its first failure, never
  fuzzed `identifiers` and the six targets after it. Seeds now: STUN, DNS on 5353 and NTP exchanges, and RFC 9001's
  and RFC 9369's own client Initial, server Initial, Retry, and a Version Negotiation, which start the fuzzer past
  the tags. `scripts/fuzz.sh 480`, as CI runs it on a push, then ran every target (40 s each, `identifiers` 4.5
  million runs), and found nothing; on the code of this round's end, all twelve targets, `quic_answers` among them
  (`identifiers` 3.9 million runs, `quic_answers` 0.62 million), found nothing either.
- **Cryptography of our own replaced** (the maintainer's rule: vetted libraries): RustCrypto's `aes-gcm` 0.11.1 in
  place of unit 9b's GHASH, its review under "Consequences". The hello's reader, which removed an Initial's
  protection without its tag, now checks it: with the library it costs one GHASH for each of a flow's first few
  datagrams, and a damaged packet names no flow.
- **What an answer costs under the table's lock** (reviews A and B), on the engine's one thread. An answer is read
  once, whatever the number of stand-ins it is checked for (`identifiers::Reading`), and opens at most 16 Initial or
  Retry packets in all (`quic::MOST_OPENED`), counted across every stand-in it is checked for, each one's latest
  identifiers first (fix round 2 found the stand-ins taken in the order they began waiting, so that one could be left
  none; they now take turns), none when it is larger than 1,500 bytes (`quic::LARGEST_ANSWER`: QUIC never lets IP
  fragment its datagrams, RFC 9000 14, and a sender makes an Initial's datagram larger than 1,200 bytes only where it
  believes the path and its peer carry it, 14.1; the path an answer takes to the app ends in the tunnel, whose MTU
  is 1,500 bytes at most, decision 5, and the app's own Initials fit it, so a larger answer is outside what
  that path carries; a Retry's token must fit the client's next Initial on the same path. Corrected in fix round 2,
  where this said the internet's paths carry no more than 1,500 bytes, which RFC 9000 does not). The server's keys of
  each destination ID are derived once and kept with the identifier, of which a stand-in keeps 8 at most. An app's
  datagram is read as RFC 9000 12.2 has a receiver read one, the packets after one to another destination ID ignored,
  no further than 16 packets, its client keys derived once, its frames checked without being kept. In a release build,
  before and after: a stranger's datagram shaped as an Initial against 64 identifiers, 65,000 bytes 31.9 ms to 0.28
  us, 1,400 bytes 839 us to 11.6 us, a Retry-shaped one of 1,400 bytes 701 us to 15 us; an app's datagram of 1,679
  tiny Initials 3.3 ms (one destination ID) and 5.6 ms (each its own) to 6.5 us and 2.0 us; of 1,523 with CRYPTO
  frames far out 3.2 ms to 6.5 us; review A's case, a 64,000-byte one while 8 QUIC stand-ins wait, 3.9 ms to 0.74 us.
  **Accepted limit** (in unit 9b's list, above): a server's Initial or Retry larger than 1,500 bytes binds nothing,
  and a stand-in that has more distinct destination IDs than the 16 opens reach, the answer to its oldest unopened;
  both need a server or a client outside what the RFCs' paths and connections allow above.
- **Compatible version negotiation** (reviews A and B, RFC 9368): a server that negotiates it answers a version 1
  Initial in version 2, with version 2's keys of the client's original destination ID. An answer's Initial in either
  version this engine reads, keyed by its own version, now carries what the app asked. (This round took the Retry in
  either version too, citing RFC 9368; RFC 9369 4.1 has the server send a Retry only in the original version and
  the client ignore one in another: fix round 2 holds the Retry to the app's version.)
- **Colliding identifiers** (review A): one DNS query, one ID and question, sent to two names, or one NTP timestamp
  to two servers, left both stand-ins on one association and every answer several's, dropped. A stand-in whose
  identifiers another on its port has too now gets an association of its own as it is placed, on port 53 too,
  where nothing else could tell them apart. Identifiers that come to be another's later still make an answer
  unmatched.
- **The tool closing the mapping's association** (review A): sing-box closes an association idle for `udp_timeout`
  (5 minutes), Xray for `connIdle` (300 s), and the engine then ended the whole mapping, and with it a flow live on a
  stand-in's own association, a TURN allocation say. Closing one association now ends only what leaves by it.
  When the tool closes the mapping's own association while one of a stand-in's own is open, the flows that left by
  the mapping's end and its record of where answers come from is forgotten; the mapping lives on, and ends once the
  last association of its stand-ins does. The next datagram that needs the mapping's association, a new destination
  or one of those whose flow ended, opens it anew through the same opening protocol, by the same mapping and its
  budget place. **What the app sees:** the destinations of the closed association are new to it again, so what they
  send before the app sends to them is filtered, as after a mapping that ended, while the stand-ins on their own
  associations see nothing.
- **Smaller points.** A stand-in bound beside another that its relay then answers by name leaves that address's
  record (review A); `udp_own_refused` counts only a stand-in whose datagrams then leave, not one whose datagrams
  waited on for another app's way (review A). DNS-shaped protocols on other ports are read as DNS only where their
  answer repeats the question (review B; under "DNS" above).
- **The emulator's step showed nothing** (the coordinator's run on Android 15): it passed with the 48th counter at
  0 before and after, since the workload app resolved the second name after its first send, so that the first answer
  came back before the second stand-in waited, which unit 9 also passed. It now resolves both names first, sends the
  two requests back to back, and the step requires the 48th counter to grow by one at least. Back to back was not
  enough: the engine makes a new mapping's stand-ins in whatever order its tasks run, and on CI on 2026-11-27 the
  first answer came back before the second request had left the engine. So the test tool's STUN server now holds its
  answers until both requests have come, at most 5 s, and the step fails, named, when its first hold had only one
  (commit `57050467`).
- **Tests, each shown to fail once without its fix.** In `quic.rs`: GCM's test cases 1 to 4 through the library (3
  and 4 from review B); RFC 9001 A.2 to A.4 and RFC 9369 A.2 to A.4 sealed byte for byte, read and told (RFC 9001
  A.3 from review B); a hello whose tag fails names no flow (it failed with the reader before this round); a
  compatible version's Initial and Retry; an app's datagram of a 0-RTT packet alone, with a second Initial whose tag
  fails, with a packet to another destination ID, and past 16 packets; at most 16 opens and none above 1,500 bytes,
  the keys kept; a server Initial of frames an Initial may not carry. In `identifiers.rs`: a STUN length field not
  the message's own, a DNS authority record, an OPT owner that is not the root, NTP packets of 44 bytes, and the
  DNS-shaped ports. In the engine: review A's probes 1 to 3, the bound-beside stand-in answered by name, and the
  refusal counted only for what leaves, with a peer kept on its association. In `chain.rs`: review A's probes 4 to 6;
  colliding DNS queries on 5353 and 53; an answer carrying two stand-ins' identifiers dropped; review B's patch 05,
  two stand-ins without identifiers asked at once, twenty times; the tool closing the mapping's association; and the
  two QUIC stand-ins both of version 1, and the Retry's client sending no source ID, so that the keys and the tag
  alone tell them (review B, patch 02). The fuzz target `quic_answers`, from review B's patch 04, builds the server's
  answers for the IDs it chooses, in either version, a byte changed or not, and requires one built whole to carry
  them (939,454 runs in 60 s, no fault).
- **Review B's mutation runner**, run over the code as it now stands: its twelve mutants that still apply, each
  at its place in the code now (its GHASH mutant went with the GHASH, and comparing the answer's version with the
  app's is now the mutant that keys a compatible version's answer with the app's version), and eight more, one for
  each of this round's fixes: all twenty killed, the eight that had survived every test of unit 9b among them.
- **Found on the way.** Changing `identifiers::of` to take the app's port left the `identifiers` fuzz target calling
  it with one: the fuzz crate builds only under `cargo fuzz`, which neither gate of `scripts/check.sh` runs, and
  `scripts/fuzz.sh 480` stopped there; fixed in its own commit, and all twelve targets built.

**Unit 9b, fix round 2 (2026-11-17).** Two fresh reviews of fix round 1, C of the engine and D of QUIC's reading,
the fuzzing, the tests and the emulator step, after the coordinator's own commit `d99da80`: `verify-network.sh` seals
its QUIC Initials with a real GCM tag now that the hello's reader checks it, and with it the emulator's network shard
passed on Android 15 and the STUN step's 48th counter rose from 0 to 1. The maintainer's rule again: every finding
gets the best-in-class fix, or an accepted limit with its reason here.
- **Identifiers the app sent two peers** (review C, major 1; a regression of unit 9b's, where unit 9 gave the answer
  to the address's peer). Fix round 1's check of colliding identifiers looked only at the other stand-ins waiting or
  bound beside one. A peer settled by then, a server the app knows by its address or a stand-in bound alone or
  answered by name, keeps none: one NTP request's timestamp sent to such a server and to a name, or a stub resolver's
  query sent again with its ID to its next server after the first, already bound, was slow (glibc's `res_send`), left
  the name on the mapping's association; the server's reply, from its own address, carried the name's identifier, went
  to the name and bound it beside the server, and the name's own server was filtered from then on (under a relay's
  name, one answer went to the wrong name). Now every peer through the tool, whatever it stands as, keeps the
  fingerprints of the last 64 identifiers the app sent it (`TOLD`: the hash of Rust's `RandomState`, keyed at random
  for each run, whose algorithm Rust leaves unspecified, SipHash-1-3 today, 8 bytes each, the port within; "the last"
  in the order each was last sent since fix round 3, where it was the order each was first sent), and its association
  counts them (`Fingerprints`). A new stand-in whose datagrams carry an identifier any peer of the mapping's
  association was sent gets an association of its own, as fix round 1's collisions do. Where the caps refuse it one,
  or where the other peer was sent the identifier only after the stand-in was placed, the identifier is no stand-in's
  to take an answer by from where that peer answers: from an address, the peer that holds it and those bound beside it
  there; under a relay's name, which may stand for any peer's address, every peer of the association. From an address
  no peer answers from, it binds as before: the other peer's answers come from its own. **What it costs:** every
  datagram through the tool is read for identifiers, as only a waiting stand-in's were, 9 to 12 ns for one that
  carries none (a release build: 1,200 bytes of noise, a QUIC short header, a game's datagram, a STUN request) and 5.2
  us for a client's QUIC Initial, whose keys and tag the hello's reader computes too in a flow's first datagrams (fix
  round 3 found the worst case, a datagram of 16 Initials of 4,000 bytes, at 200 us, and bounds it: below); and at
  most 64 fingerprints for each peer, 512 bytes, with one entry each in its association's count, 16 bytes and a
  control byte in a table whose buckets are at most 16/7 of its entries once it holds 8 or more: at most 3,008 bytes
  for a peer the app sent identifiers to (fix round 5: 32 bytes an entry, with the exclusive-or of its peers'
  addresses, so 5,339), nothing for one it sent none, nothing on the direct path, where no stand-in waits. The count's
  table keeps the size it grew to until its association ends, as Rust's tables do, so an association holds at most
  what its peers held at once. **Accepted limit** (in unit 9b's list, above): an identifier the app sent a peer more
  than 64 identifiers earlier is forgotten for it; sent again to a new name at that distance, it is no retry of the
  same request.
- **A stand-in bound beside a name outlives it** (review C, major 2). Under Xray's `freedom` or sing-box, a second
  name the tool resolved to the first's address is bound beside the first by its identifiers (fix round 1); once the
  first was silent for `udp_idle` and swept, the relay still gave its name, which no peer had any more, and the
  second's STUN keepalives and TURN refreshes were filtered. An address was handed over to the stand-in bound beside
  it (`Sources::remove`); a name was not. Now the first stand-in bound beside a name takes it when the last peer that
  had it ends (`Sources::leave_name`), lets go of its identifiers, and the relay's answers under that name, its
  identifiers' and others', a TURN server's data among them, are its own; the name goes when it ends. (Fix round 3
  replaced this: a name handed over never came back to its own peer. A name is now a hint resolved among the peers
  that live; see there.)
- **An association of a stand-in's own after the mapping's closed** (review C, minor 1). Once the tool closed the
  mapping's association, a pause long enough to ask Android again sent a stand-in's datagram through the opening of
  the mapping's association, which it does not use, and a tool that refuses a further association failed it with
  "unreachable" though its own was open. A destination that is a peer of an association of a stand-in's own now
  passes a closed mapping's association (`UdpTable::open_mapping`).
- **A flow that came in through an association of a stand-in's own** (review C, minor 2) ended with the stand-in's
  silence, where on the mapping's association it outlives it (a TFTP server goes on from a port of its own). The
  association now ends with the last flow that leaves by it (`Mapping::sweep`).
- **What waited, at the end of its wait** (review C, minors 3 and 4). A destination that became a peer while an
  association of its own failed to open was failed with it; it now leaves by the association it has. One that would
  leave by the mapping's association after the tool closed it, or opened it anew, while it waited for writability,
  was sent by the old socket; it now waits on and is routed again (`Made::Reroute`), before anything is taken from
  its queue. And the associations of a stand-in's own are counted by a place each holds while it opens and once it
  is open (`OwnPlace`), not summed over every mapping under the table's lock.
- **The opens shared among stand-ins** (review D, 1). `quic::MOST_OPENED` counts across every stand-in an answer is
  checked for, and they were taken oldest first, each with all its identifiers: two stand-ins whose clients send no
  source ID, with 8 destination IDs each, spent all 16 opens, and a newer one's genuine server Initial was dropped
  every time. What costs no packet opened is now told first for every stand-in; the opens go round by round, each
  stand-in's newest identifier first, then each one's next. Where one round has more stand-ins than opens left,
  each answer begins it where the last such answer stopped. **Remaining limit:** with more than 16 QUIC stand-ins
  whose clients send no source ID waiting at once on one port of one association, an answer opens for 16 of them:
  a server's Initial sent again, as on a loss (RFC 9002 6.2), reaches its stand-in within as many sendings as there
  are rounds of 16 (the test holds 17 stand-ins, the newest reached at the second sending); and an answer opens at
  most 16 identifiers of one stand-in, which keeps 8 at most.
- **A Retry only in the app's version** (review D, 2; RFC 9369 4.1, against fix round 1, which took one in either
  version citing RFC 9368). Only the Initial may come in a compatible version.
- **What a client discards binds nothing** (review D, 3; worded as the RFC has it in fix round 3: a packet whose
  reserved bits are set, or that holds no frame, is a connection error, not one to discard, and either way no answer):
  a packet whose reserved bits are set once its protection is removed (RFC 9000 17.2; read before the tag, since
  Initial keys are no secret, and RFC 9001 9.5's concern, timing that confirms a guess of a packet number, its length
  or the Key Phase, is an endpoint's, which the engine is not: so worded in fix round 4), one with no frame (12.4), a
  server's Initial with a token (17.2.2), a Retry without one (17.2.5.2), a Version Negotiation that lists the
  client's own version (6.2, RFC 9368 2.1). A packet matched by the app's source ID alone, of 4 bytes or more, is held
  to the token and version rules too, but not opened: its reserved bits and frames go unread, as before, and only a
  sender who saw the app's packet makes one. (Fix round 3 opens an Initial and a Retry whatever the source ID: review
  F found such a Retry or Initial bound with its tag broken.)
- **The hello's reader bounded** (review D, 4) as `asked` is: no packet after one to another destination ID (RFC
  9000 12.2), none after the first 16, its keys kept between packets without a copy. A release build, before and
  after: one datagram of 1,666 tiny Initials 508 us to 6.9 us; one Initial of 1,200 bytes 5.3 us and 5.6 us, the
  same within the measure's noise.
- **A lone QUIC stand-in whose client sends no source ID** (review D's note): a Handshake packet of the server's
  first flight that comes in a datagram of its own before the server's Initial tells nothing (its destination ID is
  the client's empty one, its keys the two ends' alone) and is dropped as unidentified; the server sends it again on
  its probe timeout (RFC 9002 6.2), after its Initial bound the stand-in, a round trip later. Coalesced with the
  Initial, as servers send their first flight, it goes with it.
- **HMAC and HKDF from RustCrypto** (review D, 7): `hkdf` 0.13.0 with `hmac` 0.13.0, reviewed under
  "Consequences".
- **The fuzzing** (review D, 6): `quic_answers` asserted only that an answer built whole carries the IDs, and only
  for four PINGs. It now builds an Initial of any frames an Initial may carry, and an Initial and a Retry for another
  destination ID; built whole, an answer must carry the IDs exactly as a client takes it, and where the app's source
  ID is too short to tell, one with any byte changed, or for another destination ID, must never carry them (but
  where the change makes it a Version Negotiation, which no tag covers). Review D's mutant Q14, opening a packet
  without its tag, fails it within seconds from the seeds, one for each kind of answer.
- **The network lab's flake** (review C): `docs/ci-flakes.md`, 2026-11-17. Linux lists an older ping socket of the
  other IP version in a table whose chain it shares (`ping_get_next`); two tests took the one unbound socket of the
  table for the engine's, and failed 4 times in 192 and 3 in 256 runs, 16 at once. They now take the one listed
  since the app's first ping: none in 256 of each.
- **The emulator step** (review D): the workload app sends each STUN request again, with its transaction ID, as RFC
  8489 6.2.1 has a client do over UDP (500 ms, doubled each time, 7 requests, 39.5 s in all); the test tool's lines
  that its STUN server listens are read as it starts, before logcat's ring can turn past them; and the 48th counter is
  read with when the engine's counters began (`counters-since` in the service's dump), so that an engine started
  afresh between the two reads runs the step once more, and fails the run as that the second time, never as a pass or
  as unit 9b's failure. Not run here.
- **Corrected above,** each where it stands: the opens counted across every stand-in, the Retry's version and the
  1,500-byte cap's wording (fix round 1); fix round 1's collision check, which missed settled peers; the Retry samples
  of A.4, which the sealer now reproduces byte for byte where before they were only read; the 48 bytes an identifier
  took at first (64 since fix round 1); NCC's summary, quoted, its remark on GCM's size limits, and "nearly seven
  years"; two advisories of crates `aes-gcm` brings, RUSTSEC-2026-0003 and RUSTSEC-2026-0385, which the locked
  versions are past; an association's end. And `docs/DESIGN.md` (port 137 and Multicast DNS between queriers ask
  nothing; the GHASH gave way), `core/net/Cargo.toml`'s comment, and a sentence of `identifiers.rs` that began in
  lower case.
- **Tests, each shown to fail once without its fix.** In `chain.rs`, on the code of `d99da80` before this round:
  review C's probe 1, one NTP timestamp to a server known by its address and to a name, both with an association of
  its own for the name and with the caps refusing one; the same with the name asked first; probe 2, a query sent again
  to the next server, both ways too; probe 3, a pause after the mapping's association closed, with a tool that
  refuses a third association; and review D's probe, a newer QUIC stand-in among two with 8 identifiers each, and
  among 16 with one each. In the engine: probe 4, a flow that came in outliving its stand-in's silence; probe 5, a
  name taken by the stand-in bound beside it, and gone with it; an identifier two names were sent under the first's
  label; what a peer is sent counted while it lives and no more than 64; the QUIC cap of 8 and the eviction of the
  oldest QUIC identifier (review D's mutants U1 and U2); what waited, leaving by a peer's association whatever failed,
  waiting on while the mapping's association is closed or opened anew; and the places of associations of a
  stand-in's own. In `quic.rs`: what a client discards; ACK with ECN counts and a reason past the end; the
  1,500/1,501 boundary; both versions in one datagram and in the hello's reader; the hello's reader bounded; the
  Version Negotiation's halves, whole words and own version; a Handshake packet opening nothing; the Retry only in
  the app's version; the RFC samples' Retries sealed. In `identifiers.rs`: STUN's high method bits, the latest QUIC
  identifier first, and the fingerprints. RFC 5869 A.1 (now all 42 bytes) and RFC 9001 A.1 hold `hkdf`.
- **The mutation runner** (review D's runner, a loop kept with the reviews outside the repository: each mutant a text
  replacement in the source, the engine's tests run, the file restored; pointed at a worktree of this round's last
  code commit): review D's 23 mutants, each at its place in the code now, and 20 more, one or two for each of this
  round's fixes: all 43 killed, review D's 13 survivors among them (in its log: the Version Negotiation's whole words
  and destination half, the 1,500-byte boundary, both versions' keys in `asked` and in the hello's reader, a Retry's
  token check, any long-header kind opened, a reason past the end, ACK's ECN counts, the oldest identifier first,
  STUN's high method bits, the QUIC cap of 8 and its eviction).
- **Fuzzing:** `scripts/fuzz.sh 480`, as CI runs it, on this round's code: all twelve targets, 40 s each, found
  nothing (`identifiers` 3,498,043 runs, `quic` 4,592,133, `quic_answers` 653,279); `quic_answers` alone, two
  minutes, 2,053,882 runs, nothing.
- **Found on the way.** The mutation runner's run beside the fuzzing failed the engine's
  `the_listener_takes_only_connections_from_the_fake_address` once with "address in use": it took the port the
  kernel picked at 127.0.0.2 as free at 127.0.0.1 too, which another socket may hold (8 runs of 256, 16 at once).
  It now takes a port free at both, and none of 256 fail; `docs/ci-flakes.md`, 2026-11-17. And the engine
  commit's message gave the fingerprints' cost as 2,560 bytes; a table's control bytes and its growth make it
  3,008, as above and in `TOLD`'s comment (5,339 since fix round 5).
- **Not done, stated:** the emulator step was not run by the builder, here as before (it passed after the round: unit
  9b's note); a peer's fingerprints cover the last 64 identifiers the app sent it (above); the `counters-since` line
  has no test of its own but the emulator step that reads it; the name's label taken over is tested in the engine, not
  through the scripted relay; and nothing here tells a stranger who learned the relay's port from a server, for a
  protocol without identifiers, as unit 9 states.

**Unit 9b, fix round 3 (2026-11-17).** Two fresh reviews of fix round 2, E of the engine and F of QUIC's reading,
the fuzzing and the tests, after the coordinator's commit `021a7b8`: fix round 2 had put the check that the test
tool's STUN server listens after the tool's first start, which does not run that server (of the script's two
starts, the round's builder placed it after the wrong one), so the emulator's chain check failed on every run; it
now follows the start that passes `--ei stun`, and counts the lines from before it. With it the network shard passed
on Android 15, the 48th counter rising from 0 to 1; review F found the same fault. The maintainer's rule again:
every finding gets the best-in-class fix, or an accepted limit with its reason here.
- **A relay's name is a hint, resolved among the peers that live** (review E, major 1, a regression of fix round 2;
  fix round 4 replaced the model below, which review G found wrong in two majors: see there). Fix round 2 handed a
  name to the stand-in bound beside it when its own peer ended, and moved the name's record to that stand-in's
  address: when the app sent to the name's stand-in again, every answer under the name went to the other name's
  stand-in, without a word, and once that one ended the record pointed at an address no peer had, so that the name's
  answers came in as a new flow from there. Review E asked whether a simpler model removes the class of fault rather
  than this one: it does, and is what this round builds. The record of a name is now only its own peers', made with
  the first and gone with the last, as before fix round 2; nothing is handed over. An answer under a name goes, in
  order, to the stand-in whose identifier it carries, waiting or bound beside on its port (as since fix round 1); else
  to the peer whose own name it is; else, while no peer has the name, to the one stand-in bound beside them under it
  on that port, which stays bound beside, keeping its identifiers (several: unmatched; none: filtered). So review C's
  major 2 stays fixed (the second name's keepalives and TURN data reach it once the first ends), the name is its own
  peer's again when the app asks it again, and no record can outlive the peers it stood for (fix round 4: it could,
  the name keeping its first stand-in address after that address's peer ended, and the rule was per name where a label
  is per name and port). **Known limit**, as unit 9b states it (in its list of accepted limits, above): while a peer
  of the name lives, what carries no identifier under its name is that peer's (fix round 4: where it lived on another
  port only, such an answer came in as a new flow of the name's stand-in on the answer's port, review G's G1; it is
  now the stand-in's bound beside under the name there, see there).
- **Under a name, another peer's identifier** (review E, minor 2). With `Others::All`, an answer under a name that
  carries an identifier the app sent a waiting stand-in and a server known by its address went to the named peer,
  which never asked it. Where an answer names what it answers in the clear (`Reading::answers`: a STUN response's
  method and transaction ID, a DNS response's ID and question, an NTP reply's origin), one that answers what the app
  sent another peer of the association, and not the peer the name would give it to, is that other peer's, which no
  name tells: dropped as unmatched; so is one that answers what one settled peer alone was sent (fix round 4: one
  that a single peer was sent is that peer's, review G's G4; see there). A QUIC answer names
  what it answers only under keys: it goes as before.
- **An identifier sent again is the latest sent** (review E, minor 3). `TOLD` kept the order in which each was first
  sent, so that one a client sent again, being answered still, was forgotten as if sent long ago, and review C's
  major 1 came back for a busy peer. A peer's fingerprints, a stand-in's identifiers (`ASKED`) and port 53's queries
  now keep the order each was last sent: one sent again moves to the latest place, a QUIC identifier with the keys it
  kept.
- **What reading every datagram costs** (review E, minor 4). A datagram larger than 1,500 bytes is read as QUIC by
  nothing now (`quic::LARGEST_DATAGRAM`, the bound fix round 1 set on answers, `LARGEST_ANSWER` until now): the
  tunnel's MTU is 1,500 at most, so a larger datagram of an app's came in IP fragments (RFC 9000 14; fix round 4
  states the limit this leaves, under "QUIC's size bound"). A settled peer's identifiers are read from the datagram's
  headers (`identifiers::named`), a QUIC Initial unopened: a datagram that only looks like one costs a false memory,
  which withholds an answer at a chance of 2^-64, never a false match. A release build on x86-64: 16 Initials of 4,000
  bytes in one datagram, 200 us to read before, now 8 ns (not read); the worst within 1,500 bytes, 16 Initials of 93
  bytes, 9.9 us for a stand-in (`of`, opened) and 0.45 us for a settled peer (`named`); one Initial of 1,500 bytes 8.5
  us and 0.05 us; the hello's reader, bound the same way, 10.4 us at most (fix round 4: 23.6 us for Initials
  alternating versions, now 7.4 us; and a STUN-shaped datagram's attributes, walked to its end, cost 36 us for 65,500
  bytes, now bounded at 1,500 bytes, 0.81 us). On a phone's cores several times more. **The peers' bound,** which
  "pays for its own" did not state: peers are not capped, as before this unit. Each destination the app sent to within
  `udp_idle` is one, 296 bytes in place on x86-64 with its flow's record in the log, and a QUIC hello's reader of 960
  bytes for its first datagrams (1,904 after fix round 4; since fix round 5, 80, and 896 more for each QUIC version a
  client's Initials use); the fingerprints add at most 47 bytes for each identifier the app sends, 3,008 for one peer
  (83.4 and 5,339 since fix round 5). A cap on peers would refuse a peer-to-peer app's destinations, a DHT node
  talking to thousands from one socket, which no NAT's mapping refuses; the budget caps sockets, and the cost of peers
  stays the app's own sending's within `udp_idle`. **Accepted limit** (in unit 9b's list, above): that the engine's
  memory grows with the destinations an app reaches, as it did before this unit, at most by these bytes for the
  identifiers it sends them.
- **Making room never ends the mapping it is made for** (review E, minor 5): `own_wanted`'s `room` could end the very
  mapping it was making room in, as an answered lookup (a resolver that answered, the app then asking the next name);
  it is no longer a candidate while its association of a stand-in's own is placed (fix round 4: nor is it one again
  while that association opens or is open, which an answer meanwhile made it). And one being opened counts as
  the mapping's: the tool closing the mapping's own association ended a mapping whose only other association was
  opening, and its task ended one such; and a mapping left with nothing open when that one fails now ends at once.
- **QUIC** (review F, minors 6 and 7). A Retry whose source connection ID is the app's destination ID binds nothing
  (RFC 9000 17.2.5.1). An Initial or a Retry is opened, its tag checked, whatever the app's source ID: with one of 4
  bytes or more, a Retry or an Initial whose tag failed still bound, matched by the ID alone; only a Handshake, 0-RTT
  or short-header packet, whose keys are the two ends' alone, is matched by it now. The cost is bounded as above,
  and the opens go round by round among the stand-ins (fix round 2). Worded as RFC 9000 has it: a packet whose
  reserved bits are set, or that holds no frame, is a connection error (17.2, 12.4), the rest the client discards;
  either way no answer. The reserved bits are read before the tag: RFC 9001 9.5, to which 17.2 points, asks an
  endpoint to remove header and packet protection together, so that their timing confirms no guess of a packet
  number, its length or the Key Phase (corrected in fix round 4, where this said its keys); the engine is no endpoint of
  these packets, sends nothing on what it reads, and Initial keys are anyone's.
- **The ping table** (review F, minor 8): fix round 2's rule still took the other version's older sockets that the
  new socket's chain lists after it; the network lab now leaves out every socket the other version's table lists
  (`docs/ci-flakes.md`'s row says so).
- **The fuzzing** (review F, minors 9 and 10). The seed meant for a changed Initial built a Version Negotiation (its
  byte 9 is kind 3 under `how % 6`), and none built a changed Initial or Retry: the kind is now `how`'s low three bits,
  8 marking a change, and the seeds build each kind, changed or not, to a source ID that tells or not (19 of them).
  Two properties are added: nothing carries the app's IDs that is not sent to them, and a changed Initial or Retry
  never does, whatever the source ID, unless the change made it a packet no tag covers. Review F's surviving
  mutants: F6's and F7's code is gone with the source-ID shortcut for Initials and Retries (their counterparts now
  are killed, F7's by a unit test); F22, a QUIC fingerprint without the source ID, would only make two connections of
  one destination ID collide, a negligible case, and is killed by a test all the same.
- **A query for the root name** (review F, minor 11): `identifiers` took it as asked off port 53, but `dns::response`,
  which reads names to learn, took no root question, so the stand-in, strict by the query, was answered by nothing;
  port 53 had the same. Answers are now read for what they answer by `dns::answered`, which takes the root as the
  query's reader does.
- **Corrected above:** the label handed over (fix round 2's note), "the last 64" (now in the order last sent), the
  per-datagram cost and the peers' bound, "never by ending its own mapping", the dates of `hmac` 0.13.0 (2026-03-29)
  and `hkdf` 0.13.0 (2026-03-30), "SipHash" where the code uses Rust's `RandomState` (its algorithm unspecified,
  SipHash-1-3 today), and "what a client discards" (connection errors, and source-ID matches, above). `engine.rs`'s
  test said one run in 256, which was 8. `docs/DESIGN.md`, `docs/VPN.md` and the CHANGELOG follow.
- **Round 2's gates, checked again.** For two of fix round 2's commits the builder had restored the files from an
  archive, which keeps their old times, and cargo, which judges by those times, may have run the gates on builds of
  the files before. Both, `547524c` and `262ca37`, now pass `scripts/check.sh rust` in worktrees of their own, built
  from nothing. This round touches every restored file before its gates.
- **Tests, each shown to fail once without its fix.** In the engine, on the engine of `021a7b8`: review E's probes 1
  (with the name given back while the other lives, and taken by the other again while it is gone), 2 (and an
  identifier one settled peer alone was sent) and 4 (with a stand-in's identifiers and port 53's queries); making
  room for an association of its own without ending the mapping; one being opened keeping its mapping. In `quic.rs`:
  an Initial and a Retry with their tags broken, in another version, without a token and from the app's own ID, with
  and without a source ID that tells; a datagram past 1,500 bytes, read by none of `asked`, `named` and the hello's
  reader; `named` without opening. In `identifiers.rs`: the root query; what an answer answers; QUIC fingerprints by
  their source ID.
- **The mutation runners** (review D's runner, as in fix round 2, pointed at a worktree of `9f521cb`): 84 mutants,
  review F's 26 (its F4 to F8, F17 and F27 moved to where the code now stands, F6's and F7's counterparts as above),
  review D's and fix round 2's 41 (at their places now, the two of fix round 2's name hand-over
  dropped with it), and 17 of this round, one or more for each fix. 82 were killed; the two left, F6 (an Initial cut
  short, matched by a source ID that tells) and S4 (a settled peer's identifiers read with `of`), are killed by two
  tests added after (`4a1a6c3`), rerun: all 84 killed.
- **Fuzzing:** `scripts/fuzz.sh 480`, as CI runs it, on `9f521cb`: all twelve targets, 40 s each, found
  nothing (`identifiers` 5,198,087 runs, `quic` 5,410,894, `quic_answers` 656,290); `quic_answers` alone, 150 s
  from its new seeds, 2,292,744 runs, nothing.
- **Not done, stated:** the emulator step was not run by the builder (it passed after the round: unit 9b's note); what
  carries no identifier under a name goes to that name's peer while it lives (above); a QUIC answer under a name is
  not told to be another peer's; peers are not capped (above).

**Unit 9b, fix round 4 (2026-11-17).** Two fresh reviews of fix round 3, G of the engine and H of the parsers, the
cryptography, the tests, the fuzzing and the docs. Since fix round 3 the network shard passed on Android 15, the STUN
step's 48th counter rising from 0 to 1 at its first sending. The maintainer's rule again: every finding gets the
best-in-class fix, or an accepted limit with its reason here.
- **A relay's name is read as a source** (review G, majors G1 and G5, and minors G2 and G4; the coordinator's
  question). The reading of a relay's name produced a major in each of fix rounds 1 to 3, each fixed where it was
  found. This round answers the class instead. The relays that give back a name (Xray and sing-box, as read for this
  unit: "What it does not do" above) put it on an answer to say that it came from the address the association's first
  destination, that name, resolved to, at the answer's own port: a label (name, port) is a source, as an address and
  port are, whose address the engine does not know. It is now read by the rules an answer from an address has been
  read by since unit 9, which every review since has gone through, with the label in place of the address
  (`Scope::by_name`):
  - its holder is the name's own peer on that port, as a destination holds its own address; with several stand-in
    addresses for the name (one from before it gave way in the stand-in map, one since), the newest's (G2: the name's
    record kept its first address after that address's peer ended);
  - while no peer of the name lives on that port, the stand-in first bound beside it under the name there holds it, as
    the first bound beside an address holds that address once its holder ends (G1: the one beside took what came under
    the name only while no peer had the name at all, so that while the name lived on another port, its data without
    identifiers came in as a new flow of the name's stand-in on that port, which the app never opened);
  - an answer carrying the identifier of a stand-in that waits on the port, or is bound beside on it (by an address
    or under any name, as the code has it and fix round 5 states: "under the label" said less), is that one's before
    the holder's, as beside an address, a waiting one being bound beside under the label by it; what carries none is
    the holder's, dropped for `udp_contest` where the holder is the one beside and a stand-in without identifiers waits
    on the port, as under an address a stand-in was bound to (fix round 5: also where the holder is the name's own
    peer, a stand-in too, review I's I2; and never what carries the holder's own identifier, I3);
  - with no holder, another port of a name the app sent to comes in as that name's stand-in's, as another port of a
    known address does; and a name no peer has is a source the app no longer sees, or never asked: a stand-in with
    identifiers is bound beside under it by an answer that carries one (G5: it was filtered before its identifier was
    read, so that `b.test` on a coturn host whose `a.test` had ended never bound).  The one difference, and why (fix
    round 5: not the only one; each is listed there): the address behind a label is unknown, so any peer of the
    association may be at it. An answer that names in the clear what the app sent (a STUN, DNS or NTP identifier,
    `Reading::answers`) is therefore the holder's if the holder was sent it, else the one peer's that was (G4: fix
    round 3 dropped it, though that peer alone asked it), and no one's where several were; and a stand-in bound beside
    under a label stays beside, keeping its identifiers, since the name's own peer may come back, as the app asks the
    first name again. **Accepted limits** (in unit 9b's list, above), each the address's own: what carries no
    identifier goes to the holder; a QUIC answer, which names what it answers only under keys, goes by its keys among
    the stand-ins that wait or are bound beside, else by the label; and a name no peer has binds no stand-in without
    identifiers, where an address the app never saw binds a lone one by its first answer: a name nobody asked for is
    dropped, as unit 9's second review decided (M21), and a name whose peers ended cannot be told from one, short of
    remembering ended names. And a flow of the name that came in on a port before a stand-in was bound beside under it
    there holds the label, as a peer holds its own address (review G's open point on its sketch): the app has that
    flow, and an answer without identifiers is its as much as the other's.
- **An answered lookup while its association of a stand-in's own opens** (review G, G3): fix round 3 took the mapping
  out of the ranks before making room, but an answer while the association opened put it back, and the next room ended
  it, with what was being opened. A mapping with an association of a stand-in's own, open or opening, is no answered
  lookup.
- **What a STUN message costs to read** (review G, G6): its attributes were walked to its end, up to 64 KB, on every
  datagram through the tool to a settled peer since fix round 3, 36 us for 65,500 bytes of empty attributes. STUN over
  UDP SHOULD keep within the path's MTU (RFC 8489 6.1, as fix round 5 corrects it, where this said 6.2.1 and "keeps"):
  a message larger than 1,500 bytes was read no further, 0.81 us at most (fix round 5: which refused a response padded
  to the server's MTU, RFC 5780's exception to the rule; its attributes are walked over 1,500 bytes now, see there).
  DNS's and NTP's reads are bounded already: a question's name and one OPT record, a response's question alone, fixed
  fields.
- **An own association with nothing to send** (review G, G7): one that opened when nothing was left to send by it was
  dropped, and a mapping whose own association had closed meanwhile lingered with nothing open, holding its budget
  place, until `udp_idle`. It ends at once now, as fix round 3 has it for one that fails to open.
- **The hello's reader, one key set for each version** (review H, minor 1): it kept one for both, so that 16 tiny
  Initials alternating versions to one destination ID derived keys for every packet, 23.6 us where fix round 3 gave
  10.4 us at most; now 7.4 us, as `asked` keeps them (`named` on the same, 0.41 us). (Fix round 5: kept in place,
  the two sets made every peer's reader 1,904 bytes, QUIC or not; see there.)
- **QUIC's size bound** (review H, doc point 13): `LARGEST_DATAGRAM` is the tunnel's largest MTU, Kotlin's
  `TunnelMtu.MOST`, which a test now holds it to. An app's larger datagram came in IP fragments, as a QUIC stack that
  cannot set "don't fragment", configured above the MTU, sends them and the engine puts together: **accepted limit**
  (in unit 9b's list, above), its Initial asks nothing, so its stand-in is bound as unit 9 binds one without
  identifiers, and its hello names no flow. A server's answer larger than that binds nothing either, also accepted:
  the engine writes it to the app as it writes any, and a relay that reframes UDP from a stream is bounded by no path.
- **Port 53 since fix round 3** (review H, doc point 16): a stand-in on port 53 is bound by a response's ID and
  question read alone (`dns::answered`), so a response whose answer section is cut or malformed binds it, where
  `dns::response` refused it before. That is right: the question is what the app asked, and the answer section is the
  app's own resolver's to read and refuse, as it would without the VPN; the engine learns names only from a response
  `dns::response` reads whole.
- **Tests that review H found missing** (minors 2 and 3): `dns::answered`'s checks, each (its mutants D2, D3, D4 and
  D6 survived); under a label held by the one beside, another peer's identifier (U2, at its place in the new rules); a
  stand-in on port 53 asked for the root name (U5); a stand-in's QUIC Initial whose tag fails never noted (U6). And
  the contest under a label held beside, which the new rules hold and nothing tested.
- **Fuzzing** (review H, minor 4 and doc point 19): `identifiers::named` and `Reading::answers` run in the
  `identifiers` target now, with review H's property that `named` reads whatever `of` reads, and of other protocols
  than QUIC the same (runs below); the `initial-changed` seed of `quic_answers` flips a byte of the tag, not of the
  length field.
- **Corrected:** fix round 3's note on the name (above) and its order, cost, and answered lookups; the `udp_unmatched`
  list; RFC 9001 9.5, which is about timing confirming a packet number, its length or the Key Phase, not keys
  (`open`'s doc and fix round 3's note); `LARGEST_DATAGRAM`'s doc ("which no QUIC client sends"); the negotiation
  test's doc; `docs/VPN.md` (a QUIC answer under a name), the CHANGELOG (the kinds a client discards, not every such
  answer), `docs/DESIGN.md`.
- **Tests, each shown to fail once without its fix.** Review G's six probes, each failing on the engine of `21e65bd`
  (G1a, G1b, G2, G3, G4, G5); and, each failing with its fix undone as a mutant in the run below, G7's case (T10), the
  size bound on STUN (T11), the hello's reader's derivations (F19, H18), the newest stand-in address while both live
  (T14), `dns::answered`'s checks (D2, D3, D4, D6), review H's three engine cases (U2 at its new place, T6; U5; U6)
  and the contest under a label held beside (T9).
- **The mutation runners** (review D's runner, as in fix round 2, pointed at a worktree of `b36d6f8`): 125 mutants,
  every runner's of this unit again: review F's 26, review D's and fix round 2's 41, fix round 3's 13 (its four on the
  name's hint dropped with the model), review H's 32 (its `foreign` four gone with fix round 3's code, their claims
  now T5 to T7), and this round's 13 (T1 to T11, T13, T14), one or more for each fix. All 125 killed.
- **Fuzzing:** `scripts/fuzz.sh 480`, as CI runs it, on `b36d6f8`: all twelve targets, 40 s each, found nothing
  (`identifiers` 3,228,988 runs, `quic` 5,134,324, `quic_answers` 604,939); `identifiers` alone, 120 s with `named`
  and `answers`, 6,714,676 runs, nothing.
- **Not done, stated:** the emulator step was not run by the builder (it passed after the round: unit 9b's note); the
  accepted limits, gathered in unit 9b's note since fix round 6.

**Unit 9b, fix round 5 (2026-11-17).** Two fresh reviews of fix round 4, I of the engine and J of the tests, the
parsers and the docs, after the network shard passed on Android 15 with `0a6a123`, the STUN step's 48th counter rising
from 0 to 1 at its first sending. Neither found a major fault: the label read as a source held, case by case, against
the rules of an address. The maintainer's rule again: every finding gets the best-in-class fix, or an accepted limit
with its reason here.
- **The holder's own answer among several sent one identifier** (review I, I1). Under a label, an answer that names in
  the clear what the app sent is the holder's if the holder was sent it; fix round 4 found the peers sent it by a walk
  that stopped at two, in the map's order, and asked whether the holder was among them, so that with three or more, as
  a stub resolver retrying one query at two more servers makes, the holder's own answer was dropped at random (5 of 20
  in the probe). The holder's own fingerprints are asked first now.
- **What an answer under a label costs** (I4): the walk went through every peer of the mapping and each one's
  fingerprints under the table's lock, 152 us for each answer with 4,000 peers on the port. Each association's
  fingerprints keep now, beside how many peers were sent each, the exclusive-or of those peers' addresses: where one
  peer was, that is its address, read without a walk; 159 ns for the same answer (release, x86-64). An entry grows
  from 16 to 32 bytes, so that an identifier the app sends a peer through the tool costs at most 83.4 bytes, 5,339 for
  one peer (corrected above). Kept so rather than as a list of peers for each fingerprint: the same answer, exact, in
  a fixed 32 bytes, where a list costs an allocation for each identifier. The index is per association, as the counts
  were: a peer of another association sent the same identifier, as a stand-in given one of its own for that very
  identifier is, is in another's (review J's J14 asked for that case's test; it is in).
- **The contest under a label its own stand-in holds** (I2): an address a stand-in holds has its answers without
  identifiers cut for `udp_contest` while a stand-in without identifiers, asked meanwhile, waits on the port, as the
  tool may have resolved both names there. A label held by the name's own stand-in was never contested, so that under
  Xray's `freedom` a second name resolved to the same address had its answers given to the first at once. It is
  contested as the stand-in beside it is: the holder of a label is a stand-in, whoever it is.
- **The contest spares what the holder was sent** (I3): it cut answers that carry the holder's own identifier, which a
  stand-in without identifiers cannot have asked: by an address, the holder's STUN response, a TURN refresh's, for 5
  s; under a label, the beside holder's QUIC answer opened by its keys. Both are the holder's at once. **Accepted
  limit:** by an address, a QUIC answer to the stand-in bound there is still cut while the contest lasts: once bound,
  a stand-in keeps no keys (`ASKED`'s memory), and its fingerprints, of the IDs its client's Initials carry, tell
  nothing of a server's answer but under keys; the contest lasts 5 s from the other stand-in's first datagram, within
  which QUIC sends again. (Fix round 6, review K's m2: untrue for a client whose source ID has 4 bytes or more, which
  every packet of its server's carries in the clear, and as true under a label its own stand-in holds; the contest
  spares such answers now, by an address and under a label, and the limit stands for shorter IDs, in unit 9b's list.)
- **Another port of a handed address** (I7): once an address passed to the stand-in bound beside its holder, another
  port of it, a STUN server's alternate port (RFC 5780), came in as a flow of the ended holder's stand-in, logged
  under its name; so did one of an address two names were bound to on two ports, once the first ended. An address
  keeps now every address the app knows its peers by, the stand-in beside its holder among them: it is shown as itself
  while the app knows a peer by it, else as the oldest of its live peers' stand-ins.
- **A clear answer to another binds no stand-in without identifiers** (I5): from an address the app never saw, an
  answer that names in the clear what the app sent a peer bound a lone stand-in without identifiers, which cannot have
  asked it, and every later answer from there went to it. It binds none now, and reaches no one: from an address the
  app never saw nothing reaches a peer but a stand-in's first answer (unit 9), where under a label, which may stand
  for the peer's own address, it is the peer's (G4). From another port of an address a stand-in was bound to, the
  stand-in that waits there is the same name's other port, and the answer plausibly its own, as RFC 5780's CHANGE-PORT
  answers: unchanged.
- **Each app's share of the associations of a stand-in's own** (I8): `udp_own_relays`, 32 for every app together, had
  no share for each, so that one app could hold all 32 (four sockets of 8) and every other app's stand-ins fell to
  unit 9's floor. Each app, and the apps Android cannot name together, may hold a quarter now, `udp_own_share`, 8, by
  the engine's `Budget`, as decision 3 shares its caps; the place is taken before room is made in the app's share of
  mappings, and given back if none is made.
- **A STUN message past 1,500 bytes** (review J, minor 2): fix round 4 refused one whole, inside `stun()`, which reads
  answers too. RFC 8489 6.1 makes the MTU a SHOULD so that STUN may probe it with RFC 5780's PADDING, an attribute
  whose own length SHOULD be the MTU of the sender's outgoing interface (5780 7.6), and which a server MUST put in its
  response to a padded request (6.1), so that a padded message exceeds 1,500 bytes on any path of 1,500 (so worded in
  fix round 6, where this said the response is as large as the MTU): a padded client's answer of some 1,524 bytes was
  refused, and a strict stand-in's dropped as unidentified. A larger message is read again, its header, cookie, length
  and transaction ID, which tell its answer apart; its attributes are walked over its first 1,500 bytes, those past
  them taken to fit: 0.78 us for 65,500 bytes of empty attributes.
- **The hello's reader's keys** (J, minor 3): fix round 4's two key sets, in place, made the reader, boxed for every
  peer the app sends to that did not come in, the direct path's among them, 1,904 bytes, QUIC or not, where this ADR
  says 960. Each set is made on the heap when an Initial of its version first comes: 80 bytes on x86-64, and 896 for
  each version a client's Initials use (corrected above).
- **What the label's rules are, in the code and here** (I's doc points 1 to 5): the code looks for what an opened
  packet tells among every stand-in bound beside on the port, by an address or under any name, where `by_name`'s doc,
  fix round 4's note and `docs/VPN.md` said "under the label". The code is right, for the reason a clear identifier
  goes to any peer of the association: the address behind a label is unknown, and a stand-in bound beside an address
  may be at it. The words follow it now. Fix round 4's "one difference" from an address was not the only one; each,
  with its reason (`Scope::by_name`'s doc):
  - an answer under a label that names in the clear what the app sent is the holder's if it was sent it, else the one
    peer's of the association that was, and no one's where several were; and what an opened packet tells is looked for
    among every stand-in bound beside on the port: the address is unknown;
  - a stand-in bound beside under a label stays beside, keeping its identifiers, where the first bound beside an
    address takes it once its holder ends: the name's own peer may come back, as the app asks the name again;
  - with several stand-in addresses for the name, the newest with a peer on the port holds the label, the one the app
    uses now;
  - the name's own stand-in, waiting with identifiers, takes an answer under its name without them, where from an
    address the app never saw it would take none: the relay names the address the name resolved to, which a stranger
    reaching the relay's port from elsewhere is not;
  - a name no peer has binds no lone stand-in without identifiers, where an address the app never saw binds one by its
    first answer: a name nobody asked for is dropped (unit 9's M21), and one whose peers ended cannot be told from it.

  The contest, a difference until this round, is none now (I2).
- **What review J's mutants found untested** (14 of 29 survived): each is killed by a test now. J23 and J30, the
  beside records per name and port, the first holding; J25 and J26, an association with nothing to send ending no
  mapping with something open; J17 and J22, the counters under a label; J20, J21, J24 and J28, an answer under a label
  with no holder on its port (J28 is no equivalent: with no holder, an answer naming what one settled peer was sent is
  that peer's, which the mutant sent elsewhere); J8, `dns::answered` refusing a response with no question; J6, a hello
  read across a new destination ID of one version, as after a Retry; J12, a peer of the name on another association
  holding nothing; J14's code is gone (above).
- **Fuzzing** (J's doc point): `Reading::answers` is held to `Reading::tells` in the `identifiers` target: it names an
  identifier only where `tells` finds it, never a QUIC one, a STUN one wherever `tells` finds it, STUN being read
  first, and for DNS and NTP something wherever `tells` finds one (a protocol read before may be named instead).
- **Corrected:** fix round 4's note (the candidates, the contest, the differences, RFC 8489 6.1 for 6.2.1 and SHOULD
  for "keeps", the reader's keys), the `udp_unmatched` list and `udp_identified`, which counts since fix round 4 an
  answer under a label that a peer other than its holder took by an identifier it was sent; the fingerprints' and the
  reader's bytes (above); review G's probes, kept as tests, describe fix round 3's faults in the past tense; a test
  fix round 4 extended is renamed for what it holds; `dns::answered`'s test is placed after its module's helpers;
  `TunnelMtu.MOST` says a Rust test ties it to `LARGEST_DATAGRAM`; the dump's KDoc; `docs/VPN.md` (the holder first,
  the contest, "the relays read for this" where it said no tool's relay filters by sender); the CHANGELOG, rewritten
  for what a user notices, the detail here; `docs/DESIGN.md`.
- **Tests, each shown to fail once without its fix.** On the engine of `0a6a123`: review I's six probes (I1, I2, I3,
  I3b, I5, I7), kept as tests, and the second case of I7's (two names bound to one address on two ports); the reader's
  size (1,904 bytes), and a STUN request of 1,504 bytes and a padded response of 1,524 (refused). And each with its
  fix undone as a mutant in the run below: the one keeper's address (V1, V2, V3, J13', J15'), the contest's (T9',
  J19', V5, V6), the shown address (V7, V8, V9), the clear answer (V10), the share (V11, V12), the STUN walk (T11',
  J1', V13), the reader's keys (J5', J6', V14), and review J's.
- **The mutation runners** (review D's runner, as in fix round 2, as review J extended it to several edits a mutant,
  pointed at a worktree of `dda8e1c`): 182 mutants, every runner's of this unit again: fix round 4's 125 (reviews F, D
  and H, and fix rounds 2 to 4), review J's 29, and this round's 28: 13 for its fixes (V1 to V3, V5 to V14) and 15
  that carry earlier mutants to where this round moved their code (F19', standing for Q18 and H18 too; R1e', R6b',
  S5', T5', T6', standing for J16 too; T9', T11', standing for J2 too; J1', J5', J6', J13', J15', J19', J20'). The 15
  stand for 19 earlier ones, which no longer apply where they were written; with J14, whose code is gone (above),
  those are the 20 not run, and 182 less 20 is 162 (so worded in fix round 6, where this said "the 20 they stand
  for"). Of the 160 run on `dda8e1c`, 159 were killed; the one left, J13' (the fingerprints naming a peer wherever any
  keeps one, not one alone), is killed by a test added after (`7053347`), five peers sent one timestamp, four of whose
  addresses cancel out; J15' and J20', added then, are killed too. All 162 killed.
- **Fuzzing:** `scripts/fuzz.sh 480`, as CI runs it, on `dda8e1c`: all twelve targets, 40 s each, found nothing
  (`identifiers` 3,634,240 runs, `quic` 5,818,459, `quic_answers` 623,856); `identifiers` alone with the new property,
  180 s, 13,850,433 runs, nothing.
- **Not done, stated:** the emulator step was not run by the builder (it passed after the round: unit 9b's note); the
  accepted limits, gathered in unit 9b's note since fix round 6.

**Unit 9b, fix round 6 (2026-11-17), the last before the push.** Two final reviews of fix round 5, K of the engine and
L of the parsers, the tests and the docs, after the network shard passed on Android 15 with `b263416`, the STUN step's
48th counter rising from 0 to 1. Neither found a major fault; review K ran a randomized model check of fix round 5's
fingerprint index, 40 runs of 3,000 steps, which held exactly after every step. The maintainer's rule again: every
finding gets the best-in-class fix, or an accepted limit with its reason, now in unit 9b's list.
- **The cap for each mapping goes** (review K, m1): `OWN_RELAYS`, 8 associations of a stand-in's own for each mapping,
  could no longer be reached, since the share of 8 for each app that fix round 5 set refuses first: a mutant turning
  it off survived every test, and the chain test meant for the caps held the share. The share covers what it was for,
  and an app's other sockets too: it is gone. The chain test tells the share from the engine's cap now: 32 and 8, 1
  and 8, 32 and 2.
- **The holder's QUIC answers in the contest** (K, m2): a label held by the name's own stand-in, once settled by its
  answer, keeps no identifiers, so that its QUIC answers under its label were cut for `udp_contest` while a stand-in
  without identifiers waited on the port; so were a bound stand-in's by an address, which fix round 5 accepted for a
  reason untrue for most clients: a client whose source ID has 4 bytes or more (quic-go, quiche, msquic, ngtcp2,
  Apple's stack) has it in every packet of its server's, as their destination, in the clear (RFC 9000 17.2, 17.3). A
  peer through the tool keeps now, beside its QUIC identifier's fingerprint, one of that source ID alone, and the
  contest spares, by an address and under a label, an answer whose first packet is addressed to it: a long header's
  destination ID, or, for a short header, which does not give its length, each length from 4 to 20 bytes. Nothing is
  opened, and it is read only where the contest would cut. The limit stands for an empty or shorter source ID,
  Chromium's and Cronet's (in the list).
- **Ending many stand-ins' records** (K, the cost): an address's record of its peers' stand-in addresses (fix round 5,
  I7) was walked to add, take out and show one, and each stand-in's end walked every label's stand-ins bound beside,
  so that ending many cost the square of their number under the table's lock. A record of members in the order they
  came, found and taken out without a walk (a tree by arrival and a table by member), keeps the stand-ins waiting on a
  port and those bound beside an address, under a label and on a port now; an address counts its peers' stand-in
  addresses in a table; each stand-in beside under a label is indexed by its label. Release, x86-64, 16,384 stand-ins:
  bound to one address, each on its own port, 88 ms to add, 163 ms to show and 178 ms to end before, 4.2 ms, 0.34 ms
  and 2.1 ms now; beside one label, 501 ms to end (each on its own port) and 384 ms (all on one), now 7.4 ms and 2.9
  ms. Review K's measures are ignored tests. Each member costs now an entry in a tree and in a table where a vector's
  place was 32 bytes; the stand-ins are bounded by the stand-in map, as before. Only a hostile or broken app reaches
  such numbers.
- **The model check** (K): kept as a test (`the_fingerprint_index_matches_its_peers_at_every_step`, 1.5 s in a debug
  build); it fails at step 16 with a peer's end not forgetting its fingerprints.
- **A large STUN message's header** (review L, point 4): over 1,500 bytes, the tests held only a message's transaction
  ID and class, so that mutants dropping its length, cookie or top bits' check above 1,500 bytes survived; a
  2,000-byte message with each wrong is refused in the test.
- **What `Reading::answers` names** (L, 5): a mutant naming a STUN request or indication survived every unit test, and
  CI's 40 s of fuzzing caught it in 4 runs of 6. A unit test holds that both answer nothing, and the `identifiers`
  target has a seed whose answer is the app's own request echoed back, review L's crash input.
- **The fuzz properties** (L, 6): for DNS as for STUN, `answers` names a query's identifier exactly where `tells`
  finds it (a STUN response's cookie reads as 0x2112 questions, so it never reads as DNS); only NTP keeps the weaker
  property, a reply reading as DNS first. The target reads each answer for the source IDs it is addressed to too.
- **`scripts/verify-chain.sh`** (L, 7): its `counter()`, unused since `counter_since`, is gone.
- **Docs** (K and L, 8 to 14): the CHANGELOG's line on what lies past the relays of a stand-in's own (it waits beside
  the other under unit 9's floor, where it said its first answer takes it) and on QUIC (only Initial packets are
  opened and Retry tags checked, under keys anyone can derive; no app's QUIC traffic is decrypted); `docs/VPN.md`'s
  contest (answers are dropped for five seconds, not held, the holder's own spared); 896 bytes for each version's key
  set, `(Cid, Keys)` aligning to 16, where fix round 5 said 888, and 83.4 bytes for each identifier, 5,339 for one
  peer, where it said 83 and 5,312; the emulator step, which passed after rounds 2 to 5 where notes said it had not
  run (`docs/DESIGN.md` too); fix round 5's changes corrected in place in unit 9b's note (the STUN definition, the
  caps, the first answer of a lone stand-in without identifiers); the accepted limits gathered into one list in unit
  9b's note, each with its reason and round, the round notes pointing there, with a STUN message's malformed tail
  added; fix round 5's mutant arithmetic; RFC 5780's PADDING (its own length SHOULD be the MTU of the sender's
  outgoing interface, 7.6, and a server MUST answer a padded request with one, 6.1, so a padded message exceeds 1,500
  bytes on any path of 1,500); and names a reader could not find. `docs/ci-flakes.md` cited a probe of review F's that
  is in no file; the notes named the mutation runner's files, which live with the reviews: both are described instead.
  The runner is not added to the repository: its mutants are text replacements tied to one commit, which go stale as
  the code moves (20 of fix round 5's 182 no longer applied where they were written, 26 of this round's 209), so that
  a list kept here would mislead more than it helps; the field's tool, cargo-mutants, makes its mutants from the code
  and would be a CI unit of its own.
- **Tests, each shown to fail once without its fix.** The source ID's, on the engine of `b263416`, under a label
  (review K's probe) and by an address, each case alone. The rest each with its fix undone as a mutant in the run
  below: the model check (R1e'), the large STUN header (L1, L2, L3), what answers names (L8), the chain test's share
  (V11, V12), the source ID (W1 to W5), the records (W6 to W10, V7', V8'), the last three killed by a test added after
  the run (below).
- **The mutation runners** (review D's runner as before): 209 mutants: fix round 5's 182 again, review L's 11, and
  this round's 16 (W1 to W10, and six that carry earlier ones to where this round moved their code: T2'', J23'', T9'',
  J19'', V7', V8'). 26 no longer apply where they were written: the 19 fix round 5 carried (two of its carriers, T9'
  and J19', carried again now), T2 and J23, fix round 5's T9', J19', V7 and V8, and J14, whose code is gone. Of the
  183 run on `4f06f24`, 180 were killed; the three left, W9 (a member pushed twice into its order), W10 (the first
  popped left found) and V8' (an address's count kept at nought), are killed by a test added after (`d1ddd90`): an
  address is let in only while a peer has it. All 183 killed.
- **Fuzzing:** `scripts/fuzz.sh 480`, as CI runs it, on `4f06f24`: all twelve targets, 40 s each, found nothing
  (`identifiers` 2,986,146 runs, `quic` 5,382,560, `quic_answers` 611,333); `identifiers` alone with this round's
  properties and seed, 180 s, 11,289,887 runs, nothing.
- **Not done, stated:** nothing beyond unit 9b's list of accepted limits.

**W5, part 1: the engine's clocks (2026-11-18, finding 4 of the review of 2026-11-09).** The review found that the
log's quarter hours followed a timer that stands still while the phone sleeps (ADR 0037, decision 1), and asked beyond
the repair for one table: every reading of time in the engine, what a sleep of hours and a jump of the wall clock do
to each, and whether the user can see a wrong result from it. It is here, not in ADR 0037, because this ADR holds the
engine's own gaps and its tests that drive time (decision 6), and all but one row are its mechanisms; ADR 0037 holds
the log's row.

- **Three clocks.** The wall clock runs on in a sleep and can be set back or forward by the user or the network.
  The monotonic clock, which tokio's timers and `std::time::Instant` read on Android and Linux, stands still in a
  sleep and never jumps, as the kernel's own timers (TCP's among them) and the apps' do. `CLOCK_BOOTTIME` runs on
  in a sleep and never jumps.
- **The engine is handed a clock** with its platform (`Platform::clock`, the phone's own by default:
  `core/net/src/engine/clock.rs`) with two readings, the wall clock in milliseconds and the time since the phone
  started, sleep included, so that tests move both: a sleep of hours, a jump back, a jump forward. The rest reads
  the monotonic clock, which tokio's paused time moves in tests. `CLOCK_BOOTTIME` is read with nix's safe
  `clock_gettime`, through its `time` feature, which brings no other crate; `cargo deny` passes.

| What reads the time | Where | Clock | A sleep of hours | A jump of the wall clock | What the user could see | Now |
|---|---|---|---|---|---|---|
| The log's times and quarter hours: each count of a flow's bytes, each lookup and answer counted, a flow's start and end, the flush, the logger's wake | `logbook.rs` (`Shared::log_now`), from `tcp.rs` and `udp.rs` | Wall, handed in | Before: the timer woke late, and a night's bytes went into one segment from the evening, filed under its day, through the timer or a flow's end | Before: a segment ending before it began, its end set to its start | A flow's bytes in another quarter hour, and another day | Fixed: each count cuts first, at the quarter hours passed either way (ADR 0037, decision 1) |
| The logger's waits: 30 s gathering, the sleep to the next quarter hour | `logbook.rs` (`logger`) | Monotonic (tokio) | It wakes late; records already cut wait in memory until it does, and are lost if the process dies first, as any record waiting is | None | Nothing now: no segment depends on it | Accepted |
| DNS answers kept for apps that go directly while a chain is on, and for chained apps' questions through the tool (ADR 0038) | `dnscache.rs`, `udp.rs` (`cached_answer`), `lookups.rs` | Was monotonic; now `CLOCK_BOOTTIME` | Before: an answer of five minutes kept before a night was served in the morning, for as long again as the phone had been awake; Android's own resolver, which this cache stands in for, would have dropped it | None | An app given an address past its time to live | Fixed. A reading that fails keeps nothing (fix round 1, engine, finding 4) |
| Names from DNS answers, and ECH public names (at least an hour, at most a day) | `names.rs`, `naming.rs` | Monotonic; and `CLOCK_BOOTTIME` to stand beside a connection's own name | A name is kept longer in real time | None | A DNS name kept through a night can name a flow that sends no name of its own; beside its own name it would show its age as a difference | Accepted for naming: apps reconnect after a night to addresses they got before it (a browser's own cache, a pool of connections), and the name they asked for names those flows; a newer answer for the address replaces it; and the connection's own name now names a flow that sends one (finding 20). Fixed beside: a name stands beside a connection's own only while held in time since the phone started (fix round 1, engine, finding 7) |
| TCP rewriting: idle limit (10 min), port cooling (60 s), the sweep (60 s), the linger after a relay (30 s) | `nat.rs`, `tcp.rs`, `engine.rs` (`run`) | Monotonic | An idle connection is kept across the night, as the app's kernel keeps it, whose TCP timers stand still too | None | None; on `CLOCK_BOOTTIME` the engine would forget a push connection the app still holds, and reset it at its first packet in the morning | Correct as it is |
| UDP mappings: idle end (120 s), quiet (5 s), asking Android again (1 s, and every 30 s), the contest (5 s), Android's answers near datagrams | `udp.rs`, `whose.rs` | Monotonic | A mapping idle across the night stays, as the app's socket does; no app opens or closes a socket while the phone sleeps, so time awake is the time in which a port can change hands | None | None | Correct as it is |
| Waits: a TCP connect (60 s), a tool's handshake, lookups through the tool, connections kept to its resolvers, the tunnel's write in a swap (200 ms), the listener's pauses, a reset's drain (2 s), pings (idle 10 s, quiet 2 s), fragments (5 s) | `upstream.rs`, `chain.rs`, `lookups.rs`, `kept.rs`, `tun.rs`, `tcp.rs`, `echo.rs`, `fragments.rs`, `engine.rs` | Monotonic (tokio or `Instant`) | A wait lasts longer in real time, as the kernel's own retransmission timers do | None | None: nothing is recorded from them | Correct as it is |
| The window of an app's own proxy's first hop in "Now" (ADR 0052, decision 8) | `now.rs`, `logbook.rs` (`finish*`) | `CLOCK_BOOTTIME` | Ten minutes asleep are ten minutes | None | A first hop shown for ten minutes after its connection ends | Correct as it is: on `CLOCK_BOOTTIME` from the start (the proxy record, unit A) |
| The owner rule's model, and the tests' own waits | `whose/model.rs`, tests | Monotonic | Test only | Test only | None | Test only |

- **Tests.** The log's: ADR 0037's note of the same day. The caches': an answer kept for five minutes answers for
  four and is gone after a night's sleep, in the cache (`dnscache.rs`), for a direct app while a chain is on
  (`udp.rs`) and for a chained app's question through the tool (`lookups.rs`), each with a clock the test moves.
  No unit test can tell `CLOCK_BOOTTIME` from `CLOCK_MONOTONIC` on a machine that has not slept since it started:
  the clock the engine reads there is checked by reading, and the tests move the clock the engine is handed (fix
  round 1, a mutant review 1 left alive).
- **Cost** (fix round 1, engine, finding 5; second fix round). Each count of the log reads the wall clock once. A
  count of a flow's bytes takes no lock within a quarter hour; a count of an app's lookups locks its count, and a
  TCP packet on the tunnel the map of its flow's bytes. `CLOCK_BOOTTIME` is read for each DNS answer
  a cache keeps or looks up, for each DNS answer whose names the engine learns, and for each hello that would set a
  differing DNS name beside a flow's own; and, for the window of an app's own proxy's first hop (ADR 0052), once at
  each flow's end and once at each sweep of "Now": never for each packet. Measured on the development machine (x86-64,
  vDSO, release build, 2026-11-18): `SystemTime::now` 22.8 ns, `CLOCK_REALTIME_COARSE` 7.9 ns, `CLOCK_BOOTTIME`
  20.4 ns, an `Arc` cloned and dropped 2.8 ns, an atomic addition 1.4 ns. So the log reads the coarse wall
  clock, as the fresh review 2 offered: its steps here are 4 ms (the kernel's tick at 250 Hz), and it lags the
  wall clock by less than two ticks, since the kernel's timekeeping adds whole ticks and is updated at each:
  under 8 ms at 250 Hz, the default, under 20 ms at 100 Hz, the lowest Linux offers (3.3 to 7.3 ms measured
  here; review 3, nit 2: no record grounds a bound of one tick for Android's kernels).
  It follows the wall clock when it is set, and is read in the vDSO also on phones whose kernels read the fine
  clock through a system call. A byte counted within that lag after a quarter hour then falls in the quarter
  hour before, which ADR 0037's note accepts: the bounds there are seconds. A count of no bytes of the
  app's own, as a tunnel packet's, adds nothing to them. ADR 0037's note says how many reads a packet costs.
- **For ADR 0046, decision 1** (W5's second part and its fix round, 2026-11-18), each count also compares the
  second it read with its flow's last, a division, an addition, a few comparisons and one atomic load, and takes
  no lock; the first count of a second notes a mark under the lock of the flow's own marks, and the lock of the
  waiting seconds' count, once a second per flow; and a clock set back by a second or more, found by the same
  reading, places what waits. Measured the same way: a count costs 12.5 to 13.2 ns with the apps' states told and
  without, no difference within the measurement; one that notes a mark, 106 to 116 ns (45 to 96 ns, the readings
  of the states every minute included, with the waiting seconds' count an atomic). The test `what_a_count_costs`
  measures it. The seconds and segments that wait for their states are shared out per app as this ADR shares its
  other bounds, a quarter of each to one app, the heaviest giving way past the bound itself; `told_late`, the 52nd
  counter, counts the seconds, and segments with no count, placed as told too late. `COUNTERS` is 52.

