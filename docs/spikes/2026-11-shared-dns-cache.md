# Android's shared DNS cache (before W6)

A spike of 2026-11-11, before W6 ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)),
on open questions 4 and 5 of [ADR 0035](../decisions/0035-wireguard-upstream.md). Script:
[`scripts/watch-lab/dns-cache.sh`](../../scripts/watch-lab/dns-cache.sh), with Watch's debug build,
whose dump takes `dns-uncached on` or `off`: with it on, every record of an answer from Watch's DNS
address reaches the app with a time to live of 0 (`dns::uncache` in `core/net`; the flags that EDNS
keeps in the OPT record's TTL field are left alone).

## The question

Android's resolver keeps one cache per network, and Watch's tunnel is one network for every app inside
it. In W6, the lookups of the apps the user chains go to the tool, the others' to the network's
resolver. If an answer the network's resolver gave a direct app sits in that cache, a chained app gets
it without a lookup: possibly a censored or forged answer. The chained app's question does not leak,
but its connection may go to the wrong address. And Watch can route a lookup by app only if Android
names the app as the lookup's owner, not its own resolver process.

## Method

Two apps inside the tunnel look the same names up with `ping`: adb's shell (UID 2000) and Watch's own
UID through `run-as`. A lookup that reaches Watch is a UDP flow to one of Watch's two DNS addresses
(IPv4 or IPv6), owned by the app; a lookup answered from the cache is none. In each case the shell
looks a name up, then the other app, then the shell again. The names are example.com, .org and .net
(RFC 2606) for answers, and random names under example.com, which do not exist, for negative answers.
Each run starts a new tunnel, which is a new network with an empty cache.

## Results

Three emulators: Android 11 (resolver module 300900700), 15 (350820300) and 17 (370399999, the 16 KB
page Play image). All three gave the same counts, in two runs each:

| Case | Shell first | Other app | Shell again |
|---|---|---|---|
| Normal TTL, an answer | 1 | 0 | 0 |
| Normal TTL, no such name | 1 | 0 | 0 |
| TTL 0, an answer | 1 | 1 | 1 |
| TTL 0, no such name | 1 | 1 | 1 |
| Normal TTL again, an answer | 1 | 0 | 0 |

1. **The owner of a lookup is the app that asked** (question 5). Android's resolver sends the query on
   a socket it gives the app's UID, so Watch can route each app's lookups by app.
2. **The cache is shared,** for answers and for "no such name" alike (question 4): the other app's
   lookup never reached Watch.
3. **An answer with a time to live of 0 is not kept,** nor a negative answer whose SOA record has one:
   every lookup reaches Watch, with its app as owner.

## What it means for W6

- While at least one app is chained (and in W7, carried by WireGuard), every answer from Watch's DNS
  address goes to the apps with a time to live of 0. Each app's lookup then reaches Watch, which answers
  it from the app's own route: the tool for a chained app, the network's resolver for the others.
- So that the network sees no more queries than before, Watch keeps a cache of its own, one per route,
  that honours the real time to live; only the apps' shared cache sees 0. Apps' own caches, such as
  Java's few seconds or a browser's, belong to one app each and stay as they are.
- While no app is chained, every app takes the same route, the shared cache does no harm, and answers
  keep their time to live.
- The cost is a trip through the tunnel for lookups the shared cache used to answer, answered from
  Watch's cache. W9's battery runs and the A40 measure it.

## Still open

- **DNS over TCP** to Watch's address, which Android uses when an answer was truncated: its records keep
  their time to live for now. W6 rewrites both.
- **Strict Private DNS:** Android then sends lookups over TLS to the user's server, past Watch's
  address, so Watch can neither route them nor rewrite their answers (ADR 0035, question 6). Watch must
  say so, as it does for W3.
- **Not run yet:** Android 10, 12, 13, 14 and 16, and the A40 (Samsung, Android 11). The resolver is a
  module Google updates through Play system updates since Android 10, so vendors share its code, but
  a phone may run an older version of it.
- An app with a resolver of its own (its own DNS, ADR 0029) never meets this cache.
