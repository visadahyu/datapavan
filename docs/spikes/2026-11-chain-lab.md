# ADR 0038's lab (W6)

The measurements [ADR 0038](../decisions/0038-dns-of-chained-apps.md) asks for before W6 is done, as far as they were
run on 2026-11-11, on the emulator with Android 17 (Play image), with adb's shell or Chrome chained through W6's
test tool (`scripts/test-tool`), which connects directly.

## 5. The delay of lookups

`dns-time`: adb's shell asks Watch's DNS address and times the first byte of the answer, six times in a row, on
the device itself (a shell loop around `toybox nc -u`), in milliseconds.

| Question | Route | First | Then |
|---|---|---|---|
| A, crypto.cloudflare.com | direct, the network's resolver | 57 | 12 to 21 |
| HTTPS, crypto.cloudflare.com | direct, the network's resolver | 56 | 11 to 16 |
| A | chained: a stand-in from Watch | 9 | 9 to 10 |
| HTTPS | chained: through the tool to Quad9, DNS over TCP, before Watch kept answers | 565 | 418 to 569 |
| TXT, example.com | the same | 565 | 111 to 456 |
| HTTPS | chained, with the tool route's own cache | 562 | 10 to 11 |
| TXT | the same | 560 | 9 to 14 |

Each question through the tool opens a TCP connection to the tool, a SOCKS5 handshake and a TCP connection to Quad9
before it is asked. Before the measurement, Watch kept no answers for the tool's route, though the ADR says it keeps a
cache for each route: every lookup of a chained app paid that half second. Watch now keeps the resolver's answers for
the tool's route too, for their time to live, and answers again from them, rebuilt with a time to live of 0; the
second lookup of a name takes about 10 ms. The first one still costs a new connection; keeping one connection to the
resolver open through the tool would save most of it, and is left for later. Through Tor the first lookup is slower
still; not measured.

## 4. Strict Private DNS

With Private DNS set to `dns.google` and the shell chained, a lookup of connectivitycheck.gstatic.com did not reach
Watch's DNS address. Android's resolver asked dns.google itself, over DNS over TLS (port 853) and over UDP port 443,
from its own UID (1051), not the app's. Watch therefore cannot route those lookups by app: they went directly,
encrypted, to the provider the user chose. The shell then connected to the real address it was given, and Watch sent
that connection through the tool by address (HTTP 204). So the chained app's traffic still goes through the tool;
only its lookups reach the user's Private DNS provider over the network beneath, encrypted, where a filtering network
can see that DNS over TLS is used and can block it.

Watch keeps warning, as its chain screen does, rather than refusing to chain: refusing would leave the app with no
way through the tool, while the warning lets the user choose "Automatic" or "Off".

## 1. Chrome and Local Network Access

Chrome 156, past its first run at the maintainer's word (signed out, usage and crash reports off), with only
Chrome chained through the test tool. Wikipedia's main page loaded whole, its images from upload.wikimedia.org and
thumb.wikimedia.org included, with no prompt for access to the local network and no request blocked. Each of
Chrome's destinations had a stand-in in 198.18.0.0/15 named after its lookup (en.wikipedia.org, thumb.wikimedia.org,
www.google.com and the rest), and its HTTPS questions went to Quad9 through the tool. Stand-ins all in one space of
Local Network Access, the loopback space, do what ADR 0038 expected. The comparison with IPv6 stand-ins in the
local or public space was not run: Watch gives no IPv6 stand-ins, and building them only to show a failure was not
worth it.

## 2. ECH through the tool

Cloudflare's trace page said `sni=plaintext` through the chain, and also without it: Chrome on this emulator did not
offer ECH at all, so the page cannot tell whether ECH survives the chain. Watch's own part was checked instead: the
HTTPS record for crypto.cloudflare.com that a chained app gets holds `alpn` and `ech`, with the address hints gone
and a time to live of 0; the direct answer holds `alpn`, `ipv4hint`, `ech` and `ipv6hint` with its real time to
live. Whether a browser then uses the key is the browser's matter; a browser that does ECH elsewhere (on a phone
where it works directly) is the next check.

## Not run yet

3. **The ten apps of W3:** they wait on the Google test account.
