# W6's acceptance against its "done when"

W6's row of [DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)
read clause by clause on 2026-11-11, on branch `watch-w6`, against the code, the tests and the runs of
[the real tools](2026-11-real-tools.md) and [ADR 0038's lab](2026-11-chain-lab.md). "Met" means a test
or a recorded run shows it. The last section lists what is left to the maintainer.

| Clause | Evidence | Status |
|---|---|---|
| Watch finds the user's tool by itself, from the table | `ToolFinder` reads the installed tools of `data/tools/tools.tsv` that have a proxy mode (shipped inside Watch's signed APK); `ToolTableTest` | Met. The table is not yet updated through a signed data pack; Watch has no packs before W8 |
| (Added) The found copy's signing key | `ToolKeys` judges the installed tool's certificates with the audit app's own rules (`android/shared`, ADR 0018) against Watch's copy of `data/app-signers`; the chain screen shows the audit app's reviewed words: genuine, a key not known yet (no claim, with the fingerprint), or a modified copy (in red, with the fingerprint); `ToolKeysTest` | Met |
| A SOCKS5 greeting on known ports only | `ToolFinder.probe`: each listener of the table, and that port shifted by the Android user's number; nothing else is greeted | Met |
| The port's owner asked from Android | `ToolFinder` asks `getConnectionOwnerUid` as soon as the connection is made, before the greeting; a port Android names as another app's is skipped | Met. Once, on Android 17, the first search after the tunnel started had no owner (NekoBox); later searches had it |
| Chained TCP through `CONNECT`, UDP through `UDP ASSOCIATE` or not at all | `core/net/tests/chain.rs`, `scripts/verify-chain.sh`; Orbot's UDP went nowhere on every device | Met |
| Their DNS goes to the tool, never to the network | Stand-ins for A, AAAA empty, other questions through the tool to Quad9 (ADR 0038); `verify-chain.sh` checks that the name went to the tool, for adb's shell and for an installed app | Met, except with strict Private DNS: Android's resolver then sends the lookups to the user's provider itself, encrypted, past Watch (lab, §4). The chain screen says exactly what leaves, to whom and what the network sees, and opens the network settings; see below |
| When the tool stops, chained apps wait, Watch says so, nothing goes out directly | `verify-chain.sh`: with the tool stopped, the shell's TCP and UDP fail and a sentinel on the host sees none of them; the chain screen says the tool does not answer and the apps wait | Met |
| The tool's own traffic goes directly and is attributed to it | `verify-chain.sh`; every real-tool run (NekoBox's DNS over HTTPS to 223.5.5.5, Orbot's Tor relays, under the tool's UID) | Met |
| Nothing comes in that a local app did not start; `BIND` is never used | `socks5::Command` has `Connect` and `UdpAssociate` only; the relay's datagrams reach only the flow that asked for the relay | Met |
| Watch offers a generated password where the tool supports one | `ChainSettings.password()` (SecureRandom, kept under a Keystore key), offered when the table says the tool can take one; Hiddify's user name is fixed and was checked on a device | Met |
| Watch opens no port of its own | Watch serves no proxy; its engine's listener on the tunnel's address takes only connections the engine rewrote (`verify-watch.sh`) | Met |
| Watch never logs SOCKS credentials | `Credentials`' `Debug` hides them; `verify-chain.sh` now checks that neither the right nor a wrong password is in Android's log or Watch's dump | Met |
| The user chooses which apps go through the tool | The chain screen: every app, or only the apps the user picks; `verify-chain.sh` picks one installed app on the screen and checks that it goes through the tool while adb's shell goes directly | Met |
| CI: a test proxy with `UDP ASSOCIATE` and a password carries a workload app's TCP, UDP and DNS | `verify-chain.sh` with `scripts/test-tool` and `scripts/workload-app`: an installed app, picked on the chain screen, looks a name up, sends TCP and UDP, all through the tool under its own UID, with the password Watch offered set in the tool | Met |
| CI: with the proxy stopped, a capture on the host shows no packet of a chained app leaving directly | A sentinel on the host instead of a capture: the emulator console's capture does not see Wi-Fi traffic. A control's direct connection shows that the sentinel sees what leaves | Met by other means |
| Checks that the chain works use only the address Android itself checks connectivity with | The device runs used connectivitycheck.gstatic.com only; CI reaches a server on the host, not the internet; Watch itself makes no such check | Met |
| On the A40 and the emulators, v2rayNG, NekoBox, Hiddify and Orbot are found and chained without a port typed | v2rayNG, NekoBox and Orbot on Android 11, 15, 17 and the A40; Hiddify on Android 17 and the A40. On the x86_64 emulators with Android 11 and 15, the emulator itself stopped at Hiddify's first connection | Met, but Hiddify only on one emulator; see below |

## Left to the maintainer

Both points below were settled by the maintainer on 2026-11-11, who accepted W6 with them
(«بله، ادغام کن»): Watch keeps warning about strict Private DNS, and Hiddify's test on the A40 stands for the
two emulators that stopped.


1. **Strict Private DNS.** Watch warns and still chains (ADR 0038's open question 4, measured in the lab).
   Refusing to chain would leave the app no way through the tool. The warning now names the provider and
   says what leaves past the tool, what the network sees and what the provider sees, and a button opens
   Android's network settings, with the Private DNS row marked on phones whose Settings app supports that.
   Sending Android's own encrypted lookups through the tool instead would hide them from the network, but
   a tool that resolves its own server's name through Android would then wait on itself; that needs a
   spike first.
2. **Hiddify on the emulators** with Android 11 and 15 could not be tested: the emulator stopped at
   its first connection, as a segfault in the emulator's renderer. Hiddify was tested on the A40 instead.

Checked on the Android 15 emulator after these changes: the chain screen showed v2rayNG's official copy as
genuine, a copy signed with another key as a key not known yet, with its fingerprint, and a copy signed with a
debug key as rebuilt by someone else, in red; with Private DNS set to dns.google the warning named it and the
button opened Android's "Network & internet" scrolled to Private DNS; and `verify-chain.sh` passed with the
workload app picked on the screen.

Settled after the first reading, at the maintainer's word: the found tool's signing key is now judged
(above), and CI chains an installed app picked on the chain screen rather than adb's shell alone.

## After the acceptance (2026-11-12)

CI on `main` failed twice at the chain screen's last step, after the merge of `w6-search`. The workload app
had just gone through the test tool. When it left, Watch's screen looked for the tool again and said that it
did not answer, although the tool was listening. With the chain on and the tool not answering, the screen
showed no switch. Watch did what it promises: the chained apps waited, and nothing of theirs went out
directly. But the user had no way to end that wait from Watch, short of turning Watch off.

Fixed on `chain-off`:
- **The switch stays.** While the chain is on, its switch stays on the screen whatever the search says,
  named after the tool the chain last went through. `verify-chain.sh` now stops the tool with the chain on.
  It checks that the screen says the apps wait and that the switch turns the chain off. It then checks
  that the picked app reaches the server directly.
- **Watch's searches are logged.** A debuggable build logs each search for the tool under the tag
  `WatchChain`, naming the part of Watch that searched (the screen, the service, the dump command). Each
  line says why a port was passed over: a timeout, a refused or reset connection, an answer that is not
  SOCKS5, or another app's UID as its owner. A release build logs none of it, since the lines name the
  user's tool. `verify-chain.sh` prints these lines when the screen misses a listening tool, and in any
  failure.

Still open: why the screen's search misses a tool that answers the service's. The logged lines should say
which step fails in the next CI run.
