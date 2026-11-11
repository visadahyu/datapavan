# W6's acceptance against its "done when"

W6's row of [DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)
read clause by clause on 2026-11-11, on branch `watch-w6`, against the code, the tests and the runs of
[the real tools](2026-11-real-tools.md) and [ADR 0038's lab](2026-11-chain-lab.md). "Met" means a test
or a recorded run shows it. The last section lists what is left to the maintainer.

| Clause | Evidence | Status |
|---|---|---|
| Watch finds the user's tool by itself, from the table | `ToolFinder` reads the installed tools of `data/tools/tools.tsv` that have a proxy mode (shipped inside Watch's signed APK); `ToolTableTest` | Met. The table is not yet updated through a signed data pack; Watch has no packs before W8 |
| A SOCKS5 greeting on known ports only | `ToolFinder.probe`: each listener of the table, and that port shifted by the Android user's number; nothing else is greeted | Met |
| The port's owner asked from Android | `ToolFinder` asks `getConnectionOwnerUid` as soon as the connection is made, before the greeting; a port Android names as another app's is skipped | Met. Once, on Android 17, the first search after the tunnel started had no owner (NekoBox); later searches had it |
| Chained TCP through `CONNECT`, UDP through `UDP ASSOCIATE` or not at all | `core/net/tests/chain.rs`, `scripts/verify-chain.sh`; Orbot's UDP went nowhere on every device | Met |
| Their DNS goes to the tool, never to the network | Stand-ins for A, AAAA empty, other questions through the tool to Quad9 (ADR 0038); `verify-chain.sh` checks that the name went to the tool | Met, except with strict Private DNS: Android's resolver then sends the lookups to the user's provider itself, encrypted, past Watch (lab, §4). Watch says so on the chain screen; see below |
| When the tool stops, chained apps wait, Watch says so, nothing goes out directly | `verify-chain.sh`: with the tool stopped, the shell's TCP and UDP fail and a sentinel on the host sees none of them; the chain screen says the tool does not answer and the apps wait | Met |
| The tool's own traffic goes directly and is attributed to it | `verify-chain.sh`; every real-tool run (NekoBox's DNS over HTTPS to 223.5.5.5, Orbot's Tor relays, under the tool's UID) | Met |
| Nothing comes in that a local app did not start; `BIND` is never used | `socks5::Command` has `Connect` and `UdpAssociate` only; the relay's datagrams reach only the flow that asked for the relay | Met |
| Watch offers a generated password where the tool supports one | `ChainSettings.password()` (SecureRandom, kept under a Keystore key), offered when the table says the tool can take one; Hiddify's user name is fixed and was checked on a device | Met |
| Watch opens no port of its own | Watch serves no proxy; its engine's listener on the tunnel's address takes only connections the engine rewrote (`verify-watch.sh`) | Met |
| Watch never logs SOCKS credentials | `Credentials`' `Debug` hides them; `verify-chain.sh` now checks that neither the right nor a wrong password is in Android's log or Watch's dump | Met |
| The user chooses which apps go through the tool | The chain screen: every app, or only the apps the user picks | Met |
| CI: a test proxy with `UDP ASSOCIATE` and a password carries a workload app's TCP, UDP and DNS | `verify-chain.sh` with `scripts/test-tool`; the chained app is adb's shell (UID 2000), not a workload app | Met with the shell; see below |
| CI: with the proxy stopped, a capture on the host shows no packet of a chained app leaving directly | A sentinel on the host instead of a capture: the emulator console's capture does not see Wi-Fi traffic. A control's direct connection shows that the sentinel sees what leaves | Met by other means |
| Checks that the chain works use only the address Android itself checks connectivity with | The device runs used connectivitycheck.gstatic.com only; CI reaches a server on the host, not the internet; Watch itself makes no such check | Met |
| On the A40 and the emulators, v2rayNG, NekoBox, Hiddify and Orbot are found and chained without a port typed | v2rayNG, NekoBox and Orbot on Android 11, 15, 17 and the A40; Hiddify on Android 17 and the A40. On the x86_64 emulators with Android 11 and 15, the emulator itself stopped at Hiddify's first connection | Met, but Hiddify only on one emulator; see below |

## Left to the maintainer

1. **Strict Private DNS.** Watch warns and still chains (ADR 0038's open question 4, measured in the lab).
   Refusing to chain would leave the app no way through the tool; warning leaves its lookups going to
   the provider the user chose, encrypted, where a filtering network can see that DNS over TLS is used.
2. **The tool's signing key.** `ToolFinder` does not check the found tool's certificate against
   `data/app-signers`, so a modified copy of a known tool is chained like the real one. The audit app
   already flags modified copies. Watch could warn on its chain screen as well: Watch already sees the
   tools of the table, and `hasSigningCertificate` needs no further permission.
3. **The chained app in CI** is adb's shell rather than a workload app. The shell is an ordinary UID
   to the engine, and the real-tool runs used it too. A workload app would also test Android's
   per-app routing of an installed app.
4. **Hiddify on the emulators** with Android 11 and 15 could not be tested: the emulator stopped at
   its first connection, as a segfault in the emulator's renderer. Hiddify was tested on the A40 instead.
