# Real tools in proxy mode, through Watch (W6)

A lab run of 2026-11-11 on the emulator with Android 15, for W6's last measure
([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools)): "v2rayNG, NekoBox,
Hiddify and Orbot in proxy mode are each found and chained without the user typing a port." Each tool came from its
developer's own GitHub release, and each signing key matched the developer's key recorded in `data/app-signers`.
No tool was given a real circumvention server. v2rayNG and NekoBox got a SOCKS5 server profile pointing at W6's test
tool on the same phone (`scripts/test-tool`, no password), so that their traffic left the phone from there or from
the tool itself; Orbot used the Tor network, as it always does. The test server was on the computer, at the
emulator's 10.0.2.2; through Tor, the address Android itself checks connectivity with.

| Tool | Version | Found by Watch | Chained TCP | Chained UDP | Notes |
|---|---|---|---|---|---|
| v2rayNG | 2.3.15 | 127.0.0.1:10808, owner confirmed, no password | yes, by address | yes | Sniffing replaces the destination with the HTTP Host header's name; private addresses go out directly from v2rayNG |
| NekoBox | 1.4.2 | 127.0.0.1:2080, owner confirmed, no password | yes, by address | yes | Drops the answer when the app closes its sending side first (half-close) |
| Orbot | 17.9.7-BETA-1 | 127.0.0.1:9050, owner confirmed, no password | yes, by a stand-in name, through Tor (HTTP 204) | refused, as Tor carries none | Proxy mode is "Power User Mode"; it asks for the alarms permission and a battery exemption |
| Hiddify | 5.5.5 | not reached on Android 15 | | | Its core did not start on this emulator; on Android 17 and on the A40 it was found and chained (below) |

In every case Watch found the tool by itself, from the table of tools, and Android named the tool as the owner of
its port; the chain was turned on from Watch's screen, with no port typed. The tool's own connections went
directly, under its own UID. The connection log held the chained app's flows with their bytes and no destination
(`tcp 2000 0.0.0.0:0`), as `Chain::log_destinations` off asks. With v2rayNG stopped and the chain still on, the
chained app got "no route to host", not a direct connection.

## What the tools do on their own

- **v2rayNG's sniffing** (on by default) reads the HTTP Host header or the TLS server name and sends the connection
  to that name rather than to the address asked for. A request whose Host header names nothing real fails. Browsers
  send honest headers, so this hurts tests more than users.
- **v2rayNG's routing** sends private addresses (10.0.0.0/8 and the like) out directly, from v2rayNG itself, by
  default: a chained app's traffic to a local server leaves the phone from the tool, not through its server.
  Watch keeps its promise (nothing of the chained app goes directly from the app); where the tool sends it is the
  tool's setting.
- **NekoBox and half-close.** When the app closes its sending side before the answer (toybox `nc` does so at the end
  of its input), NekoBox drops the answer. Watch passes the app's FIN on as TCP does; the same happens to any SOCKS
  client of NekoBox. HTTP clients keep their side open, so most apps are not affected. Worth reporting upstream.
- **Orbot's proxy mode** needs notifications, the alarms permission ("needed to keep OrbotService running when
  Orbot is not a system-wide VPN") and offers a battery exemption; the guides of W8 must say so. Its Connect button
  sat below the bottom bar on the 320 x 640 emulator screen.

## On the A40

The same day, on the Galaxy A40 (Samsung, Android 11), at the maintainer's word. Watch's tunnel covered only adb's
shell, the test tool and Orbot (the debug start's list of apps), so none of the phone's own apps went through it, and
nothing of theirs was read or printed. No computer on the phone's network was needed: the destination was the
address Android itself checks connectivity with.

- **The test tool,** with a password: Watch found it on 127.0.0.1:10870, Android confirmed it as the owner, and
  Watch saw that it wants a password. The shell, chained with that password, reached the check address by a
  stand-in name (HTTP 204); the tool's own connection went directly, under its UID.
- **Orbot 17.9.7** (the universal build) in "Power User Mode": on Android 11 it asked for no alarms permission; it
  offered the battery exemption and connected anyway. Watch found it on 127.0.0.1:9050, owner confirmed, no
  password. The shell reached the check address by a stand-in name through Tor (HTTP 204), and its UDP went nowhere.

- **v2rayNG 2.3.15 and NekoBox 1.4.2** (their arm64 builds, each signed with the developer key in
  `data/app-signers`), in proxy mode with a SOCKS profile pointing at the test tool: Watch found each (10808 and
  2080), owner confirmed, no password. Through each, the shell reached the check address by a stand-in name (HTTP
  204), and a DNS query over UDP to Quad9 came back (61 and 83 bytes) through the tool's relay.
- **What the tools did on their own:** NekoBox's own connection went to 223.5.5.5 on port 443, Alibaba's public
  DNS over HTTPS, which it uses by default for its own lookups; v2rayNG's settings show the same address as its
  default "Direct DNS". Watch showed it under the tool's own UID, as it should: this is the kind of thing Watch is
  for.

All were uninstalled afterwards, and Watch's tunnel stopped.

## On the emulators with Android 11 and 17

Later the same day, at the maintainer's word, the same three tools (their x86_64 and universal builds) were tested
the same way as on the A40, one at a time, first on the emulator with Android 17 (`dp-api37-16k`, 16 KB pages) and
then on the one with Android 11 (`dp-api30`). Each was in proxy mode, with a SOCKS profile pointing at the test
tool, or with Tor for Orbot. The tunnel covered only adb's shell, the test tool and the tool.

| Tool | Android 17 | Android 11 |
|---|---|---|
| v2rayNG 2.3.15 | 10808, owner confirmed; TCP by a stand-in name (HTTP 204); UDP to Quad9 (61 bytes) | the same |
| NekoBox 1.4.2 | 2080; owner unknown at the first search, confirmed at the next three; TCP and UDP (83 bytes) | 2080, owner confirmed; TCP and UDP |
| Orbot 17.9.7 | 9050, owner confirmed; TCP through Tor; UDP refused | the same |

In every case Watch found the tool with no port typed. Chaining took no password. The tool's own connections showed
under its own UID. These were NekoBox's DNS over HTTPS to 223.5.5.5 and Orbot's connections to Tor relays.

What Android 17 added:

- **The local network permission.** v2rayNG (target SDK 37) asked for `ACCESS_LOCAL_NETWORK` when it started. The
  dialog called it finding and connecting to nearby devices. It was declined, and v2rayNG worked anyway. Orbot
  (target 37) declares the permission but did not ask for it, was not granted it, and worked too. NekoBox (target
  35) got it without asking, as Android grants it to apps built for older versions. A tool's proxy on 127.0.0.1 is
  on loopback, which the permission does not cover. A user who refuses it loses nothing that Watch needs.
- **16 KB pages.** NekoBox's `libgojni.so` is not aligned to 16 KB pages, so Android 17 on a 16 KB device runs it
  in its compatible mode and warns once with a dialog. It still worked. v2rayNG and Orbot gave no such warning.
- **Orbot's power user mode** asked for the alarms permission there, as on Android 15, and offered the battery
  exemption. It connected with "Connect anyway". On Android 11 it asked only for the battery exemption, as on
  the A40.

NekoBox's unknown owner happened once. The first search ran six seconds after the tunnel started, and Android named
no owner of the port. The next three searches named NekoBox. It did not happen again when Orbot was searched one,
three and six seconds after the tunnel started, and not on Android 11. Watch still offered the chain: an unknown
owner does not block it, and only a port that Android names as another app's is skipped. Android returns no owner
for a UID that the VPN does not cover. The tool was inside the tunnel here, so that is not the cause. It is to be
watched for in W6's acceptance runs.

The tools and the test tool were uninstalled from both emulators afterwards. Watch's debug build stays on both, as
before.

## Hiddify

Its first screen asks the user to accept its terms (accepted for the test emulator at the maintainer's word) and
offers analytics, off by default and left off. Its proxy mode is "Proxy service only", and it shows a guide for it
with 127.0.0.1 and port 12334, as the table of tools says. A `socks5://` link was refused as a profile; a sing-box
JSON with one SOCKS outbound to the test tool was taken. Connecting then failed with "background core is not
started yet" and stayed at "Connecting…", and port 12334 never opened, after a restart of the app too; the
emulator itself ended during Hiddify's first connection. Watch was never reached.

Later that day, at the maintainer's word, Hiddify's terms were accepted on the emulators with Android 17 and 11, with
analytics left off. The same sing-box profile was used, and the same proxy mode.

- **Android 17** (`dp-api37-16k`): Hiddify connected, and 12334 opened on 127.0.0.1 and `[::1]`. Watch found it,
  owner confirmed, no password. The shell reached the check address by a stand-in name (HTTP 204), and Quad9 over
  UDP (61 bytes).
  - **Its password.** With "Require password" on, Watch saw at once that the port wants one. Chained with no
    password, the shell got "no route to host" and nothing went out directly. Chained with the user `hiddify` and
    the "Proxy secret", TCP and UDP went through. The same secret with the user `watch` was refused. So Hiddify
    checks the user name, and Watch's `hiddify` for this tool is right.
  - **Its own requests** went through its outbound, so through the test tool. These were DNS over TCP to 8.8.8.8,
    `captive.apple.com` (a connectivity check, likely the source of its "Delay" line), and ip-api.com and ipapi.co (IP
address services, likely behind its "Country" and "IP address" lines).
    Directly, it made only lookups to Watch's DNS address. Hiddify targets SDK 36, so Android gave it
    `ACCESS_LOCAL_NETWORK` without asking.
  - **A review prompt.** Right after the first connection, Hiddify opened Google Play's in-app review dialog,
    under the Google account on that emulator. Nothing was submitted ("Not now").
- **Android 11** (`dp-api30`): the emulator ended at Hiddify's first connection, as on Android 15. The host kernel
  logged a segfault in the emulator's RenderThread. It ended again with software rendering
  (`-gpu swiftshader_indirect`), with nothing in the logs, and again after Hiddify's data was cleared. Between those
  runs, Hiddify's own log said why it stayed at "Connecting…": its screen could not reach its background core over
  gRPC, failing with "CERTIFICATE_VERIFY_FAILED: self signed certificate". That is most likely what was left of a run
  cut short. Watch was not involved: Hiddify had not opened its port, and Watch's tunnel was not running.

- **The A40** (Android 11, arm64), at the maintainer's word for the download, the test and its terms. The build was
  `Hiddify-Android-arm64.apk` 5.5.5, signed with the developer key in `data/app-signers`. Analytics stayed off. The
  tunnel covered only adb's shell, the test tool and Hiddify. Hiddify connected, and 12334 opened. Google Play's
  review dialog came up again, under the phone's account. Nothing was submitted ("Not now"). Watch found Hiddify,
  owner confirmed, no password. The shell reached the check address by a stand-in name (HTTP 204), and Quad9 over
  UDP (61 bytes). Afterwards Hiddify and the test tool were uninstalled, the clipboard was cleared of the test
  profile, and Watch's tunnel stopped.

So Hiddify in proxy mode is found and chained on Android 17 and on a real phone with Android 11, with or without its
password. On the x86_64 emulator images of Android 11 and 15 the emulator itself stops at its first connection.
That is the emulator's matter, not Hiddify's or Watch's. Hiddify was uninstalled from both emulators afterwards.

## Still to do

- The rest of ADR 0038's lab ([notes](2026-11-chain-lab.md)): ECH in a browser that offers it, the ten apps of W3,
  and the delay of other record types through each real tool, Tor most of all.
