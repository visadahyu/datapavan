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
| Hiddify | 5.5.5 | not reached | | | Its core did not start on the emulator (below) |

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

## Hiddify

Its first screen asks the user to accept its terms (accepted for the test emulator at the maintainer's word) and
offers analytics, off by default and left off. Its proxy mode is "Proxy service only", and it shows a guide for it
with 127.0.0.1 and port 12334, as the table of tools says. A `socks5://` link was refused as a profile; a sing-box
JSON with one SOCKS outbound to the test tool was taken. Connecting then failed with "background core is not
started yet" and stayed at "Connecting…", and port 12334 never opened, after a restart of the app too; the
emulator itself ended during Hiddify's first connection. Watch was never reached. It is to try again on the A40,
with an arm64 build, and with a profile of the kind Hiddify expects.

## Still to do

- Hiddify, on the A40 or with another profile.
- The four tools on the emulators with Android 11 and 17.
- The rest of ADR 0038's lab: Chrome and Local Network Access with stand-ins, ECH through a tool, the ten apps of
  W3, strict Private DNS, and the delay of other record types through each tool.
