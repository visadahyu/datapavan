# The table of tools (before W1)

Notes on `data/tools/` ([DESIGN.md §13.2](../DESIGN.md#132-v020-watch-the-connection-log-next-to-circumvention-tools), "Before W1"), read on
2026-11-09. `tools.tsv` has 48 rows: the 41 packages of `data/app-signers/apps.tsv` and 7 tools
the project's research of November 2026 names that are not in that list yet (Husi, SagerNet, V2Box, Npv Tunnel,
NetMod, HTTP Injector, 1.1.1.1 + WARP). RethinkDNS, NetGuard and AdGuard were left out: they consume a
SOCKS5 upstream rather than offer one. `sources.tsv` has 376 rows of evidence.

Of the 480 machine-readable cells (48 rows, 10 columns), 260 are settled by a primary source, 51 are
`unknown` or carry a `?`, and 169 are `-` (does not apply, mostly proxy columns of VPN-only apps and
messengers).

Every source is the tool's own code at a release tag or commit, its official docs, or its store
listing. One third-party source is used, and marked: the runetfreedom report on Habr (April 2026),
for V2Box and Npv Tunnel only.

## Corrections to the earlier research

- **Amnezia VPN has no local proxy on Android.** The local proxy (Xray on 127.0.0.1:10808, Premium) is
  compiled only when `AMNEZIA_DESKTOP` is set, which excludes Android; `isSupported()` returns false
  there. On a phone, 10808 means v2rayNG (or perhaps MahsaNG), not Amnezia.
- **Happ has no documented proxy mode on Android.** Its official docs mark `proxy-enable` and
  `tun-enable` as desktop only. The docs also describe SOCKS and HTTP inbound passwords
  (`socks-auth-mode: auto` makes credentials and gives them to the tunnel), without naming platforms.
- **Orbot moves its ports.** If 9050 or 8118 is taken, `checkPortOrAuto` counts up to the next free
  port. With InviZible also installed (same Tor ports), Orbot may be on 9051.
- **MahsaNG's public source cannot settle anything.** The tree at tag v18 (October 2026) still builds
  `com.MahsaNG.EMS` version 1.8.5. Every MahsaNG value carries a `?`.
- **Oblivion v8's tag points to commit 739da893.** The research quoted 915e7864, which is the tag
  object, not the commit. Values are the same.

Agreeing with the earlier research, and now pinned to release tags: v2rayNG's HTTP shares 10808 in Xray
builds; Hiddify closes its local port in VPN mode unless the user asks; Clash Meta for Android has no
port of its own (profile only) and its proxy mode is "Route System Traffic" turned off; Psiphon,
Outline, WireGuard, Lantern (release builds) and Proton have no proxy mode.

## Facts that shape W6

- **Shared default ports.** 10808: v2rayNG and its F-Droid flavour (MahsaNG unverified). 9050: Orbot and
  InviZible (three packages). 2080: NekoBox, Husi, Exclave, SagerNet. 1080: Shadowsocks and ByeByeDPI.
  8118: Orbot, and InviZible when its HTTPTunnel is on. A port is a hint, never an identification.
- **Ports that shift with the Android user.** NekoBox, Husi, Exclave, SagerNet and Shadowsocks add the
  calling user's number to the default. In the main user it is 0; in a work profile or second user the
  port moves (for user 10, 2090). Android 17 blocks loopback between profiles anyway.
- **No password possible:** NekoBox (the mixed inbound has no user setting), ByeByeDPI, Oblivion,
  Shadowsocks, SagerNet. Tor (Orbot, InviZible) accepts any username and password but never asks for
  one; it uses them to isolate streams. Watch can send a random pair to Tor for isolation, not for
  protection.
- **Optional password:** v2rayNG, Exclave, Husi, FlClash, Hiddify (user name fixed to `hiddify`), Karing,
  WG Tunnel, sing-box and Clash Meta (in the profile). Watch's "offer a generated password" fits these.
- **No UDP:** Orbot and InviZible (Tor carries TCP only; UDP ASSOCIATE is refused). Shadowsocks drops
  to TCP only when a plugin is used without a UDP fallback profile.
- **ByeByeDPI is not a tunnel.** It reshapes packets to get past DPI and sends traffic straight out.
  Names in SOCKS requests are resolved by ByeDPI with the system resolver, so DNS goes to the network.
  Chaining through it hides nothing; Watch should say so.
- **Loopback ports left open in VPN mode** (`proxy-in-vpn`): v2rayNG, NekoBox, Husi, Exclave, SagerNet,
  FlClash, Shadowsocks, ByeByeDPI, Oblivion, Orbot, InviZible, Psiphon (on a port chosen at run time),
  and, by a third-party report only, V2Box and Npv Tunnel. This matters less for W6, since Watch takes
  the VPN slot, but it is a privacy fact the audit app could show.

## Unverified or contradictory values

- **Karing:** whether turning TUN off on Android runs without VpnService. The switch is shown on every
  platform, but the Android service plugin (`vpn-service`) and the core build are not public. UDP and
  domain names are inferred from upstream sing-box, since Karing's fork was not read.
- **Happ (both packages), V2Box, Npv Tunnel, NetMod, HTTP Injector, 1.1.1.1 + WARP:** closed source. No
  local port, binding, UDP or password option is documented for Android. HTTP Injector's 8989 comes
  from an undated manual that still names Android 4.0. NetMod's "proxy tethering" is named in its
  listing only. WARP's per-app setting on Android was not found in Cloudflare's docs.
- **MahsaNG:** every value (stale public tree).
- **Defyx VPN and Lantern:** VPN only in the public code, but the cores (DXcore, Lantern's radiance)
  were not read, so a loopback listener in VPN mode is unknown. Lantern's "stealth-novpn" builds ship
  under other package names and were not traced.
- **Tor VPN:** no SOCKS listener in the app; onionmasq itself was not read (`no?`).
- **WG Tunnel:** whether the proxy listeners also run in VPN mode (`no?`; proxy is a separate tunnel
  mode).
- **InviZible beta (`pan.alexander.tordnscrypt`) and Google Play (`.gp`) builds:** read from the stable
  branch only.
- **Proton VPN (F-Droid) and v2rayNG (F-Droid flavour):** same source as the main build.
- **Not checked:** WireGuard export in NekoBox, Husi and Hiddify (only import was found); Oblivion
  versions 1 to 7 (warp-plus core, research says 127.0.0.1:8086); FlClash's and Karing's Clash API
  defaults.
- **`no` means "not found in the source at the cited commit"** for features like WireGuard import or a
  local listener. Store listings and marketing text were not taken as proof of absence.

## What only a device test can settle

W6 tests v2rayNG, NekoBox, Hiddify and Orbot on the A40 and the emulators. For each, in proxy mode:

- **v2rayNG:** 10808 answers the SOCKS5 greeting with `05 00`, and an HTTP CONNECT on the same port; with
  a username and password set it answers `05 02`; UDP ASSOCIATE carries a DNS query; the random-port
  option is off on a fresh install; proxy mode keeps running when Watch's VPN starts.
- **NekoBox:** 2080 is a mixed port with no password; UDP ASSOCIATE works; the port in a work profile
  (expected 2080 plus the user number).
- **Hiddify:** "Proxy service only" opens 12334 on 127.0.0.1 (and ::1 with IPv6 on); with "local proxy
  auth" on, the greeting asks for user `hiddify` and the secret; Clash API on 16756 answers on
  loopback (a privacy fact).
- **Orbot:** Power User Mode opens 9050 and 8118; UDP ASSOCIATE is refused; with InviZible running first,
  Orbot's port moves to 9051 and Watch still finds it by owner, not by number.

Beyond W6, a device test (or a read of the APK by Datapavan's own tooling) is the only way to settle:
Karing with TUN off; the ports and passwords of Happ, V2Box, Npv Tunnel, NetMod and HTTP Injector;
MahsaNG v18's real ports and modes; Oblivion v8's "Proxy only mode" in the Android UI; and that Amnezia,
Tor VPN, Defyx and Lantern open no loopback listener on Android. For each listener found, Android's
owner lookup should name the app, so that a shared port never names the wrong tool.
