# 0034. Permissions for Watch

- Status: Proposed
- Date: 2026-11-09

## Context

Datapavan Watch (`org.visadahyu.datapavan.watch`) is the second app of
[ADR 0029](0029-network-access-for-v0.2.md): a local VPN that passes every app's traffic on to its
real destination over protected sockets, logs flows by app UID, chains the apps the user picks
through a circumvention tool's local SOCKS5 proxy, can carry a WireGuard configuration as its
upstream, offers its log read-only to the audit app, and has a Quick Settings tile and onboarding
for always-on VPN and battery managers ([DESIGN.md §13.2](../DESIGN.md), W1 to W9). It is signed with
the audit app's key, has minSdk 29 (Android 10) and targetSdk 37 (Android 17), and ships on GitHub,
the website and F-Droid, not on Google Play.

W1's build fails if Watch's merged manifest holds anything this ADR does not list. So every feature
of 0.2.0 needs its permission settled now, for each Android version from 10 to 17. The audit app keeps
exactly the permissions of [ADR 0014](0014-v0.1-permissions.md).

What the spikes already showed:

- The system-stack engine works only with Watch inside its own tunnel, calling `protect()` on each
  upstream socket ([packet-engine spike](../spikes/2026-11-packet-engine.md), finding 6).
- `getConnectionOwnerUid` names the UID behind a tool's loopback proxy port while the tool is inside
  the tunnel, but `getPackagesForUid` then returned nothing. The spike's Watch declared no `<queries>`
  at all ([its manifest](../../spikes/packet-engine/android/watch/src/main/AndroidManifest.xml)).
- Android 17 gates private addresses for apps that target it, but not loopback (finding 7, and "Who
  owns a local proxy port").
- On the A40, an intent query for `android.net.VpnService` missed a well-known VPN app whose service
  is not exported ([M2 spike](../spikes/2026-10-m2-access.md)). This is the case behind "a `<queries>`
  entry missed a VPN app". The M2 miss came from a run-time intent query, which returns only exported
  services to another app [unverified]; a `<queries>` intent follows the same rule, because Android
  matches visibility by intent only against exported components [code]. WireGuard, Mullvad, Proton VPN
  and PCAPdroid all declare their VpnService `exported="false"` [source], so a `<queries>` intent for
  `android.net.VpnService` would miss all four.

Tags used below: **[doc]** Android's documentation; **[code]** read in AOSP source
(`android-17.0.0_r1` unless said otherwise), not tested on a device; **[device]** measured in one of
our spikes; **[source]** another app's published source; **[unverified]** reasoning or memory that was
not checked.

## Decision (proposed)

### Watch requests these permissions

1. **`INTERNET`** (normal, granted at install, all versions). Every socket Watch opens needs it: the
   protected upstream connections, the engine's own listener that terminates rewritten connections
   ([ADR 0012](0012-packet-engine.md)), the upstream DNS, the SOCKS5 client on the tool's loopback
   port, and WireGuard's UDP. Without it no socket opens, loopback included [unverified: Android's
   rule that sockets need the network group, not re-checked here]. It is the reason Watch exists
   (ADR 0029).

2. **`ACCESS_NETWORK_STATE`** (normal, all versions). Network callbacks for the network under the
   tunnel (switches, metered state), its `LinkProperties` (the network's DNS servers and whether
   Private DNS is on, W3) and `NetworkCapabilities` (another app's VPN, validation) [doc]. Without it
   these calls throw `SecurityException`: Watch could not find the network's resolver or notice a
   switch. Two calls Watch makes need no permission: `getConnectionOwnerUid` only checks that the
   caller is the VPN that covers the UID [code], and `setUnderlyingNetworks` belongs to the VPN itself.

3. **`CHANGE_NETWORK_STATE`, on Android 10 and 11 only** (`android:maxSdkVersion="30"`; normal).
   Watch is inside its own tunnel, so `registerDefaultNetworkCallback` reports Watch's own VPN [doc].
   From Android 12, `registerBestMatchingNetworkCallback` follows the network under the tunnel with
   `ACCESS_NETWORK_STATE` alone [code: `LISTEN_FOR_BEST`]. On 10 and 11, the way to learn which network
   Android itself would use is `requestNetwork`, which needs `CHANGE_NETWORK_STATE` [doc]; sing-box for
   Android does exactly this, for the same reason [source]. A request that the current network already
   satisfies brings up no other network [doc]. Without it, Watch on 10 and 11 would have to guess the
   default among all networks. From 12 on, the permission is not granted at all.

4. **`POST_NOTIFICATIONS`** (runtime from Android 13; no such permission before). For Watch's few
   notices: the tool stopped and chained apps are waiting (W6), the tunnel stopped, the WireGuard
   upstream is down. It is asked in context, when the user first turns Watch or chaining on, not at
   first start. Without it on 13 and later, Watch posts nothing: the same states show in Watch and in
   the tile's subtitle, and Android's own VPN key icon still shows that a VPN is on. On 10 to 12,
   notifications are on unless the user turns them off.

5. **`ACCESS_LOCAL_NETWORK`** (Android 17, API 37; runtime, protection level "dangerous", in the
   `NEARBY_DEVICES` group, so a grant of another permission of that group covers it [doc]; defined
   behind a feature flag in `android-17.0.0_r1` [code]). For apps that target 37, Android 17 blocks
   traffic to and from local-network addresses: on Wi-Fi or Ethernet, 10/8, 172.16/12, 192.168/16,
   100.64/10, 169.254/16, IPv6 link-local and on-link prefixes, multicast and broadcast; on cellular and
   VPN interfaces, only the subnets of their own addresses, multicast and broadcast [doc, code]. Loopback is not gated [device].
   The network's DNS server at port 53 is exempt, and so is DNS sent by Android's own resolver [doc,
   code]. Without the grant, a TCP connect times out and UDP fails with `EPERM` [doc].
   - **Why Watch needs it.** Every app's LAN traffic (printer, TV, NAS, the router's page) leaves the
     phone from Watch's protected sockets, and Android checks the socket's UID, which is Watch's
     [code]. Without the grant, every LAN destination fails for every app while Watch runs, except DNS
     to the router at port 53.
   - **Watch must not become a way around the check.** On the tunnel's interface only Watch's own
     address subnets are local, so an app's packets to 192.168.1.10 enter the tunnel unchecked [code;
     to test]. If Watch forwarded them under its own grant, any app could reach the LAN, which Android
     17 closed. So, on Android 17, Watch forwards a flow to a local-network address only for an app that holds
     `ACCESS_LOCAL_NETWORK` itself (apps that target 36 or lower hold it implicitly [doc]), and records
     the refused attempt, so the audit app can show which apps tried to reach the local network.
     This keeps the phone as it was without Watch, as W3 asks for DNS.
   - **Watch's own path must not depend on it.** The system-stack engine passes each TCP connection
     through a listener on the tunnel's address, from a second, rewritten address. In the spike both
     sit in 10.111.0.0/24 and fd00:111::/64, which Android 17 counts as local on the tunnel's interface
     [code]. With the permission denied, every TCP flow could fail [unverified: the spike ran with it
     granted]. W2 therefore gives the tunnel a /32 and a /128 address and keeps the rewritten address
     and the in-tunnel DNS address outside them, so that a denial touches only real LAN destinations.
   - **Upstream DNS.** Plain DNS to a resolver on the LAN at port 53 is exempt; DNS over TLS to it
     (port 853, Private DNS on "automatic") is not. Watch sends its upstream queries for the network's
     resolver through Android's resolver bound to the network under the tunnel (`DnsResolver`), which
     is exempt and keeps Private DNS as the phone had it [code; to test].
   - **Android 16** had an opt-in test mode, switched on over adb and gated by `NEARBY_WIFI_DEVICES`;
     it is deprecated [doc]. Watch does not request that permission. On 10 to 16 the LAN stays open as
     before.

### Package visibility: one `<queries>` entry, not `QUERY_ALL_PACKAGES`

Watch's own screens name only the user's tool and the apps the user picks for the chain. The log
keeps UIDs, and the audit app, which holds `QUERY_ALL_PACKAGES` (ADR 0014), names them. Watch declares
exactly:

```xml
<queries>
    <intent>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent>
</queries>
```

- **What it covers.** Every app with an exported launcher activity [code], which every app a user can
  open has. That includes the tools of the table, renamed forks, and tools whose VPN service is not
  exported, such as WireGuard: the launcher activity counts, not the VPN service. A tool that hides its
  icon by disabling a launcher alias stays visible, because Android matches the manifest, not the
  enabled state [code; to test]. WireGuard's app picker uses the same entry [source].
- **What it does not cover.** Apps without a launcher activity, mostly system components such as
  Google Play services, unless the system makes them visible (platform-signed or marked
  force-queryable) [code]. The chain picker therefore offers "all apps" as one choice, which the engine
  applies by UID without names, and lists the visible apps from `getInstalledApplications` rather than
  from a launcher query, so that tools with a hidden icon are listed too.
- **The rules that apply** (Android 11 and later; on Android 10 every app is visible [doc]): Watch
  itself; force-queryable system packages; the app that installed or updates Watch; apps named in
  `<queries>` by package, by intent (exported components only) or by provider authority (exported
  providers only); apps that interact with Watch, that is, start or bind its service, use its content
  provider or call it with `startActivityForResult`, so the audit app becomes visible when it reads
  the log; apps whose library Watch uses; and, in current AOSP, an app that defines a permission Watch
  requests [doc, code]. Being the active VPN gives no visibility: `getConnectionOwnerUid` returns a
  UID that Watch still cannot name without one of these rules [device].
- **Not an intent for `android.net.VpnService`.** It would miss the apps whose VPN service is not
  exported (the M2 miss) and adds nothing the launcher entry lacks.
- **Not `QUERY_ALL_PACKAGES`.** It adds only apps without a launcher activity, which Watch's screens do
  not need to name, and ADR 0029 keeps Watch to the VPN and its network access. The launcher entry
  already lets Watch see almost every app the user can open, so the privacy policy says that plainly.
  Watch writes no list of apps anywhere.
- **If the device test fails** (a tool of the table or a chained app stays nameless), the fallback, by
  amending this ADR, is first `<package>` entries generated at build time from `data/app-signers`, then
  `QUERY_ALL_PACKAGES`.

### The log interface (W5): checked at run time, no custom permission

Watch exports one read-only content provider (or a bound service; W5 chooses) with no
`android:permission`. Every call checks its caller:

- `Binder.getCallingUid()` must belong to exactly one package, `org.visadahyu.datapavan`;
- that UID must be signed with Watch's own key: `PackageManager.checkSignatures(Process.myUid(), uid)`
  returns `SIGNATURE_MATCH`, or `hasSigningCertificate` matches the published fingerprint (ADR 0024);
- any other caller gets nothing; `getType` returns null; nothing is written and no URI is granted.

The caller is visible to Watch because it uses Watch's provider [doc]. Before it reads, the audit app
checks Watch's certificate with ADR 0024's check, so a fake Watch cannot feed it a false log.

A custom permission with `protectionLevel="signature"` was the alternative. It is not chosen:

- It adds a `<uses-permission>` to the audit app, whose list ADR 0014 fixes.
- Install order: Watch, which would define it, usually comes after the audit app, which would use
  it. Current AOSP re-checks every app's grants when a package that defines permissions is installed
  [code, AOSP main], but older releases needed the using app to be reinstalled [unverified for 10 to
  12].
- Squatting: an app with another key that defines the same name first makes Watch's install fail,
  and if Watch is removed, another app can define the name again at a weaker level [doc].
  CVE-2019-2200, permissions that outlived an uninstall, is fixed from Android 10 [doc].
- Android's own guidance prefers a signature check at run time between apps of one developer [doc].

Datapavan Lite (ADR 0031) is signed by Google's key and so gets nothing from Watch, which fits ADR
0031: Lite stays without the VPN.

### Components guarded by system permissions (nothing requested)

- The VpnService: `android:permission="android.permission.BIND_VPN_SERVICE"` (signature, so only the
  system binds it) and `exported="false"`, as in WireGuard, Mullvad, Proton VPN and PCAPdroid. The
  system still starts and binds it, always-on included [code, device].
- The tile: `android:permission="android.permission.BIND_QUICK_SETTINGS_TILE"` (signature|recents),
  `exported="true"`, marked toggleable [doc]. `StatusBarManager.requestAddTileService` (Android 13) needs
  no permission; on 10 to 12 the user adds the tile by hand. From 14, the tile starts activities with
  the `PendingIntent` form of `startActivityAndCollapse` [doc].
- AndroidX's `ProfileInstallReceiver`, guarded by `DUMP`, as in the audit app.

### Watch does not request

- **`QUERY_ALL_PACKAGES`**: see above.
- **`FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`, `FOREGROUND_SERVICE_SPECIAL_USE`.** Watch
  does not call `startForeground`. Once the tunnel is established, Android binds the VpnService with
  `BIND_FOREGROUND_SERVICE` [code]. That puts Watch's process in the "bound foreground service" state,
  which keeps network access in Doze and battery saver [code] and should keep the started service
  from being stopped in the background [unverified]. WireGuard's app works this way, with neither the
  permission nor a `startForeground` call [source], and the spike's Watch ran a 12 h 43 min night on the
  A40 without one [device]. The VpnService reference still says a VPN app "must promote itself to the
  foreground" after a background start [doc]. Watch meets the intent of that by calling `establish()`
  at once in `onStartCommand`, inside the 60 s that Android allows an always-on start [code], even
  before its upstream is ready. If the device tests show Android or a vendor stopping Watch, the
  fallback is a foreground service of type `systemExempted`, with `FOREGROUND_SERVICE` and
  `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` (both normal); that type names VPN apps among the apps allowed
  to use it, and throws for others [doc]. Not `specialUse`, which is for cases no other type covers and
  is reviewed by hand on Play [doc]. Without a foreground service Watch is not in Android 13's Task
  Manager, so no one stops the firewall there by mistake.
- **`RECEIVE_BOOT_COMPLETED`.** With always-on VPN, Android starts Watch's VpnService itself when the
  user unlocks the phone and again after Watch is updated [code]. Onboarding recommends always-on with
  "Block connections without VPN" ([VPN.md](../VPN.md)). Without always-on, Watch stays off after a
  restart until the user turns it on, and the tile and Watch's screen say so.
- **`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.** It only allows a one-tap system dialog [doc]. Onboarding
  opens the system's list (`ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS`) or Watch's app page, and the
  health check reads `isIgnoringBatteryOptimizations`; neither needs a permission. Watch's network in
  Doze does not depend on the exemption (above). None of WireGuard, NetGuard, PCAPdroid, RethinkDNS,
  Mullvad and Proton VPN declares it; sing-box for Android does [source]. Samsung's sleeping-apps
  lists are separate and belong to the vendor guides (W9).
- **`CAMERA`.** A WireGuard QR code is read from an image the user picks: the photo picker where
  Android has it (11 and later, with Google's system updates), the documents screen
  (`ACTION_OPEN_DOCUMENT`) otherwise. Neither needs a permission [doc]. The decoder must bring no
  manifest entries of its own (ZXing's core library, for example, rather than ML Kit, which relies on
  Google Play services) [unverified]. A camera permission in the app that holds `INTERNET` would
  undercut the trust story and, later, the sensor log of 0.2.1. The cost: a QR code shown on another
  screen must first be photographed with the camera app, and Watch then says that the photo holds the
  private key and should be deleted. A configuration can also come from a file or be pasted.
- **`WAKE_LOCK`.** The engine is event-driven (VPN.md), and the spike's night ran without a wake lock
  [device]. WorkManager would add it, so Watch does not use WorkManager.
- **`ACCESS_WIFI_STATE`, location, `READ_PHONE_STATE`.** Rules per Wi-Fi network or for roaming belong
  to v0.3 and would need an amendment (Wi-Fi names need location access).
- **`NEARBY_WIFI_DEVICES`.** Only Android 16's deprecated test mode used it.
- **`PACKAGE_USAGE_STATS`.** Foreground or background per flow is worked out in the audit app.
- **`INTERACT_ACROSS_USERS`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`.** A work profile or
  Private Space has its own VPN; Watch draws no overlays and does not update itself (F-Droid and
  Obtainium do).
- **A custom permission for the log**: see above.

### Compared with current VPN apps

Source manifests at the commits in Sources (merged manifests can hold more):

| App | Foreground service | Visibility | Boot | Notifications | Local network | VpnService exported |
|---|---|---|---|---|---|---|
| WireGuard | none | `<queries>` MAIN/LAUNCHER | yes | no | no | no |
| NetGuard | `specialUse` | `QUERY_ALL_PACKAGES` | yes | yes | no | yes |
| PCAPdroid | `specialUse` | `QUERY_ALL_PACKAGES` | yes | yes | yes | no |
| RethinkDNS | `systemExempted`, `connectedDevice` | `QUERY_ALL_PACKAGES` | no | yes | yes | yes |
| Mullvad | `systemExempted` | `QUERY_ALL_PACKAGES` | yes | yes | no | no |
| Proton VPN | `systemExempted` | `QUERY_ALL_PACKAGES` | yes | yes | no | no |
| sing-box for Android | `systemExempted` | `QUERY_ALL_PACKAGES` | yes | yes | yes | no |
| **Watch** | none | `<queries>` MAIN/LAUNCHER | no | yes | yes | no |

Watch requests fewer permissions than any of them. WireGuard is closest, and holds camera, boot and
self-update permissions that Watch does not. The rule that Watch forwards LAN
traffic only for apps holding their own grant goes beyond what these apps were seen to do
[unverified: their code was not read for it].

## Permissions by Android version

"Install": normal permission, granted at install. "Runtime": the user is asked.

| | 10 (API 29) | 11 (30) | 12, 12L (31, 32) | 13 (33) | 14 (34) | 15 (35) | 16 (36) | 17 (37) |
|---|---|---|---|---|---|---|---|---|
| `INTERNET` | install | install | install | install | install | install | install | install |
| `ACCESS_NETWORK_STATE` | install | install | install | install | install | install | install | install |
| `CHANGE_NETWORK_STATE` (max 30) | install: `requestNetwork` | install: `requestNetwork` | not granted: best-matching callback | not granted | not granted | not granted | not granted | not granted |
| `POST_NOTIFICATIONS` | no such permission; notifications on | same | same | runtime, asked in context | runtime | runtime | runtime | runtime |
| `ACCESS_LOCAL_NETWORK` | unknown, ignored; LAN open | same | same | same | same | same | ignored; LAN open (adb test mode only) | runtime; without it LAN through Watch fails, DNS at port 53 works |
| `<queries>` MAIN/LAUNCHER | no effect: every app visible | launchable apps visible | same | same | same | same | same | same |
| Not requested: `QUERY_ALL_PACKAGES` | would change nothing | would add apps without a launcher | same | same | same | same | same | same |
| Not requested: foreground service | system binding keeps Watch | same | same | same (and not in Task Manager) | fallback would be `systemExempted` | same | same | same |
| Not requested: `RECEIVE_BOOT_COMPLETED` | always-on starts Watch at unlock and after updates | same | same | same | same | same | same | same |
| Not requested: `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | settings screen instead | same | same | same | same | same | same | same |
| Not requested: `CAMERA` | QR from a file (documents screen) | photo picker if updated, else documents | same | same | same | same | same | same |
| Guard: `BIND_VPN_SERVICE` | yes | yes | yes | yes | yes | yes | yes | yes |
| Guard: `BIND_QUICK_SETTINGS_TILE` | user adds the tile | same | same | `requestAddTileService` | and `PendingIntent` starts | same | same | same |
| Library: `…watch.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` | guards Watch's runtime receivers | same | same | declared; platform flag used instead [unverified] | same | same | same | same |

## Allowlist for the build check (W1)

The check runs on the merged manifest of every variant of `:watch`, wired like the audit app's
`ForbiddenPermissionsCheck` in `android/app/build.gradle.kts`, but as an allowlist. It fails on
anything not listed here.

`<uses-permission>`, exactly these:

```
android.permission.INTERNET
android.permission.ACCESS_NETWORK_STATE
android.permission.CHANGE_NETWORK_STATE        (android:maxSdkVersion="30" required)
android.permission.POST_NOTIFICATIONS
android.permission.ACCESS_LOCAL_NETWORK
org.visadahyu.datapavan.watch.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
```

`<permission>` definitions, only this one, with `protectionLevel="signature"`:

```
org.visadahyu.datapavan.watch.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
```

`<queries>`: exactly the one MAIN/LAUNCHER intent above. Libraries can add `<queries>` too, so they are
checked like permissions.

Exported components: the launcher activity; the tile service, guarded by `BIND_QUICK_SETTINGS_TILE`;
the log provider (or service), with no permission attribute and the run-time check; and
`androidx.profileinstaller.ProfileInstallReceiver`, guarded by `DUMP`. The VpnService is not exported
and is guarded by `BIND_VPN_SERVICE`.

Added by libraries: the `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` pair comes from androidx.core (the
1.17.0 AAR declares `${applicationId}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` as a signature
permission and requests it); androidx.core uses it for receivers registered as not exported below
Android 13 [unverified]. If a debug build ever gets an application ID suffix, the name follows it.
The audit app's packaged release manifest (built 2026-11-08) shows only this pair and the
`ProfileInstallReceiver`; androidx.window adds two optional `<uses-library>` entries, which are not
permissions. WorkManager 2.10.0 would add `WAKE_LOCK`, `ACCESS_NETWORK_STATE`, `RECEIVE_BOOT_COMPLETED`
and `FOREGROUND_SERVICE`. Any such addition fails the build and is either removed with
`tools:node="remove"` and a comment saying why the library works without it, or added here by an
amendment.

## Consequences

- **The build check** of W1 is an allowlist over permissions, permission definitions, `<queries>` and
  exported components, not only a deny list.
- **What users read.** The privacy policy, the store texts and F-Droid's listing name Watch's five
  permissions (one only on Android 10 and 11, one only on 17) plus AndroidX's internal one, and say
  that Watch can see the apps that
  have an icon, to name the user's tool and the apps the user picks, and keeps no list of them. ADR
  0029's sentence stays true as written.
- **Requirements this ADR puts on the engine (W2, W3):** call `establish()` at once; give the tunnel a
  /32 and a /128 address with the rewritten address and the in-tunnel DNS address outside them; send
  upstream queries for the network's resolver through `DnsResolver` on the network under the tunnel;
  forward local-network flows only for apps that hold their own grant, and record refusals.
- **Onboarding (W9)** asks for the local-network permission on Android 17 and says that each app still
  needs its own; asks for notifications in context; recommends always-on with "Block connections
  without VPN"; opens the battery settings and the vendor guides.
- **The threat model** (DESIGN §8) gets a line for Watch's exported components: the launcher, the
  tile, the log interface with its run-time check, and `ProfileInstallReceiver`.
- **Lite** cannot read Watch's log, as ADR 0031 intends.
- **Without always-on,** Watch is off after a restart and perhaps after an update (open question 5).
- **A tool in a work profile or Private Space** cannot be chained: each profile has its own VPN, and
  Android 17 blocks loopback traffic across profiles [doc].
- **Planned amendments if the tests fail:** `<package>` entries, then `QUERY_ALL_PACKAGES` (question
  1); a `systemExempted` foreground service (2); `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (8).
- **Outside this ADR:** 0.2.1's sensor log, and the advanced mode with `GET_APP_OPS_STATS` and `DUMP`
  granted over USB, which DESIGN says needs its own ADR.

## Open questions (device tests)

1. **Names.** With only the MAIN/LAUNCHER entry, on the A40 (Android 11) and emulators 11 to 17: does
   `getPackagesForUid` name v2rayNG, NekoBox, Hiddify, Orbot, WireGuard, MahsaNG and Oblivion; a tool
   whose launcher alias is disabled; and what share of the UIDs in W3's ten-app session Watch cannot
   name.
2. **No foreground service.** Watch stays up and every app's traffic flows: started by always-on at
   unlock on 10 to 17; over a 24-hour idle on the A40; through the A56 battery windows of W9; in Doze
   forced with `adb shell dumpsys deviceidle force-idle`; with its task swiped away; on Samsung after
   days without opening Watch (sleeping apps).
3. **Local network on Android 17** (emulator, and a phone when one is available), with Watch's grant
   denied: does TCP through the engine work once the tunnel has /32 and /128 addresses, and fail with
   the spike's /24; does Watch's upstream to a LAN host fail while DNS to the router at port 53 works,
   DNS over TLS to it fails, and `DnsResolver` works. For an app that targets 37 without the grant: do
   its packets to a LAN address enter the tunnel. How Watch reads another app's grant by UID, the
   implicit grant of apps targeting 36 or lower included. mDNS, SSDP and broadcast with Watch's routes.
4. **The tile** turns Watch on without a foreground service on 10 to 17, and opens Watch when consent is
   missing.
5. **After an update without always-on:** does Watch come back, and could a `MY_PACKAGE_REPLACED`
   receiver (no permission needed) restart it without a foreground service.
6. **Unused-app hibernation** (Android 11 and later): does a running VPN count as use, or are
   `POST_NOTIFICATIONS` and `ACCESS_LOCAL_NETWORK` revoked after months without opening Watch
   [unverified]. If so, onboarding opens the "pause app activity if unused" switch, which needs no
   permission.
7. **Android 10 and 11:** `requestNetwork` reports the network under the tunnel, not Watch's VPN, and
   brings up no second network, on the A40 and an Android 10 emulator.
8. **The battery exemption** on Samsung: does it change anything for Watch; if it does, request
   `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` by amendment.
9. **W5:** an app signed with another key, and an app with a shared UID, get nothing; the order in
   which the two apps are installed makes no difference.
10. **Other vendors** (a Pixel, a Xiaomi) for questions 1 to 4, the gap DESIGN §13.2 already names.

## Sources

All read on 2026-11-09.

Android documentation:

- Foreground service types: https://developer.android.com/develop/background-work/services/fgs/service-types
- Restrictions on starting foreground services from the background: https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- Task Manager and user stopping: https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping
- Local network permission: https://developer.android.com/privacy-and-security/local-network-permission
- Local network definition: https://developer.android.com/privacy-and-security/local-network-definition
- `Manifest.permission` reference (`ACCESS_LOCAL_NETWORK`, `ACCESS_NETWORK_STATE`, `BIND_VPN_SERVICE`, `BIND_QUICK_SETTINGS_TILE`): https://developer.android.com/reference/android/Manifest.permission
- Apps visible automatically: https://developer.android.com/training/package-visibility/automatic
- Declaring package visibility: https://developer.android.com/training/package-visibility/declaring
- Notification permission: https://developer.android.com/develop/ui/views/notifications/notification-permission
- `VpnService` reference: https://developer.android.com/reference/android/net/VpnService
- `ConnectivityManager` reference: https://developer.android.com/reference/android/net/ConnectivityManager
- Quick Settings tiles: https://developer.android.com/develop/ui/views/quicksettings-tiles
- `TileService` reference: https://developer.android.com/reference/android/service/quicksettings/TileService
- Doze and App Standby: https://developer.android.com/training/monitoring-device-state/doze-standby
- Photo picker: https://developer.android.com/training/data-storage/shared/photo-picker
- Custom permissions risks (also cites CVE-2019-2200 and the February 2020 bulletin): https://developer.android.com/privacy-and-security/risks/custom-permissions
- Defining custom permissions: https://developer.android.com/guide/topics/permissions/defining
- Android 17 changes for apps targeting it: https://developer.android.com/about/versions/17/behavior-changes-17
- Android 17 changes for all apps: https://developer.android.com/about/versions/17/behavior-changes-all

AOSP source, tag `android-17.0.0_r1` unless marked "main":

- `ACCESS_LOCAL_NETWORK` definition: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/res/AndroidManifest.xml
- Visibility by intent and provider, exported components only: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/pm/AppsFilterUtils.java
- Force-queryable packages and visibility through a requested permission: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/pm/AppsFilterImpl.java and (main, 1cdfff555f4a) https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/AppsFilterBase.java
- Grants re-checked when a permission's defining package is installed (main, 1cdfff555f4a): https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java
- Network access in Doze for the bound-foreground-service state: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/java/android/net/NetworkPolicyManager.java
- VpnService bound with `BIND_FOREGROUND_SERVICE`; always-on start with a 60 s allowance: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/connectivity/Vpn.java
- Always-on restarted at unlock and after an update: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/VpnManagerService.java
- `getConnectionOwnerUid`, `LISTEN_FOR_BEST`, local prefixes per interface (VPN and cellular: own subnets only): https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-17.0.0_r1/service/src/com/android/server/ConnectivityService.java
- The local-network check by socket UID and interface, system DNS exempt: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-17.0.0_r1/bpf/progs/netd.c

Other apps' sources:

- WireGuard Android (e7b3a3c11883): https://github.com/WireGuard/wireguard-android/blob/e7b3a3c11883/ui/src/main/AndroidManifest.xml, https://github.com/WireGuard/wireguard-android/blob/e7b3a3c11883/tunnel/src/main/AndroidManifest.xml, https://github.com/WireGuard/wireguard-android/blob/e7b3a3c11883/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java
- NetGuard (166df969c3ce): https://github.com/M66B/NetGuard/blob/166df969c3ce/app/src/main/AndroidManifest.xml
- PCAPdroid (135b32d77169): https://github.com/emanuele-f/PCAPdroid/blob/135b32d77169/app/src/main/AndroidManifest.xml
- RethinkDNS (07fe5373f8ae): https://github.com/celzero/rethink-app/blob/07fe5373f8ae/app/src/main/AndroidManifest.xml
- Mullvad VPN (95bc5f5cdeca): https://github.com/mullvad/mullvadvpn-app/blob/95bc5f5cdeca/android/app/src/main/AndroidManifest.xml
- Proton VPN (deb11fef4092): https://github.com/ProtonVPN/android-app/blob/deb11fef4092/app/src/main/AndroidManifest.xml
- sing-box for Android (a9e27320e8bf): https://github.com/SagerNet/sing-box-for-android/blob/a9e27320e8bf/app/src/main/AndroidManifest.xml, https://github.com/SagerNet/sing-box-for-android/blob/a9e27320e8bf/app/src/main/java/io/nekohasekai/sfa/bg/DefaultNetworkListener.kt

Library manifests (Google's Maven repository):

- androidx.core 1.17.0: https://dl.google.com/android/maven2/androidx/core/core/1.17.0/core-1.17.0.aar
- androidx.work work-runtime 2.10.0: https://dl.google.com/android/maven2/androidx/work/work-runtime/2.10.0/work-runtime-2.10.0.aar

This repository: [ADR 0012](0012-packet-engine.md), [ADR 0014](0014-v0.1-permissions.md),
[ADR 0024](0024-fake-copies-of-datapavan.md), [ADR 0029](0029-network-access-for-v0.2.md),
[ADR 0031](0031-datapavan-lite-on-google-play.md), [DESIGN.md §13.2](../DESIGN.md),
[VPN.md](../VPN.md), the [M2 spike](../spikes/2026-10-m2-access.md), the
[packet-engine spike](../spikes/2026-11-packet-engine.md), and the audit app's packaged release
manifest under `android/app/build/intermediates/packaged_manifests/`.
