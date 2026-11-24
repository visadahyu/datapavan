# Privacy policy

- **Effective:** 2026-11-07
- **Updated:** 2026-11-24, with Datapavan Advanced's lines for 0.2.0, which is not yet released
- **Responsible:** the Datapavan maintainer (mehdashti), until the Visadahyu Foundation is established

**Datapavan collects no data about you.**

## What this means in practice

- **No analytics, no crash reporting, no telemetry.** The app contains no third-party SDKs that could send data.
- **No accounts.** You never sign up and never give us anything.
- **No servers that receive user data.** The app contacts none. The project's website, datapavan.org, is static and keeps no access log. It keeps no record of the downloads it serves either. Downloads from GitHub and app stores fall under those services' own policies.
- **Everything stays on your phone.** All analysis happens on the device. Datapavan's own data lives in app-private storage.
- **No backups leave the phone.** Android cloud backup and device-to-device transfer are disabled for Datapavan's data.
- **Uninstalling deletes Datapavan's data.**

## What Datapavan keeps on your phone

- **The remediation plan's journal.** For each change you make through the plan: the app's package
  name, the time, the screen it opened, and what the app held before and after (its sensitive
  permissions, special access and VPN permission, and whether it was enabled and installed). It lets
  you undo a change and see whether one has come back. The journal screen deletes it in one tap.
- **The strict sensor review:** which access each app had when you reviewed it.
- **Your settings:** the appearance, and before Android 13 the language you chose.
- **The tracker scan's results,** so that unchanged apps are not scanned again, and **data packs** you
  imported.

All of it stays in app-private storage and is never backed up or sent. Anyone who can open Datapavan on
your unlocked phone can see it, as they can see the rest of the app.

**Datapavan Advanced, from 0.2.0, also keeps:**

- **A connection log, only if you choose to keep one.** You choose none, 1, 7 or 30 days; until you choose, it
  keeps nothing. Each record holds the app, where it connected (the address, the port and the name, with where
  Datapavan learned the name), the bytes each way, the time, and whether you were using the app then, it ran with
  its notification, or neither. Each record is encrypted under a key for its day that Android's keystore protects;
  on a phone with a screen lock, earlier days can be read only while it is unlocked. Days past your choice are
  deleted with their keys, and one tap deletes everything. For apps you send through your circumvention tool, the
  log keeps no destination unless you turn that on. When an app uses a proxy of its own, the record keeps by
  default that the app used a proxy, which kind, when, the facts that name no address (such as whether a password
  was sent unencrypted, or whether it is the proxy in Android's settings), and which known trackers its
  connection's names matched (by their εxodus ids, which name a tracker's company, not a destination). Only while
  "Log where apps connect through your tool, WireGuard or a proxy" is on does it also keep where the proxy is (its
  address and the name a DNS answer gave it), what the app asked it for and, for a messenger's proxy, the name its
  connection sent in place of its destination. It never keeps a proxy's password, which Datapavan reads past and
  does not store, and says only that one was sent unencrypted. The records of a connection taken for a messenger's
  proxy wait ten minutes in memory before they are written, so that one Datapavan corrects in that time is written
  correct. When tracker blocking refused a connection, its record says so, with the name of the tracker's software
  package (for example `com.google.firebase:firebase-analytics`), which names a tracker, never a destination, and
  is kept whatever the switch for your tool says.
- **Each app's recent traffic, for the "Now" view,** in memory only. It is gone when the firewall stops. Where an
  app's own proxy is (its address, name and network, and for a messenger's proxy the name its connection sent) is
  shown there, in memory only, while the connection is open and for ten minutes after it ends, whatever "Log where
  apps connect through your tool, WireGuard or a proxy" says. Where the app asked the proxy to go is shown only
  while that switch is on. To tell Telegram's, WhatsApp's and Signal's own connections from their proxies', it
  also notes in memory, until the firewall stops (and across the tunnel's own restarts, which hand it on): when
  each of them last connected to its maker's network, which counts for ten minutes; the names Telegram and
  WhatsApp looked up through Datapavan, as hashes that cannot be read back, each for an hour; and when Signal last
  reached a payment's or a debug log's server, which counts for ten minutes. Nothing of it is written anywhere.
  With tracker blocking on, it also counts in memory how many lookups and connections blocking stopped for each
  app and tracker, and since when.
- **Your circumvention tool's settings:** whether apps go through it and which ones, the tool's host and port, and
  the password Datapavan made for it, which is encrypted under a key that Android's keystore protects.
- **The apps you leave out of the firewall,** which then go to the internet without it: their names, until you take
  them back.
- **Tracker blocking's settings, if you turn it on** (off until you do): whether it is on, whether it includes
  browsers and your tool's own lookups, when a pause ends, and the apps and trackers you allowed, by the app's
  package name and the tracker's host, with when each allowance ends. To tell, for a few hosts that serve both
  tracking and an app's own sign-in, which one an app uses, it reads the tracker scan's results already kept on
  the phone. With the setting for phones that may be searched (planned), these settings stay behind Datapavan's
  own lock and go with a wipe, and nothing of blocking is recorded.
- **The WireGuard configurations you add,** at most eight: each one's text, which holds its private key and its
  server, and the name you gave it, encrypted under a key that Android's keystore keeps (in the phone's separate
  security chip where it has one), in storage that is never backed up or moved to another phone. Beside them, also
  encrypted, under a key that opens even while the phone is locked: which apps go through each, which one is the
  default, and whether its apps reach your local network directly. With the setting for phones that may be searched
  (planned), the configurations go under a second key, which opens only while the phone is unlocked: if Datapavan
  starts again while the phone is locked, their apps wait until you unlock it, and one notification, naming no
  configuration, says so. Removing a configuration deletes its text and name; if you chose that its apps wait, their names stay
  until you give them another way. A photo of a QR code that the phone's camera takes for Datapavan is deleted as
  soon as it is read, also when it holds no code or you cancel; a picture you pick from your gallery stays there,
  and Datapavan says that it holds the configuration's key.

## Version 0.1 cannot open network connections

Datapavan Basic 0.1 does not request the INTERNET permission, so Android itself prevents it from
opening network connections. The build fails if any component tries to add that permission. Like any
app, it can still hand information to another app when you ask it to, for example when you open a link.

What Android itself does is outside Datapavan's control. On phones with Google's services, Play Protect may give Google information about the apps you install from any source, Datapavan included, and may send it an unknown app to check. You can turn part of this off in Play Protect's settings in the Play Store. Datapavan's hardware check can also make Android contact Google: on phones that get their attestation keys from Google's provisioning server, a check that finds none left asks Android for more (Android 13 tells the provisioning service, and from Android 14 the keystore asks it), and Android fetches them over its own connection. Datapavan sends nothing itself.

## What Datapavan Advanced connects to

Datapavan Advanced, from 0.2.0, passes your apps' traffic on to where they send it, through the firewall on the
phone; none of it goes to us. Of its own, it looks up the names that apps which go directly ask for. By default it
uses Oblivious DoH: each question is encrypted on the phone for a resolver (the "target"), and sent through a relay
run by another operator in another country. The relay sees your address but not the question; the target sees the
question but not your address. The default relays and targets are Numa's relay in Germany with Cloudflare's target
in the United States, and crypto.sx's relay on Fastly with dnscry.pt's target in Germany; you can see and change
them in Datapavan Advanced. When the first pair is slow to answer, Datapavan asks the second too, so both targets may see that
name. Instead, you can choose an encrypted resolver from a list, each with its operator, country, what it says it
logs and what it blocks, or give your own, which Datapavan tests with one question before it keeps it; that
resolver then sees your address and the names. When the resolver you chose does not answer, Datapavan uses Oblivious
DoH and then the others, unless you turned on "Only this resolver". When none of these answers on your network,
Datapavan uses your network's DNS resolver, which can see the names; Datapavan says so while it lasts, and with
"Strict" on it never does. Names of your own network (a printer, a router) always go to your network's resolver, and
a name under your network's own domain goes there only when the internet does not know it. Datapavan keeps no list
of the names apps look up, apart from the connection log, if you keep one; it keeps answers in memory for up to a
day. A resolver's key changes, about daily for some: Datapavan then fetches the new one minutes later, apart from
any question, first from resolvers that run none of the targets, through your circumvention tool when it is on, and
only last from that resolver directly, which shows it your address but no question.

When you send apps through your circumvention tool, their lookups go to the tool, and their other DNS questions go
through the tool by the same encrypted ways, so the resolver sees the tool's address, not yours.

When you add a WireGuard configuration of your VPN provider, Datapavan Advanced connects to that provider's server,
the one the configuration names, for the apps you send through it; their lookups go to the configuration's DNS
server through it. While any app goes through a configuration, every app's ping, and traffic Android names no app
for, also go through your default configuration, which Datapavan says, and wait while it cannot be opened. Where the configuration names its server by a host name, Datapavan looks it up by the same encrypted
ways; only when none answers, and "Strict" is off, does your network's resolver, which can then see which
provider you use, and Datapavan says so. Datapavan reads a QR code without the camera permission: the phone's own
camera app takes the photo for it, or you pick a picture.

## Permissions and why they are needed

| Permission | Used for | From |
|---|---|---|
| See installed apps | Listing apps and their permissions | v0.1 |
| Usage access (granted by you in Settings; optional) | Showing how much data each app has sent and received, and which apps you have not opened for a long time. For this, Datapavan reads only totals and the date each app was last used, and keeps none of it; Datapavan Basic never reads which app you opened when. When you check one activity in an app, it also reads the phone's total traffic counters, which need no permission, to see whether Android's count is up to date; these numbers stay in memory while the check is on screen | v0.1 |
| Usage access, in Datapavan Advanced | Telling, for each connection, whether you were using its app at that moment, it ran with a notification Android showed (music, navigation), or neither. For this, Advanced also reads Android's record, back to the phone's start, of which app was on screen and when, which apps ran a foreground service, which ones you used in other ways (as by tapping their notification), and when the screen turned on or off and the lock screen showed; and whether each app may show notifications. It keeps what it learns in two places only: in memory for the "Now" view, and, if you keep a connection log, as the state of each record, for the days you chose | Datapavan Advanced, from 0.2.0 |
| Network state | Telling whether a VPN is active. It does not allow any connection | v0.1 |
| Hide other apps' overlays | From Android 12: while Datapavan is on the screen, other apps cannot draw over it. It does not allow any connection | Datapavan Basic after 0.1.2, and Datapavan Advanced |
| VPN (granted by you) | The **local** firewall. Traffic is filtered on the phone and never sent to us | Datapavan Advanced, from 0.2.0 |
| Internet | Forwarding the traffic of other apps through the local firewall. Datapavan Basic never asks for it | Datapavan Advanced, from 0.2.0 |
| Notifications (granted by you, from Android 13) | Two notices about the WireGuard configurations: when one kept for a phone that may be searched waits for you to unlock the phone, and when Datapavan can no longer open what it kept and holds your apps until you choose; they name no provider and no configuration | Datapavan Advanced, from 0.2.0 |

## Optional updates of tracker lists (planned)

Datapavan itself only imports signed list files. If optional downloads come, they will be fetched
from a public mirror, and only if you turn this on. Like any download:

- the mirror's operator sees your IP address and the time of the request;
- the operator, and anyone observing your network, can tell that the device uses Datapavan.

The request contains nothing about your phone, your apps or your activity. Updates are signed, and older
lists are never accepted in place of newer ones. You can turn updates off and import list files
manually. Once mirrors exist, this policy will name each operator, and say what it logs and for how long.

## Contact

Questions about this policy: open an issue on GitHub. For anything sensitive, use the private
reporting form named in [SECURITY.md](SECURITY.md).
