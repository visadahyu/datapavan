# Privacy policy

- **Effective:** 2026-11-07
- **Updated:** 2026-11-18, with Datapavan Advanced's lines for 0.2.0, which is not yet released
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
  log keeps no destination unless you turn that on.
- **Each app's recent traffic, for the "Now" view,** in memory only. It is gone when the firewall stops.
- **Your circumvention tool's settings:** whether apps go through it and which ones, the tool's host and port, and
  the password Datapavan made for it, which is encrypted under a key that Android's keystore protects.

## Version 0.1 cannot open network connections

Datapavan Basic 0.1 does not request the INTERNET permission, so Android itself prevents it from
opening network connections. The build fails if any component tries to add that permission. Like any
app, it can still hand information to another app when you ask it to, for example when you open a link.

What Android itself does is outside Datapavan's control. On phones with Google's services, Play Protect may give Google information about the apps you install from any source, Datapavan included, and may send it an unknown app to check. You can turn part of this off in Play Protect's settings in the Play Store. Datapavan's hardware check can also make Android contact Google: on phones that get their attestation keys from Google's provisioning server, a check that finds none left asks Android for more (Android 13 tells the provisioning service, and from Android 14 the keystore asks it), and Android fetches them over its own connection. Datapavan sends nothing itself.

## What Datapavan Advanced connects to

Datapavan Advanced, from 0.2.0, passes your apps' traffic on to where they send it, through the firewall on the
phone; none of it goes to us. Of its own, it asks your network's DNS resolver for the names apps look up, as the
phone would without it, over an encrypted connection where the phone used one. When you send apps through your
circumvention tool, their lookups go to the tool, and their other DNS questions go through the tool to Quad9, a
Swiss foundation that does not log addresses, so Quad9 sees the tool's address, not yours.

## Permissions and why they are needed

| Permission | Used for | From |
|---|---|---|
| See installed apps | Listing apps and their permissions | v0.1 |
| Usage access (granted by you in Settings; optional) | Showing how much data each app has sent and received, and which apps you have not opened for a long time. For this, Datapavan reads only totals and the date each app was last used, and keeps none of it; Datapavan Basic never reads which app you opened when. When you check one activity in an app, it also reads the phone's total traffic counters, which need no permission, to see whether Android's count is up to date; these numbers stay in memory while the check is on screen | v0.1 |
| Usage access, in Datapavan Advanced | Telling, for each connection, whether you were using its app at that moment, it ran with its notification (music, navigation), or neither. For this, Advanced also reads Android's record of which app was on screen and when. It keeps what it learns only in memory for the "Now" view, and, if you keep a connection log, as that state of each record, for the days you chose | Datapavan Advanced, from 0.2.0 |
| Network state | Telling whether a VPN is active. It does not allow any connection | v0.1 |
| Hide other apps' overlays | From Android 12: while Datapavan is on the screen, other apps cannot draw over it. It does not allow any connection | Datapavan Basic after 0.1.2, and Datapavan Advanced |
| VPN (granted by you) | The **local** firewall. Traffic is filtered on the phone and never sent to us | Datapavan Advanced, from 0.2.0 |
| Internet | Forwarding the traffic of other apps through the local firewall. Datapavan Basic never asks for it | Datapavan Advanced, from 0.2.0 |

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
