# 0029. Where network access lives in v0.2

- Status: Proposed
- Date: 2026-11-05

(0028 is kept for the ranges of kinds of app from the lab, ADR 0025 point 5.)

## Context

v0.1 holds no INTERNET permission, and the build fails if anything adds it (ADR 0014). The release
notes teach one sentence against fake copies: "Genuine Datapavan v0.1 has no internet access and
never asks for it" (ADR 0024). It is the strongest promise the app makes, and anyone can check it.

v0.2's local VPN ([VPN.md](../VPN.md)) must pass each app's traffic on to its real destination over
sockets that Datapavan opens and protects. On Android, opening a socket needs the INTERNET permission,
and permissions belong to the app, not to a process. So the VPN cannot live in the app as it is
without giving up that promise.

Measurements on a Galaxy A56 with Android 17 on 2026-11-05, read over adb without root, show what
v0.1 cannot see and v0.2 must:

- **Instagram**, in about two and a half minutes of use: about 75 MB received and 3.6 MB sent. The
  socket tables showed only two TCP connections, both to Meta (AS32934): an MQTT edge in Istanbul and a
  measurement edge in Marseille. The images and videos came over QUIC, on UDP sockets that name no
  destination, so their servers stayed unknown. Android's records showed that Instagram read precise
  location, cell information and nearby Wi-Fi networks while the user only scrolled.
- **imo**, during two voice calls: about 9.5 MB received and 8.3 MB sent. Instagram reached one
  network; imo reached more than 30 addresses in nine networks (imo's own, three hosting companies,
  AWS, Google Cloud, Akamai, Fastly and Google). It resolved names through Google's encrypted DNS and
  once through 8.8.8.8 directly, around the phone's DNS settings. The audio went over UDP sockets that
  name no destination.

## Options

1. **One app.** The VPN joins the app, which gains INTERNET from v0.2. This is the simplest to build,
   and the way NetGuard and TrackerControl work. The taught sentence becomes version-dependent, the
   self-check and every published guide change, and a fake copy that asks for internet no longer
   stands out.
2. **A separate app for the VPN.** *Datapavan* keeps no INTERNET permission for good. *Datapavan
   Watch*, a second package from the same repository, signed with the same key, holds `VpnService`,
   INTERNET and the packet engine, and nothing else. Watch keeps the connection log in its own
   encrypted storage, and Datapavan reads it through an interface that only an app signed with the
   same key may use. Data flows one way, from Watch to Datapavan: the audit's results never reach an
   app that can open a connection.
3. **No forwarding.** The VPN only watches and drops, so it needs no INTERNET. It would cut the phone
   off, so it is not a real option.

## Proposed decision

Option 2. The sentence to teach stays true without a version number: "Datapavan never has internet
access. Datapavan Watch, a separate app, uses it only to pass your own traffic on to where it was
going." It also fits the plan for Google Play, where an audit-only edition is planned and VPN apps
face their own policy: Datapavan goes to Play, and Watch stays on the open channels until that is
settled.

From the measurements, three parts of [VPN.md](../VPN.md) move earlier:

- **QUIC.** The QUIC Initial parser for the server name comes in v0.2's first release, not later. Most
  of the bytes of Meta's apps go over QUIC.
- **Encrypted DNS of the apps themselves.** Known resolvers on port 443, such as `dns.google`, and
  plain DNS sent to an address other than the network's are recognised and named in the log.
- **UDP flows.** UDP flows that name no destination in the socket tables still pass the tunnel with
  one, so the log covers calls as well.

## Consequences

- **Two packages:** two listings on F-Droid and IzzyOnDroid, two rows in `data/app-signers`, two
  fingerprints. Each is a Gradle module of the same build, reproducible on its own.
- **The interface between them:** small and versioned. Watch answers queries for flows and never
  receives anything from Datapavan, so a fault in Watch cannot leak the audit.
- **Installing:** users who want the connection log install a second app. Datapavan offers it where
  the log would answer a question, with the same fingerprint check as for itself.
- **Before work starts:** ADR 0012's spike for the packet engine runs first, in Watch's module.
- **For the maintainer to decide:** this record stays Proposed until the maintainer accepts option 2
  or chooses option 1.
