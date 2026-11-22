# 0045. Three editions of one app: Basic, Advanced and Enterprise

- Status: Accepted (by the maintainer on 2026-11-13)
- Date: 2026-11-13
- Decisions 11 and 12 accepted by the maintainer on 2026-11-05; the app's words for the network part on 2026-11-22.

## Context

Datapavan's strongest promise is that its audit never has the INTERNET permission, and anyone can check it
(ADR 0014, ADR 0024). Its local VPN must pass each app's traffic on to its real destination over sockets it opens
and protects. On Android, opening a socket needs the INTERNET permission, and permissions belong to the app, not to
a process. So the VPN cannot live in the audit's app without giving up that promise.

Five separate names were once planned for one tool: the audit app, its Google Play build (ADR 0031), a VPN app,
the Verifier, which is the check from a second phone (ADR 0040), and the expert tool for preinstalled apps
(ADR 0032). On 2026-11-13 the maintainer asked for a fresh look. Users get confused, and do not follow through, when
asked to install several apps for one tool, and today's apps are not easy enough for ordinary people. Three
independent reviews followed:
- the platform and security;
- the people and distribution;
- the editions model below.

The first two kept two apps:
- **Android checks INTERNET per app.** Only a separate package makes "this app never has the network" a fact that
  anyone can check.
- **A person at risk can carry less:** an app with no internet that is not a VPN.
- **A genuine app with no internet can judge the networked one from outside.**

The third found that editions of one app keep all three, with fewer names, no interface between two apps, and no
log in a separate app that the Google Play build could not read.

## Decision

1. **Three editions, each one app for its user.** Each name carries "Datapavan" and its edition, in Latin letters
   in every language, so that no one takes Basic for the full app.

   | Edition | Package | What it holds | Internet |
   |---|---|---|---|
   | Datapavan Basic | `org.visadahyu.datapavan`, for good (Google Play: `org.visadahyu.datapavan.lite`, under Google's key, ADR 0031) | The audit, the check of the user's tools, every feature that needs no network, and the Verifier as a mode (it alone uses the camera) | Never |
   | Datapavan Advanced | `org.visadahyu.datapavan.advanced` | All of Basic but the camera, plus what stage 1 adds: the network part, which is the local VPN, its connection log and the chain through the user's tool (v0.2), blocking (v0.3), reports (v0.4) and the expert tool | Only for the user's own apps' traffic and the servers the user chooses |
   | Datapavan Enterprise | Decided when stage 2 begins | Stage 2's edition for organisations. Its path is reviewed afresh then; ADR 0033's first path would make it Basic in a managed mode | As that review decides |

2. **Basic and Advanced may be installed together, and Basic checks Advanced from outside:**
   - by its signing key and its permissions on the phone;
   - from a second phone, through the Verifier and key attestation.

   For a person at risk, the advice is Basic alone, or Basic beside Advanced. Advanced alone protects less: the
   app that judges is then the app that faces the network.
3. **Advanced never asks for the camera, the microphone, location, contacts, messages or the call log, and never
   contacts a server of its own.** Lists and data packs come with updates or as files. Where Advanced needs the
   Verifier's challenge, it reads it through the camera app or as a typed code.
4. **The sentence taught against fake copies** (ADR 0024, point 8) becomes: "Genuine Datapavan Basic never has
   internet access. Genuine Datapavan Advanced uses it only for your own apps' traffic and the servers you choose,
   and never asks for your camera, microphone, location, contacts, messages or call log. No Datapavan app ever asks
   you for money."
   - Stock Settings shows those runtime permissions, which spyware dressed as a VPN needs. DCHSpy, spread in Iran as
     "Earth VPN" and "Comodo VPN", took call logs, location, SMS, photos and audio
     ([Lookout](https://security.lookout.com/threat-intelligence/article/lookout-discovers-iranian-dchsy-surveillanceware)).
   - The older sentence, "Genuine Datapavan has no internet access", stays true of Basic. The release notes and the
     website say that the sentence changed.
   - *Decided by the maintainer on 2026-11-18:* Basic's page "Is this copy genuine?" takes this two-edition
     sentence with the release of Advanced's 0.2.0, not before. A Basic 0.1.3 released earlier keeps the current
     sentence, since it would otherwise speak of an edition not yet out. Basic's own check line, "This copy has no
     internet access", does not change. DESIGN.md's W9 row holds it as a gate of 0.2.0, with the texts it names.
5. **Free.** Basic and Advanced are free for everyone, and no app takes payment. Enterprise is sold by contract,
   never in an app.
6. **One family of icons, told apart by shape as well as colour, and by the name under the icon:**
   - Basic keeps the DA mark;
   - Advanced has the shield drawn as one outline around DA;
   - Enterprise has, as a first idea, the shield with a double outline, its second line in gold.

   No sword and no crown: one reads as attack, the other as a political symbol in some countries. The key, not the
   icon, is what users learn to check.
7. **Words.** The Chinese texts call Advanced 进阶版, not 高级版, which reads as "Premium". The stores, the site and
   both apps say "free" beside the names.
8. **Each part explains itself the first time it is opened:** what it does, and in Advanced, why it needs the
   internet. A redesign of both editions' look and language, tested with real users, is a gate of Advanced's first
   release (ADR 0039).
9. **Build rules that follow the package, not the module:**
   - one allowlist of permissions per edition (Basic, Basic on Play, Advanced), checked on the merged manifest in
     Gradle and in the release rehearsal;
   - `android:sharedUserId` refused everywhere, since packages sharing a UID share their permissions;
   - no network crate in Basic's native code;
   - in both editions, the audit's hostile parsers (DEX, APK, attestation) run in an `isolatedProcess` service,
     which has no network.
10. **One code base.**
    - `:app` stays the one application module, and the `datapavan.edition` property gains `advanced`.
    - The network part is a library module that only Advanced includes, so Basic never carries the Rust engine.
    - Advanced reads its own connection log: no interface between two apps is built.
    - F-Droid gets two recipes from one repository. Obtainium is set to pick each edition's APK.

11. **What the network part covers from its first release.** Measurements on a Galaxy A56 with Android 17 on
    2026-11-05, read over adb without root, showed what the audit cannot see and the network part must:
    - **Instagram**, in about two and a half minutes of use: about 75 MB received and 3.6 MB sent. The socket tables
      showed only two TCP connections, both to Meta (AS32934): an MQTT edge and a measurement edge. The images and
      videos came over QUIC, on UDP sockets that name no destination, so their servers stayed unknown. Android's
      records showed that Instagram read precise location, cell information and nearby Wi-Fi networks while the
      user only scrolled.
    - **imo**, during two voice calls: about 9.5 MB received and 8.3 MB sent. Instagram reached one network; imo
      reached more than 30 addresses in nine networks (imo's own, three hosting companies, AWS, Google Cloud,
      Akamai, Fastly and Google). It resolved names through Google's encrypted DNS and once through 8.8.8.8
      directly, around the phone's DNS settings. The audio went over UDP sockets that name no destination.

    So three parts of [VPN.md](../VPN.md) come in Advanced's first release (0.2.0), not later:
    - **QUIC.** The QUIC Initial parser for the server name. Most of the bytes of Meta's apps go over QUIC.
    - **Encrypted DNS of the apps themselves.** Known resolvers on port 443, such as `dns.google`, and plain DNS
      sent to an address other than the network's are recognised and named in the log.
    - **UDP flows.** UDP flows that name no destination in the socket tables still pass the tunnel with one, so the
      log covers calls as well.
12. **Advanced stays off Google Play until Play's policy for VPN apps is settled.** VPN apps face a policy of
    their own on Google Play. Basic goes to Play (ADR 0031); Advanced stays on the open channels until that policy
    is settled.

## Consequences

- **What users see:** two apps to choose from, Basic and Advanced, each complete for its user. Organisations see
  Enterprise.
- **Renaming:** the released "Datapavan" becomes "Datapavan Basic" in its next version, with the same package and
  key. `data/app-signers` and AppVerifier keep its earlier label.
- **Other ADRs follow it:**
  - ADR 0031's Google Play build is Datapavan Basic, with a package of its own;
  - ADR 0032's expert tool lives in Advanced;
  - ADR 0034's permissions apply to Advanced;
  - ADR 0040's Verifier is a mode of Basic;
  - ADR 0033's organisational edition is named Enterprise. Its path stays open until stage 2's review.
- **The loss:** someone with Advanced alone gets verdicts from the app that parses network input and holds ADB
  rights. The isolated parsers narrow that, and the advice in decision 2 says it plainly.

## How decisions 9 and 10 are built

- **One module, three editions.** `:app` takes `-Pdatapavan.edition`: `basic` (the default), `play` (Basic for
  Google Play) or `advanced`. Basic's tasks and output paths stay as they were, so its F-Droid recipe and
  `scripts/reproducible.sh` build it unchanged. Advanced builds in `android/app/build-advanced`, so that switching
  editions rebuilds nothing of the other's, and with `--project-cache-dir .gradle-advanced`, which the build
  requires: with one task history, a task that ran again for one edition deleted the APK it had made for the
  other (found on 2026-11-13, when Basic's release build deleted Advanced's).
- **The network part is a library.** `:network` (`android/network`) is an Android library that only Advanced
  depends on. Its manifest sets no icon, label, theme or backup rules of its own: the application's apply. Its
  screen is not exported; debug builds export it for the emulator checks (`network/src/debug`). The audit opens it
  from its Data use tab, by class name, only in Advanced (`ui/NetworkEntry.kt`).
- **Advanced's icon is study B:** the shield drawn as one clay outline around DA, on lapis, and the same in one
  colour for themed icons. Basic keeps DA alone.
- **The network part runs in a process of its own,** `:network`: its screen, its tunnel and its log's expiry. The
  part that faces the network shares no memory with the audit, a crash of either leaves the other running, and it
  keeps its own memory budget of 48 MB. The first release check of Advanced, with both in one process, measured 54 MB,
  most of it the audit's. Both still share one UID and so one sandbox; the isolated parsers below are the step
  that separates more.
- **The shared rules are a library too.** `android/shared` (the signing-key rules and the screen protection) is the
  `:shared` module; adding its sources to each module would have compiled them twice in Advanced.
- **The build checks the package, not the module** (`app/build.gradle.kts`):
  - each edition's merged manifest against its own allowlist: permissions with their `maxSdkVersion`, permission
    definitions, `<queries>`, exported components and their guards, and no `android:sharedUserId`;
  - the permissions an edition never requests, by name: INTERNET in Basic; the camera, microphone, location,
    contacts, messages and call log in Advanced. A wider allowlist cannot quietly break the sentence of decision 4;
  - each APK's native libraries: Basic holds `libdatapavan.so` and never `libdatapavan_network.so`; Advanced
    holds both and keeps the methods the network part's library calls back by name;
  - in the Rust gates (`scripts/check.sh`), that Basic's native library depends on no network crate;
  - in the release rehearsal (`scripts/release-rehearsal.sh`), Basic's signed APK against a list of its own, kept
    apart from the build's, so that a change to one is caught by the other.

  Each check was made to fail once, by adding INTERNET to Basic, the camera to Advanced, and the network part's
  library to what Basic must not carry.
- **Words.** The About page says which edition this is and what the others are. In the app, the network part has
  no name of its own (the maintainer, 2026-11-22): the subject of a sentence is "Datapavan", the network screen's
  title is "Network", and a sentence that tells the editions apart names the features, as Basic's About does:
  Advanced adds a log of each app's connections, tracker blocking and encrypted DNS. So that no two screens share
  the title, the audit's tab of each app's data use is "Data use", as Android's own "Data usage" (the maintainer,
  2026-11-22: «برگه «مصرف داده» شود», "let the tab be 'Data use'"), and a sentence that sends the user to the
  network screen names it as the Network screen, reached from that tab. In documents, "Advanced's network part"
  names it. The texts are translated and reviewed as ADR 0030 sets out.
- **The parsers of untrusted input run isolated,** in both editions (`audit/ParserService.kt`, process `:parser`):
  other apps' DEX files and ZIP directories, and the key-attestation extension. The audit opens each APK and
  passes it as a read-only file descriptor; the isolated process reads the ZIP directory itself, maps or inflates
  each DEX file (checked against its size and CRC-32), and gives back only tracker ids and library names. A DEX
  file stored in an unusual way now makes the app unreadable, where `java.util.zip.ZipFile` once read it. If the
  process dies, the audit binds again and loads the signatures again; an app it still cannot scan is reported
  unreadable and scanned again at the next audit. The build fails unless the service stays isolated and
  unexported, and the smoke test checks that Android ran it under an isolated UID.
- **The full names stay under the icons** (the maintainer, 2026-11-13). On the Android 15 emulator's launcher both
  show as "Datapavan …", cut where the edition begins, and the icons' shapes alone tell the editions apart;
  launchers that wrap names, such as Samsung's, show them whole. A shorter label under the icon alone ("Basic",
  "Advanced"), as "Docs" stands for "Google Docs", was set aside for now: the redesign's test with real users
  checks whether people tell the two apart, and decides.
- **Still to build:** the data tables' rows for Advanced, and Advanced's release rehearsal.
