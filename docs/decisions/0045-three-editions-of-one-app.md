# 0045. Three editions of one app: Basic, Advanced and Enterprise

- Status: Accepted (by the maintainer on 2026-11-13)
- Date: 2026-11-13
- Supersedes: [ADR 0029](0029-network-access-for-v0.2.md). Amends ADRs 0024, 0031, 0032, 0033, 0034 and 0040.

## Context

ADR 0029 kept the audit app without the INTERNET permission by moving the local VPN into a second app, Watch.
Since then the family grew to five names:
- the audit app;
- Lite, on Google Play (ADR 0031);
- Watch;
- the Verifier, the check from a second phone (ADR 0040);
- the expert tool for preinstalled apps (ADR 0032).

Watch and the expert tool would need the internet, and Lite cannot read Watch's log.

On 2026-11-13 the maintainer asked for a fresh look. Users get confused, and do not follow through, when asked to
install several apps for one tool, and today's apps are not easy enough for ordinary people. Three independent
reviews followed:
- the platform and security;
- the people and distribution;
- the editions model below.

The first two kept two apps:
- **Android checks INTERNET per app.** Only a separate package makes "this app never has the network" a fact that
  anyone can check.
- **A person at risk can carry less:** an app with no internet that is not a VPN.
- **A genuine app with no internet can judge the networked one from outside.**

The third found that editions of one app keep all three, and drop three of the five names, the interface between
Watch and the audit app, and the gap between Lite and Watch.

## Decision

1. **Three editions, each one app for its user.** Each name carries "Datapavan" and its edition, in Latin letters
   in every language, so that no one takes Basic for the full app.

   | Edition | Package | What it holds | Internet |
   |---|---|---|---|
   | Datapavan Basic | `org.visadahyu.datapavan`, for good (Google Play: `org.visadahyu.datapavan.lite`, under Google's key, ADR 0031) | The audit, the check of the user's tools, every feature that needs no network, and the Verifier as a mode (it alone uses the camera) | Never |
   | Datapavan Advanced | `org.visadahyu.datapavan.advanced` | All of Basic but the camera, plus what stage 1 adds: Watch's tunnel, its log and the chain (v0.2), blocking (v0.3), reports (v0.4) and the expert tool | Only for the user's own apps' traffic and the servers the user chooses |
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
    - Watch's module becomes a library that only Advanced includes, so Basic never carries the Rust engine.
    - W5's interface between two apps is not built: Advanced reads its own log.
    - F-Droid gets two recipes from one repository. Obtainium is set to pick each edition's APK.

## Consequences

- **What users see:** two apps to choose from, Basic and Advanced, each complete for its user. Organisations see
  Enterprise.
- **Renaming:** the released "Datapavan" becomes "Datapavan Basic" in its next version, with the same package and
  key. `data/app-signers` and AppVerifier keep its earlier label.
- **Watch's package is dropped before its first release,** so no user is affected.
- **ADR 0029 is superseded.** Its measurements still stand, and so does its moving of QUIC, apps' own encrypted DNS
  and UDP earlier, now in Advanced.
- **Other ADRs change:**
  - ADR 0031's Lite is "Datapavan Basic" on Google Play;
  - ADR 0032's expert tool lives in Advanced;
  - ADR 0034's permissions apply to Advanced;
  - ADR 0040's Verifier is a mode of Basic;
  - ADR 0033's organisational edition is named Enterprise. Its path stays open until stage 2's review.
- **The loss:** someone with Advanced alone gets verdicts from the app that parses network input and holds ADB
  rights. The isolated parsers narrow that, and the advice in decision 2 says it plainly.
