# 0019. Traffic-sharing, remote-support and screen-recording SDKs

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
Some SDKs inside ordinary apps do more than collect data:
- **Traffic sharing.** Commercial "monetisation" SDKs let a vendor's customers send internet traffic
  through the phone, so websites see it coming from the user's connection. These are also called
  residential proxies or proxyware.
- **Remote support.** These SDKs let an outside operator see the screen and, in some cases, control
  the phone.
- **Screen recording.** These SDKs record what the user sees and taps, so that the app's maker can
  replay it.

ADR 0015 decided that Datapavan keeps its own lists of such SDKs, under CC0, with evidence for every
entry and a public way to dispute it. This record decides how.

A review of vendor documentation, platform reports, court actions, academic work and open lists found:
- **Few vendors publish their identifiers.** Five traffic-sharing SDKs name their own classes (Bright
  SDK, Massive, Honeygain, Pawns, Repocket), and so do eight remote-support SDKs. Most publish their
  artefacts only to registered partners.
- **The worst-documented SDKs are known only from research.** The SDKs whose consent problems are on
  record are known by name only through Google, security researchers or one academic study: the four
  IPIDEA SDKs that Google removes from Play since January 2026, LumiApps/PROXYLIB, and the older
  Luminati, IPninja and MonkeySocks. Their identifiers have to be read from samples before they can be
  trusted.
- **Class names are not always enough.** Some SDKs hide their engine in native libraries, use names
  that imitate the platform or popular libraries, or survive code shrinking only in manifest
  components.
- **No open list is both current and CC0.** εxodus lists none of these SDKs. The only academic list is
  from 2019 and under GPL-3.0.
- **Wording carries legal risk.** Courts have treated labels such as "malicious" or "threat" as factual
  claims a company can sue over, while plain descriptions of what was found have held up.

The research behind this record is kept in the foundation's private repository.

## Decision
1. **Three categories, kept apart:**
   - **Traffic sharing:** code whose documented function is to send other parties' internet traffic
     through the device.
   - **Remote support:** code that lets an outside operator view the screen live or send input. Each SDK
     is flagged with what it can reach: this app's screen or the whole screen, control of this app or of
     the whole device, files, and unattended access.
   - **Screen recording:** code that records the app's screens for later replay by its maker. It is not
     remote support, because it has no live operator and no remote input. Vendors that document live
     viewing are flagged.

   A fourth category, apps named in reports on networks that relay traffic, is matched by package name
   and signing certificate in a later release.
2. **The list lives in `data/sdks/`** (CC0), apart from the εxodus import:
   - `sdks.tsv`: one row per SDK, with its vendor as published, category and capabilities;
   - `sources.tsv`: where each identifier is read;
   - `signatures.tsv`: one row per identifier, with its evidence. `update.py` writes it.
3. **An identifier ships only after Datapavan reads it in a hashed artefact.** Grades, from strongest:
   1. read in an artefact the vendor publishes (AAR, JAR, demo or source), in a form that survives code
      shrinking: a manifest component, or a class that the artefact's own keep rules preserve;
   2. named in the vendor's documentation and read in at least one host app whose hash is recorded;
   3. named by a platform owner, a court filing or a named research report, and read in at least two
      host apps of unrelated developers, together with a second marker of the same SDK;
   4. documented but not yet read, or read in a form that shrinking may rename;
   5. named by one secondary source.

   Only grades 1 to 3 reach the phone. Grades 4 and 5 are the work queue. Samples come only from
   official channels or sources whose terms allow it, and they are analysed offline, never installed or
   run.
4. **Matching on the phone uses the tracker scanner.** Shipped class and manifest-component
   identifiers are added to the scanner's signatures. Only classes an app contains count, not classes
   it merely refers to. Identifiers that look generic or like the platform are not shipped on their own.
5. **Findings state facts.** Each one says:
   - what was found;
   - what the code does when it is on;
   - what Datapavan could not check, namely whether the code is active and whether the user agreed;
   - the vendor's own stated safeguards;
   - the evidence.

   Words such as "malicious", "malware", "threat", "botnet" or "spy", and phrases such as "without your
   consent" or "violates Play policy", are never used. Whether consent was given, and what a policy
   allows, are not Datapavan's to decide. A company link that rests only on a third party's attribution
   stays in the evidence, not in the finding.
6. **Severity:**
   - traffic sharing: medium, because the capability is present;
   - remote support: low, or medium when its accessibility service is turned on;
   - screen recording: low.

   Nothing in this list is shown as high severity on a class match alone.

## Consequences
- The first list is small: Pawns for traffic sharing, LogMeIn Rescue, Cobrowse.io, Glance, Zoho Assist
  and Upscope for remote support, and Microsoft Clarity, Datadog, Sentry and PostHog session replay for
  screen recording. Bright SDK, Massive, Honeygain and Repocket wait in the queue until an official host
  app or artefact is read, because their artefacts are not public.
- The SDKs with the most documented consent problems need samples. Getting them from a sample
  repository may need an account, which the maintainer opens.
- Native-library names and identifiers in the network are recorded for the queue. Native libraries are
  matched in a later release, and network identifiers by the v0.2 VPN.
- Entries are re-checked at least every six months, the same staleness limit the *Data sources* screen
  shows, and can be disputed through `data/CORRECTIONS.md`. A vendor overturns an entry by showing that
  the identifier is not its own, or that a named version does not contain it.
- A lawyer reviews the wording and the named vendors before the first public release (ADR 0015,
  decision 12).
