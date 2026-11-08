# 0033. The organisational edition beside a device-management suite

- Status: Accepted (by the maintainer on 2026-11-08), not built yet
- Date: 2026-11-08

## Context

The maintainer, on 2026-11-08, set out three paths for Datapavan:

1. the free edition for everyone, which v0.1 to v0.4 build in order;
2. an organisational edition **beside** the device-management suite an organisation already runs
   (Intune, Workspace ONE, Knox and others), as the first step into organisations;
3. later, a complete organisational edition that manages the phones itself.

Suites hold the switches (block an app, grant a permission, turn off a system app, force a VPN) but
not the knowledge of what to switch: they do not read apps' code for trackers or traffic-sharing SDKs,
check the signing keys of VPN apps, or know which preinstalled apps collect data. Microsoft tells
administrators to "work with the OEM" to find the package names of preinstalled apps to turn off.
Datapavan has that knowledge, on the phone and offline.

The audit app holds no INTERNET permission, and the sentence it teaches against fake copies is
"genuine Datapavan has no internet access" (ADR 0014, ADR 0024). An organisational edition that
sends data over the network would break it.

A spike on 2026-11-08 ([findings](../spikes/2026-11-enterprise-channels.md)) showed on Android 11,
15 and 17 that an app with no INTERNET permission can take policy from a suite's agent, report
verdicts to it, and read the phone's network log, all through Android on the phone. A study of the
suites' documentation (2026-11-08) found:

- **Verdicts out (keyed app states):** documented by Google's Android Management API and the suites
  built on it, Workspace ONE (with Omnissa Intelligence, for an app published on Google Play), Knox
  Manage, SOTI, Hexnode, ManageEngine, Scalefusion and Cortado; not found for Intune. The library
  needs no permission; it sends over local IPC to the device or profile owner and to the Play Store
  app. Limits: key 100, message 1,000, data 1,000 characters, two severities, 500 keys a day. On
  suites built on Google's API, the verdicts pass through Google's servers.
- **Policy in (managed configurations):** every suite Google validates supports them. Consoles build
  their form from the schema published with the app on Google Play; for an app that is not on Play,
  administrators type the values by hand.
- **Network log (delegated network logging):** Android 10 on fully managed phones, Android 12 in work
  profiles; one app at a time; the user is told. Delegation is documented by Google's API, Intune (on
  corporate-owned phones) and Scalefusion. The log holds DNS lookups through the system resolver and
  TCP connects, each with the app's package; it misses UDP and QUIC, apps' own DNS, and raw system
  calls.
- **Path 3's ground has moved:** Google no longer accepts new custom device policy controllers, and
  since 2025 Play Protect blocks unapproved ones during setup. Its management API is open only to
  commercial device-management vendors, not to solutions for one's own organisation.

## Decision

1. **One audit app, two modes.** The organisational edition is the audit app with its managed mode
   turned on by a managed configuration. Same code and same rules; no separate product.
2. **No INTERNET, ever, also for organisations.** Policy comes in as managed configurations; verdicts
   go out as keyed app states to the suite's agent, which uploads them; connections come from the
   network log when the organisation delegates it. Where a suite supports none of these (Intune for
   verdicts, today), the edition shows the verdict on the phone and exports a signed report file;
   it does not open a network connection of its own.
3. **The organisation receives verdicts, not the phone's contents.** A verdict is a state per policy
   rule (meets the policy, or does not, with a category such as "an app holds remote-control access"
   or "a VPN app is not genuine") and, for apps the organisation itself manages, their package names.
   Never sent: the list of personal apps, connection logs, a stalkerware finding, sensor history,
   anything from a personal profile. The work profile is audited alone, which Android itself
   enforces; on a fully managed phone this limit is the edition's own rule.
4. **The person sees what is sent.** A screen on the phone lists every state sent to the suite, word
   for word, with its time. Nothing is sent that is not on that screen.
5. **The network log stays on the phone.** When delegated, the audit app reads it to show the person
   which app talked to whom, without a VPN, and to judge policy rules; the log itself is never
   forwarded. Watch's VPN is not needed on such phones, so the organisation's own VPN keeps its slot.
6. **Policy packs are open data.** The knowledge an organisation needs in its suite (preinstalled data
   collectors per maker and model, official keys of VPN apps, apps with traffic-sharing SDKs) is
   published as signed data under the same licences as today, in formats suites can import. The same
   data is free to everyone at the same time.
7. **Distribution:** an organisation installs the build it trusts. A listing on managed Google Play
   gives suites their configuration form; its package and key follow ADR 0031's rules for Play.
8. **Path 3 gets its own ADR,** after path 2 has run with organisations. With custom controllers
   closed, it would mean building on Google's management API as a vendor, or on an open-source
   suite, not writing a controller of Datapavan's own.

## Consequences

- The promise "no internet access" holds for every edition of the audit app.
- An organisation with Workspace ONE, Knox Manage, SOTI, Hexnode, ManageEngine, Scalefusion or a suite
  on Google's API can receive verdicts in its own console. Intune customers get the verdict on the
  phone and the report file until Intune shows keyed app states.
- On fully managed phones and Android 12+ work profiles, the audit app can show each app's connections
  without a VPN, where the organisation delegates the log.
- Verdicts may pass through Google's servers on the way to some suites, which is one more reason to
  send only verdicts.
- The edition must be designed so that it cannot become a tool for watching employees: what it sends
  is fixed in the code and shown to the person, not chosen by the organisation.

## Open questions

- Whether the managed-Play build is the audit app itself or the Lite edition of ADR 0031, and how a
  person checks it is genuine when Google holds its key.
- How Intune customers receive verdicts: a compliance connector, a report file, or nothing more.
- What the person sees on their phone while network logging is on, on several makers' phones.
- Whether connect events carry the destination on a real Android 15 phone (the emulator's did not).
- A template for the organisation's data-protection impact assessment, and works councils' rules.
