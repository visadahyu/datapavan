# 0016. No data from users; learning happens in the lab

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
Remediation needs knowledge: which preinstalled packages are safe to disable on which phones, which apps
carry trackers, what breaks when. Many products learn this from their users' devices, through telemetry,
local differential privacy, secure aggregation or private lookups. Datapavan's principles already forbid
servers that receive user data, but the question comes back with every feature, so it is decided here.

A prior-art review (2026-10-30) found:
- **Every technique needs a server.** All of them, including the privacy-preserving ones (local
  differential privacy, Prio/DAP secure aggregation, hash-prefix and private lookups), need a server that
  receives a report from each device. Even the strongest of them reveals that a phone takes part.
- **The list of installed apps is dangerous data.** A single snapshot predicts religion, relationship
  status and gender with high accuracy. Google Play classes it as personal and sensitive data. Soldiers
  in Myanmar have searched phones at checkpoints for VPN apps and extorted people who had them.
- **There are precedents.** The εxodus Android app sends the list of installed apps to its server, which
  keeps IP logs. Security vendors have sold "anonymised" data, as the FTC's order against Avast shows.
  Signal shows the opposite: it can answer a subpoena only with two dates, because it holds nothing else.
- **No server is needed for lookups.** A phone can check an app against a database without telling
  anyone, by holding the whole database, as Datapavan already does with the εxodus signatures.

## Decision
1. **Datapavan collects no data from users:** no telemetry, no crash reports sent automatically, no
   app lists, no identifiers, no "anonymous" statistics, in any edition.
2. **Lookups are local.** Every reference database ships to the phone in full, in signed data packs
   (ADR 0015), and is matched on the phone.
3. **Knowledge comes from the lab:** the project's own test phones from several vendors, its analysis of
   public app files, and published research and datasets.
4. **The only exception users may choose is a readable report that they send themselves:** for example,
   "this preinstalled package broke this feature on this model", through the share sheet, to a
   channel they pick. Such a report names the vendor, model, build, package and outcome, never apps that
   the user installed, and the user reads it before sending. Datapavan never sends anything by itself.
5. **Revisiting this needs a new ADR** that supersedes this one, after legal review and a published
   threat assessment for users in restricted regions. The least risky form found so far is secure
   aggregation with an independent second operator. It would be strictly opt-in, behind an anonymising
   relay, measure only bounded values that never include app identities, and add noise to its outputs.

## Consequences
- The privacy policy can stay one sentence long: nothing leaves the phone unless the user sends it.
  There is no server to subpoena, breach or compel.
- **Learning is slower and needs devices.** The lab has to cover several vendors and price classes, which
  costs money and time. It is a funding item, not an optional extra.
- Remediation evidence grows only as fast as the lab tests. Items without evidence for a phone stay at
  "inform only" for it.
- Users who want to help get a way that they control, and the project gets reports it can verify in the
  lab before it acts on them.
