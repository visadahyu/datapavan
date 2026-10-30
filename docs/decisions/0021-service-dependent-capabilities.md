# 0021. Tracker capabilities that need a service the phone lacks

- Status: Accepted
- Date: 2026-10-30
- Decided by: mehdashti

## Context
Some code that the scan finds depends on a system service: Google Play services, the Play Store,
Huawei's HMS Core, or a phone maker's push service. On a phone without that service, the code may do
nothing, and saying so would be useful. Saying it wrongly would hide a real data flow, and the people
whose phones lack these services are many: most phones sold in mainland China, Huawei phones since
2019, older Fire tablets, and users of de-Googled systems such as LineageOS with microG or GrapheneOS.

A review of vendor documentation, the open-source parts of the SDKs, their published artefacts and
the substitutes for Google's services found:
- **Most tracker SDKs run without their vendor's service.** Firebase lists only Cloud Messaging, the
  Play Integrity provider of App Check, Phone Number Verification and two deprecated products as
  needing Google Play services. Firebase Analytics sends events on any device, and Crashlytics,
  Performance Monitoring and Remote Config need nothing. The standard Google Mobile Ads SDK carries its
  own implementation. Huawei's Analytics Kit, crash reporting, ads and location run on other brands'
  phones without HMS Core. The Facebook SDK, AppsFlyer and Adjust switch to other identifiers when
  Google's advertising ID is missing.
- **About fifteen capabilities have a documented hard dependency**, each a part of an SDK, never the
  whole: push through Firebase Cloud Messaging, Huawei Push Kit or the OPPO and Honor push services;
  reading Google's advertising ID or Huawei's OAID; Google Play's and Huawei's install referrers;
  Huawei's Account Kit; Play Integrity. The rest of the SDK keeps running.
- **Some products are dead everywhere**, because their server shut down: Firebase Dynamic Links, legacy
  Google Analytics, Microsoft App Center.
- **A substitute changes the answer.** microG implements push fully, but drops analytics events and
  returns an empty advertising ID. GrapheneOS runs Google's own Play services as an ordinary app, only
  in the profiles where it is installed.
- **A certificate check alone is fooled.** On LineageOS, microG is shown to apps with Google's
  certificate, so a check of the signer calls it genuine. microG has its own markers.
- **The state changes.** HMS Core can be installed on any Android phone, and the SDKs are built to ask
  for it. A service can be disabled and enabled again, and each profile has its own apps.
- **A present service can widen the data path.** With Google Play services present, Firebase can hand
  events to Play services, so they may leave the phone from Play services' process rather than the
  app's.

The research behind this record is kept in the foundation's private repository.

## Decision
1. **Labels name a capability, never an SDK, a vendor or an app.** For example: "Push messages through
   this SDK need Google Play services, which is not installed or is turned off in this profile right
   now. If it is installed or turned on, push starts working. The rest of this SDK, and the app's other
   trackers, can still run." The words "cannot run", "inactive" and "safe" are not used for an SDK or
   an app, and the finding keeps its severity.
2. **Only proven dependencies get a label.** A capability is listed only where the vendor's own
   documentation, the SDK's published artefact or its source code shows the dependency. Everything
   else is assumed to run. The list is CC0, in `data/sdk-needs/`: capability, the identifiers that
   show it, the service and minimum version it needs, the evidence with its grade and date. Where class
   names cannot tell a dependent variant from an independent one (the deprecated Google Mobile Ads
   Lite SDK), there is no label.
3. **Each service has three states**, read with PackageManager, without network access and without
   any Google library:
   - **genuine:** installed, enabled, and signed with a certificate on Datapavan's list of the
     service's signers (graded as in ADR 0018), tested with `hasSigningCertificate`;
   - **substitute or unverified:** microG's markers (its fake-signature permission and meta-data, or
     its `org.microg.gms` components), an unknown signer, or a package that offers the service's
     interface. These count as present;
   - **absent or disabled.**

   Only "absent or disabled" can produce a label. The Play Store is a condition of its own, because
   push and the install referrer depend on it and not only on Play services.
4. **A label is scoped and dated.** It speaks of this profile and of the time of the check, and the
   state is read again at every audit and when packages change.
5. **A shut-down service is a separate fact**: "service shut down on DATE", not "cannot run here".
6. **A present service is noted for the VPN.** Where data can leave through a system service rather
   than through the app, v0.2's per-app traffic log does not take the app's silence as proof that its
   tracker is idle.

## Consequences
- Few labels appear at first, and most findings stay unqualified. A missing label errs towards showing
  more, which is the safe direction.
- No surveyed tool labels capabilities by the services present; GoogleApiAvailability, the usual check,
  needs Google's library, which Datapavan does not ship, and does not recognise substitutes.
- Before the first release the detection is tested on stock Android, GrapheneOS with and without
  sandboxed Play in several profiles, LineageOS with microG, a Huawei phone, and HMS Core on another
  brand. The manifests of Google's closed SDK artefacts are read first, with the maintainer's approval
  for each download.
- The capability list is re-checked at least every six months, and on each major SDK release.
