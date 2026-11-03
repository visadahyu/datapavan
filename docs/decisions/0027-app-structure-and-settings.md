# 0027. The app's structure, and settings for appearance and language

- Status: Proposed
- Date: 2026-11-03
- Decided by: mehdashti

## Context
Each milestone from M2 to M5 added its section to the end of one overview: the phone's checks, the
strict sensor review, network use, apps not opened for a long time, the app list, the plan, data
sources and the self-check. On the A40 the maintainer found a flat page that runs very far down, with
no menu, no way to reach a part directly, no grouping or search of apps, and no setting for dark or
light mode or for the language. Dark mode follows the phone. The language can be chosen per app in
system Settings only from Android 13; on Android 10 to 12, such as the A40, the app always uses the
phone's language.

The closest precedents group the same kind of content into a few destinations: Android's Safety
Center (a summary, then sections), Apple's App Privacy Report (apps and their access), and privacy
tools such as TrackerControl (apps with filters). Material 3 puts three to five top-level
destinations in a navigation bar at the bottom.

## Decision
1. **Four destinations in a navigation bar at the bottom,** each with its own back stack, kept when
   the user switches:
   - **Summary:** the plan's entry (its first action, the question three days after a session, a
     change that came back, the journal), the strict sensor review, the scan's progress and the data
     pack's age. It names what to do, never a count of problems (ADR 0026, point 7).
   - **Apps:** the app list with a search field (name or package), filters (with findings, the
     default; trackers; access that can control the phone; not opened for 90 days; preinstalled; VPN
     and proxy apps; all) and a sort (urgency, name, data use, install date). A filter shows how many
     apps it holds, since the user came here to browse; the Summary does not.
   - **Phone:** the phone's own findings with their screens, the integrity line and the security
     patch.
   - **Network:** network use, the period, the apps not opened for a long time, and the usage access
     prompt.

   System back returns to Summary from another destination, then leaves the app. In right-to-left
   languages the bar mirrors.
2. **An app's page starts with a plain-language card** (the one DESIGN.md plans for v0.1): what the
   app can reach (sensors, special access, VPN), the purposes of its trackers, what it received and
   sent in 30 days with usage access, and what the user can do (the plan's card for it, or its system
   page). Facts only, in ADR 0025's words: absolute numbers, no score, no judging word. Below the
   card, the existing sections (findings, access and permissions, trackers and SDKs, network and the
   guided check, signature and keys) can be collapsed; findings start open.
3. **Settings, from the top bar of every destination:**
   - **Appearance:** as the system, light or dark. Both themes keep ThemeTest's contrast.
   - **Language:** as the system, English, French, German or Persian, on every supported Android
     version. Android 13 and later use the system's per-app language (`LocaleManager`), so the choice
     shows in system Settings too; Android 10 to 12 keep it in app-private storage and apply it to the
     activity's context.
   - **Data sources**, **Is this copy genuine?**, the **privacy policy** as text in the app, the
     **open-source licences**, and **about** (versions, the source code's address as text).
4. **No new dependency.** Navigation stays plain Compose state, as the app does now; icons are vector
   drawables copied from Material Symbols (Apache-2.0) with their licence noted; the language works
   without AppCompat. Dependency verification (ADR 0008) stays as it is.
5. **Every destination is checked.** The emulator scripts reach each part through the navigation
   bar and labels, never through scroll positions on one long page; `scripts/screenshots.sh` takes
   every destination, the settings and an app's page in each language and both pseudo-locales, with
   its accessibility check, in light and dark.

## Consequences
- The overview's content moves, nothing is removed. The scripts that wait for "This phone" on the
  overview (`scripts/adb-ui.sh`) and every emulator script change with it, in the same unit.
- Strings for the bar, the filters, the sort, the card and the settings, in four languages; the
  plain-language check covers them.
- The language setting on Android 10 to 12 restarts the activity once; a choice made there does not
  show in system Settings, which have no per-app language before Android 13.
- The card on an app's page is the last code item of M5's "Plain-language UI".
