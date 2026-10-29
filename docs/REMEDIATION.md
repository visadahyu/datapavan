# Remediation plan

Status: designed. The first tier comes with v0.1; later tiers come with stage 2. The design applies to every
Android phone. Vendor features appear only as examples, and evidence is kept per vendor, model and build.

## Why

A list of findings is not protection. On a phone in daily use, Datapavan checked 555 apps and found 90
with something to report; nobody, expert or not, works through that by hand. The remediation plan turns
findings into a short list of actions, ordered by how much risk each one removes, that the user can finish
in a few minutes and undo afterwards.

## Principles

1. **Recommend, then confirm.** Nothing changes until the user has seen what will change and why. In stage
   2 the administrator approves a policy instead.
2. **Never break the phone.** A safety floor (below) applies at every level. No level, preset or import can
   lower it.
3. **The gentlest action that removes the risk.** Restricting comes before disabling, and disabling comes
   before removing. Datapavan never deletes an app's data.
4. **Honest undo.** Undo is promised only for what the journal can restore. What cannot be undone, such as
   a permission that a work profile denied, is said before the user confirms.
5. **Every vendor.** Android's own mechanisms come first. Vendor behaviour is learned per vendor, model and
   build, never assumed from one maker's phones.
6. **Nothing leaves the phone.** Datapavan learns from its lab, not from its users ([ADR 0016](decisions/0016-no-user-data.md)).

## What each privilege level can do

| Level | Can | Cannot |
|---|---|---|
| Ordinary app (v0.1) | Open the system's uninstall confirmation (`REQUEST_DELETE_PACKAGES`); open an app's settings page or its unused-app setting (`ACTION_AUTO_REVOKE_PERMISSIONS`); find unused apps with usage access (M4) | Disable, suspend or hide another app; revoke its permissions; touch preinstalled system apps; read or change Android's hibernation of unused apps |
| ADB bridge (not decided) | After a one-time pairing over wireless debugging: disable for the user, uninstall for the user while keeping data, suspend, restrict background running | Needs a local network connection, which v0.1 does not have; gives a large privilege to one more component; some vendors block it. Needs its own ADR before it is built |
| Profile Owner (work profile) | Inside the profile: deny permissions, suspend, hide, block uninstall, without a factory reset | Act on apps outside the profile; on Android 12+, grant back a sensor permission it denied |
| Device Owner (stage 2) | Silently uninstall user apps; hide or suspend any app; set permission policies | Delete preinstalled system apps (they can only be hidden or suspended); suspend the core apps that Android protects |

Android already puts unused apps to sleep (permission reset on Android 11+, hibernation on 12+), but it
skips system apps, apps without a launcher icon and apps that target old Android versions. In v0.1 the
plan's job is to find what Android's own protection skips and to hand each case to the right system
screen with one tap.

## Actions, from the gentlest

| Step | Action | Who can apply it | Keeps the app's data | Undo |
|---|---|---|---|---|
| 0 | Inform only | Everyone | Yes | Not needed |
| 1 | Open the right system screen for the user's decision | Ordinary app | Yes | The user reverses it on the same screen |
| 2 | Restrict background running, and stop the app | ADB bridge | Yes | Yes |
| 3 | Suspend: the app cannot open, its notifications are hidden | ADB bridge, Profile or Device Owner | Yes | Yes |
| 4 | Disable for the user | ADB bridge | Yes | Yes |
| 5 | Hide | Profile or Device Owner | Yes | Yes |
| 6 | Uninstall for the user, keeping its data, only after a quarantine at step 3 or 4 | ADB bridge, Device Owner | Yes | Reinstall the existing package |

Never: clearing an app's data, uninstalling without keeping data, or promising to delete a system app.

**The journal.** Every action records the step that was actually applied (not the one requested), the
state before it, the time, and how to reverse it. After the action, and again after the next restart,
Datapavan checks that the state is what the journal says. A few days later it asks whether everything still
works, and offers to undo.

## The safety floor

**Computed on the phone, at every run:**
- holders of the default roles: phone, messages, home screen, browser, assistant;
- the active keyboard, and a second one if the active keyboard would be touched;
- accessibility services and device administrators the user relies on;
- the installer, the package verifier and the permission controller;
- the apps Android itself refuses to suspend;
- Datapavan.

**A deny-list by function, for every vendor:**
- start-up and core system services;
- calls, mobile data, SIM and eSIM;
- system updates;
- the setup wizard and emergency information;
- time-zone data;
- connectivity components, such as tethering;
- vendor security and device-locking components, including anti-theft and device-financing locks.
  Samsung's Knox Guard is one example: removing it locks the phone until a factory reset.

Public reports of start-up loops and factory resets after removing "safe" packages are the reason this
list exists. Each vendor's entries are kept with the evidence that put them there.

**Stalkerware is reported, never removed automatically.** Removing it can alert the person who installed
it. The user gets the finding and a path to help.

## Three levels

The levels differ in how much risk they accept and how much evidence they require. The safety floor and
the reversibility rules are the same in all three.

| Level | Acts on | Evidence required | Confirmation |
|---|---|---|---|
| Light | Preinstalled data collectors with no known side effects on this model and build; sensitive permissions held by apps not used for months | A test on the same vendor, model and build | One preview of the whole batch |
| Medium | Adds non-essential permissions of rarely used apps, and unneeded preinstalled apps | A test on the same vendor and Android version | Card by card, highest impact first |
| Strict | Adds removal of apps that passed their quarantine | The same model, and the health checks passed | Item by item, with an extra confirmation for high-impact items |

Without a test on matching phones, an item drops to a lower level or to "inform only".

## Evidence

Each entry names the package, vendor, model, build or Android version, signing certificate, action,
outcome, test date and tester. It comes from the project's lab phones, which must cover several vendors.
The A40 and A56 are both Samsung phones, so the lab needs at least:
- a Pixel, as the reference for Android's own behaviour;
- a Xiaomi or Redmi phone;
- a phone from one of the low-cost brands that lead in many restricted markets, such as Tecno or
  Infinix.

The evidence is the project's own work, published under CC0 1.0 and shipped in signed data packs
([ADR 0015](decisions/0015-dataset-licences.md)). Community debloat lists are consulted for leads, never
copied: the widely used ones are copyleft, and their entries carry no test results. Every entry follows
ADR 0015's rules on evidence and disputes.

## The queue

- **Short and ordered by impact:** attention drops after the second card in a row, so the few actions
  that remove most of the risk come first.
- **Recommend, then confirm:** in studies, people accept most recommendations made this way.
- **Friction only for high-impact items:** a delay or an extra confirmation, never for every card.
- **Started by the user,** never by a notification.
- **No alarming totals:** the overview shows what to do, not how many problems there are.
- **A before-and-after summary,** and the journal, always one tap away.

## Working with Android and vendors

- Android's hibernation of unused apps already covers most user-installed apps; Datapavan focuses on what
  it skips.
- **Google Play Protect, where present.** Many phones in restricted regions have no Google services, so
  nothing may depend on it.
- **Android 16 Advanced Protection** can be read with a normal permission, and Datapavan shows it as a
  strength. Datapavan never depends on an accessibility service, which Advanced Protection restricts.
- **Vendor protections are respected,** never permanently switched off. Examples are Samsung's Auto
  Blocker and Xiaomi's separate security switch for USB debugging. When a step needs one of them off for
  a moment, the guide turns it back on.

## What triggers an action

- **A tracker finding means its code is present, not that it is active.** It ranks an app higher, for
  example an unused app with advertising trackers. It does not by itself remove anything.
- **Datapavan never says that a permission is "unneeded".** No published method infers that reliably.
  The triggers are an unused app that still holds a sensitive permission, a tracker's purpose, and a
  known preinstalled data collector.

## Releases

- **v0.1 (M4, M5):** the plan screen, the three levels, the queue, the journal of hand-offs and unused
  apps from usage access, all at the ordinary-app level.
- **v0.2:** traffic observations raise or lower an app's priority.
- **v0.3:** background network blocking becomes an action.
- **Stage 2:** the Device Owner edition and the work-profile isolation helper apply the plan without a
  confirmation per item.
- **Before any ADB bridge:** its own ADR.

## Open research

None of these is needed for v0.1:
- detecting tracker libraries after aggressive code shrinking;
- a map of which Android 14 to 17 APIs need which permission;
- inferring whether an app needs a permission, with almost no false positives;
- learning from small, high-risk groups of users without collecting their data.

Datapavan's scanner can help with the first: it can measure how often tracker SDKs are renamed beyond
recognition.
