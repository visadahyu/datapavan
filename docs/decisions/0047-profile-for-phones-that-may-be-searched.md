# 0047. A profile for phones that may be searched: nothing of use kept

- Status: Proposed
- Date: 2026-11-14

## Context

On 2026-11-14 the maintainer asked for a setting for two kinds of users. Some people's phones may be searched;
most people's will not be. For the first, the apps should leave nothing of use to whoever searches the phone.
For the second, nothing needs to change.

[ADR 0040](0040-own-safety-in-an-untrusted-environment.md) already gives every user:
- FLAG_SECURE on every screen, which also blanks the apps' cards in Recents;
- no connection log until the user chooses a retention;
- Watch's own lock, and an answer to PanicKit triggers;
- nothing in backups.

What it does not give is one choice that turns all of it to the safe side, and the rest of what the apps keep.

**What the apps keep today.** This list is read from the code on `main`. [PRIVACY.md](../../PRIVACY.md) lists
Basic's items; it does not list Advanced's yet, since Advanced is not released.

| Edition | What is kept | Where | What a searcher learns from it |
|---|---|---|---|
| Basic | The plan's journal: each change made through the plan, with the app, the time and what it held before and after | `journal.txt` in app-private files | Which apps the user changed and when. Where a partner or relative installed stalkerware, that the user found it and acted |
| Basic | The strict sensor review: which access each app had when the user reviewed it | `sensor_review` preferences | Which apps the user looked at closely |
| Basic | The tracker scan's results for each app and version | `tracker-scan.tsv` | Between two audits, an app that was installed and has since been removed |
| Basic | Data packs the user imported | `datapack/` | That a newer list was imported. The lists are public and signed |
| Basic | The appearance, and before Android 13 the language | `settings` preferences | Nothing of use |
| Advanced | All of Basic's, plus the connection log ([ADR 0037](0037-connection-log-storage.md)): the database, each day's wrapped keys and the Keystore key pair | App-private database and preferences | Which app spoke to whom, for as long as the retention keeps it |
| Advanced | The chain's settings: on or off, all apps or a list of apps, whether chained destinations are logged, the tool, its host and port, UDP, and the generated proxy password under a Keystore key | `chain` preferences | The user's circumvention tool, even after it was uninstalled before the search, and which apps the user sends through it |
| Advanced | The apps left out of the tunnel ([ADR 0041](0041-watch-visibility-and-coexistence.md)) | `left_out` preferences | Little: apps that do not work with a VPN |
| Advanced | The flows of this run, in memory, for Watch's screen | Memory | What apps did since Watch started, to anyone who opens Watch |

ADR 0046, drafted beside this one, adds a live view of what apps the user did not open sent: an ongoing
notification's summary, an optional widget on the home screen, a Quick Settings tile and an in-app "Now" view.
Each shows activity to anyone who looks at the phone, some of them on the lock screen.

**What a search is.** Three kinds matter, from the least to the most thorough:
1. **A glance.** A relative, a partner or an employer looks at the home screen, the notifications and Recents,
   and opens a few apps.
2. **A manual search of an unlocked phone,** at a border or a checkpoint. The searcher demands the unlock code,
   scrolls through the apps, opens them and opens Settings.
3. **An extraction.** A forensic tool copies the unlocked phone's data, app-private files included.

The profile aims at all three for what Datapavan itself keeps. It cannot hide what Android shows.

## Decision

### 1. The question, not a country

The first run of each edition asks the user about their own situation, never about their location:

> Could someone else look through this phone? For example at a border or a checkpoint, or someone in your
> family, your partner or your employer.
>
> - Yes, it could happen
> - No
> - I'm not sure

"Yes" and "I'm not sure" turn the profile on; "No" leaves it off. The screen says, before the answer, what
the profile changes and what it costs (decision 8). The answer can be changed at any time in Settings. No
screen, store text or document about the profile names a country or a region, and the apps never read the
phone's location, SIM country or language to guess the answer.

In Advanced the question comes in W9's onboarding before the retention choice. With the profile on, the
retention choice is not shown: the log keeps nothing.

### 2. One switch, named for what it does

The profile is one switch in each edition's Settings, labelled for what it does, not for who the user is:
**"Keep nothing on this phone"**. The switch is stored in the app's settings, so a searcher who opens Settings
can see that it is on. The label says only that the app keeps nothing, which many people choose for ordinary
privacy; it does not say that the user expects a search.

While it is on, the settings it sets are shown with their value and greyed out, with one line saying that the
profile sets them. A person at risk should not have to understand ten switches. The separate settings stay as
they are for everyone else.

Basic and Advanced may be installed together. They share no data and no UID (ADR 0045, decision 9), so each
asks the question and keeps its own switch; each says that the other edition has its own.

### 3. What the profile turns on

| Item | Ordinary users (unchanged) | With the profile |
|---|---|---|
| The connection log (Advanced) | Retention chosen at W9: none, 1, 7 or 30 days (ADR 0040) | Retention none: nothing is written (ADR 0037, decision 3) |
| Chained flows' destinations (Advanced) | Not recorded unless the user turns that on | Never recorded, and never shown: Watch's screens show a chained flow's app and bytes, and "through your tool". Proxy-like behaviour is still counted in memory (VPN.md) |
| This run's flows in memory (Advanced) | Shown until Watch stops | Cleared also when the screen turns off, so a phone handed over after it was locked shows nothing earlier |
| The tool, its host and port (Advanced) | Kept, to start faster | Not kept: Watch finds the tool again at each start, as it already can (RESTRICTED-REGIONS.md). An uninstalled tool leaves no trace in Watch |
| The chosen apps, the UDP choice and the proxy password (Advanced) | Kept | Kept, since the chain cannot work without them. Behind Watch's lock, and wiped by a wipe. "All apps through the tool" keeps no list |
| The apps left out of the tunnel (Advanced) | Kept | Kept, and wiped by a wipe |
| ADR 0046's widget | Offered | Its provider is disabled, so it cannot be added. One already placed shows only the app's mark, and the switch's screen asks the user to remove it, since no app can remove a widget from a launcher |
| ADR 0046's ongoing notification | Its summary | No summary. If Watch still posts an ongoing notification, its text is a neutral "On": no count, no app, no tool and no word for VPN; hidden on the lock screen (`VISIBILITY_SECRET`); silent |
| ADR 0046's Quick Settings tile | Its state and summary | On and off only, no count. Opening the "Now" view from it asks for the phone's unlock first (`unlockAndRun`) |
| ADR 0046's "Now" view | As ADR 0046 decides | Shows only this screen-on session, behind Watch's lock |
| Watch's own lock (ADR 0040) | Offered, off | On, with a code of its own, so that a forced unlock of the phone does not open it; it locks as soon as Watch leaves the screen or the screen turns off |
| The plan's journal (Basic, and the audit in Advanced) | Kept on disk | Held in memory only, and cleared when the screen turns off or the app's process ends. Leaving the app to make a change in Settings keeps it, so the plan still works within a session |
| The strict sensor review | Kept on disk | In memory only, cleared in the same way |
| The tracker scan's results | Kept on disk | In memory only: each audit scans every app again |
| Data packs, appearance, language | Kept | Kept: they say nothing about the user |
| Recents | The app's card shows, blank (FLAG_SECURE) | The app's tasks are excluded from Recents (decision 5) |
| Text fields | As the keyboard decides | `IME_FLAG_NO_PERSONALIZED_LEARNING` on every field, as Signal's "Incognito keyboard" does; keyboards may ignore it, and the apps say so |
| Copying a value (a fingerprint, a password) | Plain copy | Marked sensitive (`ClipDescription.EXTRA_IS_SENSITIVE`, Android 13 and later), so the clipboard's preview does not show it |
| Exports the user starts (v0.4) | A file in shared storage | Allowed, after a line saying that the file lives outside the app and outside the profile's reach |
| PanicKit | Answered at the user's choice (ADR 0040) | The wipe is the chosen answer (decision 7) |
| Backups | None | None (already so) |

Basic keeps no lock of its own, with the profile or without it. With the profile on, Basic keeps nothing the phone
does not show by itself: its audit is computed again from the phone each time. A lock would then protect nothing,
and would only draw the question of what is behind it.

Basic on Google Play (ADR 0031) has the same profile as Basic.

### 4. Turning it on and off

Turning the profile on wipes at once, after one confirmation, everything it would not have kept: the log and its
keys (as "Delete everything now" does, ADR 0037), the journal, the sensor review, the scan's results, and the
tool, host and port. Nothing is kept "for later". Turning it off restores nothing: the user chooses a retention
again, and the journal starts empty.

### 5. Recents

FLAG_SECURE already blanks the card's thumbnail. The card itself still shows the app's name and icon, which says
that the app was used recently. With the profile on, each app marks its tasks excluded from Recents at runtime
(`ActivityManager.AppTask.setExcludeFromRecents(true)`). Once the user leaves the app, its card is gone from
Recents.

What it costs:
- the user cannot come back through Recents, only through the app's icon, which opens the same task where it was;
- on some launchers the card stays until another app is opened;
- the round trip of the plan (the app opens a Settings screen, the user comes back with Back) has to keep
  working: tested on each Android version (decision 11).

Set aside:
- `android:excludeFromRecents` in the manifest would apply to every user, not only those who choose the profile;
- `finishAndRemoveTask()` on leaving would remove the card only when the user leaves with Back, not with Home;
- `setRecentsScreenshotEnabled(false)` (Android 13 and later) only removes the thumbnail, which FLAG_SECURE
  already blanks.

Android's own records still count the use: Digital Wellbeing's screen time, and Settings' list of recently opened
apps on phones that have one (decision 8).

### 6. The live view of ADR 0046

ADR 0046's views exist to show activity at a glance, which is what a searcher looks for. With the profile on, they
show nothing of use (decision 3). ADR 0046 decides their shape; this ADR decides only what the profile turns off
in them, and the profile's tests check them (decision 11).

### 7. Wiping: a panic trigger and a button

- **In the app.** With the profile on, "Delete everything now" is in each app's main menu and on Watch's lock
  screen, one tap and one confirmation. It deletes everything the app keeps but the profile's switch, the
  appearance, the language and the data packs.
- **PanicKit.** Both editions answer [PanicKit](https://guardianproject.info/code/panickit/) triggers, as ADR
  0040 decided for Watch. PanicKit's rules hold: a trigger app may make an app destroy data only once the user
  has connected the two, and the connection is never made automatically. With the profile on:
  - from the connected trigger app, the answer is the wipe above;
  - from any other app, the answer is only to lock Watch and clear the flows in memory, which loses nothing
    kept. So an app that sends the trigger on its own cannot make Datapavan delete anything.

  The responder is a small exported activity with no screen. It is added to each edition's allowlist of exported
  components (ADR 0045, decision 9). The protocol is a few intents; the project implements it itself rather than
  take its library (`info.guardianproject.panic:panic:1.0`), as ADR 0037 kept to Android's own cryptography. The connected trigger app is pinned by
  its package and signing certificate when the user connects it. Onboarding names trigger apps with which the
  responder was tested (Ripple, and Wasted, which also offers a tile, a shortcut and a wipe after the phone stays
  locked too long) without installing anything.
- **The tunnel after a wipe.** A wipe while Watch runs keeps the chain only in memory until the tunnel stops, so
  the chosen apps never go out directly (VPN.md: "Watch must not become the leak"). The next start asks for the
  apps again.

### 8. Honest limits, told when the user chooses

The question's screen, the switch's screen and the website say, in plain words:
- **The apps can be found.** Without root an installed app cannot hide itself. Settings' list of apps shows both
  editions. While Advanced runs, Android shows its key icon, and its VPN page names Advanced. Android's own records
  can show that the apps were used: screen time, battery and data use, and the list of recently opened apps. A
  searcher who has the unlocked phone can see that the apps exist.
- **The aim is that nothing useful is found, not that nothing is found.** What a searcher can learn from the apps
  is what the phone already shows: which apps are installed. The apps keep no history of what the user did or
  what other apps did.
- **The switch itself shows.** Settings shows that "Keep nothing on this phone" is on.
- **Some things are lost.** The plan's undo and its check that a change came back work only until the screen
  turns off; each audit scans every app again; a wipe means choosing the chained apps again.
- **To leave no trace of the apps at all,** uninstall them before the search and install them again afterwards
  from a source you trust. With this setting on, almost nothing is lost by doing so. An APK file left in Downloads
  would be found too.
- **Android's private space** (Android 15 and later, where the maker offers it) hides the apps installed in it
  from the launcher, Recents, notifications and Settings while it is locked
  ([AOSP](https://source.android.com/docs/security/features/private-space)). It suits Basic. It does not suit
  Advanced: the space's apps are stopped while it is locked, and a VPN covers only the apps of its own profile. A
  searcher may also demand that the space be opened.

### 9. No disguised icon or name

An activity-alias can give an app another icon and another name in the launcher.

**What the field does:**
- **Signal** lets users change its icon on Android, and from version 6.21.3 (May 2023) the name under it too
  ([AlternativeTo](https://alternativeto.net/news/2023/5/you-can-now-change-signal-s-icon-and-name-to-make-it-look-like-another-app)).
- **Proton VPN**, on Google Play, offers a disguised icon and name, for phones that soldiers and police inspect.
  Its page says that Android's "VPN connected" notification cannot be hidden, and advises disconnecting before
  a search ([Proton](https://protonvpn.com/support/disguise-app-icon)).
- **Tella** changes its name and icon, or hides behind a working calculator. Its page says that its name and
  icon "will remain visible in the Android settings", and that camouflage will not stop someone who is actively
  searching the phone ([Tella](https://tella.app/features)). Tella is on Google Play and F-Droid
  ([README](https://github.com/Horizontal-org/Tella-Android)).

**Google Play.** Play's Misrepresentation policy forbids apps that "misrepresent or conceal their ownership or
primary purpose" ([Google](https://support.google.com/googleplay/android-developer/answer/9888689)). It names the
store listing's title and icon, not an icon the user chooses inside the app, and Signal, Proton VPN and Tella ship
in-app disguises on Play. So Play's policy does not settle the question; a reviewer could still read "conceal"
against it.

**Weighed:**
- **It hides less than it seems to.** It changes the launcher and nothing else: Settings' app list, the battery
  and data use screens and notifications keep the real name. For Advanced, the VPN gives it away each time: the
  key icon, the VPN page and the consent dialog all name Advanced.
- **At a serious search, a disguise found is worse than an app in plain sight.** Datapavan is a security audit, a
  lawful and ordinary kind of app. A "Weather" app that turns out to be Datapavan reads as concealment, and invites
  the question of what else is hidden.
- **It works against what the project teaches.** ADR 0024 teaches users to trust Datapavan by its name and its
  signing key, and to distrust copies that pose as something else. ADR 0045 keeps the full names under the icons.
  An official Datapavan that poses as another app blurs both lessons.
- **The glance has a better answer.** For a relative or a partner who looks at the home screen, Android's private
  space hides Basic completely where the phone has one, and uninstalling hides both editions. A disguise covers the
  launcher only, and may fail at the worst moment.

**Decided:** no disguise is offered. This is below the field on the glance case, on purpose. To be revisited only
if the redesign's tests with real users at risk (ADR 0045, decision 8) show that the glance is common where private
space is missing. A later ADR could then offer, for Basic only, a neutral icon and name that imitate no real app.
It would be off by default, outside the first run, with the risk stated beside it.

### 10. No duress code and no decoy

A duress code is a second unlock code that wipes; a decoy is a second code that shows an empty app.

**What the field does:**
- **GrapheneOS** offers a duress PIN and password for the whole phone. Entered anywhere the phone asks for its
  credentials, it irreversibly wipes the phone and its eSIMs; the wipe "cannot be interrupted"
  ([GrapheneOS](https://grapheneos.org/features)).
- **Tella** offers deletion after 5, 10 or 20 failed unlocks, off by default ([Tella](https://tella.app/features)).
- **Wasted** locks or wipes the phone on triggers, among them a duress password through a companion app
  ([Wasted](https://github.com/x13a/Wasted)).

**Weighed:**
- **Android's limits.** Without root, no app sees the phone's unlock code. A duress code for the phone exists only
  in the operating system. Apps that try from outside watch the lock screen through an accessibility service,
  which is the access Datapavan's audit warns about; Datapavan never holds it.
- **A duress code in Watch's own lock** would wipe only what the profile already does not keep: the chosen apps
  and the password. The gain is close to none.
- **A decoy adds deception, not protection.** With the profile on, the apps already show what a decoy would: an
  app with nothing in it, honestly. A decoy would need the real data kept somewhere to show it to the right code,
  which is the opposite of keeping nothing; and found by someone who knows the app, or in an extraction, it is
  worse than having nothing.
- **Wiping in front of a searcher can itself be charged.** In 2025 a traveller whose phone was said to have been
  wiped by a duress code during a border search was charged under a law against destroying property to prevent
  its seizure, and pleaded not guilty ([Freedom of the Press Foundation](https://freedom.press/digisec/blog/protester-targeted-by-doj-over-phone-wiping-duress-passcode/), 2026-07-29).

**Decided:** no duress code, no decoy and no wipe after failed unlocks. The profile's answer is that at the moment
of a search there is nothing left to wipe: nothing is kept, memory clears when the screen turns off, and a wipe,
if the user wants one, happens before, through the button or a panic trigger. The website's guide for people whose
phone may be searched names GrapheneOS's duress code and the case above, so that the user can decide; the apps do
not recommend it.

### 11. Tests, and when it is done

On the Android 10, 15 and 17 emulators and the Galaxy A40, with debug builds where a check needs `run-as`:
- **A scripted session under the profile:** an audit, a change through the plan and back, a sensor review, and in
  Advanced the tunnel with a chain and traffic from several apps. Then the screen is turned off and on again.
  Afterwards:
  - app-private storage holds no journal, no sensor review, no scan results, no log database or write-ahead log,
    no wrapped day key, no log key pair in the Keystore, and no tool, host or port;
  - Watch's screen and the "Now" view show nothing from before the screen turned off;
  - no chained destination appears on any screen or in logcat;
  - `dumpsys notification` shows no ongoing notification but the neutral one, hidden on the lock screen;
  - the widget provider is disabled, and a widget placed before shows only the mark;
  - `dumpsys activity recents` lists no visible task of either app once the user has left it;
  - the plan's round trip to Settings and back still works.
- **Turning the profile on** deletes, at once, what it would not have kept; **turning it off** restores nothing.
- **PanicKit:** a test trigger app connected to the responder makes it wipe everything decision 7 names; the same
  trigger from an app that is not connected only locks Watch and clears memory, and deletes no file. Checked by
  hand once with Ripple and Wasted. The model-based test of ADR 0037 gains the profile and the wipe among its steps.
- **Ordinary use keeps everything:** with the profile off, the journal survives a restart, the log keeps the chosen
  retention, the widget and the summary show, and the app's card stays in Recents, blank.
- **Measured:** the time of a full audit without the scan's results on the A40, which decision 8 states to the user.
- **The lab's record:** what Android's own records show of the apps after a session (screen time, battery and data
  use, recently opened apps, notification history, Recents on each launcher tested), published as the evidence
  behind decision 8's text.
- **Words:** the question, the switch, the limits and the neutral notification text, in the eight languages, made
  and reviewed as ADR 0030 sets out. PRIVACY.md lists what each edition keeps, with and without the profile.

The profile is done when all of the above pass in CI or in the release check (ADR 0039), and the threat model
(DESIGN.md §8) names it in its row on seizure and inspection.

## Best in class, checked on 2026-11-14

| Tool | What it offers for a searched phone |
|---|---|
| Tella | A lock required at install, locking at once by default; "Quick delete", a slider on its home screen; deletion after failed unlocks, off by default; camouflage ([Tella](https://tella.app/features)) |
| Molly | Its database encrypted under a passphrase, locking by itself under conditions the user sets, and "RAM shredding" ([Molly](https://github.com/mollyim/mollyim-android)) |
| Briar | A lock of its own with a timeout of inactivity ([manual](https://briarproject.org/manual/)); answers PanicKit by signing out, with deleting the account as an opt-in answer ([issue 204](https://code.briarproject.org/briar/briar/issues/204)) |
| Signal | A screen lock of its own ([Signal](https://support.signal.org/hc/en-us/articles/360007059572)), "Incognito keyboard", which Signal says keyboards may ignore ([Signal](https://support.signal.org/hc/articles/360055276112-Incognito-Keyboard)), and a changeable icon, and on Android name ([Signal](https://support.signal.org/hc/en-us/articles/6325632279834-Change-the-Signal-app-icon-on-your-phone)) |
| Guardian Project's PanicKit | Ripple as the trigger; responders such as F-Droid, NewPipe and Zom hide, lock or clear; destructive answers only after the user connects the apps ([PanicKit](https://guardianproject.info/code/panickit/)) |
| Proton VPN | A disguised icon and name; says the VPN notification cannot be hidden ([Proton](https://protonvpn.com/support/disguise-app-icon)) |
| GrapheneOS | A duress code that wipes the whole phone ([GrapheneOS](https://grapheneos.org/features)) |
| Android 15 | Private space, which hides its apps while locked ([AOSP](https://source.android.com/docs/security/features/private-space)) |

**Honestly:**
- **Above the field:**
  - The core: what the apps can compute again is not kept at all. Tella, Molly and Signal must keep messages and
    files, so they encrypt and lock them; Datapavan's data can be recomputed, so it can afford to keep nothing.
  - One question sets everything, where the field offers separate switches.
  - Memory is cleared when the screen turns off.
  - Behind it all, the log's keys are destroyed rather than its rows deleted (ADR 0037).
- **At the field's level:** the lock, the PanicKit answer, screen security and the incognito keyboard flag.
- **Below the field, on purpose:** no disguise (Signal, Proton VPN and Tella offer one) and no wipe after failed
  unlocks (Tella offers one), for the reasons in decisions 9 and 10.
- **Not done:** Molly's overwriting of free memory. The JVM cannot promise that a value is gone, and reading
  another app's memory needs a root exploit, which ADR 0037 already accepts as a limit.

No frontier research is needed. One piece of lab work is: measuring what Android's own records show (decision 11).

## Consequences

- **People at risk answer one question** and get everything this ADR lists. Ordinary users see one question at the
  first run and nothing else changes for them.
- **Costs under the profile:** the plan's undo and its check that a change came back last only one session; each
  audit is a full scan; Recents no longer brings the app back; after a wipe, the chained apps are chosen again.
- **Build:** a PanicKit responder in each edition, added to the allowlists of exported components; the switch read
  by the journal, the review, the scan, the log, the chain, ADR 0046's views and the activities' task setup.
- **Documents to change when it is built:** PRIVACY.md (what each edition keeps, Advanced's items included), DESIGN.md
  §6.4 and §8, W9's onboarding in §13.2, and the website's guide for people whose phone may be searched.
- **RESTRICTED-REGIONS.md's row on phone inspection** points here.
- **Strings in eight languages,** with the closest reading for the question and the limits, which carry real weight.

## Questions for the maintainer

1. **"I'm not sure" turns the profile on.** The cost of leaving it off by mistake (evidence on the phone) is
   greater than the cost of turning it on by mistake (a lost undo). Agreed?
2. **The Verifier's pins** (ADR 0040, decision 6, not built yet) name a phone's attestation key, not an app.
   Proposed: kept under the profile and left out of the wipe, since losing a pin weakens the next check. Agreed?
3. **The disguise** (decision 9): closed now, to be reopened only after the tests with real users. Agreed?
