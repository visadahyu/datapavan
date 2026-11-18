# 0046. What apps sent while the user was not using them, shown live

- Status: Accepted (by the maintainer on 2026-11-15)
- Date: 2026-11-14
- Amends: [ADR 0025](0025-guided-check-and-traffic-facts.md) decision 1, for Advanced's live
  surfaces only; [ADR 0034](0034-watch-permissions.md), by one exported component (the widget), and its line on
  `PACKAGE_USAGE_STATS`; [ADR 0022](0022-network-use-and-unused-apps.md) decision 2, for Advanced only, which now
  reads the event stream (noted 2026-11-18); DESIGN.md's W5 row; the roadmap's line on the widget.

## Context

Android shows when an app uses the camera, the microphone or location. It shows nothing when an app sends data.
Yet taking data off a phone needs sending it, and sending crosses the network, where Watch, the local VPN of
Datapavan Advanced ([ADR 0045](0045-three-editions-of-one-app.md)), already sees each flow:
- its app, by UID ([VPN.md](../VPN.md), "Which app?");
- its name and where the name came from (W3);
- its destination address and organisation ([ADR 0036](0036-ip-to-organisation-dataset.md));
- its bytes each way, counted as they pass ([ADR 0037](0037-connection-log-storage.md), decision 5);
- its start and end time.

Advanced is one package, so it holds Basic's usage access as well (ADR 0014; the user grants it in Settings). With
it, Watch can tell which app is on screen. A flow from an app that is neither on screen nor recently used is "in
the background": the mark that W5 and the roadmap's log ("foreground or background") already planned.

Today no screen on `main` shows an app's connections, while Watch's tagline says "See where each app on your phone
connects." (`watch_tagline`). W5, the per-app view, is a gate of 0.2.0. ADR 0045 dropped W5's interface between two
apps ("Advanced reads its own log") but did not say what Advanced shows. This ADR says it, and so says how the W5
gate is met.

What earlier decisions require of it:

- **Facts, never alerts** ([ADR 0025](0025-guided-check-and-traffic-facts.md), decisions 1 and 4): nothing about an
  app's traffic becomes a notification, a badge, a colour, a score or a rank, and no string calls traffic unusual,
  suspicious, normal or excessive. The reason still holds: real cases are rare, so most flags of even a good
  detector are wrong, and the one consumer precedent (Norton App Advisor, 2016) was called paranoid.
- **No log that becomes evidence by default** ([RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md#principles),
  [ADR 0040](0040-own-safety-in-an-untrusted-environment.md) decision 2): retention is the user's choice, none until
  then. Chained apps' destinations are not recorded unless the user turns that on ([VPN.md](../VPN.md)). No
  notification names a VPN or a tool.
- **The log opens only on an unlocked phone** (ADR 0037), and every screen blocks screenshots (ADR 0040).
- **No foreground service** ([ADR 0034](0034-watch-permissions.md), "Watch does not request"). Android binds the
  VpnService itself, and Watch calls no `startForeground`. So Android does not require any notification of Watch:
  a live summary would be a notification that Watch chooses to post, under `POST_NOTIFICATIONS`, which ADR 0034
  already lists for "Watch's few notices".
- **The roadmap's widget** "shows only its state and the date of the last check, never a count of problems", and
  v0.1 kept a widget out because it "would tell anyone who looks at the phone more than the icon does".

Tags, as in ADR 0034: **[doc]** Android's documentation; **[code]** AOSP source, not tested on a device;
**[device]** measured in a spike; **[source]** another app's published source; **[unverified]** not checked.

## Decision

### 1. The data: what Watch already sees, and the app on screen

**Flows, as today.** The engine counts bytes each way per flow as they pass. It adds one thing: for each app, the
bytes each way in one-second slots over the last minute. When the app's state for a moment is known, those slots
are assigned to that state. A long connection, such as a messenger's own push connection, is cut into segments
where its app's state changes, as ADR 0037 already cuts flows every 15 minutes. So the bytes an app sends after
the user leaves it count as background, even on a connection opened while it was on screen.

**The app's state, from `UsageStatsManager.queryEvents`** (usage access, `PACKAGE_USAGE_STATS`, already granted to
the package for the audit):

| Event | API | What it gives |
|---|---|---|
| `ACTIVITY_RESUMED`, `ACTIVITY_PAUSED` | 29 | An activity of a package came to the foreground or left it, with its class name; one event per activity [doc] |
| `ACTIVITY_STOPPED` | 29 | The activity is no longer visible [doc] |
| `FOREGROUND_SERVICE_START`, `_STOP` | 29 | A foreground service, which shows its own notification, started or stopped [doc] |
| `USER_INTERACTION` | 23 | "A package was interacted with in some way by the user" [doc]; in AOSP, among others, a tap or reply on its notification [code; to test] |
| `SCREEN_INTERACTIVE`, `SCREEN_NON_INTERACTIVE` | 28 | The screen turned on for use, or off (ambient display counts as off) [doc] |
| `KEYGUARD_SHOWN`, `KEYGUARD_HIDDEN` | 28 | The lock screen showed or was dismissed [doc] |
| `DEVICE_SHUTDOWN`, `DEVICE_STARTUP` | 29 | Open intervals across a restart are to be ignored [doc] |

Every event has a time stamp, so a flow is placed by the events' times, not by when Watch read them. Each flow's
app is then in one of three states:

- **in use:** an activity of the app (or of any package sharing its UID) was resumed or visible, or the user
  interacted with it, at that moment or within a grace period before it. The grace covers an upload that finishes
  after the user leaves the app. It starts at 30 seconds, and the lab run of decision 4 sets it;
- **with its notification:** the app ran a foreground service, which Android shows the user (music, navigation,
  an upload it announced);
- **in the background:** neither. Push syncs, jobs, widgets' updates and anything else the user did not start.

Datapavan's minimum is Android 10 (API 29, ADR 0003), so every event above exists on every supported version.

**How often.** Watch reads events incrementally, only from its last reading: when a flow starts and the last
reading is more than five seconds old, while the screen is on; at most once a minute while the screen is off, and
only when traffic runs. There is no timer that wakes the phone. The screen's state comes from the events and from
`ACTION_SCREEN_ON`/`OFF` broadcasts registered at run time, which need no permission.

**What breaks, and how Watch says so:**

- **Before the first unlock after a restart, `queryEvents` gives an app an empty record** (Android 11 and later).
  Its documentation speaks of null, but `UsageStatsManager` turns the service's null into an empty result, for
  a user not unlocked yet, for a caller without access and for a range not valid alike [code: `UsageStatsManager`,
  `android-11.0.0_r1` and `main`; `UsageStatsService`]. So Watch asks `UserManager.isUserUnlocked` first, and flows
  of that time get no state, "no events" (corrected 2026-11-18, after the second review of W5's second part). With
  always-on, Android starts Watch only after the unlock anyway (ADR 0034).
- **Without usage access**, flows have no state. Access taken away between Watch's check and its query gives an
  empty record too, so Watch asks again after a query that found nothing, and tells such a reading as no access. The
  view then shows each app's traffic without the mark, and offers the grant. The summary of decision 2 stays off,
  since it would count nothing. Android 17 locks usage access for apps installed from a file until the user allows
  restricted settings (roadmap, M4 checks); onboarding says so.
- **Events only reach a few days back** ("Events are only kept by the system for a few days" [doc]). The live view
  needs seconds; the history needs only what Watch recorded at the time.
- **Vendors.** Split screen, floating windows (Samsung's pop-up view), picture in picture and vendors' own launchers
  report resumed activities in ways that may differ by vendor [unverified]. Several apps can be in use at once; each
  is. The device tests cover Samsung (A40, A56) and the emulators; other vendors when the lab has them (DESIGN §4).

**No new permission, no overlay, no accessibility service.**

- **No accessibility service.** RethinkDNS knows which app is in front through one (`BackgroundAccessibilityService`
  in its manifest [source]). An accessibility service can read every screen. That is the remote-control access
  that the audit flags in VPN apps ([RESTRICTED-REGIONS.md](../RESTRICTED-REGIONS.md), "Untrusted VPN apps").
  Advanced would become the kind of app it warns about, and ADR 0045's sentence against fakes would weaken.
- **No overlay** (`SYSTEM_ALERT_WINDOW`). The audit flags it too, and a floating counter over other apps shows to
  anyone near the phone and in any screen recording.
- **Nothing else would do.**
  - `getRunningTasks` has been "no longer available to third party applications" since Android 5; it still returns
    "at least the caller's own tasks, and possibly some other tasks such as home that are known to not be
    sensitive" [doc].
  - `getRunningAppProcesses` is documented only as "intended for debugging". In AOSP it returns the caller's own
    processes unless the caller holds `REAL_GET_TASKS` (signature or privileged) or is the recents component
    [code: `ActivityManagerService`, `ProcessList`, `ActivityTaskManagerService.isGetTasksAllowed`].
  - `registerAppUsageObserver` is `@SystemApi` and needs `OBSERVE_APP_USAGE`, whose protection level is
    signature, privileged or role [code: `UsageStatsManager`, `core/res/AndroidManifest.xml`].

  Usage events are the public route. The audit itself reads only totals (`queryAndAggregateUsageStats` and
  `NetworkStatsManager`, ADR 0022, decision 2), never the event stream: Advanced is the first of Datapavan to read
  it, and ADR 0022 carries a note for it (corrected 2026-11-18; this sentence said the audit already used it).

### 2. Where it shows

**(a) A summary in a notification, chosen at onboarding.** Watch posts it while the tunnel runs, on a
channel of its own: low importance, silent, no badge, updated without alerting again. Examples of its text:
- "In the last 10 minutes, 3 apps you were not using sent 2.1 MB."
- "While the screen was off (2 h 10 min), 4 apps you were not using sent 6.3 MB." This form shows for a few
  minutes after the screen comes on, then the first returns.
- "In the last 10 minutes, no app you were not using sent data."

Its window starts at 10 minutes, and the lab run of decision 4 sets it. It counts the apps "in the background" that
sent more than a floor set by the lab run (a messenger's keep-alive is not news). A tap opens the "Now" view, behind Watch's own lock when the user set one (ADR 0040). It is not a
foreground service, so ADR 0034's choice stands. If ADR 0034's fallback (a `systemExempted` foreground service) is
ever taken, the summary moves into that notification. The user can dismiss it (Android 14 lets users dismiss even
ongoing notifications, except while the phone is locked [doc]); it comes back only when Watch starts again.
Onboarding (W9) asks about it together with the question of the inspection profile (decision 3), with what it
shows and who can see it. It is on for users who do not choose that profile and off for those who do. It is not
shown before onboarding has asked.

**(b) An optional home-screen widget, in 0.2.1,** after the lab run, with the same counts and sizes, and Watch's
state. No colour, no badge, no
app name. It is drawn with `RemoteViews`, so no new library (Compose's Glance would be one). It is declared for the
home screen only, never for the lock screen. Its receiver is exported, as widget receivers are, accepts nothing from
the intent and only redraws Watch's own numbers; ADR 0034's list of exported components and the build's allowlist
grow by it. Whether a non-exported receiver works with every launcher is a device test.

**(c) The Quick Settings tile (W9)** turns Watch on and off, and its subtitle states Watch's state. It shows the
counts only while the phone is unlocked (the tile reads `isLocked()` when the panel opens), since Quick Settings can
be pulled down on a locked phone.

**(d) "Now", inside the app**, reached from the summary, the tile, the network page and each app's page:
- one row per app that used the network in the window (10 minutes, 1 hour, or since the screen came on), with its
  state, bytes up and down, and its destinations as W3 names them, each with where the name came from;
  (2026-11-18: each destination shows the name the connection itself sent and, where it differs, the DNS name
  beside it, in "Now" and in the history alike: ADR 0044, decision 4, built in W5's first part.)
- apps "in the background" first, then "with its notification", then "in use"; within each, by bytes sent;
- tracker destinations marked from the εxodus network signatures already in `data/exodus/trackers.tsv`, and nothing
  else (W5's plan);
- the flags of decision 4 beside the app they concern;
- a tap on an app opens its history: W5's "who did this app talk to?" as a timeline from the log, with the state of
  each segment, for the days the user chose to keep.

"Now" reads the engine's live counters in memory, so it works with retention "none" too: what it shows is then gone
when Watch stops. The history reads the log, which opens only on an unlocked phone (ADR 0037). Both are screens of
Watch's process (`:watch`), opened by a non-exported intent as Watch's screen is today (`ui/WatchEntry.kt`); only a
package name crosses from the audit's app page. Rows keep their order while the view is open, and re-sort only when
the user asks, so nothing moves under a finger or a screen reader's focus.

**Update rates and the battery budget:**

| What | Screen on | Screen off |
|---|---|---|
| Engine's slots | as packets pass (an addition on the existing path) | same |
| Usage events | on a new flow, at most every 5 s | at most once a minute, only with traffic |
| Summary | at most once a minute, when its numbers change | never; once when the screen comes on |
| Widget | at most every 5 minutes, when its numbers change | never; once when the screen comes on |
| Tile | when the panel opens | when the panel opens (state only) |
| "Now" | every second while open | not open |

*Noted 2026-11-18, W5's second part:* the screen coming on, a clock set, and Watch's start and stop each read at
once, so such a reading can come within 5 seconds of the one before; the screen turning off reads once more, past
the readings' margin, at the screen-on rate; and an ask that comes too soon is made in its turn, not dropped.

Nothing here wakes the phone: work happens while traffic already runs or the screen is on. The budget is Watch's
own, not an addition: Watch with the summary on still meets W9's bar of at most 3 % of a day's battery (DESIGN §7).
A paired measurement on the A40, the same workload with the summary off and on, must show the difference below a
tenth of Watch's own share. The widget is measured the same way before 0.2.1.

### 3. What may show where

Anything on the home screen, the lock screen or in a notification can be seen by whoever holds the phone, and also
by:
- apps with notification access, which read every notification's text;
- Android's notification history;
- a paired watch, unless the notification is marked local only;
- the launcher, which draws a widget's content in its own process;
- accessibility services, and screen recordings: `FLAG_SECURE` covers only the app's own windows.

| Surface | Who can see it | What it may show |
|---|---|---|
| Summary notification | Anyone who unlocks the phone, notification listeners, the notification history | Counts and sizes only. Hidden on the lock screen (`VISIBILITY_SECRET`), local only (not sent to a watch) |
| Widget | Anyone at the home screen, the launcher | Counts, sizes and Watch's state |
| Flag notice (opt-in) | As the summary | A count of new flags only. Hidden on the lock screen, local only |
| Tile | Anyone who pulls down Quick Settings, locked or not | Watch's state; counts only while unlocked |
| "Now" and the history | Whoever unlocks the phone and passes Watch's own lock, if set | Apps, destinations, sizes, times and flags; blocked from screenshots |

**The rule: outside the app, counts and sizes only, never an app's name and never a destination.** An app's name
outside the app would say which apps the user has, and with a destination, what they do. Inside, the details stay
behind the screen lock and Watch's own lock, as the log's records do (ADR 0037, ADR 0040).

**Chained apps.** Their destinations are not shown in "Now" either unless the user turned on "Log where these apps
connect" (`chain_log_destinations`). Without it, their rows say only that they went through the user's tool, with
their bytes and state. What the screen shows, a search of an unlocked phone shows too.

**A profile for people whose phones may be searched.** [ADR 0047](0047-profile-for-phones-that-may-be-searched.md)
defines this inspection profile, which the user chooses with one switch, "Keep nothing on this phone": off for
users who do not face searches, on for those who do, decided by the user's own answer and never by country. This
ADR's surfaces must follow it. Under that profile the summary, the flag notice and the widget are off, the tile
shows only Watch's state, and nothing is kept: retention is none and the minimal baseline of decision 4 is not
kept, so "Now" holds only memory and the flags do not run.

### 4. How it is framed, and what is flagged

**Background traffic is mostly ordinary.** Mail syncs, messengers receive pushes, backups run, widgets update. The
words say what ran without the user ("sent while you were not using it"), never "stole", "spied" or "leaked", and
follow ADR 0025's list in every language: absolute numbers first, no word that judges.

**Two flags, stated as facts, whose words show only inside the app:**

1. **An app's first background send:** "First time in the 30 days Watch keeps: [app] sent [X] while you were not
   using it."
2. **A volume far above the app's own usual:** "[App] sent [X] while you were not using it. On the other days Watch
   keeps, it sent at most [Y] in a day."

Both compare the app only with itself. They need at least seven days of history, and the lab run may set more. The
history comes from one of two places:

- **The log,** when the user keeps it for seven days or more. Nothing else is kept for the flags.
- **A minimal baseline, by the user's choice,** offered in the settings and off by default, so that flags work with
  a shorter retention or with none. It holds one number per app: the most the app sent in the background in one
  day, before today. It holds no time, no date for the app, no destination and no day-by-day series; the only date
  is when the user turned it on, for the seven days of learning. Today's total stays in memory and replaces the
  number at midnight if larger. With it, flag 2 reads "Before today, the most it sent in one day while you were
  not using it was [Y]", and an app with no number yet, after the learning days, gives flag 1. It is kept apart
  from the log, in Watch's private storage, sealed with a Keystore key that works only while the phone is unlocked
  (as ADR 0037's private key does); what a locked period adds waits in memory and is written at the next unlock.
  An app's number is deleted when the app is removed. The baseline is wiped with the log ("Delete the log now",
  the panic wipe of ADR 0040), its key with it, is never kept under the inspection profile, and is deleted when the
  user turns that profile on.

**Why this baseline is acceptable where a full one was not.** The full baseline set aside earlier would have kept,
past the user's retention and without asking, which apps sent in the background, when, and how much, day by day: a
timeline of the phone's use. A search of a phone with the minimal baseline learns, for each installed app that has
sent in the background since the user turned it on, the size of its largest day, and when the user turned it on.
It learns no time, no destination and no pattern. The app list already shows which apps are installed, and
Android's own data-usage screen already shows each app's background data for the last month to anyone who unlocks
the phone (ADR 0022). So the baseline adds almost nothing that a search finds elsewhere, and only for users who
chose it.

Set aside: comparing with other apps or with lab ranges per kind of app. Those ranges need their own ADR first (ADR
0025, point 5). With neither the log for seven days nor the baseline, there are no flags, and the view says why and
how to have them.

The thresholds (the floor of what counts as sending, the grace period, how many days, how far above) come from a
lab run recorded in `docs/spikes/` before they ship: W3's ten-app session and an idle night on the A40 and the
emulators, the same lab W8 plans for proxy-like behaviour. Every flag on that session is explained in the notes.

**No flag reaches the summary, the widget or the tile.** They show neutral counts, never a count of flags, in no
warning colour. This keeps ADR 0025's reason: a notification about one app, mostly wrong, teaches people to ignore
it or to remove what they need.

**A flag notice, only if the user turns it on.** A separate setting, off by default, lets a new flag raise a silent
notification on a channel of its own: a count only, with no app and no destination named, for example "1 event to
look at. Tap to see it." It follows the summary's rules (hidden on the lock screen, local only, no colour, no
badge), opens "Now" behind Watch's own lock, and never exists under the inspection profile. The words avoid
"unusual", which ADR 0025's list rules out.

**What this changes in ADR 0025.** Decision 1 is amended for Advanced's live surfaces, and only so far as this:
- a count across all apps of those that sent while not in use, with sizes and no app named, may appear in the
  summary notification and the widget;
- a count of new flags, with no app or destination named, may appear in the flag notice, once the user turned it
  on.

Nothing about one app becomes a notification, a badge, a colour, a score or a rank, and decision 4's words hold
everywhere.

**Destinations.** No destination is ever called malicious. Trackers are named only from the εxodus network
signatures, as W5 planned, and an organisation only from the dataset of ADR 0036.

### 5. What the view cannot see, said on the view

A short section "What this view cannot see" sits at the end of "Now", in plain words:

- **Traffic sent on an app's behalf is shown under the sender.** Push messages come through Google Play services,
  downloads through Android's download manager, and some apps send through another app. Their bytes show under
  that sender, not the app that asked. A messenger that fetches a message after a push shows its own fetch, in the
  background, which is ordinary.
- **Content is not seen.** Encrypted traffic shows its size, destination and time, never what was sent.
- **Use on the device is not seen.** Whether an app read contacts, files, photos or messages on the phone is not
  visible to any app without root: Android's history of such access (AppOps) needs a permission that apps cannot
  hold. Only the sending shows.
- **Some apps cannot be told apart.** Apps that share one UID count together (ADR 0022). Keyboards, live
  wallpapers and other services that the system binds have no activity of their own: a keyboard is counted "in use"
  while the screen is on, since it may be shown, and "in the background" while the screen is off (ADR 0025's
  keyboard spike: Android counts a shown keyboard as foreground). The user's circumvention tool carries the chained
  apps' traffic, so its bytes include theirs; it is marked so and not counted in the summary.
- **Gaps in the tunnel.** Nothing is seen while another VPN holds Android's one VPN slot, for apps the user left out
  (ADR 0041), for apps in a work profile, a private space or another user, which have VPNs of their own, before
  the first unlock after a restart, or when traffic goes around the VPN (DESIGN §7). Traffic between apps over
  loopback never enters the tunnel.
- **Sizes** are what the apps sent and received through Watch. Android's data-usage screen also counts headers and
  resent packets, so it shows a little more.
- **"In use" is what Android records of activities** (noted 2026-11-18, after the second review of W5's second part).
  Two things real apps meet follow from it. The feed left of the home screen on Google's launchers is the Google
  app's window over the launcher, not an activity of the Google app, so its traffic while the user scrolls it
  counts as in the background [source: Launcher3's `LauncherOverlayManager`; to check on a Google Play emulator
  image in the lab run]. And an app that Android lets start activities from the background, such as one with an
  accessibility service the system binds or with "display over other apps", can resume an activity, even an
  invisible one, just before it sends, so that its sending counts as in use for the grace after; such access is
  what stalkerware holds, and the audit flags it.

### 6. Tests, and when it is done

On the emulators with Android 10, 11, 15 and 17, by script, with debug builds' screenshot switch (ADR 0040):

1. A workload app sends in the background, on a timer and through a long connection opened while it was on screen,
   while another app is on screen. "Now" names it "in the background" with its bytes within 5 % of what it sent; the
   app on screen is "in use"; a foreground service is "with its notification".
2. The summary shows the right count and size; it shows nothing on the lock screen; it is marked local only; it does
   not exist before onboarding has asked, nor under the inspection profile, and is gone with `POST_NOTIFICATIONS`
   denied. The flag notice does not exist until the user turns it on, never under the inspection profile, and
   carries only a count.
3. The tile shows counts only while unlocked; for 0.2.1, the widget shows the summary's numbers.
4. Nothing outside the app names an app or a destination: the text of every notification, widget and tile is read
   over adb (`dumpsys notification`, the widget's views) and checked against every package and destination of the run.
5. Chained apps' destinations do not appear in "Now" while the switch is off.
6. Without usage access, and before the first unlock after a restart, flows show without a state and the summary is
   off.
7. The minimal baseline: off by default; with it on and retention "none", flags appear after the learning days;
   its file holds one number per app and no destination or time; it cannot be read while the phone is locked; it is
   gone after the log's wipe, after an app's removal (that app's number), and when the inspection profile is turned
   on.
8. Battery: the paired A40 measurement of decision 2, and W9's window on the A56 with the summary on; the widget's
   own paired measurement before 0.2.1.
9. The new screens pass the accessibility check in all eight languages and both pseudo-locales
   (`scripts/screenshots.sh`): labels, 48 dp targets, rows that keep their order, destinations isolated as
   left-to-right tokens in right-to-left text. The strings are translated and reviewed as ADR 0030 sets out, against
   ADR 0025's list of words.
10. The lab run of decision 4 is recorded in `docs/spikes/`, with every flag explained, before the flags ship.
11. **A test with real users gates the strings.** Before the words are final, a small comprehension test asks
    whether people understand "sent while you were not using it", the summary, the flags and the flag notice
    without fear, and without learning to ignore them. It is part of the redesign's test with real users that
    gates Advanced's first release (ADR 0045, decision 8). How it is run:
    - **Who:** a few people in each language tested, Persian first, among them people at risk, reached through
      organisations that already work with them (digital-security trainers), never through the project's own
      lists.
    - **What:** on a test phone of the project's, with workload apps and never the participant's own phone, each
      person sees the summary, "Now" and a flag, says in their own words what each means and what they would do,
      and then what they would do if it showed every day.
    - **Consent:** each person is told what the test is for, what is noted and that they can stop at any time,
      and agrees before it starts. No name, contact, face, voice or phone data is kept; the notes hold only the
      answers, under a number.
    - **After it:** the English strings are changed where people misread them or were afraid, and the changed
      strings go through ADR 0030's translation and review again. A summary of the findings, with nothing that
      identifies anyone, is recorded in `docs/spikes/`.

On the A40 (Samsung, Android 11), the same as 1 to 3 with split screen and pop-up view.

Done when all of these pass. 0.2.0 meets W5's gate with "Now", the per-app history, the summary and the tile's
counts (the last two with W9). The widget is not in 0.2.0: it follows in 0.2.1, after the lab run, with its own
tests.

### 7. Against the best in the field

Read on 2026-11-14:

| Tool | Live in the app | In use or in the background | Outside the app |
|---|---|---|---|
| PCAPdroid | Each connection with app, name, status and volume | Not shown | A persistent notification with "details about the captured traffic" (a `specialUse` foreground service [source]) |
| NetGuard | Access attempts logged and searchable (Pro) | A rule "allow when screen on"; no in-use state | Optional notice when an app accesses the internet; a speed graph in a notification (Pro) |
| RethinkDNS | A per-app report "on when connections were made, how many were made, and to where" | Rules by "app-foreground / app-background", through an accessibility service [source] | A Quick Settings tile [source] |
| TrackerControl | Tracker companies, destinations and countries in real time | Not shown | Not stated |
| GlassWire for Android | "When an app starts using the network, you can see it immediately"; per-app use and graphs | Reveals apps that connect in the background; no state stated | Not stated. Still on Google Play and free per its FAQ; users in its forum report it unreliable in 2025 and 2026 |
| DuckDuckGo App Tracking Protection | Trackers blocked per app in real time | Not shown | A daily summary notification of blocked tracking attempts |
| Lumen Privacy Monitor (ICSI) | Per-app flows and personal data found, with optional TLS interception | Not shown | Not found. The last release found, 2.2.2, mentions a fix for Android 9 |

**What this combination adds.** No tool read shows, live, which apps sent while the user was not using them, from
the in-use state by the public usage events rather than an accessibility service. None states what may show
outside the app, or keeps destinations off the lock screen and away from notification listeners. None flags only
against the app's own history, with thresholds from a published lab run. None says on the view what it cannot see.
Each piece exists somewhere; together, without decrypting and without new permissions, they are best in class for
an app on stock Android. iOS's App Privacy Report (iOS 15.2 and later), a system feature the user turns on, is the
closest system reference. It is a record of the past seven days, not a live view: when each app accessed data
and sensors such as location, photos, camera, microphone and contacts; the domains each app contacted, itself or
through content in it; the domains contacted by websites in apps; and the most contacted domains. It is kept
encrypted on the device. Apple's page states no sizes and no split by whether the app was in use.

**Frontier research is not needed**, beyond the lab run for thresholds. The data are Android's own and the engine's;
the open questions are measurements, not methods. Detecting what an app took, rather than that it sent, would need
decryption (Lumen) or the operating system (stage 3), and both are out of scope here.

## Consequences

- **The W5 gate is met in Advanced,** without the interface ADR 0045 dropped. DESIGN.md's W5 row links here.
- **ADR 0025 changes for Advanced's live surfaces only,** as decision 4 sets out: a count across apps in the
  summary and the widget, and a count of new flags in the opt-in flag notice, never an app's name. The roadmap's
  widget line ("only its state and the date of the last check") changes to "its state and counts across apps, never
  an app's name or a count of flags", in 0.2.1, once accepted.
- **ADR 0034 grows by one exported component in 0.2.1,** the widget's receiver, and `POST_NOTIFICATIONS` gains a use
  it did not list. No permission is added.
- **More strings,** in eight languages, held to ADR 0025's words, and a comprehension test with real users before
  they are final. More lab work: the threshold run.
- **Accepted limits:** the summary can be read by any app with notification access, which is why it carries no
  names; flags need history, either a week of the log or the minimal baseline, so users who keep nothing get no
  flags; traffic sent on an app's behalf shows under the sender.

## Sources

All read on 2026-11-14.

- `UsageEvents.Event`: https://developer.android.com/reference/android/app/usage/UsageEvents.Event
- `UsageStatsManager`: https://developer.android.com/reference/android/app/usage/UsageStatsManager
- Android 14 changes for all apps (dismissible ongoing notifications): https://developer.android.com/about/versions/14/behavior-changes-all
- `ActivityManager` (`getRunningTasks`, `getRunningAppProcesses`): https://developer.android.com/reference/android/app/ActivityManager
- AOSP `main`, read on android.googlesource.com: `services/core/java/com/android/server/am/ActivityManagerService.java`
  (`getRunningAppProcesses`), `services/core/java/com/android/server/am/ProcessList.java`
  (`getRunningAppProcessesLOSP`), `services/core/java/com/android/server/wm/ActivityTaskManagerService.java`
  (`isGetTasksAllowed`), `core/java/android/app/usage/UsageStatsManager.java` (`registerAppUsageObserver`) and
  `core/res/AndroidManifest.xml` (`REAL_GET_TASKS`, `OBSERVE_APP_USAGE`)
- Apple, "About App Privacy Report": https://support.apple.com/en-us/102188
- PCAPdroid quick start: https://emanuele-f.github.io/PCAPdroid/quick_start, and its manifest on GitHub
- NetGuard README: https://github.com/M66B/NetGuard
- RethinkDNS README and manifests: https://github.com/celzero/rethink-app (`app/src/main` and `app/src/full`)
- TrackerControl: https://trackercontrol.org/
- GlassWire FAQ: https://www.glasswire.com/faq/; Help Net Security, 2025-12-16: https://www.helpnetsecurity.com/?p=351239
- DuckDuckGo, "Introducing App Tracking Protection", 2021-11-18: https://spreadprivacy.com/introducing-app-tracking-protection
- Lumen: εxodus report 63789 (https://reports.exodus-privacy.eu.org/en/reports/63789) and APKMirror's listing of
  2.2.2, found by search; the app itself was not tested

## Settled with the maintainer (2026-11-14)

- **The summary's default:** asked at onboarding together with ADR 0047's profile question; on for users who do not
  choose the profile, off for those who do; not shown before onboarding asks (decision 2).
- **The windows:** the summary's starts at 10 minutes and the "in use" grace at 30 seconds; the lab run sets both.

- **A flag notice:** yes, opt-in and off by default, a silent count with nothing named, never under the inspection
  profile (decision 4). The maintainer's example said "1 unusual event"; the string avoids "unusual" because ADR
  0025's list rules it out.
- **The widget:** not in 0.2.0; it follows in 0.2.1, after the lab run.
- **Added at the maintainer's request:** the comprehension test with real users (decision 6, item 11) and the
  minimal baseline, so that flags work without a kept log (decision 4).
- **Checked since the first draft:** the public routes to another app's state (decision 1) and iOS's App Privacy
  Report (decision 7), against the sources below. Both held; `getRunningTasks` may also return the home screen's
  task, which the text now says.

## How it is built

**W5, part 2: the data behind "Now" and the history (2026-11-18, decisions 1 and 2 (d)).** What was chosen where
this ADR left room, and why. Part 3 builds the screens on it.

- **The one-second slots are each flow's own** (`core/net/src/engine/activity.rs`). The first count in each
  second of the wall clock notes a mark: the second, and the flow's counts before it; a second's bytes are the
  counts from its mark to the next. An app's slots are its flows' marks, so an app with no traffic holds none.
  Slots kept per app alone could not cut a flow's segment at the second its app's state changed, which needs that
  flow's own bytes on each side. The mark is taken after the log's cut at the quarter hours (ADR 0037, decision 1
  as amended), so a mark never spans two segments; an app's lookups to Watch's own DNS address are marked the
  same way, under the lock they already take.
- **The cost on the hot path.** Within a second a count adds a division, an addition, a few comparisons and one
  atomic load, and takes no lock; the first count of a second takes the lock of the flow's own marks. Measured on the
  development machine (x86-64, release build, 2026-11-18): a count costs 12.5 to 13.2 ns with states told and
  without, no difference within the measurement; a count that notes a mark costs 45 to 96 ns, the minute's
  readings included (the higher figure while other builds ran on the machine), and 106 to 116 ns since the fix
  round, which counts each app's waiting seconds under a lock for its share, once a second per flow. ADR 0044's
  cost note says the same.
- **A second is placed** once a reading covers all of it: in use if the app was in use at any moment of it, else
  with its notification if it was so at any moment, else in the background, so that a second is in the
  background only when the app was in the background throughout. Where a reading knew nothing, the second has no
  state and its reason: no usage access, no events (as before the first unlock), told too late, no app (a flow
  Android named no app for), or not told (before Watch's first reading, in a gap a clock set back left, or when
  Watch stopped before a reading came). One byte carries the state and the reason, in the log's records and in
  the snapshot (`states.rs`, `Placed::code`).
- **A segment is cut where its app's state changes,** as far back as its marks reach, where the timeline's state
  changed: the engine walks back over the seconds of the new state, at most 120 of them and never before the
  second after the last it placed in that segment (which a later, overlapping reading may tell otherwise), so that
  a quiet stretch after a change belongs to the new part (fix round 1, engine nit 2; it was cut at the first
  second with bytes in the new state). The timeline keeps the 120 seconds before the end of what was told, for
  that walk. A segment cut at a quarter hour or at its flow's end before its seconds are placed waits, held, and
  is written once they are, before the live flows' parts of the same reading, so that a flow's records reach the
  log in time order (nit 1); a segment with no count, as a refused connection's, takes the state of its last
  moment, and so does the end of one that goes quiet after its app's state changed: where the state of its last
  moment is known and differs from its last bytes', it is cut where that state began, walking back as above, and
  ends with a part of no bytes in it (fix round 2, the fresh review's m4: such a segment took its last bytes'
  state to its end). Held records are handed to the next engine when the tunnel is set up again, and an engine
  that cannot start writes them as not told at once; when Watch stops, its tracker reads once more first, and
  what is still not told is written as "not told". Lookups' records are cut the same way and carry their app's
  state.
- **The window and each app's share.** Each flow, and each app's lookups, holds at most 120 seconds with counts
  not placed yet, all of them together at most 65,536, and at most 4,096 cut segments wait. Each app may hold a
  quarter of the two bounds, 16,384 seconds and 1,024 segments, so that one app's flood never pushes another's
  states out, as ADR 0044 already shares the engine's other bounds (fix round 1, engine finding 2). Past its share
  of seconds an app gives up its own oldest, only as many as bring it 256 below it (the seconds before its n-th
  oldest, found over its flows, lookups and held segments); past the bound of all, the app that holds the most
  does the same; past its share of segments, its oldest segment is written. Fix round 2 (the second reviews' N1
  and m1) made the seconds' part so: past its share an app had all of its waiting seconds told too late at once,
  so that one app with about 273 busy flows and the screen off, read once a minute, lost 90 to 97 % of its
  states. Now 280 such flows lose 7.8 %, 300 lose 14.5 %, near what the share itself allows, and 250 none. What
  an app can still do to itself: past about 273 flows each counting every second with the screen off, or 17
  short flows ending each second, part of its own traffic has no state, "told too late"; never another app's.
  What is told too late is counted, in the engine's last counter, for all apps together: "Now" shows such bytes
  in no state without saying why (open for part 3, below). The engine asks Watch's Kotlin side for a reading when
  a flow opens, at each new second counted and when a segment is held for its states (at most every 5 seconds;
  fix round 2, the fresh review's m2: a lone burst shorter than 5 seconds asked for nothing), and after a reading
  that left seconds or segments waiting; Watch reads at most every 5 seconds with the screen on and once a minute
  with it off, and makes an ask that comes sooner in its turn. With no reading at all for 120 seconds, as with no
  tracker, each new second past a flow's window costs one settle of all that waits for each app at the window: a
  pass over the flows, once a second per app (engine nit 4 of the first review, accepted: it needs the tracker
  gone). A wall clock set back by a second or more places every second held at once, and the engine forgets
  the readings of the old clock, whose spans could cover the new clock's next seconds: those wait for readings of
  their own, so that the seconds of two clocks never meet one reading.
- **How long a record waits, and what is lost.** While Watch runs and the phone is awake, a second waits at most one
  reading's period after it, 5 seconds with the screen on and a minute with it off, plus 3 seconds: the 2 a reading
  leaves for events not reported yet, and the second itself, since a reading made at once after the second's ask may
  end before it and the next comes a period later. The window of 120 holds twice that, and the screen turning off
  reads once more, so that what was sent while it was on is placed then. A record then waits the log's usual 30
  seconds of gathering. A flow open but idle is cut at each quarter hour, and its segment asks for its state, so the
  tracker reads once a quarter hour while such a flow stays open and the phone is awake, beyond decision 1's "only
  when traffic runs" (accepted: no alarm, and one reading in 15 minutes). In deep sleep nothing runs, since no alarm
  is set, so what waits is placed when the phone wakes. If Watch's process dies meanwhile, what waits is lost with
  it: the held segments and the live flows' open segments, as any record not yet handed to the log is (ADR 0044's
  table).
- **The tracker lives in `:watch`** (`android/watch/.../activity/`), in Watch's process beside the engine it
  feeds: `:watch` cannot depend on `:app`, and needs of the audit only the rule of usage access, which moved to
  `android/shared` for both. A pure core (`UsageStates`) places the events and is tested on the JVM, one test
  for each rule; `StateTracker` reads them. The rules as built:
  - an activity is visible from its `ACTIVITY_RESUMED` to its `ACTIVITY_STOPPED` (paused but not stopped, as in
    split screen, it still is), while the screen is interactive, and while the lock screen is not over it unless
    the activity was resumed after the lock screen showed (a camera or a call over it);
  - an activity is known by its package and class only, since the instance is `@SystemApi`: a `STOPPED` that
    comes within 10 seconds after a `RESUMED` of the same class that itself followed a `PAUSED`, with no `PAUSED`
    since, is another instance's stop and ends nothing. When a screen starts another of its own class, as AOSP
    Settings opens each sub-page, or Back returns to a first instance, Android pauses the one, resumes the other
    and then stops the first [doc: "Coordinating activities"], once the new one is idle or at its idle timeout,
    10 seconds on a phone [code: `ActivityTaskSupervisor`]; that stop ended the app's use before (fix round 1,
    Kotlin finding 1). An activity kept so ends as soon as another activity is resumed while it was not paused,
    since a screen is always paused before another takes its place: an app whose process dies after a pause and
    resume of its own screen (a permission dialog, a share sheet), or that kills itself so on purpose, stays in
    use for its grace only, not until the phone restarts (fix round 2, N2). Events within one millisecond keep the
    order Android gave them, and an event read again in the overlap is matched once by its fields, so that a
    resume read twice does not undo the pause before it;
  - the default keyboard is in use while the screen is interactive and in the background while it is not, as
    decision 5 says, with no grace;
  - the grace is `UsageStates.GRACE_MS`, 30 seconds, one constant for the lab run to set;
  - each reading ends 2 seconds before the wall clock, for events not reported yet, and reads again the last 10
    seconds of the one before, so that an event late or out of order within them places its moment again; the
    first reading, and the first after one without access or one the engine did not take, reads back to the
    phone's start, at most 30 days, so that a foreground service started before Watch, as a messenger's or the
    user's own tool's, is found (fix round 2, the fresh review's M1: it read back a day), while a reading that
    finds no events keeps what is open;
  - a wall clock set back is found against the time since the phone started, and by `ACTION_TIME_CHANGED`;
    readings begin anew from the moment it was found, carrying what is open with its times moved back by how far
    the clock went, so that the grace of an app just left runs on and the lock screen keeps its order (fix round
    2, m3: the grace was dropped);
  - it reads when the engine asks, within decision 1's rates, an ask that comes sooner made in its turn; once when
    the screen turns off; and at once when Watch starts, when the screen comes on (the view may open), when the
    clock is set, and when Watch stops (`ReadingRules` and `Turns`, tested at their edges, with the rule for a clock
    set back and what a reading knows; the two lines that hand them the broadcasts have no JVM test).
    `ACTION_SCREEN_ON`, `ACTION_SCREEN_OFF` and `ACTION_TIME_CHANGED` are received while the tunnel runs. The
    engine's asking adds to decision 1's "when a flow starts" the case of a long connection with no new flow, and of
    seconds a reading left waiting: the same rates. No alarm wakes the phone;
  - each reading reads each package's UID again, since a package installed again gets a new UID in the same boot;
    from Android 15 the query asks for the twelve kinds of event only (`UsageEventsQuery`), and an empty span, as
    just after a set back, is not asked of Android, whose query refuses it.
  Without usage access, or before the first unlock (`UserManager.isUserUnlocked`), it tells the engine that
  nothing is known, and the debug dump and the snapshot say which.
- **The live counters** (`engine/now.rs`) keep each placed second's bytes, as the app sent and received them (a
  little less than Android's count, decision 5), by state in whole minutes and since the screen came on, by the
  time of the `SCREEN_INTERACTIVE` event or the broadcast. The window of 10 minutes is the current minute and the
  9 before, so it reaches back at least 9 and never more than 10 minutes; the hour likewise 59 to 60. Seconds not
  placed yet count apart, "not told yet", so that the view needs no reading to show them. Each destination is the
  flow's name, where it came from, the DNS name beside it and the app's own DNS (by address where it has no name),
  with ECH, the known resolver, came-in, and the organisation behind its network from the offline table, looked
  up out of the engine's locks, at most 64 addresses for one snapshot, and kept for at most 4,096 addresses (fix
  round 1, engine finding 7: the first snapshot after a busy hour looked them all up under the activity lock,
  108 ms for 2,048 destinations with the real table on the review's machine). A chained app's flow whose
  destination stays out of the log adds to its app's bytes only, marked as through the tool; the tool's own app
  is marked; turning "Log where these apps connect" off, or a chain that leaves an app out, drops its destinations
  at once, from the counts, from its flows and segments still waiting and from the organisations looked up
  (finding 1; fix round 2, N8), and marks the app through the tool only for flows that went through it, not for a
  connection opened directly before the chain, which goes on directly (N3). A flow of no app waits for its second
  to be over before it is placed, and a clock set back makes each flow note its next second anew, so that no byte
  counted after it is lost (findings 3 and 4). A clock set back by a second or more forgets the minutes later
  than the new clock's, and with them the bytes the old clock counted in them: the old clock's later minutes
  cannot be told apart from the new clock's (accepted; keying the windows by the time since the phone started,
  which a set back never moves, would keep them, with wall-clock minutes for the labels only). The window "since
  the screen came on" lasts until the screen next comes on, so an app and its destinations stay in memory from
  one screen-on to the next, the night after the phone was put down included. Memory only, kept with retention
  "none", handed to the next engine, gone when Watch stops.
- **Bounds.** At most 512 apps, each with at most 60 minutes of counts (about 4.4 KB); at most 2,048
  destinations, 128 for one app, each with its flow (names at their longest, 253 bytes, about 1 KB) and 60
  minutes (1.4 KB): together about 7 MB at the very worst, and some hundreds of kilobytes on a busy phone. Marks:
  65,536 of 40 bytes, 2.6 MB, and up to twice that in room their deques keep, which they give back once settled;
  held segments: 4,096, each with its flow, under 4 MB with names at their longest. Past a bound, the app or destination
  with bytes the longest ago gives way.
- **One call for the screens:** `Engine.nativeActivity`, a versioned binary snapshot (`core/net/src/snapshot.rs`,
  version 1), read by `activity/Snapshot.kt`, from a fixture the engine writes; the readings go the other way
  (`core/net/src/states.rs`, version 1), from a fixture the Kotlin side writes, read by the engine's test and
  fuzzed. Building and encoding the snapshot of 100 apps with 20 destinations each, over the hour, took 0.82 ms on
  the development machine (202 KB), without the organisation table; its at most 64 lookups add about 3 ms at the
  review's 53 µs each, with no lock held.
- **Tests.** In the engine, 70 tests: the placing of seconds, each reading's span, the cuts back in time and at a
  quiet end, the window, the bounds and each app's share at their edges, a busy app with the screen off, the clock
  set back, the asking, the counts by window, destinations and their organisations, the chain's switch, the
  snapshot's layout, the log's version 3, and an engine handing what it holds to the next, or failing to start
  with it; the readings' reader is fuzzed (`core/fuzz/fuzz_targets/states.rs`, with seeds): its first run found
  that it read a time the screen came on for a screen not on, which wrote back otherwise, and it now refuses one.
  A model test (`core/net/src/engine/model.rs`, in `cargo test`) drives 240 random runs of two apps' flows and
  flows of no app, with counts, ends, readings told from a true timeline of states in tenths of a second, two
  quarter hours, and in one run in six a reading without usage access, and 100 more with clocks set back; it
  checks against the truth each byte's state, where each cut falls, each segment's last state, each flow's records
  end to end and in time order, and "Now"'s hour. In Watch's Kotlin side, 39: one for each rule of the tracker's
  core, what a reading knows and when it is made, the reading rules at their edges, its readings' layout, the
  snapshot's and the log's readers. Hand mutants in cargo-mutants' manner, rerun after fix round 2 on the code as
  it is: of 114 in the engine (this part's 80, the four the second review found surviving, and 30 on the fix
  rounds' code), all are killed but one, argued equivalent (the timeline forgets from the oldest or the newest
  second held, less 120 seconds: every held second lies past what was told, so both are its end). Of 48 in the
  Kotlin core (this part's, the reviews' and the fix rounds'), 43 are killed, one does not build, and four are
  equivalent: an event at the start of the overlap, or at a reading's end, taken once more into the events read,
  where the overlap's matching keeps one of each and the reading's end leaves it for the next; the overlap's start
  read once more, likewise; and the lock screen kept at a restart that clears every activity. (Fix round 1's
  "each event's effect is idempotent" was not true: a resume read twice undid the pause before it, which the
  matching, now tested, prevents.) The emulator's watch
  shard runs `scripts/verify-activity.sh` (decision 6, items 1 and 6) and checks item 5 in `verify-chain.sh`. On
  the Android 15 emulator, 2026-11-18, every count matched what the workload apps logged, to the byte: 75,000
  bytes sent in the background, from a job, on a connection opened on screen and on a timer; the 3,046 before
  them in use; 8,000 from a foreground service with its notification; 24,000 from the app on screen in use;
  and without usage access, a flow's bytes in no state. After each fix round the same shard passed again on the
  Android 15 emulator, every count again to the byte (the second at `a094f50`; `b926b94` after it only drops a
  rule of the set back's carry that could no longer matter, held by the JVM tests). The emulators of Android 10, 11 and 17 that decision 6
  names, and the A40, are still to run it.
- **Accepted limits.** An activity whose `ACTIVITY_STOPPED` never comes stays visible while the screen is on (one
  kept by the rule for a second instance ends at another screen's resume). Two windows of one app's same screen class resumed side by side in split screen end
  when the other app's window resumes a screen, since Android does not tell instances apart: the rule for a second
  instance holds only for a stop within 10 seconds of a resume, and ends at another screen's resume (N2). Android
  stops a screen later than 10 seconds on a slow device, or one whose idle timeout is multiplied, and a second
  instance there ends the app's use after its grace, as before fix round 1. No emulator check holds the self-kill:
  the workload app would need a second process to send after its own died; the JVM tests hold the sequences. Watch's
  stop waits up to 2 seconds on its main thread for the tracker's last reading, so that the engine has it before its
  last flush: once, at stop, below Android's limits for a service. An event that comes more than 10 seconds late is
  not read. A second that holds a moment in use is in use whole. A quiet stretch of more than 120 seconds after a
  change of state belongs, beyond its last 120 seconds, to the segment before. A reading the engine did not take, as
  in the moment the tunnel is set up again, leaves its span "not told" in the engine, while the tracker tells the
  next one afresh. The log's records wait in memory for their states, as above, and are lost if the process dies
  meanwhile.
- **Open for part 3 and W9.**
  - [ADR 0047](0047-profile-for-phones-that-may-be-searched.md), decision 3: under the profile for phones that may
    be searched, this run's flows in memory are cleared also when the screen turns off. The live counters keep the
    windows of 10 minutes and an hour, with destinations, across a screen-off, and no call clears them yet: the
    profile needs one, or "Now" shows only "since the screen came on" and the memory is still cleared (the second
    review of W5's second part, Kotlin, nit 11). Not built in part 2; part 3 and W9 settle it.
  - ADR 0047's clearing must take the window "since the screen came on" too, which keeps apps and destinations
    until the screen next comes on, not for an hour at most (fix round 2, the fresh review's m5).
  - The feed left of the home screen on Google's launchers (decision 5) is checked on a Google Play emulator
    image in the lab run; so is whether Android hands an app its day-rollover event for a running foreground
    service, which would find one older than its record of events.
  - Decision 2 (a)'s summary "While the screen was off (2 h 10 min), N apps you were not using sent X" needs the
    bytes from the screen turning off to its coming on, by app and state, kept from that screen-on until the next
    screen-off: a window of its own, opened at `SCREEN_NON_INTERACTIVE` and closed at the next screen-on, which
    the counters do not keep yet (they reset "since the screen came on" at that moment, and their minutes reach
    back an hour). Part 3 adds it with the summary (fix round 2, the fresh review's m6).
  - "Now" shows the bytes told too late in no state, without saying so; part 3 needs the reason by app, which
    the counters keep for all apps together only (N1).
