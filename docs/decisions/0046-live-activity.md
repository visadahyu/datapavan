# 0046. What apps sent while the user was not using them, shown live

- Status: Proposed
- Date: 2026-11-14
- Amends, once accepted: [ADR 0025](0025-guided-check-and-traffic-facts.md) decision 1, for Advanced's live
  surfaces only; [ADR 0034](0034-watch-permissions.md), by one exported component (the widget); DESIGN.md's W5
  row; the roadmap's line on the widget.

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

- **Before the first unlock after a restart, `queryEvents` returns null** (Android 11 and later) [doc]. Flows of
  that time get no state. With always-on, Android starts Watch only after the unlock anyway (ADR 0034).
- **Without usage access**, flows have no state. The view then shows each app's traffic without the mark, and
  offers the grant. The summary of decision 2 stays off, since it would count nothing. Android 17 locks usage access
  for apps installed from a file until the user allows restricted settings (roadmap, M4 checks); onboarding says so.
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
- **Nothing else would do.** `getRunningAppProcesses` returns only the caller's own processes, and `getRunningTasks`
  only its own tasks, since Android 5 [unverified]. A trigger such as `registerAppUsageObserver` is system API only
  [unverified]. Usage events are the public route, and the one the audit already uses (ADR 0022).

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

**(b) An optional home-screen widget** with the same counts and sizes, and Watch's state. No colour, no badge, no
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

Nothing here wakes the phone: work happens while traffic already runs or the screen is on. The budget is Watch's
own, not an addition: Watch with the summary and the widget on still meets W9's bar of at most 3 % of a day's
battery (DESIGN §7). A paired measurement on the A40, the same workload with them off and on, must show the
difference below a tenth of Watch's own share.

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

**A profile for people whose phones may be searched.** ADR 0047, drafted on the branch `inspection-profile`,
defines this inspection profile, which the user chooses with one switch, "Keep nothing on this phone": off for users who do not
face searches, on for those who do, decided by the user's own answer and never by country. This ADR's surfaces
must follow it. Under that profile the summary and the widget are off, the tile shows
only Watch's state, and nothing is kept: retention is none, so "Now" holds only memory and the flags of decision 4
that need history do not run.

### 4. How it is framed, and what is flagged

**Background traffic is mostly ordinary.** Mail syncs, messengers receive pushes, backups run, widgets update. The
words say what ran without the user ("sent while you were not using it"), never "stole", "spied" or "leaked", and
follow ADR 0025's list in every language: absolute numbers first, no word that judges.

**Two flags, stated as facts, whose words show only inside the app:**

1. **An app's first background send:** "First time in the 30 days Watch keeps: [app] sent [X] while you were not
   using it."
2. **A volume far above the app's own usual:** "[App] sent [X] while you were not using it. On the other days Watch
   keeps, it sent at most [Y] in a day."

Both compare the app only with itself, from the log. They need at least seven days of it, and the lab run may set
more. With a shorter retention, or none, there are no flags, and the view says why. Alternatives that were set
aside:
- a baseline kept apart from the log, longer than retention: it would be a record of which apps send in the
  background, kept past the user's choice;
- comparing with other apps or with lab ranges per kind of app: those ranges need their own ADR first (ADR 0025,
  point 5).

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

### 6. Tests, and when it is done

On the emulators with Android 10, 11, 15 and 17, by script, with debug builds' screenshot switch (ADR 0040):

1. A workload app sends in the background, on a timer and through a long connection opened while it was on screen,
   while another app is on screen. "Now" names it "in the background" with its bytes within 5 % of what it sent; the
   app on screen is "in use"; a foreground service is "with its notification".
2. The summary shows the right count and size; it shows nothing on the lock screen; it is marked local only; it does
   not exist before onboarding has asked, nor under the inspection profile, and is gone with `POST_NOTIFICATIONS`
   denied. The flag notice does not exist until the user turns it on, never under the inspection profile, and
   carries only a count.
3. The widget shows the same numbers; the tile shows counts only while unlocked.
4. Nothing outside the app names an app or a destination: the text of every notification, widget and tile is read
   over adb (`dumpsys notification`, the widget's views) and checked against every package and destination of the run.
5. Chained apps' destinations do not appear in "Now" while the switch is off.
6. Without usage access, and before the first unlock after a restart, flows show without a state and the summary is
   off.
7. Battery: the paired A40 measurement of decision 2, and W9's window on the A56 with the summary and the widget on.
8. The new screens pass the accessibility check in all eight languages and both pseudo-locales
   (`scripts/screenshots.sh`): labels, 48 dp targets, rows that keep their order, destinations isolated as
   left-to-right tokens in right-to-left text. The strings are translated and reviewed as ADR 0030 sets out, against
   ADR 0025's list of words.
9. The lab run of decision 4 is recorded in `docs/spikes/`, with every flag explained, before the flags ship.

On the A40 (Samsung, Android 11), the same as 1 to 3 with split screen and pop-up view.

Done when all of these pass. "Now" and the per-app history meet W5's gate for 0.2.0; the summary and the tile's
counts come with W9; the widget ships in 0.2.0 if its tests pass, and otherwise follows without holding the
release.

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
an app on stock Android. iOS's App Privacy Report, a system feature, shows domains per app over seven days but not
live and not by state [unverified: not read now].

**Frontier research is not needed**, beyond the lab run for thresholds. The data are Android's own and the engine's;
the open questions are measurements, not methods. Detecting what an app took, rather than that it sent, would need
decryption (Lumen) or the operating system (stage 3), and both are out of scope here.

## Consequences

- **The W5 gate is met in Advanced,** without the interface ADR 0045 dropped. DESIGN.md's W5 row links here.
- **ADR 0025 changes for Advanced's live surfaces only,** as decision 4 sets out: a count across apps in the
  summary and the widget, and a count of new flags in the opt-in flag notice, never an app's name. The roadmap's widget line ("only its state and the date of the last check") changes to "its
  state and counts across apps, never an app's name or a count of flags", once accepted.
- **ADR 0034 grows by one exported component,** the widget's receiver, and `POST_NOTIFICATIONS` gains a use it did
  not list. No permission is added.
- **More strings,** in eight languages, held to ADR 0025's words. More lab work: the threshold run.
- **Accepted limits:** the summary can be read by any app with notification access, which is why it carries no
  names; flags need days of the log, which is evidence, so users who keep less get fewer flags; traffic sent on an
  app's behalf shows under the sender.

## Sources

All read on 2026-11-14.

- `UsageEvents.Event`: https://developer.android.com/reference/android/app/usage/UsageEvents.Event
- `UsageStatsManager`: https://developer.android.com/reference/android/app/usage/UsageStatsManager
- Android 14 changes for all apps (dismissible ongoing notifications): https://developer.android.com/about/versions/14/behavior-changes-all
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

## Questions for the maintainer

3. **The widget in 0.2.0**, or after it?
