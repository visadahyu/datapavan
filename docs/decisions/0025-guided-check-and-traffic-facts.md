# 0025. The guided check and facts about traffic that need no comparison

- Status: Accepted
- Date: 2026-11-02
- Decided by: mehdashti

## Context
ADR 0022 shows how much each app received and sent. The maintainer asked for more: an expected
range for each kind of app and activity, taken from apps of the same kind or from how such apps are
built, never from the app itself, so that Datapavan can say when an app sends more than its job
needs. Research on this question (in the project's private research, 2026-10-31, about 330 sources)
found:

- **Direction says more than volume.** While an app only receives (watching, scrolling, listening,
  downloading), what it sends is mostly acknowledgements and requests: about 0.5 to 3 % of what it
  receives. Volumes vary far more between accounts, regions and app versions.
- **Some facts are strong without any range:** traffic from an app that was never opened, and
  sending in the background by apps whose job needs no network.
- **Ranges for kinds of app cannot be taken from published work.** No study measures bytes per app
  and activity with repeated runs. They need the project's own lab on several vendors' phones, and
  how far a lab range carries over to a user's phone is an open research question.
- **A 30-day total cannot be judged against any range,** because the user's own posting, backups and
  sync dominate it. The fair comparison is a guided check: a reading, one activity, a reading.
- **Nothing of this may become an alert.** Real cases are rare, so even a good detector is wrong in
  most of its flags; the one consumer precedent (Norton App Advisor, 2016) flagged mainstream apps
  for background data and was called paranoid. Words such as "suspicious" or "malicious" also carry
  legal risk when attached to an app's name (Enigma v. Malwarebytes, 9th Cir. 2023).

The guided check spike ([docs/spikes/2026-11-guided-check.md](../spikes/2026-11-guided-check.md))
measured the method on the Android 17 emulator against packet captures and on the A40:

- the difference of two readings is the activity's traffic, to the byte for received bytes;
- a single reading of "since the check began" is 38 to 99 % too low;
- every query by an app other than the system restarts Android's 15 seconds, so a reading can be
  stale, and the live totals of `TrafficStats` show when it is;
- sent bytes include resent packets: on the A40, whose kernel counts with `xt_qtaguid`, they were 10
  to 29 % above what was moved;
- a messaging app downloading a 10,000,000-byte file sent 3.05 % of what it received.

## Decision
1. **Facts, never alerts.** Nothing about an app's traffic becomes a notification, a badge, a colour,
   a score or a rank. Facts and comparisons appear on the app's page, or as the result of a check
   the user starts. The remediation plan (M5) may list the facts of point 3 for review, never as a
   warning.
2. **The guided check.** On an app's page, the user can check one activity:
   - **Choose.** The user says what they will do in the app. Activities that only receive: watch
     videos, listen, scroll or read without posting, use a map, download a file. Others: send
     something, call, type, leave the app open, anything else. For activities that only receive,
     Datapavan asks the user not to post, upload or sign in during the check.
   - **Measure.** Datapavan reads the app's counts, opens the app, and reads again when the user
     returns. Both readings ask for the same period: from the two-hour boundary (a multiple of two
     hours since the Unix epoch) at least a day before the first reading, to a day after now. The
     second reading comes at least 15 seconds after Datapavan's previous query, with a countdown,
     and Datapavan makes no other query in between; the overview's refresh waits.
   - **Check that the count is up to date.** Datapavan compares the difference summed over all UIDs
     with the difference of `TrafficStats`' live totals. If the sum falls short by more than 5 % and
     more than 64 KB, it says that Android's count is not up to date yet and reads again 15 seconds
     later, up to three times; then it shows the numbers and says that they may be incomplete. With
     a VPN active the comparison is not made, because it was not tested, and the result says so.
     (Amended while building it, 2026-11-02: the first reading also waits 15 seconds after any
     earlier query, and a sum above the live totals by the same margin means that the first reading
     was behind, so the result may include traffic from before the check, and says so.)
   - **Show** the duration, and received and sent bytes for mobile data and Wi-Fi apart, per minute,
     with the share that Android counted as background. For activities that only receive, the sent
     bytes are also shown as a share of the received ones, next to one sentence: while an app only
     receives, its acknowledgements and requests come to about 0.5 to 3 % of what it receives. The
     share is not compared, with the reason, for proxy and VPN apps, apps that share a UID, system
     components, less than 1 MB received, and phones whose kernel is older than 4.9, where sent
     bytes include resent packets more than elsewhere.
   - **Limits,** under every result: byte counts do not show what was sent, to whom or why; sent
     bytes include resent packets; traffic that the system makes for an app counts under the app.
   - **Run again** shows both runs side by side while the screen is open.
   - **Nothing is kept.** The readings and results exist in memory while the screen is open
     (ADR 0016, ADR 0022). Since nothing is flagged, there is nothing to dismiss or remember.
3. **Two facts on the app's page, from the data of ADR 0022, with no range:**
   - **Not opened since it was installed, yet it used data.** For an app the user installed (not
     preinstalled, not sharing its UID with another app, and not one of the apps that work without
     being opened, as ADR 0022 lists them), installed after Android's oldest usage record, with no
     recorded use since, and network use in the period: "Android records no use of this app since it was installed on [date]. In the last
     30 days it received [X] and sent [Y]." The page adds that Android keeps a newly installed app
     from running until it is first opened, but another app can still start it.
   - **Sending in the background by an app whose role needs no network.** For keyboards, live
     wallpapers and home screens, as their manifests declare them, when the app sent at least 1 MB
     in the background in the period: "[App] sent [X] in the background in the last 30 days. Its role
     needs no network; sync, backups and reports can still send data." The 1 MB is a display
     threshold, not a judgement, and changes with lab data.
4. **Words.** Every string about traffic, in every language, gives absolute numbers before shares,
   the app's own facts before any context, and the same limits whatever the result. It never uses
   words that judge or imply intent or content: suspicious, unusual, abnormal, excessive, leak,
   spying, secretly, malicious, threat, risk, normal, expected, safe, "more than similar apps",
   grades, scores, ranks, or equivalences such as "as much as 100 photos". Translators get this list
   with the reasons.
5. **Ranges for kinds of app come later, from the lab, and are decided in their own ADR.** It needs:
   a lab plan with at least two vendors' phones and the counters checked against a capture; test
   methods in this order of preference, never evading a service's bot detection: no interaction,
   a person following a timed script, logged-out use, and automation only with the service's
   written permission; makers asked for comment before a range that names their app ships, with
   objections logged and a public corrections route; and a decision on user reports that name an
   app, which ADR 0016 does not allow today. The traffic of VPN apps beyond their own overhead
   waits for the VPN (v0.2).

## Consequences
- `UsageReader` gains a reading for a given period and the live totals of `TrafficStats`, which
  need no permission; the rules of point 2 (period, freshness, the reasons for not comparing) are
  pure functions with unit tests, and `scripts/traffic-lab` checks the whole check on the emulator.
- The kernel version comes from `os.version`. Before the check ships: whether a kernel older than
  4.9 is the right test for `xt_qtaguid`, and how Android counts a keyboard while it is on screen.
- The privacy policy says that the check reads the phone's total traffic counters, in memory only.
- The guided check and the facts of point 3 join M5, before the first release; ranges for kinds of
  app become a research item next to the v0.2 cross-checks. DESIGN.md says so.
- The sentence about 0.5 to 3 % rests on the transport rules and on the spike (0.9 to 2.2 % for the
  lab's downloads, 3.05 % for a messaging app); the lab refines it.
- Accepted limits: the check measures one activity on one phone, not the app in general; a stale
  count cannot always be ruled out, notably with a VPN; and apps that share a UID or route others'
  traffic are measured together.
- Frontier research: how far lab ranges carry over to users' phones, and how people read bytes and
  shares; both make a case for a research grant.
