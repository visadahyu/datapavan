# Spike: how Android counts the feed left of the home screen (2026-11-19)

ADR 0046's decision 5 said that the feed left of the home screen on Google's launchers is the Google app's
window drawn over the launcher, not an activity of the Google app, so that its traffic while the user scrolls it
counts in the background. That came from reading Launcher3's `LauncherOverlayManager`, not from a phone. If it
holds, "Now" shows the Google app sending in the background while the user reads its feed, and it should say so.

## Method

[`2026-11-feed-left-of-home/feed-check.sh`](2026-11-feed-left-of-home/feed-check.sh), on an emulator after
`scripts/verify-activity.sh` installed Advanced's debug build: Watch's tunnel up with usage access, the home
screen, a swipe to the feed, twelve swipes through it five seconds apart, then what Watch's debug dump says of
the Google app. It also records the home screen's package, the window holding the focus while the feed shows,
and the packages of the screen's nodes. It reads only the emulator's own lab traffic.

## Result

[`2026-11-feed-left-of-home/feed-check.log`](2026-11-feed-left-of-home/feed-check.log), on the Android 17 Google
Play image (`dp-api37-16k`), with the Pixel Launcher (`com.google.android.apps.nexuslauncher`) and the Google
app 17.76.14:

- the feed is an activity of the Google app, `MinusOneActivity`, which holds the focus while it shows;
- the Google app's traffic over the minute of scrolling counted **in use**: 81,835 bytes sent and 1,289,007
  received, nothing in the background.

## The Galaxy A40 (2026-11-19)

Samsung Galaxy A40 (SM-A405FN), One UI 3.1 on Android 11 (`A405FNXXU4CWC3`), with One UI Home
(`com.sec.android.app.launcher`) and Samsung Free 5.5.01.0 (`com.samsung.android.app.spage`), read by hand over
adb without installing anything or changing a permission:

- the panel left of the home screen is Samsung Free, on by default; the home screen's edit mode offers only its
  switch, no Google Discover;
- while it shows, the window holding the focus is Samsung Free's own `ui.MainActivity`, and Android's usage
  events record `ACTIVITY_RESUMED` for it when it shows and `ACTIVITY_PAUSED` and `ACTIVITY_STOPPED` when it goes
  (`dumpsys usagestats`, twice), so Watch places its traffic in use, by the same rule as any app on screen;
- Samsung Free answered "There is no server response" (its terms were not accepted on this phone), so no bytes
  were measured: the finding is the state, which is what decides the count.

## What it does not settle

Two launchers on two Android versions, and both show their feed as an activity. Launchers that still draw the
Google app's feed over themselves, as Launcher3's overlay does, may count it in the background, and none was
measured: One UI Home with Google Discover on later versions or in other regions, other vendors' launchers with a
feed, older versions of the Pixel Launcher. So "Now"'s "What this view cannot see" keeps one line, scoped: on some
phones the feed left of the home screen may count as in the background (the maintainer, 2026-11-19). Each phone
measured is added here.
