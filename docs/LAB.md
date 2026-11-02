# The traffic lab

Status: planned. A pilot comes first; ranges ship only after their own ADR (ADR 0025, point 5).

## Why

The guided check (ADR 0025) tells a user how much an app received and sent during one activity on
their phone. Whether that is much or little for this app and this activity cannot be judged from the
app itself, and published research has no numbers to compare with: no study measures bytes per app
and activity with repeated runs. So the project measures them itself, on its own phones, publishes
every run, and ships the resulting ranges in data packs, so that a guided check can show the user's
numbers next to the lab's.

The lab also does what users' phones cannot: it measures the same app version after version under
the same conditions. A change between versions, seen in the lab, is the strongest fact the project
can publish.

The lab sits in one place, and apps may behave differently by account, region, phone and version.
The lab cannot be everywhere. Reports that users send themselves, after a repeated check, are how
differences elsewhere come to the lab's attention (see "Reports from users").

## What it measures

Each run records, per app and app version (with its signing certificate):

- bytes and packets received and sent, as Android counts them and as the capture saw them;
- the share Android counted as background;
- the sent bytes as a share of the received ones;
- the names that the app looked up and connected to, where the traffic shows them (plain DNS and
  the TLS server name; encrypted DNS and Encrypted Client Hello hide them), and the organisations
  behind them; no traffic is decrypted;
- the duration, the phone, its Android version and kernel accounting (eBPF or `xt_qtaguid`), the
  network, the time in UTC and the tester.

### Scenarios

| Scenario | What happens | Duration |
|---|---|---|
| Installed, never opened | The app is installed and left alone | 24 hours |
| Cold start | The app is opened and left on its first screen | 1 minute |
| Background after use | The app is used for 1 minute, closed, and the phone left alone | 60 minutes |
| Scroll a feed | Scroll the main feed at a fixed pace, without posting, liking or opening messages | 1 and 5 minutes |
| Watch videos | Watch in the app's own player at a fixed quality setting | 5 minutes |
| Use a map | Pan and zoom, logged out | 5 minutes |
| Type | Type 200 fixed characters with the keyboard, by taps | about 2 minutes |
| Calibration | `scripts/traffic-lab` moves known amounts | each session |

Only scenarios that make sense for a kind of app are run for it. A one-minute warm-up before each
measured scenario is not counted.

## Equipment

- **Phones:** at least two vendors whose phones count with eBPF (for example a Pixel and a
  Xiaomi/Redmi), later a heavily customised one (Tecno or Infinix) and a recent Samsung. The A40
  stays for comparisons with `xt_qtaguid` counting. Each phone has a clean image to return to.
- **Capture:** a Wi-Fi access point the lab controls (an OpenWrt router or a small Linux computer)
  that records packet headers on its Wi-Fi side. Mobile data is measured with Android's counts only.
- **Accounts:** one test account per service and phone, following the service's rules on identity,
  with a fixed set of followed accounts and no posts. The account's age and settings are recorded.
- **Tools:** `scripts/traffic-lab` for calibration and the check of Android's counts against the
  capture; a metronome for people following a timed script.

## Method

- **Controls** (after Gui et al., ICSE 2015, and Wehner et al., MMSys 2025): app versions pinned with
  automatic updates off; caches cleared for cold runs and warm runs kept apart; scenarios in random
  order with a random start offset of 0 to 5 seconds; runs spread over at least three days.
- **Repetitions:** 10 runs per scenario on each phone, so 20 on two phones: a new run on a lab phone
  then falls above the highest run with a probability of about 1 in 21.
- **Checking the counters:** in every session, Android's counts against the capture and the
  calibration amounts, per phone. A phone whose counts drift is set aside until it is understood.
- **Who drives the app,** in this order of preference, never evading a service's bot detection:
  1. no interaction (installed, idle, background);
  2. a person following a timed script, for services whose terms forbid automated access;
  3. logged-out use where the service allows it;
  4. automation, only with the service's written permission.

## Ranges and comparisons

- **The range** for a scenario, app version and kind of phone is the lowest to the highest of the
  lab's runs, with the number of runs, the phones, the Android versions and the date. Distributions
  of traffic are skewed, so the lab works on a logarithmic scale and keeps the spread between
  phones apart from the spread between runs.
- **Sent bytes come first.** In scenarios that only receive, what an app sends depends far less on
  the account's content, the region's ads or the network than what it receives does. Received
  bytes are shown, and compared only with care.
- **Outside the range** is said only when both hold: the user's value is more than a set multiple of
  the top of the range, and above it by more than a set absolute amount. Both numbers come from the
  lab's measured spread and are printed with the result.
- **Lab against lab:** each new app version is measured in the same scenarios; a change beyond the
  spread between runs is a lab finding, published after the maker has been asked for comment.

## On the user's phone

The guided check (ADR 0025) gains the lab's range for the same scenario, when the lab has one:

- the user's numbers first, then the range and where it comes from, for example: "In our lab, while
  scrolling, this app sent 1 to 3 % of what it received (20 runs, 2 phones, version X, date). On your
  phone, in this check: 10 %, about three times the top of our range." Then the limits: bytes do not
  show what was sent, to whom or why.
- the words are those of ADR 0025: "outside the range we measured", "about N times the top"; never
  a warning or a judgement, and no red.
- **A second run before anything else.** When a result is outside the range, Datapavan offers to run
  the check again with stricter instructions for the scenario. For scrolling: only scroll, at a
  steady pace; do not post, reply, like, upload or open messages; stay on the same network; wait
  until any upload in the app has finished. Both runs are shown side by side. A one-off cause, such
  as a post or a sync, rarely repeats; what repeats is a difference of account, region, phone or
  app version, which is what the lab cannot see.
- the option to report is offered after two runs that are both outside the range.
- the app's signing certificate is checked as everywhere in Datapavan (ADR 0018); a modified copy is
  never compared with the lab's runs of the genuine app.

## Reports from users

- **Readable before it is sent.** The report holds only: the app's package, version and signing
  certificate fingerprint; the scenario; both runs (received, sent, duration, network type,
  background share); the phone model, Android version and kernel accounting; Datapavan's and the
  data pack's versions; the date; and the country, only if the user picks one. Nothing about other
  apps, no account and no identifier.
- **The user chooses the channel** through Android's share sheet: email, a messenger, the website's
  form or its onion form. Datapavan has no network access itself, and says that the channel may
  reveal who sent the report.
- **Reports are leads, not findings.** None is published on its own. The project counts reports by
  app, version and region; when several independent reports agree, the lab measures again, with a
  partner in that region where possible. Only what the lab can reproduce is published, after the
  maker has been asked for comment. This also keeps false reports from harming an app.
- **Kept briefly:** reports are deleted after a set time, and the privacy policy says how long.
- ADR 0016 allows reports that users send themselves, but not ones that name an app they have
  installed, so this needs a new ADR and a legal review.

## Publication

- Every run is published as a dataset under CC0, with the method, the phones, the versions and the
  dates, and a changelog.
- Ranges reach phones in signed data packs (ADR 0017), never over the network from the app. A range
  older than six months, or measured on a version far from the user's, is shown as not compared.
- Makers are asked for comment before a range that names their app ships. Objections are logged and
  answered, and anyone can dispute an entry through `data/CORRECTIONS.md`.
- The strings in every language and the dataset get a legal review before the first range ships.

## First steps

1. Two phones that count with eBPF and a capture access point.
2. A pilot with five apps and three scenarios (installed and never opened, scrolling a feed for five
   minutes, background after use), ten runs each on both phones, Android's counts checked against
   the capture.
3. An ADR for ranges, the comparison on the phone, the second run and reports from users.
4. The legal review, and the notices to makers before the first ranges ship.

## Best in class and frontier research

No tool or project publishes per-version baselines of app traffic in fixed scenarios with an open
method, compares a user's own check with them, or offers a route for reports; this would lead the
field. Three parts need research beyond engineering: how far lab ranges carry over to users' phones,
how to see differences between regions from sparse reports with statistical confidence and without
harming privacy, and how people read bytes and shares. They make a case for a research grant.
