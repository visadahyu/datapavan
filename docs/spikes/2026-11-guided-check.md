# Spike: two readings of Android's counts around an activity (the guided check)

- Date: 2026-11-02
- Question: research on expected traffic (in the project's private research, 2026-10-31) proposes a
  guided check: Datapavan reads an app's network counts, the user performs one activity, Datapavan
  reads again, and the difference is the activity's traffic. Is that difference exact, and how must
  the two readings be taken?

## Method

A lab tool, `scripts/traffic-lab`, stands in for both sides on the Android 17 emulator
(`dp-api37-16k`, Google Play image):

- **The activity.** A small app, built like the audit's test fixture and never shipped, moves a
  known number of bytes over plain HTTP to and from a server on the computer (`server.py`), either
  with its screen open (foreground) or from a broadcast receiver with nothing on screen
  (background). Unlike Datapavan it has network access, and nothing else on the emulator uses its
  user ID.
- **The readings.** The same app, given usage access over adb, reads the counts with the call
  Datapavan makes (`NetworkStatsManager.querySummary` for Wi-Fi and for mobile data with a null
  subscriber ID, ADR 0022), for several windows at once, and the live interface totals of
  `TrafficStats` just before. So the readings take Android's path that Datapavan takes, but not
  Datapavan's own code.
- **What the network really carried.** The emulator was started with `-tcpdump` for mobile data
  (its `eth0`) and with `-netsim-args --pcap`, which makes the netsim daemon capture Wi-Fi (`wlan0`)
  as 802.11 frames. `capture.py` adds up the IP length of every packet, as Android counts bytes:
  headers included, frames not.
- **The protocol** (`run.py`), per trial: a reading A, the transfer, and a reading B taken at least
  16 seconds after A. Each reading asks for four windows:
  1. from the start of A's two-hour bucket to a day later (aligned start, end in the future);
  2. from the same start to now;
  3. the last 30 days, as Datapavan's overview reads them;
  4. at B only, from the moment of A to now: a single reading, with no difference taken.
- **The trials**, three times each: on Wi-Fi, 1 MB and 20 MB down, 5 MB up, all on screen, and 5 MB
  down in the background; on mobile data (Wi-Fi switched off), 1 MB and 10 MB down, 2 MB up, and 2 MB
  down in the background. Separately, on Wi-Fi: a reading, a 1 MB transfer (below the 2 MB at which
  Android counts on its own), and readings 10, 20 and 36 seconds after the first, to see which of them
  show the transfer.
- **Clocks.** The emulator's `-tcpdump` writes the computer's local time as if it were UTC, and its
  clock ran 3.78 seconds apart from the computer's; netsimd writes UTC. `capture.py` finds each
  capture's shift by matching bursts of packets with the times in the server's log.
- **The default network.** In a first attempt the emulator's Wi-Fi lost its validation and Android
  moved to mobile data while Wi-Fi stayed connected. The run therefore checks the default network
  before and after each trial and repeats a trial when it changed; in the run reported here none
  had to be repeated.

## Results

Each row is three runs; the differences are Android's count of the lab app's bytes (reading B
minus reading A, window 1) against the IP bytes of the same connections in the capture:

| Network | Activity | Received | Sent | Counted as background |
|---|---|---|---|---|
| Wi-Fi | 1 MB down, on screen | identical to the byte | identical | 0 % |
| Wi-Fi | 20 MB down, on screen | identical | identical | 0 % |
| Wi-Fi | 5 MB up, on screen | identical | +0.71 to +0.72 % | 0 % |
| Wi-Fi | 5 MB down, in the background | identical | identical | 100 % |
| Mobile data | 1 MB down, on screen | +0.42 to +0.46 % | identical | 0 % |
| Mobile data | 10 MB down, on screen | +0.41 to +0.44 % | identical | 0 % |
| Mobile data | 2 MB up, on screen | identical | +0.37 to +0.40 % | 0 % |
| Mobile data | 2 MB down, in the background | +0.31 to +0.36 % | identical | 100 % |

- **The difference of two readings is the activity's traffic.** On Wi-Fi, downloads matched the
  capture to the byte in both directions (for example 20,556,107 bytes received and 284,138 sent).
  Android never counted less than the capture, and its packet counts equalled the capture's in all
  24 trials.
- **Where Android counts a little more,** it is the bytes of full-size data packets: sending on both
  networks and receiving on mobile data, by 6 to 11 bytes per packet. The emulator's network does
  not use TCP timestamps (20-byte TCP headers in every packet), while Android's counter estimates
  offloaded packets larger than 1,500 bytes as if they carried timestamps (`bpf/progs/netd.c` in
  AOSP). That the estimate causes the difference is likely but was not shown: an estimate of that
  kind would also have changed the packet counts.
- **Foreground and background** were split as expected: the transfers with the lab app on screen
  counted entirely as foreground, the ones from its broadcast receiver entirely as background.
- **All apps together** (the sum of the difference over every UID) came within 0 to +0.99 % of
  everything the capture saw on that network between the two readings, and the live totals of
  `TrafficStats` within 0 to +2.04 %.

### The windows

Against window 1 (aligned start, end a day later), for the lab app's total:

| Window | Difference of two readings | One reading only |
|---|---|---|
| 2. aligned start, end now | −0.017 to +0.016 % | |
| 3. last 30 days, as the overview reads | −0.017 to +0.016 % | |
| 4. from the first reading to now | | −38 to −99 % |

- A period ending "now" loses a sliver. The app's "now" is taken a few milliseconds before the
  system's, and Android counts the current two-hour bucket only up to the system's time of the query
  (`NetworkStatsHistory.getValues` with `now`, AOSP). The sliver is that delay over the time since the
  bucket began: tiny here, larger just after a bucket starts. An end in the future loses nothing.
- **A single reading of "since the check began" is useless.** Android cannot tell when within a
  bucket the bytes came, so it counts the share of the current bucket that the period covers: here
  between 38 and 99 % too little, depending on how long the bucket had been running.

### The 15-second limit

After a fresh reading and a 1 MB transfer, in three runs:

| Reading after the first | Lab app's bytes in the count | All UIDs | `TrafficStats` live totals |
|---|---|---|---|
| 10 s | 0 | 0 | 1,048,602 to 1,091,166 |
| 20 s | 0 | 0 | the same |
| 36 s | 1,028,306 | equal to `TrafficStats`, to the byte | 1,048,602 to 1,091,166 |

- The reading at 20 seconds came 20 seconds after the last count but only 10 after the previous
  query, and it was still stale: **every query by an app other than the system restarts the
  15 seconds**, whether or not it caused a count (`isRateLimitedForPoll` in AOSP sets the timer on
  every call). A guided check that queries every few seconds would never see new numbers.
- **A stale reading can be recognised.** `TrafficStats.getTotalRxBytes()` and `getTotalTxBytes()`
  are live and need no permission. When a reading is fresh, the sum over all UIDs of the difference
  matches their difference; when it is stale, it falls short (here 0 against about 1 MB).

## On a real phone: the A40

The same trials on Wi-Fi ran on the A40 (Samsung, Android 11, kernel 4.4) on the maintainer's home
network, the same day, with `run.py private`: it changes no setting and keeps nothing, the phone
returns other apps' counts only as a sum (the lab app's `private` extra), and only the lab app's
numbers and percentages are printed. The computer's firewall lets no connection in, so the lab app
listened and the computer connected to it. With no capture, the reference is the bytes moved.

| Activity, three runs each | Android's count against the bytes moved | Counted as background |
|---|---|---|
| 1 MB down, on screen | + 52.0 bytes per packet (1,036,096 bytes in 694 packets, every run) | 0 % |
| 20 MB down, on screen | + 52.0 bytes per packet (20,718,440 in 13,816) | 0 to 1 % |
| 5 MB down, in the background | + 52.0 bytes per packet (5,179,772 in 3,457) | 100 % |
| 5 MB up, on screen | + 10 to + 29 % (5.52 to 6.43 MB, in 982 to 1,673 packets) | 22 to 64 % |

- **Received bytes are exact:** the payload plus 52 bytes per packet, which are the IPv4 header
  (20), the TCP header (20) and its timestamp option (12).
- **Sent bytes were well above what was moved.** The A40's kernel has no eBPF, so Android counts
  per app with the older `xt_qtaguid` module, which counts packets as the kernel hands them out:
  offloaded packets as one (fewer packets than the 3,454 segments that 5 MB needs) and, most likely,
  every retransmission on the home Wi-Fi. The cause was not shown. The background share is an
  artefact of the listening mode: the lab app closed its screen once it had handed the data to the
  kernel, which was still sending it.
- **The windows** behaved as on the emulator: −0.027 to +0.004 % for the windows ending now, and
  −61 to −99 % for a single reading.
- **The 15-second limit** is the same on Android 11. In two runs the readings at 10 and 20 seconds
  were stale and the one at 36 seconds fresh. In the first run the reading at 10 seconds was already
  fresh: something else, most likely other apps' traffic reaching Android's own threshold, had made
  Android count. The sum over all apps against `TrafficStats` was −100 % for every stale reading,
  and between −1.2 and 0 % for fresh ones.
- **A guided check of a real app.** The user sent a file of 10,000,000 random bytes from a computer
  to their own account and downloaded it on the A40 in a messaging app of their choice, between two
  readings 249 seconds apart. Android counted 10,625,896 bytes received in 8,438 packets and 324,541
  sent in 3,784 packets, none in the background; the sum over all apps matched `TrafficStats` within
  0.08 %. Of the received bytes, 4.39 % are TCP/IP headers (52 per packet) and 1.87 % the app's
  protocol and whatever else it did in those four minutes. Sent bytes were 3.05 % of received: the
  top of the transport floor of 0.5 to 3 % that the research expects while only downloading.

## What this means for the guided check

1. **Two readings, never one,** each with the same start and an end in the future. The start is a
   two-hour boundary (a multiple of two hours since the Unix epoch) well before the first reading,
   such as a day earlier: Android spreads each count over the time since its previous count, so a
   count that came late can land in an earlier bucket. (The trials started at the first reading's
   own bucket, where every count was fresh; the earlier start follows from AOSP and was not tested.)
2. **The end reading must be fresh.** It comes at least 15 seconds after any earlier query by
   Datapavan, with none in between; the overview must not refresh in that time, for example when the
   user returns to Datapavan from the app. Another app's query also restarts the timer, and Datapavan
   cannot see it, so each reading is checked against the live totals of `TrafficStats`: if the sum
   over all UIDs falls clearly short, Datapavan says the count is not up to date yet and reads again
   15 seconds later. (According to AOSP, Android also counts on its own once about 2 MB more has
   been used, less on some devices, so a stale reading misses at most that much; not measured.)
3. **The numbers are IP bytes, headers included.** Received bytes matched the capture to the byte
   on the emulator's Wi-Fi, were up to 0.46 % above it on its mobile data, and on the A40 were the
   payload plus exactly its headers. Sent bytes include every transmission: up to 0.72 % above the
   bytes on the wire on the emulator, and 10 to 29 % above the bytes moved on the A40, whose kernel
   counts with `xt_qtaguid`. The check reports them as Android's count and says that sent bytes
   include resent packets; phones with kernels older than 4.9, which cannot count with eBPF, need
   that note most.
4. **Foreground and background can be shown apart** for the activity, as Android recorded them.

## Not checked yet

- Phones that count with eBPF, of other vendors, against a capture at a lab access point (lab plan,
  research note); whether retransmissions explain the A40's sent bytes.
- Mobile data on a real carrier, IPv6, and QUIC or other UDP traffic.
- Another app querying in between, a 2 MB activity during a stale period, an activity across a
  two-hour boundary, and traffic through a VPN.
