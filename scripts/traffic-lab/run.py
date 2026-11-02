#!/usr/bin/env python3
"""Guided check spike (docs/spikes/2026-11-guided-check.md): does the difference of two readings of
Android's network counts give an activity's traffic exactly, and how must the readings be taken?

  run.py trials OUT.jsonl     moves known amounts with the traffic lab app and reads the counts
                              before and after each transfer; also tests the 15-second limit
  run.py report OUT.jsonl WIFI_PCAP MOBILE_PCAP
                              compares the counts with the emulator's packet captures

Emulators only, started with `-tcpdump MOBILE_PCAP -netsim-args --pcap` (netsimd writes the Wi-Fi
capture under /tmp/android-$USER/netsimd/pcaps), with the lab app installed (build.sh) and given
usage access (appops set org.visadahyu.datapavan.trafficlab GET_USAGE_STATS allow).
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capture  # noqa: E402

PKG = "org.visadahyu.datapavan.trafficlab"
PORT = 8765
BUCKET = 2 * 3600 * 1000  # Android's per-UID buckets, in ms since the epoch
DAY = 24 * 3600 * 1000
GAP = 16  # seconds: a query polls only if no app other than the system opened a session in the last 15 s
REPS = 3
TRIALS = [  # network, in the background, bytes down, bytes up
    ("wifi", False, 1_000_000, 0),
    ("wifi", False, 20_000_000, 0),
    ("wifi", False, 0, 5_000_000),
    ("wifi", True, 5_000_000, 0),
    ("mobile", False, 1_000_000, 0),
    ("mobile", False, 10_000_000, 0),
    ("mobile", False, 0, 2_000_000),
    ("mobile", True, 2_000_000, 0),
]


def adb(*args):
    return subprocess.run(["adb", "shell", *args], check=True, capture_output=True, text=True).stdout


def now_ms():
    return int(time.time() * 1000)


def read(windows):
    """One reading: the counts for each (start, end) window; an end of 0 means the phone's now."""
    starts = ",".join(str(s) for s, _ in windows)
    ends = ",".join(str(e) for _, e in windows)
    before = time.time()
    out = adb("am", "broadcast", "-n", f"{PKG}/.ReadReceiver", "--ela", "starts", starts, "--ela", "ends", ends)
    after = time.time()
    reading = {"before": before, "after": after, "windows": windows, "q": {}}
    for line in out.split('data="', 1)[1].rsplit('"', 1)[0].splitlines():
        f = line.split()
        if f[0] == "error":
            sys.exit(line)
        if f[0] == "me":
            reading["me"] = f[1]
        elif f[0] == "at":
            reading["at"] = int(f[1])
        elif f[0] == "totals":
            reading["totals"] = [int(x) for x in f[1:]]
        elif f[0] == "q":
            window, net, uid, state = f[1:5]
            reading["q"].setdefault(window, {}).setdefault(net, {}).setdefault(uid, {})[state] = [int(x) for x in f[5:]]
    return reading


def lines(log):
    with open(log) as f:
        return sum(1 for _ in f)


def transfer(log, background, down, up):
    expected = lines(log) + (down > 0) + (up > 0)
    extras = ["--el", "down", str(down), "--el", "up", str(up)]
    if background:
        adb("am", "broadcast", "-n", f"{PKG}/.TransferReceiver", *extras)
    else:
        adb("am", "start", "-W", "-n", f"{PKG}/.TransferActivity", *extras)
    deadline = time.time() + 180
    while lines(log) < expected:
        if time.time() > deadline:
            sys.exit("transfer did not finish; see adb logcat -s TrafficLab")
        time.sleep(0.2)


def wait_until(moment):
    time.sleep(max(0.0, moment - time.time()))


def default_network():
    """"wifi" or "mobile": the transport of Android's default network, or None."""
    state = adb("dumpsys", "connectivity")
    default = state.split("Active default network: ", 1)[1].split()[0]
    for line in state.splitlines():
        if f"network{{{default}}}" in line:
            return "wifi" if "ni{WIFI" in line else "mobile" if "ni{MOBILE" in line else None
    return None


def use(net):
    """Makes the network the default one. The emulator's Wi-Fi can lose its validation, and Android
    then prefers mobile data; switching Wi-Fi off and on again brings it back."""
    for attempt in range(3):
        if net == "wifi" and attempt > 0:
            adb("svc", "wifi", "disable")
            time.sleep(3)
        adb("svc", "wifi", "enable" if net == "wifi" else "disable")
        for _ in range(60):
            if default_network() == net:
                time.sleep(10)  # let the switch settle
                return
            time.sleep(1)
    sys.exit(f"{net} did not become the default network")


def trial(log, net, background, down, up, last):
    """Reading A, the transfer, reading B; again if the default network changed meanwhile."""
    for _ in range(3):
        if default_network() != net:
            use(net)
        wait_until(last + GAP)
        start = now_ms()
        bucket = start // BUCKET * BUCKET
        a = read([(bucket, bucket + DAY), (bucket, 0), (start - 30 * DAY, 0)])
        time.sleep(2)
        transfer(log, background, down, up)
        time.sleep(2)
        wait_until(a["after"] + GAP)
        b = read([(bucket, bucket + DAY), (bucket, 0), (now_ms() - 30 * DAY, 0), (a["at"], 0)])
        if default_network() == net:
            return {"kind": "trial", "net": net, "background": background, "down": down, "up": up, "a": a, "b": b}
        print("default network changed during the trial; again", flush=True)
        last = b["after"]
    sys.exit(f"{net} did not stay the default network")


def rate_limit(log, last):
    """A fresh reading, a 1 MB transfer (below the 2 MB that makes Android count on its own), then
    readings 10, 20 and 36 s after the first: which of them show the transfer?"""
    if default_network() != "wifi":
        use("wifi")
    wait_until(last + GAP)
    bucket = now_ms() // BUCKET * BUCKET
    window = [(bucket, bucket + DAY)]
    readings = [read(window)]
    first = readings[0]["after"]
    time.sleep(1)
    transfer(log, False, 1_000_000, 0)
    for offset in (10, 20, 36):
        wait_until(first + offset)
        readings.append(read(window))
    return {"kind": "rate_limit", "readings": readings, "stayed": default_network() == "wifi"}


def trials(out):
    if not adb("getprop", "ro.kernel.qemu").strip() == "1":
        sys.exit("run.py changes device settings and runs on emulators only")
    log = out + ".server.log"
    open(log, "a").close()
    server = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py"), log])
    try:
        time.sleep(1)
        last = 0.0
        with open(out, "a") as results:
            for net in ("wifi", "mobile"):
                use(net)
                for rep in range(REPS):
                    for t in [t for t in TRIALS if t[0] == net]:
                        record = trial(log, *t, last)
                        last = record["b"]["after"]
                        results.write(json.dumps({"rep": rep, **record}) + "\n")
                        results.flush()
                        print(net, rep, t[1:], flush=True)
                    if net == "wifi":
                        record = rate_limit(log, last)
                        last = record["readings"][-1]["after"]
                        results.write(json.dumps({"rep": rep, "net": net, **record}) + "\n")
                        print(net, rep, "rate limit", flush=True)
    finally:
        server.terminate()
        use("wifi")


def counted(reading, window, net, uid):
    """rx, tx, rx packets, tx packets, and the background share of rx and tx."""
    states = reading["q"].get(str(window), {}).get(net, {}).get(uid, {})
    total = [sum(s[i] for s in states.values()) for i in range(4)]
    background = [sum(s[i] for state, s in states.items() if state != "2") for i in range(2)]
    return total + background


def minus(b, a):
    return [x - y for x, y in zip(b, a, strict=True)]


def everyone(reading, window, net):
    uids = reading["q"].get(str(window), {}).get(net, {})
    return [sum(counted(reading, window, net, uid)[i] for uid in uids) for i in range(2)]


def pct(value, base):
    return f"{100 * (value - base) / base:+.3f} %" if base else "n/a"


def activity(r):
    moved = f"down {r['down'] / 1e6:g} MB" if r["down"] else f"up {r['up'] / 1e6:g} MB"
    return ("background " if r["background"] else "") + moved


def row(*cells):
    print("| " + " | ".join(str(c) for c in cells) + " |")


def report(out, wifi_pcap, mobile_pcap):
    with open(out) as f:
        records = [json.loads(line) for line in f]
    trials = [r for r in records if r["kind"] == "trial"]
    pcaps = {"wifi": wifi_pcap, "mobile": mobile_pcap}
    windows = {"wifi": [], "mobile": []}
    for r in trials:
        a, b = r["a"], r["b"]
        r["port_window"] = len(windows[r["net"]])
        windows[r["net"]].append((a["after"], b["before"], PORT))
        middle = ((a["before"] + a["after"]) / 2, (b["before"] + b["after"]) / 2)
        r["all_window"] = {net: len(windows[net]) for net in windows}
        for net in windows:
            windows[net].append((*middle, None))
    with open(out + ".server.log") as f:
        finished = [float(line.split()[0]) for line in f]
    shifts = {net: capture.clock_shift(pcaps[net], PORT, finished) for net in pcaps}
    print("Clock shifts of the captures, in seconds: " + ", ".join(f"{n} {s:+.3f}" for n, s in shifts.items()) + "\n")
    seen = {net: capture.summarise(pcaps[net], windows[net], shifts[net]) for net in windows}

    row("Net", "Activity", "Rep", "Android rx", "Capture rx", "rx diff", "Android tx", "Capture tx", "tx diff",
        "Background", "All UIDs vs capture", "TrafficStats vs capture")
    row(*["---"] * 12)
    for r in trials:
        a, b, net, me = r["a"], r["b"], r["net"], r["a"]["me"]
        mine = minus(counted(b, 0, net, me), counted(a, 0, net, me))
        port = seen[net][r["port_window"]]
        all_counted = sum(minus(everyone(b, 0, net), everyone(a, 0, net)))
        all_seen = seen[net][r["all_window"][net]]
        both_seen = sum(seen[n][r["all_window"][n]]["rx"] + seen[n][r["all_window"][n]]["tx"] for n in seen)
        live = sum(minus(b["totals"][:2], a["totals"][:2]))
        share = f"{(mine[4] + mine[5]) / max(1, mine[0] + mine[1]):.0%}"
        row(net, activity(r), r["rep"], f"{mine[0]:,}", f"{port['rx']:,}", pct(mine[0], port["rx"]),
            f"{mine[1]:,}", f"{port['tx']:,}", pct(mine[1], port["tx"]), share,
            pct(all_counted, all_seen["rx"] + all_seen["tx"]), pct(live, both_seen))

    print("\nOther windows, the lab app's total (rx + tx), against the aligned window with a future end:")
    row("Net", "Activity", "Rep", "[bucket, bucket + 1 day]", "[bucket, now]", "[now - 30 days, now]",
        "one reading [first reading, now]")
    row(*["---"] * 7)
    for r in trials:
        a, b, net, me = r["a"], r["b"], r["net"], r["a"]["me"]
        diffs = [sum(minus(counted(b, w, net, me), counted(a, w, net, me))[:2]) for w in range(3)]
        single = sum(counted(b, 3, net, me)[:2])
        row(net, activity(r), r["rep"], f"{diffs[0]:,}", pct(diffs[1], diffs[0]), pct(diffs[2], diffs[0]),
            pct(single, diffs[0]))

    print("\nThe 15-second limit: the lab app's Wi-Fi rx at each reading, minus the first (1 MB moved after it):")
    for r in [r for r in records if r["kind"] == "rate_limit"]:
        first = r["readings"][0]
        me = first["me"]
        steps = []
        for x in r["readings"][1:]:
            mine = counted(x, 0, "wifi", me)[0] - counted(first, 0, "wifi", me)[0]
            everybody = sum(everyone(x, 0, "wifi")) - sum(everyone(first, 0, "wifi"))
            live = sum(x["totals"][:2]) - sum(first["totals"][:2])
            after = x["after"] - first["after"]
            steps.append(f"{after:.0f} s: {mine:,} (all UIDs {everybody:,}, TrafficStats {live:,})")
        note = "" if r["stayed"] else " (Wi-Fi stopped being the default)"
        print(f"- rep {r['rep']}{note}: " + "; ".join(steps))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "trials":
        trials(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == "report":
        report(*sys.argv[2:])
    else:
        sys.exit(__doc__)
