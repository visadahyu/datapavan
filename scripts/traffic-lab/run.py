#!/usr/bin/env python3
"""Guided check spike (docs/spikes/2026-11-guided-check.md): does the difference of two readings of
Android's network counts give an activity's traffic exactly, and how must the readings be taken?

  run.py trials OUT.jsonl     moves known amounts with the traffic lab app and reads the counts
                              before and after each transfer; also tests the 15-second limit
  run.py report OUT.jsonl WIFI_PCAP MOBILE_PCAP
                              compares the counts with the emulator's packet captures
  run.py private              on a personal phone on the same Wi-Fi as this computer: the Wi-Fi
                              trials and the 15-second test against the bytes moved. The app listens
                              and this computer connects to it, since a computer's firewall usually
                              lets nothing in. Changes no setting, writes nothing, and prints only
                              the lab app's numbers and percentages; the phone returns other apps'
                              counts only as a sum (ReadReceiver's "private" extra).
  run.py guided PACKAGE SIGNAL_FILE
                              a guided check of one installed app on a personal phone: reading A,
                              then the person performs one activity in the app and SIGNAL_FILE is
                              created, then reading B; prints only that app's numbers

Except for "private": emulators only, started with `-tcpdump MOBILE_PCAP -netsim-args --pcap` (netsimd writes the Wi-Fi
capture under /tmp/android-$USER/netsimd/pcaps, and deletes it when it exits: copy it before the
emulator stops), with the lab app installed (build.sh) and given usage access (appops set
org.visadahyu.datapavan.trafficlab GET_USAGE_STATS allow).
"""
import json
import os
import socket
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
# Set by "private" and "guided": the phone's address on Wi-Fi when the app listens, whether the phone
# is a personal one, and the UID whose counts it returns.
OPTIONS = {"phone": None, "private": False, "uid": None}
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
    personal = ["--ez", "private", "true"] if OPTIONS["private"] else []
    if OPTIONS["uid"] is not None:
        personal += ["--ei", "uid", str(OPTIONS["uid"])]
    before = time.time()
    out = adb("am", "broadcast", "-n", f"{PKG}/.ReadReceiver", "--ela", "starts", starts, "--ela", "ends", ends,
              *personal)
    after = time.time()
    reading = {"before": before, "after": after, "windows": windows, "q": {}, "sum": {}}
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
        elif f[0] == "s":
            reading["sum"].setdefault(f[1], {})[f[2]] = [int(x) for x in f[3:5]]
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
    if OPTIONS["phone"]:
        extras += ["--ei", "listen", str(PORT)]
    if background and OPTIONS["phone"]:
        # `am broadcast` returns when the receiver is done, and a listening receiver is done only
        # after this computer has connected.
        broadcast = subprocess.Popen(["adb", "shell", "am", "broadcast", "-n", f"{PKG}/.TransferReceiver", *extras],
                                     stdout=subprocess.DEVNULL)
        exchange(OPTIONS["phone"], down, up, log)
        broadcast.wait()
    elif background:
        adb("am", "broadcast", "-n", f"{PKG}/.TransferReceiver", *extras)
    else:
        adb("am", "start", "-W", "-n", f"{PKG}/.TransferActivity", *extras)
        if OPTIONS["phone"]:
            exchange(OPTIONS["phone"], down, up, log)
    deadline = time.time() + 180
    while lines(log) < expected:
        if time.time() > deadline:
            sys.exit("transfer did not finish; see adb logcat -s TrafficLab")
        time.sleep(0.2)


def exchange(phone, down, up, log):
    """This computer's end of a transfer with an app that listens: sends [down] bytes, then reads
    what the app sends back until it closes, and logs both like server.py."""
    deadline = time.time() + 15
    while True:
        try:
            connection = socket.create_connection((phone, PORT), timeout=5)
            break
        except OSError:
            if time.time() > deadline:
                sys.exit(f"could not connect to {phone}:{PORT}")
            time.sleep(0.2)
    received = 0
    with connection:
        connection.settimeout(120)
        block = os.urandom(64 * 1024)
        for offset in range(0, down, len(block)):
            connection.sendall(block[:min(len(block), down - offset)])
        while chunk := connection.recv(64 * 1024):
            received += len(chunk)
    with open(log, "a") as f:
        if down:
            f.write(f"{time.time():.3f} down {down} socket\n")
        if up:
            f.write(f"{time.time():.3f} up {received} socket\n")


def wait_until(moment):
    time.sleep(max(0.0, moment - time.time()))


def default_network():
    """"wifi" or "mobile": the transport of Android's default network, or None."""
    state = adb("dumpsys", "connectivity")
    default = state.split("Active default network: ", 1)[1].split()[0]
    for line in state.splitlines():
        if f"network{{{default}}}" in line:  # "ni{WIFI" since Android 12, "ni{[type: WIFI" before
            if "ni{WIFI" in line or "type: WIFI" in line:
                return "wifi"
            if "ni{MOBILE" in line or "type: MOBILE" in line:
                return "mobile"
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
            if OPTIONS["private"]:
                sys.exit(f"{net} is not the default network; a personal phone's settings are left alone")
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
        if OPTIONS["private"]:
            sys.exit("Wi-Fi is not the default network; a personal phone's settings are left alone")
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
    if reading.get("sum"):
        return reading["sum"].get(str(window), {}).get(net, [0, 0])
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


def phone_address():
    for line in adb("ip", "-4", "addr", "show", "wlan0").splitlines():
        if line.strip().startswith("inet "):
            return line.split()[1].split("/")[0]
    sys.exit("the phone has no Wi-Fi address")


def private():
    """The Wi-Fi trials on a personal phone, reported at once and kept nowhere."""
    OPTIONS.update(phone=phone_address(), private=True)
    log = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"traffic-lab-{os.getpid()}.log")
    open(log, "w").close()
    records, last = [], 0.0
    try:
        for rep in range(REPS):
            for t in [t for t in TRIALS if t[0] == "wifi"]:
                record = trial(log, *t, last)
                last = record["b"]["after"]
                records.append({"rep": rep, **record})
                print("wifi", rep, t[1:], flush=True)
            record = rate_limit(log, last)
            last = record["readings"][-1]["after"]
            records.append({"rep": rep, "net": "wifi", **record})
            print("wifi", rep, "rate limit", flush=True)
    finally:
        os.remove(log)
    private_report(records)


def guided(package, signal):
    """A guided check of one app: only its numbers are printed, and nothing is kept."""
    uid = next((line.split("userId=")[1].split()[0] for line in adb("dumpsys", "package", package).splitlines()
                if "userId=" in line), None)
    if uid is None:
        sys.exit(f"{package} is not installed")
    OPTIONS.update(private=True, uid=int(uid))
    start = now_ms()
    bucket = (start - DAY) // BUCKET * BUCKET
    window = [(bucket, start + DAY)]
    a = read(window)
    print(f"reading A at {time.strftime('%H:%M:%S')}: perform the activity, then create {signal}", flush=True)
    while not os.path.exists(signal):
        time.sleep(0.5)
    wait_until(a["after"] + GAP)
    b = read(window)
    for net in ("wifi", "mobile"):
        mine = minus(counted(b, 0, net, uid), counted(a, 0, net, uid))
        if any(mine[:2]):
            print(f"{net}: received {mine[0]:,} B in {mine[2]:,} packets, sent {mine[1]:,} B in {mine[3]:,} packets;"
                  f" background {mine[4]:,} B received, {mine[5]:,} B sent")
    everybody = sum(sum(minus(everyone(b, 0, n), everyone(a, 0, n))) for n in ("wifi", "mobile"))
    live = sum(minus(b["totals"][:2], a["totals"][:2]))
    between = b["after"] - a["after"]
    print(f"seconds between the readings: {between:.0f}; all apps against TrafficStats: {pct(everybody, live)}")


def private_report(records):
    """Only the lab app's own numbers, and the sum over all apps as a percentage of the live totals."""
    def all_apps(b, a):
        return sum(sum(minus(everyone(b, 0, n), everyone(a, 0, n))) for n in ("wifi", "mobile"))

    trials = [r for r in records if r["kind"] == "trial"]
    print("\nThe lab app's count in the direction of the transfer, against the bytes the server moved:")
    row("Activity", "Rep", "Moved", "Android", "Packets", "Above the payload, per packet", "Other direction",
        "Background", "All apps vs TrafficStats")
    row(*["---"] * 9)
    for r in trials:
        a, b, me = r["a"], r["b"], r["a"]["me"]
        mine = minus(counted(b, 0, "wifi", me), counted(a, 0, "wifi", me))
        way = 0 if r["down"] else 1
        moved = r["down"] or r["up"]
        live = sum(minus(b["totals"][:2], a["totals"][:2]))
        share = f"{(mine[4] + mine[5]) / max(1, mine[0] + mine[1]):.0%}"
        row(activity(r), r["rep"], f"{moved:,}", f"{mine[way]:,}", f"{mine[2 + way]:,}",
            f"{(mine[way] - moved) / max(1, mine[2 + way]):.1f} B", f"{mine[1 - way]:,}", share,
            pct(all_apps(b, a), live))

    print("\nOther windows, the lab app's total (rx + tx), against the aligned window with a future end:")
    row("Activity", "Rep", "[bucket, bucket + 1 day]", "[bucket, now]", "[now - 30 days, now]",
        "one reading [first reading, now]")
    row(*["---"] * 6)
    for r in trials:
        a, b, me = r["a"], r["b"], r["a"]["me"]
        diffs = [sum(minus(counted(b, w, "wifi", me), counted(a, w, "wifi", me))[:2]) for w in range(3)]
        single = sum(counted(b, 3, "wifi", me)[:2])
        row(activity(r), r["rep"], f"{diffs[0]:,}", pct(diffs[1], diffs[0]), pct(diffs[2], diffs[0]),
            pct(single, diffs[0]))

    print("\nThe 15-second limit: the lab app's Wi-Fi rx at each reading, minus the first (1 MB moved after it):")
    for r in [r for r in records if r["kind"] == "rate_limit"]:
        first = r["readings"][0]
        me = first["me"]
        steps = []
        for x in r["readings"][1:]:
            mine = counted(x, 0, "wifi", me)[0] - counted(first, 0, "wifi", me)[0]
            live = sum(minus(x["totals"][:2], first["totals"][:2]))
            after = x["after"] - first["after"]
            steps.append(f"{after:.0f} s: {mine:,} (all apps vs TrafficStats {pct(all_apps(x, first), live)})")
        note = "" if r["stayed"] else " (Wi-Fi stopped being the default)"
        print(f"- rep {r['rep']}{note}: " + "; ".join(steps))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "trials":
        trials(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == "report":
        report(*sys.argv[2:])
    elif len(sys.argv) == 2 and sys.argv[1] == "private":
        private()
    elif len(sys.argv) == 4 and sys.argv[1] == "guided":
        guided(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
