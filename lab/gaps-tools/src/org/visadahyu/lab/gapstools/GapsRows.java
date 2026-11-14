package org.visadahyu.lab.gapstools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Turns the raw output of one run of lab/run.sh into rows of docs/platform-gaps/results.csv.
 *
 *   GapsRows row RUN_DIR             prints the run's rows
 *   GapsRows add RUN_DIR RESULTS     puts them into RESULTS, in place of the rows of the same behaviour,
 *                                    part and API level
 *
 * The result of each row compares what was measured with what the behaviour's public source states
 * (ADR 0048): "held", "not held", "in part", "not run", or "measured" where no source makes a claim to hold
 * (the resolver without Private DNS: ADR 0048 measures its UIDs, not assumes them). A row whose result differs from its source,
 * or that measures what no public source states, is a possible new finding and is not added (ADR 0048,
 * decision 4): adding is a person's decision, after reading the row.
 */
public final class GapsRows {
    /** The behaviours in the order of ADR 0048's table. */
    static final List<String> ORDER = List.of("vpn-seen", "appops-closed", "proc-net", "loopback", "indicators",
            "carried-by-system", "short-lived", "webview");
    private static final String PROBE = "org.visadahyu.lab.gapsprobe";
    private static final String FIXTURE = "org.visadahyu.lab.gapsfixture";
    private static final String READ = "2026-11-14";
    private static final String UNDATED = "-";

    private GapsRows() {}

    public static void main(String[] args) throws IOException {
        if (args.length == 2 && args[0].equals("row")) {
            for (List<String> row : rows(Path.of(args[1]))) System.out.println(GapsCsv.format(row));
        } else if (args.length == 3 && args[0].equals("add")) {
            add(rows(Path.of(args[1])), Path.of(args[2]));
        } else {
            System.err.println("usage: GapsRows row RUN_DIR | add RUN_DIR RESULTS_CSV");
            System.exit(2);
        }
    }

    /** One run's raw output, as lab/run.sh writes it. */
    static final class GapsRun {
        final Path dir;
        final Map<String, String> facts = new HashMap<>();
        final List<String> probe;
        final List<String> observed;
        final Map<String, Integer> capture = new HashMap<>();
        /** The names under .gaps.example that the capture's DNS packets hold. */
        final Set<String> queries = new TreeSet<>();
        final Map<Integer, List<String>> packages = new TreeMap<>();

        GapsRun(Path dir) throws IOException {
            this.dir = dir;
            for (String file : List.of("run.txt", "image.txt")) {
                for (String line : lines(dir.resolve(file))) {
                    int space = line.indexOf(' ');
                    if (space > 0) facts.putIfAbsent(line.substring(0, space), line.substring(space + 1).trim());
                }
            }
            probe = lines(dir.resolve("probe.log"));
            observed = lines(dir.resolve("observed.txt"));
            for (String line : lines(dir.resolve("capture.txt"))) {
                String[] f = line.split(" ");
                if (f[0].equals("pattern") && f.length == 3) capture.put("pattern " + f[1], Integer.parseInt(f[2]));
                if (f[0].equals("to") && f.length == 4) capture.put(f[1] + " " + f[2], Integer.parseInt(f[3]));
                if (f[0].equals("query") && f.length == 2) queries.add(f[1]);
            }
            for (String line : lines(dir.resolve("uids.txt"))) {
                String[] f = line.split(" ");
                if (f.length == 2 && f[0].startsWith("package:") && f[1].startsWith("uid:")) {
                    packages.computeIfAbsent(Integer.parseInt(f[1].substring(4)), k -> new ArrayList<>()).add(f[0].substring(8));
                }
            }
        }

        String fact(String key) {
            return facts.getOrDefault(key, "-");
        }

        int uid(String pkg) {
            for (Map.Entry<Integer, List<String>> e : packages.entrySet()) if (e.getValue().contains(pkg)) return e.getKey();
            return -1;
        }

        /** The probe's lines that start with the behaviour and step given. */
        List<Map<String, String>> probeLines(String behaviourAndStep) {
            List<Map<String, String>> out = new ArrayList<>();
            for (String line : probe) {
                if (line.startsWith(behaviourAndStep + " ")) out.add(keys(line.substring(behaviourAndStep.length() + 1)));
            }
            return out;
        }

        /** Watch's flows: protocol, app, destination, uid, outcome, ... */
        List<String[]> flows(String label) throws IOException {
            List<String[]> out = new ArrayList<>();
            for (String line : lines(dir.resolve("flows-" + label + ".txt"))) out.add(line.split(" "));
            return out;
        }

        /** The flows in "after" that were not in "before". */
        List<String[]> newFlows(String before, String after) throws IOException {
            Set<String> old = new LinkedHashSet<>(lines(dir.resolve("flows-" + before + ".txt")));
            List<String[]> out = new ArrayList<>();
            for (String line : lines(dir.resolve("flows-" + after + ".txt"))) if (!old.contains(line)) out.add(line.split(" "));
            return out;
        }

        String who(String uid) {
            if (uid.equals("-")) return "no owner";
            List<String> names = packages.get(Integer.parseInt(uid));
            return "UID " + uid + (names == null ? "" : " (" + String.join(", ", names) + ")");
        }
    }

    static List<String> lines(Path file) throws IOException {
        if (!Files.exists(file)) return List.of();
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) if (!line.isBlank()) out.add(line.strip());
        return out;
    }

    /** "a=1 b=two" as a map; the first word without "=" is kept under "". */
    static Map<String, String> keys(String text) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String word : text.split(" ")) {
            int eq = word.indexOf('=');
            if (eq > 0) out.put(word.substring(0, eq), word.substring(eq + 1));
            else out.putIfAbsent("", word);
        }
        return out;
    }

    static List<List<String>> rows(Path dir) throws IOException {
        GapsRun run = new GapsRun(dir);
        List<Map<String, String>> parts = new ArrayList<>();
        switch (run.fact("behaviour")) {
            case "vpn-seen": parts.add(vpnSeen(run)); break;
            case "appops-closed": parts.add(appOpsClosed(run)); break;
            case "proc-net": parts.add(procNet(run)); break;
            case "loopback": parts.add(loopback(run)); break;
            case "indicators": parts.add(indicators(run)); break;
            case "carried-by-system": parts.addAll(carriedBySystem(run)); break;
            case "short-lived": parts.add(shortLived(run, "udp")); parts.add(shortLived(run, "tcp")); break;
            case "webview": parts.add(webview(run)); break;
            default: throw new IllegalArgumentException("no behaviour in " + dir.resolve("run.txt"));
        }
        List<List<String>> out = new ArrayList<>();
        for (Map<String, String> part : parts) {
            Map<String, String> row = new HashMap<>(part);
            for (String key : List.of("behaviour", "android", "api", "image", "image_revision", "archive_sha1",
                    "image_files_sha256", "fingerprint", "security_patch", "play_update", "resolver", "emulator",
                    "probe_commit", "run", "capture_sha256")) {
                row.putIfAbsent(key, run.fact(key));
            }
            row.put("date", run.fact("date").length() >= 10 ? run.fact("date").substring(0, 10) : "-");
            row.putIfAbsent("part", "-");
            row.putIfAbsent("trials", "1");
            row.putIfAbsent("events", "-");
            row.putIfAbsent("rate", "-");
            row.putIfAbsent("ci95", "-");
            row.put("replicated", "not yet");
            List<String> fields = new ArrayList<>();
            for (String column : GapsCsv.COLUMNS) fields.add(row.getOrDefault(column, "-"));
            out.add(fields);
        }
        return out;
    }

    private static Map<String, String> row(String result, String measured, String source, String read, String watch) {
        Map<String, String> row = new HashMap<>();
        row.put("result", result);
        row.put("measured", measured);
        row.put("source", source);
        row.put("source_read", read);
        row.put("watch", watch);
        return row;
    }

    private static void timing(Map<String, String> row, int events, int trials) {
        row.put("trials", Integer.toString(trials));
        row.put("events", Integer.toString(events));
        if (trials > 0) {
            row.put("rate", GapsWilson.rate(events, trials));
            row.put("ci95", GapsWilson.format(events, trials));
        }
    }

    static Map<String, String> vpnSeen(GapsRun run) {
        Map<String, String> seen = new LinkedHashMap<>();
        boolean held = true;
        for (String phase : List.of("inside", "left-out", "none")) {
            List<Map<String, String>> active = new ArrayList<>();
            boolean listed = false;
            String tun = null;
            for (String line : run.probe) {
                if (!line.startsWith("vpn-seen " + phase + " ")) continue;
                String rest = line.substring(("vpn-seen " + phase + " ").length());
                Map<String, String> k = keys(rest);
                if (rest.startsWith("active ")) active.add(k);
                if (rest.startsWith("network ") && k.getOrDefault("transports", "").contains("vpn")) listed = true;
                if (rest.startsWith("interface ") && k.getOrDefault("name", "").startsWith("tun")) {
                    tun = k.get("name") + " " + k.getOrDefault("addresses", "-").replaceAll("fe80::[^,]*,?", "");
                }
            }
            boolean ownVpn = !active.isEmpty() && active.get(0).getOrDefault("transports", "").contains("vpn");
            if (active.isEmpty()) {
                seen.put(phase, "not measured");
                held = false;
                continue;
            }
            String own = ownVpn ? "own network a VPN" : "own network not a VPN (" + active.get(0).getOrDefault("transports", "-") + ")";
            seen.put(phase, own + ", " + (listed ? "a VPN in getAllNetworks" : "no VPN in getAllNetworks") + ", "
                    + (tun == null ? "no tun interface" : "interface " + tun.replaceAll(",$", "")));
            if (phase.equals("inside")) held &= ownVpn && listed && tun != null;
            else held &= !ownVpn;
        }
        String measured = "inside the tunnel: " + seen.get("inside") + "; left out: " + seen.get("left-out") + "; no VPN: " + seen.get("none");
        return row(held ? "held" : "not held", measured,
                "Android's references for NetworkCapabilities, ConnectivityManager and VpnService.Builder; ADR 0041", UNDATED,
                "Common tunnel addresses (ADR 0041, decision 3); says that every app can tell a VPN is on, and that an app left out may still find the VPN interface");
    }

    static Map<String, String> appOpsClosed(GapsRun run) {
        Map<String, String> history = new LinkedHashMap<>();
        boolean ownOpened = false;
        for (String step : List.of("history-default", "history-hidden-open", "history-granted", "history-granted-hidden-open")) {
            String answer = "not measured";
            for (Map<String, String> k : run.probeLines("appops-closed " + step)) {
                if (k.getOrDefault("scope", "").equals("all")) {
                    answer = k.getOrDefault("answer", "-") + (k.containsKey("error") ? " (" + k.get("error") + " at " + k.get("stage") + ")" : "")
                            + (k.containsKey("sought") ? ", the fixture " + k.get("sought") : "");
                }
                if (k.getOrDefault("scope", "").equals("own") && "opened".equals(k.get("answer"))) ownOpened = true;
            }
            history.put(step, answer);
        }
        Map<String, String> end = run.probeLines("appops-closed watch").stream().filter(k -> k.get("").equals("end")).findFirst().orElse(Map.of());
        int own = Integer.parseInt(end.getOrDefault("own", "0"));
        int fixture = Integer.parseInt(end.getOrDefault("fixture", "0"));
        int other = Integer.parseInt(end.getOrDefault("other", "0"));
        boolean closed = !history.get("history-default").startsWith("opened");
        boolean unavailable = end.containsKey("unavailable");
        String result = !closed || fixture > 0 || other > 0 ? "not held" : (own > 0 || unavailable) && ownOpened ? "held" : "in part";
        String measured = "every app's history, as installed: " + history.get("history-default")
                + "; with hidden APIs opened on the emulator: " + history.get("history-hidden-open")
                + "; with GET_APP_OPS_STATS granted over adb: " + history.get("history-granted")
                + "; with both: " + history.get("history-granted-hidden-open")
                + "; the probe's own history (control): " + (ownOpened ? "opened" : "not opened")
                + "; startWatchingActive: " + (unavailable ? "not in this version (from Android 11)" : "the probe's own microphone " + own
                + " callbacks (control), the fixture's microphone " + fixture + ", other apps " + other);
        return row(result, measured, "AOSP's AppOpsService.getHistoricalOps, whose code answers another app's history only to the system, "
                + "an instrumented caller, the permission controller or a holder of GET_HISTORICAL_APP_OPS_STATS, and an empty answer to anyone "
                + "else; AppOpsManager reference (startWatchingActive)", READ,
                "Not seen. The audit app shows which apps hold each permission (ADR 0014); the words on Watch's view: not built (ADR 0046, decision 5)");
    }

    static Map<String, String> procNet(GapsRun run) {
        Map<String, List<String>> byAnswer = new LinkedHashMap<>();
        boolean held = true;
        int files = 0;
        Set<String> seen = new LinkedHashSet<>();
        for (Map<String, String> k : run.probeLines("proc-net once")) {
            // A step that ran twice (an activity created again) gives the same files twice: each counts once.
            if (!k.containsKey("file") || !seen.add(k.get("file"))) continue;
            files++;
            String answer = k.get("answer");
            String error = k.getOrDefault("error", "");
            java.util.regex.Matcher code = java.util.regex.Pattern.compile("E[A-Z]{3,}").matcher(error);
            String errno = code.find() ? code.group() : error;
            String key = answer.equals("read") ? "read (" + k.get("lines") + " lines)" : "refused" + (errno.isEmpty() ? "" : " (" + errno + ")");
            byAnswer.computeIfAbsent(key, x -> new ArrayList<>()).add(k.get("file"));
            held &= !answer.equals("read");
        }
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : byAnswer.entrySet()) parts.add(String.join(", ", e.getValue()) + ": " + e.getKey());
        return row(held && files == 6 ? "held" : files == 6 ? "not held" : "in part",
                "/proc/net/ " + (parts.isEmpty() ? "not measured" : String.join("; ", parts)),
                "Android 10 privacy changes", READ, "Not a route Watch labels: Watch names each flow's app with getConnectionOwnerUid, as the active VPN");
    }

    static Map<String, String> loopback(GapsRun run) throws IOException {
        Map<String, Boolean> exchanged = new TreeMap<>();
        for (String family : List.of("v4", "v6")) {
            boolean listened = run.probeLines("loopback listen").stream().anyMatch(k -> family.equals(k.get("")) && "match".equals(k.get("ask")));
            boolean answered = run.probeLines("loopback connect").stream().anyMatch(k -> family.equals(k.get("")) && "match".equals(k.get("answer")));
            exchanged.put(family, listened && answered);
        }
        int toLoopback = 0;
        for (String[] f : run.newFlows("before", "after")) {
            if (f.length > 2 && (f[2].startsWith("127.") || f[2].startsWith("[::1]"))) toLoopback++;
        }
        int inCapture = run.capture.getOrDefault("pattern gaps-loopback", -1);
        String fixture = run.probe.stream().filter(l -> l.startsWith("fixture socket ")).map(l -> keys(l.substring(15)))
                .map(k -> k.getOrDefault("answer", "-") + (k.containsKey("error") ? " (" + k.get("error").replace('_', ' ') + ")" : ""))
                .findFirst().orElse("not measured");
        boolean held = exchanged.get("v4") && exchanged.get("v6") && toLoopback == 0 && inCapture == 0;
        String measured = "two apps exchanged the payload over 127.0.0.1: " + yes(exchanged.get("v4")) + ", over ::1: " + yes(exchanged.get("v6"))
                + "; Watch's flows to loopback: " + toLoopback + "; packets with the payload in the capture: " + inCapture
                + "; a socket of an app without INTERNET: " + fixture;
        return row(held ? "held" : "not held", measured, "Local Mess disclosure, June 2025 (localmess.github.io); ADR 0034", READ,
                "Not seen; the words on Watch's view: not built (ADR 0046, decision 5)");
    }

    static Map<String, String> indicators(GapsRun run) {
        int api = (int) Double.parseDouble(run.fact("api"));
        Map<String, String> reads = new LinkedHashMap<>();
        for (String line : run.probe) {
            if (!line.startsWith("fixture read ")) continue;
            Map<String, String> k = keys(line.substring(13));
            reads.put(k.get("kind"), "read".equals(k.get("answer")) ? k.get("count") : k.getOrDefault("answer", "-"));
        }
        boolean chip = false;
        boolean toast = false;
        List<String> toasts = new ArrayList<>();
        List<String> notifications = new ArrayList<>();
        List<String> dashboard = new ArrayList<>();
        for (String line : run.observed) {
            if (line.startsWith("chip ") && line.contains("icrophone")) chip = true;
            if (line.startsWith("privacy-item TYPE_MICROPHONE " + FIXTURE)) chip = true;
            if (line.startsWith("toast ")) {
                toasts.add(line.substring(6));
                if (line.contains("Gaps fixture (lab)") && line.contains("clipboard")) toast = true;
            }
            if (line.startsWith("notification ")) notifications.add(line.substring(13));
            if (line.startsWith("dashboard ")) dashboard.add(line.substring(10));
        }
        boolean allRead = reads.size() == 6 && reads.values().stream().allMatch(v -> v.matches("[1-9][0-9]*"));
        boolean fixtureNotified = notifications.stream().anyMatch(n -> n.startsWith(FIXTURE));
        boolean held = allRead && !fixtureNotified && (api >= 31 ? chip && toast : !chip && !toast);
        String measured = "the fixture's reads (items, or bytes of the microphone): " + reads
                + "; microphone indicator: " + (chip ? "shown" : "none")
                + "; toasts: " + (toasts.isEmpty() ? "none" : String.join(" / ", new TreeSet<>(toasts)))
                + "; notifications of the fixture: " + (fixtureNotified ? "yes" : "none")
                + "; the dashboard: " + (dashboard.isEmpty() ? "none" : String.join(" / ", dashboard));
        return row(allRead ? held ? "held" : "not held" : "in part", measured,
                "Android 12 behaviour changes for all apps; Google's Help, Manage permissions from the privacy dashboard (in part: it names "
                        + "camera, microphone, calendar \"and more\", not the other groups); Android 10 privacy changes", READ,
                "Not seen. The audit app shows which apps hold each permission (ADR 0014); the words on Watch's view: not built (ADR 0046, decision 5)");
    }

    static List<Map<String, String>> carriedBySystem(GapsRun run) throws IOException {
        List<Map<String, String>> out = new ArrayList<>();
        int probe = run.uid(PROBE);
        int downloads = run.uid("com.android.providers.downloads");
        String notBuilt = "The flow stays under the UID Android names; marking it as carried for another app, and the words: not built (ADR 0048, decision 3)";
        String parts = "," + (run.fact("parts").equals("-") ? "download,tab,push,resolver" : run.fact("parts")) + ",";

        Map<String, String> answer = run.probeLines("carried-by-system download").stream().filter(k -> k.containsKey("answer")).findFirst().orElse(Map.of());
        Map<String, Integer> owners = owners(run.newFlows("download-before", "download-after"), ":8792");
        boolean held = "done".equals(answer.get("answer")) && !owners.isEmpty()
                && owners.keySet().stream().allMatch(u -> u.equals(Integer.toString(downloads)));
        Map<String, String> download = row(owners.isEmpty() ? "in part" : held ? "held" : "not held",
                "the download service: " + answer.getOrDefault("answer", "no answer") + ", " + answer.getOrDefault("bytes", "0") + " bytes; Watch's flows to the lab's server: "
                        + describe(run, owners) + "; connections in the capture: " + run.capture.getOrDefault("tcp-syn 10.0.2.2:8792", 0),
                "NetGuard FAQ, items 8 and 66", READ, notBuilt);
        download.put("part", "download");
        if (parts.contains(",download,")) out.add(download);

        owners = owners(run.newFlows("tab-before", "tab-after"), ":8792");
        String handler = run.probeLines("carried-by-system tab").stream().filter(k -> k.containsKey("handler")).map(k -> k.get("handler")).findFirst().orElse("none");
        String screen = run.observed.stream().filter(l -> l.startsWith("tab-screen ")).map(l -> l.substring(11)).findFirst().orElse("-");
        Map<String, String> tab;
        if (owners.isEmpty() && screen.contains("FirstRun")) {
            tab = row("not run", "the browser (" + handler + ") showed its first-run screen (" + screen
                    + "), whose terms the run does not accept for anyone; no request reached the lab's server", "Custom Tabs overview", UNDATED, notBuilt);
        } else {
            int browser = run.uid(handler);
            held = !owners.isEmpty() && owners.keySet().stream().allMatch(u -> u.equals(Integer.toString(browser)));
            tab = row(owners.isEmpty() ? "in part" : held ? "held" : "not held", "the Custom Tab's handler: " + handler + "; Watch's flows to the lab's server: "
                    + describe(run, owners), "Custom Tabs overview", UNDATED, notBuilt);
        }
        tab.put("part", "tab");
        if (parts.contains(",tab,")) out.add(tab);

        Map<String, String> push = row("not run", "needs a Firebase project, an account: the maintainer's word (ADR 0048, what it does not decide)",
                "NetGuard FAQ, items 8 and 66", READ, notBuilt);
        push.put("part", "push");
        if (parts.contains(",push,")) out.add(push);

        for (String mode : List.of("off", "opportunistic", "hostname")) {
            List<Map<String, String>> lookups = run.probeLines("carried-by-system resolve-" + mode);
            int trials = (int) lookups.stream().filter(k -> k.containsKey("trial")).count();
            if (trials == 0 || !parts.contains(",resolver,")) continue;
            int seen = (int) lookups.stream().filter(k -> k.containsKey("trial") && run.queries.contains(k.get("name"))).count();
            // The window's DNS flows (port 53 or 853, the lab's or another's, as redacted), by who carried them.
            Map<String, Integer> system = new TreeMap<>();
            int own = 0;
            int others = 0;
            int unknown = 0;
            int systemTls = 0;
            for (String[] f : run.flows("resolve-" + mode)) {
                if (f.length < 4 || !(f[2].endsWith(":53") || f[2].endsWith(":853"))) continue;
                String port = f[2].replaceAll(".*:", "");
                if (f[3].equals(Integer.toString(probe))) own++;
                else if (f[3].equals("-")) unknown++;
                else if (f[3].matches("[0-9]+") && Integer.parseInt(f[3]) < 10_000) {
                    system.merge("UID " + f[3] + " to port " + port, 1, Integer::sum);
                    if (port.equals("853")) systemTls++;
                } else others++;
            }
            // Each of the probe's lookups left under the probe's UID or under a UID of the system. With none
            // under the probe's, none did; with some under it and none under the system's or without owner,
            // every lookup that left (its name is in the capture) did. Otherwise the split is not known.
            int systemFlows = system.values().stream().mapToInt(Integer::intValue).sum();
            Integer events = own == 0 ? Integer.valueOf(0) : systemFlows == 0 && unknown == 0 && !mode.equals("hostname") ? Integer.valueOf(seen) : null;
            // Strict Private DNS: the source says the system secures every app's queries, so none should leave
            // under the app's UID; without it, the row records the UIDs, as ADR 0048 asks, and claims nothing.
            String result = !mode.equals("hostname") ? "measured" : own == 0 && systemTls > 0 ? "held" : "not held";
            List<String> described = new ArrayList<>();
            for (Map.Entry<String, Integer> e : system.entrySet()) described.add(e.getValue() + " " + e.getKey());
            String watchSays = run.observed.stream().filter(l -> l.startsWith("private-dns " + mode + " ")).map(l -> l.replaceAll(".*watch=", "")).findFirst().orElse("-");
            Map<String, String> resolver = row(result, trials + " lookups of names under .example, Private DNS " + mode + " (Watch read: " + watchSays
                    + "); their names in the capture: " + seen + (mode.equals("hostname") ? " (encrypted)" : "")
                    + "; the window's DNS flows: " + own + " under the probe's UID, " + (described.isEmpty() ? "none under a UID of the system" : String.join(", ", described))
                    + ", " + unknown + " without owner, and " + others + " of other apps, not counted"
                    + "; trials are the probe's lookups, and events those that left under its UID"
                    + (events == null ? ", which these flows cannot tell apart, so no rate" : ""),
                    "Android Developers blog, DNS over TLS support in Android P, 2018 (in part: the system \"automatically secures the DNS "
                            + "queries from all apps\"; it names no UID); otherwise measured, not assumed (ADR 0048)", READ,
                    "A lookup shows under the app when Android names it; under \"Android's resolver\" otherwise: not built (ADR 0048, decision 3)");
            resolver.put("part", "resolver-" + mode);
            resolver.put("trials", Integer.toString(trials));
            // A rate needs at least 100 trials (ADR 0048, decision 2) and a known count of events.
            if (events != null && trials >= 100) timing(resolver, events, trials);
            else if (events != null) resolver.put("events", Integer.toString(events));
            out.add(resolver);
        }
        return out;
    }

    static Map<String, String> shortLived(GapsRun run, String protocol) throws IOException {
        int[] closed = owned(run, protocol + "-closed");
        int[] open = owned(run, protocol + "-open");
        String result = closed[0] > 0 && open[0] == 0 && open[2] > 0 ? "held" : "in part";
        String measured = protocol.toUpperCase() + " sockets closed at once: " + closed[0] + " of " + closed[2] + " flows with no owner, "
                + closed[1] + " trials without a flow; kept open (control): " + open[0] + " of " + open[2] + " with no owner, "
                + open[1] + " without a flow; the event counted: a closed socket's flow with no owner";
        Map<String, String> row = row(result, measured, "PCAPdroid FAQ, the \"unknown\" app; ConnectivityManager.getConnectionOwnerUid reference",
                READ + ": PCAPdroid FAQ",
                "The flow is kept with no app, and counted among the flows Android cannot name; shown as \"app not known\": not built (ADR 0044)");
        row.put("part", protocol);
        timing(row, closed[0], closed[2] + closed[1]);
        return row;
    }

    /** For a step of short-lived: flows with no owner, trials without a flow, trials with one. */
    private static int[] owned(GapsRun run, String step) throws IOException {
        String protocol = step.substring(0, 3);
        String server = protocol.equals("udp") ? "10.0.2.2:8796" : "10.0.2.2:8792";
        Map<String, String> ownerByPort = new HashMap<>();
        for (String[] f : run.flows(step)) {
            if (f.length > 3 && f[0].equals(protocol) && f[2].equals(server)) ownerByPort.putIfAbsent(f[1].replaceAll(".*:", ""), f[3]);
        }
        int none = 0;
        int missing = 0;
        int found = 0;
        for (Map<String, String> k : run.probeLines("short-lived " + step)) {
            if (!k.containsKey("local")) continue;
            String owner = ownerByPort.get(k.get("local"));
            if (owner == null) missing++;
            else {
                found++;
                if (owner.equals("-")) none++;
            }
        }
        return new int[] {none, missing, found};
    }

    static Map<String, String> webview(GapsRun run) throws IOException {
        int probe = run.uid(PROBE);
        Map<String, Integer> first = owners(run.newFlows("before", "after"), ":8792");
        Map<String, Integer> second = owners(run.newFlows("before", "after"), ":8793");
        boolean held = !first.isEmpty() && !second.isEmpty()
                && first.keySet().stream().allMatch(u -> u.equals(Integer.toString(probe)))
                && second.keySet().stream().allMatch(u -> u.equals(Integer.toString(probe)));
        return row(first.isEmpty() || second.isEmpty() ? "in part" : held ? "held" : "not held",
                "the page's origin: " + describe(run, first) + "; the second origin (image and fetch): " + describe(run, second),
                "Chromium's WebView architecture document (in part: WebView's browser code, its network service included, runs in the "
                        + "app's process; it says nothing of UIDs)", READ,
                "The flow stays under the app, with its destination's name; the words: not built (ADR 0048, decision 3)");
    }

    private static Map<String, Integer> owners(List<String[]> flows, String port) {
        Map<String, Integer> out = new TreeMap<>();
        for (String[] f : flows) if (f.length > 3 && f[2].endsWith(port)) out.merge(f[3], 1, Integer::sum);
        return out;
    }

    private static String describe(GapsRun run, Map<String, Integer> owners) {
        if (owners.isEmpty()) return "none";
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Integer> e : owners.entrySet()) out.add(e.getValue() + " under " + run.who(e.getKey()));
        return String.join(", ", out);
    }

    private static String yes(boolean value) {
        return value ? "yes" : "no";
    }

    /** Puts the rows into the CSV in place of the rows of the same behaviour, part and API level. */
    static void add(List<List<String>> rows, Path csv) throws IOException {
        List<List<String>> all = new ArrayList<>(read(csv));
        for (List<String> row : rows) {
            all.removeIf(old -> key(old).equals(key(row)));
            all.add(row);
        }
        all.sort(ROW_ORDER);
        List<String> out = new ArrayList<>();
        out.add(String.join(",", GapsCsv.COLUMNS));
        for (List<String> row : all) out.add(GapsCsv.format(row));
        Files.write(csv, out, StandardCharsets.UTF_8);
    }

    static List<List<String>> read(Path csv) throws IOException {
        List<List<String>> rows = new ArrayList<>();
        List<String> lines = lines(csv);
        if (lines.isEmpty()) return rows;
        if (!GapsCsv.parse(lines.get(0)).equals(GapsCsv.COLUMNS)) throw new IOException(csv + ": the header is not " + GapsCsv.COLUMNS);
        for (String line : lines.subList(1, lines.size())) {
            List<String> row = GapsCsv.parse(line);
            if (row.size() != GapsCsv.COLUMNS.size()) throw new IOException(csv + ": a row of " + row.size() + " fields: " + line);
            rows.add(row);
        }
        return rows;
    }

    private static String key(List<String> row) {
        return row.get(0) + "|" + row.get(1) + "|" + row.get(3);
    }

    static final Comparator<List<String>> ROW_ORDER = Comparator
            .<List<String>>comparingInt(r -> ORDER.indexOf(r.get(0)))
            .thenComparing(r -> r.get(1))
            .thenComparingDouble(r -> r.get(3).matches("[0-9.]+") ? Double.parseDouble(r.get(3)) : 0);
}
