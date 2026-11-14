package org.visadahyu.lab.gapstools;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The unit tests of lab/gaps-tools, on the JVM, with a runner of their own: every method whose name starts
 * with "test" runs, and any failure fails the run. lab/gaps-tools/build.sh runs them.
 */
public final class GapsToolsTest {
    public static void main(String[] args) throws Exception {
        int failed = 0;
        int passed = 0;
        List<Method> tests = new ArrayList<>();
        for (Method m : GapsToolsTest.class.getDeclaredMethods()) if (m.getName().startsWith("test")) tests.add(m);
        tests.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (Method test : tests) {
            try {
                test.invoke(null);
                passed++;
            } catch (InvocationTargetException e) {
                failed++;
                System.err.println("FAIL " + test.getName() + ": " + e.getCause());
            }
        }
        System.out.println("gaps-tools: " + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError(what);
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected <" + expected + "> but was <" + actual + ">");
    }

    private static void near(double expected, double actual) {
        if (Math.abs(expected - actual) > 0.0005) throw new AssertionError("expected " + expected + " but was " + actual);
    }

    // Wilson's interval, against values computed by hand from the formula (z = 1.96).
    static void testWilsonKnownValues() {
        double[] none = GapsWilson.interval(0, 100);
        near(0.0, none[0]);
        near(0.0370, none[1]);
        double[] half = GapsWilson.interval(50, 100);
        near(0.4038, half[0]);
        near(0.5962, half[1]);
        double[] all = GapsWilson.interval(100, 100);
        near(0.9630, all[0]);
        near(1.0, all[1]);
        double[] small = GapsWilson.interval(5, 10);
        near(0.2366, small[0]);
        near(0.7634, small[1]);
        equal("0.000-0.037", GapsWilson.format(0, 100));
        equal("0.970", GapsWilson.rate(97, 100));
    }

    static void testWilsonRefusesImpossibleCounts() {
        for (int[] bad : new int[][] {{1, 0}, {-1, 10}, {11, 10}}) {
            try {
                GapsWilson.interval(bad[0], bad[1]);
                throw new AssertionError("accepted " + bad[0] + " of " + bad[1]);
            } catch (IllegalArgumentException expected) {
                // as it should
            }
        }
    }

    static void testCsvQuotesWhatItMust() {
        List<String> fields = List.of("plain", "a, b", "say \"no\"", "");
        String line = GapsCsv.format(fields);
        equal("plain,\"a, b\",\"say \"\"no\"\"\",", line);
        equal(fields, GapsCsv.parse(line));
    }

    private static Path run(String behaviour, Map<String, String> files) throws Exception {
        Path dir = Files.createTempDirectory("gaps-run");
        Files.writeString(dir.resolve("run.txt"), "behaviour " + behaviour + "\nandroid 15\napi 35\ndate 2026-11-14T10:00:00Z\n"
                + "probe_commit 0123456789ab\ntrials 100\nrun runs/test\ncapture_sha256 " + "ab".repeat(32) + "\n");
        Files.writeString(dir.resolve("image.txt"), "image system-images;android-35;google_apis;x86_64\nimage_revision 9\n"
                + "archive_sha1 0103e6dab21290c4b9d16550a3ce99476f884eef\nimage_files_sha256 " + "cd".repeat(32) + "\n"
                + "fingerprint google/sdk_gphone64_x86_64/emu64xa:15/AE3A/1:userdebug/dev-keys\nsecurity_patch 2024-09-05\n"
                + "play_update 2024-07\nresolver com.google.android.resolv@350820300\nemulator 37.2.13.0\n");
        for (Map.Entry<String, String> file : files.entrySet()) Files.writeString(dir.resolve(file.getKey()), file.getValue());
        return dir;
    }

    private static Map<String, String> column(List<String> row) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (int i = 0; i < row.size(); i++) out.put(GapsCsv.COLUMNS.get(i), row.get(i));
        return out;
    }

    static void testProcNetRowFromRawOutput() throws Exception {
        StringBuilder log = new StringBuilder();
        for (String f : List.of("tcp", "tcp6", "udp", "udp6", "unix", "route")) {
            log.append("proc-net once file=").append(f).append(" answer=refused error=/proc/net/").append(f)
                    .append(":_open_failed:_EACCES_(Permission_denied)\n");
        }
        log.append("proc-net once done\n");
        // The same step run twice, as when Android creates the activity again, gives the same row.
        log.append(log);
        List<List<String>> rows = GapsRows.rows(run("proc-net", Map.of("probe.log", log.toString())));
        equal(1, rows.size());
        Map<String, String> row = column(rows.get(0));
        equal(GapsCsv.COLUMNS.size(), rows.get(0).size());
        equal("held", row.get("result"));
        equal("/proc/net/ tcp, tcp6, udp, udp6, unix, route: refused (EACCES)", row.get("measured"));
        equal("2026-11-14", row.get("date"));
        equal("not yet", row.get("replicated"));
        equal("-", row.get("ci95"));
        equal("2024-07", row.get("play_update"));
    }

    static void testProcNetRowNotHeldWhenAFileOpens() throws Exception {
        String log = "proc-net once file=tcp answer=read lines=7\n"
                + String.join("", Collections.nCopies(1, "")) + "proc-net once file=tcp6 answer=refused error=EACCES\n"
                + "proc-net once file=udp answer=refused error=EACCES\nproc-net once file=udp6 answer=refused error=EACCES\n"
                + "proc-net once file=unix answer=refused error=EACCES\nproc-net once file=route answer=refused error=EACCES\n";
        Map<String, String> row = column(GapsRows.rows(run("proc-net", Map.of("probe.log", log))).get(0));
        equal("not held", row.get("result"));
        check(row.get("measured").contains("tcp: read (7 lines)"), row.get("measured"));
    }

    static void testShortLivedRowCountsFlowsWithoutOwner() throws Exception {
        StringBuilder log = new StringBuilder();
        StringBuilder closed = new StringBuilder();
        StringBuilder open = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            log.append("short-lived udp-closed trial=").append(i).append(" local=").append(40000 + i).append('\n');
            log.append("short-lived udp-open trial=").append(i).append(" local=").append(50000 + i).append('\n');
            // 90 closed sockets lost their owner, 8 kept it, 2 never reached Watch.
            if (i < 98) closed.append("udp 10.1.10.1:").append(40000 + i).append(" 10.0.2.2:8796 ").append(i < 90 ? "-" : "10210").append(" opened - - - - -\n");
            // One kept-open trial whose flow the run did not read: missing, which is not a flow without owner.
            if (i != 7) open.append("udp 10.1.10.1:").append(50000 + i).append(" 10.0.2.2:8796 10210 opened - - - - -\n");
        }
        // Another app's flow from the same port number to another destination is not the trial's.
        closed.append("udp 10.1.10.1:40095 10.1.10.3:53 10150 opened - - - - -\n");
        List<List<String>> rows = GapsRows.rows(run("short-lived", Map.of("probe.log", log.toString(),
                "flows-udp-closed.txt", closed.toString(), "flows-udp-open.txt", open.toString())));
        Map<String, String> udp = column(rows.get(0));
        equal("udp", udp.get("part"));
        equal("held", udp.get("result"));
        equal("100", udp.get("trials"));
        equal("90", udp.get("events"));
        equal("0.900", udp.get("rate"));
        equal(GapsWilson.format(90, 100), udp.get("ci95"));
        check(udp.get("measured").startsWith("UDP sockets closed at once: 90 of 98 flows with no owner, 2 trials without a flow; "
                + "kept open (control): 0 of 99 with no owner, 1 without a flow"), udp.get("measured"));
        Map<String, String> tcp = column(rows.get(1));
        equal("tcp", tcp.get("part"));
        equal("in part", tcp.get("result"));
    }

    static void testLoopbackRowNotHeldWhenWatchSawIt() throws Exception {
        String log = "loopback listen ready\nloopback listen v4 accepted=yes ask=match\nloopback connect v4 answer=match\n"
                + "loopback listen v6 accepted=yes ask=match\nloopback connect v6 answer=match\n"
                + "fixture socket v4 answer=refused error=SocketException:socket_failed:_EPERM_(Operation_not_permitted)\n";
        String before = "tcp 10.1.10.1:1000 10.0.2.2:8792 10095 opened - - - - -\n";
        Map<String, String> clean = column(GapsRows.rows(run("loopback", Map.of("probe.log", log, "flows-before.txt", before,
                "flows-after.txt", before, "capture.txt", "packets 10\npattern gaps-loopback 0\n"))).get(0));
        equal("held", clean.get("result"));
        check(clean.get("measured").contains("SocketException:socket failed: EPERM (Operation not permitted)"), clean.get("measured"));
        Map<String, String> seen = column(GapsRows.rows(run("loopback", Map.of("probe.log", log, "flows-before.txt", before,
                "flows-after.txt", before + "tcp 10.1.10.1:2000 127.0.0.1:8794 10210 opened - - - - -\n",
                "capture.txt", "pattern gaps-loopback 0\n"))).get(0));
        equal("not held", seen.get("result"));
        check(seen.get("measured").contains("Watch's flows to loopback: 1"), seen.get("measured"));
    }

    static void testVpnSeenRowReadsEachPhase() throws Exception {
        String log = "vpn-seen none active transports=wifi not_vpn=true iface=wlan0 addresses=10.0.2.16/24 routes=5 dns=10.0.2.3\n"
                + "vpn-seen inside active transports=vpn,wifi not_vpn=false iface=tun0 addresses=10.1.10.1/32 routes=4 dns=10.1.10.3\n"
                + "vpn-seen inside network transports=vpn,wifi not_vpn=false iface=tun0 addresses=10.1.10.1/32 routes=4 dns=10.1.10.3\n"
                + "vpn-seen inside interface name=tun0 up=true addresses=fe80::1%tun0/64,10.1.10.1/32\n"
                + "vpn-seen left-out active transports=wifi not_vpn=true iface=wlan0 addresses=10.0.2.16/24 routes=5 dns=10.0.2.3\n"
                + "vpn-seen left-out network transports=vpn,wifi not_vpn=false iface=tun0 addresses=10.1.10.1/32 routes=4 dns=10.1.10.3\n"
                + "vpn-seen left-out interface name=tun0 up=true addresses=fe80::1%tun0/64,10.1.10.1/32\n";
        Map<String, String> row = column(GapsRows.rows(run("vpn-seen", Map.of("probe.log", log))).get(0));
        equal("held", row.get("result"));
        equal("inside the tunnel: own network a VPN, a VPN in getAllNetworks, interface tun0 10.1.10.1/32; "
                + "left out: own network not a VPN (wifi), a VPN in getAllNetworks, interface tun0 10.1.10.1/32; "
                + "no VPN: own network not a VPN (wifi), no VPN in getAllNetworks, no tun interface", row.get("measured"));
    }

    private static List<String> sample(String behaviour, String part, String api, String measured) {
        List<String> row = new ArrayList<>(Collections.nCopies(GapsCsv.COLUMNS.size(), "-"));
        String[][] values = {{"behaviour", behaviour}, {"part", part}, {"android", api.equals("30") ? "11" : "15"}, {"api", api},
                {"image", "system-images;android-" + api + ";google_apis;x86_64"}, {"image_revision", "9"},
                {"fingerprint", "google/sdk/emu:" + api}, {"result", "held"}, {"measured", measured},
                {"source", "Android 10 privacy changes"}, {"source_read", "2026-11-14"}, {"watch", "Not seen"},
                {"date", "2026-11-14"}, {"run", "runs/r1"}, {"replicated", "not yet"}};
        for (String[] v : values) row.set(GapsCsv.COLUMNS.indexOf(v[0]), v[1]);
        return row;
    }

    static void testTableFormat() {
        List<List<String>> rows = List.of(sample("proc-net", "-", "35", "a | b"));
        String table = GapsTable.results(rows);
        String[] lines = table.split("\n");
        equal(3, lines.length);
        equal("| `proc-net` | - | 15 | held | a \\| b | - | Android 10 privacy changes (2026-11-14) | Not seen | [2026-11-14](runs/r1) |", lines[2]);
        String images = GapsTable.images(List.of(sample("proc-net", "-", "35", "x"), sample("loopback", "-", "35", "y"),
                sample("proc-net", "-", "30", "z")));
        String[] imageLines = images.split("\n");
        equal(4, imageLines.length);
        check(imageLines[2].startsWith("| 11 (API 30) | `system-images;android-30;google_apis;x86_64` r9 |"), imageLines[2]);
    }

    static void testCheckFindsAHandEdit() {
        String readme = "# Gaps\n\n" + GapsTable.RESULTS_START + "\nold\n" + GapsTable.RESULTS_END + "\n\n" + GapsTable.IMAGES_START
                + "\n" + GapsTable.IMAGES_END + "\n";
        List<List<String>> rows = List.of(sample("proc-net", "-", "35", "m"));
        String written = GapsTable.write(readme, rows);
        equal(written, GapsTable.write(written, rows));
        String edited = written.replace("| held |", "| not held |");
        check(!edited.equals(written), "the edit changed nothing");
        check(!GapsTable.write(edited, rows).equals(edited), "a hand edit of the table went unnoticed");
    }

    static void testAddReplacesTheSameRowAndSorts() throws Exception {
        Path csv = Files.createTempFile("results", ".csv");
        Files.writeString(csv, String.join(",", GapsCsv.COLUMNS) + "\n", StandardCharsets.UTF_8);
        GapsRows.add(List.of(sample("proc-net", "-", "35", "first"), sample("vpn-seen", "-", "35", "v")), csv);
        GapsRows.add(List.of(sample("proc-net", "-", "35", "second"), sample("proc-net", "-", "30", "older")), csv);
        List<List<String>> rows = GapsRows.read(csv);
        equal(3, rows.size());
        int measured = GapsCsv.COLUMNS.indexOf("measured");
        equal("v", rows.get(0).get(measured));
        equal("older", rows.get(1).get(measured));
        equal("second", rows.get(2).get(measured));
    }

    static void testCarriedBySystemRowsOnlyForThePartsRun() throws Exception {
        Path dir = run("carried-by-system", Map.of(
                "probe.log", "carried-by-system download answer=done bytes=4096 reason=0\ncarried-by-system tab handler=com.android.chrome\n",
                "flows-download-before.txt", "",
                "flows-download-after.txt", "tcp 10.1.10.1:1000 10.0.2.2:8792 10095 opened - - - - -\n",
                "observed.txt", "tab-screen com.android.chrome/org.chromium.chrome.browser.firstrun.FirstRunActivity\n",
                "uids.txt", "package:com.android.providers.downloads uid:10095\npackage:org.visadahyu.lab.gapsprobe uid:10210\n"));
        Files.writeString(dir.resolve("run.txt"), Files.readString(dir.resolve("run.txt")) + "parts download,tab,push\n");
        List<List<String>> rows = GapsRows.rows(dir);
        equal(3, rows.size());
        Map<String, String> download = column(rows.get(0));
        equal("download", download.get("part"));
        equal("held", download.get("result"));
        check(download.get("measured").contains("1 under UID 10095 (com.android.providers.downloads)"), download.get("measured"));
        equal("not run", column(rows.get(1)).get("result"));
        equal("push", column(rows.get(2)).get("part"));
    }

    static void testResolverRowsCountTheProbesLookups() throws Exception {
        StringBuilder log = new StringBuilder();
        StringBuilder capture = new StringBuilder("packets 1000\npattern gaps.example 400\n");
        for (int i = 0; i < 100; i++) {
            log.append("carried-by-system resolve-off trial=").append(i).append(" name=t").append(i).append("-a.gaps.example answer=none\n");
            log.append("carried-by-system resolve-opportunistic trial=").append(i).append(" name=t").append(i).append("-b.gaps.example answer=none\n");
            log.append("carried-by-system resolve-hostname trial=").append(i).append(" name=t").append(i).append("-c.gaps.example answer=none\n");
            capture.append("query t").append(i).append("-a.gaps.example\n");
            if (i < 98) capture.append("query t").append(i).append("-b.gaps.example\n");
        }
        // Off: 200 flows under the probe and 68 of other apps, which do not count. Automatic: both the probe and
        // the resolver's own UID, so the split is not known. Strict: two DNS over TLS flows of the system.
        StringBuilder off = new StringBuilder();
        for (int i = 0; i < 200; i++) off.append("udp 10.1.10.1:").append(30000 + i).append(" 10.1.10.3:53 10210 opened - - - - -\n");
        for (int i = 0; i < 68; i++) off.append("udp 10.1.10.1:").append(40000 + i).append(" 10.1.10.3:53 10156 opened - - - - -\n");
        StringBuilder automatic = new StringBuilder();
        for (int i = 0; i < 100; i++) automatic.append("udp 10.1.10.1:").append(50000 + i).append(" 10.1.10.3:53 10210 opened - - - - -\n");
        automatic.append("udp 10.1.10.1:60000 10.1.10.3:53 1051 opened - - - - -\n");
        String strict = "tcp - other:853 1051 - - - - - -\ntcp - other:853 1051 - - - - - -\n";
        Path dir = run("carried-by-system", Map.of("probe.log", log.toString(), "capture.txt", capture.toString(),
                "flows-resolve-off.txt", off.toString(), "flows-resolve-opportunistic.txt", automatic.toString(),
                "flows-resolve-hostname.txt", strict, "uids.txt", "package:org.visadahyu.lab.gapsprobe uid:10210\n"));
        Files.writeString(dir.resolve("run.txt"), Files.readString(dir.resolve("run.txt")) + "parts resolver\n");
        List<List<String>> rows = GapsRows.rows(dir);
        equal(3, rows.size());
        Map<String, String> plain = column(rows.get(0));
        equal("resolver-off", plain.get("part"));
        equal("measured", plain.get("result"));
        equal("100", plain.get("trials"));
        equal("100", plain.get("events"));
        equal("1.000", plain.get("rate"));
        check(plain.get("measured").contains("their names in the capture: 100; the window's DNS flows: 200 under the probe's UID, none under a UID of the system, 0 without owner, and 68 of other apps, not counted"), plain.get("measured"));
        Map<String, String> mixed = column(rows.get(1));
        equal("100", mixed.get("trials"));
        equal("-", mixed.get("events"));
        equal("-", mixed.get("ci95"));
        check(mixed.get("measured").endsWith("so no rate"), mixed.get("measured"));
        Map<String, String> hostname = column(rows.get(2));
        equal("resolver-hostname", hostname.get("part"));
        equal("held", hostname.get("result"));
        equal("100", hostname.get("trials"));
        equal("0", hostname.get("events"));
        equal("0.000-0.037", hostname.get("ci95"));
        equal("2026-11-14", hostname.get("source_read"));
    }
}
