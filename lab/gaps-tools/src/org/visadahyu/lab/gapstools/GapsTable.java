package org.visadahyu.lab.gapstools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes the tables of docs/platform-gaps/README.md from results.csv, never by hand (ADR 0048, decision 2).
 *
 *   GapsTable write RESULTS README   rewrites the tables between their markers
 *   GapsTable check RESULTS README   fails if the README's tables are not what RESULTS gives
 */
public final class GapsTable {
    static final String RESULTS_START = "<!-- results: written from results.csv by lab/gaps-tools; do not edit -->";
    static final String RESULTS_END = "<!-- results end -->";
    static final String IMAGES_START = "<!-- images: written from results.csv by lab/gaps-tools; do not edit -->";
    static final String IMAGES_END = "<!-- images end -->";

    private GapsTable() {}

    public static void main(String[] args) throws IOException {
        if (args.length != 3 || !(args[0].equals("write") || args[0].equals("check"))) {
            System.err.println("usage: GapsTable write|check RESULTS_CSV README");
            System.exit(2);
        }
        Path csv = Path.of(args[1]);
        Path readme = Path.of(args[2]);
        String text = Files.readString(readme, StandardCharsets.UTF_8);
        String written = write(text, GapsRows.read(csv));
        if (args[0].equals("write")) {
            Files.writeString(readme, written, StandardCharsets.UTF_8);
        } else if (!written.equals(text)) {
            System.err.println(readme + ": its tables are not what " + csv + " gives; run lab/gaps-tools/build.sh and "
                    + "java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsTable write " + csv + " " + readme);
            System.exit(1);
        }
    }

    /** The README with both tables written from the rows. */
    static String write(String readme, List<List<String>> rows) {
        return between(between(readme, RESULTS_START, RESULTS_END, results(rows)), IMAGES_START, IMAGES_END, images(rows));
    }

    private static String between(String text, String start, String end, String table) {
        int from = text.indexOf(start);
        int to = text.indexOf(end);
        if (from < 0 || to < from) throw new IllegalArgumentException("the markers are missing: " + start + " ... " + end);
        return text.substring(0, from + start.length()) + "\n" + table + text.substring(to);
    }

    static String results(List<List<String>> rows) {
        StringBuilder out = new StringBuilder();
        out.append("| Behaviour | Part | Android | Result | Measured | Trials: events, rate (95 % interval) | Source (read) | What Watch does | Run |\n");
        out.append("|---|---|---|---|---|---|---|---|---|\n");
        for (List<String> row : rows) {
            Map<String, String> r = named(row);
            String timing = r.get("events").equals("-") ? "-" : r.get("trials") + ": " + r.get("events") + ", " + r.get("rate") + " (" + r.get("ci95") + ")";
            String run = r.get("run").equals("-") ? "-" : "[" + r.get("date") + "](" + r.get("run") + ")";
            out.append(line(List.of("`" + r.get("behaviour") + "`", r.get("part"), r.get("android"), r.get("result"), r.get("measured"), timing,
                    r.get("source") + " (" + r.get("source_read") + ")", r.get("watch"), run)));
        }
        return out.toString();
    }

    static String images(List<List<String>> rows) {
        Map<String, Map<String, String>> byImage = new LinkedHashMap<>();
        List<List<String>> sorted = new ArrayList<>(rows);
        sorted.sort((a, b) -> Double.compare(api(a), api(b)));
        for (List<String> row : sorted) {
            Map<String, String> r = named(row);
            byImage.putIfAbsent(r.get("api") + "|" + r.get("image_revision") + "|" + r.get("fingerprint"), r);
        }
        StringBuilder out = new StringBuilder();
        out.append("| Android | Image and revision | Archive SHA-1 | Image files' SHA-256 | Fingerprint | Security patch | Google Play system update | Resolver | Emulator |\n");
        out.append("|---|---|---|---|---|---|---|---|---|\n");
        for (Map<String, String> r : byImage.values()) {
            out.append(line(List.of(r.get("android") + " (API " + r.get("api") + ")", "`" + r.get("image") + "` r" + r.get("image_revision"),
                    code(r.get("archive_sha1")), code(r.get("image_files_sha256")), code(r.get("fingerprint")), r.get("security_patch"),
                    r.get("play_update"), code(r.get("resolver")), r.get("emulator"))));
        }
        return out.toString();
    }

    private static double api(List<String> row) {
        String api = row.get(GapsCsv.COLUMNS.indexOf("api"));
        return api.matches("[0-9.]+") ? Double.parseDouble(api) : 0;
    }

    private static String code(String value) {
        return value.equals("-") ? "-" : "`" + value + "`";
    }

    private static Map<String, String> named(List<String> row) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < GapsCsv.COLUMNS.size(); i++) out.put(GapsCsv.COLUMNS.get(i), row.get(i));
        return out;
    }

    /** One table line; a pipe inside a cell is escaped, so that it does not end the cell. */
    static String line(List<String> cells) {
        StringBuilder out = new StringBuilder("|");
        for (String cell : cells) out.append(' ').append(cell.replace("|", "\\|")).append(" |");
        return out.append('\n').toString();
    }
}
