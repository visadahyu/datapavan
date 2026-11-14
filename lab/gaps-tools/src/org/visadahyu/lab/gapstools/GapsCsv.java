package org.visadahyu.lab.gapstools;

import java.util.ArrayList;
import java.util.List;

/** The CSV of docs/platform-gaps/results.csv: RFC 4180, one row per line, a field quoted when it must be. */
final class GapsCsv {
    /** The columns, in order; docs/platform-gaps/README.md defines each. */
    static final List<String> COLUMNS = List.of(
            "behaviour", "part", "android", "api", "image", "image_revision", "archive_sha1", "image_files_sha256",
            "fingerprint", "security_patch", "play_update", "resolver", "emulator", "result", "measured", "trials",
            "events", "rate", "ci95", "source", "source_read", "watch", "probe_commit", "date", "run",
            "capture_sha256", "replicated");

    private GapsCsv() {}

    static List<String> parse(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else if (c == '"') {
                    quoted = false;
                } else {
                    field.append(c);
                }
            } else if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                fields.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        if (quoted) throw new IllegalArgumentException("an unclosed quote: " + line);
        fields.add(field.toString());
        return fields;
    }

    static String format(List<String> fields) {
        StringBuilder line = new StringBuilder();
        for (String field : fields) {
            if (line.length() > 0) line.append(',');
            if (field.contains("\n")) throw new IllegalArgumentException("a field holds a line break: " + field);
            if (field.contains(",") || field.contains("\"")) {
                line.append('"').append(field.replace("\"", "\"\"")).append('"');
            } else {
                line.append(field);
            }
        }
        return line.toString();
    }
}
