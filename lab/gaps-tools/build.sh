#!/usr/bin/env bash
# Builds the lab's gaps tools (ADR 0048) with javac alone, into build/gaps-tools/classes, and runs their unit
# tests on the JVM: turning a run's raw output into rows, Wilson's interval, and the README's tables.
#
#   lab/gaps-tools/build.sh
#
# Then, from the repository's root:
#   java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsRows row RUN_DIR
#   java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsRows add RUN_DIR docs/platform-gaps/results.csv
#   java -cp build/gaps-tools/classes org.visadahyu.lab.gapstools.GapsTable write|check docs/platform-gaps/results.csv docs/platform-gaps/README.md
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/build/gaps-tools"

rm -rf "$OUT" && mkdir -p "$OUT/classes"
javac --release 17 -XDsuppressNotes -d "$OUT/classes" $(find "$HERE/src" "$HERE/test" -name '*.java')
java -cp "$OUT/classes" org.visadahyu.lab.gapstools.GapsToolsTest
