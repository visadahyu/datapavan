# SPDX-License-Identifier: Apache-2.0
"""Refreshes the tracker signatures from the εxodus tracker database.

Run from anywhere with `python3 -I data/exodus/update.py`; it writes trackers.tsv and SOURCE next to
itself. It fails when the εxodus README no longer states the database licence, so that a licence
change is read by a person before the data changes (ADR 0015, decision 9), and when a code
signature uses more than the matcher in core/engine/src/trackers.rs understands: alternatives
separated by `|`, `.` for any one character, and literal letters, digits, `_` and `-`.
"""
import datetime
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

API_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
README_URL = "https://raw.githubusercontent.com/Exodus-Privacy/exodus/v1/README.md"
LICENCE_STATEMENT = (
    "The εxodus database and API results are made available under the Open Database License: "
    "http://opendatacommons.org/licenses/odbl/1.0/. Any rights in individual contents of the database "
    "are licensed under the Database Contents License: http://opendatacommons.org/licenses/dbcl/1.0/."
)
CODE_SIGNATURE = re.compile(r"[A-Za-z0-9_.-]+(\|[A-Za-z0-9_.-]+)*")
HERE = pathlib.Path(__file__).resolve().parent
COLUMNS = ["id", "name", "categories", "website", "code_signature", "network_signature"]


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def field(value: str) -> str:
    if any(c in value for c in "\t\r\n"):
        sys.exit(f"a field contains a tab or a line break: {value!r}")
    return value


def main() -> None:
    readme = fetch(README_URL).decode("utf-8")
    if LICENCE_STATEMENT not in readme:
        sys.exit("the εxodus README no longer states the database licence; read it and update data/exodus/LICENSE")
    api = fetch(API_URL)
    trackers = json.loads(api)["trackers"]

    rows = []
    for key, tracker in trackers.items():
        if int(key) != tracker["id"]:
            sys.exit(f"tracker key {key} does not match its id {tracker['id']}")
        signature = tracker["code_signature"]
        if signature and not CODE_SIGNATURE.fullmatch(signature):
            sys.exit(f"tracker {tracker['id']} uses a code signature the matcher does not support: {signature}")
        rows.append([
            str(tracker["id"]),
            field(tracker["name"]),
            field(",".join(sorted(tracker["categories"]))),
            field(tracker["website"]),
            field(signature),
            field(tracker["network_signature"]),
        ])
    rows.sort(key=lambda row: int(row[0]))

    (HERE / "trackers.tsv").write_text(
        "# SPDX-License-Identifier: ODbL-1.0\n"
        "# Contains information from the εxodus tracker database (https://reports.exodus-privacy.eu.org),\n"
        "# which is made available here under the Open Database License (ODbL). Converted by update.py.\n"
        "# " + "\t".join(COLUMNS) + "\n"
        + "".join("\t".join(row) + "\n" for row in rows)
    )
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (HERE / "SOURCE").write_text(
        "# SPDX-License-Identifier: CC0-1.0\n"
        f"retrieved: {now}\n"
        f"api: {API_URL}\n"
        f"api-sha256: {hashlib.sha256(api).hexdigest()}\n"
        f"licence-statement: {README_URL}\n"
        f"licence-statement-sha256: {hashlib.sha256(LICENCE_STATEMENT.encode()).hexdigest()}\n"
        f"trackers: {len(rows)}\n"
        f"with-code-signature: {sum(1 for row in rows if row[4])}\n"
    )
    print(f"{len(rows)} trackers, {sum(1 for row in rows if row[4])} with a code signature")


if __name__ == "__main__":
    main()
