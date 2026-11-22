"""The licences of the crates inside the native libraries the APKs ship (W7's fix round, review M4), written into
licences/ as one file per library, for the APK to carry beside NOTICE (android/app/build.gradle.kts) and for
scripts/check.sh to hold current.

For each library (libdatapavan.so from core/jni, libdatapavan_network.so from core/network-jni), the crates its code is
built from on the shipped Android targets: normal dependencies, not build or development ones, and not procedural
macros, whose code runs in the compiler and is not shipped. For each crate: its name, version and licence
expression, then its own licence texts, as its package on crates.io carries them (LICENSE*, LICENCE*, COPYING*,
NOTICE*, COPYRIGHT*), each text written once with every crate that carries it. A crate whose package carries no
text names the texts this repository keeps for it (VENDORED), or, where Apache-2.0 is among its licences, is
taken under Apache-2.0, whose text is the repository's LICENSE; any other crate without one fails the run, so that
no library ships a crate whose notice nobody wrote down.

    python3 -I scripts/licences.py           writes licences/native-*.txt
    python3 -I scripts/licences.py --check   fails if they are not what the lock file gives

Reads the crates from cargo's registry, where `cargo fetch --locked` (or any build) put them; downloads nothing.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.path.join(ROOT, "core")
OUT = os.path.join(ROOT, "licences")
TARGETS = ["aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android"]
LIBRARIES = {
    "native-core.txt": ("datapavan-jni", "libdatapavan.so, in every edition"),
    "native-network.txt": ("datapavan-network-jni", "libdatapavan_network.so, the network part's engine, in Datapavan Advanced"),
}
# Packages that carry no licence text of their own, and the texts this repository keeps for them.
VENDORED = {
    "gotatun": ["licences/MPL-2.0.txt", "licences/gotatun-BSD-3-Clause.txt"],
}
TEXT_FILE = re.compile(r"^(licen[cs]e|copying|notice|copyright)([-_.].*)?$", re.IGNORECASE)


def metadata(target):
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", target],
        cwd=CORE, check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def shipped(root_name):
    """The packages of root_name's library on any shipped target: (name, version) -> package."""
    found = {}
    for target in TARGETS:
        data = metadata(target)
        packages = {p["id"]: p for p in data["packages"]}
        nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
        root = next(p["id"] for p in data["packages"] if p["name"] == root_name and p["source"] is None)
        stack, seen = [root], set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for dep in nodes[current]["deps"]:
                if any(k["kind"] is None for k in dep["dep_kinds"]):
                    stack.append(dep["pkg"])
        for package_id in seen:
            package = packages[package_id]
            if package["source"] is None:
                continue
            if any("proc-macro" in t["kind"] for t in package["targets"]):
                continue
            found[(package["name"], package["version"])] = package
    return found


def texts_of(package):
    folder = os.path.dirname(package["manifest_path"])
    names = sorted(n for n in os.listdir(folder) if TEXT_FILE.match(n) and os.path.isfile(os.path.join(folder, n)))
    texts = []
    for name in names:
        with open(os.path.join(folder, name), encoding="utf-8", errors="replace") as f:
            texts.append((name, f.read().replace("\r\n", "\n").strip() + "\n"))
    return texts


def render(file_name):
    root_name, what = LIBRARIES[file_name]
    packages = shipped(root_name)
    lines = [
        f"The crates inside {what}, built from core/{'jni' if root_name == 'datapavan-jni' else 'network-jni'}",
        "(Datapavan's own crates are under Apache-2.0: LICENSE). Each crate's name, version and licence, then",
        "the licence texts its package carries, each text once with the crates that carry it.",
        "Written by scripts/licences.py from core/Cargo.lock; do not edit by hand.",
        "",
    ]
    by_text, missing = {}, []
    for key in sorted(packages):
        package = packages[key]
        name, version = key
        texts = texts_of(package)
        line = f"- {name} {version}: {package.get('license') or package.get('license_file') or 'no licence named'}"
        if texts:
            for file, text in texts:
                digest = hashlib.sha256(text.encode()).hexdigest()
                by_text.setdefault(digest, (text, []))[1].append(f"{name} {version} ({file})")
        elif name in VENDORED:
            line += "; its package carries no licence text: " + ", ".join(VENDORED[name])
        elif re.search(r"\bApache-2\.0\b", package.get("license") or ""):
            # Taken under Apache-2.0, whose text is the repository's own LICENSE, which the APK carries too.
            line += "; its package carries no licence text: taken under Apache-2.0, whose text is LICENSE"
        else:
            missing.append(f"{name} {version}")
        lines.append(line)
    if missing:
        sys.exit("crates whose package carries no licence text, and none is kept here: " + ", ".join(missing))
    for text, carriers in sorted(by_text.values(), key=lambda entry: entry[1][0]):
        lines += ["", "=" * 78, "Carried by: " + "; ".join(carriers), "=" * 78, "", text.rstrip("\n")]
    return "\n".join(lines) + "\n"


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for path in VENDORED.values():
        for vendored in path:
            if not os.path.isfile(os.path.join(ROOT, vendored)):
                sys.exit(f"{vendored} is missing")
    for file_name in LIBRARIES:
        text = render(file_name)
        path = os.path.join(OUT, file_name)
        if check:
            try:
                with open(path, encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(file_name)
            except FileNotFoundError:
                stale.append(file_name)
        else:
            os.makedirs(OUT, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
    if stale:
        sys.exit("licences/ is not what core/Cargo.lock gives: run python3 -I scripts/licences.py (" + ", ".join(stale) + ")")
    print("licences/: " + ", ".join(LIBRARIES) + (" current" if check else " written"))


main()
