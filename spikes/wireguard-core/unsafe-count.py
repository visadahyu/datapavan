"""Counts the `unsafe` sites in crates' Rust sources, per crate (W7's spike, ADR 0035, item 5).

    cargo tree --locked -p wg-size --features ring -e normal --target aarch64-linux-android --prefix none \\
        | python3 -I spikes/wireguard-core/unsafe-count.py [--except crates-of-today.txt]

Reads "name vX.Y.Z" lines (cargo tree's) on standard input, finds each crate in the cargo registry's
sources, and counts in its .rs files, outside tests/, benches/ and examples/: unsafe blocks, unsafe
functions, unsafe impls and traits, unsafe extern blocks and unsafe attributes (`#[unsafe(no_mangle)]`),
after removing comments and string literals. Code under `#[cfg(test)]` inside src/ is counted too, and so is
code behind features this build does not enable: a site is a place to review, not proof that it runs.
Crates that forbid unsafe code at their root say so. For crates with C or assembly it gives their files and
lines as well. Crates named in the --except file ("name vX.Y.Z" lines) are left out: those already in the network part.
"""

import os
import re
import sys

REGISTRY = os.path.join(os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")), "registry", "src")
KINDS = [
    ("block", re.compile(r"\bunsafe\s*\{")),
    ("fn", re.compile(r"\bunsafe\s+(?:extern\s*(?:\"\"\s*)?)?fn\b")),
    ("impl", re.compile(r"\bunsafe\s+impl\b")),
    ("trait", re.compile(r"\bunsafe\s+trait\b")),
    ("extern", re.compile(r"\bunsafe\s+extern\s*(?:\"\"\s*)?\{")),
    ("attribute", re.compile(r"\bunsafe\s*\(")),
]
RAW = re.compile(r'b?r(#*)"')
CHAR = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'")


def strip(src):
    """The source without comments, string literals and character literals."""
    out = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        prev = src[i - 1] if i else " "
        raw = RAW.match(src, i)
        if raw and not (prev.isalnum() or prev == "_"):
            end = src.find('"' + raw.group(1), raw.end())
            i = n if end < 0 else end + 1 + len(raw.group(1))
            out.append('""')
            continue
        if src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            out.append('""')
            continue
        if src[i] == "'":
            char = CHAR.match(src, i)
            if char:
                i = char.end()
                continue
        out.append(src[i])
        i += 1
    return "".join(out)


def count(crate_dir):
    counts = {kind: 0 for kind, _ in KINDS}
    files = {}
    native = [0, 0]
    for root, dirs, names in os.walk(crate_dir):
        rel = os.path.relpath(root, crate_dir)
        if rel.split(os.sep)[0] in ("tests", "benches", "examples", "target"):
            dirs[:] = []
            continue
        for name in names:
            path = os.path.join(root, name)
            if name.endswith((".c", ".h", ".S", ".s", ".asm", ".cc", ".inl")):
                native[0] += 1
                with open(path, "rb") as f:
                    native[1] += f.read().count(b"\n")
            if not name.endswith(".rs"):
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = strip(f.read())
            here = sum(len(pattern.findall(text)) for _, pattern in KINDS)
            for kind, pattern in KINDS:
                counts[kind] += len(pattern.findall(text))
            if here:
                files[os.path.relpath(path, crate_dir)] = here
    forbids = False
    for root_file in ("src/lib.rs", "src/main.rs"):
        path = os.path.join(crate_dir, root_file)
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                forbids = forbids or bool(re.search(r"#!\[\s*forbid\s*\([^)]*unsafe_code", strip(f.read())))
    return counts, files, native, forbids


def main():
    args = sys.argv[1:]
    skip = set()
    if args[:1] == ["--except"]:
        with open(args[1]) as f:
            skip = {tuple(line.split()[:2]) for line in f if line.strip()}
    crates, macros = [], set()
    for line in sys.stdin:
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            crates.append((parts[0], parts[1]))
            if "(proc-macro)" in line:
                macros.add((parts[0], parts[1]))
    crates = sorted(set(crates) - skip)
    index = [d for d in os.listdir(REGISTRY)]
    total = 0
    print("crate\tversion\tsites\tblock\tfn\timpl\ttrait\textern\tattribute\tforbids\tC/asm files\tC/asm lines\tfiles with most")
    for name, version in crates:
        crate_dir = next((os.path.join(REGISTRY, i, f"{name}-{version[1:]}") for i in index
                          if os.path.isdir(os.path.join(REGISTRY, i, f"{name}-{version[1:]}"))), None)
        if crate_dir is None:
            print(f"{name}\t{version}\t(not in the registry: a path crate)")
            continue
        counts, files, native, forbids = count(crate_dir)
        sites = sum(counts.values())
        total += sites
        top = ", ".join(f"{k} {v}" for k, v in sorted(files.items(), key=lambda kv: -kv[1])[:3])
        if (name, version) in macros:
            name += " (proc-macro: runs in the build only)"
        print("\t".join([name, version, str(sites)] + [str(counts[k]) for k, _ in KINDS]
                        + ["yes" if forbids else "", str(native[0]), str(native[1]), top]))
    print(f"total\t\t{total}")


main()
