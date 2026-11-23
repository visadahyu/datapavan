#!/usr/bin/env python3
"""The per-tool guides for proxy mode (W8, part 3b; ADR 0041, "How the per-tool guides are built").

Checks data/tools/guides.tsv, guide-steps.tsv and guide-labels.tsv against tools.tsv, sources.tsv and the network part's
English strings, and writes the website's pages from the same data and words, so that the site says what the network
part says.

  scripts/guides.py                 the data check (scripts/check.sh data runs it)
  scripts/guides.py --site DIR      the check, then the pages into DIR (scripts/build-site.sh: site/content/guides)
  scripts/guides.py --against DIR   the check, then every label against the line its source names, in clones of the
                                    tools' sources at their commits under DIR (lab work: CI keeps no clones)
  scripts/guides.py --self-test     the check's own test, on broken copies of the data

What it holds the data to:
- every package of tools.tsv with a VPN or proxy mode has one guide, and no other package has one;
- a proxy page's tools have a settled proxy mode (no '?') and the page's listener and auth are tools.tsv's; where
  tools.tsv says the profile sets the listener, the steps set the port the page names;
- each tool's proxy label (tools.tsv) is one of its guide's labels;
- every step's words are a string of the network part's with as many places as the step fills, and every label it names
  exists;
- every step, label, listener and auth has its source: a line of the tool's code at the guide's commit (or a line of
  another repository at a full commit), or tools.tsv's own evidence for the pages without steps; navigation steps alone
  need none; no source is a release, a store listing or a file to install;
- a guide tried on a phone was read at the version tried;
- after the first six (the tool usage matrix's order), the tools with a proxy mode follow tools.tsv's order.
"""
import html
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/tools"
STRINGS = ROOT / "android/network/src/main/res/values/strings.xml"

PAGES = {"proxy", "wireguard", "vpn", "waiting"}
PARTS = ["on", "password", "asks", "back", "note"]
LANGS = {"en", "fa", "ar", "ru", "zh", "fr", "de", "es"}
# The order of the tool usage matrix among the tools with a proxy mode (BRIEF-part-3b, read 2026-11-21); the rest follow
# tools.tsv. No figure of the matrix is public.
MATRIX_FIRST = 6
NAVIGATION = {"guide_step_back_home", "guide_step_back_once"}
LINE = re.compile(r"^https://(github\.com|gitlab\.torproject\.org)/([^/]+)/([^/]+)/(?:-/)?blob/([0-9a-f]{40})/([^#]+)#L(\d+)(?:-L(\d+))?$")
TREE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/tree/[^/]+$")
RESOURCE = re.compile(r"^(string/[A-Za-z0-9_.]+|array/[A-Za-z0-9_.]+/\d+|-)$")
LISTENER = re.compile(r"^(socks5|http|mixed):(127\.0\.0\.1|\[::1\]):(\d{1,5})$")
FORBIDDEN = re.compile(r"/releases|\.apk\b|play\.google|apkpure|apkmirror|f-droid\.org", re.I)
# AmneziaWG's configurations are not WireGuard's protocol (ADR 0035, point 14): never the WireGuard page.
AMNEZIA = "org.amnezia."


def table(path):
    """The rows of a TSV, comments and blank lines skipped."""
    return [line.split("\t") for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]


def strings(path=STRINGS):
    """the network part's English strings by name, Android's escapes undone."""
    out = {}
    for element in ET.parse(path).getroot():
        if element.tag == "string":
            out[element.get("name")] = "".join(element.itertext()).replace("\\'", "'").replace('\\"', '"').replace("\\n", "\n")
    return out


def places(text):
    return sorted({int(n) for n in re.findall(r"%(\d+)\$[sd]", text)})


class Data:
    def __init__(self, guides, steps, labels, tools, sources, words):
        self.tools = {c[0]: c for c in tools}
        self.tool_order = [c[0] for c in tools]
        self.sources = {c[0] for c in sources}
        self.words = words
        self.guides = [dict(zip(["guide", "packages", "page", "version", "source", "commit", "listener", "listener_source", "auth",
                                 "auth_source", "checked", "note"], c)) for c in guides]
        self.steps = [dict(zip(["guide", "part", "string", "labels", "source"], c)) for c in steps]
        self.labels = [dict(zip(["guide", "key", "lang", "text", "resource", "source"], c)) for c in labels]
        self.width = {"guides": [len(c) for c in guides], "steps": [len(c) for c in steps], "labels": [len(c) for c in labels]}

    @staticmethod
    def load(directory=DATA, strings_path=STRINGS):
        return Data(table(directory / "guides.tsv"), table(directory / "guide-steps.tsv"), table(directory / "guide-labels.tsv"),
                    table(directory / "tools.tsv"), table(directory / "sources.tsv"), strings(strings_path))

    def guide(self, name):
        return next(g for g in self.guides if g["guide"] == name)

    def steps_of(self, name, part=None):
        return [s for s in self.steps if s["guide"] == name and (part is None or s["part"] == part)]

    def label(self, name, key, lang="en"):
        return next((label for label in self.labels if label["guide"] == name and label["key"] == key and label["lang"] == lang), None)


def modes(tool):
    return [m.strip() for m in tool[2].split(",")]


def check(data):
    """Every problem with the data, as lines; none when it holds."""
    bad = []
    for kind, widths, want in (("guides.tsv", data.width["guides"], 12), ("guide-steps.tsv", data.width["steps"], 5),
                               ("guide-labels.tsv", data.width["labels"], 6)):
        for n, width in enumerate(widths):
            if width != want:
                bad.append(f"{kind}: row {n + 1} has {width} columns, not {want}")
    if bad:
        return bad
    names = [g["guide"] for g in data.guides]
    for name in {n for n in names if names.count(n) > 1}:
        bad.append(f"guides.tsv: {name} twice")
    covered = {}
    for g in data.guides:
        name = g["guide"]
        if not re.fullmatch(r"[a-z0-9-]+", name):
            bad.append(f"{name}: not a page name")
        if g["page"] not in PAGES:
            bad.append(f"{name}: page {g['page']}")
            continue
        packages = g["packages"].split(",")
        for package in packages:
            if package not in data.tools:
                bad.append(f"{name}: {package} is not in tools.tsv")
            elif package in covered:
                bad.append(f"{name}: {package} is also in {covered[package]}")
            covered[package] = name
        tools = [data.tools[p] for p in packages if p in data.tools]
        bad += check_page(data, g, tools)
    for package, tool in data.tools.items():
        wanted = any(m.rstrip("?") in ("vpn", "proxy") for m in modes(tool))
        if wanted and package not in covered:
            bad.append(f"{package}: has a VPN or proxy mode but no guide")
        if not wanted and package in covered:
            bad.append(f"{package}: neither a VPN nor a proxy, but in {covered[package]}")
    bad += check_steps(data)
    bad += check_labels(data)
    bad += check_order(data)
    return bad


def check_page(data, g, tools):
    bad = []
    name, page = g["guide"], g["page"]
    steps = data.steps_of(name)
    parts = {s["part"] for s in steps}
    settled = all("proxy" in modes(t) and "?" not in t[4] + t[6] for t in tools)
    if page == "proxy":
        if not settled:
            bad.append(f"{name}: a proxy page for a tool whose proxy mode is not settled ('?'): it waits")
        if not re.fullmatch(r"[0-9a-f]{40}", g["commit"]):
            bad.append(f"{name}: commit {g['commit']}")
        if not TREE.match(g["source"]):
            bad.append(f"{name}: source {g['source']} is not a repository at a tag")
        for field in ("listener_source", "auth_source"):
            bad += check_link(data, g, g[field], f"{name}: {field}")
        listeners = g["listener"].split(",")
        if not all(LISTENER.match(x) for x in listeners):
            bad.append(f"{name}: listener {g['listener']}")
        for t in tools:
            if t[4] == "profile":
                ports = {LISTENER.match(x).group(3) for x in listeners if LISTENER.match(x)}
                values = {a[1:] for s in data.steps_of(name, "on") for a in s["labels"].split(",") if a.startswith("=")}
                if not ports or not ports <= values:
                    bad.append(f"{name}: {t[0]}'s profile sets its listener, and no step sets the page's port {sorted(ports)}")
            elif t[4] != g["listener"]:
                bad.append(f"{name}: listener {g['listener']} is not tools.tsv's {t[4]} for {t[0]}")
            if t[6] != g["auth"]:
                bad.append(f"{name}: auth {g['auth']} is not tools.tsv's {t[6]} for {t[0]}")
            label = re.sub(r" \([^)]*\)$", "", t[3])
            if not label.startswith("(") and label not in {x["text"] for x in data.labels if x["guide"] == name and x["lang"] == "en"}:
                bad.append(f"{name}: tools.tsv's proxy label '{t[3]}' for {t[0]} is none of the guide's labels")
        for part in ("on", "asks", "back"):
            if part not in parts:
                bad.append(f"{name}: no {part} step")
        if (g["auth"] == "none") == ("password" in parts):
            bad.append(f"{name}: auth {g['auth']}, and {'a' if 'password' in parts else 'no'} password step")
        if g["checked"] not in ("waiting", g["version"]):
            bad.append(f"{name}: tried at {g['checked']}, read at {g['version']}")
    else:
        if any(v != "-" for v in (g["version"], g["source"], g["commit"], g["listener"], g["auth"])):
            bad.append(f"{name}: a {page} page has no version, source, listener or auth")
        if g["checked"] not in ("-", "waiting"):
            bad.append(f"{name}: checked {g['checked']}")
        if parts - {"note"} or not steps:
            bad.append(f"{name}: a {page} page has notes only, and at least one")
        for t in tools:
            only_vpn = modes(t) == ["vpn"] and "?" not in t[2]
            if page in ("vpn", "wireguard") and not only_vpn:
                bad.append(f"{name}: {t[0]} does not run only as a VPN (modes {t[2]})")
            if page == "wireguard" and ("provider" not in t[11] and "export" not in t[11] or t[0].startswith(AMNEZIA)):
                bad.append(f"{name}: {t[0]}'s WireGuard ({t[11]}) gives no configuration the network part can carry")
            if page == "vpn" and "provider" in t[11]:
                bad.append(f"{name}: {t[0]}'s provider gives WireGuard configurations: the WireGuard page")
        if page == "waiting" and not any(s["string"].startswith("guide_waiting_") for s in steps):
            bad.append(f"{name}: a waiting page says why")
    return bad


def check_link(data, g, url, where, allow=()):
    if url in allow:
        return []
    if FORBIDDEN.search(url):
        return [f"{where}: {url} points to a release, a store or a file to install"]
    m = LINE.match(url)
    if not m:
        return [f"{where}: {url} is not a line of code at a full commit"]
    repo = TREE.match(g["source"]) if g["source"] != "-" else None
    if repo and (m.group(2), m.group(3)) == (repo.group(1), repo.group(2)) and m.group(4) != g["commit"]:
        return [f"{where}: {url} is not at the guide's commit {g['commit']}"]
    return []


def check_steps(data):
    bad = []
    pages = {g["guide"]: g for g in data.guides}
    for s in data.steps:
        where = f"guide-steps.tsv: {s['guide']} {s['part']} {s['string']}"
        g = pages.get(s["guide"])
        if g is None:
            bad.append(f"{where}: no such guide")
            continue
        if s["part"] not in PARTS:
            bad.append(f"{where}: part {s['part']}")
        text = data.words.get(s["string"])
        if text is None or not s["string"].startswith("guide_"):
            bad.append(f"{where}: no such string of the network part's")
            continue
        args = [] if s["labels"] == "-" else s["labels"].split(",")
        want = places(text)
        tool_name = s["string"] in TOOL_NAMED
        if want != list(range(1, len(args) + 1 + tool_name)):
            bad.append(f"{where}: the string has places {want}, the step fills {len(args)}")
        for arg in args:
            if arg.startswith("="):
                if len(arg) < 2:
                    bad.append(f"{where}: an empty value")
            elif data.label(s["guide"], arg) is None:
                bad.append(f"{where}: no English label {arg}")
        allow = ("sources.tsv",) if g["page"] != "proxy" or s["part"] == "note" else ()
        if s["source"] == "-" and s["string"] in NAVIGATION:
            continue
        bad += check_link(data, g, s["source"], where, allow)
        if s["source"] == "sources.tsv":
            for package in g["packages"].split(","):
                if package not in data.sources:
                    bad.append(f"{where}: sources.tsv has nothing for {package}")
    return bad


# Strings whose first place is the tool's name, filled by the screen and the site, not by the step.
TOOL_NAMED = {"guide_vpn_only", "guide_wireguard_only"}


def check_labels(data):
    bad = []
    pages = {g["guide"]: g for g in data.guides}
    used = {(s["guide"], a) for s in data.steps for a in s["labels"].split(",") if a != "-" and not a.startswith("=")}
    seen = set()
    for x in data.labels:
        where = f"guide-labels.tsv: {x['guide']} {x['key']} {x['lang']}"
        g = pages.get(x["guide"])
        if g is None:
            bad.append(f"{where}: no such guide")
            continue
        if (x["guide"], x["key"], x["lang"]) in seen:
            bad.append(f"{where}: twice")
        seen.add((x["guide"], x["key"], x["lang"]))
        if (x["guide"], x["key"]) not in used:
            bad.append(f"{where}: no step uses it")
        if x["lang"] not in LANGS:
            bad.append(f"{where}: language {x['lang']}")
        if not RESOURCE.match(x["resource"]):
            bad.append(f"{where}: resource {x['resource']}")
        if x["resource"] != "-" and x["lang"] != "en":
            bad.append(f"{where}: a resource is read in the tool's language, so it is given once, in English")
        if not x["text"].strip() or len(x["text"]) > 80:
            bad.append(f"{where}: text '{x['text']}'")
        bad += check_link(data, g, x["source"], where)
    for g, key in used:
        if data.label(g, key) is None:
            bad.append(f"guide-labels.tsv: {g} {key} has no English row")
    return bad


def check_order(data):
    bad = []
    proxy = [g for g in data.guides if any("proxy" in m for p in g["packages"].split(",") if p in data.tools for m in modes(data.tools[p]))]
    rest = [g for g in data.guides if g not in proxy]
    if data.guides[: len(proxy)] != proxy:
        bad.append("guides.tsv: the tools with a proxy mode come first, then the others")
    first = [min(data.tool_order.index(p) for p in g["packages"].split(",") if p in data.tools) for g in proxy[MATRIX_FIRST:]]
    if first != sorted(first):
        bad.append("guides.tsv: after the matrix's first six, the tools with a proxy mode follow tools.tsv's order")
    first = [min(data.tool_order.index(p) for p in g["packages"].split(",") if p in data.tools) for g in rest]
    if first != sorted(first):
        bad.append("guides.tsv: the tools without a proxy mode follow tools.tsv's order")
    return bad


def against(data, clones):
    """Checks every label's text, and every other source's line, in clones of the sources under [clones]."""
    heads = {}
    for d in sorted(Path(clones).iterdir()):
        if d.is_dir():
            head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            heads.setdefault(head, d)
    bad, verified, missing = [], 0, set()

    def lines(url):
        m = LINE.match(url)
        if not m:
            return None
        clone = heads.get(m.group(4))
        if clone is None:
            missing.add(f"{m.group(2)}/{m.group(3)}@{m.group(4)[:8]}")
            return None
        path = clone / m.group(5)
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
        first, last = int(m.group(6)), int(m.group(7) or m.group(6))
        return text[first - 1:last] if last <= len(text) else []

    for x in data.labels:
        got = lines(x["source"])
        if got is None:
            continue
        forms = {x["text"], html.escape(x["text"], quote=False), x["text"].replace("'", "\\'"), x["text"].replace('"', '\\"')}
        if not got or not any(f in line for f in forms for line in got):
            bad.append(f"{x['guide']} {x['key']} {x['lang']}: '{x['text']}' is not at {x['source']}")
        else:
            verified += 1
    for url, where in [(s["source"], f"{s['guide']} {s['string']}") for s in data.steps] + \
                      [(g[f], f"{g['guide']} {f}") for g in data.guides for f in ("listener_source", "auth_source")]:
        got = lines(url)
        if got is not None and not got:
            bad.append(f"{where}: {url} has no such line")
        elif got:
            verified += 1
    return bad, verified, sorted(missing)


# The website's pages, from the data and the network part's English words: the same blocks in the same order as the
# network screen (guides/GuidePage.kt).

def blocks(data, g):
    """The page of guide [g] as (kind, string, args) blocks: kind is heading, text or step; an arg is ('label', key),
    ('value', text), ('tool',) or ('version',)."""
    name, page = g["guide"], g["page"]
    out = []

    def args(step):
        return [] if step["labels"] == "-" else [("value", a[1:]) if a.startswith("=") else ("label", a) for a in step["labels"].split(",")]

    def notes():
        for s in data.steps_of(name, "note"):
            out.append(("text", s["string"], ([("tool",)] if s["string"] in TOOL_NAMED else []) + args(s)))

    if page != "proxy":
        if page == "waiting":
            out.append(("text", "guide_waiting_intro", [("tool",)]))
        notes()
        if page == "wireguard":
            out.append(("text", "guide_wireguard_add", []))
        else:
            out.append(("text", "guide_audit", []))
        return out
    out.append(("text", "guide_intro", [("tool",)]))
    out.append(("text", "guide_assumes", [("tool",)]))
    out.append(("heading", "guide_heading_on", []))
    out += [("step", s["string"], args(s)) for s in data.steps_of(name, "on")]
    listener = next(x for x in g["listener"].split(",") if not x.startswith("http:"))
    address, port = LISTENER.match(listener).group(2, 3)
    out.append(("text", "guide_listener", [("value", address.strip("[]")), ("value", port)]))
    notes()
    out.append(("text", "guide_next", []))
    out.append(("heading", "guide_heading_password", []))
    if g["auth"] == "none":
        out.append(("text", "guide_password_none", []))
    else:
        out.append(("text", "guide_password_optional", []))
        out += [("step", s["string"], args(s)) for s in data.steps_of(name, "password")]
    out.append(("heading", "guide_heading_asks", []))
    out += [("text", s["string"], args(s)) for s in data.steps_of(name, "asks")]
    out.append(("heading", "guide_heading_back", []))
    out += [("step", s["string"], args(s)) for s in data.steps_of(name, "back")]
    out.append(("text", "guide_back_note", [("tool",)]))
    out.append(("text", "guide_read", [("tool",), ("version",)]))
    out.append(("text", "guide_checked" if g["checked"] != "waiting" else "guide_not_checked", []))
    out.append(("text", "guide_labels_recorded", []))
    return out


def tool_name(data, g):
    return data.tools[g["packages"].split(",")[0]][1]


def markdown_escape(text):
    return re.sub(r"([\\`*_\[\]<>#|])", r"\\\1", text)


def fill(data, g, string, arguments, link):
    text = data.words[string]
    values = []
    for arg in arguments:
        if arg[0] == "tool":
            values.append(markdown_escape(tool_name(data, g)))
        elif arg[0] == "version":
            values.append(f"[{markdown_escape(g['version'])}]({g['source']})" if link else g["version"])
        elif arg[0] == "value":
            values.append(markdown_escape(arg[1]))
        else:
            label = data.label(g["guide"], arg[1])
            values.append(f"[{markdown_escape(label['text'])}]({label['source']})" if link else markdown_escape(label["text"]))
    parts = re.split(r"(%\d+\$[sd])", markdown_escape(text))
    return "".join(values[int(p[1:-2]) - 1] if re.fullmatch(r"%\d+\$[sd]", p) else p for p in parts)


def page_markdown(data, g):
    title = data.words["guide_title_proxy" if g["page"] == "proxy" else "guide_title_other"].replace("%1$s", tool_name(data, g))
    out = ["---", f"title: {quote_yaml(title)}", "---", ""]
    n = 0
    # The words in quotes are plain text in the steps, so that a screen reader does not say "link" at every step;
    # where each one is in the tool's code is listed once, at the end (the accessibility unit, WCAG 2.4.4).
    quoted = {}
    for kind, string, arguments in blocks(data, g):
        for arg in arguments:
            if arg[0] == "label":
                quoted.setdefault(arg[1], data.label(g["guide"], arg[1]))
        if kind == "heading":
            out += ["", f"## {markdown_escape(data.words[string])}", ""]
            n = 0
        elif kind == "step":
            n += 1
            out.append(f"{n}. {fill(data, g, string, arguments, link=False)}")
        else:
            if n:
                out.append("")
                n = 0
            out += [fill(data, g, string, arguments, link=string == "guide_read"), ""]
    if quoted:
        out += [markdown_escape(data.words["guide_labels_where"].replace("%1$s", tool_name(data, g))), ""]
        out += [f"- [{markdown_escape(label['text'])}]({label['source']})" for label in quoted.values()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(line.rstrip() for line in out)).rstrip() + "\n"


def quote_yaml(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def index_markdown(data):
    w = data.words
    out = ["---", f"title: {quote_yaml(w['guide_index_title'])}", "---", "", markdown_escape(w["guide_index_intro"]), ""]
    for page, heading in (("proxy", "guide_index_proxy"), ("wireguard", "guide_index_wireguard"), ("vpn", "guide_index_vpn"),
                          ("waiting", "guide_index_waiting")):
        out += [f"## {markdown_escape(w[heading])}", ""]
        out += [f"- [{markdown_escape(tool_name(data, g))}]({g['guide']}/index.html)" for g in data.guides if g["page"] == page]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def write_site(data, directory):
    directory = Path(directory)
    if directory.exists():
        for old in sorted(directory.rglob("*"), reverse=True):
            old.unlink() if old.is_file() else old.rmdir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "_index.en.md").write_text(index_markdown(data), encoding="utf-8")
    for g in data.guides:
        (directory / g["guide"]).mkdir()
        (directory / g["guide"] / "index.en.md").write_text(page_markdown(data, g), encoding="utf-8")


def self_test():
    """Breaks copies of the data one way at a time, and expects the check to say so."""
    good = Data.load()
    assert not check(good), check(good)
    cases = [
        ("listener", lambda d: d.guide("v2rayng").update(listener="mixed:127.0.0.1:10809"), "not tools.tsv's"),
        ("auth", lambda d: d.guide("nekobox").update(auth="optional"), "auth optional is not"),
        ("label", lambda d: d.labels.remove(d.label("orbot", "power_user")), "no English label power_user"),
        ("proxy label", lambda d: d.label("orbot", "power_user").update(text="Power Mode"), "proxy label"),
        ("source", lambda d: d.steps_of("orbot", "on")[0].update(source="https://example.org/x"), "not a line of code"),
        ("store", lambda d: d.steps_of("orbot", "on")[0].update(source="https://github.com/a/b/releases/x"), "store"),
        ("commit", lambda d: d.label("v2rayng", "settings").update(source=d.label("v2rayng", "settings")["source"]
                                                                   .replace("57907cf354d9769200ed4717b4430d605abe0952", "0" * 40)),
         "not at the guide's commit"),
        ("places", lambda d: d.steps_of("v2rayng", "on")[1].update(labels="mode_settings,mode"), "places"),
        ("string", lambda d: d.steps_of("v2rayng", "on")[1].update(string="guide_step_nothing"), "no such string"),
        ("coverage", lambda d: d.guides.remove(d.guide("psiphon")), "no guide"),
        ("waiting", lambda d: d.guide("karing").update(page="proxy"), "not settled"),
        ("profile port", lambda d: d.guide("clash-meta").update(listener="mixed:127.0.0.1:7891"), "no step sets"),
        ("checked", lambda d: d.guide("orbot").update(checked="17.9.6"), "tried at"),
        ("amnezia", lambda d: d.guide("amneziawg").update(page="wireguard"), "gives no configuration"),
        ("provider", lambda d: d.guide("mullvad").update(page="vpn"), "the WireGuard page"),
        ("order", lambda d: d.guides.insert(7, d.guides.pop(8)), "tools.tsv's order"),
        ("password", lambda d: d.guide("zedsecure").update(auth="optional"), "password step"),
        ("unused", lambda d: d.labels.append(dict(d.label("orbot", "more"), key="spare")), "no step uses it"),
        ("resource", lambda d: d.label("orbot", "more").update(resource="string/menu more"), "resource"),
    ]
    for name, breaks, expect in cases:
        d = Data.load()
        breaks(d)
        problems = check(d)
        assert any(expect in p for p in problems), f"{name}: expected '{expect}' in {problems}"
    # The site's words are the network part's, filled in: a page names the tool, its version and its labels.
    page = page_markdown(good, good.guide("v2rayng"))
    assert 'choose "Proxy only"' in page, page
    assert '- [Proxy only](https://github.com/2dust/v2rayNG/blob/' in page, page
    assert "[2.3.15](https://github.com/2dust/v2rayNG/tree/2.3.15)" in page
    assert "127.0.0.1, port 10808" in page
    with tempfile.TemporaryDirectory() as out:
        write_site(good, out)
        assert len(list(Path(out).rglob("index.en.md"))) == len(good.guides)
    print(f"guides.py self-test: {len(cases)} broken copies caught")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    data = Data.load()
    problems = check(data)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    proxy = sum(g["page"] == "proxy" for g in data.guides)
    print(f"guides: {len(data.guides)} pages ({proxy} with steps), {len(data.steps)} steps, {len(data.labels)} labels: the data holds")
    if len(argv) == 3 and argv[1] == "--site":
        write_site(data, argv[2])
    elif len(argv) == 3 and argv[1] == "--against":
        bad, verified, missing = against(data, argv[2])
        for problem in bad:
            print(problem, file=sys.stderr)
        print(f"against the sources: {verified} lines found, {len(bad)} not; no clone of: {', '.join(missing) or 'none'}")
        return 1 if bad else 0
    elif len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
