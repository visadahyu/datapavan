#!/usr/bin/env python3
"""Checks the built website in docs/site (site/README.md): no script, nothing from another server, about
200 KB or less on a first load before images, and every link inside the site leads somewhere. For search engines
(site/README.md, "Search engines"): robots.txt, one sitemap at the root that lists every page and nothing else,
llms.txt's links, the IndexNow key file, and on every page one canonical address, matching its og:url, with a title no other page of its
language has. For accessibility (site/README.md, "Accessibility"), what needs no browser: each page's language and direction,
one h1 and no skipped heading level, names for links, controls, pictures and drawings, the language list's languages, one
main with a link to it first, zoom allowed, and the contrast of the stylesheet's colours in both schemes. The rest is
scripts/a11y-site.sh's, run locally."""
import datetime
import gzip
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/site"
LIMIT = 200 * 1024
FP = "FA:6A:24:04:2A:BC:AC:8B"
BASE = "https://datapavan.org/"
LANGS = ("fr", "de", "es", "ru", "zh", "ar", "fa")


def main():
    bad = []
    pages = sorted(SITE.rglob("*.html"))
    print(f"{'page':24} {'gzipped':>8} {'fonts':>7} {'load':>7}")
    for page in pages:
        name = str(page.relative_to(SITE))
        html = page.read_text(encoding="utf-8")
        for pattern, what in (
            (r"<script|<iframe|<object|<embed", "script or frame"),
            (r'<link\b(?![^>]*rel="?(alternate|icon|canonical)")', "a link tag other than alternate, icon or canonical"),
            (r'(src|srcset)="?https?:|url\(\s*["\']?https?:|@import|rel="?icon"? href="?https?:', "loads from another server"),
            (r'\son[a-z]+="', "inline event handler"),
        ):
            if re.search(pattern, html):
                bad.append(f"{name}: {what}")
        fonts = 0
        for url in set(re.findall(r"url\(([^)\"']+)\)", html)):
            target = (page.parent / url).resolve()
            if not target.exists():
                bad.append(f"{name}: missing {url}")
            else:
                fonts += target.stat().st_size
        load = len(gzip.compress(html.encode(), 9, mtime=0)) + fonts
        print(f"{name:24} {len(gzip.compress(html.encode(), 9, mtime=0)):8} {fonts:7} {load:7}")
        if load > LIMIT:
            bad.append(f"{name}: first load is {load} bytes")
        for link in re.findall(r'(?:href|src)="?([^"\s>]+)', html):
            if re.match(r"[a-z]+:|//|#", link):
                continue
            target = (page.parent / link.split("#")[0]).resolve()
            # A release's signed files are published beside the site, not built with it (site/README.md).
            if target.is_relative_to(SITE.resolve() / "download"):
                continue
            if not target.exists():
                bad.append(f"{name}: broken link {link}")
    bad += search(pages)
    # An element of nothing but microdata still takes a place in the layout: as a child of a grid or a flex row, an
    # empty cell that pushes the rest out of place. Microdata goes inside an element that shows something.
    for page in pages:
        html = page.read_text(encoding="utf-8")
        for grid in re.findall(r'<div class="(hero)"[^>]*>(?:<meta [^>]*>|\s)*<div[^>]*>(?:<meta [^>]*>|\s)*</div>', html):
            bad.append(f"{page.relative_to(SITE)}: a div of nothing but meta elements is a cell of .{grid}'s grid")
    bad += accessibility(pages)
    home = pages and (SITE / "index.html").read_text(encoding="utf-8")
    if not home or FP not in home:
        bad.append("index.html: no signing fingerprint")
    security = SITE / ".well-known/security.txt"
    if not security.exists():
        bad.append(".well-known/security.txt is missing")
    else:
        # RFC 9116: Expires is required, and a stale file tells reporters the contacts may be dead. Renew it a
        # month ahead, at most a year out (site/static/.well-known/security.txt).
        expires = [line.split(":", 1)[1].strip() for line in security.read_text(encoding="utf-8").splitlines()
                   if line.startswith("Expires:")]
        if len(expires) != 1:
            bad.append(".well-known/security.txt: needs exactly one Expires line")
        else:
            when = datetime.datetime.fromisoformat(expires[0].replace("Z", "+00:00"))
            if when - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(days=30):
                bad.append(f".well-known/security.txt: Expires {expires[0]} is less than 30 days away; renew it")
    for problem in bad:
        print(problem)
    print(f"site: {len(pages)} pages, {len(bad)} problems")
    return 1 if bad else 0


def search(pages):
    """What search engines read: robots.txt, the sitemap, the IndexNow key, and each page's address and title."""
    bad = []
    robots = SITE / "robots.txt"
    if not robots.exists() or f"Sitemap: {BASE}sitemap.xml" not in robots.read_text(encoding="utf-8"):
        bad.append("robots.txt is missing or does not name the sitemap")
    keys = [f for f in SITE.glob("*.txt") if re.fullmatch(r"[0-9a-f]{32}", f.stem)]
    if len(keys) != 1 or keys[0].read_text(encoding="utf-8").strip() != keys[0].stem:
        bad.append("needs exactly one IndexNow key file, <key>.txt holding the key (site/static)")
    addresses, titles = {}, {}
    for page in pages:
        name = str(page.relative_to(SITE))
        html = page.read_text(encoding="utf-8")
        canonical = re.findall(r'<link rel="canonical" href="([^"]+)"', html)
        og = re.findall(r'<meta property="og:url" content="([^"]+)"', html)
        if len(canonical) != 1 or og != canonical:
            bad.append(f"{name}: needs one canonical link, matching og:url")
            continue
        address = canonical[0]
        if not address.startswith(BASE) or "index.html" in address:
            bad.append(f"{name}: canonical {address} is not a clean address on {BASE}")
        if address != BASE + name.removesuffix("index.html"):
            bad.append(f"{name}: canonical {address} is not this page's address")
        addresses[address] = name
        language = name.split("/")[0] if name.split("/")[0] in LANGS else "en"
        title = re.search(r"<title>([^<]*)</title>", html)
        if not title:
            bad.append(f"{name}: no title")
        elif (language, title[1]) in titles:
            bad.append(f"{name}: same title as {titles[language, title[1]]}")
        else:
            titles[language, title[1]] = name
    llms = SITE / "llms.txt"
    if not llms.exists() or not llms.read_text(encoding="utf-8").startswith("# Datapavan\n"):
        bad.append("llms.txt is missing or does not start with its title")
    else:
        for address in re.findall(r"\]\((https://datapavan\.org/[^)]*)\)", llms.read_text(encoding="utf-8")):
            if address not in addresses:
                bad.append(f"llms.txt links {address}, which is no page here")
    sitemap = SITE / "sitemap.xml"
    if not sitemap.exists():
        return bad + ["sitemap.xml is missing"]
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    listed = [loc.text for loc in ET.parse(sitemap).getroot().iterfind("s:url/s:loc", ns)]
    for address in sorted(set(listed) - set(addresses)):
        bad.append(f"sitemap.xml lists {address}, which is no page here")
    for address in sorted(set(addresses) - set(listed)):
        bad.append(f"sitemap.xml leaves out {addresses[address]}")
    if len(listed) != len(set(listed)):
        bad.append("sitemap.xml lists an address twice")
    return bad


RTL = ("ar", "fa")
# The stylesheet's colours (site/assets/style.css): every text colour on every ground, as the app's ThemeTest does, and
# the pairs that only ever meet each other. A colour the stylesheet uses for text or ground that is in none of these
# fails, so that a new colour cannot skip the check.
TEXT = ("--ink", "--mute", "--lab", "--tag")
GROUNDS = ("--paper", "--panel", "--band")
PAIRS = (("--paper", "--lab"), ("--paper", "--ink"), ("--on-deep", "--deep"), ("--own-t", "--own-p"), ("--own-ink", "--own-p"))
# Grounds that carry no text of their own colour: the plan's bars are drawn, not read.
DRAWN = ("--lab",)


def luminance(colour):
    def channel(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def blend(colour, ground, alpha):
    mix = (round(alpha * int(colour[i:i + 2], 16) + (1 - alpha) * int(ground[i:i + 2], 16)) for i in (1, 3, 5))
    return "#" + "".join(f"{c:02X}" for c in mix)


def schemes(css):
    """The colour tokens in the light scheme, and in the dark one (the light ones with the dark scheme's changes)."""
    light = {}
    for body in re.findall(r"(?<![\w)])(?:^|[}\s]):root\{([^}]*)\}", css):
        light.update(re.findall(r"(--[\w-]+):(#[0-9A-Fa-f]{6})", body))
    dark, chosen = dict(light), {}
    found = 0
    for body in re.findall(r'@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)\s*\{\s*:root:not\(\[data-theme="light"\]\)\s*\{([^}]*)\}', css):
        dark.update(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9A-Fa-f]{6})", body))
        found += 1
    # The dark scheme a reader chooses on the page must be the one the phone's setting gives.
    for body in re.findall(r':root\[data-theme="dark"\]\s*\{([^}]*)\}', css):
        chosen.update(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9A-Fa-f]{6})", body))
    return {"light": light, "dark": dark, "found": found, "chosen": chosen}


def stylesheet(focusable):
    """The stylesheet's colours: text at least 4.5:1 on its grounds in both schemes, a focus ring at least 3:1 on the
    grounds around it, a motion rule where anything moves. FOCUSABLE is the classes the pages give to links and
    controls."""
    bad = []
    css = (ROOT / "site/assets/style.css").read_text(encoding="utf-8")
    for colour in sorted(set(re.findall(r"(?<![-\w])color:var\((--[\w-]+)\)", css))):
        if colour not in TEXT and colour not in (p[0] for p in PAIRS):
            bad.append(f"style.css: text colour {colour} is in no pair of check-site.py's TEXT, GROUNDS and PAIRS")
    for ground in sorted(set(re.findall(r"background(?:-color)?:var\((--[\w-]+)\)", css))):
        if ground not in GROUNDS and ground not in (p[1] for p in PAIRS) and ground not in DRAWN:
            bad.append(f"style.css: ground {ground} is in no pair of check-site.py's TEXT, GROUNDS and PAIRS")
    parsed = schemes(css)
    if not parsed["found"]:
        bad.append("style.css: no dark scheme found (@media (prefers-color-scheme:dark) with :root:not([data-theme=\"light\"]))")
    for token, value in parsed["chosen"].items():
        if parsed["dark"].get(token) != value:
            bad.append(f"style.css: {token} is {value} in :root[data-theme=\"dark\"] but {parsed['dark'].get(token)} in the dark scheme")
    for scheme, tokens in ((k, parsed[k]) for k in ("light", "dark")):
        pairs = [(t, g) for t in TEXT for g in GROUNDS] + list(PAIRS)
        for text, ground in pairs:
            if text not in tokens or ground not in tokens:
                bad.append(f"style.css: {text} or {ground} has no {scheme} value")
            elif contrast(tokens[text], tokens[ground]) < 4.5:
                bad.append(f"style.css: {text} on {ground} is {contrast(tokens[text], tokens[ground]):.2f}:1 in the {scheme} scheme")
        # The name's Latin letters beside a name in another script are drawn lighter (.lat2) on the page's paper.
        alpha = re.search(r"\.lat2\{[^}]*opacity:([.\d]+)", css)
        if alpha:
            seen = blend(tokens["--lab"], tokens["--paper"], float(alpha[1]))
            if contrast(seen, tokens["--paper"]) < 4.5:
                bad.append(f"style.css: .lat2 is {contrast(seen, tokens['--paper']):.2f}:1 in the {scheme} scheme")
        # A focus ring drawn in the element's own colour: where a component has a colour of its own, its ring must
        # be given one that stands out from the grounds around it (WCAG 2.4.7; 3:1, the house rule after 1.4.11).
        for name, own in re.findall(r"(?:^|[}\s])\.([\w-]+)\{[^}]*(?<![-\w])color:var\((--[\w-]+)\)", css):
            ring = re.search(r"\." + re.escape(name) + r":focus-visible\{[^}]*outline-color:var\((--[\w-]+)\)", css)
            colour = ring[1] if ring else own
            for ground in GROUNDS:
                if name not in focusable or colour not in tokens:
                    continue
                if contrast(tokens[colour], tokens[ground]) < 3:
                    bad.append(f"style.css: the focus ring of .{name} ({colour}) is {contrast(tokens[colour], tokens[ground]):.2f}:1 on {ground} in the {scheme} scheme")
    if not re.search(r"a:focus-visible,summary:focus-visible[^{]*\{outline:3px solid currentColor", css):
        bad.append("style.css: links and the language list need a visible focus ring")
    if re.search(r"animation|transition", css) and "@media (prefers-reduced-motion:reduce)" not in css:
        bad.append("style.css: something moves, and nothing stops it for readers who ask for less motion")
    return bad


def accessibility(pages):
    """What needs no browser, on every page; scripts/a11y-site.sh checks the rest locally."""
    focusable = set()
    for page in pages:
        for classes in re.findall(r'<(?:a|summary)\b[^>]*\bclass="([^"]+)"', page.read_text(encoding="utf-8")):
            focusable.update(classes.split())
    bad = stylesheet(focusable)
    for page in pages:
        name = str(page.relative_to(SITE))
        html = page.read_text(encoding="utf-8")
        language = name.split("/")[0] if name.split("/")[0] in LANGS else "en"
        direction = "rtl" if language in RTL else "ltr"
        if not re.search(rf'<html lang="{language}" dir="{direction}">', html):
            bad.append(f"{name}: <html> needs lang=\"{language}\" and dir=\"{direction}\"")
        levels = [int(n) for n in re.findall(r"<h([1-6])\b", html)]
        if levels.count(1) != 1:
            bad.append(f"{name}: needs exactly one h1, has {levels.count(1)}")
        # House rule: no heading level skipped (WCAG asks only that the levels be true).
        for before, after in zip(levels, levels[1:]):
            if after > before + 1:
                bad.append(f"{name}: h{after} follows h{before}")
                break
        for img in re.findall(r"<img\b[^>]*>", html):
            if not re.search(r'\balt="', img):
                bad.append(f"{name}: a picture without alt: {img[:60]}")
        for svg in re.findall(r"<svg\b[^>]*>", html):
            if 'aria-hidden="true"' not in svg and not ('role="img"' in svg and re.search(r'aria-label="[^"]+"', svg)):
                bad.append(f"{name}: a drawing that is neither hidden nor named: {svg[:60]}")
        for tag, attributes, inner in re.findall(r"<(a|summary)\b([^>]*)>(.*?)</\1>", html, re.S):
            label = re.search(r'aria-label="([^"]*)"', attributes)
            text = " ".join(re.sub(r"<[^>]+>", " ", inner).split())
            pictures = re.findall(r'<img\b[^>]*alt="([^"]+)"', inner)
            if not (label and label[1].strip()) and not text and not pictures:
                bad.append(f"{name}: a {tag} without a name: <{tag}{attributes[:50]}>")
            elif label and text and text.casefold() not in label[1].casefold():
                bad.append(f"{name}: the {tag} \"{text[:30]}\" is named \"{label[1][:30]}\", which leaves out its visible text")
        lists = re.findall(r'<details class="lng">(.*?)</details>', html, re.S)
        if len(lists) != 1:
            bad.append(f"{name}: needs one language list")
        else:
            for link in re.findall(r"<a\b[^>]*>", lists[0]):
                if not re.search(r'\blang="[\w-]+"', link) or not re.search(r'\bhreflang="[\w-]+"', link):
                    bad.append(f"{name}: a language in the language list without lang and hreflang: {link[:60]}")
        if html.count("<main") != 1 or '<main id="main">' not in html:
            bad.append(f"{name}: needs one <main id=\"main\">")
        first = re.search(r"<body>\s*(<a\b[^>]*>)", html)
        if not first or 'href="#main"' not in first[1]:
            bad.append(f"{name}: the first thing in the body must be the link to the content, #main")
        viewport = re.search(r'<meta name="viewport" content="([^"]*)"', html)
        scale = viewport and re.search(r"maximum-scale=([\d.]+)", viewport[1])
        if not viewport or re.search(r"user-scalable=(no|0)", viewport[1]) or (scale and float(scale[1]) < 5):
            bad.append(f"{name}: the viewport must let readers zoom (house rule: no maximum-scale below 5)")
        for element in re.findall(r"<(?!a\b|summary\b)\w+\b[^>]*\btabindex=\"0\"[^>]*>", html):
            if 'role="region"' not in element or not re.search(r'aria-label="[^"]+"', element):
                bad.append(f"{name}: a box that takes the focus needs role=\"region\" and a name: {element[:60]}")
    return bad


if __name__ == "__main__":
    sys.exit(main())
