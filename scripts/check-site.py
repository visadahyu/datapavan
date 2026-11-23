#!/usr/bin/env python3
"""Checks the built website in docs/site (site/README.md): no script, nothing from another server, about
200 KB or less on a first load before images, and every link inside the site leads somewhere. For search engines
(site/README.md, "Search engines"): robots.txt, one sitemap at the root that lists every page and nothing else, the
IndexNow key file, and on every page one canonical address, matching its og:url, with a title no other page of its
language has."""
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


if __name__ == "__main__":
    sys.exit(main())
