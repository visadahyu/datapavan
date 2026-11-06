#!/usr/bin/env python3
"""Checks the built website in docs/site (site/README.md): no script, nothing from another server, about
200 KB or less on a first load before images, and every link inside the site leads somewhere."""
import gzip
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/site"
LIMIT = 200 * 1024
FP = "FA:6A:24:04:2A:BC:AC:8B"


def main():
    bad = []
    pages = sorted(SITE.rglob("*.html"))
    print(f"{'page':24} {'gzipped':>8} {'fonts':>7} {'load':>7}")
    for page in pages:
        name = str(page.relative_to(SITE))
        html = page.read_text(encoding="utf-8")
        for pattern, what in (
            (r"<script|<iframe|<object|<embed", "script or frame"),
            (r'<link\b(?![^>]*rel="?(alternate|icon)")', "a link tag other than alternate or icon"),
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
            if not target.exists():
                bad.append(f"{name}: broken link {link}")
    home = pages and (SITE / "index.html").read_text(encoding="utf-8")
    if not home or FP not in home:
        bad.append("index.html: no signing fingerprint")
    if not (SITE / ".well-known/security.txt").exists():
        bad.append(".well-known/security.txt is missing")
    for problem in bad:
        print(problem)
    print(f"site: {len(pages)} pages, {len(bad)} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
