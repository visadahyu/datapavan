#!/usr/bin/env python3
"""The date each page of datapavan.org last changed, for the sitemap's lastmod (site/README.md, "Search engines").

site/data/lastmod.json holds, for each page's address, the SHA-256 of its built <main> and the date it last changed.
A date moves only when that hash does, so a build from the same sources gives the same site (scripts/build-site.sh
--check), and the date says when the page's own content last changed, not when the site was built or its frame (the
header, the footer, the language list) was touched. Search engines use lastmod only while it stays accurate (Google,
"Build and submit a sitemap"; Bing). Git's dates would not do: a build from a copy without history would differ.

    scripts/lastmod.py SITE           update the ledger from the site built in SITE: a page whose <main> changed, or
                                      a new one, gets today's date (UTC); a page that is gone leaves it
    scripts/lastmod.py --check SITE   fail unless the ledger holds exactly the built pages, each with its hash
"""
import datetime
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "site/data/lastmod.json"


def pages(site):
    """Each built page's address, as Hugo's RelPermalink names it, and the hash of its <main>. Pages are folders'
    index.html: the page for a missing address, 404.html, has no address of its own (site/layouts/404.html)."""
    out = {}
    for page in sorted(site.rglob("index.html")):
        html = page.read_text(encoding="utf-8")
        start, end = html.find("<main"), html.find("</main>")
        if start < 0 or end < start:
            sys.exit(f"{page.relative_to(site)} has no <main>")
        folder = page.parent.relative_to(site)
        address = "/" if folder == Path(".") else f"/{folder.as_posix()}/"
        out[address] = hashlib.sha256(html[start:end].encode()).hexdigest()
    return out


def load():
    return json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else {}


def main(argv):
    check = argv[1:2] == ["--check"]
    rest = argv[2:] if check else argv[1:]
    if len(rest) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    built, ledger = pages(Path(rest[0])), load()
    if check:
        bad = [f"{a}: not in site/data/lastmod.json" for a in sorted(set(built) - set(ledger))]
        bad += [f"{a}: in site/data/lastmod.json, but no page" for a in sorted(set(ledger) - set(built))]
        bad += [f"{a}: its <main> changed since site/data/lastmod.json" for a in sorted(set(built) & set(ledger))
                if ledger[a]["sha256"] != built[a]]
        for problem in bad:
            print(problem)
        if bad:
            print("lastmod: the ledger is not the built site's: run scripts/build-site.sh")
            return 1
        return 0
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    new = {a: ledger[a] if a in ledger and ledger[a]["sha256"] == h else {"sha256": h, "date": today}
           for a, h in built.items()}
    changed = sorted(a for a in new if new[a] is not ledger.get(a))
    if new != ledger:
        LEDGER.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"lastmod: {len(new)} pages, {len(changed)} changed{': ' + ', '.join(changed[:8]) if changed else ''}"
          f"{' …' if len(changed) > 8 else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
