#!/usr/bin/env python3
"""Tells the search engines that take IndexNow (Bing, Yandex, Naver, Seznam and others; not Google, which reads the
sitemap) that datapavan.org's pages changed. Run it by hand after a deploy (site/README.md, "Search engines").

    scripts/indexnow.py --since COMMIT           show what would be sent: the pages that changed since COMMIT
    scripts/indexnow.py --since COMMIT --send    send it
    scripts/indexnow.py [--send]                 every address in the sitemap, for a first run or after a long gap

COMMIT is the one the server last got (its docs/site). A page counts as changed when its built file under docs/site
differs from COMMIT's, here or in Git, a removed page included, so that the engines drop it; the page for a missing
address has no address of its own (site/layouts/404.html). Sending every page at each run would tell the engines
that pages changed that did not (the site for search engines, fix 11).

It reads the built site in docs/site: the addresses in sitemap.xml, and the key from the one <key>.txt at the root,
which must already be live on the server, since the engines fetch it to check that the sender owns the site. It sends
the addresses and the key, nothing else."""
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "docs/site"
HOST = "datapavan.org"
ENDPOINT = "https://api.indexnow.org/indexnow"
ANSWERS = {
    200: "accepted",
    202: "received; the key is still being checked",
    400: "bad request",
    403: "the key file was not found or does not match",
    422: "an address is not on the host, or the key does not match the protocol",
    429: "too many requests; wait before sending again",
}


def changed(commit):
    """The addresses of the pages whose built file differs from COMMIT's: changed, added or removed."""
    def git(*args):
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.split("\n")
    git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
    files = git("diff", "--name-only", "--no-renames", commit, "--", "docs/site")
    files += git("ls-files", "--others", "--exclude-standard", "--", "docs/site")
    urls = set()
    for name in filter(None, files):
        path = Path(name).relative_to("docs/site")
        if path.name != "index.html":
            continue
        folder = path.parent.as_posix()
        urls.add(f"https://{HOST}/" if folder == "." else f"https://{HOST}/{folder}/")
    return sorted(urls)


def main():
    args = sys.argv[1:]
    keys = [f.stem for f in SITE.glob("*.txt") if re.fullmatch(r"[0-9a-f]{32}", f.stem)]
    if len(keys) != 1:
        sys.exit("docs/site needs exactly one <key>.txt: run scripts/build-site.sh")
    if "--since" in args:
        if args.index("--since") + 1 >= len(args):
            sys.exit(__doc__)
        commit = args[args.index("--since") + 1]
        try:
            urls = changed(commit)
        except subprocess.CalledProcessError as error:
            sys.exit(f"git: {commit}: {error.stderr.strip() or 'not a commit'}")
        if not urls:
            print(f"no page changed since {commit}: nothing to send")
            return 0
    else:
        ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        urls = [loc.text for loc in ET.parse(SITE / "sitemap.xml").getroot().iterfind("s:url/s:loc", ns)]
    if not urls or any(not u.startswith(f"https://{HOST}/") for u in urls):
        sys.exit("no address, or one that is not on datapavan.org")
    body = {"host": HOST, "key": keys[0], "urlList": urls}
    print(f"{len(urls)} addresses for {HOST}, key file https://{HOST}/{keys[0]}.txt")
    for url in urls[:200]:
        print(f"  {url}")
    if "--send" not in args:
        print("not sent: add --send")
        return 0
    with urllib.request.urlopen(f"https://{HOST}/{keys[0]}.txt", timeout=30) as live:
        if live.read().decode().strip() != keys[0]:
            sys.exit("the live key file does not hold the key: deploy the site first")
    request = urllib.request.Request(ENDPOINT, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json; charset=utf-8", "User-Agent": "datapavan-indexnow"})
    try:
        with urllib.request.urlopen(request, timeout=60) as answer:
            status = answer.status
    except urllib.error.HTTPError as error:
        status = error.code
    print(f"IndexNow: {status} {ANSWERS.get(status, 'unexpected answer')}")
    return 0 if status in (200, 202) else 1


if __name__ == "__main__":
    sys.exit(main())
