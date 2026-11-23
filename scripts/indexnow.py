#!/usr/bin/env python3
"""Tells the search engines that take IndexNow (Bing, Yandex, Naver, Seznam and others; not Google, which reads the
sitemap) that datapavan.org's pages changed. Run it by hand after a deploy (site/README.md, "Search engines").

    scripts/indexnow.py           show what would be sent
    scripts/indexnow.py --send    send it

It reads the built site in docs/site: the addresses in sitemap.xml, and the key from the one <key>.txt at the root,
which must already be live on the server, since the engines fetch it to check that the sender owns the site. It sends
the addresses and the key, nothing else."""
import json
import re
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


def main():
    keys = [f.stem for f in SITE.glob("*.txt") if re.fullmatch(r"[0-9a-f]{32}", f.stem)]
    if len(keys) != 1:
        sys.exit("docs/site needs exactly one <key>.txt: run scripts/build-site.sh")
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = [loc.text for loc in ET.parse(SITE / "sitemap.xml").getroot().iterfind("s:url/s:loc", ns)]
    if not urls or any(not u.startswith(f"https://{HOST}/") for u in urls):
        sys.exit("sitemap.xml lists no address, or one that is not on datapavan.org")
    body = {"host": HOST, "key": keys[0], "urlList": urls}
    print(f"{len(urls)} addresses for {HOST}, key file https://{HOST}/{keys[0]}.txt")
    if "--send" not in sys.argv[1:]:
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
