# SPDX-License-Identifier: Apache-2.0
"""The DNS lab's captive portal (scripts/dnslab, W8): an HTTP server on port 80 for a check that points the
emulator's captive_portal_http_url at it (through the censor's portal front).

  open      /generate_204 (any path ending in generate_204 or gen_204) answers 204, as a network with no
            portal; /login says the network is open; anything else is 404;
  captive   every path but /login answers 302 to http://HOST/login (HOST as the client asked for it), and
            /login answers 200 with a page, as a portal before its login.

  python3 -I portal.py serve        the server (open at its start)
  python3 -I portal.py ctl open|captive|state
                                    switches it, or says its state (in its container)

One line per request on stdout: the state, the method, the path and the answer. Python's standard library only."""

import http.server
import sys

STATE = "/run/dnslab-portal.state"


def state():
    try:
        with open(STATE) as file:
            return file.read().strip() or "open"
    except FileNotFoundError:
        return "open"


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "dnslab-portal"
    sys_version = ""

    def answer(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_any(self):
        now = state()
        path = self.path.split("?", 1)[0]
        if path == "/login":
            text = "open: nothing to log in to" if now == "open" else "lab captive portal: log in"
            status, body, headers = 200, f"<!doctype html><title>{text}</title><p>{text}</p>\n".encode(), \
                [("Content-Type", "text/html; charset=utf-8")]
        elif now == "captive":
            host = self.headers.get("Host", "portal.dnslab.test")
            status, body, headers = 302, b"", [("Location", f"http://{host}/login")]
        elif path.endswith("generate_204") or path.endswith("gen_204"):
            status, body, headers = 204, b"", []
        else:
            status, body, headers = 404, b"", []
        print(f"request state={now} method={self.command} path={path} status={status}", flush=True)
        if status == 204:
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        else:
            self.answer(status, body, headers)

    do_GET = do_HEAD = do_POST = handle_any

    def log_message(self, *args):
        pass


def main():
    if sys.argv[1:2] == ["serve"]:
        with open(STATE, "w") as file:
            file.write("open\n")
        print("portal ready", flush=True)
        http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
    elif sys.argv[1:2] == ["ctl"] and sys.argv[2:3] in (["open"], ["captive"]):
        with open(STATE, "w") as file:
            file.write(sys.argv[2] + "\n")
        print(f"portal {sys.argv[2]}")
        return 0
    elif sys.argv[1:] == ["ctl", "state"]:
        print(f"portal {state()}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
