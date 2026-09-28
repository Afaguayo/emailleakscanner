#!/usr/bin/env python3
"""Desktop app for emailleakscanner.

The interface is web/index.html, served by a tiny local server and shown in a native
window (pywebview: WebKit on macOS, Edge WebView2 on Windows). Without pywebview it
opens in your default browser instead.

    python3 gui.py              # native window (or browser if pywebview isn't installed)
    python3 gui.py --browser    # always use the browser
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import emailleakscanner as s

# PyInstaller unpacks bundled files to sys._MEIPASS.
BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(BASE, "web", "index.html")
# Every API call must carry this token, so other web pages can't drive the local server.
TOKEN = secrets.token_urlsafe(24)
LAST = {}  # email -> latest report, for saving


def reports_folder() -> str:
    home = os.path.expanduser("~")
    base = os.path.join(home, "Downloads")
    return os.path.join(base if os.path.isdir(base) else home, "Email Leak Scanner")


def reveal(path: str) -> None:
    if sys.platform == "win32":
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", path])
    else:
        subprocess.Popen(["xdg-open", os.path.dirname(path)])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            with open(INDEX, "rb") as f:
                page = f.read().replace(b"__TOKEN__", TOKEN.encode())
            return self._send(200, page, "text/html; charset=utf-8")
        if not self._authorized():
            return self._json(403, {"error": "Forbidden"})
        params = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/api/settings":
            key = s.hibp_key()
            return self._json(200, {"hibp": bool(key), "version": s.__version__, "folder": reports_folder()})
        if url.path == "/api/open":
            link = params.get("url", "")
            if link.startswith(("https://", "http://")):  # never hand other schemes to the OS
                webbrowser.open(link)
            return self._json(200, {})
        self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._authorized():
            return self._json(403, {"error": "Forbidden"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self._json(400, {"error": "Bad request"})
        path = urlparse(self.path).path
        try:
            if path == "/api/scan":
                report = s.scan(body.get("email", ""), s.hibp_key(), web=body.get("web", True))
                LAST[report["email"].lower()] = report
                self._json(200, report)
            elif path == "/api/password":
                # the password only lives in this request; it's hashed and only 5 hash chars go out
                self._json(200, {"count": s.check_password(body.get("password", ""))})
            elif path == "/api/save":
                report = LAST.get(str(body.get("email", "")).lower())
                if not report:
                    return self._json(404, {"error": "Scan the address first."})
                saved = s.save_report(report, reports_folder(), "json" if body.get("format") == "json" else "txt")
                reveal(saved)
                self._json(200, {"path": saved})
            elif path == "/api/settings":
                cfg = s.load_config()
                key = str(body.get("hibp_api_key", "")).strip()
                if key:
                    cfg["hibp_api_key"] = key
                else:
                    cfg.pop("hibp_api_key", None)
                s.save_config(cfg)
                self._json(200, {"hibp": bool(s.hibp_key())})
            else:
                self._json(404, {"error": "Not found"})
        except ValueError as e:  # bad email
            self._json(400, {"error": str(e)})
        except s.ScanError as e:
            self._json(502, {"error": str(e)})
        except Exception as e:  # network down, API changed, etc.
            self._json(500, {"error": f"Something went wrong: {e}"})

    def _authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def _json(self, code, data):
        self._send(code, json.dumps(data).encode(), "application/json")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the console quiet
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser", action="store_true", help="open in the default browser instead of a window")
    ap.add_argument("--port", type=int, default=0, help="port for the local server (default: any free port)")
    ap.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)  # server only, for testing
    args = ap.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)  # localhost only
    url = f"http://127.0.0.1:{server.server_address[1]}/"

    if args.serve:
        print(url, TOKEN, flush=True)
        server.serve_forever()
        return

    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not args.browser:
        try:
            import webview
        except ImportError:
            print("pywebview isn't installed; opening in your browser instead.", file=sys.stderr)
        else:
            webview.create_window("Email Leak Scanner", url, width=1080, height=800, min_size=(420, 560))
            webview.start()
            return

    webbrowser.open(url)
    print(f"Email Leak Scanner is running at {url} — press Ctrl+C to quit.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
