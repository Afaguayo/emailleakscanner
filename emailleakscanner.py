#!/usr/bin/env python3
"""Email Leak Scanner: check whether an email address shows up in known data breaches.

Sources (all free; only HaveIBeenPwned needs a key):
  - XposedOrNot      breach list with details, exposed data types and a risk score
  - LeakCheck        public breach lookup
  - HaveIBeenPwned   optional, needs HIBP_API_KEY (paid key from haveibeenpwned.com/API/Key)
  - DuckDuckGo       public web pages that contain the address
Plus an optional password check against Pwned Passwords. Only the first 5 characters
of the password's SHA-1 hash leave your computer (k-anonymity), never the password.

    python3 emailleakscanner.py                         # interactive
    python3 emailleakscanner.py you@example.com         # one or more addresses
    python3 emailleakscanner.py -f emails.txt --save reports
    python3 emailleakscanner.py you@example.com --json
    python3 emailleakscanner.py --password              # check a password (hidden prompt)

Only scan addresses you own or have permission to check.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen

__version__ = "1.0.0"

USER_AGENT = f"EmailLeakScanner/{__version__} (+https://github.com/Afaguayo/emailleakscanner)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
TIMEOUT = 20

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")

# Data types that make a breach worse than "your email is on a list".
PASSWORD_TYPES = {"passwords", "password hints", "historical passwords", "auth tokens"}
SENSITIVE_TYPES = {
    "ssn", "social security numbers", "government issued ids", "passport numbers",
    "government ids", "partial government issued ids", "credit cards", "credit card details",
    "partial credit card data", "bank account numbers", "financial data",
    "dates of birth", "physical addresses", "phone numbers",
    "security questions and answers", "health information",
}


class ScanError(Exception):
    """A source couldn't be reached or answered with something unexpected."""


# ---------------------------------------------------------------- helpers

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or "")) and len(email) <= 254


def fetch(url: str, headers: dict | None = None, timeout: int = TIMEOUT) -> tuple[int, str]:
    """GET a URL and return (status, body). 4xx/5xx are returned, not raised."""
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urlopen(req, timeout=timeout) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (URLError, TimeoutError, OSError) as e:
        raise ScanError(f"couldn't connect ({getattr(e, 'reason', e)})") from e


def fetch_json(url: str, headers: dict | None = None):
    status, body = fetch(url, headers)
    try:
        return status, json.loads(body) if body.strip() else None
    except ValueError:
        return status, None


def norm_key(name: str) -> str:
    """Key used to merge the same breach reported by several services: 'StockX.com' == 'StockX'."""
    name = name.lower().strip()
    name = re.sub(r"\.(com|net|org|io|co|me|to|ru|de|fr|br|in|cn|tw|info|biz)$", "", name)
    return re.sub(r"[^a-z0-9]", "", name)


# Different services name the same data differently ("dob" vs "Dates of birth"); fold them together.
TYPE_ALIASES = {
    "password": "Passwords", "passwords": "Passwords",
    "dob": "Dates of birth", "date of birth": "Dates of birth",
    "ssn": "Social security numbers",
    "phone": "Phone numbers",
    "address": "Physical addresses", "address1": "Physical addresses", "street": "Physical addresses",
    "ip": "IP addresses", "ip1": "IP addresses", "ip2": "IP addresses",
    "username": "Usernames", "email": "Email addresses",
    "name": "Names", "first name": "Names", "last name": "Names", "middle name": "Names",
    "surnames": "Names", "profile name": "Names",
    "gender": "Genders", "nationality": "Nationalities", "title": "Titles",
    "location": "Geographic locations", "city": "Geographic locations", "country": "Geographic locations",
    "province": "Geographic locations", "region": "Geographic locations", "state": "Geographic locations",
    "zip": "Geographic locations", "area": "Geographic locations",
    "company name": "Employers", "government issued ids": "Government IDs",
}
IGNORED_TYPES = {"id", "origin", "qqmail"}  # LeakCheck bookkeeping fields, not personal data


def canonical_type(t: str) -> str | None:
    key = t.replace("_", " ").strip().lower()
    if not key or key in IGNORED_TYPES:
        return None
    return TYPE_ALIASES.get(key) or (t[:1].upper() + t[1:]).strip()


def split_types(text: str) -> list[str]:
    out = []
    for t in re.split(r"[;,]", text or ""):
        c = canonical_type(t)
        if c and c not in out:
            out.append(c)
    return out


# ---------------------------------------------------------------- sources

def check_xposedornot(email: str, fetch_json=fetch_json) -> dict:
    status, data = fetch_json(f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email)}")
    if status == 429:
        raise ScanError("rate limited, try again in a minute")
    if status != 200 or not isinstance(data, dict):
        raise ScanError(f"unexpected answer (HTTP {status})")
    details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
    breaches = []
    for b in details:
        breaches.append({
            "name": b.get("breach") or "Unknown",
            "domain": b.get("domain") or "",
            "date": str(b.get("xposed_date") or ""),
            "records": b.get("xposed_records") or 0,
            "description": b.get("details") or "",
            "data": split_types(b.get("xposed_data", "")),
            "password_risk": b.get("password_risk") or "",
            "verified": b.get("verified") == "Yes",
        })
    risk = None
    for r in ((data.get("BreachMetrics") or {}).get("risk") or []):
        risk = {"label": r.get("risk_label"), "score": r.get("risk_score")}
    pastes = (data.get("PastesSummary") or {}).get("cnt") or 0
    return {"breaches": breaches, "risk": risk, "pastes": pastes}


def check_leakcheck(email: str, fetch_json=fetch_json) -> dict:
    status, data = fetch_json(f"https://leakcheck.io/api/public?check={quote(email)}")
    if status == 429:
        raise ScanError("rate limited, try again in a minute")
    if status != 200 or not isinstance(data, dict):
        raise ScanError(f"unexpected answer (HTTP {status})")
    if not data.get("success"):
        if str(data.get("error", "")).lower() == "not found":
            return {"breaches": [], "fields": []}
        raise ScanError(data.get("error") or "lookup failed")
    breaches = [{"name": s.get("name") or "Unknown", "date": s.get("date") or ""} for s in data.get("sources", [])]
    # LeakCheck's free API lists exposed fields for the address as a whole, not per breach.
    return {"breaches": breaches, "fields": data.get("fields") or [], "total": data.get("found", len(breaches))}


def check_hibp(email: str, api_key: str, fetch_json=fetch_json) -> dict:
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
    status, data = fetch_json(url, {"hibp-api-key": api_key})
    if status == 404:
        return {"breaches": []}
    if status == 401:
        raise ScanError("the HIBP API key was rejected")
    if status == 429:
        raise ScanError("rate limited by HIBP, try again shortly")
    if status != 200 or not isinstance(data, list):
        raise ScanError(f"unexpected answer (HTTP {status})")
    breaches = []
    for b in data:
        breaches.append({
            "name": b.get("Title") or b.get("Name") or "Unknown",
            "domain": b.get("Domain") or "",
            "date": b.get("BreachDate") or "",
            "records": b.get("PwnCount") or 0,
            "description": re.sub(r"<[^>]+>", "", b.get("Description") or ""),
            "data": split_types(";".join(b.get("DataClasses") or [])),
            "verified": bool(b.get("IsVerified")),
        })
    return {"breaches": breaches}


def search_mentions(email: str, fetch=fetch, limit: int = 10, sleep: bool = True) -> list[dict]:
    """Public pages whose DuckDuckGo title or snippet actually contains the address."""
    url = "https://html.duckduckgo.com/html/?" + urlencode({"q": f'"{email}"'})
    for attempt in range(2):
        status, body = fetch(url, {"User-Agent": BROWSER_UA})
        # DuckDuckGo answers 202 with a captcha page when it throttles; one retry usually clears it
        throttled = status == 202 or "anomaly-modal" in body or "challenge-form" in body
        if not throttled:
            break
        time.sleep(3 if sleep else 0)
    if throttled:
        raise ScanError("DuckDuckGo is limiting searches right now, try again in a few minutes")
    if status != 200:
        raise ScanError(f"search unavailable (HTTP {status})")
    results, needle = [], email.lower()
    for block in re.split(r'<div class="result results_links', body)[1:]:
        link = re.search(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not link:
            continue
        href, title = html.unescape(link.group(1)), clean_html(link.group(2))
        snippet_m = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', block, re.S)
        snippet = clean_html(snippet_m.group(1)) if snippet_m else ""
        if href.startswith("//"):
            href = "https:" + href
        target = parse_qs(urlparse(href).query).get("uddg", [href])[0]  # unwrap DDG redirect
        if "duckduckgo.com/y.js" in target:  # ads
            continue
        if needle in (title + " " + snippet).lower() or needle in target.lower():
            results.append({"title": title, "url": target, "snippet": snippet})
        if len(results) >= limit:
            break
    return results


def clean_html(s: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()


def check_password(password: str, fetch=fetch) -> int:
    """How many times a password appears in Pwned Passwords. Only a 5-char hash prefix is sent."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    status, body = fetch(f"https://api.pwnedpasswords.com/range/{prefix}", {"Add-Padding": "true"})
    if status != 200:
        raise ScanError(f"Pwned Passwords unavailable (HTTP {status})")
    for line in body.splitlines():
        hash_suffix, _, count = line.strip().partition(":")
        if hash_suffix == suffix:
            return int(count or 0)
    return 0


# ---------------------------------------------------------------- scan + report

def scan(email: str, hibp_key: str | None = None, web: bool = True, sources: dict | None = None) -> dict:
    """Run every source in parallel and merge the results into one report dict.

    `sources` lets tests swap in fakes: {"xposedornot": fn, "leakcheck": fn, "hibp": fn, "web": fn}.
    """
    email = email.strip()
    if not is_valid_email(email):
        raise ValueError(f"'{email}' doesn't look like an email address")
    fns = {"xposedornot": check_xposedornot, "leakcheck": check_leakcheck,
           "hibp": check_hibp, "web": search_mentions, **(sources or {})}

    jobs = {"XposedOrNot": lambda: fns["xposedornot"](email),
            "LeakCheck": lambda: fns["leakcheck"](email)}
    if hibp_key:
        jobs["HaveIBeenPwned"] = lambda: fns["hibp"](email, hibp_key)
    if web:
        jobs["Web search"] = lambda: fns["web"](email)

    status, out = {}, {}
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, fut in futures.items():
            try:
                out[name] = fut.result()
                n = len(out[name]) if isinstance(out[name], list) else len(out[name]["breaches"])
                status[name] = {"ok": True, "count": n}
            except Exception as e:  # one broken source shouldn't sink the scan
                status[name] = {"ok": False, "error": str(e) or e.__class__.__name__}
    if not hibp_key:
        status["HaveIBeenPwned"] = {"ok": False, "skipped": True, "error": "no API key set"}
    if not web:
        status["Web search"] = {"ok": False, "skipped": True, "error": "turned off"}

    breaches = merge_breaches({k: v["breaches"] for k, v in out.items() if isinstance(v, dict)})
    exposed = set()
    for b in breaches:
        exposed.update(b["data"])
    exposed.update(filter(None, map(canonical_type, (out.get("LeakCheck") or {}).get("fields", []))))

    report = {
        "email": email,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "version": __version__,
        "sources": status,
        "breaches": breaches,
        "exposed_data": sorted(exposed, key=str.lower),
        "mentions": out.get("Web search", []),
        "pastes": (out.get("XposedOrNot") or {}).get("pastes", 0),
        "leakcheck_total": (out.get("LeakCheck") or {}).get("total", 0),
    }
    report["risk"] = assess_risk(report, (out.get("XposedOrNot") or {}).get("risk"))
    report["advice"] = advice(report)
    return report


def breach_keys(b: dict) -> list[str]:
    keys = [norm_key(b["name"])]
    if b.get("domain"):
        keys.append(norm_key(b["domain"]))
    return [k for k in keys if k]


def merge_breaches(by_source: dict) -> list[dict]:
    """One entry per breach, even when several services report it under different names.

    'Baxter.com' (LeakCheck) and 'BaxterInternational' with domain baxter.com (XposedOrNot) match
    on the domain; 'StockX.com' and 'StockX' match on the name.
    """
    merged: list[dict] = []
    index: dict[str, dict] = {}
    # sources with domains go first so their keys are known when name-only sources arrive
    order = sorted(by_source, key=lambda s: not any(b.get("domain") for b in by_source[s]))
    for source in order:
        for b in by_source[source]:
            keys = breach_keys(b) or [b["name"]]
            m = next((index[k] for k in keys if k in index), None)
            if m is None:
                m = {"name": b["name"], "domain": "", "date": "", "records": 0,
                     "description": "", "data": [], "sources": []}
                merged.append(m)
            for k in keys:
                index.setdefault(k, m)
            if source not in m["sources"]:
                m["sources"].append(source)
            for field in ("domain", "description"):
                if not m[field] and b.get(field):
                    m[field] = b[field]
            if len(b.get("date") or "") > len(m["date"]):  # prefer "2019-07" over "2019"
                m["date"] = b["date"]
            m["records"] = max(m["records"], b.get("records") or 0)
            for d in b.get("data", []):
                if d not in m["data"]:
                    m["data"].append(d)
            if b.get("password_risk"):
                m["password_risk"] = b["password_risk"]
    # newest first; undated at the end
    return sorted(merged, key=lambda b: (b["date"] or "0000", b["name"].lower()), reverse=True)


def has_type(types, wanted: set) -> bool:
    return any(t.lower().strip() in wanted for t in types)


def assess_risk(report: dict, xon_risk: dict | None = None) -> dict:
    breaches = report["breaches"]
    n = len(breaches)
    pw = sum(1 for b in breaches if has_type(b["data"], PASSWORD_TYPES))
    plaintext = sum(1 for b in breaches if (b.get("password_risk") or "").lower() in ("plaintext", "easytocrack"))
    sensitive = has_type(report["exposed_data"], SENSITIVE_TYPES)
    leak_pw = has_type(report["exposed_data"], PASSWORD_TYPES)

    score = min(40, n * 4) + min(30, pw * 6) + min(15, plaintext * 5) + (10 if sensitive else 0)
    score += 5 if report["mentions"] else 0
    if leak_pw and not pw:
        score += 10
    if xon_risk and isinstance(xon_risk.get("score"), (int, float)):
        score = max(score, int(xon_risk["score"]) if n else 0)
    score = max(0, min(100, score))
    label = ("None" if n == 0 and not report["mentions"] else
             "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical")
    return {"score": score, "label": label, "breaches": n, "password_breaches": pw, "sensitive": sensitive}


def advice(report: dict) -> list[str]:
    risk, tips = report["risk"], []
    if risk["breaches"] == 0:
        tips.append("No known breaches found. Keep using a unique password for every site.")
    if risk["password_breaches"] or has_type(report["exposed_data"], PASSWORD_TYPES):
        tips.append("Passwords tied to this email were leaked: change them anywhere you reused one, starting with email and banking.")
    if risk["breaches"]:
        tips.append("Turn on two-factor authentication (an authenticator app or passkey) for your email account first.")
        tips.append("Use a password manager so every site gets its own random password.")
        tips.append("Expect phishing: leaked emails get targeted scam messages that mention the breached site.")
    if risk["sensitive"]:
        tips.append("Personal details (phone, address, date of birth or IDs) leaked: consider a credit freeze and watch for SIM-swap or identity fraud.")
    if report["mentions"]:
        tips.append("Your address appears on public pages: ask site owners to remove it if you didn't publish it.")
    return tips


def report_text(r: dict) -> str:
    lines = [
        f"Email Leak Scanner report  v{r['version']}",
        f"Email:    {r['email']}",
        f"Scanned:  {r['scanned_at']}",
        f"Risk:     {r['risk']['label']} ({r['risk']['score']}/100)",
        "",
        "Sources:",
    ]
    for name, s in r["sources"].items():
        state = f"{s['count']} found" if s.get("ok") else ("skipped: " if s.get("skipped") else "error: ") + s["error"]
        lines.append(f"  - {name}: {state}")
    lines += ["", f"Breaches ({len(r['breaches'])}):"]
    for b in r["breaches"]:
        head = f"  - {b['name']}"
        if b["date"]:
            head += f" ({b['date']})"
        if b["records"]:
            head += f", {b['records']:,} accounts"
        lines.append(head)
        if b["data"]:
            lines.append(f"      exposed: {', '.join(b['data'])}")
        lines.append(f"      reported by: {', '.join(b['sources'])}")
    if not r["breaches"]:
        lines.append("  none found")
    if r["exposed_data"]:
        lines += ["", "Exposed data types:", "  " + ", ".join(r["exposed_data"])]
    lines += ["", f"Public web mentions ({len(r['mentions'])}):"]
    for m in r["mentions"]:
        lines.append(f"  - {m['title']}\n      {m['url']}")
    if not r["mentions"]:
        lines.append("  none found")
    lines += ["", "What to do:"] + [f"  - {t}" for t in r["advice"]]
    return "\n".join(lines) + "\n"


def safe_filename(email: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", email.replace("@", "_at_"))


def save_report(r: dict, folder: str = "reports", fmt: str = "txt") -> str:
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join(folder, f"{safe_filename(r['email'])}_{stamp}.{fmt}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(r, indent=2) if fmt == "json" else report_text(r))
    return path


# ---------------------------------------------------------------- config

def config_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".emailleakscanner.json")


def load_config() -> dict:
    try:
        with open(config_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    with open(config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env reader (KEY=value lines) so HIBP_API_KEY can live next to the script."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key and not key.startswith("#"):
                    os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    except OSError:
        pass


def hibp_key() -> str | None:
    load_dotenv()
    return os.environ.get("HIBP_API_KEY") or load_config().get("hibp_api_key") or None


# ---------------------------------------------------------------- CLI

class C:
    """ANSI colors, blank when output isn't a terminal."""
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RED, YEL, GRN, CYN, DIM, BOLD, END = (("\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[2m", "\033[1m", "\033[0m")
                                          if on else ("",) * 7)


RISK_COLOR = {"None": C.GRN, "Low": C.GRN, "Medium": C.YEL, "High": C.RED, "Critical": C.RED}


def print_report(r: dict, limit: int = 25) -> None:
    risk = r["risk"]
    print(f"\n{C.BOLD}{r['email']}{C.END}  risk: {RISK_COLOR[risk['label']]}{C.BOLD}{risk['label']}{C.END} ({risk['score']}/100)")
    for name, s in r["sources"].items():
        if s.get("ok"):
            print(f"  {C.GRN}✓{C.END} {name}: {s['count']} found")
        elif s.get("skipped"):
            print(f"  {C.DIM}- {name}: skipped ({s['error']}){C.END}")
        else:
            print(f"  {C.YEL}!{C.END} {name}: {s['error']}")
    if r["breaches"]:
        print(f"\n{C.BOLD}Breaches ({len(r['breaches'])}){C.END}")
        for b in r["breaches"][:limit]:
            pw = has_type(b["data"], PASSWORD_TYPES)
            mark = f"{C.RED}●{C.END}" if pw else f"{C.YEL}●{C.END}"
            when = f" {C.DIM}{b['date']}{C.END}" if b["date"] else ""
            print(f"  {mark} {b['name']}{when}")
            if b["data"]:
                print(f"      {C.DIM}{', '.join(b['data'])}{C.END}")
        if len(r["breaches"]) > limit:
            print(f"  {C.DIM}…and {len(r['breaches']) - limit} more (use --all, --save or --json for the full list){C.END}")
    else:
        print(f"\n{C.GRN}No known breaches found.{C.END}")
    if r["exposed_data"]:
        print(f"\n{C.BOLD}Exposed data types{C.END}\n  {', '.join(r['exposed_data'])}")
    if r["mentions"]:
        print(f"\n{C.BOLD}Public web mentions ({len(r['mentions'])}){C.END}")
        for m in r["mentions"]:
            print(f"  - {m['title']}\n    {C.CYN}{m['url']}{C.END}")
    print(f"\n{C.BOLD}What to do{C.END}")
    for t in r["advice"]:
        print(f"  - {t}")


def run_password_check() -> None:
    pw = getpass.getpass("Password to check (hidden, never sent): ")
    if not pw:
        return
    try:
        n = check_password(pw)
    except ScanError as e:
        print(f"{C.YEL}Couldn't check: {e}{C.END}")
        return
    if n:
        print(f"{C.RED}{C.BOLD}Found {n:,} times in known leaks.{C.END} Stop using this password.")
    else:
        print(f"{C.GRN}Not found in known leaks.{C.END} That's good, but still use it on one site only.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("emails", nargs="*", help="email addresses to scan")
    ap.add_argument("-f", "--file", help="text file with one email per line")
    ap.add_argument("--json", action="store_true", help="print the full report(s) as JSON")
    ap.add_argument("--save", metavar="DIR", help="save a report per email into DIR")
    ap.add_argument("--format", choices=["txt", "json"], default="txt", help="format for --save (default: txt)")
    ap.add_argument("--all", action="store_true", help="list every breach instead of the newest 25")
    ap.add_argument("--no-web", action="store_true", help="skip the public web search")
    ap.add_argument("--hibp-key", help="HaveIBeenPwned API key (or set HIBP_API_KEY)")
    ap.add_argument("--password", action="store_true", help="check a password against Pwned Passwords")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if os.name == "nt":
        os.system("")  # turns on ANSI colors in the Windows console

    if args.password:
        run_password_check()
        return 0

    emails = list(args.emails)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            emails += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    key = args.hibp_key or hibp_key()

    if not emails:
        return interactive(key, not args.no_web)

    reports, failed = [], 0
    for i, email in enumerate(emails):
        if i:
            time.sleep(1.5)  # be polite to the free APIs
        try:
            r = scan(email, key, web=not args.no_web)
        except ValueError as e:
            print(f"{C.RED}{e}{C.END}", file=sys.stderr)
            failed += 1
            continue
        reports.append(r)
        if not args.json:
            print_report(r, limit=len(r["breaches"]) if args.all else 25)
        if args.save:
            path = save_report(r, args.save, args.format)
            print(f"{C.DIM}saved {path}{C.END}", file=sys.stderr)
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
    return 1 if failed else 0


def interactive(key: str | None, web: bool) -> int:
    print(f"{C.BOLD}Email Leak Scanner {__version__}{C.END}  {C.DIM}(Ctrl+C to quit){C.END}")
    if not key:
        print(f"{C.DIM}Tip: set HIBP_API_KEY to add HaveIBeenPwned results.{C.END}")
    try:
        while True:
            email = input(f"\n{C.CYN}Email to scan (or 'p' to check a password): {C.END}").strip()
            if not email:
                continue
            if email.lower() == "p":
                run_password_check()
                continue
            if not is_valid_email(email):
                print(f"{C.RED}That doesn't look like an email address.{C.END}")
                continue
            print(f"{C.DIM}Scanning…{C.END}")
            r = scan(email, key, web=web)
            print_report(r)
            if input(f"\n{C.CYN}Save a report? (y/N): {C.END}").strip().lower() == "y":
                print(f"{C.GRN}Saved {save_report(r)}{C.END}")
    except (KeyboardInterrupt, EOFError):
        print("\nStay safe out there.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
