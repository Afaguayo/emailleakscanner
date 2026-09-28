"""Offline tests: every network call is replaced by a fake. Run with `python -m unittest -v`."""
import hashlib
import json
import os
import tempfile
import unittest

import emailleakscanner as s

EMAIL = "someone@example.com"

XON = {
    "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 60}]},
    "ExposedBreaches": {"breaches_details": [
        {"breach": "BaxterInternational", "domain": "baxter.com", "xposed_date": "2026",
         "xposed_records": 488992, "details": "Healthcare breach.", "password_risk": "unknown",
         "xposed_data": "Email addresses;Names;Physical addresses;", "verified": "Yes"},
        {"breach": "StockX", "domain": "stockx.com", "xposed_date": "2019", "xposed_records": 6840339,
         "details": "Sneaker marketplace.", "password_risk": "easytocrack",
         "xposed_data": "Email addresses;Passwords;Usernames", "verified": "Yes"},
    ]},
    "PastesSummary": {"cnt": 2},
}
LEAKCHECK = {"success": True, "found": 3, "fields": ["password", "dob", "ip1", "id", "first_name"],
             "sources": [{"name": "StockX.com", "date": "2019-07"}, {"name": "Baxter.com", "date": "2026-08"},
                         {"name": "Luxottica", "date": "2021-03"}]}
HIBP = [{"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
         "PwnCount": 152445165, "Description": "<a href='#'>Adobe</a> was breached.",
         "DataClasses": ["Email addresses", "Password hints", "Passwords"], "IsVerified": True}]

DDG_HTML = """
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title"><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fforum.example.org%2Fthread%2F1&amp;rut=abc">Contact list &amp; more</a></h2>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=x">Reach me at <b>someone@example.com</b> any time.</a>
</div>
<div class="result results_links results_links_deep web-result ">
  <h2 class="result__title"><a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Funrelated.example.com%2F&amp;rut=def">Unrelated page</a></h2>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=y">Nothing to see here.</a>
</div>
"""


def fake_json(payload, status=200):
    return lambda url, headers=None: (status, payload)


class Validation(unittest.TestCase):
    def test_valid(self):
        for e in ["a@b.co", "first.last+tag@sub.example.com", "x_y@domain.io"]:
            self.assertTrue(s.is_valid_email(e), e)

    def test_invalid(self):
        for e in ["", "plain", "a@b", "@b.com", "a@.com", "a b@c.com", "a@b.c"]:
            self.assertFalse(s.is_valid_email(e), e)

    def test_scan_rejects_bad_email(self):
        with self.assertRaises(ValueError):
            s.scan("not-an-email")


class Sources(unittest.TestCase):
    def test_xposedornot(self):
        r = s.check_xposedornot(EMAIL, fetch_json=fake_json(XON))
        self.assertEqual([b["name"] for b in r["breaches"]], ["BaxterInternational", "StockX"])
        self.assertEqual(r["breaches"][1]["data"], ["Email addresses", "Passwords", "Usernames"])
        self.assertEqual(r["risk"], {"label": "High", "score": 60})
        self.assertEqual(r["pastes"], 2)

    def test_xposedornot_not_found(self):
        empty = {"BreachMetrics": None, "ExposedBreaches": None, "PastesSummary": {"cnt": 0}}
        self.assertEqual(s.check_xposedornot(EMAIL, fetch_json=fake_json(empty))["breaches"], [])

    def test_xposedornot_rate_limited(self):
        with self.assertRaisesRegex(s.ScanError, "rate limited"):
            s.check_xposedornot(EMAIL, fetch_json=fake_json(None, 429))

    def test_leakcheck(self):
        r = s.check_leakcheck(EMAIL, fetch_json=fake_json(LEAKCHECK))
        self.assertEqual(len(r["breaches"]), 3)
        self.assertEqual(r["total"], 3)

    def test_leakcheck_not_found(self):
        r = s.check_leakcheck(EMAIL, fetch_json=fake_json({"success": False, "error": "Not found"}))
        self.assertEqual(r["breaches"], [])

    def test_leakcheck_other_error(self):
        with self.assertRaises(s.ScanError):
            s.check_leakcheck(EMAIL, fetch_json=fake_json({"success": False, "error": "Limit reached"}))

    def test_hibp(self):
        seen = {}

        def fj(url, headers=None):
            seen.update(headers or {})
            return 200, HIBP
        r = s.check_hibp(EMAIL, "KEY", fetch_json=fj)
        self.assertEqual(seen["hibp-api-key"], "KEY")
        self.assertEqual(r["breaches"][0]["description"], "Adobe was breached.")
        self.assertIn("Passwords", r["breaches"][0]["data"])

    def test_hibp_not_found_and_bad_key(self):
        self.assertEqual(s.check_hibp(EMAIL, "K", fetch_json=fake_json(None, 404))["breaches"], [])
        with self.assertRaisesRegex(s.ScanError, "rejected"):
            s.check_hibp(EMAIL, "K", fetch_json=fake_json(None, 401))

    def test_mentions_keep_only_pages_containing_the_email(self):
        r = s.search_mentions(EMAIL, fetch=lambda url, headers=None: (200, DDG_HTML))
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["url"], "https://forum.example.org/thread/1")
        self.assertEqual(r[0]["title"], "Contact list & more")
        self.assertIn(EMAIL, r[0]["snippet"])

    def test_mentions_throttled(self):
        with self.assertRaisesRegex(s.ScanError, "limiting"):
            s.search_mentions(EMAIL, fetch=lambda url, headers=None: (202, "anomaly-modal"), sleep=False)


class Password(unittest.TestCase):
    def test_only_hash_prefix_is_sent(self):
        sha1 = hashlib.sha1(b"hunter2").hexdigest().upper()
        urls = []

        def f(url, headers=None):
            urls.append(url)
            return 200, f"0000000000000000000000000000000000A:1\r\n{sha1[5:]}:4242\r\n"
        self.assertEqual(s.check_password("hunter2", fetch=f), 4242)
        self.assertTrue(urls[0].endswith("/range/" + sha1[:5]))
        self.assertNotIn("hunter2", urls[0])

    def test_not_found(self):
        self.assertEqual(s.check_password("x", fetch=lambda url, headers=None: (200, "ABC:1")), 0)


class Merge(unittest.TestCase):
    def test_types_are_canonical(self):
        self.assertEqual(s.canonical_type("dob"), "Dates of birth")
        self.assertEqual(s.canonical_type("first_name"), "Names")
        self.assertEqual(s.canonical_type("ip2"), "IP addresses")
        self.assertIsNone(s.canonical_type("qqmail"))
        self.assertEqual(s.split_types("Passwords;password;Names;"), ["Passwords", "Names"])

    def test_same_breach_from_two_services_is_merged(self):
        xon = s.check_xposedornot(EMAIL, fetch_json=fake_json(XON))["breaches"]
        lc = s.check_leakcheck(EMAIL, fetch_json=fake_json(LEAKCHECK))["breaches"]
        merged = s.merge_breaches({"LeakCheck": lc, "XposedOrNot": xon})
        names = {b["name"]: b for b in merged}
        self.assertEqual(len(merged), 3)  # Baxter (by domain), StockX (by name), Luxottica
        self.assertEqual(sorted(names["StockX"]["sources"]), ["LeakCheck", "XposedOrNot"])
        self.assertEqual(sorted(names["BaxterInternational"]["sources"]), ["LeakCheck", "XposedOrNot"])
        self.assertEqual(names["StockX"]["date"], "2019-07")  # the more precise date wins
        self.assertEqual([b["name"] for b in merged], ["BaxterInternational", "Luxottica", "StockX"])


def fake_sources(**over):
    base = {
        "xposedornot": lambda e: s.check_xposedornot(e, fetch_json=fake_json(XON)),
        "leakcheck": lambda e: s.check_leakcheck(e, fetch_json=fake_json(LEAKCHECK)),
        "hibp": lambda e, k: s.check_hibp(e, k, fetch_json=fake_json(HIBP)),
        "web": lambda e: s.search_mentions(e, fetch=lambda url, headers=None: (200, DDG_HTML)),
    }
    base.update(over)
    return base


class Scan(unittest.TestCase):
    def test_full_scan(self):
        r = s.scan(EMAIL, hibp_key="K", sources=fake_sources())
        self.assertEqual(len(r["breaches"]), 4)
        self.assertEqual(r["sources"]["HaveIBeenPwned"], {"ok": True, "count": 1})
        self.assertEqual(len(r["mentions"]), 1)
        self.assertIn("Dates of birth", r["exposed_data"])
        self.assertNotIn("Id", r["exposed_data"])
        self.assertIn(r["risk"]["label"], ("High", "Critical"))
        self.assertTrue(any("two-factor" in t for t in r["advice"]))
        json.dumps(r)  # the GUI sends it as JSON

    def test_a_broken_source_does_not_sink_the_scan(self):
        def boom(e):
            raise s.ScanError("couldn't connect (offline)")
        r = s.scan(EMAIL, sources=fake_sources(leakcheck=boom))
        self.assertFalse(r["sources"]["LeakCheck"]["ok"])
        self.assertIn("offline", r["sources"]["LeakCheck"]["error"])
        self.assertEqual(len(r["breaches"]), 2)

    def test_skipped_sources(self):
        r = s.scan(EMAIL, web=False, sources=fake_sources())
        self.assertTrue(r["sources"]["HaveIBeenPwned"]["skipped"])
        self.assertTrue(r["sources"]["Web search"]["skipped"])

    def test_clean_email(self):
        none = lambda e: {"breaches": [], "fields": [], "pastes": 0, "risk": None}
        r = s.scan(EMAIL, sources=fake_sources(xposedornot=none, leakcheck=none, web=lambda e: []))
        self.assertEqual(r["risk"]["label"], "None")
        self.assertEqual(r["risk"]["score"], 0)


class Reports(unittest.TestCase):
    def test_text_and_save(self):
        r = s.scan(EMAIL, sources=fake_sources())
        text = s.report_text(r)
        self.assertIn("StockX (2019-07)", text)
        self.assertIn("reported by:", text)
        with tempfile.TemporaryDirectory() as d:
            for fmt in ("txt", "json"):
                path = s.save_report(r, d, fmt)
                self.assertTrue(os.path.basename(path).startswith("someone_at_example.com_"))
                self.assertTrue(path.endswith("." + fmt))
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f)["email"], EMAIL)

    def test_filename_is_safe(self):
        self.assertEqual(s.safe_filename("a/../b@x.com"), "a_.._b_at_x.com")


if __name__ == "__main__":
    unittest.main()
