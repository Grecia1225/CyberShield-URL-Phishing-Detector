import os
import sys
import unittest
from unittest import mock
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
import app as app_module

FAKE = {"points": 30, "reasons": ["The domain was registered only 2 day(s) ago; new domains are common in phishing."],
        "details": {"resolved_ip": "1.2.3.4", "domain_age_days": 2, "safe_browsing": "no match"}, "force_high": False}

class ApiTests(unittest.TestCase):
    def setUp(self):
        app_module._hits.clear()
        self.client = app_module.app.test_client()

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")

    def test_scan_adds_online_signals(self):
        with mock.patch.object(app_module, "enrich", return_value=FAKE):
            data = self.client.post("/api/scan", json={"url": "https://avzo.hzunx.xyz/VHFPileln/c197e1a8987792744ca0ed4d83"}).get_json()
        self.assertGreaterEqual(data["risk_score"], 30)
        self.assertIn(data["label"], {"SUSPICIOUS", "HIGH RISK"})
        self.assertEqual(data["details"]["domain_age_days"], 2)

    def test_safe_browsing_match_forces_high(self):
        fake = dict(FAKE, points=60, force_high=True)
        with mock.patch.object(app_module, "enrich", return_value=fake):
            data = self.client.post("/api/scan", json={"url": "https://example.com"}).get_json()
        self.assertEqual(data["label"], "HIGH RISK")

    def test_lookup_failure_does_not_break_scan(self):
        with mock.patch.object(app_module, "enrich", side_effect=RuntimeError("boom")):
            r = self.client.post("/api/scan", json={"url": "https://www.google.com"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["risk_score"], 0)

    def test_bad_input(self):
        self.assertEqual(self.client.post("/api/scan", json={"url": 123}).status_code, 400)
        self.assertEqual(self.client.post("/api/scan", json={"url": ""}).status_code, 400)

    def test_rate_limit(self):
        with mock.patch.object(app_module, "enrich", return_value=FAKE):
            codes = [self.client.post("/api/scan", json={"url": "example.com"}).status_code for _ in range(22)]
        self.assertEqual(codes[:20], [200] * 20)
        self.assertEqual(codes[20], 429)

if __name__ == "__main__":
    unittest.main()
