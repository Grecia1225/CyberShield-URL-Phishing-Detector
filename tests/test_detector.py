import os
import sys
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from detector import analyze_url, label_for, registered_domain

class DetectorTests(unittest.TestCase):
    def test_normalizes_missing_scheme(self):
        result = analyze_url("example.com")
        self.assertEqual(result["hostname"], "example.com")
        self.assertTrue(result["normalized_url"].startswith("http://"))

    def test_http_and_password_terms_raise_score(self):
        result = analyze_url("http://account-verify-login-example.invalid/signin")
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertIn(result["label"], {"SUSPICIOUS", "HIGH RISK"})

    def test_punycode_flag(self):
        result = analyze_url("https://xn--example-ova.invalid")
        self.assertTrue(any("punycode" in reason.lower() for reason in result["reasons"]))

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            analyze_url("javascript:alert(1)")

    def test_rejects_empty_url(self):
        with self.assertRaises(ValueError):
            analyze_url("")

    # --- tests for the fixes ---
    def test_real_brand_domains_not_flagged(self):
        for url in ["https://www.google.com", "https://accounts.google.com",
                    "https://www.paypal.com", "https://www.amazon.in", "https://mail.google.co.in"]:
            with self.subTest(url=url):
                self.assertFalse(any("brand" in r.lower() for r in analyze_url(url)["reasons"]))
        self.assertEqual(analyze_url("https://www.google.com")["risk_score"], 0)

    def test_fake_brand_domains_flagged(self):
        for url in ["https://paypal.com.evil.top/x", "https://secure-paypal-login.xyz", "https://google.evil.com"]:
            with self.subTest(url=url):
                self.assertTrue(any("brand" in r.lower() for r in analyze_url(url)["reasons"]))

    def test_random_domain_and_abused_tld(self):
        reasons = " ".join(analyze_url("https://avzo.hzunx.xyz/VHFPileln/c197e1a8987792744ca0ed4d83?p=w")["reasons"])
        self.assertIn(".xyz", reasons)
        self.assertIn("randomly generated", reasons)
        self.assertIn("hex", reasons)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(registered_domain("www.bbc.co.uk"), "bbc.co.uk")

    def test_label_thresholds(self):
        self.assertEqual(label_for(29), "LOW RISK")
        self.assertEqual(label_for(30), "SUSPICIOUS")
        self.assertEqual(label_for(60), "HIGH RISK")

if __name__ == "__main__":
    unittest.main()
