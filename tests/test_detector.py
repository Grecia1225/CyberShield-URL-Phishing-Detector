import os
import sys
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from detector import analyze_url

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

if __name__ == "__main__":
    unittest.main()
