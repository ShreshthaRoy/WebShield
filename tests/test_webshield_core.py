import tempfile
import unittest
from pathlib import Path

from history_store import HISTORY_COLUMNS, append_scan
import history_store
from risk_engine import calculate_domain_risk, calculate_final_risk, calculate_page_risk
from url_validation import validate_url


TRUSTED = ["google.com", "microsoft.com", "bit-bangalore.edu.in", "github.com", "paypal.com"]


class URLValidationTests(unittest.TestCase):
    def test_adds_https_and_preserves_path_case(self):
        url, error = validate_url("Example.com/CaseSensitive?Token=AbC")
        self.assertIsNone(error)
        self.assertEqual(url, "https://example.com/CaseSensitive?Token=AbC")

    def test_rejects_non_web_scheme(self):
        url, error = validate_url("javascript:alert(1)")
        self.assertIsNone(url)
        self.assertIn("HTTP and HTTPS", error)

    def test_rejects_credentials(self):
        url, error = validate_url("https://user:secret@example.com")
        self.assertIsNone(url)
        self.assertIn("username", error)

    def test_rejects_bad_port_and_spaces(self):
        self.assertIsNotNone(validate_url("https://example.com:bad")[1])
        self.assertIsNotNone(validate_url("https://example.com/a b")[1])


class RiskEngineTests(unittest.TestCase):
    def test_bit_official_host_is_trusted(self):
        risk, unknown, _ = calculate_domain_risk("bit-bangalore.edu.in", TRUSTED)
        self.assertEqual(risk, 0)
        self.assertFalse(unknown)
        from risk_engine import calculate_url_risk
        url_risk, _ = calculate_url_risk("https://bit-bangalore.edu.in/ise-about")
        self.assertEqual(url_risk, 0)

    def test_trusted_domain_adjustment_is_explicit(self):
        score, breakdown = calculate_final_risk(1.0, 1.0, 0, 0, None, True)
        self.assertEqual(score, 20)
        self.assertTrue(breakdown["trusted_domain_adjustment"])

    def test_bit_lookalike_is_not_trusted(self):
        risk, unknown, reasons = calculate_domain_risk("bit-banglore.edu.in", TRUSTED)
        self.assertGreater(risk, 0)
        self.assertTrue(unknown)
        self.assertTrue(any("resembles trusted domain" in reason for reason in reasons))

    def test_nested_subdomain_is_not_automatically_trusted(self):
        risk, unknown, reasons = calculate_domain_risk("login.bit-bangalore.edu.in", TRUSTED)
        self.assertGreater(risk, 0)
        self.assertTrue(unknown)
        self.assertTrue(any("Subdomain is not automatically trusted" in reason for reason in reasons))

    def test_missing_page_telemetry_is_not_zero_risk(self):
        page_risk, _ = calculate_page_risk({})
        self.assertIsNone(page_risk)
        score, breakdown = calculate_final_risk(.8, .9, 10, 15, None, False)
        self.assertGreater(score, 0)
        self.assertFalse(breakdown["page_analysis_available"])
        self.assertIsNone(breakdown["page_risk"])

    def test_external_form_action_is_a_signal(self):
        score, reasons = calculate_page_risk({
            "forms": 1, "password_fields": 1, "iframes": 0,
            "external_links": 1, "external_form_actions": 1, "https": True,
        })
        self.assertGreaterEqual(score, 40)
        self.assertTrue(any("different hostname" in reason for reason in reasons))


class HistoryTests(unittest.TestCase):
    def test_history_has_one_consistent_schema(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original = history_store.HISTORY_PATH
            history_store.HISTORY_PATH = Path(temp_dir) / "history.csv"
            try:
                # Seed the prior 10-column format, then verify automatic migration.
                history_store.HISTORY_PATH.write_text(
                    "url,risk_score,status,ml_score,dl_score,model_score,url_risk,domain_risk,page_risk,time\n"
                    "https://old.example/,12,SAFE,10,8,9,0,20,0,2026-10-01T10:00:00\n",
                    encoding="utf-8",
                )
                append_scan({"url": "https://bit-bangalore.edu.in/", "risk_score": 4,
                             "status": "SAFE", "ml_score": 2, "dl_score": 3,
                             "model_score": 2.5, "url_risk": 0, "domain_risk": 0,
                             "page_risk": None, "page_analysis_available": False})
                import csv
                with history_store.HISTORY_PATH.open(newline="", encoding="utf-8") as handle:
                    rows = list(csv.reader(handle))
                self.assertEqual(rows[0], HISTORY_COLUMNS)
                self.assertEqual(len(rows[1]), len(HISTORY_COLUMNS))
                self.assertEqual(len(rows[2]), len(HISTORY_COLUMNS))
                self.assertEqual(rows[1][0], "https://old.example/")
            finally:
                history_store.HISTORY_PATH = original


if __name__ == "__main__":
    unittest.main()
