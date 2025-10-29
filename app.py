# test_cors_checker.py
import unittest
from unittest.mock import Mock, patch
import cors_checker


def _make_resp(headers: dict):
    """
    Utility to create a simple mock response object with a headers attribute.
    """
    resp = Mock()
    # ensure dict-like .headers.get works
    resp.headers = headers
    return resp


class TestCORSChecker(unittest.TestCase):
    fake_origin = "https://evil-attacker.com"

    @patch("cors_checker._get_session")
    def test_reflection_detection(self, mock_get_session):
        """
        If the server reflects the attacker origin in Access-Control-Allow-Origin, we expect a High severity reflection finding.
        """
        # Prepare mock responses
        orig_get = _make_resp({})
        orig_options = _make_resp({})
        # Probe GET/OPTIONS respond with ACAO reflecting fake_origin
        probe_get = _make_resp({"Access-Control-Allow-Origin": self.fake_origin})
        probe_options = _make_resp({"Access-Control-Allow-Origin": self.fake_origin})

        # Mock session: get() called twice (orig_get, probe_get); options() twice (orig_options, probe_options)
        session = Mock()
        session.get.side_effect = [orig_get, probe_get]
        session.options.side_effect = [orig_options, probe_options]
        mock_get_session.return_value = session

        findings = cors_checker.analyze_cors("http://example.test", fake_origin=self.fake_origin)
        descriptions = " ".join(f["Description"] for f in findings)
        self.assertIn("reflected attacker Origin", descriptions.lower())

    @patch("cors_checker._get_session")
    def test_wildcard_with_credentials_detection(self, mock_get_session):
        """
        If ACAO is '*' and ACAC is 'true', expect a High severity critical finding.
        """
        orig_get = _make_resp({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        orig_options = _make_resp({})
        probe_get = _make_resp({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        probe_options = _make_resp({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})

        session = Mock()
        session.get.side_effect = [orig_get, probe_get]
        session.options.side_effect = [orig_options, probe_options]
        mock_get_session.return_value = session

        findings = cors_checker.analyze_cors("http://example.test", fake_origin=self.fake_origin)
        # Look for the wildcard+credentials description
        found = any("wildcard" in f["Description"].lower() and "credentials" in f["Description"].lower() for f in findings)
        self.assertTrue(found, f"Expected wildcard+credentials finding, got: {findings}")

    @patch("cors_checker._get_session")
    def test_missing_vary_detection(self, mock_get_session):
        """
        If server returns a specific Access-Control-Allow-Origin but no 'Vary: Origin', expect a Medium severity finding about missing Vary.
        """
        # orig responses empty
        orig_get = _make_resp({})
        orig_options = _make_resp({})
        # probe returns ACAO = specific allowed origin but Vary missing
        probe_get = _make_resp({"Access-Control-Allow-Origin": "https://good.example.com"})
        probe_options = _make_resp({"Access-Control-Allow-Origin": "https://good.example.com"})

        session = Mock()
        session.get.side_effect = [orig_get, probe_get]
        session.options.side_effect = [orig_options, probe_options]
        mock_get_session.return_value = session

        findings = cors_checker.analyze_cors("http://example.test", fake_origin=self.fake_origin)
        # Expect a finding mentioning "Missing 'Vary: Origin'"
        found = any("vary" in f["Description"].lower() for f in findings)
        self.assertTrue(found, f"Expected missing Vary finding, got: {findings}")

    @patch("cors_checker._get_session")
    def test_unsafe_methods_exposed_detection(self, mock_get_session):
        """
        If Access-Control-Allow-Methods exposes unsafe methods (e.g., PUT or DELETE) via preflight/OPTIONS, expect detection.
        """
        orig_get = _make_resp({})
        orig_options = _make_resp({})
        probe_get = _make_resp({})
        # preflight returns Allow-Methods containing PUT and DELETE
        probe_options = _make_resp({"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE"})

        session = Mock()
        session.get.side_effect = [orig_get, probe_get]
        session.options.side_effect = [orig_options, probe_options]
        mock_get_session.return_value = session

        findings = cors_checker.analyze_cors("http://example.test", fake_origin=self.fake_origin)
        # Find description mentioning unsafe methods
        found = any("unsafe http methods" in f["Description"].lower() or "unsafe methods" in f["Description"].lower() for f in findings)
        # Alternatively, check that method names appear in Description
        contains_put = any("put" in f["Description"].lower() for f in findings)
        self.assertTrue(found or contains_put, f"Expected unsafe methods finding, got: {findings}")


if __name__ == "__main__":
    unittest.main()
