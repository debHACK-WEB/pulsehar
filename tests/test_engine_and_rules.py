import json
import unittest
from engine import AnalysisEngine
from exporters.summary_reporter import SummaryReporter
from models import Finding, HTTPExchange
from rules.base import BaseRule
from rules.cookie_security import CookieSecurityRule
from rules.sensitive_params import SensitiveParamsRule


class _BrokenRule(BaseRule):
    rule_id = "PH-ERR-001"
    title = "Simulated Rule Failure"
    severity = "High"
    confidence = "Firm"
    description = "Always raises an error to verify fault isolation."
    remediation = "Fix rule implementation."

    def check(self, exchange: HTTPExchange) -> list[Finding]:
        raise RuntimeError("boom inside rule")


class TestEngineAndRules(unittest.TestCase):
    def _make_exchange(
        self,
        url: str = "https://example.com/app",
        status: int = 200,
        response_headers: dict | None = None,
    ) -> HTTPExchange:
        return HTTPExchange(
            method="GET",
            url=url,
            status=status,
            request_headers={},
            response_headers=response_headers or {},
            request_body="",
            response_body="",
        )

    def test_cookie_expires_comma_and_session_cookie_without_expires(self):
        rule = CookieSecurityRule()
        # Session cookie without Expires/Max-Age (with Secure, HttpOnly, SameSite)
        # followed by a cookie whose Expires contains a comma.
        exchange = self._make_exchange(
            url="https://example.com/dashboard",
            response_headers={
                "set-cookie": (
                    "sessionid=tok_123; HttpOnly; Secure; SameSite=Lax, "
                    "theme=dark; Expires=Mon, 23 Nov 2026 14:41:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax"
                )
            },
        )
        findings = rule.check(exchange)
        self.assertEqual(len(findings), 0)

    def test_sensitive_query_params_detected(self):
        rule = SensitiveParamsRule()
        exchange = self._make_exchange(url="https://example.com/reset?token=abc&user_id=7")
        findings = rule.check(exchange)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0].rule_id, "PH-PARAM-001")

    def test_engine_runs_multiple_exchanges_and_isolates_rule_errors(self):
        exchanges = [
            self._make_exchange(url="https://example.com/a?token=secret1"),
            self._make_exchange(url="https://example.com/b?user_id=99"),
        ]
        engine = AnalysisEngine(
            rules=[_BrokenRule(), SensitiveParamsRule()],
            max_workers=2,
        )
        findings = engine.run(exchanges)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PH-PARAM-001", rule_ids)

    def test_summary_reporter_json_output(self):
        exchanges = [self._make_exchange(url="https://example.com/a?token=secret1")]
        engine = AnalysisEngine(rules=[SensitiveParamsRule()], max_workers=1)
        findings = engine.run(exchanges)

        raw = SummaryReporter.generate(findings)
        parsed = json.loads(raw)
        self.assertEqual(parsed["total_findings"], len(findings))
        self.assertIn("severity_counts", parsed)
        self.assertIn("summary", parsed)


if __name__ == "__main__":
    unittest.main()
