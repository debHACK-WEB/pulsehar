import unittest
from models import HTTPExchange
from rules.security_headers import SecurityHeadersRule


class TestSecurityHeadersRule(unittest.TestCase):
    def setUp(self):
        self.rule = SecurityHeadersRule()

    def _make_exchange(self, response_headers, url="https://example.com/", status=200):
        return HTTPExchange(
            method="GET",
            url=url,
            status=status,
            request_headers={},
            response_headers=response_headers,
            request_body="",
            response_body="",
        )

    def test_missing_headers(self):
        exchange = self._make_exchange({"content-type": "text/html"})
        findings = self.rule.check(exchange)
        self.assertTrue(len(findings) > 0)
        self.assertIn("Content-Security-Policy", findings[0].evidence)

    def test_all_headers_present(self):
        exchange = self._make_exchange(
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            }
        )
        findings = self.rule.check(exchange)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
