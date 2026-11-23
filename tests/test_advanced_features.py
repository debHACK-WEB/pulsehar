import unittest
from models import HTTPExchange
from rules.context_logic import ContextLogicRule
from advisor import compute_hotspots, build_attack_plan, diff_sessions
from fingerprint import build_executive_fingerprint


class TestAdvancedFeatures(unittest.TestCase):
    def test_context_logic_cors_and_redirect(self):
        rule = ContextLogicRule()
        ex = HTTPExchange(
            method="GET",
            url="https://app.example.com/auth/callback?next=https://evil.example.com/phish&debug=1",
            status=302,
            request_headers={"Origin": "https://evil.example.com"},
            response_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Location": "https://evil.example.com/phish",
            },
        )
        findings = rule.check(ex)
        rule_titles = {f.title for f in findings}
        self.assertIn("Overly Permissive CORS with Credentials", rule_titles)
        self.assertIn("External or Scheme Redirect in Parameter", rule_titles)
        self.assertIn("Cross-Origin Location Redirect", rule_titles)
        self.assertIn("Debug or Diagnostic Parameter Present", rule_titles)

    def test_hotspots_and_plan_prioritization(self):
        exchanges = [
            HTTPExchange(method="GET", url="https://shop.example.com/static/app.js", status=200),
            HTTPExchange(method="GET", url="https://shop.example.com/api/orders/105?user_id=105", status=200),
            HTTPExchange(method="POST", url="https://shop.example.com/auth/login", status=200, request_body="user=a&pass=b"),
        ]
        spots = compute_hotspots(exchanges, findings=[], limit=5)
        self.assertTrue(len(spots) >= 2)
        self.assertGreaterEqual(spots[0]["priority"], spots[-1]["priority"])

        plan = build_attack_plan(exchanges, findings=[])
        self.assertTrue(len(plan) >= 2)
        self.assertTrue(any("IDOR" in step["test_type"] or "Auth" in step["test_type"] for step in plan))

    def test_diff_sessions_detects_access_changes(self):
        session_unauth = [
            HTTPExchange(method="GET", url="https://app.example.com/api/admin/users", status=403, response_body="Forbidden"),
            HTTPExchange(method="GET", url="https://app.example.com/profile", status=302, response_body="Redirecting"),
        ]
        session_auth = [
            HTTPExchange(method="GET", url="https://app.example.com/api/admin/users", status=200, response_body='{"users":[{"id":1}]}' * 10),
            HTTPExchange(method="GET", url="https://app.example.com/profile", status=200, response_body='{"user":"ibbz"}' * 10),
        ]
        diffs = diff_sessions(session_unauth, session_auth)
        endpoints = {d["endpoint"] for d in diffs}
        self.assertIn("/api/admin/users", endpoints)
        self.assertIn("/profile", endpoints)

    def test_executive_fingerprint_deterministic(self):
        exchanges = [
            HTTPExchange(method="GET", url="https://app.example.com/api/items/12?id=12", status=200),
        ]
        fp1 = build_executive_fingerprint(exchanges, findings=[], scope="app.example.com")
        fp2 = build_executive_fingerprint(exchanges, findings=[], scope="app.example.com")
        self.assertEqual(fp1["scan_fingerprint"], fp2["scan_fingerprint"])
        self.assertEqual(len(fp1["scan_fingerprint"]), 12)
        self.assertIn("MODERATE-SIGNAL", fp1["verdict"])



    def test_diff_sessions_detects_sensitive_field_diff_on_200(self):
        s_a = [HTTPExchange(method="GET", url="https://app.example.com/me", status=200, response_body='{"user_id": 10, "role": "user"}')]
        s_b = [HTTPExchange(method="GET", url="https://app.example.com/me", status=200, response_body='{"user_id": 10, "role": "admin"}')]
        diffs = diff_sessions(s_a, s_b)
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0]["signal"], "SENSITIVE_FIELD_DIFF")
        self.assertIn("role", diffs[0]["changed_fields"])



    def test_dataflow_tracks_values_across_exchanges(self):
        from dataflow import build_dataflow_graph
        exchanges = [
            HTTPExchange(method="POST", url="https://app.example.com/api/orders", status=200, response_body='{"order_id": "98765", "token": "tok_abc123"}'),
            HTTPExchange(method="DELETE", url="https://app.example.com/api/orders/98765", status=200, request_headers={"Authorization": "Bearer tok_abc123"}),
        ]
        edges = build_dataflow_graph(exchanges)
        flow_types = {e["flow_type"] for e in edges}
        self.assertTrue(len(edges) >= 1)
        self.assertTrue("IDOR_FLOW" in flow_types or "AUTH_TOKEN_FLOW" in flow_types)



    def test_context_logic_null_origin_and_csrf_signal(self):
        rule = ContextLogicRule()
        ex = HTTPExchange(
            method="POST",
            url="https://app.example.com/api/email/change",
            status=200,
            request_headers={"Cookie": "sessionid=xyz123"},
            request_body="email=new@example.com",
            response_headers={
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        findings = rule.check(ex)
        titles = {f.title for f in findings}
        self.assertIn("Null Origin CORS with Credentials", titles)
        self.assertIn("State-Changing Request Without Apparent CSRF Token", titles)



    def test_graphql_endpoint_prioritized_in_plan(self):
        exchanges = [
            HTTPExchange(method="GET", url="https://app.example.com/about", status=200),
            HTTPExchange(
                method="POST",
                url="https://app.example.com/graphql",
                status=200,
                request_body='{"operationName":"GetUser","query":"query GetUser { user { id email } }"}',
            ),
        ]
        plan = build_attack_plan(exchanges, findings=[])
        self.assertTrue(any("GraphQL" in step["test_type"] for step in plan))


if __name__ == "__main__":
    unittest.main()
