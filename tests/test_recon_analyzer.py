from advisor import build_attack_plan, compute_hotspots
from models import Finding, HTTPExchange
from recon_analyzer import ReconAnalyzer


def test_recon_analyzer_filters_static_and_extracts_surface():
    exchanges = [
        HTTPExchange(method="GET", url="https://example.com/static/app.js?v=1", status=200),
        HTTPExchange(method="GET", url="https://example.com/images/logo.png", status=200),
        HTTPExchange(
            method="GET",
            url="https://app.example.com/api/v1/users?role=admin&page=1",
            status=200,
        ),
        HTTPExchange(
            method="POST",
            url="https://app.example.com/auth/login",
            status=200,
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="username=alice&redirect_to=/dashboard",
        ),
        HTTPExchange(
            method="POST",
            url="https://app.example.com/api/v1/upload",
            status=201,
            request_headers={"Content-Type": "application/json"},
            request_body='{"file_name": "report.pdf", "token": "abc"}',
        ),
    ]

    analyzer = ReconAnalyzer(extra_param_keys={"redirect_to", "role"})
    surface = analyzer.analyze_surface(exchanges)

    assert surface["skipped_static_count"] == 2
    assert surface["hosts"] == ["app.example.com"]
    assert "https://app.example.com/api/v1/users?role=admin&page=1" in surface["critical_endpoints"]
    assert "https://app.example.com/auth/login" in surface["critical_endpoints"]
    assert "GET:/api/v1/users" in surface["data_flow_nodes"]
    assert "POST:/auth/login" in surface["data_flow_nodes"]

    assert surface["parameter_patterns"]["role"] == 1
    assert surface["parameter_patterns"]["username"] == 1
    assert surface["parameter_patterns"]["redirect_to"] == 1
    assert surface["parameter_patterns"]["file_name"] == 1
    assert surface["parameter_intents"]["page"] == "pagination_or_filter"
    assert surface["parameter_intents"]["redirect_to"] == "open_redirect_or_ssrf"

    plan = analyzer.generate_priority_plan(surface)
    assert any(item["priority"] == "high" for item in plan)
    assert any(
        "redirect_to" in item["target"] and "role" in item["target"]
        for item in plan
    )


def test_recon_analyzer_custom_keywords_and_deduplication():
    exchanges = [
        HTTPExchange(method="GET", url="https://target.local/portal/settings", status=200),
        HTTPExchange(method="GET", url="https://target.local/portal/settings", status=200),
    ]

    analyzer = ReconAnalyzer(sensitive_keywords={"portal"})
    surface = analyzer.analyze_surface(exchanges)

    assert surface["critical_endpoints"] == ["https://target.local/portal/settings"]
    plan = analyzer.generate_priority_plan(surface)
    assert len(plan) == 1
    assert plan[0]["priority"] == "high"


def test_response_analysis_value_tracking_and_composite_scoring():
    exchanges = [
        HTTPExchange(
            method="GET",
            url="https://app.example.com/api/v1/account?doc_id=42&page=2",
            status=403,
            response_headers={"WWW-Authenticate": "Bearer"},
        ),
        HTTPExchange(
            method="POST",
            url="https://app.example.com/api/v1/export",
            status=200,
            request_headers={"Content-Type": "application/json"},
            request_body='{"doc_id": "42"}',
        ),
    ]
    findings = [
        Finding(
            rule_id="AUTHZ-01",
            title="Access control signal",
            severity="HIGH",
            confidence="MEDIUM",
            method="GET",
            url="https://app.example.com/api/v1/account?doc_id=42&page=2",
            evidence="403 on account endpoint",
            manual_check="Verify object authorization",
        )
    ]

    analyzer = ReconAnalyzer()
    surface = analyzer.analyze_surface(exchanges, findings=findings)

    assert "doc_id=42" in surface["tracked_values"]
    assert "GET:/api/v1/account" in surface["tracked_values"]["doc_id=42"]
    assert "POST:/api/v1/export" in surface["tracked_values"]["doc_id=42"]
    assert "authz_boundary:403" in surface["response_profiles"]["GET:/api/v1/account"]["signals"]

    plan = analyzer.generate_priority_plan(surface, findings=findings)
    assert len(plan) >= 1
    assert plan[0]["score"] > 20
    assert "findings weight" in plan[0]["reason"]

    spots = compute_hotspots(exchanges, findings=findings, limit=5)
    assert spots[0]["endpoint"] == "/api/v1/account"
    assert "Authz boundary (401/403)" in spots[0]["reason"]

    attack_plan = build_attack_plan(exchanges, findings=findings)
    assert len(attack_plan) >= 1
