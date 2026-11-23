import hashlib
import json
from typing import Any
from models import Finding, HTTPExchange

try:
    from inventory import build_inventory
except Exception:
    build_inventory = None


def build_executive_fingerprint(
    exchanges: list[HTTPExchange],
    findings: list[Finding],
    scope: str | None = None,
) -> dict[str, Any]:
    inv = build_inventory(exchanges) if build_inventory is not None else None
    unique_endpoints = getattr(inv, "unique_endpoints", len({(e.method, e.normalized_path) for e in exchanges}))
    sensitive_params = getattr(inv, "sensitive_parameters_count", 0)
    endpoints = getattr(inv, "endpoints", [])

    high_or_med = sum(1 for f in findings if f.severity in ("High", "Medium"))
    actionable_rules = {"PH-PARAM-001", "PH-CTX-001", "PH-LEAK-001", "PH-COOKIE-001"}
    actionable_findings = sum(1 for f in findings if f.rule_id in actionable_rules or f.severity in ("High", "Medium"))
    high_value_endpoints = sum(
        1
        for ep in endpoints
        if getattr(ep, "interest_score", 0) >= 8
        or any(
            any(k in t.lower() for k in ("idor", "redirect", "auth", "session"))
            for t in (getattr(ep, "tags", []) or [])
        )
    )

    top_signal = "None"
    if findings:
        ranked_f = sorted(
            findings,
            key=lambda x: (
                0 if x.severity == "High" else 1 if x.severity == "Medium" else 2 if x.rule_id != "PH-HDR-001" else 3,
                x.rule_id,
            ),
        )
        top_f = ranked_f[0]
        top_signal = f"[{top_f.severity}] {top_f.title} ({top_f.method} {top_f.url})"
    elif endpoints:
        ranked_ep = sorted(endpoints, key=lambda e: -getattr(e, "interest_score", 0))
        top_ep = ranked_ep[0]
        top_signal = f"Endpoint {top_ep.method} {top_ep.normalized_path} (score={getattr(top_ep, 'interest_score', 0)})"

    if high_or_med > 0 or actionable_findings > 0:
        verdict = "HIGH-SIGNAL / ACTIONABLE TARGETS"
    elif high_value_endpoints > 0 or sensitive_params > 0:
        verdict = "MODERATE-SIGNAL / AUTH-SURFACE"
    elif unique_endpoints > 0:
        verdict = "LOW-SIGNAL / LIMITED SURFACE"
    else:
        verdict = "NO-TRAFFIC / EMPTY SCOPE"

    payload = json.dumps(
        {
            "scope": scope or "ALL",
            "exchanges": len(exchanges),
            "endpoints": unique_endpoints,
            "sensitive_params": sensitive_params,
            "findings": len(findings),
            "top_signal": top_signal,
        },
        sort_keys=True,
    )
    scan_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    return {
        "verdict": verdict,
        "scan_fingerprint": scan_hash,
        "scope": scope or "ALL",
        "exchanges": len(exchanges),
        "unique_endpoints": unique_endpoints,
        "sensitive_params": sensitive_params,
        "hotspots": high_value_endpoints,
        "findings_total": len(findings),
        "high_or_medium_findings": high_or_med,
        "top_signal": top_signal,
    }
