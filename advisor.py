import json
import re
from collections import defaultdict
from typing import Any
from models import Finding, HTTPExchange

try:
    from inventory import build_inventory
except Exception:
    build_inventory = None

try:
    from recon_analyzer import ReconAnalyzer
except Exception:
    ReconAnalyzer = None

SENSITIVE_KEYS = {
    "role", "roles", "is_admin", "admin", "permissions", "privilege",
    "user_id", "userid", "owner_id", "account_id", "email", "username",
    "balance", "credits", "token", "access_token", "api_key", "secret",
}


def _extract_sensitive_fields(body: str) -> dict[str, Any]:
    if not body:
        return {}
    stripped = body.strip()
    found: dict[str, Any] = {}
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)

            def walk(obj: Any) -> None:
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        kl = str(k).lower()
                        if kl in SENSITIVE_KEYS and not isinstance(v, (dict, list)):
                            found[kl] = v
                        else:
                            walk(v)
                elif isinstance(obj, list):
                    for item in obj[:20]:
                        walk(item)

            walk(parsed)
            if found:
                return found
        except Exception:
            pass

    for key in SENSITIVE_KEYS:
        m = re.search(rf'["\']?{re.escape(key)}["\']?\s*[:=]\s*["\']?([^"\',\s}}\]]+)', body, re.IGNORECASE)
        if m:
            found[key] = m.group(1)
    return found


def _is_graphql_exchange(ex: HTTPExchange) -> bool:
    path_low = (ex.normalized_path or ex.url or "").lower()
    if "graphql" in path_low:
        return True
    body = ex.request_body or ""
    if '"query"' in body or '"mutation"' in body or '"operationName"' in body:
        return True
    return False


def compute_hotspots(
    exchanges: list[HTTPExchange],
    findings: list[Finding],
    limit: int = 10,
) -> list[dict[str, Any]]:
    inv = build_inventory(exchanges) if build_inventory is not None else None
    endpoints = getattr(inv, "endpoints", []) if inv else []

    recon_surface: dict[str, Any] = {}
    if ReconAnalyzer is not None and exchanges:
        try:
            recon_surface = ReconAnalyzer().analyze_surface(exchanges, findings=findings)
        except Exception:
            recon_surface = {}

    response_profiles: dict[str, dict[str, Any]] = recon_surface.get("response_profiles", {})
    tracked_values: dict[str, list[str]] = recon_surface.get("tracked_values", {})

    finding_counts: dict[str, int] = defaultdict(int)
    high_med_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        finding_counts[f.url] += 1
        if f.severity in ("High", "Medium"):
            high_med_counts[f.url] += 1

    spots: list[dict[str, Any]] = []
    for ep in endpoints:
        score = int(getattr(ep, "interest_score", 1))
        tags = list(getattr(ep, "tags", []) or [])
        params = list(getattr(ep, "params", []) or [])
        examples = list(getattr(ep, "examples", []) or [])
        node_key = f"{ep.method.upper()}:{ep.normalized_path}"

        f_hits = sum(
            cnt for u, cnt in finding_counts.items()
            if any(ex_url == u or ep.normalized_path in u for ex_url in (examples or [ep.normalized_path]))
        )
        hm_hits = sum(
            cnt for u, cnt in high_med_counts.items()
            if any(ex_url == u or ep.normalized_path in u for ex_url in (examples or [ep.normalized_path]))
        )

        total_priority = score + (hm_hits * 6) + (f_hits * 2)
        gql_hits = sum(
            1 for e in exchanges
            if _is_graphql_exchange(e)
            and (e.normalized_path == ep.normalized_path or any(ex_u == e.url for ex_u in examples))
        )
        if gql_hits > 0:
            total_priority += 4

        prof = response_profiles.get(node_key, {})
        signals = list(prof.get("signals", []))
        if any(s.startswith("authz_boundary:") for s in signals):
            total_priority += 4
        if any(s.startswith("server_error:") for s in signals):
            total_priority += 3
        if any(s.startswith("redirect_response:") for s in signals):
            total_priority += 2

        tracked_for_node = [k for k, nodes in tracked_values.items() if node_key in nodes]
        if tracked_for_node:
            total_priority += min(len(tracked_for_node) * 2, 6)

        reasons: list[str] = []
        if gql_hits > 0:
            reasons.append("GraphQL surface")
        if hm_hits > 0:
            reasons.append(f"{hm_hits} High/Medium finding(s)")
        if any("Auth" in t or "Session" in t for t in tags):
            reasons.append("Auth/Session surface")
        if any("IDOR" in t for t in tags):
            reasons.append("IDOR-like identifier")
        if any("Redirect" in t for t in tags):
            reasons.append("Redirect parameter")
        if any("authz_boundary:" in s for s in signals):
            reasons.append("Authz boundary (401/403)")
        if any("server_error:" in s for s in signals):
            reasons.append("Server error (5xx)")
        if tracked_for_node:
            reasons.append(f"tracked values ({len(tracked_for_node)})")
        if any("StateChange" in t for t in tags):
            reasons.append(f"State-changing {ep.method}")
        if params:
            reasons.append(f"params: {', '.join(params[:4])}")
        if not reasons:
            reasons.append("Indexed endpoint")

        spots.append(
            {
                "priority": total_priority,
                "method": ep.method,
                "endpoint": ep.normalized_path,
                "tags": tags,
                "params": params,
                "reason": " | ".join(reasons),
            }
        )

    spots.sort(key=lambda s: (-s["priority"], s["endpoint"], s["method"]))
    return spots[:limit]


def build_attack_plan(
    exchanges: list[HTTPExchange],
    findings: list[Finding],
) -> list[dict[str, str]]:
    raw_spots = compute_hotspots(exchanges, findings, limit=16)
    actionable_spots = [
        s for s in raw_spots
        if "static-asset" not in " ".join(s.get("tags", [])).lower()
        and int(s.get("priority", 0)) > 0
    ]
    spots = (actionable_spots or raw_spots)[:8]
    plan: list[dict[str, str]] = []

    for idx, spot in enumerate(spots, start=1):
        tags_str = " ".join(spot.get("tags", [])).lower()
        params_lower = [p.lower() for p in spot.get("params", [])]

        if "graphql surface" in spot["reason"].lower() or "graphql" in spot["endpoint"].lower():
            test_type = "GraphQL Query/Mutation & Auth Review"
            action = f"Inspect GraphQL queries/mutations, object ownership, and field authorization on {spot['method']} {spot['endpoint']}."
        elif any(k in params_lower for k in ("id", "user_id", "userid", "account_id", "order_id", "doc_id", "uid")):
            test_type = "Access Control / IDOR Check"
            action = f"Test object ownership and cross-session access on {spot['method']} {spot['endpoint']} with modified IDs."
        elif any(k in params_lower for k in ("url", "next", "redirect", "return_to", "callback", "dest")):
            test_type = "Open Redirect & SSRF Probe"
            action = f"Test redirect handling on {spot['method']} {spot['endpoint']} using controlled external/relative targets."
        elif "auth" in tags_str or "session" in tags_str or "authz boundary" in spot["reason"].lower():
            test_type = "Authentication & Session Flow Review"
            action = f"Inspect auth tokens, cookie attributes, rate limits, and session transitions on {spot['method']} {spot['endpoint']}."
        elif "statechange" in tags_str or spot["method"] in ("POST", "PUT", "PATCH", "DELETE"):
            test_type = "State-Change & Input Validation Check"
            action = f"Verify authorization, CSRF/token enforcement, and parameter tampering on {spot['method']} {spot['endpoint']}."
        else:
            test_type = "Data Exposure & Parameter Analysis"
            action = f"Review response fields, error messages, and query/body parameters on {spot['method']} {spot['endpoint']}."

        plan.append(
            {
                "step": str(idx),
                "target": f"{spot['method']} {spot['endpoint']}",
                "test_type": test_type,
                "action": action,
                "why": spot["reason"],
            }
        )

    return plan


def diff_sessions(
    exchanges_a: list[HTTPExchange],
    exchanges_b: list[HTTPExchange],
) -> list[dict[str, Any]]:
    map_a: dict[tuple[str, str], list[HTTPExchange]] = defaultdict(list)
    map_b: dict[tuple[str, str], list[HTTPExchange]] = defaultdict(list)

    for ex in exchanges_a:
        map_a[(ex.method.upper(), ex.normalized_path)].append(ex)
    for ex in exchanges_b:
        map_b[(ex.method.upper(), ex.normalized_path)].append(ex)

    all_keys = sorted(set(map_a.keys()) | set(map_b.keys()), key=lambda x: (x[1], x[0]))
    diffs: list[dict[str, Any]] = []

    for method, path in all_keys:
        list_a = map_a.get((method, path), [])
        list_b = map_b.get((method, path), [])

        if not list_a and list_b:
            diffs.append(
                {
                    "method": method,
                    "endpoint": path,
                    "status_a": None,
                    "status_b": [e.status for e in list_b],
                    "len_diff": None,
                    "signal": "ONLY_IN_SESSION_B",
                }
            )
            continue
        if list_a and not list_b:
            diffs.append(
                {
                    "method": method,
                    "endpoint": path,
                    "status_a": [e.status for e in list_a],
                    "status_b": None,
                    "len_diff": None,
                    "signal": "ONLY_IN_SESSION_A",
                }
            )
            continue

        statuses_a = [e.status for e in list_a]
        statuses_b = [e.status for e in list_b]
        body_a = list_a[-1].response_body or ""
        body_b = list_b[-1].response_body or ""
        len_delta = len(body_b) - len(body_a)

        fields_a = _extract_sensitive_fields(body_a)
        fields_b = _extract_sensitive_fields(body_b)
        changed_keys = [
            k for k in sorted(set(fields_a.keys()) | set(fields_b.keys()))
            if fields_a.get(k) != fields_b.get(k)
        ]

        if changed_keys:
            diffs.append(
                {
                    "method": method,
                    "endpoint": path,
                    "status_a": statuses_a,
                    "status_b": statuses_b,
                    "len_diff": len_delta,
                    "changed_fields": changed_keys,
                    "signal": "SENSITIVE_FIELD_DIFF",
                }
            )
        elif statuses_a != statuses_b or abs(len_delta) > 120:
            signal = "POTENTIAL_AUTHZ_DIFF" if (set(statuses_a) != set(statuses_b) and (200 in statuses_a or 200 in statuses_b)) else "STATUS_OR_CONTENT_SHIFT"
            diffs.append(
                {
                    "method": method,
                    "endpoint": path,
                    "status_a": statuses_a,
                    "status_b": statuses_b,
                    "len_diff": len_delta,
                    "signal": signal,
                }
            )

    return diffs
