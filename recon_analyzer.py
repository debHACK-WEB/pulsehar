import json
import logging
import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qs, urlparse

from inventory import (
    AUTH_PARAM_NAMES,
    DEBUG_PARAM_NAMES,
    IDOR_PARAM_NAMES,
    REDIRECT_PARAM_NAMES,
    _is_static_path,
    build_inventory,
)
from models import Finding, HTTPExchange


SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 12,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 1,
}

PARAM_INTENT_MAP: dict[str, str] = {
    "redirect": "open_redirect_or_ssrf",
    "redirect_uri": "open_redirect_or_ssrf",
    "redirect_url": "open_redirect_or_ssrf",
    "next": "open_redirect_or_ssrf",
    "url": "open_redirect_or_ssrf",
    "return_to": "open_redirect_or_ssrf",
    "callback": "open_redirect_or_ssrf",
    "dest": "open_redirect_or_ssrf",
    "upload": "file_upload_or_path",
    "file": "file_upload_or_path",
    "filepath": "file_upload_or_path",
    "filename": "file_upload_or_path",
    "file_name": "file_upload_or_path",
    "path": "file_upload_or_path",
    "doc_id": "object_access_idor",
    "document_id": "object_access_idor",
    "user_id": "object_access_idor",
    "userid": "object_access_idor",
    "account_id": "object_access_idor",
    "order_id": "object_access_idor",
    "id": "object_access_idor",
}


class ReconAnalyzer:
    """
    محلل استراتيجي لتحويل حركة المرور السلبية إلى خريطة سطح هجوم،
    تحليل استجابات وتدفق قيم، وخطة فحص مرتبة بنظام تسجيل نقاط مركب.
    """

    DEFAULT_STATIC_EXTENSIONS = {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".woff", ".woff2", ".ico", ".map", ".webp", ".ttf", ".eot",
    }
    DEFAULT_SENSITIVE_KEYWORDS = {
        "login", "logout", "signin", "auth", "oauth", "token",
        "admin", "manage", "api", "graphql", "upload", "download",
        "user", "account", "profile", "session", "reset", "internal",
    }

    def __init__(
        self,
        static_extensions: set[str] | None = None,
        sensitive_keywords: set[str] | None = None,
        extra_param_keys: set[str] | None = None,
        context_headers: set[str] | None = None,
    ):
        self.logger = logging.getLogger("PulseHar.ReconAnalyzer")
        self.static_extensions = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in (static_extensions or self.DEFAULT_STATIC_EXTENSIONS)
        }
        self.sensitive_keywords = {
            kw.lower() for kw in (sensitive_keywords or self.DEFAULT_SENSITIVE_KEYWORDS)
        }
        self.extra_param_keys = {k.lower() for k in (extra_param_keys or set())}
        self.context_headers = {
            h.lower()
            for h in (
                context_headers
                or {
                    "location",
                    "set-cookie",
                    "www-authenticate",
                    "access-control-allow-origin",
                    "x-request-id",
                    "x-correlation-id",
                    "content-type",
                }
            )
        }

    def is_static(self, url: str, method: str = "GET") -> bool:
        if method and method.upper() not in ("GET", "HEAD"):
            return False
        parsed_path = (urlparse(url).path or "").lower()
        if any(parsed_path.endswith(ext) for ext in self.static_extensions):
            return True
        return _is_static_path(parsed_path)

    def _extract_params(self, ex: HTTPExchange) -> list[tuple[str, str, str]]:
        """
        إرجاع قائمة من (location, param_name, sample_value).
        """
        items: list[tuple[str, str, str]] = []
        for qk, qvals in (ex.query_params or {}).items():
            val = qvals[0] if qvals else ""
            items.append(("query", str(qk), str(val)))

        req_headers = {str(k).lower(): str(v) for k, v in (ex.request_headers or {}).items()}
        content_type = req_headers.get("content-type", "").lower()

        if ex.request_body:
            body = ex.request_body.strip()
            if "application/json" in content_type or body.startswith(("{", "[")):
                try:
                    parsed = json.loads(body)

                    def _walk_json(obj: Any, prefix: str = "") -> None:
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                key_name = f"{prefix}.{k}" if prefix else str(k)
                                if isinstance(v, (dict, list)):
                                    _walk_json(v, key_name)
                                else:
                                    items.append(("body-json", key_name, "" if v is None else str(v)))
                        elif isinstance(obj, list):
                            list_key = f"{prefix}[]" if prefix else "[]"
                            for elem in obj[:10]:
                                if isinstance(elem, (dict, list)):
                                    _walk_json(elem, list_key)
                                else:
                                    items.append(("body-json", list_key, "" if elem is None else str(elem)))

                    _walk_json(parsed)
                except Exception:
                    pass
            elif "application/x-www-form-urlencoded" in content_type or ("=" in body and not body.startswith(("{", "<"))):
                parsed_form = parse_qs(body, keep_blank_values=True)
                for fk, fvals in parsed_form.items():
                    items.append(("body-form", str(fk), str(fvals[0] if fvals else "")))

        return items

    def _classify_parameter_intent(self, name: str, value: str) -> str:
        low_name = name.lower().split(".")[-1].rstrip("[]")
        if low_name in PARAM_INTENT_MAP:
            return PARAM_INTENT_MAP[low_name]
        if low_name in REDIRECT_PARAM_NAMES or any(k in low_name for k in ("redirect", "next", "callback", "return_to", "url")):
            return "open_redirect_or_ssrf"
        if low_name in IDOR_PARAM_NAMES or low_name.endswith("_id") or low_name == "id":
            return "object_access_idor"
        if low_name in AUTH_PARAM_NAMES or any(k in low_name for k in ("token", "secret", "password", "auth", "session", "api_key")):
            return "auth_or_secret"
        if low_name in DEBUG_PARAM_NAMES or any(k in low_name for k in ("debug", "admin", "role", "internal", "privilege")):
            return "privilege_or_debug"
        if any(k in low_name for k in ("upload", "file", "path", "dir", "attachment")):
            return "file_upload_or_path"
        if low_name in {"page", "limit", "offset", "per_page", "sort", "order", "filter", "q", "search", "lang"}:
            return "pagination_or_filter"
        if value.startswith(("http://", "https://", "/")):
            return "path_or_url_value"
        return "general_input"

    def _analyze_response(self, ex: HTTPExchange) -> dict[str, Any]:
        status = int(ex.status or 0)
        resp_headers = {str(k).lower(): str(v) for k, v in (ex.response_headers or {}).items()}
        signals: list[str] = []

        if status in (401, 403):
            signals.append(f"authz_boundary:{status}")
        elif status in (301, 302, 303, 307, 308):
            signals.append(f"redirect_response:{status}")
            if "location" in resp_headers:
                signals.append("has_location_header")
        elif status >= 500:
            signals.append(f"server_error:{status}")
        elif status == 200:
            signals.append("ok_200")

        if "set-cookie" in resp_headers:
            signals.append("sets_cookie")
        if "www-authenticate" in resp_headers:
            signals.append("auth_challenge")
        if "access-control-allow-origin" in resp_headers:
            signals.append("cors_header_present")

        matched_headers = {
            h: resp_headers[h] for h in self.context_headers if h in resp_headers
        }

        return {
            "status": status,
            "signals": signals,
            "headers": matched_headers,
            "body_len": len(ex.response_body or ""),
        }

    def analyze_surface(
        self,
        exchanges: list[HTTPExchange],
        findings: list[Finding] | None = None,
    ) -> dict[str, Any]:
        """
        تحليل شامل لسطح الهجوم والاستجابات وتتبع القيم عبر الطلبات.
        """
        findings = findings or []
        inventory = build_inventory(exchanges)
        ep_lookup: dict[tuple[str, str], Any] = {
            (ep.method.upper(), ep.normalized_path): ep for ep in inventory.endpoints
        }

        critical_endpoints: list[str] = []
        seen_endpoints: set[str] = set()
        parameter_patterns: dict[str, int] = {}
        parameter_intents: dict[str, str] = {}
        data_flow_nodes: set[str] = set()
        hosts: set[str] = set()
        response_profiles: dict[str, dict[str, Any]] = {}
        value_occurrences: dict[str, list[str]] = defaultdict(list)
        skipped_static = 0

        for ex in exchanges:
            method = (ex.method or "GET").upper()
            if self.is_static(ex.url, method=method):
                skipped_static += 1
                continue

            if ex.host:
                hosts.add(ex.host)

            norm_path = ex.normalized_path or urlparse(ex.url).path or "/"
            ep_key = (method, norm_path)
            ep_entry = ep_lookup.get(ep_key)

            path_to_check = f"{norm_path} {ex.url}".lower()
            ep_tags = list(getattr(ep_entry, "tags", []) or [])
            ep_score = int(getattr(ep_entry, "interest_score", 1))

            resp_info = self._analyze_response(ex)
            node_label = f"{method}:{norm_path}"
            data_flow_nodes.add(node_label)

            profile = response_profiles.setdefault(
                node_label,
                {
                    "statuses": [],
                    "signals": [],
                    "headers": {},
                    "max_body_len": 0,
                    "hits": 0,
                },
            )
            profile["hits"] += 1
            if resp_info["status"] and resp_info["status"] not in profile["statuses"]:
                profile["statuses"].append(resp_info["status"])
            for sig in resp_info["signals"]:
                if sig not in profile["signals"]:
                    profile["signals"].append(sig)
            profile["headers"].update(resp_info["headers"])
            profile["max_body_len"] = max(profile["max_body_len"], resp_info["body_len"])

            has_keyword = any(kw in path_to_check for kw in self.sensitive_keywords)
            has_risk_tag = any(
                t not in ("Standard", "Static-Asset") for t in ep_tags
            )
            has_interesting_resp = any(
                s.startswith(("authz_boundary:", "redirect_response:", "server_error:")) or s == "sets_cookie"
                for s in resp_info["signals"]
            )

            if has_keyword or has_risk_tag or has_interesting_resp or ep_score >= 4:
                if ex.url not in seen_endpoints:
                    seen_endpoints.add(ex.url)
                    critical_endpoints.append(ex.url)

            for _, pname, pval in self._extract_params(ex):
                parameter_patterns[pname] = parameter_patterns.get(pname, 0) + 1
                parameter_intents[pname] = self._classify_parameter_intent(pname, pval)

                cleaned_val = pval.strip()
                if cleaned_val and len(cleaned_val) <= 120:
                    val_key = f"{pname}={cleaned_val}"
                    if node_label not in value_occurrences[val_key]:
                        value_occurrences[val_key].append(node_label)

            # تتبع القيم المنقولة في ترويسة Location عبر الطلبات
            loc_val = resp_info["headers"].get("location", "").strip()
            if loc_val:
                loc_key = f"Location->{loc_val}"
                if node_label not in value_occurrences[loc_key]:
                    value_occurrences[loc_key].append(node_label)

        tracked_values = {
            k: nodes for k, nodes in value_occurrences.items() if len(nodes) > 1
        }

        finding_summary: dict[str, int] = defaultdict(int)
        for f in findings:
            finding_summary[f.url] += 1

        return {
            "hosts": sorted(hosts),
            "critical_endpoints": critical_endpoints,
            "parameter_patterns": parameter_patterns,
            "parameter_intents": parameter_intents,
            "data_flow_nodes": sorted(data_flow_nodes),
            "response_profiles": response_profiles,
            "tracked_values": tracked_values,
            "finding_hits_by_url": dict(finding_summary),
            "skipped_static_count": skipped_static,
            "inventory_summary": {
                "total_exchanges": inventory.total_exchanges,
                "unique_endpoints": inventory.unique_endpoints,
                "sensitive_parameters_count": inventory.sensitive_parameters_count,
            },
        }

    def generate_priority_plan(
        self,
        attack_surface: dict[str, Any],
        findings: list[Finding] | None = None,
    ) -> list[dict[str, Any]]:
        """
        توليد خطة فحص بنظام تسجيل نقاط (scoring) مركب يدمج السياق، الاستجابات،
        تتبع القيم، وشدة التنبيهات الأمنية.
        """
        findings = findings or []
        plan: list[dict[str, Any]] = []
        seen_targets: set[str] = set()

        response_profiles: dict[str, dict[str, Any]] = attack_surface.get("response_profiles", {})
        tracked_values: dict[str, list[str]] = attack_surface.get("tracked_values", {})
        param_intents: dict[str, str] = attack_surface.get("parameter_intents", {})
        param_patterns: dict[str, int] = attack_surface.get("parameter_patterns", {})

        finding_weight_by_url: dict[str, int] = defaultdict(int)
        for f in findings:
            sev = str(getattr(f, "severity", "INFO")).upper()
            finding_weight_by_url[f.url] += SEVERITY_WEIGHTS.get(sev, 1)

        # 1. تسجيل نقاط المسارات الحساسة وعقد تدفق البيانات
        candidate_urls = list(attack_surface.get("critical_endpoints", []))
        for endpoint in candidate_urls:
            parsed = urlparse(endpoint)
            norm_path = parsed.path or "/"
            matching_nodes = [
                node for node in response_profiles if node.endswith(f":{norm_path}")
            ]
            primary_node = matching_nodes[0] if matching_nodes else f"ANY:{norm_path}"
            if primary_node in seen_targets:
                continue
            seen_targets.add(primary_node)

            prof = response_profiles.get(primary_node, {})
            hits = int(prof.get("hits", 1))
            signals = list(prof.get("signals", []))

            score = 20
            reasons: list[str] = ["Sensitive surface"]

            # نقاط تكرار السلوك
            if hits > 1:
                repeat_bonus = min(hits * 2, 10)
                score += repeat_bonus
                reasons.append(f"repeated behavior ({hits} hits)")

            # نقاط إشارات الاستجابة
            if any(s.startswith("authz_boundary:") for s in signals):
                score += 12
                reasons.append("authz boundary (401/403)")
            if any(s.startswith("redirect_response:") for s in signals):
                score += 10
                reasons.append("redirect response")
            if any(s.startswith("server_error:") for s in signals):
                score += 9
                reasons.append("server error (5xx)")
            if "sets_cookie" in signals:
                score += 6
                reasons.append("session/cookie set")

            # نقاط تتبع القيم العابرة للطلبات
            cross_req_matches = [
                k for k, nodes in tracked_values.items() if primary_node in nodes
            ]
            if cross_req_matches:
                score += min(len(cross_req_matches) * 5, 15)
                reasons.append(f"cross-request values ({len(cross_req_matches)})")

            # نقاط التنبيهات الأمنية المرتبطة بالرابط أو المسار
            f_score = 0
            for f_url, w in finding_weight_by_url.items():
                if f_url == endpoint or norm_path in f_url:
                    f_score += w
            if f_score > 0:
                score += f_score
                reasons.append(f"findings weight (+{f_score})")

            priority_tier = "high" if score >= 24 else ("medium" if score >= 15 else "low")
            plan.append(
                {
                    "target": endpoint,
                    "node": primary_node,
                    "score": score,
                    "priority": priority_tier,
                    "reason": " | ".join(reasons),
                }
            )

        # 2. تسجيل نقاط البارامترات الحساسة أو المخصصة للهدف (مع استبعاد الترقيم العام)
        high_risk_intents = {
            "open_redirect_or_ssrf",
            "object_access_idor",
            "auth_or_secret",
            "privilege_or_debug",
            "file_upload_or_path",
        }
        actionable_params: list[tuple[str, int, str]] = []
        for pname, count in param_patterns.items():
            intent = param_intents.get(pname, "general_input")
            is_custom = pname.lower() in self.extra_param_keys
            if intent == "pagination_or_filter" and not is_custom:
                continue
            if intent in high_risk_intents or is_custom:
                p_score = 12 + min(count * 2, 10) + (8 if is_custom else 0) + (6 if intent in ("object_access_idor", "open_redirect_or_ssrf", "auth_or_secret") else 0)
                actionable_params.append((pname, p_score, intent))

        if actionable_params:
            actionable_params.sort(key=lambda x: (-x[1], x[0]))
            top_names = ", ".join(p[0] for p in actionable_params[:5])
            max_p_score = actionable_params[0][1]
            intents_desc = ", ".join(sorted({p[2] for p in actionable_params[:5]}))
            plan.append(
                {
                    "target": top_names,
                    "node": "params",
                    "score": max_p_score,
                    "priority": "high" if max_p_score >= 25 else "medium",
                    "reason": f"High-signal parameters ({intents_desc})",
                }
            )

        plan.sort(key=lambda item: (-int(item.get("score", 0)), str(item.get("target", ""))))
        return plan
