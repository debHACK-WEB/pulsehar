from urllib.parse import urlparse
from models import Finding, HTTPExchange
from rules.base import BaseRule

REDIRECT_KEYS = {
    "url", "next", "redirect", "redirect_uri", "redirect_url",
    "return_to", "returnurl", "dest", "destination", "callback", "continue", "ref"
}
DEBUG_KEYS = {"debug", "trace", "verbose", "test", "admin", "internal", "phpinfo"}
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_TOKEN_MARKERS = ("csrf", "xsrf", "_token", "anti-csrf", "authenticity_token")



def _extract_cookies(exchange) -> dict[str, str]:
    cookies = getattr(exchange, "cookies", None)
    if isinstance(cookies, dict):
        return cookies
    extracted: dict[str, str] = {}
    req_headers = getattr(exchange, "request_headers", {}) or {}
    cookie_hdr = ""
    if isinstance(req_headers, dict):
        for k, v in req_headers.items():
            if str(k).lower() == "cookie":
                cookie_hdr = str(v)
                break
    for part in cookie_hdr.split(";"):
        if "=" in part:
            name, val = part.strip().split("=", 1)
            if name.strip():
                extracted[name.strip()] = val.strip()
    return extracted


class ContextLogicRule(BaseRule):
    rule_id = "PH-CTX-001"
    title = "Context-Aware CORS, Redirect, CSRF, or Debug Signal"
    severity = "Medium"
    confidence = "Firm"
    description = "Detects risky CORS configurations, external/scheme redirect targets, missing CSRF markers on state-changing requests, or debug parameters."
    remediation = "Restrict CORS origins explicitly, validate redirect targets strictly, enforce anti-CSRF tokens on state-changing routes, and disable debug flags in production."

    def check(self, exchange: HTTPExchange) -> list[Finding]:
        findings: list[Finding] = []
        resp_headers = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        req_headers = {k.lower(): v for k, v in (exchange.request_headers or {}).items()}
        ctx_prefix = f"[{exchange.method} {exchange.url} -> HTTP {exchange.status}]"

        # 1. CORS checks
        acao = resp_headers.get("access-control-allow-origin", "").strip()
        acac = resp_headers.get("access-control-allow-credentials", "").strip().lower()
        req_origin = req_headers.get("origin", "").strip()

        if acao == "*" and acac == "true":
            findings.append(
                self.create_finding(
                    exchange=exchange,
                    severity="High",
                    confidence="Certain",
                    title="Overly Permissive CORS with Credentials",
                    evidence=f"{ctx_prefix} Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                    manual_check="Verify whether credentialed cross-origin requests are allowed from any origin.",
                    meta={"category": "cors", "status": exchange.status},
                )
            )
        elif acao.lower() == "null" and acac == "true":
            findings.append(
                self.create_finding(
                    exchange=exchange,
                    severity="High",
                    confidence="Firm",
                    title="Null Origin CORS with Credentials",
                    evidence=f"{ctx_prefix} Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true",
                    manual_check="Check whether sandboxed/null origins can perform credentialed cross-origin reads.",
                    meta={"category": "cors", "status": exchange.status},
                )
            )
        elif req_origin and acao == req_origin and acac == "true":
            findings.append(
                self.create_finding(
                    exchange=exchange,
                    severity="Medium",
                    confidence="Firm",
                    title="Reflected CORS Origin with Credentials",
                    evidence=f"{ctx_prefix} Reflected Origin '{acao[:80]}' with Access-Control-Allow-Credentials: true",
                    manual_check="Test whether arbitrary untrusted Origin headers are reflected with credentials enabled.",
                    meta={"category": "cors", "status": exchange.status},
                )
            )

        # 2. Open redirect candidates in query params and Location header
        for key, vals in (exchange.query_params or {}).items():
            if key.lower() in REDIRECT_KEYS and vals:
                val = vals[0].strip()
                val_low = val.lower()
                if val.startswith(("http://", "https://", "//")) or val_low.startswith("javascript:"):
                    findings.append(
                        self.create_finding(
                            exchange=exchange,
                            severity="Medium" if not val_low.startswith("javascript:") else "High",
                            confidence="Firm",
                            title="External or Scheme Redirect in Parameter",
                            evidence=f"{ctx_prefix} Redirect param '{key}' points to '{val[:100]}'",
                            manual_check="Check whether arbitrary external domains or unsafe schemes can be supplied to redirect users.",
                            meta={"category": "open_redirect", "param": key, "status": exchange.status},
                        )
                    )

        location = resp_headers.get("location", "").strip()
        if location.startswith(("http://", "https://", "//")):
            loc_host = urlparse(location).netloc.lower()
            req_host = (exchange.host or urlparse(exchange.url).netloc).lower()
            if loc_host and req_host and loc_host != req_host:
                findings.append(
                    self.create_finding(
                        exchange=exchange,
                        severity="Medium",
                        confidence="Firm",
                        title="Cross-Origin Location Redirect",
                        evidence=f"{ctx_prefix} Redirects to external host '{loc_host}' ({location[:100]})",
                        manual_check="Verify whether user-controlled input influences the external Location target.",
                        meta={"category": "open_redirect", "location": location[:120], "status": exchange.status},
                    )
                )

        # 3. CSRF indicator on state-changing requests with cookie/session present
        if exchange.method.upper() in STATE_METHODS:
            has_cookie = bool(req_headers.get("cookie") or _extract_cookies(exchange))
            if has_cookie:
                combined_req = " ".join([
                    " ".join(req_headers.keys()),
                    " ".join((exchange.query_params or {}).keys()),
                    exchange.request_body or "",
                ]).lower()
                if not any(m in combined_req for m in CSRF_TOKEN_MARKERS):
                    findings.append(
                        self.create_finding(
                            exchange=exchange,
                            severity="Low",
                            confidence="Tentative",
                            title="State-Changing Request Without Apparent CSRF Token",
                            evidence=f"{ctx_prefix} {exchange.method.upper()} request with session cookie and no visible CSRF token",
                            manual_check="Verify whether state-changing action is protected by SameSite cookies, CSRF tokens, or custom headers.",
                            meta={"category": "csrf", "method": exchange.method.upper()},
                        )
                    )

        # 4. Debug / internal parameters
        for key, vals in (exchange.query_params or {}).items():
            if key.lower() in DEBUG_KEYS:
                val = vals[0] if vals else ""
                findings.append(
                    self.create_finding(
                        exchange=exchange,
                        severity="Low",
                        confidence="Tentative",
                        title="Debug or Diagnostic Parameter Present",
                        evidence=f"{ctx_prefix} Query param '{key}'='{str(val)[:60]}'",
                        manual_check="Verify whether debug/diagnostic flags alter error verbosity or bypass checks.",
                        meta={"category": "debug", "param": key, "status": exchange.status},
                    )
                )

        return findings
