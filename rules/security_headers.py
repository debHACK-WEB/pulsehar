from models import Finding, HTTPExchange
from rules.base import BaseRule
from typing import List

# Modern security headers list (Removed X-XSS-Protection as it is deprecated/legacy)
REQUIRED_HEADERS = {
    "Content-Security-Policy": "Prevents XSS and data injection.",
    "X-Frame-Options": "Prevents Clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Strict-Transport-Security": "Enforces HTTPS.",
    "Referrer-Policy": "Controls how much referrer information is included.",
    "Permissions-Policy": "Restricts browser features."
}

class SecurityHeadersRule(BaseRule):
    rule_id = "PH-HDR-001"
    title = "Missing Modern Security Response Headers"
    severity = "Low"
    confidence = "Certain"
    description = "The application is missing critical modern security headers that protect against common web vulnerabilities."
    remediation = "Configure your web server or application framework to include the missing security headers."

    def check(self, exchange: HTTPExchange) -> List[Finding]:
        # Only check HTML/API responses
        content_type = exchange.response_headers.get("content-type", "").lower()
        # Skip if not a relevant response type
        if not any(t in content_type for t in ["text/html", "application/json", "application/xml", "text/plain"]):
            return []

        missing = []
        headers_lower = {k.lower(): v for k, v in exchange.response_headers.items()}

        for header, desc in REQUIRED_HEADERS.items():
            if header.lower() not in headers_lower:
                # Special case for HSTS: only required on HTTPS
                if header == "Strict-Transport-Security" and not exchange.url.lower().startswith("https://"):
                    continue
                missing.append(header)

        if not missing:
            return []

        return [
            self.create_finding(
                exchange=exchange,
                evidence=f"Missing headers: {', '.join(missing)}",
                manual_check="Verify if these headers are intentionally omitted or if they should be implemented for defense-in-depth.",
                meta={"missing_headers": missing}
            )
        ]
