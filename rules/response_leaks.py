import re
from models import Finding, HTTPExchange
from rules.base import BaseRule

LEAK_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("Stack Trace or Debug Output", "Medium", re.compile(r"(traceback \(most recent call last\)|syntaxerror:|sql syntax|ora-\d{5}|exception in thread)", re.IGNORECASE)),
    ("Private IP Address in Response Body", "Low", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
    ("Potential API Key or Bearer Secret", "High", re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{30,}|bearer\s+[A-Za-z0-9\-_.~+/]{20,})\b", re.IGNORECASE)),
]

class ResponseLeaksRule(BaseRule):
    rule_id = "PH-LEAK-001"
    title = "Potential Sensitive Data in Response Body"
    severity = "Medium"
    confidence = "Tentative"

    def check(self, exchange: HTTPExchange) -> list[Finding]:
        body = (exchange.response_body or "")[:50000]
        if not body:
            return []
        findings: list[Finding] = []
        for label, sev, pattern in LEAK_PATTERNS:
            match = pattern.search(body)
            if match:
                matched = match.group(0)
                if len(matched) > 40:
                    matched = matched[:40] + "..."
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=label,
                        severity=sev,
                        confidence="Tentative",
                        method=exchange.method,
                        url=exchange.url,
                        evidence=f"matched '{matched}'",
                        manual_check="Inspect the full response context to confirm whether sensitive or internal details are exposed.",
                    )
                )
        return findings
