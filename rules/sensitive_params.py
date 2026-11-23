from models import Finding, HTTPExchange
from rules.base import BaseRule


ID_LIKE_KEYS = {
    "id", "user_id", "userid", "account_id", "accountid",
    "order_id", "orderid", "item_id", "doc_id", "profile_id", "uid", "uuid"
}
URL_OR_FILE_KEYS = {
    "url", "next", "redirect", "redirect_uri", "return_to",
    "dest", "destination", "file", "path", "filepath", "document", "src", "ref"
}


class SensitiveParamsRule(BaseRule):
    rule_id = "PH-PARAM-001"
    title = "Interesting Query Parameters Detected"
    severity = "Medium"
    confidence = "Firm"
    description = "Detection of parameters that often lead to IDOR, Open Redirect, or Path Traversal vulnerabilities."
    remediation = "Ensure proper access control checks, validate redirect destinations, and sanitize file paths."

    def check(self, exchange: HTTPExchange) -> list[Finding]:
        findings: list[Finding] = []

        for key, values in exchange.query_params.items():
            key_lower = key.lower()
            sample_val = values[0] if values else ""

            if key_lower in ID_LIKE_KEYS:
                findings.append(
                    self.create_finding(
                        exchange=exchange,
                        evidence=f"param '{key}' = '{sample_val}'",
                        manual_check="Test access control / IDOR by changing the identifier value or testing across different session roles."
                    )
                )
            elif key_lower in URL_OR_FILE_KEYS:
                findings.append(
                    self.create_finding(
                        exchange=exchange,
                        evidence=f"param '{key}' = '{sample_val}'",
                        manual_check="Inspect how input is handled for open redirect, path/file traversal, or server-side URL fetching."
                    )
                )

        return findings
