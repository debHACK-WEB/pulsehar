from models import Finding, HTTPExchange
from rules.base import BaseRule
from typing import List
import re

SESSION_COOKIE_HINTS = {"session", "sessionid", "sess", "phpsessid", "jsessionid", "connect.sid", "auth", "token", "jwt", "sid"}
TOKEN_QUERY_HINTS = {"token", "access_token", "auth_token", "api_key", "apikey", "jwt", "session_id"}

class CookieSecurityRule(BaseRule):
    rule_id = "PH-COOKIE-001"
    title = "Session Cookie or Token Hygiene Issue"
    severity = "Medium"
    confidence = "Firm"
    description = "Sensitive tokens found in URL or cookies missing security flags (HttpOnly, Secure, SameSite)."
    remediation = "Use headers for tokens instead of URL parameters. Set HttpOnly, Secure, SameSite=Lax/Strict."

    def check(self, exchange: HTTPExchange) -> List[Finding]:
        findings = []
        
        # 1. Check for tokens in URL
        for key in exchange.query_params.keys():
            if key.lower() in TOKEN_QUERY_HINTS:
                findings.append(
                    self.create_finding(
                        exchange=exchange,
                        evidence=f"Sensitive parameter found in URL: {key}",
                        manual_check="Ensure tokens are passed via Authorization header instead of URL parameters."
                    )
                )

        # 2. Check Set-Cookie headers
        set_cookie = exchange.response_headers.get("set-cookie", "")
        if set_cookie:
            # Split cookies correctly, ignoring commas inside date strings (Expires=...)
            # This regex splits by comma only if it's followed by a cookie name (word=)
            cookies = re.split(r',(?=\s*[^=;]+=[^;]+)', set_cookie)
            
            for cookie_line in cookies:
                parts = [p.strip() for p in cookie_line.split(";")]
                if not parts or "=" not in parts[0]: continue
                
                name = parts[0].split("=", 1)[0].strip()
                attrs = {p.lower() for p in parts[1:]}
                
                if any(h in name.lower() for h in SESSION_COOKIE_HINTS):
                    missing = []
                    if "httponly" not in attrs: missing.append("HttpOnly")
                    if exchange.url.lower().startswith("https://") and "secure" not in attrs: missing.append("Secure")
                    if not any(a.startswith("samesite") for a in attrs): missing.append("SameSite")
                    
                    # Note: Removed mandatory Expires/Max-Age check as per requirements
                    
                    if missing:
                        findings.append(
                            self.create_finding(
                                exchange=exchange,
                                evidence=f"Cookie '{name}' missing: {', '.join(missing)}",
                                manual_check="Verify if these attributes are required based on the cookie's purpose."
                            )
                        )
        return findings
