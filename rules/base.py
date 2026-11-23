from abc import ABC, abstractmethod
import inspect
from typing import Any, Dict, Optional
from models import Finding, HTTPExchange


class BaseRule(ABC):
    rule_id: str = "BASE-000"
    title: str = "Base Rule"
    severity: str = "Info"
    confidence: str = "Firm"
    description: str = ""
    remediation: str = ""

    @abstractmethod
    def check(self, exchange: HTTPExchange) -> list[Finding]:
        raise NotImplementedError

    def create_finding(
        self,
        exchange: HTTPExchange,
        evidence: str,
        manual_check: str = "",
        remediation: Optional[str] = None,
        confidence: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
        title: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Finding:
        sig = inspect.signature(Finding)
        params = sig.parameters

        merged_extra: Dict[str, Any] = {}
        if meta:
            merged_extra.update(meta)
        if extra:
            merged_extra.update(extra)

        candidates: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": title or self.title,
            "severity": severity or self.severity,
            "confidence": confidence or getattr(self, "confidence", "Firm"),
            "method": exchange.method,
            "url": exchange.url,
            "evidence": evidence,
            "remediation": remediation if remediation is not None else self.remediation,
            "manual_check": manual_check,
            "extra": merged_extra,
            "meta": merged_extra,
        }

        kwargs: Dict[str, Any] = {}
        for name, param in params.items():
            if name == "self":
                continue
            if name in candidates:
                kwargs[name] = candidates[name]
            elif param.default is inspect.Parameter.empty:
                kwargs[name] = ""

        return Finding(**kwargs)
