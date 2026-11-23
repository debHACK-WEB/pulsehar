from collections import Counter
import json
from typing import Any

from models import Finding, HTTPExchange

try:
    from recon_analyzer import ReconAnalyzer
except Exception:
    ReconAnalyzer = None


class SummaryReporter:
    def __init__(self, findings: list[Finding] | None = None):
        self.findings = findings or []

    @staticmethod
    def build_summary_dict(findings: list[Finding] | None = None) -> dict[str, Any]:
        target = findings or []
        counts = dict(Counter(str(getattr(f, "severity", "INFO")).upper() for f in target))
        return {
            "total_findings": len(target),
            "severity_counts": counts,
            "by_severity": counts,
            "summary": {
                "total_findings": len(target),
                "severity_counts": counts,
            },
            "findings": [f.__dict__ for f in target],
        }

    @staticmethod
    def generate(findings: list[Finding] | None = None) -> str:
        payload = SummaryReporter.build_summary_dict(findings)
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def to_json(self, findings: list[Finding] | None = None) -> str:
        target = self.findings if findings is None else findings
        return self.generate(target)

    def to_dict(self, findings: list[Finding] | None = None) -> dict[str, Any]:
        target = self.findings if findings is None else findings
        return self.build_summary_dict(target)


def build_recon_summary(
    exchanges: list[HTTPExchange],
    findings: list[Finding] | None = None,
) -> dict[str, Any]:
    if ReconAnalyzer is None:
        return {"surface": {}, "priority_plan": []}
    analyzer = ReconAnalyzer()
    surface = analyzer.analyze_surface(exchanges, findings=findings or [])
    priority_plan = analyzer.generate_priority_plan(surface, findings=findings or [])
    return {
        "surface": {
            "hosts": surface.get("hosts", []),
            "critical_endpoints": surface.get("critical_endpoints", []),
            "tracked_values": surface.get("tracked_values", {}),
            "skipped_static_count": surface.get("skipped_static_count", 0),
        },
        "priority_plan": priority_plan,
    }


def format_findings_json(findings: list[Finding]) -> str:
    return SummaryReporter.generate(findings)
