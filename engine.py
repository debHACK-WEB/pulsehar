import json
from models import Finding, HTTPExchange
from rules.base import BaseRule
import concurrent.futures
import logging

class AnalysisEngine:
    def __init__(self, rules: list[BaseRule], max_workers: int = 4) -> None:
        self.rules = rules
        self.max_workers = max_workers
        self.logger = logging.getLogger("PulseHar.Engine")
        # مخزن السياق العام للتحليل السلبي
        self.context = {"global_params": {}, "paths_visited": set()}

    def _invoke_rule(self, rule: Any, exchange: HTTPExchange, context: dict) -> list[Finding]:
        import inspect
        try:
            sig = inspect.signature(rule.check)
            params = [
                p for p in sig.parameters.values()
                if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
            ]
            accepts_context = len(params) >= 2 or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            )
        except Exception:
            accepts_context = False

        if accepts_context:
            return rule.check(exchange, context)
        return rule.check(exchange)

    def _process_exchange(self, exchange: HTTPExchange, context: dict) -> list[Finding]:
        findings = []
        for rule in self.rules:
            try:
                findings.extend(self._invoke_rule(rule, exchange, context))
            except Exception as e:
                self.logger.error(f"Error running rule {rule.rule_id} on {exchange.url}: {e}")
        return findings

    def run(self, exchanges: list[HTTPExchange]) -> list[Finding]:
        all_findings: list[Finding] = []
        # تحديث السياق قبل المعالجة
        for ex in exchanges:
            self.context["paths_visited"].add(ex.url)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_exchange = {executor.submit(self._process_exchange, ex, self.context): ex for ex in exchanges}
            for future in concurrent.futures.as_completed(future_to_exchange):
                all_findings.extend(future.result())
        return all_findings

    def export_findings_json(self, findings: list[Finding]) -> str:
        return json.dumps([f.__dict__ for f in findings], indent=2)
