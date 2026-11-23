import os
import sys
import json
from collections import Counter, defaultdict
from models import Finding, HTTPExchange
from fingerprint import build_executive_fingerprint


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}

SEVERITY_BADGE = {
    "High": "[HIGH]",
    "Medium": "[MED ]",
    "Low": "[LOW ]",
    "Info": "[INFO]",
}

SEVERITY_COLOR = {
    "High": "\033[1;31m",
    "Medium": "\033[1;33m",
    "Low": "\033[1;36m",
    "Info": "\033[1;34m",
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled or not color:
        return text
    return f"{color}{text}{RESET}"


def print_cli_report(findings: list[Finding], total_exchanges: int, scope: str | None = None, exchanges: list[HTTPExchange] | None = None) -> None:
    color = _supports_color()
    scope_label = scope if scope else "ALL"
    title_line = "PULSEHAR // Passive HTTP Traffic & Logic Analyzer"
    box_width = len(title_line) + 4

    print()
    print(_paint("╔" + "═" * box_width + "╗", CYAN, color))
    print(
        _paint("║", CYAN, color)
        + "  "
        + _paint("PULSEHAR", BOLD, color)
        + " "
        + _paint("// Passive HTTP Traffic & Logic Analyzer", DIM, color)
        + "  "
        + _paint("║", CYAN, color)
    )
    print(_paint("╚" + "═" * box_width + "╝", CYAN, color))

    print(
        f"  Scope: {_paint(scope_label, BOLD, color)}  |  "
        f"Exchanges: {_paint(str(total_exchanges), GREEN, color)}  |  "
        f"Findings: {_paint(str(len(findings)), BOLD, color)}\n"
    )

    if not findings:
        print(f"  {_paint('• No findings matched the active ruleset.', DIM, color)}\n")
        return

    counts = Counter(f.severity for f in findings)
    parts: list[str] = []
    for sev in SEVERITY_ORDER:
        if counts[sev] > 0:
            badge = SEVERITY_BADGE.get(sev, f"[{sev}]")
            scolor = SEVERITY_COLOR.get(sev, "")
            parts.append(_paint(f"{badge} {counts[sev]}", scolor, color))
    print(f"  Breakdown : {'   '.join(parts)}\n")
    print(f"  {_paint('─' * box_width, DIM, color)}")

    sorted_findings = sorted(findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 99))

    for idx, item in enumerate(sorted_findings, start=1):
        sev_color = SEVERITY_COLOR.get(item.severity, "")
        badge = SEVERITY_BADGE.get(item.severity, f"[{item.severity}]")

        print(
            f"\n  {_paint(f'#{idx:02d}', BOLD, color)} "
            f"{_paint(badge, sev_color, color)} "
            f"{_paint(f'({item.rule_id})', DIM, color)} "
            f"{_paint(item.title, BOLD, color)}"
        )
        print(f"       {_paint('Endpoint :', CYAN, color)} {item.method} {item.url}")
        print(f"       {_paint('Evidence :', CYAN, color)} {item.evidence}")
        print(f"       {_paint('Action   :', GREEN, color)} {item.manual_check}")

    fp = build_executive_fingerprint(exchanges or [], findings, scope=scope)
    print(f"\n  {_paint('Executive Fingerprint', BOLD, color)}")
    print(f"    Verdict     : {_paint(fp['verdict'], GREEN if 'HIGH-SIGNAL' in fp['verdict'] else CYAN, color)}")
    print(f"    Fingerprint : {_paint(fp['scan_fingerprint'], BOLD, color)}")
    print(f"    Top Signal  : {fp['top_signal']}")
    print(f"\n  {_paint('─' * box_width, DIM, color)}\n")


def export_json_report(findings: list[Finding], output_file: str | None = None) -> str:
    """Exports findings to JSON format."""
    data = [f.__dict__ for f in findings]
    json_output = json.dumps(data, indent=2)
    if output_file:
        with open(output_file, "w") as f:
            f.write(json_output)
    return json_output


def print_endpoints_map(exchanges: list[HTTPExchange], scope: str | None = None) -> None:
    color = _supports_color()
    scope_label = scope if scope else "ALL"

    try:
        from inventory import build_inventory
        inv = build_inventory(exchanges)
    except Exception:
        inv = None

    if inv is not None:
        print(
            f"\n  {_paint('Endpoints & Parameters Inventory', BOLD, color)} "
            f"(Scope: {_paint(scope_label, CYAN, color)} | "
            f"Endpoints: {inv.unique_endpoints} | "
            f"Sensitive Params: {inv.sensitive_parameters_count})\n"
        )
        if not inv.endpoints:
            print(f"  {_paint('• No endpoints found.', DIM, color)}\n")
            return

        ranked = sorted(
            inv.endpoints,
            key=lambda ep: (-getattr(ep, "interest_score", 0), ep.normalized_path, ep.method),
        )
        for ep in ranked:
            statuses = [s for s in getattr(ep, "statuses", []) if s and s > 0]
            status_str = ", ".join(str(s) for s in sorted(set(statuses))) or "-"
            score = getattr(ep, "interest_score", 0)
            tags = [t for t in getattr(ep, "tags", []) if t != "Standard"]
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            params = getattr(ep, "params", [])
            param_str = f" | params: {', '.join(params[:5])}" if params else ""
            print(
                f"  {_paint(f'{ep.method:<7}', GREEN, color)} "
                f"{_paint(f'{ep.normalized_path:<32}', BOLD, color)} "
                f"[{status_str}] "
                f"{_paint(f'(score={score})', CYAN, color)}"
                f"{_paint(tag_str, DIM, color)}"
                f"{_paint(param_str, DIM, color)}"
            )

        if inv.parameters:
            print(f"\n  {_paint('Indexed Parameters', BOLD, color)} ({len(inv.parameters)}):\n")
            for p in inv.parameters[:20]:
                name = getattr(p, "name", str(p))
                locs = ", ".join(getattr(p, "locations", []) or [])
                methods = ", ".join(getattr(p, "methods", []) or [])
                p_tags = [t for t in getattr(p, "tags", []) if t]
                sens = " [SENSITIVE]" if getattr(p, "is_sensitive", False) or p_tags else ""
                extra_tags = f" ({', '.join(p_tags)})" if p_tags else ""
                print(
                    f"    • {_paint(name, BOLD, color)} "
                    f"[{locs or '-'}] "
                    f"methods={methods or '-'} "
                    f"{_paint(sens + extra_tags, SEVERITY_COLOR.get('Medium', ''), color)}"
                )
        print()
        return

    grouped: dict[tuple[str, str], set[int]] = defaultdict(set)
    for ex in exchanges:
        grouped[(ex.method, ex.normalized_path)].add(ex.status)

    print(f"\n  {_paint('Endpoints Map', BOLD, color)} (Scope: {_paint(scope_label, CYAN, color)} | Unique: {len(grouped)})\n")
    if not grouped:
        print(f"  {_paint('• No endpoints found.', DIM, color)}\n")
        return

    for (method, path), statuses in sorted(grouped.items(), key=lambda x: (x[0][1], x[0][0])):
        status_str = ", ".join(str(s) for s in sorted(statuses) if s) or "-"
        print(f"  {_paint(f'{method:<7}', GREEN, color)} {_paint(f'{path:<36}', BOLD, color)} [{status_str}]")
    print()
