import argparse
from pathlib import Path
from urllib.parse import urlparse
import json
from capture.browser_capture import capture_har_from_url
from engine import AnalysisEngine
from rules.context_logic import ContextLogicRule
from fingerprint import build_executive_fingerprint
from advisor import compute_hotspots, build_attack_plan, diff_sessions
from exporters.summary_reporter import build_recon_summary
from dataflow import build_dataflow_graph
from exporters.cli_reporter import print_cli_report, print_endpoints_map
from parsers.har_parser import parse_har_file
from rules.cookie_security import CookieSecurityRule
from rules.response_leaks import ResponseLeaksRule
from rules.security_headers import SecurityHeadersRule
from rules.sensitive_params import SensitiveParamsRule


def _default_rules():
    return [
        SensitiveParamsRule(),
        CookieSecurityRule(),
        SecurityHeadersRule(),
        ResponseLeaksRule(),
        ContextLogicRule(),
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pulsehar",
        description="Modular HTTP traffic analyzer for web security review.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = subparsers.add_parser("analyze", help="Analyze a HAR traffic file")
    analyze_cmd.add_argument("har_file", type=Path, help="Path to the .har file")
    analyze_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")
    analyze_cmd.add_argument("--json", action="store_true", help="Output results in JSON format")

    endpoints_cmd = subparsers.add_parser("endpoints", help="List normalized endpoints from a HAR file")
    endpoints_cmd.add_argument("har_file", type=Path, help="Path to the .har file")
    endpoints_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")

    hotspots_cmd = subparsers.add_parser("hotspots", help="Rank high-priority endpoints and attack surfaces")
    hotspots_cmd.add_argument("har_file", type=Path, help="Path to the .har file")
    hotspots_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")
    hotspots_cmd.add_argument("--limit", type=int, default=10, help="Max hotspots to display")
    hotspots_cmd.add_argument("--json", action="store_true", help="Output hotspots in JSON format")

    plan_cmd = subparsers.add_parser("plan", help="Generate a prioritized testing plan from HAR analysis")
    plan_cmd.add_argument("har_file", type=Path, help="Path to the .har file")
    plan_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")
    plan_cmd.add_argument("--json", action="store_true", help="Output plan in JSON format")

    diff_cmd = subparsers.add_parser("auth-diff", help="Compare responses and access behavior between two HAR sessions")
    diff_cmd.add_argument("har_a", type=Path, help="First HAR file (e.g., user A or unauthenticated)")
    diff_cmd.add_argument("har_b", type=Path, help="Second HAR file (e.g., user B or authenticated)")
    diff_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")
    diff_cmd.add_argument("--json", action="store_true", help="Output diff in JSON format")

    df_cmd = subparsers.add_parser("dataflow", help="Track IDs, tokens, and redirects across exchanges in a session")
    df_cmd.add_argument("har_file", type=Path, help="Path to the .har file")
    df_cmd.add_argument("--scope", type=str, default=None, help="Filter by target domain/host")
    df_cmd.add_argument("--json", action="store_true", help="Output dataflow edges in JSON format")

    capture_cmd = subparsers.add_parser("capture", help="Open a browser session and record HAR traffic")
    capture_cmd.add_argument("url", type=str, help="Target URL to open")
    capture_cmd.add_argument("--out", type=Path, default=Path("capture.har"), help="Output HAR file path")
    capture_cmd.add_argument("--scope", type=str, default=None, help="Domain scope for optional analysis")
    capture_cmd.add_argument("--wait", type=int, default=8, help="Seconds to wait after page load")
    capture_cmd.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    capture_cmd.add_argument("--interactive", action="store_true", help="Pause until Enter is pressed")
    capture_cmd.add_argument(
        "--browser",
        type=str,
        default="firefox",
        choices=["firefox", "chromium", "webkit"],
        help="Browser engine to use",
    )
    capture_cmd.add_argument(
        "--executable-path",
        type=str,
        default=None,
        help="Optional path to a custom browser binary",
    )
    capture_cmd.add_argument("--analyze", action="store_true", help="Run analysis immediately after capture")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        exchanges = parse_har_file(args.har_file, scope_domain=args.scope)
        engine = AnalysisEngine(rules=_default_rules())
        findings = engine.run(exchanges)
        
        if args.json:
            fp = build_executive_fingerprint(exchanges, findings, scope=args.scope)
            print(json.dumps({"fingerprint": fp, "findings": [f.__dict__ for f in findings]}, indent=2))
        else:
            print_cli_report(findings, total_exchanges=len(exchanges), scope=args.scope, exchanges=exchanges)

    elif args.command == "endpoints":
        exchanges = parse_har_file(args.har_file, scope_domain=args.scope)
        print_endpoints_map(exchanges, scope=args.scope)

    elif args.command == "hotspots":
        exchanges = parse_har_file(args.har_file, scope_domain=args.scope)
        findings = AnalysisEngine(rules=_default_rules()).run(exchanges)
        spots = compute_hotspots(exchanges, findings, limit=args.limit)
        if args.json:
            print(json.dumps(spots, indent=2))
        else:
            print(f"\n  Hotspots (Scope: {args.scope or 'ALL'} | Count: {len(spots)})\n")
            for i, s in enumerate(spots, start=1):
                print(f"  #{i:02d} [{s['priority']}] {s['method']:<7} {s['endpoint']} -> {s['reason']}")
            print()

    elif args.command == "plan":
        exchanges = parse_har_file(args.har_file, scope_domain=args.scope)
        findings = AnalysisEngine(rules=_default_rules()).run(exchanges)
        steps = build_attack_plan(exchanges, findings)
        recon_summary = build_recon_summary(exchanges, findings)
        if args.json:
            print(json.dumps({"steps": steps, "recon": recon_summary}, indent=2))
        else:
            print(f"\n  Actionable Attack Plan (Scope: {args.scope or 'ALL'} | Steps: {len(steps)})\n")
            for item in steps:
                print(f"  Step {item['step']}: [{item['test_type']}] {item['target']}")
                print(f"       Why    : {item['why']}")
                print(f"       Action : {item['action']}")
            p_plan = recon_summary.get("priority_plan", [])
            if p_plan:
                print("\n  Composite Priority Targets:\n")
                for p in p_plan[:6]:
                    print(f"  - [{p.get('priority', 'med').upper()}] (score={p.get('score', 0)}) {p.get('target')} -> {p.get('reason')}")
            print()

    elif args.command == "auth-diff":
        ex_a = parse_har_file(args.har_a, scope_domain=args.scope)
        ex_b = parse_har_file(args.har_b, scope_domain=args.scope)
        diffs = diff_sessions(ex_a, ex_b)
        if args.json:
            print(json.dumps(diffs, indent=2))
        else:
            print(f"\n  Auth Diff (Scope: {args.scope or 'ALL'} | Differences: {len(diffs)})\n")
            for d in diffs:
                print(
                    f"  • [{d['signal']}] {d['method']:<7} {d['endpoint']} "
                    f"| A={d['status_a']} vs B={d['status_b']} | len_delta={d['len_diff']}"
                )
            print()

    elif args.command == "dataflow":
        exchanges = parse_har_file(args.har_file, scope_domain=args.scope)
        edges = build_dataflow_graph(exchanges)
        if args.json:
            print(json.dumps(edges, indent=2))
        else:
            print(f"\n  Session Dataflow Graph (Scope: {args.scope or 'ALL'} | Flows: {len(edges)})\n")
            for e in edges:
                flag = " [STATE-CHANGE]" if e["state_changing"] else ""
                print(f"  • [{e['flow_type']}]{flag} {e['key']}='{e['value_preview']}'")
                print(f"      {e['source']}  -->  {e['sink']}")
            print()

    elif args.command == "capture":
        saved_path = capture_har_from_url(
            target_url=args.url,
            output_har=args.out,
            wait_seconds=args.wait,
            headless=args.headless,
            interactive_pause=args.interactive,
            browser_name=args.browser,
            executable_path=args.executable_path,
        )
        print(f"\n  [+] Saved HAR capture to: {saved_path}\n")

        if args.analyze:
            effective_scope = args.scope or (urlparse(args.url).netloc or None)
            exchanges = parse_har_file(saved_path, scope_domain=effective_scope)
            engine = AnalysisEngine(rules=_default_rules())
            findings = engine.run(exchanges)
            print_cli_report(findings, total_exchanges=len(exchanges), scope=effective_scope)


if __name__ == "__main__":
    main()
