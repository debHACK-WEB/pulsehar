from pathlib import Path
import json
import sys
from parsers.har_parser import parse_har_file
from engine import AnalysisEngine
from cli import _default_rules, main


def test_sample_har_parses_and_produces_findings():
    sample = Path("examples/sample.har")
    assert sample.exists()
    exchanges = parse_har_file(sample)
    assert len(exchanges) >= 1
    findings = AnalysisEngine(rules=_default_rules()).run(exchanges)
    assert isinstance(findings, list)


def test_cli_json_and_ignore_filter(tmp_path, monkeypatch, capsys):
    har_file = tmp_path / "synthetic.har"
    har_data = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.test/api?token=SECRET_TEST_TOKEN_999",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer SECRET_TEST_TOKEN_999"}
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "text/html"},
                            {"name": "Set-Cookie", "value": "sid=xyz123; Path=/"}
                        ],
                        "content": {"mimeType": "text/html", "text": "<html>ok</html>"},
                    },
                }
            ],
        }
    }
    har_file.write_text(json.dumps(har_data), encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["pulsehar", "analyze", str(har_file), "--json"])
    main()
    out_all = json.loads(capsys.readouterr().out)
    all_ids = [f["rule_id"] for f in out_all["findings"]]
    assert len(all_ids) >= 1

    target_ignore = all_ids[0]
    monkeypatch.setattr(
        sys,
        "argv",
        ["pulsehar", "analyze", str(har_file), "--json", "--ignore", target_ignore],
    )
    main()
    out_filtered = json.loads(capsys.readouterr().out)
    filtered_ids = [f["rule_id"] for f in out_filtered["findings"]]
    assert target_ignore not in filtered_ids
