import json
from pathlib import Path
from models import HTTPExchange
from normalizer import normalize_path


def _headers_to_dict(headers_list: list[dict[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in headers_list or []:
        name = item.get("name", "").strip().lower()
        value = item.get("value", "")
        if name:
            result[name] = value
    return result


def parse_har_file(har_path: str | Path, scope_domain: str | None = None) -> list[HTTPExchange]:
    path = Path(har_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"HAR file not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = data.get("log", {}).get("entries", [])

    exchanges: list[HTTPExchange] = []
    target_scope = scope_domain.lower().strip() if scope_domain else None

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})

        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        if not url:
            continue

        req_headers = _headers_to_dict(req.get("headers", []))
        resp_headers = _headers_to_dict(resp.get("headers", []))
        status = int(resp.get("status", 0) or 0)

        req_post = req.get("postData", {}) or {}
        resp_content = resp.get("content", {}) or {}

        req_body = req_post.get("text", "") or ""
        resp_body = resp_content.get("text", "") or ""

        exchange = HTTPExchange(
            method=method,
            url=url,
            status=status,
            request_headers=req_headers,
            response_headers=resp_headers,
            request_body=req_body,
            response_body=resp_body,
        )

        if target_scope and target_scope not in exchange.host:
            continue

        exchanges.append(exchange)

    return exchanges
