import json
import re
from typing import Any
from urllib.parse import unquote
from models import HTTPExchange

TRACKED_KEY_RE = re.compile(
    r"^(?:id|user_?id|account_?id|order_?id|doc_?id|item_?id|uid|uuid|"
    r"token|access_?token|auth_?token|csrf_?token|session_?id|"
    r"url|next|redirect(?:_uri|_url)?|return_?to|dest|destination|callback)$",
    re.IGNORECASE,
)

JSON_PAIR_RE = re.compile(
    r'["\']([A-Za-z0-9_-]{2,40})["\']\s*[:=]\s*["\']?([A-Za-z0-9_.\-:/@%?=&+~]{3,160})["\']?'
)


def _classify_flow(key: str, value: str, target_exchange: HTTPExchange) -> str:
    kl = key.lower()
    if any(t in kl for t in ("token", "csrf", "session", "auth")):
        return "AUTH_TOKEN_FLOW"
    if any(r in kl for r in ("url", "next", "redirect", "return_to", "dest", "callback")) or value.startswith(("http://", "https://", "//")):
        return "REDIRECT_FLOW"
    if any(i in kl for i in ("id", "uid", "uuid")) or value.isdigit():
        return "IDOR_FLOW"
    if target_exchange.method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return "STATE_FLOW"
    return "DATA_FLOW"


def _extract_candidates_from_exchange(ex: HTTPExchange) -> list[tuple[str, str, str]]:
    """Returns list of (key, value, source_location) from response and request."""
    items: list[tuple[str, str, str]] = []

    for k, vals in (ex.query_params or {}).items():
        if TRACKED_KEY_RE.match(k):
            for v in vals:
                v_clean = unquote(str(v)).strip()
                if len(v_clean) >= 1:
                    items.append((k, v_clean, "query"))

    resp_headers = ex.response_headers or {}
    for hk, hv in resp_headers.items():
        if TRACKED_KEY_RE.match(hk) or hk.lower() == "location":
            v_clean = str(hv).strip()
            if len(v_clean) >= 3:
                items.append((hk, v_clean, "response_header"))

    for blob, loc in ((ex.response_body or "", "response_body"), (ex.request_body or "", "request_body")):
        if not blob:
            continue
        snippet = blob[:60000]
        for m in JSON_PAIR_RE.finditer(snippet):
            k, v = m.group(1), unquote(m.group(2)).strip()
            if TRACKED_KEY_RE.match(k) and len(v) >= 1:
                items.append((k, v, loc))

    return items


def _target_contains_value(ex: HTTPExchange, val: str) -> str | None:
    if not val or len(val) < 2:
        return None
    if val in (ex.url or ""):
        return "url/query"
    if val in (ex.request_body or ""):
        return "request_body"
    for hk, hv in (ex.request_headers or {}).items():
        if val in str(hv):
            return f"header:{hk}"
    return None


def build_dataflow_graph(exchanges: list[HTTPExchange], max_edges: int = 100) -> list[dict[str, Any]]:
    """Tracks values/IDs/tokens/redirects from earlier exchanges to later exchanges in session order."""
    seen_sources: list[tuple[int, HTTPExchange, str, str, str]] = []
    edges: list[dict[str, Any]] = []
    dedup: set[tuple[str, str, str, str]] = set()

    for idx, ex in enumerate(exchanges):
        # Check earlier values appearing in current exchange
        for src_idx, src_ex, key, val, src_loc in seen_sources:
            if src_idx == idx:
                continue
            sink_loc = _target_contains_value(ex, val)
            if sink_loc:
                edge_key = (
                    f"{src_ex.method} {src_ex.normalized_path}",
                    f"{ex.method} {ex.normalized_path}",
                    key,
                    val[:60],
                )
                if edge_key in dedup:
                    continue
                dedup.add(edge_key)
                flow_type = _classify_flow(key, val, ex)
                edges.append(
                    {
                        "flow_type": flow_type,
                        "key": key,
                        "value_preview": val if len(val) <= 48 else val[:45] + "...",
                        "source": f"#{src_idx + 1} {src_ex.method} {src_ex.normalized_path} ({src_loc})",
                        "sink": f"#{idx + 1} {ex.method} {ex.normalized_path} ({sink_loc})",
                        "state_changing": ex.method.upper() in ("POST", "PUT", "PATCH", "DELETE"),
                    }
                )
                if len(edges) >= max_edges:
                    return edges

        for k, v, loc in _extract_candidates_from_exchange(ex):
            seen_sources.append((idx, ex, k, v, loc))

    return edges
