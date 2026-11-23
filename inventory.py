from collections import defaultdict
from dataclasses import dataclass, field
import json
import re
from typing import Any
from urllib.parse import parse_qs
from models import HTTPExchange
from normalizer import normalize_path


IDOR_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "order_id", "orderid", "invoice_id", "doc_id", "document_id",
    "file_id", "profile_id", "member_id", "org_id", "team_id",
    "project_id", "item_id", "record_id", "uuid",
}

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "next", "url",
    "return", "return_to", "returnto", "callback", "continue",
    "dest", "destination", "goto", "target", "forward",
}

AUTH_PARAM_NAMES = {
    "token", "access_token", "refresh_token", "id_token", "auth",
    "authorization", "api_key", "apikey", "secret", "password",
    "passwd", "pwd", "session", "session_id", "sid", "csrf", "xsrf",
}

DEBUG_PARAM_NAMES = {
    "debug", "test", "trace", "verbose", "admin", "role", "is_admin",
    "preview", "internal", "cmd", "exec",
}

PATH_TAGS: list[tuple[str, re.Pattern[str]]] = [
    ("Auth", re.compile(r"/(login|logout|signin|sign-in|signup|sign-up|register|auth|oauth|sso|token|refresh|password|reset)", re.I)),
    ("Session/Account", re.compile(r"/(account|profile|me|user|users|session|sessions|settings|preferences)", re.I)),
    ("Admin/Debug", re.compile(r"/(admin|administrator|manage|management|debug|trace|actuator|swagger|graphql|console|internal|_next|phpinfo)", re.I)),
    ("Upload/Files", re.compile(r"/(upload|uploads|download|downloads|file|files|attachment|attachments|export|import|media)", re.I)),
    ("API", re.compile(r"^/api(/|$)|/v\d+(/|$)", re.I)),
]


@dataclass
class EndpointEntry:
    method: str
    normalized_path: str
    hosts: list[str] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    hits: int = 0
    tags: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    interest_score: int = 0


@dataclass
class ParameterEntry:
    name: str
    locations: list[str] = field(default_factory=list)
    value_types: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    sample_values: list[str] = field(default_factory=list)
    hits: int = 0
    sensitivity_score: int = 0


@dataclass
class TrafficInventory:
    endpoints: list[EndpointEntry] = field(default_factory=list)
    parameters: list[ParameterEntry] = field(default_factory=list)
    total_exchanges: int = 0
    unique_endpoints: int = 0
    sensitive_parameters_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_exchanges": self.total_exchanges,
            "unique_endpoints": self.unique_endpoints,
            "sensitive_parameters_count": self.sensitive_parameters_count,
            "endpoints": [ep.__dict__ for ep in self.endpoints],
            "parameters": [p.__dict__ for p in self.parameters],
        }


def _infer_value_type(val: Any) -> str:
    if isinstance(val, bool):
        return "bool"
    if isinstance(val, int):
        return "int"
    if isinstance(val, float):
        return "float"
    if isinstance(val, list):
        return "list"
    if isinstance(val, dict):
        return "object"
    s = str(val).strip()
    if s.isdigit():
        return "int"
    if s.lower() in ("true", "false"):
        return "bool"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        s,
    ):
        return "uuid"
    if len(s) >= 24 and re.fullmatch(r"[A-Za-z0-9\-_=.]+", s):
        return "token/secret-like"
    return "str"


def _classify_param(name: str, location: str, val_type: str) -> tuple[list[str], int]:
    lower = name.lower().strip()
    cats: list[str] = []
    score = 1

    if lower in AUTH_PARAM_NAMES or any(k in lower for k in ("token", "secret", "password", "auth", "api_key", "apikey", "session")):
        cats.append("Auth/Token")
        score += 4
    if lower in IDOR_PARAM_NAMES or (lower.endswith("_id") and val_type in ("int", "uuid", "str")) or (lower == "id"):
        cats.append("IDOR/ObjectRef")
        score += 3
    if lower in REDIRECT_PARAM_NAMES or any(k in lower for k in ("redirect", "next", "callback", "return_to", "url")):
        cats.append("OpenRedirect")
        score += 3
    if lower in DEBUG_PARAM_NAMES or any(k in lower for k in ("debug", "admin", "role", "internal", "trace")):
        cats.append("Privilege/Debug")
        score += 3
    if location in ("header", "cookie") and lower in ("authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token"):
        if "Auth/Token" not in cats:
            cats.append("Auth/Header")
            score += 2
    if val_type == "token/secret-like" and "Auth/Token" not in cats:
        cats.append("HighEntropyValue")
        score += 2

    if not cats:
        cats.append("General")
    return cats, score


STATIC_ASSET_EXTS = (
    ".webp", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff2", ".woff", ".ttf", ".eot", ".css", ".js",
    ".ico", ".map",
)


def _is_static_path(path: str) -> bool:
    clean_path = (path or "").lower().split("?", 1)[0]
    if clean_path.startswith("/cdn-cgi/"):
        return True
    return any(clean_path.endswith(ext) for ext in STATIC_ASSET_EXTS)


def _classify_path(path: str, method: str, param_names: set[str]) -> tuple[list[str], int]:
    if _is_static_path(path) and method.upper() == "GET":
        return ["Static-Asset"], 0

    tags: list[str] = []
    score = 1

    for tag, pattern in PATH_TAGS:
        if pattern.search(path):
            tags.append(tag)
            score += 3 if tag in ("Auth", "Admin/Debug", "Session/Account") else 2

    if "{id}" in path or "{uuid}" in path or "{hash}" in path or (param_names & IDOR_PARAM_NAMES):
        tags.append("IDOR-Candidate")
        score += 3

    if param_names & REDIRECT_PARAM_NAMES:
        tags.append("Redirect-Param")
        score += 2

    if param_names & AUTH_PARAM_NAMES:
        tags.append("Auth-Param")
        score += 3

    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        tags.append(f"StateChange:{method.upper()}")
        score += 2

    if not tags:
        tags.append("Standard")
    return tags, score


def _flatten_json(obj: Any, prefix: str = "", out: list[tuple[str, Any]] | None = None) -> list[tuple[str, Any]]:
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                _flatten_json(v, key, out)
            else:
                out.append((key, v))
    elif isinstance(obj, list):
        key = f"{prefix}[]" if prefix else "[]"
        if not obj:
            out.append((key, ""))
        else:
            for item in obj[:5]:
                if isinstance(item, (dict, list)):
                    _flatten_json(item, key, out)
                else:
                    out.append((key, item))
    else:
        out.append((prefix or "body", obj))
    return out


def _extract_body_params(body: str, content_type: str) -> list[tuple[str, str, Any]]:
    if not body or not body.strip():
        return []
    ct = (content_type or "").lower()
    raw = body.strip()

    if "application/json" in ct or raw.startswith(("{", "[")):
        try:
            parsed = json.loads(raw)
            return [("body-json", k, v) for k, v in _flatten_json(parsed)]
        except Exception:
            pass

    if "application/x-www-form-urlencoded" in ct or ("=" in raw and not raw.startswith(("{", "<"))):
        parsed_qs = parse_qs(raw, keep_blank_values=True)
        items: list[tuple[str, str, Any]] = []
        for k, vals in parsed_qs.items():
            items.append(("body-form", k, vals[0] if vals else ""))
        if items:
            return items

    return [("body-raw", "raw_body", raw[:120])]


def _redact_sample(val: Any) -> str:
    s = str(val)
    if len(s) > 36:
        return f"{s[:10]}...({len(s)} chars)"
    return s


def build_inventory(exchanges: list[HTTPExchange]) -> TrafficInventory:
    ep_map: dict[tuple[str, str], dict[str, Any]] = {}
    param_map: dict[tuple[str, str], dict[str, Any]] = {}

    for ex in exchanges:
        method = (ex.method or "GET").upper()
        norm_path = ex.normalized_path or normalize_path(ex.url)
        ep_key = (method, norm_path)

        if ep_key not in ep_map:
            ep_map[ep_key] = {
                "method": method,
                "normalized_path": norm_path,
                "hosts": set(),
                "statuses": set(),
                "hits": 0,
                "params": set(),
                "examples": [],
            }
        ep_rec = ep_map[ep_key]
        ep_rec["hits"] += 1
        if ex.host:
            ep_rec["hosts"].add(ex.host)
        if ex.status:
            ep_rec["statuses"].add(int(ex.status))
        if ex.url and ex.url not in ep_rec["examples"] and len(ep_rec["examples"]) < 3:
            ep_rec["examples"].append(ex.url)

        req_headers = {str(k).lower(): str(v) for k, v in (ex.request_headers or {}).items()}
        resp_headers = {str(k).lower(): str(v) for k, v in (ex.response_headers or {}).items()}
        ct = req_headers.get("content-type", "") or resp_headers.get("content-type", "")

        collected: list[tuple[str, str, Any]] = []

        # 1. Query params
        for qk, qvals in (ex.query_params or {}).items():
            collected.append(("query", qk, qvals[0] if qvals else ""))

        # 2. Body params
        for loc, bk, bv in _extract_body_params(ex.request_body or "", ct):
            collected.append((loc, bk, bv))

        # 3. Interesting request headers
        for hk, hv in req_headers.items():
            if hk in ("authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token", "x-forwarded-for", "x-forwarded-host", "x-original-url", "x-rewrite-url") or hk.startswith("x-"):
                if hk != "cookie":
                    collected.append(("header", hk, hv))

        # 4. Cookies from Cookie header or Set-Cookie header
        cookie_header = req_headers.get("cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    collected.append(("cookie", ck.strip(), cv.strip()))

        set_cookie_header = resp_headers.get("set-cookie", "")
        if set_cookie_header:
            for raw_cookie in re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", set_cookie_header):
                first_seg = raw_cookie.split(";", 1)[0]
                if "=" in first_seg:
                    ck, cv = first_seg.split("=", 1)
                    collected.append(("cookie", ck.strip(), cv.strip()))

        ep_param_names_this_ex: set[str] = set()
        for loc, pname, pval in collected:
            vtype = _infer_value_type(pval)
            cats, pscore = _classify_param(pname, loc, vtype)
            ep_rec["params"].add(pname)
            ep_param_names_this_ex.add(pname.lower())

            pkey = (pname, loc)
            if pkey not in param_map:
                param_map[pkey] = {
                    "name": pname,
                    "locations": set(),
                    "value_types": set(),
                    "endpoints": set(),
                    "methods": set(),
                    "categories": set(),
                    "sample_values": [],
                    "hits": 0,
                    "sensitivity_score": pscore,
                }
            prec = param_map[pkey]
            prec["hits"] += 1
            prec["locations"].add(loc)
            prec["value_types"].add(vtype)
            prec["endpoints"].add(f"{method} {norm_path}")
            prec["methods"].add(method)
            prec["categories"].update(cats)
            prec["sensitivity_score"] = max(prec["sensitivity_score"], pscore)
            sample = _redact_sample(pval)
            if sample not in prec["sample_values"] and len(prec["sample_values"]) < 3:
                prec["sample_values"].append(sample)

    endpoints_out: list[EndpointEntry] = []
    for (_, _), rec in ep_map.items():
        pnames_lower = {p.lower() for p in rec["params"]}
        tags, score = _classify_path(rec["normalized_path"], rec["method"], pnames_lower)
        endpoints_out.append(
            EndpointEntry(
                method=rec["method"],
                normalized_path=rec["normalized_path"],
                hosts=sorted(rec["hosts"]),
                statuses=sorted(rec["statuses"]),
                hits=rec["hits"],
                tags=tags,
                params=sorted(rec["params"]),
                examples=rec["examples"],
                interest_score=score,
            )
        )

    endpoints_out.sort(key=lambda e: (-e.interest_score, -e.hits, e.normalized_path, e.method))

    parameters_out: list[ParameterEntry] = []
    for (_, _), rec in param_map.items():
        parameters_out.append(
            ParameterEntry(
                name=rec["name"],
                locations=sorted(rec["locations"]),
                value_types=sorted(rec["value_types"]),
                endpoints=sorted(rec["endpoints"]),
                methods=sorted(rec["methods"]),
                categories=sorted(rec["categories"]),
                sample_values=rec["sample_values"],
                hits=rec["hits"],
                sensitivity_score=rec["sensitivity_score"],
            )
        )

    parameters_out.sort(key=lambda p: (-p.sensitivity_score, -p.hits, p.name))

    sensitive_params = [
        p for p in parameters_out if any(c != "General" for c in p.categories)
    ]

    return TrafficInventory(
        endpoints=endpoints_out,
        parameters=parameters_out,
        total_exchanges=len(exchanges),
        unique_endpoints=len(endpoints_out),
        sensitive_parameters_count=len(sensitive_params),
    )
