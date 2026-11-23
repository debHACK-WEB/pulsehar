from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, parse_qs


@dataclass
class HTTPExchange:
    method: str
    url: str
    status: int
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    normalized_path: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        self.query_params = parse_qs(parsed.query)
        if not self.normalized_path:
            self.normalized_path = parsed.path or "/"

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc.lower()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    method: str
    url: str
    evidence: str
    manual_check: str
    meta: dict[str, Any] = field(default_factory=dict)
