import re
from urllib.parse import urlparse


UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
INT_ID_RE = re.compile(r"^\d+$")
HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_path(url: str) -> str:
    parsed = urlparse(url)
    raw_path = parsed.path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    normalized_segments: list[str] = []

    for seg in segments:
        if INT_ID_RE.match(seg):
            normalized_segments.append("{id}")
        elif UUID_RE.match(seg):
            normalized_segments.append("{uuid}")
        elif HEX_TOKEN_RE.match(seg):
            normalized_segments.append("{hash}")
        else:
            normalized_segments.append(seg)

    return "/" + "/".join(normalized_segments) if normalized_segments else "/"
