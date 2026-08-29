from __future__ import annotations

import html
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import quote, urljoin

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from ravage.web_core.http_probe import ProbeResponse, ProbeSession

_RESPONSE_PATH = re.compile(r"""(?<![A-Za-z0-9_])(/[A-Za-z0-9_.~!$&'()*+,;=:@%/-]{1,500})""")


def prioritize_observed_upload_attempts(
    attempts: Sequence[Mapping[str, object]],
    *,
    form: Mapping[str, object],
) -> list[dict[str, object]]:
    """Let the live authenticated form outrank ambient pre-auth page noise."""
    contract = json.dumps(
        {
            "action": form.get("action"),
            "categories": form.get("categories"),
            "inputs": form.get("inputs"),
            "page_context": form.get("page_context"),
        },
        sort_keys=True,
        default=str,
    ).lower()
    if any(marker in contract for marker in ("pdf", "invoice")):
        suffixes = (".pdf.php", ".pdf", ".php")
    elif any(marker in contract for marker in ("image", "avatar", "photo", "picture")):
        suffixes = (".jpg.php", ".php.jpg", ".jpeg.php", ".php.jpeg", ".jpg", ".jpeg")
    else:
        return [dict(item) for item in attempts]

    indexed = list(enumerate(attempts))
    indexed.sort(
        key=lambda item: (
            _suffix_priority(str(item[1].get("filename") or ""), suffixes),
            item[0],
        )
    )
    return [dict(item) for _, item in indexed]


def evidence_directed_upload_readback_urls(
    session: ProbeSession,
    *,
    upload_response: ProbeResponse,
    filename: str,
    limit: int = 4,
) -> tuple[str, ...]:
    """
    Convert a server-reported saved path into the first bounded readback.

    A response such as "saved to /uploaded_invoices/" is stronger evidence than
    a generic directory dictionary, so it must be tried before path guessing.
    """
    if limit <= 0:
        return ()
    candidates: list[str] = []
    location = str(
        upload_response.headers.get("location") or upload_response.headers.get("Location") or ""
    ).strip()
    if location:
        candidates.append(_candidate_with_filename(location, filename))
    candidates.extend(
        _candidate_with_filename(match.group(1), filename)
        for match in _RESPONSE_PATH.finditer(html.unescape(upload_response.body))
    )

    base_url = upload_response.final_url or upload_response.url or session.target_url
    urls: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        absolute = urljoin(base_url, candidate)
        if not session.in_scope(absolute) or absolute in urls:
            continue
        urls.append(absolute)
        if len(urls) >= limit:
            break
    return tuple(urls)


def _candidate_with_filename(candidate: str, filename: str) -> str:
    text = candidate.strip().rstrip(".,;:)]}\"'")
    if not text:
        return ""
    if filename in text:
        return text
    path_tail = text.rsplit("/", 1)[-1]
    looks_like_directory = text.endswith("/") or (
        "." not in path_tail
        and any(marker in text.lower() for marker in ("upload", "file", "image", "media"))
    )
    if not looks_like_directory:
        return ""
    return text.rstrip("/") + "/" + quote(filename, safe="._-")


def _suffix_priority(filename: str, suffixes: tuple[str, ...]) -> int:
    lowered = filename.lower()
    for index, suffix in enumerate(suffixes):
        if lowered.endswith(suffix):
            return index
    return len(suffixes)


__all__ = [
    "evidence_directed_upload_readback_urls",
    "prioritize_observed_upload_attempts",
]
