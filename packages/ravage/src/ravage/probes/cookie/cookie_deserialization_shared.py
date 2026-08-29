from __future__ import annotations

from ravage.web_core.http_probe import ProbeResponse, ProbeSession


def _in_scope(session: ProbeSession, url: str) -> bool:
    checker = getattr(session, "in_scope", None)
    if callable(checker):
        return bool(checker(url))
    return True


def _dedupe_urls(urls: list[str]) -> list[str]:
    deduped: list[str] = []
    for url in urls:
        if url and url not in deduped:
            deduped.append(url)
    return deduped


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, dict):
            items.append(dict(item))
    return items


def _cookie_header(cookie_jar: dict[str, str], target_name: str, target_value: str) -> str:
    values = dict(cookie_jar)
    values[target_name] = target_value
    pairs: list[str] = []
    for name, value in values.items():
        if name and value:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _request_summary(
    response: ProbeResponse, *, url: str, cookie: str, gadget: str
) -> dict[str, object]:
    return response.summary(body_chars=200) | {
        "replay_url": url,
        "cookie": cookie,
        "gadget": gadget,
    }
