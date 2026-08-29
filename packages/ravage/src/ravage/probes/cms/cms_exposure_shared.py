from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.web_core.proof_recognizer import recognize_proofs

_CMS_BUDGET = 64
_MAX_ARCHIVE_BYTES = 30_000_000
_MAX_ARCHIVE_MEMBERS = 80
_MAX_MEMBER_BYTES = 800_000
_BACKUP_ARTIFACT_RE = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:zip|tar|tar\.gz|tgz|sql|sqlite|db|log)\b", re.IGNORECASE
)
_BACKUP_MIGRATION_ARCHIVE_RE = re.compile(
    r"\b((?:BM_)?Backup_[A-Za-z0-9_.-]+\.zip|backup_\d+\.zip)\b", re.IGNORECASE
)
_STABLE_TAG_RE = re.compile(r"(?im)^\s*Stable tag:\s*([^\r\n<]+)")
_PLUGIN_NAME_RE = re.compile(r"(?im)^\s*===\s*([^=\r\n]+?)\s*===")


def _header_value(response: ProbeResponse, name: str) -> str:
    lowered = name.lower()
    for key, value in response.headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _rewrite_url(session: ProbeSession, url: str, *, headers: dict[str, str] | None = None) -> str:
    absolute = session.absolute(url)
    rewritten = _session_rewritten_url(session, absolute)
    if rewritten is not None:
        return rewritten

    host = _host_header(headers)
    if host:
        canonical = _host_canonical_url(session, absolute, host)
        if canonical:
            return canonical

    return absolute


def _session_rewritten_url(session: ProbeSession, absolute_url: str) -> str | None:
    rewrite = getattr(session, "_rewrite_canonical_url", None)
    if not callable(rewrite):
        return None

    rewritten = rewrite(absolute_url)
    if not isinstance(rewritten, str):
        return None
    if rewritten == absolute_url:
        return None
    return rewritten


def _host_header(headers: dict[str, str] | None) -> str:
    if not headers:
        return ""
    host = headers.get("Host")
    if host:
        return host
    return headers.get("host", "")


def _host_canonical_url(session: ProbeSession, absolute_url: str, host: str) -> str:
    parsed = urlsplit(absolute_url)
    if not parsed.hostname:
        return ""

    canonical = host.split(":", 1)[0].strip("[]").lower()
    hostname = parsed.hostname.strip("[]").lower()
    if hostname != canonical:
        return ""

    target_url = str(getattr(session, "target_url", ""))
    target = urlsplit(target_url)
    return urlunsplit((target.scheme, target.netloc, parsed.path or "/", parsed.query, ""))


def _queue_key(url: str, headers: dict[str, str]) -> str:
    return url + "\0" + repr(sorted(headers.items()))


def _plugin_metadata_finding(response: ProbeResponse, url: str) -> dict[str, object] | None:
    if response.status not in {200, 201, 202, 206}:
        return None
    if not url.lower().endswith("/readme.txt"):
        return None
    body = response.body[:4000]
    lowered = body.lower()
    if not _text_has_plugin_marker(lowered):
        return None
    return {
        "type": "cms_plugin_version_signal",
        "url": url,
        "plugin": _plugin_name(body),
        "stable_tag": _stable_tag(body),
        "detail": "public WordPress plugin metadata identifies an installed backup/migration component",
    }


def _text_has_plugin_marker(lowered_text: str) -> bool:
    markers = ("backup", "migration", "duplicator", "updraft", "restore")
    for marker in markers:
        if marker in lowered_text:
            return True
    return False


def _plugin_name(body: str) -> str:
    plugin = _PLUGIN_NAME_RE.search(body)
    if plugin is None:
        return ""
    return plugin.group(1).strip()


def _stable_tag(body: str) -> str:
    stable = _STABLE_TAG_RE.search(body)
    if stable is None:
        return ""
    return stable.group(1).strip()


def _record_proof(response: ProbeResponse, findings: list[dict[str, object]], *, url: str) -> bool:
    proofs = recognize_proofs(response.body)
    if not proofs:
        return False
    findings.append(
        {
            "type": "cms_exposure_extracted_proof",
            "url": url,
            "proof": proofs[0],
            "proofs": proofs,
            "response": response.summary(body_chars=700),
        }
    )
    return True


def _interesting_artifact(response: ProbeResponse) -> bool:
    if response.status not in {200, 201, 202, 206}:
        return False
    body = response.body.strip()
    if len(body) < 20:
        return False
    lowered = body.lower()
    if response_secrets(response):
        return True
    if _BACKUP_MIGRATION_ARCHIVE_RE.search(body) or _BACKUP_ARTIFACT_RE.search(body):
        return True
    if _body_has_cms_artifact_marker(lowered):
        return True
    if _body_has_database_backup_marker(lowered):
        return True
    return False


def _body_has_cms_artifact_marker(lowered_body: str) -> bool:
    markers = (
        "backup-migration-",
        "backup-backup",
        "backupbliss",
        "wp-config",
        "wp-content/",
        "wordpress",
        "content-configdir",
        "content-backups",
        "backup-heart",
        "bmi_backup_manifest.json",
        "insert into",
        "create table",
    )
    for marker in markers:
        if marker in lowered_body:
            return True
    return False


def _body_has_database_backup_marker(lowered_body: str) -> bool:
    if "database" not in lowered_body and "mysql" not in lowered_body:
        return False
    markers = (
        "backup",
        "dump",
        "wordpress",
        "wp_",
        "schema",
        "insert into",
        "create table",
    )
    for marker in markers:
        if marker in lowered_body:
            return True
    return False


def _looks_archive_url(url: str) -> bool:
    lowered = url.lower().split("?", 1)[0]
    return lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def _priority_member_name(name: str) -> bool:
    lowered = name.lower()
    markers = (
        "bmi_backup_manifest.json",
        "wp_users.sql",
        "wp_usermeta.sql",
        "wp-config",
        ".env",
        "flag",
        "secret",
    )
    for marker in markers:
        if marker in lowered:
            return True
    return False


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _string_items(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if item:
            items.append(str(item))
    return items
