from __future__ import annotations

import re
import tarfile
import zipfile
from io import BytesIO

from ravage.probes.cms.cms_exposure_php_include import _probe_archive_php_include_entrypoints
from ravage.probes.cms.cms_exposure_shared import (
    _MAX_ARCHIVE_BYTES,
    _MAX_ARCHIVE_MEMBERS,
    _MAX_MEMBER_BYTES,
    _priority_member_name,
    _rewrite_url,
)
from ravage.web_core.http_probe import ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs

_WP_USER_ROW_RE = re.compile(r"\((\d+),'([^']+)','([^']+)'")


def _inspect_archive(
    session: ProbeSession, url: str, *, headers: dict[str, str] | None = None
) -> dict[str, object] | None:
    data = _fetch_bytes(session, url, headers=headers)
    if not data:
        return None
    raw_proof = _proof_from_bytes(data[:_MAX_MEMBER_BYTES])
    if raw_proof:
        return {
            "type": "cms_exposure_extracted_proof",
            "url": url,
            "proof": raw_proof,
            "proofs": [raw_proof],
            "detail": "downloaded CMS backup artifact contained proof text",
        }
    members: list[str] = []
    extracted_signals: list[dict[str, object]] = []
    proof = ""
    if zipfile.is_zipfile(BytesIO(data)):
        proof = _inspect_zip(data, members, extracted_signals)
    if not proof:
        proof = _inspect_tar(BytesIO(data), members)
    if proof:
        return {
            "type": "cms_exposure_extracted_proof",
            "url": url,
            "proof": proof,
            "proofs": [proof],
            "archive_members": members[:30],
        }
    if zipfile.is_zipfile(BytesIO(data)):
        include_finding = _probe_archive_php_include_entrypoints(
            session, url, data, headers=headers
        )
        if include_finding:
            include_finding.setdefault("archive_members", members[:30])
            return include_finding
    interesting = _interesting_member_names(members)
    if interesting or extracted_signals:
        return {
            "type": "cms_backup_artifact",
            "url": url,
            "archive_members": members[:30],
            "interesting_members": interesting[:20],
            "extracted_signals": extracted_signals[:10],
            "detail": "public CMS backup archive contains config/database-like files",
        }
    return None


def _fetch_bytes(
    session: ProbeSession, url: str, *, headers: dict[str, str] | None = None
) -> bytes:
    absolute = _rewrite_url(session, url, headers=headers)
    if not session.in_scope(absolute):
        return b""
    try:
        return session.get_bytes(
            absolute,
            headers=headers,
            max_bytes=_MAX_ARCHIVE_BYTES,
        )
    except Exception:  # noqa: BLE001 - exposed archives may be forbidden/truncated.
        return b""


def _inspect_zip(
    data: bytes, members: list[str], extracted_signals: list[dict[str, object]]
) -> str:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = _zip_file_infos(archive)
            priority = _priority_zip_infos(infos)
            ordered: list[zipfile.ZipInfo] = []
            seen_names: set[str] = set()
            for info in priority + infos[:_MAX_ARCHIVE_MEMBERS]:
                if info.filename in seen_names:
                    continue
                seen_names.add(info.filename)
                ordered.append(info)
            for info in ordered:
                if info.is_dir():
                    continue
                members.append(info.filename)
                if info.file_size > _MAX_MEMBER_BYTES:
                    continue
                with archive.open(info) as handle:
                    member_data = handle.read(_MAX_MEMBER_BYTES)
                _collect_archive_signal(info.filename, member_data, extracted_signals)
                proof = _proof_from_bytes(member_data)
                if proof:
                    return proof
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _inspect_tar(fileobj: BytesIO, members: list[str]) -> str:
    try:
        fileobj.seek(0)
        with tarfile.open(fileobj=fileobj) as archive:
            for member in archive.getmembers()[:_MAX_ARCHIVE_MEMBERS]:
                if not member.isfile():
                    continue
                members.append(member.name)
                if member.size > _MAX_MEMBER_BYTES:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                proof = _proof_from_bytes(handle.read(_MAX_MEMBER_BYTES))
                if proof:
                    return proof
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _zip_file_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos: list[zipfile.ZipInfo] = []
    for info in archive.infolist():
        if not info.is_dir():
            infos.append(info)
    return infos


def _priority_zip_infos(infos: list[zipfile.ZipInfo]) -> list[zipfile.ZipInfo]:
    priority: list[zipfile.ZipInfo] = []
    for info in infos:
        if _priority_member_name(info.filename):
            priority.append(info)
    return priority


def _proof_from_bytes(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    proofs = recognize_proofs(text)
    if proofs:
        return proofs[0]
    return ""


def _collect_archive_signal(
    name: str, data: bytes, extracted_signals: list[dict[str, object]]
) -> None:
    lowered = name.lower()
    text = data.decode("utf-8", errors="replace")
    if lowered.endswith("bmi_backup_manifest.json"):
        config_keys = _backup_manifest_config_keys(text)
        version_match = re.search(r'"version"\s*:\s*"([^"]+)"', text)
        if config_keys:
            extracted_signals.append(
                {
                    "kind": "backup_migration_manifest",
                    "member": name,
                    "version": _regex_group_value(version_match),
                    "config_keys": config_keys,
                    "detail": (
                        "Backup Migration manifest exposes WordPress config material "
                        "required for follow-on auth/nonce reasoning"
                    ),
                }
            )
    if lowered.endswith("wp_users.sql"):
        users: list[dict[str, str]] = []
        for match in _WP_USER_ROW_RE.finditer(text[:20_000]):
            users.append(
                {"id": match.group(1), "login": match.group(2), "pass_hash": match.group(3)}
            )
        if users:
            extracted_signals.append(
                {
                    "kind": "wordpress_users_table",
                    "member": name,
                    "users": users[:5],
                    "detail": "WordPress users table exposed inside public backup archive",
                }
            )
    if lowered.endswith("wp_usermeta.sql") and "session_tokens" in text:
        extracted_signals.append(
            {
                "kind": "wordpress_session_tokens",
                "member": name,
                "detail": (
                    "WordPress user metadata includes session token rows; "
                    "expiration still must be validated before cookie reuse"
                ),
            }
        )


def _backup_manifest_config_keys(text: str) -> list[str]:
    pattern = r'"((?:AUTH|SECURE_AUTH|LOGGED_IN|NONCE)_(?:KEY|SALT)|DB_[A-Z_]+|table_prefix)"\s*:'
    keys: set[str] = set()
    for match in re.finditer(pattern, text):
        keys.add(match.group(1))
    return sorted(keys)


def _regex_group_value(match: re.Match[str] | None) -> str:
    if match is None:
        return ""
    return match.group(1)


def _interesting_member_names(members: list[str]) -> list[str]:
    interesting: list[str] = []
    for name in members:
        if _interesting_member_name(name):
            interesting.append(name)
    return interesting


def _interesting_member_name(name: str) -> bool:
    lowered = name.lower()
    markers = ("wp-config", ".env", "database", "backup", ".sql", ".sqlite", ".db", "config")
    for marker in markers:
        if marker in lowered:
            return True
    return False
