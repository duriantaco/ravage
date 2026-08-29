from __future__ import annotations

from ravage.agent_core.agent_state import AgentState
from ravage.web_core.http_probe import ProbeSession, response_secrets
from ravage.probe_suite_parts.result import ProbeRunResult
from ravage.probe_suite_parts.support import _canonical_host_headers
from ravage.probes.cms.cms_exposure_archives import _inspect_archive
from ravage.probes.cms.cms_exposure_backup_migration import (
    _backup_migration_unlock_flow,
    _is_backup_migration_signal,
)
from ravage.probes.cms.cms_exposure_shared import (
    _CMS_BUDGET,
    _interesting_artifact,
    _looks_archive_url,
    _plugin_metadata_finding,
    _queue_key,
    _record_proof,
)
from ravage.probes.cms.cms_exposure_urls import _derived_urls, _initial_urls


def probe_cms_exposure(session: ProbeSession, state: AgentState) -> ProbeRunResult:
    findings: list[dict[str, object]] = []
    requests: list[dict[str, object]] = []
    budget = _CMS_BUDGET
    seed_urls = _initial_urls(session, state)
    queue = _initial_queue(seed_urls)
    _add_canonical_host_queue_items(session, state, seed_urls, queue)
    seen: set[str] = set()
    backup_migration_unlocks: set[str] = set()

    while queue and budget > 0:
        url, headers = queue.pop(0)
        key = _queue_key(url, headers)
        if key in seen or not session.in_scope(url):
            continue
        seen.add(key)
        budget -= 1
        response = session.get(url, headers=headers or None)
        requests.append(
            response.summary(body_chars=320)
            | {"probe_kind": "cms_exposure", "url": url, "headers_used": headers}
        )
        if _record_proof(response, findings, url=url):
            break
        if _is_backup_migration_signal(response, url):
            unlock_key = repr(sorted(headers.items()))
            if unlock_key not in backup_migration_unlocks:
                backup_migration_unlocks.add(unlock_key)
                unlock_findings, unlock_requests = _backup_migration_unlock_flow(
                    session, headers=headers
                )
                findings.extend(unlock_findings)
                requests.extend(unlock_requests)
                if _findings_have_extracted_proof(unlock_findings):
                    break
        if _looks_archive_url(url) and response.status in {200, 201, 202, 206} and budget > 0:
            budget -= 1
            archive_finding = _inspect_archive(session, url, headers=headers)
            requests.append(_archive_inspect_request(url, headers, archive_finding))
            if archive_finding:
                findings.append(archive_finding)
                if archive_finding.get("type") == "cms_exposure_extracted_proof":
                    break
        if _interesting_artifact(response):
            findings.append(
                {
                    "type": "cms_backup_artifact",
                    "url": url,
                    "status": response.status,
                    "matches": response_secrets(response),
                    "detail": "public CMS/backup artifact returned non-baseline sensitive or backup-looking content",
                }
            )
        plugin_finding = _plugin_metadata_finding(response, url)
        if plugin_finding:
            findings.append(plugin_finding)
        for next_url in _derived_urls(session, url, response.body):
            next_item = (next_url, headers)
            if _queue_key(next_url, headers) not in seen and next_item not in queue:
                queue.append(next_item)

    return ProbeRunResult(
        ok=bool(findings),
        probe="cms_exposure",
        summary=f"checked={len(seen)}, findings={len(findings)}, budget_remaining={budget}",
        findings=findings[:40],
        requests=requests[:60],
    )


def _initial_queue(seed_urls: list[str]) -> list[tuple[str, dict[str, str]]]:
    queue: list[tuple[str, dict[str, str]]] = []
    for url in seed_urls:
        queue.append((url, {}))
    return queue


def _add_canonical_host_queue_items(
    session: ProbeSession,
    state: AgentState,
    seed_urls: list[str],
    queue: list[tuple[str, dict[str, str]]],
) -> None:
    for headers in _canonical_host_headers(session, state):
        for url in seed_urls:
            queue.append((url, headers))


def _findings_have_extracted_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "cms_exposure_extracted_proof":
            return True
    return False


def _archive_inspect_request(
    url: str,
    headers: dict[str, str],
    archive_finding: dict[str, object] | None,
) -> dict[str, object]:
    finding: dict[str, object] = {}
    if archive_finding is not None:
        finding = archive_finding
    return {
        "probe_kind": "cms_archive_inspect",
        "url": url,
        "headers_used": headers,
        "finding": finding,
    }
