from __future__ import annotations

import re
from typing import Callable, cast
from urllib.parse import parse_qs, urlsplit

from ravage.probe_suite_parts.command.command_query import _probe_command_query_timing
from ravage.probe_suite_parts.command.command_timing import _command_timing_extraction, _extract_command_file
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

SECRET = "FLAG{bl1nd_t1m1ng_cmdi}"
_FILES = {"/flag": SECRET}


def _matched_group(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    if match is None:
        return ""
    return match.group(1)


def _command_file_content(command: str, files: dict[str, str]) -> str:
    file_path = _matched_group(r"cat (\S+) 2>/dev/null", command)
    if not file_path:
        return ""
    return files.get(file_path, "")


def _threshold(command: str) -> int:
    value = _matched_group(r"-gt (\d+)", command)
    if not value:
        return 0
    return int(value)


def _cut_position(command: str) -> int:
    value = _matched_group(r"cut -c (\d+)", command)
    if not value:
        return 0
    return int(value)


def _proofs_from_findings(findings: list[dict[str, object]]) -> list[str]:
    proofs: list[str] = []
    for finding in findings:
        raw_proofs = finding.get("proofs")
        if not isinstance(raw_proofs, list):
            continue
        for proof in raw_proofs:
            if isinstance(proof, str):
                proofs.append(proof)
    return proofs


def _predicate_true(command: str) -> bool:
    """Evaluate a generated conditional-sleep predicate against a known file set."""
    content = _command_file_content(command, _FILES)
    if not content:
        return False
    mid = _threshold(command)
    if "wc -c" in command:
        return len(content) > mid
    position = _cut_position(command)
    if position > len(content):
        return False
    return ord(content[position - 1]) > mid


def _predicate_for_files(files: dict[str, str]) -> Callable[[str], bool]:
    def predicate(command: str) -> bool:
        content = _command_file_content(command, files)
        if not content:
            return False
        mid = _threshold(command)
        if "wc -c" in command:
            return len(content) > mid
        position = _cut_position(command)
        if position > len(content):
            return False
        return ord(content[position - 1]) > mid

    return predicate


def test_extract_command_file_recovers_flag_via_predicate_oracle() -> None:
    file_path, value = _extract_command_file(_predicate_true)
    assert file_path == "/flag"
    assert value == SECRET


def test_extract_command_file_checks_common_uppercase_app_paths() -> None:
    file_path, value = _extract_command_file(_predicate_for_files({"/app/FLAG.txt": SECRET}))
    assert file_path == "/app/FLAG.txt"
    assert value == SECRET


def test_timing_extraction_wrapper_builds_proof_from_simulated_timing() -> None:
    baseline_ms = 10

    def send_payload(payload: str) -> ProbeResponse:
        slept = _predicate_true(payload)
        elapsed = baseline_ms + (2000 if slept else 0)
        return ProbeResponse(
            method="GET", url="http://t/x", status=200, final_url="http://t/x", elapsed_ms=elapsed, headers={}, body=""
        )

    findings, requests, _budget = _command_timing_extraction(
        send_payload=send_payload,
        timing_payload="127.0.0.1; sleep 2",
        marker="CMD123",
        baseline_ms=baseline_ms,
        target_brief={"name": "host"},
        budget=600,
    )

    assert findings
    proof = findings[0]
    assert proof["type"] == "command_boundary_proof"
    assert proof["channel"] == "timing_file_read"
    proofs = _proofs_from_findings(findings)
    assert SECRET in proofs
    assert requests  # extraction issued timing requests


def test_query_timing_probe_reserves_budget_for_blind_extraction() -> None:
    baseline_ms = 10

    class _TimingSession:
        target_url = "http://t/ping"

        def get(self, url: str) -> ProbeResponse:
            payload = parse_qs(urlsplit(url).query).get("ip", [""])[0]
            slept = "sleep 2" in payload and ("test " not in payload or _predicate_true(payload))
            elapsed = baseline_ms + (2000 if slept else 0)
            return ProbeResponse(
                method="GET",
                url=url,
                status=200,
                final_url=url,
                elapsed_ms=elapsed,
                headers={},
                body="",
            )

    findings, _requests, _budget = _probe_command_query_timing(
        cast(ProbeSession, _TimingSession()),
        {"url": "http://t/ping?ip=127.0.0.1", "name": "ip"},
        "CMD123",
        {"127.0.0.1; sleep 2": "timing"},
        budget=1,
    )

    proofs = _proofs_from_findings(findings)
    assert SECRET in proofs
