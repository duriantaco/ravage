from __future__ import annotations

from ravage.web_core.http_probe import ProbeResponse
from ravage.probe_suite_parts.sqli.sqli_payloads import _synthetic_proof_subject
from ravage.probe_suite_parts.sqli.sqli_targets import _sqli_target_brief
from ravage.probe_suite_parts.sqli.sqli_transport import _sqli_replay
from ravage.probe_suite_parts.support import _dedupe
from ravage.web_core.proof_recognizer import recognize_proofs

def _preg_match_warning_finding(
    target: dict[str, object],
    response: ProbeResponse,
) -> dict[str, object]:
    return {
        "type": "preg_match_subject_type_signal",
        "input": _sqli_target_brief(target),
        "payload": f"{target.get('input')}[]=admin",
        "response": response.summary(body_chars=360),
    }

def _preg_match_value_finding(
    *,
    target: dict[str, object],
    payload: str,
    response: ProbeResponse,
    matched_value: str,
    proofs: list[str],
) -> dict[str, object]:
    synthetic_subject = _synthetic_proof_subject(payload)
    matched_proofs = recognize_proofs(matched_value)
    proof_values = _preg_match_finding_proofs(
        synthetic_subject=synthetic_subject,
        response_proofs=proofs,
        matched_proofs=matched_proofs,
    )
    return {
        "type": _preg_match_finding_type(
            synthetic_subject=synthetic_subject,
            proof_values=proof_values,
            matched_value=matched_value,
        ),
        "input": _sqli_target_brief(target),
        "payload": payload,
        "matched_value": matched_value,
        "proofs": proof_values,
        "synthetic_subject": synthetic_subject,
        "response": response.summary(body_chars=420),
        "replay": _sqli_replay(target, payload),
    }

def _preg_match_proof_finding(
    target: dict[str, object],
    payload: str,
    response: ProbeResponse,
    proofs: list[str],
) -> dict[str, object]:
    synthetic_subject = _synthetic_proof_subject(payload)
    proof_values = proofs
    finding_type = "preg_match_subject_proof"
    if synthetic_subject:
        proof_values = []
        finding_type = "preg_match_subject_synthetic_match"
    return {
        "type": finding_type,
        "input": _sqli_target_brief(target),
        "payload": payload,
        "proofs": proof_values,
        "synthetic_subject": synthetic_subject,
        "response": response.summary(body_chars=420),
        "replay": _sqli_replay(target, payload),
    }

def _preg_match_finding_proofs(
    *,
    synthetic_subject: bool,
    response_proofs: list[str],
    matched_proofs: list[str],
) -> list[str]:
    if synthetic_subject and (response_proofs or matched_proofs):
        return []
    proofs: list[str] = []
    proofs.extend(response_proofs)
    proofs.extend(matched_proofs)
    return _dedupe(proofs)

def _preg_match_finding_type(
    *,
    synthetic_subject: bool,
    proof_values: list[str],
    matched_value: str,
) -> str:
    _ = matched_value
    if synthetic_subject and not proof_values:
        return "preg_match_subject_synthetic_match"
    if proof_values:
        return "preg_match_subject_proof"
    return "preg_match_subject_match"

def _has_preg_match_proof(findings: list[dict[str, object]]) -> bool:
    for finding in findings:
        if finding.get("type") == "preg_match_subject_proof":
            return True
    return False
