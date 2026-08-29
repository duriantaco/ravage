from __future__ import annotations


def accepted_proof_bundle_failures(bundle: object) -> tuple[str, ...]:
    failures: list[str] = []
    if not isinstance(bundle, dict):
        return ("proof_bundle must be an object",)

    verifier = bundle.get("verifier")
    if not isinstance(verifier, dict) or verifier.get("verdict") != "accepted":
        failures.append("proof_bundle.verifier.verdict must be accepted")

    controls = bundle.get("controls", [])
    has_passed_control = False
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict) and control.get("passed") is True:
                has_passed_control = True
                break
    if not has_passed_control:
        failures.append("proof_bundle.controls must include at least one passed control")

    step_ids = _bundle_step_ids(bundle)
    provenance = bundle.get("provenance")
    if isinstance(provenance, list):
        for index, link in enumerate(provenance):
            if not isinstance(link, dict):
                continue
            source_id = str(link.get("source_step_id") or "")
            observed_id = str(link.get("observed_step_id") or "")
            if source_id and source_id not in step_ids:
                failures.append(
                    f"proof_bundle.provenance[{index}].source_step_id references unknown step"
                )
            if observed_id and observed_id not in step_ids:
                failures.append(
                    f"proof_bundle.provenance[{index}].observed_step_id references unknown step"
                )

    return tuple(failures)


def _bundle_step_ids(bundle: dict[str, object]) -> set[str]:
    steps = bundle.get("steps")
    if not isinstance(steps, list):
        return set()
    ids: set[str] = set()
    for step in steps:
        if isinstance(step, dict):
            step_id = str(step.get("step_id") or "")
            if step_id:
                ids.add(step_id)
    return ids
