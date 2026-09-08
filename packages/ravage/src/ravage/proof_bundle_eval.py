from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from pentest_schemas.proof_bundle import ProofBundle, ProofVerifierVerdict

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_VERDICTS = frozenset({"accepted", "rejected", "inconclusive"})


class ProofBundleEvalInputError(ValueError):
    """Raised when the supplied evaluation dataset is malformed."""


@dataclass(frozen=True)
class ProofBundleEvalCase:
    case_id: str
    expected_verdict: str
    proof_bundle: dict[str, object]

    @property
    def bundle(self) -> dict[str, object]:
        return self.proof_bundle


@dataclass(frozen=True)
class ProofBundleEvalResult:
    case_id: str
    expected_verdict: str
    actual_verdict: str
    gate_failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProofBundleEvalReport:
    results: list[ProofBundleEvalResult] = field(default_factory=list)
    evaluation_mode: Literal["recorded_verdicts", "provided_verifier"] = "recorded_verdicts"

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(
            item.expected_verdict == item.actual_verdict and not item.gate_failures
            for item in self.results
        )

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def false_positive(self) -> int:
        return sum(
            item.expected_verdict != "accepted" and item.actual_verdict == "accepted"
            for item in self.results
        )

    @property
    def false_negative(self) -> int:
        return sum(
            item.expected_verdict == "accepted" and item.actual_verdict != "accepted"
            for item in self.results
        )

    @property
    def status(self) -> Literal["empty", "failed", "passed"]:
        if not self.total:
            return "empty"
        return "failed" if self.failed else "passed"

    @property
    def successful(self) -> bool:
        return self.status == "passed"

    def to_json(self) -> dict[str, object]:
        return {
            "evaluation_mode": self.evaluation_mode,
            "status": self.status,
            "successful": self.successful,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "results": [
                {
                    "case_id": item.case_id,
                    "expected_verdict": item.expected_verdict,
                    "actual_verdict": item.actual_verdict,
                    "gate_failures": list(item.gate_failures),
                }
                for item in self.results
            ],
        }


def evaluate_proof_bundle_cases(
    cases: list[ProofBundleEvalCase],
    *,
    verifier: Callable[[object], ProofVerifierVerdict] | None = None,
    semantic_verifier: Callable[[object], ProofVerifierVerdict] | None = None,
) -> ProofBundleEvalReport:
    """Score supplied offline cases; recorded verdicts are not independent verification."""
    results: list[ProofBundleEvalResult] = []
    selected_verifier = semantic_verifier or verifier
    validated_bundles = _validate_cases(cases)
    for case, bundle in zip(cases, validated_bundles, strict=True):
        verdict = (
            ProofVerifierVerdict.model_validate(selected_verifier(case.bundle))
            if selected_verifier is not None
            else bundle.verifier
        )
        gate_failures = _gate_failures(bundle, verdict)
        results.append(
            ProofBundleEvalResult(
                case.case_id,
                case.expected_verdict,
                verdict.verdict,
                gate_failures=gate_failures,
            )
        )
    return ProofBundleEvalReport(
        results,
        evaluation_mode="provided_verifier" if selected_verifier else "recorded_verdicts",
    )


def load_proof_bundle_eval_cases(path: Path) -> list[ProofBundleEvalCase]:
    cases: list[ProofBundleEvalCase] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            message = f"{path}:{line_number}: invalid JSON: {exc.msg}"
            raise ProofBundleEvalInputError(message) from exc
        if not isinstance(raw, dict):
            message = f"{path}:{line_number}: case must be a JSON object"
            raise ProofBundleEvalInputError(message)
        bundle = raw.get("proof_bundle")
        if "proof_bundle" not in raw:
            bundle = raw.get("bundle")
        if not isinstance(bundle, dict):
            message = f"{path}:{line_number}: proof_bundle must be an object"
            raise ProofBundleEvalInputError(message)
        case_id = raw.get("case_id")
        expected_verdict = raw.get("expected_verdict")
        if not isinstance(case_id, str) or not isinstance(expected_verdict, str):
            message = f"{path}:{line_number}: case_id and expected_verdict must be strings"
            raise ProofBundleEvalInputError(message)
        cases.append(
            ProofBundleEvalCase(
                case_id=case_id,
                expected_verdict=expected_verdict,
                proof_bundle=bundle,
            )
        )
    _validate_cases(cases)
    return cases


def write_proof_bundle_eval_report(report: ProofBundleEvalReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_cases(cases: list[ProofBundleEvalCase]) -> list[ProofBundle]:
    seen_ids: set[str] = set()
    bundles: list[ProofBundle] = []
    for case in cases:
        if not case.case_id.strip() or case.case_id in seen_ids:
            message = "proof-bundle evaluation case IDs must be nonempty and unique"
            raise ProofBundleEvalInputError(message)
        if case.expected_verdict not in _VERDICTS:
            message = f"case {case.case_id!r}: invalid expected_verdict"
            raise ProofBundleEvalInputError(message)
        seen_ids.add(case.case_id)
        try:
            bundle = ProofBundle.model_validate(case.bundle)
        except ValueError as exc:
            message = f"case {case.case_id!r}: invalid proof_bundle: {exc}"
            raise ProofBundleEvalInputError(message) from exc
        reference_errors = _bundle_reference_errors(bundle)
        if reference_errors:
            message = f"case {case.case_id!r}: " + "; ".join(reference_errors)
            raise ProofBundleEvalInputError(message)
        bundles.append(bundle)
    return bundles


def _bundle_reference_errors(bundle: ProofBundle) -> list[str]:
    errors: list[str] = []
    step_ids = [step.step_id for step in bundle.steps]
    if any(not step_id.strip() for step_id in step_ids) or len(set(step_ids)) != len(step_ids):
        errors.append("proof step IDs must be nonempty and unique")
    control_ids = [control.control_id for control in bundle.controls]
    if any(not item.strip() for item in control_ids) or len(set(control_ids)) != len(control_ids):
        errors.append("proof control IDs must be nonempty and unique")
    known_steps = set(step_ids)
    errors.extend(
        f"control {control.control_id!r} refers to an unknown proof step"
        for control in bundle.controls
        if any(step_id not in known_steps for step_id in control.step_ids)
    )
    if any(
        link.source_step_id not in known_steps or link.observed_step_id not in known_steps
        for link in bundle.provenance
    ):
        errors.append("provenance refers to an unknown proof step")
    return errors


def _gate_failures(bundle: ProofBundle, verdict: ProofVerifierVerdict) -> tuple[str, ...]:
    failures: list[str] = []
    if verdict.verdict != "accepted":
        return ()
    if not (verdict.impact or "").strip():
        failures.append("missing proof_bundle.verifier.impact")
    failures.extend(
        f"proof control {control.control_id!r} did not pass"
        for control in bundle.controls
        if not control.passed
    )
    return tuple(failures)
