from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pentest_schemas.proof_bundle import ProofVerifierVerdict


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

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(item.expected_verdict == item.actual_verdict and not item.gate_failures for item in self.results)

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def false_positive(self) -> int:
        return sum(item.expected_verdict != "accepted" and item.actual_verdict == "accepted" for item in self.results)

    @property
    def false_negative(self) -> int:
        return sum(item.expected_verdict == "accepted" and item.actual_verdict != "accepted" for item in self.results)


def evaluate_proof_bundle_cases(
    cases: list[ProofBundleEvalCase],
    *,
    verifier: Callable[[object], ProofVerifierVerdict] | None = None,
    semantic_verifier: Callable[[object], ProofVerifierVerdict] | None = None,
) -> ProofBundleEvalReport:
    results: list[ProofBundleEvalResult] = []
    selected_verifier = semantic_verifier or verifier
    for case in cases:
        verdict = _actual_verdict(case.bundle, selected_verifier)
        gate_failures = _gate_failures(case.bundle, verdict)
        results.append(
            ProofBundleEvalResult(
                case.case_id,
                case.expected_verdict,
                verdict,
                gate_failures=gate_failures,
            )
        )
    return ProofBundleEvalReport(results)


def load_proof_bundle_eval_cases(path: Path) -> list[ProofBundleEvalCase]:
    cases: list[ProofBundleEvalCase] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        raw = json.loads(text)
        bundle = raw.get("proof_bundle")
        if not isinstance(bundle, dict):
            bundle = raw.get("bundle")
        if not isinstance(bundle, dict):
            bundle = {}
        cases.append(
            ProofBundleEvalCase(
                case_id=str(raw["case_id"]),
                expected_verdict=str(raw["expected_verdict"]),
                proof_bundle=bundle,
            )
        )
    return cases


def _actual_verdict(
    bundle: dict[str, object],
    verifier: Callable[[object], ProofVerifierVerdict] | None,
) -> str:
    if verifier is not None:
        return verifier(bundle).verdict

    raw_verifier = bundle.get("verifier")
    if not isinstance(raw_verifier, dict):
        return "rejected"
    return str(raw_verifier.get("verdict") or "rejected")


def _gate_failures(bundle: dict[str, object], verdict: str) -> tuple[str, ...]:
    failures: list[str] = []
    if verdict != "accepted":
        return ()

    verifier = bundle.get("verifier")
    impact = ""
    if isinstance(verifier, dict):
        impact = str(verifier.get("impact") or "").strip()
    if not impact:
        failures.append("missing proof_bundle.verifier.impact")
    return tuple(failures)
