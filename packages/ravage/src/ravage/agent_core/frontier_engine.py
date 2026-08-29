from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.action_parser import parse_action
from ravage.agent_core.agent_specialists import available_specialists
from ravage.agent_core.agent_state import AgentState, append_unique, save_agent_state
from ravage.agent_core.agent_strategy import observation_digest
from ravage.agent_core.frontier_auth_transition import (
    AuthTransitionIssue,
    auth_transition_guard_message,
    detect_auth_transition_issue,
    remember_auth_bypass_matrix_attempt,
)
from ravage.agent_core.frontier_closure_obligation import (
    ClosureObligation,
    action_advances_closure_obligation,
    closure_handoff_rejection_count,
    closure_objective_matches_obligation,
    closure_obligation_after_checkpoint,
    closure_obligation_completed_by_result,
    closure_obligation_context,
    closure_obligation_from_observation,
    closure_obligation_message,
    closure_obligation_objective,
    closure_obligation_worker_attempted,
    mark_closure_obligation_attempted,
    pending_closure_obligation,
    record_closure_handoff_rejection,
    remember_closure_obligation,
)
from ravage.agent_core.frontier_context import focused_frontier_context
from ravage.agent_core.frontier_contract_completion import (
    objective_has_observed_request_contract,
    objective_requires_observed_request_contract,
    observed_request_contract_constraints,
    observed_request_contract_message,
)
from ravage.agent_core.frontier_contract_memory import (
    ContractRouteContext,
    remember_observed_request_contracts,
    remembered_request_contracts,
)
from ravage.agent_core.frontier_contract_specialist import (
    ContractSpecialistIssue,
    contract_specialist_completed,
    contract_specialist_constraints,
    contract_specialist_guard_message,
    contract_specialist_handoff_message,
    detect_contract_specialist_issue,
    objective_requires_contract_specialist,
    queue_contract_specialist_objective,
    remember_contract_specialist_completion,
    worker_attempted_contract_specialist,
)
from ravage.agent_core.frontier_credential_replay import (
    detect_rejected_credential_replay,
    rejected_credential_replay_constraints,
    rejected_credential_replay_message,
    remember_rejected_credential_replay,
    remembered_rejected_credential_replays,
)
from ravage.agent_core.frontier_evidence_revisit import (
    EvidenceRevisitIssue,
    detect_evidence_revisit_issue,
    evidence_revisit_constraints,
    evidence_revisit_guard_message,
    evidence_revisit_handoff_message,
    evidence_revisit_kind,
    next_evidence_revisit_objective,
    objective_is_evidence_revisit,
    objective_requires_oracle_revisit,
    worker_attempted_oracle_revisit,
)
from ravage.agent_core.frontier_extraction_memory import (
    ExtractionMemoryUpdate,
    extraction_calibration_objective,
    extraction_checkpoint_issue_message,
    latest_extraction_checkpoint,
    remember_extraction_checkpoint,
    remembered_extraction_checkpoints,
)
from ravage.agent_core.frontier_extractor_correctness import (
    ExtractorCorrectnessIssue,
    detect_extractor_correctness_issue,
    extractor_correctness_constraints,
    extractor_correctness_message,
)
from ravage.agent_core.frontier_objective_guard import (
    ObjectiveAlignmentIssue,
    alignment_guard_message,
    detect_objective_alignment_issue,
    missing_aligned_action_issue,
    objective_requires_aligned_action,
)
from ravage.agent_core.frontier_oracle_calibration import (
    OracleCalibrationIssue,
    assess_oracle_calibration,
    oracle_calibration_constraints,
    oracle_calibration_message,
    oracle_calibration_resolved_message,
    pending_oracle_calibration_issue,
    remember_oracle_calibration_issue,
    remembered_oracle_calibration_issues,
    resolve_oracle_calibration_issues,
)
from ravage.agent_core.frontier_progress_gate import (
    trusted_material_progress_tokens,
)
from ravage.agent_core.frontier_proof_work import (
    bounded_proof_work_constraints,
    bounded_proof_work_message,
    objective_requires_bounded_proof_work,
    worker_attempted_bounded_proof_work,
)
from ravage.agent_core.frontier_replay_contract import (
    AuthoritativeReplayContract,
    ReplayContractIssue,
    authoritative_replay_for_family,
    authoritative_replay_for_objective,
    detect_replay_contract_issue,
    rebase_frontier_objective,
    replay_contract_constraints,
    replay_contract_guard_message,
)
from ravage.agent_core.frontier_request_contract import (
    RequestContractIssue,
    action_satisfies_contract,
    detect_request_contract_issue,
    guard_message,
    pending_contract_issue,
    resolved_message,
)
from ravage.agent_core.frontier_route import (
    FrontierDecision,
    FrontierObjective,
    FrontierObjectiveBasis,
    FrontierObservation,
    FrontierRoute,
    FrontierRouteStatus,
    FrontierWorker,
    FrontierWorkerRole,
)
from ravage.agent_core.frontier_sql_oracle import (
    SqlOracleAssignmentIssue,
    SqlOracleContract,
    authoritative_sql_oracle_for_objective,
    detect_sql_oracle_assignment_issue,
    remember_sql_oracle_contracts,
    remembered_sql_oracle_contracts,
    sql_oracle_constraints,
    sql_oracle_correction_objective,
    sql_oracle_guard_message,
)
from ravage.agent_core.frontier_timeout_hygiene import (
    pending_timeout_recovery,
    resolve_timeout_recoveries,
    timeout_recovery_context,
    timeout_recovery_message,
    timeout_recovery_resolved_message,
)
from ravage.agent_core.observation_analysis import observation_facts
from ravage.agent_core.observation_memory import summarize_state
from ravage.agent_core.primitive_state import promote_primitives
from ravage.agent_core.recovery_evidence import assess_recovery_evidence
from ravage.agent_core.recovery_policy import ProgressSnapshot
from ravage.probe_suite import (
    authenticated_probe_unavailability,
    authenticated_unavailable_probes,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from ravage.run_data.workspace import AgentWorkspace

_MAX_SESSION_MESSAGES = 40
_MAX_SESSION_CONTENT_CHARS = 80_000
_MAX_STATE_ACTIONS = 200
_MAX_STATE_ATTEMPTS = 200
_EXPLOIT_PHASE_TURN = 3
_MAX_TOOL_ERROR_CHARS = 4_000


@dataclass(frozen=True)
class FrontierModelReply:
    content: str
    cost_usd: float = 0.0
    artifact_content: str | None = None

    def __post_init__(self) -> None:
        if self.cost_usd < 0:
            message = "frontier model reply cost_usd cannot be negative"
            raise ValueError(message)


class FrontierComplete(Protocol):
    def __call__(self, messages: list[dict[str, str]]) -> FrontierModelReply: ...


class FrontierExecute(Protocol):
    def __call__(
        self,
        action: dict[str, object],
        *,
        repeat_count: int,
        action_id: str,
    ) -> ActionResult: ...


@dataclass(frozen=True)
class FrontierSessionStore:
    root: Path

    @classmethod
    def open(cls, root: Path) -> FrontierSessionStore:
        root.mkdir(parents=True, exist_ok=True)
        return cls(root=root)

    def append(self, worker_id: str, *, role: str, content: str) -> None:
        path = self._path(worker_id)
        clipped = _clip_session_content(content)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"role": role, "content": clipped},
                    sort_keys=True,
                )
                + "\n"
            )

    def messages(self, worker_id: str) -> list[dict[str, str]]:
        path = self._path(worker_id)
        if not path.exists():
            return []
        messages: list[dict[str, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            role = str(payload.get("role") or "")
            content = str(payload.get("content") or "")
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content})
        return messages[-_MAX_SESSION_MESSAGES:]

    def _path(self, worker_id: str) -> Path:
        safe = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in worker_id)
        return self.root / f"{safe or 'worker'}.jsonl"


class FrontierEngine:
    """
    Execute bounded specialists while the deterministic route owns lifecycle.

    The model can choose one action at a time. Only executor-produced target
    observations can change the route's evidence or proof state.
    """

    def __init__(  # noqa: PLR0913 - dependencies form the engine boundary.
        self,
        *,
        route: FrontierRoute,
        state: AgentState,
        objectives: tuple[FrontierObjective, ...],
        workspace: AgentWorkspace,
        complete: FrontierComplete,
        execute: FrontierExecute,
    ) -> None:
        self.route = route
        self.state = state
        self.objectives = objectives
        self.workspace = workspace
        self.complete = complete
        self.execute = execute
        self.route_state_path = workspace.root / "frontier-route.json"
        self.sessions = FrontierSessionStore.open(workspace.root / "frontier-sessions")

    def run(self) -> FrontierRoute:  # noqa: C901, PLR0912, PLR0915 - explicit lifecycle.
        if self.route.pending_worker_id is not None:
            decision = self.route.account_interrupted_request()
            self._record_decision(decision, interrupted=True)
            self._persist()

        while self.route.status is FrontierRouteStatus.RUNNING:
            worker = self.route.begin_model_request()
            self.state.turn = self.route.total_model_requests_including_base
            self._persist()

            user_content = _worker_turn_context(
                route=self.route,
                state=self.state,
                worker=worker,
                queued_objectives=self.objectives,
            )
            self.sessions.append(worker.worker_id, role="user", content=user_content)
            messages = [
                {"role": "system", "content": _worker_system_prompt()},
                *self.sessions.messages(worker.worker_id),
            ]
            self.workspace.record_event(
                kind="frontier_model_request_started",
                payload=_request_event_payload(self.route, worker),
            )

            reply = self.complete(messages)
            if not isinstance(reply, FrontierModelReply):
                message = "frontier model callable must return FrontierModelReply"
                raise TypeError(message)
            artifact_content = reply.artifact_content or reply.content
            self.sessions.append(worker.worker_id, role="assistant", content=artifact_content)
            self.workspace.record_transcript(role="assistant", content=artifact_content)
            self.workspace.record_event(
                kind="frontier_model_reply_received",
                payload={
                    **_request_event_payload(self.route, worker),
                    "cost_usd": reply.cost_usd,
                },
            )

            action = parse_action(reply.content)
            contract_issue = pending_contract_issue(self.sessions.messages(worker.worker_id))
            closure_obligation = pending_closure_obligation(self.state)
            if self._handle_final_action(
                action=action,
                worker=worker,
                contract_issue=contract_issue,
                closure_obligation=closure_obligation,
                cost_usd=reply.cost_usd,
            ):
                self._persist()
                continue

            contract_specialist_issue = detect_contract_specialist_issue(
                worker.objective,
                action,
                attempts=self.state.attempts,
                worker_id=worker.worker_id,
                stage_completed=contract_specialist_completed(
                    self.state,
                    worker.objective,
                ),
            )
            if contract_specialist_issue is not None:
                decision = self._reject_contract_specialist_action(
                    worker=worker,
                    issue=contract_specialist_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="contract_specialist_action_rejected",
                )
                self._persist()
                continue

            auth_transition_issue = detect_auth_transition_issue(
                self.state,
                obligation=closure_obligation,
                action=action,
            )
            if auth_transition_issue is not None and closure_obligation is not None:
                decision = self._reject_auth_transition_action(
                    worker=worker,
                    obligation=closure_obligation,
                    issue=auth_transition_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="auth_transition_action_rejected",
                )
                self._persist()
                continue

            evidence_revisit_issue = detect_evidence_revisit_issue(
                worker.objective,
                action,
            )
            if evidence_revisit_issue is not None:
                decision = self._reject_evidence_revisit_action(
                    worker=worker,
                    issue=evidence_revisit_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="evidence_revisit_action_rejected",
                )
                self._persist()
                continue

            alignment_issue = detect_objective_alignment_issue(
                worker.objective,
                action,
            )
            if alignment_issue is not None and not (
                closure_obligation is not None
                and action_advances_closure_obligation(
                    action,
                    closure_obligation,
                )
            ):
                decision = self._reject_objective_drift(
                    worker=worker,
                    issue=alignment_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="objective_alignment_rejected",
                )
                self._persist()
                continue

            replay_contract = authoritative_replay_for_objective(
                self.state,
                worker.objective,
                target_url=self.route.base.target_url,
            )
            replay_issue = detect_replay_contract_issue(
                action,
                replay_contract,
                allow_candidate_correction=(
                    objective_requires_observed_request_contract(worker.objective)
                ),
            )
            if replay_issue is not None and replay_contract is not None:
                decision = self._reject_authoritative_replay_drift(
                    worker=worker,
                    contract=replay_contract,
                    issue=replay_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="authoritative_replay_rejected",
                )
                self._persist()
                continue

            sql_oracle = authoritative_sql_oracle_for_objective(
                self.state,
                worker.objective,
            )
            sql_oracle_issue = detect_sql_oracle_assignment_issue(
                worker.objective,
                action,
                sql_oracle,
            )
            if sql_oracle_issue is not None and sql_oracle is not None:
                decision = self._reject_sql_oracle_assignment(
                    worker=worker,
                    contract=sql_oracle,
                    issue=sql_oracle_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="sql_oracle_assignment_rejected",
                )
                self._persist()
                continue

            extractor_issue = detect_extractor_correctness_issue(
                worker.objective,
                action,
            )
            if extractor_issue is not None:
                decision = self._reject_extractor_correctness(
                    worker=worker,
                    issue=extractor_issue,
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="extractor_correctness_rejected",
                )
                self._persist()
                continue

            action_id = str(uuid4())
            repeat_count = self.state.ledger.remember(
                action,
                context=worker.objective.fingerprint,
            )
            self.workspace.record_event(
                kind="frontier_action_started",
                payload=_action_started_event_payload(
                    self.route,
                    worker,
                    action=action,
                    action_id=action_id,
                    repeat_count=repeat_count,
                ),
            )
            outcome = self._execute_visible(
                action,
                repeat_count=repeat_count,
                action_id=action_id,
            )
            if (
                objective_requires_contract_specialist(worker.objective)
                and str(action.get("action") or "") == "run_probe"
                and str(action.get("probe") or "") == worker.objective.probe
                and remember_contract_specialist_completion(
                    self.state,
                    worker.objective,
                )
            ):
                self.workspace.record_event(
                    kind="frontier_contract_specialist_completed",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "probe": worker.objective.probe,
                    },
                )
            target_observation = _trusted_target_observation(outcome)
            if (
                outcome.ok
                and closure_obligation is not None
                and remember_auth_bypass_matrix_attempt(
                    self.state,
                    obligation=closure_obligation,
                    action=action,
                    observation=target_observation,
                )
            ):
                self.workspace.record_event(
                    kind="frontier_auth_bypass_matrix_attempted",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "obligation_fingerprint": closure_obligation.fingerprint,
                        "stage": closure_obligation.stage,
                    },
                )
            self._remember_target_contracts(
                worker=worker,
                target_observation=target_observation,
            )
            oracle_contracts = remember_sql_oracle_contracts(
                self.state,
                target_observation,
                objective=worker.objective,
            )
            if oracle_contracts:
                self.workspace.record_event(
                    kind="frontier_sql_oracle_remembered",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "contract_fingerprints": [item.fingerprint for item in oracle_contracts],
                    },
                )
            calibration = assess_oracle_calibration(
                worker.objective,
                target_observation,
            )
            if calibration.issue is not None:
                remember_oracle_calibration_issue(self.state, calibration.issue)
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=oracle_calibration_message(
                        worker.objective,
                        calibration.issue,
                    ),
                )
                self.workspace.record_event(
                    kind="frontier_oracle_calibration_rejected",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        **calibration.issue.to_json(),
                    },
                )
            elif calibration.calibrated:
                resolved_calibrations = resolve_oracle_calibration_issues(
                    self.state,
                    objective=worker.objective,
                )
                if resolved_calibrations:
                    self.sessions.append(
                        worker.worker_id,
                        role="user",
                        content=oracle_calibration_resolved_message(),
                    )
                    self.workspace.record_event(
                        kind="frontier_oracle_calibration_resolved",
                        payload={
                            "worker_id": worker.worker_id,
                            "objective_fingerprint": worker.objective.fingerprint,
                            "resolved_fingerprints": list(resolved_calibrations),
                        },
                    )
            extraction_update = (
                ExtractionMemoryUpdate()
                if calibration.issue is not None or not outcome.ok
                else remember_extraction_checkpoint(
                    self.state,
                    objective=worker.objective,
                    action=action,
                    observation=target_observation,
                    oracle_calibrated=(
                        calibration.calibrated
                        or authoritative_sql_oracle_for_objective(
                            self.state,
                            worker.objective,
                        )
                        is not None
                    ),
                )
            )
            checkpoint_correction = None
            if extraction_update.checkpoint is not None:
                checkpoint = extraction_update.checkpoint
                self.workspace.record_event(
                    kind="frontier_extraction_checkpoint_remembered",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "checkpoint_fingerprint": checkpoint.fingerprint,
                        "candidate_kind": checkpoint.candidate_kind,
                        "position": checkpoint.position,
                        "expected_length": checkpoint.expected_length,
                        "complete": checkpoint.complete,
                    },
                )
            elif extraction_update.issue is not None:
                checkpoint_correction = extraction_calibration_objective(
                    worker.objective,
                    extraction_update.issue,
                )
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=extraction_checkpoint_issue_message(
                        worker.objective,
                        extraction_update.issue,
                    ),
                )
                self.workspace.record_event(
                    kind="frontier_extraction_checkpoint_quarantined",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "correction_fingerprint": checkpoint_correction.fingerprint,
                        **extraction_update.issue.to_json(),
                    },
                )
            replay_checkpoint = extraction_update.checkpoint or latest_extraction_checkpoint(
                self.state,
                objective=worker.objective,
            )
            rejected_replay = detect_rejected_credential_replay(
                objective=worker.objective,
                checkpoint=replay_checkpoint,
                action=action,
                observation=target_observation,
            )
            if rejected_replay is not None and remember_rejected_credential_replay(
                self.state,
                rejected_replay,
            ):
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=rejected_credential_replay_message(rejected_replay),
                )
                self.workspace.record_event(
                    kind="frontier_credential_replay_rejected",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        **rejected_replay.to_json(),
                    },
                )
            new_obligation = closure_obligation_from_observation(
                target_observation,
                family=worker.objective.family,
            )
            if (
                new_obligation is None
                and closure_obligation is not None
                and outcome.ok
                and action_advances_closure_obligation(action, closure_obligation)
            ):
                new_obligation = closure_obligation_after_checkpoint(
                    closure_obligation,
                    extraction_update.checkpoint,
                )
            if closure_obligation is not None and closure_obligation_completed_by_result(
                action,
                closure_obligation,
                tool_ok=outcome.ok,
                observation=target_observation,
                checkpoint=extraction_update.checkpoint,
            ):
                mark_closure_obligation_attempted(self.state, closure_obligation)
                self.workspace.record_event(
                    kind="frontier_closure_obligation_completed",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "obligation_fingerprint": closure_obligation.fingerprint,
                        "stage": closure_obligation.stage,
                    },
                )
            if new_obligation is not None:
                remember_closure_obligation(self.state, new_obligation)
            if contract_issue is not None and action_satisfies_contract(
                action,
                contract_issue,
            ):
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=resolved_message(contract_issue),
                )
                self.workspace.record_event(
                    kind="frontier_request_contract_resolved",
                    payload=_contract_event_payload(worker, contract_issue),
                )
            self.sessions.append(
                worker.worker_id,
                role="user",
                content=f"TOOL_OBSERVATION\n{outcome.observation}",
            )
            self.workspace.record_transcript(role="tool", content=outcome.observation)
            self.workspace.record_event(
                kind="frontier_action_completed",
                payload={
                    "worker_id": worker.worker_id,
                    "action_id": action_id,
                    "action": action,
                    "outcome": outcome.to_json(),
                },
            )
            self._update_timeout_recovery(worker=worker, outcome=outcome)
            if (
                new_obligation is not None
                and pending_closure_obligation(self.state) == new_obligation
            ):
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=closure_obligation_message(new_obligation),
                )
                self.workspace.record_event(
                    kind="frontier_closure_obligation_opened",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": worker.objective.fingerprint,
                        "obligation_fingerprint": new_obligation.fingerprint,
                        "stage": new_obligation.stage,
                        "artifact_count": len(new_obligation.artifacts),
                    },
                )
            observed_issue = detect_request_contract_issue(
                action,
                outcome.evidence_observation or outcome.observation,
            )
            if observed_issue is not None:
                self.sessions.append(
                    worker.worker_id,
                    role="user",
                    content=guard_message(observed_issue),
                )
                self.workspace.record_event(
                    kind="frontier_request_contract_guarded",
                    payload=_contract_event_payload(worker, observed_issue),
                )
            self._remember_action(
                worker=worker,
                action=action,
                outcome=outcome,
                action_id=action_id,
                repeat_count=repeat_count,
            )
            if calibration.issue is not None:
                decision = self._record_oracle_calibration_failure(
                    cost_usd=reply.cost_usd,
                )
                self._record_decision(
                    decision,
                    lifecycle="oracle_calibration_rejected",
                )
            else:
                observation = _frontier_observation(
                    action=action,
                    outcome=outcome,
                    cost_usd=reply.cost_usd,
                    next_objective=checkpoint_correction or self._next_objective(),
                    objective=worker.objective,
                    coordinator_progress=extraction_update.material_progress,
                )
                decision = self.route.record_observation(observation)
                self._record_decision(decision)
            self._persist()

        return self.route

    def _handle_final_action(
        self,
        *,
        action: Mapping[str, object],
        worker: FrontierWorker,
        contract_issue: RequestContractIssue | None,
        closure_obligation: ClosureObligation | None,
        cost_usd: float,
    ) -> bool:
        if action.get("action") != "final":
            return False
        if contract_issue is not None:
            decision = self._reject_contract_handoff(
                worker=worker,
                issue=contract_issue,
                cost_usd=cost_usd,
            )
            lifecycle = "request_contract_handoff_rejected"
        elif closure_obligation is not None:
            decision, lifecycle = self._closure_final_decision(
                action=action,
                worker=worker,
                obligation=closure_obligation,
                cost_usd=cost_usd,
            )
        elif objective_rejection := self._objective_handoff_rejection(
            worker=worker,
            cost_usd=cost_usd,
        ):
            decision, lifecycle = objective_rejection
        elif calibration_issue := pending_oracle_calibration_issue(
            self.state,
            objective=worker.objective,
        ):
            decision = self._reject_oracle_calibration_handoff(
                worker=worker,
                issue=calibration_issue,
                cost_usd=cost_usd,
            )
            lifecycle = "oracle_calibration_handoff_rejected"
        elif objective_requires_bounded_proof_work(
            worker.objective
        ) and not self._worker_attempted_bounded_proof_work(worker.worker_id):
            decision = self._reject_bounded_proof_work_handoff(
                worker=worker,
                cost_usd=cost_usd,
            )
            lifecycle = "bounded_proof_work_handoff_rejected"
        elif worker.role is FrontierWorkerRole.PROOF_CLOSURE and not self._worker_has_tool_action(
            worker.worker_id
        ):
            decision = self._reject_premature_proof_handoff(
                worker=worker,
                cost_usd=cost_usd,
            )
            lifecycle = "proof_closure_handoff_rejected"
        else:
            next_objective = self._next_objective()
            if next_objective is not None and objective_is_evidence_revisit(next_objective):
                self.workspace.record_event(
                    kind="frontier_evidence_revisit_offered",
                    payload={
                        "worker_id": worker.worker_id,
                        "objective_fingerprint": next_objective.fingerprint,
                        "evidence_revisit_kind": evidence_revisit_kind(next_objective),
                    },
                )
            decision = self.route.record_handoff(
                summary=str(action.get("summary") or ""),
                next_objective=next_objective,
                cost_usd=cost_usd,
            )
            lifecycle = "worker_handoff"
        self._record_decision(decision, lifecycle=lifecycle)
        return True

    def _closure_final_decision(
        self,
        *,
        action: Mapping[str, object],
        worker: FrontierWorker,
        obligation: ClosureObligation,
        cost_usd: float,
    ) -> tuple[FrontierDecision, str]:
        focused_attempt = closure_obligation_worker_attempted(
            self.state,
            obligation=obligation,
            worker_id=worker.worker_id,
        )
        prior_rejections = closure_handoff_rejection_count(
            self.state,
            obligation=obligation,
            worker_id=worker.worker_id,
        )
        if focused_attempt or prior_rejections >= 1:
            next_objective = self._next_objective_after_closure(
                template=worker.objective,
                obligation=obligation,
            )
            self.workspace.record_event(
                kind="frontier_closure_obligation_worker_handoff",
                payload={
                    "worker_id": worker.worker_id,
                    "objective_fingerprint": worker.objective.fingerprint,
                    "obligation_fingerprint": obligation.fingerprint,
                    "closure_objective_fingerprint": (
                        next_objective.fingerprint if next_objective is not None else ""
                    ),
                    "stage": obligation.stage,
                    "reason": (
                        "focused_action_attempted" if focused_attempt else "repeated_handoff"
                    ),
                },
            )
            return (
                self.route.record_handoff(
                    summary=str(action.get("summary") or ""),
                    next_objective=next_objective,
                    cost_usd=cost_usd,
                ),
                "closure_obligation_worker_handoff",
            )
        record_closure_handoff_rejection(
            self.state,
            obligation=obligation,
            worker_id=worker.worker_id,
        )
        return (
            self._reject_closure_handoff(
                worker=worker,
                obligation=obligation,
                cost_usd=cost_usd,
            ),
            "closure_obligation_handoff_rejected",
        )

    def _next_objective_after_closure(
        self,
        *,
        template: FrontierObjective,
        obligation: ClosureObligation,
    ) -> FrontierObjective | None:
        closure_already_routed = any(
            closure_objective_matches_obligation(worker.objective, obligation)
            for worker in self.route.workers
        )
        if not closure_already_routed:
            routed = closure_obligation_objective(template, obligation)
            if routed.fingerprint not in self.route.attempted_objective_fingerprints:
                return routed
        return self._next_objective()

    def _objective_handoff_rejection(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> tuple[FrontierDecision, str] | None:
        mandatory = self._mandatory_stage_handoff_rejection(
            worker=worker,
            cost_usd=cost_usd,
        )
        if mandatory is not None:
            return mandatory
        if objective_requires_aligned_action(
            worker.objective
        ) and not self._worker_has_aligned_tool_action(worker.worker_id):
            return (
                self._reject_objective_drift(
                    worker=worker,
                    issue=missing_aligned_action_issue(worker.objective),
                    cost_usd=cost_usd,
                ),
                "objective_alignment_handoff_rejected",
            )
        if objective_requires_observed_request_contract(
            worker.objective
        ) and not objective_has_observed_request_contract(
            self.state,
            worker.objective,
            target_url=self.route.base.target_url,
        ):
            return (
                self._reject_observed_contract_handoff(
                    worker=worker,
                    cost_usd=cost_usd,
                ),
                "observed_contract_handoff_rejected",
            )
        return None

    def _reject_auth_transition_action(
        self,
        *,
        worker: FrontierWorker,
        obligation: ClosureObligation,
        issue: AuthTransitionIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=auth_transition_guard_message(obligation, issue),
        )
        self.workspace.record_event(
            kind="frontier_auth_transition_action_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_auth_transition_gate",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _mandatory_stage_handoff_rejection(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> tuple[FrontierDecision, str] | None:
        if objective_requires_contract_specialist(worker.objective) and not (
            contract_specialist_completed(self.state, worker.objective)
            or worker_attempted_contract_specialist(
                self.state.attempts,
                worker_id=worker.worker_id,
                probe=worker.objective.probe,
            )
        ):
            return (
                self._reject_contract_specialist_handoff(
                    worker=worker,
                    cost_usd=cost_usd,
                ),
                "contract_specialist_handoff_rejected",
            )
        if objective_requires_oracle_revisit(
            worker.objective
        ) and not worker_attempted_oracle_revisit(
            self.state.attempts,
            worker_id=worker.worker_id,
        ):
            return (
                self._reject_evidence_revisit_handoff(
                    worker=worker,
                    cost_usd=cost_usd,
                ),
                "evidence_revisit_handoff_rejected",
            )
        return None

    def _reject_contract_specialist_action(
        self,
        *,
        worker: FrontierWorker,
        issue: ContractSpecialistIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=contract_specialist_guard_message(worker.objective, issue),
        )
        self.workspace.record_event(
            kind="frontier_contract_specialist_action_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_contract_specialist_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=None,
                cost_usd=cost_usd,
            )
        )

    def _reject_contract_specialist_handoff(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=contract_specialist_handoff_message(worker.objective),
        )
        self.workspace.record_event(
            kind="frontier_contract_specialist_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "probe": worker.objective.probe,
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_contract_specialist_handoff_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=None,
                cost_usd=cost_usd,
            )
        )

    def _reject_evidence_revisit_action(
        self,
        *,
        worker: FrontierWorker,
        issue: EvidenceRevisitIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=evidence_revisit_guard_message(worker.objective, issue),
        )
        self.workspace.record_event(
            kind="frontier_evidence_revisit_action_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_evidence_revisit_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=None,
                cost_usd=cost_usd,
            )
        )

    def _reject_evidence_revisit_handoff(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=evidence_revisit_handoff_message(worker.objective),
        )
        self.workspace.record_event(
            kind="frontier_evidence_revisit_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_evidence_revisit_handoff_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=None,
                cost_usd=cost_usd,
            )
        )

    def _reject_objective_drift(
        self,
        *,
        worker: FrontierWorker,
        issue: ObjectiveAlignmentIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=alignment_guard_message(worker.objective, issue),
        )
        self.workspace.record_event(
            kind="frontier_objective_alignment_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_objective_alignment_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _reject_authoritative_replay_drift(
        self,
        *,
        worker: FrontierWorker,
        contract: AuthoritativeReplayContract,
        issue: ReplayContractIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=replay_contract_guard_message(contract, issue),
        )
        self.workspace.record_event(
            kind="frontier_authoritative_replay_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_authoritative_replay_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _reject_sql_oracle_assignment(
        self,
        *,
        worker: FrontierWorker,
        contract: SqlOracleContract,
        issue: SqlOracleAssignmentIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=sql_oracle_guard_message(contract, issue),
        )
        correction = sql_oracle_correction_objective(worker.objective, contract)
        self.workspace.record_event(
            kind="frontier_sql_oracle_assignment_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "correction_fingerprint": correction.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_sql_oracle_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=correction,
                cost_usd=cost_usd,
            )
        )

    def _reject_extractor_correctness(
        self,
        *,
        worker: FrontierWorker,
        issue: ExtractorCorrectnessIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=extractor_correctness_message(worker.objective, issue),
        )
        self.workspace.record_event(
            kind="frontier_extractor_correctness_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_extractor_correctness_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _remember_target_contracts(
        self,
        *,
        worker: FrontierWorker,
        target_observation: str,
    ) -> None:
        update = remember_observed_request_contracts(
            self.state,
            target_observation,
            context=ContractRouteContext(
                target_url=self.route.base.target_url,
                family=worker.objective.family,
                objective_endpoint=worker.objective.endpoint,
                objective_inputs=worker.objective.inputs,
            ),
        )
        if not update.contracts:
            return
        self.workspace.record_event(
            kind="frontier_request_contract_remembered",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "contract_fingerprints": [item.fingerprint for item in update.contracts],
                "superseded_sql_replays": update.superseded_sql_replays,
            },
        )
        self._rebase_pending_objectives(worker=worker)

    def _rebase_pending_objectives(self, *, worker: FrontierWorker) -> None:
        contract = authoritative_replay_for_family(
            self.state,
            family=worker.objective.family,
            target_url=self.route.base.target_url,
            preferred_inputs=worker.objective.inputs,
        )
        if contract is None or not contract.authoritative:
            return
        attempted_stages = {_objective_stage_key(item.objective) for item in self.route.workers}
        rebased: list[dict[str, object]] = []
        objectives: list[FrontierObjective] = []
        for objective in self.objectives:
            if (
                objective.family == contract.family
                and objective_requires_contract_specialist(objective)
                and _objective_stage_key(objective) not in attempted_stages
            ):
                continue
            if (
                objective.family != contract.family
                or _objective_stage_key(objective) in attempted_stages
            ):
                objectives.append(objective)
                continue
            updated = rebase_frontier_objective(objective, contract)
            objectives.append(updated)
            if updated.fingerprint == objective.fingerprint:
                continue
            rebased.append(
                {
                    "payload_class": objective.payload_class,
                    "previous_fingerprint": objective.fingerprint,
                    "rebased_fingerprint": updated.fingerprint,
                }
            )
        queued, specialist = queue_contract_specialist_objective(
            objectives,
            contract,
            attempted_stage_keys=attempted_stages,
        )
        self.objectives = queued
        if specialist is not None:
            self.workspace.record_event(
                kind="frontier_contract_specialist_objective_queued",
                payload={
                    "worker_id": worker.worker_id,
                    "contract_fingerprint": contract.fingerprint,
                    "objective_fingerprint": specialist.fingerprint,
                    "probe": specialist.probe,
                },
            )
        if not rebased:
            return
        self.workspace.record_event(
            kind="frontier_pending_objectives_rebased",
            payload={
                "worker_id": worker.worker_id,
                "contract_fingerprint": contract.fingerprint,
                "family": contract.family,
                "objectives": rebased,
            },
        )

    def _update_timeout_recovery(
        self,
        *,
        worker: FrontierWorker,
        outcome: ActionResult,
    ) -> None:
        recovery = pending_timeout_recovery(self.state)
        if recovery is None:
            return
        if outcome.timed_out:
            self.sessions.append(
                worker.worker_id,
                role="user",
                content=timeout_recovery_message(recovery),
            )
            self.workspace.record_event(
                kind="frontier_timeout_recovery_required",
                payload={
                    "worker_id": worker.worker_id,
                    "objective_fingerprint": worker.objective.fingerprint,
                    "cleanup_fingerprint": recovery.fingerprint,
                    "cleanup_status": recovery.status,
                    "cleanup_verified": recovery.verified,
                },
            )
            return
        if not outcome.ok or not outcome.evidence_source_kind.startswith("tool_"):
            return
        resolved = resolve_timeout_recoveries(self.state)
        if not resolved:
            return
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=timeout_recovery_resolved_message(),
        )
        self.workspace.record_event(
            kind="frontier_timeout_recovery_resolved",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "resolved_fingerprints": list(resolved),
            },
        )

    def _reject_premature_proof_handoff(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=(
                "COORDINATOR_PROOF_CLOSURE_GATE\n"
                "A confirmed vulnerability signal is not objective proof. Execute at "
                "least one scoped target-observed closure action before returning control."
            ),
        )
        self.workspace.record_event(
            kind="frontier_proof_closure_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_proof_closure_gate",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _reject_closure_handoff(
        self,
        *,
        worker: FrontierWorker,
        obligation: ClosureObligation,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=closure_obligation_message(obligation),
        )
        self.workspace.record_event(
            kind="frontier_closure_obligation_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "obligation_fingerprint": obligation.fingerprint,
                "stage": obligation.stage,
            },
        )
        next_objective = self._next_objective_after_closure(
            template=worker.objective,
            obligation=obligation,
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_closure_obligation_gate",
                observation_digest="",
                route_fingerprint="",
                next_objective=next_objective,
                cost_usd=cost_usd,
            )
        )

    def _worker_has_tool_action(self, worker_id: str) -> bool:
        return any(
            str(attempt.get("frontier_worker_id") or "") == worker_id
            for attempt in self.state.attempts
        )

    def _worker_has_aligned_tool_action(self, worker_id: str) -> bool:
        return any(
            str(attempt.get("frontier_worker_id") or "") == worker_id
            and attempt.get("frontier_objective_aligned") is True
            for attempt in self.state.attempts
        )

    def _worker_attempted_bounded_proof_work(self, worker_id: str) -> bool:
        return worker_attempted_bounded_proof_work(
            self.state.attempts,
            worker_id=worker_id,
        )

    def _reject_bounded_proof_work_handoff(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=bounded_proof_work_message(worker.objective),
        )
        self.workspace.record_event(
            kind="frontier_bounded_proof_work_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_bounded_proof_work_gate",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _record_oracle_calibration_failure(
        self,
        *,
        cost_usd: float,
    ) -> FrontierDecision:
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_oracle_calibration_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _reject_oracle_calibration_handoff(
        self,
        *,
        worker: FrontierWorker,
        issue: OracleCalibrationIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=oracle_calibration_message(worker.objective, issue),
        )
        self.workspace.record_event(
            kind="frontier_oracle_calibration_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                **issue.to_json(),
            },
        )
        return self._record_oracle_calibration_failure(cost_usd=cost_usd)

    def _reject_observed_contract_handoff(
        self,
        *,
        worker: FrontierWorker,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=observed_request_contract_message(worker.objective),
        )
        self.workspace.record_event(
            kind="frontier_observed_contract_handoff_rejected",
            payload={
                "worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
            },
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_observed_contract_gate",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _reject_contract_handoff(
        self,
        *,
        worker: FrontierWorker,
        issue: RequestContractIssue,
        cost_usd: float,
    ) -> FrontierDecision:
        self.sessions.append(
            worker.worker_id,
            role="user",
            content=guard_message(issue),
        )
        self.workspace.record_event(
            kind="frontier_request_contract_handoff_rejected",
            payload=_contract_event_payload(worker, issue),
        )
        return self.route.record_observation(
            FrontierObservation(
                source_kind="coordinator_request_contract_guard",
                observation_digest="",
                route_fingerprint="",
                next_objective=self._next_objective(),
                cost_usd=cost_usd,
            )
        )

    def _execute_visible(
        self,
        action: dict[str, object],
        *,
        repeat_count: int,
        action_id: str,
    ) -> ActionResult:
        try:
            return self.execute(
                action,
                repeat_count=repeat_count,
                action_id=action_id,
            )
        except Exception as exc:  # noqa: BLE001 - tool failures are worker observations.
            detail = f"{type(exc).__name__}: {exc}"[:_MAX_TOOL_ERROR_CHARS]
            return ActionResult(
                ok=False,
                observation=f"tool execution failed: {detail}",
                outcome="tool_error",
                evidence_source_kind="tool_error",
            )

    def _next_objective(self) -> FrontierObjective | None:
        attempted_keys = {_objective_stage_key(worker.objective) for worker in self.route.workers}
        pending: list[FrontierObjective] = []
        for objective in self.objectives:
            if _objective_stage_key(objective) in attempted_keys:
                continue
            candidate = _as_counterfactual(objective)
            if candidate.fingerprint in self.route.attempted_objective_fingerprints:
                continue
            pending.append(candidate)
        if pending and pending[0].family == "sql_injection":
            return pending[0]
        revisit = next_evidence_revisit_objective(
            self.state,
            self.objectives,
            target_url=self.route.base.target_url,
            attempted_fingerprints=self.route.attempted_objective_fingerprints,
        )
        return revisit or (pending[0] if pending else None)

    def _remember_action(
        self,
        *,
        worker: FrontierWorker,
        action: Mapping[str, object],
        outcome: ActionResult,
        action_id: str,
        repeat_count: int,
    ) -> None:
        if outcome.flag and outcome.evidence_source_kind.startswith("tool_"):
            append_unique(self.state.flags, outcome.flag, limit=20)
        if outcome.observation and not self.state.last_observation:
            digest = observation_digest(outcome.observation)
            digest["source_kind"] = outcome.evidence_source_kind
            self.state.last_observation = digest
        for item in observation_facts(outcome.observation):
            append_unique(self.state.facts, item, limit=80)
        for item in _strings(action.get("memory_updates")):
            append_unique(self.state.facts, item, limit=80)
        for item in _strings(action.get("hypotheses")):
            append_unique(self.state.hypotheses, item, limit=40)
        record = {
            "turn": self.state.turn,
            "action": action.get("action"),
            "task_id": action.get("task_id"),
            "strategy": action.get("strategy"),
            "probe": action.get("probe"),
            "ok": outcome.ok,
            "outcome": outcome.outcome,
            "repeat_count": repeat_count,
            "frontier_worker_id": worker.worker_id,
            "frontier_role": worker.role.value,
        }
        self.state.actions.append(record)
        del self.state.actions[:-_MAX_STATE_ACTIONS]
        self.state.attempts.append(
            {
                "action_id": action_id,
                "turn": self.state.turn,
                "selected_action": dict(action),
                "outcome": outcome.to_json(),
                "frontier_worker_id": worker.worker_id,
                "objective_fingerprint": worker.objective.fingerprint,
                "frontier_objective_aligned": True,
            }
        )
        del self.state.attempts[:-_MAX_STATE_ATTEMPTS]
        promote_primitives(self.state)
        if self.state.flags:
            self.state.phase = "done"
        elif self.state.primitives or self.state.turn >= _EXPLOIT_PHASE_TURN:
            self.state.phase = "exploit"
        self.state.summary = summarize_state(self.state)

    def _record_decision(
        self,
        decision: FrontierDecision,
        **extra: object,
    ) -> None:
        self.workspace.record_event(
            kind="frontier_route_decision",
            payload={
                "status": decision.status.value,
                "reason": decision.reason,
                "model_requests_started": decision.model_requests_started,
                "remaining_model_requests": decision.remaining_model_requests,
                "active_worker_id": decision.active_worker_id,
                **extra,
            },
        )

    def _persist(self) -> None:
        self.route.save(self.route_state_path)
        save_agent_state(
            self.workspace.state_path,
            target_url=self.route.base.target_url,
            state=self.state,
        )


def _worker_system_prompt() -> str:
    return (
        "You are one bounded specialist inside an autonomous security route for an "
        "authorized target. Work depth-first on the assigned objective. Return exactly "
        "one JSON action and no markdown. Tool observations are evidence; your own prose "
        "is not. A final action returns control to the deterministic coordinator and can "
        "never declare the whole route solved."
    )


def _worker_turn_context(
    *,
    route: FrontierRoute,
    state: AgentState,
    worker: FrontierWorker,
    queued_objectives: tuple[FrontierObjective, ...],
) -> str:
    replay_contract = authoritative_replay_for_objective(
        state,
        worker.objective,
        target_url=route.base.target_url,
    )
    sql_oracle = authoritative_sql_oracle_for_objective(
        state,
        worker.objective,
    )
    payload = {
        "target_url": route.base.target_url,
        "scope": list(route.scope),
        "assignment": worker.objective.to_json(),
        "assigned_specialist": _assigned_specialist(worker.objective.probe),
        "objective_constraints": [
            *_objective_constraints(worker.objective),
            *replay_contract_constraints(replay_contract),
            *sql_oracle_constraints(sql_oracle),
            *contract_specialist_constraints(
                state,
                worker.objective,
                worker_id=worker.worker_id,
            ),
            *evidence_revisit_constraints(worker.objective),
            *rejected_credential_replay_constraints(
                state,
                objective=worker.objective,
            ),
        ],
        "worker": {
            "worker_id": worker.worker_id,
            "role": worker.role.value,
            "lease_limit": worker.lease_limit,
            "lease_used": worker.requests_started,
        },
        "role_directives": _role_directives(worker.role),
        "coordinator_memory": {
            "replay_contract": (replay_contract.to_json() if replay_contract is not None else None),
            "sql_oracle_contracts": remembered_sql_oracle_contracts(
                state,
                objective=worker.objective,
            ),
            "request_contracts": remembered_request_contracts(state),
            "pending_closure_obligation": closure_obligation_context(state),
            "timeout_recovery": timeout_recovery_context(state),
            "sql_extraction_checkpoints": remembered_extraction_checkpoints(
                state,
                objective=worker.objective,
            ),
            "rejected_credential_replays": remembered_rejected_credential_replays(
                state,
                objective=worker.objective,
            ),
            "oracle_calibration_issues": remembered_oracle_calibration_issues(
                state,
                objective=worker.objective,
            ),
        },
        "route_budget": {
            "model_requests_used": route.model_requests_started,
            "model_requests_remaining": route.remaining_model_requests,
            "max_model_requests": route.config.max_model_requests,
        },
        "working_state": focused_frontier_context(state, worker.objective),
        "known_frontier_count": len(queued_objectives),
        "action_contract": {
            "run_probe": {
                "action": "run_probe",
                "probe": "one available Ravage specialist",
                "expected_signal": "target observation that confirms or falsifies the route",
            },
            "run_command": {
                "action": "run_command",
                "command": "one scoped command",
                "expected_signal": "specific target response",
                "timeout_seconds": "optional integer 1-120",
            },
            "run_python": {
                "action": "run_python",
                "code": "one scoped script",
                "expected_signal": "specific target response",
                "timeout_seconds": "optional integer 1-120",
            },
            "validate_poc": {
                "action": "validate_poc",
                "steps": [
                    {
                        "evidence_role": "control",
                        "method": "same method as exploit",
                        "url": "same endpoint as exploit",
                        "form": {"field": "benign control value"},
                        "expect_contains": "stable control evidence",
                    },
                    {
                        "evidence_role": "exploit",
                        "method": "same method as control",
                        "url": "same endpoint as control",
                        "form": {"field": "security test value with the same input shape"},
                        "expect_contains": "class-specific security-relevant differential",
                    },
                ],
                "finding": {
                    "vuln_class": (
                        "sql_injection, ssti, server_side_template_injection, "
                        "template_injection, path_traversal, lfi, local_file_inclusion, "
                        "arbitrary_file_read, or file_read"
                    ),
                    "severity": "critical, high, medium, low, or informational",
                    "hypothesis": "concise evidence-backed vulnerability statement",
                    "impact": "bounded impact supported by explicit replay expectations",
                    "exploit_steps": ["concise operator-readable replay step"],
                },
            },
            "capture_flag": {
                "action": "capture_flag",
                "flag": "exact proof copied from the latest target observation",
            },
            "final": {
                "action": "final",
                "summary": "why this worker should return control",
            },
        },
        "rules": [
            "Use one action only.",
            "Stay within scope.",
            "Do not repeat a semantic route without changing a material variable.",
            "Verify target-observed request fields before declaring a route exhausted.",
            "Prefer a named specialist before recreating its checks manually.",
            (
                "A finding validate_poc requires control and exploit steps labeled with "
                "evidence_role, using the same endpoint, method, headers, and input shape. "
                "Explicit expectations must prove a class-specific, security-relevant "
                "differential; the executor owns proof and provenance."
            ),
            (
                "HTTP validate_poc supports sql_injection; ssti and the "
                "server_side_template_injection/template_injection aliases; and path_traversal "
                "with lfi, local_file_inclusion, arbitrary_file_read, and file_read aliases. "
                "SQLi requires injection input plus a new SQL error; SSTI requires a template "
                "expression plus a computed marker absent control; traversal requires traversal "
                "input plus known file content absent control. Unsupported claims remain "
                "candidates. IDOR, authorization, SSRF, and other classes require a trusted "
                "typed validator. Plain reflection cannot confirm XSS; XSS requires "
                "dom_execution evidence."
            ),
            "Use final when this assignment is exhausted; the coordinator chooses the next route.",
            "Use capture_flag only for an exact proof present in target-produced tool output.",
            (
                "After a timed-out extraction with target-observed progress, resume from the "
                "observed prefix, use a bounded chunk, and set timeout_seconds explicitly; "
                "do not restart from position one."
            ),
        ],
    }
    authenticated_identity = str(state.surface.get("authenticated_identity") or "").strip()
    if authenticated_identity:
        unavailable_catalog = authenticated_unavailable_probes()
        unavailable_names = frozenset(unavailable_catalog)
        action_contract = payload.get("action_contract")
        if isinstance(action_contract, dict):
            action_contract.pop("run_command", None)
            action_contract.pop("run_python", None)
        payload["authentication"] = {
            "session_mode": f"identity:{authenticated_identity}",
            "identity": authenticated_identity,
            "credential_transport": "managed_http_only",
        }
        constraints = payload.get("objective_constraints")
        if isinstance(constraints, list):
            payload["objective_constraints"] = [
                item
                for item in constraints
                if "run_command" not in str(item)
                and "run_python" not in str(item)
                and not _mentions_authenticated_unavailable_probe(item, unavailable_names)
            ]
        rules = payload.get("rules")
        if isinstance(rules, list):
            rewritten_rules = [
                _rewrite_authenticated_frontier_rule(item) for item in rules
            ]
            rules[:] = [
                item
                for item in rewritten_rules
                if not _mentions_authenticated_unavailable_probe(item, unavailable_names)
            ]
            rules.extend(
                [
                    (
                        "The selected identity is attached only by the managed HTTP lane. "
                        "Use run_probe or validate_poc; command and Python actions are unavailable."
                    ),
                    (
                        "Never supply, request, print, or infer authentication credentials, "
                        "Authorization headers, or Cookie headers."
                    ),
                ]
            )
        payload["unavailable_authenticated_probes"] = [
            {"name": name, "reason": unavailable_catalog[name]}
            for name in sorted(unavailable_catalog)
        ]
        assigned_probe = worker.objective.probe
        unavailable_reason = authenticated_probe_unavailability(assigned_probe)
        if unavailable_reason:
            payload["assignment"] = {
                "fingerprint": worker.objective.fingerprint,
                "status": "unavailable_authenticated_transport",
                "reason": unavailable_reason,
            }
            payload["assigned_specialist"] = {
                "status": "unavailable_authenticated_transport",
                "reason": unavailable_reason,
            }
            payload["objective_constraints"] = [
                "This persisted objective has no managed authenticated transport. Return final so the coordinator can choose an eligible frontier."
            ]
    if state.surface.get("flag_objective") is False:
        action_contract = payload.get("action_contract")
        if isinstance(action_contract, dict):
            action_contract.pop("capture_flag", None)
        rules = payload.get("rules")
        if isinstance(rules, list):
            payload["rules"] = [item for item in rules if "capture_flag" not in str(item)]
    return json.dumps(payload, indent=2, sort_keys=True)


def _mentions_authenticated_unavailable_probe(
    value: object,
    unavailable_names: frozenset[str],
) -> bool:
    if isinstance(value, str):
        text = value.casefold()
    else:
        try:
            text = json.dumps(value, sort_keys=True, default=str).casefold()
        except (TypeError, ValueError):
            text = str(value).casefold()
    return any(
        marker in text
        for name in unavailable_names
        for marker in (name, name.replace("_", " "), name.replace("_", "-"))
    )


def _rewrite_authenticated_frontier_rule(value: object) -> object:
    if not isinstance(value, str):
        return value
    return value.replace(
        "Plain reflection cannot confirm XSS; XSS requires dom_execution evidence.",
        (
            "Plain reflection cannot confirm XSS in managed authenticated mode; keep it "
            "as a candidate unless an eligible trusted validator supplies execution evidence."
        ),
    )


def _role_directives(role: FrontierWorkerRole) -> list[str]:
    if role is FrontierWorkerRole.SCOUT:
        return [
            "Run the cheapest discriminating action for this assigned frontier.",
            "Narrow or falsify the route before attempting broad exploitation.",
        ]
    if role is FrontierWorkerRole.COUNTERFACTUAL:
        return [
            "Change a material route dimension from prior attempts.",
            "Do not repeat the same endpoint, input, payload class, and expected signal.",
        ]
    return [
        "Stay on the evidence-backed route and avoid unrelated reconnaissance.",
        "Treat vulnerability confirmation as an oracle, not as objective closure.",
        (
            "Extract target data, credentials, file content, or access needed for the "
            "shortest replayable objective-proof chain."
        ),
    ]


def _assigned_specialist(probe: str) -> dict[str, object]:
    for card in available_specialists():
        if card.get("probe") == probe:
            return card
    return {
        "probe": probe,
        "purpose": "Execute the assigned scoped probe and preserve target observations.",
        "handoff": "Return control when this exact route is exhausted.",
    }


def _objective_constraints(objective: FrontierObjective) -> list[str]:
    if not objective.payload_class.startswith("confirmed_primitive:"):
        return []
    constraints = [
        "Treat the confirmed primitive as established; do not restart broad discovery.",
        "Change only the material dimension named by this objective.",
    ]
    if "do not rerun it unchanged" in objective.expected_signal.lower():
        constraints.append(
            f"Do not call run_probe {objective.probe} unchanged; use the preserved "
            "route in a focused run_command or run_python adaptation."
        )
    if objective_requires_observed_request_contract(objective):
        constraints.extend(observed_request_contract_constraints())
    constraints.extend(extractor_correctness_constraints(objective))
    constraints.extend(oracle_calibration_constraints(objective))
    if objective_requires_bounded_proof_work(objective):
        constraints.extend(bounded_proof_work_constraints())
    return constraints


def _frontier_observation(  # noqa: PLR0913 - observation fields stay explicit.
    *,
    action: Mapping[str, object],
    outcome: ActionResult,
    cost_usd: float,
    next_objective: FrontierObjective | None,
    objective: FrontierObjective,
    coordinator_progress: tuple[str, ...] = (),
) -> FrontierObservation:
    assessment = assess_recovery_evidence(
        ProgressSnapshot(),
        action=action,
        outcome=outcome.to_json(),
        source_kind=outcome.evidence_source_kind,
        raw_observation=outcome.evidence_observation or None,
    )
    proofs = (outcome.flag,) if outcome.flag else ()
    return FrontierObservation(
        source_kind=outcome.evidence_source_kind,
        observation_digest=_objective_scoped_watchdog_key(
            assessment.observation_digest,
            objective,
        ),
        route_fingerprint=_objective_scoped_watchdog_key(
            assessment.route_fingerprint,
            objective,
        ),
        material_progress=trusted_material_progress_tokens(
            assessment,
            coordinator_progress=coordinator_progress,
        ),
        proofs=proofs,
        next_objective=next_objective,
        cost_usd=cost_usd,
        low_value_route=assessment.low_value_route and not coordinator_progress,
    )


def _as_counterfactual(objective: FrontierObjective) -> FrontierObjective:
    return FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
        evidence_refs=objective.evidence_refs,
        basis=FrontierObjectiveBasis.NOVEL_COUNTERFACTUAL,
    )


def _objective_stage_key(objective: FrontierObjective) -> tuple[str, str, str]:
    return (
        objective.family,
        objective.probe,
        objective.payload_class,
    )


def _request_event_payload(
    route: FrontierRoute,
    worker: FrontierWorker,
) -> dict[str, object]:
    return {
        "worker_id": worker.worker_id,
        "role": worker.role.value,
        "objective_fingerprint": worker.objective.fingerprint,
        "worker_request": worker.requests_started,
        "worker_lease": worker.lease_limit,
        "route_model_request": route.model_requests_started,
        "route_model_request_budget": route.config.max_model_requests,
    }


def _action_started_event_payload(
    route: FrontierRoute,
    worker: FrontierWorker,
    *,
    action: Mapping[str, object],
    action_id: str,
    repeat_count: int,
) -> dict[str, object]:
    """Describe one execution without persisting model-authored arguments."""
    return {
        **_request_event_payload(route, worker),
        "action_id": action_id,
        "action_kind": str(action.get("action") or "invalid"),
        "repeat_count": repeat_count,
    }


def _contract_event_payload(
    worker: FrontierWorker,
    issue: RequestContractIssue,
) -> dict[str, object]:
    return {
        "worker_id": worker.worker_id,
        "objective_fingerprint": worker.objective.fingerprint,
        "contract_fingerprint": issue.fingerprint,
        "method": issue.method,
        "endpoint": issue.endpoint,
        "field_names": [field.name for field in issue.fields],
        "missing_field_names": list(issue.missing_fields),
    }


def _objective_scoped_watchdog_key(
    value: str,
    objective: FrontierObjective,
) -> str:
    if not value:
        return ""
    return f"{value}:{objective.fingerprint[:16]}"


def _trusted_target_observation(outcome: ActionResult) -> str:
    if outcome.evidence_source_kind not in {
        "tool_run_command",
        "tool_run_python",
        "tool_run_probe",
        "tool_validate_poc",
    }:
        return ""
    return outcome.evidence_observation or outcome.observation


def _clip_session_content(content: str) -> str:
    if len(content) <= _MAX_SESSION_CONTENT_CHARS:
        return content
    marker = "\n...[session content clipped]...\n"
    remaining = _MAX_SESSION_CONTENT_CHARS - len(marker)
    head = remaining * 2 // 3
    tail = remaining - head
    return content[:head] + marker + content[-tail:]


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


__all__ = [
    "FrontierEngine",
    "FrontierModelReply",
    "FrontierSessionStore",
]
