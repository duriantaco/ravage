# ruff: noqa: CPY001

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.autonomous_graph.evidence import (
    EvidenceBlackboard,
    EvidenceWorkKind,
)
from ravage.agent_core.autonomous_graph.models import GraphObjective
from ravage.agent_core.autonomous_graph.routing import (
    GraphActionRejectedError,
    GraphRoutingDirective,
)
from ravage.agent_core.frontier_auth_transition import (
    action_attempts_paired_secret_extraction,
    action_attempts_sql_auth_bypass,
)
from ravage.agent_core.frontier_credential_replay import (
    detect_rejected_credential_replay,
    rejected_credential_replay_message,
)
from ravage.agent_core.frontier_extraction_memory import (
    extraction_checkpoint_from_observation,
)
from ravage.agent_core.frontier_proof_work import (
    action_attempts_bounded_proof_work,
)
from ravage.agent_core.frontier_route import FrontierObjective
from ravage.agent_core.frontier_sql_oracle import (
    sql_oracle_contracts_from_observation,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ravage.agent_core.action_executor import ActionResult
    from ravage.agent_core.autonomous_graph.evidence import EvidencePromotion
    from ravage.agent_core.autonomous_graph.scheduler import ProgressReceipt
    from ravage.agent_core.autonomous_graph.worker import GraphToolResult

_HASH_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,128}(?![0-9A-Fa-f])")
_TARGET_REQUEST_MARKERS = ("curl", "http", "post(", "requests.", "urlopen", "urllib")
_AUTH_MARKERS = ("login", "password", "passwd", "credential", "session")


@dataclass(frozen=True)
class ClosureRoutingUpdate:
    evidence_refs: tuple[str, ...] = ()
    progress_receipts: tuple[ProgressReceipt, ...] = ()
    routing_directive: GraphRoutingDirective | None = None
    visible: dict[str, object] | None = None

    @property
    def counterfactual_objective_fingerprint(self) -> str:
        if self.routing_directive is None:
            return ""
        return self.routing_directive.objective.fingerprint


class GraphClosureRouter:
    """
    Convert target-observed SQL closure failures into one guarded route.

    This is intentionally outside the frozen base and the generic worker loop.
    """

    def __init__(
        self,
        *,
        blackboard: EvidenceBlackboard,
        objective_for_node: Callable[[str], GraphObjective],
    ) -> None:
        self.blackboard = blackboard
        self.objective_for_node = objective_for_node

    def observe(
        self,
        *,
        node_id: str,
        action: Mapping[str, object],
        result: ActionResult,
        promotion: EvidencePromotion,
    ) -> ClosureRoutingUpdate:
        objective = self.objective_for_node(node_id)
        if objective.family != "sql_injection" or not promotion.source_trusted:
            return ClosureRoutingUpdate()
        observation = result.evidence_observation or result.observation
        frontier = _frontier_objective(objective)
        evidence_refs: list[str] = []
        receipts: list[ProgressReceipt] = []
        visible: dict[str, object] = {}

        oracle_updates = []
        if result.evidence_source_kind in {
            "tool_run_probe",
            "tool_validate_poc",
        }:
            oracle_updates = [
                self.blackboard.record_sql_oracle_contract(
                    producer_node_id=node_id,
                    raw_evidence_ref=promotion.raw_evidence_ref,
                    contract=contract,
                )
                for contract in sql_oracle_contracts_from_observation(
                    observation,
                    objective=frontier,
                )
            ]
        if oracle_updates:
            evidence_refs.extend(update.record.evidence_id for update in oracle_updates)
            receipts.extend(
                update.progress_receipt
                for update in oracle_updates
                if update.progress_receipt is not None
            )
            visible["sql_oracle"] = {
                "status": "calibrated",
                "evidence_refs": [update.record.evidence_id for update in oracle_updates],
            }

        checkpoint = extraction_checkpoint_from_observation(
            objective=frontier,
            action=action,
            observation=observation,
        )
        if checkpoint is None:
            return ClosureRoutingUpdate(
                evidence_refs=_unique(evidence_refs),
                progress_receipts=tuple(receipts),
                visible=visible or None,
            )

        oracle_refs = self.blackboard.trusted_sql_oracle_refs(
            family=frontier.family,
            endpoint=frontier.endpoint,
        )
        if not oracle_refs:
            visible["extraction_checkpoint"] = {
                "status": "quarantined",
                "reason": "calibrated_sql_oracle_required",
                "candidate_kind": checkpoint.candidate_kind,
                "position": checkpoint.position,
            }
            return ClosureRoutingUpdate(
                evidence_refs=_unique(evidence_refs),
                progress_receipts=tuple(receipts),
                visible=visible,
            )

        checkpoint_update = self.blackboard.record_extraction_checkpoint(
            producer_node_id=node_id,
            raw_evidence_ref=promotion.raw_evidence_ref,
            oracle_evidence_refs=oracle_refs,
            checkpoint=checkpoint,
        )
        evidence_refs.append(checkpoint_update.record.evidence_id)
        if checkpoint_update.progress_receipt is not None:
            receipts.append(checkpoint_update.progress_receipt)
        visible["extraction_checkpoint"] = {
            "status": "validated",
            "evidence_ref": checkpoint_update.record.evidence_id,
            "candidate_kind": checkpoint.candidate_kind,
            "position": checkpoint.position,
            "expected_length": checkpoint.expected_length,
            "complete": checkpoint.complete,
        }

        replay = detect_rejected_credential_replay(
            objective=frontier,
            checkpoint=checkpoint,
            action=action,
            observation=observation,
        )
        if replay is None:
            return ClosureRoutingUpdate(
                evidence_refs=_unique(evidence_refs),
                progress_receipts=tuple(receipts),
                visible=visible,
            )

        rejection_update = self.blackboard.record_rejected_credential_replay(
            producer_node_id=node_id,
            raw_evidence_ref=promotion.raw_evidence_ref,
            checkpoint_evidence_ref=checkpoint_update.record.evidence_id,
            replay=replay,
        )
        evidence_refs.append(rejection_update.record.evidence_id)
        if rejection_update.progress_receipt is not None:
            receipts.append(rejection_update.progress_receipt)
        route_objective = _credential_recovery_objective(
            source=objective,
            checkpoint_ref=checkpoint_update.record.evidence_id,
            rejection_ref=rejection_update.record.evidence_id,
            representation_hint=replay.representation_hint,
            candidate_kind=replay.candidate_kind,
        )
        registration = self.blackboard.register_work(
            kind=EvidenceWorkKind.CLOSURE_OBLIGATION,
            canonical_key=(
                f"credential-representation:{frontier.endpoint}:{replay.candidate_digest}"
            ),
            evidence_refs=(
                checkpoint_update.record.evidence_id,
                rejection_update.record.evidence_id,
            ),
        )
        directive = (
            GraphRoutingDirective(
                name="credential-representation-closure",
                objective=route_objective,
                reason=rejected_credential_replay_message(replay),
                evidence_refs=route_objective.evidence_refs,
                work_id=registration.item.work_id,
                lease_limit=2,
                park_source=True,
            )
            if rejection_update.created and registration.created
            else None
        )
        visible["credential_replay"] = {
            "status": "rejected",
            "evidence_ref": rejection_update.record.evidence_id,
            "representation_hint": replay.representation_hint,
            "candidate_kind": replay.candidate_kind,
            "candidate_length": replay.candidate_length,
            "route_work_id": registration.item.work_id,
            "route_created": registration.created,
        }
        return ClosureRoutingUpdate(
            evidence_refs=_unique(evidence_refs),
            progress_receipts=tuple(receipts),
            routing_directive=directive,
            visible=visible,
        )

    def guard(
        self,
        node_id: str,
        tool: str,
        arguments: Mapping[str, object],
    ) -> None:
        """Reject the Run-27 loop before it reaches tool accounting or the target."""
        if tool not in {"run_command", "run_python"}:
            return
        objective = self.objective_for_node(node_id)
        family = "sql_injection" if objective.family == "credential_recovery" else objective.family
        rejections = self.blackboard.rejected_credential_records(
            family=family,
            endpoint=objective.endpoint,
        )
        if not rejections:
            return
        action = {"action": tool, **dict(arguments)}
        source = str(action.get("command") or action.get("code") or "")
        lowered = source.lower()
        latest = rejections[-1]

        if not action_attempts_sql_auth_bypass(action) and (
            action_attempts_bounded_proof_work(action)
            or action_attempts_paired_secret_extraction(action)
        ):
            candidate_kind = str(latest.payload.get("candidate_kind") or "credential")
            if candidate_kind in lowered or any(
                marker in lowered for marker in ("extract", "substring", "prefix[")
            ):
                message = (
                    "credential_loop_guard: the complete rejected stored value may not "
                    "be extracted again; choose representation recovery or an adjacent "
                    "bounded authentication sink"
                )
                raise GraphActionRejectedError(message)

        if _replays_rejected_hash(lowered, latest.payload):
            message = (
                "credential_loop_guard: the target-rejected hash-shaped value may not "
                "be replayed unchanged as plaintext"
            )
            raise GraphActionRejectedError(message)


def merge_closure_update(
    base: GraphToolResult,
    update: ClosureRoutingUpdate,
) -> GraphToolResult:
    from ravage.agent_core.autonomous_graph.worker import (  # noqa: PLC0415
        GraphToolResult,
    )

    if (
        not update.evidence_refs
        and not update.progress_receipts
        and update.routing_directive is None
        and update.visible is None
    ):
        return base
    try:
        envelope = json.loads(base.output)
    except (TypeError, ValueError):
        envelope = {"observation": base.output}
    if not isinstance(envelope, dict):
        envelope = {"observation": envelope}
    if update.visible is not None:
        envelope["closure_routing"] = update.visible
    receipts = {
        receipt.token: receipt for receipt in (*base.progress_receipts, *update.progress_receipts)
    }
    return GraphToolResult(
        output=json.dumps(
            envelope,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        observation_digest=base.observation_digest,
        progress_receipts=tuple(receipts[token] for token in sorted(receipts)),
        evidence_refs=_unique((*base.evidence_refs, *update.evidence_refs)),
        target_requests=base.target_requests,
        counterfactual_objective_fingerprint=(
            update.counterfactual_objective_fingerprint or base.counterfactual_objective_fingerprint
        ),
        routing_directive=update.routing_directive,
    )


def _frontier_objective(objective: GraphObjective) -> FrontierObjective:
    return FrontierObjective.create(
        family=objective.family,
        probe=objective.strategy or objective.endpoint,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class="confirmed_primitive:sqli_confirmed:proof_channel",
        expected_signal=objective.expected_signal,
    )


def _credential_recovery_objective(
    *,
    source: GraphObjective,
    checkpoint_ref: str,
    rejection_ref: str,
    representation_hint: str,
    candidate_kind: str,
) -> GraphObjective:
    return GraphObjective.create(
        family="credential_recovery",
        instruction=(
            f"Close authentication for {source.endpoint}. The extracted {candidate_kind} "
            f"is {representation_hint} and the target rejected it as plaintext. Do not "
            "extract or replay it again. Use one bounded offline representation recovery "
            "or adjacent username/password authentication-bypass strategy, then require "
            "an explicit login success and protected same-session access."
        ),
        endpoint=source.endpoint,
        inputs=source.inputs,
        strategy="credential_representation_recovery",
        expected_signal=(
            "target-observed explicit authentication success plus protected same-session "
            "access, or typed counter-evidence from one bounded materially different attempt"
        ),
        evidence_refs=(checkpoint_ref, rejection_ref),
    )


def _replays_rejected_hash(
    source: str,
    payload: Mapping[str, object],
) -> bool:
    if not any(marker in source for marker in _TARGET_REQUEST_MARKERS):
        return False
    if not any(marker in source for marker in _AUTH_MARKERS):
        return False
    digest = str(payload.get("candidate_digest") or "")
    length = int(payload.get("candidate_length") or 0)
    if not digest or length <= 0:
        return False
    return any(
        len(match.group(0)) == length
        and hashlib.sha256(match.group(0).encode()).hexdigest() == digest
        for match in _HASH_TOKEN.finditer(source)
    )


def _unique(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    return tuple(sorted({str(value).strip() for value in values if str(value).strip()}))


__all__ = [
    "ClosureRoutingUpdate",
    "GraphClosureRouter",
    "merge_closure_update",
]
