# ruff: noqa: CPY001

from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ravage.agent_core.agent_specialists import (
    available_specialists,
    recommended_specialists,
)
from ravage.agent_core.autonomous_graph.data_query_seed import (
    data_query_seed_objective,
)
from ravage.agent_core.autonomous_graph.seed_admission import (
    graph_seed_admission_reason,
)
from ravage.agent_core.autonomous_graph.template_form_closure import (
    template_form_contract,
)
from ravage.agent_core.autonomous_graph.transition_seeds import (
    sql_auth_transition_objective,
)
from ravage.agent_core.frontier_route import (
    BaseRouteOutcome,
    FrontierObjective,
    FrontierObjectiveBasis,
)
from ravage.agent_core.frontier_transition import seed_frontier_objectives
from ravage.agent_core.primitive_state import primitive_rule
from ravage.probes.ssti_deferred_context import deferred_ssti_contract

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.agent_state import AgentState
    from ravage.agent_core.autonomous_graph.learning import SeedLearningPolicy

_CANDIDATE_POOL_LIMIT = 64
_STRONG_PRIMITIVE_CAP = 2
_WEAK_PRIMITIVE_CAP = 1
_DEFAULT_PROBE_CAP = 2
_DIVERSE_FAMILY_CAP = 1
_DIVERSE_TASK_CAP = 1
_PRIMITIVE_PAYLOAD_PARTS = 3
_DIALOG_CALL = re.compile(r"\b(?:alert|confirm|prompt)\s*\(", flags=re.IGNORECASE)
_WEAK_PRIMITIVE_MARKERS = ("candidate", "exposed", "observed", "surface")
_STRONG_PRIMITIVE_MARKERS = ("confirmed", "unlocked")

_FAMILY_TASKS = {
    "authentication": "stateful-session",
    "command_injection": "command-boundary",
    "cross_site_scripting": "input-reflection",
    "deserialization": "file-fetch-parser",
    "exposure": "flag-and-secret-sweep",
    "file_upload": "file-fetch-parser",
    "graphql": "api-behavior",
    "object_authorization": "stateful-session",
    "path_traversal": "file-fetch-parser",
    "server_side_request_forgery": "file-fetch-parser",
    "sql_injection": "data-query",
    "template_injection": "server-rendering",
    "xml_external_entity": "file-fetch-parser",
}
_GRAPH_PROBE_FAMILIES = {
    "api_behavior": "api_behavior",
    "browser_boundary": "api_behavior",
    "captcha_form_state": "authentication",
    "csrf_session": "authentication",
    "file_fetch_parser": "file_handling",
    "preg_match_subject": "sql_injection",
    "ssti_deferred_context_closure": "template_injection",
    "template_form_closure": "template_injection",
    "xss_filter_constraint": "cross_site_scripting",
}


@dataclass(frozen=True)
class RankedSeed:
    objective: FrontierObjective
    score: int
    confidence: str
    task_id: str
    selected: bool

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.objective.fingerprint,
            "family": self.objective.family,
            "probe": self.objective.probe,
            "payload_class": self.objective.payload_class,
            "score": self.score,
            "confidence": self.confidence,
            "task_id": self.task_id,
            "selected": self.selected,
        }


@dataclass(frozen=True)
class SuppressedSeed:
    objective: FrontierObjective
    reason: str

    def to_json(self) -> dict[str, object]:
        return {
            "fingerprint": self.objective.fingerprint,
            "family": self.objective.family,
            "probe": self.objective.probe,
            "payload_class": self.objective.payload_class,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SeedPortfolio:
    """Deterministic graph-only route selection over a broad frozen-base frontier."""

    objectives: tuple[FrontierObjective, ...]
    ranking: tuple[RankedSeed, ...]
    suppressed: tuple[SuppressedSeed, ...] = ()
    policy_id: str = ""
    flag_objective: bool = True

    def to_json(self) -> dict[str, object]:
        return {
            "version": 1,
            "policy": "evidence_diverse_seed_portfolio_v1",
            "mission": (
                "flag_capture" if self.flag_objective else "vulnerability_assessment"
            ),
            "learned_policy_id": self.policy_id,
            "selected_fingerprints": [objective.fingerprint for objective in self.objectives],
            "suppressed": [item.to_json() for item in self.suppressed],
            "ranking": [item.to_json() for item in self.ranking],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


@dataclass(frozen=True)
class _Candidate:
    objective: FrontierObjective
    index: int
    score: int
    confidence: str
    primitive_name: str
    task_id: str


def build_seed_portfolio(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    limit: int,
    policy: SeedLearningPolicy | None = None,
    flag_objective: bool = True,
) -> SeedPortfolio:
    """
    Select a bounded, evidence-diverse graph frontier without mutating base state.

    A broad pool is intentional: the frozen base selector can be depth-first, while
    this post-base route must retain strong closure paths without letting one weak
    surface marker consume nearly every worker.
    """
    if limit <= 0:
        return SeedPortfolio(
            objectives=(),
            ranking=(),
            flag_objective=flag_objective,
        )
    pool_limit = max(_CANDIDATE_POOL_LIMIT, limit * 8)
    inherited = [
        _normalize_graph_family(objective)
        for objective in seed_frontier_objectives(
            state,
            base=base,
            limit=pool_limit,
        )
    ]
    supplemental = _supplemental_objectives(
        state,
        base=base,
        inherited=inherited,
        flag_objective=flag_objective,
    )
    inherited, shadowed_suppressed = _suppress_shadowed_reconnaissance(
        inherited,
        supplemental=supplemental,
    )
    inherited, admission_suppressed = _suppress_unbound_seeds(
        state,
        inherited,
        target_url=base.target_url,
    )
    suppressed = (*shadowed_suppressed, *admission_suppressed)
    transition = sql_auth_transition_objective(state, base=base)
    ordered: Sequence[FrontierObjective] = [
        *((transition,) if transition is not None else ()),
        *supplemental,
        *inherited,
    ]
    if not flag_objective:
        ordered = tuple(_ordinary_assessment_objective(item) for item in ordered)
    candidates = _rank_candidates(
        state,
        _dedupe_objectives(ordered),
        policy=policy,
    )
    selected = _select_candidates(candidates, limit=limit)
    selected_fingerprints = {candidate.objective.fingerprint for candidate in selected}
    ranking = tuple(
        RankedSeed(
            objective=candidate.objective,
            score=candidate.score,
            confidence=candidate.confidence,
            task_id=candidate.task_id,
            selected=candidate.objective.fingerprint in selected_fingerprints,
        )
        for candidate in candidates
    )
    return SeedPortfolio(
        objectives=tuple(candidate.objective for candidate in selected),
        ranking=ranking,
        suppressed=suppressed,
        policy_id=policy.policy_id if policy is not None else "",
        flag_objective=flag_objective,
    )


def _suppress_unbound_seeds(
    state: AgentState,
    inherited: Sequence[FrontierObjective],
    *,
    target_url: str,
) -> tuple[tuple[FrontierObjective, ...], tuple[SuppressedSeed, ...]]:
    kept: list[FrontierObjective] = []
    suppressed: list[SuppressedSeed] = []
    for objective in inherited:
        reason = graph_seed_admission_reason(
            state,
            objective,
            target_url=target_url,
        )
        if reason:
            suppressed.append(SuppressedSeed(objective=objective, reason=reason))
        else:
            kept.append(objective)
    return tuple(kept), tuple(suppressed)


def _suppress_shadowed_reconnaissance(
    inherited: Sequence[FrontierObjective],
    *,
    supplemental: Sequence[FrontierObjective],
) -> tuple[tuple[FrontierObjective, ...], tuple[SuppressedSeed, ...]]:
    closure_probes = {
        objective.probe
        for objective in supplemental
        if objective.probe
        in {
            "ssti_deferred_context_closure",
            "template_form_closure",
        }
    }
    if not closure_probes:
        return tuple(inherited), ()
    shadowed = tuple(
        objective
        for objective in inherited
        if (objective.family == "template_injection" and objective.probe == "ssti_fingerprint")
    )
    kept = tuple(objective for objective in inherited if objective not in shadowed)
    suppressed = tuple(
        SuppressedSeed(
            objective=objective,
            reason=_template_shadow_reason(closure_probes),
        )
        for objective in shadowed
    )
    return kept, suppressed


def _template_shadow_reason(closure_probes: set[str]) -> str:
    if closure_probes == {"ssti_deferred_context_closure"}:
        return "confirmed_deferred_closure_supersedes_generic_fingerprint"
    return "bounded_template_closure_supersedes_generic_fingerprint:" + ",".join(
        sorted(closure_probes)
    )


def _supplemental_objectives(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    inherited: Sequence[FrontierObjective],
    flag_objective: bool,
) -> tuple[FrontierObjective, ...]:
    objectives = (
        _xss_filter_constraint_objective(
            state,
            base=base,
            inherited=inherited,
            flag_objective=flag_objective,
        ),
        _ssti_deferred_context_objective(
            state,
            base=base,
            flag_objective=flag_objective,
        ),
        _template_form_closure_objective(
            state,
            base=base,
            flag_objective=flag_objective,
        ),
        data_query_seed_objective(
            state,
            base=base,
        ),
    )
    return tuple(objective for objective in objectives if objective is not None)


def _xss_filter_constraint_objective(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    inherited: Sequence[FrontierObjective],
    flag_objective: bool,
) -> FrontierObjective | None:
    description = str(state.surface.get("visible_description") or "")
    reflection = _reflection_contract(state)
    if reflection is None or _DIALOG_CALL.search(description) is None:
        return None
    endpoint, input_name = reflection
    inherited_xss = next(
        (objective for objective in inherited if objective.family == "cross_site_scripting"),
        None,
    )
    return FrontierObjective.create(
        family="cross_site_scripting",
        probe="xss_filter_constraint",
        endpoint=endpoint or (inherited_xss.endpoint if inherited_xss else ""),
        inputs=(
            (input_name,)
            if input_name
            else (inherited_xss.inputs if inherited_xss is not None else ())
        ),
        payload_class="graph_constraint:xss_filter_element_boundary",
        expected_signal=(
            "Reuse the exact target-observed reflected request and visible dialog value. "
            "Run one bounded filter-constraint campaign that varies only the element-name "
            + (
                "boundary, and stop on target-returned proof or finite exhaustion."
                if flag_objective
                else "boundary. Persist a finding only after trusted DOM execution; "
                "otherwise finish with bounded coverage."
            )
        ),
        evidence_refs=(f"base-state:{base.state_digest}",),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def _reflection_contract(state: AgentState) -> tuple[str, str] | None:
    reflections = state.surface.get("reflections")
    if isinstance(reflections, list):
        for raw in reflections:
            if not isinstance(raw, Mapping):
                continue
            input_name = str(raw.get("name") or raw.get("input") or "").strip()
            endpoint = str(raw.get("page") or raw.get("endpoint") or raw.get("url") or "").strip()
            if input_name and endpoint:
                return endpoint, input_name
    for raw in state.signals.get("reflections", []):
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, Mapping):
            continue
        input_name = str(payload.get("name") or payload.get("input") or "").strip()
        endpoint = str(
            payload.get("page") or payload.get("endpoint") or payload.get("url") or ""
        ).strip()
        if input_name and endpoint:
            return endpoint, input_name
    return None


def _ssti_deferred_context_objective(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    flag_objective: bool,
) -> FrontierObjective | None:
    contract = deferred_ssti_contract(state)
    if contract is None:
        return None
    return FrontierObjective.create(
        family="template_injection",
        probe="ssti_deferred_context_closure",
        endpoint=contract.endpoint,
        inputs=contract.required_fields,
        payload_class="graph_constraint:deferred_template_context_closure",
        expected_signal=(
            "Preserve the target-observed multi-step POST/session contract and vary "
            "only a bounded template context-variable payload. Follow same-origin "
            + (
                "wizard steps, stop immediately on target-returned proof, and otherwise "
                "emit finite exhaustion."
                if flag_objective
                else "wizard steps. Confirm only a class-specific server-side execution "
                "differential against a control; otherwise finish with bounded coverage."
            )
        ),
        evidence_refs=(f"base-state:{base.state_digest}",),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def _template_form_closure_objective(
    state: AgentState,
    *,
    base: BaseRouteOutcome,
    flag_objective: bool,
) -> FrontierObjective | None:
    if deferred_ssti_contract(state) is not None:
        return None
    contract = template_form_contract(state)
    if contract is None:
        return None
    return FrontierObjective.create(
        family="template_injection",
        probe="template_form_closure",
        endpoint=contract.endpoint,
        inputs=(contract.payload_field, *contract.required_fields),
        payload_class="graph_constraint:bounded_template_form_closure",
        expected_signal=(
            "Preserve the observed POST form and companion fields. Run one tiny "
            + (
                "template-dialect matrix, then immediately use only the confirmed "
                "engine for proof extraction. Stop on target-returned proof or finite "
                "dialect exhaustion."
                if flag_objective
                else "template-dialect matrix, then validate a confirmed engine with "
                "paired control and exploit observations. Persist the finding or finish "
                "with finite dialect coverage."
            )
        ),
        evidence_refs=(f"base-state:{base.state_digest}",),
        basis=FrontierObjectiveBasis.BASE_FRONTIER,
    )


def _ordinary_assessment_objective(objective: FrontierObjective) -> FrontierObjective:
    payload_class = objective.payload_class
    if payload_class.endswith(":proof_channel"):
        payload_class = payload_class.removesuffix(":proof_channel") + ":finding_evidence"
    return FrontierObjective.create(
        family=objective.family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=payload_class,
        expected_signal=(
            "Use executor-owned, class-aware target observations to persist a confirmed "
            f"{objective.family} finding for this route, or finish after finite materially "
            "distinct checks establish bounded negative coverage."
        ),
        evidence_refs=objective.evidence_refs,
        basis=objective.basis,
    )


def _rank_candidates(
    state: AgentState,
    objectives: Sequence[FrontierObjective],
    *,
    policy: SeedLearningPolicy | None,
) -> tuple[_Candidate, ...]:
    task_scores = _task_scores(state)
    probe_tasks = _probe_tasks()
    recommendation_scores = {
        str(item.get("probe") or ""): _int(item.get("score"))
        for item in recommended_specialists(state, limit=_CANDIDATE_POOL_LIMIT)
    }
    attempt_counts = _probe_attempt_counts(state)
    ranked: list[_Candidate] = []
    for index, objective in enumerate(objectives):
        primitive_name = _primitive_name(objective) or _evidenced_primitive_for_probe(
            state,
            objective.probe,
        )
        confidence = _confidence(primitive_name)
        task_id = _objective_task_id(
            objective,
            primitive_name=primitive_name,
            probe_tasks=probe_tasks,
        )
        score = _base_score(objective, confidence=confidence)
        score += task_scores.get(task_id, 0) * 4
        score += recommendation_scores.get(objective.probe, 0) * 12
        score -= min(attempt_counts.get(objective.probe, 0), 10) * 45
        score += _dimension_bonus(objective.payload_class)
        if policy is not None:
            score += policy.score_delta(objective)
        ranked.append(
            _Candidate(
                objective=objective,
                index=index,
                score=score,
                confidence=confidence,
                primitive_name=primitive_name,
                task_id=task_id,
            )
        )
    ranked.sort(
        key=lambda item: (
            -item.score,
            item.index,
            item.objective.fingerprint,
        )
    )
    return tuple(ranked)


def _select_candidates(  # noqa: C901 - selection caps are explicit audit invariants.
    candidates: Sequence[_Candidate],
    *,
    limit: int,
) -> tuple[_Candidate, ...]:
    if limit <= 0:
        return ()
    selected: list[_Candidate] = []
    selected_ids: set[str] = set()
    family_counts: Counter[str] = Counter()
    probe_counts: Counter[str] = Counter()
    primitive_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    weak_probes = {
        candidate.objective.probe for candidate in candidates if candidate.confidence == "weak"
    }

    def add(candidate: _Candidate, *, enforce_diversity: bool) -> bool:
        objective = candidate.objective
        if objective.fingerprint in selected_ids:
            return False
        primitive_cap = (
            _WEAK_PRIMITIVE_CAP if candidate.confidence == "weak" else _STRONG_PRIMITIVE_CAP
        )
        if candidate.primitive_name and primitive_counts[candidate.primitive_name] >= primitive_cap:
            return False
        probe_cap = _WEAK_PRIMITIVE_CAP if objective.probe in weak_probes else _DEFAULT_PROBE_CAP
        if objective.probe != "sqli_auth_transition" and probe_counts[objective.probe] >= probe_cap:
            return False
        if enforce_diversity and objective.probe != "sqli_auth_transition":
            family_cap = (
                _STRONG_PRIMITIVE_CAP if candidate.confidence == "strong" else _DIVERSE_FAMILY_CAP
            )
            if family_counts[objective.family] >= family_cap:
                return False
            if (
                candidate.confidence != "strong"
                and candidate.task_id
                and task_counts[candidate.task_id] >= _DIVERSE_TASK_CAP
            ):
                return False
        selected.append(candidate)
        selected_ids.add(objective.fingerprint)
        family_counts[objective.family] += 1
        probe_counts[objective.probe] += 1
        if candidate.primitive_name:
            primitive_counts[candidate.primitive_name] += 1
        if candidate.task_id:
            task_counts[candidate.task_id] += 1
        return True

    for candidate in candidates:
        if candidate.objective.probe == "sqli_auth_transition":
            add(candidate, enforce_diversity=False)
            if len(selected) >= limit:
                return tuple(selected[:limit])

    for candidate in candidates:
        if len(selected) >= limit:
            break
        add(candidate, enforce_diversity=True)

    for candidate in candidates:
        if len(selected) >= limit:
            break
        add(candidate, enforce_diversity=False)
    return tuple(selected[:limit])


def _base_score(objective: FrontierObjective, *, confidence: str) -> int:
    if objective.probe == "sqli_auth_transition":
        return 100_000
    if objective.payload_class.startswith("graph_constraint:"):
        return 5_000
    if confidence == "strong":
        return 3_000
    if confidence == "medium":
        return 1_800
    if confidence == "weak":
        return 1_000
    return 100 if objective.family == "unknown" else 400


def _confidence(primitive_name: str) -> str:
    if not primitive_name:
        return "specialist"
    return _confidence_name(primitive_name)


def _primitive_name(objective: FrontierObjective) -> str:
    parts = objective.payload_class.split(":")
    if len(parts) >= _PRIMITIVE_PAYLOAD_PARTS and parts[0] == "confirmed_primitive":
        return parts[1]
    return ""


def _evidenced_primitive_for_probe(state: AgentState, probe: str) -> str:
    matches: list[tuple[int, int, str]] = []
    confidence_rank = {"strong": 2, "medium": 1, "weak": 0}
    for name, turn in state.primitives.items():
        rule = primitive_rule(name)
        if rule is None or rule.probe != probe:
            continue
        confidence = _confidence_name(name)
        matches.append((confidence_rank[confidence], _int(turn), name))
    if not matches:
        return ""
    matches.sort(reverse=True)
    return matches[0][2]


def _confidence_name(primitive_name: str) -> str:
    lowered = primitive_name.lower()
    if any(marker in lowered for marker in _WEAK_PRIMITIVE_MARKERS):
        return "weak"
    if any(marker in lowered for marker in _STRONG_PRIMITIVE_MARKERS):
        return "strong"
    return "medium"


def _objective_task_id(
    objective: FrontierObjective,
    *,
    primitive_name: str,
    probe_tasks: Mapping[str, str],
) -> str:
    if primitive_name:
        rule = primitive_rule(primitive_name)
        if rule is not None:
            return rule.task_id
    return probe_tasks.get(
        objective.probe,
        _FAMILY_TASKS.get(objective.family, ""),
    )


def _probe_tasks() -> dict[str, str]:
    result = {
        str(item.get("probe") or ""): str(item.get("task_id") or "")
        for item in available_specialists()
    }
    result["xss_filter_constraint"] = "input-reflection"
    result["ssti_deferred_context_closure"] = "server-rendering"
    result["template_form_closure"] = "server-rendering"
    result["sqli_auth_transition"] = "stateful-session"
    return result


def _task_scores(state: AgentState) -> dict[str, int]:
    scores: dict[str, int] = {}
    for task in state.tasks:
        task_id = str(task.get("id") or "").strip()
        if not task_id:
            continue
        priority = max(_int(task.get("priority")), 0)
        attempts = min(max(_int(task.get("attempts")), 0), 12)
        status = str(task.get("status") or "")
        status_bonus = {
            "in_progress": 24,
            "blocked": 16,
            "pending": 0,
            "done": -40,
        }.get(status, 0)
        scores[task_id] = max(scores.get(task_id, 0), priority + attempts * 4 + status_bonus)
    recent_task_counts: Counter[str] = Counter()
    for action in state.actions[-16:]:
        task_id = str(action.get("task_id") or "").strip()
        if task_id:
            recent_task_counts[task_id] += 1
    for task_id, count in recent_task_counts.items():
        scores[task_id] = scores.get(task_id, 0) + min(count, 6) * 8
    return scores


def _probe_attempt_counts(state: AgentState) -> Counter[str]:
    counts: Counter[str] = Counter()
    for action in state.actions:
        probe = str(action.get("probe") or "").strip()
        if probe:
            counts[probe] += max(_int(action.get("repeat_count")), 1)
    for attempt in state.attempts:
        for key in ("selected_action", "proposed_action"):
            action = attempt.get(key)
            if not isinstance(action, Mapping):
                continue
            probe = str(action.get("probe") or "").strip()
            if probe:
                counts[probe] += 1
    return counts


def _dimension_bonus(payload_class: str) -> int:
    if payload_class.endswith(":request_contract"):
        return 30
    if payload_class.endswith(":payload_semantics"):
        return 20
    if payload_class.endswith(":proof_channel"):
        return 10
    return 0


def _normalize_graph_family(objective: FrontierObjective) -> FrontierObjective:
    family = (
        _GRAPH_PROBE_FAMILIES.get(objective.probe, objective.family)
        if objective.family == "unknown" or objective.probe in _GRAPH_PROBE_FAMILIES
        else objective.family
    )
    if family == objective.family:
        return objective
    return FrontierObjective.create(
        family=family,
        probe=objective.probe,
        endpoint=objective.endpoint,
        inputs=objective.inputs,
        payload_class=objective.payload_class,
        expected_signal=objective.expected_signal,
        evidence_refs=objective.evidence_refs,
        basis=objective.basis,
    )


def _dedupe_objectives(
    objectives: Sequence[FrontierObjective],
) -> tuple[FrontierObjective, ...]:
    unique: list[FrontierObjective] = []
    seen: set[str] = set()
    for objective in objectives:
        if objective.fingerprint in seen:
            continue
        seen.add(objective.fingerprint)
        unique.append(objective)
    return tuple(unique)


def _int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "RankedSeed",
    "SeedPortfolio",
    "build_seed_portfolio",
]
