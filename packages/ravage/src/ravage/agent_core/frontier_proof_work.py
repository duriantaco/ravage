from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ravage.agent_core.frontier_route import FrontierObjective

_CONFIRMED_PROOF_CHANNEL_SUFFIX = ":proof_channel"
_SQL_FAMILY = "sql_injection"
_EXECUTABLE_ACTIONS = frozenset({"run_command", "run_python"})
_POSITION_MARKERS = ("substring(", "substr(", "mid(")
_PREFIX_PREDICATE_MARKERS = (" like ", " glob ", "startswith(")
_CHARACTER_MARKERS = ("ascii(", "ord(", "unicode(")
_FINITE_CHARACTER_ENUMERATION_MARKERS = (
    "for code in range(",
    "for char in ",
    "for ch in ",
    "for candidate in ",
    "string.printable",
)
_FINITE_LOOP_MARKERS = ("range(", "seq ")
_UNBOUNDED_LOOP_MARKERS = (
    "while true",
    "while 1",
    "itertools.count(",
)
_REQUEST_MARKERS = ("curl", "http", "requests.", "urlopen", "urllib")
_CHECKPOINT_MARKERS = (
    "checkpoint",
    "prefix",
    "print(",
    "resume",
    "write(",
    "write_text(",
)
_AUTOMATED_EXTRACTOR_MARKERS = ("sqlmap", "--dump", "--sql-query")


def objective_requires_bounded_proof_work(objective: FrontierObjective) -> bool:
    return (
        objective.family == _SQL_FAMILY
        and objective.payload_class.startswith("confirmed_primitive:")
        and objective.payload_class.endswith(_CONFIRMED_PROOF_CHANNEL_SUFFIX)
    )


def action_attempts_bounded_proof_work(action: Mapping[str, object]) -> bool:
    kind = str(action.get("action") or "")
    if kind not in _EXECUTABLE_ACTIONS:
        return False
    source = str(action.get("command") or action.get("code") or "").lower()
    if not source or not any(marker in source for marker in _REQUEST_MARKERS):
        return False
    if all(marker in source for marker in _AUTOMATED_EXTRACTOR_MARKERS[:1]) and any(
        marker in source for marker in _AUTOMATED_EXTRACTOR_MARKERS[1:]
    ):
        return True
    if any(marker in source for marker in _UNBOUNDED_LOOP_MARKERS):
        return False
    position_search = any(marker in source for marker in _POSITION_MARKERS) or (
        "prefix" in source and any(marker in source for marker in _PREFIX_PREDICATE_MARKERS)
    )
    character_search = any(marker in source for marker in _CHARACTER_MARKERS) or (
        any(marker in source for marker in _FINITE_CHARACTER_ENUMERATION_MARKERS)
        and position_search
    )
    return character_search and all(
        any(marker in source for marker in markers)
        for markers in (
            (*_POSITION_MARKERS, *_PREFIX_PREDICATE_MARKERS),
            _FINITE_LOOP_MARKERS,
            _CHECKPOINT_MARKERS,
        )
    )


def worker_attempted_bounded_proof_work(
    attempts: Sequence[Mapping[str, object]],
    *,
    worker_id: str,
) -> bool:
    for attempt in attempts:
        if str(attempt.get("frontier_worker_id") or "") != worker_id:
            continue
        if attempt.get("frontier_objective_aligned") is not True:
            continue
        action = attempt.get("selected_action")
        if isinstance(action, Mapping) and action_attempts_bounded_proof_work(action):
            return True
    return False


def bounded_proof_work_constraints() -> tuple[str, ...]:
    return (
        (
            "Before handoff, attempt one bounded extraction program rather than isolated "
            "one-off predicates."
        ),
        (
            "Calibrate target-observed true/false markers, keep the request contract fixed, "
            "and use a finite loop or binary search over character positions."
        ),
        (
            "Emit or persist each recovered prefix so a timeout can resume from the last "
            "target-observed checkpoint instead of restarting."
        ),
        (
            "Use coordinator-readable stdout markers: TARGET_LEN=<n>, "
            "PREFIX[position]=<cumulative value>, and EXTRACTED_PASSWORD=<value> (or the "
            "matching extracted kind). If the same action replays the candidate, also emit "
            "LOGIN_RESPONSE=<exact target body>."
        ),
    )


def bounded_proof_work_message(objective: FrontierObjective) -> str:
    inputs = ", ".join(objective.inputs) or "the assigned input"
    return (
        "COORDINATOR_BOUNDED_PROOF_WORK_GATE\n"
        "Handoff rejected. One-off SQL predicates are not a completed proof-channel "
        "attempt. Execute one bounded run_python or run_command extraction program on "
        f"endpoint={objective.endpoint}, input={inputs}: calibrate true/false response "
        "markers, iterate over character positions with a finite bound, and emit or "
        "persist each recovered prefix for timeout-safe resume. The rejected model "
        "request remains charged; global request, worker, scope, and cost limits remain "
        "enforced."
    )


__all__ = [
    "action_attempts_bounded_proof_work",
    "bounded_proof_work_constraints",
    "bounded_proof_work_message",
    "objective_requires_bounded_proof_work",
    "worker_attempted_bounded_proof_work",
]
