from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ravage.agent_core.agent_strategy import ActionLedger
from ravage.agent_core.surface_graph import SurfaceGraphError, SurfaceGraphState
from ravage.agent_core.surface_graph_ingest import import_legacy_surface

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(init=False)
class AgentState:
    phase: str = "recon"
    turn: int = 0
    summary: str = ""
    facts: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    actions: list[dict[str, object]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    signals: dict[str, list[str]] = field(default_factory=dict)
    primitives: dict[str, int] = field(default_factory=dict)
    surface: dict[str, object] = field(default_factory=dict)
    surface_graph: SurfaceGraphState = field(default_factory=SurfaceGraphState)
    tasks: list[dict[str, object]] = field(default_factory=list)
    attempts: list[dict[str, object]] = field(default_factory=list)
    last_observation: dict[str, object] = field(default_factory=dict)
    ledger: ActionLedger = field(default_factory=ActionLedger)

    def __init__(  # noqa: PLR0913
        self,
        phase: str = "recon",
        turn: int = 0,
        summary: str = "",
        facts: list[str] | None = None,
        hypotheses: list[str] | None = None,
        actions: list[dict[str, object]] | None = None,
        flags: list[str] | None = None,
        signals: dict[str, list[str]] | None = None,
        primitives: dict[str, int] | None = None,
        surface: dict[str, object] | None = None,
        surface_graph: SurfaceGraphState | None = None,
        tasks: list[dict[str, object]] | None = None,
        attempts: list[dict[str, object]] | None = None,
        last_observation: dict[str, object] | None = None,
        ledger: ActionLedger | None = None,
    ) -> None:
        self.phase = phase
        self.turn = turn
        self.summary = summary
        self.facts = [] if facts is None else facts
        self.hypotheses = [] if hypotheses is None else hypotheses
        self.actions = [] if actions is None else actions
        self.flags = [] if flags is None else flags
        self.signals = {} if signals is None else signals
        self.primitives = {} if primitives is None else primitives
        self.surface = {} if surface is None else surface
        self.surface_graph = SurfaceGraphState() if surface_graph is None else surface_graph
        self.tasks = [] if tasks is None else tasks
        self.attempts = [] if attempts is None else attempts
        self.last_observation = {} if last_observation is None else last_observation
        self.ledger = ActionLedger() if ledger is None else ledger

    def to_json(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "turn": self.turn,
            "summary": self.summary,
            "facts": list(self.facts),
            "hypotheses": list(self.hypotheses),
            "actions": list(self.actions),
            "flags": list(self.flags),
            "signals": _copy_signals(self.signals),
            "primitives": dict(self.primitives),
            "surface": dict(self.surface),
            "surface_graph": self.surface_graph.to_json(),
            "tasks": list(self.tasks),
            "attempts": list(self.attempts),
            "last_observation": dict(self.last_observation),
            "ledger": self.ledger.to_json(),
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> AgentState:
        surface = _dict(payload.get("surface"))
        surface_graph = _surface_graph(payload.get("surface_graph"), surface=surface)
        state = cls(
            phase=str(payload.get("phase") or "recon"),
            turn=_int(payload.get("turn")),
            summary=str(payload.get("summary") or ""),
            facts=_string_list(payload.get("facts")),
            hypotheses=_string_list(payload.get("hypotheses")),
            actions=_dict_list(payload.get("actions")),
            flags=_string_list(payload.get("flags")),
            signals=_signals(payload.get("signals")),
            primitives=_primitives(payload.get("primitives")),
            surface=surface,
            surface_graph=surface_graph,
            tasks=_dict_list(payload.get("tasks")),
            attempts=_dict_list(payload.get("attempts")),
            last_observation=_dict(payload.get("last_observation")),
        )
        ledger = payload.get("ledger")
        if isinstance(ledger, dict):
            state.ledger.fingerprints = _ledger_fingerprints(ledger)
        return state

    def to_prompt_context(self) -> str:
        ledger = self.ledger.to_json()
        payload = {
            "phase": self.phase,
            "summary": self.summary,
            "facts": self.facts[-30:],
            "hypotheses": self.hypotheses[-20:],
            "recent_actions": self.actions[-12:],
            "flags": self.flags,
            "signals": _copy_recent_signals(self.signals, limit=20),
            "confirmed_primitives": dict(self.primitives),
            "surface": self.surface,
            "tasks": self.tasks[-20:],
            "last_observation": self.last_observation,
            "repetition_ledger": _recent_ledger_items(ledger, limit=20),
        }
        if self.surface_graph.operations:
            payload["surface_graph"] = self.surface_graph.to_prompt_json()
        return json.dumps(payload, indent=2, sort_keys=True)


def load_agent_state(path: Path) -> AgentState | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    raw_state = payload.get("state", payload)
    if not isinstance(raw_state, dict):
        return None
    return AgentState.from_json(raw_state)


def resolve_agent_state_path(
    resume_from: Path | None,
    *,
    workspace_state_path: Path,
) -> Path:
    """Resolve every supported resume form to the canonical working-state file."""
    if resume_from is None:
        return workspace_state_path
    if resume_from.is_dir():
        direct_state = resume_from / "working_state.json"
        nested_state = resume_from / "workspace" / "working_state.json"
        if direct_state.is_file():
            return direct_state
        if nested_state.is_file():
            return nested_state
        return direct_state if resume_from.name == "workspace" else nested_state
    if resume_from.name != "working_state.json" and (
        resume_from.is_file() or resume_from.suffix.casefold() in {".json", ".md"}
    ):
        return resume_from.parent / "workspace" / "working_state.json"
    return resume_from


def save_agent_state(path: Path, *, target_url: str, state: AgentState) -> None:
    path.write_text(
        json.dumps(
            {"target_url": target_url, "turn": state.turn, "state": state.to_json()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def append_unique(items: list[str], value: str, *, limit: int) -> None:
    if value and value not in items:
        items.append(value)
    del items[:-limit]


def merge_signals(state: AgentState, signals: dict[str, list[str]]) -> None:
    for key, values in signals.items():
        bucket = state.signals.setdefault(key, [])
        for value in values:
            append_unique(bucket, str(value), limit=30)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = str(item)
        if text:
            items.append(text)
    return items


def _dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _signals(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    signals: dict[str, list[str]] = {}
    for key, values in value.items():
        signals[str(key)] = _string_list(values)
    return signals


def _primitives(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    primitives: dict[str, int] = {}
    for key, turn in value.items():
        primitives[str(key)] = _int(turn)
    return primitives


def _dict(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _surface_graph(value: object, *, surface: dict[str, object]) -> SurfaceGraphState:
    if value is not None:
        return SurfaceGraphState.from_json(value)
    target = str(surface.get("target_url") or surface.get("origin") or "").strip()
    if not target:
        return SurfaceGraphState()
    try:
        graph = SurfaceGraphState.for_target(target)
        import_legacy_surface(
            graph,
            surface,
            identity_alias=str(surface.get("authenticated_identity") or "anonymous"),
        )
    except SurfaceGraphError:
        # Legacy surfaces were untyped and may contain malformed URLs.  Import
        # only the safe subset; a malformed *versioned* graph still fails closed.
        return SurfaceGraphState()
    return graph


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _copy_signals(signals: dict[str, list[str]]) -> dict[str, list[str]]:
    copied: dict[str, list[str]] = {}
    for key, values in signals.items():
        copied[key] = list(values)
    return copied


def _copy_recent_signals(signals: dict[str, list[str]], *, limit: int) -> dict[str, list[str]]:
    copied: dict[str, list[str]] = {}
    for key, values in signals.items():
        copied[key] = values[-limit:]
    return copied


def _ledger_fingerprints(ledger: dict[object, object]) -> dict[str, int]:
    fingerprints: dict[str, int] = {}
    for key, value in ledger.items():
        fingerprints[str(key)] = _int(value)
    return fingerprints


def _recent_ledger_items(ledger: dict[str, int], *, limit: int) -> dict[str, int]:
    items = list(ledger.items())
    recent_items = items[-limit:]
    return dict(recent_items)
