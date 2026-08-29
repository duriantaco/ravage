from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ravage.memory import MemoryItem, UnsafeMemoryError


@dataclass(frozen=True)
class ReflectionPrompt:
    system: str
    user: str


def build_reflection_prompt(
    items: list[MemoryItem] | None = None,
    *,
    audit_path: Path | None = None,
    workspace_events_path: Path | None = None,
    engagement_id: str = "",
    target_url: str = "",
    objectives: list[str] | None = None,
    discovered_routes: list[str] | None = None,
    confirmed_vuln_classes: list[str] | None = None,
    captured_flags: list[str] | None = None,
) -> ReflectionPrompt | str:
    if items is not None:
        return "\n".join(f"{item.key}: {item.value}" for item in items)

    system = (
        "Extract durable Ravage memories from a completed run. "
        "Return at most 3 memories as compact JSON. Keep retrieval_text under 300 characters. "
        "Do not include raw secrets, flags, credentials, or destructive instructions."
    )
    user = json.dumps(
        {
            "audit_path": str(audit_path or ""),
            "workspace_events_path": str(workspace_events_path or ""),
            "engagement_id": engagement_id,
            "target_url": target_url,
            "objectives": objectives or [],
            "discovered_routes": discovered_routes or [],
            "confirmed_vuln_classes": confirmed_vuln_classes or [],
            "captured_flags_count": len(captured_flags or []),
        },
        sort_keys=True,
    )
    return ReflectionPrompt(system=system, user=user)


def parse_reflection_memories(text: str, *, source_run_id: str = "") -> list[MemoryItem]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid memory reflection JSON") from exc

    raw_memories = payload.get("memories") if isinstance(payload, dict) else None
    if not isinstance(raw_memories, list):
        raise ValueError("invalid memory reflection JSON")

    memories: list[MemoryItem] = []
    for raw in raw_memories:
        if not isinstance(raw, dict):
            continue
        _reject_unsafe_memory(raw)
        memories.append(
            MemoryItem.new(
                type=str(raw.get("type") or "lesson"),
                status=str(raw.get("status") or "candidate"),
                summary=str(raw.get("summary") or ""),
                vuln_class=_optional_string(raw.get("vuln_class")),
                target_fingerprint=_dict_value(raw.get("target_fingerprint")),
                preconditions=_string_list(raw.get("preconditions")),
                recommended_actions=_string_list(raw.get("recommended_actions")),
                negative_actions=_string_list(raw.get("negative_actions")),
                evidence_requirements=_string_list(raw.get("evidence_requirements")),
                confidence=_float_value(raw.get("confidence"), default=0.5),
                retrieval_text=str(raw.get("retrieval_text") or ""),
                redacted_proof=_dict_value(raw.get("redacted_proof")),
            )
        )
    _ = source_run_id
    return memories


def _reject_unsafe_memory(raw: dict[str, object]) -> None:
    text = json.dumps(raw, sort_keys=True).lower()
    if "rm -rf" in text:
        raise UnsafeMemoryError("destructive_payload")


def _dict_value(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _float_value(value: object, *, default: float) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default
