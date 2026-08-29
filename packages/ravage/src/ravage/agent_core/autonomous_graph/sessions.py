from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class SessionRole(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True)
class SessionRecord:
    role: SessionRole
    content: str

    def to_message(self) -> dict[str, str]:
        return {"role": self.role.value, "content": self.content}


@dataclass(frozen=True)
class GraphSessionStore:
    """Crash-tolerant, bounded, per-node conversation histories."""

    root: Path
    max_records: int = 48
    max_content_chars: int = 120_000

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        max_records: int = 48,
        max_content_chars: int = 120_000,
    ) -> GraphSessionStore:
        if max_records <= 0 or max_content_chars <= 0:
            message = "session limits must be greater than zero"
            raise ValueError(message)
        root.mkdir(parents=True, exist_ok=True)
        return cls(
            root=root,
            max_records=max_records,
            max_content_chars=max_content_chars,
        )

    def append(
        self,
        node_id: str,
        *,
        role: SessionRole,
        content: str,
    ) -> None:
        clipped = content[-self.max_content_chars :]
        path = self._path(node_id)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"role": role.value, "content": clipped},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )

    def records(self, node_id: str) -> tuple[SessionRecord, ...]:
        path = self._path(node_id)
        if not path.exists():
            return ()
        records: list[SessionRecord] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            try:
                role = SessionRole(str(payload.get("role") or ""))
            except ValueError:
                continue
            content = str(payload.get("content") or "")
            if content:
                records.append(SessionRecord(role=role, content=content))
        return self._bounded(tuple(records))

    def messages(self, node_id: str) -> list[dict[str, str]]:
        return [record.to_message() for record in self.records(node_id)]

    def _bounded(
        self,
        records: tuple[SessionRecord, ...],
    ) -> tuple[SessionRecord, ...]:
        selected: list[SessionRecord] = []
        characters = 0
        for record in reversed(records[-self.max_records :]):
            remaining = self.max_content_chars - characters
            if remaining <= 0:
                break
            content = record.content[-remaining:]
            selected.append(SessionRecord(role=record.role, content=content))
            characters += len(content)
        return tuple(reversed(selected))

    def _path(self, node_id: str) -> Path:
        safe = "".join(
            character if character.isalnum() or character in {"-", "_"} else "-"
            for character in node_id
        )
        return self.root / f"{safe or 'node'}.jsonl"


__all__ = [
    "GraphSessionStore",
    "SessionRecord",
    "SessionRole",
]
