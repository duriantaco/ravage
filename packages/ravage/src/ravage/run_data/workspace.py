from __future__ import annotations

import json
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path
    from typing import Any

MAX_INLINE_CHARS = 6_000


@dataclass(frozen=True)
class AgentWorkspace:
    root: Path
    events_path: Path
    transcript_path: Path
    state_path: Path
    artifacts_dir: Path
    terminal_dir: Path
    event_sink: Callable[[Mapping[str, Any]], None] | None = None
    _write_lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
        compare=False,
    )

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        event_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> AgentWorkspace:
        root.mkdir(parents=True, exist_ok=True)
        artifacts_dir = root / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        terminal_dir = root / "terminal"
        terminal_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            root=root,
            events_path=root / "events.jsonl",
            transcript_path=root / "transcript.jsonl",
            state_path=root / "working_state.json",
            artifacts_dir=artifacts_dir,
            terminal_dir=terminal_dir,
            event_sink=event_sink,
        )

    def record_event(self, *, kind: str, payload: Mapping[str, Any]) -> str:
        with self._write_lock:
            event_id = str(uuid4())
            event = {
                "event_id": event_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "kind": kind,
                "payload": self._prepare_payload(event_id, kind, payload),
            }
            self._append_jsonl(self.events_path, event)
            if self.event_sink is not None:
                with suppress(Exception):
                    self.event_sink(event)
        return event_id

    def record_transcript(self, *, role: str, content: str) -> str:
        with self._write_lock:
            event_id = str(uuid4())
            event = {
                "event_id": event_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "role": role,
                "content": self._prepare_string(event_id, "transcript", "content", content),
            }
            self._append_jsonl(self.transcript_path, event)
        return event_id

    def record_terminal(
        self,
        *,
        session: str,
        stream: str,
        content: str,
        command: list[str] | tuple[str, ...] | None = None,
    ) -> Path:
        with self._write_lock:
            path = self.terminal_dir / f"{_safe_name(session) or 'default'}.jsonl"
            event_id = str(uuid4())
            event = {
                "event_id": event_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "session": session,
                "stream": stream,
                "command": list(command or ()),
                "content": self._prepare_string(event_id, "terminal", stream, content),
            }
            self._append_jsonl(path, event)
        return path

    def write_state(self, payload: Mapping[str, Any]) -> None:
        with self._write_lock:
            self.state_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
                encoding="utf-8",
            )

    def _prepare_payload(self, event_id: str, kind: str, value: object) -> object:
        if isinstance(value, str):
            return self._prepare_string(event_id, kind, "value", value)
        if isinstance(value, list):
            return [
                self._prepare_payload(event_id, f"{kind}-{index}", item)
                for index, item in enumerate(value)
            ]
        if isinstance(value, dict):
            return {
                str(key): self._prepare_payload(event_id, f"{kind}-{key}", item)
                for key, item in value.items()
            }
        return value

    def _prepare_string(
        self,
        event_id: str,
        kind: str,
        key: str,
        value: str,
    ) -> object:
        if len(value) <= MAX_INLINE_CHARS:
            return value
        artifact_name = f"{event_id}-{_safe_name(kind)}-{_safe_name(key)}.txt"
        artifact_path = self.artifacts_dir / artifact_name
        artifact_path.write_text(value, encoding="utf-8")
        return {
            "artifact_path": str(artifact_path),
            "snippet": value[:MAX_INLINE_CHARS],
            "truncated": True,
            "original_chars": len(value),
        }

    @staticmethod
    def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in value)[:80]
