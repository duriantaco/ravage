# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.traffic.manifest import (
    TrafficRunError,
    TrafficRunManifest,
    read_traffic_manifest,
    write_traffic_manifest,
)
from ravage.traffic.recorders import ProbeTrafficRecorder
from ravage.traffic.redaction import redact_text
from ravage.traffic.store import TrafficStore, TrafficStoreError

if TYPE_CHECKING:
    from ravage.traffic.contracts import CapturedHttpExchange

_AGENT_HTTP_SOURCE = "agent_http"


class GraphTrafficLifecycleError(RuntimeError):
    """Raised when graph traffic cannot preserve one safe run identity."""


@dataclass(frozen=True, slots=True)
class GraphTrafficTerminal:
    capture_session_id: str
    resumed: bool
    exchange_count: int
    agent_http_exchange_count: int
    manifest_completed: bool
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @classmethod
    def failed_start(
        cls,
        *,
        capture_session_id: str,
        error: BaseException,
    ) -> GraphTrafficTerminal:
        detail = redact_text(error, max_chars=300)
        return cls(
            capture_session_id=capture_session_id,
            resumed=False,
            exchange_count=0,
            agent_http_exchange_count=0,
            manifest_completed=False,
            errors=(detail,),
        )

    def to_json(self) -> dict[str, object]:
        status = "error" if self.errors else "warning" if self.warnings else "completed"
        return {
            "status": status,
            "capture_session_id": self.capture_session_id,
            "resumed": self.resumed,
            "exchange_count": self.exchange_count,
            "agent_http_exchange_count": self.agent_http_exchange_count,
            "manifest_completed": self.manifest_completed,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


@dataclass(slots=True)
class GraphTrafficLifecycle:
    """Own one strict, resumable agent-HTTP capture for a graph workspace."""

    store: TrafficStore
    manifest: TrafficRunManifest
    recorder: ProbeTrafficRecorder
    resumed: bool
    graph_resumed: bool
    existing_agent_http_exchange_count: int
    _terminal: GraphTrafficTerminal | None = field(default=None, init=False, repr=False)

    @classmethod
    def open(  # noqa: PLR0913 - lifecycle identity fields stay explicit.
        cls,
        workspace_dir: Path,
        *,
        target_url: str,
        in_scope: tuple[str, ...],
        out_of_scope: tuple[str, ...],
        capture_session_id: str,
        graph_resume_expected: bool | None = None,
        identity_alias: str = "",
    ) -> GraphTrafficLifecycle:
        traffic_root = Path(workspace_dir) / "traffic"
        try:
            expected = TrafficRunManifest.create(
                target_url=target_url,
                capture_session_id=capture_session_id,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
            )
            if graph_resume_expected is True and not traffic_root.exists():
                raise GraphTrafficLifecycleError(
                    "graph resume is missing its prior traffic history"
                )
            if traffic_root.exists():
                manifest = read_traffic_manifest(workspace_dir)
                _validate_manifest(manifest, expected=expected)
                store = TrafficStore.open(workspace_dir, writable=True)
                agent_http_count = _validate_store_sessions(
                    store,
                    capture_session_id=capture_session_id,
                    identity_alias=identity_alias,
                )
                if graph_resume_expected is False and agent_http_count:
                    raise GraphTrafficLifecycleError(
                        "new graph state cannot reuse prior agent HTTP traffic"
                    )
                resumed = True
            else:
                store = TrafficStore.create(workspace_dir, require_empty=True)
                write_traffic_manifest(workspace_dir, expected)
                manifest = expected
                resumed = False
                agent_http_count = 0
        except (OSError, TrafficRunError, TrafficStoreError) as exc:
            raise GraphTrafficLifecycleError(f"graph traffic initialization failed: {exc}") from exc

        errors: list[str] = []
        recorder = ProbeTrafficRecorder(
            store,
            capture_session_id=capture_session_id,
            identity_alias=identity_alias,
            error_sink=errors,
            source=_AGENT_HTTP_SOURCE,
            strict=True,
        )
        return cls(
            store=store,
            manifest=manifest,
            recorder=recorder,
            resumed=resumed,
            graph_resumed=bool(graph_resume_expected),
            existing_agent_http_exchange_count=agent_http_count,
        )

    def finalize(self) -> GraphTrafficTerminal:
        if self._terminal is not None:
            return self._terminal
        warnings: list[str] = []
        errors = list(self.recorder.errors)
        exchanges: tuple[CapturedHttpExchange, ...] = ()
        try:
            exchanges = self.store.exchanges()
        except TrafficStoreError as exc:
            warnings.append(
                f"traffic exchange count unavailable: {redact_text(exc, max_chars=300)}"
            )
        completed = self.manifest.complete()
        try:
            write_traffic_manifest(self.store.workspace_dir, completed)
        except (OSError, TrafficRunError) as exc:
            warnings.append(
                f"traffic manifest finalization failed: {redact_text(exc, max_chars=300)}"
            )
            manifest_completed = False
        else:
            self.manifest = completed
            manifest_completed = True
        self._terminal = GraphTrafficTerminal(
            capture_session_id=self.manifest.capture_session_id,
            resumed=self.resumed,
            exchange_count=len(exchanges),
            agent_http_exchange_count=sum(
                exchange.source == _AGENT_HTTP_SOURCE for exchange in exchanges
            ),
            manifest_completed=manifest_completed,
            warnings=tuple(warnings),
            errors=tuple(errors),
        )
        return self._terminal


def graph_traffic_session_id(graph_id: str) -> str:
    """Derive a stable, non-secret capture identity from a graph run identity."""
    digest = hashlib.sha256(graph_id.encode("utf-8", errors="replace")).hexdigest()
    return f"agent-http-{digest[:12]}"


def _validate_manifest(
    manifest: TrafficRunManifest,
    *,
    expected: TrafficRunManifest,
) -> None:
    if (
        manifest.target_url != expected.target_url
        or manifest.target_identity != expected.target_identity
        or manifest.origin != expected.origin
    ):
        raise GraphTrafficLifecycleError("graph traffic target does not match its manifest")
    if manifest.in_scope != expected.in_scope or manifest.out_of_scope != expected.out_of_scope:
        raise GraphTrafficLifecycleError("graph traffic scope does not match its manifest")
    if manifest.capture_session_id != expected.capture_session_id:
        raise GraphTrafficLifecycleError("graph traffic capture session does not match")


def _validate_store_sessions(
    store: TrafficStore,
    *,
    capture_session_id: str,
    identity_alias: str = "",
) -> int:
    exchanges = store.exchanges()
    replays = store.replay_receipts()
    exchange_mismatch = any(
        exchange.capture_session_id != capture_session_id for exchange in exchanges
    )
    replay_mismatch = any(receipt.capture_session_id != capture_session_id for receipt in replays)
    if exchange_mismatch or replay_mismatch:
        raise GraphTrafficLifecycleError("graph traffic store contains a different capture session")
    identity_mismatch = any(
        exchange.source == _AGENT_HTTP_SOURCE and exchange.identity_alias != identity_alias
        for exchange in exchanges
    )
    if identity_mismatch:
        raise GraphTrafficLifecycleError(
            "graph traffic store contains a different authentication identity"
        )
    return sum(exchange.source == _AGENT_HTTP_SOURCE for exchange in exchanges)


__all__ = [
    "GraphTrafficLifecycle",
    "GraphTrafficLifecycleError",
    "GraphTrafficTerminal",
    "graph_traffic_session_id",
]
