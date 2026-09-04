# Request-boundary errors intentionally carry precise fail-closed context.
# ruff: noqa: BLE001, EM101, TC001, TC003, TRY003, TRY004
"""Persistent structured HTTP replay for the default web-agent route."""

from __future__ import annotations

import json
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.action_bridge import ActionExecution
from ravage.agent_core.autonomous_graph.evidence import EvidenceBlackboard
from ravage.agent_core.autonomous_graph.operational_profile import (
    GraphOperationalProfileName,
    graph_operational_profile,
)
from ravage.agent_core.autonomous_graph.scoped_http import ScopedGraphHttpExecutor
from ravage.agent_core.autonomous_graph.traffic_lifecycle import (
    GraphTrafficLifecycle,
    GraphTrafficTerminal,
    graph_traffic_session_id,
)
from ravage.agent_core.evidence_lead_lock import (
    reactivate_for_session_change,
    release_for_session_reset,
)
from ravage.agent_core.surface_graph import SurfaceGraphError
from ravage.agent_core.surface_graph_ingest import project_surface_graph
from ravage.traffic.redaction import redact_text as redact_traffic_text
from ravage.traffic.redaction import sanitize_url
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pentest_schemas import Scope

    from ravage.agent_core.agent_state import AgentState
    from ravage.auth.runtime import ManagedAttackAuthentication
    from ravage.traffic.contracts import CapturedHttpExchange
    from ravage.traffic.policy import TrafficPolicyController

_HTTP_STATE_EPOCH_KEY = "http_state_epoch"
_HTTP_SESSION_DIRTY_KEY = "http_session_dirty"


@dataclass(slots=True)
class StatefulHttpActionSession:
    """Own one cookie-preserving, metered HTTP executor for a base-agent run."""

    target_url: str
    scope: Scope
    allow_remote_target: bool
    roe_max_rps: int
    max_total_requests: int
    workspace_dir: Path
    state: AgentState
    proof_recognition_enabled: bool = False
    authentication: ManagedAttackAuthentication | None = None
    traffic_policy: TrafficPolicyController | None = None
    low_noise: bool = False
    resume_expected: bool = False
    _traffic: GraphTrafficLifecycle | None = field(default=None, init=False, repr=False)
    _executor: ScopedGraphHttpExecutor | None = field(default=None, init=False, repr=False)
    _blackboard: EvidenceBlackboard | None = field(default=None, init=False, repr=False)
    _validation_proofs: list[str] = field(default_factory=list, init=False, repr=False)
    _call_lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        # A resumed process owns a fresh in-memory cookie jar. Give its physical
        # requests a new executor-owned repeat context instead of treating them
        # as identical to requests issued by the prior process.
        lane_artifacts = self._lane_artifacts()
        if self.resume_expected and any(lane_artifacts) and not all(lane_artifacts):
            raise RuntimeError(
                "structured HTTP resume requires request state, traffic history, and evidence"
            )
        if (
            self.resume_expected
            and self.state.surface.get(_HTTP_SESSION_DIRTY_KEY) is True
            and not all(lane_artifacts)
        ):
            raise RuntimeError("structured HTTP session state exists without its durable lane")
        if self.resume_expected and all(lane_artifacts):
            try:
                self._advance_http_state_epoch()
                executor = self._open()
                session_was_dirty = (
                    self.state.surface.get(_HTTP_SESSION_DIRTY_KEY) is True
                    or executor.session_dirty
                )
                if session_was_dirty:
                    release_for_session_reset(self.state)
                    fact = (
                        "structured HTTP session was reset on resume; re-establish "
                        "authentication before rediscovering the released evidence route"
                    )
                    if fact not in self.state.facts:
                        self.state.facts.append(fact)
                        del self.state.facts[:-80]
                    self.state.surface.pop(_HTTP_SESSION_DIRTY_KEY, None)
                    executor.clear_session_dirty()
            except BaseException as exc:
                if self._traffic is not None:
                    try:
                        self.finalize()
                    except BaseException as cleanup_error:
                        exc.add_note(
                            "structured HTTP resumed-session cleanup also failed: "
                            f"{type(cleanup_error).__name__}"
                        )
                    finally:
                        self._executor = None
                        self._traffic = None
                        self._blackboard = None
                raise

    def __call__(
        self,
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
    ) -> ActionExecution:
        # Keep traffic-delta recovery inside the executor's single-action
        # boundary. This also prevents one caller from claiming another
        # caller's captured exchanges when an action is interrupted.
        with self._call_lock:
            return self._execute_action(
                node_id=node_id,
                arguments=arguments,
                action_id=action_id,
                _deadline_monotonic=None,
            )

    def _execute_action(
        self,
        *,
        node_id: str,
        arguments: dict[str, object],
        action_id: str,
        _deadline_monotonic: float | None,
    ) -> ActionExecution:
        executor = self._executor or self._open()
        traffic = self._traffic
        blackboard = self._blackboard
        if traffic is None or blackboard is None:
            raise RuntimeError("structured HTTP durable lane is unavailable")
        known_exchange_ids = {
            exchange.exchange_id
            for exchange in traffic.store.exchanges()
            if exchange.source == "agent_http"
        }
        session_before = self._session_tokens(executor)
        # Persist this before dispatch. Any target response can rotate server-side
        # session state even when no Set-Cookie line is visible, and cookie jars
        # themselves are intentionally never written to disk.
        executor.mark_session_dirty()
        self.state.surface[_HTTP_SESSION_DIRTY_KEY] = True
        try:
            try:
                execution = executor(
                    node_id=node_id,
                    arguments=arguments,
                    action_id=action_id,
                    _deadline_monotonic=_deadline_monotonic,
                )
            except BaseException as exc:
                try:
                    self._record_interrupted_action(
                        producer_node_id=node_id,
                        arguments=arguments,
                        action_id=action_id,
                        known_exchange_ids=known_exchange_ids,
                    )
                except BaseException as evidence_error:
                    exc.add_note(
                        "structured HTTP interruption evidence could not be persisted: "
                        f"{type(evidence_error).__name__}"
                    )
                raise
        finally:
            session_after = self._session_tokens(executor)
            if session_before.shape != session_after.shape:
                self._advance_http_state_epoch()
            if session_before.full != session_after.full:
                reactivate_for_session_change(self.state)
        blackboard.record_action_result(
            producer_node_id=node_id,
            action={"action": "http_request", **arguments},
            result=execution.result,
            observation_id=execution.observation_id,
        )
        return execution

    def _record_interrupted_action(
        self,
        *,
        producer_node_id: str,
        arguments: Mapping[str, object],
        action_id: str,
        known_exchange_ids: set[str],
    ) -> None:
        """Close the evidence half of any action that captured a physical hop."""
        traffic = self._traffic
        blackboard = self._blackboard
        if traffic is None or blackboard is None:
            return
        captured = [
            exchange
            for exchange in traffic.store.exchanges()
            if exchange.source == "agent_http" and exchange.exchange_id not in known_exchange_ids
        ]
        observation_ids = tuple(
            dict.fromkeys(
                exchange.source_observation_id
                for exchange in captured
                if exchange.source_observation_id
            )
        )
        for observation_id in observation_ids:
            exchanges = [
                exchange
                for exchange in captured
                if exchange.source_observation_id == observation_id
            ]
            latest = exchanges[-1]
            evidence = json.dumps(
                {
                    "action_id": action_id,
                    "node_id": producer_node_id,
                    "outcome": "http_request_interrupted",
                    "traffic_exchange_ids": [item.exchange_id for item in exchanges],
                    "response": {
                        "status": latest.response_status,
                        "final_url": latest.response_final_url,
                        "headers": dict(latest.response_headers),
                        "body": "",
                        "body_sha256": latest.response_body_sha256,
                        "body_unavailable": True,
                        "truncated": latest.response_body_observed,
                        "error": "structured HTTP action was blocked after a captured hop",
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            blackboard.record_action_result(
                producer_node_id=producer_node_id,
                action={"action": "http_request", **arguments},
                result=ActionResult(
                    ok=False,
                    observation=evidence,
                    outcome="http_request_interrupted",
                    evidence_source_kind="tool_http_request",
                    evidence_observation=evidence,
                ),
                observation_id=observation_id,
            )

    @property
    def opened(self) -> bool:
        return self._traffic is not None

    @property
    def request_count(self) -> int:
        """Return physical requests dispatched by the persistent HTTP lane."""
        executor = self._executor
        return executor.request_count if executor is not None else 0

    def session_for_native_probe(
        self,
        *,
        timeout_seconds: int = 10,
        wall_timeout_seconds: int | None = None,
    ) -> ProbeSession:
        """
        Adapt a trusted native probe to this run's anonymous HTTP owner.

        Managed authentication has a separate owner-issued probe-session path. This
        adapter is deliberately available only for the anonymous stateful lane so a
        source-guided probe cannot silently create an independent cookie jar or
        traffic-policy boundary.
        """
        if self.authentication is not None:
            raise RuntimeError("managed authentication must issue its own native probe session")
        with self._call_lock:
            if self._executor is None:
                self._open()
        session = _StatefulProbeSession(
            self,
            timeout_seconds=timeout_seconds,
            wall_timeout_seconds=wall_timeout_seconds,
        )
        session.configure_managed_identity_forks(header_names=())
        session.bind_managed_request_delegate(
            self._request_from_native_probe,
            generation=0,
            lease=object(),
            session_observer=_ignore_probe_session,
        )
        session.bind_traffic_identity("anonymous", generation=0)
        return session

    def finalize(self) -> GraphTrafficTerminal | None:
        if self._traffic is None:
            return None
        primary_error: BaseException | None = None
        terminal: GraphTrafficTerminal | None = None
        try:
            if self._executor is not None:
                self._executor.close()
        except BaseException as exc:  # preserve lifecycle cleanup below.
            primary_error = exc
        try:
            terminal = self._traffic.finalize()
        except BaseException as exc:
            if primary_error is None:
                primary_error = exc
            else:
                primary_error.add_note(
                    f"structured HTTP traffic finalization also failed: {type(exc).__name__}"
                )
        try:
            if self.authentication is not None:
                self.authentication.configure_request_gate(None)
        except BaseException as exc:
            if primary_error is None:
                primary_error = exc
            else:
                primary_error.add_note(
                    f"structured HTTP authentication-gate cleanup also failed: {type(exc).__name__}"
                )
        if primary_error is not None:
            raise primary_error
        return terminal

    def request(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 10,
        _deadline_monotonic: float | None = None,
    ) -> ProbeResponse:
        """Adapt the persistent lane for ``validate_http_poc`` paired replays."""
        arguments: dict[str, object] = {
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "timeout_seconds": timeout_seconds,
        }
        if data is not None:
            arguments["body"] = data.decode("utf-8", errors="replace")
        try:
            with self._call_lock:
                execution = self._execute_action(
                    node_id="base-agent-validator",
                    arguments=arguments,
                    action_id=f"validate-{uuid4()}",
                    _deadline_monotonic=_deadline_monotonic,
                )
        except ValueError as exc:
            error = str(exc)
            if self.authentication is not None:
                error = self.authentication.redact_text(error)
            return ProbeResponse(
                method=str(method).upper(),
                url=sanitize_url(url),
                status=None,
                final_url=sanitize_url(url),
                elapsed_ms=0,
                error=redact_traffic_text(error, max_chars=300),
            )
        if execution.result.flag and execution.result.flag not in self._validation_proofs:
            self._validation_proofs.append(execution.result.flag)
        try:
            envelope = json.loads(execution.result.evidence_observation)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("structured HTTP validation returned invalid evidence") from exc
        response = envelope.get("response") if isinstance(envelope, dict) else None
        if not isinstance(response, dict):
            raise RuntimeError("structured HTTP validation returned no response evidence")
        status_value = response.get("status")
        status = (
            status_value
            if isinstance(status_value, int) and not isinstance(status_value, bool)
            else None
        )
        response_headers = response.get("headers")
        body = str(response.get("body") or "")
        return ProbeResponse(
            method=str(method).upper(),
            url=url,
            status=status,
            final_url=str(response.get("final_url") or url),
            elapsed_ms=_final_physical_response_elapsed_ms(envelope),
            headers=(
                {str(name): str(value) for name, value in response_headers.items()}
                if isinstance(response_headers, dict)
                else {}
            ),
            body=body,
            error=str(response.get("error") or ""),
            truncated=response.get("truncated") is True,
        )

    def _request_from_native_probe(  # noqa: PLR0913 - ProbeSession delegate protocol.
        self,
        session: ProbeSession,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProbeResponse:
        """Dispatch one native-probe request through the persistent owner."""
        merged_headers = dict(session.default_headers)
        merged_headers.update(headers or {})
        timeout = session.timeout_seconds if timeout_seconds is None else timeout_seconds
        return self.request(
            method,
            url,
            data=data,
            headers=merged_headers,
            timeout_seconds=timeout,
            _deadline_monotonic=session.wall_clock_deadline_monotonic,
        )

    def begin_validation(self) -> None:
        """Start one outer PoC replay proof-aggregation boundary."""
        self._validation_proofs.clear()

    def consume_validation_proofs(self) -> tuple[str, ...]:
        """Return and clear proofs recognized before validator body clipping."""
        proofs = tuple(self._validation_proofs)
        self._validation_proofs.clear()
        return proofs

    def _open(self) -> ScopedGraphHttpExecutor:  # noqa: C901 - durable lane setup.
        identity_alias = self.authentication.identity if self.authentication is not None else ""
        http_state_path = self.workspace_dir / "agent-http-state.json"
        blackboard_path = self.workspace_dir / "evidence-blackboard.json"
        lane_artifacts = self._lane_artifacts()
        if any(lane_artifacts) and not all(lane_artifacts):
            raise RuntimeError(
                "structured HTTP resume requires request state, traffic history, and evidence"
            )
        lane_resumed = all(lane_artifacts)
        if lane_resumed and not self.resume_expected:
            raise RuntimeError("new agent run cannot reuse prior structured HTTP state")
        try:
            self._blackboard = EvidenceBlackboard(
                target_url=self.target_url,
                state_path=blackboard_path,
            )
            traffic = GraphTrafficLifecycle.open(
                self.workspace_dir,
                target_url=self.target_url,
                in_scope=tuple(str(item) for item in self.scope.in_scope),
                out_of_scope=tuple(str(item) for item in self.scope.out_of_scope),
                capture_session_id=graph_traffic_session_id(
                    f"base-agent:{self.target_url}:{identity_alias or 'anonymous'}"
                ),
                graph_resume_expected=lane_resumed,
                identity_alias=identity_alias,
            )
            self._traffic = traffic
            traffic.recorder.set_exchange_sink(self._ingest_exchange)
            executor = ScopedGraphHttpExecutor(
                target_url=self.target_url,
                scope=self.scope,
                allow_remote_target=self.allow_remote_target,
                profile=graph_operational_profile(
                    (
                        GraphOperationalProfileName.LOW_NOISE
                        if self.low_noise
                        else GraphOperationalProfileName.STANDARD
                    ),
                    roe_max_rps=self.roe_max_rps,
                    max_total_requests=self.max_total_requests,
                ),
                proof_recognition_enabled=self.proof_recognition_enabled,
                state_path=http_state_path,
                traffic_observer=traffic.recorder,
                require_existing_state=traffic.resumed,
                minimum_request_count=traffic.existing_agent_http_exchange_count,
                authentication=self.authentication,
                traffic_policy=self.traffic_policy,
                # This lane deliberately carries cookies between actions. The
                # policy fingerprint is computed before urllib adds Cookie, so a
                # cached pre-login GET could otherwise mask a post-login response.
                cache_anonymous_gets=False,
                persistent_managed_session=True,
            )
            self._executor = executor
            if lane_resumed:
                self._validate_resumed_evidence(traffic)
                self._restore_surface_from_traffic(traffic)
        except BaseException as exc:
            try:
                if self._traffic is not None:
                    self.finalize()
                elif self.authentication is not None:
                    self.authentication.configure_request_gate(None)
            except BaseException as cleanup_error:
                exc.add_note(
                    "structured HTTP failed-open cleanup also failed: "
                    f"{type(cleanup_error).__name__}"
                )
            finally:
                self._executor = None
                self._traffic = None
                self._blackboard = None
            if not lane_resumed:
                try:
                    self._rollback_fresh_lane()
                except OSError as cleanup_error:
                    exc.add_note(
                        "structured HTTP fresh-lane rollback failed: "
                        f"{type(cleanup_error).__name__}"
                    )
            raise
        else:
            return executor

    def _lane_artifacts(self) -> tuple[bool, bool, bool]:
        return (
            (self.workspace_dir / "agent-http-state.json").is_file(),
            (self.workspace_dir / "traffic").exists(),
            (self.workspace_dir / "evidence-blackboard.json").is_file(),
        )

    def _rollback_fresh_lane(self) -> None:
        """Remove only artifacts created by a failed, previously empty lane."""
        for name in ("agent-http-state.json", "evidence-blackboard.json"):
            path = self.workspace_dir / name
            if path.is_file():
                path.unlink()
        traffic_path = self.workspace_dir / "traffic"
        if traffic_path.exists():
            shutil.rmtree(traffic_path)

    def _session_tokens(self, executor: ScopedGraphHttpExecutor) -> _SessionTokens:
        prefix: tuple[object, ...] = (
            (
                "managed",
                self.authentication.identity_generation,
            )
            if self.authentication is not None
            else ("anonymous",)
        )
        transport = getattr(executor, "transport", None)
        cookies = getattr(transport, "cookies", None)
        if cookies is None:
            return _SessionTokens(shape=prefix, full=prefix)
        try:
            entries = tuple(
                (
                    (
                        str(cookie.domain),
                        str(cookie.path),
                        str(cookie.name),
                        bool(cookie.secure),
                        str(cookie.port or ""),
                        int(cookie.version),
                        bool(cookie.discard),
                    ),
                    str(cookie.value),
                    cookie.expires,
                )
                for cookie in cookies
            )
            shaped = tuple(sorted(shape for shape, _value, _expires in entries))
            valued = tuple(sorted((*shape, value, expires) for shape, value, expires in entries))
            return _SessionTokens(shape=(*prefix, *shaped), full=(*prefix, *valued))
        except (AttributeError, TypeError):
            # A custom test transport may not expose stdlib Cookie objects.
            return _SessionTokens(shape=prefix, full=prefix)

    def _advance_http_state_epoch(self) -> None:
        value = self.state.surface.get(_HTTP_STATE_EPOCH_KEY)
        current = value if isinstance(value, int) and not isinstance(value, bool) else 0
        self.state.surface[_HTTP_STATE_EPOCH_KEY] = max(0, current) + 1

    def _ingest_exchange(self, exchange: CapturedHttpExchange) -> None:
        try:
            self.state.surface_graph.ingest_exchange(exchange)
        except SurfaceGraphError:
            # One structured lane may target multiple explicitly scoped origins,
            # while the canonical graph is intentionally bound to one origin.
            return
        self.state.surface = project_surface_graph(self.state.surface_graph, self.state.surface)

    def _validate_resumed_evidence(self, traffic: GraphTrafficLifecycle) -> None:
        blackboard = self._blackboard
        if blackboard is None:
            raise RuntimeError("structured HTTP evidence blackboard is unavailable")
        traffic_observations = {
            exchange.source_observation_id
            for exchange in traffic.store.exchanges()
            if exchange.source == "agent_http"
        }
        blackboard_observations = {
            record.observation_id
            for record in blackboard.state.records.values()
            if record.kind.value == "raw_observation" and record.source.value == "tool_http_request"
        }
        if "" in traffic_observations or not traffic_observations.issubset(blackboard_observations):
            raise RuntimeError(
                "structured HTTP traffic and evidence are inconsistent after interruption"
            )

    def _restore_surface_from_traffic(self, traffic: GraphTrafficLifecycle) -> None:
        known_refs = {
            ref
            for observation in (self.state.surface_graph.observations or {}).values()
            for ref in observation.evidence_refs
        }
        for exchange in traffic.store.exchanges():
            if exchange.source != "agent_http" or exchange.exchange_id in known_refs:
                continue
            self._ingest_exchange(exchange)


@dataclass(frozen=True, slots=True)
class _SessionTokens:
    shape: tuple[object, ...]
    full: tuple[object, ...]


class _StatefulProbeSession(ProbeSession):
    """Probe facade whose accounting is owned by StatefulHttpActionSession."""

    def __init__(
        self,
        owner: StatefulHttpActionSession,
        *,
        timeout_seconds: int,
        wall_timeout_seconds: int | None,
    ) -> None:
        self._stateful_owner = owner
        deadline = (
            time.monotonic() + max(1, wall_timeout_seconds)
            if wall_timeout_seconds is not None
            else None
        )
        super().__init__(
            owner.target_url,
            timeout_seconds=timeout_seconds,
            allow_remote_target=owner.allow_remote_target,
            in_scope=tuple(str(item) for item in owner.scope.in_scope),
            out_of_scope=tuple(str(item) for item in owner.scope.out_of_scope),
            _deadline_monotonic=deadline,
        )

    @property
    def physical_request_count(self) -> int:
        return self._stateful_owner.request_count

    def fork(
        self,
        *,
        timeout_seconds: int | None = None,
        inherit_identity: bool | None = None,
        max_body_bytes: int | None = None,
    ) -> ProbeSession:
        # This owner is already anonymous, so dropping "identity" must never
        # detach a descendant from its scope, cookie jar, or traffic ledger.
        _ = inherit_identity
        return super().fork(
            timeout_seconds=timeout_seconds,
            inherit_identity=True,
            max_body_bytes=max_body_bytes,
        )


def _ignore_probe_session(
    _lease: object,
    _session: ProbeSession,
    _source_session: ProbeSession | None,
) -> None:
    return


def _final_physical_response_elapsed_ms(envelope: object) -> int:
    """Recover transport duration without including executor scheduling delay."""
    if not isinstance(envelope, dict):
        return 0
    requests = envelope.get("requests")
    if not isinstance(requests, list) or not requests:
        return 0
    final_request = requests[-1]
    if not isinstance(final_request, dict) or final_request.get("physical_request") is not True:
        return 0
    elapsed_ms = final_request.get("elapsed_ms")
    if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, int):
        return 0
    return max(0, elapsed_ms)


def request_arguments(action: Mapping[str, object]) -> dict[str, object]:
    """Return only executor-owned HTTP dispatch fields from a model action."""
    allowed = {"method", "url", "path", "headers", "body", "json", "form", "timeout_seconds"}
    return {key: action[key] for key in allowed if key in action}


__all__ = ["StatefulHttpActionSession", "request_arguments"]
