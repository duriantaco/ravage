from __future__ import annotations

import json
import mimetypes
import re
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

import yaml

from ravage.live_dashboard_view import (
    _activity,
    _agents,
    _collect_flags,
    _command_output,
    _command_request,
    _kill_chain_breakdown,
    _loads_object,
    _mask_flag,
    _mask_sensitive,
    _metrics,
    _object_dict,
    _selection,
    _stage_flow,
    _StreamCursor,
    _viewer_state,
    _warnings,
    _work_chart,
)
from ravage.run_data.run_manifest import (
    MANIFEST_NAME,
    STATUS_TORN_DOWN,
    RunManifest,
    find_active_run_dir,
    read_manifest,
    update_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

FRONTEND_DIR = Path(__file__).resolve().parents[3] / "ravage-cockpit"
REPO_ASSETS_DIR = Path(__file__).resolve().parents[4] / "assets"

__all__ = [
    "CockpitServer",
    "DashboardSettings",
    "_StreamCursor",
    "_command_output",
    "_command_request",
    "build_dashboard_state",
    "serve_dashboard",
    "settings_from_run_dir",
    "start_cockpit",
    "teardown_active_run",
]


@dataclass(frozen=True, init=False)
class DashboardSettings:
    workspace_dir: Path
    db_path: Path | None = None
    stdout_path: Path | None = None
    docker_log_path: Path | None = None
    lab_manifest_path: Path | None = None
    run_root: Path | None = None
    max_events: int = 200
    max_audit_rows: int = 200
    max_stdout_lines: int = 200
    max_docker_log_lines: int = 200
    max_terminal_events: int = 200

    def __init__(  # noqa: PLR0913
        self,
        workspace_dir: Path,
        db_path: Path | None = None,
        stdout_path: Path | None = None,
        docker_log_path: Path | None = None,
        lab_manifest_path: Path | None = None,
        run_root: Path | None = None,
        max_events: int = 200,
        max_audit_rows: int = 200,
        max_stdout_lines: int = 200,
        max_docker_log_lines: int = 200,
        max_terminal_events: int = 200,
    ) -> None:
        object.__setattr__(self, "workspace_dir", workspace_dir)
        object.__setattr__(self, "db_path", db_path)
        object.__setattr__(self, "stdout_path", stdout_path)
        object.__setattr__(self, "docker_log_path", docker_log_path)
        object.__setattr__(self, "lab_manifest_path", lab_manifest_path)
        object.__setattr__(self, "run_root", run_root)
        object.__setattr__(self, "max_events", max_events)
        object.__setattr__(self, "max_audit_rows", max_audit_rows)
        object.__setattr__(self, "max_stdout_lines", max_stdout_lines)
        object.__setattr__(self, "max_docker_log_lines", max_docker_log_lines)
        object.__setattr__(self, "max_terminal_events", max_terminal_events)


@dataclass(frozen=True)
class _DashboardPaths:
    workspace_dir: Path
    events_path: Path
    transcript_path: Path
    working_state_path: Path
    terminal_dir: Path
    docker_log_path: Path | None


@dataclass(frozen=True)
class _DashboardSources:
    events: list[dict[str, Any]]
    transcript: list[dict[str, Any]]
    working_state: dict[str, Any]
    audit_rows: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    stdout_lines: list[str]
    docker_log_lines: list[str]
    terminal: list[dict[str, Any]]
    lab: dict[str, Any]
    docker: dict[str, Any]


@dataclass(frozen=True)
class _DashboardDerived:
    flags: list[str]
    metrics: dict[str, Any]
    selection: dict[str, Any]
    activity: list[dict[str, Any]]
    stage_flow: list[dict[str, str]]
    kill_chain: list[dict[str, Any]]
    viewer: dict[str, Any]


def _resolve_active(
    settings: DashboardSettings,
) -> tuple[DashboardSettings, RunManifest | None]:
    if settings.run_root is None:
        return settings, _manifest_beside(settings.workspace_dir)

    run_dir = find_active_run_dir(settings.run_root)
    if run_dir is None:
        return settings, None

    manifest = read_manifest(run_dir)
    lab_manifest = _active_lab_manifest_path(settings=settings, manifest=manifest)
    derived = settings_from_run_dir(run_dir, lab_manifest_path=lab_manifest)
    return replace(derived, run_root=settings.run_root), manifest


def _active_lab_manifest_path(
    *,
    settings: DashboardSettings,
    manifest: RunManifest | None,
) -> Path | None:
    if manifest is None or not manifest.lab_manifest_path:
        return settings.lab_manifest_path

    candidate = Path(manifest.lab_manifest_path)
    if candidate.exists():
        return candidate
    return settings.lab_manifest_path


def _manifest_beside(workspace_dir: Path) -> RunManifest | None:
    run_dir = workspace_dir
    if workspace_dir.name == "workspace":
        run_dir = workspace_dir.parent
    return read_manifest(run_dir)


def build_dashboard_state(settings: DashboardSettings) -> dict[str, Any]:
    settings, manifest = _resolve_active(settings)
    mode = _dashboard_mode(manifest)
    paths = _dashboard_paths(settings)
    sources = _read_dashboard_sources(settings=settings, paths=paths)
    derived = _derive_dashboard_state(
        sources=sources,
        manifest=manifest,
        mode=mode,
    )
    return _dashboard_payload(
        settings=settings,
        manifest=manifest,
        mode=mode,
        paths=paths,
        sources=sources,
        derived=derived,
    )


def _dashboard_mode(manifest: RunManifest | None) -> str:
    if manifest is None:
        return "live"
    return manifest.mode


def _dashboard_paths(settings: DashboardSettings) -> _DashboardPaths:
    workspace_dir = settings.workspace_dir
    return _DashboardPaths(
        workspace_dir=workspace_dir,
        events_path=workspace_dir / "events.jsonl",
        transcript_path=workspace_dir / "transcript.jsonl",
        working_state_path=workspace_dir / "working_state.json",
        terminal_dir=workspace_dir / "terminal",
        docker_log_path=settings.docker_log_path or _derived_docker_log_path(settings),
    )


def _read_dashboard_sources(
    *,
    settings: DashboardSettings,
    paths: _DashboardPaths,
) -> _DashboardSources:
    events = _read_jsonl(paths.events_path, limit=settings.max_events)
    transcript = _read_jsonl(paths.transcript_path, limit=settings.max_events)
    working_state = _read_json_file(paths.working_state_path)
    audit_rows = _read_audit_rows(settings.db_path, limit=settings.max_audit_rows)
    findings = _read_findings(settings.db_path)
    stdout_lines = _tail_lines(settings.stdout_path, limit=settings.max_stdout_lines)
    docker_log_lines = _tail_lines(paths.docker_log_path, limit=settings.max_docker_log_lines)
    terminal = _read_terminal_sessions(paths.terminal_dir, limit=settings.max_terminal_events)
    lab = _read_lab_manifest(settings.lab_manifest_path)
    docker = _docker_runtime_state(settings=settings, lab=lab, docker_log_lines=docker_log_lines)
    return _DashboardSources(
        events=events,
        transcript=transcript,
        working_state=working_state,
        audit_rows=audit_rows,
        findings=findings,
        stdout_lines=stdout_lines,
        docker_log_lines=docker_log_lines,
        terminal=terminal,
        lab=lab,
        docker=docker,
    )


def _derive_dashboard_state(
    *,
    sources: _DashboardSources,
    manifest: RunManifest | None,
    mode: str,
) -> _DashboardDerived:
    flags = _collect_flags(sources.events, sources.audit_rows)
    metrics = _metrics(sources.events, sources.audit_rows, sources.findings, sources.terminal)
    selection = _selection(sources.audit_rows)
    activity = _activity(sources.events, sources.audit_rows)
    stage_flow = _stage_flow(sources.audit_rows)
    kill_chain = _kill_chain_breakdown(sources.audit_rows, sources.findings)
    viewer = _viewer_state(
        events=sources.events,
        audit_rows=sources.audit_rows,
        working_state=sources.working_state,
        lab=sources.lab,
        metrics=metrics,
        findings=sources.findings,
        flags=flags,
        manifest=manifest,
        mode=mode,
    )
    return _DashboardDerived(
        flags=flags,
        metrics=metrics,
        selection=selection,
        activity=activity,
        stage_flow=stage_flow,
        kill_chain=kill_chain,
        viewer=viewer,
    )


def _dashboard_payload(
    *,
    settings: DashboardSettings,
    manifest: RunManifest | None,
    mode: str,
    paths: _DashboardPaths,
    sources: _DashboardSources,
    derived: _DashboardDerived,
) -> dict[str, Any]:
    return {
        "schema": "ravage.live_dashboard.v1",
        "mode": mode,
        "manifest": _manifest_json(manifest),
        "paths": _dashboard_path_payload(settings=settings, paths=paths),
        "exists": _dashboard_exists_payload(settings=settings, paths=paths),
        "metrics": derived.metrics,
        "viewer": _mask_sensitive(derived.viewer),
        "selection": derived.selection,
        "warnings": _warnings(derived.metrics, derived.selection),
        "lab": sources.lab,
        "working_state": _mask_sensitive(sources.working_state),
        "events": _masked_items(sources.events),
        "transcript": _masked_items(sources.transcript),
        "audit_rows": _masked_items(sources.audit_rows),
        "activity": _masked_items(derived.activity),
        "stage_flow": derived.stage_flow,
        "kill_chain_breakdown": derived.kill_chain,
        "agents": _agents(sources.audit_rows),
        "terminal_sessions": sources.terminal,
        "docker": sources.docker,
        "findings": _masked_items(sources.findings),
        "flags": _dashboard_flags_payload(derived.flags),
        "charts": _dashboard_charts_payload(sources),
        "stdout": _masked_lines(sources.stdout_lines),
        "docker_log": _masked_lines(sources.docker_log_lines),
    }


def _manifest_json(manifest: RunManifest | None) -> dict[str, Any] | None:
    if manifest is None:
        return None
    return manifest.to_json()


def _dashboard_path_payload(
    *,
    settings: DashboardSettings,
    paths: _DashboardPaths,
) -> dict[str, Any]:
    return {
        "workspace_dir": str(paths.workspace_dir),
        "events": str(paths.events_path),
        "transcript": str(paths.transcript_path),
        "working_state": str(paths.working_state_path),
        "db": _optional_path_text(settings.db_path),
        "stdout": _optional_path_text(settings.stdout_path),
        "docker_log": _optional_path_text(paths.docker_log_path),
        "lab_manifest": _optional_path_text(settings.lab_manifest_path),
    }


def _dashboard_exists_payload(
    *,
    settings: DashboardSettings,
    paths: _DashboardPaths,
) -> dict[str, Any]:
    return {
        "workspace": paths.workspace_dir.exists(),
        "events": paths.events_path.exists(),
        "transcript": paths.transcript_path.exists(),
        "working_state": paths.working_state_path.exists(),
        "terminal": paths.terminal_dir.exists(),
        "audit_db": _optional_path_exists(settings.db_path),
        "stdout": _optional_path_exists(settings.stdout_path),
        "docker_log": _optional_path_exists(paths.docker_log_path),
        "lab_manifest": _optional_path_exists(settings.lab_manifest_path),
    }


def _optional_path_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return str(path)


def _optional_path_exists(path: Path | None) -> bool:
    if path is None:
        return False
    return path.exists()


def _masked_items(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    masked: list[dict[str, Any]] = []
    for value in values:
        masked.append(_object_dict(_mask_sensitive(value)))
    return masked


def _dashboard_flags_payload(flags: list[str]) -> dict[str, Any]:
    return {
        "count": len(flags),
        "masked": _masked_lines(flags),
    }


def _dashboard_charts_payload(sources: _DashboardSources) -> dict[str, Any]:
    return {
        "work": _work_chart(sources.events, sources.audit_rows),
    }


def _masked_lines(lines: list[str]) -> list[str]:
    masked: list[str] = []
    for line in lines:
        masked.append(_mask_flag(line))
    return masked


def serve_dashboard(
    settings: DashboardSettings,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> None:
    cockpit = start_cockpit(settings, host=host, port=port)
    sys.stdout.write(f"ravage cockpit listening on {cockpit.url}\n")
    sys.stdout.flush()
    try:
        cockpit.wait_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\nstopping ravage cockpit\n")
        sys.stdout.flush()
    finally:
        cockpit.shutdown()


@dataclass
class CockpitServer:
    """A running cockpit HTTP server the runner can keep alive and shut down."""

    server: ThreadingHTTPServer
    thread: threading.Thread
    url: str
    stop_event: threading.Event

    def wait_forever(self) -> None:
        while not self.stop_event.wait(0.5):
            pass

    def shutdown(self) -> None:
        self.stop_event.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_cockpit(
    settings: DashboardSettings,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> CockpitServer:
    handler = _handler(settings)
    server = ThreadingHTTPServer((host, port), handler)
    stop_event = threading.Event()
    thread = threading.Thread(
        target=server.serve_forever, name="ravage-cockpit", daemon=True
    )
    thread.start()
    if settings.run_root is not None:
        reaper = threading.Thread(
            target=_ttl_reaper,
            args=(settings.run_root, stop_event),
            name="ravage-cockpit-reaper",
            daemon=True,
        )
        reaper.start()
    return CockpitServer(
        server=server, thread=thread, url=f"http://{host}:{port}", stop_event=stop_event
    )


def _ttl_reaper(run_root: Path, stop_event: threading.Event) -> None:
    while not stop_event.wait(10):
        for path in run_root.glob(f"*/{MANIFEST_NAME}"):
            manifest = read_manifest(path.parent)
            if manifest is None or not manifest.keep_target or not manifest.target_alive:
                continue
            if manifest.status == STATUS_TORN_DOWN:
                continue
            anchor = manifest.finished_at or manifest.updated_at
            if _age_seconds(anchor) <= manifest.ttl_seconds:
                continue
            _teardown_docker_project(manifest.docker_project)
            update_manifest(
                path.parent,
                status=STATUS_TORN_DOWN,
                target_alive=False,
                teardown_at=datetime.now(UTC).isoformat(),
            )


def _age_seconds(iso_timestamp: str) -> float:
    if not iso_timestamp:
        return 0.0
    try:
        moment = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return (datetime.now(UTC) - moment).total_seconds()


def _teardown_docker_project(project: str) -> int:
    """Force-remove all containers belonging to a compose project. Returns count."""
    if not project:
        return 0
    try:
        listing = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    container_ids = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    if not container_ids:
        return 0
    try:
        subprocess.run(  # noqa: S603
            ["docker", "rm", "-f", *container_ids],  # noqa: S607
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    return len(container_ids)


def teardown_active_run(settings: DashboardSettings, run_id: str = "") -> dict[str, Any]:
    """Tear down the target for a run and flip its manifest into replay."""
    resolved, manifest = _resolve_active(settings)
    if manifest is None:
        return {"ok": False, "error": "no active run to tear down"}
    if run_id and manifest.run_id != run_id:
        return {"ok": False, "error": f"run {run_id} is not the active run"}
    removed = _teardown_docker_project(manifest.docker_project)
    workspace_dir = resolved.workspace_dir
    run_dir = workspace_dir.parent if workspace_dir.name == "workspace" else workspace_dir
    update_manifest(
        run_dir,
        status=STATUS_TORN_DOWN,
        target_alive=False,
        teardown_at=datetime.now(UTC).isoformat(),
    )
    return {"ok": True, "removed": removed, "run_id": manifest.run_id}


def settings_from_run_dir(
    run_dir: Path,
    *,
    lab_manifest_path: Path | None = None,
) -> DashboardSettings:
    workspace_dir = run_dir / "workspace" if (run_dir / "workspace").exists() else run_dir
    db_path = _first_existing(run_dir / "audit.db", workspace_dir / "audit.db")
    stdout_path = _first_existing(
        run_dir / "stdout.log",
        run_dir / "agent.stdout",
        run_dir / "scan.stdout",
    )
    docker_log_path = _first_existing(run_dir / "docker.log", workspace_dir / "docker.log")
    return DashboardSettings(
        workspace_dir=workspace_dir,
        db_path=db_path,
        stdout_path=stdout_path,
        docker_log_path=docker_log_path,
        lab_manifest_path=lab_manifest_path,
    )


def _derived_docker_log_path(settings: DashboardSettings) -> Path | None:
    for anchor in (settings.stdout_path, settings.db_path):
        if anchor is None:
            continue
        candidate = anchor.parent / "docker.log"
        if candidate.exists():
            return candidate
    return None


def _docker_runtime_state(
    *,
    settings: DashboardSettings,
    lab: dict[str, Any],
    docker_log_lines: list[str],
) -> dict[str, Any]:
    project_hint = _docker_project_hint(settings=settings, lab=lab)
    containers = _docker_containers(project_hint)
    return {
        "operator_only": True,
        "project_hint": project_hint,
        "available": bool(containers or docker_log_lines),
        "containers": containers,
        "logs": docker_log_lines,
    }


def _docker_project_hint(*, settings: DashboardSettings, lab: dict[str, Any]) -> str | None:
    case_dir = (
        settings.workspace_dir.parent
        if settings.workspace_dir.name == "workspace"
        else settings.workspace_dir
    )
    benchmark_id = case_dir.name if case_dir.name.startswith("XBEN-") else ""
    if benchmark_id:
        run_slug = _docker_project_slug(case_dir.parent.name)
        if run_slug:
            return f"ravage-{benchmark_id.lower()}-{run_slug}-"
        return f"ravage-{benchmark_id.lower()}-"
    lab_id = str(lab.get("id") or "").strip()
    if lab_id:
        return lab_id
    return None


def _docker_project_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()


_DOCKER_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_DOCKER_REFRESHING: set[str] = set()
_DOCKER_LOCK = threading.Lock()
_DOCKER_CACHE_TTL_SECONDS = 4.0


def _docker_containers(project_hint: str | None) -> list[dict[str, Any]]:
    if not project_hint:
        return []
    now = time.monotonic()
    with _DOCKER_LOCK:
        cached = _DOCKER_CACHE.get(project_hint)
        fresh = cached is not None and now - cached[0] < _DOCKER_CACHE_TTL_SECONDS
        if not fresh and project_hint not in _DOCKER_REFRESHING:
            _DOCKER_REFRESHING.add(project_hint)
            threading.Thread(
                target=_refresh_docker_cache,
                args=(project_hint,),
                name="ravage-cockpit-docker",
                daemon=True,
            ).start()
        return cached[1] if cached is not None else []


def _refresh_docker_cache(project_hint: str) -> None:
    try:
        containers = _query_docker_containers(project_hint)
        with _DOCKER_LOCK:
            _DOCKER_CACHE[project_hint] = (time.monotonic(), containers)
    finally:
        with _DOCKER_LOCK:
            _DOCKER_REFRESHING.discard(project_hint)


def _query_docker_containers(project_hint: str) -> list[dict[str, Any]]:
    result = _run_docker_json_lines(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            f"name={project_hint}",
            "--format",
            "{{json .}}",
        ],
        timeout=2,
    )
    containers: list[dict[str, Any]] = []
    for row in result:
        container_id = str(row.get("ID") or "").strip()
        name = str(row.get("Names") or row.get("Name") or "").strip()
        container = {
            "id": container_id,
            "name": name,
            "image": str(row.get("Image") or ""),
            "status": str(row.get("Status") or ""),
            "state": str(row.get("State") or ""),
            "ports": str(row.get("Ports") or ""),
            "logs": _docker_container_logs(container_id or name),
        }
        containers.append(_object_dict(_mask_sensitive(container)))
    return containers[:12]


def _docker_container_logs(container: str) -> list[str]:
    if not container:
        return []
    try:
        result = subprocess.run(  # noqa: S603
            ["docker", "logs", "--tail", "40", container],  # noqa: S607
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    lines = ((result.stdout or "") + (result.stderr or "")).splitlines()
    return [_mask_flag(line) for line in lines[-40:]]


def _run_docker_json_lines(command: list[str], *, timeout: int) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(  # noqa: S603
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(_object_dict(value))
    return rows


_RUN_TEARDOWN_RE = re.compile(r"/api/run/(?P<run_id>[^/]*)/teardown")


def _handler(settings: DashboardSettings) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def handle(self) -> None:
            try:
                super().handle()
            except ConnectionResetError:
                return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            self._route_get(path)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            run_id = _teardown_run_id(path)
            if run_id is not None:
                self._send_json(teardown_active_run(settings, run_id))
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

        def _route_get(self, path: str) -> None:
            if path == "/api/state":
                self._send_json(build_dashboard_state(settings))
                return
            if path == "/api/events/stream":
                self._send_state_stream()
                return
            if path == "/assets/ravage_logo.png":
                self._send_file(REPO_ASSETS_DIR / "ravage_logo.png")
                return
            self._send_frontend_file(path)

        def _send_json(self, payload: Mapping[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            self._send_body(body, status=HTTPStatus.OK, content_type="application/json")

        def _send_state_stream(self) -> None:
            self._send_stream_headers()
            cursor = _StreamCursor()
            while True:
                try:
                    self._write_state_stream_tick(cursor)
                    time.sleep(1.0)
                except (BrokenPipeError, ConnectionResetError):
                    return

        def _send_stream_headers(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

        def _write_state_stream_tick(self, cursor: _StreamCursor) -> None:
            state = build_dashboard_state(settings)
            for event_name, data in cursor.deltas(state):
                self._write_sse(event_name, data)
            self.wfile.write(b": keepalive\n\n")
            self.wfile.flush()

        def _write_sse(self, event_name: str, data: object) -> None:
            body = json.dumps(data, sort_keys=True, default=str)
            self.wfile.write(f"event: {event_name}\ndata: {body}\n\n".encode())

        def _send_frontend_file(self, request_path: str) -> None:
            path = _frontend_request_path(request_path)
            resolved = _safe_static_path(FRONTEND_DIR, path)
            if resolved is not None and _static_file_available(resolved):
                self._send_file(resolved)
                return
            if path != "/index.html":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._send_missing_frontend()

        def _send_file(self, path: Path) -> None:
            if not path.exists() or not path.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            body = path.read_bytes()
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self._send_body(body, status=HTTPStatus.OK, content_type=content_type)

        def _send_missing_frontend(self) -> None:
            body = _missing_frontend_body()
            self._send_body(
                body,
                status=HTTPStatus.SERVICE_UNAVAILABLE,
                content_type="text/plain; charset=utf-8",
            )

        def _send_body(
            self,
            body: bytes,
            *,
            status: HTTPStatus,
            content_type: str,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def _teardown_run_id(path: str) -> str | None:
    if path == "/api/teardown":
        return ""
    match = _RUN_TEARDOWN_RE.fullmatch(path)
    if match is None:
        return None
    return unquote(match.group("run_id"))


def _frontend_request_path(request_path: str) -> str:
    if request_path in {"", "/"}:
        return "/index.html"
    return request_path


def _static_file_available(path: Path) -> bool:
    return path.exists() and path.is_file()


def _missing_frontend_body() -> bytes:
    message = (
        "Ravage cockpit frontend is missing. Expected files under "
        f"{FRONTEND_DIR}."
    )
    return message.encode()


def _safe_static_path(root: Path, request_path: str) -> Path | None:
    relative = unquote(request_path).lstrip("/")
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    if candidate == root_resolved or root_resolved in candidate.parents:
        return candidate
    return None


def _read_jsonl(path: Path, *, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            rows.append({"malformed": stripped[:500]})
            continue
        if isinstance(value, dict):
            rows.append(_object_dict(value))
        else:
            rows.append({"value": value})
    return rows


def _read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"error": "malformed json", "path": str(path)}
    if isinstance(value, dict):
        return _object_dict(value)
    return {"value": value}


def _read_audit_rows(db_path: Path | None, *, limit: int) -> list[dict[str, Any]]:
    if not db_path or not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, timestamp, engagement_id, actor, action, payload_json, cost_usd
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    parsed: list[dict[str, Any]] = []
    for row_id, timestamp, engagement_id, actor, action, payload_json, cost_usd in reversed(rows):
        parsed.append(
            {
                "id": row_id,
                "timestamp": timestamp,
                "engagement_id": engagement_id,
                "actor": actor,
                "action": action,
                "payload": _loads_object(payload_json),
                "cost_usd": cost_usd,
            }
        )
    return parsed


def _read_findings(db_path: Path | None) -> list[dict[str, Any]]:
    if not db_path or not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT finding_id, engagement_id, vuln_class, status, validator_vote, payload_json
            FROM findings
            ORDER BY finding_id
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    findings: list[dict[str, Any]] = []
    for finding_id, engagement_id, vuln_class, status, validator_vote, payload_json in rows:
        payload = _loads_object(payload_json)
        finding = dict(payload) if isinstance(payload, dict) else {"payload": payload}
        finding.update(
            {
                "finding_id": finding_id,
                "engagement_id": engagement_id,
                "vuln_class": vuln_class,
                "status": status,
                "validator_vote": validator_vote,
            }
        )
        findings.append(finding)
    return findings


def _read_terminal_sessions(path: Path, *, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    sessions: list[dict[str, Any]] = []
    for session_path in sorted(path.glob("*.jsonl")):
        events = _read_jsonl(session_path, limit=limit)
        sessions.append(
            {
                "name": session_path.stem,
                "path": str(session_path),
                "events": [_mask_sensitive(event) for event in events],
                "last": _mask_sensitive(events[-1]) if events else {},
            }
        )
    return sessions


def _read_lab_manifest(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return {"error": str(exc), "path": str(path)}
    if not isinstance(data, dict):
        return {"value": data, "path": str(path)}
    lab = dict(data)
    lab["path"] = str(path)
    if "tags" in lab and "content" in lab:
        lab.pop("tags", None)
    compose = _read_compose_summary(path, _manifest_compose_value(path, lab))
    if compose:
        lab["compose"] = compose
    return _object_dict(_mask_sensitive(lab))


def _manifest_compose_value(path: Path, lab: dict[str, Any]) -> object:
    compose_value = lab.get("compose_file")
    if isinstance(compose_value, str) and compose_value.strip():
        return compose_value
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        if (path.parent / name).exists():
            return name
    return compose_value


def _read_compose_summary(manifest_path: Path, compose_value: object) -> dict[str, Any]:
    if not isinstance(compose_value, str) or not compose_value.strip():
        return {}
    compose_path = manifest_path.parent / compose_value
    if not compose_path.exists():
        return {"path": str(compose_path), "exists": False, "services": []}
    try:
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return {"path": str(compose_path), "exists": True, "error": str(exc), "services": []}
    services = compose.get("services") if isinstance(compose, dict) else {}
    summary: list[dict[str, Any]] = []
    if isinstance(services, dict):
        for name, raw_config in services.items():
            config = raw_config if isinstance(raw_config, dict) else {}
            summary.append(
                {
                    "name": str(name),
                    "image": config.get("image"),
                    "build": config.get("build"),
                    "ports": config.get("ports", []),
                    "depends_on": config.get("depends_on", []),
                    "environment": _environment_keys(config.get("environment")),
                }
            )
    return {"path": str(compose_path), "exists": True, "services": summary}


def _environment_keys(value: object) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value)
    if isinstance(value, list):
        return sorted(str(item).split("=", 1)[0] for item in value)
    return []


def _tail_lines(path: Path | None, *, limit: int) -> list[str]:
    if not path or not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None
