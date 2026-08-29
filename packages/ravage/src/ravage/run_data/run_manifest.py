from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

MANIFEST_NAME = "run.json"
STATUS_CREATED = "created"
STATUS_STARTING_TARGET = "starting_target"
STATUS_AGENT_RUNNING = "agent_running"
STATUS_FINISHED = "finished"
STATUS_TORN_DOWN = "torn_down"

_ACTIVE_STATUSES = frozenset(
    {STATUS_CREATED, STATUS_STARTING_TARGET, STATUS_AGENT_RUNNING}
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class RunManifest:
    run_id: str
    benchmark_id: str = ""
    lab_id: str = ""
    status: str = STATUS_CREATED
    phase: str = STATUS_CREATED
    target_url: str = ""
    docker_project: str = ""
    keep_target: bool = False
    ttl_seconds: int = 1800
    target_alive: bool = False
    max_turns: int = 0
    workspace_dir: str = ""
    db_path: str = ""
    docker_log_path: str = ""
    stdout_path: str = ""
    lab_manifest_path: str = ""
    result_label: str = ""
    flag_found: bool = False
    created_at: str = field(default_factory=_now)
    target_ready_at: str = ""
    finished_at: str = ""
    teardown_at: str = ""
    updated_at: str = field(default_factory=_now)

    @property
    def is_active(self) -> bool:
        return self.status in _ACTIVE_STATUSES

    @property
    def mode(self) -> str:
        if self.status == STATUS_TORN_DOWN:
            return "replay"
        if self.status == STATUS_FINISHED and not self.target_alive:
            return "replay"
        return "live"

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mode"] = self.mode
        payload["is_active"] = self.is_active
        return payload

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RunManifest:
        known = {f.name for f in fields(cls)}
        kwargs = {key: value for key, value in data.items() if key in known}
        return cls(**kwargs)


def manifest_path(run_dir: Path) -> Path:
    return run_dir / MANIFEST_NAME


def write_manifest(run_dir: Path, manifest: RunManifest) -> RunManifest:
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest.updated_at = _now()
    path = manifest_path(run_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(manifest.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
    return manifest


def read_manifest(run_dir: Path) -> RunManifest | None:
    path = manifest_path(run_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return RunManifest.from_json(data)
    except TypeError:
        return None


def update_manifest(run_dir: Path, **changes: object) -> RunManifest:
    manifest = read_manifest(run_dir) or RunManifest(run_id=run_dir.name)
    for key, value in changes.items():
        if hasattr(manifest, key):
            setattr(manifest, key, value)
    return write_manifest(run_dir, manifest)


def find_active_run_dir(run_root: Path) -> Path | None:
    candidates: list[tuple[bool, str, Path]] = []
    for path in sorted(run_root.glob(f"*/{MANIFEST_NAME}")):
        manifest = read_manifest(path.parent)
        if manifest is None:
            continue
        candidates.append((manifest.is_active, manifest.updated_at, path.parent))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]
