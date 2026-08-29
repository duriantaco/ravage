"""Disposable candidate workspaces and hardened offline job specifications."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# These messages are the public fail-closed operator diagnostics for the lab.
# ruff: noqa: C901, EM101, EM102, PLR0913, S108, TRY003, TRY301

_COMMIT_RE: Final = re.compile(r"[0-9a-f]{40,64}")
_IMAGE_RE: Final = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
_NAME_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_MAX_PATCH_BYTES = 10 * 1024 * 1024
_MAX_MARKER_BYTES = 4096
_MAX_VIEW_BYTES = 128 * 1024 * 1024
_WORKSPACE_MARKER_SCHEMA_VERSION = 2
_INDEX_STAGE_FIELD_COUNT = 3
_MIN_TAGGED_INDEX_RECORD_BYTES = 3


class CandidateWorkspaceError(RuntimeError):
    """Raised when candidate isolation cannot preserve the source checkout."""


@dataclass(frozen=True)
class GitSourceState:
    root: Path
    head_commit: str
    tree_digest: str
    status_digest: str
    dirty_entries: int

    @property
    def clean(self) -> bool:
        return self.dirty_entries == 0


@dataclass(frozen=True)
class CandidateWorkspace:
    candidate_id: str
    path: Path
    base_commit: str
    patch_sha256: str
    candidate_tree_digest: str
    candidate_content_digest: str
    source_state: GitSourceState


@dataclass(frozen=True)
class OfflineContainerJob:
    """A networkless container command for deterministic candidate checks."""

    argv: tuple[str, ...]
    image: str
    candidate_workspace: Path
    episodes_root: Path
    trusted_tests_root: Path
    output_root: Path
    candidate_id: str
    candidate_tree_digest: str
    candidate_content_digest: str
    trusted_tests_digest: str

    def to_json(self) -> dict[str, object]:
        # Paths are operator-side job metadata and must not be given to the
        # candidate as an experience capsule.
        return {
            "schema_version": _WORKSPACE_MARKER_SCHEMA_VERSION,
            "execution_kind": "offline_candidate_container",
            "network": "none",
            "image": self.image,
            "candidate_workspace": str(self.candidate_workspace),
            "episodes_root": str(self.episodes_root),
            "trusted_tests_root": str(self.trusted_tests_root),
            "output_root": str(self.output_root),
            "candidate_id": self.candidate_id,
            "candidate_tree_digest": self.candidate_tree_digest,
            "candidate_content_digest": self.candidate_content_digest,
            "trusted_tests_digest": self.trusted_tests_digest,
            "argv": list(self.argv),
        }


def capture_source_state(source_root: Path) -> GitSourceState:
    """Capture content state without writing Git refs, the index, or worktree."""
    requested = _real_directory(source_root, label="source checkout")
    top_level = Path(_git(requested, "rev-parse", "--show-toplevel").strip()).resolve()
    if top_level != requested:
        raise CandidateWorkspaceError("source path must be the Git repository root")
    head = _git(requested, "rev-parse", "--verify", "HEAD").strip().lower()
    tree = _git(requested, "rev-parse", "--verify", "HEAD^{tree}").strip().lower()
    if _COMMIT_RE.fullmatch(head) is None or _COMMIT_RE.fullmatch(tree) is None:
        raise CandidateWorkspaceError("source checkout returned an invalid Git identity")
    _reject_hidden_index_entries(requested)
    status = _git_bytes(
        requested,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "-z",
    )
    entries = sum(bool(item) for item in status.split(b"\0"))
    return GitSourceState(
        root=requested,
        head_commit=head,
        tree_digest=tree,
        status_digest=hashlib.sha256(status).hexdigest(),
        dirty_entries=entries,
    )


def require_clean_champion(
    source_root: Path,
    *,
    expected_commit: str | None = None,
) -> GitSourceState:
    state = capture_source_state(source_root)
    if not state.clean:
        raise CandidateWorkspaceError(
            "champion checkout is dirty; commit or separately snapshot the reviewed baseline first"
        )
    if expected_commit is not None:
        resolved = _resolve_commit(state.root, expected_commit)
        if resolved != state.head_commit:
            raise CandidateWorkspaceError("expected champion commit is not the checkout HEAD")
    return state


def materialize_candidate(
    *,
    source_root: Path,
    lab_root: Path,
    candidate_id: str,
    base_commit: str,
    patch: bytes,
) -> CandidateWorkspace:
    """Create and patch an independent clone, then prove source state is unchanged."""
    if _NAME_RE.fullmatch(candidate_id) is None:
        raise CandidateWorkspaceError("candidate ID contains unsupported characters")
    if not isinstance(patch, bytes) or len(patch) > _MAX_PATCH_BYTES or b"\0" in patch:
        raise CandidateWorkspaceError("candidate patch is invalid or exceeds the byte cap")

    before = require_clean_champion(source_root, expected_commit=base_commit)
    resolved_commit = _resolve_commit(before.root, base_commit)
    prospective_lab = lab_root.expanduser().resolve(strict=False)
    if _paths_overlap(before.root, prospective_lab):
        raise CandidateWorkspaceError("lab root and source checkout must be disjoint")
    root = _owned_directory(lab_root)
    workspaces = _owned_directory(root / "workspaces")
    destination = workspaces / candidate_id
    if destination.exists() or destination.is_symlink():
        raise CandidateWorkspaceError("candidate workspace already exists")

    try:
        _run(
            (
                "git",
                "clone",
                "--no-local",
                "--no-checkout",
                "--",
                str(before.root),
                str(destination),
            ),
            cwd=workspaces,
        )
        _git(destination, "checkout", "--detach", resolved_commit)
        _git(destination, "remote", "remove", "origin")
        if patch:
            _git_bytes_input(
                destination,
                patch,
                "apply",
                "--check",
                "--whitespace=error-all",
                "-",
            )
            _git_bytes_input(
                destination,
                patch,
                "apply",
                "--index",
                "--whitespace=error-all",
                "-",
            )
        candidate_tree = _git(destination, "write-tree").strip().lower()
        if _COMMIT_RE.fullmatch(candidate_tree) is None:
            raise CandidateWorkspaceError("candidate tree identity is invalid")
        marker = destination / ".improvement-candidate.json"
        if marker.exists() or marker.is_symlink():
            raise CandidateWorkspaceError("candidate patch may not create the reserved marker path")
        candidate_content = _tracked_worktree_digest(destination)
        identity = {
            "schema_version": _WORKSPACE_MARKER_SCHEMA_VERSION,
            "candidate_id": candidate_id,
            "base_commit": resolved_commit,
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "candidate_tree_digest": candidate_tree,
            "candidate_content_digest": candidate_content,
        }
        _write_reserved_marker(marker, identity)
        after = capture_source_state(before.root)
        if after != before:
            raise CandidateWorkspaceError(
                "source checkout changed during candidate materialization"
            )
    except Exception:
        _remove_new_workspace(destination, allowed_parent=workspaces)
        raise

    return CandidateWorkspace(
        candidate_id=candidate_id,
        path=destination.resolve(),
        base_commit=resolved_commit,
        patch_sha256=hashlib.sha256(patch).hexdigest(),
        candidate_tree_digest=candidate_tree,
        candidate_content_digest=candidate_content,
        source_state=before,
    )


def build_offline_container_job(
    *,
    image: str,
    candidate: CandidateWorkspace,
    episodes_root: Path,
    trusted_tests_root: Path,
    expected_trusted_tests_digest: str,
    output_root: Path,
    command: tuple[str, ...],
    name: str = "ravage-improvement-check",
) -> OfflineContainerJob:
    """Build a pinned, networkless Docker command without executing it."""
    if _IMAGE_RE.fullmatch(image) is None:
        raise CandidateWorkspaceError("candidate image must be pinned by sha256 digest")
    if _NAME_RE.fullmatch(name) is None:
        raise CandidateWorkspaceError("container name contains unsupported characters")
    if not command or any(not item or "\0" in item for item in command):
        raise CandidateWorkspaceError("offline job command is invalid")
    workspace = _real_directory(candidate.path, label="candidate workspace")
    episodes = _real_directory(episodes_root, label="episode directory")
    trusted_tests = _real_directory(trusted_tests_root, label="trusted test directory")
    output_candidate = output_root.expanduser().resolve(strict=False)
    _require_disjoint_roots(
        {
            "candidate workspace": workspace,
            "episode directory": episodes,
            "trusted test directory": trusted_tests,
            "job output": output_candidate,
        }
    )
    _verify_candidate_marker(workspace, expected=candidate)
    _verify_candidate_view(episodes)
    trusted_tests_digest = directory_tree_digest(trusted_tests)
    if trusted_tests_digest != expected_trusted_tests_digest:
        raise CandidateWorkspaceError("trusted test tree differs from the campaign suite")
    output = _owned_empty_directory(output_root)
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        uid = 65532
    if gid == 0:
        gid = 65532
    argv = (
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--user",
        f"{uid}:{gid}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=512m",
        "--mount",
        f"type=bind,src={workspace},dst=/candidate,readonly",
        "--mount",
        f"type=bind,src={episodes},dst=/episodes,readonly",
        "--mount",
        f"type=bind,src={trusted_tests},dst=/trusted-tests,readonly",
        "--mount",
        f"type=bind,src={output},dst=/out",
        "--workdir",
        "/candidate",
        image,
        *command,
    )
    return OfflineContainerJob(
        argv=argv,
        image=image,
        candidate_workspace=workspace,
        episodes_root=episodes,
        trusted_tests_root=trusted_tests,
        output_root=output,
        candidate_id=candidate.candidate_id,
        candidate_tree_digest=candidate.candidate_tree_digest,
        candidate_content_digest=candidate.candidate_content_digest,
        trusted_tests_digest=trusted_tests_digest,
    )


def _resolve_commit(root: Path, value: str) -> str:
    if not value or value.startswith("-"):
        raise CandidateWorkspaceError("champion commit is invalid")
    resolved = _git(root, "rev-parse", "--verify", f"{value}^{{commit}}").strip().lower()
    if _COMMIT_RE.fullmatch(resolved) is None:
        raise CandidateWorkspaceError("champion commit did not resolve to a commit object")
    return resolved


def _git(root: Path, *args: str) -> str:
    completed = _run(("git", "-C", str(root), *args), cwd=root)
    return completed.stdout.decode("utf-8", errors="strict")


def _git_bytes(root: Path, *args: str) -> bytes:
    return _run(("git", "-C", str(root), *args), cwd=root).stdout


def _git_bytes_input(root: Path, content: bytes, *args: str) -> bytes:
    return _run(("git", "-C", str(root), *args), cwd=root, input_bytes=content).stdout


def _reject_hidden_index_entries(root: Path) -> None:
    """Reject index hints that can make status/diff omit changed worktree bytes."""
    records = _git_bytes(root, "ls-files", "-v", "-z").split(b"\0")
    for record in records:
        if not record:
            continue
        if len(record) < _MIN_TAGGED_INDEX_RECORD_BYTES or record[:2] != b"H ":
            raise CandidateWorkspaceError(
                "Git index contains hidden, skipped, or unresolved tracked entries"
            )


def _tracked_worktree_digest(root: Path) -> str:
    """Hash the exact mounted bytes for every stage-zero tracked path."""
    _reject_hidden_index_entries(root)
    records: list[dict[str, object]] = []
    total_bytes = 0
    raw_entries = _git_bytes(root, "ls-files", "--stage", "-z").split(b"\0")
    for raw_entry in raw_entries:
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        parts = metadata.split(b" ")
        if separator != b"\t" or len(parts) != _INDEX_STAGE_FIELD_COUNT or parts[2] != b"0":
            raise CandidateWorkspaceError("candidate index contains an unresolved entry")
        try:
            index_mode = parts[0].decode("ascii")
            index_object = parts[1].decode("ascii").lower()
            relative = raw_path.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise CandidateWorkspaceError("candidate index contains a non-UTF-8 path") from exc
        relative_path = Path(relative)
        if (
            index_mode not in {"100644", "100755"}
            or _COMMIT_RE.fullmatch(index_object) is None
            or not relative
            or relative_path.is_absolute()
            or any(part in {"", ".", ".."} for part in relative_path.parts)
        ):
            raise CandidateWorkspaceError("candidate index entry is unsupported")
        path = root / relative_path
        try:
            item_stat = path.lstat()
            resolved = path.resolve(strict=True)
            if (
                not resolved.is_relative_to(root)
                or not stat.S_ISREG(item_stat.st_mode)
                or item_stat.st_nlink != 1
            ):
                raise CandidateWorkspaceError("candidate tracked path is not an isolated file")
            executable = bool(stat.S_IMODE(item_stat.st_mode) & 0o111)
            if executable != (index_mode == "100755"):
                raise CandidateWorkspaceError("candidate tracked file mode differs from its index")
            content = path.read_bytes()
        except OSError as exc:
            raise CandidateWorkspaceError("candidate tracked content is unreadable") from exc
        total_bytes += len(content)
        if total_bytes > _MAX_VIEW_BYTES:
            raise CandidateWorkspaceError("candidate tracked content exceeds the byte cap")
        records.append(
            {
                "path": relative,
                "index_mode": index_mode,
                "index_object": index_object,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _run(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        return subprocess.run(  # noqa: S603 - argv is an explicit sequence, never a shell.
            argv,
            cwd=cwd,
            env=environment,
            input=input_bytes,
            capture_output=True,
            timeout=120,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise CandidateWorkspaceError("candidate Git operation failed") from exc


def _real_directory(path: Path, *, label: str) -> Path:
    candidate = path.expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise CandidateWorkspaceError(f"{label} must be a real directory")
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise CandidateWorkspaceError(f"cannot inspect {label}") from exc


def _owned_directory(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise CandidateWorkspaceError("lab path must not be a symlink")
    candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = candidate.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise CandidateWorkspaceError("lab path must be a real directory")
    resolved.chmod(0o700)
    return resolved


def _owned_empty_directory(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.exists() or candidate.is_symlink():
        raise CandidateWorkspaceError("job output must be a fresh directory")
    candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if candidate.parent.is_symlink():
        raise CandidateWorkspaceError("job output parent must not be a symlink")
    try:
        candidate.mkdir(mode=0o700)
    except OSError as exc:
        raise CandidateWorkspaceError("cannot create fresh job output directory") from exc
    resolved = candidate.resolve(strict=True)
    resolved.chmod(0o700)
    return resolved


def _write_reserved_marker(path: Path, identity: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise CandidateWorkspaceError("candidate patch may not create the reserved marker path")
    encoded = (json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise CandidateWorkspaceError("cannot create reserved candidate marker") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_candidate_marker(
    workspace: Path,
    *,
    expected: CandidateWorkspace,
) -> dict[str, object]:
    marker = workspace / ".improvement-candidate.json"
    try:
        marker_stat = marker.lstat()
        if (
            marker.is_symlink()
            or not stat.S_ISREG(marker_stat.st_mode)
            or marker_stat.st_nlink != 1
        ):
            raise CandidateWorkspaceError(
                "candidate workspace marker is not a regular private file"
            )
        if marker_stat.st_size > _MAX_MARKER_BYTES:
            raise CandidateWorkspaceError("candidate workspace marker exceeds the byte cap")
        payload = _decode_canonical_json_object(marker.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CandidateWorkspaceError("candidate workspace marker is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "candidate_id",
        "base_commit",
        "patch_sha256",
        "candidate_tree_digest",
        "candidate_content_digest",
    }:
        raise CandidateWorkspaceError("candidate workspace marker is malformed")
    if (
        payload.get("schema_version") != _WORKSPACE_MARKER_SCHEMA_VERSION
        or _NAME_RE.fullmatch(str(payload.get("candidate_id") or "")) is None
        or _COMMIT_RE.fullmatch(str(payload.get("base_commit") or "")) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(payload.get("patch_sha256") or "")) is None
        or _COMMIT_RE.fullmatch(str(payload.get("candidate_tree_digest") or "")) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(payload.get("candidate_content_digest") or ""))
        is None
    ):
        raise CandidateWorkspaceError("candidate workspace marker identity is invalid")
    expected_identity = {
        "schema_version": _WORKSPACE_MARKER_SCHEMA_VERSION,
        "candidate_id": expected.candidate_id,
        "base_commit": expected.base_commit,
        "patch_sha256": expected.patch_sha256,
        "candidate_tree_digest": expected.candidate_tree_digest,
        "candidate_content_digest": expected.candidate_content_digest,
    }
    if payload != expected_identity:
        raise CandidateWorkspaceError(
            "candidate workspace marker differs from archive materialization"
        )
    if _git(workspace, "rev-parse", "--verify", "HEAD").strip().lower() != expected.base_commit:
        raise CandidateWorkspaceError("candidate workspace HEAD differs from its archived base")
    _reject_hidden_index_entries(workspace)
    if _git(workspace, "write-tree").strip().lower() != expected.candidate_tree_digest:
        raise CandidateWorkspaceError(
            "candidate workspace index tree changed after materialization"
        )
    if _git_bytes(workspace, "diff", "--name-only"):
        raise CandidateWorkspaceError("candidate workspace has unstaged changes")
    if _tracked_worktree_digest(workspace) != expected.candidate_content_digest:
        raise CandidateWorkspaceError("candidate workspace content changed after materialization")
    untracked = {
        item.decode("utf-8", errors="strict")
        for item in _git_bytes(
            workspace,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ).split(b"\0")
        if item
    }
    if untracked != {".improvement-candidate.json"}:
        raise CandidateWorkspaceError("candidate workspace contains unexpected untracked files")
    return {str(key): value for key, value in payload.items()}


def directory_tree_digest(root: Path) -> str:
    """Hash a bounded, symlink-free evaluator tree by path, mode, size, and content."""
    directory = _real_directory(root, label="tree digest directory")
    records: list[dict[str, object]] = []
    total_bytes = 0
    try:
        paths = sorted(
            directory.rglob("*"),
            key=lambda item: item.relative_to(directory).as_posix(),
        )
        for path in paths:
            relative = path.relative_to(directory).as_posix()
            item_stat = path.lstat()
            if path.is_symlink():
                raise CandidateWorkspaceError("tree digest input must not contain symlinks")
            if path.is_dir():
                records.append({"path": relative, "kind": "directory"})
                continue
            if not stat.S_ISREG(item_stat.st_mode) or item_stat.st_nlink != 1:
                raise CandidateWorkspaceError("tree digest input contains a non-regular file")
            total_bytes += item_stat.st_size
            if total_bytes > _MAX_VIEW_BYTES:
                raise CandidateWorkspaceError("tree digest input exceeds the byte cap")
            records.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": stat.S_IMODE(item_stat.st_mode),
                    "size": item_stat.st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    except (OSError, UnicodeError) as exc:
        raise CandidateWorkspaceError("cannot compute evaluator tree digest") from exc
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _decode_canonical_json_object(content: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite JSON value")

    payload = json.loads(
        content,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
    if not isinstance(payload, dict):
        raise TypeError("JSON marker is not an object")
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if content != canonical:
        raise ValueError("JSON marker is not canonical")
    return payload


def _verify_candidate_view(root: Path) -> None:
    marker = root / ".improvement-candidate-view.json"
    try:
        marker_stat = marker.lstat()
        if (
            marker.is_symlink()
            or not stat.S_ISREG(marker_stat.st_mode)
            or marker_stat.st_nlink != 1
        ):
            raise CandidateWorkspaceError("candidate view marker is not a regular file")
        if marker_stat.st_size > _MAX_MARKER_BYTES:
            raise CandidateWorkspaceError("candidate view marker exceeds the byte cap")
        payload = _decode_canonical_json_object(marker.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CandidateWorkspaceError("candidate view marker is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "archive_id", "entries"}:
        raise CandidateWorkspaceError("candidate view marker is malformed")
    entries = payload.get("entries")
    if payload.get("schema_version") != 1 or not isinstance(entries, list) or not entries:
        raise CandidateWorkspaceError("candidate view marker has no approved entries")
    expected_files = {".improvement-candidate-view.json"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "artifact_id",
            "kind",
            "content_object",
            "filename",
        }:
            raise CandidateWorkspaceError("candidate view entry is malformed")
        filename = str(entry.get("filename") or "")
        artifact_id = str(entry.get("artifact_id") or "")
        kind = str(entry.get("kind") or "")
        digest = str(entry.get("content_object") or "")
        if (
            filename != f"{artifact_id}-{kind}.json"
            or not filename
            or Path(filename).name != filename
            or kind not in {"development_corpus", "capability_brief"}
            or re.fullmatch(r"artifact_[0-9a-f]{24}", artifact_id) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise CandidateWorkspaceError("candidate view entry identity is invalid")
        content_path = root / filename
        try:
            content_stat = content_path.lstat()
            if (
                content_path.is_symlink()
                or not stat.S_ISREG(content_stat.st_mode)
                or content_stat.st_nlink != 1
                or content_stat.st_size > _MAX_VIEW_BYTES
            ):
                raise CandidateWorkspaceError("candidate view content file is invalid")
            actual = hashlib.sha256(content_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise CandidateWorkspaceError("candidate view content is unreadable") from exc
        if digest != f"sha256:{actual}" or filename in expected_files:
            raise CandidateWorkspaceError("candidate view content digest or name is invalid")
        expected_files.add(filename)
    actual_files = {path.name for path in root.iterdir()}
    if actual_files != expected_files:
        raise CandidateWorkspaceError("candidate view contains unapproved files")


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _require_disjoint_roots(roots: dict[str, Path]) -> None:
    entries = list(roots.items())
    for index, (first_label, first) in enumerate(entries):
        for second_label, second in entries[index + 1 :]:
            if _paths_overlap(first, second):
                raise CandidateWorkspaceError(
                    f"{first_label} and {second_label} must be disjoint directories"
                )


def _remove_new_workspace(destination: Path, *, allowed_parent: Path) -> None:
    if not destination.exists() and not destination.is_symlink():
        return
    resolved_parent = allowed_parent.resolve(strict=True)
    resolved_destination = destination.resolve(strict=False)
    if resolved_destination.parent != resolved_parent:
        raise CandidateWorkspaceError("refusing to clean a workspace outside the lab")
    if destination.is_symlink():
        destination.unlink()
    else:
        shutil.rmtree(destination)


__all__ = [
    "CandidateWorkspace",
    "CandidateWorkspaceError",
    "GitSourceState",
    "OfflineContainerJob",
    "build_offline_container_job",
    "capture_source_state",
    "directory_tree_digest",
    "materialize_candidate",
    "require_clean_champion",
]
