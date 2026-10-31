# ruff: noqa: EM101,PLR2004,S105,S108,S607,SLF001,TRY003
from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tools.paired_xben import preflight

if TYPE_CHECKING:
    from collections.abc import Mapping


def _case_pool(root: Path, count: int = 104) -> None:
    root.mkdir(parents=True)
    for number in range(1, count + 1):
        case = root / f"XBEN-{number:03d}-24"
        case.mkdir()
        (case / "benchmark.json").touch()
        (case / "docker-compose.yml").touch()


def _short_socket_parent() -> Path:
    private_tmp = Path("/private/tmp")
    return private_tmp if private_tmp.is_dir() else Path("/tmp")


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603
        ("git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit_fixture_repository(root: Path, *, origin: str) -> str:
    subprocess.run(  # noqa: S603
        ("git", "init", "--quiet", str(root)),
        check=True,
        capture_output=True,
    )
    _git(root, "config", "user.name", "Paired XBEN Test")
    _git(root, "config", "user.email", "paired-xben@example.invalid")
    _git(root, "remote", "add", "origin", origin)
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "fixture")
    return _git(root, "rev-parse", "HEAD")


def _strix_fixture(root: Path) -> tuple[str, Path]:
    root.mkdir()
    (root / "strix").mkdir()
    (root / "strix" / "__init__.py").write_text("\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "strix-agent"\nversion = "0"\n',
        encoding="utf-8",
    )
    executable = root / "bin" / "strix"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    head = _commit_fixture_repository(root, origin=preflight.STRIX_CANONICAL_ORIGIN_URL)
    return head, executable


def _ready_git_state(
    _root: Path | None, expected: str | None, **_kwargs: object
) -> dict[str, object]:
    head = "a" * 40
    return {
        "available": True,
        "head": head,
        "dirty": False,
        "pin_status": "match" if expected else "unresolved",
        "expected_head": expected,
    }


def _ready_source_binding(**_kwargs: object) -> dict[str, object]:
    return {
        "ready": True,
        "status": "ready",
        "repository_root_verified": True,
        "expected_head": "a" * 40,
        "expected_origin_url": preflight.XBEN_CANONICAL_ORIGIN_URL,
        "origin_url": preflight.XBEN_CANONICAL_ORIGIN_URL,
        "origin_matches_expected": True,
        "origin_observed_sha256": "sha256:" + "b" * 64,
        "tree_path": "benchmarks",
        "tree_object": "c" * 40,
        "tree_object_algorithm": "sha1",
        "tree_matches_worktree": True,
        "location_is_canonical": True,
    }


def _patch_ready_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight,
        "_disk_status",
        lambda _path, *, required_free_gib: {
            "ready": True,
            "status": "ready",
            "free_bytes": 40 * 1024**3,
            "free_gib": 40.0,
            "required_free_bytes": required_free_gib * 1024**3,
            "required_free_gib": required_free_gib,
        },
    )
    monkeypatch.setattr(
        preflight,
        "_docker_status",
        lambda *, timeout_seconds, **_kwargs: {
            "ready": True,
            "executable_present": True,
            "daemon_responsive": True,
            "status": "ready",
            "timeout_seconds": timeout_seconds,
        },
    )
    monkeypatch.setattr(
        preflight,
        "_strix_runtime_status",
        lambda **_kwargs: {
            "ready": True,
            "source_present": True,
            "executable_present": True,
            "dependency_probe_ok": True,
            "executable_source": "explicit",
            "status": "ready",
        },
    )
    monkeypatch.setattr(preflight, "_git_state", _ready_git_state)
    monkeypatch.setattr(preflight, "_repository_binding_status", _ready_source_binding)


def test_collect_preflight_is_ready_and_never_emits_secrets_or_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = tmp_path / "benchmarks"
    _case_pool(pool)
    _patch_ready_runtime(monkeypatch)
    secret = "provider-secret-canary-never-emit"
    private_target = "http://private-target.invalid/target-token-never-emit"
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name.startswith(".env"):
            raise AssertionError("preflight attempted to open a dotenv file")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    report = preflight.collect_preflight(
        evidence_dir=tmp_path / "evidence",
        benchmarks_root=pool,
        strix_repo_root=tmp_path / "strix",
        ravage_repo_root=tmp_path / "ravage",
        xben_repo_root=tmp_path / "xben",
        environment={"OPENAI_API_KEY": secret},
        expected_ravage_head="a" * 40,
        expected_strix_head="a" * 40,
        expected_xben_head="a" * 40,
        website_target=private_target,
        website_classification="known_site",
        captured_at="2026-09-11T00:00:00+00:00",
    )

    encoded = preflight.canonical_json_bytes(report).decode("utf-8")
    assert report["schema_version"] == preflight.PREFLIGHT_SCHEMA
    assert report["blocked"] is False
    assert report["xben"]["case_count"] == 104
    assert report["xben"]["eligible_case_count"] == 104
    assert report["xben"]["exact_case_set"] is True
    assert len(report["xben"]["eligible_case_ids"]) == 104
    assert report["provider_environment"] == {
        "ready": True,
        "required": [{"name": "OPENAI_API_KEY", "present": True}],
        "missing": [],
        "source": "process_environment_only",
        "dotenv_loaded": False,
    }
    assert report["website"]["classification"] == "known_site"
    assert report["website"]["raw_reference_emitted"] is False
    assert secret not in encoded
    assert private_target not in encoded
    assert ".env" not in encoded


def test_write_preflight_is_canonical_and_create_only(tmp_path: Path) -> None:
    report = {"z": 1, "a": {"ready": True}}
    path = preflight.write_preflight(tmp_path / "evidence", report)
    expected = b'{"a":{"ready":true},"z":1}\n'

    assert path.read_bytes() == expected
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(preflight.PreflightConfigurationError):
        preflight.write_preflight(tmp_path / "evidence", {"replacement": True})
    assert path.read_bytes() == expected


def test_blockers_name_dirty_mismatched_and_unresolved_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = tmp_path / "benchmarks"
    _case_pool(pool, count=2)
    _patch_ready_runtime(monkeypatch)

    def git_state(_root: Path | None, expected: str | None, **_kwargs: object) -> dict[str, object]:
        return {
            "available": True,
            "head": "a" * 40,
            "dirty": True,
            "pin_status": "mismatch" if expected == "b" * 40 else "unresolved",
            "expected_head": expected,
        }

    monkeypatch.setattr(preflight, "_git_state", git_state)
    report = preflight.collect_preflight(
        evidence_dir=tmp_path / "evidence",
        benchmarks_root=pool,
        strix_repo_root=tmp_path / "strix",
        ravage_repo_root=tmp_path / "ravage",
        xben_repo_root=tmp_path / "xben",
        expected_xben_case_count=2,
        environment={"OPENAI_API_KEY": "configured"},
        expected_strix_head="b" * 40,
        captured_at="2026-09-11T00:00:00+00:00",
    )

    assert report["blocked"] is True
    assert report["block_reasons"] == [
        "website_target_unresolved",
        "ravage_source_dirty",
        "ravage_pin_unresolved",
        "strix_source_dirty",
        "strix_head_mismatch",
        "xben_source_dirty",
        "xben_pin_unresolved",
    ]
    assert preflight.preflight_exit_code(report) == 2


def test_docker_probe_timeout_is_bounded_and_does_not_emit_process_output(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "docker"
    executable.write_text("#!/bin/sh\nsleep 10\n", encoding="utf-8")
    executable.chmod(0o755)
    with tempfile.TemporaryDirectory(
        prefix="px-docker-", dir=_short_socket_parent()
    ) as socket_directory:
        socket_path = Path(socket_directory).resolve() / "d.sock"
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(socket_path))
        try:
            result = preflight._docker_status(
                executable=executable,
                socket_path=socket_path,
                trusted_path=preflight.DEFAULT_TRUSTED_PATH,
                timeout_seconds=0.25,
            )
        finally:
            listener.close()

    assert result == {
        "ready": False,
        "executable_present": True,
        "daemon_responsive": False,
        "status": "timeout",
        "timeout_seconds": 0.25,
    }
    assert "secret" not in json.dumps(result)


def test_docker_probe_uses_only_explicit_binary_socket_path_and_clean_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = tmp_path / "docker-audit.json"
    executable = tmp_path / "pinned-docker"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                f"Path({str(audit)!r}).write_text(json.dumps({{'argv': sys.argv, "
                "'environment': dict(os.environ), 'cwd': os.getcwd()}), encoding='utf-8')",
                "raise SystemExit(0)",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("OPENAI_API_KEY", "provider-canary")
    monkeypatch.setenv("AMBIENT_SECRET_CANARY", "ambient-canary")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("DOCKER_CONTEXT", "attacker-context")
    monkeypatch.setenv("PATH", "/ambient/path/canary")
    with tempfile.TemporaryDirectory(
        prefix="px-docker-", dir=_short_socket_parent()
    ) as socket_directory:
        socket_path = Path(socket_directory).resolve() / "exact.sock"
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(socket_path))
        try:
            result = preflight._docker_status(
                executable=executable,
                socket_path=socket_path,
                trusted_path=preflight.DEFAULT_TRUSTED_PATH,
                timeout_seconds=1,
            )
        finally:
            listener.close()

        observed = json.loads(audit.read_text(encoding="utf-8"))
        assert observed["environment"]["DOCKER_HOST"] == f"unix://{socket_path}"

    environment = observed["environment"]
    assert result["ready"] is True
    assert observed["argv"] == [
        str(executable),
        "info",
        "--format",
        "{{.ServerVersion}}",
    ]
    assert environment["PATH"] == preflight.DEFAULT_TRUSTED_PATH
    assert environment["DOCKER_CONFIG"].startswith(environment["HOME"])
    assert not Path(environment["HOME"]).exists()
    assert not Path(observed["cwd"]).exists()
    for name in (
        "OPENAI_API_KEY",
        "AMBIENT_SECRET_CANARY",
        "GIT_DIR",
        "DOCKER_CONTEXT",
    ):
        assert name not in environment


def test_git_state_reports_head_dirty_and_exact_pin_without_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    head = "0123456789abcdef" * 2 + "01234567"

    def fake_git(_root: Path, args: tuple[str, ...], **_kwargs: object) -> str:
        if args[0] == "rev-parse":
            return head + "\n"
        return "?? private-file\n"

    monkeypatch.setattr(preflight, "_run_git", fake_git)
    state = preflight._git_state(root, head)

    assert state == {
        "available": True,
        "head": head,
        "dirty": True,
        "pin_status": "match",
        "expected_head": head,
    }
    assert "private-file" not in json.dumps(state)


def test_git_probe_scrubs_ambient_git_and_provider_state_and_disables_extensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    head = _commit_fixture_repository(repository, origin=preflight.XBEN_CANONICAL_ORIGIN_URL)
    audit = tmp_path / "git-audit.json"
    wrapper = tmp_path / "pinned-git"
    wrapper.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                f"Path({str(audit)!r}).write_text(json.dumps({{'argv': sys.argv, "
                "'environment': dict(os.environ), 'cwd': os.getcwd()}), encoding='utf-8')",
                "os.execve('/usr/bin/git', ['/usr/bin/git', *sys.argv[1:]], dict(os.environ))",
                "",
            )
        ),
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    monkeypatch.setenv("OPENAI_API_KEY", "provider-canary")
    monkeypatch.setenv("AMBIENT_SECRET_CANARY", "ambient-canary")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "hostile-work-tree"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/tmp/hostile-fsmonitor")
    monkeypatch.setenv("PATH", "/ambient/path/canary")

    observed_head = preflight._run_git(
        repository,
        ("rev-parse", "--verify", "HEAD"),
        git_executable=wrapper,
        trusted_path=preflight.DEFAULT_TRUSTED_PATH,
    )

    observed = json.loads(audit.read_text(encoding="utf-8"))
    environment = observed["environment"]
    argv = observed["argv"]
    assert observed_head is not None
    assert observed_head.strip() == head
    assert observed["cwd"] == str(repository)
    assert environment["PATH"] == preflight.DEFAULT_TRUSTED_PATH
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert argv[1:11] == [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "submodule.recurse=false",
    ]
    for name in (
        "OPENAI_API_KEY",
        "AMBIENT_SECRET_CANARY",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
    ):
        assert name not in environment


def test_main_writes_blocked_evidence_before_returning_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report: dict[str, object] = {
        "schema_version": preflight.PREFLIGHT_SCHEMA,
        "blocked": True,
        "block_reasons": ["docker_daemon_unhealthy"],
    }
    monkeypatch.setattr(preflight, "collect_preflight", lambda **_kwargs: report)
    evidence = tmp_path / "evidence"

    exit_code = preflight.main(
        [
            "--evidence-dir",
            str(evidence),
            "--benchmarks-root",
            str(tmp_path / "benchmarks"),
            "--strix-repo-root",
            str(tmp_path / "strix"),
        ]
    )

    assert exit_code == 2
    stored: Mapping[str, object] = json.loads(
        (evidence / preflight.PREFLIGHT_FILENAME).read_text(encoding="utf-8")
    )
    assert stored == report


def test_write_rejects_nonempty_preexisting_evidence_directory(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    marker = evidence / "prior-artifact.json"
    marker.write_text("{}\n", encoding="utf-8")

    with pytest.raises(preflight.PreflightConfigurationError, match="new or empty"):
        preflight.write_preflight(evidence, {"blocked": False})
    assert marker.read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("captured_at", ["2026-09-11T00:00:00", "not-a-time"])
def test_captured_at_must_be_timezone_aware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    captured_at: str,
) -> None:
    pool = tmp_path / "benchmarks"
    _case_pool(pool)
    _patch_ready_runtime(monkeypatch)

    with pytest.raises(preflight.PreflightConfigurationError, match="timezone-aware"):
        preflight.collect_preflight(
            evidence_dir=tmp_path / "evidence",
            benchmarks_root=pool,
            strix_repo_root=tmp_path / "strix",
            ravage_repo_root=tmp_path / "ravage",
            xben_repo_root=tmp_path / "xben",
            environment={"OPENAI_API_KEY": "configured"},
            expected_ravage_head="a" * 40,
            expected_strix_head="a" * 40,
            expected_xben_head="a" * 40,
            website_target="known-site",
            website_classification="known_site",
            captured_at=captured_at,
        )


def test_xben_binding_requires_canonical_tracked_tree_and_records_provenance(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "xben"
    repository.mkdir()
    pool = repository / "benchmarks"
    _case_pool(pool, count=1)
    head = _commit_fixture_repository(repository, origin=preflight.XBEN_CANONICAL_ORIGIN_URL)

    status = preflight._xben_status(
        pool,
        xben_repo_root=repository,
        expected_head=head,
        expected_case_count=1,
    )

    binding = status["source_binding"]
    assert status["ready"] is True
    assert binding["ready"] is True
    assert binding["repository_root_verified"] is True
    assert binding["location_is_canonical"] is True
    assert binding["origin_url"] == preflight.XBEN_CANONICAL_ORIGIN_URL
    assert binding["origin_matches_expected"] is True
    assert binding["tree_object"] == _git(repository, "rev-parse", f"{head}:benchmarks")
    assert binding["tree_object_algorithm"] == "sha1"
    assert binding["tree_matches_worktree"] is True


@pytest.mark.parametrize("location_name", ["outside", "untracked-copy"])
def test_xben_binding_rejects_outside_or_untracked_case_directory(
    tmp_path: Path,
    location_name: str,
) -> None:
    repository = tmp_path / "xben"
    repository.mkdir()
    _case_pool(repository / "benchmarks", count=1)
    head = _commit_fixture_repository(repository, origin=preflight.XBEN_CANONICAL_ORIGIN_URL)
    candidate = (
        tmp_path / "outside" / "benchmarks"
        if location_name == "outside"
        else repository / "benchmarks-copy"
    )
    _case_pool(candidate, count=1)

    status = preflight._xben_status(
        candidate,
        xben_repo_root=repository,
        expected_head=head,
        expected_case_count=1,
    )

    assert status["exact_case_set"] is True
    assert status["ready"] is False
    assert status["status"] == "source_unbound"
    assert status["source_binding"]["status"] == "noncanonical_tree_location"


def test_xben_binding_rejects_worktree_substitution(tmp_path: Path) -> None:
    repository = tmp_path / "xben"
    repository.mkdir()
    pool = repository / "benchmarks"
    _case_pool(pool, count=1)
    head = _commit_fixture_repository(repository, origin=preflight.XBEN_CANONICAL_ORIGIN_URL)
    (pool / "XBEN-001-24" / "benchmark.json").write_text("substituted\n", encoding="utf-8")

    status = preflight._xben_status(
        pool,
        xben_repo_root=repository,
        expected_head=head,
        expected_case_count=1,
    )

    assert status["exact_case_set"] is True
    assert status["ready"] is False
    assert status["source_binding"]["status"] == "worktree_mismatch"
    assert status["source_binding"]["tree_matches_worktree"] is False


def test_xben_binding_rejects_wrong_origin_without_emitting_remote_secret(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "xben"
    repository.mkdir()
    pool = repository / "benchmarks"
    _case_pool(pool, count=1)
    remote = "https://remote-token-canary@evil.invalid/substitute.git"
    head = _commit_fixture_repository(repository, origin=remote)

    status = preflight._xben_status(
        pool,
        xben_repo_root=repository,
        expected_head=head,
        expected_case_count=1,
    )
    encoded = json.dumps(status)

    assert status["ready"] is False
    assert status["source_binding"]["status"] == "origin_mismatch"
    assert status["source_binding"]["origin_url"] is None
    assert status["source_binding"]["origin_observed_sha256"].startswith("sha256:")
    assert remote not in encoded
    assert "remote-token-canary" not in encoded


def test_strix_runtime_accepts_only_pinned_source_blob_or_expected_binary_digest(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "strix-source"
    head, tracked_executable = _strix_fixture(repository)
    unrelated = tmp_path / "unrelated-strix"
    unrelated.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    unrelated.chmod(0o755)

    source_bound = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=tracked_executable,
        expected_source_head=head,
        expected_executable_sha256=None,
        timeout_seconds=1,
    )
    rejected = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=unrelated,
        expected_source_head=head,
        expected_executable_sha256=None,
        timeout_seconds=1,
    )
    digest = preflight._sha256_file(unrelated)
    digest_bound = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=unrelated,
        expected_source_head=head,
        expected_executable_sha256=digest,
        timeout_seconds=1,
    )

    assert source_bound["ready"] is True
    assert source_bound["identity_mode"] == "pinned_source_blob"
    assert source_bound["identity_verified"] is True
    assert source_bound["source_relative_executable"] == "bin/strix"
    assert source_bound["source_binding"]["origin_url"] == preflight.STRIX_CANONICAL_ORIGIN_URL
    assert rejected["dependency_probe_ok"] is True
    assert rejected["ready"] is False
    assert rejected["identity_mode"] == "unverified"
    assert rejected["status"] == "identity_unverified"
    assert digest is not None
    assert digest_bound["ready"] is True
    assert digest_bound["identity_mode"] == "binary_sha256"
    assert digest_bound["expected_executable_sha256"] == digest


def test_strix_runtime_rejects_substituted_tracked_executable(tmp_path: Path) -> None:
    repository = tmp_path / "strix-source"
    head, executable = _strix_fixture(repository)
    executable.write_text("#!/bin/sh\n# substituted\nexit 0\n", encoding="utf-8")

    status = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=executable,
        expected_source_head=head,
        expected_executable_sha256=None,
        timeout_seconds=1,
    )

    assert status["dependency_probe_ok"] is True
    assert status["ready"] is False
    assert status["identity_verified"] is False
    assert status["source_binding"]["status"] == "worktree_mismatch"


def test_strix_runtime_rejects_wrong_source_origin_even_with_binary_digest(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "strix-source"
    head, executable = _strix_fixture(repository)
    _git(repository, "remote", "set-url", "origin", "https://evil.invalid/strix.git")
    digest = preflight._sha256_file(executable)

    status = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=executable,
        expected_source_head=head,
        expected_executable_sha256=digest,
        timeout_seconds=1,
    )

    assert digest is not None
    assert status["identity_mode"] == "binary_sha256"
    assert status["identity_verified"] is True
    assert status["ready"] is False
    assert status["status"] == "source_unbound"
    assert status["source_binding"]["status"] == "origin_mismatch"


def test_strix_probe_uses_isolated_home_cwd_clean_environment_and_no_pycache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "strix-source"
    repository.mkdir()
    (repository / "strix").mkdir()
    (repository / "strix" / "__init__.py").write_text("\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "strix-agent"\nversion = "0"\n',
        encoding="utf-8",
    )
    bin_directory = repository / "bin"
    bin_directory.mkdir()
    (bin_directory / "probe_module.py").write_text("VALUE = 1\n", encoding="utf-8")
    audit = tmp_path / "strix-audit.json"
    executable = bin_directory / "strix"
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "sys.path.insert(0, str(Path(__file__).parent))",
                "import probe_module",
                "assert probe_module.VALUE == 1",
                f"Path({str(audit)!r}).write_text(json.dumps({{'environment': "
                "dict(os.environ), 'cwd': os.getcwd()}), encoding='utf-8')",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    head = _commit_fixture_repository(repository, origin=preflight.STRIX_CANONICAL_ORIGIN_URL)
    monkeypatch.setenv("OPENAI_API_KEY", "provider-canary")
    monkeypatch.setenv("AMBIENT_SECRET_CANARY", "ambient-canary")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "hostile-git-dir"))
    monkeypatch.setenv("PATH", "/ambient/path/canary")

    status = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=executable,
        expected_source_head=head,
        expected_executable_sha256=None,
        timeout_seconds=1,
        git_executable=preflight.DEFAULT_GIT_EXECUTABLE,
        trusted_path=preflight.DEFAULT_TRUSTED_PATH,
    )

    observed = json.loads(audit.read_text(encoding="utf-8"))
    environment = observed["environment"]
    assert status["ready"] is True
    assert environment["PATH"] == preflight.DEFAULT_TRUSTED_PATH
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert environment["HOME"] != str(Path.home())
    assert not Path(environment["HOME"]).exists()
    assert not Path(observed["cwd"]).exists()
    assert not list(repository.rglob("__pycache__"))
    for name in ("OPENAI_API_KEY", "AMBIENT_SECRET_CANARY", "GIT_DIR"):
        assert name not in environment


def test_strix_probe_timeout_kills_its_process_group_and_descendants(tmp_path: Path) -> None:
    repository = tmp_path / "strix-source"
    head, executable = _strix_fixture(repository)
    group_id_path = tmp_path / "probe-process-group"
    survived_path = tmp_path / "descendant-survived"
    executable.write_text(
        "\n".join(
            (
                "#!/bin/sh",
                f"printf '%s' \"$$\" > {group_id_path}",
                f"(trap '' TERM; sleep 1; printf survived > {survived_path}; sleep 10) &",
                "sleep 10",
                "",
            )
        ),
        encoding="utf-8",
    )
    _git(repository, "add", "bin/strix")
    _git(repository, "commit", "--quiet", "-m", "hostile version probe")
    head = _git(repository, "rev-parse", "HEAD")

    status = preflight._strix_runtime_status(
        strix_repo_root=repository,
        executable=executable,
        expected_source_head=head,
        expected_executable_sha256=None,
        timeout_seconds=0.5,
    )

    assert group_id_path.exists(), json.dumps(status, sort_keys=True)
    process_group = int(group_id_path.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.killpg(process_group, 0)
    time.sleep(1.1)
    assert not survived_path.exists()
    assert status["dependency_probe_ok"] is False
    assert status["status"] in {"timeout", "probe_failed"}
