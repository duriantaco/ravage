# ruff: noqa: ANN401,ARG001,ARG005,EM101,PLR2004,SLF001,TRY003
from __future__ import annotations

import base64
import hashlib
import json
import signal
from collections import Counter
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from tools.xben_head_to_head import campaign

if TYPE_CHECKING:
    from pathlib import Path

API_KEY = "sk-test-campaign-secret-never-persist"


def _executable(path: Path, version: str) -> tuple[Path, str]:
    path.write_text(f"#!/bin/sh\necho {version}\n", encoding="utf-8")
    path.chmod(0o755)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _config(
    tmp_path: Path,
    *,
    case_ids: tuple[str, ...] = campaign.FIXED_CASE_IDS,
) -> campaign.CampaignConfig:
    project = tmp_path / "project"
    source = tmp_path / "xben"
    skill = tmp_path / "ravage-safe-reproduction"
    project.mkdir()
    source.mkdir()
    skill.mkdir()
    (skill / "SKILL.md").write_text("# Frozen test skill\n", encoding="utf-8")
    codex, codex_digest = _executable(tmp_path / "codex", "codex-cli 0.153.2")
    strix, strix_digest = _executable(tmp_path / "strix", "strix 1.6.2")
    return campaign.CampaignConfig(
        project_root=project,
        source_repo=source,
        output_dir=tmp_path / "out",
        skill_dir=skill,
        codex_executable=codex,
        codex_executable_sha256=codex_digest,
        strix_executable=strix,
        strix_executable_sha256=strix_digest,
        api_key=API_KEY,
        case_ids=case_ids,
        codex_environment={"PATH": "/usr/bin:/bin"},
        strix_environment={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path / "tmp"),
            "DOCKER_HOST": "unix:///private/test-docker.sock",
            "UNRELATED_SECRET": "must-not-be-inherited",
        },
    )


def _patch_preflight(
    monkeypatch: pytest.MonkeyPatch,
    config: campaign.CampaignConfig,
) -> None:
    def identity(path: Path, label: str, errors: list[str]) -> dict[str, object]:
        commit = config.source_commit if label == "source_repo" else "a" * 40
        return {"commit": commit, "dirty": label == "project_root", "path": str(path)}

    def metadata(_source: Path, case_id: str) -> dict[str, object]:
        index = campaign.FIXED_CASE_IDS.index(case_id)
        level = 1 if index < 9 else (2 if index < 18 else 3)
        return {"description": f"Authorized target {case_id}", "level": level}

    monkeypatch.setattr(campaign, "_path_git_identity", identity)
    monkeypatch.setattr(
        campaign,
        "_docker_preflight",
        lambda _config, _errors: {
            "server_version": "test",
            "strix_image_repo_digests": [config.strix_image],
        },
    )
    monkeypatch.setattr(
        campaign,
        "_verify_strix_checkout",
        lambda _config, _errors: {
            "path": "/pinned/strix",
            "commit": config.strix_source_commit,
            "dirty": False,
        },
    )
    monkeypatch.setattr(
        campaign,
        "_disk_preflight",
        lambda _config, _errors: {
            "path": str(config.output_dir.parent),
            "free_bytes": 10 * 1024**3,
            "required_free_bytes": 4 * 1024**3,
        },
    )
    monkeypatch.setattr(
        campaign,
        "_executable_version",
        lambda path, label, errors: "codex-cli 0.153.2" if label == "Codex" else "strix 1.6.2",
    )
    monkeypatch.setattr(campaign.target_runner, "read_case_metadata", metadata)
    monkeypatch.setattr(campaign.target_runner.BuildxBuilder, "create", lambda: _FakeBuilder())


class _FakeBuilder:
    name = "ravage_xben_cmp_" + "a" * 32

    def verify_owned(self) -> None:
        pass

    def destroy(self) -> dict[str, object]:
        return {"verified": True, "returncode": 0}


class _FakeTarget:
    def __init__(
        self,
        *,
        case_id: str,
        expected_flag: str,
        port: int,
        events: dict[str, Any],
    ) -> None:
        self.case_id = case_id
        self.expected_flag = expected_flag
        self.host_port = port
        self.events = events
        self.active = False
        self.build_calls = 0

    @property
    def strix_target_url(self) -> str:
        return f"http://host.docker.internal:{self.host_port}"

    def build(self, *, timeout_seconds: int) -> None:
        self.build_calls += 1
        self.events["builds"].append((self.case_id, timeout_seconds))

    def start(self, *, timeout_seconds: int) -> str:
        self.active = True
        self.events["starts"].append((self.case_id, timeout_seconds))
        return f"http://127.0.0.1:{self.host_port}"

    def reset(self, *, timeout_seconds: int) -> None:
        self.active = False
        self.events["resets"].append((self.case_id, timeout_seconds))

    def destroy(self, *, evidence_dir: Path, timeout_seconds: int) -> dict[str, object]:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "target.log").write_text("sanitized target log\n", encoding="utf-8")
        self.events["destroys"].append((self.case_id, timeout_seconds))
        return {"verified": True, "remaining_container_ids": []}

    def public_receipt(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_flag_sha256": hashlib.sha256(self.expected_flag.encode()).hexdigest(),
            "build_calls": self.build_calls,
        }


def _patch_execution(
    monkeypatch: pytest.MonkeyPatch,
    config: campaign.CampaignConfig,
    *,
    codex_error: bool = False,
) -> dict[str, Any]:
    events: dict[str, Any] = {
        "builds": [],
        "starts": [],
        "resets": [],
        "destroys": [],
        "cache": 0,
        "flags": {},
        "targets": {},
        "invocations": [],
        "instructions": {},
    }
    counter = 0

    def make_flag() -> str:
        nonlocal counter
        counter += 1
        return f"flag{{ravage_cmp_{counter:064x}}}"

    def prepare_target(
        *,
        source_repo: Path,
        case_id: str,
        expected_flag: str,
        destination: Path,
        buildx_builder: _FakeBuilder,
        source_commit: str,
    ) -> _FakeTarget:
        destination.mkdir(parents=True)
        index = campaign.FIXED_CASE_IDS.index(case_id)
        target = _FakeTarget(
            case_id=case_id,
            expected_flag=expected_flag,
            port=41000 + index,
            events=events,
        )
        events["flags"][case_id] = expected_flag
        events["targets"][target.host_port] = target
        return target

    def cleanup(builder: _FakeBuilder) -> dict[str, object]:
        assert builder.name == _FakeBuilder.name
        events["cache"] += 1
        return {"returncode": 0, "elapsed_seconds": 0.01}

    def codex(request: Any) -> dict[str, object]:
        target = events["targets"][request.target_port]
        events["invocations"].append((target.case_id, "codex_skill"))
        events["instructions"].setdefault(target.case_id, {})["codex_skill"] = request.instruction
        assert request.skill_directory != config.skill_dir
        assert request.skill_directory.name == "frozen-skill"
        auth = json.loads(request.auth_file.read_text(encoding="utf-8"))
        assert auth == {"OPENAI_API_KEY": API_KEY, "auth_mode": "apikey"}
        (request.output_directory / "raw-evidence.txt").write_text(
            f"credential={API_KEY}; candidate={target.expected_flag}; "
            f"candidate_b64={base64.b64encode(target.expected_flag.encode()).decode()}\n",
            encoding="utf-8",
        )
        if codex_error:
            raise RuntimeError("single Codex launch failure")
        return {
            "status": "completed",
            "error": None,
            "duration_seconds": 1.25,
            "request_count": 7,
            "flag_candidates": [target.expected_flag],
            "usage": {
                "input_tokens": 1000,
                "cached_input_tokens": 400,
                "output_tokens": 100,
            },
            "nested": {"raw_candidate": target.expected_flag},
        }

    def strix(request: Any) -> dict[str, object]:
        port = int(urlsplit(request.target_url).port or 0)
        target = events["targets"][port]
        events["invocations"].append((target.case_id, "strix"))
        instruction = request.instruction_file.read_text(encoding="utf-8").strip()
        events["instructions"].setdefault(target.case_id, {})["strix"] = instruction
        assert request.model == "openai/gpt-5.4-2026-03-05"
        assert request.sandbox_image == campaign.PINNED_STRIX_IMAGE
        assert request.environment["STRIX_IMAGE"] == campaign.PINNED_STRIX_IMAGE
        assert request.environment["STRIX_SANDBOX_LOG_MAX_SIZE"] == "10m"
        assert request.environment["STRIX_SANDBOX_LOG_MAX_FILE"] == "2"
        assert "UNRELATED_SECRET" not in request.environment
        (request.working_directory / "report.md").write_text(
            f"credential={API_KEY}; candidate={target.expected_flag}\n",
            encoding="utf-8",
        )
        return {
            "status": "completed",
            "error": None,
            "duration_seconds": 2.5,
            "flag_candidates": [target.expected_flag],
            "usage": {
                "requests": 11,
                "input_tokens": 2000,
                "cached_input_tokens": 500,
                "output_tokens": 200,
            },
        }

    monkeypatch.setattr(campaign.target_runner, "make_pair_flag", make_flag)
    monkeypatch.setattr(campaign.target_runner, "prepare_target", prepare_target)
    monkeypatch.setattr(campaign.target_runner, "cleanup_build_cache", cleanup)
    monkeypatch.setattr(campaign.codex_runner, "run_codex", codex)
    monkeypatch.setattr(campaign.strix_runner, "run_strix", strix)
    return events


def test_preflight_records_exact_pins_versions_and_balanced_orders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _patch_preflight(monkeypatch, config)

    receipt = campaign.run_preflight(config)

    assert receipt["ready"] is True
    assert receipt["case_ids"] == list(campaign.FIXED_CASE_IDS)
    assert Counter(order[0] for order in receipt["arm_orders"].values()) == {
        "codex_skill": 10,
        "strix": 10,
    }
    assert receipt["runtime"]["cli_versions"] == {
        "codex": "codex-cli 0.153.2",
        "strix": "strix 1.6.2",
    }
    assert receipt["runtime"]["strix_image"] == campaign.PINNED_STRIX_IMAGE
    assert len(receipt["runtime"]["harness_code_sha256"]) == 64
    assert receipt["runtime"]["harness_code_sha256"] == campaign._harness_code_sha256()

    credential_free = campaign.run_preflight(replace(config, api_key=""))
    assert credential_free["ready"] is True


def test_preflight_rejects_unpinned_strix_commit_and_dirty_xben(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    original_identity = campaign._path_git_identity

    def dirty_xben(path: Path, label: str, errors: list[str]) -> dict[str, object]:
        identity = original_identity(path, label, errors)
        assert identity is not None
        if label == "source_repo":
            identity["dirty"] = True
        return identity

    monkeypatch.setattr(campaign, "_path_git_identity", dirty_xben)
    receipt = campaign.run_preflight(replace(config, strix_source_commit="f" * 40))

    assert receipt["ready"] is False
    assert any("Strix source commit differs" in error for error in receipt["errors"])
    assert any("XBEN source_repo must be clean" in error for error in receipt["errors"])


def test_preflight_docker_timeout_reports_error_and_still_checks_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    docker_preflight = campaign._docker_preflight
    disk_preflight = campaign._disk_preflight
    _patch_preflight(monkeypatch, config)
    monkeypatch.setattr(campaign, "_docker_preflight", docker_preflight)
    monkeypatch.setattr(campaign, "_disk_preflight", disk_preflight)
    monkeypatch.setattr(campaign.shutil, "which", lambda _name: "/sensitive/docker-command")
    monkeypatch.setattr(
        campaign.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=7 * 1024**3),
    )

    def timed_out(command: list[str], **kwargs: Any) -> None:
        assert command[1:3] == ["info", "--format"]
        assert kwargs["timeout"] == 30
        raise campaign.subprocess.TimeoutExpired(
            cmd=command,
            timeout=30,
            output="sensitive stdout",
            stderr="sensitive stderr",
        )

    monkeypatch.setattr(campaign.subprocess, "run", timed_out)

    receipt = campaign.run_preflight(config)

    assert receipt["ready"] is False
    assert receipt["errors"] == [
        "Docker daemon or exact pinned Strix sandbox image is unavailable"
    ]
    assert receipt["runtime"]["docker"] is None
    assert receipt["runtime"]["disk_preflight"]["free_bytes"] == 7 * 1024**3
    assert receipt["runtime"]["disk_preflight"]["required_free_bytes"] == 6 * 1024**3
    serialized = json.dumps(receipt)
    for sensitive in (
        config.api_key,
        "/sensitive/docker-command",
        "sensitive stdout",
        "sensitive stderr",
    ):
        assert sensitive not in serialized


def test_canary_preflight_rejects_low_disk_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    monkeypatch.setattr(
        campaign.shutil, "disk_usage", lambda _path: SimpleNamespace(free=2 * 1024**3)
    )
    errors: list[str] = []

    receipt = campaign._disk_preflight(config, errors)

    assert receipt is not None
    assert receipt["required_free_bytes"] == 6 * 1024**3
    assert errors == [f"output filesystem needs at least {6 * 1024**3} free bytes"]


def test_full_preflight_requires_more_headroom_than_one_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(
        campaign.shutil, "disk_usage", lambda _path: SimpleNamespace(free=6 * 1024**3)
    )
    errors: list[str] = []

    receipt = campaign._disk_preflight(config, errors)

    assert receipt is not None
    assert receipt["required_free_bytes"] == 8 * 1024**3
    assert errors == [f"output filesystem needs at least {8 * 1024**3} free bytes"]


def test_full_campaign_builds_once_runs_balanced_pairs_and_retains_sanitized_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _patch_preflight(monkeypatch, config)
    events = _patch_execution(monkeypatch, config)
    checkpoints = 0
    original_checkpoint = campaign._persist_checkpoint

    def counted_checkpoint(*args: Any, **kwargs: Any) -> None:
        nonlocal checkpoints
        checkpoints += 1
        original_checkpoint(*args, **kwargs)

    monkeypatch.setattr(campaign, "_persist_checkpoint", counted_checkpoint)

    result = campaign.run_campaign(config)

    assert result["phase"] == "completed"
    assert len(result["rows"]) == 40
    assert len(events["builds"]) == 20
    assert len(events["starts"]) == 40
    assert len(events["resets"]) == 40
    assert len(events["destroys"]) == 20
    assert events["cache"] == 20
    assert len(set(events["flags"].values())) == 20
    assert checkpoints == 62  # initial + 40 arms + 20 cases + final
    assert Counter(
        next(system for observed_case, system in events["invocations"] if observed_case == case_id)
        for case_id in campaign.FIXED_CASE_IDS
    ) == {"codex_skill": 10, "strix": 10}
    assert all(row["solved"] is True and row["valid"] is True for row in result["rows"])
    assert all(row["request_count"] is None for row in result["rows"])
    assert all(row["declared_candidate_sha256s"] for row in result["rows"])
    assert all(
        row["matched_candidate_sha256"]
        == next(
            item["expected_flag_sha256"]
            for item in result["cases"]
            if item["case_id"] == row["case_id"]
        )
        for row in result["rows"]
    )
    assert all(row["sanitized_runner_receipt_sha256"] for row in result["rows"])
    assert all(row["evidence_manifest_sha256"] for row in result["rows"])
    assert (config.output_dir / "COMPARISON.md").is_file()
    assert (config.output_dir / "report.json").is_file()
    assert all(case["cache_cleanup"]["returncode"] == 0 for case in result["cases"])
    assert "standard-tier list-price estimate" in result["model"]["cost_basis"]
    assert "long-context billing may differ" in result["methodology"]["cost_caveat"]
    assert "warm-up" in result["methodology"]["cost_caveat"]
    assert "raw HTTP request smuggling" in result["methodology"]["system_capability_caveat"]
    assert "browser-based XSS" in result["methodology"]["system_capability_caveat"]
    for instructions in events["instructions"].values():
        assert instructions["codex_skill"] == instructions["strix"]
        assert "same-shape baseline or negative control" in instructions["codex_skill"]
        assert "stop after the exact flag" in instructions["codex_skill"]

    retained = b"".join(
        path.read_bytes() for path in config.output_dir.rglob("*") if path.is_file()
    )
    assert API_KEY.encode() not in retained
    for flag in events["flags"].values():
        assert flag.encode() not in retained
        assert base64.b64encode(flag.encode()) not in retained
    assert b"[REDACTED]" in retained


def test_exact_candidate_scoring_and_timeout_validity() -> None:
    expected = "flag{ravage_cmp_" + "a" * 64 + "}"
    near_match = campaign._score_receipt(
        {
            "status": "completed",
            "duration_seconds": 1,
            "flag_candidates": [expected + "x"],
            "usage": {},
        },
        case_id=campaign.FIXED_CASE_IDS[0],
        level=1,
        system="codex_skill",
        expected_flag=expected,
    )
    timed_out = campaign._score_receipt(
        {
            "status": "timed_out",
            "duration_seconds": 600,
            "flag_candidates": [expected],
            "usage": {},
        },
        case_id=campaign.FIXED_CASE_IDS[0],
        level=1,
        system="strix",
        expected_flag=expected,
    )

    assert near_match["valid"] is True
    assert near_match["solved"] is False
    assert near_match["matched_candidate_sha256"] is None
    assert timed_out["valid"] is False
    assert timed_out["solved"] is False


def test_setup_failure_emits_both_invalid_rows_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    attempts = 0

    def fail_prepare(**kwargs: object) -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("one setup attempt")

    monkeypatch.setattr(campaign.target_runner, "prepare_target", fail_prepare)
    monkeypatch.setattr(
        campaign.target_runner,
        "cleanup_build_cache",
        lambda builder: {"returncode": 0},
    )

    result = campaign.run_campaign(config)

    assert attempts == 1
    assert len(result["rows"]) == 2
    assert {row["system"] for row in result["rows"]} == {"codex_skill", "strix"}
    assert all(row["status"] == "infrastructure_error" for row in result["rows"])
    assert all(row["valid"] is False and row["solved"] is False for row in result["rows"])
    assert (config.output_dir / "CANARY.md").is_file()


def test_one_pair_canary_runs_both_arms_without_docker_or_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_id = campaign.FIXED_CASE_IDS[0]
    config = _config(tmp_path, case_ids=(case_id,))
    _patch_preflight(monkeypatch, config)
    events = _patch_execution(monkeypatch, config)

    result = campaign.run_canary(config, case_id=case_id)

    assert [(row["system"], row["solved"]) for row in result["rows"]] == [
        ("codex_skill", True),
        ("strix", True),
    ]
    assert events["invocations"] == [(case_id, "codex_skill"), (case_id, "strix")]
    assert (config.output_dir / "CANARY.md").is_file()
    assert not (config.output_dir / "COMPARISON.md").exists()


def test_builder_removal_failure_invalidates_completed_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    _patch_execution(monkeypatch, config)

    class UnremovedBuilder(_FakeBuilder):
        def destroy(self) -> dict[str, object]:
            return {"verified": False, "returncode": 1}

    monkeypatch.setattr(campaign.target_runner.BuildxBuilder, "create", lambda: UnremovedBuilder())

    with pytest.raises(campaign.CampaignError, match="builder cleanup failed"):
        campaign.run_campaign(config)

    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "builder_cleanup_error"
    assert checkpoint["cases"][0]["status"] == "infrastructure_error"
    assert len(checkpoint["rows"]) == 2
    assert all(row["valid"] is False and row["solved"] is False for row in checkpoint["rows"])
    assert API_KEY not in json.dumps(checkpoint)


def test_builder_create_failure_stops_before_target_or_paid_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)

    def fail_create() -> None:
        raise RuntimeError("Buildx create failed")

    def fail_if_target_prepared(**kwargs: object) -> None:
        pytest.fail("target preparation must not start without a dedicated builder")

    monkeypatch.setattr(campaign.target_runner.BuildxBuilder, "create", fail_create)
    monkeypatch.setattr(campaign.target_runner, "prepare_target", fail_if_target_prepared)

    with pytest.raises(campaign.CampaignError, match="builder setup failed"):
        campaign.run_campaign(config)

    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "builder_setup_error"
    assert checkpoint["rows"] == []
    assert API_KEY not in json.dumps(checkpoint)


def test_campaign_stops_before_next_case_when_disk_headroom_falls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _patch_preflight(monkeypatch, config)
    events = _patch_execution(monkeypatch, config)
    checks = 0

    def disk_preflight(_config: campaign.CampaignConfig, errors: list[str]) -> dict[str, object]:
        nonlocal checks
        checks += 1
        if checks == 3:
            errors.append("output filesystem needs at least 4294967296 free bytes")
        return {"free_bytes": 2 * 1024**3 if checks == 3 else 10 * 1024**3}

    monkeypatch.setattr(campaign, "_disk_preflight", disk_preflight)

    with pytest.raises(campaign.CampaignError, match="insufficient disk headroom"):
        campaign.run_campaign(config)

    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "disk_headroom_error"
    assert len(checkpoint["cases"]) == 1
    assert len(checkpoint["rows"]) == 2
    assert events["builds"] == [(campaign.FIXED_CASE_IDS[0], 900)]


def test_gpt54_pricing_uses_cached_discount() -> None:
    assert (
        campaign.gpt54_cost_usd(
            input_tokens=1_000_000,
            cached_input_tokens=200_000,
            output_tokens=100_000,
        )
        == 3.55
    )


def test_private_cleanup_failure_prevents_success_and_is_checkpointed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    private_root = tmp_path / "mocked-private-root"
    real_cleanup = campaign._remove_private_campaign_state

    def private_directory(*, prefix: str) -> str:
        assert prefix == "ravage-xben-head-to-head-"
        private_root.mkdir(mode=0o700)
        return str(private_root)

    monkeypatch.setattr(campaign.tempfile, "mkdtemp", private_directory)
    monkeypatch.setattr(
        campaign.target_runner,
        "prepare_target",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("setup failed")),
    )
    monkeypatch.setattr(
        campaign.target_runner,
        "cleanup_build_cache",
        lambda builder: {"returncode": 0},
    )
    monkeypatch.setattr(
        campaign,
        "_remove_private_campaign_state",
        lambda auth_file, private_root: ["mocked unlink failure", "mocked rmtree failure"],
    )

    with pytest.raises(campaign.CampaignError, match="cleanup failed"):
        campaign.run_campaign(config)

    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "credential_cleanup_error"
    assert checkpoint["campaign_errors"] == [
        "mocked unlink failure",
        "mocked rmtree failure",
    ]
    assert API_KEY not in json.dumps(checkpoint)
    assert real_cleanup(private_root / "codex-auth.json", private_root) == []


@pytest.mark.parametrize("requested_signal", [signal.SIGTERM, signal.SIGINT])
def test_signal_during_target_setup_runs_outer_secret_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    requested_signal: signal.Signals,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    installed: dict[signal.Signals, Any] = {}
    private_root = tmp_path / "known-private-root"

    def fake_signal(requested: signal.Signals, handler: Any) -> Any:
        if callable(handler):
            installed[requested] = handler
        return signal.SIG_DFL

    def private_directory(*, prefix: str) -> str:
        private_root.mkdir()
        return str(private_root)

    def interrupted_prepare(**kwargs: object) -> None:
        installed[requested_signal](requested_signal, None)

    monkeypatch.setattr(campaign.signal, "getsignal", lambda requested: signal.SIG_DFL)
    monkeypatch.setattr(campaign.signal, "signal", fake_signal)
    monkeypatch.setattr(campaign.tempfile, "mkdtemp", private_directory)
    monkeypatch.setattr(campaign.target_runner, "prepare_target", interrupted_prepare)
    monkeypatch.setattr(
        campaign.target_runner,
        "cleanup_build_cache",
        lambda builder: {"returncode": 0},
    )

    with pytest.raises(campaign.CampaignError, match="interrupted"):
        campaign.run_campaign(config)

    assert not private_root.exists()
    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "interrupted"
    assert checkpoint["campaign_errors"] == [f"received {requested_signal.name}"]
    assert API_KEY not in json.dumps(checkpoint)


def test_builder_interrupt_still_removes_private_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path, case_ids=(campaign.FIXED_CASE_IDS[0],))
    _patch_preflight(monkeypatch, config)
    _patch_execution(monkeypatch, config)
    private_root = tmp_path / "known-private-root"

    class InterruptedBuilder(_FakeBuilder):
        def destroy(self) -> dict[str, object]:
            raise KeyboardInterrupt

    def private_directory(*, prefix: str) -> str:
        private_root.mkdir()
        return str(private_root)

    monkeypatch.setattr(
        campaign.target_runner.BuildxBuilder, "create", lambda: InterruptedBuilder()
    )
    monkeypatch.setattr(campaign.tempfile, "mkdtemp", private_directory)

    with pytest.raises(KeyboardInterrupt):
        campaign.run_campaign(config)

    assert not private_root.exists()
    checkpoint = json.loads((config.output_dir / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["phase"] == "builder_cleanup_error"
    assert all(row["valid"] is False for row in checkpoint["rows"])
    assert API_KEY not in json.dumps(checkpoint)
