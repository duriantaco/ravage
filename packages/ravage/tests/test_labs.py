from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError

import pytest
from ravage import labs
from ravage.labs import LabCommandError, handle_lab_command, load_lab
from ravage.run_data.brief import load_engagement_brief

EXPECTED_ACME_FLAGS = 4
EXPECTED_FORGEOPS_FLAGS = 6
EXPECTED_NODE_MARKET_FLAGS = 5
EXPECTED_PERIMETER_FLAGS = 5
EXPECTED_SESSION_BOUNDARY_FLAGS = 3
ARGPARSE_ERROR_EXIT = 2


def test_load_repo_lab_manifest() -> None:
    repo_root = Path(__file__).resolve().parents[3]

    lab = load_lab("ravage-acme-box", labs_dir=repo_root / "examples" / "labs")

    assert lab.id == "ravage-acme-box"
    assert lab.default_url == "http://127.0.0.1:8088"
    assert lab.flag_count == EXPECTED_ACME_FLAGS
    assert lab.compose_path.exists()
    assert lab.brief_path.exists()


def test_load_harder_go_lab_manifest() -> None:
    repo_root = Path(__file__).resolve().parents[3]

    lab = load_lab("ravage-forgeops-box", labs_dir=repo_root / "examples" / "labs")

    assert lab.id == "ravage-forgeops-box"
    assert lab.default_url == "http://127.0.0.1:8090"
    assert lab.flag_count == EXPECTED_FORGEOPS_FLAGS
    assert lab.compose_path.exists()
    assert lab.brief_path.exists()


def test_load_node_market_lab_manifest() -> None:
    repo_root = Path(__file__).resolve().parents[3]

    lab = load_lab("ravage-node-market-box", labs_dir=repo_root / "examples" / "labs")

    assert lab.id == "ravage-node-market-box"
    assert lab.default_url == "http://127.0.0.1:8092"
    assert lab.flag_count == EXPECTED_NODE_MARKET_FLAGS
    assert lab.compose_path.exists()
    assert lab.brief_path.exists()


def test_load_perimeter_lab_manifest() -> None:
    repo_root = Path(__file__).resolve().parents[3]

    lab = load_lab("ravage-perimeter-box", labs_dir=repo_root / "examples" / "labs")

    assert lab.id == "ravage-perimeter-box"
    assert lab.default_url == "http://127.0.0.1:8094"
    assert lab.flag_count == EXPECTED_PERIMETER_FLAGS
    assert lab.compose_path.exists()
    assert lab.brief_path.exists()


def test_load_session_boundary_lab_manifest() -> None:
    repo_root = Path(__file__).resolve().parents[3]

    lab = load_lab("ravage-session-boundary-box", labs_dir=repo_root / "examples" / "labs")

    assert lab.id == "ravage-session-boundary-box"
    assert lab.default_url == "http://127.0.0.1:8096"
    assert lab.flag_count == EXPECTED_SESSION_BOUNDARY_FLAGS
    assert lab.compose_path.exists()
    assert lab.brief_path.exists()


def test_perimeter_lab_brief_declares_multi_origin_recon_scope() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    brief = load_engagement_brief(
        repo_root / "examples" / "labs" / "ravage-perimeter-box" / "brief.yaml"
    )

    assert brief.scope.in_scope == [
        "http://127.0.0.1:8094",
        "http://127.0.0.1:8095",
    ]
    assert brief.context["required_capabilities"] == ["port_scan", "dir_bruteforce"]
    assert brief.context["tool_recon"] is True
    assert brief.context["tool_recon_ports"] == "8094,8095"


def test_acme_authenticated_brief_matches_local_lab_contract() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    lab_dir = repo_root / "examples" / "labs" / "ravage-acme-box"

    brief = load_engagement_brief(lab_dir / "brief.authenticated.yaml")

    assert brief.authentication is not None
    [identity] = brief.authentication.identities
    assert identity.alias == "analyst"
    assert identity.flow.kind == "form"
    assert identity.flow.endpoint is not None
    assert identity.flow.endpoint.url == "http://127.0.0.1:8088/login"
    assert identity.health_check.endpoint.url == "http://127.0.0.1:8088/api/me"
    assert identity.flow.secret_refs["username"].key == "RAVAGE_ACME_USERNAME"
    assert identity.flow.secret_refs["password"].key == "RAVAGE_ACME_PASSWORD"


def test_lab_list_prints_available_labs(capsys: pytest.CaptureFixture[str]) -> None:
    repo_root = Path(__file__).resolve().parents[3]

    handle_lab_command(["--labs-dir", str(repo_root / "examples" / "labs"), "list"])

    output = capsys.readouterr().out
    assert "RAVAGE // LABS" in output
    assert "ravage-acme-box" in output
    assert "flags=4" in output
    assert "ravage-forgeops-box" in output
    assert "flags=6" in output
    assert "ravage-node-market-box" in output
    assert "flags=5" in output
    assert "ravage-perimeter-box" in output
    assert "ravage-session-boundary-box" in output


def test_lab_show_does_not_require_project_option(capsys: pytest.CaptureFixture[str]) -> None:
    repo_root = Path(__file__).resolve().parents[3]

    handle_lab_command(
        ["--labs-dir", str(repo_root / "examples" / "labs"), "show", "ravage-forgeops-box"]
    )

    output = capsys.readouterr().out
    assert "RAVAGE // LAB" in output
    assert "ravage-forgeops-box" in output
    assert "flags       6" in output


def test_default_lab_directory_works_outside_checkout_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    handle_lab_command(["list"])

    assert "ravage-acme-box" in capsys.readouterr().out


def test_unknown_lab_has_actionable_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as captured:
        handle_lab_command(["show", "does-not-exist"])

    assert captured.value.code == ARGPARSE_ERROR_EXIT
    error = capsys.readouterr().err
    assert "lab manifest not found" in error
    assert "ravage lab list" in error
    assert "Traceback" not in error


def test_lab_up_waits_and_prints_copy_paste_next_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    calls: list[tuple[object, ...]] = []

    monkeypatch.setattr(labs, "_compose", lambda *args: calls.append(args))
    monkeypatch.setattr(
        labs,
        "_wait_for_health",
        lambda lab, *, timeout_seconds: calls.append(("wait", lab.id, timeout_seconds)),
    )

    handle_lab_command(
        [
            "--labs-dir",
            str(repo_root / "examples" / "labs"),
            "up",
            "ravage-acme-box",
        ]
    )

    assert calls[0][1:] == ("up", "--build", "-d")
    assert calls[1] == ("wait", "ravage-acme-box", 60)
    output = capsys.readouterr().out
    assert "ravage scan" in output
    assert "--probe surface_map --report" in output
    assert "ravage traffic capture http://127.0.0.1:8088" in output
    assert "ravage lab down ravage-acme-box" in output


def test_lab_up_rejects_invalid_wait_before_starting_compose(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(labs, "_compose", lambda *args: calls.append(args))

    with pytest.raises(SystemExit) as captured:
        handle_lab_command(["up", "ravage-acme-box", "--wait-seconds", "0"])

    assert captured.value.code == ARGPARSE_ERROR_EXIT
    assert calls == []
    assert "must be at least 1" in capsys.readouterr().err


def test_lab_health_does_not_treat_404_as_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    lab = load_lab("ravage-acme-box", labs_dir=repo_root / "examples" / "labs")

    class Opener:
        def open(self, _url: str, *, timeout: int) -> object:
            assert timeout == 1
            raise HTTPError(lab.healthcheck, 404, "Not Found", None, None)

    clock = iter((0.0, 0.0, 1.0))
    monkeypatch.setattr(labs, "build_opener", lambda *_handlers: Opener())
    monkeypatch.setattr(labs.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(labs.time, "sleep", lambda _seconds: None)

    with pytest.raises(LabCommandError, match="HTTP 404"):
        labs._wait_for_health(lab, timeout_seconds=1)  # noqa: SLF001


def test_compose_missing_docker_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    lab = load_lab("ravage-acme-box", labs_dir=repo_root / "examples" / "labs")
    monkeypatch.setattr(labs.shutil, "which", lambda _name: None)

    with pytest.raises(LabCommandError, match="ravage doctor --workflow lab"):
        labs._compose(lab, "up", "-d")  # noqa: SLF001
