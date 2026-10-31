# ruff: noqa: PLR2004,SLF001

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

import pytest
from ravage.xben_parts import comparison_adapters as adapters
from ravage.xben_parts.comparison_contracts import (
    COMPARISON_GATEWAY_TOKEN_ENV,
    DESCRIPTION_ENV,
    OUTER_PROCESS_GROUP_ENV,
    OUTER_PROCESS_GROUP_VALUE,
    TARGET_URL_ENV,
    ExternalExecutionLimits,
)


def test_adapter_interpreter_preserves_active_environment_and_imports_module() -> None:
    interpreter = adapters._adapter_interpreter_path()

    assert interpreter == sys.executable
    completed = subprocess.run(  # noqa: S603
        (
            interpreter,
            "-c",
            "import ravage.xben_parts.comparison_adapters as module; assert module.ADAPTER_VERSION",
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    if Path(sys.executable).is_symlink():
        assert interpreter != str(Path(sys.executable).resolve())


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603
        ("git", "-C", str(root), *arguments),  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _trusted_path() -> str:
    git = shutil.which("git")
    assert git is not None
    return str(Path(git).resolve(strict=True).parent.resolve(strict=True))


@pytest.mark.parametrize(
    "value",
    [
        " /usr/bin",
        "/usr/bin\n/bin",
        "/" + "a" * 4096,
    ],
)
def test_trusted_path_rejects_noncanonical_or_unbounded_values(value: str) -> None:
    with pytest.raises(adapters.AdapterConfigurationError, match="trusted PATH"):
        adapters._trusted_path(value)


def test_trusted_path_rejects_missing_nondirectory_symlinked_and_writable_entries(
    tmp_path: Path,
) -> None:
    regular_file = tmp_path / "file"
    regular_file.write_text("not a directory", encoding="utf-8")
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(directory, target_is_directory=True)
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o770)

    for unsafe in (tmp_path / "missing", regular_file, linked, writable):
        with pytest.raises(adapters.AdapterConfigurationError, match="trusted PATH"):
            adapters._trusted_path(str(unsafe))


def _runtime(
    tmp_path: Path,
    name: str,
    *,
    executable_program: str = "raise SystemExit(0)\n",
) -> adapters.PinnedAgentRuntime:
    source = tmp_path / f"{name}-source"
    source.mkdir()
    (source / "agent.py").write_text("SYSTEM = 'fixture'\n", encoding="utf-8")
    (source / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    subprocess.run(  # noqa: S603
        ("git", "init", "--quiet", str(source)),  # noqa: S607
        check=True,
        capture_output=True,
    )
    _git(source, "config", "user.name", "Adapter Test")
    _git(source, "config", "user.email", "adapter@example.invalid")
    _git(source, "remote", "add", "origin", f"https://github.com/example/{name}.git")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "fixture")
    environment_root = tmp_path / f"{name}-environment"
    interpreter = environment_root / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path(sys.executable).resolve())
    executable = environment_root / "bin" / name
    executable.write_text(
        f"#!{interpreter.absolute()}\n{executable_program}",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    site_packages = environment_root / "lib" / "python" / "site-packages"
    package = site_packages / f"{name}_fixture"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = '1.0'\n", encoding="utf-8")
    dist_info = site_packages / f"{name}_fixture-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}-fixture\nVersion: 1.0\n",
        encoding="utf-8",
    )
    (dist_info / "direct_url.json").write_text(
        json.dumps(
            {
                "url": source.resolve().as_uri(),
                "dir_info": {"editable": True},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest_document = adapters._runtime_environment_document(
        interpreter=interpreter,
        lockfile=source / "uv.lock",
        site_packages=(site_packages,),
        source_root=source,
    )
    manifest_body = adapters._canonical_json(manifest_document)
    manifest = tmp_path / f"{name}-runtime-environment.json"
    manifest.write_bytes(manifest_body)
    manifest_digest = adapters._sha256_bytes(manifest_body)
    digest = adapters._sha256_file(executable)
    assert digest is not None
    return adapters.PinnedAgentRuntime(
        executable=executable,
        executable_sha256=digest,
        source_root=source,
        source_commit=_git(source, "rev-parse", "HEAD"),
        source_tree=_git(source, "rev-parse", "HEAD^{tree}"),
        source_origin_url=f"https://github.com/example/{name}.git",
        runtime_environment_manifest=manifest,
        runtime_environment_manifest_sha256=manifest_digest,
    )


def _gateway() -> adapters.RowModelGateway:
    return adapters.RowModelGateway(
        base_url="http://model-gateway.internal:8080/v1/",
        token="row-token-" + "x" * 64,
        model="gpt-test-fixed",
        reasoning_effort="high",
        pricing=adapters.GatewayPricing(
            input_per_million="1.25",
            cached_input_per_million="0.125",
            output_per_million="7.50",
        ),
        max_output_tokens=4096,
    )


def _limits() -> ExternalExecutionLimits:
    return ExternalExecutionLimits(
        wall_seconds=120,
        max_model_requests=24,
        max_target_requests=300,
        max_cost_usd=Decimal("2.5000"),
    )


_VISIBLE_DESCRIPTION = (
    "A small web application accepts user-controlled input and exposes a proof after "
    "successful exploitation."
)
_DOCKER_HOST = "unix:///var/run/docker.sock"


def _launch(agent_command: tuple[str, ...]) -> adapters.AdapterLaunch:
    assert agent_command[-2] == "--launch-spec"
    return adapters._decode_launch_spec(agent_command[-1])


def test_ravage_adapter_is_deterministic_and_keeps_row_token_out_of_argv(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    first = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    second = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    serialized_command = json.dumps(first.command)
    raw_launch = json.loads(base64.b64decode(first.command[-1], altchars=b"-_", validate=True))

    assert first == second
    assert first.system_id == "ravage"
    assert first.artifact_path == adapters.CANDIDATE_ARTIFACT_PATH
    assert gateway.token not in serialized_command
    assert first.environment == {
        COMPARISON_GATEWAY_TOKEN_ENV: gateway.token,
        adapters.GATEWAY_BASE_URL_ENV: "http://model-gateway.internal:8080/v1",
        OUTER_PROCESS_GROUP_ENV: OUTER_PROCESS_GROUP_VALUE,
    }
    assert set(first.environment_allowlist) == set(first.environment)
    assert raw_launch["limits"]["max_cost_usd"] == "2.5"
    assert not isinstance(raw_launch["limits"]["max_cost_usd"], float)
    launch = _launch(first.command)
    assert launch.limits.max_cost_usd == Decimal("2.5")
    assert launch.docker_host == _DOCKER_HOST
    assert launch.runtime.executable_sha256 == runtime.executable_sha256
    assert launch.runtime.source_commit == runtime.source_commit
    assert launch.runtime.source_tree == runtime.source_tree
    for forbidden in (
        "XBEN-007-24",
        "flag{expected-value-never-disclosed}",
        "/private/benchmark/source/XBEN-007-24",
    ):
        assert forbidden not in serialized_command


def test_runtime_identity_rejects_executable_and_source_substitution(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "strix")
    adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())
    original_executable = runtime.executable.read_text(encoding="utf-8")
    runtime.executable.write_text(original_executable + "# changed\n", encoding="utf-8")

    with pytest.raises(adapters.AdapterIdentityError, match="executable SHA-256"):
        adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())

    runtime.executable.write_text(original_executable, encoding="utf-8")
    (runtime.source_root / "agent.py").write_text("SYSTEM = 'substitute'\n", encoding="utf-8")
    with pytest.raises(adapters.AdapterIdentityError, match="worktree is not clean"):
        adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())


def test_runtime_identity_rejects_git_ignored_and_assume_unchanged_source_bytes(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    ignored = runtime.source_root / "ignored.py"
    (runtime.source_root / ".git" / "info" / "exclude").write_text(
        "ignored.py\n",
        encoding="utf-8",
    )
    ignored.write_text("SYSTEM = 'ignored substitution'\n", encoding="utf-8")

    # Git's normal clean-worktree predicate intentionally suppresses this path;
    # the adapter's literal checkout verifier must still reject executable
    # bytes that are absent from the pinned tree.
    assert _git(runtime.source_root, "status", "--porcelain=v1", "--untracked-files=all") == ""
    with pytest.raises(adapters.AdapterIdentityError, match="bytes absent from HEAD"):
        adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())

    ignored.unlink()
    tracked = runtime.source_root / "agent.py"
    tracked.write_text("SYSTEM = 'assume-unchanged substitution'\n", encoding="utf-8")
    _git(runtime.source_root, "update-index", "--assume-unchanged", "agent.py")
    assert _git(runtime.source_root, "status", "--porcelain=v1", "--untracked-files=all") == ""
    with pytest.raises(adapters.AdapterIdentityError, match="bytes differ from HEAD"):
        adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())


def test_runtime_identity_rejects_caller_owned_git_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setattr(adapters, "_SYSTEM_GIT", fake_git)

    with pytest.raises(adapters.AdapterIdentityError, match="root-controlled"):
        adapters.verify_pinned_runtime(runtime, trusted_path=str(tmp_path))


def test_runtime_environment_manifest_binds_required_identity_dimensions(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    document = json.loads(runtime.runtime_environment_manifest.read_text(encoding="utf-8"))

    assert document["expected_install_command"] == ["uv", "sync", "--frozen"]
    assert Path(document["interpreter"]["realpath"]) == Path(sys.executable).resolve()
    assert document["interpreter"]["sha256"] == adapters._sha256_file(
        Path(sys.executable).resolve()
    )
    assert Path(document["lockfile"]["path"]) == (runtime.source_root / "uv.lock").resolve()
    assert document["lockfile"]["sha256"] == adapters._sha256_file(runtime.source_root / "uv.lock")
    assert document["distributions"] == [
        {
            "name": "ravage-fixture",
            "version": "1.0",
            "direct_url_sha256": document["distributions"][0]["direct_url_sha256"],
            "editable_source_root": str(runtime.source_root.resolve()),
        }
    ]
    assert document["distribution_inventory_sha256"] == adapters._sha256_bytes(
        adapters._canonical_json(document["distributions"])
    )
    assert document["editable_source_roots"] == [str(runtime.source_root.resolve())]
    assert document["site_packages_file_count"] == 3


def test_runtime_environment_manifest_rejects_dependency_tamper(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    manifest = json.loads(runtime.runtime_environment_manifest.read_text(encoding="utf-8"))
    site_packages = Path(manifest["site_packages"][0])
    package_file = site_packages / "ravage_fixture" / "__init__.py"

    package_file.write_text("VERSION = 'substituted'\n", encoding="utf-8")
    with pytest.raises(adapters.AdapterIdentityError, match="no longer matches"):
        adapters.verify_pinned_runtime(runtime, trusted_path=_trusted_path())


@pytest.mark.parametrize("suffix", [".pth", ".egg-link"])
def test_runtime_path_configuration_rejects_unresolved_entries(
    tmp_path: Path,
    suffix: str,
) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (site_packages / f"broken{suffix}").write_text("../missing-source\n", encoding="utf-8")

    with pytest.raises(adapters.AdapterConfigurationError, match="unresolved path"):
        adapters._editable_sources_from_path_files((site_packages,), source_root=source)


def test_runtime_path_configuration_rejects_malformed_egg_link(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (site_packages / "broken.egg-link").write_text("# no path\n", encoding="utf-8")

    with pytest.raises(adapters.AdapterConfigurationError, match="contains no path entry"):
        adapters._editable_sources_from_path_files((site_packages,), source_root=source)


def test_runtime_path_configuration_rejects_non_directory_entry(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    not_a_directory = tmp_path / "module.py"
    not_a_directory.write_text("VALUE = 1\n", encoding="utf-8")
    (site_packages / "broken.pth").write_text(str(not_a_directory), encoding="utf-8")

    with pytest.raises(adapters.AdapterConfigurationError, match="not a directory"):
        adapters._editable_sources_from_path_files((site_packages,), source_root=source)


def test_exclusive_write_removes_partial_file_after_write_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence.json"
    real_write = os.write
    calls = 0

    def failing_write(descriptor: int, body: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, body[:1])
        raise OSError("injected write failure")

    monkeypatch.setattr(os, "write", failing_write)

    with pytest.raises(adapters.AdapterEvidenceError, match="write failed"):
        adapters._write_bytes_exclusive(output, b"partial")
    assert not output.exists()


def test_exclusive_write_removes_file_after_fsync_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence.json"
    monkeypatch.setattr(
        os,
        "fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError("injected fsync failure")),
    )

    with pytest.raises(adapters.AdapterEvidenceError, match="write failed"):
        adapters._write_bytes_exclusive(output, b"complete-but-not-durable")
    assert not output.exists()


def test_exclusive_write_never_removes_an_existing_or_replacement_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"existing")
    with pytest.raises(adapters.AdapterEvidenceError, match="refusing to replace"):
        adapters._write_bytes_exclusive(existing, b"new")
    assert existing.read_bytes() == b"existing"

    output = tmp_path / "raced.json"

    def replace_then_fail(_descriptor: int, _body: bytes | memoryview) -> int:
        output.unlink()
        output.write_bytes(b"replacement")
        raise OSError("injected replacement race")

    monkeypatch.setattr(os, "write", replace_then_fail)
    with pytest.raises(adapters.AdapterEvidenceError, match="write failed"):
        adapters._write_bytes_exclusive(output, b"partial")
    assert output.read_bytes() == b"replacement"


def test_identity_reader_enforces_limit_during_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = tmp_path / "identity"
    identity.write_bytes(b"abc")
    real_read = os.read
    mutated = False

    def growing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, maximum_bytes)
        if chunk and not mutated:
            mutated = True
            with identity.open("ab") as output:
                output.write(b"de")
        return chunk

    monkeypatch.setattr(adapters, "_MAX_RUNTIME_MANIFEST_BYTES", 3)
    monkeypatch.setattr(os, "read", growing_read)

    with pytest.raises(adapters.AdapterConfigurationError, match="changed while reading"):
        adapters._read_identity_bytes(identity, "test identity")


def test_identity_reader_rejects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = tmp_path / "identity"
    identity.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    real_read = os.read
    replaced = False

    def replacing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, maximum_bytes)
        if chunk and not replaced:
            replaced = True
            replacement.replace(identity)
        return chunk

    monkeypatch.setattr(os, "read", replacing_read)

    with pytest.raises(adapters.AdapterConfigurationError, match="changed while reading"):
        adapters._read_identity_bytes(identity, "test identity")


def test_file_hasher_enforces_limit_during_growth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = tmp_path / "identity"
    identity.write_bytes(b"abc")
    real_read = os.read
    mutated = False

    def growing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, maximum_bytes)
        if chunk and not mutated:
            mutated = True
            with identity.open("ab") as output:
                output.write(b"de")
        return chunk

    monkeypatch.setattr(adapters, "_MAX_IDENTITY_FILE_BYTES", 3)
    monkeypatch.setattr(os, "read", growing_read)

    assert adapters._sha256_file(identity) is None


def test_file_hasher_rejects_path_replacement_and_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = tmp_path / "identity"
    identity.write_bytes(b"original")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement")
    real_read = os.read
    replaced = False

    def replacing_read(descriptor: int, maximum_bytes: int) -> bytes:
        nonlocal replaced
        chunk = real_read(descriptor, maximum_bytes)
        if chunk and not replaced:
            replaced = True
            replacement.replace(identity)
        return chunk

    monkeypatch.setattr(os, "read", replacing_read)
    assert adapters._sha256_file(identity) is None

    link = tmp_path / "identity-link"
    link.symlink_to(identity)
    assert adapters._sha256_file(link) is None
    with pytest.raises(adapters.AdapterConfigurationError, match="unreadable or changed"):
        adapters._read_identity_bytes(link, "linked identity")


def test_runtime_manifest_rejects_unexpected_editable_source(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "strix")
    manifest = json.loads(runtime.runtime_environment_manifest.read_text(encoding="utf-8"))
    site_packages = Path(manifest["site_packages"][0])
    unrelated = tmp_path / "unrelated-editable"
    unrelated.mkdir()
    direct_url = next(site_packages.glob("*.dist-info")) / "direct_url.json"
    direct_url.write_text(
        json.dumps({"url": unrelated.resolve().as_uri(), "dir_info": {"editable": True}}),
        encoding="utf-8",
    )

    with pytest.raises(adapters.AdapterConfigurationError, match="unexpected editable"):
        adapters._runtime_environment_document(
            interpreter=Path(manifest["interpreter"]["path"]),
            lockfile=Path(manifest["lockfile"]["path"]),
            site_packages=(site_packages,),
            source_root=runtime.source_root,
        )


def test_ravage_uses_generic_brief_gateway_route_and_supported_public_attack_path(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    launch = _launch(agent.command)
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    layout = adapters._claim_layout(native_output)
    target_url = "http://target-gateway.internal:8081"

    command, child_cwd = adapters._prepare_ravage(
        launch=launch,
        layout=layout,
        target_url=target_url,
        gateway_base_url="http://model-gateway.internal:8080/v1",
        semantic_prompt=adapters._semantic_prompt(_VISIBLE_DESCRIPTION),
    )
    brief = json.loads((layout.work / "brief.json").read_text(encoding="utf-8"))
    brief_bytes = (layout.work / "brief.json").read_bytes()
    models = json.loads((layout.work / "models.json").read_text(encoding="utf-8"))

    assert child_cwd == layout.work
    assert command[0] == str(runtime.executable.resolve())
    assert command[1:3] == ("attack", str(layout.work / "brief.json"))
    for required in (
        "--agent-mode",
        "ctf-free-roam",
        "--autonomous-route",
        "--autonomous-route-engine",
        "agent-graph",
        "--operational-profile",
        "standard",
        "--tool-recon",
        "--tool-runtime",
        "docker",
    ):
        assert required in command
    assert "--source-root" not in command
    assert "--resume" not in command
    planner_index = command.index("--graph-planner-mode")
    assert command[planner_index + 1] == "legacy"
    assert brief["scope"] == {"in_scope": [target_url], "out_of_scope": []}
    # The pinned Ravage brief schema is strict-float. Keep that compatibility
    # conversion explicit and prove its JSON spelling matches the exact limit.
    assert brief["budget"]["max_cost_usd"] == 2.5
    assert b'"max_cost_usd":2.5' in brief_bytes
    assert brief["context"]["description"] == adapters._semantic_prompt(_VISIBLE_DESCRIPTION)
    encoded_brief = json.dumps(brief)
    assert "XBEN-" not in encoded_brief
    assert "flag{expected-value-never-disclosed}" not in encoded_brief
    route = models["profiles"]["paired-row-gateway"]["routes"]["high"][0]
    assert route["provider"] == "custom_openai"
    assert route["base_url"] == "http://model-gateway.internal:8080/v1"
    assert route["api_key_env"] == "OPENAI_API_KEY"
    assert gateway.token not in json.dumps(models)


def test_both_systems_receive_byte_equivalent_semantic_prompt_payloads(
    tmp_path: Path,
) -> None:
    ravage_root = tmp_path / "ravage"
    strix_root = tmp_path / "strix"
    ravage_root.mkdir()
    strix_root.mkdir()
    ravage_runtime = _runtime(ravage_root, "ravage")
    strix_runtime = _runtime(strix_root, "strix")
    gateway = _gateway()
    ravage = adapters.build_ravage_agent(
        runtime=ravage_runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    strix = adapters.build_strix_agent(
        runtime=strix_runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        sandbox_image="registry.invalid/strix-sandbox@sha256:" + "b" * 64,
        sandbox_network="paired_agent_net",
        docker_host=_DOCKER_HOST,
    )
    description = "Unicode café behavior is visible.\nTest the documented login flow exactly."
    shared_prompt = adapters._semantic_prompt(description)
    ravage_output = tmp_path / "ravage-output"
    strix_output = tmp_path / "strix-output"
    ravage_output.mkdir()
    strix_output.mkdir()
    ravage_layout = adapters._claim_layout(ravage_output)
    strix_layout = adapters._claim_layout(strix_output)
    ravage_target = "http://ravage-target.internal:8081"
    strix_target = "http://strix-target.internal:8081"

    adapters._prepare_ravage(
        launch=_launch(ravage.command),
        layout=ravage_layout,
        target_url=ravage_target,
        gateway_base_url="http://model-gateway.internal:8080/v1",
        semantic_prompt=shared_prompt,
    )
    strix_command, _ = adapters._prepare_strix(
        launch=_launch(strix.command),
        layout=strix_layout,
        target_url=strix_target,
        semantic_prompt=shared_prompt,
    )
    ravage_brief = json.loads((ravage_layout.work / "brief.json").read_text(encoding="utf-8"))
    ravage_prompt = ravage_brief["context"]["description"]
    instruction_index = strix_command.index("--instruction")
    strix_prompt = strix_command[instruction_index + 1]

    assert ravage_prompt.encode("utf-8") == strix_prompt.encode("utf-8")
    assert ravage_prompt == shared_prompt
    assert f"<target_description>\n{description}\n</target_description>" in shared_prompt
    assert ravage_target not in shared_prompt
    assert strix_target not in shared_prompt
    assert ravage_brief["context"]["win_condition"] == adapters._GENERIC_OBJECTIVE
    assert ravage_brief["context"]["rules"] == list(adapters._GENERIC_RULES)


@pytest.mark.parametrize(
    "description",
    [
        "XBEN-007-24 evaluator-only case details",
        "The expected result is flag{never-disclose-this}",
        "Read /private/benchmark/source/app.py to solve it",
    ],
)
def test_semantic_prompt_rejects_evaluator_only_identifiers_values_and_paths(
    description: str,
) -> None:
    with pytest.raises(adapters.AdapterConfigurationError):
        adapters._semantic_prompt(description)


def test_strix_uses_noninteractive_deep_scan_and_sanitized_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, "strix")
    gateway = _gateway()
    agent = adapters.build_strix_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        sandbox_image="registry.invalid/strix-sandbox@sha256:" + "b" * 64,
        sandbox_network="paired_agent_net",
        docker_host=_DOCKER_HOST,
    )
    launch = _launch(agent.command)
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    layout = adapters._claim_layout(native_output)
    target_url = "http://target-gateway.internal:8081"
    command, child_cwd = adapters._prepare_strix(
        launch=launch,
        layout=layout,
        target_url=target_url,
        semantic_prompt=adapters._semantic_prompt(_VISIBLE_DESCRIPTION),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-key-must-not-survive")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-anthropic-must-not-survive")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid")
    monkeypatch.setenv("DOCKER_HOST", "tcp://ambient-daemon.invalid:2375")
    child_environment = adapters._child_environment(
        launch=launch,
        layout=layout,
        gateway_base_url="http://model-gateway.internal:8080/v1",
        gateway_token=gateway.token,
    )

    assert child_cwd == layout.run_root
    assert command == (
        str(runtime.executable.resolve()),
        "--target",
        target_url,
        "--instruction",
        adapters._semantic_prompt(_VISIBLE_DESCRIPTION),
        "--non-interactive",
        "--scan-mode",
        "deep",
        "--scope-mode",
        "full",
        "--config",
        str(layout.work / "strix-config.json"),
        "--max-budget-usd",
        "2.5",
        "--max-turns",
        "24",
    )
    assert json.loads((layout.work / "strix-config.json").read_text(encoding="utf-8")) == {
        "env": {}
    }
    assert child_environment["HOME"] == str(layout.home)
    assert child_environment["OPENAI_API_KEY"] == gateway.token
    assert child_environment["LLM_API_KEY"] == gateway.token
    assert child_environment["OPENAI_BASE_URL"] == "http://model-gateway.internal:8080/v1"
    assert child_environment["LLM_API_BASE"] == "http://model-gateway.internal:8080/v1"
    assert child_environment["STRIX_LLM"] == "openai/gpt-test-fixed"
    assert child_environment["STRIX_REASONING_EFFORT"] == "high"
    assert child_environment["STRIX_TELEMETRY"] == "false"
    assert child_environment["STRIX_DOCKER_SANDBOX_NETWORK"] == "paired_agent_net"
    assert child_environment["DOCKER_CONFIG"] == str(layout.home / ".docker")
    assert child_environment["DOCKER_HOST"] == _DOCKER_HOST
    assert "ANTHROPIC_API_KEY" not in child_environment
    assert "HTTPS_PROXY" not in child_environment
    assert "HTTP_PROXY" not in child_environment
    assert "ALL_PROXY" not in child_environment
    assert "NO_PROXY" not in child_environment
    assert "ambient-key-must-not-survive" not in child_environment.values()


@pytest.mark.parametrize(
    "docker_host",
    [
        "tcp://127.0.0.1:2375",
        "ssh://docker@example.invalid",
        "unix://relative/socket",
        "unix:///",
        "unix:////var/run/docker.sock",
        "unix:///var/run/../run/docker.sock",
        "unix:///var/run/docker%2Esock",
        "unix:///var/run/docker.sock ",
    ],
)
def test_adapter_rejects_nonlocal_or_noncanonical_docker_hosts(docker_host: str) -> None:
    with pytest.raises(adapters.AdapterConfigurationError, match="canonical local Unix"):
        adapters._validated_docker_host(docker_host)


def test_launch_decoder_rejects_docker_host_substitution(tmp_path: Path) -> None:
    agent = adapters.build_ravage_agent(
        runtime=_runtime(tmp_path, "ravage"),
        gateway=_gateway(),
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    raw = base64.urlsafe_b64decode(agent.command[-1])
    launch = json.loads(raw)
    launch["docker_host"] = "tcp://127.0.0.1:2375"
    substituted = base64.urlsafe_b64encode(
        json.dumps(launch, sort_keys=True, separators=(",", ":")).encode()
    ).decode()

    with pytest.raises(adapters.AdapterConfigurationError, match="canonical local Unix"):
        adapters._decode_launch_spec(substituted)


def test_layout_and_candidate_artifact_are_create_only(tmp_path: Path) -> None:
    root = tmp_path / "native-output"
    root.mkdir()
    layout = adapters._claim_layout(root)

    assert layout.home.is_dir()
    assert layout.work.is_dir()
    assert layout.run_root.is_dir()
    assert layout.temporary.is_dir()
    with pytest.raises(adapters.AdapterEvidenceError, match="empty directory"):
        adapters._claim_layout(root)

    candidate_path = root / adapters.CANDIDATE_ARTIFACT_PATH
    adapters._write_candidate_artifact(candidate_path, (b"flag{b}", b"flag{a}"))
    assert candidate_path.read_bytes() == b"flag{a}\nflag{b}\n"
    with pytest.raises(adapters.AdapterEvidenceError, match="refusing to replace"):
        adapters._write_candidate_artifact(candidate_path, (b"flag{replacement}",))
    assert candidate_path.read_bytes() == b"flag{a}\nflag{b}\n"


def test_strix_persisted_row_gateway_credential_is_redacted(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "strix")
    gateway = _gateway()
    agent = adapters.build_strix_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        sandbox_image="registry.invalid/strix-sandbox@sha256:" + "b" * 64,
        sandbox_network="paired_agent_net",
        docker_host=_DOCKER_HOST,
    )
    launch = _launch(agent.command)
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    layout = adapters._claim_layout(native_output)
    adapters._prepare_strix(
        launch=launch,
        layout=layout,
        target_url="http://target-gateway.internal:8081",
        semantic_prompt=adapters._semantic_prompt(_VISIBLE_DESCRIPTION),
    )
    config = layout.work / "strix-config.json"
    config.write_text(
        json.dumps({"env": {"LLM_API_KEY": gateway.token}}),
        encoding="utf-8",
    )

    redacted = adapters._sanitize_known_credential_artifacts(
        launch=launch,
        layout=layout,
        gateway_token=gateway.token,
    )

    assert redacted == 1
    assert gateway.token not in config.read_text(encoding="utf-8")
    assert "[REDACTED ROW CREDENTIAL]" in config.read_text(encoding="utf-8")


def test_artifact_extraction_is_sorted_unique_bounded_and_expected_flag_agnostic(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "agent-run"
    nested = run_root / "nested"
    nested.mkdir(parents=True)
    (run_root / "z.txt").write_bytes(b"noise flag{zulu} ctf{alpha} flag{zulu}")
    (nested / "a.json").write_bytes(b'{"proof":"XBEN{bravo}"}')

    candidates, complete, scanned = adapters.extract_artifact_candidates((run_root,))

    assert complete is True
    assert candidates == (b"XBEN{bravo}", b"ctf{alpha}", b"flag{zulu}")
    assert scanned["files"] == 2
    assert scanned["bytes"] > 0
    assert "expected" not in adapters.extract_artifact_candidates.__code__.co_varnames

    _, overflow_complete, _ = adapters.extract_artifact_candidates(
        (run_root,),
        maximum_bytes=4,
    )
    assert overflow_complete is False


def test_artifact_extraction_fails_closed_for_missing_or_symlinked_roots_and_files(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"
    assert adapters.extract_artifact_candidates((missing,))[1] is False

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    assert adapters.extract_artifact_candidates((linked_root,))[1] is False

    outside = tmp_path / "outside.txt"
    outside.write_text("flag{outside}", encoding="utf-8")
    (real_root / "escape.txt").symlink_to(outside)
    candidates, complete, _scanned = adapters.extract_artifact_candidates((real_root,))
    assert candidates == ()
    assert complete is False


def test_process_capture_stays_bounded_but_extracts_late_and_cross_chunk_flags(
    tmp_path: Path,
) -> None:
    prefix = "A" * (adapters._READ_CHUNK_BYTES - 3)
    script = (
        "import sys;"
        f"sys.stdout.write({prefix!r} + 'flag{{cross_chunk}}' + 'B' * 5000);"
        "sys.stderr.write('ctf{stderr_proof}')"
    )
    result = adapters.run_bounded_process(
        (sys.executable, "-c", script),
        cwd=tmp_path,
        environment={"PATH": _trusted_path()},
        timeout_seconds=5,
        maximum_retained_bytes=32,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.extraction_complete is True
    assert result.stdout == b"A" * 32
    assert result.stdout_truncated is True
    assert result.stdout_total_bytes > len(result.stdout)
    assert result.candidates == (b"ctf{stderr_proof}", b"flag{cross_chunk}")


def test_process_timeout_kills_group_within_bounded_time(tmp_path: Path) -> None:
    started = time.monotonic()
    result = adapters.run_bounded_process(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        cwd=tmp_path,
        environment={"PATH": _trusted_path()},
        timeout_seconds=0.05,
        maximum_retained_bytes=32,
    )

    assert result.timed_out is True
    assert result.returncode < 0
    assert result.stdout_complete is True
    assert result.stderr_complete is True
    assert result.extraction_complete is True
    assert time.monotonic() - started < 3


def test_process_timeout_marks_capture_incomplete_when_descendant_holds_pipes_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A surviving descendant must not turn a partial timeout capture into evidence."""
    holder_pid_path = tmp_path / "holder.pid"
    program = tmp_path / "spawn-holder.py"
    program.write_text(
        """import pathlib, subprocess, sys, time
child = subprocess.Popen(
    [sys.executable, '-c', 'import time; time.sleep(30)'],
    stdout=sys.stdout, stderr=sys.stderr, start_new_session=True,
)
pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')
time.sleep(30)
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(adapters, "_PROCESS_TERMINATE_GRACE_SECONDS", 0.1)

    try:
        result = adapters.run_bounded_process(
            (sys.executable, str(program), str(holder_pid_path)),
            cwd=tmp_path,
            environment={"PATH": _trusted_path()},
            timeout_seconds=0.5,
            maximum_retained_bytes=32,
            create_process_group=False,
        )
    finally:
        if holder_pid_path.is_file():
            holder_pid = int(holder_pid_path.read_text(encoding="ascii"))
            with contextlib.suppress(ProcessLookupError):
                os.kill(holder_pid, signal.SIGKILL)

    assert result.timed_out is True
    assert result.stdout_complete is False
    assert result.stderr_complete is False
    assert result.extraction_complete is False


def test_process_timeout_does_not_allow_sigterm_handler_to_write_late_artifact(
    tmp_path: Path,
) -> None:
    late_artifact = tmp_path / "late-artifact.txt"
    script = (
        "import pathlib,signal,time;"
        f"path=pathlib.Path({str(late_artifact)!r});"
        "signal.signal(signal.SIGTERM, lambda *_: path.write_text('late'));"
        "time.sleep(30)"
    )

    result = adapters.run_bounded_process(
        (sys.executable, "-c", script),
        cwd=tmp_path,
        environment={"PATH": _trusted_path()},
        timeout_seconds=0.05,
        maximum_retained_bytes=32,
    )

    assert result.timed_out is True
    assert result.returncode < 0
    assert not late_artifact.exists()


def test_gateway_environment_binding_rejects_token_or_route_substitution(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    launch = _launch(agent.command)

    with pytest.raises(adapters.AdapterConfigurationError, match="token does not match"):
        adapters._bound_gateway_environment(
            launch,
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: "substitute-" + "q" * 64,
                adapters.GATEWAY_BASE_URL_ENV: gateway.base_url,
            },
        )
    with pytest.raises(adapters.AdapterConfigurationError, match="URL does not match"):
        adapters._bound_gateway_environment(
            launch,
            environment={
                COMPARISON_GATEWAY_TOKEN_ENV: gateway.token,
                adapters.GATEWAY_BASE_URL_ENV: "https://api.openai.com/v1",
            },
        )


def test_execute_wrapper_uses_exact_sanitized_description_and_binds_its_digest(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    environment = {
        **agent.environment,
        TARGET_URL_ENV: "http://target-gateway.internal:8081",
        DESCRIPTION_ENV: _VISIBLE_DESCRIPTION,
    }

    returncode, receipt = adapters.execute_launch_spec(
        agent.command[-1],
        cwd=native_output,
        environment=environment,
    )

    assert returncode == 0
    assert receipt["wrapper_returncode"] == returncode
    assert receipt["process_group_policy"] == "joined_evaluator_outer_group"
    assert receipt["gateway"] == gateway.public_json()
    assert receipt["limits"] == _limits().to_json()
    assert receipt["docker_host_sha256"] == adapters._sha256_text(_DOCKER_HOST)
    capture = receipt["capture"]
    assert isinstance(capture, dict)
    assert capture["stdout"]["complete"] is True
    assert capture["stderr"]["complete"] is True
    candidate_extraction = receipt["candidate_extraction"]
    assert isinstance(candidate_extraction, dict)
    assert candidate_extraction["expected_flag_used"] is False
    assert (native_output / adapters.CANDIDATE_ARTIFACT_PATH).read_bytes() == b""
    assert (native_output / adapters.ADAPTER_RESULT_PATH).is_file()
    assert not (native_output / "agent-run" / adapters.CANDIDATE_ARTIFACT_PATH).exists()
    brief = json.loads((native_output / "adapter-work" / "brief.json").read_text(encoding="utf-8"))
    assert brief["context"]["description"] == adapters._semantic_prompt(_VISIBLE_DESCRIPTION)
    input_contract = receipt["input_contract"]
    assert isinstance(input_contract, dict)
    assert input_contract["mode"] == "description-only-black-box"
    assert input_contract["description_sha256"] == adapters._sha256_text(_VISIBLE_DESCRIPTION)
    assert input_contract["semantic_prompt_sha256"] == adapters._sha256_text(
        adapters._semantic_prompt(_VISIBLE_DESCRIPTION)
    )
    runtime_receipt = receipt["runtime"]
    assert isinstance(runtime_receipt, dict)
    assert runtime_receipt["source_origin_url"] == runtime.source_origin_url
    assert receipt["tool_image"] == "registry.invalid/ravage-tools@sha256:" + "a" * 64
    assert _VISIBLE_DESCRIPTION not in json.dumps(receipt)


def test_execute_wrapper_never_extracts_candidates_after_inner_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    late_candidate = b"flag{written-by-descendant-after-timeout}"
    monkeypatch.setattr(
        adapters,
        "run_bounded_process",
        lambda *_args, **_kwargs: adapters.BoundedProcessResult(
            returncode=-9,
            timed_out=True,
            stdout=late_candidate,
            stderr=b"",
            stdout_total_bytes=len(late_candidate),
            stderr_total_bytes=0,
            stdout_sha256=adapters._sha256_bytes(late_candidate),
            stderr_sha256=adapters._sha256_bytes(b""),
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_complete=True,
            stderr_complete=True,
            candidates=(late_candidate,),
            extraction_complete=True,
        ),
    )

    def unexpected_scan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("timed-out agent artifacts must not be scanned")

    monkeypatch.setattr(adapters, "extract_artifact_candidates", unexpected_scan)

    returncode, receipt = adapters.execute_launch_spec(
        agent.command[-1],
        cwd=native_output,
        environment={
            **agent.environment,
            TARGET_URL_ENV: "http://target-gateway.internal:8081",
            DESCRIPTION_ENV: _VISIBLE_DESCRIPTION,
        },
    )

    assert returncode == 124
    assert receipt["status"] == "timed_out"
    assert receipt["wrapper_returncode"] == 124
    capture = receipt["capture"]
    assert isinstance(capture, dict)
    assert capture["stdout"]["complete"] is True
    assert capture["stderr"]["complete"] is True
    extraction = receipt["candidate_extraction"]
    assert isinstance(extraction, dict)
    assert extraction == {
        "complete": False,
        "candidate_count": 0,
        "artifact_path": None,
        "scanned_artifact_files": 0,
        "scanned_artifact_bytes": 0,
        "scanned_roots": ["agent-run", "adapter-home", "adapter-work", "adapter-tmp"],
        "expected_flag_used": False,
    }
    assert not (native_output / adapters.CANDIDATE_ARTIFACT_PATH).exists()


def test_execute_wrapper_never_persists_gateway_token_as_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    contaminated = f"flag{{{gateway.token}}}".encode()
    monkeypatch.setattr(
        adapters,
        "run_bounded_process",
        lambda *_args, **_kwargs: adapters.BoundedProcessResult(
            returncode=0,
            timed_out=False,
            stdout=contaminated,
            stderr=b"",
            stdout_total_bytes=len(contaminated),
            stderr_total_bytes=0,
            stdout_sha256=hashlib.sha256(contaminated).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_complete=True,
            stderr_complete=True,
            candidates=(contaminated,),
            extraction_complete=True,
        ),
    )

    returncode, receipt = adapters.execute_launch_spec(
        agent.command[-1],
        cwd=native_output,
        environment={
            **agent.environment,
            TARGET_URL_ENV: "http://target-gateway.internal:8081",
            DESCRIPTION_ENV: _VISIBLE_DESCRIPTION,
        },
    )

    assert returncode == 125
    assert receipt["wrapper_returncode"] == 125
    extraction = receipt["candidate_extraction"]
    assert isinstance(extraction, dict)
    assert extraction["complete"] is False
    assert extraction["candidate_count"] == 0
    assert extraction["artifact_path"] is None
    assert not (native_output / adapters.CANDIDATE_ARTIFACT_PATH).exists()
    assert gateway.token.encode() not in (native_output / adapters.ADAPTER_STDOUT_PATH).read_bytes()
    assert gateway.token not in json.dumps(receipt)


@pytest.mark.parametrize(
    ("stream", "truncated"), [("stdout", False), ("stderr", False), ("stdout", True)]
)
def test_redacted_adapter_log_reproduces_capture_without_hiding_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
    truncated: bool,
) -> None:
    from tools.paired_xben.report import _validate_adapter_capture

    runtime = _runtime(tmp_path, "ravage")
    gateway = _gateway()
    agent = adapters.build_ravage_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        tool_image="registry.invalid/ravage-tools@sha256:" + "a" * 64,
        docker_host=_DOCKER_HOST,
    )
    original = ("gateway=" + gateway.token + "\n").encode()
    omitted_bytes = 8 if truncated else 0
    captured = {
        "stdout": original if stream == "stdout" else b"",
        "stderr": original if stream == "stderr" else b"",
    }
    monkeypatch.setattr(
        adapters,
        "run_bounded_process",
        lambda *_args, **_kwargs: adapters.BoundedProcessResult(
            returncode=0,
            timed_out=False,
            stdout=captured["stdout"],
            stderr=captured["stderr"],
            stdout_total_bytes=len(captured["stdout"])
            + (omitted_bytes if stream == "stdout" else 0),
            stderr_total_bytes=len(captured["stderr"])
            + (omitted_bytes if stream == "stderr" else 0),
            stdout_sha256=hashlib.sha256(captured["stdout"]).hexdigest(),
            stderr_sha256=hashlib.sha256(captured["stderr"]).hexdigest(),
            stdout_truncated=stream == "stdout" and truncated,
            stderr_truncated=stream == "stderr" and truncated,
            stdout_complete=True,
            stderr_complete=True,
            candidates=(),
            extraction_complete=True,
        ),
    )
    native_output = tmp_path / "native-output"
    native_output.mkdir()
    _returncode, receipt = adapters.execute_launch_spec(
        agent.command[-1],
        cwd=native_output,
        environment={
            **agent.environment,
            TARGET_URL_ENV: "http://target-gateway.internal:8081",
            DESCRIPTION_ENV: _VISIBLE_DESCRIPTION,
        },
    )
    path = native_output / f"adapter-{stream}.log"
    sanitized = path.read_bytes()
    capture = receipt["capture"][stream]
    assert gateway.token.encode() not in sanitized
    assert capture["sha256"] == "sha256:" + hashlib.sha256(sanitized).hexdigest()
    assert capture["retained_bytes"] == len(sanitized)
    assert capture["total_bytes"] == len(sanitized) + omitted_bytes
    assert capture["truncated"] is truncated
    assert _validate_adapter_capture(capture, path=path, label=stream) is not truncated


def test_execute_strix_extracts_candidate_written_only_under_fresh_home(
    tmp_path: Path,
) -> None:
    runtime = _runtime(
        tmp_path,
        "strix",
        executable_program=(
            "from pathlib import Path\n"
            "report = Path.home() / '.strix' / 'reports' / 'result.md'\n"
            "report.parent.mkdir(parents=True)\n"
            "report.write_text('flag{home-report-only}\\n', encoding='utf-8')\n"
        ),
    )
    gateway = _gateway()
    agent = adapters.build_strix_agent(
        runtime=runtime,
        gateway=gateway,
        limits=_limits(),
        trusted_path=_trusted_path(),
        sandbox_image="registry.invalid/strix-sandbox@sha256:" + "b" * 64,
        sandbox_network="paired_agent_net",
        docker_host=_DOCKER_HOST,
    )
    native_output = tmp_path / "native-output"
    native_output.mkdir()

    returncode, receipt = adapters.execute_launch_spec(
        agent.command[-1],
        cwd=native_output,
        environment={
            **agent.environment,
            TARGET_URL_ENV: "http://target-gateway.internal:8081",
            DESCRIPTION_ENV: _VISIBLE_DESCRIPTION,
        },
    )

    assert returncode == 0
    assert receipt["wrapper_returncode"] == returncode
    assert receipt["process_group_policy"] == "joined_evaluator_outer_group"
    assert receipt["gateway"] == gateway.public_json()
    assert receipt["limits"] == _limits().to_json()
    assert (native_output / adapters.CANDIDATE_ARTIFACT_PATH).read_bytes() == (
        b"flag{home-report-only}\n"
    )
    extraction = receipt["candidate_extraction"]
    assert isinstance(extraction, dict)
    assert extraction["scanned_roots"] == [
        "agent-run",
        "adapter-home",
        "adapter-work",
        "adapter-tmp",
    ]
    assert extraction["candidate_count"] == 1
    runtime_receipt = receipt["runtime"]
    assert isinstance(runtime_receipt, dict)
    assert runtime_receipt["source_origin_url"] == runtime.source_origin_url
    assert receipt["tool_image"] == "registry.invalid/strix-sandbox@sha256:" + "b" * 64
