from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from ravage.xben_parts.comparison_target import (
    BoundedSubprocessRunner,
    CommandResult,
    CompatibilityPatchCatalog,
    ComparisonTargetError,
    DockerComparisonTargetBackend,
    DockerEvidenceError,
    DockerTargetConfiguration,
    GatewayConfiguration,
    GatewayUnavailableError,
    MaterializedCase,
    PinnedGitCaseMaterializer,
    PinnedXbenSource,
    PreparedTargetArmBackend,
    ProbeConfiguration,
    SourceMaterializationError,
    TeardownVerificationError,
    UnsafeComposeError,
    _write_sanitized_compose,
    validate_prepared_target_arm_provenance,
    validate_prepared_target_provenance,
    validate_request_meter_stop_provenance,
)
from ravage.xben_parts.http_meter_gateway import (
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    HTTP_METER_PROTOCOL,
    HTTP_METER_SCHEMA_VERSION,
    MAX_CONCURRENT_REQUESTS,
    program_sha256,
)
from ravage.xben_parts.models import XbenCase

TARGET_IMAGE_ID = f"sha256:{'a' * 64}"
PROBE_IMAGE_ID = f"sha256:{'b' * 64}"
GATEWAY_IMAGE_ID = f"sha256:{'c' * 64}"
AGENT_NETWORK_ID = "d" * 64
TARGET_NETWORK_ID = "e" * 64
TARGET_CONTAINER_ID = "3" * 64
DEPENDENCY_CONTAINER_ID = "5" * 64
UNOWNED_CONTAINER_ID = "6" * 64
GATEWAY_CONTAINER_ID = "4" * 64
PROBE_IMAGE = f"registry.invalid/probe@sha256:{'1' * 64}"
GATEWAY_IMAGE = f"registry.invalid/gateway@sha256:{'2' * 64}"
EXPECTED_FLAG = f"flag{{ravage_cmp_{'f' * 64}}}"
MAX_TARGET_REQUESTS = 3
GATEWAY_AGENT_IP = "172.30.0.8"


def test_bounded_subprocess_runner_enforces_captured_output_limit(tmp_path: Path) -> None:
    runner = BoundedSubprocessRunner(max_stdout_bytes=8, max_stderr_bytes=8)

    with pytest.raises(RuntimeError, match="stdout exceeded"):
        runner.run(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 64)"),
            cwd=tmp_path,
            environment={"PATH": str(Path(sys.executable).parent)},
            timeout_seconds=5,
        )


def test_materializer_exports_exact_clean_commit_and_applies_only_pinned_patch(
    tmp_path: Path,
) -> None:
    repository, commit, case = _git_repository(tmp_path)
    original = (case.path / "Dockerfile").read_bytes()
    patch_path = tmp_path / "compat.patch"
    patch_path.write_text(
        """diff --git a/benchmarks/XBEN-001-24/Dockerfile b/benchmarks/XBEN-001-24/Dockerfile
index 4b2ea45..8bd0b4b 100644
--- a/benchmarks/XBEN-001-24/Dockerfile
+++ b/benchmarks/XBEN-001-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# compatibility-only
""",
        encoding="utf-8",
    )
    patch_sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=_compatibility_catalog(
                tmp_path=tmp_path,
                repository=repository,
                commit=commit,
                patches={
                    "XBEN-001-24": (
                        patch_path,
                        patch_sha,
                        ("benchmarks/XBEN-001-24/Dockerfile",),
                    )
                },
            ),
        ),
        private_root=tmp_path / "private",
    )

    materialized = materializer.materialize(case=case, instance_id="xben-row-abc123")

    assert materialized.root.parent == (tmp_path / "private").resolve()
    assert "compatibility-only" in (materialized.case_path / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert (case.path / "Dockerfile").read_bytes() == original
    evidence = materialized.source_evidence
    assert evidence["commit"] == commit
    assert evidence["checkout_clean_before_and_after"] is True
    compatibility = evidence["compatibility_patch"]
    assert isinstance(compatibility, dict)
    assert compatibility["sha256"] == patch_sha
    assert compatibility["applied"] is True
    catalog = evidence["compatibility_patch_catalog"]
    assert isinstance(catalog, dict)
    assert catalog["selected_action"] == "apply_patch"
    assert catalog["selected_patch_sha256"] == patch_sha
    assert catalog["complete_case_set_verified"] is True
    assert _git_output(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""


def test_materializer_rejects_dirty_checkout_before_archive(tmp_path: Path) -> None:
    repository, commit, case = _git_repository(tmp_path)
    (case.path / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=_compatibility_catalog(
                tmp_path=tmp_path,
                repository=repository,
                commit=commit,
                patches={},
            ),
        ),
        private_root=tmp_path / "private",
    )

    with pytest.raises(SourceMaterializationError, match="dirty"):
        materializer.materialize(case=case, instance_id="xben-row-dirty")

    assert not (tmp_path / "private" / "xben-row-dirty").exists()


def test_materializer_rejects_runtime_metadata_not_in_pinned_archive(tmp_path: Path) -> None:
    repository, commit, case = _git_repository(tmp_path)
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=_compatibility_catalog(
                tmp_path=tmp_path,
                repository=repository,
                commit=commit,
                patches={},
            ),
        ),
        private_root=tmp_path / "private",
    )

    with pytest.raises(SourceMaterializationError, match="metadata differs"):
        materializer.materialize(
            case=replace(case, description="Operator-supplied easier description"),
            instance_id="xben-row-metadata",
        )

    assert not (tmp_path / "private" / "xben-row-metadata").exists()


def test_materializer_rejects_patch_digest_mismatch_and_removes_private_copy(
    tmp_path: Path,
) -> None:
    repository, commit, case = _git_repository(tmp_path)
    patch_path = tmp_path / "compat.patch"
    patch_path.write_text("not the committed patch\n", encoding="utf-8")
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=_compatibility_catalog(
                tmp_path=tmp_path,
                repository=repository,
                commit=commit,
                patches={
                    "XBEN-001-24": (
                        patch_path,
                        "0" * 64,
                        ("benchmarks/XBEN-001-24/Dockerfile",),
                    )
                },
            ),
        ),
        private_root=tmp_path / "private",
    )

    with pytest.raises(SourceMaterializationError, match="does not match"):
        materializer.materialize(case=case, instance_id="xben-row-patch")

    assert not (tmp_path / "private" / "xben-row-patch").exists()


def test_materializer_applies_the_hashed_patch_bytes_not_a_later_replacement(
    tmp_path: Path,
) -> None:
    repository, commit, case = _git_repository(tmp_path)
    patch_path = tmp_path / "compat.patch"
    patch_path.write_text(
        """diff --git a/benchmarks/XBEN-001-24/Dockerfile b/benchmarks/XBEN-001-24/Dockerfile
--- a/benchmarks/XBEN-001-24/Dockerfile
+++ b/benchmarks/XBEN-001-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# pinned-content
""",
        encoding="utf-8",
    )
    patch_sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    runner = PatchReplacingRunner(patch_path=patch_path)
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=_compatibility_catalog(
                tmp_path=tmp_path,
                repository=repository,
                commit=commit,
                patches={
                    "XBEN-001-24": (
                        patch_path,
                        patch_sha,
                        ("benchmarks/XBEN-001-24/Dockerfile",),
                    )
                },
            ),
        ),
        private_root=tmp_path / "private",
        runner=runner,
    )

    materialized = materializer.materialize(case=case, instance_id="xben-row-race")

    assert "pinned-content" in (materialized.case_path / "Dockerfile").read_text(encoding="utf-8")
    assert "replacement-content" not in (materialized.case_path / "Dockerfile").read_text(
        encoding="utf-8"
    )


def test_materializer_selects_only_the_drawn_case_from_complete_patch_catalog(
    tmp_path: Path,
) -> None:
    repository, commit, first_case = _git_repository(tmp_path)
    second_path = repository / "benchmarks" / "XBEN-002-24"
    second_case = _case(second_path, benchmark_id="XBEN-002-24")
    first_patch = tmp_path / "XBEN-001-24.patch"
    first_patch.write_text(
        """diff --git a/benchmarks/XBEN-001-24/Dockerfile b/benchmarks/XBEN-001-24/Dockerfile
--- a/benchmarks/XBEN-001-24/Dockerfile
+++ b/benchmarks/XBEN-001-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# first-case-only
""",
        encoding="utf-8",
    )
    second_patch = tmp_path / "XBEN-002-24.patch"
    second_patch.write_text(
        """diff --git a/benchmarks/XBEN-002-24/Dockerfile b/benchmarks/XBEN-002-24/Dockerfile
--- a/benchmarks/XBEN-002-24/Dockerfile
+++ b/benchmarks/XBEN-002-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# second-case-only
""",
        encoding="utf-8",
    )
    catalog = _compatibility_catalog(
        tmp_path=tmp_path,
        repository=repository,
        commit=commit,
        patches={
            "XBEN-001-24": (
                first_patch,
                hashlib.sha256(first_patch.read_bytes()).hexdigest(),
                ("benchmarks/XBEN-001-24/Dockerfile",),
            ),
            "XBEN-002-24": (
                second_patch,
                hashlib.sha256(second_patch.read_bytes()).hexdigest(),
                ("benchmarks/XBEN-002-24/Dockerfile",),
            ),
        },
    )
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(repository=repository, commit=commit, catalog=catalog),
        private_root=tmp_path / "private",
    )

    first = materializer.materialize(case=first_case, instance_id="xben-row-first")
    second = materializer.materialize(case=second_case, instance_id="xben-row-second")

    assert "first-case-only" in (first.case_path / "Dockerfile").read_text(encoding="utf-8")
    assert not (first.root / "benchmarks" / "XBEN-002-24").exists()
    assert "second-case-only" in (second.case_path / "Dockerfile").read_text(encoding="utf-8")
    assert not (second.root / "benchmarks" / "XBEN-001-24").exists()
    first_catalog = first.source_evidence["compatibility_patch_catalog"]
    second_catalog = second.source_evidence["compatibility_patch_catalog"]
    assert isinstance(first_catalog, dict)
    assert isinstance(second_catalog, dict)
    assert first_catalog["catalog_sha256"] == catalog.sha256
    assert second_catalog["catalog_sha256"] == catalog.sha256
    assert first_catalog["patch_count"] == second_catalog["patch_count"] == 2
    assert first_catalog["selected_case_id"] == "XBEN-001-24"
    assert second_catalog["selected_case_id"] == "XBEN-002-24"


def test_materializer_rejects_unknown_catalog_case_and_catalog_tampering(
    tmp_path: Path,
) -> None:
    repository, commit, case = _git_repository(tmp_path)
    patch_path = tmp_path / "unknown.patch"
    patch_path.write_text("not reached\n", encoding="utf-8")
    unknown_catalog = _compatibility_catalog(
        tmp_path=tmp_path,
        repository=repository,
        commit=commit,
        patches={
            "XBEN-999-24": (
                patch_path,
                hashlib.sha256(patch_path.read_bytes()).hexdigest(),
                ("benchmarks/XBEN-999-24/Dockerfile",),
            )
        },
        filename="unknown-catalog.json",
    )
    unknown_materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(
            repository=repository,
            commit=commit,
            catalog=unknown_catalog,
        ),
        private_root=tmp_path / "private-unknown",
    )
    with pytest.raises(SourceMaterializationError, match="case is unknown"):
        unknown_materializer.materialize(case=case, instance_id="xben-row-unknown")

    clean_catalog = _compatibility_catalog(
        tmp_path=tmp_path,
        repository=repository,
        commit=commit,
        patches={},
        filename="tampered-catalog.json",
    )
    clean_catalog.path.write_bytes(clean_catalog.path.read_bytes() + b" \n")
    tampered_materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(repository=repository, commit=commit, catalog=clean_catalog),
        private_root=tmp_path / "private-tampered",
    )
    with pytest.raises(SourceMaterializationError, match="catalog content does not match"):
        tampered_materializer.materialize(case=case, instance_id="xben-row-tampered")


def test_materializer_rejects_patch_changes_outside_catalog_declaration(
    tmp_path: Path,
) -> None:
    repository, commit, case = _git_repository(tmp_path)
    patch_path = tmp_path / "extra-change.patch"
    patch_path.write_text(
        """diff --git a/benchmarks/XBEN-001-24/Dockerfile b/benchmarks/XBEN-001-24/Dockerfile
--- a/benchmarks/XBEN-001-24/Dockerfile
+++ b/benchmarks/XBEN-001-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# declared
diff --git a/benchmarks/XBEN-002-24/extra.txt b/benchmarks/XBEN-002-24/extra.txt
new file mode 100644
--- /dev/null
+++ b/benchmarks/XBEN-002-24/extra.txt
@@ -0,0 +1 @@
+undeclared
""",
        encoding="utf-8",
    )
    catalog = _compatibility_catalog(
        tmp_path=tmp_path,
        repository=repository,
        commit=commit,
        patches={
            "XBEN-001-24": (
                patch_path,
                hashlib.sha256(patch_path.read_bytes()).hexdigest(),
                ("benchmarks/XBEN-001-24/Dockerfile",),
            )
        },
    )
    materializer = PinnedGitCaseMaterializer(
        source=_pinned_source(repository=repository, commit=commit, catalog=catalog),
        private_root=tmp_path / "private",
    )

    with pytest.raises(SourceMaterializationError, match="outside the selected case"):
        materializer.materialize(case=case, instance_id="xben-row-extra")

    assert not (tmp_path / "private" / "xben-row-extra").exists()


def test_sanitized_compose_removes_public_ports_and_uses_unique_resources(
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "site").mkdir()
    (case_path / "docker-compose.yml").write_text(
        """services:
  web:
    build: .
    container_name: shared-web
    ports:
      - "8080:80"
    volumes:
      - ./site:/srv/site:ro
    networks:
      - shared
networks:
  shared:
    external: true
volumes:
  cache:
    name: shared-cache
""",
        encoding="utf-8",
    )

    output, evidence = _write_sanitized_compose(
        case_path=case_path,
        project="ravagecmp_abc",
        network_name="ravagecmp_abc_target",
        instance_id="xben-row-safe",
    )

    compose = yaml.safe_load(output.read_text(encoding="utf-8"))
    service = compose["services"]["web"]
    assert "ports" not in service
    assert "container_name" not in service
    assert service["networks"] == ["ravage_comparison_target"]
    network = compose["networks"]["ravage_comparison_target"]
    assert network["name"] == "ravagecmp_abc_target"
    assert network["internal"] is True
    assert compose["volumes"]["cache"]["name"] == "ravagecmp_abc_volume_001"
    assert evidence["published_ports_removed"] == 1
    assert evidence["container_names_removed"] == 1


@pytest.mark.parametrize(
    "unsafe_fragment",
    [
        "    privileged: true\n",
        "    network_mode: host\n",
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        "    extra_hosts:\n      - host.docker.internal:host-gateway\n",
        "    volumes:\n      source: /tmp\n",
        "    gpus: all\n",
        "    deploy:\n      resources:\n        reservations:\n          devices:\n"
        "            - capabilities: [gpu]\n",
        "    logging:\n      driver: syslog\n",
    ],
)
def test_sanitized_compose_rejects_host_escape_features(
    tmp_path: Path,
    unsafe_fragment: str,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        f"services:\n  web:\n    image: nginx\n{unsafe_fragment}",
        encoding="utf-8",
    )

    with pytest.raises(UnsafeComposeError):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_unsafe",
            network_name="ravagecmp_unsafe_target",
            instance_id="xben-row-unsafe",
        )


def test_sanitized_compose_rejects_top_level_volume_driver_escape(tmp_path: Path) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        """services:
  web:
    image: nginx
    volumes:
      - cache:/data
volumes:
  cache:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /etc
""",
        encoding="utf-8",
    )

    with pytest.raises(UnsafeComposeError, match="host driver settings"):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_unsafe_volume_driver",
            network_name="ravagecmp_unsafe_volume_driver_target",
            instance_id="xben-row-unsafe-volume-driver",
        )


@pytest.mark.parametrize(
    "build_setting",
    [
        "network: host",
        "privileged: true",
        "entitlements: [network.host]",
        "ssh: [default]",
        "secrets: [build-secret]",
        "cache_from: [type=local,src=/tmp/cache]",
    ],
)
def test_sanitized_compose_rejects_explicit_privileged_or_external_build_inputs(
    tmp_path: Path,
    build_setting: str,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (case_path / "docker-compose.yml").write_text(
        f"services:\n  web:\n    build:\n      context: .\n      {build_setting}\n",
        encoding="utf-8",
    )

    with pytest.raises(UnsafeComposeError, match="forbidden host/remote inputs"):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_unsafe_build",
            network_name="ravagecmp_unsafe_build_target",
            instance_id="xben-row-unsafe-build",
        )


def test_sanitized_compose_forces_local_only_runtime_images(tmp_path: Path) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:latest\n",
        encoding="utf-8",
    )

    output, evidence = _write_sanitized_compose(
        case_path=case_path,
        project="ravagecmp_local_only",
        network_name="ravagecmp_local_only_target",
        instance_id="xben-row-local-only",
    )

    compose = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert compose["services"]["web"]["pull_policy"] == "never"
    assert evidence["runtime_pull_policy"] == "never"


def test_sanitized_compose_rejects_environment_backed_top_level_secret(
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        """services:
  web:
    image: nginx
    secrets:
      - host_secret
secrets:
  host_secret:
    environment: HOME
""",
        encoding="utf-8",
    )

    with pytest.raises(UnsafeComposeError, match="non-file source"):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_secret",
            network_name="ravagecmp_secret_target",
            instance_id="xben-row-secret",
        )


@pytest.mark.parametrize(
    "compose_document",
    [
        """services:
  web:
    image: nginx
    volumes:
      - '${UNSET:-/etc}:/mnt:ro'
""",
        """services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: '$HOST_SOURCE'
        target: /mnt
""",
        """services:
  web:
    image: nginx
    env_file: '${UNSET:-/etc/passwd}'
""",
        """services:
  web:
    build: '${UNSET:-/etc}'
""",
        """services:
  web:
    build:
      context: '${UNSET:-/etc}'
""",
        """services:
  web:
    build:
      context: .
      dockerfile: '${UNSET:-/etc/passwd}'
""",
        """services:
  web:
    image: nginx
    configs: [host_config]
configs:
  host_config:
    file: '${UNSET:-/etc/passwd}'
""",
        """services:
  web:
    image: nginx
    secrets: [host_secret]
secrets:
  host_secret:
    file: '$$HOME/.secret'
""",
    ],
)
def test_sanitized_compose_rejects_interpolation_in_host_paths(
    tmp_path: Path,
    compose_document: str,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(compose_document, encoding="utf-8")

    with pytest.raises(UnsafeComposeError, match="interpolation"):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_interpolation",
            network_name="ravagecmp_interpolation_target",
            instance_id="xben-row-interpolation",
        )


@pytest.mark.parametrize(
    "compose_document",
    [
        """include:
  - path: '${COMPOSE_FRAGMENT}'
services:
  web:
    image: nginx
""",
        """services:
  web:
    extends:
      file: '${COMPOSE_FRAGMENT}'
      service: base
""",
        """services:
  web:
    build:
      context: .
      additional_contexts:
        assets: '${UNSET:-/etc}'
""",
    ],
)
def test_sanitized_compose_rejects_unsupported_external_compose_sources(
    tmp_path: Path,
    compose_document: str,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(compose_document, encoding="utf-8")

    with pytest.raises(UnsafeComposeError):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_external_source",
            network_name="ravagecmp_external_source_target",
            instance_id="xben-row-external-source",
        )


def test_sanitized_compose_allows_interpolation_in_container_environment(
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        """services:
  web:
    image: nginx
    environment:
      APP_ROOT: '${APP_ROOT:-/srv/app}'
""",
        encoding="utf-8",
    )

    output, _evidence = _write_sanitized_compose(
        case_path=case_path,
        project="ravagecmp_container_environment",
        network_name="ravagecmp_container_environment_target",
        instance_id="xben-row-container-environment",
    )

    compose = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert compose["services"]["web"]["environment"]["APP_ROOT"] == "${APP_ROOT:-/srv/app}"


@pytest.mark.parametrize("second_name", ["compose.yaml", "nested/compose.yml"])
def test_sanitized_compose_rejects_ambiguous_compose_discovery(
    tmp_path: Path,
    second_name: str,
) -> None:
    case_path = tmp_path / "case"
    case_path.mkdir()
    (case_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n",
        encoding="utf-8",
    )
    second_path = case_path / second_name
    second_path.parent.mkdir(parents=True, exist_ok=True)
    second_path.write_text("services:\n  other:\n    image: nginx\n", encoding="utf-8")

    with pytest.raises(UnsafeComposeError, match="multiple ambiguous"):
        _write_sanitized_compose(
            case_path=case_path,
            project="ravagecmp_ambiguous",
            network_name="ravagecmp_ambiguous_target",
            instance_id="xben-row-ambiguous",
        )


def test_backend_fails_closed_before_materialization_without_gateway(tmp_path: Path) -> None:
    materializer = FakeMaterializer(tmp_path / "private")
    backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=DockerTargetConfiguration(
            gateway=None,
            probe=_probe_configuration(),
        ),
        runner=FakeDockerRunner(instance_id="xben-row-no-gateway"),
    )

    with pytest.raises(GatewayUnavailableError, match="gateway"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id="xben-row-no-gateway",
        )

    assert materializer.calls == []
    assert not (tmp_path / "evidence").exists()


def test_backend_never_deletes_unowned_gateway_name_collision(tmp_path: Path) -> None:
    instance_id = "xben-row-unowned-collision"
    docker = FakeDockerRunner(instance_id=instance_id, gateway_create_mode="unowned_collision")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(TeardownVerificationError, match="unowned container"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )

    assert not any(
        call["command"][:3] == ("docker", "rm", "-f")
        for call in docker.calls
        if isinstance(call["command"], tuple)
    )


def test_backend_derives_boundary_evidence_and_verifies_complete_cleanup(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-complete"
    materializer = FakeMaterializer(tmp_path / "private")
    docker = FakeDockerRunner(instance_id=instance_id)
    backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    assert target.target_url == "http://ravage-target:8080"
    provenance = target.build_provenance
    assert provenance["comparison_safe"] is True
    assert EXPECTED_FLAG not in json.dumps(provenance)
    evidence_dir = tmp_path / "evidence" / instance_id
    build = json.loads((evidence_dir / "build.json").read_text(encoding="utf-8"))
    assert build["comparison_safe"] is True
    assert build["gateway"]["derived_from"] == "docker inspect"
    request_counting = build["target_request_counting"]
    assert request_counting["verified_by_this_backend"] is True
    assert request_counting["max_target_requests"] == MAX_TARGET_REQUESTS
    assert request_counting["protocol"] == HTTP_METER_PROTOCOL
    assert request_counting["https_connect_supported"] is False
    assert request_counting["max_response_body_bytes"] == DEFAULT_MAX_RESPONSE_BODY_BYTES
    assert request_counting["streaming_response_supported"] is False
    assert request_counting["verification_kind"] == (
        "operational-docker-inspection-and-meter-receipt"
    )
    assert request_counting["cryptographically_attested"] is False
    assert build["mount_isolation"]["gateway_docker_socket_mounts_absent"] is True
    assert build["mount_isolation"]["agent_runtime_mounts_in_scope"] is False
    assert build["target_inspection"]["network"]["internal"] is True
    assert build["target_inspection"]["containers"][0]["published_host_ports"] == []
    assert build["readiness"]["status"] == "ready"
    assert EXPECTED_FLAG not in json.dumps(build)
    assert "[REDACTED_EXPECTED_FLAG]" in json.dumps(build)
    assert all(int(str(call["timeout_seconds"])) > 0 for call in docker.calls)

    teardown = backend.stop(target=target)

    assert teardown["removed"] is True
    assert teardown["verified"] is True
    assert teardown["request_count"]["receipt"]["target_request_attempts"] == 2
    request_meter = teardown["request_meter"]
    assert request_meter["schema_version"] == "ravage.xben.request-meter-stop.v2"
    assert request_meter["sealed"] is True
    assert request_meter["access_boundary"] == "evaluator-owned-docker-network"
    assert request_meter["observed_count"] == 2
    assert request_meter["hard_limit"] == MAX_TARGET_REQUESTS
    assert request_meter["limit_enforced"] is True
    assert request_meter["complete"] is True
    assert request_meter["valid"] is True
    assert request_meter["cryptographically_attested"] is False
    assert request_meter["receipt_path"] == str(evidence_dir / "request-count.json")
    assert (
        request_meter["receipt_sha256"]
        == hashlib.sha256((evidence_dir / "request-count.json").read_bytes()).hexdigest()
    )
    assert not (tmp_path / "private" / instance_id).exists()
    retained = json.loads((evidence_dir / "teardown.json").read_text(encoding="utf-8"))
    assert retained["status"] == "succeeded"
    assert retained["workspace_removed"] is True
    assert retained["residual_resources"] == {
        "container": [],
        "network": [],
        "volume": [],
    }
    assert retained["known_resource_residuals"] == {
        "container": [],
        "network": [],
        "volume": [],
    }
    assert retained["request_count"]["status"] == "verified"
    receipt = json.loads((evidence_dir / "request-count.json").read_text(encoding="utf-8"))
    assert receipt["receipt"]["max_target_requests"] == MAX_TARGET_REQUESTS

    assert validate_request_meter_stop_provenance(
        request_meter,
        evidence_dir=evidence_dir,
    ) == dict(request_meter)


def test_prepared_case_builds_once_and_launches_two_fresh_exact_image_arms(
    tmp_path: Path,
) -> None:
    pair_id = "xben-pair-build-once"
    materializer = FakeMaterializer(tmp_path / "private")
    ravage_runner = FakeDockerRunner(
        instance_id="xben-arm-ravage",
        endpoint_mode="host_loopback",
    )
    ravage_backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(endpoint_mode="host_loopback"),
        runner=ravage_runner,
    )
    prepared = ravage_backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id=pair_id,
    )
    validated = validate_prepared_target_provenance(
        prepared.provenance,
        evidence_dir=prepared.evidence_dir,
    )
    assert validated["build_once"] is True
    assert EXPECTED_FLAG not in json.dumps(validated)
    calls_after_prepare = len(ravage_runner.calls)

    ravage_target = ravage_backend.start_prepared(
        prepared=prepared,
        arm="ravage",
        instance_id="xben-arm-ravage",
    )
    ravage_backend.stop(target=ravage_target)
    strix_runner = FakeDockerRunner(instance_id="xben-arm-strix")
    strix_backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=strix_runner,
    )
    strix_target = strix_backend.start_prepared(
        prepared=prepared,
        arm="strix",
        instance_id="xben-arm-strix",
    )
    strix_backend.stop(target=strix_target)

    all_arm_calls = [*ravage_runner.calls[calls_after_prepare:], *strix_runner.calls]
    assert not any("build" in call["command"] for call in all_arm_calls)
    up_commands = [
        call["command"]
        for call in all_arm_calls
        if "up" in call["command"] and "compose" in call["command"]
    ]
    assert len(up_commands) == 2
    assert all("--no-build" in command and "never" in command for command in up_commands)
    assert (
        ravage_target.build_provenance["target_image_ids"]
        == (strix_target.build_provenance["target_image_ids"])
    )
    assert ravage_target.build_provenance["prepared_image_reuse_verified"] is True
    assert strix_target.build_provenance["prepared_image_reuse_verified"] is True
    assert ravage_target.build_provenance["gateway_endpoint_mode"] == "host_loopback"
    assert ravage_target.target_url.startswith("http://127.0.0.1:")
    assert strix_target.build_provenance["gateway_endpoint_mode"] == "docker_alias"
    assert strix_target.target_url.startswith("http://ravage-target:")
    assert ravage_target.build_provenance["flag_disclosure"] == (
        "withheld_until_both_arms_terminal"
    )
    assert validate_prepared_target_arm_provenance(
        ravage_target.build_provenance,
        evidence_dir=Path(str(ravage_target.build_provenance["evidence_dir"])),
    ) == dict(ravage_target.build_provenance)
    assert validate_prepared_target_arm_provenance(
        strix_target.build_provenance,
        evidence_dir=Path(str(strix_target.build_provenance["evidence_dir"])),
    ) == dict(strix_target.build_provenance)
    assert materializer.calls == [f"{pair_id}.prepared"]

    released = ravage_backend.release_prepared(prepared=prepared)
    assert released["valid"] is True
    assert released["both_arms_terminated"] is True
    assert released["owned_image_reference_absence_verified"] is True
    assert not prepared.materialized.root.exists()


def test_prepared_arm_adapter_rejects_evaluator_flag_mismatch_before_consumption(
    tmp_path: Path,
) -> None:
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-arm-ravage"),
    )
    case = _case(tmp_path / "checkout")
    prepared = backend.prepare_case(
        case=case,
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-adapter-binding",
    )
    adapter = PreparedTargetArmBackend(
        backend=backend,
        prepared=prepared,
        arm="ravage",
    )

    with pytest.raises(ComparisonTargetError, match="flag binding") as error:
        adapter.start(
            case=case,
            expected_flag=f"flag{{ravage_cmp_{'e' * 64}}}",
            instance_id="xben-arm-ravage",
        )

    assert prepared.started_arms == {}
    assert EXPECTED_FLAG not in str(error.value)


def test_prepared_arm_public_validator_rejects_runtime_build_claim_tampering(
    tmp_path: Path,
) -> None:
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-arm-ravage"),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-arm-validator",
    )
    target = backend.start_prepared(
        prepared=prepared,
        arm="ravage",
        instance_id="xben-arm-ravage",
    )
    tampered = dict(target.build_provenance)
    tampered["runtime_build_allowed"] = True

    with pytest.raises(DockerEvidenceError, match="runtime_build_allowed"):
        validate_prepared_target_arm_provenance(
            tampered,
            evidence_dir=Path(str(target.build_provenance["evidence_dir"])),
        )

    backend.stop(target=target)


def test_prepared_arm_validator_recomputes_inspected_image_binding(
    tmp_path: Path,
) -> None:
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-arm-ravage"),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-inspection-validator",
    )
    target = backend.start_prepared(
        prepared=prepared,
        arm="ravage",
        instance_id="xben-arm-ravage",
    )
    evidence_dir = Path(str(target.build_provenance["evidence_dir"]))
    build_path = evidence_dir / "build.json"
    build = json.loads(build_path.read_text(encoding="utf-8"))
    build["target_inspection"]["containers"][0]["image_id"] = f"sha256:{'9' * 64}"
    build_path.write_text(json.dumps(build, sort_keys=True) + "\n", encoding="utf-8")
    tampered = dict(target.build_provenance)
    tampered["build_sha256"] = hashlib.sha256(build_path.read_bytes()).hexdigest()

    with pytest.raises(DockerEvidenceError, match="inspected image IDs drifted"):
        validate_prepared_target_arm_provenance(
            tampered,
            evidence_dir=evidence_dir,
        )

    backend.stop(target=target)


def test_prepared_case_arm_cannot_be_retried_after_failed_launch(tmp_path: Path) -> None:
    runner = FakeDockerRunner(instance_id="xben-arm-ravage")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=runner,
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-one-shot",
    )
    runner.target_running = False
    with pytest.raises(Exception):
        backend.start_prepared(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-arm-ravage",
        )
    runner.target_running = True
    with pytest.raises(ComparisonTargetError, match="already attempted"):
        backend.start_prepared(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-arm-ravage-retry",
        )


def test_prepared_case_resolves_image_only_services_once_before_freezing(
    tmp_path: Path,
) -> None:
    runner = FakeDockerRunner(instance_id="xben-pair-image-only", include_dependency=True)
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(
            tmp_path / "private",
            include_dependency=True,
        ),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=runner,
    )

    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-image-only",
    )

    pull_commands = [
        call["command"]
        for call in runner.calls
        if call["command"][:3] == ("docker", "image", "pull")
    ]
    assert pull_commands == [
        ("docker", "image", "pull", "--platform", "linux/amd64", "postgres:latest")
    ]
    assert prepared.provenance["image_ids_by_service"] == {
        "db": TARGET_IMAGE_ID,
        "web": TARGET_IMAGE_ID,
    }
    retained_build = json.loads((prepared.evidence_dir / "build.json").read_text(encoding="utf-8"))
    assert retained_build["preparation_pull_invocations"] == 1


def test_prepared_release_fails_when_owned_tag_inventory_is_not_empty(
    tmp_path: Path,
) -> None:
    runner = FakeDockerRunner(
        instance_id="xben-pair-release-residual",
        image_tag_remains_after_release=True,
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=runner,
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-release-residual",
    )
    prepared.started_arms.update({"ravage": "arm-r", "strix": "arm-s"})
    prepared.stopped_arms.update({"ravage", "strix"})

    with pytest.raises(TeardownVerificationError, match="image tag remains"):
        backend.release_prepared(prepared=prepared)

    release = json.loads((prepared.evidence_dir / "release.json").read_text(encoding="utf-8"))
    assert release["owned_image_reference_absence_verified"] is False
    assert release["valid"] is False


def test_unstarted_prepared_arms_can_be_abandoned_once_then_released(
    tmp_path: Path,
) -> None:
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-row-abandoned-ravage"),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-abandoned",
    )

    ravage = backend.abandon_prepared_arm(
        prepared=prepared,
        arm="ravage",
        instance_id="xben-row-abandoned-ravage",
    )
    raw_ravage = Path(str(ravage["evidence_path"])).read_text(encoding="utf-8")
    assert ravage["schema_version"] == ("ravage.xben.prepared-target-arm-abandonment.v1")
    assert ravage["target_backend_start_attempted"] is False
    assert EXPECTED_FLAG not in raw_ravage

    with pytest.raises(ComparisonTargetError, match="already abandoned"):
        backend.abandon_prepared_arm(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-row-abandoned-ravage",
        )
    with pytest.raises(ComparisonTargetError, match="already terminalized"):
        backend.start_prepared(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-row-abandoned-ravage-retry",
        )

    backend.abandon_prepared_arm(
        prepared=prepared,
        arm="strix",
        instance_id="xben-row-abandoned-strix",
        reason_code="campaign_cancelled_before_target_start",
    )
    released = backend.release_prepared(prepared=prepared)

    assert released["valid"] is True
    assert released["both_arms_terminated"] is True
    assert released["arms"] == {
        "ravage": "xben-row-abandoned-ravage",
        "strix": "xben-row-abandoned-strix",
    }


def test_abandoned_arm_evidence_is_create_only_and_digest_bound_at_release(
    tmp_path: Path,
) -> None:
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-row-abandonment-digest"),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-abandonment-digest",
    )
    receipt = backend.abandon_prepared_arm(
        prepared=prepared,
        arm="ravage",
        instance_id="xben-row-abandonment-digest",
    )
    backend.abandon_prepared_arm(
        prepared=prepared,
        arm="strix",
        instance_id="xben-row-abandonment-digest-strix",
    )
    path = Path(str(receipt["evidence_path"]))
    original = path.read_bytes()
    path.write_bytes(original.replace(b'"valid": true', b'"valid": false'))

    with pytest.raises(TeardownVerificationError, match="digest is invalid"):
        backend.release_prepared(prepared=prepared)

    path.write_bytes(original)
    assert backend.release_prepared(prepared=prepared)["valid"] is True


def test_terminalize_prepared_arm_reconciles_stopped_launch_and_abandons_unstarted(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-terminal-state-ravage"
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=instance_id),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-terminal-state",
    )
    target = backend.start_prepared(
        prepared=prepared,
        arm="ravage",
        instance_id=instance_id,
    )

    with pytest.raises(TeardownVerificationError, match="still live"):
        backend.terminalize_prepared_arm(
            prepared=prepared,
            arm="ravage",
            instance_id=instance_id,
        )

    backend.stop(target=target)
    terminal = backend.terminalize_prepared_arm(
        prepared=prepared,
        arm="ravage",
        instance_id=instance_id,
    )
    assert terminal["status"] == "already_terminal_via_target_lifecycle"
    assert terminal["target_backend_start_attempted"] is True
    assert EXPECTED_FLAG not in json.dumps(terminal)

    with pytest.raises(ComparisonTargetError, match="instance binding"):
        backend.terminalize_prepared_arm(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-row-terminal-state-wrong",
        )

    abandoned = backend.terminalize_prepared_arm(
        prepared=prepared,
        arm="strix",
        instance_id="xben-row-terminal-state-strix",
    )
    assert abandoned["schema_version"] == ("ravage.xben.prepared-target-arm-abandonment.v1")
    repeated = backend.terminalize_prepared_arm(
        prepared=prepared,
        arm="strix",
        instance_id="xben-row-terminal-state-strix",
    )
    assert repeated["status"] == "already_abandoned_before_target_start"
    assert backend.release_prepared(prepared=prepared)["valid"] is True


def test_only_preparation_backend_can_abandon_or_release_pair(tmp_path: Path) -> None:
    owner = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-row-owner"),
    )
    prepared = owner.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-owner",
    )
    non_owner = DockerComparisonTargetBackend(
        materializer=owner.materializer,
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id="xben-row-non-owner"),
    )

    with pytest.raises(ComparisonTargetError, match="preparation backend"):
        non_owner.abandon_prepared_arm(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-row-non-owner",
        )
    with pytest.raises(ComparisonTargetError, match="preparation backend"):
        non_owner.release_prepared(prepared=prepared)


def test_prepared_case_rejects_runtime_container_image_drift(tmp_path: Path) -> None:
    runner = FakeDockerRunner(instance_id="xben-arm-ravage")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=runner,
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-image-drift",
    )
    runner.target_image_id_override = f"sha256:{'9' * 64}"

    with pytest.raises(DockerEvidenceError, match="image IDs drifted"):
        backend.start_prepared(
            prepared=prepared,
            arm="ravage",
            instance_id="xben-arm-ravage",
        )


def test_terminal_request_meter_rejects_receipt_tampering(tmp_path: Path) -> None:
    instance_id = "xben-row-meter-tamper"
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=instance_id),
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )
    teardown = backend.stop(target=target)
    evidence_dir = tmp_path / "evidence" / instance_id
    receipt_path = evidence_dir / "request-count.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")

    with pytest.raises(Exception, match="SHA-256"):
        validate_request_meter_stop_provenance(
            teardown["request_meter"],
            evidence_dir=evidence_dir,
        )


def test_backend_rejects_residual_project_resources_after_teardown(tmp_path: Path) -> None:
    instance_id = "xben-row-residual"
    materializer = FakeMaterializer(tmp_path / "private")
    docker = FakeDockerRunner(instance_id=instance_id, residual_after_down=True)
    backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    with pytest.raises(TeardownVerificationError, match="residual Docker container"):
        backend.stop(target=target)

    retained = json.loads(
        (tmp_path / "evidence" / instance_id / "teardown.json").read_text(encoding="utf-8")
    )
    assert retained["status"] == "error"
    assert retained["residual_resources"]["container"] == ["residual-container"]


def test_backend_rejects_gateway_inspection_that_does_not_prove_read_only_boundary(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-bad-gateway"
    materializer = FakeMaterializer(tmp_path / "private")
    docker = FakeDockerRunner(instance_id=instance_id, gateway_read_only=False)
    backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(Exception, match="gateway privilege boundary"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )

    assert not (tmp_path / "private" / instance_id).exists()
    teardown = json.loads(
        (tmp_path / "evidence" / instance_id / "teardown.json").read_text(encoding="utf-8")
    )
    assert teardown["workspace_removed"] is True


def test_backend_never_reuses_flag_after_failed_startup(tmp_path: Path) -> None:
    first_instance = "xben-row-failed-flag"
    materializer = FakeMaterializer(tmp_path / "private")
    backend = DockerComparisonTargetBackend(
        materializer=materializer,  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=first_instance, gateway_read_only=False),
    )
    with pytest.raises(Exception, match="gateway privilege boundary"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=first_instance,
        )

    with pytest.raises(Exception, match="already used"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id="xben-row-retry-flag",
        )

    assert materializer.calls == [first_instance]


def test_backend_inventories_stopped_compose_services_and_rejects_them(tmp_path: Path) -> None:
    instance_id = "xben-row-stopped-target"
    docker = FakeDockerRunner(
        instance_id=instance_id,
        include_dependency=True,
        dependency_running=False,
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(  # type: ignore[arg-type]
            tmp_path / "private",
            include_dependency=True,
        ),
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(Exception, match="target container is not running"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )

    assert any(
        call["command"][-3:] == ("ps", "--all", "-q")
        for call in docker.calls
        if isinstance(call["command"], tuple)
    )
    assert not any(
        call["command"][:3] == ("docker", "run", "--rm")
        for call in docker.calls
        if isinstance(call["command"], tuple)
    )


def test_backend_rejects_target_hostconfig_port_binding_even_if_runtime_ports_are_empty(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-hidden-binding"
    docker = FakeDockerRunner(instance_id=instance_id, target_host_port_binding=True)
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(Exception, match="published host ports"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )


def test_backend_rejects_target_host_device_requests_from_runtime_inspection(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-host-device-request"
    docker = FakeDockerRunner(instance_id=instance_id, target_device_request=True)
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(Exception, match="host device requests"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )


def test_backend_rejects_unhealthy_declared_healthcheck(tmp_path: Path) -> None:
    instance_id = "xben-row-unhealthy"
    docker = FakeDockerRunner(instance_id=instance_id, target_health_status="unhealthy")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )

    with pytest.raises(Exception, match="healthcheck is not healthy"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )


def test_gateway_receipt_proves_hard_limit_rejections_without_exceeding_target_cap(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-hard-cap"
    docker = FakeDockerRunner(instance_id=instance_id, final_receipt_mode="limit_exceeded")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    teardown = backend.stop(target=target)

    receipt = teardown["request_count"]["receipt"]
    assert receipt["observed_requests"] == 5
    assert receipt["accepted_requests"] == MAX_TARGET_REQUESTS
    assert receipt["target_request_attempts"] == MAX_TARGET_REQUESTS
    assert receipt["rejected_over_limit"] == 2


def test_host_endpoint_mode_is_exact_loopback_binding_to_same_meter_port(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-host-loopback"
    docker = FakeDockerRunner(instance_id=instance_id, endpoint_mode="host_loopback")
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(endpoint_mode="host_loopback"),
        runner=docker,
    )

    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    assert target.target_url == f"http://127.0.0.1:{docker.gateway_port}"
    assert 49_152 <= docker.gateway_port <= 65_535
    build = json.loads(
        (tmp_path / "evidence" / instance_id / "build.json").read_text(encoding="utf-8")
    )
    assert build["gateway"]["endpoint_mode"] == "host_loopback"
    assert build["gateway"]["published_host_ports"] == [
        {
            "host_ip": "127.0.0.1",
            "host_port": str(docker.gateway_port),
            "container_port": str(docker.gateway_port),
            "protocol": "tcp",
        }
    ]
    assert (
        build["gateway"]["routes"]["docker_alias"]["gateway_container_id"]
        == (build["gateway"]["routes"]["host_loopback"]["gateway_container_id"])
    )
    assert any(
        f"127.0.0.1:{docker.gateway_port}:{docker.gateway_port}" in call["command"]
        for call in docker.calls
        if isinstance(call["command"], tuple)
    )
    backend.stop(target=target)


def test_cross_daemon_mode_keeps_gateway_on_target_network_and_returns_host_gateway(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-cross-daemon"
    docker = FakeDockerRunner(
        instance_id=instance_id,
        endpoint_mode="cross_daemon_host_gateway",
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(endpoint_mode="cross_daemon_host_gateway"),
        runner=docker,
    )

    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    assert target.target_url == f"http://10.0.2.2:{docker.gateway_port}"
    build = json.loads(
        (tmp_path / "evidence" / instance_id / "build.json").read_text(encoding="utf-8")
    )
    gateway = build["gateway"]
    assert gateway["endpoint_mode"] == "cross_daemon_host_gateway"
    assert gateway["networks"] == [f"{docker.project}_target"]
    assert gateway["agent_network_attached"] is False
    assert gateway["rootful_target_network_only"] is True
    assert gateway["docker_socket_mounted"] is False
    assert gateway["evaluator_source_mounted"] is False
    assert gateway["published_host_ports"] == [
        {
            "host_ip": "127.0.0.1",
            "host_port": str(docker.gateway_port),
            "container_port": str(docker.gateway_port),
            "protocol": "tcp",
        }
    ]
    assert gateway["cross_daemon_boundary"] == {
        "enabled": True,
        "agent_host_gateway": "10.0.2.2",
        "rootful_publish_host": "127.0.0.1",
        "rootful_gateway_target_network_only": True,
        "agent_docker_network_attached": False,
        "root_owned_uid_firewall_required": True,
        "root_owned_uid_firewall_verified_here": False,
        "live_rootless_route_qualification_required": True,
    }
    gateway_run = next(
        call["command"]
        for call in docker.calls
        if tuple(call["command"])[:3] == ("docker", "run", "-d")
    )
    assert "agent-evaluator-net" not in gateway_run
    assert not any(
        tuple(call["command"])[:3] == ("docker", "network", "connect") for call in docker.calls
    )
    assert not any(
        tuple(call["command"])[:4] == ("docker", "network", "inspect", "agent-evaluator-net")
        for call in docker.calls
    )

    teardown = backend.stop(target=target)
    assert teardown["request_meter"]["endpoint_mode"] == "cross_daemon_host_gateway"
    assert teardown["request_meter"]["access_boundary"] == "root-owned-cross-daemon-loopback"


@pytest.mark.parametrize(
    "mutation",
    ["agent_network", "extra_port_binding"],
)
def test_cross_daemon_gateway_rejects_agent_network_or_extra_port_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    instance_id = f"xben-row-cross-{mutation}"
    docker = FakeDockerRunner(
        instance_id=instance_id,
        endpoint_mode="cross_daemon_host_gateway",
        gateway_extra_network=mutation == "agent_network",
        gateway_extra_port_binding=mutation == "extra_port_binding",
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(endpoint_mode="cross_daemon_host_gateway"),
        runner=docker,
    )

    with pytest.raises(DockerEvidenceError):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )


def test_cross_daemon_configuration_cannot_name_an_agent_docker_network(
    tmp_path: Path,
) -> None:
    configuration = _docker_configuration(endpoint_mode="cross_daemon_host_gateway")
    assert configuration.gateway is not None
    unsafe_gateway = replace(
        configuration.gateway,
        agent_network="agent-evaluator-net",
        expected_agent_network_id=AGENT_NETWORK_ID,
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=replace(configuration, gateway=unsafe_gateway),
        runner=FakeDockerRunner(
            instance_id="xben-row-cross-invalid-network",
            endpoint_mode="cross_daemon_host_gateway",
        ),
    )

    with pytest.raises(GatewayUnavailableError, match="must not accept an agent Docker network"):
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id="xben-row-cross-invalid-network",
        )


def test_prepared_cross_daemon_provenance_rejects_non_dynamic_port(
    tmp_path: Path,
) -> None:
    instance_id = "xben-arm-cross-port"
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(endpoint_mode="cross_daemon_host_gateway"),
        runner=FakeDockerRunner(
            instance_id=instance_id,
            endpoint_mode="cross_daemon_host_gateway",
        ),
    )
    prepared = backend.prepare_case(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        pair_id="xben-pair-cross-port",
    )
    target = backend.start_prepared(
        prepared=prepared,
        arm="ravage",
        instance_id=instance_id,
    )
    tampered = dict(target.build_provenance)
    tampered["target_url"] = "http://10.0.2.2:1024"

    with pytest.raises(DockerEvidenceError, match="URL does not match"):
        validate_prepared_target_arm_provenance(
            tampered,
            evidence_dir=Path(str(target.build_provenance["evidence_dir"])),
        )

    backend.stop(target=target)


@pytest.mark.parametrize("receipt_mode", ["missing", "malformed"])
def test_backend_fails_closed_on_missing_or_malformed_final_request_receipt(
    tmp_path: Path,
    receipt_mode: str,
) -> None:
    instance_id = f"xben-row-{receipt_mode}-receipt"
    docker = FakeDockerRunner(instance_id=instance_id, final_receipt_mode=receipt_mode)
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    with pytest.raises(TeardownVerificationError, match="request-count receipt"):
        backend.stop(target=target)

    evidence_dir = tmp_path / "evidence" / instance_id
    assert not (evidence_dir / "request-count.json").exists()
    teardown = json.loads((evidence_dir / "teardown.json").read_text(encoding="utf-8"))
    assert teardown["status"] == "error"
    assert teardown["request_count"]["status"] == "error"
    assert teardown["request_meter"]["valid"] is False
    assert teardown["request_meter"]["complete"] is False
    assert teardown["request_meter"]["limit_enforced"] is False
    with pytest.raises(TeardownVerificationError, match="already stopped"):
        backend.stop(target=target)


def test_backend_rejects_foreign_agent_network_membership_before_terminal_receipt(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-foreign-agent-network"
    docker = FakeDockerRunner(
        instance_id=instance_id,
        foreign_agent_member_after_start=True,
    )
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=docker,
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    with pytest.raises(TeardownVerificationError, match="agent network membership"):
        backend.stop(target=target)

    teardown = json.loads(
        (tmp_path / "evidence" / instance_id / "teardown.json").read_text(encoding="utf-8")
    )
    assert teardown["request_meter"]["valid"] is False
    assert teardown["request_meter"]["complete"] is False
    operations = [entry["operation"] for entry in teardown["commands"]]
    assert operations.index("agent network inspect") < operations.index("gateway admission seal")


def test_request_receipt_is_create_only_and_cannot_replace_reserved_evidence(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-receipt-collision"
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=instance_id),
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )
    receipt_path = tmp_path / "evidence" / instance_id / "request-count.json"
    receipt_path.write_bytes(b"reserved\n")

    with pytest.raises(TeardownVerificationError, match="request-count receipt"):
        backend.stop(target=target)

    assert receipt_path.read_bytes() == b"reserved\n"


def test_gateway_logs_are_bounded_and_expected_flag_is_redacted(tmp_path: Path) -> None:
    instance_id = "xben-row-bounded-logs"
    noisy_log = (EXPECTED_FLAG.encode() + b"/secret/request/path\n") * 10_000
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=instance_id, gateway_log_bytes=noisy_log),
    )
    target = backend.start(
        case=_case(tmp_path / "checkout"),
        expected_flag=EXPECTED_FLAG,
        instance_id=instance_id,
    )

    backend.stop(target=target)

    evidence_dir = tmp_path / "evidence" / instance_id
    retained = json.loads((evidence_dir / "gateway-log.json").read_text(encoding="utf-8"))
    assert retained["stdout_truncated"] is True
    assert len(retained["stdout"].encode()) <= 64 * 1024
    assert EXPECTED_FLAG not in json.dumps(retained)
    teardown_bytes = (evidence_dir / "teardown.json").read_bytes()
    assert EXPECTED_FLAG.encode() not in teardown_bytes


def test_expected_flag_is_redacted_from_failed_command_exception_and_evidence(
    tmp_path: Path,
) -> None:
    instance_id = "xben-row-secret-error"
    backend = DockerComparisonTargetBackend(
        materializer=FakeMaterializer(tmp_path / "private"),  # type: ignore[arg-type]
        evidence_root=tmp_path / "evidence",
        configuration=_docker_configuration(),
        runner=FakeDockerRunner(instance_id=instance_id, compose_build_fails=True),
    )

    with pytest.raises(Exception) as raised:
        backend.start(
            case=_case(tmp_path / "checkout"),
            expected_flag=EXPECTED_FLAG,
            instance_id=instance_id,
        )

    assert EXPECTED_FLAG not in str(raised.value)
    evidence_dir = tmp_path / "evidence" / instance_id
    for path in evidence_dir.iterdir():
        if path.is_file():
            assert EXPECTED_FLAG.encode() not in path.read_bytes()


@dataclass
class FakeMaterializer:
    private_root: Path
    include_dependency: bool = False
    calls: list[str] = field(default_factory=list)

    def materialize(self, *, case: XbenCase, instance_id: str) -> MaterializedCase:
        self.calls.append(instance_id)
        root = self.private_root / instance_id
        case_path = root / "benchmarks" / case.benchmark_id
        case_path.mkdir(parents=True)
        (case_path / "Dockerfile").write_text("FROM nginx:latest\n", encoding="utf-8")
        dependency = "\n  db:\n    image: postgres:latest\n" if self.include_dependency else ""
        (case_path / "docker-compose.yml").write_text(
            f"""services:
  web:
    build: .
    ports:
      - "8080:80"
{dependency}""",
            encoding="utf-8",
        )
        return MaterializedCase(
            root=root,
            case_path=case_path,
            source_evidence={
                "mode": "test-pinned-archive",
                "commit": "9" * 40,
                "archived_tree": {"sha256": "8" * 64},
            },
        )


@dataclass
class PatchReplacingRunner:
    patch_path: Path
    replaced: bool = False

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        del environment
        argv = tuple(str(item) for item in command)
        if argv[:2] == ("git", "apply") and not self.replaced:
            self.patch_path.write_text(
                """diff --git a/benchmarks/XBEN-001-24/Dockerfile b/benchmarks/XBEN-001-24/Dockerfile
--- a/benchmarks/XBEN-001-24/Dockerfile
+++ b/benchmarks/XBEN-001-24/Dockerfile
@@ -1 +1,2 @@
 FROM nginx:latest
+# replacement-content
""",
                encoding="utf-8",
            )
            self.replaced = True
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return CommandResult(
            command=argv,
            returncode=completed.returncode,
            stdout=completed.stdout or b"",
            stderr=completed.stderr or b"",
        )


@dataclass
class FakeDockerRunner:
    instance_id: str
    residual_after_down: bool = False
    gateway_read_only: bool = True
    endpoint_mode: str = "docker_alias"
    target_running: bool = True
    include_dependency: bool = False
    dependency_running: bool = True
    target_host_port_binding: bool = False
    target_device_request: bool = False
    target_health_status: str | None = None
    target_image_id_override: str | None = None
    gateway_create_mode: str = "valid"
    compose_build_fails: bool = False
    final_receipt_mode: str = "valid"
    gateway_log_bytes: bytes = b""
    foreign_agent_member_after_start: bool = False
    gateway_extra_network: bool = False
    gateway_extra_port_binding: bool = False
    image_tag_remains_after_release: bool = False
    calls: list[dict[str, object]] = field(default_factory=list)
    project: str | None = None
    network: str | None = None
    torn_down: bool = False
    receipt_reads: int = 0
    gateway_name_inventory_reads: int = 0
    gateway_created: bool = False
    gateway_sealed: bool = False
    gateway_port: int = 8080
    removed_image_references: set[str] = field(default_factory=set)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> CommandResult:
        argv = tuple(command)
        self.calls.append(
            {
                "command": argv,
                "cwd": cwd,
                "environment_names": sorted(environment),
                "timeout_seconds": timeout_seconds,
            }
        )
        if "-p" in argv:
            self.project = argv[argv.index("-p") + 1]
            self.network = f"{self.project}_target"
        stdout = b""
        returncode = 0
        if argv[:3] == ("docker", "container", "ls") and any(
            part.startswith("name=^/") for part in argv
        ):
            self.gateway_name_inventory_reads += 1
            if (
                self.gateway_create_mode == "unowned_collision"
                and self.gateway_name_inventory_reads > 1
            ):
                stdout = f"{UNOWNED_CONTAINER_ID}\n".encode()
        elif argv[:3] == ("docker", "compose", "-f") and argv[-3:] == (
            "ps",
            "--all",
            "-q",
        ):
            ids = [TARGET_CONTAINER_ID]
            if self.include_dependency:
                ids.append(DEPENDENCY_CONTAINER_ID)
            stdout = ("\n".join(ids) + "\n").encode()
        elif argv[:2] == ("docker", "inspect") and set(argv[2:]).issubset(
            {TARGET_CONTAINER_ID, DEPENDENCY_CONTAINER_ID}
        ):
            stdout = json.dumps(
                [
                    self._target_inspect(
                        container_id=container_id,
                        service="web" if container_id == TARGET_CONTAINER_ID else "db",
                        running=(
                            self.target_running
                            if container_id == TARGET_CONTAINER_ID
                            else self.dependency_running
                        ),
                    )
                    for container_id in argv[2:]
                ]
            ).encode()
        elif argv[:3] == ("docker", "network", "inspect"):
            if argv[-1] == "agent-evaluator-net":
                stdout = json.dumps([self._agent_network_inspect()]).encode()
            else:
                stdout = json.dumps([self._target_network_inspect()]).encode()
        elif argv[:3] == ("docker", "image", "rm"):
            if not self.image_tag_remains_after_release:
                self.removed_image_references.update(argv[3:])
            stdout = ("\n".join(argv[3:]) + "\n").encode()
        elif argv[:3] == ("docker", "image", "ls"):
            reference = argv[-1]
            if reference not in self.removed_image_references:
                stdout = f"{TARGET_IMAGE_ID}\n".encode()
        elif argv[:3] == ("docker", "image", "inspect"):
            if any(image in self.removed_image_references for image in argv[3:]):
                returncode = 1
            else:
                stdout = json.dumps(self._image_inspect(argv[3:])).encode()
        elif argv[:3] == ("docker", "run", "--rm"):
            stdout = b"200"
        elif argv[:3] == ("docker", "run", "-d"):
            if self.gateway_create_mode == "unowned_collision":
                returncode = 1
            else:
                self.gateway_port = int(argv[argv.index("--listen-port") + 1])
                self.gateway_created = True
                stdout = f"{GATEWAY_CONTAINER_ID}\n".encode()
        elif argv == ("docker", "kill", "--signal=USR1", GATEWAY_CONTAINER_ID):
            self.gateway_sealed = True
            stdout = f"{GATEWAY_CONTAINER_ID}\n".encode()
        elif argv == ("docker", "rm", "-f", GATEWAY_CONTAINER_ID):
            self.gateway_created = False
            stdout = f"{GATEWAY_CONTAINER_ID}\n".encode()
        elif argv == ("docker", "inspect", GATEWAY_CONTAINER_ID):
            stdout = json.dumps([self._gateway_inspect()]).encode()
        elif argv == ("docker", "inspect", UNOWNED_CONTAINER_ID):
            stdout = json.dumps(
                [
                    {
                        "Id": UNOWNED_CONTAINER_ID,
                        "Image": "sha256:" + "9" * 64,
                        "Name": "/somebody-elses-container",
                        "Config": {"Labels": {}},
                    }
                ]
            ).encode()
        elif argv[:3] == ("docker", "exec", GATEWAY_CONTAINER_ID):
            if argv[-1] == "identity":
                stdout = json.dumps(
                    {
                        "schema_version": HTTP_METER_SCHEMA_VERSION,
                        "program_sha256": program_sha256(),
                        "protocol": HTTP_METER_PROTOCOL,
                    }
                ).encode()
            elif "receipt" in argv:
                self.receipt_reads += 1
                if self.receipt_reads > 1 and self.final_receipt_mode == "missing":
                    returncode = 2
                elif self.receipt_reads > 1 and self.final_receipt_mode == "malformed":
                    stdout = b'{"not":"a receipt"}\n'
                else:
                    stdout = json.dumps(self._meter_receipt(final=self.receipt_reads > 1)).encode()
        elif argv[:4] == ("docker", "logs", "--tail", "200"):
            stdout = self.gateway_log_bytes
        elif len(argv) > 2 and argv[1] == "compose" and "down" in argv:
            self.torn_down = True
        elif self.torn_down and len(argv) >= 3 and argv[2] == "ls":
            if self.residual_after_down and argv[1] == "container":
                stdout = b"residual-container\n"
        if EXPECTED_FLAG in " ".join(argv):
            stdout = f"built using {EXPECTED_FLAG}\n".encode()
            if self.compose_build_fails and "build" in argv:
                returncode = 1
        return CommandResult(
            command=argv,
            returncode=returncode,
            stdout=stdout,
            elapsed_seconds=0.01,
        )

    def _target_inspect(
        self,
        *,
        container_id: str = TARGET_CONTAINER_ID,
        service: str = "web",
        running: bool | None = None,
    ) -> dict[str, object]:
        assert self.project is not None
        assert self.network is not None
        if running is None:
            running = self.target_running
        config: dict[str, object] = {
            "Labels": {
                "com.docker.compose.project": self.project,
                "com.docker.compose.service": service,
                "com.ravage.evaluator.target": "true",
            }
        }
        state: dict[str, object] = {"Running": running}
        if self.target_health_status is not None and service == "web":
            config["Healthcheck"] = {"Test": ["CMD", "true"]}
            state["Health"] = {"Status": self.target_health_status}
        return {
            "Id": container_id,
            "Image": self.target_image_id_override or TARGET_IMAGE_ID,
            "Name": f"/{self.project}-{service}-1",
            "Config": config,
            "State": state,
            "HostConfig": {
                "Privileged": False,
                "PidMode": "",
                "IpcMode": "private",
                "CapAdd": None,
                "Devices": [],
                "DeviceRequests": (
                    [{"Capabilities": [["gpu"]]}] if self.target_device_request else []
                ),
                "PortBindings": (
                    {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
                    if self.target_host_port_binding
                    else {}
                ),
            },
            "NetworkSettings": {
                "Networks": {self.network: {"NetworkID": TARGET_NETWORK_ID}},
                "Ports": {"80/tcp": None},
            },
            "Mounts": [],
        }

    def _target_network_inspect(self) -> dict[str, object]:
        assert self.network is not None
        return {
            "Id": TARGET_NETWORK_ID,
            "Name": self.network,
            "Internal": True,
            "Labels": {
                "com.ravage.evaluator.instance": self.instance_id,
                "com.ravage.evaluator.target-network": "true",
            },
        }

    def _agent_network_inspect(self) -> dict[str, object]:
        containers: dict[str, object] = {}
        if self.gateway_created:
            containers[GATEWAY_CONTAINER_ID] = {"Name": "gateway"}
        if self.foreign_agent_member_after_start and self.receipt_reads > 0:
            containers[UNOWNED_CONTAINER_ID] = {"Name": "foreign"}
        return {
            "Id": AGENT_NETWORK_ID,
            "Name": "agent-evaluator-net",
            "Internal": True,
            "Labels": {
                "com.ravage.evaluator.agent-network": "true",
                "com.ravage.evaluator.instance": self.instance_id,
            },
            "Containers": containers,
        }

    def _image_inspect(self, images: Sequence[str]) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        for image in images:
            image_id = (
                PROBE_IMAGE_ID
                if image == PROBE_IMAGE
                else GATEWAY_IMAGE_ID
                if image == GATEWAY_IMAGE
                else TARGET_IMAGE_ID
            )
            records.append(
                {
                    "Id": image_id,
                    "RepoDigests": [image] if "@sha256:" in image else [],
                    "Created": "2026-01-01T00:00:00Z",
                    "Architecture": "amd64",
                    "Os": "linux",
                    "Size": 123,
                    "RootFS": {"Layers": [f"sha256:{'7' * 64}"]},
                }
            )
        return records

    def _gateway_inspect(self) -> dict[str, object]:
        assert self.project is not None
        assert self.network is not None
        port_entries = (
            [{"HostIp": "127.0.0.1", "HostPort": str(self.gateway_port)}]
            if self.endpoint_mode in {"host_loopback", "cross_daemon_host_gateway"}
            else None
        )
        port_bindings = {f"{self.gateway_port}/tcp": port_entries} if port_entries else {}
        runtime_ports = dict(port_bindings)
        if self.gateway_extra_port_binding:
            extra = [{"HostIp": "127.0.0.1", "HostPort": "49000"}]
            port_bindings["49000/tcp"] = extra
            runtime_ports["49000/tcp"] = extra
        networks = {
            self.network: {
                "NetworkID": TARGET_NETWORK_ID,
                "IPAddress": "172.31.0.9",
                "Aliases": [self.network],
            }
        }
        if self.endpoint_mode != "cross_daemon_host_gateway" or self.gateway_extra_network:
            networks["agent-evaluator-net"] = {
                "NetworkID": AGENT_NETWORK_ID,
                "IPAddress": GATEWAY_AGENT_IP,
                "Aliases": ["ravage-target"],
            }
        return {
            "Id": GATEWAY_CONTAINER_ID,
            "Image": GATEWAY_IMAGE_ID,
            "Config": {
                "Labels": {
                    "com.ravage.evaluator.gateway": "true",
                    "com.ravage.evaluator.instance": self.instance_id,
                    "com.docker.compose.project": self.project,
                },
                "Entrypoint": ["python3"],
                "User": "65532:65532",
                "Healthcheck": {"Test": ["NONE"]},
                "Cmd": [
                    "-m",
                    "ravage.xben_parts.http_meter_gateway",
                    "serve",
                    "--listen-config",
                    "/run/ravage-http-meter/listen.json",
                    "--receipt",
                    "/run/ravage-http-meter/receipt.json",
                    "--instance-id",
                    self.instance_id,
                    "--listen-port",
                    str(self.gateway_port),
                    "--upstream-host",
                    "web",
                    "--upstream-port",
                    "80",
                    "--max-target-requests",
                    str(MAX_TARGET_REQUESTS),
                    "--access-boundary",
                    (
                        "trusted-host-loopback"
                        if self.endpoint_mode == "host_loopback"
                        else "root-owned-cross-daemon-loopback"
                        if self.endpoint_mode == "cross_daemon_host_gateway"
                        else "evaluator-owned-docker-network"
                    ),
                    "--max-request-body-bytes",
                    str(DEFAULT_MAX_REQUEST_BODY_BYTES),
                    "--max-response-body-bytes",
                    str(DEFAULT_MAX_RESPONSE_BODY_BYTES),
                    "--upstream-timeout-seconds",
                    "3",
                ],
            },
            "State": {"Running": True},
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": self.gateway_read_only,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidsLimit": 64,
                "Memory": 256 * 1024 * 1024,
                "NanoCpus": 250_000_000,
                "Tmpfs": {
                    "/run/ravage-http-meter": (
                        "rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=65532,gid=65532"
                    )
                },
                "PortBindings": port_bindings,
            },
            "NetworkSettings": {
                "Networks": networks,
                "Ports": runtime_ports,
            },
            "Mounts": [
                {
                    "Type": "tmpfs",
                    "Source": "",
                    "Destination": "/run/ravage-http-meter",
                    "RW": True,
                }
            ],
        }

    def _meter_receipt(self, *, final: bool) -> dict[str, object]:
        observed = 2 if final else 0
        accepted = observed
        rejected = 0
        if final and self.final_receipt_mode == "limit_exceeded":
            observed = 5
            accepted = MAX_TARGET_REQUESTS
            rejected = observed - accepted
        return {
            "schema_version": HTTP_METER_SCHEMA_VERSION,
            "program_sha256": program_sha256(),
            "protocol": HTTP_METER_PROTOCOL,
            "instance_id": self.instance_id,
            "ready": True,
            "sealed": final and self.gateway_sealed,
            "access_boundary": (
                "trusted-host-loopback"
                if self.endpoint_mode == "host_loopback"
                else "root-owned-cross-daemon-loopback"
                if self.endpoint_mode == "cross_daemon_host_gateway"
                else "evaluator-owned-docker-network"
            ),
            "caller_authentication": "none",
            "trusted_host_no_concurrent_local_adversary": (self.endpoint_mode == "host_loopback"),
            "listen_host": (
                "172.31.0.9"
                if self.endpoint_mode == "cross_daemon_host_gateway"
                else GATEWAY_AGENT_IP
            ),
            "listen_port": self.gateway_port,
            "upstream_host": "web",
            "upstream_port": 80,
            "max_target_requests": MAX_TARGET_REQUESTS,
            "max_request_body_bytes": DEFAULT_MAX_REQUEST_BODY_BYTES,
            "max_response_body_bytes": DEFAULT_MAX_RESPONSE_BODY_BYTES,
            "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
            "observed_requests": observed,
            "accepted_requests": accepted,
            "target_request_attempts": accepted,
            "unsupported_requests": 0,
            "rejected_over_limit": rejected,
            "upstream_errors": 0,
            "oversize_responses": 0,
            "in_flight_requests": 0,
            "sequence": 1 + observed + accepted + accepted + (1 if final else 0),
            "updated_at": "2026-09-11T00:00:00+00:00",
        }


def _docker_configuration(*, endpoint_mode: str = "docker_alias") -> DockerTargetConfiguration:
    cross_daemon = endpoint_mode == "cross_daemon_host_gateway"
    return DockerTargetConfiguration(
        gateway=GatewayConfiguration(
            image=GATEWAY_IMAGE,
            expected_image_id=GATEWAY_IMAGE_ID,
            agent_network=None if cross_daemon else "agent-evaluator-net",
            expected_agent_network_id=None if cross_daemon else AGENT_NETWORK_ID,
            expected_program_sha256=program_sha256(),
            max_target_requests=MAX_TARGET_REQUESTS,
            endpoint_mode=endpoint_mode,  # type: ignore[arg-type]
            agent_host_gateway="10.0.2.2" if cross_daemon else None,
            listen_port=50_000 if cross_daemon else 8_080,
            upstream_timeout_seconds=3,
        ),
        probe=_probe_configuration(),
        build_timeout_seconds=30,
        startup_timeout_seconds=20,
        inspect_timeout_seconds=10,
        teardown_timeout_seconds=15,
    )


def _probe_configuration() -> ProbeConfiguration:
    return ProbeConfiguration(
        image=PROBE_IMAGE,
        expected_image_id=PROBE_IMAGE_ID,
        attempts=2,
        per_attempt_timeout_seconds=1,
    )


def _git_repository(tmp_path: Path) -> tuple[Path, str, XbenCase]:
    repository = tmp_path / "xben"
    benchmarks = repository / "benchmarks"
    for number in range(1, 105):
        catalog_case = benchmarks / f"XBEN-{number:03d}-24"
        catalog_case.mkdir(parents=True)
        (catalog_case / ".catalog-member").write_text("XBEN\n", encoding="utf-8")
        (catalog_case / "Dockerfile").write_text("FROM nginx:latest\n", encoding="utf-8")
        (catalog_case / "benchmark.json").write_text(
            json.dumps(
                {
                    "name": "Comparison fixture",
                    "level": 1,
                    "description": "Find the proof through the application.",
                    "main_service": "web",
                    "main_service_port": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
    case_path = benchmarks / "XBEN-001-24"
    (case_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - '8080:80'\n",
        encoding="utf-8",
    )
    _git(repository, "init")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Comparison Test",
        "-c",
        "user.email=comparison@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    commit = _git_output(repository, "rev-parse", "HEAD")
    return repository, commit, _case(case_path)


def _compatibility_catalog(
    *,
    tmp_path: Path,
    repository: Path,
    commit: str,
    patches: Mapping[str, tuple[Path, str, Sequence[str]]],
    filename: str = "catalog.json",
) -> CompatibilityPatchCatalog:
    entries = []
    for case_id, (patch_path, patch_sha, touched_files) in patches.items():
        entries.append(
            {
                "case_id": case_id,
                "path": patch_path.relative_to(tmp_path).as_posix(),
                "sha256": patch_sha,
                "touched_files": list(touched_files),
            }
        )
    payload = {
        "schema_version": "ravage.paired-xben.compatibility-catalog.v1",
        "benchmark": "XBEN",
        "source": {
            "origin": "https://github.com/xbow-engineering/validation-benchmarks.git",
            "commit_sha": commit,
            "benchmarks_tree_sha": _git_output(repository, "rev-parse", f"{commit}:benchmarks"),
        },
        "coverage": {
            "case_id_pattern": "XBEN-001-24..XBEN-104-24",
            "case_count": 104,
            "default_action": "no_patch",
            "unlisted_cases_receive_patch": False,
        },
        "policy": {
            "purpose": (
                "Restore package-index availability for archived Debian releases without "
                "changing challenge application logic, services, credentials, vulnerabilities, "
                "or flags."
            ),
            "allowed_change_class": "legacy_debian_apt_mirror_only",
            "semantic_challenge_changes_allowed": False,
            "selection_time_changes_allowed": False,
            "post_draw_changes_allowed": False,
        },
        "patches": entries,
    }
    catalog_path = tmp_path / filename
    catalog_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return CompatibilityPatchCatalog(
        path=catalog_path,
        sha256=hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
    )


def _pinned_source(
    *,
    repository: Path,
    commit: str,
    catalog: CompatibilityPatchCatalog,
) -> PinnedXbenSource:
    return PinnedXbenSource(
        repository=repository,
        commit=commit,
        compatibility_patch_catalog=catalog,
    )


def _git(repository: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _git_output(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _case(path: Path, *, benchmark_id: str = "XBEN-001-24") -> XbenCase:
    return XbenCase(
        benchmark_id=benchmark_id,
        path=path,
        name="Comparison fixture",
        level=1,
        description="Find the proof through the application.",
        main_service="web",
        main_service_port=80,
    )
