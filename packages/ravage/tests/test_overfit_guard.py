from __future__ import annotations

from pathlib import Path

from ravage.overfit_guard import (
    Violation,
    default_scan_roots,
    is_scannable,
    scan_paths,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_scan_flags_hardcoded_benchmark_id() -> None:
    found = scan_text(Path("probe.py"), "    if benchmark == 'XBEN-099-24':\n")
    assert [violation.rule for violation in found] == ["benchmark_id"]


def test_scan_flags_hardcoded_flag_value_but_not_redaction_placeholder() -> None:
    flagged = scan_text(Path("probe.py"), "    expected = 'flag{objectid_idor_first_profile}'\n")
    assert [violation.rule for violation in flagged] == ["hardcoded_flag"]
    assert scan_text(Path("reporting.py"), "    return 'flag{REDACTED}'\n") == []
    assert scan_text(Path("self_check.py"), "    probe = 'flag{probe}'\n") == []
    assert scan_text(Path("self_check.py"), "    probe = 'flag{test}'\n") == []


def test_generated_flag_requires_nonzero_randomness() -> None:
    generated = 'flag = f"flag{{ravage_{secrets.token_hex(32)}}}"\n'
    deterministic = 'flag = f"flag{{known_{secrets.token_hex(0)}}}"\n'

    assert scan_text(Path("benchmark.py"), generated) == []
    assert [violation.rule for violation in scan_text(Path("benchmark.py"), deterministic)] == [
        "hardcoded_flag"
    ]


def test_scan_allows_cryptographically_generated_flag_template() -> None:
    source = '    flag = f"flag{{ravage_{secrets.token_hex(32)}}}"\n'
    assert scan_text(Path("runner.py"), source) == []


def test_scan_flags_forbidden_literal() -> None:
    found = scan_text(Path("runbook.py"), "    paths = ('/starttime',)\n")
    assert [violation.rule for violation in found] == ["forbidden_literal"]


def test_scan_flags_known_benchmark_shaped_runtime_literals() -> None:
    samples = (
        "target = '10032'",
        "username = 'not_that_easy'",
        "path = '/amortization'",
        "field = 'image_profile'",
        "template = 'not_implemented.html'",
        "path = 'register/step'",
        "path = '/password/test'",
        "path = '/api/change_password.php'",
        "path = '/orders_archive'",
    )

    for sample in samples:
        found = scan_text(Path("runtime.py"), sample + "\n")
        assert [violation.rule for violation in found] == ["forbidden_literal"]


def test_scan_flags_competitor_and_benchmark_patterns() -> None:
    assert [v.rule for v in scan_text(Path("a.py"), "url = 'KeygraphHQ/shannon'\n")] == [
        "competitor_name"
    ]
    assert [v.rule for v in scan_text(Path("b.py"), "root = 'xbow-validation-benchmarks'\n")] == [
        "benchmark_repo"
    ]
    assert [v.rule for v in scan_text(Path("c.py"), "target = '/var/secret.txt'\n")] == [
        "challenge_file"
    ]
    assert [v.rule for v in scan_text(Path("d.py"), "case = 'XBEN-9'\n")] == [
        "benchmark_id"
    ]
    assert [v.rule for v in scan_text(Path("e.py"), "root = 'xbow-validation'\n")] == [
        "benchmark_repo"
    ]


def test_only_canonical_file_read_payload_list_may_name_secret_file() -> None:
    package = Path("packages/ravage/src/ravage")
    payloads = package / "probes/file_read/payloads.py"
    runtime = package / "probes/file_read/runtime.py"

    assert scan_text(payloads, 'candidate = "secret.txt"\n') == []
    assert [v.rule for v in scan_text(runtime, 'candidate = "secret.txt"\n')] == [
        "challenge_file"
    ]


def test_benchmark_trees_exempt_metadata_rules_only(tmp_path: Path) -> None:
    package = tmp_path / "packages" / "ravage" / "src" / "ravage"
    metadata_files = []
    dangerous_files = []
    for subtree in ("xben_parts", "authbench"):
        metadata = package / subtree / "metadata.py"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            "system = 'KeygraphHQ/shannon'  # XBEN-099-24, xbow-validation-benchmarks\n",
            encoding="utf-8",
        )
        metadata_files.append(metadata)

        dangerous = package / subtree / "executor.py"
        dangerous.write_text(
            "expected = 'flag{known_benchmark_proof}'\n"
            "endpoint = '/starttime'\n"
            "proof_file = '/var/secret.txt'\n",
            encoding="utf-8",
        )
        dangerous_files.append(dangerous)

    competitor_benchmarks = package / "competitor_benchmarks.py"
    competitor_benchmarks.write_text(
        "system = 'Keygraph'  # cites XBEN-099-24\n", encoding="utf-8"
    )
    production_xben = package / "runtime" / "xben.py"
    production_xben.parent.mkdir()
    production_xben.write_text("system = 'Keygraph'\n", encoding="utf-8")

    violations = scan_paths([package])
    rules_by_path = {
        path: [violation.rule for violation in violations if violation.path == path]
        for path in (*metadata_files, *dangerous_files, competitor_benchmarks, production_xben)
    }

    assert all(rules_by_path[path] == [] for path in metadata_files)
    assert all(
        rules_by_path[path] == ["hardcoded_flag", "forbidden_literal", "challenge_file"]
        for path in dangerous_files
    )
    assert rules_by_path[competitor_benchmarks] == ["benchmark_id", "competitor_name"]
    assert rules_by_path[production_xben] == ["competitor_name"]


def test_default_scan_root_is_the_complete_production_package() -> None:
    roots = default_scan_roots(REPO_ROOT)
    package = REPO_ROOT / "packages" / "ravage" / "src" / "ravage"
    proof_recognizer = package / "web_core" / "proof_recognizer.py"
    formerly_omitted_module = package / "control_plane" / "runner_protocol.py"

    assert roots == (package,)
    assert package.exists()
    assert proof_recognizer.exists()
    assert formerly_omitted_module.exists()


def test_default_scan_catches_formerly_omitted_production_subtrees(tmp_path: Path) -> None:
    package = default_scan_roots(tmp_path)[0]
    omitted_module = package / "control_plane" / "challenge_shortcut.py"
    omitted_module.parent.mkdir(parents=True)
    omitted_module.write_text("endpoint = '/starttime'\n", encoding="utf-8")

    found = scan_paths(default_scan_roots(tmp_path))

    assert [(violation.path, violation.rule) for violation in found] == [
        (omitted_module, "forbidden_literal")
    ]


def test_scan_paths_reports_missing_configured_root(tmp_path: Path) -> None:
    missing_root = tmp_path / "removed-source-root"

    found = scan_paths([missing_root])

    assert found == [
        Violation(
            path=missing_root,
            line=0,
            rule="missing_scan_path",
            match="missing",
            source="configured scan path does not exist",
        )
    ]


def test_exemptions_are_narrow_and_do_not_hide_production_near_misses() -> None:
    package = Path("packages/ravage/src/ravage")

    assert not is_scannable(package / "overfit_guard.py")
    assert not is_scannable(Path("packages/ravage/tests/test_overfit_guard.py"))
    assert not is_scannable(Path("tests/integration/fixtures/sample.py"))

    assert is_scannable(package / "xben_parts/runner.py")
    assert is_scannable(package / "xben_setup_parts/compose.py")
    assert is_scannable(package / "authbench/fixtures.py")
    assert is_scannable(package / "runtime/xben.py")
    assert is_scannable(package / "xben_parts_extra/runner.py")
    assert is_scannable(package / "runtime/tests/challenge_shortcut.py")
    assert is_scannable(package / "runtime/fixtures/challenge_shortcut.py")
    assert is_scannable(package / "runtime/challenge_shortcut.js")


def test_default_roots_cover_builtin_skills_and_have_no_stale_paths() -> None:
    roots = default_scan_roots(REPO_ROOT)
    package = REPO_ROOT / "packages" / "ravage" / "src" / "ravage"

    assert roots == (package,)
    assert (package / "agent_knowledge" / "builtin").exists()
    assert (package / "satcom").exists()
    assert all(path.exists() for path in roots)


def test_violation_render_is_relative_when_possible() -> None:
    violation = Violation(REPO_ROOT / "pkg" / "mod.py", 3, "benchmark_id", "x", "line")
    assert violation.render(repo_root=REPO_ROOT) == "pkg/mod.py:3: [benchmark_id] x -- line"
