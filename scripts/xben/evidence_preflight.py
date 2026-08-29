"""Record source and runtime state before an auditable XBEN run."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET_ENV_KEYS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "XBOW_API_KEY",
)


def _source_pythonpath_env() -> dict[str, str]:
    env = os.environ.copy()
    source_paths = [
        str(REPO_ROOT / "packages" / "ravage" / "src"),
        str(REPO_ROOT / "packages" / "schemas" / "src"),
    ]
    if env.get("PYTHONPATH"):
        source_paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(source_paths)
    return env


def _benchmark_python() -> Path:
    for candidate in (
        REPO_ROOT / ".venv" / "bin" / "python",
        REPO_ROOT / ".venv" / "bin" / "python3",
    ):
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def _run(command: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    proc = subprocess.run(  # noqa: S603
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def _checked_stdout(command: list[str]) -> str:
    result = _run(command)
    if result["returncode"] != 0:
        sys.stderr.write(
            f"[xben:evidence:error] command failed: {' '.join(command)}\n"
            f"{result['stderr']}\n"
        )
        raise SystemExit(2)
    return str(result["stdout"]).strip()


def _project_version(path: Path) -> str | None:
    if not path.exists():
        return None
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    project = data.get("project", {})
    version = project.get("version")
    return str(version) if version is not None else None


def _source_version(path: Path) -> str | None:
    if not path.exists():
        return None
    match = re.search(
        r"""SOURCE_VERSION\s*=\s*["']([^"']+)["']""",
        path.read_text(encoding="utf-8"),
    )
    return match.group(1) if match else None


def _versions() -> dict[str, Any]:
    return {
        "root_project": _project_version(REPO_ROOT / "pyproject.toml"),
        "ravage_project": _project_version(REPO_ROOT / "packages" / "ravage" / "pyproject.toml"),
        "schemas_project": _project_version(REPO_ROOT / "packages" / "schemas" / "pyproject.toml"),
        "ravage_source": _source_version(
            REPO_ROOT / "packages" / "ravage" / "src" / "ravage" / "_version.py"
        ),
        "schemas_source": _source_version(
            REPO_ROOT / "packages" / "schemas" / "src" / "pentest_schemas" / "_version.py"
        ),
    }


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    status = _checked_stdout(["git", "status", "--porcelain=v1"])
    commit = _checked_stdout(["git", "rev-parse", "HEAD"])
    tree = _checked_stdout(["git", "rev-parse", "HEAD^{tree}"])
    branch = _checked_stdout(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    benchmark_python = _benchmark_python()

    return {
        "schema": "ravage.xben.evidence_preflight.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "label": args.label,
        "case_ids": args.case_id,
        "intended_command": args.command,
        "repository": {
            "root": str(REPO_ROOT),
            "branch": branch,
            "head_commit": commit,
            "head_tree": tree,
            "head_subject": _checked_stdout(["git", "log", "-1", "--format=%s"]),
            "head_author_date": _checked_stdout(["git", "log", "-1", "--format=%aI"]),
            "tags_pointing_at_head": _checked_stdout(
                ["git", "tag", "--points-at", "HEAD"]
            ).splitlines(),
            "status_porcelain": status.splitlines(),
            "clean": status == "",
            "diff_name_status": _checked_stdout(["git", "diff", "--name-status"]).splitlines(),
            "staged_diff_name_status": _checked_stdout(
                ["git", "diff", "--cached", "--name-status"]
            ).splitlines(),
        },
        "expected_baseline": {
            "head_commit": args.baseline_head,
            "head_tree": args.baseline_tree,
        },
        "package_versions": _versions(),
        "runtime": {
            "python": sys.version,
            "python_executable": sys.executable,
            "benchmark_python_executable": str(benchmark_python),
            "benchmark_python_version": _run([str(benchmark_python), "--version"]),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "git_version": _run(["git", "--version"]),
            "docker_version": _run(["docker", "version", "--format", "{{json .}}"]),
            "docker_compose_version": _run(["docker", "compose", "version"]),
            "ravage_cli_version": _run(
                [
                    str(benchmark_python),
                    "-m",
                    "ravage",
                    "--version",
                ],
                env=_source_pythonpath_env(),
            ),
        },
        "environment_presence": {key: bool(os.environ.get(key)) for key in SECRET_ENV_KEYS},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True, help="Short name for this evidence point.")
    parser.add_argument("--case-id", action="append", default=[], help="XBEN case id being run.")
    parser.add_argument("--command", help="Exact benchmark command planned after this preflight.")
    parser.add_argument("--baseline-head", help="Expected git commit SHA for the run.")
    parser.add_argument("--baseline-tree", help="Expected git tree SHA for the run.")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Fail if the worktree is dirty.",
    )
    parser.add_argument("--output", type=Path, help="Path to write the JSON preflight record.")
    args = parser.parse_args()

    payload = build_payload(args)
    repo = payload["repository"]
    failures: list[str] = []
    if args.require_clean and not repo["clean"]:
        failures.append("worktree is not clean")
    if args.baseline_head and repo["head_commit"] != args.baseline_head:
        failures.append(f"HEAD mismatch: expected {args.baseline_head}, got {repo['head_commit']}")
    if args.baseline_tree and repo["head_tree"] != args.baseline_tree:
        failures.append(f"tree mismatch: expected {args.baseline_tree}, got {repo['head_tree']}")

    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
        sys.stdout.write(f"[xben:evidence] wrote {args.output}\n")
    else:
        sys.stdout.write(serialized)

    if failures:
        for failure in failures:
            sys.stderr.write(f"[xben:evidence:blocked] {failure}\n")
        raise SystemExit(3)


if __name__ == "__main__":
    main()
