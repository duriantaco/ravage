"""Run the offline corpus or the bounded loopback source navigation canary."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "packages/ravage/src"))

from tools.source_navigation_eval.corpus import MANIFEST, evaluate_corpus  # noqa: E402


def revision() -> dict[str, object]:
    executable = shutil.which("git")
    if executable is None:
        message = "git is required to attest the evaluated revision"
        raise RuntimeError(message)

    def git(*args: str) -> str:
        # Arguments are fixed read-only Git queries below.
        return subprocess.check_output([executable, *args], cwd=ROOT, text=True).strip()  # noqa: S603

    return {
        "head": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "clean": not git("status", "--porcelain"),
    }


def toolchain_digest() -> str:
    paths = [Path(__file__).resolve(), MANIFEST]
    paths.extend(sorted((ROOT / "tools/source_navigation_eval").glob("*.py")))
    paths.extend(
        ROOT / "packages/ravage/src/ravage" / name
        for name in (
            "agent_core/source_navigation.py",
            "agent_core/source_context.py",
            "agent_core/ai_agent.py",
            "repository_context.py",
            "model_core/providers.py",
        )
    )
    lock = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
    }
    return hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest()


def parse_args(argv: list[str] | None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["offline", "canary"])
    parser.add_argument(
        "--output", type=Path, help="create a new JSON report; existing files are never overwritten"
    )
    parser.add_argument("--pairs", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--driver", choices=["scripted", "gpt54"], default="scripted")
    parser.add_argument("--allow-paid-models", action="store_true")
    parser.add_argument(
        "--budget-usd", type=float, default=2.0, help="aggregate GPT-5.4 budget across all arms"
    )
    args = parser.parse_args(argv)
    if args.mode == "offline" and (args.driver != "scripted" or args.allow_paid_models):
        parser.error("offline mode never uses a model")
    if args.driver == "gpt54" and not args.allow_paid_models:
        parser.error("GPT-5.4 canary requires --allow-paid-models")
    if args.output is not None and args.output.exists():
        parser.error("output already exists; choose a new report path")
    return parser, args


def main(argv: list[str] | None = None) -> int:
    parser, args = parse_args(argv)
    try:
        before, toolchain_before = revision(), toolchain_digest()
        if args.mode == "offline":
            report = evaluate_corpus()
        else:
            from tools.source_navigation_eval.canary import (  # noqa: PLC0415
                ScriptedDriver,
                run_canary,
            )

            if args.driver == "gpt54":
                from tools.source_navigation_eval.provider import (  # noqa: PLC0415
                    GPT54Driver,
                    ModelBudget,
                )

                if not before["clean"]:
                    parser.error("paid canary requires a clean committed revision")
                budget = ModelBudget(args.budget_usd)

                def factory() -> GPT54Driver:
                    return GPT54Driver(allow_paid_models=args.allow_paid_models, budget=budget)

                report = run_canary(pairs=args.pairs, driver_factory=factory)
            else:
                report = run_canary(pairs=args.pairs, driver_factory=ScriptedDriver)
        after, toolchain_after = revision(), toolchain_digest()
        report.update(
            {"revision": before, "post_revision": after, "toolchain_sha256": toolchain_before}
        )
        if before != after or toolchain_before != toolchain_after:
            report["passed"] = False
            report["integrity_error"] = "revision or toolchain changed during the run"
        rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
            args.output.chmod(0o600)
            sys.stdout.write(f"passed={report['passed']}; report={args.output}\n")
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
