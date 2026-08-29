#!/usr/bin/env python3
"""
Anti-overfit guard (Gate 1 of ``docs/blackbox-gap-analysis-and-plan.md``).

Scans non-test source for benchmark-specific constants that turn a generic class
capability into a single-challenge solver: hardcoded benchmark ids, baked-in flag
values, and known-overfit literals. Prints ``file:line`` for each offence and
exits non-zero when any are found. No model calls, no Docker -- pure static scan.

    python scripts/check_overfit.py
    python scripts/check_overfit.py packages/ravage/src/ravage/agent_core
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RAVAGE_SRC = REPO_ROOT / "packages" / "ravage" / "src"
if RAVAGE_SRC.exists():
    sys.path.insert(0, str(RAVAGE_SRC))

from ravage.overfit_guard import default_scan_roots, scan_paths  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Files or directories to scan. Defaults to the production package.",
    )
    args = parser.parse_args()

    roots = tuple(args.paths) if args.paths else default_scan_roots(REPO_ROOT)
    violations = scan_paths(roots)
    if not violations:
        print("overfit-guard: clean")  # noqa: T201 - CLI summary output
        return 0
    print(f"overfit-guard: {len(violations)} violation(s)")  # noqa: T201 - CLI summary output
    for violation in violations:
        print(f"  {violation.render(repo_root=REPO_ROOT)}")  # noqa: T201 - CLI summary output
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
