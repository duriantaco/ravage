#!/usr/bin/env python3
"""
Classify an XBEN run's failures into a rankable taxonomy.

Reads ``report.json`` produced by ``scripts/run_xben.py`` and writes a committable
``failure_taxonomy.json`` + ``failure_taxonomy.md`` next to it (Phase 0 of
``docs/competitor-gap-plan.md``). No model calls, no Docker -- pure trace
analysis, safe to run on any saved run directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RAVAGE_SRC = REPO_ROOT / "packages" / "ravage" / "src"
if RAVAGE_SRC.exists():
    sys.path.insert(0, str(RAVAGE_SRC))

from ravage.failure_taxonomy import load_failure_taxonomy, render_markdown  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report",
        type=Path,
        help="Path to an XBEN report.json (or its run directory).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Where to write failure_taxonomy.{json,md}. Defaults to the report directory.",
    )
    args = parser.parse_args()

    report_path = args.report
    if report_path.is_dir():
        report_path = report_path / "report.json"
    if not report_path.exists():
        sys.stderr.write(f"[grade:error] report not found: {report_path}\n")
        raise SystemExit(2)

    taxonomy = load_failure_taxonomy(report_path)
    output_dir = args.output_dir or report_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "failure_taxonomy.json"
    md_path = output_dir / "failure_taxonomy.md"
    json_path.write_text(
        json.dumps(taxonomy.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(taxonomy), encoding="utf-8")

    sys.stdout.write(
        f"[grade:summary] cases={taxonomy.total_cases} "
        f"solved={taxonomy.solved} solve_rate={taxonomy.solve_rate:.3f} "
        f"json={json_path} md={md_path}\n"
    )
    for category, count in sorted(
        taxonomy.category_counts.items(), key=lambda item: (-item[1], item[0])
    ):
        sys.stdout.write(f"[grade:category] {category}={count}\n")


if __name__ == "__main__":
    main()
