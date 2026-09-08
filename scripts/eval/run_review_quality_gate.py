"""Entry point for the mandatory read-only repository-review quality gate."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT, ROOT / "packages/ravage/src", ROOT / "packages/schemas/src"):
    sys.path.insert(0, str(path))

from tools.review_quality_gate.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
