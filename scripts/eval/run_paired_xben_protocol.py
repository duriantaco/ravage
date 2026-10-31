"""Run the create-only paired-XBEN comparison protocol."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.paired_xben.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
