"""Run the create-only paired known-site website regression protocol."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_SOURCE = ROOT / "packages" / "ravage" / "src"
for location in (str(ROOT), str(PACKAGE_SOURCE)):
    if location not in sys.path:
        sys.path.insert(0, location)

from tools.known_site_regression.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
