from __future__ import annotations

import sys


def main() -> None:
    sys.stderr.write(
        "This Ravage entrypoint is stale and still imports `orchestrator`.\n"
        "Repair the source checkout virtualenv:\n\n"
        "  scripts/bootstrap.sh\n\n"
        "Then rerun:\n\n"
        "  ravage setup check\n"
    )
    raise SystemExit(2)
