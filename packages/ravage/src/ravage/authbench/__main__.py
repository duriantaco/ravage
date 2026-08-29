from __future__ import annotations

import json

from .evaluator import run_authbench
from .managed import ManagedSessionAuthBenchStrategy


def main() -> int:
    result = run_authbench(ManagedSessionAuthBenchStrategy())
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
