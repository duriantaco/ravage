from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ravage.agent_core.agent_state import AgentState
from ravage.probes.api_authorization import inventory_api_authorization


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path, help="Saved Ravage agent-state JSON file.")
    parser.add_argument("--output", type=Path, help="Write JSON here instead of stdout.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output file (never the input state).",
    )
    args = parser.parse_args(argv)

    try:
        loaded = _load_saved_state(args.state)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read state: {exc}")
    if loaded is None:
        parser.error("cannot read state: state payload must be an object")
    state, target_url = loaded

    text = (
        json.dumps(
            inventory_api_authorization(state, target_url=target_url),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.output:
        _write_output(
            parser,
            input_path=args.state,
            output_path=args.output,
            text=text,
            force=args.force,
        )
    else:
        sys.stdout.write(text)
    return 0


def _load_saved_state(path: Path) -> tuple[AgentState, str] | None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    raw_state = payload.get("state", payload)
    if not isinstance(raw_state, dict):
        return None
    target_url = str(payload.get("target_url") or "")
    return AgentState.from_json(raw_state), target_url


def _write_output(
    parser: argparse.ArgumentParser,
    *,
    input_path: Path,
    output_path: Path,
    text: str,
    force: bool,
) -> None:
    if _same_file(input_path, output_path):
        parser.error("--output must not replace the input state file")
    if output_path.exists() and not force:
        parser.error(f"output already exists (use --force to replace it): {output_path}")
    try:
        output_path.write_text(text, encoding="utf-8")
    except OSError as exc:
        parser.error(f"cannot write output: {exc}")


def _same_file(input_path: Path, output_path: Path) -> bool:
    if input_path.resolve() == output_path.resolve():
        return True
    try:
        output_exists = output_path.exists()
        points_to_input = output_exists and input_path.samefile(output_path)
    except OSError:
        return False
    return points_to_input


if __name__ == "__main__":
    raise SystemExit(main())
