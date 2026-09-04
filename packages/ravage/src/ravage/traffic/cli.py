# ruff: noqa: EM101, EM102, TRY003
"""Command-line interface for scoped request capture and one-shot replay."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from ravage.cli_ui import badge, banner, tone
from ravage.web_core.scope_policy import is_local_url

from .manifest import (
    TrafficRunError,
    TrafficRunManifest,
    read_traffic_manifest,
    resolve_workspace,
    resolve_workspaces,
)
from .provenance import load_traffic_provenance
from .redaction import redact_text, sanitize_url
from .replay import SAFE_REPLAY_METHODS, diff_records, replay_exchange
from .store import TrafficStore, TrafficStoreError

_ASSET_RESOURCE_TYPES = frozenset(
    {"font", "image", "media", "script", "stylesheet", "manifest", "other"}
)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SLOT_RE = re.compile(
    r"(?:path\.[0-9]+|query\.[A-Za-z0-9_.\[\]-]+|header\.[A-Za-z0-9-]+|"
    r"body)"
)
_MAX_DISPLAY_URL_CHARS = 100

if TYPE_CHECKING:
    from .contracts import CapturedHttpExchange, ReplayReceipt
    from .provenance import AgentHttpEvidenceLink, TrafficProvenanceIndex


@dataclass(frozen=True, slots=True)
class _TrafficLane:
    name: str
    workspace: Path
    manifest: TrafficRunManifest
    store: TrafficStore
    exchanges: tuple[CapturedHttpExchange, ...]
    replays: tuple[ReplayReceipt, ...]
    provenance: TrafficProvenanceIndex


def handle_traffic_command(args: Sequence[str]) -> None:
    parser = _parser()
    parsed = parser.parse_args(list(args))
    try:
        if parsed.command == "capture":
            _capture(parsed)
        elif parsed.command == "list":
            _list(parsed)
        elif parsed.command == "show":
            _show(parsed)
        elif parsed.command == "replay":
            _replay(parsed)
        elif parsed.command == "diff":
            _diff(parsed)
        else:  # pragma: no cover - argparse requires a known subcommand.
            parser.error("a traffic command is required")
    except (TrafficRunError, TrafficStoreError, KeyError, ValueError) as exc:
        parser.error(_safe_error(exc))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ravage traffic",
        description=(
            "Capture scoped browser requests, inspect their redacted contracts, "
            "and replay one request at a time."
        ),
        epilog=(
            "Start local:  ravage traffic capture http://127.0.0.1:3000\n"
            "Then inspect: ravage traffic list RUN_DIR\n"
            "Platform:     macOS, Linux, or WSL (not native Windows)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    capture = commands.add_parser(
        "capture",
        help="open a scope-restricted browser and capture request shapes",
    )
    capture.add_argument("target_url", help="authorized HTTP(S) application URL")
    capture.add_argument("--run-dir", type=Path)
    capture.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help="confirm explicit authorization for this remote target",
    )
    capture.add_argument(
        "--headless",
        action="store_true",
        help="run without a visible browser; normally pair with --duration",
    )
    capture.add_argument(
        "--duration",
        type=float,
        help="stop automatically after this many seconds",
    )
    capture.add_argument("--timeout-seconds", type=int, default=30)
    capture.add_argument(
        "--max-requests",
        type=int,
        default=5_000,
        help="fail closed after this many HTTP/WebSocket requests (default: 5000)",
    )
    capture.add_argument("--json", action="store_true")

    listing = commands.add_parser("list", help="list captured application requests")
    listing.add_argument("run_dir", type=Path)
    listing.add_argument("--all", action="store_true", help="include static assets")
    listing.add_argument("--json", action="store_true")

    show = commands.add_parser("show", help="show one redacted request contract")
    show.add_argument("run_dir", type=Path)
    show.add_argument("request_id")
    show.add_argument("--json", action="store_true")

    replay = commands.add_parser("replay", help="replay one captured request once")
    replay.add_argument("run_dir", type=Path)
    replay.add_argument("request_id")
    replay.add_argument(
        "--authorized-remote-target",
        action="store_true",
        help="confirm explicit authorization for this remote target",
    )
    replay.add_argument(
        "--allow-state-change",
        action="store_true",
        help="arm this one replay when the method may change server state",
    )
    replay.add_argument(
        "--set",
        dest="values",
        action="append",
        default=[],
        metavar="SLOT=VALUE",
        help="supply a non-secret redacted slot value",
    )
    replay.add_argument(
        "--bind",
        dest="env_values",
        action="append",
        default=[],
        metavar="SLOT=ENV_VAR",
        help="read a secret slot value from an environment variable",
    )
    replay.add_argument("--timeout-seconds", type=int, default=10)
    replay.add_argument("--json", action="store_true")

    diff = commands.add_parser("diff", help="compare two captures/replays offline")
    diff.add_argument("run_dir", type=Path)
    diff.add_argument("left_id")
    diff.add_argument("right_id")
    diff.add_argument("--json", action="store_true")
    return parser


def _capture(parsed: argparse.Namespace) -> None:  # noqa: C901
    if parsed.duration is not None and parsed.duration <= 0:
        raise ValueError("--duration must be greater than zero")
    if parsed.headless and parsed.duration is None:
        raise ValueError("--headless requires --duration so the capture has a stop condition")
    run_dir = parsed.run_dir or _default_capture_run_dir()

    # Import lazily so list/show/diff and the main Ravage CLI do not require the
    # optional browser dependency.
    try:
        from .capture_runtime import (  # noqa: PLC0415
            BrowserCaptureError,
            capture_browser_traffic,
        )
    except ImportError as exc:  # pragma: no cover - module is in this package.
        raise ValueError(f"browser capture is unavailable: {exc}") from None

    if not parsed.json:
        _line(banner("TRAFFIC CAPTURE", sanitize_url(parsed.target_url)))
        _line(
            f"{badge('scope', 'info')} same origin · routed HTTP(S) and WebSocket "
            "connections checked before send"
        )
        if not is_local_url(parsed.target_url):
            _line(
                f"{badge('network', 'info')} loopback SOCKS5 · approved DNS pins only · "
                "QUIC disabled"
            )
        _line(f"{badge('limit', 'muted')} {parsed.max_requests} requests · fail closed")
        if not parsed.headless and parsed.duration is None:
            _line(f"{badge('ready', 'ok')} use the browser, then press Enter here to finish")

    def on_exchange(exchange: CapturedHttpExchange) -> None:
        if parsed.json:
            return
        status = exchange.response_status if exchange.response_status is not None else "blocked"
        marker = "ok" if exchange.request_sent else "blocked"
        style = "ok" if exchange.request_sent else "warn"
        _line(
            f"{badge(marker, style)} {exchange.exchange_id} "
            f"{tone(exchange.request_method, 'info')} {status} "
            f"{_display_url(exchange.request_url)}"
        )

    try:
        summary = capture_browser_traffic(
            target_url=parsed.target_url,
            run_dir=run_dir,
            allow_remote_target=parsed.authorized_remote_target,
            headless=parsed.headless,
            duration_seconds=parsed.duration,
            timeout_seconds=parsed.timeout_seconds,
            max_requests=parsed.max_requests,
            on_exchange=on_exchange,
        )
    except BrowserCaptureError as exc:
        raise ValueError(str(exc)) from None

    payload = summary.to_json()
    if parsed.json:
        _line(json.dumps(payload, indent=2, sort_keys=True))
        if summary.interrupted:
            raise SystemExit(130)
        return
    if summary.interrupted:
        _line(
            f"{badge('capture:partial', 'warn')} {summary.captured} requests · "
            f"{summary.contracts} contracts"
        )
        _line(f"{badge('run', 'info')} {summary.run_dir}")
        _line(f"{badge('next', 'info')} ravage traffic list {summary.run_dir}")
        raise SystemExit(130)
    _line(
        f"{badge('capture:done', 'ok')} {summary.captured} requests · {summary.contracts} contracts"
    )
    _line(f"{badge('run', 'info')} {summary.run_dir}")
    if summary.recorder_errors:
        _line(f"{badge('warning', 'warn')} {len(summary.recorder_errors)} capture warnings")
    _line(f"{badge('next', 'info')} ravage traffic list {summary.run_dir}")


def _list(parsed: argparse.Namespace) -> None:
    lanes = _open_lanes(parsed.run_dir)
    qualified = len(lanes) > 1
    visible: list[tuple[_TrafficLane, CapturedHttpExchange, AgentHttpEvidenceLink]] = []
    hidden_assets = 0
    for lane in lanes:
        links_by_id = {link.request_id: link for link in lane.provenance.links}
        for exchange in lane.exchanges:
            if not parsed.all and exchange.request_resource_type in _ASSET_RESOURCE_TYPES:
                hidden_assets += 1
                continue
            visible.append((lane, exchange, links_by_id[exchange.exchange_id]))
    payload: dict[str, object] = {
        "run_dir": str(parsed.run_dir),
        "workspace_dir": str(lanes[0].workspace),
        "requests": [
            _exchange_summary(
                exchange,
                request_id=_qualified_id(lane.name, exchange.exchange_id)
                if qualified
                else exchange.exchange_id,
                lane=lane.name if qualified else "",
                agent_evidence=evidence_link.summary_json(),
            )
            for lane, exchange, evidence_link in visible
        ],
        "contracts": sum(len(lane.store.contracts()) for lane in lanes),
        "hidden_assets": hidden_assets,
    }
    if qualified:
        payload["workspaces"] = [
            {"lane": lane.name, "workspace_dir": str(lane.workspace)} for lane in lanes
        ]
    if parsed.json:
        _line(json.dumps(payload, indent=2, sort_keys=True))
        return
    _line(banner("TRAFFIC HISTORY", f"{len(visible)} requests"))
    if not visible:
        _line(f"{badge('empty', 'muted')} no application requests were captured")
    for lane, exchange, evidence_link in visible:
        status = exchange.response_status if exchange.response_status is not None else "—"
        sent = "" if exchange.request_sent else " blocked"
        request_id = (
            _qualified_id(lane.name, exchange.exchange_id) if qualified else exchange.exchange_id
        )
        request_id_width = 27 if qualified else 9
        _line(
            f"{request_id:<{request_id_width}} {exchange.request_method:<7} {status!s:<7} "
            f"{_display_url(exchange.request_url)}{sent}"
            f"{_evidence_list_suffix(evidence_link)}"
        )
    if payload["hidden_assets"]:
        _line(
            f"{badge('filtered', 'muted')} {payload['hidden_assets']} static assets hidden; "
            "add --all"
        )
    if visible:
        lane, exchange, _evidence_link = visible[0]
        request_id = (
            _qualified_id(lane.name, exchange.exchange_id) if qualified else exchange.exchange_id
        )
        _line(f"{badge('next', 'info')} ravage traffic show {parsed.run_dir} {request_id}")


def _show(parsed: argparse.Namespace) -> None:
    lanes = _open_lanes(parsed.run_dir)
    lane, exchange = _select_exchange(lanes, parsed.request_id)
    qualified = len(lanes) > 1
    request_id = (
        _qualified_id(lane.name, exchange.exchange_id) if qualified else exchange.exchange_id
    )
    evidence_link = lane.provenance.for_exchange_id(exchange.exchange_id)
    contract = lane.store.contract(exchange.semantic_fingerprint)
    payload: dict[str, object] = {
        "exchange": exchange.to_json(),
        "contract": contract.to_json() if contract is not None else None,
        "agent_evidence": evidence_link.to_json(),
    }
    if qualified:
        payload.update(
            {
                "lane": lane.name,
                "qualified_id": request_id,
                "workspace_dir": str(lane.workspace),
            }
        )
    if parsed.json:
        _line(json.dumps(payload, indent=2, sort_keys=True))
        return
    _line(banner("REQUEST CONTRACT", request_id))
    _line(f"method     {exchange.request_method}")
    _line(f"url        {exchange.request_url}")
    _line(f"source     {exchange.source} · {exchange.request_resource_type or 'http'}")
    response_status = exchange.response_status if exchange.response_status is not None else "none"
    _line(f"response   {response_status}")
    _line(f"replay     {exchange.replayability}")
    if exchange.request_body_field_names:
        fields = ", ".join(exchange.request_body_field_names)
        _line(f"body       {exchange.request_body_media_type or 'unknown'} · fields: {fields}")
    if exchange.unresolved_slots:
        _line(f"needs      {', '.join(exchange.unresolved_slots)}")
    else:
        _line("needs      no replacement values")
    observations = contract.observation_count if contract is not None else 1
    _line(f"observed   {observations} time{'s' if observations != 1 else ''}")
    _show_evidence_link(evidence_link)
    _line(f"{badge('next', 'info')} fill the values below, then run:")
    for line in _replay_command_skeleton(
        parsed.run_dir,
        exchange,
        lane.manifest.origin,
        request_id=request_id,
    ):
        _line(f"  {line}")


def _replay(parsed: argparse.Namespace) -> None:
    lanes = _open_lanes(parsed.run_dir, writable=True)
    lane, exchange = _select_exchange(lanes, parsed.request_id)
    qualified = len(lanes) > 1
    request_id = (
        _qualified_id(lane.name, exchange.exchange_id) if qualified else exchange.exchange_id
    )
    bindings = _bindings(parsed.values, parsed.env_values)
    result = replay_exchange(
        store=lane.store,
        manifest=lane.manifest,
        exchange=exchange,
        allow_remote_target=parsed.authorized_remote_target,
        allow_state_change=parsed.allow_state_change,
        bindings=bindings,
        timeout_seconds=parsed.timeout_seconds,
    )
    receipt = result.receipt
    payload = receipt.to_json()
    replay_id = _qualified_id(lane.name, receipt.replay_id) if qualified else receipt.replay_id
    if qualified:
        payload.update(
            {
                "lane": lane.name,
                "qualified_id": replay_id,
                "source_request_ref": request_id,
                "workspace_dir": str(lane.workspace),
            }
        )
    if parsed.json:
        _line(json.dumps(payload, indent=2, sort_keys=True))
        if not result.sent:
            raise SystemExit(2)
        if receipt.response_status is None:
            raise SystemExit(1)
    elif result.sent and receipt.response_status is not None:
        _line(banner("REQUEST REPLAY", replay_id))
        _line(
            f"{badge('sent', 'ok')} {receipt.request_method} "
            f"{receipt.response_status if receipt.response_status is not None else 'no response'} "
            f"{_display_url(receipt.request_url)}"
        )
        _line(
            f"{badge('next', 'info')} ravage traffic diff {parsed.run_dir} {request_id} {replay_id}"
        )
    elif not result.sent:
        _line(f"{badge('blocked', 'warn')} {result.error}")
        _line(f"{badge('receipt', 'info')} {replay_id} · no request sent")
        raise SystemExit(2)
    else:
        _line(banner("REQUEST REPLAY", replay_id))
        _line(
            f"{badge('attempted', 'warn')} {receipt.request_method} · no response · "
            f"{_display_url(receipt.request_url)}"
        )
        _line(f"{badge('error', 'warn')} {receipt.response_error or 'transport failed'}")
        _line(f"{badge('receipt', 'info')} {replay_id} · request attempted")
        raise SystemExit(1)


def _diff(parsed: argparse.Namespace) -> None:
    lanes = _open_lanes(parsed.run_dir)
    left_lane, left_id = _select_record(lanes, parsed.left_id)
    right_lane, right_id = _select_record(lanes, parsed.right_id)
    if left_lane.workspace != right_lane.workspace:
        raise ValueError("traffic diff requires both records to be in the same lane/store")
    try:
        payload = diff_records(left_lane.store, left_id, right_id)
    except KeyError as exc:
        raise KeyError(f"unknown traffic record ID: {exc.args[0]}") from None
    if len(lanes) > 1:
        payload.update(
            {
                "lane": left_lane.name,
                "left_ref": _qualified_id(left_lane.name, left_id),
                "right_ref": _qualified_id(right_lane.name, right_id),
                "workspace_dir": str(left_lane.workspace),
            }
        )
    if parsed.json:
        _line(json.dumps(payload, indent=2, sort_keys=True))
        return
    _line(banner("TRAFFIC DIFF", f"{parsed.left_id} → {parsed.right_id}"))
    changes = payload["changes"]
    assert isinstance(changes, Mapping)
    if not changes:
        _line(f"{badge('same', 'ok')} no recorded metadata changed")
        return
    for name, change in changes.items():
        if isinstance(change, Mapping):
            suffix = f" · Δ {change['delta']}" if "delta" in change else ""
            _line(f"{name:<22} {change.get('left')} → {change.get('right')}{suffix}")


def _open_lanes(run_dir: Path, *, writable: bool = False) -> tuple[_TrafficLane, ...]:
    supplied = Path(run_dir)
    try:
        os.lstat(supplied / "traffic")
    except FileNotFoundError:
        workspaces = resolve_workspaces(supplied)
    except OSError as exc:
        raise TrafficRunError("could not inspect explicit traffic workspace") from exc
    else:
        # Preserve exact selection when the operator names a workspace. Run
        # roots have no direct traffic directory and intentionally aggregate.
        workspaces = (resolve_workspace(supplied),)
    if not workspaces:
        raise TrafficRunError(f"no traffic history found in run directory {run_dir}")
    lanes: list[_TrafficLane] = []
    for workspace in workspaces:
        manifest = read_traffic_manifest(workspace)
        store = TrafficStore.open(workspace, writable=writable)
        exchanges = store.exchanges()
        replays = store.replay_receipts()
        if any(
            exchange.capture_session_id != manifest.capture_session_id
            for exchange in exchanges
        ) or any(
            receipt.capture_session_id != manifest.capture_session_id for receipt in replays
        ):
            raise TrafficStoreError("traffic store contains records from another capture session")
        provenance = load_traffic_provenance(
            workspace,
            exchanges=exchanges,
            target_identity=manifest.target_identity,
        )
        lanes.append(
            _TrafficLane(
                name=_lane_name(workspace),
                workspace=workspace,
                manifest=manifest,
                store=store,
                exchanges=exchanges,
                replays=replays,
                provenance=provenance,
            )
        )
    if lanes:
        expected_boundary = _lane_manifest_boundary(lanes[0].manifest)
        if any(
            _lane_manifest_boundary(lane.manifest) != expected_boundary
            for lane in lanes[1:]
        ):
            raise TrafficRunError("traffic histories disagree on target or scope")
    return tuple(lanes)


def _open_store(run_dir: Path, *, writable: bool = False) -> tuple[Path, TrafficStore]:
    """Open one explicit traffic store for compatibility with internal callers."""
    workspace = resolve_workspace(run_dir)
    manifest = read_traffic_manifest(workspace)
    store = TrafficStore.open(workspace, writable=writable)
    exchanges = store.exchanges()
    replays = store.replay_receipts()
    if any(
        exchange.capture_session_id != manifest.capture_session_id for exchange in exchanges
    ) or any(
        receipt.capture_session_id != manifest.capture_session_id for receipt in replays
    ):
        raise TrafficStoreError("traffic store contains records from another capture session")
    load_traffic_provenance(
        workspace,
        exchanges=exchanges,
        target_identity=manifest.target_identity,
    )
    return workspace, store


def _select_exchange(
    lanes: Sequence[_TrafficLane],
    request_ref: str,
) -> tuple[_TrafficLane, CapturedHttpExchange]:
    selected_lane, request_id = _parse_qualified_ref(lanes, request_ref)
    candidates = (
        (lane, exchange)
        for lane in lanes
        if selected_lane is None or lane.name == selected_lane
        if (
            exchange := next(
                (item for item in lane.exchanges if item.exchange_id == request_id),
                None,
            )
        )
        is not None
    )
    matches = tuple(candidates)
    if not matches:
        raise KeyError(f"unknown request ID: {request_ref}")
    if len(matches) > 1:
        choices = ", ".join(_qualified_id(lane.name, request_id) for lane, _ in matches)
        raise TrafficRunError(f"request ID {request_id} is ambiguous; use one of: {choices}")
    return matches[0]


def _select_record(
    lanes: Sequence[_TrafficLane],
    record_ref: str,
) -> tuple[_TrafficLane, str]:
    selected_lane, record_id = _parse_qualified_ref(lanes, record_ref)
    matches = tuple(
        lane
        for lane in lanes
        if selected_lane is None or lane.name == selected_lane
        if _lane_has_record(lane, record_id)
    )
    if not matches:
        raise KeyError(f"unknown traffic record ID: {record_ref}")
    if len(matches) > 1:
        choices = ", ".join(_qualified_id(lane.name, record_id) for lane in matches)
        raise TrafficRunError(f"traffic record ID {record_id} is ambiguous; use one of: {choices}")
    return matches[0], record_id


def _parse_qualified_ref(
    lanes: Sequence[_TrafficLane],
    record_ref: str,
) -> tuple[str | None, str]:
    lane_name, separator, record_id = record_ref.partition(":")
    if not separator:
        return None, record_ref
    known = {lane.name for lane in lanes}
    if lane_name not in known:
        raise ValueError(f"unknown traffic lane: {lane_name}")
    if not record_id:
        raise ValueError("qualified traffic ID is missing its record ID")
    return lane_name, record_id


def _lane_has_record(lane: _TrafficLane, record_id: str) -> bool:
    if record_id.startswith("rq_"):
        return any(exchange.exchange_id == record_id for exchange in lane.exchanges)
    if record_id.startswith("rp_"):
        return any(receipt.replay_id == record_id for receipt in lane.replays)
    return False


def _lane_name(workspace: Path) -> str:
    if workspace.name == "agent-graph" and workspace.parent.name == "autonomous-route":
        return "autonomous_graph"
    return "base"


def _lane_manifest_boundary(manifest: TrafficRunManifest) -> tuple[object, ...]:
    return (
        manifest.target_url,
        manifest.target_identity,
        manifest.origin,
        manifest.in_scope,
        manifest.out_of_scope,
    )


def _qualified_id(lane: str, record_id: str) -> str:
    return f"{lane}:{record_id}"


def _bindings(values: Sequence[str], env_values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for assignment in values:
        slot, value = _assignment(assignment, label="--set")
        if slot in result:
            raise ValueError(f"replacement slot supplied more than once: {slot}")
        result[slot] = value
    for assignment in env_values:
        slot, env_name = _assignment(assignment, label="--bind")
        if not _ENV_NAME_RE.fullmatch(env_name):
            raise ValueError(f"invalid environment variable name for {slot}")
        if env_name not in os.environ or not os.environ[env_name]:
            raise ValueError(f"environment variable {env_name} is missing or empty")
        if slot in result:
            raise ValueError(f"replacement slot supplied more than once: {slot}")
        result[slot] = os.environ[env_name]
    return result


def _assignment(value: str, *, label: str) -> tuple[str, str]:
    slot, separator, replacement = value.partition("=")
    if not separator or not slot or not replacement:
        raise ValueError(f"{label} expects SLOT=VALUE")
    if not _SLOT_RE.fullmatch(slot):
        raise ValueError(f"invalid replacement slot: {slot}")
    return slot, replacement


def _exchange_summary(
    exchange: CapturedHttpExchange,
    *,
    request_id: str,
    lane: str,
    agent_evidence: Mapping[str, object],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": request_id,
        "method": exchange.request_method,
        "url": exchange.request_url,
        "resource_type": exchange.request_resource_type,
        "navigation": exchange.request_navigation,
        "sent": exchange.request_sent,
        "status": exchange.response_status,
        "replayability": exchange.replayability,
        "unresolved_slots": list(exchange.unresolved_slots),
        "agent_evidence": dict(agent_evidence),
    }
    if lane:
        payload["lane"] = lane
    return payload


def _evidence_list_suffix(link: AgentHttpEvidenceLink) -> str:
    if link.status == "not_applicable":
        return ""
    if link.status == "linked":
        return f" evidence=linked:{len(link.evidence_refs)}"
    return f" evidence={link.status.replace('_', '-')}"


def _show_evidence_link(link: AgentHttpEvidenceLink) -> None:
    if link.observation_id:
        _line(f"observation {link.observation_id}")
    if link.status == "linked":
        _line(
            f"evidence   {len(link.evidence_refs)} linked · "
            f"{len(link.material_evidence_refs)} material"
        )
        for record in link.evidence_records:
            material = " · material" if record.material else ""
            _line(
                f"  {record.kind} {record.evidence_id} · {record.source} · "
                f"{record.producer_node_id}{material}"
            )
    elif link.status == "observation_only":
        _line("evidence   observation only · no matching blackboard record")
    elif link.status == "missing_observation":
        _line("evidence   missing agent observation ID")
    else:
        _line("evidence   not applicable to this capture source")
    if link.blackboard_path:
        _line(f"blackboard {link.blackboard_path}")


def _replay_command_skeleton(
    run_dir: Path,
    exchange: CapturedHttpExchange,
    origin: str,
    *,
    request_id: str | None = None,
) -> tuple[str, ...]:
    if exchange.replayability == "not_replayable":
        return ("This blocked request is not replayable.",)
    lines: list[str] = []
    bindings: list[str] = []
    used_env_names: set[str] = set()
    for slot in exchange.unresolved_slots:
        base_env_name = "RAVAGE_REPLAY_" + re.sub(r"[^A-Za-z0-9]+", "_", slot).upper()
        env_name = base_env_name
        suffix = 2
        while env_name in used_env_names:
            env_name = f"{base_env_name}_{suffix}"
            suffix += 1
        used_env_names.add(env_name)
        lines.append(f"export {env_name}='<fill-me>'")
        bindings.extend(("--bind", f"{slot}={env_name}"))
    command = [
        "ravage",
        "traffic",
        "replay",
        str(run_dir),
        request_id or exchange.exchange_id,
        *bindings,
    ]
    if not is_local_url(origin):
        command.append("--authorized-remote-target")
    if (
        exchange.request_method not in SAFE_REPLAY_METHODS
        or exchange.replayability == "requires_authorization"
    ):
        command.append("--allow-state-change")
    lines.append(shlex.join(command))
    return tuple(lines)


def _display_url(url: str) -> str:
    parsed = urlsplit(url)
    short = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    if len(short) <= _MAX_DISPLAY_URL_CHARS:
        return short
    return short[: _MAX_DISPLAY_URL_CHARS - 1] + "…"


def _default_capture_run_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return Path("runs") / f"traffic-capture-{stamp}"


def _safe_error(exc: BaseException) -> str:
    text = redact_text(exc, max_chars=1_000).replace("\n", " ").replace("\r", " ").strip()
    return text[:1_000] or type(exc).__name__


def _line(value: str) -> None:
    sys.stdout.write(value + "\n")
    sys.stdout.flush()


__all__ = ["handle_traffic_command"]
