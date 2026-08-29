from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml

from ravage.run_data.run_manifest import RunManifest

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

FLAG_RE = re.compile(r"flag\{[^}\s]*\}", re.IGNORECASE)
MAX_SMALL_VALUE_DEPTH = 3


class _StreamCursor:

    def __init__(self) -> None:
        self.run_key: str | None = None
        self.sent_steps: set[str] = set()
        self.docker_sig: str | None = None
        self.target_sig: str | None = None
        self.status_sig: str | None = None

    def deltas(self, state: dict[str, Any]) -> list[tuple[str, object]]:
        run_key = _run_key(state)
        if run_key != self.run_key:
            return self._reset_to(run_key, state)
        out: list[tuple[str, object]] = []
        for command in _stream_commands(state):
            signature = _step_signature(command)
            if signature not in self.sent_steps:
                self.sent_steps.add(signature)
                out.append(("step", command))
        out.extend(self._panel_delta(state))
        return out

    def _reset_to(self, run_key: str, state: dict[str, Any]) -> list[tuple[str, object]]:
        self.run_key = run_key
        self.sent_steps = {_step_signature(c) for c in _stream_commands(state)}
        self.docker_sig = _sig(_docker_block(state))
        self.target_sig = _sig(_target_block(state))
        self.status_sig = _sig(_status_block(state))
        return [("state", state)]

    def _panel_delta(self, state: dict[str, Any]) -> list[tuple[str, object]]:
        out: list[tuple[str, object]] = []
        docker_sig = _sig(_docker_block(state))
        if docker_sig != self.docker_sig:
            self.docker_sig = docker_sig
            out.append(("docker", _docker_block(state)))
        target_sig = _sig(_target_block(state))
        if target_sig != self.target_sig:
            self.target_sig = target_sig
            out.append(("target", _target_block(state)))
        status_sig = _sig(_status_block(state))
        if status_sig != self.status_sig:
            self.status_sig = status_sig
            out.append(("status", _status_block(state)))
        return out


def _run_key(state: dict[str, Any]) -> str:
    manifest = state.get("manifest")
    if isinstance(manifest, dict) and manifest.get("run_id"):
        suffix = manifest.get("created_at") or manifest.get("docker_project") or ""
        return f"{manifest['run_id']}|{suffix}"
    paths = state.get("paths")
    if isinstance(paths, dict):
        return str(paths.get("workspace_dir") or "")
    return ""


def _stream_commands(state: dict[str, Any]) -> list[dict[str, Any]]:
    viewer = state.get("viewer")
    if not isinstance(viewer, dict):
        return []
    commands = viewer.get("commands")
    return [c for c in commands if isinstance(c, dict)] if isinstance(commands, list) else []


def _step_signature(command: dict[str, Any]) -> str:
    return "|".join(
        str(command.get(key)) for key in ("timestamp", "kind", "commandId", "yaml")
    )


def _docker_block(state: dict[str, Any]) -> dict[str, Any]:
    return {"docker": state.get("docker"), "docker_log": state.get("docker_log")}


def _target_block(state: dict[str, Any]) -> dict[str, Any]:
    viewer = _object_dict(state.get("viewer"))
    return {
        "mode": state.get("mode"),
        "target": viewer.get("target"),
        "run": viewer.get("run"),
    }


def _status_block(state: dict[str, Any]) -> dict[str, Any]:
    viewer = _object_dict(state.get("viewer"))
    return {
        "mode": state.get("mode"),
        "metrics": state.get("metrics"),
        "warnings": state.get("warnings"),
        "flags": state.get("flags"),
        "run": viewer.get("run"),
        "evidence": viewer.get("evidence"),
        "surface": viewer.get("surface"),
        "findings": state.get("findings"),
        "stage_flow": state.get("stage_flow"),
        "selection": state.get("selection"),
    }


def _sig(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)

def _loads_object(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _object_dict(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    parsed: dict[str, Any] = {}
    for key, item in value.items():
        parsed[str(key)] = item
    return parsed


def _record_payload(record: dict[str, Any]) -> dict[str, Any]:
    return _object_dict(record.get("payload"))


def _metrics(
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    terminal: list[dict[str, Any]],
) -> dict[str, Any]:
    run_completed = _last_payload(events, "run_completed") or _last_audit_payload(
        audit_rows,
        "run_completed",
    )
    max_actions = _last_audit_payload(audit_rows, "max_actions_reached")
    completed = bool(run_completed or _has_audit_action(audit_rows, "agent_finished"))
    run_success = _run_success(run_completed)
    model_replies = sum(1 for row in audit_rows if row.get("action") == "model_reply_received")
    flags = _collect_flags(events, audit_rows)
    return {
        "completed": completed,
        "run_success": run_success,
        "run_label": _run_label(
            completed=completed,
            run_success=run_success,
            run_completed=run_completed,
            max_actions=max_actions,
        ),
        "events": len(events),
        "audit_rows": len(audit_rows),
        "model_replies": model_replies,
        "findings": len(findings),
        "flags": len(flags),
        "terminal_sessions": len(terminal),
        "current_turn": _current_turn(audit_rows),
        "cost_usd_total": _cost_total(audit_rows),
    }


def _current_turn(audit_rows: list[dict[str, Any]]) -> int:
    turn = 0
    for row in audit_rows:
        payload = row.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("turn"), int):
            turn = max(turn, payload["turn"])
    return turn


def _cost_total(audit_rows: list[dict[str, Any]]) -> float:
    total = 0.0
    for row in audit_rows:
        cost = row.get("cost_usd")
        if isinstance(cost, (int, float)):
            total += float(cost)
    return round(total, 4)


def _latest_objective(audit_rows: list[dict[str, Any]], events: list[dict[str, Any]]) -> str:
    """Return a short human line describing what the agent is currently pursuing."""
    for event in reversed(events):
        if event.get("kind") == "action_started" and isinstance(event.get("payload"), dict):
            payload = event["payload"]
            summary = str(payload.get("summary") or "").strip()
            detail = str(payload.get("detail") or "").strip()
            if summary:
                return f"{summary} — {detail}" if detail else summary
    for row in reversed(audit_rows):
        if row.get("action") == "agent_action_selected" and isinstance(row.get("payload"), dict):
            action = row["payload"].get("action")
            if isinstance(action, dict):
                notes = str(action.get("notes") or action.get("strategy") or "").strip()
                if notes:
                    return _clip(notes, 220)
    return ""


def _run_success(run_completed: object) -> bool:
    if not isinstance(run_completed, dict):
        return False
    if "completed" in run_completed:
        return run_completed.get("completed") is True
    status = str(run_completed.get("status") or "").lower()
    return status in {"ok", "success", "completed", "passed"}


def _run_label(
    *,
    completed: bool,
    run_success: bool,
    run_completed: object,
    max_actions: object,
) -> str:
    if max_actions or (
        isinstance(run_completed, dict)
        and str(run_completed.get("status") or "") == "max_actions_reached"
    ):
        return "Stopped: action limit"
    if run_success:
        return "Completed"
    if completed:
        return "Completed with issues"
    return "Running"


def _selection(audit_rows: list[dict[str, Any]]) -> dict[str, Any]:
    route: dict[str, Any] = {}
    runtime_mode = None
    tool_image = None
    missing_optional: list[str] = []
    selected_tools: list[str] = []
    for row in audit_rows:
        action = row.get("action")
        payload = row.get("payload")
        if action == "model_reply_received" and isinstance(payload, dict):
            raw_route = payload.get("route")
            if isinstance(raw_route, dict):
                route = dict(raw_route)
            else:
                route = {key: payload[key] for key in ("provider", "model") if key in payload}
        if action == "tool_capability_preflight" and isinstance(payload, dict):
            runtime_mode = payload.get("runtime_mode")
            tool_image = payload.get("tool_image")
            missing_optional = [str(item) for item in payload.get("missing_optional", [])]
            selected_tools = _selected_tools(payload.get("capabilities"))
    return {
        "tool_runtime_mode": runtime_mode,
        "tool_image": tool_image,
        "missing_optional": missing_optional,
        "selected_tools": selected_tools,
        "last_model_route": route,
    }


def _selected_tools(capabilities: object) -> list[str]:
    if not isinstance(capabilities, dict):
        return []
    selected: list[str] = []
    for capability in capabilities.values():
        if not isinstance(capability, dict) or not capability.get("available"):
            continue
        provider = capability.get("selected_provider")
        if not isinstance(provider, dict):
            continue
        binary = provider.get("binary") or provider.get("action")
        runtime = provider.get("selected_runtime")
        if binary and runtime:
            selected.append(f"{binary} ({runtime})")
        elif binary:
            selected.append(str(binary))
    return sorted(selected)


def _warnings(metrics: Mapping[str, Any], selection: Mapping[str, Any]) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    if metrics.get("run_label") == "Stopped: action limit":
        warnings.append(
            {
                "title": "Run stopped at action limit",
                "detail": (
                    "The agent reached its configured action budget before "
                    "a clean success state."
                ),
            }
        )
    missing_optional = selection.get("missing_optional")
    if missing_optional:
        warnings.append(
            {
                "title": "Optional tools unavailable",
                "detail": ", ".join(str(item) for item in missing_optional),
            }
        )
    return warnings


def _activity(
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = [
        {
            "timestamp": event.get("timestamp"),
            "source": "workspace",
            "kind": event.get("kind") or event.get("role") or "event",
            "payload": event.get("payload", event.get("content")),
        }
        for event in events
    ]
    items.extend(
        [
            {
                "timestamp": row.get("timestamp"),
                "source": "audit",
                "kind": row.get("action"),
                "actor": row.get("actor"),
                "payload": row.get("payload"),
            }
            for row in audit_rows
        ]
    )
    return sorted(items, key=lambda item: str(item.get("timestamp") or ""))[-200:]


def _stage_flow(audit_rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    stages = [
        ("setup", "Setup"),
        ("reconnaissance", "Reconnaissance"),
        ("access", "Access"),
        ("exploitation", "Exploitation"),
        ("validation", "Validation"),
        ("proof", "Proof"),
    ]
    active: set[str] = set()
    for row in audit_rows:
        if row.get("action") != "kill_chain_stage":
            continue
        payload = _object_dict(row.get("payload"))
        stage_id = str(payload.get("stage_id") or "")
        if stage_id:
            active.add(stage_id)
    actions = {str(row.get("action") or "") for row in audit_rows}
    if "agent_started" in actions:
        active.add("setup")
    if "recon_completed" in actions:
        active.add("reconnaissance")
    if actions & {"model_reply_received", "agent_action_selected"}:
        active.add("access")
    if any(action.startswith("tool_") for action in actions):
        active.add("exploitation")
    if _has_audit_action(audit_rows, "finding_confirmed"):
        active.add("validation")
    if _has_audit_action(audit_rows, "flag_captured"):
        active.add("proof")
    return [
        {"id": stage_id, "label": label, "status": "done" if stage_id in active else "pending"}
        for stage_id, label in stages
    ]


def _kill_chain_breakdown(
    audit_rows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    breakdown = _initial_kill_chain_breakdown(findings_count=len(findings))
    by_id = _breakdown_by_id(breakdown)

    for row in audit_rows:
        _apply_breakdown_audit_row(row, breakdown=breakdown, by_id=by_id)

    for item in breakdown:
        _dedupe_breakdown_actions(item)
    return breakdown


_KILL_CHAIN_STAGE_SPECS = (
    ("setup", "Setup"),
    ("reconnaissance", "Recon"),
    ("access", "Access"),
    ("exploitation", "Exploit"),
    ("validation", "Validate"),
    ("proof", "Proof"),
)


def _initial_kill_chain_breakdown(*, findings_count: int) -> list[dict[str, Any]]:
    breakdown: list[dict[str, Any]] = []
    for stage_id, label in _KILL_CHAIN_STAGE_SPECS:
        stage = _empty_breakdown_stage(stage_id=stage_id, label=label)
        if stage_id == "validation":
            stage["findings"] = findings_count
        breakdown.append(stage)
    return breakdown


def _empty_breakdown_stage(*, stage_id: str, label: str) -> dict[str, Any]:
    return {
        "id": stage_id,
        "label": label,
        "actions": [],
        "flags": 0,
        "findings": 0,
    }


def _breakdown_by_id(breakdown: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in breakdown:
        stage_id = str(item.get("id") or "")
        if stage_id:
            by_id[stage_id] = item
    return by_id


def _apply_breakdown_audit_row(
    row: dict[str, Any],
    *,
    breakdown: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
) -> None:
    action = str(row.get("action") or "")
    if action == "kill_chain_stage":
        _mark_breakdown_stage_update(row, breakdown=breakdown, by_id=by_id)
        return
    if action == "flag_captured":
        _record_breakdown_flag_capture(breakdown)
        return
    if action == "agent_action_selected":
        stage = _breakdown_stage(breakdown, "exploitation")
        _append_breakdown_action(stage, "Agent action selected")
        return
    if action.startswith("tool_"):
        stage = _breakdown_stage(breakdown, "exploitation")
        _append_breakdown_action(stage, "Tool result")


def _mark_breakdown_stage_update(
    row: dict[str, Any],
    *,
    breakdown: list[dict[str, Any]],
    by_id: dict[str, dict[str, Any]],
) -> None:
    payload = _object_dict(row.get("payload"))
    stage_id = str(payload.get("stage_id") or "")
    stage = by_id.get(stage_id)
    if stage is None:
        stage = _breakdown_stage(breakdown, "reconnaissance")
    _append_breakdown_action(stage, "Stage updated")


def _record_breakdown_flag_capture(breakdown: list[dict[str, Any]]) -> None:
    stage = _breakdown_stage(breakdown, "proof")
    _increment_breakdown_flags(stage)
    _append_breakdown_action(stage, "Flag captured")


def _breakdown_stage(breakdown: list[dict[str, Any]], stage_id: str) -> dict[str, Any]:
    for item in breakdown:
        if item.get("id") == stage_id:
            return item
    return breakdown[0]


def _dedupe_breakdown_actions(stage: dict[str, Any]) -> None:
    actions = stage.get("actions")
    if isinstance(actions, list):
        stage["actions"] = list(dict.fromkeys(actions))


def _append_breakdown_action(stage: dict[str, Any], label: str) -> None:
    actions = stage.get("actions")
    if isinstance(actions, list):
        actions.append(label)


def _increment_breakdown_flags(stage: dict[str, Any]) -> None:
    current = stage.get("flags")
    if isinstance(current, int):
        stage["flags"] = current + 1
        return
    stage["flags"] = 1


def _agents(audit_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actors = sorted({str(row.get("actor")) for row in audit_rows if row.get("actor")})
    return [{"id": actor, "label": _actor_label(actor)} for actor in actors]


def _actor_label(actor: str) -> str:
    labels = {
        "ai_web_agent": "AI web agent",
        "agent": "Agent",
        "model": "Model",
        "tool": "Tool runtime",
        "orchestrator": "Orchestrator",
        "dast_scan": "DAST scan",
    }
    return labels.get(actor, actor.replace("_", " ").capitalize())


def _work_chart(
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for event in events:
        key = str(event.get("kind") or event.get("role") or "event")
        counts[key] = counts.get(key, 0) + 1
    for row in audit_rows:
        key = str(row.get("action") or "audit")
        counts[key] = counts.get(key, 0) + 1
    return [
        {"label": label, "count": count}
        for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]


def _viewer_state(  # noqa: PLR0913
    *,
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    working_state: dict[str, Any],
    lab: dict[str, Any],
    metrics: dict[str, Any],
    findings: list[dict[str, Any]],
    flags: list[str],
    manifest: RunManifest | None = None,
    mode: str = "live",
) -> dict[str, Any]:
    target_url = _viewer_target_url(
        events=events,
        audit_rows=audit_rows,
        lab=lab,
        manifest=manifest,
    )
    target_status = _target_status_for_mode(target_url, mode)
    progress = _object_dict(working_state.get("progress"))
    planner = _object_dict(working_state.get("planner"))
    recommended = planner.get("recommended_actions", [])

    return {
        "brand": "Ravage Cockpit",
        "run": _viewer_run_block(
            events=events,
            audit_rows=audit_rows,
            working_state=working_state,
            lab=lab,
            metrics=metrics,
            manifest=manifest,
            mode=mode,
            target_url=target_url,
        ),
        "commands": _viewer_commands(events=events, audit_rows=audit_rows, metrics=metrics),
        "target": _viewer_target_block(lab=lab, target_url=target_url, target_status=target_status),
        "surface": _viewer_surface_block(
            working_state=working_state,
            progress=progress,
            recommended=recommended,
            flags=flags,
        ),
        "evidence": _viewer_evidence_block(findings=findings, flags=flags),
    }


def _viewer_target_url(
    *,
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    lab: dict[str, Any],
    manifest: RunManifest | None,
) -> str:
    target_url = _target_url(events, audit_rows, lab)
    if target_url:
        return target_url
    if manifest is not None and manifest.target_url:
        return manifest.target_url
    return ""


def _viewer_run_block(  # noqa: PLR0913
    *,
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    working_state: dict[str, Any],
    lab: dict[str, Any],
    metrics: dict[str, Any],
    manifest: RunManifest | None,
    mode: str,
    target_url: str,
) -> dict[str, Any]:
    return {
        "label": metrics.get("run_label"),
        "active": _viewer_run_active(manifest=manifest, metrics=metrics),
        "phase": _viewer_run_phase(manifest=manifest, working_state=working_state),
        "status": _viewer_manifest_status(manifest),
        "mode": mode,
        "benchmark_id": _viewer_benchmark_id(manifest=manifest, lab=lab),
        "run_id": _viewer_manifest_run_id(manifest),
        "started_at": _viewer_manifest_created_at(manifest),
        "target_url": target_url,
        "keep_target": _viewer_manifest_keep_target(manifest),
        "lab_name": _viewer_lab_name(lab),
        "objective": _latest_objective(audit_rows, events),
        "turn": metrics.get("current_turn", 0),
        "max_turns": _viewer_manifest_max_turns(manifest),
        "cost_usd": metrics.get("cost_usd_total", 0.0),
        "model_requests": metrics.get("model_replies", 0),
    }


def _viewer_run_active(*, manifest: RunManifest | None, metrics: dict[str, Any]) -> bool:
    if manifest is not None:
        return manifest.is_active
    return not bool(metrics.get("completed"))


def _viewer_run_phase(*, manifest: RunManifest | None, working_state: dict[str, Any]) -> str:
    phase = str(working_state.get("phase") or working_state.get("status") or "idle")
    if manifest is not None and manifest.phase:
        return manifest.phase
    return phase


def _viewer_manifest_status(manifest: RunManifest | None) -> str | None:
    if manifest is None:
        return None
    return manifest.status


def _viewer_benchmark_id(*, manifest: RunManifest | None, lab: dict[str, Any]) -> str:
    if manifest is not None and manifest.benchmark_id:
        return manifest.benchmark_id
    return str(lab.get("id") or "")


def _viewer_manifest_run_id(manifest: RunManifest | None) -> str:
    if manifest is None:
        return ""
    return manifest.run_id


def _viewer_manifest_created_at(manifest: RunManifest | None) -> str:
    if manifest is None:
        return ""
    return manifest.created_at


def _viewer_manifest_keep_target(manifest: RunManifest | None) -> bool:
    if manifest is None:
        return False
    return manifest.keep_target


def _viewer_manifest_max_turns(manifest: RunManifest | None) -> int:
    if manifest is None:
        return 0
    return manifest.max_turns


def _viewer_lab_name(lab: dict[str, Any]) -> str:
    name = str(lab.get("name") or lab.get("id") or "")
    if name:
        return name
    return "Unlabeled target"


def _viewer_target_block(
    *,
    lab: dict[str, Any],
    target_url: str,
    target_status: dict[str, Any],
) -> dict[str, Any]:
    return {
        "url": target_url,
        "status": target_status,
        "name": lab.get("name") or lab.get("id") or "Target",
        "healthcheck": lab.get("healthcheck"),
        "difficulty": lab.get("difficulty"),
        "category": lab.get("category"),
        "services": _compose_services(lab),
    }


def _viewer_surface_block(
    *,
    working_state: dict[str, Any],
    progress: dict[str, Any],
    recommended: object,
    flags: list[str],
) -> dict[str, Any]:
    return {
        "route_count": progress.get("route_count"),
        "captured_flag_count": len(flags),
        "recommended_actions": _small_value(recommended),
        "facts": _small_value(working_state.get("facts", [])),
    }


def _viewer_evidence_block(
    *,
    findings: list[dict[str, Any]],
    flags: list[str],
) -> dict[str, Any]:
    return {
        "findings": len(findings),
        "flags": len(flags),
    }


def _viewer_commands(
    *,
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> list[dict[str, Any]]:
    records = _command_records(events=events, audit_rows=audit_rows)
    commands: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        is_last = index == len(records) - 1
        payload = _record_payload(record)
        commands.append(
            {
                "commandId": str(index + 1),
                "yaml": _record_yaml(record),
                "depth": _command_depth(record),
                "status": _record_status(record, is_last=is_last, metrics=metrics),
                "label": _command_label(record),
                "detail": _command_detail(record),
                "request": _command_request(record),
                "output": _command_output(record),
                "why": _command_why(record),
                "action_id": str(payload.get("action_id") or ""),
                "errorMessage": _record_error(record),
                "timestamp": record.get("timestamp"),
                "kind": record.get("kind"),
                "source": record.get("source"),
            }
        )
    return commands


def _command_request(record: dict[str, Any]) -> dict[str, Any] | None:
    """
    Return the request the agent sent for this step, for the detail pane.

    Fields are already credential-masked upstream (describe_action / http_step).
    """
    kind = str(record.get("kind") or "")
    payload = _record_payload(record)
    if kind == "http_step":
        headers = payload.get("response_headers")
        return {
            "method": payload.get("method"),
            "path": payload.get("path") or payload.get("url"),
            "fields": _object_dict(payload.get("fields")),
            "status": payload.get("status"),
            "ok": payload.get("ok"),
            "response_headers": _object_dict(headers),
        }
    if kind == "action_started":
        params = _object_dict(payload.get("params"))
        for key in ("steps", "command", "probe"):
            if key not in params:
                continue
            return {key: params.get(key)}
        return None
    return None


def _command_why(record: dict[str, Any]) -> list[dict[str, str]]:
    if record.get("kind") != "action_started":
        return []

    payload = _record_payload(record)
    rows: list[dict[str, str]] = []
    for key, label in _COMMAND_REASON_FIELDS:
        row = _command_reason_row(payload, key=key, label=label)
        if row:
            rows.append(row)
    return rows


_COMMAND_REASON_FIELDS = (
    ("strategy", "strategy"),
    ("notes", "why"),
    ("expected_signal", "expect"),
    ("fallback", "fallback"),
)


def _command_reason_row(payload: dict[str, Any], *, key: str, label: str) -> dict[str, str]:
    value = str(payload.get(key) or "").strip()
    if not value:
        return {}
    return {
        "label": label,
        "text": _clip(value, 400),
    }


def _command_output(record: dict[str, Any]) -> str:
    """Return the response/output text for this step (masked at the state boundary)."""
    kind = str(record.get("kind") or "")
    payload = _record_payload(record)
    if kind == "http_step":
        return _http_step_output(payload)
    if kind == "model_reply_received":
        return _model_reply_output(payload)
    if kind.startswith("tool_"):
        return _tool_output(payload)
    if kind in {"recon_completed", "recon_failed"}:
        return _json_payload_output(payload)
    return ""


def _http_step_output(payload: dict[str, Any]) -> str:
    return _clip(str(payload.get("body") or ""), 4000)


def _model_reply_output(payload: dict[str, Any]) -> str:
    return _clip(str(payload.get("content") or ""), 4000)


def _tool_output(payload: dict[str, Any]) -> str:
    direct_output = _first_text_payload_value(payload, keys=("result", "observation"))
    if direct_output:
        return _clip(direct_output, 4000)

    stream_output = _joined_text_payload_values(payload, keys=("stdout", "stderr"))
    return _clip(stream_output, 4000)


def _json_payload_output(payload: dict[str, Any]) -> str:
    text = json.dumps(_small_value(payload), sort_keys=True, default=str)
    return _clip(text, 2000)


def _first_text_payload_value(payload: dict[str, Any], *, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _joined_text_payload_values(payload: dict[str, Any], *, keys: tuple[str, ...]) -> str:
    parts: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return "\n".join(parts)


def _command_label(record: dict[str, Any]) -> str:
    kind = str(record.get("kind") or "")
    payload = _record_payload(record)
    if kind == "action_started":
        return str(payload.get("summary") or "Agent action")
    if kind == "http_step":
        method = str(payload.get("method") or "GET")
        path = str(payload.get("path") or payload.get("url") or "")
        status = payload.get("status")
        suffix = _status_suffix(status)
        return f"{method} {path}{suffix}".strip()
    return _STEP_LABELS.get(kind) or _tool_label(kind)


def _command_depth(record: dict[str, Any]) -> int:
    if record.get("kind") == "http_step":
        return 1
    return 0


def _status_suffix(status: object) -> str:
    if not status:
        return ""
    return f" → {status}"


def _tool_label(kind: str) -> str:
    if kind.startswith("tool_"):
        return "Run " + kind.removeprefix("tool_").replace("_", " ")
    return kind.replace("_", " ") or "event"


def _command_detail(record: dict[str, Any]) -> str:
    kind = str(record.get("kind") or "")
    payload = _record_payload(record)
    if kind == "action_started":
        return str(payload.get("detail") or "")
    if kind == "http_step":
        fields = payload.get("fields")
        if isinstance(fields, dict) and fields:
            return ", ".join(f"{key}={value}" for key, value in fields.items())
    if kind == "flag_captured":
        flag = payload.get("flag")
        if isinstance(flag, str):
            return flag
    return ""


_STEP_LABELS = {
    "agent_started": "Launch Ravage agent",
    "recon_completed": "Discover attack surface",
    "recon_failed": "Recon failed",
    "model_reply_received": "Model planned the next action",
    "agent_action_selected": "Agent selected next action",
    "agent_finished": "Agent finished",
    "agent_final": "Agent stopped",
    "flag_captured": "Capture proof string",
    "flag_capture_rejected": "Reject non-proof candidate",
    "finding_confirmed": "Confirm finding with evidence",
    "finding_rejected_no_evidence": "Reject finding without evidence",
    "run_completed": "Run completed",
    "max_actions_reached": "Stopped at action budget",
    "tool_capability_preflight": "Check tool runtime and Docker image",
    "tool_run_command": "Run command",
    "tool_run_python": "Run Python helper",
    "tool_run_probe": "Run probe",
    "tool_validate_poc": "Validate proof of concept",
}

_WORKSPACE_STEP_KINDS = frozenset({"action_started", "http_step", "agent_final"})


def _command_records(
    *,
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = _audit_command_records(audit_rows)
    rows.extend(_workspace_step_records(events))

    if not rows:
        rows.extend(_fallback_event_records(events))

    rows.sort(key=lambda item: str(item.get("timestamp") or ""))
    return rows[-200:]


def _audit_command_records(audit_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in audit_rows:
        record = _audit_command_record(row)
        if record:
            records.append(record)
    return records


def _audit_command_record(row: dict[str, Any]) -> dict[str, Any]:
    action = str(row.get("action") or "")
    if not _is_viewer_action(action):
        return {}
    return {
        "timestamp": row.get("timestamp"),
        "kind": action,
        "source": row.get("actor") or "audit",
        "payload": row.get("payload"),
    }


def _workspace_step_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for event in events:
        kind = str(event.get("kind") or "")
        if kind not in _WORKSPACE_STEP_KINDS:
            continue
        records.append(_workspace_event_record(event, kind=kind))
    return records


def _fallback_event_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for event in events:
        kind = str(event.get("kind") or "")
        if not kind:
            continue
        records.append(_workspace_event_record(event, kind=kind))
    return records


def _workspace_event_record(event: dict[str, Any], *, kind: str) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "kind": kind,
        "source": "workspace",
        "payload": event.get("payload"),
    }


def _is_viewer_action(action: str) -> bool:
    return (
        action
        in {
            "agent_started",
            "agent_action_selected",
            "agent_finished",
            "model_reply_received",
            "recon_completed",
            "recon_failed",
            "kill_chain_stage",
            "flag_captured",
            "flag_capture_rejected",
            "finding_confirmed",
            "finding_rejected_no_evidence",
            "run_completed",
            "max_actions_reached",
            "tool_capability_preflight",
        }
        or action.startswith("tool_")
    )


def _record_yaml(record: dict[str, Any]) -> str:
    kind = str(record.get("kind") or "event")
    payload = _record_payload(record)
    step_name = _step_name(kind, payload)
    step_payload = _step_payload(kind, payload)
    return yaml.safe_dump(
        [{step_name: step_payload}],
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=False,
    ).strip()


def _step_name(kind: str, payload: dict[str, Any]) -> str:
    if kind == "agent_action_selected":
        action = payload.get("action")
        if isinstance(action, dict):
            return _camel_step(str(action.get("action") or "agent_action"))
    mapping = {
        "agent_started": "launchRun",
        "agent_finished": "finishRun",
        "model_reply_received": "modelPlan",
        "recon_completed": "discoverSurface",
        "recon_failed": "discoverSurface",
        "kill_chain_stage": "stage",
        "flag_captured": "captureProof",
        "flag_capture_rejected": "rejectProof",
        "finding_confirmed": "confirmFinding",
        "finding_rejected_no_evidence": "rejectFinding",
        "run_completed": "completeRun",
        "max_actions_reached": "stopAtBudget",
        "tool_capability_preflight": "checkTools",
    }
    if kind in mapping:
        return mapping[kind]
    if kind.startswith("tool_"):
        return _camel_step(kind.removeprefix("tool_"))
    return _camel_step(kind)


def _step_payload(kind: str, payload: dict[str, Any]) -> object:
    if kind == "agent_action_selected":
        action = payload.get("action")
        if isinstance(action, dict):
            return _small_value(action)
    if kind == "model_reply_received":
        return {
            key: _small_value(payload.get(key))
            for key in ("turn", "provider", "model", "route")
            if key in payload
        }
    if kind == "tool_capability_preflight":
        return {
            "runtime": payload.get("runtime_mode"),
            "image": payload.get("tool_image"),
            "missing": _small_value(payload.get("missing_optional", [])),
        }
    return _small_value(payload)


def _record_status(record: dict[str, Any], *, is_last: bool, metrics: dict[str, Any]) -> str:
    kind = str(record.get("kind") or "")
    payload = _record_payload(record)
    if kind in {"recon_failed", "flag_capture_rejected", "finding_rejected_no_evidence"}:
        return "failed"
    if payload.get("ok") is False:
        return "failed"
    if kind == "max_actions_reached":
        return "warned"
    if kind == "action_started":
        # The client flips this to done/failed when a finish with the same
        # action_id arrives; until then it renders a spinner.
        return "started"
    if is_last and not metrics.get("completed") and kind == "agent_action_selected":
        return "started"
    return "completed"


def _record_error(record: dict[str, Any]) -> str | None:
    payload = _record_payload(record)
    for key in ("error", "errorMessage", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return _clip(value.strip(), 240)
    return None


def _small_value(value: object, *, depth: int = 0) -> object:
    if depth > MAX_SMALL_VALUE_DEPTH:
        return "..."
    if isinstance(value, str):
        return _clip(value, 220)
    if isinstance(value, dict):
        items = list(value.items())[:8]
        return {str(key): _small_value(item, depth=depth + 1) for key, item in items}
    if isinstance(value, list):
        return [_small_value(item, depth=depth + 1) for item in value[:8]]
    return value


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _camel_step(value: str) -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", value) if part]
    if not parts:
        return "event"
    return parts[0].lower() + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _target_url(
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    lab: dict[str, Any],
) -> str:
    for payload in _event_payloads(events) + _audit_payloads(audit_rows):
        if isinstance(payload, dict) and isinstance(payload.get("target_url"), str):
            return str(payload["target_url"])
    return str(lab.get("default_url") or "")


def _target_status_for_mode(target_url: str, mode: str) -> dict[str, Any]:
    if mode == "replay":
        return {
            "reachable": False,
            "status": None,
            "error": "target torn down (replay)",
            "replay": True,
        }
    return _target_status(target_url)


def _target_status(target_url: str) -> dict[str, Any]:
    if not target_url:
        return {"reachable": False, "status": None, "error": "target URL pending"}
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        return {"reachable": False, "status": None, "error": "unsupported target URL"}
    try:
        request = Request(target_url, method="GET")  # noqa: S310
        with urlopen(request, timeout=1) as response:  # noqa: S310
            response.read(1)
            return {"reachable": True, "status": response.status, "error": None}
    except HTTPError as exc:
        return {"reachable": True, "status": exc.code, "error": f"HTTP {exc.code}"}
    except (OSError, URLError, TimeoutError) as exc:
        return {"reachable": False, "status": None, "error": str(exc)}


def _compose_services(lab: dict[str, Any]) -> list[dict[str, Any]]:
    compose = lab.get("compose")
    if not isinstance(compose, dict):
        return []
    services = compose.get("services")
    return services if isinstance(services, list) else []


def _collect_flags(
    events: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
) -> list[str]:
    flags: list[str] = []
    for payload in _event_payloads(events) + _audit_payloads(audit_rows):
        for flag in _flags_from_value(payload):
            if flag not in flags:
                flags.append(flag)
    return flags


def _event_payloads(events: list[dict[str, Any]]) -> list[Any]:
    return [event.get("payload") for event in events]


def _audit_payloads(audit_rows: list[dict[str, Any]]) -> list[Any]:
    return [row.get("payload") for row in audit_rows]


def _flags_from_value(value: object) -> list[str]:
    if isinstance(value, str):
        return FLAG_RE.findall(value)
    if isinstance(value, dict):
        flags: list[str] = []
        for item in value.values():
            flags.extend(_flags_from_value(item))
        return flags
    if isinstance(value, list):
        flags = []
        for item in value:
            flags.extend(_flags_from_value(item))
        return flags
    return []


def _last_payload(events: list[dict[str, Any]], kind: str) -> object:
    for event in reversed(events):
        if event.get("kind") == kind:
            return event.get("payload")
    return None


def _last_audit_payload(audit_rows: list[dict[str, Any]], action: str) -> object:
    for row in reversed(audit_rows):
        if row.get("action") == action:
            return row.get("payload")
    return None


def _has_audit_action(audit_rows: list[dict[str, Any]], action: str) -> bool:
    return any(row.get("action") == action for row in audit_rows)


def _mask_sensitive(value: object) -> object:
    if isinstance(value, str):
        return _mask_flag(value)
    if isinstance(value, list):
        return [_mask_sensitive(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _mask_sensitive(item) for key, item in value.items()}
    return value


def _mask_flag(value: str) -> str:
    return FLAG_RE.sub("flag{REDACTED}", value)
