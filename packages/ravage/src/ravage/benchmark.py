# Compatibility entry points retain their historical call shape and diagnostics.
# ruff: noqa: CPY001, EM101, EM102, PLR0913, PLR0915, TRY003, TRY004, TRY301

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid5

import yaml  # type: ignore[import-untyped]

from ravage.agent_core.ai_agent import ChatClient, ChatMessage
from ravage.local_agent import HttpExchange
from ravage.model_core.providers import (
    ResolvedModelRoute,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)
from ravage.run_data.brief import load_engagement_brief
from ravage.run_data.workspace import AgentWorkspace
from ravage.web_core.scope_policy import is_local_url

if TYPE_CHECKING:
    from collections.abc import Mapping

_SQL_ERROR_STATUS = 500


@dataclass(frozen=True)
class BenchmarkOverrides:
    max_turns: int | None = None
    model_profile: str | None = None
    model_config: Path | None = None
    model_tier: str | None = None


def load_benchmark_manifest(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("benchmark manifest must contain a mapping")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark manifest must define at least one case")
    return payload


def preflight_benchmark(
    *,
    manifest_path: Path,
    **_: object,
) -> dict[str, object]:
    try:
        payload = load_benchmark_manifest(manifest_path)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        return {"ok": False, "blocked": True, "error": str(exc)}
    return {
        "ok": True,
        "blocked": False,
        "cases": len(payload.get("cases", [])),
    }


def run_benchmark(
    *,
    manifest_path: Path,
    output_dir: Path,
    overrides: BenchmarkOverrides | None = None,
    model_config: Path | None = None,
    model_profile: str | None = None,
    model_tier: str | None = None,
    max_turns: int | None = None,
    stdout: IO[str] | None = None,
    ai_model_clients: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """
    Run the small manifest-driven regression harness used by the public CLI.

    This harness is intentionally localhost-only. Named fixtures are controlled
    test applications; arbitrary remote benchmark targets are not started or
    contacted through this compatibility route.
    """
    manifest_path = manifest_path.resolve()
    payload = load_benchmark_manifest(manifest_path)
    cases = payload["cases"]
    assert isinstance(cases, list)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    selected = overrides or BenchmarkOverrides()
    selected_model_config = model_config or selected.model_config
    selected_model_profile = model_profile or selected.model_profile or "local-ollama"
    selected_model_tier = model_tier or selected.model_tier or "mid"
    selected_max_turns = max_turns or selected.max_turns or 40
    stream = stdout or sys.stdout
    case_reports: list[dict[str, object]] = []

    for index, raw_case in enumerate(cases, start=1):
        if not isinstance(raw_case, dict):
            case_reports.append(
                {
                    "id": f"case-{index}",
                    "passed": False,
                    "status": "error",
                    "error": "case must be a mapping",
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 1,
                }
            )
            continue
        case_reports.append(
            _run_case(
                raw_case,
                manifest_dir=manifest_path.parent,
                output_dir=output_dir,
                model_config=selected_model_config,
                model_profile=selected_model_profile,
                model_tier=selected_model_tier,
                max_turns=selected_max_turns,
                stdout=stream,
                model_client=(ai_model_clients or {}).get(str(raw_case.get("id") or "")),
            )
        )

    summary = {
        "cases": len(case_reports),
        "passed_cases": sum(bool(case.get("passed")) for case in case_reports),
        "true_positives": sum(_int(case.get("true_positives")) for case in case_reports),
        "false_positives": sum(_int(case.get("false_positives")) for case in case_reports),
        "false_negatives": sum(_int(case.get("false_negatives")) for case in case_reports),
        "errors": sum(case.get("status") == "error" for case in case_reports),
    }
    report = {
        "schema_version": "ravage.benchmark.v1",
        "passed": all(bool(case.get("passed")) for case in case_reports),
        "summary": summary,
        "cases": case_reports,
    }
    (output_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _run_case(
    case: dict[str, object],
    *,
    manifest_dir: Path,
    output_dir: Path,
    model_config: Path | None,
    model_profile: str,
    model_tier: str,
    max_turns: int,
    stdout: IO[str],
    model_client: object | None,
) -> dict[str, object]:
    case_id = str(case.get("id") or "unnamed-case")
    workspace_dir = output_dir / f"{case_id}.workspace"
    db_path = output_dir / f"{case_id}.audit.db"
    agent_report_path = output_dir / f"{case_id}.agent-report.json"
    try:
        brief_path = _resolve_manifest_path(case.get("brief"), base=manifest_dir)
        target_url = str(case.get("target_url") or "")
        if not target_url:
            raise ValueError("case target_url is required")
        if not is_local_url(target_url):
            raise ValueError("compatibility benchmarks are restricted to localhost targets")
        fixture = str(case.get("fixture") or "")
        fixture_http_client = _fixture_http_client(fixture)
        _run_compat_case_agent(
            brief_path=brief_path,
            target_url=target_url,
            workspace_dir=workspace_dir,
            db_path=db_path,
            report_path=agent_report_path,
            model_config=model_config,
            model_profile=model_profile,
            model_tier=model_tier,
            max_turns=max_turns,
            model_client=model_client,
            http_client=fixture_http_client,
            stdout=stdout,
        )
        actual = _confirmed_findings(workspace_dir / "events.jsonl")
        expected_present, expected_absent = _case_expectations(case)
        true_positives = sum(
            any(_finding_matches(finding, expectation) for finding in actual)
            for expectation in expected_present
        )
        false_negatives = len(expected_present) - true_positives
        false_positives = sum(
            not any(_finding_matches(finding, expectation) for expectation in expected_present)
            or any(_finding_matches(finding, expectation) for expectation in expected_absent)
            for finding in actual
        )
        passed = false_negatives == 0 and false_positives == 0
        return {
            "id": case_id,
            "status": "passed" if passed else "failed",
            "passed": passed,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "workspace": str(workspace_dir),
            "agent_report": str(agent_report_path),
            "actual_findings": actual,
        }
    except Exception as exc:  # noqa: BLE001 - each case must yield a durable result.
        return {
            "id": case_id,
            "status": "error",
            "passed": False,
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": len(_case_expectations(case)[0]) or 1,
            "workspace": str(workspace_dir),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _run_compat_case_agent(
    *,
    brief_path: Path,
    target_url: str,
    workspace_dir: Path,
    db_path: Path,
    report_path: Path,
    model_config: Path | None,
    model_profile: str,
    model_tier: str,
    max_turns: int,
    model_client: object | None,
    http_client: object | None,
    stdout: IO[str],
) -> None:
    """Execute the frozen manifest action contract used by compatibility tests."""
    if not brief_path.exists():
        raise ValueError(f"brief does not exist: {brief_path}")
    brief = load_engagement_brief(brief_path)
    engagement_id = brief.engagement_id
    workspace = AgentWorkspace.open(workspace_dir)
    registry = load_model_registry(model_config)
    routes = resolve_model_routes(
        registry,
        profile_name=model_profile,
        tier=model_tier,  # type: ignore[arg-type]
    )
    ready = ready_model_routes(routes)
    if not ready:
        raise RuntimeError(f"no ready model route for profile {model_profile!r}")
    route = ready[0]
    client = model_client or ChatClient(route)
    evidence: dict[tuple[str, str], dict[str, object]] = {}
    findings: list[dict[str, object]] = []
    workspace.record_event(
        kind="agent_started",
        payload={
            "target_url": target_url,
            "contract": "manifest-compat-v1",
            "engagement_id": str(engagement_id),
        },
    )

    for turn in range(1, max(max_turns, 1) + 1):
        messages = [
            ChatMessage(
                role="system",
                content=(
                    "Return exactly one JSON action. Supported compatibility actions: "
                    "discover_attack_surface, test_sqli_param, report_sqli, final."
                ),
            ),
            ChatMessage(
                role="user",
                content=json.dumps(
                    {
                        "target_url": target_url,
                        "turn": turn,
                        "confirmed_probe_keys": [
                            f"{path} {param}" for path, param in sorted(evidence)
                        ],
                    },
                    sort_keys=True,
                ),
            ),
        ]
        workspace.record_event(
            kind="model_request_started",
            payload={"turn": turn, "model": route.model, "provider": route.provider},
        )
        reply = _compat_model_reply(client, messages=messages, route=route)
        workspace.record_transcript(role="assistant", content=reply)
        workspace.record_event(
            kind="model_reply",
            payload={"turn": turn, "model": route.model, "content": reply},
        )
        action = _compat_action(reply)
        kind = str(action.get("action") or "invalid")
        args = action.get("args")
        action_args = args if isinstance(args, dict) else {}
        workspace.record_event(
            kind="agent_action",
            payload={"turn": turn, "action": kind, "args": action_args},
        )

        if kind == "discover_attack_surface":
            workspace.record_event(
                kind="observation",
                payload={
                    "turn": turn,
                    "ok": True,
                    "routes": [
                        {"method": "GET", "path": "/search", "params": ["q"]},
                        {"method": "GET", "path": "/hash", "params": ["data"]},
                    ],
                },
            )
            continue
        if kind == "test_sqli_param":
            path = str(action_args.get("path") or "/")
            param = str(action_args.get("param") or "")
            result = _compat_sqli_probe(
                target_url=target_url,
                path=path,
                param=param,
                http_client=http_client,
            )
            workspace.record_event(kind="tool_call", payload={"turn": turn, **result})
            workspace.record_event(kind="observation", payload={"turn": turn, **result})
            if bool(result.get("confirmed")):
                evidence[(path, param)] = result
            continue
        if kind == "report_sqli":
            path = str(action_args.get("path") or "/")
            param = str(action_args.get("param") or "")
            probe = evidence.get((path, param))
            if probe is None:
                workspace.record_event(
                    kind="finding_rejected",
                    payload={
                        "turn": turn,
                        "vuln_class": "sql_injection",
                        "reason": "missing confirming probe evidence",
                    },
                )
                continue
            finding = {
                "finding_id": str(
                    uuid5(engagement_id, f"{path}:{param}:sql_injection")
                ),
                "engagement_id": str(engagement_id),
                "vuln_class": "sql_injection",
                "severity": "High",
                "endpoint": {
                    "url": target_url.rstrip("/") + path,
                    "method": str(action_args.get("method") or "GET").upper(),
                    "params": [param],
                },
                "status": "confirmed",
                "proof": probe,
                "finding_record_path": str(workspace.events_path),
            }
            findings.append(finding)
            workspace.record_event(kind="finding_confirmed", payload=finding)
            continue
        if kind == "final":
            workspace.record_event(
                kind="agent_final",
                payload={"turn": turn, "summary": action_args.get("summary", "")},
            )
            break
        workspace.record_event(
            kind="invalid_action",
            payload={"turn": turn, "raw": reply[:2000]},
        )

    workspace.record_event(
        kind="agent_finished",
        payload={
            "engagement_id": str(engagement_id),
            "findings": len(findings),
            "db_path": str(db_path),
        },
    )
    report_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "target_url": target_url,
                "findings": findings,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    stdout.write(f"benchmark case completed target={target_url} findings={len(findings)}\n")


def _compat_model_reply(
    client: object,
    *,
    messages: list[ChatMessage],
    route: ResolvedModelRoute,
) -> str:
    complete = getattr(client, "complete", None)
    if callable(complete):
        result = complete(messages=messages, route=route)
    else:
        chat = getattr(client, "chat", None)
        if not callable(chat):
            raise TypeError("benchmark model client must expose complete() or chat()")
        result = chat([{"role": message.role, "content": message.content} for message in messages])
    content = getattr(result, "content", result)
    return str(content)


def _compat_action(reply: str) -> dict[str, object]:
    try:
        payload = json.loads(reply)
    except json.JSONDecodeError:
        return {"action": "invalid", "raw": reply}
    return payload if isinstance(payload, dict) else {"action": "invalid", "raw": reply}


def _compat_sqli_probe(
    *,
    target_url: str,
    path: str,
    param: str,
    http_client: object | None,
) -> dict[str, object]:
    if http_client is None or not callable(getattr(http_client, "get", None)):
        raise ValueError("SQL compatibility probe requires a controlled fixture client")

    base = target_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")
    baseline_url = f"{base}?{urlencode({param: 'alice'})}"
    quote_query = urlencode({param: "'"})
    quote_url = f"{base}?{quote_query}"
    baseline = http_client.get(baseline_url)
    quote = http_client.get(quote_url)
    body = str(getattr(quote, "body", "") or "")
    quote_status = int(getattr(quote, "status_code", 0) or 0)
    confirmed = quote_status >= _SQL_ERROR_STATUS and any(
        marker in body.lower() for marker in ("sql", "sqlite", "syntax", "operationalerror")
    )
    return {
        "tool": "test_sqli_param",
        "method": "GET",
        "path": path,
        "param": param,
        "baseline_status": int(getattr(baseline, "status_code", 0) or 0),
        "probe_status": quote_status,
        "response_snippet": body[:500],
        "confirmed": confirmed,
    }


def _fixture_http_client(fixture: str) -> object | None:
    if not fixture:
        return None
    if fixture == "vulnerable_openapi":
        return _VulnerableOpenApiHttpClient()
    raise ValueError(f"unknown benchmark fixture: {fixture}")


class _VulnerableOpenApiHttpClient:
    def get(self, url: str) -> HttpExchange:
        parsed = urlparse(url)
        if parsed.path == "/openapi.json":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body=json.dumps(
                    {
                        "openapi": "3.0.0",
                        "paths": {
                            "/search": {
                                "get": {
                                    "parameters": [{"name": "q", "in": "query"}],
                                }
                            },
                            "/hash": {
                                "get": {
                                    "parameters": [{"name": "data", "in": "query"}],
                                }
                            },
                        },
                    }
                ),
            )
        if parsed.path == "/":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body=(
                    '<html><a href="/openapi.json">api</a>'
                    '<a href="/search?q=alice">search</a></html>'
                ),
            )
        if parsed.path == "/search":
            query = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
            if query == "'":
                return HttpExchange(
                    method="GET",
                    url=url,
                    status_code=500,
                    body="sqlite3.OperationalError: unrecognized token",
                )
            if query == "%' OR 1=1 -- ":
                body = '{"results":["alice","bob","charlie"]}'
            elif query == "%' AND 1=2 -- ":
                body = '{"results":[]}'
            else:
                body = '{"results":["alice"]}'
            return HttpExchange(method="GET", url=url, status_code=200, body=body)
        if parsed.path == "/hash":
            return HttpExchange(
                method="GET",
                url=url,
                status_code=200,
                body='{"digest":"stable"}',
            )
        return HttpExchange(method="GET", url=url, status_code=404, body="")

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: object = None,
        cookies: object = None,
        body: bytes | None = None,
        body_text: str | None = None,
    ) -> HttpExchange:
        _ = headers, cookies, body, body_text
        if method.upper() == "GET":
            return self.get(url)
        return HttpExchange(
            method=method.upper(),
            url=url,
            status_code=404,
            body="",
            request_body=body_text or "",
        )

    def post_form(self, url: str, _data: object) -> HttpExchange:
        return HttpExchange(method="POST", url=url, status_code=404, body="")

    def post_json(self, url: str, _data: object) -> HttpExchange:
        return HttpExchange(method="POST", url=url, status_code=404, body="")


def _confirmed_findings(events_path: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if not events_path.exists():
        return findings
    for line in events_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("kind") != "finding_confirmed":
            continue
        payload = event.get("payload")
        if isinstance(payload, dict):
            findings.append(payload)
    return findings


def _case_expectations(
    case: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    expect = case.get("expect")
    if not isinstance(expect, dict):
        return [], []
    present = [item for item in expect.get("present", []) if isinstance(item, dict)]
    absent = [item for item in expect.get("absent", []) if isinstance(item, dict)]
    return present, absent


def _finding_matches(finding: dict[str, object], expectation: dict[str, object]) -> bool:
    expected_class = str(expectation.get("vuln_class") or "")
    if expected_class and str(finding.get("vuln_class") or "") != expected_class:
        return False
    expected_path = str(expectation.get("endpoint_path") or "")
    if expected_path and _finding_path(finding) != expected_path:
        return False
    expected_param = str(expectation.get("param") or "")
    return not expected_param or expected_param in _finding_params(finding)


def _finding_path(finding: dict[str, object]) -> str:
    endpoint = finding.get("endpoint")
    if isinstance(endpoint, dict):
        raw = endpoint.get("path") or endpoint.get("url") or ""
    else:
        raw = finding.get("endpoint_path") or finding.get("path") or ""
    text = str(raw)
    if text.startswith(("http://", "https://")):
        return urlparse(text).path or "/"
    return text


def _finding_params(finding: dict[str, object]) -> set[str]:
    result: set[str] = set()
    direct = finding.get("param")
    if direct:
        result.add(str(direct))
    endpoint = finding.get("endpoint")
    raw_params = endpoint.get("params") if isinstance(endpoint, dict) else None
    if isinstance(raw_params, list):
        for item in raw_params:
            name = item.get("name") if isinstance(item, dict) else item
            if name:
                result.add(str(name))
    return result


def _resolve_manifest_path(value: object, *, base: Path) -> Path:
    if not value:
        raise ValueError("case brief is required")
    path = Path(str(value))
    return path if path.is_absolute() else (base / path).resolve()


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
