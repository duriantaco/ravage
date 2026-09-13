from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self

from ai_agent_fixtures import OpenAIStubServer
from ravage.agent_core.autonomous_graph.work_planner import ONLINE_PLANNER_POLICY_VERSION

_BASE_MODEL_REQUESTS = 2
_MAX_MODEL_REQUESTS = 12


class _TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = (
            b"<!doctype html><form action='/search' method='get'>"
            b"<input name='q'><button>Search</button></form>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
        return


class _TargetServer:
    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"


def test_public_attack_cli_runs_online_planner_with_offline_stubs(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    run_dir = tmp_path / "run"
    graph_dir = run_dir / "workspace" / "autonomous-route" / "agent-graph"
    graph_finish = {
        "kind": "finish",
        "payload": {
            "summary": "offline planner smoke complete",
            "evidence_refs": [],
        },
        "rationale": "return bounded control",
    }
    actions: list[dict[str, object]] = [
        {
            "action": "http_request",
            "task_id": "surface-map",
            "method": "GET",
            "path": "/",
            "rationale": "create one target-observed base state",
        },
        {
            "action": "final",
            "args": {"summary": "base remains unsolved"},
            "rationale": "hand off to the graph",
        },
        graph_finish,
    ]

    with _TargetServer() as target, OpenAIStubServer(actions, repeat_last=True) as model:
        brief_path = tmp_path / "brief.yaml"
        brief_path.write_text(
            f"""
engagement_id: "11111111-1111-4111-8111-111111111111"
scope:
  in_scope:
    - "{target.url}"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "capture_flag"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 2
context:
  description: "Inspect the authorized local target and capture its proof if present."
""".lstrip(),
            encoding="utf-8",
        )
        model_config_path = tmp_path / "models.yaml"
        model_config_path.write_text(
            f"""
profiles:
  online-smoke:
    default_tier: mid
    routes:
      mid:
        - provider: custom_openai
          model: offline-online-planner-smoke
          base_url: {model.base_url}
          api_key_required: false
          input_cost_per_1m_tokens: 0.0
          cached_input_cost_per_1m_tokens: 0.0
          output_cost_per_1m_tokens: 0.0
          max_retries: 0
""".lstrip(),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            (
                str(repo_root / "packages/ravage/src"),
                str(repo_root / "packages/schemas/src"),
            )
        )
        result = subprocess.run(  # noqa: S603 - fixed argv runs this checkout's public CLI.
            [
                sys.executable,
                "-m",
                "ravage",
                "attack",
                str(brief_path),
                "--target-url",
                target.url,
                "--run-dir",
                str(run_dir),
                "--model-config",
                str(model_config_path),
                "--model-profile",
                "online-smoke",
                "--model-tier",
                "mid",
                "--max-turns",
                str(_BASE_MODEL_REQUESTS),
                "--traffic-policy",
                "low-noise",
                "--max-physical-requests",
                "6",
                "--traffic-max-rps",
                "0.9",
                "--recovery-profile",
                "off",
                "--autonomous-route",
                "--autonomous-route-engine",
                "agent-graph",
                "--autonomous-route-max-requests",
                "8",
                "--graph-planner-mode",
                "online",
                "--operational-profile",
                "standard",
                "--tool-runtime",
                "host",
                "--no-tool-recon",
                "--memory",
                "off",
                # The custom route declares zero prices; the CLI still requires
                # explicit acknowledgement for any priced transport contract.
                "--allow-paid-models",
                "--display",
                "quiet",
            ],
            check=False,
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )

    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads((graph_dir / "graph-route-receipt.json").read_text(encoding="utf-8"))
    planner = receipt["graph"]["investigation"]["planner"]
    assert planner["mode"] == "online"
    assert planner["policy_version"] == ONLINE_PLANNER_POLICY_VERSION
    assert planner["degraded"] is False
    assert planner["decision_records"] > 0
    decisions_path = graph_dir / "investigation-planner-decisions.jsonl"
    decisions = [
        json.loads(line)
        for line in decisions_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(decisions) == planner["decision_records"]
    assert any(record["candidate"] for record in decisions)
    assert _BASE_MODEL_REQUESTS < len(model.requests_seen) <= _MAX_MODEL_REQUESTS
