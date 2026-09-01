from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ravage.model_core.providers import (
    ModelTier,
)
from ravage.runtime import DEFAULT_TOOL_IMAGE, ToolRuntimeMode

if TYPE_CHECKING:
    from http.client import HTTPMessage
    from typing import IO

AgentName = Literal["ai-web"]
XbenMode = Literal["black-box", "white-box", "source-aware"]
ComparisonProfile = Literal["none", "mapta-awe-xben"]
CaseStatus = Literal["solved", "failed", "errored", "timeout", "quota_error", "skipped"]
FlagMode = Literal["exact", "pattern"]
AgentMode = Literal["hybrid", "ctf-free-roam"]
RecoveryProfile = Literal["off", "recovery-v1"]
AutonomousRouteEngine = Literal["frontier", "agent-graph"]
SolutionRoute = Literal["base", "autonomous_route"]
METADATA_ISSUE_DISPLAY_LIMIT = 8


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        _ = req, fp, code, msg, headers, newurl
        return None


urlopen = build_opener(_NoRedirectHandler).open

DEFAULT_BENCHMARKS_ROOT = Path("/private/tmp/xbow-validation-benchmarks/benchmarks")
DEFAULT_CASE_TIMEOUT_SECONDS = 1800
DEFAULT_MAX_TURNS = 40
DEFAULT_MAX_MODEL_REQUESTS_PER_CASE = 40
DEFAULT_INPUT_TOKEN_CEILING_PER_MODEL_CALL = 12_000
DEFAULT_MIN_FREE_GIB = 0
HTTP_SERVER_ERROR_MIN = 500
PREFLIGHT_CASE_SAMPLE_LIMIT = 12
FLAG_PATTERN = re.compile(r"\b[A-Za-z0-9_-]*flag\{[^}\s]{3,256}\}", re.IGNORECASE)
XBEN_ID_PATTERN = re.compile(r"\bXBEN-\d{3}-\d{2}\b\s*", re.IGNORECASE)
DOCKER = "docker"
LEGACY_APT_COMPAT_MARKER = "# ravage-xben-legacy-apt-compat"
LEGACY_APT_COMPAT_SNIPPET = f"""{LEGACY_APT_COMPAT_MARKER}
RUN if [ -f /etc/apt/sources.list ]; then \\
    sed -i \\
           -e 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' \\
           -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' \\
           -e 's|security.debian.org|archive.debian.org/debian-security|g' \\
           -e '/buster-updates/d' /etc/apt/sources.list; \\
    printf 'Acquire::Check-Valid-Until "false";\\n' > /etc/apt/apt.conf.d/99ravage-archive; \\
fi
"""
LEGACY_APT_BASE_MARKERS = (
    "python:2.7.18-slim",
    "slim-buster",
    "debian:buster",
    "php:7.1-apache",
    "httpd:2.4.49",
    "httpd:2.4.50",
    "haproxy:2.0",
)
MYSQL_ARM_COMPAT_MARKER = "# ravage-xben-mysql-arm64-compat"
MYSQL_ARM_COMPAT_IMAGE = "mariadb:10.11"
MYSQL_ARM_COMPAT_PLATFORM_LINE = "    platform: linux/arm64/v8\n"
COMPOSE_SERVICE_INDENT = 2
COMPOSE_SERVICE_KEY_INDENT = 4
MAX_TCP_PORT = 65535
WILDCARD_PUBLISHED_HOSTS = ("", "::", "0.0.0.0")  # noqa: S104 - normalized to localhost.


@dataclass(frozen=True)
class XbenCase:
    benchmark_id: str
    path: Path
    name: str
    level: int
    description: str
    main_service: str | None
    main_service_port: int | None

    @property
    def numeric_id(self) -> int:
        match = re.search(r"XBEN-(\d+)-", self.benchmark_id)
        if match is not None:
            return int(match.group(1))
        digits = _digits_from_text(self.benchmark_id)
        return int(digits)

    def to_json(self) -> dict[str, object]:
        return {
            "benchmark_id": self.benchmark_id,
            "name": self.name,
            "level": self.level,
            "description": self.description,
            "main_service": self.main_service,
            "main_service_port": self.main_service_port,
            "path": str(self.path),
        }


def _digits_from_text(text: str) -> str:
    pieces = re.findall(r"\d+", text)
    return "".join(pieces)


@dataclass(frozen=True)
class XbenSettings:
    benchmarks_root: Path = DEFAULT_BENCHMARKS_ROOT
    output_dir: Path = Path("runs/xben")
    all_cases: bool = False
    case_range: str | None = None
    ids: tuple[str, ...] = ()
    exclude_ids: tuple[str, ...] = ()
    sample: int | None = None
    sample_seed: int | None = None
    levels: tuple[int, ...] = ()
    resume: bool = False
    retry_failed: bool = False
    dry_run: bool = False
    list_cases: bool = False
    preflight: bool = False
    mode: XbenMode = "black-box"
    comparison_profile: ComparisonProfile = "none"
    agent: AgentName = "ai-web"
    agent_mode: AgentMode = "ctf-free-roam"
    recovery_profile: RecoveryProfile = "off"
    autonomous_route: bool = False
    autonomous_route_engine: AutonomousRouteEngine = "frontier"
    autonomous_route_max_requests: int = 24
    model_config: Path | None = None
    model_profile: str = "local-ollama"
    model_tier: ModelTier = "mid"
    max_turns: int = DEFAULT_MAX_TURNS
    knowledge_pack_path: Path | None = None
    knowledge_pack_sha256: str | None = None
    knowledge_pack_limit: int = 4
    knowledge_pack_max_chars: int = 6_000
    case_timeout_seconds: int = DEFAULT_CASE_TIMEOUT_SECONDS
    max_model_requests_per_case: int = DEFAULT_MAX_MODEL_REQUESTS_PER_CASE
    max_cost_usd: float | None = None
    min_free_gib: int = DEFAULT_MIN_FREE_GIB
    allow_paid_models: bool = False
    require_clean_source: bool = False
    allow_degraded: bool = False
    input_token_ceiling_per_model_call: int = DEFAULT_INPUT_TOKEN_CEILING_PER_MODEL_CALL
    concurrency: int = 1
    docker_platform: str = "linux/amd64"
    flag_mode: FlagMode = "exact"
    tool_runtime: ToolRuntimeMode = "host"
    tool_image: str = DEFAULT_TOOL_IMAGE
    memory_mode: str | None = None
    memory_db_path: Path | None = None
    proof_bundle_verifier: bool = False
    require_proof_bundle_findings: bool = False
    operator_log_root: Path = Path("logs")
    stream_agent_output: bool = False
    cockpit: bool = False
    cockpit_host: str = "127.0.0.1"
    cockpit_port: int = 8787
    keep_target: bool = False
    prune_case_images: bool = False
    target_ttl_seconds: int = 1800


@dataclass(frozen=True)
class XbenPreflight:
    report_path: Path
    blocked: bool
    block_reasons: tuple[str, ...]
    payload: dict[str, object]

    def write(self) -> None:
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(
            json.dumps(self.payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        source_payload = {
            "captured_at": self.payload.get("captured_at"),
            "command_argv": self.payload.get("command_argv"),
            "source_provenance": self.payload.get("source_provenance"),
            "model_config": self.payload.get("model_config"),
            "tool_image": self.payload.get("tool_image"),
            "tool_image_provenance": self.payload.get("tool_image_provenance"),
            "operator_log_root": self.payload.get("operator_log_root"),
        }
        self.report_path.with_name("preflight-source.json").write_text(
            json.dumps(source_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


@dataclass(frozen=True)
class XbenCaseResult:
    benchmark_id: str
    name: str
    level: int
    target_url: str | None
    flag: str
    found_flag: str | None
    status: CaseStatus
    solved: bool
    elapsed_seconds: float
    model_request_count: int
    http_request_count: int
    db_path: Path
    workspace_path: Path
    transcript_path: Path
    events_path: Path
    artifacts_path: Path
    stdout_path: Path
    clean_log_path: Path
    docker_log_path: Path
    error: str | None
    http_request_count_status: str = "unavailable"
    http_request_count_provenance: str = "unspecified"
    http_unmetered_action_count: int = 0
    http_incomplete_request_count: int = 0
    tool_action_count: int = 0
    base_model_request_count: int = 0
    autonomous_route_model_request_count: int = 0
    solution_route: SolutionRoute | None = None
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    cost_status: str = "unknown"
    cost_provenance: str | None = None
    cost_scope: str = "standard_list_model_text_tokens"
    known_reply_cost_usd: float = 0.0
    unmatched_model_attempts: int = 0
    budget_charge_per_unmatched_attempt_usd: float | None = None
    budget_charge_usd: float | None = None
    budget_charge_status: str = "unknown"
    budget_charge_provenance: str | None = None
    response_models: tuple[str, ...] = ()
    system_fingerprints: tuple[str, ...] = ()
    service_tiers: tuple[str, ...] = ()
    outcome_stage: str = "none"
    outcome_evidence_count: int = 0
    confirmed_finding_count: int = 0
    outcome_vulnerability_classes: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "benchmark_id": self.benchmark_id,
            "name": self.name,
            "level": self.level,
            "target_url": self.target_url,
            "flag": self.flag,
            "found_flag": self.found_flag,
            "status": self.status,
            "solved": self.solved,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "model_request_count": self.model_request_count,
            "base_model_request_count": self.base_model_request_count,
            "autonomous_route_model_request_count": (self.autonomous_route_model_request_count),
            "solution_route": self.solution_route,
            "http_request_count": self.http_request_count,
            "http_request_count_status": self.http_request_count_status,
            "http_request_count_provenance": self.http_request_count_provenance,
            "http_unmetered_action_count": self.http_unmetered_action_count,
            "http_incomplete_request_count": self.http_incomplete_request_count,
            "tool_action_count": self.tool_action_count,
            "db_path": str(self.db_path),
            "workspace_path": str(self.workspace_path),
            "transcript_path": str(self.transcript_path),
            "events_path": str(self.events_path),
            "artifacts_path": str(self.artifacts_path),
            "stdout_path": str(self.stdout_path),
            "clean_log_path": str(self.clean_log_path),
            "docker_log_path": str(self.docker_log_path),
            "error": self.error,
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost_usd,
            "cost_status": self.cost_status,
            "cost_provenance": self.cost_provenance,
            "cost_scope": self.cost_scope,
            "known_reply_cost_usd": self.known_reply_cost_usd,
            "unmatched_model_attempts": self.unmatched_model_attempts,
            "budget_charge_per_unmatched_attempt_usd": (
                self.budget_charge_per_unmatched_attempt_usd
            ),
            "budget_charge_usd": self.budget_charge_usd,
            "budget_charge_status": self.budget_charge_status,
            "budget_charge_provenance": self.budget_charge_provenance,
            "response_models": list(self.response_models),
            "system_fingerprints": list(self.system_fingerprints),
            "service_tiers": list(self.service_tiers),
            "outcome_stage": self.outcome_stage,
            "outcome_evidence_count": self.outcome_evidence_count,
            "confirmed_finding_count": self.confirmed_finding_count,
            "outcome_vulnerability_classes": list(self.outcome_vulnerability_classes),
        }
