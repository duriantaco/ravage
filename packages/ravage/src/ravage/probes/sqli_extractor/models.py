from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ravage.web_core.http_probe import ProbeResponse

SendTarget = Callable[[dict[str, object], str], ProbeResponse]
BriefTarget = Callable[[dict[str, object]], dict[str, object]]
ReplayTarget = Callable[[dict[str, object], str], dict[str, object]]
BaselineValue = Callable[[str], str]
ValueExpr = Callable[[str, str, int], str]

COMMON_TABLES = [
    "flag",
    "flags",
    "secret",
    "secrets",
    "users",
    "user",
    "admin",
    "admins",
    "accounts",
    "credentials",
    "jobs",
    "posts",
    "items",
    "messages",
    "contact",
    "contacts",
    "submissions",
    "notes",
]
COMMON_COLUMNS = [
    "flag",
    "value",
    "secret",
    "token",
    "password",
    "passwd",
    "pass",
    "username",
    "user",
    "email",
    "name",
    "data",
    "content",
    "message",
    "title",
    "description",
]
FAST_FLAG_TABLES = ("flag", "flags", "secret", "secrets")
FAST_FLAG_COLUMNS = ("flag", "value", "secret", "token", "data", "content")
FAST_CREDENTIAL_TABLES = ("users", "user", "admin", "admins", "accounts", "credentials")
FAST_CREDENTIAL_COLUMNS = ("username", "user", "email", "name", "password", "passwd", "pass", "secret", "token")
UNION_RESERVE_BUDGET = 160
AUTH_BYPASS_PREFLIGHT_BUDGET = 32
AUTH_BYPASS_FOLLOWUP_BUDGET = 48
MAX_BLIND_VALUE_CHARS = 72
TIMING_CANDIDATE_DELAYS = (0.5, 1.0)
TIMING_WALL_CLOCK_SECONDS = 28.0
TIMING_TRUE_FACTOR = 0.6
TIMING_THRESHOLD_FACTOR = 0.5


@dataclass(frozen=True)
class SqliExploitRun:
    ok: bool
    summary: str
    findings: list[dict[str, object]] = field(default_factory=list)
    requests: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _ErrorPrimitive:
    target: dict[str, object]
    prefix: str
    function: str
    sample_payload: str
    sample_leak: str


@dataclass(frozen=True)
class _UnionPrimitive:
    target: dict[str, object]
    prefix: str
    column_count: int
    marker_index: int
    sample_payload: str
    style: str = "space"


@dataclass(frozen=True)
class _BooleanPrimitive:
    target: dict[str, object]
    template: str
    true_body: str
    false_body: str
    true_status: int | None
    false_status: int | None


@dataclass(frozen=True)
class _TimingPrimitive:
    target: dict[str, object]
    template: str
    dialect: str
    delay_seconds: float
    baseline_ms: float
    threshold_ms: float


@dataclass(frozen=True)
class _TimingProbeOutcome:
    primitive: _TimingPrimitive | None = None
    abort: bool = False


@dataclass(frozen=True)
class _AuthBypassCase:
    input_name: str
    username: str
    password: str
    payload: str
    expr: str
    finding_fields: dict[str, object]
    next_message: str
