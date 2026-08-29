from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeterministicAgentSpec:
    name: str
    status: str
    probe_names: tuple[str, ...]
    purpose: str
    missing_engine_work: tuple[str, ...] = ()


DETERMINISTIC_AGENT_SPECS: tuple[DeterministicAgentSpec, ...] = (
    DeterministicAgentSpec(
        name="surface_recon",
        status="partial",
        probe_names=("surface_map", "input_reflection", "direct_exposure"),
        purpose="Build the HTTP evidence graph: pages, forms, params, scripts, cookies, headers, and exposed files.",
        missing_engine_work=(
            "content-aware wordlists from observed framework and routes",
            "JavaScript route extraction and source-map scraping",
            "response-body clustering so 404-like pages do not pollute evidence",
        ),
    ),
    DeterministicAgentSpec(
        name="xss_browser",
        status="partial",
        probe_names=("xss_context", "dom_execution", "reflection_value_boundary"),
        purpose="Map reflected contexts, select a browser payload, verify execution, and extract browser-side proof evidence.",
        missing_engine_work=(
            "stored-XSS workflow replay",
            "browser response/HAR capture with snippets for same-origin fetches",
            "context-specific payload mutation when the first executable payload fails",
            "state-changing branch exploration after confirmed browser execution",
        ),
    ),
    DeterministicAgentSpec(
        name="sqli",
        status="partial",
        probe_names=("sqli_differential", "sqli_exploit", "filtered_query_bypass", "preg_match_subject"),
        purpose="Verify query influence, preserve request templates, then run bounded error/UNION/blind extraction.",
        missing_engine_work=(
            "time-based blind extraction with adaptive jitter control",
            "DBMS-specific stacked-query and file-read checks gated by evidence",
            "credential replay across discovered auth forms",
        ),
    ),
    DeterministicAgentSpec(
        name="ssti",
        status="partial",
        probe_names=("ssti_fingerprint", "server_rendering"),
        purpose="Fingerprint template evaluation with harmless probes, then try bounded engine-specific proof extraction.",
        missing_engine_work=(
            "filter/context analysis before exploit payload selection",
            "engine-specific read primitives that avoid noisy RCE where output is not rendered",
            "payload mutation loop using the previous response as failure context",
        ),
    ),
    DeterministicAgentSpec(
        name="command_boundary",
        status="partial",
        probe_names=("command_boundary",),
        purpose="Detect OS command boundary crossing and extract proof through bounded output/timing probes.",
        missing_engine_work=(
            "shell family fingerprinting",
            "argument-position and separator mutation",
            "time-based confirmation when output is suppressed",
        ),
    ),
    DeterministicAgentSpec(
        name="file_parser",
        status="partial",
        probe_names=("file_fetch_parser", "file_read_extract"),
        purpose="Verify LFI/path traversal/upload/parser primitives and reuse confirmed request templates for proof extraction.",
        missing_engine_work=(
            "XXE/SVG/XML parser engine",
            "upload readback and extension/content-type mutation matrix",
            "archive and image metadata parser probes",
        ),
    ),
    DeterministicAgentSpec(
        name="ssrf",
        status="partial",
        probe_names=("ssrf_boundary",),
        purpose="Exercise URL fetchers against loopback, internal service aliases, and metadata-style endpoints with response or timing oracles.",
        missing_engine_work=(
            "redirect-chain payload server or same-origin redirect reuse",
            "metadata/admin path extraction once an internal fetch primitive is proven",
            "blind timing and DNS/OAST-style confirmation for no-response fetchers",
        ),
    ),
    DeterministicAgentSpec(
        name="auth_session",
        status="partial",
        probe_names=("stateful_session", "csrf_session", "default_credentials"),
        purpose="Create/login low-privilege accounts, test CSRF/session lifecycle behavior, and discover identity-specific routes.",
        missing_engine_work=(
            "password reset/invite/email workflow integration",
            "JWT/session decoding and unsigned/weak-secret checks",
            "long-duration session timeout validation",
        ),
    ),
    DeterministicAgentSpec(
        name="browser_boundary",
        status="partial",
        probe_names=("browser_boundary",),
        purpose="Check CORS policy, frame policy/clickjacking, WebSocket Origin handling, and browser storage secret exposure.",
        missing_engine_work=(
            "authenticated WebSocket message replay and proof extraction",
            "browser-backed SameSite cross-site form submission validation",
            "dynamic localStorage/sessionStorage capture after SPA interactions",
        ),
    ),
    DeterministicAgentSpec(
        name="xxe",
        status="partial",
        probe_names=("xxe_boundary",),
        purpose="Find XML/SOAP/upload parsing surfaces and use bounded external-entity payloads to read proof-bearing files.",
        missing_engine_work=(
            "out-of-band XXE callback confirmation",
            "parser-specific DTD payload mutation",
            "authenticated XML import workflow ownership",
        ),
    ),
    DeterministicAgentSpec(
        name="idor_authorization",
        status="partial",
        probe_names=("idor_boundary",),
        purpose="Compare object and function access across IDs, roles, and sessions with proof-oriented response analysis.",
        missing_engine_work=(
            "two-session BOLA comparison",
            "method override and hidden function-level authorization checks",
            "business object graph inference from links, forms, and API responses",
        ),
    ),
    DeterministicAgentSpec(
        name="api_graphql",
        status="partial",
        probe_names=("api_behavior",),
        purpose="Map JSON/API/GraphQL behavior, schemas, methods, and object-boundary inputs.",
        missing_engine_work=(
            "GraphQL introspection and persisted-query checks",
            "OpenAPI/Swagger discovery",
            "mass-assignment and BOPLA field mutation",
        ),
    ),
    DeterministicAgentSpec(
        name="validation",
        status="partial",
        probe_names=("validate_poc",),
        purpose="Turn candidate findings into replayable request sequences and reject non-proof markers.",
        missing_engine_work=(
            "per-vulnerability validation adapters",
            "browser-backed validation for XSS and auth workflows",
            "side-effect validation for real-world non-CTF runs",
        ),
    ),
)


def deterministic_agent_specs() -> list[dict[str, object]]:
    specs: list[dict[str, object]] = []
    for spec in DETERMINISTIC_AGENT_SPECS:
        specs.append(
            {
                "name": spec.name,
                "status": spec.status,
                "probe_names": list(spec.probe_names),
                "purpose": spec.purpose,
                "missing_engine_work": list(spec.missing_engine_work),
            }
        )
    return specs


__all__ = [
    "DETERMINISTIC_AGENT_SPECS",
    "DeterministicAgentSpec",
    "deterministic_agent_specs",
]
