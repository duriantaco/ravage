from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StrategyCard:
    name: str
    goal: str
    evidence: tuple[str, ...]
    next_actions: tuple[str, ...]
    stop_condition: str

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "goal": self.goal,
            "evidence": list(self.evidence),
            "next_actions": list(self.next_actions),
            "stop_condition": self.stop_condition,
        }


@dataclass
class ActionLedger:
    fingerprints: dict[str, int] = field(default_factory=dict)

    def remember(self, action: Mapping[str, object], *, context: str = "") -> int:
        fingerprint = action_fingerprint(action, context=context)
        count = self.fingerprints.get(fingerprint, 0) + 1
        self.fingerprints[fingerprint] = count
        return count

    def repeated(self, action: Mapping[str, object], *, context: str = "") -> bool:
        return self.fingerprints.get(action_fingerprint(action, context=context), 0) > 0

    def to_json(self) -> dict[str, int]:
        return dict(sorted(self.fingerprints.items()))


STRATEGY_BOOK: tuple[StrategyCard, ...] = (
    StrategyCard(
        name="surface_map",
        goal="Build a map of pages, forms, parameters, cookies, and response patterns.",
        evidence=("new target", "unknown application", "missing form/endpoint inventory"),
        next_actions=(
            "Fetch the root with headers and redirects preserved.",
            "Crawl same-origin links and inspect forms/actions/inputs.",
            "Record cookies, CSRF fields, JavaScript URLs, API endpoints, and hidden fields.",
        ),
        stop_condition="A compact inventory of reachable pages, forms, params, and cookies exists.",
    ),
    StrategyCard(
        name="input_reflection",
        goal="Find fields or parameters whose values influence HTML, JSON, headers, or follow-up pages.",
        evidence=("forms", "query parameters", "search fields", "profile/comment/post fields"),
        next_actions=(
            "Submit unique markers to safe GET endpoints first.",
            "Use fresh CSRF tokens and cookies when forms require them.",
            "Compare baseline and marker responses; note exact sink context.",
        ),
        stop_condition="Reflected or stored marker sinks are confirmed or ruled out for current inputs.",
    ),
    StrategyCard(
        name="client_execution",
        goal="Confirm whether a reflected input executes in a real browser (XSS) instead of only echoing.",
        evidence=("reflected", "marker", "script", "html sink", "xss", "innerhtml", "onerror"),
        next_actions=(
            "On a confirmed reflected sink, run_probe dom_execution to render the input in headless Chromium.",
            "Treat a captured dialog or unique-token callback as execution proof; plain reflection is not.",
            "Adapt the breakout (attribute, tag, script, event handler) to the observed sink context.",
        ),
        stop_condition="Client-side execution is confirmed in the browser or the sink is proven inert/escaped.",
    ),
    StrategyCard(
        name="stateful_auth",
        goal="Understand identities, sessions, role boundaries, and gated paths.",
        evidence=("login form", "register form", "session cookie", "user/account/profile paths"),
        next_actions=(
            "Create low-privilege accounts when allowed by the UI.",
            "Track cookies and CSRF per account.",
            "Compare pages and object IDs across accounts before attempting privilege-sensitive reads.",
        ),
        stop_condition="Account creation/login behavior and accessible identity objects are understood.",
    ),
    StrategyCard(
        name="server_side_interpreter",
        goal="Check whether user-controlled text is evaluated by a server-side interpreter.",
        evidence=("template-like rendering", "debug errors", "custom formatting", "calculation outputs"),
        next_actions=(
            "Use harmless arithmetic/string probes in the same sink that reflected a marker.",
            "Compare literal echo vs evaluated result before trying extraction.",
            "Adapt payload syntax from observed errors or framework clues.",
        ),
        stop_condition="A specific interpreter behavior is confirmed or the sink is literal-only.",
    ),
    StrategyCard(
        name="data_query",
        goal="Probe whether inputs reach database queries and can alter result sets or timing.",
        evidence=("search/filter/login forms", "database errors", "numeric ids", "sort/page params"),
        next_actions=(
            "Run run_probe sqli_differential to perform paired SQLi/blind-SQLi checks across parameters, forms, and query-like endpoints.",
            "After a SQLi signal, run run_probe sqli_exploit to extract data with the confirmed request template.",
            "If captcha/code/CSRF state blocks the query form, run run_probe captcha_form_state before further payload loops.",
            "If obvious SQL payloads are filtered but normal values affect results, run run_probe filtered_query_bypass.",
            "If PHP preg_match warnings or username[] array-subject errors appear, run run_probe preg_match_subject.",
            "Establish baseline responses for normal values.",
            "Try syntax-balanced perturbations and boolean/time comparisons.",
            "Use response length, status, timing, and content deltas as evidence.",
        ),
        stop_condition="A stable query influence signal is confirmed or current inputs are exhausted.",
    ),
    StrategyCard(
        name="file_and_url_fetch",
        goal="Test file path, upload, include, import, webhook, and URL-fetch workflows.",
        evidence=("file upload", "download path", "url parameter", "import/webhook/fetch wording", "xml input"),
        next_actions=(
            "Identify where uploaded or referenced content is read back.",
            "Use harmless local file/path probes and response deltas.",
            "Check XML parsing behavior only on XML-consuming endpoints.",
        ),
        stop_condition="The file/fetch workflow is mapped and high-risk reads are confirmed or ruled out.",
    ),
    StrategyCard(
        name="command_boundary",
        goal="Determine whether inputs are passed to shell commands or OS utilities.",
        evidence=("ping/nslookup/traceroute/curl tools", "host/ip/domain inputs", "command errors"),
        next_actions=(
            "Start with benign separators that produce observable but safe output.",
            "Prefer timing or echo-style proof before reading target files.",
            "Vary encoding and option placement based on the command shape.",
        ),
        stop_condition="Command influence is confirmed or no command-shaped input remains.",
    ),
    StrategyCard(
        name="secret_hunting",
        goal="Find exposed flags, credentials, backups, debug pages, source maps, and config leaks.",
        evidence=("debug markers", "directory listing", "backup/static assets", "robots/sitemap", "stack trace"),
        next_actions=(
            "Run run_probe direct_exposure before repeating manual admin/config/backup loops.",
            "Inspect robots, sitemap, source maps, JavaScript, backups, and error pages.",
            "Search responses for flag-like strings, keys, credentials, and file paths.",
            "Use discovered credentials only against in-scope target services.",
            "After credentialed shell/service access, preserve exact-case filenames and read proof paths with both upper and lower case variants.",
        ),
        stop_condition="Exposed assets and secrets are inventoried and any discovered credential is tested.",
    ),
)


def strategy_cards_for_state(
    *,
    description: str,
    signals: dict[str, list[str]],
    facts: list[str],
    limit: int = 5,
) -> list[dict[str, object]]:
    text = _strategy_evidence_text(description=description, signals=signals, facts=facts)
    scored: list[tuple[int, StrategyCard]] = []
    for card in STRATEGY_BOOK:
        score = _evidence_score(text, card.evidence)
        if card.name == "surface_map" and not facts:
            score += 3
        if score:
            scored.append((score, card))
    if not scored:
        scored.append((1, STRATEGY_BOOK[0]))
        scored.append((1, STRATEGY_BOOK[-1]))
    scored.sort(key=lambda item: (-item[0], item[1].name))
    cards: list[dict[str, object]] = []
    for score, card in scored[:limit]:
        payload = card.to_json()
        payload["score"] = score
        cards.append(payload)
    return cards


def action_fingerprint(action: Mapping[str, object], *, context: str = "") -> str:
    kind = str(action.get("action") or "")
    if kind == "run_command":
        body = str(action.get("command") or "")
    elif kind == "run_python":
        body = str(action.get("code") or "")
    elif kind == "run_probe":
        body = str(action.get("probe") or "")
    elif kind == "validate_poc":
        body = str(
            {
                "steps": action.get("steps") or [],
                "finding": action.get("finding") or {},
            }
        )
    else:
        body = str(action)
    normalized = re.sub(r"\s+", " ", body.strip())
    normalized = re.sub(r"ravage-[a-z0-9_:-]+", "ravage-*", normalized, flags=re.I)
 
    if context:
        suffix = f"|ctx:{context}"
    else:
        suffix = ""
    return f"{kind}:{normalized[:500]}{suffix}"


def observation_digest(text: str, *, limit: int = 2000) -> dict[str, Any]:
    lowered = text.lower()
    markers = [marker for marker in _OBSERVATION_MARKERS if marker in lowered]
    return {
        "chars": len(text),
        "markers": markers,
        "snippet": _compact_observation_snippet(text, limit=limit),
    }


def _compact_observation_snippet(text: str, *, limit: int) -> str:  # noqa: PLR0911
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text

    marker = "\n...[observation clipped]...\n"
    if limit <= len(marker) + 2:
        return text[:limit]

    signal_offset = _high_signal_offset(text)
    if signal_offset < 0:
        keep = limit - len(marker)
        head_chars = max(1, (keep * 2) // 3)
        return text[:head_chars] + marker + text[-(keep - head_chars) :]

    keep = limit - (2 * len(marker))
    if keep <= _MIN_COMPACT_SEGMENT_CHARS:
        return text[:limit]
    head_chars = max(1, keep // 4)
    tail_chars = max(1, keep // 4)
    signal_chars = keep - head_chars - tail_chars
    signal_start = max(head_chars, signal_offset - (signal_chars // 4))
    signal_start = min(signal_start, len(text) - tail_chars - signal_chars)
    signal_end = signal_start + signal_chars
    if signal_start <= head_chars or signal_end >= len(text) - tail_chars:
        head_chars = max(1, (limit - len(marker)) * 2 // 3)
        return text[:head_chars] + marker + text[-(limit - len(marker) - head_chars) :]
    return (
        text[:head_chars]
        + marker
        + text[signal_start:signal_end]
        + marker
        + text[-tail_chars:]
    )


def _high_signal_offset(text: str) -> int:
    lowered = text.lower()
    for marker in _HIGH_SIGNAL_OBSERVATION_MARKERS:
        offset = lowered.find(marker)
        if offset >= 0:
            return offset
    return -1


_OBSERVATION_MARKERS = (
    "set-cookie",
    "csrf",
    "<form",
    "href=",
    "action=",
    "traceback",
    "exception",
    "sql",
    "sqlite",
    "mysql",
    "postgres",
    "jwt",
    "xml",
    "graphql",
    "upload",
    "root:x:0:0:",
    "local_file_read",
    "file_read_primitive",
    "command_boundary_proof",
    "finding_confirmed",
)

_MIN_COMPACT_SEGMENT_CHARS = 3

_HIGH_SIGNAL_OBSERVATION_MARKERS = (
    "root:x:0:0:",
    "finding_confirmed",
    "command_boundary_proof",
    "file_read_extracted_proof",
    "file_read_primitive",
    "local_file_read",
    '"stdout"',
    "stdout:",
    "flag{",
    "xben{",
    "ctf{",
    "htb{",
)


def _strategy_evidence_text(
    *,
    description: str,
    signals: dict[str, list[str]],
    facts: list[str],
) -> str:
    parts: list[str] = [description]
    parts.extend(facts[-20:])
    for values in signals.values():
        parts.extend(values[-20:])
    return " ".join(parts).lower()


def _evidence_score(text: str, evidence_phrases: tuple[str, ...]) -> int:
    score = 0
    for phrase in evidence_phrases:
        if _phrase_matches(text, phrase):
            score += 1
    return score


def _phrase_matches(text: str, phrase: str) -> bool:
    if not phrase.strip():
        return False
    if not phrase.replace(" ", "").isalnum():
        return phrase in text
    return re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", text) is not None
