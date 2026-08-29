from __future__ import annotations

from ravage.agent_core.agent_state import AgentState


def methodology_context(state: AgentState) -> dict[str, object]:
    multi_finding = state.surface.get("continue_after_proof") is True
    return {
        "loop": [
            "Observe: gather one new fact from the target or prior output.",
            "Orient: connect that fact to an active task and hypothesis.",
            "Act: run one scoped command or script that should change knowledge.",
            "Review: record whether the result was new surface, confirmed signal, blocked, or flag.",
        ],
        "phase_rules": _phase_rules(state.phase),
        "tool_use": [
            "Use curl with -i and a cookie jar for HTTP state.",
            "Use short Python stdlib urllib scripts when request chaining, CSRF extraction, encoding, timing, or response diffing is needed.",
            "Use urllib.parse.urlencode for quote-heavy SQL/auth payloads instead of nested shell quoting.",
            "Prefer custom one-off probes over black-box scanners when the app has visible forms or tokens.",
            "Keep commands scoped to the target URL and local workspace.",
        ],
        "fallback_ladders": _fallback_ladders(state),
        "completion_rules": _completion_rules(multi_finding=multi_finding),
    }


def _completion_rules(*, multi_finding: bool) -> list[str]:
    rules = [
        "A reflected marker is not a flag.",
        "A shell, admin page, or credential is only progress until target impact is validated.",
    ]
    if multi_finding:
        rules.extend(
            [
                "A captured proof closes one branch but does not complete this multi-finding assessment.",
                "Only final after open assessment tasks are exhausted or the turn budget is reached.",
            ]
        )
    else:
        rules.append("Only final after a flag is captured or the turn budget is exhausted.")
    return rules


def _phase_rules(phase: str) -> list[str]:
    if phase == "recon":
        return [
            "Map endpoints, forms, cookies, scripts, redirects, and errors.",
            "Extract CSRF fields and stateful workflows before mutating forms.",
            "Check exposed static files and source maps early.",
        ]
    if phase == "exploit":
        return [
            "Pick the strongest evidence-backed workflow and go depth-first for a few turns.",
            "Use baseline versus probe comparisons and exact response deltas.",
            "Escalate payload strength only after a harmless probe confirms influence.",
        ]
    if phase == "done":
        return ["Report the captured flag and the minimal evidence path."]
    return ["Run the next action that maximizes new evidence."]


def _fallback_ladders(state: AgentState) -> list[str]:
    ladders = [
        "If commands repeat or outputs are unchanged, change endpoint, parameter, session, encoding, or method.",
        "If a form fails, refresh CSRF/cookies and inspect hidden fields before retrying.",
        "If scanner output is noisy or empty, switch to manual curl/Python comparisons.",
        "If one workflow stalls after multiple blocked outcomes, move to the next active task.",
    ]
    if state.signals.get("reflections"):
        ladders.append(
            "For reflected inputs: identify context, then test literal echo, arithmetic/string evaluation, and encoding filters."
        )
    if state.signals.get("forms"):
        ladders.append(
            "For forms: submit benign markers first, then compare status, length, redirects, cookies, and saved content."
        )
    if state.signals.get("cookies"):
        ladders.append(
            "For cookies: decode only locally visible structure first; never assume a signing key unless evidence supports it."
        )
    return ladders
