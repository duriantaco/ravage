from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from ravage.agent_knowledge.mappings import (
    ALL_SKILL_TYPED_IDENTIFIERS,
    mapped_probes,
    skill_keywords,
    skill_typed_identifiers,
)
from ravage.agent_knowledge.models import KnowledgeCard, KnowledgeSkill
from ravage.agent_knowledge.skill_pack import load_skill_pack

if TYPE_CHECKING:
    from pathlib import Path

    from ravage.agent_core.agent_state import AgentState

DEFAULT_KNOWLEDGE_CARD_LIMIT = 4
DEFAULT_KNOWLEDGE_MAX_CHARS = 6_000
_MAX_KNOWLEDGE_CARD_LIMIT = 8
_MAX_KNOWLEDGE_CHARS = 12_000
_MIN_DESCRIPTION_TOKEN_CHARS = 4
_KEYWORD_SCORE = 6
_PHRASE_KEYWORD_SCORE = 8
_WORD_RE = re.compile(r"[a-z0-9_./{}:-]+")
_NEGATED_BEFORE_RE = re.compile(
    r"(?:^|\b)(?:no|non|not|without|excluding|exclude|excluded)\b"
    r"(?:\W+\w+){0,3}\W*$"
)
_NEGATED_AFTER_RE = re.compile(
    r"^\s*(?:"
    r"(?:(?:is|was|were|appears|seems)\s+)?(?:absent|unavailable)"
    r"|(?:is|was|were)\s+not\s+(?:present|observed|available)"
    r"|(?:isn['\u2019]t|wasn['\u2019]t|weren['\u2019]t)\s+(?:present|observed|available)"
    r"|(?:does|did)\s+not\s+(?:(?:appear|seem)\s+to\s+be\s+)?"
    r"(?:present|observed|available)"
    r")\b"
)
_URL_PARAMETER_NAMES = frozenset(
    {
        "callback",
        "callback_url",
        "destination",
        "endpoint",
        "feed_url",
        "fetch_url",
        "image_url",
        "remote_url",
        "source_url",
        "uri",
        "url",
        "webhook",
        "webhook_url",
    }
)
_FETCH_SURFACE_TERMS = (
    "callback",
    "fetch",
    "feed",
    "image",
    "import",
    "preview",
    "proxy",
    "remote",
    "webhook",
)
_FILE_PARAMETER_NAMES = frozenset(
    {"archive", "attachment", "document", "file", "filename", "image", "upload"}
)
_OBJECT_PARAMETER_NAMES = frozenset(
    {
        "account_id",
        "document_id",
        "object_id",
        "org_id",
        "organization_id",
        "owner_id",
        "resource_id",
        "tenant_id",
        "user_id",
    }
)
_PATH_PARAMETER_NAMES = frozenset(
    {"document", "file", "filename", "folder", "include", "page", "path", "template"}
)
_COMMAND_PARAMETER_NAMES = frozenset(
    {"cmd", "command", "executable", "host", "hostname", "process", "program"}
)


def select_knowledge_cards(  # noqa: PLR0913 - explicit immutable selection contract.
    *,
    pack_path: Path | None,
    expected_sha256: str | None = None,
    state: AgentState,
    description: str,
    limit: int = DEFAULT_KNOWLEDGE_CARD_LIMIT,
    max_chars: int = DEFAULT_KNOWLEDGE_MAX_CHARS,
) -> list[KnowledgeCard]:
    if pack_path is None or limit <= 0 or max_chars <= 0:
        return []

    bounded_limit = min(limit, _MAX_KNOWLEDGE_CARD_LIMIT)
    bounded_chars = min(max_chars, _MAX_KNOWLEDGE_CHARS)
    pack = load_skill_pack(pack_path, expected_sha256=expected_sha256)
    operator_text = description.lower()
    typed_text, typed_identifiers = _typed_evidence(state)
    scored: list[tuple[int, KnowledgeSkill]] = []
    for skill in pack.skills:
        score = _score_skill(
            skill,
            operator_text=operator_text,
            typed_text=typed_text,
            typed_identifiers=typed_identifiers,
        )
        if score > 0:
            scored.append((score, skill))

    scored.sort(key=lambda item: (-item[0], item[1].name))
    selected = scored[:bounded_limit]
    if not selected:
        return []

    cards: list[KnowledgeCard] = []
    for score, skill in selected:
        card = _knowledge_card(
            score=score,
            skill=skill,
            guidance=_strip_markdown_noise(skill.body),
        )
        provisional = [*cards, card]
        if _serialized_cards_chars(provisional) > bounded_chars:
            continue
        cards.append(card)

    return cards


def _knowledge_card(*, score: int, skill: KnowledgeSkill, guidance: str) -> KnowledgeCard:
    return KnowledgeCard(
        name=skill.name,
        description=skill.description,
        score=score,
        mapped_probes=mapped_probes(skill.name),
        guidance=guidance,
        sha256=skill.sha256,
        report_count=skill.report_count,
    )


def _serialized_cards_chars(cards: list[KnowledgeCard]) -> int:
    return len(
        json.dumps(
            [card.to_json() for card in cards],
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )


def _score_skill(
    skill: KnowledgeSkill,
    *,
    operator_text: str,
    typed_text: str,
    typed_identifiers: frozenset[str],
) -> int:
    score = 0
    name = skill.name.lower()
    activated = False
    if name and _contains_routing_signal(
        operator_text=operator_text,
        typed_text=typed_text,
        signal=name,
    ):
        score += 10
        activated = True
    short_name = name.removeprefix("hunt-") if name.startswith("hunt-") else ""
    if short_name and _contains_routing_signal(
        operator_text=operator_text,
        typed_text=typed_text,
        signal=short_name,
    ):
        score += 8
        activated = True

    for keyword in skill_keywords(skill.name):
        if _contains_routing_signal(
            operator_text=operator_text,
            typed_text=typed_text,
            signal=keyword.lower(),
        ):
            score += _PHRASE_KEYWORD_SCORE if " " in keyword.strip() else _KEYWORD_SCORE
            activated = True

    typed_matches = len(set(skill_typed_identifiers(skill.name)).intersection(typed_identifiers))
    if typed_matches:
        score += 12 + min(typed_matches - 1, 4) * 2
        activated = True

    if not activated:
        return 0

    evidence_text = f"{operator_text} {typed_text}"
    for token in sorted(_tokens(skill.description))[:16]:
        if len(token) >= _MIN_DESCRIPTION_TOKEN_CHARS and token in evidence_text:
            score += 1
    return score


def _typed_evidence(state: AgentState) -> tuple[str, frozenset[str]]:
    # Route from operator context and code-owned typed state. Model-authored
    # summaries, hypotheses, tasks, and memory updates are deliberately excluded
    # so a selected card cannot make itself increasingly likely on later turns.
    parts = {str(key).lower() for key in state.signals}
    parts.update(str(key).lower() for key in state.primitives)
    identifiers = {item for item in parts if item in ALL_SKILL_TYPED_IDENTIFIERS}
    for values in state.signals.values():
        for value in values[-20:]:
            normalized = str(value).strip().lower()
            if normalized in ALL_SKILL_TYPED_IDENTIFIERS:
                identifiers.add(normalized)

    surface_parts, surface_identifiers = _surface_evidence(state)
    parts.update(surface_parts)
    identifiers.update(surface_identifiers)
    return " ".join(sorted(parts)), frozenset(identifiers)


def _surface_evidence(state: AgentState) -> tuple[set[str], set[str]]:  # noqa: C901
    parts: set[str] = set()
    identifiers: set[str] = set()
    for operation in (state.surface_graph.operations or {}).values():
        route = operation.route_shape.casefold()
        selector = operation.selector.casefold()
        content_types = {item.casefold() for item in operation.content_types}
        hints = {item.casefold() for item in operation.hints}
        provenance = {item.casefold() for item in operation.provenance}
        parameters = tuple(operation.parameters)
        parameter_names = {item.name.casefold() for item in parameters}
        parameter_types = {item.data_type.casefold() for item in parameters}

        parts.update({route, selector, *content_types, *hints, *provenance})
        parts.update(parameter_names)
        parts.update(parameter_types)
        identifiers.update(
            item
            for item in (*hints, *parameter_names, *parameter_types)
            if item in ALL_SKILL_TYPED_IDENTIFIERS
        )

        surface_text = " ".join((route, selector, *sorted(hints)))
        if (
            "graphql" in surface_text
            or "graphql" in provenance
            or any(item.location == "graphql" for item in parameters)
        ):
            identifiers.add("graphql_surface")
        if _is_file_upload_surface(
            route=route,
            hints=hints,
            content_types=content_types,
            parameter_names=parameter_names,
            parameter_types=parameter_types,
        ):
            identifiers.add("file_upload_surface")
        if _is_xml_parser_surface(
            route=route,
            hints=hints,
            content_types=content_types,
        ):
            identifiers.add("xml_parser_surface")
        if _is_ssrf_fetch_surface(
            surface_text=surface_text,
            parameter_names=parameter_names,
        ):
            identifiers.add("ssrf_fetch_surface")
        if _is_serialized_object_surface(
            surface_text=surface_text,
            content_types=content_types,
            parameter_types=parameter_types,
        ):
            identifiers.add("serialized_object_surface")
        if _OBJECT_PARAMETER_NAMES.intersection(parameter_names):
            identifiers.add("object_authorization_surface")
        if _is_file_read_surface(
            surface_text=surface_text,
            parameter_names=parameter_names,
        ):
            identifiers.add("file_read_inputs")
        if _is_command_surface(
            surface_text=surface_text,
            parameter_names=parameter_names,
        ):
            identifiers.add("command_execution_surface")
        if any(term in surface_text for term in ("render", "template")) and parameter_names:
            identifiers.add("template_render_surface")
    return parts, identifiers


def _is_file_upload_surface(
    *,
    route: str,
    hints: set[str],
    content_types: set[str],
    parameter_names: set[str],
    parameter_types: set[str],
) -> bool:
    file_parameter = bool(_FILE_PARAMETER_NAMES.intersection(parameter_names)) or bool(
        {"binary", "byte", "file"}.intersection(parameter_types)
    )
    upload_context = "upload" in route or any("upload" in hint for hint in hints)
    return file_parameter and ("multipart/form-data" in content_types or upload_context)


def _is_xml_parser_surface(
    *,
    route: str,
    hints: set[str],
    content_types: set[str],
) -> bool:
    xml_media = any(
        item in {"application/xml", "text/xml", "application/soap+xml"} or item.endswith("+xml")
        for item in content_types
    )
    typed_path = any(term in route for term in ("/soap", "/wsdl", "/xml"))
    typed_hint = any(term in hint for hint in hints for term in ("soap", "wsdl", "xml"))
    return xml_media or typed_path or typed_hint


def _is_ssrf_fetch_surface(*, surface_text: str, parameter_names: set[str]) -> bool:
    url_parameter = bool(_URL_PARAMETER_NAMES.intersection(parameter_names)) or any(
        item.endswith(("_url", "_uri")) and item not in {"next_url", "redirect_uri", "return_url"}
        for item in parameter_names
    )
    return url_parameter and any(term in surface_text for term in _FETCH_SURFACE_TERMS)


def _is_serialized_object_surface(
    *,
    surface_text: str,
    content_types: set[str],
    parameter_types: set[str],
) -> bool:
    combined = " ".join((surface_text, *content_types, *parameter_types))
    return any(
        term in combined
        for term in (
            "deserial",
            "java_object",
            "objectstream",
            "pickle",
            "serialized",
            "yaml_object",
        )
    )


def _is_file_read_surface(*, surface_text: str, parameter_names: set[str]) -> bool:
    return bool(_PATH_PARAMETER_NAMES.intersection(parameter_names)) and any(
        term in surface_text
        for term in ("document", "download", "file", "include", "read", "render", "template")
    )


def _is_command_surface(*, surface_text: str, parameter_names: set[str]) -> bool:
    return bool(_COMMAND_PARAMETER_NAMES.intersection(parameter_names)) and any(
        term in surface_text
        for term in ("command", "convert", "diagnostic", "exec", "ping", "process", "run")
    )


def _contains_routing_signal(*, operator_text: str, typed_text: str, signal: str) -> bool:
    return _contains_operator_signal(operator_text, signal) or _contains_signal(
        typed_text,
        signal,
    )


def _contains_operator_signal(operator_text: str, signal: str) -> bool:
    normalized = signal.strip().lower()
    if not normalized:
        return False
    pattern = rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])"
    for match in re.finditer(pattern, operator_text):
        prefix = operator_text[max(0, match.start() - 48) : match.start()]
        suffix = operator_text[match.end() : match.end() + 48]
        prefix_clause = re.split(r"[.;,\n]", prefix)[-1]
        suffix_clause = re.split(r"[.;,\n]", suffix)[0]
        if _NEGATED_BEFORE_RE.search(prefix_clause) or _NEGATED_AFTER_RE.search(suffix_clause):
            continue
        return True
    return False


def _contains_signal(evidence_text: str, signal: str) -> bool:
    normalized = signal.strip().lower()
    if not normalized:
        return False
    pattern = rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])"
    return re.search(pattern, evidence_text) is not None


def _tokens(text: str) -> set[str]:
    return {match.group(0).lower() for match in _WORD_RE.finditer(text)}


def _strip_markdown_noise(body: str) -> str:
    lines: list[str] = []
    blank = False
    for raw_line in body.splitlines():
        line = raw_line.rstrip()
        if line.startswith(("![", "<")):
            continue
        if not line.strip():
            if not blank:
                lines.append("")
            blank = True
            continue
        blank = False
        lines.append(line)
    return "\n".join(lines).strip()
