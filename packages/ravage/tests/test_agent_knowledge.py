from __future__ import annotations

import json
import subprocess
from io import StringIO
from pathlib import Path
from typing import cast

import pytest
from ai_agent_fixtures import BRIEF_YAML
from ravage import __main__ as cli
from ravage.agent_core.agent_state import AgentState
from ravage.agent_core.ai_agent import (
    AIWebAgentSettings,
    _build_messages,
    _final_is_premature,
)
from ravage.agent_knowledge import (
    BUILTIN_KNOWLEDGE_PACK_PATH,
    describe_knowledge_pack,
    load_skill_pack,
    select_knowledge_cards,
)
from ravage.agent_knowledge.mappings import mapped_probes
from ravage.model_core.providers import ResolvedModelRoute
from ravage.probe_suite import available_probes, probe_requires_external_process
from ravage.run_data.brief import load_engagement_brief
from ravage.xben_parts.agent import _run_agent_subprocess
from ravage.xben_parts.logs import _write_report
from ravage.xben_parts.models import XbenCase, XbenSettings
from ravage.xben_parts.runner import _assert_xben_resume_knowledge_pack_contract

EXPECTED_BUILTIN_SKILLS = (
    "analyze-satcom",
    "hunt-deserialization",
    "hunt-file-upload",
    "hunt-graphql",
    "hunt-idor",
    "hunt-lfi",
    "hunt-rce",
    "hunt-sqli",
    "hunt-ssrf",
    "hunt-ssti",
    "hunt-xss",
    "hunt-xxe",
)
BUILTIN_SELECTION_LIMIT = 8
BUILTIN_SELECTION_MAX_CHARS = 12_000


def test_knowledge_pack_selector_picks_relevant_cards(tmp_path: Path) -> None:
    skills = _write_skill_pack(tmp_path)
    state = AgentState()
    state.facts.extend(
        [
            "Observed IDOR object reference on /api/users/123 with account_id and tenant boundary.",
            "GraphQL was not observed.",
        ]
    )

    cards = select_knowledge_cards(
        pack_path=skills,
        state=state,
        description="Find the IDOR authorization issue.",
        limit=2,
        max_chars=900,
    )

    assert cards
    assert cards[0].name == "hunt-idor"
    assert "idor_boundary" in cards[0].mapped_probes
    assert len(cards[0].guidance) <= 900
    assert describe_knowledge_pack(skills) is not None
    assert load_skill_pack(skills).metadata.skill_count == 2


def test_ai_web_prompt_includes_bounded_external_knowledge_cards(tmp_path: Path) -> None:
    skills = _write_skill_pack(tmp_path)
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    brief = load_engagement_brief(brief_path)
    state = AgentState()
    state.facts.append("GraphQL introspection endpoint exposes query IDs.")
    cards = select_knowledge_cards(
        pack_path=skills,
        state=state,
        description="GraphQL object access challenge.",
        limit=1,
        max_chars=700,
    )
    metadata = describe_knowledge_pack(skills)
    assert metadata is not None
    metadata_payload = metadata.to_json()
    metadata_payload["card_limit"] = 1
    metadata_payload["max_chars"] = 700

    messages = _build_messages(
        brief=brief,
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        state=state,
        settings=AIWebAgentSettings(knowledge_pack_path=skills),
        route=_route(),
        knowledge_cards=cards,
        knowledge_pack_metadata=metadata_payload,
    )

    user = json.loads(messages[1]["content"])
    assert isinstance(user, dict)
    knowledge = user["external_knowledge_pack"]
    assert isinstance(knowledge, dict)
    metadata = knowledge["metadata"]
    assert isinstance(metadata, dict)
    cards_payload = knowledge["cards"]
    assert isinstance(cards_payload, list)
    assert cards_payload
    card = cards_payload[0]
    assert isinstance(card, dict)
    tool_guidance = user["tool_guidance"]
    assert isinstance(tool_guidance, list)
    action_schema = user["action_schema"]
    assert isinstance(action_schema, dict)
    validate_poc = action_schema["validate_poc"]
    assert isinstance(validate_poc, dict)
    assert isinstance(validate_poc["finding"], dict)
    steps = validate_poc["steps"]
    assert isinstance(steps, list)
    assert [step["evidence_role"] for step in steps] == ["control", "exploit"]
    assert "capture_flag" not in action_schema
    assert metadata["skill_count"] == 2
    assert metadata["schema_version"] == "ravage.knowledge-pack.v1"
    assert "path" not in metadata
    assert card["name"] == "hunt-graphql"
    assert card["authority"] == "advisory"
    assert "graphql_exploit" in card["mapped_probes"]
    assert "Use external knowledge cards only" in "\n".join(str(item) for item in tool_guidance)
    assert "cannot filter a native probe's fixed payload" in "\n".join(
        str(item) for item in tool_guidance
    )
    assert "record each replayable vulnerability" in str(user["objective"])
    assert "No flag is required for this assessment" in "\n".join(
        str(item) for item in tool_guidance
    )
    assert "Plain reflection cannot confirm XSS" in "\n".join(str(item) for item in tool_guidance)
    guidance_text = "\n".join(str(item) for item in tool_guidance)
    assert "same endpoint, method, headers, and input shape" in guidance_text
    assert "server_side_template_injection/template_injection aliases" in guidance_text
    assert "local_file_inclusion, arbitrary_file_read, and file_read aliases" in guidance_text
    assert "new SQL error" in guidance_text
    assert "Unsupported claims remain candidates" in guidance_text
    assert "capture_flag" not in guidance_text


def test_flag_objective_keeps_capture_contract_and_premature_final_guard(
    tmp_path: Path,
) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(
        BRIEF_YAML.replace('- "sql_injection"', '- "capture_flag"'),
        encoding="utf-8",
    )
    brief = load_engagement_brief(brief_path)
    state = AgentState()
    state.surface["flag_objective"] = True

    messages = _build_messages(
        brief=brief,
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        state=state,
        settings=AIWebAgentSettings(),
        route=_route(),
    )

    user = json.loads(messages[1]["content"])
    assert "capture_flag" in user["action_schema"]
    assert "immediately use capture_flag" in "\n".join(user["tool_guidance"])
    assert _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=1,
        max_turns=2,
    )


def test_low_noise_prompt_exposes_only_metered_native_action_schema(tmp_path: Path) -> None:
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    brief = load_engagement_brief(brief_path)

    messages = _build_messages(
        brief=brief,
        brief_path=brief_path,
        target_url="http://127.0.0.1:8765",
        state=AgentState(),
        settings=AIWebAgentSettings(traffic_policy_mode="low-noise"),
        route=_route(),
        traffic_budget={
            "mode": "enforce",
            "physical_request_count": 9,
            "max_physical_requests": 20,
            "remaining_physical_requests": 11,
            "blocked_count": 1,
            "circuit_state": "closed",
        },
    )

    user = json.loads(messages[1]["content"])
    action_schema = user["action_schema"]
    assert "run_command" not in action_schema
    assert "run_python" not in action_schema
    assert all(
        not probe_requires_external_process(str(item["name"])) for item in user["available_probes"]
    )
    assert all(
        not probe_requires_external_process(str(item["probe"]))
        for item in user["available_specialists"]
    )
    assert user["traffic_budget"]["remaining_physical_requests"] == 11

    remote_messages = _build_messages(
        brief=brief,
        brief_path=brief_path,
        target_url="https://example.test/",
        state=AgentState(),
        settings=AIWebAgentSettings(
            traffic_policy_mode="low-noise",
            allow_remote_target=True,
        ),
        route=_route(),
    )
    remote_user = json.loads(remote_messages[1]["content"])
    guidance = "\n".join(str(item) for item in remote_user["tool_guidance"])
    assert "Remote shell, Python, and scanner actions" not in guidance
    assert "remote target was explicitly authorized" in guidance


def test_ordinary_objective_allows_final_only_after_assessment_tasks_close() -> None:
    state = AgentState()
    state.surface["flag_objective"] = False

    assert not _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=1,
        max_turns=40,
    )

    state.tasks = [{"id": "surface-map", "status": "pending"}]
    assert _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=1,
        max_turns=40,
    )

    state.tasks[0]["status"] = "blocked"
    assert not _final_is_premature(
        action={"action": "final"},
        state=state,
        turn=2,
        max_turns=40,
    )


def test_xben_report_records_knowledge_pack_metadata(tmp_path: Path) -> None:
    skills = _write_skill_pack(tmp_path)
    output_dir = tmp_path / "runs"
    output_dir.mkdir()
    case = XbenCase(
        benchmark_id="XBEN-001-24",
        path=tmp_path / "case",
        name="Case",
        level=1,
        description="Description",
        main_service="web",
        main_service_port=80,
    )

    report = _write_report(
        settings=XbenSettings(
            output_dir=output_dir,
            knowledge_pack_path=skills,
            knowledge_pack_limit=3,
            knowledge_pack_max_chars=1_500,
        ),
        results=[],
        selected_cases=[case],
    )

    knowledge_pack = report["knowledge_pack"]
    assert isinstance(knowledge_pack, dict)
    assert knowledge_pack["skill_count"] == 2
    assert knowledge_pack["card_limit"] == 3
    assert knowledge_pack["max_chars"] == 1_500
    started_at = report["started_at"]

    rewritten = _write_report(
        settings=XbenSettings(
            output_dir=output_dir,
            knowledge_pack_path=skills,
            knowledge_pack_limit=3,
            knowledge_pack_max_chars=1_500,
        ),
        results=[],
        selected_cases=[case],
    )

    assert rewritten["started_at"] == started_at
    manifest = (output_dir / "artifacts.sha256").read_text(encoding="utf-8")
    assert "  report.json\n" in manifest


def test_xben_resume_rejects_pack_free_report_for_skill_run_without_rewrite(
    tmp_path: Path,
) -> None:
    skills = _write_skill_pack(tmp_path / "current")
    output_dir = tmp_path / "runs"
    output_dir.mkdir()
    report_path = output_dir / "report.json"
    _write_report(
        settings=XbenSettings(output_dir=output_dir),
        results=[],
        selected_cases=[],
    )
    before = report_path.read_bytes()

    with pytest.raises(ValueError, match="knowledge-pack contract"):
        _assert_xben_resume_knowledge_pack_contract(
            XbenSettings(output_dir=output_dir, resume=True, knowledge_pack_path=skills),
            report_path,
        )

    assert report_path.read_bytes() == before


def test_xben_resume_allows_same_digest_from_relocated_pack(tmp_path: Path) -> None:
    first = _write_skill_pack(tmp_path / "first")
    relocated = _write_skill_pack(tmp_path / "relocated")
    output_dir = tmp_path / "runs"
    output_dir.mkdir()
    report_path = output_dir / "report.json"
    _write_report(
        settings=XbenSettings(output_dir=output_dir, knowledge_pack_path=first),
        results=[],
        selected_cases=[],
    )

    _assert_xben_resume_knowledge_pack_contract(
        XbenSettings(output_dir=output_dir, resume=True, knowledge_pack_path=relocated),
        report_path,
    )


@pytest.mark.parametrize(
    ("setting", "value"),
    [("knowledge_pack_limit", 3), ("knowledge_pack_max_chars", 1_500)],
)
def test_xben_resume_rejects_changed_knowledge_pack_bounds(
    tmp_path: Path,
    setting: str,
    value: int,
) -> None:
    skills = _write_skill_pack(tmp_path / "pack")
    output_dir = tmp_path / "runs"
    output_dir.mkdir()
    report_path = output_dir / "report.json"
    _write_report(
        settings=XbenSettings(output_dir=output_dir, knowledge_pack_path=skills),
        results=[],
        selected_cases=[],
    )
    settings = XbenSettings(
        output_dir=output_dir,
        retry_failed=True,
        knowledge_pack_path=skills,
        **{setting: value},
    )

    with pytest.raises(ValueError, match="does not match"):
        _assert_xben_resume_knowledge_pack_contract(settings, report_path)


def test_xben_agent_subprocess_passes_knowledge_pack_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skills = _write_skill_pack(tmp_path)
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        stdout = cast("StringIO", kwargs["stdout"])
        stdout.write("ok\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("ravage.xben_parts.agent.subprocess.run", fake_run)

    _run_agent_subprocess(
        settings=XbenSettings(
            output_dir=tmp_path / "runs",
            max_turns=1,
            knowledge_pack_path=skills,
            knowledge_pack_limit=2,
            knowledge_pack_max_chars=800,
        ),
        brief_path=tmp_path / "brief.yaml",
        target_url="http://127.0.0.1:8000",
        db_path=tmp_path / "audit.db",
        workspace_path=tmp_path / "workspace",
        stdout=StringIO(),
    )

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[cmd.index("--knowledge-pack") + 1] == str(skills)
    assert cmd[cmd.index("--knowledge-pack-sha256") + 1] == load_skill_pack(skills).metadata.sha256
    assert cmd[cmd.index("--knowledge-pack-limit") + 1] == "2"
    assert cmd[cmd.index("--knowledge-pack-max-chars") + 1] == "800"


def test_code_bug_attack_forwards_skills_as_internal_knowledge_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skills = _write_skill_pack(tmp_path)
    brief_path = tmp_path / "brief.yaml"
    brief_path.write_text(BRIEF_YAML, encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_attack(args: list[str]) -> None:
        captured["args"] = args

    monkeypatch.setattr(cli, "_attack", fake_attack)

    cli.main(
        [
            "code-bug",
            str(brief_path),
            "--skills",
            str(skills),
            "--card-limit",
            "2",
            "--max-card-chars",
            "800",
            "--model-profile",
            "local-ollama",
        ]
    )

    args = captured["args"]
    assert args[0] == str(brief_path)
    assert "--skills" not in args
    assert args[args.index("--knowledge-pack") + 1] == str(skills)
    assert (
        args[args.index("--knowledge-pack-sha256") + 1] == load_skill_pack(skills).metadata.sha256
    )
    assert args[args.index("--knowledge-pack-limit") + 1] == "2"
    assert args[args.index("--knowledge-pack-max-chars") + 1] == "800"
    assert args[args.index("--model-profile") + 1] == "local-ollama"


def test_code_bug_xben_forwards_skills_as_internal_knowledge_pack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skills = _write_skill_pack(tmp_path)
    captured: dict[str, list[str]] = {}

    def fake_xben(args: list[str]) -> None:
        captured["args"] = args

    monkeypatch.setattr(cli, "_xben", fake_xben)

    cli.main(
        [
            "code-bug",
            "xben",
            "--skills",
            str(skills),
            "--ids",
            "XBEN-001-24",
            "--card-limit",
            "3",
        ]
    )

    args = captured["args"]
    assert args[args.index("--ids") + 1] == "XBEN-001-24"
    assert "--skills" not in args
    assert args[args.index("--knowledge-pack") + 1] == str(skills)
    assert (
        args[args.index("--knowledge-pack-sha256") + 1] == load_skill_pack(skills).metadata.sha256
    )
    assert args[args.index("--knowledge-pack-limit") + 1] == "3"


def test_code_bug_rejects_a_changed_or_malformed_expected_pack_digest(tmp_path: Path) -> None:
    skills = _write_skill_pack(tmp_path)

    with pytest.raises(SystemExit) as mismatched:
        cli.main(
            [
                "code-bug",
                "brief.yaml",
                "--skills",
                str(skills),
                "--skills-sha256",
                "0" * 64,
            ]
        )
    assert mismatched.value.code == 2

    with pytest.raises(SystemExit) as malformed:
        cli.main(
            [
                "code-bug",
                "brief.yaml",
                "--skills",
                str(skills),
                "--skills-sha256",
                "invalid",
            ]
        )
    assert malformed.value.code == 2


def test_builtin_pack_is_explicit_versioned_and_bounded() -> None:
    pack = load_skill_pack(Path("builtin"))

    assert pack.root == BUILTIN_KNOWLEDGE_PACK_PATH.resolve()
    assert pack.metadata.schema_version == "ravage.knowledge-pack.v1"
    assert pack.metadata.skill_count == len(EXPECTED_BUILTIN_SKILLS)
    assert tuple(skill.name for skill in pack.skills) == EXPECTED_BUILTIN_SKILLS


@pytest.mark.parametrize(
    ("expected", "description"),
    [
        ("hunt-deserialization", "Assess unsafe pickle deserialization in a session cookie."),
        ("hunt-file-upload", "Assess an authorized multipart/form-data file upload."),
        ("hunt-lfi", "Assess an authorized local file inclusion and path traversal surface."),
        ("hunt-rce", "Assess an authorized OS command injection surface."),
        ("hunt-sqli", "Assess SQL injection in an authorized query-backed input."),
        ("hunt-ssrf", "Assess an authorized server-side URL fetch boundary."),
        ("hunt-ssti", "Assess authorized server-side template injection."),
        ("hunt-xss", "Assess authorized reflected cross-site scripting."),
        ("hunt-xxe", "Assess an authorized XML external entity parser."),
    ],
)
def test_selector_activates_each_builtin_hunting_skill(
    expected: str,
    description: str,
) -> None:
    max_chars = 2_500
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=description,
        limit=1,
        max_chars=max_chars,
    )

    assert [card.name for card in cards] == [expected]
    assert "## Evidence Gate" in cards[0].guidance
    assert "## Stop Conditions" in cards[0].guidance
    assert "contract_missing" in cards[0].guidance
    serialized = json.dumps(
        [card.to_json() for card in cards],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    assert len(serialized) <= max_chars


@pytest.mark.parametrize(
    ("expected", "typed_key"),
    [
        ("hunt-deserialization", "serialized_cookie_confirmed"),
        ("hunt-graphql", "graphql_schema_available"),
        ("hunt-idor", "idor_confirmed"),
        ("hunt-lfi", "file_read_confirmed"),
        ("hunt-rce", "command_exec_confirmed"),
        ("hunt-rce", "werkzeug_console_exposed"),
        ("hunt-rce", "werkzeug_console_unlocked"),
        ("hunt-sqli", "sqli_confirmed"),
        ("hunt-ssrf", "ssrf_confirmed"),
        ("hunt-ssti", "ssti_confirmed"),
        ("hunt-xss", "client_xss_confirmed"),
        ("hunt-xxe", "xxe_surface_observed"),
    ],
)
def test_selector_activates_from_code_owned_typed_state(
    expected: str,
    typed_key: str,
) -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(primitives={typed_key: 1}),
        description="Assess this ordinary authorized application.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == [expected]


def test_selector_activates_file_upload_from_typed_surface_graph() -> None:
    state = AgentState()
    state.surface_graph.add(
        url="https://example.test/assets",
        method="POST",
        parameters=(
            {
                "name": "document",
                "location": "form",
                "data_type": "binary",
                "required": True,
            },
        ),
        content_types=("multipart/form-data",),
        source_kind="openapi",
    )

    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Assess this ordinary authorized application.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == ["hunt-file-upload"]


def test_selector_activates_file_upload_from_code_owned_marker_value() -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(signals={"markers": ["file_upload_sink_reachable"]}),
        description="Assess this ordinary authorized application.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == ["hunt-file-upload"]


@pytest.mark.parametrize(
    ("url", "parameters", "content_types", "hints", "expected"),
    [
        (
            "https://example.test/fetch",
            ({"name": "url", "location": "form"},),
            (),
            (),
            "hunt-ssrf",
        ),
        (
            "https://example.test/ingest",
            (),
            ("application/xml",),
            (),
            "hunt-xxe",
        ),
        (
            "https://example.test/process",
            ({"name": "payload", "location": "body", "data_type": "pickle"},),
            (),
            (),
            "hunt-deserialization",
        ),
    ],
)
def test_selector_derives_family_from_typed_surface_metadata(
    url: str,
    parameters: tuple[dict[str, object], ...],
    content_types: tuple[str, ...],
    hints: tuple[str, ...],
    expected: str,
) -> None:
    state = AgentState()
    state.surface_graph.add(
        url=url,
        method="POST",
        parameters=parameters,
        content_types=content_types,
        hints=hints,
        source_kind="openapi",
    )

    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Assess this ordinary authorized application.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == [expected]


def test_selector_scans_the_complete_bounded_surface_graph() -> None:
    state = AgentState()
    for index in range(511):
        state.surface_graph.add(
            url=f"https://example.test/noise-{index:03d}",
            source_kind="native_recon",
        )
    graphql = state.surface_graph.add(
        url="https://example.test/graphql",
        method="POST",
        source_kind="graphql",
    )
    projected_ids = set(sorted(state.surface_graph.operations or {})[:80])
    assert graphql.operation_id not in projected_ids

    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Assess this ordinary authorized application.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == ["hunt-graphql"]


@pytest.mark.parametrize(
    "description",
    [
        (
            "Document a PostgreSQL-backed JavaScript application with YAML configuration "
            "and SVG icons."
        ),
        "Review a command-line script template that uploads metadata callbacks.",
        "Collect HTTP telemetry for an ordinary web service.",
        "Review authorization header parsing in a REST client.",
        "Run mutation testing against a non-GraphQL API.",
        "Validate an ordinary server-side request object.",
        "Document a benign SOAP client schema.",
        "Use Python introspection to inspect class members.",
        "Telemetry packet loss in an ordinary HTTP collector.",
        "Document tenant naming conventions for an ordinary application.",
        "Render a harmless Jinja documentation example.",
    ],
)
def test_selector_ignores_broad_non_security_terms(description: str) -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=description,
    )

    assert cards == []


@pytest.mark.parametrize(
    ("expected", "description"),
    [
        ("hunt-graphql", "Assess GraphQL introspection on the authorized API."),
        ("analyze-satcom", "Inspect the authorized CCSDS telemetry packet stream."),
        ("hunt-idor", "Assess cross-tenant object references in the authorized API."),
        ("hunt-ssti", "Assess Jinja injection in the authorized render endpoint."),
    ],
)
def test_selector_preserves_specific_lexical_routing(
    expected: str,
    description: str,
) -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=description,
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == [expected]


@pytest.mark.parametrize(
    "description",
    [
        "GraphQL is absent; assess SQL injection in the search input.",
        "GraphQL isn't present; assess SQL injection in the search input.",
        "GraphQL does not appear to be present; assess SQL injection in the search input.",
    ],
)
def test_selector_honors_explicit_operator_negation(description: str) -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=description,
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == ["hunt-sqli"]


def test_specific_pickle_upload_outranks_generic_rce_objective() -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description="Uploading a pickle file without sanitization may lead to RCE.",
        limit=1,
        max_chars=2_500,
    )

    assert [card.name for card in cards] == ["hunt-deserialization"]


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("Investigate SQL injection in a YAML serialized object.", {"hunt-sqli"}),
        (
            "Investigate server-side template injection with command execution.",
            {"hunt-ssti"},
        ),
        (
            "Investigate XML external entity behavior in a multipart file upload.",
            {"hunt-xxe", "hunt-file-upload"},
        ),
        (
            "Investigate local file inclusion through a multipart upload.",
            {"hunt-lfi", "hunt-file-upload"},
        ),
    ],
)
def test_selector_keeps_ambiguous_routing_relevant(
    description: str,
    expected: set[str],
) -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=description,
        limit=4,
        max_chars=12_000,
    )

    assert {card.name for card in cards} == expected


def test_builtin_selection_remains_globally_bounded() -> None:
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description=" ".join(EXPECTED_BUILTIN_SKILLS),
        limit=999,
        max_chars=999_999,
    )
    serialized = json.dumps(
        [card.to_json() for card in cards],
        ensure_ascii=True,
        separators=(",", ":"),
    )

    assert 0 < len(cards) <= BUILTIN_SELECTION_LIMIT
    assert len(serialized) <= BUILTIN_SELECTION_MAX_CHARS


def test_builtin_skill_probe_mappings_reference_native_probes() -> None:
    native_probes = {item["name"] for item in available_probes()}

    for skill in load_skill_pack(Path("builtin")).skills:
        probes = mapped_probes(skill.name)
        if skill.name == "analyze-satcom":
            assert probes == ()
        else:
            assert probes
        assert len(probes) == len(set(probes))
        assert set(probes) <= native_probes, skill.name


def test_selector_ignores_model_authored_self_reinforcement() -> None:
    poison = "SSRF XXE deserialization XSS SQLi SSTI LFI RCE file upload GraphQL IDOR SATCOM"
    state = AgentState(
        summary=poison,
        facts=[poison],
        hypotheses=[poison],
        actions=[{"summary": poison}],
        tasks=[{"description": poison}],
        last_observation={"summary": poison},
        surface={"notes": poison},
    )

    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=state,
        description="Assess this ordinary authorized web application.",
    )

    assert cards == []


def test_selector_activates_satcom_only_from_operator_or_typed_context() -> None:
    max_chars = 2_500
    cards = select_knowledge_cards(
        pack_path=Path("builtin"),
        state=AgentState(),
        description="Inspect this offline CCSDS telemetry packet stream.",
        limit=1,
        max_chars=max_chars,
    )

    assert [card.name for card in cards] == ["analyze-satcom"]
    assert "## Evidence Gate" in cards[0].guidance
    assert "## Stop Conditions" in cards[0].guidance
    serialized = json.dumps(
        [card.to_json() for card in cards],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    assert len(serialized) <= max_chars


def test_skill_loader_rejects_ambiguous_or_substituted_files(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate" / "hunt-idor"
    duplicate.mkdir(parents=True)
    duplicate.joinpath("SKILL.md").write_text(
        "---\nname: hunt-idor\nname: hunt-idor\ndescription: Duplicate.\n---\nBody\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate field"):
        load_skill_pack(duplicate.parent)

    substituted = tmp_path / "substituted" / "hunt-idor"
    substituted.mkdir(parents=True)
    source = tmp_path / "source.md"
    source.write_text(
        "---\nname: hunt-idor\ndescription: Safe description.\n---\nBody\n",
        encoding="utf-8",
    )
    substituted.joinpath("SKILL.md").symlink_to(source)
    with pytest.raises(ValueError, match=r"unsafe|symlink|read"):
        load_skill_pack(substituted.parent)


def test_skills_cli_lists_builtin_pack(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["skills", "list"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["metadata"]["skill_count"] == len(EXPECTED_BUILTIN_SKILLS)
    assert tuple(item["name"] for item in payload["skills"]) == EXPECTED_BUILTIN_SKILLS


def _write_skill_pack(tmp_path: Path) -> Path:
    skills = tmp_path / "skills"
    _write_skill(
        skills,
        "hunt-idor",
        "Hunting skill for IDOR object reference and tenant authorization issues.",
        """
## Attack Surface Signals

Look for object references, user_id, account_id, org_id, invoices, and tenant boundaries.

## Methodology

Compare two same-privilege identities and replay the owner resource ID as the other identity.
""",
        report_count=26,
    )
    _write_skill(
        skills,
        "hunt-graphql",
        "Hunting skill for GraphQL introspection and object authorization flaws.",
        """
## Attack Surface Signals

Look for /graphql, __schema, query IDs, mutations, and object fields.

## Methodology

Use introspection to find ID-taking queries and route to GraphQL-specific probes.
""",
        report_count=12,
    )
    return skills


def _write_skill(
    root: Path,
    name: str,
    description: str,
    body: str,
    *,
    report_count: int,
) -> None:
    directory = root / name
    directory.mkdir(parents=True)
    directory.joinpath("SKILL.md").write_text(
        f"""---
name: {name}
description: {description}
report_count: {report_count}
---
{body.strip()}
""",
        encoding="utf-8",
    )


def _route() -> ResolvedModelRoute:
    return ResolvedModelRoute(
        requested_tier="low",
        selected_tier="low",
        ordinal=0,
        provider="ollama",
        model="local",
        base_url="http://localhost:11434/v1",
        api_key_env=None,
        missing_env=(),
        reasoning_effort=None,
        max_output_tokens=256,
        output_token_limit_parameter="max_tokens",
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
        timeout_seconds=1,
        max_retries=0,
    )
