from uuid import UUID

from pentest_schemas import (
    AttackSurface,
    Budget,
    DataHandling,
    Endpoint,
    EngagementBrief,
    ExploitStep,
    Finding,
    Param,
    Proof,
    RulesOfEngagement,
    Scope,
    SqlInjectionFinding,
    VulnerabilityFinding,
    __version__,
)
from pydantic import TypeAdapter

ENGAGEMENT_ID = UUID("11111111-1111-4111-8111-111111111111")
FINDING_ID = UUID("22222222-2222-4222-8222-222222222222")
SEMVER_PART_COUNT = 3


def test_schema_package_exports_semver() -> None:
    parts = __version__.split(".")

    assert len(parts) == SEMVER_PART_COUNT
    assert all(part.isdigit() for part in parts)


def test_engagement_brief_round_trips() -> None:
    original = EngagementBrief.model_validate(
        {
            "engagement_id": ENGAGEMENT_ID,
            "scope": Scope(in_scope=["http://target"], out_of_scope=["http://example.com"]),
            "roe": RulesOfEngagement(
                max_rps=10,
                no_destructive_actions=True,
                data_handling=DataHandling.PLACEHOLDERS_ONLY,
            ),
            "objectives": ["sql_injection"],
            "budget": Budget(max_cost_usd=10.0, max_runtime_min=30),
        }
    )

    round_tripped = EngagementBrief.model_validate_json(original.model_dump_json())

    assert round_tripped == original


def test_engagement_brief_accepts_broad_web_assessment_objective() -> None:
    brief = EngagementBrief.model_validate(
        {
            "engagement_id": ENGAGEMENT_ID,
            "scope": Scope(in_scope=["http://target"], out_of_scope=[]),
            "roe": RulesOfEngagement(max_rps=10),
            "objectives": ["web_application_assessment"],
            "budget": Budget(max_cost_usd=10.0, max_runtime_min=30),
        }
    )

    assert brief.objectives == ["web_application_assessment"]


def test_attack_surface_round_trips() -> None:
    original = AttackSurface.model_validate(
        {
            "engagement_id": ENGAGEMENT_ID,
            "endpoints": [
                Endpoint.model_validate(
                    {
                        "url": "http://target/vulnerabilities/sqli/?id=1",
                        "method": "GET",
                        "params": [Param(name="id", location="query", example_value="1")],
                        "auth_required": False,
                        "notes": "DVWA SQLi endpoint",
                    }
                )
            ],
            "stack_hints": ["php", "mysql-likely"],
            "auth_surfaces": [],
        }
    )

    round_tripped = AttackSurface.model_validate_json(original.model_dump_json())

    assert round_tripped == original


def test_sql_injection_finding_round_trips() -> None:
    endpoint = Endpoint.model_validate(
        {
            "url": "http://target/vulnerabilities/sqli/?id=1",
            "method": "GET",
            "params": [Param(name="id", location="query", example_value="1")],
            "auth_required": False,
            "notes": None,
        }
    )
    original = SqlInjectionFinding.model_validate(
        {
            "finding_id": FINDING_ID,
            "engagement_id": ENGAGEMENT_ID,
            "endpoint": endpoint,
            "hypothesis": "The id query parameter is injectable.",
            "exploit_steps": [
                ExploitStep(
                    http_request="GET /vulnerabilities/sqli/?id=1' HTTP/1.1",
                    response_snippet="SQL syntax error",
                    indicator="Database error confirms input reaches SQL parser.",
                )
            ],
            "proof": Proof(
                http_request_final="GET /vulnerabilities/sqli/?id=1' OR '1'='1 HTTP/1.1",
                response_final="Rows returned for boolean true branch.",
                impact_description="Boolean-based SQL injection changes the result set.",
            ),
            "status": "confirmed",
            "validator_vote": "confirm",
        }
    )

    round_tripped = SqlInjectionFinding.model_validate_json(original.model_dump_json())

    assert round_tripped == original


def test_finding_discriminated_union_round_trips() -> None:
    endpoint = Endpoint.model_validate(
        {
            "url": "http://target/vulnerabilities/sqli/?id=1",
            "method": "GET",
            "params": [Param(name="id", location="query", example_value="1")],
            "auth_required": False,
            "notes": None,
        }
    )
    original = SqlInjectionFinding(
        finding_id=FINDING_ID,
        engagement_id=ENGAGEMENT_ID,
        endpoint=endpoint,
        hypothesis="The id query parameter is injectable.",
        exploit_steps=[
            ExploitStep(
                http_request="GET /vulnerabilities/sqli/?id=1' HTTP/1.1",
                response_snippet="SQL syntax error",
                indicator="Database error confirms input reaches SQL parser.",
            )
        ],
        proof=Proof(
            http_request_final="GET /vulnerabilities/sqli/?id=1' OR '1'='1 HTTP/1.1",
            response_final="Rows returned for boolean true branch.",
            impact_description="Boolean-based SQL injection changes the result set.",
        ),
        status="confirmed",
        validator_vote="confirm",
    )
    adapter: TypeAdapter[Finding] = TypeAdapter(Finding)

    round_tripped = adapter.validate_json(adapter.dump_json(original))

    assert round_tripped == original


def test_generic_vulnerability_finding_round_trips() -> None:
    endpoint = Endpoint.model_validate(
        {
            "url": "http://target/fetch?url=http://127.0.0.1/admin",
            "method": "GET",
            "params": [Param(name="url", location="query")],
            "auth_required": False,
            "notes": "SSRF probe endpoint",
        }
    )
    original = VulnerabilityFinding(
        finding_id=FINDING_ID,
        engagement_id=ENGAGEMENT_ID,
        vuln_class="ssrf",
        endpoint=endpoint,
        hypothesis="The url query parameter fetched a controlled local resource.",
        exploit_steps=[
            ExploitStep(
                http_request="GET /fetch?url=http://127.0.0.1/admin HTTP/1.1",
                response_snippet="internal admin panel",
                indicator="ssrf_local_resource_disclosure",
            )
        ],
        proof=Proof(
            http_request_final="GET /fetch?url=http://127.0.0.1/admin HTTP/1.1",
            response_final="internal admin panel",
            impact_description="SSRF confirmed by bounded tool evidence.",
        ),
        status="confirmed",
        validator_vote="confirm",
    )
    adapter: TypeAdapter[Finding] = TypeAdapter(Finding)

    round_tripped = adapter.validate_json(adapter.dump_json(original))

    assert round_tripped == original
