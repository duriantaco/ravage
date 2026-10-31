# ruff: noqa: ANN401,C901,EM101,EM102,PERF401,PLR0912,TRY003
"""Deterministic reporting for the local Codex-versus-Strix XBEN diagnostic."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Final

REPORT_SCHEMA: Final = "ravage.xben-head-to-head-report.v1"
EXPECTED_CASES: Final = 20
SYSTEMS: Final = ("codex_skill", "strix")
SYSTEM_LABELS: Final = {
    "codex_skill": "Codex + Ravage skill",
    "strix": "Strix",
}

_INTEGER_METRICS: Final = (
    "request_count",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
)
_METADATA_ALIASES: Final = {
    "sources": ("sources", "source", "source_pins"),
    "model": ("model", "model_pin"),
    "runtimes": ("runtimes", "runtime", "runtime_pins"),
    "budgets": ("budgets",),
}


class HeadToHeadReportError(ValueError):
    """The campaign cannot be represented as a matched 20-case report."""


def exact_sign_test_p_value(first_only: int, second_only: int) -> float:
    """Return the two-sided exact sign-test p-value for discordant pairs."""
    if (
        isinstance(first_only, bool)
        or not isinstance(first_only, int)
        or first_only < 0
        or isinstance(second_only, bool)
        or not isinstance(second_only, int)
        or second_only < 0
    ):
        raise HeadToHeadReportError("sign-test counts must be non-negative integers")
    discordant = first_only + second_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, index) for index in range(min(first_only, second_only) + 1))
    return min(1.0, (2 * tail) / (2**discordant))


def build_report(campaign: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and aggregate a local 20-case campaign without adding timestamps."""
    if not isinstance(campaign, Mapping):
        raise HeadToHeadReportError("campaign must be a mapping")
    top_level_metadata = {
        key: value for key, value in campaign.items() if key not in {"metadata", "rows"}
    }
    nested_metadata = campaign.get("metadata")
    if nested_metadata is None:
        raw_metadata = top_level_metadata
    else:
        raw_metadata = {
            **top_level_metadata,
            **_mapping(nested_metadata, "campaign metadata"),
        }
    metadata = _json_copy(_mapping(raw_metadata, "campaign metadata"))
    contract = {
        name: _required_metadata_section(metadata, name, aliases)
        for name, aliases in _METADATA_ALIASES.items()
    }
    raw_rows = campaign.get("rows")
    if not isinstance(raw_rows, Sequence) or isinstance(raw_rows, str | bytes):
        raise HeadToHeadReportError("campaign rows must be a sequence")
    rows = [_normalize_row(row, index=index) for index, row in enumerate(raw_rows)]
    pairs = _matched_pairs(rows)
    _validate_declared_case_ids(metadata, rows)
    rows = sorted(
        rows, key=lambda row: (_natural_key(row["case_id"]), SYSTEMS.index(row["system"]))
    )

    system_summaries = {
        system: _aggregate_rows([row for row in rows if row["system"] == system])
        for system in SYSTEMS
    }
    overall = _aggregate_rows(rows)
    both = sum(
        pair["codex_skill"]["scored_solved"] and pair["strix"]["scored_solved"] for pair in pairs
    )
    codex_only = sum(
        pair["codex_skill"]["scored_solved"] and not pair["strix"]["scored_solved"]
        for pair in pairs
    )
    strix_only = sum(
        not pair["codex_skill"]["scored_solved"] and pair["strix"]["scored_solved"]
        for pair in pairs
    )
    neither = EXPECTED_CASES - both - codex_only - strix_only
    delta = (
        system_summaries["codex_skill"]["solve_rate"] - system_summaries["strix"]["solve_rate"]
    ) * 100
    contingency = {
        "both_solved": both,
        "codex_skill_only": codex_only,
        "strix_only": strix_only,
        "neither_solved": neither,
        "discordant_pairs": codex_only + strix_only,
        "solve_rate_delta_percentage_points": round(delta, 10),
        "two_sided_exact_sign_test_p_value": exact_sign_test_p_value(codex_only, strix_only),
    }
    failures = [
        {
            "case_id": row["case_id"],
            "system": row["system"],
            "status": row["status"],
            "reported_solved": row["solved"],
            "evidence_valid": row["evidence_valid"],
            "error": row["error"],
        }
        for row in rows
        if not row["scored_solved"]
        or row["error"] is not None
        or row["status"] not in {"completed", "solved"}
    ]
    return {
        "schema_version": REPORT_SCHEMA,
        "metadata": metadata,
        "contract": contract,
        "summary": {
            "case_count": EXPECTED_CASES,
            "row_count": len(rows),
            "systems": system_summaries,
            "overall_resources": overall["resources"],
            "contingency": contingency,
            "failure_count": len(failures),
        },
        "rows": rows,
        "failures": failures,
    }


def render_markdown(campaign_or_report: Mapping[str, Any]) -> str:
    """Render a deterministic human-readable comparison report."""
    if campaign_or_report.get("schema_version") == REPORT_SCHEMA:
        report = _json_copy(campaign_or_report)
    else:
        report = build_report(campaign_or_report)
    metadata = _mapping(report["metadata"], "report metadata")
    contract = _mapping(report["contract"], "report contract")
    summary = _mapping(report["summary"], "report summary")
    systems = _mapping(summary["systems"], "system summaries")
    contingency = _mapping(summary["contingency"], "contingency")
    rows = report["rows"]
    failures = report["failures"]

    lines = [
        "# Codex + Ravage Skill vs Strix — 20-Case XBEN Diagnostic",
        "",
        "> **Scope:** exploratory local diagnostic—not official/public/SOTA XBEN score.",
        "",
        "Solve rates below use all 20 scheduled cases. A solve counts only when the row completed "
        "without an error and reports `solved=true` with valid evidence.",
        "",
        "## Campaign identity",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    identity_keys = (
        "campaign_id",
        "title",
        "created_at",
        "started_at",
        "completed_at",
        "generated_at",
        "selection_seed",
    )
    found_identity = False
    for key in identity_keys:
        if key in metadata:
            found_identity = True
            lines.append(f"| {_md(key)} | {_md(_scalar_text(metadata[key]))} |")
    if not found_identity:
        lines.append("| supplied identity fields | none |")

    for heading, key in (
        ("Source pins", "sources"),
        ("Model pin", "model"),
        ("Runtime pins", "runtimes"),
        ("Budgets", "budgets"),
    ):
        lines.extend(("", f"### {heading}", "", _json_code_block(contract[key])))
    methodology = metadata.get("methodology")
    if isinstance(methodology, Mapping) and methodology:
        lines.extend(("", "### Campaign methodology", "", _json_code_block(methodology)))

    lines.extend(
        (
            "",
            "## Aggregate comparison",
            "",
            "| System | Validated solves | Solve rate | Evidence-valid rows |",
            "|---|---:|---:|---:|",
        )
    )
    for system in SYSTEMS:
        aggregate = _mapping(systems[system], f"{system} summary")
        lines.append(
            f"| {SYSTEM_LABELS[system]} | {aggregate['solved']}/{EXPECTED_CASES} | "
            f"{_percent(aggregate['solve_rate'])} | "
            f"{aggregate['evidence_valid_rows']}/{EXPECTED_CASES} |"
        )

    lines.extend(
        (
            "",
            "### Matched contingency",
            "",
            "| Both solved | Codex + skill only | Strix only | Neither | Discordant | "
            "Codex delta |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {contingency['both_solved']} | {contingency['codex_skill_only']} | "
            f"{contingency['strix_only']} | {contingency['neither_solved']} | "
            f"{contingency['discordant_pairs']} | "
            f"{_signed_points(contingency['solve_rate_delta_percentage_points'])} |",
            "",
            "Two-sided exact sign-test p-value over discordant pairs: "
            f"**{_probability(contingency['two_sided_exact_sign_test_p_value'])}**.",
            "",
            "### Resource totals",
            "",
            "Unknown observations are reported as unknown; they are never added as zero.",
            "",
            "| System | Requests | Input tokens | Cached input | Output tokens | Total tokens | "
            "Cost (USD) | Row runtime sum |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        )
    )
    for system in (*SYSTEMS, "overall"):
        resources = (
            _mapping(systems[system], f"{system} summary")["resources"]
            if system in SYSTEMS
            else summary["overall_resources"]
        )
        resource_map = _mapping(resources, f"{system} resources")
        label = SYSTEM_LABELS.get(system, "All 40 rows")
        lines.append(
            f"| {label} | {_metric(resource_map['request_count'])} | "
            f"{_metric(resource_map['input_tokens'])} | "
            f"{_metric(resource_map['cached_input_tokens'])} | "
            f"{_metric(resource_map['output_tokens'])} | "
            f"{_metric(resource_map['total_tokens'])} | "
            f"{_cost(resource_map['cost_usd'])} | "
            f"{_duration(resource_map['duration_seconds'])} |"
        )

    lines.extend(
        (
            "",
            "## Matched per-case outcomes",
            "",
            "| Case | Level | Codex + Ravage skill | Strix | Pair outcome |",
            "|---|---|---|---|---|",
        )
    )
    by_case: dict[str, dict[str, Mapping[str, Any]]] = {}
    for row in rows:
        by_case.setdefault(row["case_id"], {})[row["system"]] = row
    for case_id in sorted(by_case, key=_natural_key):
        pair = by_case[case_id]
        codex = pair["codex_skill"]
        strix = pair["strix"]
        lines.append(
            f"| {_md(case_id)} | {_md(_scalar_text(codex['level']))} | "
            f"{_row_cell(codex)} | {_row_cell(strix)} | {_pair_outcome(codex, strix)} |"
        )

    lines.extend(
        (
            "",
            "## Unsolved, invalid, and failed rows",
            "",
            "| Case | System | Status | Reported solve | Evidence | Error |",
            "|---|---|---|---:|---|---|",
        )
    )
    if failures:
        for failure in failures:
            lines.append(
                f"| {_md(failure['case_id'])} | {SYSTEM_LABELS[failure['system']]} | "
                f"{_md(failure['status'])} | {_yes_no(failure['reported_solved'])} | "
                f"{_valid_invalid(failure['evidence_valid'])} | "
                f"{_md(failure['error'] or '—')} |"
            )
    else:
        lines.append("| — | — | — | — | — | None |")

    lines.extend(
        (
            "",
            "## Methodology and caveats",
            "",
            "- This is an exploratory local diagnostic—not official/public/SOTA XBEN score.",
            "",
            "- Both tools retain shared Docker authority in this local setup; there is no "
            "independent anti-cheat isolation. A tool with Docker control could inspect peer or "
            "target containers, so these results are not publication-grade.",
            "",
            "- Unknown cost, request, token, or runtime observations are unknown—not zero. Known "
            "subtotals are lower bounds whenever coverage is incomplete.",
            "",
            "- Infrastructure errors, timeouts, and invalid evidence remain in the 20-case "
            "denominator and do not count as validated solves.",
            "",
            "- The exact sign test uses only discordant matched pairs. With 20 selected cases it "
            "does not establish equivalence, superiority, or broad benchmark generality.",
            "",
            "- Strix's historical 96% result is contextual only: it used Strix v0.4.0 with "
            "Gemini 3 Pro Preview, not this campaign's pinned source/model/runtime, so it is "
            "not a directly comparable baseline.",
            "",
        )
    )
    return "\n".join(lines)


def write_report(
    output_directory: Path | str,
    campaign: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Atomically replace ``COMPARISON.md`` and ``report.json`` in a directory."""
    destination = Path(output_directory).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    if not destination.is_dir():
        raise HeadToHeadReportError("report output is not a directory")
    report = build_report(campaign)
    markdown = render_markdown(report)
    json_text = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    markdown_path = destination / "COMPARISON.md"
    json_path = destination / "report.json"
    markdown_temporary = _stage_text(markdown_path, markdown)
    json_temporary: Path | None = None
    try:
        json_temporary = _stage_text(json_path, json_text)
        json_temporary.replace(json_path)
        json_temporary = None
        markdown_temporary.replace(markdown_path)
    finally:
        markdown_temporary.unlink(missing_ok=True)
        if json_temporary is not None:
            json_temporary.unlink(missing_ok=True)
    return markdown_path, json_path


def _normalize_row(raw_row: object, *, index: int) -> dict[str, Any]:
    row = _mapping(raw_row, f"row {index}")
    case_id = _nonempty_string(row.get("case_id"), f"row {index} case_id")
    system = _nonempty_string(row.get("system"), f"row {index} system")
    if system not in SYSTEMS:
        raise HeadToHeadReportError(f"row {index} has unsupported system {system!r}")
    if "level" not in row or (
        isinstance(row["level"], Mapping | Sequence) and not isinstance(row["level"], str)
    ):
        raise HeadToHeadReportError(f"row {index} level must be a scalar")
    level = _json_copy(row["level"])
    status = _nonempty_string(row.get("status"), f"row {index} status")
    solved = row.get("solved")
    if not isinstance(solved, bool):
        raise HeadToHeadReportError(f"row {index} solved must be boolean")
    usage_value = row.get("usage")
    if usage_value is None:
        usage: Mapping[str, Any] = {}
    else:
        usage = _mapping(usage_value, f"row {index} usage")
    duration = _optional_number(row.get("duration_seconds"), f"row {index} duration_seconds")
    error = _optional_text(row.get("error"), f"row {index} error")
    declared_evidence_valid = _evidence_validity(row, index=index)
    terminally_completed = status in {"completed", "solved"} and error is None
    evidence_valid = declared_evidence_valid and terminally_completed
    normalized: dict[str, Any] = {
        "case_id": case_id,
        "level": level,
        "system": system,
        "status": status,
        "solved": solved,
        "evidence_valid": evidence_valid,
        # Fail closed even if a malformed caller claims a solve on a timeout or
        # errored row.  The campaign performs the ground-truth comparison; the
        # report independently enforces terminal eligibility.
        "scored_solved": solved and evidence_valid and terminally_completed,
        "duration_seconds": duration,
        "error": error,
        "declared_candidate_sha256s": _sha256_list(
            row.get("declared_candidate_sha256s"),
            f"row {index} declared_candidate_sha256s",
        ),
        "matched_candidate_sha256": _optional_sha256(
            row.get("matched_candidate_sha256"),
            f"row {index} matched_candidate_sha256",
        ),
        "sanitized_runner_receipt_sha256": _optional_sha256(
            row.get("sanitized_runner_receipt_sha256"),
            f"row {index} sanitized_runner_receipt_sha256",
        ),
        "evidence_manifest_sha256": _optional_sha256(
            row.get("evidence_manifest_sha256"),
            f"row {index} evidence_manifest_sha256",
        ),
        "evidence_path": _optional_text(
            row.get("evidence_path"),
            f"row {index} evidence_path",
        ),
        "codex_target_http_requests": _optional_nonnegative_int(
            row.get("codex_target_http_requests"),
            f"row {index} codex_target_http_requests",
        ),
        "strix_model_requests": _optional_nonnegative_int(
            row.get("strix_model_requests"),
            f"row {index} strix_model_requests",
        ),
    }
    for metric in _INTEGER_METRICS:
        aliases = ("requests",) if metric == "request_count" else ()
        value = _first_present(row, usage, names=(metric, *aliases))
        normalized[metric] = _optional_nonnegative_int(value, f"row {index} {metric}")
    if normalized["total_tokens"] is None:
        input_tokens = normalized["input_tokens"]
        output_tokens = normalized["output_tokens"]
        if input_tokens is not None and output_tokens is not None:
            normalized["total_tokens"] = input_tokens + output_tokens
    raw_cost = _first_present(row, usage, names=("cost_usd", "known_cost_usd", "cost"))
    cost = _optional_decimal(raw_cost, f"row {index} cost_usd")
    normalized["cost_usd"] = _decimal_json(cost) if cost is not None else None
    return normalized


def _matched_pairs(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Mapping[str, Any]]]:
    if len(rows) != EXPECTED_CASES * len(SYSTEMS):
        raise HeadToHeadReportError(
            f"campaign must contain exactly {EXPECTED_CASES * len(SYSTEMS)} rows"
        )
    by_case: dict[str, dict[str, Mapping[str, Any]]] = {}
    for row in rows:
        case_id = row["case_id"]
        system = row["system"]
        pair = by_case.setdefault(case_id, {})
        if system in pair:
            raise HeadToHeadReportError(f"duplicate {system} row for case {case_id}")
        pair[system] = row
    if len(by_case) != EXPECTED_CASES:
        raise HeadToHeadReportError(f"campaign must contain exactly {EXPECTED_CASES} unique cases")
    pairs: list[dict[str, Mapping[str, Any]]] = []
    for case_id in sorted(by_case, key=_natural_key):
        pair = by_case[case_id]
        missing = [system for system in SYSTEMS if system not in pair]
        if missing:
            raise HeadToHeadReportError(f"case {case_id} is missing rows for {missing}")
        if pair["codex_skill"]["level"] != pair["strix"]["level"]:
            raise HeadToHeadReportError(f"case {case_id} has mismatched levels")
        pairs.append(pair)
    return pairs


def _aggregate_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    resources: dict[str, Any] = {}
    for metric in _INTEGER_METRICS:
        resources[metric] = _sum_metric(rows, metric)
    resources["duration_seconds"] = _sum_metric(rows, "duration_seconds")
    known_costs = [Decimal(str(row["cost_usd"])) for row in rows if row["cost_usd"] is not None]
    unknown_costs = sum(row["cost_usd"] is None for row in rows)
    known_cost = sum(known_costs, Decimal(0))
    resources["cost_usd"] = {
        "known_subtotal": _decimal_json(known_cost),
        "unknown_rows": unknown_costs,
        "total": _decimal_json(known_cost) if unknown_costs == 0 else None,
    }
    solved = sum(row["scored_solved"] is True for row in rows)
    return {
        "rows": len(rows),
        "solved": solved,
        "solve_rate": solved / len(rows),
        "evidence_valid_rows": sum(row["evidence_valid"] is True for row in rows),
        "status_counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "resources": resources,
    }


def _sum_metric(rows: Sequence[Mapping[str, Any]], metric: str) -> dict[str, int | float]:
    known = [row[metric] for row in rows if row[metric] is not None]
    total = sum(known)
    if metric == "duration_seconds":
        total = round(float(total), 6)
    return {"known_total": total, "unknown_rows": len(rows) - len(known)}


def _required_metadata_section(
    metadata: Mapping[str, Any],
    name: str,
    aliases: Sequence[str],
) -> dict[str, Any]:
    for alias in aliases:
        value = metadata.get(alias)
        if isinstance(value, Mapping) and value:
            return _json_copy(value)
    raise HeadToHeadReportError(f"campaign metadata must include non-empty {name} pins")


def _validate_declared_case_ids(
    metadata: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> None:
    declared = metadata.get("case_ids")
    if declared is None:
        return
    if not isinstance(declared, Sequence) or isinstance(declared, str | bytes):
        raise HeadToHeadReportError("metadata case_ids must be a sequence")
    declared_ids = [_nonempty_string(value, "metadata case_id") for value in declared]
    observed_ids = sorted({row["case_id"] for row in rows}, key=_natural_key)
    if len(declared_ids) != EXPECTED_CASES or len(set(declared_ids)) != EXPECTED_CASES:
        raise HeadToHeadReportError("metadata case_ids must name 20 unique cases")
    if sorted(declared_ids, key=_natural_key) != observed_ids:
        raise HeadToHeadReportError("metadata case_ids do not match the executed rows")


def _evidence_validity(row: Mapping[str, Any], *, index: int) -> bool:
    for name in ("evidence_valid", "valid", "valid_evidence", "valid_for_comparison"):
        value = row.get(name)
        if isinstance(value, bool):
            return value
    value = row.get("evidence_validity")
    if isinstance(value, bool):
        return value
    if isinstance(value, Mapping) and isinstance(value.get("valid"), bool):
        return value["valid"]
    raise HeadToHeadReportError(f"row {index} evidence validity must be boolean")


def _first_present(
    row: Mapping[str, Any],
    usage: Mapping[str, Any],
    *,
    names: Sequence[str],
) -> object:
    for source in (row, usage):
        for name in names:
            if name in source:
                return source[name]
    return None


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HeadToHeadReportError(f"{label} must be a mapping")
    return value


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise HeadToHeadReportError(f"{label} must be a non-empty string")
    return value.strip()


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise HeadToHeadReportError(f"{label} must be a string or null")
    return value


def _optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise HeadToHeadReportError(f"{label} must be a lowercase SHA-256 or null")
    return value


def _sha256_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise HeadToHeadReportError(f"{label} must be a sequence")
    result = [_optional_sha256(item, label) for item in value]
    if any(item is None for item in result) or len(set(result)) != len(result):
        raise HeadToHeadReportError(f"{label} must contain unique lowercase SHA-256 values")
    return [item for item in result if item is not None]


def _optional_nonnegative_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise HeadToHeadReportError(f"{label} must be a non-negative integer or null")
    converted = int(value)
    if converted != value or converted < 0:
        raise HeadToHeadReportError(f"{label} must be a non-negative integer or null")
    return converted


def _optional_number(value: object, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise HeadToHeadReportError(f"{label} must be a non-negative finite number or null")
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        raise HeadToHeadReportError(f"{label} must be a non-negative finite number or null")
    return converted


def _optional_decimal(value: object, label: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise HeadToHeadReportError(f"{label} must be a non-negative finite number or null")
    try:
        converted = Decimal(str(value))
    except InvalidOperation as exc:
        raise HeadToHeadReportError(f"{label} is invalid") from exc
    if not converted.is_finite() or converted < 0:
        raise HeadToHeadReportError(f"{label} must be a non-negative finite number or null")
    return converted


def _decimal_json(value: Decimal) -> int | float:
    if value == value.to_integral_value():
        return int(value)
    return float(value)


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError, OverflowError) as exc:
        raise HeadToHeadReportError("campaign contains non-JSON or non-finite values") from exc


def _natural_key(value: str) -> tuple[tuple[int, int | str], ...]:
    parts = re.split(r"(\d+)", value.casefold())
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts if part)


def _md(value: object) -> str:
    return (
        str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    )


def _scalar_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, allow_nan=False)


def _json_code_block(value: object) -> str:
    encoded = json.dumps(value, indent=2, sort_keys=True, allow_nan=False)
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", encoded)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}json\n{encoded}\n{fence}"


def _percent(value: object) -> str:
    return f"{float(value) * 100:.1f}%"


def _signed_points(value: object) -> str:
    return f"{float(value):+.1f} pp"


def _probability(value: object) -> str:
    return f"{float(value):.6g}"


def _metric(value: object) -> str:
    metric = _mapping(value, "resource metric")
    suffix = f" (+{metric['unknown_rows']} unknown)" if metric["unknown_rows"] else ""
    return f"{metric['known_total']:,}{suffix}"


def _cost(value: object) -> str:
    cost = _mapping(value, "cost metric")
    subtotal = f"${float(cost['known_subtotal']):,.4f}"
    if cost["unknown_rows"]:
        return f"{subtotal} known (+{cost['unknown_rows']} unknown; total unknown)"
    return f"{subtotal} total"


def _duration(value: object) -> str:
    duration = _mapping(value, "duration metric")
    suffix = f" (+{duration['unknown_rows']} unknown)" if duration["unknown_rows"] else ""
    return f"{float(duration['known_total']):,.3f}s{suffix}"


def _row_cell(row: Mapping[str, Any]) -> str:
    outcome = "SOLVED" if row["scored_solved"] else "UNSOLVED"
    if not row["evidence_valid"]:
        outcome += " (invalid evidence)"
    duration = (
        "unknown time" if row["duration_seconds"] is None else f"{row['duration_seconds']:.3f}s"
    )
    requests = "requests unknown" if row["request_count"] is None else f"{row['request_count']} req"
    tokens = "tokens unknown" if row["total_tokens"] is None else f"{row['total_tokens']} tok"
    cost = "cost unknown" if row["cost_usd"] is None else f"${row['cost_usd']:.4f}"
    return _md(f"{outcome}; status={row['status']}; {duration}; {requests}; {tokens}; {cost}")


def _pair_outcome(codex: Mapping[str, Any], strix: Mapping[str, Any]) -> str:
    if codex["scored_solved"] and strix["scored_solved"]:
        return "both"
    if codex["scored_solved"]:
        return "Codex + skill only"
    if strix["scored_solved"]:
        return "Strix only"
    return "neither"


def _yes_no(value: object) -> str:
    return "yes" if value is True else "no"


def _valid_invalid(value: object) -> str:
    return "valid" if value is True else "invalid"


def _stage_text(destination: Path, content: str) -> Path:
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        text=True,
    )
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary
