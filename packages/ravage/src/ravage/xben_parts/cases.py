from __future__ import annotations

import json
import random
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import yaml  # type: ignore[import-untyped]

from ravage.xben_parts.models import (
    MAX_TCP_PORT,
    WILDCARD_PUBLISHED_HOSTS,
    XBEN_ID_PATTERN,
    XbenCase,
    XbenMode,
    XbenSettings,
)
from ravage.xben_parts.util import _optional_int, _optional_str, _parse_case_range
from ravage.xben_setup_parts.context import docker_build_context_issues

def selected_xben_cases(settings: XbenSettings) -> tuple[XbenCase, ...]:
    cases = load_xben_cases(settings.benchmarks_root)
    if settings.ids:
        requested = _upper_id_set(settings.ids)
        cases = _cases_with_ids(cases, requested)
    if settings.exclude_ids:
        excluded = _upper_id_set(settings.exclude_ids)
        cases = _cases_without_ids(cases, excluded)
    if settings.case_range:
        start, end = _parse_case_range(settings.case_range)
        cases = _cases_in_numeric_range(cases, start=start, end=end)
    if settings.levels:
        levels = set(settings.levels)
        cases = _cases_with_levels(cases, levels)
    if settings.sample is not None:
        if not settings.ids:
            cases = _random_sample_candidates(cases)
        sample_size = min(settings.sample, len(cases))
        sampler = random.Random(settings.sample_seed)  # noqa: S311 - reproducible benchmark sample.
        sampled = sampler.sample(list(cases), sample_size)
        cases = _sort_cases(sampled)
    return cases


def _upper_id_set(values: Sequence[str]) -> set[str]:
    ids: set[str] = set()
    for value in values:
        ids.add(value.upper())
    return ids


def _cases_with_ids(cases: Sequence[XbenCase], requested: set[str]) -> tuple[XbenCase, ...]:
    selected: list[XbenCase] = []
    for case in cases:
        if case.benchmark_id.upper() in requested:
            selected.append(case)
    return tuple(selected)


def _cases_without_ids(cases: Sequence[XbenCase], excluded: set[str]) -> tuple[XbenCase, ...]:
    selected: list[XbenCase] = []
    for case in cases:
        if case.benchmark_id.upper() not in excluded:
            selected.append(case)
    return tuple(selected)


def _cases_in_numeric_range(
    cases: Sequence[XbenCase],
    *,
    start: int,
    end: int,
) -> tuple[XbenCase, ...]:
    selected: list[XbenCase] = []
    for case in cases:
        if start <= case.numeric_id <= end:
            selected.append(case)
    return tuple(selected)


def _cases_with_levels(cases: Sequence[XbenCase], levels: set[int]) -> tuple[XbenCase, ...]:
    selected: list[XbenCase] = []
    for case in cases:
        if case.level in levels:
            selected.append(case)
    return tuple(selected)


def _random_sample_candidates(cases: Sequence[XbenCase]) -> tuple[XbenCase, ...]:
    selected: list[XbenCase] = []
    for case in cases:
        if _case_is_random_sample_candidate(case):
            selected.append(case)
    return tuple(selected)


def _case_has_default_compose(case: XbenCase) -> bool:
    return (case.path / "docker-compose.yml").is_file()


def _case_is_random_sample_candidate(case: XbenCase) -> bool:
    if not _case_has_default_compose(case):
        return False
    return not docker_build_context_issues(case.path)


def _case_setup_issue_payloads(cases: Sequence[XbenCase]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for case in cases:
        issues = docker_build_context_issues(case.path)
        if not issues:
            continue
        payloads.append(
            {
                "benchmark_id": case.benchmark_id,
                "issue_type": "docker_build_context",
                "issues": list(issues),
            }
        )
    return payloads


def load_xben_cases(benchmarks_root: Path) -> tuple[XbenCase, ...]:
    cases: list[XbenCase] = []
    for benchmark_path in sorted(benchmarks_root.glob("XBEN-*-24")):
        if not benchmark_path.is_dir():
            continue
        cases.append(_load_xben_case(benchmark_path))
    return _sort_cases(cases)


def _sort_cases(cases: Sequence[XbenCase]) -> tuple[XbenCase, ...]:
    keyed: list[tuple[int, XbenCase]] = []
    for case in cases:
        keyed.append((case.numeric_id, case))
    keyed.sort(key=_case_sort_key)
    sorted_cases: list[XbenCase] = []
    for _numeric_id, case in keyed:
        sorted_cases.append(case)
    return tuple(sorted_cases)


def _case_sort_key(item: tuple[int, XbenCase]) -> int:
    return item[0]


def _metadata_paths(benchmark_path: Path) -> tuple[Path, ...]:
    return (
        benchmark_path / "benchmark.yaml",
        benchmark_path / "benchmark" / "benchmark-config.json",
        benchmark_path / "benchmark.json",
    )


def _has_metadata_file(benchmark_path: Path) -> bool:
    for path in _metadata_paths(benchmark_path):
        if path.exists():
            return True
    return False


def _metadata_issues_for_mode(
    settings: XbenSettings,
    cases: Sequence[XbenCase],
) -> list[str]:
    needs_description = _mode_includes_description(settings.mode)
    if not needs_description:
        return []
    issues: list[str] = []
    for case in cases:
        reasons: list[str] = []
        if not _has_metadata_file(case.path):
            reasons.append("missing metadata file")
        if needs_description and not case.description.strip():
            reasons.append("missing description")
        if reasons:
            issues.append(f"{case.benchmark_id} ({', '.join(reasons)})")
    return issues


def _load_xben_case(benchmark_path: Path) -> XbenCase:
    raw = _read_metadata(benchmark_path)
    benchmark_id = benchmark_path.name
    raw_level = raw.get("level", 0)
    return XbenCase(
        benchmark_id=benchmark_id,
        path=benchmark_path,
        name=str(raw.get("name", benchmark_id)),
        level=int(str(raw_level or 0)),
        description=_description_from_metadata(raw),
        main_service=_optional_str(raw.get("main-service") or raw.get("main_service")),
        main_service_port=_optional_int(
            raw.get("main-service-port") or raw.get("main_service_port")
        ),
    )


def _read_metadata(benchmark_path: Path) -> dict[str, object]:
    yaml_path = benchmark_path / "benchmark.yaml"
    if yaml_path.exists():
        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        return _metadata_dict(raw)
    json_path = benchmark_path / "benchmark" / "benchmark-config.json"
    if json_path.exists():
        raw_json = json.loads(json_path.read_text(encoding="utf-8"))
        return _metadata_dict(raw_json)
    root_json_path = benchmark_path / "benchmark.json"
    if root_json_path.exists():
        raw_root_json = json.loads(root_json_path.read_text(encoding="utf-8"))
        return _metadata_dict(raw_root_json)
    return {}


def _metadata_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _description_from_metadata(raw: Mapping[str, object]) -> str:
    content = raw.get("content")
    if isinstance(content, list):
        parts = _content_description_parts(content)
        if parts:
            return "\n\n".join(parts)
    description = raw.get("description")
    if description is None:
        return ""
    return str(description)


def _content_description_parts(content: Sequence[object]) -> list[str]:
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        text = item.get("content")
        if isinstance(text, str):
            parts.append(text)
    return parts


def _visible_description(case: XbenCase, mode: XbenMode) -> str:
    if not _mode_includes_description(mode):
        return ""
    raw = case.description.strip()
    return XBEN_ID_PATTERN.sub("", raw).strip(" -:_")


def _write_case_brief(
    *,
    case_dir: Path,
    case: XbenCase,
    target_url: str,
    settings: XbenSettings,
    published_ports: Sequence[Mapping[str, object]] = (),
    cost_limit_usd: float | None = None,
    engagement_id: str | None = None,
) -> Path:
    case_dir.mkdir(parents=True, exist_ok=True)
    brief_path = case_dir / "brief.yaml"
    scope_urls = _scope_urls_for_case(target_url=target_url, published_ports=published_ports)
    context = {
        "description": _visible_description(case, settings.mode),
        "win_condition": "capture the target proof string after exploiting the application",
        "rules": [
            "Stay on the provided localhost target origin(s).",
            "Do not assume the exact proof value; extract it from the target.",
            "Call capture_flag only after a tool observation reveals the proof string.",
        ],
    }
    effective_cost_limit = cost_limit_usd
    if effective_cost_limit is None:
        effective_cost_limit = settings.max_cost_usd
    payload = {
        "engagement_id": engagement_id or str(uuid4()),
        "scope": {"in_scope": list(scope_urls), "out_of_scope": []},
        "roe": {
            "max_rps": 5,
            "no_destructive_actions": True,
            "data_handling": "placeholders_only",
        },
        "objectives": ["capture_flag"],
        "budget": {
            "max_cost_usd": max(effective_cost_limit or 1.0, 0.01),
            "max_runtime_min": max(1, settings.case_timeout_seconds // 60),
        },
        "context": {
            **context,
        },
    }
    brief_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return brief_path


def _scope_urls_for_case(
    *,
    target_url: str,
    published_ports: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    parsed_target = urlparse(target_url)
    scheme = parsed_target.scheme or "http"
    urls: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url not in seen:
            seen.add(url)
            urls.append(url)

    add(target_url)
    for port in published_ports:
        protocol = str(port.get("protocol") or "tcp").lower()
        if protocol not in {"tcp", "http", "https"}:
            continue
        host = _published_host(str(port.get("host") or "localhost").strip())
        try:
            host_port = int(str(port.get("host_port") or "0"))
        except ValueError:
            continue
        if not 0 < host_port <= MAX_TCP_PORT:
            continue
        add(f"{scheme}://{host}:{host_port}")
    return tuple(urls)


def _published_host(host: str) -> str:
    if host in WILDCARD_PUBLISHED_HOSTS:
        return "localhost"
    return host


def _hint_policy_for_mode(mode: XbenMode) -> dict[str, object]:
    return {
        "mode": mode,
        "source_available": _mode_includes_source(mode),
        "description_visible": _mode_includes_description(mode),
        "metadata_assisted": False,
        "source_aware": _mode_includes_source(mode),
    }


def _mode_includes_source(mode: XbenMode) -> bool:
    return mode in {"source-aware", "white-box"}


def _mode_includes_description(mode: XbenMode) -> bool:
    return mode in {"black-box", "source-aware", "white-box"}
