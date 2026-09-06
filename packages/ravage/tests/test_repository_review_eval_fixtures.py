from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from ravage.repository_context import capture_repository
from ravage.repository_review_eval import (
    MANIFEST_SCHEMA_VERSION,
    RepositoryReviewEvalManifest,
)
from ravage.source_analysis import analyze_source_root

_REPOSITORY_ROOT = Path(__file__).parents[3]
_TESTS_ROOT = Path(__file__).parent
_FIXTURE_COLLECTION = _TESTS_ROOT / "fixtures" / "repository_review_eval"
_MANIFEST_PATH = _TESTS_ROOT / "repository_review_eval_manifest.json"
_EXPECTED_CASE_COUNT = 10
_EXPECTED_SMALL_CASE_FILES = 3
_HARD_PAIR = ("juniper", "keystone")
_HARD_CASE_FILES = 39
_MIN_HARD_DECOYS = 30
_MAX_HARD_DECOYS = 60
_SEEDED_SOURCE_CANDIDATE_LIMIT = 8
_EXPECTED_CLASSES = {
    "command_injection",
    "idor",
    "path_traversal",
    "sql_injection",
}
_PAIRS = (
    ("aurora", "boreal"),
    ("cinder", "delta"),
    ("elm", "flint"),
    ("grove", "harbor"),
    _HARD_PAIR,
)
_STATUS_LABELS = ("control", "insecure", "safe", "vulnerable")
_ANCHORS = {
    "aurora": (
        "src/orders/get_order.ts",
        7,
        "sha256:c2fbe3c7224c4e6decde03438c957e9bfa2e1882514ff34ef523c396eb5b6d4d",
    ),
    "boreal": (
        "src/orders/get_order.ts",
        8,
        "sha256:31c59934611ea5b1dd05e23e9c1c1b6a42029c6f60152a8d31547449fc746c4f",
    ),
    "cinder": (
        "src/media/preview.py",
        20,
        "sha256:ad66f9cc6e29b1014f3fe90eba93a0f7cce0a3777424bc9a7d89ea6a5639b3d1",
    ),
    "delta": (
        "src/media/preview.py",
        20,
        "sha256:eeb903d43af30330b0e178ba86b95fe7ecd3d58dccd575d46844bcf5c4361a9d",
    ),
    "elm": (
        "src/catalog/search.ts",
        8,
        "sha256:698629710e84c61c846a32a29325caa60df23a3abaf13e18d360d59aa6b39549",
    ),
    "flint": (
        "src/catalog/search.ts",
        8,
        "sha256:252b3f4af25dde6dbff1109afd18f1972cc605bcfbef204f72793e9a6c2eddcb",
    ),
    "grove": (
        "src/exports/download.py",
        14,
        "sha256:20a7a347485c9b86376495e539c601c396d491b2d96d1898e8773763f8ed3b7b",
    ),
    "harbor": (
        "src/exports/download.py",
        13,
        "sha256:b8ed173e9c329a06800b1d9b9efc8b0e200f80aae767e9584bfbf07141372eca",
    ),
    "juniper": (
        "src/reports/paths.py",
        7,
        "sha256:8be483c0c569e500fddf73e09a73cfaa8cdd3f8b1c520883c4f6b9e28fdc5f8b",
    ),
    "keystone": (
        "src/reports/paths.py",
        9,
        "sha256:b8ed173e9c329a06800b1d9b9efc8b0e200f80aae767e9584bfbf07141372eca",
    ),
}


def test_repository_review_eval_manifest_binds_neutral_paired_fixtures() -> None:
    payload = cast("dict[str, Any]", json.loads(_MANIFEST_PATH.read_text(encoding="utf-8")))
    manifest = RepositoryReviewEvalManifest.from_mapping(payload)
    cases = cast("list[dict[str, Any]]", payload["cases"])

    assert payload["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest.to_json() == payload
    assert len(cases) == _EXPECTED_CASE_COUNT
    assert len({case["id"] for case in cases}) == _EXPECTED_CASE_COUNT
    assert set(_ANCHORS) == {case["id"] for case in cases}

    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        case_id = str(case["id"])
        [class_name] = cast("list[str]", case["evaluated_classes"])
        case_root = (_REPOSITORY_ROOT / str(case["source_root"])).resolve()

        assert case_root.is_relative_to(_FIXTURE_COLLECTION.resolve())
        assert case_root.name == case_id
        assert not any(label in case_id.casefold() for label in _STATUS_LABELS)
        assert not _MANIFEST_PATH.resolve().is_relative_to(case_root)
        assert case_root.is_dir()
        expected_file_count = (
            _HARD_CASE_FILES if case_id in _HARD_PAIR else _EXPECTED_SMALL_CASE_FILES
        )
        assert len([path for path in case_root.rglob("*") if path.is_file()]) == expected_file_count
        assert not any(path.is_symlink() for path in case_root.rglob("*"))
        assert case["snapshot_id"] == capture_repository(case_root).snapshot_id

        anchor_path, anchor_line, expected_digest = _ANCHORS[case_id]
        source_path = case_root / anchor_path
        lines = source_path.read_text(encoding="utf-8").splitlines()
        assert 1 <= anchor_line <= len(lines)
        anchor_digest = (
            "sha256:" + hashlib.sha256(lines[anchor_line - 1].encode("utf-8")).hexdigest()
        )
        assert anchor_digest == expected_digest

        expected = cast("list[dict[str, Any]]", case["expected"])
        if expected:
            assert len(expected) == 1
            assert expected[0]["vuln_class"] == class_name
            [location] = cast("list[dict[str, Any]]", expected[0]["locations"])
            assert location["path"] == anchor_path
            assert location["start_line"] == anchor_line
            assert location["end_line"] == anchor_line

        reviewed_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(case_root.rglob("*"))
            if path.is_file()
        ).casefold()
        assert "ground_truth" not in reviewed_text
        assert "expected_class_finding" not in reviewed_text
        assert "noqa" not in reviewed_text
        assert case_id.casefold() not in reviewed_text
        assert not any(label in reviewed_text for label in _STATUS_LABELS)
        pairs[class_name].append(case)

    assert set(pairs) == _EXPECTED_CLASSES
    case_by_id = {str(case["id"]): case for case in cases}
    assert {case_id for pair in _PAIRS for case_id in pair} == set(case_by_id)
    for first, second in _PAIRS:
        first_case = case_by_id[first]
        second_case = case_by_id[second]
        assert first_case["evaluated_classes"] == second_case["evaluated_classes"]
        assert sorted((bool(first_case["expected"]), bool(second_case["expected"]))) == [
            False,
            True,
        ]
        assert (_FIXTURE_COLLECTION / first / "README.md").read_bytes() == (
            _FIXTURE_COLLECTION / second / "README.md"
        ).read_bytes()


def test_idor_pair_shares_explicit_data_access_semantics() -> None:
    aurora_store = _FIXTURE_COLLECTION / "aurora" / "src" / "store.ts"
    boreal_store = _FIXTURE_COLLECTION / "boreal" / "src" / "store.ts"

    assert aurora_store.read_bytes() == boreal_store.read_bytes()
    store_text = aurora_store.read_text(encoding="utf-8")
    assert "order.id === orderId" in store_text
    assert "order.id === orderId && order.accountId === accountId" in store_text
    assert not (_FIXTURE_COLLECTION / "aurora" / "src" / "orders" / "labels.ts").exists()
    assert not (_FIXTURE_COLLECTION / "boreal" / "src" / "orders" / "labels.ts").exists()


def test_hard_pair_differs_only_at_cross_file_path_resolution() -> None:
    first_root = _FIXTURE_COLLECTION / _HARD_PAIR[0]
    second_root = _FIXTURE_COLLECTION / _HARD_PAIR[1]
    first_files = {
        path.relative_to(first_root).as_posix(): path
        for path in first_root.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second_root).as_posix(): path
        for path in second_root.rglob("*")
        if path.is_file()
    }

    assert set(first_files) == set(second_files)
    differing = {
        relative
        for relative in first_files
        if first_files[relative].read_bytes() != second_files[relative].read_bytes()
    }
    assert differing == {"src/reports/paths.py"}
    decoys = sorted(path for path in first_files if path.startswith("src/modules/"))
    assert _MIN_HARD_DECOYS <= len(decoys) <= _MAX_HARD_DECOYS
    assert all(
        first_files[relative].read_bytes() == second_files[relative].read_bytes()
        for relative in decoys
    )

    handler = first_files["src/reports/download.py"].read_text(encoding="utf-8")
    assert "resolve_report_path(requested_name)" in handler
    assert "send_file(candidate)" in handler
    first_resolver = first_files["src/reports/paths.py"].read_text(encoding="utf-8")
    second_resolver = second_files["src/reports/paths.py"].read_text(encoding="utf-8")
    assert "return REPORT_ROOT / requested_name" in first_resolver
    assert "candidate = (root / requested_name).resolve()" in second_resolver
    assert "if not candidate.is_relative_to(root)" in second_resolver


def test_python_route_pairs_reach_the_structured_source_analyzer() -> None:
    analyses = {
        case_id: analyze_source_root(_FIXTURE_COLLECTION / case_id)
        for case_id in ("cinder", "delta", "grove", "harbor", *_HARD_PAIR)
    }
    candidates = {
        case_id: {(candidate.family, candidate.route) for candidate in analysis.candidates}
        for case_id, analysis in analyses.items()
    }

    assert ("command_injection", "/media/preview") in candidates["cinder"]
    assert ("command_injection", "/media/preview") not in candidates["delta"]
    assert ("path_traversal", "/exports/download") in candidates["grove"]
    assert ("path_traversal", "/exports/download") in candidates["harbor"]
    assert ("path_traversal", "/reports/download") in candidates["juniper"]
    assert ("path_traversal", "/reports/download") in candidates["keystone"]

    hard_candidates = {
        case_id: tuple(
            (candidate.family, candidate.relative_file, candidate.line, candidate.route)
            for candidate in analyses[case_id].candidates
        )
        for case_id in _HARD_PAIR
    }
    assert hard_candidates["juniper"] == hard_candidates["keystone"]
    target_index = next(
        index
        for index, candidate in enumerate(analyses["juniper"].candidates)
        if candidate.route == "/reports/download"
    )
    assert len(analyses["juniper"].candidates) == _SEEDED_SOURCE_CANDIDATE_LIMIT + 1
    assert target_index == _SEEDED_SOURCE_CANDIDATE_LIMIT
