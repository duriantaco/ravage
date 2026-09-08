from __future__ import annotations

import socket
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from tools.source_navigation_eval.corpus import evaluate_case, evaluate_corpus, load_cases

if TYPE_CHECKING:
    from tools.source_navigation_eval.corpus import Case

CASES = load_cases()


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
def test_diagnostic_route_inventory(case: Case, *, reverse: bool) -> None:
    result = evaluate_case(case, reverse=reverse)
    assert result["passed"], result


def test_offline_corpus_opens_no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("offline corpus attempted to open a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    result = evaluate_corpus()
    assert result["passed"]
    assert result["http_requests"] == result["model_calls"] == result["cost_usd"] == 0
    assert result["categories"] == {"supported": 8, "negative": 3, "unsupported": 3}
    assert result["supported_route_recall"] == result["route_precision"] == 1.0


def test_missing_and_extra_routes_make_the_evaluation_fail() -> None:
    case = next(case for case in CASES if case.name == "flask-direct")
    missing = replace(
        case, files={"app.py": case.files["app.py"].replace("'/health'", "'/changed'")}
    )
    result = evaluate_case(missing)
    assert not result["passed"]
    assert result["false_negatives"] == result["false_positives"] == 1
    assert result["missed_routes"] == [("GET", "/health")]
    assert result["unexpected_routes"] == [("GET", "/changed")]


def test_omission_is_visible_and_not_scored_as_a_discovered_route() -> None:
    case = next(case for case in CASES if case.name == "omitted-runtime-file")
    result = evaluate_case(case)
    assert result["omissions"] == [{"path": "app.py", "reason": "file_too_large"}]
    assert result["true_positives"] == 0
    assert result["authorized_routes"] == []
