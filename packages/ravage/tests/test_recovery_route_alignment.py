from __future__ import annotations

from dataclasses import dataclass

from ravage.agent_core.recovery_route_alignment import consensus_low_value_family


@dataclass(frozen=True)
class _Attempt:
    family: str
    low_value: bool = True


def test_consensus_requires_two_latest_strict_majority_routes() -> None:
    assert (
        consensus_low_value_family(
            [
                _Attempt("cross_site_scripting"),
                _Attempt("cross_site_scripting"),
            ]
        )
        == "cross_site_scripting"
    )
    assert consensus_low_value_family([_Attempt("cross_site_scripting")]) == ""


def test_tied_or_stale_family_cannot_claim_consensus() -> None:
    assert (
        consensus_low_value_family(
            [
                _Attempt("cross_site_scripting"),
                _Attempt("cross_site_scripting"),
                _Attempt("command_injection"),
                _Attempt("command_injection"),
            ]
        )
        == ""
    )
    assert (
        consensus_low_value_family(
            [
                _Attempt("cross_site_scripting"),
                _Attempt("cross_site_scripting"),
                _Attempt("cross_site_scripting"),
                _Attempt("command_injection"),
            ]
        )
        == ""
    )


def test_unknown_and_material_attempts_do_not_create_route_consensus() -> None:
    assert (
        consensus_low_value_family(
            [
                _Attempt("unknown"),
                _Attempt("cross_site_scripting", low_value=False),
                _Attempt("cross_site_scripting"),
            ]
        )
        == ""
    )
