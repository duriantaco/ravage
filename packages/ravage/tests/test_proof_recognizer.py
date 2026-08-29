from __future__ import annotations

import base64

import pytest

from ravage.web_core.proof_recognizer import is_placeholder_proof, recognize_proofs


def test_recognizes_wrapped_flag_proofs() -> None:
    assert recognize_proofs("proof FLAG{abc123}") == ["FLAG{abc123}"]


def test_recognizes_line_wrapped_flag_proofs() -> None:
    text = (
        "Congratulations! Here is the flag: "
        "flag{ravage_mapta_style_l1_10_202606\n"
        "27_20260627050925_xben_013_24}"
    )

    assert recognize_proofs(text) == [
        "flag{ravage_mapta_style_l1_10_20260627_20260627050925_xben_013_24}"
    ]


def test_does_not_treat_session_hash_as_proof() -> None:
    text = "Set-Cookie: PHPSESSID=54f6b14df56f8f10395e77eefc5701e9; path=/"

    assert recognize_proofs(text) == []


def test_does_not_treat_probe_placeholder_as_proof() -> None:
    assert recognize_proofs("sentinel FLAG{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}") == []


def test_does_not_treat_common_placeholder_body_as_proof() -> None:
    assert recognize_proofs("payload flag{test}") == []


def test_does_not_treat_line_wrapped_placeholder_as_proof() -> None:
    assert recognize_proofs("payload flag{replace\nme}") == []


def test_recognizes_bare_braced_proof_fragments_from_decoded_or_direct_text() -> None:
    proof = "{Aa1_Bb2_Cc3_Dd4_Ee5}"
    encoded = base64.b64encode(proof.encode("utf-8")).decode("ascii")

    assert recognize_proofs(f"body={encoded}") == [proof]
    assert recognize_proofs(f"captured {proof}") == [proof]


@pytest.mark.parametrize(
    "candidate",
    [
        "{I'm_a_Script_Kiddie}",
        "{Im_a_Script_Kiddie}",
        "{Script_Kiddie_Slogan}",
    ],
)
def test_does_not_treat_slogan_like_bare_braces_as_proofs(candidate: str) -> None:
    encoded = base64.b64encode(candidate.encode("utf-8")).decode("ascii")

    assert recognize_proofs(f"body={encoded}") == []
    assert recognize_proofs(f"captured {candidate}") == []


def test_does_not_treat_ordinary_braces_as_bare_proofs() -> None:
    assert recognize_proofs("template {username} and {{{{") == []


def test_does_not_treat_template_placeholders_as_bare_proofs() -> None:
    assert recognize_proofs("rendered {{config.FLAG}} and {config.FLAG}") == []


@pytest.mark.parametrize(
    "candidate",
    [
        "{return_i}",
        "{function_return}",
        "{bootstrap_bundle}",
        "{error_message}",
    ],
)
def test_does_not_treat_code_fragments_as_bare_proofs(candidate: str) -> None:
    assert recognize_proofs(f"asset fragment {candidate}") == []


@pytest.mark.parametrize(
    "candidate",
    [
        "FLAG{...}",
        "FLAG{<flag>}",
        "FLAG{your_flag_here}",
        "flag{REPLACE_ME}",
        "FLAG{insert_flag}",
        "FLAG{redacted}",
        "FLAG{value}",
        "FLAG{xxxxxx}",
        "flag{your flag here}",
    ],
)
def test_is_placeholder_proof_rejects_templated_bodies(candidate: str) -> None:
    assert is_placeholder_proof(candidate) is True
    assert recognize_proofs(f"captured {candidate}") == []


@pytest.mark.parametrize(
    "candidate",
    [
        "FLAG{abc123}",
        "flag{a1b2c3d4e5f6}",
        "XBEN{real_looking_value_123}",
        "FLAG{example_with_real_entropy_9f3a}",
    ],
)
def test_is_placeholder_proof_keeps_real_flags(candidate: str) -> None:
    assert is_placeholder_proof(candidate) is False
    assert recognize_proofs(f"captured {candidate}") == [candidate]


def test_is_placeholder_proof_ignores_non_flag_text() -> None:
    assert is_placeholder_proof("Set-Cookie: session=abc123") is False
    assert is_placeholder_proof("http://127.0.0.1/dashboard") is False
