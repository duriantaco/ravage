# ruff: noqa: S105
from __future__ import annotations

import base64
import json
import pickle

import pytest
from ravage.auth import (
    AuthArtifactRedactor,
    EnvironmentSecretResolver,
    IdentityProfile,
    MappingSecretResolver,
    SecretRef,
    SecretResolutionError,
    SecretValue,
)


def test_secret_value_requires_explicit_reveal_and_redacts_display() -> None:
    plaintext = "correct-horse-battery-staple"
    secret = SecretValue(plaintext)

    assert secret.reveal() == plaintext
    assert plaintext not in repr(secret)
    assert plaintext not in str(secret)
    assert plaintext not in f"{secret}"
    assert repr(secret) == "SecretValue([REDACTED])"


def test_secret_value_refuses_common_serializers() -> None:
    secret = SecretValue("do-not-serialize-me")

    with pytest.raises(TypeError):
        json.dumps(secret)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(secret)


def test_environment_resolver_does_not_leak_values() -> None:
    plaintext = "environment-only-password"
    resolver = EnvironmentSecretResolver({"RAVAGE_TEST_PASSWORD": plaintext})

    resolved = resolver.resolve(SecretRef.env("RAVAGE_TEST_PASSWORD"))

    assert resolved.reveal() == plaintext
    assert plaintext not in repr(resolver)
    with pytest.raises(TypeError) as json_error:
        json.dumps(resolver)
    assert plaintext not in str(json_error.value)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(resolver)


def test_missing_secret_error_identifies_reference_without_neighbor_values() -> None:
    neighboring_secret = "must-not-appear-in-errors"
    resolver = EnvironmentSecretResolver({"NEIGHBOR": neighboring_secret})

    with pytest.raises(SecretResolutionError) as captured:
        resolver.resolve(SecretRef.env("MISSING_PASSWORD"))

    message = str(captured.value)
    assert "environment:MISSING_PASSWORD" in message
    assert neighboring_secret not in message


def test_mapping_resolver_is_provider_scoped_and_redacted() -> None:
    plaintext = "injected-token-value"
    resolver = MappingSecretResolver({"access_token": plaintext}, provider="fixture")

    assert resolver.resolve(SecretRef("fixture", "access_token")).reveal() == plaintext
    assert plaintext not in repr(resolver)
    with pytest.raises(SecretResolutionError, match="unsupported secret provider"):
        resolver.resolve(SecretRef.env("access_token"))


def test_identity_profile_rejects_inline_secret_values() -> None:
    with pytest.raises(TypeError, match="SecretRef"):
        IdentityProfile(
            "customer",
            secrets={"password": "plaintext-is-not-allowed"},  # type: ignore[dict-item]
        )


def test_identity_profile_public_form_contains_references_not_values() -> None:
    plaintext = "not-part-of-the-profile"
    profile = IdentityProfile(
        "customer",
        secrets={"password": SecretRef.env("CUSTOMER_PASSWORD")},
    )

    encoded = json.dumps(profile.to_public_dict())

    assert "CUSTOMER_PASSWORD" in encoded
    assert '"provider": "environment"' in encoded
    assert plaintext not in encoded


def test_legacy_env_reference_serializes_with_canonical_provider_name() -> None:
    reference = SecretRef("env", "LEGACY_PASSWORD")

    assert reference.to_public_dict() == {
        "provider": "environment",
        "key": "LEGACY_PASSWORD",
    }
    assert (
        EnvironmentSecretResolver({"LEGACY_PASSWORD": "value"}).resolve(reference).reveal()
        == "value"
    )


def test_auth_artifact_redactor_scrubs_nested_headers_fields_and_known_values() -> None:
    plaintext = "configured-secret-value"
    redactor = AuthArtifactRedactor([SecretValue(plaintext)])

    safe = redactor.redact(
        {
            "headers": {
                "Content-Type": "text/plain",
                "Set-Cookie": "session=runtime-cookie; HttpOnly",
            },
            "form": {"username": "alice", "password": plaintext},
            "body_snippet": f"Authorization: Bearer {plaintext}",
            "cookies": ["session=runtime-cookie"],
        }
    )
    encoded = json.dumps(safe)

    assert plaintext not in encoded
    assert "runtime-cookie" not in encoded
    assert "alice" in encoded
    assert "text/plain" in encoded
    assert "[REDACTED]" in encoded
    assert plaintext not in repr(redactor)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(redactor)


def test_auth_artifact_redactor_keeps_contextual_identity_labels_usable() -> None:
    redactor = AuthArtifactRedactor()
    redactor.register_secret_values((SecretValue("a"), SecretValue("alice")), context_free=False)

    prose = "Map an alice route at /v1 and analyze a response"

    assert redactor.redact_text(prose) == prose
    assert redactor.redact_text("a") == "[REDACTED]"
    assert redactor.redact({"value": "alice"}) == {"value": "[REDACTED]"}
    assert redactor.redact_text("password=a") == "password=[REDACTED]"
    assert redactor.redact_text("Authorization: Bearer alice") == ("Authorization: [REDACTED]")
    assert redactor.redact_text("GET /users/alice and /a returned HTTP/1.1") == (
        "GET /users/[REDACTED] and /[REDACTED] returned HTTP/1.1"
    )


def test_auth_artifact_redactor_still_removes_short_credentials_from_prose() -> None:
    redactor = AuthArtifactRedactor((SecretValue("s3cr3t"),))

    assert redactor.redact_text("target reflected s3cr3t in a body") == (
        "target reflected [REDACTED] in a body"
    )


def test_artifact_redaction_is_strict_while_prompt_redaction_preserves_action_words() -> None:
    redactor = AuthArtifactRedactor()
    redactor.register_named_secret_values({"password": SecretValue("secret")})

    assert redactor.redact_text("response echoed secret from the target") == (
        "response echoed [REDACTED] from the target"
    )
    guidance = "Use the secret field in validate_poc action schemas."
    assert redactor.redact_prompt_text(guidance) == guidance


@pytest.mark.parametrize("credential", ["a", "1", "secret"])
def test_auth_artifact_redactor_does_not_globally_corrupt_ambiguous_credentials(
    credential: str,
) -> None:
    redactor = AuthArtifactRedactor()
    redactor.register_named_secret_values({"password": SecretValue(credential)})

    prose = "validate_poc action at /v1/account returned 401 and FLAG{real_proof}"
    assert redactor.redact_text(prose) == prose
    assert redactor.redact_text(credential) == "[REDACTED]"
    assert redactor.redact_text(f"password={credential}") == "password=[REDACTED]"


def test_auth_artifact_redactor_taints_contextual_and_decoded_proof_derivatives() -> None:
    encoded_proof = base64.b64encode(b"FLAG{credential-derived-proof}").decode("ascii")
    redactor = AuthArtifactRedactor()
    redactor.register_secret_values(
        (SecretValue("a"), SecretValue("alice"), SecretValue(encoded_proof)),
        context_free=False,
    )

    assert redactor.contains_secret("FLAG{alice}")
    assert redactor.contains_secret("FLAG{credential-derived-proof}")
    assert not redactor.contains_secret("FLAG{ravage_real_8f31c9}")
    encoded_tainted_proof = base64.b64encode(b"FLAG{alice}").decode("ascii")
    safe = redactor.redact_text(
        f'alice inspected {{"action":"capture_flag","flag":"FLAG{{alice}}"}} '
        f"and encoded={encoded_tainted_proof} but kept FLAG{{ravage_real_8f31c9}}"
    )
    assert "alice inspected" in safe
    assert "FLAG{alice}" not in safe
    assert encoded_tainted_proof not in safe
    assert "FLAG{ravage_real_8f31c9}" in safe


def test_auth_artifact_redactor_redacts_mapping_keys_without_value_loss() -> None:
    redactor = AuthArtifactRedactor((SecretValue("alpha-value"), SecretValue("beta-value")))

    safe = redactor.redact({"alpha-value": 1, "beta-value": "1"})
    normalized_collision = redactor.redact({1: "number", "1": "string"})

    assert safe == {"[REDACTED]": 1, "[REDACTED]#2": "1"}
    assert normalized_collision == {"1": "number", "1#2": "string"}
