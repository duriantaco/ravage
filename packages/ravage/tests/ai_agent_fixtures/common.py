from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

BRIEF_YAML = """
engagement_id: "77777777-7777-4777-8777-777777777777"
scope:
  in_scope:
    - "http://127.0.0.1:8765"
  out_of_scope: []
roe:
  max_rps: 5
  no_destructive_actions: true
  data_handling: "placeholders_only"
objectives:
  - "sql_injection"
budget:
  max_cost_usd: 1.0
  max_runtime_min: 10
""".lstrip()
EXPECTED_STUB_REQUESTS = 4
MIN_JWT_PARTS = 2
JWT_PARTS = 3
HTTP_OK = 200
SSH_TEST_HOST_PORT = 49_222
SSH_TEST_DECODED_PASSWORD = "sandbag!"  # noqa: S105 - synthetic credential fixture.


def _test_jwt(payload: Mapping[str, object]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return f"{_test_b64url(header)}.{_test_b64url(payload)}."


def _test_b64url(payload: Mapping[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_test_jwt(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) < MIN_JWT_PARTS:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    return payload if isinstance(payload, dict) else {}


def _verify_test_hs256_jwt(token: str, secret: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) != JWT_PARTS:
        return {}
    signing_input = f"{parts[0]}.{parts[1]}"
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return _decode_test_jwt(token) if hmac.compare_digest(expected, parts[2]) else {}
