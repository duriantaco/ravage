from __future__ import annotations

import json
import re


_BENCHMARK_FLAG_RE = re.compile(r"flag\{[^{}\s]{1,240}\}", flags=re.IGNORECASE)


def proof_bundle_verifier_payload(bundle: object) -> dict[str, object]:
    raw = _bundle_dict(bundle)
    text = json.dumps(raw, sort_keys=True, default=str).lower()
    if "benchmark_flag" in text or _BENCHMARK_FLAG_RE.search(text):
        raise ValueError("proof bundle verifier payload must not contain benchmark flags")
    payload = dict(raw)
    payload.pop("verifier", None)
    return payload


def _bundle_dict(bundle: object) -> dict[str, object]:
    dump = getattr(bundle, "model_dump", None)
    if callable(dump):
        value = dump()
        if isinstance(value, dict):
            return dict(value)
    if isinstance(bundle, dict):
        return dict(bundle)
    return {"bundle": bundle}
