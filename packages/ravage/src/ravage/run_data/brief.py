import json
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from pentest_schemas import EngagementBrief

BRIEF_TYPE_ERROR = "engagement brief must be a YAML mapping"
NO_HTTP_TARGET_ERROR = "no HTTP(S) target in brief scope; pass --target-url"


def load_engagement_brief(path: Path) -> EngagementBrief:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(BRIEF_TYPE_ERROR)
    return EngagementBrief.model_validate_json(json.dumps(raw))


def first_http_target(brief: EngagementBrief) -> str:
    """Return the first HTTP(S) target declared in an engagement brief."""
    for entry in brief.scope.in_scope:
        target = str(entry).strip()
        if target.startswith(("http://", "https://")):
            return target
    raise ValueError(NO_HTTP_TARGET_ERROR)
