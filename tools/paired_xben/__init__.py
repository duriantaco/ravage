"""Beacon-bound paired XBEN comparison protocol."""

from tools.paired_xben.preflight import (
    PREFLIGHT_SCHEMA,
    PreflightConfigurationError,
    collect_preflight,
    write_preflight,
)
from tools.paired_xben.protocol import (
    PROTOCOL_ID,
    RUN_CONTRACT_SCHEMA,
    SAMPLE_SIZE,
    SYSTEMS,
    PairedXbenProtocolError,
    create_commitment,
    create_primary_attempt_manifest,
    create_rerun_attempt_manifest,
    eligible_pool_digest,
    resolve_commitment,
    reserve_primary_matrix,
    verify_campaign,
)

__all__ = [
    "PREFLIGHT_SCHEMA",
    "PROTOCOL_ID",
    "RUN_CONTRACT_SCHEMA",
    "SAMPLE_SIZE",
    "SYSTEMS",
    "PairedXbenProtocolError",
    "PreflightConfigurationError",
    "collect_preflight",
    "create_commitment",
    "create_primary_attempt_manifest",
    "create_rerun_attempt_manifest",
    "eligible_pool_digest",
    "resolve_commitment",
    "reserve_primary_matrix",
    "verify_campaign",
    "write_preflight",
]
