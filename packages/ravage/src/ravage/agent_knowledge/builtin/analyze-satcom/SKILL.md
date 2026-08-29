---
name: analyze-satcom
description: Inspect authorized offline satellite and SATCOM artifacts without transmitting. Use for TLE sets, CCSDS Space Packet streams, telemetry or telecommand captures, sequence-counter anomalies, spacecraft identifiers, packet-length validation, or passive mission-data triage.
---

# Analyze SATCOM Artifacts

Keep this workflow passive and offline. Never transmit RF, send a telecommand, contact a ground
station, or infer authorization from this card. Active work belongs only in an explicitly
authorized simulator with a separately enforced execution policy.

## Workflow

1. Identify the artifact type and record its digest before interpretation.
2. Use `ravage satcom inspect` for supported TLE or CCSDS Space Packet inputs.
3. Preserve spacecraft catalog identities, APIDs, packet direction, sequence flags and counts,
   declared lengths, offsets, digests, and evidence references in the SATCOM surface artifact.
4. Correlate repeated identities and counters only after preserving per-record evidence refs.
5. Retain the complete inventory and anomalies even when there is no flag or confirmed finding.

## Evidence Gate

Malformed lengths, invalid TLE checksums, unsupported versions, and truncated records are strict
input errors, not partial findings. Treat repeated packets and sequence-counter reuse only as
observations or candidates. A packet header cannot prove missing authentication, replay acceptance,
command execution, or impact. Promote nothing without target-origin evidence from an authorized
simulator or another trusted validator.

## Stop Conditions

Stop on oversized, truncated, ambiguous, special-device, or unsupported artifacts. Do not guess
payload semantics, fabricate ground stations or radio links, or include packet payload bytes in
the prompt-facing surface graph.
