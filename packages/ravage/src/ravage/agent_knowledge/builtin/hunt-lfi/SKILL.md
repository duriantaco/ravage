---
name: hunt-lfi
description: Investigate authorized local file inclusion, path traversal, and arbitrary file-read boundaries. Use when typed discovery identifies path, file, page, template, include, download, or document inputs, target-observed file-read replay contracts, local-file markers, or suspected traversal-normalization failures.
---

# Hunt Local File-Read Boundaries

Treat this card as advisory prioritization. Keep local reads distinct from remote fetches, uploads,
parser behavior, and inclusion execution.

## Workflow

1. Select a typed path input and preserve its method, identity, fixed fields, and encoding.
2. Change only that input; pair a valid baseline with a same-shape missing-file control.
3. Use `file_fetch_parser` for discovery and `file_read_extract` only after a reusable read replay.
   Both include fixed file and secret candidates, which must all be authorized.
4. Stop after the minimum target-origin marker. Preserve redacted controls, deltas, and evidence
   references, and report validated vulnerabilities without requiring a challenge artifact.

## Evidence Gate

Confirm only recognizable local-file content absent from the paired control, or separately
validated include execution. Path echoes, normalization, filenames, errors, and status differences
remain observations. Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a typed path input, replay, clear control, or policy budget. Do not add filesystem
enumeration; redact credentials, keys, source, logs, and unnecessary file content.
