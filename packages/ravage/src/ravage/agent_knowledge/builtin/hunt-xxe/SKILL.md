---
name: hunt-xxe
description: Investigate authorized XML external entity and XML parser boundaries. Use when typed discovery identifies XML or SOAP request bodies, document imports, XML or SVG uploads, DOCTYPE handling, entity-resolution behavior, parser errors, or a suspected external-entity primitive.
---

# Hunt XML Entity Boundaries

Treat this card as advisory prioritization. XML syntax, parser errors, and DOCTYPE support are not
proof of entity resolution.

## Workflow

1. Preserve a well-formed, target-observed XML request as the baseline.
2. Pair a bounded entity candidate with a same-shape unresolved control. A native result without
   that replay remains an exploit primitive, not a verified vulnerability.
3. Use `xxe_boundary`; use `file_fetch_parser` only for a typed upload or import. Its fixed local-file
   candidates must all be authorized.
4. Separate parsing, resolution, readback, and outbound behavior. Preserve redacted controls and
   evidence references, and report validated vulnerabilities without requiring a challenge artifact.

## Evidence Gate

Confirm only replayable entity-derived readback or a controlled interaction absent from the paired
control. Reflected declarations, accepted syntax, errors, and timing remain observations. Keep any
`contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a typed parser, replay, unambiguous control, or policy budget. Do not add entity bombs,
file targets, or out-of-band services beyond the authorized native set.
