---
name: hunt-deserialization
description: Investigate authorized unsafe deserialization and serialized-data trust boundaries. Use when typed discovery identifies encoded object cookies or tokens, pickle or object streams, YAML type tags, serialized uploads or imports, type-confusion errors, or suspected server-side object reconstruction.
---

# Hunt Deserialization Boundaries

Treat this card as advisory prioritization. Encodings, format fingerprints, and parser errors do not
prove unsafe object construction.

## Workflow

1. Identify the format, carrier, integrity protection, identity, and target-observed replay.
2. Pair an unchanged baseline with a same-shape inert structural control; change one property.
3. Use `cookie_deserialization` for cookies or tokens and `file_fetch_parser` only for typed imports
   or uploads. Their fixed command and file-read candidates must all be authorized.
4. Preserve redacted inputs, format decisions, controls, deltas, and evidence references. Report a
   validated vulnerability independently of any challenge objective.

## Evidence Gate

Confirm only a replayable unsafe type, object-handling, or execution effect absent from the paired
control. Decoder errors, library names, gadget strings, and status changes remain observations.
Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop when format, integrity, identity, replay, or controls are unavailable, or policy limits fire.
Do not add destructive gadgets, persistence, or outbound effects; redact returned secrets.
