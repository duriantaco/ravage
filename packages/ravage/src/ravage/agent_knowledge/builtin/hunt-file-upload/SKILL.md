---
name: hunt-file-upload
description: Investigate authorized file-upload, stored-file, and upload-parser boundaries. Use when typed discovery identifies upload forms, multipart requests, filename or content-type handling, stored-file readback, image or document ingestion, archive processing, XML or SVG parsing, or suspected upload-policy bypasses.
---

# Hunt File Upload Boundaries

Treat this card as advisory prioritization. Expected acceptance and returned storage paths are not
vulnerabilities by themselves.

## Workflow

1. Preserve the upload method, identity, form state, media policy, and returned storage reference.
2. `file_fetch_parser` includes fixed interpreted-file and deserialization candidates. Run it only
   when the complete set is authorized; preserve multipart shape and change one property.
3. Follow only target-returned same-origin readback. Use `xxe_boundary` only for a typed XML or SVG
   parser, and keep acceptance, storage, serving, readback, and parser effects separate.
4. Preserve controls and evidence references. Report validated vulnerabilities independently of
   any challenge objective.

## Evidence Gate

Confirm only a replayable policy bypass with security-relevant target-origin readback/effect, or an
independently validated parser flaw. Acceptance, extension or media disagreement, and saved paths
remain observations. Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a replay, required state, in-scope readback, clear control, or policy budget. Do not
add overwrites, persistent shells, decompression bombs, or parser exhaustion; clean up canaries.
