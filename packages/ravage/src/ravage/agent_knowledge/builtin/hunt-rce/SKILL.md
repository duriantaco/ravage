---
name: hunt-rce
description: Investigate authorized server-side command and code-execution boundaries. Use when typed discovery or target-origin behavior identifies command injection, process-launching, diagnostic, converter, expression-evaluation, parser, include, or other server-side execution-sink signals.
---

# Hunt Server Execution Boundaries

Treat this card as advisory prioritization. Errors, reflection, and isolated timing do not prove
server-side execution.

## Workflow

1. Require a typed execution sink and preserve its target-observed replay.
2. Use `command_boundary` for command inputs and `werkzeug_console` only for a typed debugger
   primitive. Use `ssti_fingerprint` or `file_fetch_parser` only on their typed sinks.
3. Pair a same-route baseline with the candidate, changing one input. Native closers include fixed
   command, file, environment, and timing candidates; all must be authorized.
4. Stop after the first sufficient marker. Retain redacted controls and evidence references, and
   report the vulnerability independently of any challenge objective.

## Evidence Gate

Confirm only replayable target-origin output unique to the candidate, repeated timing above jitter,
or a separately validated template/file-chain effect. Other deltas remain observations. Keep any
`contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a typed sink, replay, stable control, or policy budget. Do not add shells, persistence,
privilege escalation, lateral movement, or secret collection; redact native output.
