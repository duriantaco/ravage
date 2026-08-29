---
name: hunt-sqli
description: Investigate authorized SQL injection boundaries on web and API inputs. Use when typed discovery or target-origin evidence identifies query-backed parameters, database-error signals, boolean or timing SQL differentials, SQL-filter behavior, or a suspected injectable login, search, sort, filter, or identifier input.
---

# Hunt SQL Injection Boundaries

Treat this card as advisory prioritization. Scope, replay contracts, TrafficPolicy, and native
evidence gates remain authoritative.

## Workflow

1. Select a query-backed input and preserve its method, identity, session, fixed fields, and encoding.
2. Run `sqli_differential` first; change one input and pair each candidate with a same-shape control.
3. Interleave bounded timing pairs. Use `sqli_exploit` only after a reproducible differential and
   `filtered_query_bypass` only when target evidence shows filtering.
4. Preserve redacted replays, deltas, controls, and evidence references. Report validated
   vulnerabilities independently of any challenge objective.

## Evidence Gate

Confirm only a new database error absent from control, a reproducible boolean differential, or
repeatable timing above baseline jitter. Vendor fingerprints, isolated errors, length changes, and
one slow response remain observations. Keep `contract_missing` results suspected.

## Stop Conditions

Stop without a replayable query input, stable control, or policy budget, or after minimal proof.
Do not request extraction beyond the authorized native closer; redact credentials and bodies.
