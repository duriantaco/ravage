---
name: hunt-ssti
description: Investigate authorized server-side template injection boundaries. Use when typed discovery or target-origin behavior identifies server-rendered inputs, evaluated-expression differentials, template-engine errors, rendering workflows, or suspected Jinja, Twig, FreeMarker, Mako, ERB, Smarty, Thymeleaf, or Django template evaluation.
---

# Hunt Template Evaluation Boundaries

Treat this card as advisory prioritization. Reflection and template syntax do not prove server-side
evaluation.

## Workflow

1. Preserve a target-observed server-rendered request and its render transition.
2. Pair a bounded expression with a baseline and same-shape syntax control; change one input.
3. `ssti_fingerprint` may escalate to fixed file, environment, and command candidates. Run it only
   when the complete set is authorized; use `command_boundary` only on an independent typed sink.
4. Preserve identity, route, fields, controls, and evidence references. Report validated
   vulnerabilities independently of any challenge objective.

## Evidence Gate

Confirm only a derived expression result absent from the paired control and replayable at the same
sink. Reflection, syntax disappearance, engine errors, and framework names remain observations.
Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a server-rendered replay, reproducible transition, clear control, or policy budget.
Do not add arbitrary code or extraction beyond the native set; redact environment data and bodies.
