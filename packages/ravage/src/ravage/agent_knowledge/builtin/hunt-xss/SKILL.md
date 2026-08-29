---
name: hunt-xss
description: Investigate authorized reflected, stored, and DOM cross-site scripting boundaries. Use when typed discovery identifies controllable HTML or JavaScript contexts, reflection sinks, stored render workflows, DOM source-to-sink flows, browser execution signals, or suspected executable markup injection.
---

# Hunt Browser Injection Boundaries

Treat this card as advisory prioritization. Reflection, broken markup, and sink names are not proof
of browser execution.

## Workflow

1. Map the controllable source, render transition, context, browser identity, and sink.
2. Use `reflection_value_boundary`, then `xss_context`. Use `dom_execution` only when its external
   browser lane is available; it is unavailable with managed authentication.
3. Compare a unique inert marker with a same-shape encoded control. For stored flows, preserve the
   write/render chain and clean up the marker.
4. Retain the source, sink, execution observation, control, and evidence references. Report every
   validated vulnerability without requiring a challenge artifact.

## Evidence Gate

Confirm only controlled browser or DOM execution at the in-scope sink, absent from the paired
control. Reflection, context guesses, handler text, and static DOM presence remain observations.
Keep any `contract_missing` result suspected rather than promoting it.

## Stop Conditions

Stop without a controllable source-to-sink path, accounted browser lane, clear control, or policy
budget. Do not target third-party users, exfiltrate data, or leave persistent effects.
