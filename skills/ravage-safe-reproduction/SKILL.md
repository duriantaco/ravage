---
name: ravage-safe-reproduction
description: Safely reproduce a fitted vulnerability hypothesis on an exactly authorized local, lab, or approved target using paired controls and minimum-impact evidence. Use after source review or advisory applicability, not for broad discovery.
---

# Reproduce A Vulnerability Safely

Do not begin until the exact target, identity, routes, methods, state changes, traffic budget, and
cleanup obligations are authorized.

1. Read [references/reproduction-protocol.md](references/reproduction-protocol.md).
2. Translate the hypothesis into one predicate and one benign target-origin marker. Prefer an
   operator-created canary over host files, secrets, commands, timing, or third-party callbacks.
3. Capture an ordinary baseline and a same-shape negative control, then change one property for the
   candidate. Use Ravage native probes only when their complete fixed behavior is authorized; a skill
   cannot trim their candidate set.
4. Stop at the first sufficient differential. Re-run only enough to exclude instability, then clean up
   created state and preserve redacted, replayable evidence with traffic accounting.
5. Hand the completed packet to `$ravage-finding-adjudication` when installed; otherwise request an
   independent review of provenance, controls, authorization, alternatives, impact, and cleanup.

Never execute a downloaded PoC, use production/customer data, collect credentials, persist access,
escalate beyond the hypothesis, perform denial-of-service testing, or bypass Ravage scope and identity
controls. If a class-specific validator or safe control is unavailable, return `inconclusive`.
