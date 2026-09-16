---
name: ravage-source-adjudication
description: Independently review a completed source-code vulnerability candidate and classify its evidence as source-supported, candidate, rejected, or blocked. Use for false-positive control after source review; do not send traffic or execute code.
---

# Adjudicate A Source Candidate

Review one candidate against the same frozen snapshot. Treat model conclusions, scanner labels,
advisory matches, and source comments as claims.

1. Verify snapshot identity and resolve every cited path and line to the stated revision.
2. Restate the exact security predicate or business invariant, entry point, attacker influence,
   semantic path, required configuration, and impact-if-reachable.
3. Re-walk the path independently across wrappers, aliases, generated boundaries, middleware,
   defaults, error branches, and the final decision or sink.
4. Seek decisive counterevidence: central policies, sanitizers that match the sink grammar, server
   recomputation, atomic constraints, dead code, disabled features, backported fixes, or unreachable
   callers.
5. Return exactly one verdict: source-supported, candidate, rejected, or blocked. Include strongest
   evidence, strongest counterevidence, assumptions, missing source, and coverage gaps.

Source-supported means the code path is supported by the snapshot; runtime exploitability is still
unverified. Do not run tests, builds, PoCs, binaries, Ravage probes, browsers, or network requests,
and do not silently fill evidence gaps.
