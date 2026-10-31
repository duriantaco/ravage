# Safe Reproduction Protocol

## Preconditions

Record the authorization source, target origin, permitted routes and methods, test identities,
request/rate budget, allowed state changes, data-handling rules, and cleanup owner. For remote work,
require Ravage's explicit authorized-remote acknowledgement. Managed identities must stay inside the
managed HTTP owner; never drop them to gain command, browser, or raw transport access.

## Experiment

Define:

- predicate: the exact security boundary being tested;
- baseline: ordinary valid behavior;
- negative control: same shape but unable to trigger the hypothesized condition;
- candidate: one changed property;
- observable: target-origin value or postcondition that distinguishes outcomes;
- stop: first sufficient evidence, ambiguity, policy block, or budget limit;
- cleanup: exact reversal or expiry of synthetic state.

Interleave timing controls when timing is unavoidable and account for jitter, but prefer deterministic
content or state. Source evidence and advisory text can justify the experiment; neither can satisfy the
observable.

Do not read operating-system files when an operator-created canary can prove traversal. Do not spawn a
shell when a fixed benign output marker can prove command execution. Do not use external callbacks
unless the exact listener and destination are authorized and metered. Never add brute force, resource
exhaustion, persistence, lateral movement, or secret collection.

## Packet

Preserve target and revision identity, request shapes, identity roles, controls, candidate,
observations, evidence references, traffic accounting, cleanup result, and all policy blocks. Redact
tokens, cookies, credentials, personal data, and unnecessary bodies.
