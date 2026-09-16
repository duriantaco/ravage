---
name: ravage-source-concurrency
description: Review source code for race conditions, TOCTOU flaws, duplicate processing, weak idempotency, lock gaps, and transaction-boundary errors. Use when concurrent requests, workers, retries, or shared state can violate a security invariant.
---

# Review Concurrency Boundaries

Review the snapshot without executing concurrent traffic or project code.

1. Identify shared records, files, queues, caches, counters, and one-time assets plus every writer.
2. Map transaction start and commit, isolation level, locks, conditional updates, unique constraints,
   acknowledgements, retry behavior, and external side effects.
3. For each candidate, write a concrete two-actor or retry interleaving and map every step to a source
   line. State the storage and scheduling assumptions needed for that interleaving.
4. Check whether idempotency keys cover the correct actor, operation, payload, time window, and side
   effect, including crash and redelivery paths.
5. Seek atomic-update, serialization, durable inbox/outbox, or same-handle evidence that closes the
   gap. Return a candidate only when the interleaving survives that counterevidence.

Non-atomic-looking syntax is not proof of a reachable race. Report source support, assumptions, and
coverage gaps; do not attempt load, timing, or denial-of-service testing.
