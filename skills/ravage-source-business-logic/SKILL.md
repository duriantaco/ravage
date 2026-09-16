---
name: ravage-source-business-logic
description: Review source code for business-logic and workflow flaws involving pricing, entitlement, credits, quotas, approvals, recovery, refunds, replay, or state transitions. Use when security depends on a domain invariant rather than a conventional sink.
---

# Review Business-Logic Invariants

Keep the review source-only and bind every claim to the frozen snapshot.

1. Define actors, assets, authoritative state, preconditions, permitted transitions, and the
   invariant that must survive retries, reordering, partial failure, and role changes.
2. Trace the valid sequence to its commit point, then inspect skipped, reordered, duplicated,
   cancelled, rolled-back, and exception paths.
3. Identify client-controlled price, quantity, status, entitlement, identity, or approval values and
   determine whether the server recomputes or cryptographically binds them before persistence.
4. Inspect one-time assets such as coupons, invitations, resets, refunds, credits, and approvals for
   atomic consumption and consistent scope.
5. Return an invariant table and suspected violating sequence with exact source references,
   postcondition, counterevidence, assumptions, and gaps.

Do not call an unusual branch a vulnerability without a security-relevant invariant. Do not run the
workflow, tests, project code, or target traffic.
