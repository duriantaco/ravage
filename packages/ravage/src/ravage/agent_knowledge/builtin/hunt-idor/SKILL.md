---
name: hunt-idor
description: Investigate object-level and tenant authorization boundaries on authorized web or API targets. Use when typed routes or operator context expose object identifiers, account or tenant selectors, user-owned resources, GraphQL object lookups, or suspected cross-identity access.
---

# Hunt Authorization Boundaries

Treat this card as advisory prioritization. Scope, identity ownership, traffic policy,
available probes, and evidence gates remain authoritative.

## Workflow

1. Inventory operations carrying object, account, organization, tenant, or user identifiers.
2. Establish an owner control and a same-shape missing or non-owner control before mutation.
3. Prefer two explicitly configured same-privilege identities. Change one identifier at a time.
4. Route HTTP evidence through `idor_boundary`; use `api_behavior` or `graphql_exploit`
   only when the typed surface calls for them.
5. Preserve the exact identity, operation, request shape, response differential, and evidence
   reference used for validation.

## Evidence Gate

Confirm only when a non-owner identity reads or changes another identity's resource and the
paired control excludes public access, ownership, caching, and response-shape ambiguity.
Introspection, predictable identifiers, status differences, and object existence alone are
candidate signals, not findings.

## Stop Conditions

Stop the branch when the operation is out of scope, the required identity is unavailable,
controls remain ambiguous, or further enumeration would violate the traffic policy. Do not
brute-force identifier spaces.
