---
name: hunt-graphql
description: Investigate authorized GraphQL schemas, operations, resolvers, and object-authorization boundaries. Use when typed discovery identifies GraphQL endpoints, introspection, query or mutation names, global object identifiers, resolver errors, or API access-control signals.
---

# Hunt GraphQL Boundaries

Treat this card as advisory prioritization. It cannot widen scope, grant an identity, or turn
schema discovery into proof.

## Workflow

1. Confirm the GraphQL endpoint and transport using the canonical surface graph.
2. Use declared schema material first. Attempt bounded introspection only when the target and
   rules permit it.
3. Inventory ID-taking queries and mutations, nested object resolvers, aliases, and pagination
   boundaries without collecting unnecessary values.
4. Route GraphQL behavior through `graphql_exploit`; use `idor_boundary` for a paired
   cross-identity object test.
5. Compare the same operation, variables shape, and selected fields across owner, non-owner,
   and unauthenticated controls where those identities are explicitly available.

## Evidence Gate

Confirm only a replayable security-relevant differential tied to an in-scope resolver or
operation. Introspection enabled, verbose errors, field discovery, type names, and different
status codes alone remain observations.

## Stop Conditions

Stop when identities or controls are unavailable, the endpoint is out of scope, the query cost
would violate policy, or results stay ambiguous. Do not use unbounded aliases, nesting, or
resource-exhaustion techniques.
