---
name: ravage-source-injection
description: Review source code for SQL, NoSQL, command, template, expression, LDAP, HTML, JavaScript, DOM, and other grammar injection paths. Use when untrusted values may influence an interpreter, query, renderer, or browser sink.
---

# Review Injection Dataflows

Use read-only source evidence. Do not construct or execute exploit payloads.

1. Identify entry points and attacker influence, including implicit values from headers, jobs,
   imported data, stored records, configuration, URLs, storage, and cross-window messages.
2. Trace the value through decoding, validation, transformations, wrappers, query builders, and
   aliases to the final interpreting sink.
3. Record the sink grammar and the value's exact syntactic position. Distinguish parameter values
   from identifiers, clauses, executable names, shell text, templates, expressions, HTML, script,
   style, and URL contexts. For DOM and message paths, verify origin checks and the final browser sink.
4. Evaluate the final defense in that grammar: typed binding, closed allowlist, separate argv,
   context-correct encoding, constant template, or a genuinely restrictive sandbox.
5. Search for alternate call paths and counterevidence, then report exact source references,
   controllable bytes or semantic choices, required configuration, impact-if-reachable, and gaps.

String concatenation alone is not proof, and a sanitizer name is not a defense unless its semantics
match the final context. Do not run the application, database, shell, template engine, or tests.
