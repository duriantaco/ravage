# Source Applicability Matrix

Mark each condition supported, contradicted, or unknown and attach evidence.

| Condition | Source-only question |
| --- | --- |
| Identity | Is this the affected ecosystem, package, product, fork, plugin, or vendored component? |
| Version | Does the resolved lock or artifact metadata fall within the affected range? |
| Patch | Is the fixed semantic change present through backport, cherry-pick, or equivalent code? |
| Build | Is the affected code compiled, bundled, or otherwise included by repository build logic? |
| Feature | Is the affected module, parser, protocol, route, or optional feature present? |
| Configuration | Can repository defaults and precedence enable every required condition? |
| Entry point | Does an untrusted source path reach the affected behavior in this snapshot? |
| Data flow | Can the required data shape survive parsing, validation, and wrappers? |
| Mitigation | Does policy, sandboxing, privilege separation, or a wrapper block the stated impact? |

Source-applicable requires all material source conditions to be supported and none contradicted.
Not-applicable requires decisive counterevidence. Otherwise return inconclusive. None of these
verdicts claims that a deployed target was tested.
