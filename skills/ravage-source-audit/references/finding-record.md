# Source Candidate Record

Record each candidate with:

- snapshot revision or digest;
- title and vulnerability family;
- source entry point and attacker-controlled value or state;
- exact path and line references;
- source-to-decision, source-to-sink, or state-transition trace;
- violated security predicate or business invariant;
- required feature, configuration, identity, and deployment assumptions;
- supporting evidence and deliberately searched counterevidence;
- impact if the path is reachable at runtime;
- confidence and unresolved evidence;
- reviewed files, omitted files, generated/vendor boundaries, and other coverage gaps.

Use these source-only dispositions:

- source-supported: the snapshot contains a complete reachable semantic path and the expected
  guard is absent or ineffective in that path;
- candidate: the path is plausible but a material caller, configuration, build, or runtime fact
  is unresolved;
- rejected: decisive source counterevidence defeats the predicate;
- blocked: required source or artifact evidence is unavailable within the review boundary.

Source-supported is not a claim that a deployed system was exploited. Do not invent runtime
observations, CVE applicability, or environmental conditions.
