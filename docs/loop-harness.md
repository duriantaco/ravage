---
title: Loop Harness
---

# Loop Harness

Ravage's agent loop is deliberately narrow: the model proposes one JSON action,
the runtime validates and executes it, then the observation is fed back into the
next turn. That is necessary, but it is not enough for a reliable agentic
system. The production harness around the loop needs durable state,
verification, event replay, and trace-driven improvement.

This document maps the loop-engineering pattern described in
[The Art of Loop Engineering](https://www.langchain.com/blog/the-art-of-loop-engineering)
onto Ravage's security-testing runtime.

## Loop Stack

Ravage uses four cooperating loops.

### Agent Loop

The agent loop is the existing `ai-web` turn cycle:

1. Build context from the engagement brief, scope, memory hints, working state,
   planner recommendations, source-guided observations, and previous
   observations.
2. Ask the model for one structured action.
3. Parse and validate the action.
4. Execute one scoped tool or deterministic workflow.
5. Record the observation and append it to the next model turn.

The model does not get to execute tools directly, expand scope, report proof
from text alone, or override safety policy.

### Verification Loop

The verification loop runs after and around the agent loop. Its job is to
decide whether a run earned trust, not to discover vulnerabilities itself.

The first verifier slice uses:

- `workspace/events.jsonl`
- `workspace/transcript.jsonl`
- trace-quality findings
- trace-derived evidence gates for no-proof findings, premature final, and
  max-turns exhaustion without evidence

The first harness artifact is:

```text
workspace/loop_verification.json
```

It aggregates `run_trace` and `trace_quality` output into verifier feedback and
hill-climb suggestions. The initial implementation is observational. It does
not reject actions during the run. Later phases can feed selected verifier
feedback into the next model turn, include `audit.db`/`report.json` and
proof-bundle checks, add stricter scope-policy replay, or fail CI on
high-severity regressions.

### Event Loop

The event loop is the scheduled or triggered harness around many runs:

- local lab smoke tests
- deterministic DAST checks
- `ai-web` benchmark manifests
- XBEN-style controlled runs
- memory off/read comparisons
- AI red-team manifests
- regression runs for previously fixed failures

The event loop should always preserve run artifacts. A failed run with a clean
trace is more useful than a pass that cannot be explained.

### Hill-Climbing Loop

The hill-climbing loop turns traces into proposed improvements. It should not
auto-edit prompts or tools without review.

Examples:

- repeated identical tool calls -> add a planner guard or no-progress memory
- invalid action burn -> tighten schema instructions or parser repair feedback
- premature final -> strengthen final-gate feedback
- finding without replayable proof -> require proof-bundle or evidence fields
- turn budget exhausted without evidence -> prioritize better probes earlier

The first harness artifact stores these as candidates:

```json
{
  "hill_climb_suggestions": [
    {
      "kind": "harness_improvement",
      "key": "repeated_identical_tool_call",
      "source": "trace_quality",
      "status": "candidate"
    }
  ]
}
```

## State, Memory, And Traces

The loop-harness API can write a state snapshot beside the existing working
state:

```text
workspace/loop_state.json
```

`working_state.json` remains the compact live operator view. `loop_state.json`
is the structured harness view.

The harness separates three concepts:

- State: per-run facts needed to continue, debug, and verify one run.
- Memory: reviewed cross-run lessons that may guide later runs.
- Trace: immutable event and transcript history used for replay and scoring.

State includes:

- discovered routes and parameters
- session/header/cookie counters
- credential and identity signals
- attempted probe candidates
- blocked actions
- confirmed evidence metadata
- budget counters
- memory retrieval feedback
- verifier feedback
- hill-climb suggestions

Memory remains advisory:

- it can suggest tactics,
- it can be measured through memory evals,
- it cannot report findings,
- it cannot capture flags,
- it cannot expand scope,
- it cannot override live evidence.

## Current Implementation

Core module:

```text
packages/ravage/src/ravage/loop_harness.py
```

Artifacts:

```text
workspace/loop_state.json
workspace/loop_verification.json
```

Integration status:

- The state snapshot and verification report are standalone, explicitly
  invoked APIs.
- They are covered by focused tests but are not yet wired into the existing
  `ai-web` or benchmark execution paths.
- Existing execution workflows remain unchanged until that integration is
  reviewed separately.

## Next Phases

1. Add `eval/ai_redteam_manifest.yaml` for prompt-injection, hostile redirect,
   fake tool-output, memory-poisoning, and scope-escape cases.
2. Add a CLI reader such as `ravage harness show <workspace>` for concise
   inspection.
3. Feed selected verifier feedback into resumed runs as untrusted harness
   observations.
4. Fail benchmark cases on severe harness findings when the manifest requires
   strict verification.
5. Promote useful hill-climb suggestions into reviewed planner, prompt, memory,
   or tool-contract changes.
