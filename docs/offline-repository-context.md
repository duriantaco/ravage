---
title: Offline Repository Context
---

# Offline Repository Context

`ravage.repository_context` provides a read-only text snapshot for offline code
review. It includes UTF-8 source, configuration, and documentation across file
extensions. It does not execute repository code or contact a model or network.
The dedicated `ravage review` agent uses this snapshot through a closed set of
read-only context actions. The attack agent can use the same bounded reader only
when the operator explicitly enables model source access.

```python
from pathlib import Path

from ravage.repository_context import ContextIgnorePolicy, capture_repository

context = capture_repository(Path("/path/to/repository"))
matches = context.search("formatGreeting")
excerpt = context.excerpt("frontend/greetings.ts", start_line=1, end_line=3)

# Explicitly include files matched by project-local .gitignore rules.
unfiltered = capture_repository(
    Path("/path/to/repository"),
    ignore_policy=ContextIgnorePolicy.NONE,
)
```

Run a bounded review with the default local model profile:

```bash
ravage review /path/to/repository
```

The review agent can list captured files and omissions, search literal text,
request bounded excerpts, and finish with source-backed candidates. It cannot
invoke shell, Python, project code, target HTTP or network actions, browsers,
probes, or attack runtimes. A nonempty repository must yield at least one excerpt
before the agent may finish. A final candidate must cite an excerpt receipt from
the same frozen snapshot; Ravage supplies the relative path, exact lines, excerpt
and file digests, and snapshot identity rather than trusting model-authored
references.

The default profile calls a loopback Ollama endpoint. A hosted or paid-risk model
requires `--allow-paid-models` and receives only the file metadata, search results,
and excerpts requested during the review. Repository text is treated as untrusted
data, but the capture exclusions are not a general secret detector. Review the
repository and provider policy before allowing source text to leave the machine.
The command writes candidate metadata and source references to standard output.
Ravage omits raw search-line and excerpt fields from the JSON trace; model-authored
summaries and candidate descriptions can still quote source content.
The top-level summary is explicitly marked `model_authored_unverified`. Raw
excerpt text and the frozen snapshot are not persisted by this command, so retain
the reviewed revision or rerun the review if the working tree changes.
The JSON also records an objective digest and length, requested and selected
model tiers, route ordinal, reasoning mode, output cap, turn and cost limits,
usage, and context-coverage counters for comparing recorded run settings without
copying the objective text into the artifact. Retain the model configuration,
Ravage revision, repository revision, and objective separately for reproduction.

## Attack source navigation

`ravage attack` keeps source text away from the model unless both
`--source-root` and `--allow-source-to-model` are supplied. A hosted route sends
the file lists, search results, and excerpts the model requests to that provider.
The repository is captured before run artifacts are created, and the run,
workspace, audit database, report, traffic ledger, and memory database must be
outside the source root. The configured tool-network evidence file is checked as
well. Programmatic callers remain responsible for keeping any custom runtime or
event-sink writes outside the source tree.

```bash
ravage attack brief.yaml \
  --run-dir /tmp/ravage-run \
  --source-root /path/to/repository \
  --allow-source-to-model
```

The model can list files and omissions, search literal text, and request bounded
excerpts. File contents and model lookup literals exist only in the next model
request. Consecutive reads for one task may accumulate snapshot-specific integer
atoms for structurally relevant lines in process memory; source text is not kept
in that authorization state. The chain is limited to 16 observations and 2,048
atoms. While a chain is active, the focused action schema pins the next action to
its task. If the model labels an otherwise authorized non-source action with a
different active task, Ravage records it under the evidence task before applying
the route or probe gate. A source read for a different task, failed or invalid
read, limit violation, or first non-source action discards the chain, and a resumed
process starts with an empty chain. Durable receipts retain the snapshot identity,
usage counts, and structural paths and coordinates; they omit file contents,
per-file and excerpt digests, errors, and search terms. A resume must use the same
snapshot, consent flag, and cumulative observation budget.

Source is hypothesis material and never target evidence or proof. Immediately
after a source observation, the model may issue another source action, a
catalogued native probe, or a bodyless `GET`, `HEAD`, or `OPTIONS` request. An
exact static route path whose complete structural lines appeared in the current
consecutive-read chain may be used so the agent can test hidden application
routes. Empty-valued query-field names are allowed only when they are structurally
tied to the same handler and visible in that chain. Query values, URL fragments,
headers, bodies,
commands, findings, and narrative fields are blocked on that turn. Any security
conclusion still requires evidence returned by the live target or a trusted typed
validator.

For Python applications, static route discovery follows direct relative imports
between modules for FastAPI `FastAPI`/`APIRouter` `include_router` mounts and
Flask `Flask`/`Blueprint` `register_blueprint` mounts. It composes literal router,
blueprint, and registration prefixes, including bounded nested mounts, and
requires the relevant constructor, import, mount, and route lines from every file
before authorizing a request. Route authority is emitted only for modules whose
import-time statements fit the passive static subset; receiver escapes,
mutation hooks, uncertain control flow, active package initializers, and local
modules that can shadow a framework import fail closed. Dynamic prefixes,
ambiguous bindings, multiple mounts of one component, absolute application
imports, re-exports, application-factory mounts, annotations outside the narrow
validated builtin/FastAPI/typing subset, and annotated module assignments
currently yield no route authorization. An omitted runtime-source file or
directory also makes route coverage incomplete and yields no authority.
Framework metadata/static routes, implicit Flask methods, alternate-slash
redirects, and competing recognized roots occupy their live paths without
granting source authority themselves. Routes added to a FastAPI router after a
same-file mount are also excluded until dependency-version evidence can select
the framework's copy or live-refresh behavior safely. Discovery starts from
every supported application constructor in the captured snapshot; ambiguous
method/path ownership across those roots and other supported languages fails
closed. It does not identify which application object a deployment serves or
prove that a discovered route is live. Python can also select constructors and
modules through arbitrary runtime data flow; only the direct imports and literal
dynamic-import forms recognized by this static grammar participate in the
completeness check. The bodyless request to the configured target is the
reachability check.

Search is case-sensitive literal text lookup. It returns matching lines with
one-based line/column positions, repository-relative paths, and file content
digests. Matching text is not proof that two symbols refer to the same
implementation. Excerpts preserve captured text and line endings.

All reads after capture use the immutable snapshot. A later capture produces a
different identity when included content or omission records change. Captured
root and nested `.gitignore` files are included in that identity, so changing an
ignore rule or comment changes the snapshot even when the resulting inventory is
otherwise the same. Files are checked for changes while being read; this is not
an atomic Git checkout.

By default, root and nested project-local `.gitignore` files are applied with Git
wildmatch ordering and negation semantics. Ignored files and directories appear
in `context.omissions` as `gitignored_file` and `gitignored_directory`.
Directories are pruned before descendant entries consume capture limits. Ravage
does not read global Git configuration or excludes, invoke Git, or use ignore
files outside the supplied root. `ContextIgnorePolicy.NONE` disables project
ignore matching. Built-in VCS/dependency-directory and credential-file exclusions
always take precedence over project rules.

Ignore files are opened relative to the traversed directory descriptor without
following symlinks, checked for replacement while read, and required to be valid,
bounded UTF-8 text. Pattern lines that Git treats as malformed no-ops remain
no-ops. A file with invalid encoding or NUL bytes, or an oversized, non-regular,
or changing ignore file, aborts capture rather than returning a context based on
incomplete rules.

`ContextLimits` defaults to 10,000 files, 64 MiB total file content, 100,000
directory entries, 512 KiB per file, and depth 32 (the root counts as depth one).
Exceeding a hard limit raises `ContextLimitError` without returning a partial
snapshot. Oversized individual files, symlinks, binary/non-UTF-8 files,
build/dependency directories, and common credential-file names appear in
`context.omissions`. These exclusions are not a general secret redactor. Review
omissions when deciding whether enough context is available. Descriptor-based
traversal currently requires POSIX, including Linux and macOS.

Search results mark additional matches with `truncated=True`. Long matching
lines return a bounded window around the match with its starting column and a
`text_truncated` flag. Excerpts over 100 lines or 20,000 characters are rejected.
The review agent applies narrower per-action limits, a total observation budget,
a model-turn limit, duplicate-action blocking, and a model-cost ceiling. Paid
routes use a conservative pre-request bound and stop before dispatch when the
remaining configured budget cannot cover the next request. Routes that cannot
enforce their configured output-token cap are rejected before a model call. A
review excerpt whose requested end is past the file's last line is clamped to
EOF and reports that adjustment; a request that starts past EOF still fails.

## Regression cases

The [source navigation regression runner](source-navigation-regressions.md)
adds a labelled route corpus, a bounded local receipt canary, and an optional
GPT-5.4 adapter. CI runs the offline corpus and scripted regressions.

Run the offline suite:

```bash
.venv/bin/python -m pytest \
  packages/ravage/tests/test_repository_context.py \
  packages/ravage/tests/test_repository_review.py \
  packages/ravage/tests/test_source_navigation.py \
  packages/ravage/tests/test_source_navigation_python_mounts.py \
  packages/ravage/tests/test_ai_agent_source_context.py -q
```

The fixed fixture contains eight harmless Python, TypeScript/TSX, JSON, YAML,
and Markdown files. Four lookup cases assert exact references for Python
definitions/imports/checks, TypeScript definitions/imports/components,
configuration/documentation, and absent text. Additional cases cover content
identity, Unicode and line endings, project-ignore ordering and negation,
omissions, changing files, and resource bounds. The fixtures and expected
references are separate from the reader.

The Python source analyzer reads three of these eight files, as its
documented contract requires. This reader exposes all eight. That difference
measures file-context breadth; it is not a vulnerability-detection score or a
semantic retrieval evaluation. The review regressions
prove that model-selected searches and excerpts reach the model and that final
candidates bind to captured evidence. They do not establish improved vulnerability
detection. Attack regressions separately verify consent, transient source
observations, snapshot-bound resume, and source-guided live requests; they do not
establish a recall gain.
