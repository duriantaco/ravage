---
title: Offline Repository Context
---

# Offline Repository Context

`ravage.repository_context` provides a read-only text snapshot for offline code
review. It includes UTF-8 source, configuration, and documentation across file
extensions. It does not execute repository code or contact a model or network.
The dedicated `ravage review` agent uses this snapshot through a closed set of
read-only context actions. The target-facing attack agent remains separate.

```python
from pathlib import Path

from ravage.repository_context import capture_repository

context = capture_repository(Path("/path/to/repository"))
matches = context.search("formatGreeting")
excerpt = context.excerpt("frontend/greetings.ts", start_line=1, end_line=3)
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

Search is case-sensitive literal text lookup. It returns matching lines with
one-based line/column positions, repository-relative paths, and file content
digests. Matching text is not proof that two symbols refer to the same
implementation. Excerpts preserve captured text and line endings.

All reads after capture use the immutable snapshot. A later capture produces a
different identity when included content or omission records change. Files are
checked for changes while being read; this is not an atomic Git checkout.

`ContextLimits` bounds file count, total bytes, directory entries, and depth
(the root counts as depth one). Exceeding those limits raises `ContextLimitError`
without returning a partial snapshot. Oversized individual files, symlinks,
binary/non-UTF-8 files, build/dependency directories, and common credential-file
names appear in `context.omissions`. These exclusions are not a general secret
redactor, and capture does not implement `.gitignore` semantics. Review omissions
when deciding whether enough context is available. Descriptor-based traversal
currently requires POSIX, including Linux and macOS.

Search results mark additional matches with `truncated=True`. Long matching
lines return a bounded window around the match with its starting column and a
`text_truncated` flag. Excerpts over 100 lines or 20,000 characters are rejected.
The review agent applies narrower per-action limits, a total observation budget,
a model-turn limit, duplicate-action blocking, and a model-cost ceiling. Paid
routes use a conservative pre-request bound and stop before dispatch when the
remaining configured budget cannot cover the next request. Routes that cannot
enforce their configured output-token cap are rejected before a model call.

## Regression cases

Run the offline suite:

```bash
.venv/bin/python -m pytest \
  packages/ravage/tests/test_repository_context.py \
  packages/ravage/tests/test_repository_review.py -q
```

The fixed fixture contains eight harmless Python, TypeScript/TSX, JSON, YAML,
and Markdown files. Four lookup cases assert exact references for Python
definitions/imports/checks, TypeScript definitions/imports/components,
configuration/documentation, and absent text. Additional cases cover content
identity, Unicode and line endings, omissions, changing files, and resource
bounds. The fixtures and expected references are separate from the reader.

The existing Python source analyzer reads three of these eight files, as its
documented contract requires. This reader exposes all eight. That difference
measures file-context breadth; it is not a vulnerability-detection score, a
semantic retrieval evaluation, or a Strix comparison. The review regressions
prove that model-selected searches and excerpts reach the model and that final
candidates bind to captured evidence. They do not establish improved vulnerability
detection. The existing source-guided attack analyzer and its live-evidence rules
are unchanged.
