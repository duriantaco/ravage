---
title: Open Core And Pro Reports
---

# Open Core And Pro Reports

Ravage core is open source under the Apache License 2.0 (`Apache-2.0`). The
core repository contains the CLI, agent runtime, schemas, labs, scanners, audit
trail, benchmark harness, evidence gates, and Markdown or JSON pentest report
generation.

Professional report formats are the commercial boundary. Core can produce
portable `.md` and `.json` artifacts. `.pdf` and `.docx` exports require a
separately licensed Ravage Pro package.

## CLI Behavior

Core report generation:

```bash
ravage report runs/demo --brief brief.yaml --output report.md
ravage report runs/demo --brief brief.yaml --output report.json
```

Professional report generation:

```bash
ravage report runs/demo --brief brief.yaml --output report.pdf
ravage report runs/demo --brief brief.yaml --output report.docx
```

If the Pro package is not installed, the CLI fails before rendering and tells
the operator to use `.md` or `.json` from core.

## Extension Contract

Core discovers the Pro renderer by importing `ravage_pro.report`. The Pro
package should provide this callable:

```python
from pathlib import Path
from typing import Any


def write_professional_report(
    *,
    report: dict[str, Any],
    markdown: str,
    output_path: Path,
) -> dict[str, str]:
    ...
```

The callable receives the already redacted structured report, the rendered
Markdown, and the requested `.pdf` or `.docx` path. It should write the
professional artifact and return any extra artifact metadata to merge into the
JSON report.

## Commercial Boundary

Good paid features sit above the core evidence pipeline:

- polished PDF and DOCX templates
- customer branding and report themes
- report review and approval workflow
- team collaboration and comments
- hosted dashboards and engagement history
- integrations for Jira, Linear, Slack, GitHub, GitLab, and ticketing systems
- managed cloud execution and retention controls

The core should remain useful without Pro: a user can run authorized tests,
inspect evidence, verify audit output, reproduce benchmark results, and export
Markdown or JSON. Pro should save time or produce client-ready deliverables, not
hide the basic security result.

Before publishing commercial terms, have counsel review the exact license
layout, package boundary, trademark terms, and hosted-service obligations.
