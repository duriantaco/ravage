from __future__ import annotations

from typing import TYPE_CHECKING

from ravage.runtime.host import ExternalToolRuntime

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_host_runtime_executes_project_local_tool_from_temporary_workdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    tool = project / ".tools" / "bin" / "ravage-local-tool"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\nprintf 'project-local tool ran\\n'\n", encoding="utf-8")
    tool.chmod(0o755)
    shell = tmp_path / "shell-bin" / "sh"
    shell.parent.mkdir()
    shell.write_text(
        '#!/bin/sh\nPATH=/usr/bin:/bin\nexport PATH\nexec /bin/sh "$@"\n',
        encoding="utf-8",
    )
    shell.chmod(0o755)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    monkeypatch.setenv("PATH", str(shell.parent))
    monkeypatch.chdir(project)
    runtime = ExternalToolRuntime()
    monkeypatch.chdir(elsewhere)
    try:
        result = runtime.run_command(
            command="ravage-local-tool",
            target_url="http://127.0.0.1:8765",
        )
    finally:
        runtime.close()

    assert result.ok is True
    assert result.stdout == "project-local tool ran\n"
