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


def test_host_runtime_scrubs_parent_secrets_from_shell_and_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "fake-openai-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-secret")
    monkeypatch.setenv("RAVAGE_ARBITRARY_PARENT_SECRET", "fake-parent-secret")
    runtime = ExternalToolRuntime()
    try:
        shell = runtime.run_command(
            command=(
                "printf '%s|%s|%s|%s' "
                '"${OPENAI_API_KEY-unset}" "${ANTHROPIC_API_KEY-unset}" '
                '"${RAVAGE_ARBITRARY_PARENT_SECRET-unset}" "$RAVAGE_TARGET_URL"'
            ),
            target_url="http://127.0.0.1:8765",
        )
        python = runtime.run_python(
            code=(
                "import os\n"
                "keys = ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', "
                "'RAVAGE_ARBITRARY_PARENT_SECRET')\n"
                "print('|'.join(os.environ.get(key, 'unset') for key in keys))\n"
                "print(os.environ['RAVAGE_TARGET_URL'])\n"
                "print(os.environ['HOME'])\n"
            ),
            target_url="http://127.0.0.1:8765",
        )
    finally:
        runtime.close()

    assert shell.ok is True
    assert shell.stdout == "unset|unset|unset|http://127.0.0.1:8765"
    assert python.ok is True
    assert python.stdout.splitlines() == [
        "unset|unset|unset",
        "http://127.0.0.1:8765",
        str(runtime.workdir),
    ]
