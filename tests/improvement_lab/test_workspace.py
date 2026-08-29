from __future__ import annotations

import hashlib
import json
import subprocess
from typing import TYPE_CHECKING

import pytest

from tools.improvement_lab.workspace import (
    CandidateWorkspace,
    CandidateWorkspaceError,
    build_offline_container_job,
    capture_source_state,
    directory_tree_digest,
    materialize_candidate,
    require_clean_champion,
)

if TYPE_CHECKING:
    from pathlib import Path


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603
        ("git", "-C", str(root), *args),  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _source_repo(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.email", "improvement@example.invalid")
    _git(root, "config", "user.name", "Improvement Test")
    (root / "app.txt").write_text("champion\n", encoding="utf-8")
    _git(root, "add", "app.txt")
    _git(root, "commit", "-m", "champion")
    return root


def _candidate(tmp_path: Path) -> CandidateWorkspace:
    source = _source_repo(tmp_path)
    before = capture_source_state(source)
    return materialize_candidate(
        source_root=source,
        lab_root=tmp_path / "lab",
        candidate_id="candidate-1",
        base_commit=before.head_commit,
        patch=b"",
    )


def _candidate_view(root: Path) -> None:
    content = b'{"schema_version":"ravage.improvement-corpus.v1","capsules":[]}\n'
    artifact_id = f"artifact_{'c' * 24}"
    kind = "development_corpus"
    filename = f"{artifact_id}-{kind}.json"
    (root / filename).write_bytes(content)
    (root / ".improvement-candidate-view.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "archive_id": f"archive_{'d' * 24}",
                "entries": [
                    {
                        "artifact_id": artifact_id,
                        "kind": kind,
                        "content_object": f"sha256:{hashlib.sha256(content).hexdigest()}",
                        "filename": filename,
                    }
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def test_candidate_is_patched_in_independent_clone_without_source_change(tmp_path: Path) -> None:
    source = _source_repo(tmp_path)
    before = capture_source_state(source)
    patch = b"""diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1 +1 @@
-champion
+candidate
"""

    candidate = materialize_candidate(
        source_root=source,
        lab_root=tmp_path / "lab",
        candidate_id="candidate-1",
        base_commit=before.head_commit,
        patch=patch,
    )

    assert (candidate.path / "app.txt").read_text(encoding="utf-8") == "candidate\n"
    assert (source / "app.txt").read_text(encoding="utf-8") == "champion\n"
    assert capture_source_state(source) == before
    assert _git(candidate.path, "remote") == ""


def test_dirty_source_cannot_be_registered_as_champion(tmp_path: Path) -> None:
    source = _source_repo(tmp_path)
    (source / "app.txt").write_text("unreviewed\n", encoding="utf-8")

    with pytest.raises(CandidateWorkspaceError, match="dirty"):
        require_clean_champion(source)


def test_hidden_source_change_cannot_be_registered_as_champion(tmp_path: Path) -> None:
    source = _source_repo(tmp_path)
    _git(source, "update-index", "--assume-unchanged", "app.txt")
    (source / "app.txt").write_text("hidden unreviewed bytes\n", encoding="utf-8")

    with pytest.raises(CandidateWorkspaceError, match="hidden, skipped, or unresolved"):
        require_clean_champion(source)


def test_offline_job_is_digest_pinned_and_hardened(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    workspace = candidate.path
    episodes = tmp_path / "episodes"
    trusted_tests = tmp_path / "trusted-tests"
    output = tmp_path / "output"
    episodes.mkdir()
    trusted_tests.mkdir()
    _candidate_view(episodes)
    image = f"example.invalid/improvement@sha256:{'a' * 64}"

    job = build_offline_container_job(
        image=image,
        candidate=candidate,
        episodes_root=episodes,
        trusted_tests_root=trusted_tests,
        expected_trusted_tests_digest=directory_tree_digest(trusted_tests),
        output_root=output,
        command=("python", "-m", "pytest", "-q"),
    )

    assert job.argv[job.argv.index("--network") + 1] == "none"
    assert job.argv[job.argv.index("--cap-drop") + 1] == "ALL"
    assert "--read-only" in job.argv
    assert "no-new-privileges" in job.argv
    assert image in job.argv
    assert str(workspace) in " ".join(job.argv)
    assert f"type=bind,src={job.candidate_workspace},dst=/candidate,readonly" in job.argv
    assert f"type=bind,src={job.trusted_tests_root},dst=/trusted-tests,readonly" in job.argv


def test_offline_job_rejects_mutable_image_tag(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    for name in ("episodes", "trusted-tests"):
        (tmp_path / name).mkdir()
    _candidate_view(tmp_path / "episodes")
    with pytest.raises(CandidateWorkspaceError, match="pinned"):
        build_offline_container_job(
            image="example.invalid/improvement:latest",
            candidate=candidate,
            episodes_root=tmp_path / "episodes",
            trusted_tests_root=tmp_path / "trusted-tests",
            expected_trusted_tests_digest=directory_tree_digest(tmp_path / "trusted-tests"),
            output_root=tmp_path / "output",
            command=("true",),
        )


def test_candidate_patch_cannot_replace_reserved_marker_with_symlink(tmp_path: Path) -> None:
    source = _source_repo(tmp_path)
    before = capture_source_state(source)
    patch = rb"""diff --git a/.improvement-candidate.json b/.improvement-candidate.json
new file mode 120000
--- /dev/null
+++ b/.improvement-candidate.json
@@ -0,0 +1 @@
+../../source/app.txt
\ No newline at end of file
"""

    with pytest.raises(CandidateWorkspaceError, match="reserved marker"):
        materialize_candidate(
            source_root=source,
            lab_root=tmp_path / "lab",
            candidate_id="candidate-symlink",
            base_commit=before.head_commit,
            patch=patch,
        )

    assert (source / "app.txt").read_text(encoding="utf-8") == "champion\n"
    assert capture_source_state(source) == before


def test_offline_job_rejects_overlapping_or_unverified_mounts(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    workspace = candidate.path
    episodes = workspace / "episodes"
    trusted_tests = tmp_path / "trusted-tests"
    episodes.mkdir()
    trusted_tests.mkdir()
    _candidate_view(episodes)

    with pytest.raises(CandidateWorkspaceError, match="disjoint"):
        build_offline_container_job(
            image=f"example.invalid/improvement@sha256:{'a' * 64}",
            candidate=candidate,
            episodes_root=episodes,
            trusted_tests_root=trusted_tests,
            expected_trusted_tests_digest=directory_tree_digest(trusted_tests),
            output_root=tmp_path / "output",
            command=("true",),
        )

    (workspace / ".improvement-candidate.json").unlink()
    separate_episodes = tmp_path / "separate-episodes"
    separate_episodes.mkdir()
    _candidate_view(separate_episodes)
    with pytest.raises(CandidateWorkspaceError, match="marker"):
        build_offline_container_job(
            image=f"example.invalid/improvement@sha256:{'a' * 64}",
            candidate=candidate,
            episodes_root=separate_episodes,
            trusted_tests_root=trusted_tests,
            expected_trusted_tests_digest=directory_tree_digest(trusted_tests),
            output_root=tmp_path / "other-output",
            command=("true",),
        )


def test_offline_job_rejects_modified_candidate_or_test_tree(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    episodes = tmp_path / "episodes"
    trusted_tests = tmp_path / "trusted-tests"
    episodes.mkdir()
    trusted_tests.mkdir()
    _candidate_view(episodes)
    expected_tests = directory_tree_digest(trusted_tests)
    (candidate.path / "app.txt").write_text("substituted\n", encoding="utf-8")

    with pytest.raises(CandidateWorkspaceError, match="unstaged changes"):
        build_offline_container_job(
            image=f"example.invalid/improvement@sha256:{'a' * 64}",
            candidate=candidate,
            episodes_root=episodes,
            trusted_tests_root=trusted_tests,
            expected_trusted_tests_digest=expected_tests,
            output_root=tmp_path / "modified-output",
            command=("true",),
        )

    _git(candidate.path, "restore", "app.txt")
    (trusted_tests / "case.json").write_text("changed\n", encoding="utf-8")
    with pytest.raises(CandidateWorkspaceError, match="test tree differs"):
        build_offline_container_job(
            image=f"example.invalid/improvement@sha256:{'a' * 64}",
            candidate=candidate,
            episodes_root=episodes,
            trusted_tests_root=trusted_tests,
            expected_trusted_tests_digest=expected_tests,
            output_root=tmp_path / "changed-tests-output",
            command=("true",),
        )


def test_offline_job_rejects_assume_unchanged_content_substitution(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path)
    episodes = tmp_path / "episodes"
    trusted_tests = tmp_path / "trusted-tests"
    episodes.mkdir()
    trusted_tests.mkdir()
    _candidate_view(episodes)
    _git(candidate.path, "update-index", "--assume-unchanged", "app.txt")
    (candidate.path / "app.txt").write_text("hidden substitution\n", encoding="utf-8")

    with pytest.raises(CandidateWorkspaceError, match="hidden, skipped, or unresolved"):
        build_offline_container_job(
            image=f"example.invalid/improvement@sha256:{'a' * 64}",
            candidate=candidate,
            episodes_root=episodes,
            trusted_tests_root=trusted_tests,
            expected_trusted_tests_digest=directory_tree_digest(trusted_tests),
            output_root=tmp_path / "hidden-output",
            command=("true",),
        )
