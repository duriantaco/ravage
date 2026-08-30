# Releasing Ravage

Ravage releases are immutable, reproducible artifacts for a pre-1.0 security
research project. Publishing is allowed only from a reviewed tag on `main`
after the checks below pass. Never publish from a development branch or reuse a
version that has appeared on an index.

## Release infrastructure

Before preparing a release, verify all of the following:

- GitHub private vulnerability reporting is enabled for the repository.
- A GitHub tag ruleset protects `v*` tags from unreviewed creation, update, and
  deletion.
- The GitHub `pypi` environment accepts only `v*` tag refs and requires an
  independent deployment approval.
- Trusted Publishers exist on PyPI for both `ravage` and `ravage-schemas`, using
  repository `duriantaco/ravage`, workflow `publish-pypi.yml`, and environment
  `pypi`.
- The GitHub `testpypi` environment is separately approval-gated. Trusted
  Publishers exist on TestPyPI for both projects, using workflow
  `publish-testpypi.yml` and environment `testpypi`.
- Every workflow's third-party actions are pinned to full commit SHAs.
- GitHub Pages uses GitHub Actions as its source and the `github-pages`
  environment is available for the documentation workflow.
- `main` is protected, clean, and passing its required CI checks.
- `RELEASE_PLEASE_TOKEN` is a narrowly scoped token that can update the Release
  Please branch and trigger CI for the generated lockfile commit.

The publishing workflow uses GitHub OIDC. Do not add a long-lived PyPI token to
the repository or workflow.

## Prepare the release

1. Create a release branch from an up-to-date `main`.
2. Choose a new semantic version. Synchronize the workspace, both packages,
   both source-version constants, `CITATION.cff`, the exact
   `ravage-schemas` dependency, the lockfile, and the Release Please manifest.
3. Move the intended changes from `Unreleased` into a dated changelog entry.
   Release history must describe what was actually published.
4. In one shell, create an isolated release-tool environment and a new artifact
   directory. Change `0.6.0` for later releases:

   ```bash
   export RAVAGE_RELEASE_VERSION=0.6.0
   export RAVAGE_RELEASE_REPO="$(pwd -P)"
   export RAVAGE_RELEASE_ROOT="$(mktemp -d)"
   python3.12 -m venv "${RAVAGE_RELEASE_ROOT}/tools"
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m pip install \
     build==1.6.0 \
     hatchling==1.32.0 \
     mypy==2.1.0 \
     pydantic==2.13.4 \
     pytest==9.0.3 \
     pytest-asyncio==1.3.0 \
     pyyaml==6.0.3 \
     ruff==0.15.14 \
     twine==7.0.0 \
     uv==0.12.5
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m pip install \
     -e packages/schemas -e packages/ravage
   export RAVAGE_RELEASE_DIST="${RAVAGE_RELEASE_ROOT}/dist"
   mkdir -p "${RAVAGE_RELEASE_DIST}/schemas" "${RAVAGE_RELEASE_DIST}/ravage"
   ```

5. Confirm that the lockfile is current and neither package version is occupied
   on production PyPI:

   ```bash
   "${RAVAGE_RELEASE_ROOT}/tools/bin/uv" lock --check
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" scripts/check_release.py
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" scripts/check_pypi_version.py
   ```

6. Run the same consumer checks used by CI:

   ```bash
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" scripts/check_docs.py
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" scripts/check_clean_install.py
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m pytest -m "not integration" -q
   RAVAGE_REQUIRE_DOCKER_INTEGRATION=1 \
     "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m pytest -m integration -q
   ```

7. Build both projects with the installed, pinned backend. Validate and hash
   every artifact. `pip hash` is portable across Linux and macOS:

   ```bash
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m build --no-isolation \
     packages/schemas --outdir "${RAVAGE_RELEASE_DIST}/schemas"
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m build --no-isolation \
     packages/ravage --outdir "${RAVAGE_RELEASE_DIST}/ravage"
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m twine check \
     "${RAVAGE_RELEASE_DIST}"/schemas/* \
     "${RAVAGE_RELEASE_DIST}"/ravage/*
   "${RAVAGE_RELEASE_ROOT}/tools/bin/python" -m pip hash \
     "${RAVAGE_RELEASE_DIST}"/schemas/* \
     "${RAVAGE_RELEASE_DIST}"/ravage/*
   ```

8. From an unrelated directory, install the two built wheels into a fresh
   Python 3.12 environment and run a bounded, model-free bundled-lab smoke. This
   uses one deterministic probe with a ten-second probe timeout and no provider
   credentials:

   ```bash
   export RAVAGE_SMOKE_ROOT="$(mktemp -d)"
   python3.12 -m venv "${RAVAGE_SMOKE_ROOT}/venv"
   "${RAVAGE_SMOKE_ROOT}/venv/bin/python" -m pip install \
     "${RAVAGE_RELEASE_DIST}"/schemas/*.whl \
     "${RAVAGE_RELEASE_DIST}"/ravage/*.whl
   cleanup_release_smoke() {
     "${RAVAGE_SMOKE_ROOT}/venv/bin/ravage" lab down ravage-acme-box \
       >/dev/null 2>&1 || true
   }
   trap cleanup_release_smoke EXIT
   cd "${RAVAGE_SMOKE_ROOT}"
   ./venv/bin/ravage doctor --json >doctor.json
   ./venv/bin/ravage lab list
   ./venv/bin/ravage lab up ravage-acme-box
   ./venv/bin/ravage init http://127.0.0.1:8088 \
     --brief brief.yaml \
     --env-file .env.ravage \
     --description "Bundled local release smoke target"
   ./venv/bin/ravage scan brief.yaml \
     --run-dir scan \
     --probe surface_map \
     --timeout-seconds 10 \
     --report
   ./venv/bin/ravage audit verify scan
   ./venv/bin/ravage observe scan --json >observer.json
   cleanup_release_smoke
   trap - EXIT
   cd "${RAVAGE_RELEASE_REPO}"
   ```

   The earlier `check_clean_install.py` invocation also launches the installed
   observer HTTP UI and fetches its HTML, JavaScript, CSS, and logo from outside
   the checkout.

## Rehearse and publish

Rehearse both packages through the separately gated TestPyPI workflow before
the production release. Run it from the reviewed release branch and supply the
exact version:

```bash
gh workflow run publish-testpypi.yml \
  --ref "$(git branch --show-current)" \
  -f version="${RAVAGE_RELEASE_VERSION}"
```

Approve only the `testpypi` environment deployment. The workflow refuses an
occupied TestPyPI version, builds with the pinned backend, publishes through
TestPyPI OIDC, downloads only those published wheels from TestPyPI, installs
runtime dependencies from production PyPI, and repeats the bounded model-free
lab smoke from an unrelated directory. It has no production repository URL or
production environment.

Optionally run the production workflow as a non-publishing dry run from the
same branch:

```bash
gh workflow run publish-pypi.yml --ref "$(git branch --show-current)"
```

Production publishing jobs require a GitHub `release` event; a manual dispatch
can test and build artifacts but cannot publish them.

For the `0.6.0` relaunch, the reviewed preparation PR carries the synchronized
version because it establishes the new Release Please baseline. After that PR
merges, create the reviewed `v0.6.0` GitHub release from the exact `main`
commit. For subsequent versions, use the Release Please workflow to create the
version PR and GitHub release. When Release Please creates or updates its PR,
the workflow installs `uv==0.12.5`, runs `uv lock`, validates
`scripts/check_release.py`, and commits the synchronized `uv.lock` to that PR.
Do not merge the generated PR until that lockfile commit and all required CI
checks are present.

Publishing a non-prerelease GitHub release triggers `publish-pypi.yml`. The
workflow requires the peeled release tag commit to equal the current
`origin/main` commit, serializes attempts for the release ref, tests once,
publishes `ravage-schemas` first, and publishes `ravage` only after the schema
package succeeds.

If `ravage-schemas` publishes but the final `ravage` upload fails, use GitHub's
**Re-run failed jobs** action on that same workflow run. Do not re-run every job
or create a second release: the successful immutable schema upload must remain
the dependency for the retried `ravage` job.

Do not manually upload local artifacts to production PyPI.

## Verify the public release

After publishing:

1. Compare the PyPI wheel and source-distribution SHA-256 digests with the
   workflow artifacts.
2. Verify the PyPI provenance links point to the expected repository, workflow,
   tag, and commit.
3. Run `pip install --no-cache-dir ravage==VERSION` in a fresh Python 3.12
   environment on Linux and macOS.
4. Repeat `doctor`, lab listing, observer, deterministic scan, and bounded
   model-free lab smoke tests from an unrelated directory.
5. Confirm the GitHub release, tag, changelog, package metadata, documentation,
   and `ravage --help` all show the same version and support status.

## Retiring a broken release

Prefer yanking over deletion. PyPI documents yanking as the non-destructive
alternative: normal dependency resolution ignores the release, while exact
pins and existing lockfiles can remain reproducible. Deletion is permanent and
breaks pinned downstream installations.

Publish and verify the replacement first. Then yank both matching Ravage
packages with a clear reason and replacement version. Delete an artifact only
for an exceptional incident where preserving it is more harmful than breaking
reproducibility.

The historical `0.5.0` artifacts were published on 2026-07-14 and do not match
the later source tree that also identified itself as `0.5.0`. Do not reuse that
version. Once `0.6.0` is verified, yank both `0.5.0` releases with a reason that
directs users to `0.6.0`.

References:

- [PyPI yanking documentation](https://docs.pypi.org/project-management/yanking/)
- [PyPI deletion warning](https://docs.pypi.org/project-management/storage-limits/#freeing-up-storage-on-an-existing-project)
