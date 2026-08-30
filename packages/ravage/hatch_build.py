from __future__ import annotations

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Bundle monorepo-owned runtime resources into distributions."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, object]) -> None:  # noqa: ARG002
        project_root = Path(self.root).resolve()
        package_resources = project_root / "src" / "ravage" / "_resources"
        source_resources = _source_resources(project_root)

        # Wheels built from an sdist already contain resources under src/ravage.
        if not source_resources and package_resources.is_dir():
            return
        if not source_resources:
            msg = "Ravage release resources are missing from the source checkout"
            raise RuntimeError(msg)

        destination_root = (
            "ravage/_resources" if self.target_name == "wheel" else "src/ravage/_resources"
        )
        force_include = build_data.setdefault("force_include", {})
        if not isinstance(force_include, dict):
            msg = "Hatch force_include build data must be a mapping"
            raise TypeError(msg)
        for source, destination in source_resources.items():
            force_include[str(source)] = f"{destination_root}/{destination}"


def _source_resources(project_root: Path) -> dict[Path, str]:
    repository_root = project_root.parents[1]
    cockpit_root = project_root.parent / "ravage-cockpit"
    labs_root = repository_root / "examples" / "labs"
    candidates = {
        cockpit_root / "index.html": "cockpit/index.html",
        cockpit_root / "src": "cockpit/src",
        repository_root / "assets" / "ravage_logo.png": "assets/ravage_logo.png",
        **{
            labs_root / lab_id: f"labs/{lab_id}"
            for lab_id in (
                "ravage-acme-box",
                "ravage-forgeops-box",
                "ravage-node-market-box",
                "ravage-perimeter-box",
                "ravage-session-boundary-box",
            )
        },
    }
    if all(path.exists() for path in candidates):
        return candidates
    return {}
