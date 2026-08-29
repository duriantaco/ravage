from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class KnowledgeSkill:
    name: str
    description: str
    body: str
    path: Path
    sha256: str
    report_count: int | None = None


@dataclass(frozen=True)
class KnowledgePackMetadata:
    path: str
    skill_count: int
    sha256: str
    schema_version: str = "ravage.knowledge-pack.v1"

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "path": self.path,
            "skill_count": self.skill_count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class KnowledgePack:
    root: Path
    skills: tuple[KnowledgeSkill, ...]
    metadata: KnowledgePackMetadata


@dataclass(frozen=True)
class KnowledgeCard:
    name: str
    description: str
    score: int
    mapped_probes: tuple[str, ...]
    guidance: str
    sha256: str
    report_count: int | None = None
    authority: str = "advisory"

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "description": self.description,
            "score": self.score,
            "mapped_probes": list(self.mapped_probes),
            "guidance": self.guidance,
            "sha256": self.sha256,
            "authority": self.authority,
        }
        if self.report_count is not None:
            payload["report_count"] = self.report_count
        return payload
