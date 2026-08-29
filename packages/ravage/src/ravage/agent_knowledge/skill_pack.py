from __future__ import annotations

# Validation failures intentionally carry precise operator-facing paths and
# reasons. Local construction keeps the fail-closed branches auditable.
# ruff: noqa: EM101, EM102, TRY003
import hashlib
import hmac
import os
import re
import stat
from contextlib import suppress
from functools import lru_cache
from pathlib import Path

from ravage.agent_knowledge.frontmatter import FrontmatterError, parse_frontmatter
from ravage.agent_knowledge.models import KnowledgePack, KnowledgePackMetadata, KnowledgeSkill
from ravage.overfit_guard import scan_text

KNOWLEDGE_PACK_SCHEMA = "ravage.knowledge-pack.v1"
BUILTIN_KNOWLEDGE_PACK_PATH = Path(__file__).with_name("builtin")

_ALLOWED_FRONTMATTER_FIELDS = frozenset({"name", "description", "report_count"})
_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_PACK_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_SKILLS = 64
_MAX_SKILL_FILE_BYTES = 64 * 1024
_MAX_SKILL_BODY_CHARS = 32_000
_MAX_DESCRIPTION_CHARS = 1_000
_MAX_SKILL_NAME_CHARS = 64
_ASCII_CONTROL_LIMIT = 32


def describe_knowledge_pack(
    path: Path | None,
    *,
    expected_sha256: str | None = None,
) -> KnowledgePackMetadata | None:
    if path is None:
        if expected_sha256 is not None:
            raise ValueError("a knowledge-pack digest requires a knowledge-pack path")
        return None
    return load_skill_pack(path, expected_sha256=expected_sha256).metadata


def load_skill_pack(path: Path, *, expected_sha256: str | None = None) -> KnowledgePack:
    root = _resolve_pack_root(path)
    pack = _load_skill_pack(str(root))
    if expected_sha256 is not None:
        expected = normalize_knowledge_pack_sha256(expected_sha256)
        if not hmac.compare_digest(pack.metadata.sha256, expected):
            raise ValueError("knowledge pack does not match the expected SHA-256 digest")
    return pack


def normalize_knowledge_pack_sha256(value: str) -> str:
    digest = str(value or "").strip().lower().removeprefix("sha256:")
    if _PACK_DIGEST_RE.fullmatch(digest) is None:
        raise ValueError("knowledge-pack SHA-256 must be 64 lowercase hexadecimal characters")
    return digest


def clear_knowledge_pack_cache() -> None:
    """Clear process-local immutable pack snapshots for tests and explicit reloads."""
    _load_skill_pack.cache_clear()


@lru_cache(maxsize=8)
def _load_skill_pack(path_text: str) -> KnowledgePack:
    root = Path(path_text)
    _verify_pack_root(root)
    skill_files = tuple(_iter_skill_files(root))
    if not skill_files:
        message = f"knowledge pack has no SKILL.md files: {root}"
        raise ValueError(message)

    skills: list[KnowledgeSkill] = []
    names: set[str] = set()
    digest = hashlib.sha256(f"{KNOWLEDGE_PACK_SCHEMA}\0".encode())
    relative_root = root if root.is_dir() else root.parent
    for path in skill_files:
        raw = _read_skill_file(path)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"knowledge skill is not UTF-8: {path}") from exc
        if scan_text(path, text):
            raise ValueError(f"knowledge skill violates the anti-overfit policy: {path}")
        relative = path.relative_to(relative_root)
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(raw)
        try:
            metadata, body = parse_frontmatter(text)
        except FrontmatterError as exc:
            raise ValueError(f"invalid knowledge skill frontmatter: {path}: {exc}") from exc
        unexpected = set(metadata) - _ALLOWED_FRONTMATTER_FIELDS
        if unexpected:
            raise ValueError(f"knowledge skill contains unsupported frontmatter fields: {path}")
        name = _skill_name(metadata.get("name"), path=path)
        if name != path.parent.name:
            raise ValueError(f"knowledge skill name must match its directory: {path}")
        if name in names:
            raise ValueError(f"knowledge pack contains a duplicate skill name: {name}")
        names.add(name)
        description = _description(metadata.get("description"), path=path)
        guidance = _skill_body(body, path=path)
        skills.append(
            KnowledgeSkill(
                name=name,
                description=description,
                body=guidance,
                path=path,
                sha256=hashlib.sha256(raw).hexdigest(),
                report_count=_optional_int(metadata.get("report_count"), path=path),
            )
        )

    skills.sort(key=lambda item: item.name)
    pack_metadata = KnowledgePackMetadata(
        path=str(root),
        skill_count=len(skills),
        sha256=digest.hexdigest(),
        schema_version=KNOWLEDGE_PACK_SCHEMA,
    )
    return KnowledgePack(root=root, skills=tuple(skills), metadata=pack_metadata)


def _resolve_pack_root(path: Path) -> Path:
    candidate = BUILTIN_KNOWLEDGE_PACK_PATH if str(path) == "builtin" else path.expanduser()
    try:
        item_stat = candidate.lstat()
    except OSError as exc:
        raise FileNotFoundError(f"knowledge pack path does not exist: {candidate}") from exc
    if stat.S_ISLNK(item_stat.st_mode):
        raise ValueError("knowledge pack path must not be a symlink")
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise FileNotFoundError(f"knowledge pack path does not exist: {candidate}") from exc


def _verify_pack_root(root: Path) -> None:
    try:
        item_stat = root.lstat()
    except OSError as exc:
        raise FileNotFoundError(f"knowledge pack path does not exist: {root}") from exc
    if stat.S_ISLNK(item_stat.st_mode) or not (
        stat.S_ISREG(item_stat.st_mode) or stat.S_ISDIR(item_stat.st_mode)
    ):
        raise ValueError("knowledge pack root must be a regular file or directory")
    if stat.S_IMODE(item_stat.st_mode) & 0o022:
        raise ValueError("knowledge pack root must not be group- or world-writable")


def _iter_skill_files(root: Path) -> list[Path]:
    if root.is_file():
        if root.name != "SKILL.md":
            raise ValueError("knowledge pack file must be named SKILL.md")
        return [root]
    direct = root / "SKILL.md"
    if direct.exists() or direct.is_symlink():
        return [direct]

    skills: list[Path] = []
    for entry in sorted(root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink():
            raise ValueError("knowledge pack must not contain symlinked skill entries")
        if not entry.is_dir():
            continue
        if stat.S_IMODE(entry.stat().st_mode) & 0o022:
            raise ValueError("knowledge skill directory must not be group- or world-writable")
        skill_file = entry / "SKILL.md"
        if skill_file.exists() or skill_file.is_symlink():
            skills.append(skill_file)
        if len(skills) > _MAX_SKILLS:
            raise ValueError("knowledge pack exceeds the skill-count limit")
    return skills


def _read_skill_file(path: Path) -> bytes:
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        descriptor_stat = os.fstat(descriptor)
        path_stat = path.lstat()
        _validate_open_skill_file(
            descriptor_stat=descriptor_stat,
            path_stat=path_stat,
            path_is_symlink=path.is_symlink(),
        )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(_MAX_SKILL_FILE_BYTES + 1)
            final_descriptor_stat = os.fstat(stream.fileno())
            try:
                final_path_stat = path.lstat()
            except OSError as exc:
                raise ValueError(
                    f"knowledge skill changed while it was being read: {path}"
                ) from exc
            _validate_open_skill_file(
                descriptor_stat=final_descriptor_stat,
                path_stat=final_path_stat,
                path_is_symlink=stat.S_ISLNK(final_path_stat.st_mode),
            )
            if (
                _skill_file_version(final_descriptor_stat) != _skill_file_version(descriptor_stat)
                or len(content) != final_descriptor_stat.st_size
            ):
                raise ValueError(  # noqa: TRY301 - normalize the descriptor-race boundary.
                    f"knowledge skill changed while it was being read: {path}"
                )
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot read knowledge skill file: {path}") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    if not content or len(content) > _MAX_SKILL_FILE_BYTES:
        raise ValueError("knowledge skill file is empty or exceeds the size limit")
    return content


def _validate_open_skill_file(
    *,
    descriptor_stat: os.stat_result,
    path_stat: os.stat_result,
    path_is_symlink: bool,
) -> None:
    if (
        path_is_symlink
        or not stat.S_ISREG(descriptor_stat.st_mode)
        or descriptor_stat.st_nlink != 1
        or stat.S_IMODE(descriptor_stat.st_mode) & 0o022
        or descriptor_stat.st_dev != path_stat.st_dev
        or descriptor_stat.st_ino != path_stat.st_ino
        or descriptor_stat.st_size <= 0
        or descriptor_stat.st_size > _MAX_SKILL_FILE_BYTES
    ):
        raise ValueError("knowledge skill file is unsafe or exceeds the size limit")


def _skill_file_version(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _skill_name(value: object, *, path: Path) -> str:
    name = str(value or "").strip()
    if len(name) > _MAX_SKILL_NAME_CHARS or _SKILL_NAME_RE.fullmatch(name) is None:
        raise ValueError(f"knowledge skill has an invalid name: {path}")
    return name


def _description(value: object, *, path: Path) -> str:
    description = str(value or "").strip()
    if not description or len(description) > _MAX_DESCRIPTION_CHARS:
        raise ValueError(f"knowledge skill has an invalid description: {path}")
    if _contains_unsafe_control(description):
        raise ValueError(f"knowledge skill description contains a control character: {path}")
    return description


def _skill_body(value: str, *, path: Path) -> str:
    body = value.strip()
    if not body or len(body) > _MAX_SKILL_BODY_CHARS:
        raise ValueError(f"knowledge skill body is empty or exceeds the size limit: {path}")
    if _contains_unsafe_control(body):
        raise ValueError(f"knowledge skill body contains a control character: {path}")
    return body


def _contains_unsafe_control(value: str) -> bool:
    return any(
        ord(character) < _ASCII_CONTROL_LIMIT and character not in {"\n", "\r", "\t"}
        for character in value
    )


def _optional_int(value: object, *, path: Path) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"knowledge skill report_count is invalid: {path}")  # noqa: TRY004
    try:
        parsed = int(str(value))
    except ValueError as exc:
        raise ValueError(f"knowledge skill report_count is invalid: {path}") from exc
    if parsed < 0:
        raise ValueError(f"knowledge skill report_count is invalid: {path}")
    return parsed


__all__ = [
    "BUILTIN_KNOWLEDGE_PACK_PATH",
    "KNOWLEDGE_PACK_SCHEMA",
    "clear_knowledge_pack_cache",
    "describe_knowledge_pack",
    "load_skill_pack",
    "normalize_knowledge_pack_sha256",
]
