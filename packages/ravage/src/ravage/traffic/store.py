# ruff: noqa: EM101, EM102, TRY003
"""Private, append-only JSONL persistence for safe HTTP traffic contracts."""

from __future__ import annotations

import importlib
import json
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from .contracts import (
    CapturedHttpExchange,
    ReplayReceipt,
    RequestContract,
    TrafficContractError,
    aggregate_request_contracts,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping

_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIRECTORY_MODE = 0o700
_MAX_RECORD_BYTES = 65_536
_READ_CHUNK_BYTES = 65_536
_MAX_TRAFFIC_RECORDS = 50_000
_MAX_TRAFFIC_FILE_BYTES = 64 * 1_024 * 1_024

_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}


class _PosixLockModule(Protocol):
    LOCK_EX: int
    LOCK_SH: int
    LOCK_UN: int

    def flock(self, descriptor: int, operation: int) -> None: ...


class TrafficStoreError(RuntimeError):
    """Raised when the traffic store cannot preserve its safety invariants."""


class TrafficStore:
    """Thread-safe traffic persistence rooted at ``workspace/traffic``."""

    def __init__(
        self,
        workspace_dir: Path,
        *,
        create: bool,
        writable: bool,
        require_empty: bool = False,
    ) -> None:
        if os.name != "posix":
            raise TrafficStoreError(
                "traffic storage requires a POSIX filesystem; on Windows, use WSL"
            )
        self.workspace_dir = Path(workspace_dir)
        self.root = self.workspace_dir / "traffic"
        self.exchanges_path = self.root / "exchanges.jsonl"
        self.replays_path = self.root / "replay-receipts.jsonl"
        self.lock_path = self.root / ".store.lock"
        self._writable = writable
        self._lock = _path_lock(self.root)
        with self._lock:
            if create:
                self._create(require_empty=require_empty)
            else:
                self._verify_existing()

    @classmethod
    def create(
        cls,
        workspace_dir: Path,
        *,
        require_empty: bool = True,
    ) -> TrafficStore:
        """Create a writable store, optionally rejecting any prior traffic state."""
        return cls(
            workspace_dir,
            create=True,
            writable=True,
            require_empty=require_empty,
        )

    @classmethod
    def open(cls, workspace_dir: Path, *, writable: bool = False) -> TrafficStore:
        """Open an existing store without mutating it unless explicitly writable."""
        return cls(workspace_dir, create=False, writable=writable)

    def _create(self, *, require_empty: bool) -> None:
        if self.root.is_symlink():
            raise TrafficStoreError("traffic store directory cannot be a symlink")
        if require_empty and self.root.exists():
            try:
                has_prior_state = any(self.root.iterdir())
            except OSError as exc:
                raise TrafficStoreError(f"could not inspect traffic store: {exc}") from exc
            if has_prior_state:
                raise TrafficStoreError("traffic store already contains prior run state")
        self.root.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
        _verify_directory(self.root)
        self.root.chmod(_PRIVATE_DIRECTORY_MODE)
        _ensure_private_file(self.exchanges_path)
        _ensure_private_file(self.replays_path)
        _ensure_private_file(self.lock_path)

    def _verify_existing(self) -> None:
        if self.root.is_symlink():
            raise TrafficStoreError("traffic store directory cannot be a symlink")
        _verify_directory(self.root)
        _verify_private_file(self.exchanges_path)
        _verify_private_file(self.replays_path)
        _verify_private_file(self.lock_path, enforce_size=False)

    def append_exchange(self, exchange: CapturedHttpExchange) -> CapturedHttpExchange:
        """Assign an exchange ID and atomically append one safe capture."""
        self._require_writable()
        if exchange.exchange_id or exchange.sequence:
            raise TrafficStoreError("exchange already has a store identity")
        with self._lock, _store_file_lock(self.lock_path, exclusive=True):
            sequence = _next_sequence_from_tail(self.exchanges_path, prefix="rq")
            _validate_record_ceiling(sequence)
            stored = exchange.with_store_identity(
                exchange_id=f"rq_{sequence:04d}",
                sequence=sequence,
            )
            _append_json_line(self.exchanges_path, stored.to_json())
            return stored

    def append_replay(self, receipt: ReplayReceipt) -> ReplayReceipt:
        """Assign a replay ID and atomically append one replay receipt."""
        self._require_writable()
        if receipt.replay_id or receipt.sequence:
            raise TrafficStoreError("replay receipt already has a store identity")
        with self._lock, _store_file_lock(self.lock_path, exclusive=True):
            _validate_replay_sources((receipt,), self._load_exchanges_unlocked())
            sequence = _next_sequence_from_tail(self.replays_path, prefix="rp")
            _validate_record_ceiling(sequence)
            stored = receipt.with_store_identity(
                replay_id=f"rp_{sequence:04d}",
                sequence=sequence,
            )
            _append_json_line(self.replays_path, stored.to_json())
            return stored

    def reserve_replay_dispatch(
        self,
        receipt: ReplayReceipt,
    ) -> tuple[ReplayReceipt, bool]:
        """Atomically reserve the only network dispatch for one captured request."""
        self._require_writable()
        if receipt.replay_id or receipt.sequence:
            raise TrafficStoreError("replay dispatch reservation already has a store identity")
        if receipt.outcome != "dispatch_reserved" or receipt.request_sent:
            raise TrafficStoreError("invalid replay dispatch reservation")
        with self._lock, _store_file_lock(self.lock_path, exclusive=True):
            exchanges = self._load_exchanges_unlocked()
            _validate_replay_sources((receipt,), exchanges)
            prior = next(
                (
                    item
                    for item in self._load_replays_unlocked()
                    if item.source_exchange_id == receipt.source_exchange_id
                    and (item.outcome == "dispatch_reserved" or item.request_sent)
                ),
                None,
            )
            if prior is not None:
                return prior, False
            sequence = _next_sequence_from_tail(self.replays_path, prefix="rp")
            _validate_record_ceiling(sequence)
            stored = receipt.with_store_identity(
                replay_id=f"rp_{sequence:04d}",
                sequence=sequence,
            )
            _append_json_line(self.replays_path, stored.to_json())
            return stored, True

    def _require_writable(self) -> None:
        if not self._writable:
            raise TrafficStoreError("traffic store was opened read-only")

    def exchanges(self) -> tuple[CapturedHttpExchange, ...]:
        """Load captured exchanges in store sequence order."""
        with self._lock, _store_file_lock(self.lock_path, exclusive=False):
            return self._load_exchanges_unlocked()

    def replay_receipts(self) -> tuple[ReplayReceipt, ...]:
        """Load replay receipts in store sequence order."""
        with self._lock, _store_file_lock(self.lock_path, exclusive=False):
            return self._load_replays_unlocked()

    def contracts(self) -> tuple[RequestContract, ...]:
        """Aggregate all captures into deterministic request contracts."""
        with self._lock, _store_file_lock(self.lock_path, exclusive=False):
            return aggregate_request_contracts(self._load_exchanges_unlocked())

    def contract(self, semantic_fingerprint: str) -> RequestContract | None:
        """Return one aggregated contract by its semantic fingerprint."""
        return next(
            (
                contract
                for contract in self.contracts()
                if contract.semantic_fingerprint == semantic_fingerprint
            ),
            None,
        )

    def exchange(self, exchange_id: str) -> CapturedHttpExchange | None:
        """Return one stored exchange by its assigned ID."""
        return next(
            (exchange for exchange in self.exchanges() if exchange.exchange_id == exchange_id),
            None,
        )

    def _load_exchanges_unlocked(self) -> tuple[CapturedHttpExchange, ...]:
        records = _load_json_lines(self.exchanges_path)
        try:
            exchanges = tuple(CapturedHttpExchange.from_json(record) for record in records)
        except TrafficContractError as exc:
            raise TrafficStoreError(f"invalid captured exchange: {exc}") from exc
        _validate_sequences(
            ((exchange.sequence, exchange.exchange_id) for exchange in exchanges),
            prefix="rq",
        )
        return exchanges

    def _load_replays_unlocked(self) -> tuple[ReplayReceipt, ...]:
        records = _load_json_lines(self.replays_path)
        try:
            receipts = tuple(ReplayReceipt.from_json(record) for record in records)
        except TrafficContractError as exc:
            raise TrafficStoreError(f"invalid replay receipt: {exc}") from exc
        _validate_sequences(
            ((receipt.sequence, receipt.replay_id) for receipt in receipts),
            prefix="rp",
        )
        _validate_replay_sources(receipts, self._load_exchanges_unlocked())
        return receipts


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.absolute())
    with _LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


def _verify_directory(path: Path) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise TrafficStoreError(f"could not inspect traffic store directory: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise TrafficStoreError("traffic store path is not a directory")
    if metadata.st_mode & 0o077:
        raise TrafficStoreError("traffic store directory permissions must be owner-only")


def _verify_private_file(path: Path, *, enforce_size: bool = True) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TrafficStoreError(f"could not open traffic file {path.name}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_private_metadata(metadata, path.name, enforce_size=enforce_size)
    finally:
        os.close(descriptor)


def _ensure_private_file(path: Path) -> None:
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        raise TrafficStoreError(f"could not open private traffic file {path.name}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TrafficStoreError(f"traffic path is not a regular file: {path.name}")
        if metadata.st_nlink != 1:
            raise TrafficStoreError(f"traffic file must not be hard-linked: {path.name}")
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)


def _append_json_line(path: Path, payload: Mapping[str, object]) -> None:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_RECORD_BYTES:
        raise TrafficStoreError("traffic record exceeds the bounded JSONL record size")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        raise TrafficStoreError(f"could not append traffic record: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_private_metadata(metadata, path.name)
        if metadata.st_size + len(encoded) > _MAX_TRAFFIC_FILE_BYTES:
            raise TrafficStoreError("traffic store reached its 64 MiB file safety limit")
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise TrafficStoreError("traffic record append was incomplete")
        os.fsync(descriptor)
    except OSError as exc:
        raise TrafficStoreError(f"could not persist traffic record: {exc}") from exc
    finally:
        os.close(descriptor)


def _load_json_lines(path: Path) -> tuple[Mapping[str, object], ...]:
    raw = _read_private_file(path)
    records: list[Mapping[str, object]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        if len(records) >= _MAX_TRAFFIC_RECORDS:
            raise TrafficStoreError(
                f"traffic store exceeds its {_MAX_TRAFFIC_RECORDS}-record safety limit"
            )
        if len(line.encode("utf-8")) > _MAX_RECORD_BYTES:
            raise TrafficStoreError(f"traffic record {line_number} exceeds the size limit")
        try:
            payload = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise TrafficStoreError(f"invalid traffic JSON on line {line_number}: {exc}") from exc
        if not isinstance(payload, dict):
            raise TrafficStoreError(f"traffic record {line_number} must be an object")
        records.append({str(key): value for key, value in payload.items()})
    return tuple(records)


def _read_private_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TrafficStoreError(f"could not read private traffic file {path.name}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_private_metadata(metadata, path.name)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            chunks.append(chunk)
    except OSError as exc:
        raise TrafficStoreError(f"could not read traffic file: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrafficStoreError("traffic file is not valid UTF-8") from exc


def _next_sequence_from_tail(path: Path, *, prefix: str) -> int:
    """Read only the final bounded JSONL record on the append hot path."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TrafficStoreError(f"could not read traffic sequence: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_private_metadata(metadata, path.name)
        if metadata.st_size == 0:
            return 1
        start = max(0, metadata.st_size - (_MAX_RECORD_BYTES + 1))
        os.lseek(descriptor, start, os.SEEK_SET)
        raw = os.read(descriptor, _MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise TrafficStoreError(f"could not read traffic sequence: {exc}") from exc
    finally:
        os.close(descriptor)
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        return 1
    try:
        payload = json.loads(lines[-1])
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TrafficStoreError("last traffic record is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise TrafficStoreError("last traffic record must be an object")
    sequence = payload.get("sequence")
    identifier = payload.get("exchange_id" if prefix == "rq" else "replay_id")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or identifier != f"{prefix}_{sequence:04d}"
    ):
        raise TrafficStoreError("last traffic record sequence is invalid")
    return sequence + 1


@contextmanager
def _store_file_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    # Windows' byte-range locking requires a read/write descriptor. Using the
    # same mode on POSIX keeps this path consistent without changing the file.
    flags = os.O_RDWR
    try:
        descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TrafficStoreError(f"could not open traffic store lock: {exc}") from exc
    try:
        _validate_private_metadata(os.fstat(descriptor), path.name, enforce_size=False)
        _acquire_file_lock(descriptor, exclusive=exclusive)
    except OSError as exc:
        os.close(descriptor)
        raise TrafficStoreError(f"could not lock traffic store: {exc}") from exc
    try:
        yield
    finally:
        try:
            _release_file_lock(descriptor)
        finally:
            os.close(descriptor)


def _acquire_file_lock(descriptor: int, *, exclusive: bool) -> None:
    """Acquire a process lock without importing a platform-incompatible module."""
    fcntl = cast("_PosixLockModule", importlib.import_module("fcntl"))
    fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)


def _release_file_lock(descriptor: int) -> None:
    """Release the platform lock acquired by :func:`_acquire_file_lock`."""
    fcntl = cast("_PosixLockModule", importlib.import_module("fcntl"))
    fcntl.flock(descriptor, fcntl.LOCK_UN)


def _validate_private_metadata(
    metadata: os.stat_result,
    name: str,
    *,
    enforce_size: bool = True,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise TrafficStoreError(f"traffic path is not a regular file: {name}")
    if metadata.st_nlink != 1:
        raise TrafficStoreError(f"traffic file must not be hard-linked: {name}")
    if metadata.st_mode & 0o077:
        raise TrafficStoreError(f"traffic file permissions must be owner-only: {name}")
    if enforce_size and metadata.st_size > _MAX_TRAFFIC_FILE_BYTES:
        raise TrafficStoreError(f"traffic file exceeds the 64 MiB safety limit: {name}")


def _validate_record_ceiling(sequence: int) -> None:
    if sequence > _MAX_TRAFFIC_RECORDS:
        raise TrafficStoreError(
            f"traffic store reached its {_MAX_TRAFFIC_RECORDS}-record safety limit"
        )


def _validate_sequences(records: Iterable[tuple[int, str]], *, prefix: str) -> None:
    expected = 1
    for sequence, record_id in records:
        if sequence != expected or record_id != f"{prefix}_{sequence:04d}":
            raise TrafficStoreError("traffic store sequence is not contiguous")
        expected += 1


def _validate_replay_sources(
    receipts: Iterable[ReplayReceipt],
    exchanges: Iterable[CapturedHttpExchange],
) -> None:
    sources = {exchange.exchange_id: exchange for exchange in exchanges}
    for receipt in receipts:
        source = sources.get(receipt.source_exchange_id)
        if source is None:
            raise TrafficStoreError("replay source exchange is not present in this store")
        if receipt.capture_session_id != source.capture_session_id:
            raise TrafficStoreError("replay capture session does not match its source exchange")
        if receipt.request_semantic_fingerprint != source.semantic_fingerprint:
            raise TrafficStoreError("replay request fingerprint does not match its source exchange")


__all__ = ["TrafficStore", "TrafficStoreError"]
