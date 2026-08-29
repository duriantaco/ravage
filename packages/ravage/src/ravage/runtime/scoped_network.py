from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import ParseResult, urlunparse

from ravage.web_core.scope_policy import is_local_host

from .common import assert_tool_target_url, clip

SCOPED_TARGET_ALIAS = "ravage-target"
SESSION_LABEL = "io.ravage.tool-session"
KIND_LABEL = "io.ravage.tool-kind"
FORWARDER_CONFIG_MOUNT = "/ravage-forwarder"

_FORWARDER_DIR_PREFIX = "ravage-forwarder-"
_LOW_FORWARD_PORT_START = 40000
_MAX_TCP_PORT = 65535

_FORWARDER_SOURCE = r'''from __future__ import annotations

import json
import socket
import sys
import threading


def pump(source, destination):
    try:
        while data := source.recv(65536):
            destination.sendall(data)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def relay(client, destination_host, destination_port):
    upstream = socket.create_connection((destination_host, destination_port), timeout=10)
    upstream.settimeout(None)
    client_to_upstream = threading.Thread(target=pump, args=(client, upstream), daemon=True)
    client_to_upstream.start()
    try:
        pump(upstream, client)
        client_to_upstream.join(timeout=5)
    finally:
        upstream.close()
        client.close()


def serve(route):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", int(route["listen_port"])))
    listener.listen(64)
    while True:
        client, _ = listener.accept()
        thread = threading.Thread(
            target=relay,
            args=(client, route["destination_host"], int(route["destination_port"])),
            daemon=True,
        )
        thread.start()


with open(sys.argv[1], encoding="utf-8") as handle:
    routes = json.load(handle)["routes"]
if not routes:
    raise SystemExit("no forwarding routes configured")
threads = [threading.Thread(target=serve, args=(route,), daemon=True) for route in routes]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
'''


class ScopedNetworkError(RuntimeError):
    pass


@dataclass(frozen=True)
class ForwardRoute:
    target_host: str
    destination_host: str
    destination_port: int
    listen_port: int
    remote: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "listen_port": self.listen_port,
            "target_host": self.target_host,
            "destination_host": self.destination_host,
            "destination_port": self.destination_port,
            "remote": self.remote,
        }


class ScopedDockerNetwork:
    def __init__(
        self,
        *,
        image: str,
        scope: object,
        session_id: str,
        evidence_path: str | Path | None = None,
        allow_remote_target: bool = False,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
    ) -> None:
        self.image = image
        self.session_id = _validate_session_id(session_id)
        self.session_key = _session_key(self.session_id)
        self.evidence_path = Path(evidence_path) if evidence_path is not None else None
        self.allow_remote_target = allow_remote_target
        self.network_name = f"ravage-tool-net-{self.session_key}"
        self.gateway_name = f"ravage-target-{self.session_key}"
        self.routes = _routes_from_scope(
            scope,
            allow_remote_target=allow_remote_target,
            resolver=resolver or _resolve_addresses,
        )
        self._local_route_by_destination = {
            route.destination_port: route for route in self.routes if not route.remote
        }
        self._remote_route_by_target = {
            (route.target_host, route.destination_port): route
            for route in self.routes
            if route.remote
        }
        remote_aliases = [
            route.target_host
            for route in self.routes
            if route.remote and not _is_ip_literal(route.target_host)
        ]
        self.gateway_aliases = tuple(dict.fromkeys((SCOPED_TARGET_ALIAS, *remote_aliases)))
        self._forwarder_dir: Path | None = None
        self._started = False
        self._closed = False
        self._tool_index = 0
        self.cleanup_evidence: dict[str, object] | None = None

    @property
    def started(self) -> bool:
        return self._started

    def ensure_started(self) -> None:
        if self._closed:
            raise ScopedNetworkError("scoped Docker network is already closed")
        if self._started:
            return
        try:
            self._forwarder_dir = _write_forwarder_files(self.routes)
            _run_checked(
                (
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    f"{SESSION_LABEL}={self.session_key}",
                    "--label",
                    f"{KIND_LABEL}=network",
                    self.network_name,
                ),
                operation="create isolated tool network",
            )
            _run_checked(self._gateway_run_argv(), operation="start scoped target forwarder")
            alias_args = tuple(
                item for alias in self.gateway_aliases for item in ("--alias", alias)
            )
            _run_checked(
                (
                    "docker",
                    "network",
                    "connect",
                    *alias_args,
                    self.network_name,
                    self.gateway_name,
                ),
                operation="connect target forwarder to isolated tool network",
            )
            self._verify_setup()
            self._started = True
            self._write_setup_evidence(status="succeeded")
        except Exception as exc:
            self._write_setup_evidence(status="error", error=str(exc))
            self.cleanup_evidence = cleanup_scoped_network_session(
                self.session_id,
                evidence_path=self.evidence_path,
            )
            self._cleanup_forwarder_dir()
            if isinstance(exc, ScopedNetworkError):
                raise
            raise ScopedNetworkError(str(exc)) from exc

    def container_url(self, target_url: str) -> str:
        parsed = assert_tool_target_url(
            target_url,
            allow_remote_target=self.allow_remote_target,
        )
        route = self._route_for_parsed(parsed)
        if route.remote and not _is_ip_literal(route.target_host):
            host = _url_host(route.target_host)
        else:
            host = SCOPED_TARGET_ALIAS
        netloc = f"{host}:{route.listen_port}"
        return urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )

    def rewrite_for_container(self, text: str) -> str:
        rewritten = text
        for destination_port, route in self._local_route_by_destination.items():
            listener = route.listen_port
            host_pattern = r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|host\.docker\.internal)"
            rewritten = re.sub(
                rf"(?i)(?P<scheme>https?://){host_pattern}:{destination_port}(?=[/?#\s'\"\\]|$)",
                rf"\g<scheme>{SCOPED_TARGET_ALIAS}:{listener}",
                rewritten,
            )
            rewritten = re.sub(
                rf"(?i)\b{host_pattern}:{destination_port}\b",
                f"{SCOPED_TARGET_ALIAS}:{listener}",
                rewritten,
            )
            rewritten = re.sub(
                rf"(?i)\b{host_pattern}(?P<space>\s+){destination_port}\b",
                rf"{SCOPED_TARGET_ALIAS}\g<space>{listener}",
                rewritten,
            )
        for route in self._remote_route_by_target.values():
            if route.listen_port == route.destination_port and not _is_ip_literal(
                route.target_host
            ):
                continue
            escaped_host = re.escape(route.target_host)
            replacement_host = (
                SCOPED_TARGET_ALIAS
                if _is_ip_literal(route.target_host)
                else route.target_host
            )
            rewritten = re.sub(
                rf"(?i)(?P<scheme>https?://){escaped_host}(?::{route.destination_port})?(?=[/?#\s'\"\\]|$)",
                rf"\g<scheme>{replacement_host}:{route.listen_port}",
                rewritten,
            )
            rewritten = re.sub(
                rf"(?i)\b{escaped_host}:{route.destination_port}\b",
                f"{replacement_host}:{route.listen_port}",
                rewritten,
            )
            rewritten = re.sub(
                rf"(?i)\b{escaped_host}(?P<space>\s+){route.destination_port}\b",
                rf"{replacement_host}\g<space>{route.listen_port}",
                rewritten,
            )
        return rewritten

    def next_tool_container_name(self) -> str:
        self._tool_index += 1
        return f"ravage-tool-{self.session_key}-{self._tool_index}"

    def tool_labels(self) -> tuple[str, ...]:
        return (
            "--label",
            f"{SESSION_LABEL}={self.session_key}",
            "--label",
            f"{KIND_LABEL}=tool",
        )

    def close(self) -> dict[str, object]:
        if self._closed and self.cleanup_evidence is not None:
            return self.cleanup_evidence
        self.cleanup_evidence = cleanup_scoped_network_session(
            self.session_id,
            evidence_path=self.evidence_path,
        )
        self._cleanup_forwarder_dir()
        self._started = False
        self._closed = True
        return self.cleanup_evidence

    def _gateway_run_argv(self) -> tuple[str, ...]:
        if self._forwarder_dir is None:
            raise ScopedNetworkError("forwarder files were not created")
        mount = f"type=bind,src={self._forwarder_dir},dst={FORWARDER_CONFIG_MOUNT},readonly"
        return (
            "docker",
            "run",
            "--detach",
            "--pull=never",
            "--name",
            self.gateway_name,
            "--label",
            f"{SESSION_LABEL}={self.session_key}",
            "--label",
            f"{KIND_LABEL}=gateway",
            "--network",
            "bridge",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65534:65534",
            "--sysctl",
            "net.ipv4.ip_forward=0",
            "--sysctl",
            "net.ipv4.ip_unprivileged_port_start=0",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--mount",
            mount,
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            self.image,
            "python3",
            f"{FORWARDER_CONFIG_MOUNT}/forwarder.py",
            f"{FORWARDER_CONFIG_MOUNT}/routes.json",
        )

    def _route_for_parsed(self, parsed: ParseResult) -> ForwardRoute:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = _normalized_host(parsed.hostname or "")
        if is_local_host(host):
            route = self._local_route_by_destination.get(port)
        else:
            route = self._remote_route_by_target.get((host, port))
        if route is None:
            raise ScopedNetworkError(
                f"target origin {host}:{port} is not in the Docker tool scope"
            )
        return route

    def _verify_setup(self) -> None:
        network = _run_checked(
            ("docker", "network", "inspect", self.network_name),
            operation="inspect isolated tool network",
        )
        gateway = _run_checked(
            ("docker", "inspect", self.gateway_name),
            operation="inspect scoped target forwarder",
        )
        try:
            network_payload = json.loads(network.stdout)
            gateway_payload = json.loads(gateway.stdout)
            network_item = network_payload[0]
            gateway_item = gateway_payload[0]
            internal = network_item["Internal"] is True
            state_running = gateway_item["State"]["Running"] is True
            networks = gateway_item["NetworkSettings"]["Networks"]
            attached = "bridge" in networks and self.network_name in networks
            aliases = networks[self.network_name].get("Aliases") or []
            aliased = all(alias in aliases for alias in self.gateway_aliases)
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ScopedNetworkError("Docker returned malformed isolation inspection data") from exc
        if not internal:
            raise ScopedNetworkError("tool network was not created with Docker Internal=true")
        if not state_running:
            raise ScopedNetworkError("scoped target forwarder exited during setup")
        if not attached or not aliased:
            raise ScopedNetworkError("scoped target forwarder network attachment is incomplete")

    def _write_setup_evidence(self, *, status: str, error: str | None = None) -> None:
        if self.evidence_path is None:
            return
        current = _read_evidence(self.evidence_path)
        current.update(
            {
                "session_id": self.session_id,
                "session_key": self.session_key,
                "setup": {
                    "status": status,
                    "recorded_at": _now_iso(),
                    "network": self.network_name,
                    "gateway": self.gateway_name,
                    "gateway_aliases": list(self.gateway_aliases),
                    "image": self.image,
                    "routes": [route.to_json() for route in self.routes],
                    "error": error,
                },
            }
        )
        _write_evidence(self.evidence_path, current)

    def _cleanup_forwarder_dir(self) -> None:
        if self._forwarder_dir is None:
            return
        _remove_safe_forwarder_dir(self._forwarder_dir)
        self._forwarder_dir = None


def cleanup_scoped_network_session(
    session_id: str,
    *,
    evidence_path: str | Path | None = None,
) -> dict[str, object]:
    validated_session_id = _validate_session_id(session_id)
    session_key = _session_key(validated_session_id)
    path = Path(evidence_path) if evidence_path is not None else None
    evidence = _read_evidence(path) if path is not None else {}
    evidence.setdefault("session_id", validated_session_id)
    evidence.setdefault("session_key", session_key)
    evidence.setdefault("setup", {"status": "unknown"})

    commands: list[dict[str, object]] = []
    errors: list[str] = []
    containers_before = _resource_ids(
        ("docker", "ps", "--all", "--quiet", "--filter", f"label={SESSION_LABEL}={session_key}"),
        commands=commands,
        errors=errors,
    )
    config_dirs = _forwarder_config_dirs(
        containers_before,
        commands=commands,
        errors=errors,
    )
    networks_before = _resource_ids(
        (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"label={SESSION_LABEL}={session_key}",
        ),
        commands=commands,
        errors=errors,
    )
    if containers_before:
        _cleanup_command(
            ("docker", "rm", "--force", *containers_before),
            commands=commands,
            errors=errors,
        )
    for network_id in networks_before:
        _cleanup_command(
            ("docker", "network", "rm", network_id),
            commands=commands,
            errors=errors,
        )
    containers_after = _resource_ids(
        ("docker", "ps", "--all", "--quiet", "--filter", f"label={SESSION_LABEL}={session_key}"),
        commands=commands,
        errors=errors,
    )
    networks_after = _resource_ids(
        (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"label={SESSION_LABEL}={session_key}",
        ),
        commands=commands,
        errors=errors,
    )
    verified = not errors and not containers_after and not networks_after
    if verified:
        for config_dir in config_dirs:
            _remove_safe_forwarder_dir(config_dir)
    evidence["cleanup"] = {
        "status": "verified" if verified else "error",
        "verified": verified,
        "recorded_at": _now_iso(),
        "containers_before": containers_before,
        "networks_before": networks_before,
        "containers_after": containers_after,
        "networks_after": networks_after,
        "forwarder_config_dirs_removed": [str(item) for item in config_dirs] if verified else [],
        "errors": errors,
        "commands": commands,
    }
    if path is not None:
        _write_evidence(path, evidence)
    return evidence


def _routes_from_scope(
    scope: object,
    *,
    allow_remote_target: bool = False,
    resolver: Callable[[str, int], Sequence[str]] | None = None,
) -> tuple[ForwardRoute, ...]:
    raw_in_scope = getattr(scope, "in_scope", None)
    if raw_in_scope is None and isinstance(scope, Mapping):
        raw_in_scope = scope.get("in_scope")
    if not isinstance(raw_in_scope, Sequence) or isinstance(raw_in_scope, (str, bytes)):
        raise ValueError("Docker tool runtime requires an explicit in_scope URL list")
    effective_resolver = resolver or _resolve_addresses
    candidates: list[tuple[str, str, int, bool]] = []
    seen: set[tuple[str, int, bool]] = set()
    for raw in raw_in_scope:
        parsed = assert_tool_target_url(
            str(raw),
            allow_remote_target=allow_remote_target,
        )
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValueError(f"invalid scoped TCP port in {raw!s}") from exc
        if not 0 < port <= _MAX_TCP_PORT:
            raise ValueError(f"invalid scoped TCP port in {raw!s}")
        host = _normalized_host(parsed.hostname or "")
        remote = not is_local_host(host)
        key = (host if remote else SCOPED_TARGET_ALIAS, port, remote)
        if key in seen:
            continue
        seen.add(key)
        destination_host = (
            _pinned_destination(host, port, resolver=effective_resolver)
            if remote
            else "host.docker.internal"
        )
        candidates.append((host, destination_host, port, remote))
    if not candidates:
        raise ValueError("Docker tool runtime scope contains no TCP targets")

    destination_ports = {item[2] for item in candidates}
    used_listener_ports: set[int] = set()
    next_low_listener = _LOW_FORWARD_PORT_START
    routes: list[ForwardRoute] = []
    for target_host, destination_host, destination_port, remote in candidates:
        if (remote or destination_port >= 1024) and destination_port not in used_listener_ports:
            listen_port = destination_port
        else:
            while (
                next_low_listener in used_listener_ports
                or next_low_listener in destination_ports
            ):
                next_low_listener += 1
            if next_low_listener > _MAX_TCP_PORT:
                raise ValueError("too many scoped TCP ports")
            listen_port = next_low_listener
            next_low_listener += 1
        used_listener_ports.add(listen_port)
        routes.append(
            ForwardRoute(
                target_host=target_host,
                destination_host=destination_host,
                destination_port=destination_port,
                listen_port=listen_port,
                remote=remote,
            )
        )
    return tuple(routes)


def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    addresses: list[str] = []
    for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM,
    ):
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            continue
        address = str(sockaddr[0]).strip()
        if address and address not in addresses:
            addresses.append(address)
    return tuple(addresses)


def _pinned_destination(
    host: str,
    port: int,
    *,
    resolver: Callable[[str, int], Sequence[str]],
) -> str:
    if _is_ip_literal(host):
        return host
    try:
        resolved = tuple(dict.fromkeys(str(item).strip() for item in resolver(host, port)))
    except OSError as exc:
        raise ValueError(f"could not resolve scoped remote target {host}:{port}: {exc}") from exc
    addresses = tuple(item for item in resolved if item)
    if not addresses:
        raise ValueError(f"could not resolve scoped remote target {host}:{port}")
    # Docker's default bridge is reliably IPv4-capable. Prefer an IPv4 pin but
    # retain IPv6-only target support when the daemon is configured for it.
    for address in addresses:
        try:
            if ipaddress.ip_address(address).version == 4:
                return address
        except ValueError as exc:
            raise ValueError(
                f"resolver returned an invalid address for {host}:{port}: {address!r}"
            ) from exc
    try:
        ipaddress.ip_address(addresses[0])
    except ValueError as exc:
        raise ValueError(
            f"resolver returned an invalid address for {host}:{port}: {addresses[0]!r}"
        ) from exc
    return addresses[0]


def _normalized_host(host: str) -> str:
    normalized = host.rstrip(".").lower()
    if not normalized:
        raise ValueError("scoped target URL must include a host")
    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"scoped target hostname is invalid: {host!r}") from exc


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _write_forwarder_files(routes: Sequence[ForwardRoute]) -> Path:
    directory = Path(tempfile.mkdtemp(prefix=_FORWARDER_DIR_PREFIX))
    script_path = directory / "forwarder.py"
    config_path = directory / "routes.json"
    script_path.write_text(_FORWARDER_SOURCE, encoding="utf-8")
    config_path.write_text(
        json.dumps({"routes": [route.to_json() for route in routes]}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    script_path.chmod(0o444)
    config_path.chmod(0o444)
    directory.chmod(0o555)
    return directory


def _run_checked(argv: tuple[str, ...], *, operation: str) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScopedNetworkError(f"could not {operation}: {exc}") from exc
    if completed.returncode != 0:
        detail = clip((completed.stderr or completed.stdout or "").strip(), 1000)
        raise ScopedNetworkError(f"could not {operation}: {detail or 'Docker command failed'}")
    return completed


def _resource_ids(
    argv: tuple[str, ...],
    *,
    commands: list[dict[str, object]],
    errors: list[str],
) -> list[str]:
    completed = _cleanup_command(argv, commands=commands, errors=errors)
    if completed is None or completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _forwarder_config_dirs(
    container_ids: Sequence[str],
    *,
    commands: list[dict[str, object]],
    errors: list[str],
) -> list[Path]:
    if not container_ids:
        return []
    completed = _cleanup_command(
        ("docker", "inspect", *container_ids),
        commands=commands,
        errors=errors,
    )
    if completed is None or completed.returncode != 0:
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        errors.append("Docker returned malformed container inspection data during cleanup")
        return []
    found: list[Path] = []
    for item in payload if isinstance(payload, list) else []:
        for mount in item.get("Mounts", []) if isinstance(item, dict) else []:
            if not isinstance(mount, dict) or mount.get("Destination") != FORWARDER_CONFIG_MOUNT:
                continue
            source = mount.get("Source")
            if isinstance(source, str):
                candidate = Path(source)
                if _is_safe_forwarder_dir(candidate) and candidate not in found:
                    found.append(candidate)
    return found


def _cleanup_command(
    argv: tuple[str, ...],
    *,
    commands: list[dict[str, object]],
    errors: list[str],
) -> subprocess.CompletedProcess[str] | None:
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"{' '.join(argv[:3])}: {exc}")
        commands.append({"argv": list(argv), "returncode": None, "error": str(exc)})
        return None
    commands.append(
        {
            "argv": list(argv),
            "returncode": completed.returncode,
            "stdout": clip(completed.stdout or "", 1000),
            "stderr": clip(completed.stderr or "", 1000),
        }
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Docker command failed").strip()
        errors.append(f"{' '.join(argv[:3])}: {clip(detail, 500)}")
    return completed


def _validate_session_id(session_id: str) -> str:
    normalized = str(session_id).strip()
    if not normalized:
        raise ValueError("Docker tool runtime requires a non-empty session_id")
    return normalized


def _session_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


def _read_evidence(path: Path | None) -> dict[str, object]:
    if path is None or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_evidence(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _is_safe_forwarder_dir(path: Path) -> bool:
    try:
        resolved = path.resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
    except OSError:
        return False
    return resolved.parent == temp_root and resolved.name.startswith(_FORWARDER_DIR_PREFIX)


def _remove_safe_forwarder_dir(path: Path) -> None:
    if not _is_safe_forwarder_dir(path):
        return
    try:
        path.chmod(0o700)
        for child in path.iterdir():
            child.chmod(0o600)
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=True)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "SCOPED_TARGET_ALIAS",
    "ScopedDockerNetwork",
    "ScopedNetworkError",
    "cleanup_scoped_network_session",
]
