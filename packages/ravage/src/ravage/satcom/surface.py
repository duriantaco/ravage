# ruff: noqa: EM101, PLR0913, TRY003
"""Deterministic, payload-free SATCOM surface graph contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from ravage.satcom.contracts import (
    MAX_EVIDENCE_REFS,
    MAX_SURFACE_EDGES,
    MAX_SURFACE_NODES,
    SATCOM_SCHEMA_VERSION,
    SATCOM_SURFACE_GRAPH_SCHEMA,
    SatcomSurfaceError,
    safe_identifier,
    safe_text,
    stable_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

type SurfaceScalar = str | int | bool

_MAX_NODE_ATTRIBUTES = 32
_NODE_ID_LENGTH = 27


class SatcomNodeKind(StrEnum):
    ARTIFACT = "artifact"
    SPACECRAFT = "spacecraft"
    GROUND_STATION = "ground_station"
    RF_LINK = "rf_link"
    CCSDS_APID = "ccsds_apid"
    VIRTUAL_CHANNEL = "virtual_channel"
    TELECOMMAND = "telecommand"
    TELEMETRY = "telemetry"
    FIRMWARE = "firmware"
    HARDWARE_BUS = "hardware_bus"


class SatcomRelation(StrEnum):
    DESCRIBES = "describes"
    CONTAINS = "contains"
    USES_APID = "uses_apid"
    OBSERVED_IN = "observed_in"
    UPLINKS_TO = "uplinks_to"
    DOWNLINKS_FROM = "downlinks_from"


class SatcomProvenance(StrEnum):
    TLE = "tle"
    CCSDS_SPACE_PACKET = "ccsds_space_packet"
    DECLARED_MANIFEST = "declared_manifest"
    EXTERNAL_TOOL = "external_tool"


@dataclass(frozen=True, slots=True, order=True)
class SatcomAttribute:
    name: str
    value: SurfaceScalar

    @classmethod
    def create(cls, name: object, value: object) -> SatcomAttribute:
        canonical_name = safe_identifier(name, label="SATCOM attribute name")
        if isinstance(value, bool):
            canonical_value: SurfaceScalar = value
        elif isinstance(value, int):
            canonical_value = value
        elif isinstance(value, str):
            canonical_value = safe_text(value, label="SATCOM attribute value", allow_empty=True)
        else:
            raise SatcomSurfaceError("SATCOM attributes accept only string, integer, or boolean")
        return cls(name=canonical_name, value=canonical_value)

    def to_json(self) -> dict[str, SurfaceScalar]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True, slots=True)
class SatcomSurfaceNode:
    node_id: str
    kind: SatcomNodeKind
    selector: str
    attributes: tuple[SatcomAttribute, ...]
    provenance: tuple[SatcomProvenance, ...]

    @classmethod
    def create(
        cls,
        *,
        namespace: str,
        kind: SatcomNodeKind | str,
        selector: object,
        attributes: Mapping[str, object] | None = None,
        provenance: tuple[SatcomProvenance | str, ...],
    ) -> SatcomSurfaceNode:
        canonical_namespace = safe_identifier(namespace, label="SATCOM graph namespace")
        canonical_kind = _node_kind(kind)
        canonical_selector = safe_text(selector, label="SATCOM node selector")
        canonical_attributes = _attributes(attributes or {})
        canonical_provenance = _provenance(provenance)
        return cls(
            node_id=stable_id(
                "sn",
                canonical_namespace,
                canonical_kind.value,
                canonical_selector,
            ),
            kind=canonical_kind,
            selector=canonical_selector,
            attributes=canonical_attributes,
            provenance=canonical_provenance,
        )

    def merged(self, other: SatcomSurfaceNode) -> SatcomSurfaceNode:
        if self.node_id != other.node_id or self.kind is not other.kind:
            raise SatcomSurfaceError("cannot merge different SATCOM nodes")
        ours = {item.name: item.value for item in self.attributes}
        theirs = {item.name: item.value for item in other.attributes}
        conflicts = {key for key in ours.keys() & theirs if ours[key] != theirs[key]}
        if conflicts:
            raise SatcomSurfaceError("SATCOM node attributes conflict")
        return replace(
            self,
            attributes=_attributes(ours | theirs),
            provenance=tuple(sorted(set(self.provenance) | set(other.provenance))),
        )

    def to_json(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "selector": self.selector,
            "attributes": [item.to_json() for item in self.attributes],
            "provenance": [item.value for item in self.provenance],
        }


@dataclass(frozen=True, slots=True)
class SatcomSurfaceEdge:
    edge_id: str
    source_node_id: str
    relation: SatcomRelation
    target_node_id: str
    provenance: tuple[SatcomProvenance, ...]
    evidence_refs: tuple[str, ...]
    observation_count: int = 1

    @classmethod
    def create(
        cls,
        *,
        source_node_id: str,
        relation: SatcomRelation | str,
        target_node_id: str,
        provenance: tuple[SatcomProvenance | str, ...],
        evidence_refs: tuple[str, ...] = (),
        observation_count: int = 1,
    ) -> SatcomSurfaceEdge:
        source = _node_id(source_node_id)
        target = _node_id(target_node_id)
        canonical_relation = _relation(relation)
        if observation_count <= 0:
            raise SatcomSurfaceError("SATCOM edge observation count must be positive")
        refs = _evidence_refs(evidence_refs)
        return cls(
            edge_id=stable_id("se", source, canonical_relation.value, target),
            source_node_id=source,
            relation=canonical_relation,
            target_node_id=target,
            provenance=_provenance(provenance),
            evidence_refs=refs,
            observation_count=observation_count,
        )

    def merged(self, other: SatcomSurfaceEdge) -> SatcomSurfaceEdge:
        if self.edge_id != other.edge_id:
            raise SatcomSurfaceError("cannot merge different SATCOM edges")
        return replace(
            self,
            provenance=tuple(sorted(set(self.provenance) | set(other.provenance))),
            evidence_refs=tuple(sorted(set(self.evidence_refs) | set(other.evidence_refs)))[
                :MAX_EVIDENCE_REFS
            ],
            observation_count=self.observation_count + other.observation_count,
        )

    def to_json(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "relation": self.relation.value,
            "target_node_id": self.target_node_id,
            "provenance": [item.value for item in self.provenance],
            "evidence_refs": list(self.evidence_refs),
            "observation_count": self.observation_count,
        }


@dataclass(slots=True)
class SatcomSurfaceGraph:
    namespace: str
    nodes: dict[str, SatcomSurfaceNode]
    edges: dict[str, SatcomSurfaceEdge]

    def __post_init__(self) -> None:
        self.namespace = safe_identifier(self.namespace, label="SATCOM graph namespace")
        initial_nodes = dict(self.nodes)
        initial_edges = dict(self.edges)
        self.nodes = {}
        self.edges = {}
        for key, node in initial_nodes.items():
            if key != getattr(node, "node_id", None):
                raise SatcomSurfaceError("SATCOM node mapping key does not match its identity")
            self.add_node(node)
        for key, edge in initial_edges.items():
            if key != getattr(edge, "edge_id", None):
                raise SatcomSurfaceError("SATCOM edge mapping key does not match its identity")
            self.add_edge(edge)

    @classmethod
    def create(cls, namespace: str) -> SatcomSurfaceGraph:
        return cls(
            namespace=safe_identifier(namespace, label="SATCOM graph namespace"),
            nodes={},
            edges={},
        )

    def add_node(self, node: SatcomSurfaceNode) -> SatcomSurfaceNode:
        node = _validated_node(node, namespace=self.namespace)
        existing = self.nodes.get(node.node_id)
        merged = node if existing is None else existing.merged(node)
        if existing is None and len(self.nodes) >= MAX_SURFACE_NODES:
            raise SatcomSurfaceError("SATCOM surface exceeds the node limit")
        self.nodes[node.node_id] = merged
        return merged

    def node(
        self,
        *,
        kind: SatcomNodeKind | str,
        selector: object,
        attributes: Mapping[str, object] | None = None,
        provenance: tuple[SatcomProvenance | str, ...],
    ) -> SatcomSurfaceNode:
        return self.add_node(
            SatcomSurfaceNode.create(
                namespace=self.namespace,
                kind=kind,
                selector=selector,
                attributes=attributes,
                provenance=provenance,
            )
        )

    def add_edge(self, edge: SatcomSurfaceEdge) -> SatcomSurfaceEdge:
        edge = _validated_edge(edge)
        if edge.source_node_id not in self.nodes or edge.target_node_id not in self.nodes:
            raise SatcomSurfaceError("SATCOM edge references an unknown node")
        existing = self.edges.get(edge.edge_id)
        merged = edge if existing is None else existing.merged(edge)
        if existing is None and len(self.edges) >= MAX_SURFACE_EDGES:
            raise SatcomSurfaceError("SATCOM surface exceeds the edge limit")
        self.edges[edge.edge_id] = merged
        return merged

    def edge(
        self,
        *,
        source: SatcomSurfaceNode,
        relation: SatcomRelation | str,
        target: SatcomSurfaceNode,
        provenance: tuple[SatcomProvenance | str, ...],
        evidence_refs: tuple[str, ...] = (),
        observation_count: int = 1,
    ) -> SatcomSurfaceEdge:
        return self.add_edge(
            SatcomSurfaceEdge.create(
                source_node_id=source.node_id,
                relation=relation,
                target_node_id=target.node_id,
                provenance=provenance,
                evidence_refs=evidence_refs,
                observation_count=observation_count,
            )
        )

    def to_json(self) -> dict[str, object]:
        return {
            "schema": SATCOM_SURFACE_GRAPH_SCHEMA,
            "schema_version": SATCOM_SCHEMA_VERSION,
            "namespace": self.namespace,
            "counts": {"nodes": len(self.nodes), "edges": len(self.edges)},
            "nodes": [self.nodes[key].to_json() for key in sorted(self.nodes)],
            "edges": [self.edges[key].to_json() for key in sorted(self.edges)],
        }


def _node_kind(value: SatcomNodeKind | str) -> SatcomNodeKind:
    if isinstance(value, SatcomNodeKind):
        return value
    try:
        return SatcomNodeKind(str(value).strip().casefold())
    except ValueError as exc:
        raise SatcomSurfaceError("unsupported SATCOM node kind") from exc


def _relation(value: SatcomRelation | str) -> SatcomRelation:
    if isinstance(value, SatcomRelation):
        return value
    try:
        return SatcomRelation(str(value).strip().casefold())
    except ValueError as exc:
        raise SatcomSurfaceError("unsupported SATCOM relation") from exc


def _provenance(
    values: tuple[SatcomProvenance | str, ...],
) -> tuple[SatcomProvenance, ...]:
    if not values:
        raise SatcomSurfaceError("SATCOM provenance is required")
    sources: set[SatcomProvenance] = set()
    for value in values:
        try:
            source = value if isinstance(value, SatcomProvenance) else SatcomProvenance(value)
        except ValueError as exc:
            raise SatcomSurfaceError("unsupported SATCOM provenance") from exc
        sources.add(source)
    return tuple(sorted(sources))


def _attributes(values: Mapping[str, object]) -> tuple[SatcomAttribute, ...]:
    if len(values) > _MAX_NODE_ATTRIBUTES:
        raise SatcomSurfaceError("SATCOM node contains too many attributes")
    attributes: dict[str, SatcomAttribute] = {}
    for key, value in values.items():
        attribute = SatcomAttribute.create(key, value)
        if attribute.name in attributes:
            raise SatcomSurfaceError("SATCOM node contains duplicate attributes")
        attributes[attribute.name] = attribute
    return tuple(attributes[key] for key in sorted(attributes))


def _node_id(value: object) -> str:
    text = str(value or "")
    if not re_full_node_id(text):
        raise SatcomSurfaceError("invalid SATCOM node reference")
    return text


def re_full_node_id(value: str) -> bool:
    return (
        len(value) == _NODE_ID_LENGTH
        and value.startswith("sn_")
        and all(character in "0123456789abcdef" for character in value[3:])
    )


def _evidence_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(values) > MAX_EVIDENCE_REFS:
        raise SatcomSurfaceError("SATCOM edge contains too many evidence references")
    refs = {safe_text(value, label="SATCOM evidence reference") for value in values}
    return tuple(sorted(refs))


def _validated_node(
    node: SatcomSurfaceNode,
    *,
    namespace: str,
) -> SatcomSurfaceNode:
    if not isinstance(node, SatcomSurfaceNode):
        raise SatcomSurfaceError("SATCOM graph accepts only typed nodes")
    try:
        attributes: dict[str, SurfaceScalar] = {}
        for item in node.attributes:
            if not isinstance(item, SatcomAttribute) or item.name in attributes:
                raise SatcomSurfaceError("SATCOM node is not canonical")
            attributes[item.name] = item.value
        canonical = SatcomSurfaceNode.create(
            namespace=namespace,
            kind=node.kind,
            selector=node.selector,
            attributes=attributes,
            provenance=node.provenance,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise SatcomSurfaceError("SATCOM node is not canonical") from exc
    if canonical != node:
        raise SatcomSurfaceError("SATCOM node is not canonical")
    return canonical


def _validated_edge(edge: SatcomSurfaceEdge) -> SatcomSurfaceEdge:
    if not isinstance(edge, SatcomSurfaceEdge):
        raise SatcomSurfaceError("SATCOM graph accepts only typed edges")
    try:
        canonical = SatcomSurfaceEdge.create(
            source_node_id=edge.source_node_id,
            relation=edge.relation,
            target_node_id=edge.target_node_id,
            provenance=edge.provenance,
            evidence_refs=edge.evidence_refs,
            observation_count=edge.observation_count,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise SatcomSurfaceError("SATCOM edge is not canonical") from exc
    if canonical != edge:
        raise SatcomSurfaceError("SATCOM edge is not canonical")
    return canonical


__all__ = [
    "SatcomAttribute",
    "SatcomNodeKind",
    "SatcomProvenance",
    "SatcomRelation",
    "SatcomSurfaceEdge",
    "SatcomSurfaceGraph",
    "SatcomSurfaceNode",
]
