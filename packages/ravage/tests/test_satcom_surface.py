# ruff: noqa: PLR2004
from __future__ import annotations

import pytest
from ravage.satcom.contracts import SatcomSurfaceError
from ravage.satcom.surface import (
    SatcomAttribute,
    SatcomNodeKind,
    SatcomProvenance,
    SatcomRelation,
    SatcomSurfaceEdge,
    SatcomSurfaceGraph,
    SatcomSurfaceNode,
)


def test_surface_ids_are_deterministic_and_edges_merge_evidence() -> None:
    first = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")
    second = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")

    first_artifact = first.node(
        kind=SatcomNodeKind.ARTIFACT,
        selector="artifact_0123456789abcdef01234567",
        attributes={"size_bytes": 10},
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
    )
    first_apid = first.node(
        kind=SatcomNodeKind.CCSDS_APID,
        selector="apid:7",
        attributes={"apid": 7},
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
    )
    edge = first.edge(
        source=first_artifact,
        relation=SatcomRelation.CONTAINS,
        target=first_apid,
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
        evidence_refs=("artifact_0123456789abcdef01234567:offset=0:length=7",),
    )
    merged = first.edge(
        source=first_artifact,
        relation=SatcomRelation.CONTAINS,
        target=first_apid,
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
        evidence_refs=("artifact_0123456789abcdef01234567:offset=7:length=7",),
    )

    second_artifact = second.node(
        kind="artifact",
        selector="artifact_0123456789abcdef01234567",
        attributes={"size_bytes": 10},
        provenance=("ccsds_space_packet",),
    )
    assert first_artifact.node_id == second_artifact.node_id
    assert edge.edge_id == merged.edge_id
    assert merged.observation_count == 2
    assert len(merged.evidence_refs) == 2
    assert first.to_json()["schema"] == "ravage.satcom-surface.v1"


def test_surface_rejects_conflicting_values_and_unknown_edge_nodes() -> None:
    graph = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")
    node = graph.node(
        kind="ccsds_apid",
        selector="apid:7",
        attributes={"apid": 7},
        provenance=("ccsds_space_packet",),
    )

    with pytest.raises(SatcomSurfaceError, match="attributes conflict"):
        graph.node(
            kind="ccsds_apid",
            selector="apid:7",
            attributes={"apid": 8},
            provenance=("ccsds_space_packet",),
        )
    with pytest.raises(SatcomSurfaceError, match="unknown node"):
        graph.add_edge(
            SatcomSurfaceEdge.create(
                source_node_id=node.node_id,
                relation="contains",
                target_node_id="sn_000000000000000000000000",
                provenance=("ccsds_space_packet",),
            )
        )


def test_surface_contract_rejects_unsafe_or_unknown_metadata() -> None:
    graph = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")

    with pytest.raises(SatcomSurfaceError, match="unsupported SATCOM node kind"):
        graph.node(
            kind="imaginary_transmitter",
            selector="x",
            provenance=("ccsds_space_packet",),
        )
    with pytest.raises(SatcomSurfaceError, match="attributes accept only"):
        graph.node(
            kind="spacecraft",
            selector="catalog:25544",
            attributes={"payload": {"secret": "value"}},
            provenance=("tle",),
        )


def test_surface_rejects_forged_typed_nodes_and_edges() -> None:
    graph = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")
    forged_node = SatcomSurfaceNode(
        node_id="sn_000000000000000000000000",
        kind=SatcomNodeKind.CCSDS_APID,
        selector="apid:7",
        attributes=(SatcomAttribute(name="apid", value=7),),
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
    )

    with pytest.raises(SatcomSurfaceError, match="not canonical"):
        graph.add_node(forged_node)

    source = graph.node(
        kind="artifact",
        selector="artifact_0123456789abcdef01234567",
        provenance=("ccsds_space_packet",),
    )
    target = graph.node(
        kind="ccsds_apid",
        selector="apid:7",
        attributes={"apid": 7},
        provenance=("ccsds_space_packet",),
    )
    forged_edge = SatcomSurfaceEdge(
        edge_id="se_000000000000000000000000",
        source_node_id=source.node_id,
        relation=SatcomRelation.CONTAINS,
        target_node_id=target.node_id,
        provenance=(SatcomProvenance.CCSDS_SPACE_PACKET,),
        evidence_refs=(),
    )
    with pytest.raises(SatcomSurfaceError, match="not canonical"):
        graph.add_edge(forged_edge)


def test_surface_constructor_revalidates_initial_mappings() -> None:
    graph = SatcomSurfaceGraph.create("artifact_0123456789abcdef01234567")
    node = graph.node(
        kind="artifact",
        selector="artifact_0123456789abcdef01234567",
        provenance=("ccsds_space_packet",),
    )

    with pytest.raises(SatcomSurfaceError, match="mapping key"):
        SatcomSurfaceGraph(
            namespace=graph.namespace,
            nodes={"wrong": node},
            edges={},
        )
