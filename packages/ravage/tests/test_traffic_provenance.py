from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from ravage.__main__ import main
from ravage.agent_core.action_executor import ActionResult
from ravage.agent_core.autonomous_graph.evidence import EvidenceBlackboard
from ravage.agent_core.autonomous_graph.traffic_lifecycle import (
    GraphTrafficLifecycle,
    GraphTrafficLifecycleError,
)
from ravage.traffic.contracts import build_captured_http_exchange
from ravage.traffic.manifest import (
    TrafficRunError,
    TrafficRunManifest,
    read_traffic_manifest,
    write_traffic_manifest,
)
from ravage.traffic.provenance import load_traffic_provenance
from ravage.traffic.recorders import ProbeTrafficRecorder
from ravage.traffic.store import TrafficStore
from ravage.web_core.http_probe import ProbeResponse, ProbeSession

if TYPE_CHECKING:
    from pathlib import Path

_TARGET_URL = "http://127.0.0.1:8765"
_CAPTURE_SESSION_ID = "agent-http-provenance"
_OBSERVATION_ID = "http:obs-provenance-1"
_SECRET = "flag{provenance-must-not-appear}"  # noqa: S105 - redaction sentinel.
_ARGPARSE_ERROR = 2


def _run(
    tmp_path: Path,
    *,
    target_url: str = _TARGET_URL,
) -> tuple[Path, Path, TrafficStore]:
    run_dir = tmp_path / "run"
    workspace = run_dir / "workspace"
    store = TrafficStore.create(workspace)
    manifest = TrafficRunManifest.create(
        target_url=target_url,
        capture_session_id=_CAPTURE_SESSION_ID,
    )
    write_traffic_manifest(workspace, manifest.complete())
    return run_dir, workspace, store


def _blackboard(
    workspace: Path,
    *,
    name: str = "evidence-blackboard.json",
    observation_id: str = _OBSERVATION_ID,
    target_url: str = _TARGET_URL,
) -> tuple[EvidenceBlackboard, tuple[str, ...]]:
    blackboard = EvidenceBlackboard(
        target_url=target_url,
        state_path=workspace / name,
    )
    promotion = blackboard.record_action_result(
        producer_node_id="node-http-001",
        action={"action": "http_request", "method": "GET", "url": "/proof"},
        result=ActionResult(
            ok=True,
            observation=f"target returned {_SECRET}",
            outcome="flag_candidate",
            flag=_SECRET,
            evidence_source_kind="tool_http_request",
            evidence_observation=f"target returned {_SECRET}",
        ),
        observation_id=observation_id,
    )
    refs = (
        promotion.raw_evidence_ref,
        *promotion.promoted_evidence_refs,
        *promotion.lead_evidence_refs,
    )
    return blackboard, tuple(dict.fromkeys(refs))


def _append_exchange(
    store: TrafficStore,
    *,
    source: str = "agent_http",
    observation_id: str = _OBSERVATION_ID,
    path: str = "/proof",
) -> str:
    exchange = store.append_exchange(
        build_captured_http_exchange(
            capture_session_id=_CAPTURE_SESSION_ID,
            source=source,
            source_observation_id=observation_id,
            method="GET",
            url=f"{_TARGET_URL}{path}?token={_SECRET}",
            request_headers={"Authorization": f"Bearer {_SECRET}"},
            request_sent=True,
            response_status=200,
            response_final_url=f"{_TARGET_URL}{path}",
            response_headers={"Set-Cookie": f"proof={_SECRET}"},
            response_body=f"target returned {_SECRET}",
            scope_decision="allowed",
            known_secrets=(_SECRET,),
        )
    )
    return exchange.exchange_id


def test_anonymous_managed_fork_clears_authenticated_traffic_identity(
    tmp_path: Path,
) -> None:
    store = TrafficStore.create(tmp_path / "traffic")
    recorder = ProbeTrafficRecorder(
        store,
        capture_session_id="managed-fork-provenance",
        identity_alias="alice",
    )
    parent = ProbeSession(_TARGET_URL, traffic_observer=recorder)
    parent.configure_managed_identity_forks(header_names=("Authorization", "Cookie"))
    inherited = parent.fork()
    anonymous = parent.fork(inherit_identity=False)
    response = ProbeResponse(
        method="GET",
        url=f"{_TARGET_URL}/boundary",
        status=200,
        final_url=f"{_TARGET_URL}/boundary",
        elapsed_ms=1,
        body="boundary response",
    )

    inherited._observe_traffic(response, disposition="sent")  # noqa: SLF001
    anonymous._observe_traffic(response, disposition="sent")  # noqa: SLF001

    exchanges = store.exchanges()
    assert exchanges[0].identity_alias == "alice"
    assert exchanges[1].identity_alias == ""


@pytest.mark.parametrize(
    "raw_target",
    [_TARGET_URL, f"{_TARGET_URL}/entry?token={_SECRET}"],
)
def test_manifest_persists_a_safe_identity_for_the_exact_raw_target(
    raw_target: str,
) -> None:
    manifest = TrafficRunManifest.create(
        target_url=raw_target,
        capture_session_id=_CAPTURE_SESSION_ID,
    )
    expected = "target:" + hashlib.sha256(raw_target.encode()).hexdigest()

    assert manifest.target_identity == expected
    assert TrafficRunManifest.from_json(manifest.to_json()).target_identity == expected
    assert _SECRET not in json.dumps(manifest.to_json())

    legacy_payload = manifest.to_json()
    del legacy_payload["target_identity"]
    legacy = TrafficRunManifest.from_json(legacy_payload)
    stored_target = str(legacy_payload["target_url"])
    assert legacy.target_identity == (
        "target:" + hashlib.sha256(stored_target.encode()).hexdigest()
    )

    invalid_payload = manifest.to_json()
    invalid_payload["target_identity"] = "target:not-a-digest"
    with pytest.raises(TrafficRunError, match="target identity"):
        TrafficRunManifest.from_json(invalid_payload)


def test_manifest_identity_cannot_change_on_write_or_graph_resume(
    tmp_path: Path,
) -> None:
    _run_dir, workspace, _store = _run(tmp_path)
    manifest = read_traffic_manifest(workspace)
    altered_identity = "target:" + ("0" * 64)

    with pytest.raises(TrafficRunError, match="cannot change"):
        write_traffic_manifest(
            workspace,
            replace(manifest, target_identity=altered_identity),
        )
    assert read_traffic_manifest(workspace).target_identity == manifest.target_identity

    manifest_path = workspace / "traffic" / "run.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["target_identity"] = altered_identity
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(GraphTrafficLifecycleError, match="target does not match"):
        GraphTrafficLifecycle.open(
            workspace,
            target_url=_TARGET_URL,
            in_scope=(),
            out_of_scope=(),
            capture_session_id=_CAPTURE_SESSION_ID,
        )


@pytest.mark.parametrize(
    "blackboard_name",
    ["evidence-blackboard.json", "remote-evidence-blackboard.json"],
)
def test_cli_exposes_only_identifier_provenance_for_valid_blackboards(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    blackboard_name: str,
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    board, expected_refs = _blackboard(workspace, name=blackboard_name)
    request_id = _append_exchange(store)

    # The manifest canonicalizes an origin-only URL with '/', while its one-way
    # identity remains bound to the exact no-trailing-slash operator input.
    manifest = read_traffic_manifest(workspace)
    assert manifest.target_url == f"{_TARGET_URL}/"
    assert manifest.target_identity == board.target_identity

    main(["traffic", "list", str(run_dir), "--json"])
    listing_text = capsys.readouterr().out
    listing = json.loads(listing_text)
    agent_evidence = listing["requests"][0]["agent_evidence"]

    assert agent_evidence == {
        "status": "linked",
        "observation_id": _OBSERVATION_ID,
        "evidence_refs": list(expected_refs),
        "material_evidence_refs": [
            ref for ref in expected_refs if board.state.records[ref].material
        ],
    }
    assert _SECRET not in listing_text

    main(["traffic", "list", str(run_dir)])
    human_listing = capsys.readouterr().out
    assert "evidence=linked:" in human_listing
    assert _SECRET not in human_listing

    main(["traffic", "show", str(run_dir), request_id, "--json"])
    shown_text = capsys.readouterr().out
    shown = json.loads(shown_text)
    detail = shown["agent_evidence"]

    assert detail["status"] == "linked"
    assert detail["blackboard_path"].endswith(blackboard_name)
    assert {record["evidence_id"] for record in detail["evidence_records"]} == set(
        expected_refs
    )
    assert all(
        set(record) == {
            "evidence_id",
            "kind",
            "source",
            "producer_node_id",
            "material",
        }
        for record in detail["evidence_records"]
    )
    assert _SECRET not in shown_text

    main(["traffic", "show", str(run_dir), request_id])
    human = capsys.readouterr().out
    assert f"observation {_OBSERVATION_ID}" in human
    assert "evidence   " in human
    assert expected_refs[0] in human
    assert _SECRET not in human


def test_query_target_uses_one_way_manifest_identity_for_the_join(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw_target = f"{_TARGET_URL}/entry?token={_SECRET}"
    run_dir, workspace, store = _run(tmp_path, target_url=raw_target)
    board, expected_refs = _blackboard(workspace, target_url=raw_target)
    _append_exchange(store)

    manifest = read_traffic_manifest(workspace)
    assert manifest.target_identity == board.target_identity
    assert _SECRET not in json.dumps(manifest.to_json())

    main(["traffic", "list", str(run_dir), "--json"])
    output = capsys.readouterr().out
    linked = json.loads(output)["requests"][0]["agent_evidence"]
    assert linked["status"] == "linked"
    assert linked["evidence_refs"] == list(expected_refs)
    assert _SECRET not in output


def test_redirect_exchanges_share_forward_and_reverse_evidence_links(
    tmp_path: Path,
) -> None:
    _run_dir, workspace, store = _run(tmp_path)
    _board, expected_refs = _blackboard(workspace)
    first_id = _append_exchange(store, path="/redirect")
    final_id = _append_exchange(store, path="/proof")

    index = load_traffic_provenance(
        workspace,
        exchanges=store.exchanges(),
        target_identity=read_traffic_manifest(workspace).target_identity,
    )

    assert index.for_exchange_id(first_id).evidence_refs == expected_refs
    assert index.for_exchange_id(final_id).evidence_refs == expected_refs
    assert index.exchange_ids_for_evidence(expected_refs[0]) == (first_id, final_id)


def test_orphan_and_non_agent_captures_do_not_gain_evidence_links(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    _blackboard(workspace)
    orphan_id = _append_exchange(store, observation_id="http:obs-orphan")
    browser_id = _append_exchange(store, source="browser")
    missing_id = _append_exchange(store, observation_id="")

    main(["traffic", "list", str(run_dir), "--json"])
    requests = {
        item["id"]: item["agent_evidence"]
        for item in json.loads(capsys.readouterr().out)["requests"]
    }

    assert requests[orphan_id] == {
        "status": "observation_only",
        "observation_id": "http:obs-orphan",
        "evidence_refs": [],
        "material_evidence_refs": [],
    }
    assert requests[browser_id] == {
        "status": "not_applicable",
        "observation_id": "",
        "evidence_refs": [],
        "material_evidence_refs": [],
    }
    assert requests[missing_id]["status"] == "missing_observation"


def test_agent_capture_without_blackboard_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, _workspace, store = _run(tmp_path)
    _append_exchange(store)

    with pytest.raises(SystemExit) as raised:
        main(["traffic", "list", str(run_dir), "--json"])

    assert raised.value.code == _ARGPARSE_ERROR
    assert "without its canonical evidence blackboard" in capsys.readouterr().err


def test_non_agent_capture_ignores_unrelated_malformed_blackboard(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    request_id = _append_exchange(store, source="browser")
    (workspace / "evidence-blackboard.json").write_text("not-json", encoding="utf-8")

    main(["traffic", "list", str(run_dir), "--json"])

    [request] = json.loads(capsys.readouterr().out)["requests"]
    assert request["id"] == request_id
    assert request["agent_evidence"]["status"] == "not_applicable"


def test_tampered_blackboard_fails_closed_without_leaking_payload(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    blackboard, _refs = _blackboard(workspace)
    _append_exchange(store)
    payload = json.loads(blackboard.state_path.read_text(encoding="utf-8"))
    payload["records"][0]["payload"]["outcome"] = _SECRET
    blackboard.state_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        main(["traffic", "list", str(run_dir), "--json"])

    assert raised.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "invalid evidence blackboard" in error
    assert _SECRET not in error


def test_valid_blackboard_for_another_target_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    _blackboard(workspace, target_url="http://127.0.0.1:9999")
    _append_exchange(store)

    with pytest.raises(SystemExit) as raised:
        main(["traffic", "list", str(run_dir), "--json"])

    assert raised.value.code == _ARGPARSE_ERROR
    assert "invalid evidence blackboard" in capsys.readouterr().err


def test_dual_canonical_blackboards_fail_as_ambiguous(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir, workspace, store = _run(tmp_path)
    blackboard, _refs = _blackboard(workspace)
    _append_exchange(store)
    (workspace / "remote-evidence-blackboard.json").write_bytes(
        blackboard.state_path.read_bytes()
    )

    with pytest.raises(SystemExit) as raised:
        main(["traffic", "show", str(run_dir), "rq_0001", "--json"])

    assert raised.value.code == _ARGPARSE_ERROR
    error = capsys.readouterr().err
    assert "multiple canonical evidence blackboards" in error
    assert "evidence-blackboard.json" in error
    assert "remote-evidence-blackboard.json" in error
