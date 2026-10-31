"""Command-line entry point for the paired-XBEN comparison protocol."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.paired_xben.coordinator import (
    CampaignCoordinatorError,
    execute_paired_campaign_from_config,
)
from tools.paired_xben.prepare import ProductionPreparationError, prepare_from_config
from tools.paired_xben.protocol import (
    PairedXbenProtocolError,
    create_commitment,
    create_primary_attempt_manifest,
    create_rerun_attempt_manifest,
    load_eligible_pool,
    load_run_contract,
    reserve_primary_matrix,
    resolve_commitment,
    verify_campaign,
)
from tools.paired_xben.report import PairedXbenReportError, write_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Commit, resolve, and verify a non-cherry-picked paired XBEN-20 draw."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare",
        help="create a no-live-action preflight and strict run contract from exact local inputs",
    )
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)

    commit = subparsers.add_parser(
        "commit",
        help="create a frozen commitment to a future drand round",
    )
    commit.add_argument("--output-dir", type=Path, required=True)
    commit.add_argument("--campaign-id", required=True)
    commit.add_argument("--preflight", type=Path, required=True)
    commit.add_argument("--run-contract", type=Path, required=True)
    commit.add_argument("--chain-hash", required=True)
    commit.add_argument("--chain-genesis-time", type=int, required=True)
    commit.add_argument("--chain-period-seconds", type=int, required=True)
    commit.add_argument("--observed-latest-round", type=int, required=True)
    commit.add_argument("--draw-round", type=int, required=True)
    commit.add_argument("--drand-verifier-binary", type=Path, required=True)
    commit.add_argument("--cosign-binary", type=Path, required=True)
    commit.add_argument("--sigstore-trusted-root", type=Path, required=True)
    commit.add_argument("--publication-certificate-identity", required=True)
    commit.add_argument("--publication-certificate-oidc-issuer", required=True)

    resolve = subparsers.add_parser(
        "resolve",
        help="resolve by fetching the exact round from two fixed official drand relays",
    )
    resolve.add_argument("--campaign-dir", type=Path, required=True)
    resolve.add_argument("--drand-chain-info", type=Path, required=True)
    resolve.add_argument("--publication-anchor", type=Path, required=True)
    resolve.add_argument("--commitment-digest", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="recompute every protocol binding without network access",
    )
    verify.add_argument("--campaign-dir", type=Path, required=True)
    verify.add_argument("--require-all-primary-attempts", action="store_true")

    report = subparsers.add_parser(
        "report",
        help="create a fail-closed paired report from all 40 primary rows",
    )
    report.add_argument("--campaign-dir", type=Path, required=True)
    report.add_argument("--output-dir", type=Path, required=True)

    execute = subparsers.add_parser(
        "execute",
        help="run the complete reserved matrix once in honest paired-local mode",
    )
    execute.add_argument("--campaign-dir", type=Path, required=True)
    execute.add_argument("--executor-config", type=Path, required=True)

    primary = subparsers.add_parser(
        "start-primary",
        help="deprecated and disabled; use reserve-primary-matrix",
    )
    primary.add_argument("--campaign-dir", type=Path, required=True)
    primary.add_argument("--slot", required=True)

    matrix = subparsers.add_parser(
        "reserve-primary-matrix",
        help="reserve and seal all 40 scored schedule slots before execution",
    )
    matrix.add_argument("--campaign-dir", type=Path, required=True)

    rerun = subparsers.add_parser(
        "start-rerun",
        help="exclusively retain an unscored diagnostic rerun",
    )
    rerun.add_argument("--campaign-dir", type=Path, required=True)
    rerun.add_argument("--rerun-id", required=True)
    rerun.add_argument("--primary-slot", required=True)
    rerun.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:  # noqa: C901
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepared, _preflight_path = prepare_from_config(args.config, args.output_dir)
            payload = {
                "ready": prepared["ready"],
                "block_reasons": prepared["block_reasons"],
                "output_dir": str(args.output_dir),
                "no_live_actions": prepared["no_live_actions"],
            }
            if prepared["ready"] is not True:
                sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
                return 2
        elif args.command == "commit":
            payload = create_commitment(
                args.output_dir,
                campaign_id=args.campaign_id,
                preflight_json_path=args.preflight,
                eligible_case_ids=load_eligible_pool(args.preflight),
                chain_hash=args.chain_hash,
                chain_genesis_time=args.chain_genesis_time,
                chain_period_seconds=args.chain_period_seconds,
                observed_latest_round=args.observed_latest_round,
                draw_round=args.draw_round,
                run_contract=load_run_contract(args.run_contract),
                drand_verifier_binary_path=args.drand_verifier_binary,
                cosign_binary_path=args.cosign_binary,
                sigstore_trusted_root_path=args.sigstore_trusted_root,
                publication_certificate_identity=args.publication_certificate_identity,
                publication_certificate_oidc_issuer=args.publication_certificate_oidc_issuer,
            )
        elif args.command == "resolve":
            payload = resolve_commitment(
                args.campaign_dir,
                drand_chain_info_json_path=args.drand_chain_info,
                publication_anchor_json_path=args.publication_anchor,
                expected_commitment_digest=args.commitment_digest,
            )
        elif args.command == "verify":
            payload = verify_campaign(
                args.campaign_dir,
                require_all_primary_attempts=args.require_all_primary_attempts,
            )
        elif args.command == "report":
            report_path, manifest_path = write_report(
                args.campaign_dir,
                args.output_dir,
            )
            payload = {
                "report": str(report_path),
                "manifest": str(manifest_path),
            }
        elif args.command == "execute":
            payload = execute_paired_campaign_from_config(
                args.campaign_dir,
                executor_config_path=args.executor_config,
            )
        elif args.command == "reserve-primary-matrix":
            path = reserve_primary_matrix(args.campaign_dir)
            payload = {
                "created": str(path),
                "score_eligible_slots": 40,
                "matrix_reserved": True,
            }
        elif args.command == "start-primary":
            path = create_primary_attempt_manifest(
                args.campaign_dir,
                slot_id=args.slot,
            )
            payload = {"created": str(path), "score_eligible": True}
        else:
            path = create_rerun_attempt_manifest(
                args.campaign_dir,
                rerun_id=args.rerun_id,
                primary_slot_id=args.primary_slot,
                reason=args.reason,
            )
            payload = {"created": str(path), "score_eligible": False}
    except (
        OSError,
        CampaignCoordinatorError,
        PairedXbenProtocolError,
        PairedXbenReportError,
        ProductionPreparationError,
    ) as exc:
        sys.stderr.write(f"[paired-xben:blocked] {exc}\n")
        return 2
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


__all__ = ["main"]
