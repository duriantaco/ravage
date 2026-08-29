from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ravage.agent_core.ai_agent import ProviderChatClient
from ravage.model_core.providers import (
    LOCAL_PROVIDERS,
    load_model_registry,
    ready_model_routes,
    resolve_model_routes,
)
from ravage.proof_bundle_eval import (
    evaluate_proof_bundle_cases,
    load_proof_bundle_eval_cases,
    write_proof_bundle_eval_report,
)
from ravage.proof_bundle_verifier import verify_proof_bundle_with_model

if TYPE_CHECKING:
    from pentest_schemas import ProofBundle, ProofVerifierVerdict
    from ravage.model_core.providers import ResolvedModelRoute


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate offline proof-bundle JSONL cases.")
    parser.add_argument("cases", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--live-verifier", action="store_true")
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--model-profile", default="hosted-openai")
    parser.add_argument("--model-tier", choices=["high", "mid", "low"], default="high")
    parser.add_argument("--allow-paid-models", action="store_true")
    args = parser.parse_args()

    cases = load_proof_bundle_eval_cases(args.cases)
    semantic_verifier = None
    if args.live_verifier:
        route = _ready_verifier_route(
            model_config=args.model_config,
            model_profile=args.model_profile,
            model_tier=args.model_tier,
            allow_paid_models=args.allow_paid_models,
        )
        model_client = ProviderChatClient()

        def semantic_verifier(bundle: ProofBundle) -> ProofVerifierVerdict:
            return verify_proof_bundle_with_model(
                bundle,
                model_client=model_client,
                route=route,
            )

    report = evaluate_proof_bundle_cases(cases, semantic_verifier=semantic_verifier)
    payload = report.to_json()
    if args.output is not None:
        write_proof_bundle_eval_report(report, args.output)
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _ready_verifier_route(
    *,
    model_config: Path | None,
    model_profile: str,
    model_tier: str,
    allow_paid_models: bool,
) -> ResolvedModelRoute:
    registry = load_model_registry(model_config)
    routes = resolve_model_routes(registry, profile_name=model_profile, tier=model_tier)
    ready_routes = ready_model_routes(routes)
    if not ready_routes:
        missing = {env_name for route in routes for env_name in route.missing_env}
        message = "no ready model routes"
        if missing:
            message += "; missing env: " + ", ".join(sorted(missing))
        raise SystemExit(message)
    route = ready_routes[0]
    if not allow_paid_models and _is_paid_route(route):
        message = (
            "live verifier route may incur model costs; rerun with --allow-paid-models "
            "after confirming this is intentional"
        )
        raise SystemExit(message)
    return route


def _is_paid_route(route: ResolvedModelRoute) -> bool:
    if route.provider in LOCAL_PROVIDERS:
        return False
    return route.provider not in {"custom_openai", "litellm"}


if __name__ == "__main__":
    main()
