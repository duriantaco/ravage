from __future__ import annotations

import shutil


class MissingToolCapabilitiesError(RuntimeError):
    pass


_CAPABILITY_PROVIDERS = {
    "dir_bruteforce": ("ffuf_dir", "gobuster_dir", "katana_crawl"),
    "port_scan": ("nmap_scan",),
    "crawl": ("katana_crawl",),
}
_PRIMARY_ACTION_CAPABILITY = {
    "ffuf_dir": "dir_bruteforce",
    "gobuster_dir": "dir_bruteforce",
    "nmap_scan": "port_scan",
    "katana_crawl": "crawl",
}


def build_tool_capability_report(
    *,
    context: dict[str, object],
    tool_recon: bool,
    runtime_mode: str,
) -> dict[str, object]:
    required = _list_items(context.get("required_capabilities"))
    optional = _list_items(context.get("optional_capabilities"))
    if tool_recon:
        optional.extend(["dir_bruteforce", "port_scan"])
        required = []
    capabilities: dict[str, object] = {}
    for capability in dict.fromkeys([*required, *optional]):
        providers = [
            {"action": action, "available": shutil.which(action.split("_", 1)[0]) is not None}
            for action in _CAPABILITY_PROVIDERS.get(str(capability), ())
        ]
        selected = next((item for item in providers if item["available"]), None)
        capabilities[str(capability)] = {
            "available": selected is not None,
            "providers": providers,
            "selected_provider": selected,
        }
    missing_required = [
        item for item in required if not _capability_available(capabilities.get(str(item)))
    ]
    missing_optional = [
        item for item in optional if not _capability_available(capabilities.get(str(item)))
    ]
    return {
        "required_capabilities": required,
        "optional_capabilities": optional,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "blocking": bool(missing_required),
        "degraded": bool(missing_required or missing_optional),
        "capabilities": capabilities,
        "runtime_mode": runtime_mode,
    }


def replacement_action_for_capability(report: dict[str, object], action: str) -> str | None:
    capabilities = report.get("capabilities")
    if not isinstance(capabilities, dict):
        return None
    capability = _PRIMARY_ACTION_CAPABILITY.get(action)
    status = capabilities.get(capability) if capability is not None else None
    if isinstance(status, dict):
        selected = status.get("selected_provider")
        if isinstance(selected, dict):
            return str(selected.get("action") or "")
    return None


def _list_items(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _capability_available(status: object) -> bool:
    if not isinstance(status, dict):
        return False
    return bool(status.get("available"))


def unavailable_tool_observation_fields(
    *,
    action: str,
    args: dict[str, object],
    capability_report: dict[str, object],
) -> dict[str, object]:
    del args
    return {
        "error_type": "tool_unavailable",
        "action": action,
        "capability": "dir_bruteforce" if "ffuf" in action or "gobuster" in action else "",
        "fallbacks_available": ["katana_crawl", "gobuster_dir"],
        "install_hint": "Run ravage tools install or ravage tools check.",
        "capability_report": capability_report,
    }
