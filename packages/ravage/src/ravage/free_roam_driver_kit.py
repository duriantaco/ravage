from __future__ import annotations

FREE_ROAM_DRIVER_KIT = """
# Free-roam drivers are intentionally not exposed as callable Python stubs.
# Use the probe-backed recommendations in the prompt instead:
#   {"action": "run_probe", "probe": "<recommended probe>"}
#
# This avoids teaching the agent to call fake helpers such as
# run_deserialization() or run_blind_sqli() when no such runtime driver exists.
"""
