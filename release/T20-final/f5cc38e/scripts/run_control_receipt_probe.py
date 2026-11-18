"""Safe control-plane and receipt fail-closed probe.

This probe uses the canonical named pipe and deliberately sends no valid
flow-enforcement request. The mutation-shaped requests are invalid by
construction, so they must be rejected before a WFP filter can be created.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from aegisctl.client import AegisClient, AegisCtlError  # noqa: E402


READ_ONLY = (
    ("enforcement.status", {}),
    ("enforcement.simulate", {}),
    ("enforcement.verify", {}),
)
INVALID_MUTATIONS = (
    ("enforcement.block", {}),
    ("enforcement.unblock", {"filter_id": 0}),
)


def send(client: AegisClient, command: str, payload: dict) -> dict:
    try:
        response = client.send(command, payload)
    except AegisCtlError as exc:
        response = {"ok": False, "transport_error": str(exc)}
        print(json.dumps({"command": command, "response": response}, sort_keys=True))
        return response
    print(json.dumps({"command": command, "response": response}, sort_keys=True))
    return response


def main() -> int:
    client = AegisClient(transport="pipe")
    failures: list[str] = []

    print("[1/2] Read-only enforcement routes")
    for command, payload in READ_ONLY:
        response = send(client, command, payload)
        if "transport_error" in response:
            failures.append(f"{command}: transport error")

    print("[2/2] Invalid mutation routes must fail closed")
    for command, payload in INVALID_MUTATIONS:
        response = send(client, command, payload)
        data = response.get("data")
        text = json.dumps(response, sort_keys=True)
        if response.get("ok") is True:
            failures.append(f"{command}: unexpectedly accepted invalid payload")
        if "ENFORCED" in text or (isinstance(data, dict) and data.get("filter_id")):
            failures.append(f"{command}: response contains an enforcement receipt")

    result = {"passed": not failures, "failures": failures}
    print("CONTROL_RECEIPT_PROBE_RESULT " + json.dumps(result, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
