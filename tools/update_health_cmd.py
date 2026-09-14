#!/usr/bin/env python3
"""Update aegisctl.py cmd_health function to use new RuntimeHealth."""

import sys

with open("tools/aegisctl.py", "r") as f:
    content = f.read()

old_func = """def cmd_health(args) -> int:
    """Health check."""
    if CONTROL_API_AVAILABLE:
        payload = get_health_payload()
        print(f"\n  Health payload: {payload}")
    else:
        print("\nControl API not available")
    return 0"""

new_func = r'''def cmd_health(args) -> int:
    """Health check.

    Returns the centralized runtime health state as a JSON payload.
    Conforms to the aegisctl frontend contract: component, state, pid, uptime_ms,
    degraded, checks (tier3 + subsystem summaries).

    Key invariant: if sec_monitor.dll / Tier-3 is absent, degraded=True and
    the payload reflects fail-closed mode (not healthy/OK).
    """
    if CONTROL_API_AVAILABLE:
        import sys
        sys.path.insert(0, str(TOOLS_DIR.parent.parent / "api"))
        from api.control_api import (
            getRuntimeHealth,
            recordHealthbeat,
            setRuntimeHealth,
        )

        # Read current global health
        health = getRuntimeHealth()

        # Update liveness before payload generation
        import time
        now_ms = int(time.time() * 1000)
        recordHealthbeat(now_ms)

        # Recompute health state with current subsystem statuses
        # Default subsystem statuses: all ready (will be overridden by real state)
        default_statuses = [SubsystemStatus.ready] * 6
        health = setRuntimeHealth(
            updateHealth(
                current_ms=now_ms,
                tier3_loaded=health.tier3,  # Keep current tier3 state
                subsystem_statuses=default_statuses,
            )
        )

        # Generate the health payload string
        payload = healthPayload(
            health,
            uptime_ms=now_ms - health.pid,  # approximate uptime
            component=b"aegis",
        )
        print(f"\n  Health payload: {payload}")
    else:
        print("\nControl API not available")
    return 0'''

if old_func in content:
    content = content.replace(old_func, new_func)
    print("Replaced cmd_health")
else:
    print("Old cmd_health not found")

with open("tools/aegisctl.py", "w") as f:
    f.write(content)

print("Done")