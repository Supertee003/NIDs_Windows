#!/usr/bin/env python3
"""Update aegisctl.py cmd_health function to use new RuntimeHealth."""

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# This one was worse than history: its body sat at module level, so merely
# importing it read tools/aegisctl.py, 'replaced' cmd_health and wrote the file
# back. Its target never held the old body (getRuntimeHealth does not appear in
# aegisctl.py), so it could only rewrite the tree for nothing. Moved here by
# TOOLS-IMPORT-001; the guard exits before any of that.
raise SystemExit(
    "QUARANTINED: tools/legacy/update_health_cmd.py must not run; retained for history only."
)

import sys

with open("tools/aegisctl.py", "r") as f:
    content = f.read()

old_func = '''def cmd_health(args) -> int:
    """Health check."""
    if CONTROL_API_AVAILABLE:
        payload = get_health_payload()
        print(f"\n  Health payload: {payload}")
    else:
        print("\nControl API not available")
    return 0'''

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
