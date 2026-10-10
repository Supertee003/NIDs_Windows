#!/usr/bin/env python3
"""AEGIS NIDS Control Plane CLI (aegisctl) v6.1

Modular CLI for managing the AEGIS NIDS service.
Each command is a separate module in tools/aegisctl/commands/.
# The command surface follows the aegisctl.commands modular contract; this
# file remains the thin process entry point and delegates state/business logic.

STRICT INVARIANT: No component may bypass the Rust PEP for enforcement.
All block/allow/quarantine requests route through aegis_pep_enforce() FFI.
Direct operating-system firewall calls or bridge mutation calls are NEVER permitted.

Usage:
    python tools/aegisctl.py status                    # pipe transport (Windows ACL protected)
    python tools/aegisctl.py rules list
    python tools/aegisctl.py alerts view
    python tools/aegisctl.py dashboard
"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import sys
import time
from pathlib import Path
from typing import Dict, Callable
from aegisctl.contracts import project_operator_state

# Ensure tools/ is on the path
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# Import control API with ALL business logic
# The control_api module is a subpackage of the aegisctl package.
# It contains the single source of truth for control plane business logic,
# and CLI/TUI/WEB must ALL delegate to this module for enforcement decisions.
try:
    from aegisctl.api.control_api import (
        get_all_status,
        get_subsystem_status,
        load_rules,
        compile_tier2_rules,
        run_regex_scan,
        request_enforcement_via_pep,
        apply_firewall_block,
        get_defcon,
        get_active_rules,
        get_health_payload,
        query_control,
        query_forensic_records,
        verify_authority_invariant,
        diagnose_endpoint_ownership,
        bridge_diagnostic,
        pipe_latency_probe,
        rule_id_to_u32,
    )
    from aegisctl.components import components_status
    CONTROL_API_AVAILABLE = True
except ImportError as e:
    # Fallback: try adding api to path
    sys.path.insert(0, str(TOOLS_DIR / "api"))
    try:
        from api.control_api import (
            get_all_status,
            get_subsystem_status,
            load_rules,
            compile_tier2_rules,
            run_regex_scan,
            request_enforcement_via_pep,
            apply_firewall_block,
            get_defcon,
            get_active_rules,
            get_health_payload,
            query_control,
            query_forensic_records,
            verify_authority_invariant,
            diagnose_endpoint_ownership,
            bridge_diagnostic,
            pipe_latency_probe,
            rule_id_to_u32,
        )
        from aegisctl.components import components_status
        CONTROL_API_AVAILABLE = True
    except ImportError:
        CONTROL_API_AVAILABLE = False
else:
    CONTROL_API_AVAILABLE = True


def cmd_status(args) -> int:
    """Show subsystem status.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    if CONTROL_API_AVAILABLE:
        statuses = get_all_status()
        health = get_health_payload()
        component = getattr(args, "component", None)
        if component:
            aliases = {
                "bridge": {"bridge", "c_bridge"},
                "core": {"core", "zig"},
                "brain": {"brain", "python_brain"},
                "aggregator": {"aggregator", "go_aggregator"},
            }
            accepted = aliases.get(component, {component})
            statuses = [item for item in statuses if item[0] in accepted]
            if not statuses:
                # A named component that the daemon does not know about is
                # NOT running. Reporting the global daemon state here (with a
                # 0/0 subsystem list) would claim a component exists when it
                # does not.
                if getattr(args, "json", False):
                    print(json.dumps({
                        "component": component,
                        "subsystem_list": [],
                        "available": False,
                        "state": "NOT_REGISTERED",
                        "reason": "component_not_registered_in_runtime",
                    }, sort_keys=True))
                else:
                    print(f"\n  Component: {component}")
                    print("  Subsystem list: (none registered)")
                    print("  State: NOT_REGISTERED")
                    print("  Reason: component_not_registered_in_runtime")
                return 1
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        if getattr(args, "json", False):
            print(json.dumps({"health": health, "subsystems": statuses}, sort_keys=True))
            return 0
        print(f"\n  State: {health['state']}")
        print(f"  Version: {health.get('version', 'unknown')}")
        print(f"  Uptime: {health.get('uptime_ms', 0)} ms")
        print(f"  Packets captured: {health.get('packets_captured', 0)}")
        print(f"  Flows active: {health.get('flows_active', 0)}")
        print(f"  {running}/{total} subsystems running")
        for name, is_running, pid in statuses:
            if is_running:
                print(f"  [RUNNING] {name.upper():<10} (PID: {pid})")
            else:
                print(f"  [STOPPED] {name.upper():<10}")
    else:
        print("\nControl API not available - showing basic status")
        # Basic fallback
        print("\n  Subsystem status (basic)")
    return 0


def cmd_start(args) -> int:
    """Request runtime start from the Zig daemon.

    Normal lifecycle is owned by the daemon supervisor.  This CLI command is
    intentionally a thin client and must not create processes, write PID
    files, or infer readiness from executable presence.  Emergency recovery is
    a separate, explicitly named operation and is not part of ``start``.
    """
    from aegisctl import EXIT_OK, EXIT_RUNTIME_UNAVAILABLE
    from aegisctl.client import AegisCtlError, AegisClient

    payload = {"all": bool(getattr(args, "all", False))}
    component = getattr(args, "component", None)
    if component:
        payload["component"] = component

    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        response = client.send("runtime.start", payload)
    except AegisCtlError as exc:
        print(f"CORE_NOT_RUNNING: runtime control unavailable: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE

    if not response.get("ok", False):
        code = response.get("code", "RUNTIME_START_FAILED")
        data = response.get("data") or {}
        message = data.get("message", "runtime start was not completed") if isinstance(data, dict) else str(data)
        print(f"{code}: {message}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE if code == "NOT_IMPLEMENTED" else 1

    data = response.get("data") or {}
    print(f"[OK] runtime start requested: {data}")
    return EXIT_OK


def cmd_stop(args) -> int:
    """Request an orderly daemon shutdown through the control plane.

    The daemon owns the worker handles and performs the signal/join sequence
    after this response is flushed.  The CLI therefore reports ``STOPPING``
    rather than claiming that all threads have already joined.  There is no
    process-kill fallback in the normal command.
    """
    from aegisctl import EXIT_OK, EXIT_RUNTIME_UNAVAILABLE
    from aegisctl.client import AegisCtlError, AegisClient

    component = getattr(args, "component", None)
    all_flag = bool(getattr(args, "all", False))
    if component and all_flag:
        print("ERROR: --component and --all are mutually exclusive", file=sys.stderr)
        return 2
    if not component and not all_flag:
        print("ERROR: --component NAME or --all required", file=sys.stderr)
        return 2
    if component and component not in {"core", "zig"}:
        print("ERROR: daemon control owns the complete runtime; use --all or --component core", file=sys.stderr)
        return 2

    try:
        client = AegisClient(transport=getattr(args, "transport", "pipe"))
        response = client.send("daemon.shutdown", {"all": all_flag, "component": component})
    except AegisCtlError as exc:
        print(f"CONTROL_PIPE_UNAVAILABLE: orderly stop was not requested: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_UNAVAILABLE

    if not response.get("ok", False):
        code = response.get("code", "RUNTIME_STOP_FAILED")
        data = response.get("data") or {}
        message = data.get("message", "runtime stop was not accepted") if isinstance(data, dict) else str(data)
        print(f"{code}: {message}", file=sys.stderr)
        return 1

    print("[OK] runtime stop requested; daemon is stopping and will join workers")
    return EXIT_OK


def cmd_restart(args) -> int:
    """Reject restart until one owner can prove stop/join/start readiness."""
    print(
        "RUNTIME_RESTART_UNAVAILABLE: restart requires an external service manager "
        "or a daemon-owned stop/join/start transaction",
        file=sys.stderr,
    )
    return 4


def cmd_diagnose(args) -> int:
    """Print a structured diagnostic snapshot without mutating runtime state."""
    if not CONTROL_API_AVAILABLE:
        print("\nControl API not available")
        return 4

    payload = get_health_payload()
    print("\n  VERSION")
    print(f"  {payload.get('version', 'unknown')}")
    print("  RUNTIME STATUS")
    print(f"  State: {payload['state']}")
    print(f"  Degraded: {payload.get('degraded', True)}")
    print("  SUBSYSTEM HEALTH")
    for name, status in payload.get("subsystems", {}).items():
        print(f"  [{status['state']}] {name.upper():<18}")
    print("  TIER3")
    print(f"  [{payload.get('tier3', {}).get('state', 'UNKNOWN')}] Rust PEP")
    print("  LOG FILES")
    print(f"  Repo root: {TOOLS_DIR.parent}")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  Platform: {sys.platform}")
    print("  WORKERS")
    workers = payload.get("workers", {})
    if workers:
        for name, ready in workers.items():
            if name == "failure_reason":
                print(f"  [REASON] {ready}")
            elif name == "failure_mask":
                print(f"  [MASK] {ready}")
            elif name == "failure_reasons":
                print(f"  [REASONS] {', '.join(ready) if ready else 'none'}")
            else:
                print(f"  [{'READY' if ready else 'NOT READY'}] {name}")
    else:
        print("  [UNKNOWN] readiness fields unavailable")
    print("  ENDPOINT OWNERSHIP")
    ownership = diagnose_endpoint_ownership()
    for finding in ownership["findings"]:
        endpoint = finding.get("endpoint", "?")
        status = finding.get("status", "?")
        detail = finding.get("detail", "")
        if finding.get("pid") is not None:
            detail += " (pid %s)" % finding["pid"]
        print(f"  [{status}] {endpoint}: {detail}")
    if ownership["foreign_count"]:
        print(f"  [ORPHAN?] {ownership['foreign_count']} foreign listener(s) "
              "on owned endpoints — detection only, nothing was stopped")
    print("  Diagnostic report complete")
    return 0


def cmd_health(args) -> int:
    """Health check.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    Key invariant: if sec_monitor.dll / Tier-3 is absent, degraded=True
    and the payload reflects fail-closed mode (not healthy/OK).
    """
    if CONTROL_API_AVAILABLE:
        payload = get_health_payload()
        if getattr(args, "json", False):
            print(json.dumps(payload, sort_keys=True))
            return 1 if getattr(args, "strict", False) and payload.get("degraded", True) else 0
        print(f"  State: {payload.get('state', 'UNKNOWN')}")
        print(f"  Degraded: {payload.get('degraded', True)}")
        print(f"  Packets captured: {payload.get('packets_captured', 0)}")
        print(f"  Flows active: {payload.get('flows_active', 0)}")
        print(f"\n  Health payload: {payload}")
        workers = payload.get("workers", {})
        if workers:
            print("  Worker readiness:")
            for name, ready in workers.items():
                if name == "failure_reason":
                    print(f"    {name}: {ready}")
                elif name == "failure_mask":
                    print(f"    {name}: {ready}")
                elif name == "failure_reasons":
                    print(f"    {name}: {', '.join(ready) if ready else 'none'}")
                elif name == "failed":
                    print(f"    {name}: {'FAILED' if ready else 'NO'}")
                else:
                    print(f"    {name}: {'READY' if ready else 'NOT READY'}")
    else:
        print("\nControl API not available")
    return 0


def _print_control_query(command: str, as_json: bool = True, payload: dict | None = None) -> int:
    """Print a read-only control-plane response as formatted JSON."""
    if not CONTROL_API_AVAILABLE:
        print("\nControl API not available")
        return 4
    result = query_control(command, payload=payload)
    if result is None:
        print(f"\nControl query failed: {command}")
        return 3
    import json
    print(json.dumps(result, indent=2 if as_json else None, sort_keys=True))
    return 0


def cmd_version(args) -> int:
    """Show component versions from the control-plane contract."""
    # VER-TRUTH-032: every value mirrors its component's own source of truth:
    # core/nose 5.0.0 (product line; nose/main.go AEGIS_NOSE_VERSION), pep
    # 5.0.0 (Cargo package aegis_pep), brain 2.0.0 (windows_brain --version),
    # shield 0.1.0 (shield/Cargo.toml), aggregator 0.1.0 (its --version).
    versions = {
        "core": "5.0.0",
        "nose": "5.0.0",
        "pep": "5.0.0",
        "brain": "2.0.0",
        "shield": "0.1.0",
        "bridge": "1.0.0",
        "aggregator": "0.1.0",
    }
    component = getattr(args, "component", None)
    print("Component        Version")
    for name, version in versions.items():
        if component is None or component == name:
            print(f"{name:<16} {version}")
    return 0


def cmd_metrics(args) -> int:
    return _print_control_query("metrics.snapshot", as_json=getattr(args, "json", True))


def _format_queue_rows(response: dict) -> list[str]:
    """Pure: render queue.stats buckets + pipeline stages as text rows."""
    rows = [
        f"queue {response.get('depth', '?')}/{response.get('queue_size', '?')} "
        f"pushed={response.get('pushed_total', '?')} "
        f"dropped={response.get('dropped_total', '?')} "
        f"shed_overload={response.get('shed_overload', '?')}",
    ]
    for bucket in response.get("by_source", []) or []:
        rows.append(
            f"  src={bucket.get('name', '?')}({bucket.get('ordinal', '?')}) "
            f"pushed={bucket.get('pushed', '?')} "
            f"dropped={bucket.get('dropped', '?')}"
        )
    etw = response.get("etw") or {}
    if etw:
        rows.append(
            f"  etw start={etw.get('process_start', '?')} "
            f"name={etw.get('file_name_create', '?')}+{etw.get('file_name_delete', '?')} "
            f"write={etw.get('file_write', '?')} "
            f"reg={etw.get('reg_create', '?')}+{etw.get('reg_set', '?')} "
            f"unmapped={etw.get('dropped_unmapped', '?')} "
            f"predecode={etw.get('predecode_dropped', '?')} "
            f"exempt={etw.get('shed_exempted', '?')}"
        )
    for stage in response.get("pipeline", []) or []:
        rows.append(
            f"  stage={stage.get('stage', '?')} count={stage.get('count', '?')} "
            f"p50={stage.get('p50_ns', '?')}ns p95={stage.get('p95_ns', '?')}ns "
            f"max={stage.get('max_ns', '?')}ns"
        )
    return rows


def cmd_queue(args) -> int:
    """Show pipeline queue ingress per source plus latency snapshot (GAP-015).

    Thin over the queue.stats control command; the daemon owns every number.
    """
    if not CONTROL_API_AVAILABLE:
        return _unavailable("queue", "control_api_unavailable")
    try:
        response = query_control("queue.stats")
    except Exception:
        response = None
    if not response:
        return _unavailable("queue", "control_daemon_query_failed")
    if bool(getattr(args, "json", False)):
        print(json.dumps(response, sort_keys=True))
        return 0
    for row in _format_queue_rows(response):
        print(row)
    return 0


def cmd_federation(args) -> int:
    """Show federation cluster status (read-only, runtime federation.status)."""
    return _print_control_query("federation.status", as_json=getattr(args, "json", True))


def cmd_snapshot(args) -> int:
    """Emit one authoritative daemon snapshot for dashboards and automation."""
    if not CONTROL_API_AVAILABLE:
        print(json.dumps({
            "available": False,
            "reason": "control_api_unavailable",
        }, sort_keys=True))
        return 4

    try:
        health = get_health_payload()
        metrics = query_control("metrics.snapshot")
        forensic = query_control("forensics.verify")
        enforcement = query_control("enforcement.status")
    except Exception as exc:
        print(json.dumps({
            "available": False,
            "reason": "control_query_exception",
            "error": str(exc),
        }, sort_keys=True))
        return 3

    if any(value is None for value in (
        health, metrics, forensic, enforcement
    )):
        print(json.dumps({
            "available": False,
            "reason": "control_query_failed",
            "health": health,
            "metrics": metrics,
            "forensic": forensic,
            "enforcement": enforcement,
        }, sort_keys=True))
        return 3

    enforcement = dict(enforcement)
    enforcement.setdefault("host_effect_confirmed", False)

    try:
        authority_held = bool(verify_authority_invariant())
    except Exception:
        authority_held = False

    gate = str(
        enforcement.get("prevention_gate", "closed")
    ).lower()

    operator = project_operator_state(health, enforcement)
    try:
        # EVT-163: the five components as concepts for native dashboards.
        # Fast path only (health-derived + path checks): the GUI polls this
        # every 30s, so no process probes here -- see `aegisctl components`.
        components = components_status(health if isinstance(health, dict) else {})
    except Exception:
        components = []
    document = {
        "available": True,
        "health": health,
        "metrics": metrics,
        "forensic": forensic,
        "enforcement": enforcement,
        "components": components,
        "authority": {
            "canonical": health.get(
                "canonical_enforcement_authority",
                "rust_pep",
            ),
            "invariant": "HELD" if authority_held else "VIOLATED",
        },
        "operator": operator,
        "presentation": {
            "mode": (
                "CONTRACT_VIOLATION"
                if operator["contract_errors"]
                else "CONTROLLED_ENFORCEMENT"
                if gate == "open"
                else "OBSERVE_ONLY"
            ),
            "host_effect": (
                "CONFIRMED"
                if enforcement.get("host_effect_confirmed") is True and not operator["contract_errors"]
                else "NOT_PROVEN"
            ),
            "contract_errors": operator["contract_errors"],
        },
    }

    print(json.dumps(document, sort_keys=True))
    return 0


def cmd_forensics(args) -> int:
    if args.forensics_command == "verify":
        return _print_control_query("forensics.verify", as_json=getattr(args, "json", True))
    limit = max(1, min(int(getattr(args, "limit", 100)), 1000))
    if getattr(args, "all", False):
        if not CONTROL_API_AVAILABLE:
            print("\nControl API not available")
            return 4
        # `--all` follows the daemon's byte-budgeted page cursor so a large
        # result set is complete instead of silently short.
        document = query_forensic_records(
            limit,
            source=getattr(args, "source", None),
            payload_prefix=getattr(args, "payload_prefix", None),
            after=getattr(args, "after", None),
        )
        if document is None:
            print("\nControl query failed: forensics.list", file=sys.stderr)
            return 3
        if document.get("truncated") is True:
            # Report incompleteness on stderr; stdout stays the merged document.
            print(json.dumps({
                "command": "forensics.list",
                "warning": "page_budget_exhausted",
                "pages": document.get("pages"),
                "next_after": document.get("next_after"),
                "records_returned": document.get("records_returned"),
            }, sort_keys=True), file=sys.stderr)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    payload = {}
    payload["limit"] = limit
    if getattr(args, "after", None) is not None:
        payload["after"] = max(0, int(args.after))
    if getattr(args, "source", None) is not None:
        payload["source"] = int(args.source)
    if getattr(args, "payload_prefix", None):
        payload["payload_prefix"] = args.payload_prefix
    result = _print_control_query("forensics.list", as_json=getattr(args, "json", True), payload=payload)
    return result


def cmd_readiness(args) -> int:
    """Machine-oriented readiness gate for operators and automation."""
    if not CONTROL_API_AVAILABLE:
        print(json.dumps({"ready": False, "reason": "control_api_unavailable"}, sort_keys=True))
        return 3
    payload = get_health_payload()
    workers = payload.get("workers", {})
    required = ["pipeline_ready", "sensor_ready", "nose_ready", "etw_ready", "fim_ready", "registry_ready"]
    missing_workers = [name for name in required if workers.get(name) is not True]
    missing = list(missing_workers)
    rules_loaded = int(payload.get("rules_loaded", 0) or 0)
    policies_loaded = int(payload.get("policies_loaded", 0) or 0)
    if rules_loaded <= 0:
        missing.append("rules_loaded")
    degraded_components = []
    for name, status in (payload.get("subsystems") or {}).items():
        if not isinstance(status, dict):
            continue
        if str(status.get("state", "")).upper() in {"DEGRADED", "FAILED", "STOPPED"}:
            degraded_components.append({"name": name, "state": status.get("state"), "error": status.get("error")})
    worker_gate = not missing_workers and not workers.get("failed", False)
    overall_gate = (
        payload.get("state") == "RUNNING"
        and not payload.get("degraded", True)
        and worker_gate
        and rules_loaded > 0
    )
    reasons = list(workers.get("failure_reasons", []))
    if rules_loaded <= 0:
        reasons.append("rules_not_loaded")
    reasons.extend(
        f"{item['name']}_{str(item.get('error') or item.get('state', 'not_ready')).lower()}"
        for item in degraded_components
    )
    result = {
        "ready": overall_gate,
        "state": payload.get("state"),
        "degraded": payload.get("degraded", True),
        "worker_gate": worker_gate,
        "overall_gate": overall_gate,
        "missing": missing,
        "rules_loaded": rules_loaded,
        "policies_loaded": policies_loaded,
        "degraded_components": degraded_components,
        "failure_reasons": sorted(set(reasons)),
    }
    print(json.dumps(result, indent=2 if getattr(args, "pretty", False) else None, sort_keys=True))
    return 0 if overall_gate else 1


def cmd_rules(args) -> int:
    """Rules management.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    rules = load_rules().get("nids_rules", []) if CONTROL_API_AVAILABLE else []
    op = getattr(args, "rules_command", "list")
    if op == "list":
        original = rules
        severity = getattr(args, "severity", None)
        category = getattr(args, "category", None)
        if severity:
            rules = [r for r in rules if str(r.get("severity", "")).lower() == severity.lower()]
        if category:
            rules = [r for r in rules if category.lower() in json.dumps(r).lower()]
        if not rules and (severity or category):
            print(f"No rules found; filtered by {severity or category}")
        else:
            print("Rule ID        Name                         Severity   Category")
            for r in rules:
                print(f"{r.get('rule_id',''):14} {r.get('name','')[:28]:28} {r.get('severity',''):10} {r.get('category','')}")
            suffix = f" (filtered by {severity or category})" if severity or category else ""
            print(f"Total: {len(rules)}{suffix}")
        daemon_count = _daemon_rules_count()
        if daemon_count is None:
            print("Active daemon rules: UNKNOWN (control daemon unavailable)")
        elif daemon_count != len(original):
            print(f"WARNING: local catalog={len(original)} but active daemon rules={daemon_count}")
        else:
            print(f"Active daemon rules: {daemon_count} (matches local catalog)")
        return 0
    if op == "show":
        rule_id = str(args.id)
        match = next((r for r in rules if str(r.get("rule_id")) == rule_id), None)
        if match is None:
            print(f"Rule {rule_id} not found")
            return 1
        print(json.dumps(match, indent=2))
        return 0
    if op == "validate":
        valid, errors = _validate_rules(rules)
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
        print(f"{'VALID' if valid else 'INVALID'}: {len(rules)} rules checked")
        daemon_count = _daemon_rules_count()
        if daemon_count is None:
            print("Active daemon rules: UNKNOWN (control daemon unavailable)")
        elif daemon_count != len(rules):
            print(f"WARNING: validated local catalog={len(rules)} but active daemon rules={daemon_count}")
        else:
            print(f"Active daemon rules: {daemon_count} (matches validated catalog)")
        return 0 if valid else 1
    if op == "reload":
        response = query_control("rules.reload") if CONTROL_API_AVAILABLE else None
        if response is None:
            print("Rules reload failed: daemon control pipe unavailable", file=sys.stderr)
            return 1
        if not isinstance(response, dict):
            print("Rules reload failed: invalid daemon response", file=sys.stderr)
            return 1
        loaded = int(response.get("rules_loaded", response.get("loaded", 0)) or 0)
        postcondition = response.get("postcondition")
        result = {
            "command": "rules.reload",
            "previous_rules_loaded": response.get("previous_rules_loaded"),
            "rules_loaded": loaded,
            "status": response.get("status"),
            "postcondition": postcondition,
        }
        # BE-DRIFT-098: pass the named-skip report through when the
        # daemon serves it (old binaries omit these keys; the gate
        # below only depends on the long-standing keys).
        if isinstance(response.get("skipped"), dict):
            result["skipped"] = response["skipped"]
        if isinstance(response.get("skipped_ids"), list):
            result["skipped_ids"] = response["skipped_ids"]
        if isinstance(response.get("skipped_truncated"), bool):
            result["skipped_truncated"] = response["skipped_truncated"]
        print(json.dumps(result, indent=2, sort_keys=True))
        if loaded <= 0 or response.get("status") != "reloaded" or postcondition != "ACTIVE":
            return 5
        return 0
    if op in {"add", "update", "delete"}:
        return _mutate_rules(args, op)
    return 2


def _rules_path() -> Path:
    return TOOLS_DIR.parent / "configs" / "Rules.json"


def _validate_rules(rules: list[dict]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    allowed_severity = {"Low", "Medium", "High", "Critical"}
    allowed_action = {"Pass", "Log", "Alert", "RateLimit", "Block", "Drop", "Quarantine", "Escalate"}
    ids: set[str] = set()
    for index, rule in enumerate(rules):
        prefix = f"rule[{index}]"
        rid = str(rule.get("rule_id", ""))
        if not rid: errors.append(f"{prefix} missing rule_id")
        if rid in ids: errors.append(f"{prefix} duplicate rule_id {rid}")
        ids.add(rid)
        if not rule.get("name"): errors.append(f"{prefix} missing name")
        if rule.get("severity") not in allowed_severity: errors.append(f"{prefix} invalid severity")
        if rule.get("action") not in allowed_action: errors.append(f"{prefix} invalid action")
        if not (rule.get("match_pattern") or rule.get("regex_pattern") or rule.get("fast_pattern")):
            errors.append(f"{prefix} needs match_pattern, regex_pattern, or fast_pattern")
    return not errors, errors


def _save_rules(rules: list[dict]) -> None:
    valid, errors = _validate_rules(rules)
    if not valid:
        raise ValueError("; ".join(errors))
    path = _rules_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps({"schema_version": "2.0", "nids_rules": rules}, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _mutate_rules(args, op: str) -> int:
    rules = load_rules().get("nids_rules", [])
    rid = str(getattr(args, "id", ""))
    index = next((i for i, rule in enumerate(rules) if str(rule.get("rule_id")) == rid), None)
    if op == "delete":
        if index is None:
            print(f"Rule {rid} not found")
            return 1
        rules.pop(index)
    else:
        try:
            candidate = json.loads(args.rule_json) if getattr(args, "rule_json", None) else {
                "rule_id": rid,
                "name": args.name,
                "category": args.category,
                "layer": args.layer,
                "severity": args.severity,
                "action": args.action,
                "match_pattern": args.match_pattern,
                "regex_pattern": args.regex_pattern,
            }
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON rule: {exc}")
            return 2
        if op == "add" and index is not None:
            print(f"Rule {rid} already exists")
            return 1
        if op == "update":
            if index is None:
                print(f"Rule {rid} not found")
                return 1
            candidate["rule_id"] = rid
            rules[index] = {**rules[index], **{k: v for k, v in candidate.items() if v is not None}}
        else:
            rules.append(candidate)
    try:
        _save_rules(rules)
    except ValueError as exc:
        print(f"INVALID rule set: {exc}")
        return 1
    except OSError as exc:
        # Guest/hardened hosts: Rules.json may be admin-writable only.
        # A traceback here would leak paths and confuse operators.
        print(f"Cannot write rules file (need elevation?): {exc}")
        return 1
    print(f"Rule {rid} {'deleted' if op == 'delete' else 'added' if op == 'add' else 'updated'}")
    return 0


def _event_log_candidates() -> list[Path]:
    # The service writes relative to ITS cwd (System32), an interactive run
    # relative to the repo. events must read whichever is live, never a
    # stale default blindly (F2: the CWD file held 2 test lines for weeks
    # while the service wrote megabytes elsewhere).
    return [
        Path(r"C:\Windows\System32\logs\aegis_core.ndjson"),
        TOOLS_DIR.parent / "logs" / "aegis_core.ndjson",
    ]


def _select_event_log(candidates: list[Path]) -> Path | None:
    """Newest existing candidate wins; None when nothing exists."""
    best: Path | None = None
    best_mtime = -1.0
    for path in candidates:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_mtime:
            best, best_mtime = path, mtime
    return best


def _event_log() -> Path:
    selected = _select_event_log(_event_log_candidates())
    if selected is not None:
        return selected
    return TOOLS_DIR.parent / "logs" / "aegis_core.ndjson"


def _event_log_note(path: Path) -> str:
    try:
        age = time.time() - path.stat().st_mtime
        return f"events source: {path} ({age:.0f}s old)"
    except OSError:
        return f"events source: {path} (unreadable)"


def _read_events() -> list[dict]:
    path = _event_log()
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
        except json.JSONDecodeError:
            continue
    return rows


def cmd_events(args) -> int:
    path = _event_log()
    note = _event_log_note(path)
    events = _read_events()
    op = getattr(args, "events_command", "count")
    if op == "count":
        if getattr(args, "json", False):
            print(json.dumps({"events": len(events), "source": str(path)}, sort_keys=True))
        else:
            print(f"Events: {len(events)}")
            print(note)
    elif op == "tail":
        count = getattr(args, "count", 10)
        if not events:
            print("No events found")
            print(note)
        else:
            for item in events[-count:]:
                print(json.dumps(item, sort_keys=True) if getattr(args, "json", True) else item)
            print(f"{min(count, len(events))} event(s)")
            print(note)
            if getattr(args, "follow", False):
                seen = len(events)
                try:
                    while True:
                        time.sleep(max(0.1, getattr(args, "interval", 1.0)))
                        current = _read_events()
                        for item in current[seen:]:
                            print(json.dumps(item, sort_keys=True) if getattr(args, "json", True) else item, flush=True)
                        seen = len(current)
                except KeyboardInterrupt:
                    return 0
    else:
        if not events:
            print("No log file or events available")
            print(note)
        else:
            levels = {}
            for item in events:
                level = item.get("level", item.get("severity", "unknown"))
                levels[str(level)] = levels.get(str(level), 0) + 1
            print("Event Statistics")
            payload = {"total": len(events), "levels": levels, "source": str(path)}
            print(json.dumps(payload, indent=2) if getattr(args, "json", True) else payload)
            print(note)
    return 0


def cmd_forensic(args) -> int:
    """Query forensic evidence through the authenticated control daemon."""
    if not CONTROL_API_AVAILABLE:
        print(json.dumps({"available": False, "reason": "control_api_unavailable"}, sort_keys=True), file=sys.stderr)
        return 1
    op = getattr(args, "forensic_command", "list")
    if op == "verify":
        response = query_control("forensics.verify")
    elif op == "show":
        response = query_control("forensics.show", payload={"id": int(args.id)})
    elif op == "search":
        field = str(args.field)
        value = str(args.value)
        if field == "source":
            # Source is the numeric origin ordinal (9 npcap, 10 host
            # telemetry), not an IP: reject text cleanly, never traceback.
            try:
                payload = {"source": int(value)}
            except ValueError:
                print(json.dumps({"available": False, "command": "forensics.search",
                                  "reason": "source_must_be_a_numeric_ordinal",
                                  "hint": "use --field payload_prefix for text"}, sort_keys=True),
                      file=sys.stderr)
                return 2
        elif field == "rule":
            # Catalog id ("R9059") or bare integer: hashed client-side to
            # the daemon's u32 rule space (FNV-1a, same as the engine).
            try:
                payload = {"rule": rule_id_to_u32(value)}
            except ValueError:
                print(json.dumps({"available": False, "command": "forensics.search",
                                  "reason": "rule_must_be_an_id_or_integer"}, sort_keys=True),
                      file=sys.stderr)
                return 2
        elif field == "payload_prefix":
            payload = {"payload_prefix": value}
        else:
            print(json.dumps({"available": False, "command": "forensics.search", "reason": "control_protocol_supports_source_or_payload_prefix_filters_only", "field": field}, sort_keys=True), file=sys.stderr)
            return 2
        response = query_control("forensics.list", payload=payload)
    elif op == "export":
        verification = query_control("forensics.verify")
        if not verification or verification.get("verified") is not True:
            print(json.dumps({
                "available": False,
                "command": "forensics.verify",
                "reason": "forensic_integrity_verification_failed",
            }, sort_keys=True), file=sys.stderr)
            return 1

        response = query_control("forensics.list")
        if response is None:
            print(json.dumps({
                "available": False,
                "command": "forensics.list",
                "reason": "control_daemon_query_failed",
            }, sort_keys=True), file=sys.stderr)
            return 1

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)

        export_document = {
            "export_kind": "forensic_ring_summary",
            "integrity": verification,
            "data": response,
        }

        output.write_text(
            json.dumps(export_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        print(json.dumps({
            "exported": True,
            "output": str(output),
            "verified": True,
            "export_kind": "forensic_ring_summary",
        }, sort_keys=True))
        return 0
    else:
        response = query_control("forensics.list")
    if response is None:
        print(json.dumps({"available": False, "command": f"forensics.{op}", "reason": "control_daemon_query_failed_or_not_implemented"}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0

def _state_file(name: str) -> Path:
    path = TOOLS_DIR.parent / "logs" / "runtime" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_state(path: Path, default: dict) -> dict:
    if not path.exists():
        return default.copy()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default.copy()


def _save_state(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _rules() -> list[dict]:
    return load_rules().get("nids_rules", []) if CONTROL_API_AVAILABLE else []


def _daemon_rules_count() -> int | None:
    """Return the active daemon count; local files are only a catalog view."""
    if not CONTROL_API_AVAILABLE:
        return None
    try:
        response = query_control("rules.list")
    except Exception:
        return None
    if not isinstance(response, dict) or "rules_loaded" not in response:
        return None
    try:
        return int(response["rules_loaded"])
    except (TypeError, ValueError):
        return None


def cmd_policy(args) -> int:
    if getattr(args, "policy_command", "list") not in {"list", "show", "verify", "validate"}:
        return _unavailable("policy", "policy_runtime_postcondition_not_connected")
    rules = _rules()
    # BE-DIS-089: the daemon engine (rule_loader.zig) honors
    # configs/disabled_rules.json on startup + rules.reload. The old
    # singular config/ path never met the engine — fixed to the
    # canonical configs/ dir so CLI and engine read the same file.
    disabled_path = TOOLS_DIR.parent / "configs" / "disabled_rules.json"
    state = _load_state(disabled_path, {"disabled_rules": []})
    disabled = set(state.get("disabled_rules", []))
    op = args.policy_command
    if op == "list":
        print("Rule ID        State       Name")
        for r in rules:
            rid = str(r.get("rule_id", "")); print(f"{rid:14} {'DISABLED' if rid in disabled else 'ENABLED':10} {r.get('name','')}")
        print(f"Total: {len(rules)}")
        daemon_count = _daemon_rules_count()
        if daemon_count is None:
            print("Active daemon rules: UNKNOWN (control daemon unavailable; DISABLED above is a local candidate until rules.reload)")
        else:
            print(f"Active daemon rules: {daemon_count} (authoritative; DISABLED takes effect on rules.reload)")
        return 0
    rid = getattr(args, "id", None)
    match = next((r for r in rules if str(r.get("rule_id")) == str(rid)), None)
    if op == "show":
        if match is None: print(f"Rule {rid} not found"); return 1
        data = dict(match); data["state"] = "DISABLED" if str(rid) in disabled else "ENABLED"; print(json.dumps(data)); return 0
    if op == "verify":
        # BE-RCPT-091: report the daemon's canonical envelope verification
        # (policies.json + IR mirror). Read-only; exit 3 when the daemon
        # does not answer, never a local guess.
        return _print_control_query("policy.verify", as_json=getattr(args, "json", True))
    if op == "validate":
        return _print_control_query("policy.validate", as_json=getattr(args, "json", True))
    if op in {"enable", "disable"}:
        if match is None: print(f"Rule {rid} not found"); return 1
        if op == "disable":
            if str(rid) in disabled: print(f"Rule {rid} already DISABLED")
            else: disabled.add(str(rid)); print(f"Rule {rid} DISABLED")
        else:
            if str(rid) not in disabled: print(f"Rule {rid} already ENABLED")
            else: disabled.discard(str(rid)); print(f"Rule {rid} ENABLED")
        _save_state(disabled_path, {"disabled_rules": sorted(disabled)})
        return 0
    if op == "reload":
        reachable = _query_control_safe("policy.reload")
        print("Policy reloaded" if reachable else "Policy reload: core not running")
        return 0 if reachable else 1
    return 2


def _query_control_safe(command: str) -> bool:
    try: return query_control(command) is not None
    except Exception: return False


def _unavailable(command: str, reason: str = "not_implemented") -> int:
    """Never report success for a command without a verified postcondition."""
    print(json.dumps({
        "available": False,
        "command": command,
        "reason": reason,
        "status": "UNAVAILABLE_NOT_IMPLEMENTED",
    }, sort_keys=True), file=sys.stderr)
    return 4


def cmd_simulate(args) -> int:
    # Gate-E + T16 AC1: the canonical CLI never spawns processes and
    # simulation stays fail-closed here. Controlled fixtures run through
    # the sanctioned script directly (it owns its pipe/protocol contract);
    # this message names the exact invocation so guidance replaces the stub.
    return _unavailable(
        "simulate",
        "run: python scripts/aegis_event_gen.py --pipe --fixture {xss,command-injection,path-traversal}; verify: forensics --source 0 --after <tip> or: alerts",
    )


def _load_canary_defs() -> tuple[list[dict], str]:
    """Load Gate-E canary definitions. Returns (tests, error_reason)."""
    path = TOOLS_DIR.parent / "configs" / "canary_tests.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], "canary_definitions_missing"
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return [], "canary_definitions_unreadable"
    tests = doc.get("tests") if isinstance(doc, dict) else None
    if not isinstance(tests, list):
        return [], "canary_definitions_malformed"
    return tests, ""


def _load_rules_file() -> tuple[dict, str]:
    """Load configs/Rules.json keyed by rule_id. Returns (by_id, error_reason)."""
    path = TOOLS_DIR.parent / "configs" / "Rules.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "rules_file_missing"
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return {}, "rules_file_unreadable"
    rules = doc.get("nids_rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list):
        return {}, "rules_file_malformed"
    by_id = {}
    for r in rules:
        if isinstance(r, dict) and isinstance(r.get("rule_id"), str):
            by_id.setdefault(r["rule_id"], r)
    return by_id, ""


def _live_engine_rule_count() -> int | None:
    """Best-effort live engine rule count; None when the daemon is unreachable."""
    if not CONTROL_API_AVAILABLE:
        return None
    try:
        response = query_control("rules.list")
    except Exception:
        return None
    if not isinstance(response, dict):
        return None
    for key in ("rules_loaded", "rule_count", "count"):
        value = response.get(key)
        if isinstance(value, int):
            return value
    return None


def cmd_canary(args) -> int:
    """Gate-E canary: verify detection READINESS from definitions.

    Honest scope: the wire carries no payload bytes for injected events,
    so no CLI path can prove live firing (that needs a capture-path
    fixture, not a control command). What this proves instead: every
    ACTIVE canary's expected rule exists in configs/Rules.json with
    matching severity, plus an optional live-engine count cross-check when
    the daemon answers. Quarantined definitions (payload/rule mismatch,
    dedicated rule pending) are reported separately, never graded.
    Read-only; never touches enforcement or the engine.
    """
    sub = getattr(args, "canary_command", "status")
    if sub == "status":
        tests, err = _load_canary_defs()
        by_id, rules_err = _load_rules_file()
        print(json.dumps({
            "available": True,
            "definitions": len(tests),
            "definitions_error": err or None,
            "rules_in_file": len(by_id),
            "rules_error": rules_err or None,
            "engine_rules": _live_engine_rule_count(),
        }, sort_keys=True))
        return 0
    if sub == "report":
        receipt_path = TOOLS_DIR.parent / "logs" / "canary_last.json"
        try:
            print(json.dumps(json.loads(receipt_path.read_text(encoding="utf-8")), sort_keys=True))
            return 0
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            print(json.dumps({"available": False, "reason": "no_canary_runs_yet"}, sort_keys=True))
            return 3
    if sub != "run":
        return _unavailable("canary", "unknown_canary_command")
    only = getattr(args, "test", None)
    tests, err = _load_canary_defs()
    if err:
        print(json.dumps({"available": False, "reason": err}, sort_keys=True))
        return 2
    by_id, rules_err = _load_rules_file()
    if rules_err:
        print(json.dumps({"available": False, "reason": rules_err}, sort_keys=True))
        return 2
    engine_count = _live_engine_rule_count()
    details = []
    quarantined = []
    for t in tests:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "?")
        if only is not None and name != only:
            continue
        # Quarantined definitions (payload never matches the named rule;
        # dedicated rule pending owner verdict) are reported, never graded.
        if t.get("quarantined") is True:
            if only is not None:
                print(json.dumps({"available": True, "quarantined": True,
                                  "name": name,
                                  "reason": t.get("quarantine_reason", "")},
                                 sort_keys=True))
                return 0
            quarantined.append({"name": name,
                                "reason": t.get("quarantine_reason", "")})
            continue
        want_rule = t.get("expected_rule_id")
        want_sev = t.get("expected_severity")
        got = by_id.get(want_rule) if isinstance(want_rule, str) else None
        if got is None:
            details.append({"name": name, "passed": False, "reason": "rule_not_in_file"})
            continue
        if want_sev is not None and got.get("severity") != want_sev:
            details.append({"name": name, "passed": False, "reason": "severity_mismatch",
                            "expected": want_sev, "actual": got.get("severity")})
            continue
        details.append({"name": name, "passed": True, "rule_id": want_rule,
                        "severity": got.get("severity")})
    if only is not None and not details:
        print(json.dumps({"available": False, "reason": "unknown_canary_test",
                          "test": only}, sort_keys=True))
        return 2
    passed = sum(1 for d in details if d["passed"])
    failed = len(details) - passed
    result = {"available": True, "passed": passed, "failed": failed,
              "quarantined": len(quarantined),
              "engine_rules": engine_count, "details": details}
    if quarantined:
        result["quarantined_tests"] = quarantined
    if engine_count is not None and engine_count != len(by_id):
        result["engine_drift"] = {"file": len(by_id), "engine": engine_count}
    try:
        (TOOLS_DIR.parent / "logs").mkdir(parents=True, exist_ok=True)
        (TOOLS_DIR.parent / "logs" / "canary_last.json").write_text(
            json.dumps(result, sort_keys=True), encoding="utf-8")
    except OSError:
        pass  # receipt is best-effort; the stdout verdict is authoritative
    print(json.dumps(result, sort_keys=True))
    return 0 if failed == 0 else 1


def _ip_entries(path: Path, key: str) -> list[dict]:
    return _load_state(path, {key: []}).get(key, [])


def cmd_block(args) -> int:
    # NEG-002: list-only. Mutations go through the control plane
    # (enforcement.block -> Rust PEP -> receipt -> postcondition). The local
    # file is a candidate view, never a host effect: this command must never
    # print BLOCKED and never write blocked_ips.json.
    # BLOCK-LABEL-038: no active writer maintains this file (the legacy
    # direct-write path is gone), so entries are labeled local candidates —
    # an entry here is not proof of a live WFP filter, and an empty file
    # does not prove no filters exist. Live state: enforce status.
    if getattr(args, "block_command", "list") != "list":
        return _unavailable("block", "pep_wfp_postcondition_not_connected")
    path = TOOLS_DIR.parent / "logs" / "blocked_ips.json"
    entries = _ip_entries(path, "blocked_ips")
    if not entries:
        print("No IPs in the block list (local candidates only; live state: enforce status)")
        return 0
    print("local block candidates (not live filter state; verify: enforce status):")
    for e in entries:
        print(f"{e['ip']}  {e.get('reason','')}")
    return 0


def _control_mutation(command: str, payload: dict) -> int:
    """Route a privileged mutation to the daemon control plane.

    Exit-code contract (AEGIS_Operator_UX_Specification, Unified CLI):
    0 = daemon answered, 3 = daemon unreachable (honest offline JSON),
    4 = local control API itself unavailable. Never claims a host effect;
    the printed payload is the daemon's response verbatim.
    """
    if not CONTROL_API_AVAILABLE:
        print(json.dumps({
            "available": False,
            "command": command,
            "reason": "control_api_unavailable",
        }, sort_keys=True))
        return 4
    response = query_control(command, payload=payload)
    if response is None:
        print(json.dumps({
            "available": False,
            "command": command,
            "reason": "control_daemon_query_failed",
        }, sort_keys=True))
        return 3
    print(json.dumps(dict(response), sort_keys=True))
    return 0


def cmd_enforce(args) -> int:
    """Show authoritative daemon enforcement status."""
    sub = getattr(args, "enforce_command", "status")
    if sub == "two-person":
        # Project 3 (T3-TWOP-023): route the two-person rule flip to the
        # daemon. Privilege is enforced daemon-side (role gate + FFI caps);
        # the CLI never touches the PEP directly.
        mode = getattr(args, "mode", None)
        if mode not in ("on", "off"):
            print(json.dumps({
                "available": False,
                "command": "enforcement.two_person",
                "reason": "mode_must_be_on_or_off",
            }, sort_keys=True))
            return 2
        return _control_mutation("enforcement.two_person", {"enabled": mode == "on"})
    if sub == "approve":
        try:
            request_id = int(getattr(args, "request_id", 0))
        except (TypeError, ValueError):
            request_id = 0
        if request_id <= 0:
            print(json.dumps({
                "available": False,
                "command": "enforcement.approve",
                "reason": "request_id_must_be_positive_integer",
            }, sort_keys=True))
            return 2
        return _control_mutation("enforcement.approve", {"request_id": request_id})
    if sub == "simulate":
        # Read-only posture projection (B3-SIM-029): asks the daemon what the
        # current gate/provider posture would do with an action, without
        # invoking the PEP. Never a mutation; offline answers honestly.
        action = getattr(args, "action", None)
        severity = getattr(args, "severity", None)
        if action not in ("allow", "block", "rate_limit", "quarantine"):
            print(json.dumps({
                "available": False,
                "command": "enforcement.simulate",
                "reason": "action_must_be_allow_block_rate_limit_quarantine",
            }, sort_keys=True))
            return 2
        try:
            severity = int(severity)
        except (TypeError, ValueError):
            severity = -1
        if severity < 0 or severity > 10:
            print(json.dumps({
                "available": False,
                "command": "enforcement.simulate",
                "reason": "severity_must_be_integer_0_to_10",
            }, sort_keys=True))
            return 2
        if not CONTROL_API_AVAILABLE:
            print(json.dumps({
                "available": False,
                "command": "enforcement.simulate",
                "reason": "control_api_unavailable",
            }, sort_keys=True))
            return 4
        response = query_control("enforcement.simulate",
                                 payload={"action": action, "severity": severity})
        if response is None:
            print(json.dumps({
                "available": False,
                "command": "enforcement.simulate",
                "reason": "control_daemon_query_failed",
            }, sort_keys=True))
            return 3
        print(json.dumps(dict(response), sort_keys=True))
        return 0
    if sub != "status":
        return _unavailable(
            "enforce",
            "pep_runtime_postcondition_not_connected",
        )

    if not CONTROL_API_AVAILABLE:
        print(json.dumps({
            "available": False,
            "command": "enforcement.status",
            "reason": "control_api_unavailable",
        }, sort_keys=True))
        return 4

    response = query_control("enforcement.status")
    if response is None:
        print(json.dumps({
            "available": False,
            "command": "enforcement.status",
            "reason": "control_daemon_query_failed",
        }, sort_keys=True))
        return 3

    response = dict(response)
    response.setdefault("host_effect_confirmed", False)
    print(json.dumps(response, sort_keys=True))
    return 0


def cmd_quarantine(args) -> int:
    # NEG-002: list-only, same authority rule as cmd_block.
    # BLOCK-LABEL-038: same candidate labeling — no active writer maintains
    # this file, so entries are local candidates, never live-state proof.
    if getattr(args, "quarantine_command", "list") != "list":
        return _unavailable("quarantine", "pep_wfp_postcondition_not_connected")
    qpath = TOOLS_DIR.parent / "logs" / "quarantine.json"
    entries = _ip_entries(qpath, "quarantined_ips")
    if not entries:
        print("No IPs in quarantine (local candidates only; live state: enforce status)")
        return 0
    print("local quarantine candidates (not live state; verify: enforce status):")
    for e in entries:
        print(f"{e['ip']}  {e.get('reason','')}")
    return 0


def _fnv1a32(text: str) -> int:
    """FNV-1a 32-bit over UTF-8 bytes. Same derivation the Zig loader and
    the Go nose use for numeric rule IDs (e.g. R1004 -> 3730098280)."""
    h = 0x811C9DC5
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _alert_rule_map() -> dict[int, dict]:
    """Numeric rule_id -> rule object, derived from configs/Rules.json.

    The forensic ring stores only the numeric FNV-1a of the rule_id
    string, so the CLI re-derives the same mapping to label alerts.
    Unknown numerics stay visible as UNKNOWN_RULE (never dropped).
    """
    by_id, _ = _load_rules_file()
    return {_fnv1a32(rid): rule for rid, rule in by_id.items()}


def _select_alerts(records: list) -> list[dict]:
    """Pure: every forensic record carrying a rule match becomes an alert.

    rule_id 0 means 'no rule fired'. Tolerates missing/str fields so one
    malformed record never hides the rest.
    """
    alerts = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        try:
            rule_num = int(rec.get("rule_id", 0) or 0)
        except (TypeError, ValueError):
            continue
        if rule_num == 0:
            continue
        alerts.append({
            "record_seq": rec.get("record_seq"),
            "event_id": rec.get("event_id"),
            "source": rec.get("source_name") or rec.get("source"),
            "rule_num": rule_num,
            "payload_len": rec.get("payload_len"),
            "verified": rec.get("verified"),
        })
    return alerts


def _enrich_alert(alert: dict, by_num: dict[int, dict]) -> dict:
    rule = by_num.get(alert["rule_num"])
    if rule is None:
        return {**alert, "rule_id": "UNKNOWN_RULE", "name": "unmapped numeric rule", "severity": "?", "action": "?"}
    return {
        **alert,
        "rule_id": rule.get("rule_id"),
        "name": rule.get("name"),
        "severity": rule.get("severity"),
        "action": rule.get("action"),
    }


def cmd_alerts(args) -> int:
    """View alerts.

    Live composition, no daemon change: pages forensics.list through the
    control plane, keeps every record whose rule_id is non-zero, and
    labels it from Rules.json. Scan totals are always reported, so a
    quiet result is distinguishable from a blind result.
    """
    if not CONTROL_API_AVAILABLE:
        return _unavailable("alerts", "control_api_unavailable")
    want = getattr(args, "limit", 20) or 20
    try:
        want = max(1, int(want))
    except (TypeError, ValueError):
        want = 20
    as_json = bool(getattr(args, "json", False))
    found: list[dict] = []
    scanned = 0
    pages = 0
    cursor_exhausted = False
    # NOTE: no after-anchor. forensics.list's after-cursor does not window
    # under ring wrap (proven live: after=435000 and after=422786 both
    # return the tip), so an anchor would claim a window it cannot hold.
    # The unanchored scan returns tip records first in practice; the scan
    # totals are always reported so coverage stays honest.
    after = None
    while len(found) < want and pages < 5 and not cursor_exhausted:
        payload: dict = {"limit": 200}
        if after is not None:
            payload["after"] = after
        try:
            response = query_control("forensics.list", payload=payload)
        except Exception:
            response = None
        if not response or not isinstance(response.get("records"), list):
            if pages == 0:
                return _unavailable("alerts", "control_daemon_query_failed")
            break
        records = response["records"]
        scanned += len(records)
        pages += 1
        found.extend(_select_alerts(records))
        nxt = response.get("next_after")
        if not records or nxt is None or nxt == after:
            cursor_exhausted = True
        else:
            after = nxt
    by_num = _alert_rule_map()
    alerts = [_enrich_alert(a, by_num) for a in found[:want]]
    if as_json:
        print(json.dumps({
            "alerts": alerts,
            "alerts_returned": len(alerts),
            "available": True,
            "command": "alerts",
            "cursor_exhausted": cursor_exhausted,
            "pages_scanned": pages,
            "records_scanned": scanned,
        }, sort_keys=True))
        return 0
    if not alerts:
        print(f"No alerts in {scanned} scanned forensic records ({pages} page(s)).")
        return 0
    print(f"ALERTS ({scanned} scanned records, {pages} page(s)):")
    for a in alerts:
        print(f"  seq={a['record_seq']} event={a['event_id']} src={a['source']} "
              f"rule={a['rule_id']}({a['rule_num']}) severity={a['severity']} "
              f"action={a['action']} verified={a['verified']} :: {a['name']}")
    return 0


def _render_dashboard_once() -> int:
    """One dashboard frame. Pure display over control_api reads."""
    if CONTROL_API_AVAILABLE:
        statuses = get_all_status()
        defcon = get_defcon()
        health = get_health_payload()
        workers = health.get("workers", {})

        # Color constants for dashboard formatting
        C_CYAN = "\x1b[96m"
        C_BOLD = "\x1b[1m"
        C_RESET = "\x1b[0m"
        C_GREEN = "\x1b[92m"
        C_RED = "\x1b[91m"
        C_YELLOW = "\x1b[93m"
        C_DIM = "\x1b[2m"
        C_ORANGE = "\x1b[38;5;208m"
        C_MAGENTA = "\x1b[95m"

        # Use ASCII box drawing for Windows compatibility
        border = "=" * 50
        header = "+" + border + "+"
        footer = "+" + border + "+"

        print(f"\n{C_CYAN}{C_BOLD}   AEGIS DASHBOARD v6.1 - DEFCON ENFORCER{C_RESET}")
        print(f"{C_DIM}   Guardian + Voice - Alert + Mitigate + Enforce{C_RESET}")
        print(f"  {header}")

        # DEFCON Display - FOCAL POINT
        if defcon:
            defcon_level = defcon[0]
            defcon_label = defcon[1]
            # Color mapping for DEFCON
            defcon_colors = {
                1: C_MAGENTA,  # MAXIMUM
                2: C_RED,    # SEVERE
                3: C_ORANGE, # HIGH
                4: C_YELLOW, # ELEVATED
                5: C_GREEN,  # SAFE
            }
            dc_color = defcon_colors.get(defcon_level, C_DIM)
            print(f"  DEFCON: {dc_color}{C_BOLD}DEFCON {defcon_level}: {defcon_label}{C_RESET}")
        else:
            print(f"  DEFCON: {C_YELLOW}SAFE{C_RESET}")

        print(f"  State: {health.get('state', 'UNKNOWN')}")
        print(f"  Degraded: {health.get('degraded', True)}")
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        print(f"  {running}/{total} subsystems running")
        print(f"  Worker readiness:")

        for name, ready in workers.items():
            if name == "failure_reason":
                print(f"    [REASON] {ready}")
            elif name == "failure_mask":
                print(f"    [MASK] {ready}")
            elif name == "failure_reasons":
                reasons = ready if ready else []
                print(f"    [REASONS] {', '.join(reasons) if reasons else 'none'}")
            elif name == "failed":
                print(f"    [FAILED] {ready}")
            elif ready:
                print(f"    [READY] {name}")
            else:
                print(f"    [NOT READY] {name}")

        # readiness gate
        required = ["pipeline_ready", "sensor_ready", "nose_ready", "etw_ready", "fim_ready", "registry_ready"]
        missing = [n for n in required if workers.get(n) is not True]
        worker_gate = not missing and not workers.get("failed", False)
        overall_gate = health.get("state") == "RUNNING" and not health.get("degraded", True) and worker_gate
        gate_text = "CLOSED - Ready for operations" if overall_gate else "OPEN - Issues must be resolved"
        gate_color = C_GREEN if overall_gate else C_RED
        print(f"  READY GATE: {gate_color}{C_BOLD}{gate_text}{C_RESET}")
        # EVT-162: the five components as concepts of their own. Fast path
        # only (health-derived + path checks): the watch polls every few
        # seconds, so no process probes here -- see `aegisctl components`.
        print(f"  COMPONENTS:")
        try:
            comp_rows = components_status(health if isinstance(health, dict) else {})
        except Exception:
            comp_rows = []
        for row in comp_rows:
            print(f"    [{str(row.get('status', '?')).upper():<8}] {row.get('name', '?')} ({row.get('language', '?')}) v{row.get('version', '?')}")
        print(f"  {footer}")
    else:
        print("\nControl API not available")
    return 0


def cmd_dashboard(args) -> int:
    """Real-time dashboard; --watch refreshes every --interval seconds."""
    try:
        interval = max(0.5, float(getattr(args, "interval", 2.0) or 2.0))
    except (TypeError, ValueError):
        interval = 2.0
    try:
        iterations = getattr(args, "iterations", None)
        remaining = None if iterations is None else max(1, int(iterations))
    except (TypeError, ValueError):
        remaining = None
    if not bool(getattr(args, "watch", False)) and remaining is None:
        return _render_dashboard_once()
    try:
        first = True
        while True:
            if bool(getattr(args, "watch", False)) and not first:
                print("\x1b[2J\x1b[H", end="")
            first = False
            if bool(getattr(args, "watch", False)):
                print(f"aegisctl dashboard --watch every {interval:g}s (Ctrl+C to stop)")
            rc = _render_dashboard_once()
            if rc != 0:
                return rc
            if remaining is not None:
                remaining -= 1
                if remaining <= 0:
                    return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


def cmd_bridge(args) -> int:
    """Bridge IPC status (RB-017 step 3): brain-channel listener honesty.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    Exit 0 = listener owned by the brain entrypoint; 1 = no/wrong
    listener (actionable); 2 = identity indeterminate (unknown, not failed).
    """
    if not CONTROL_API_AVAILABLE:
        return _unavailable("bridge", "control_api_unavailable")
    doc = bridge_diagnostic()
    if bool(getattr(args, "json", False)):
        print(json.dumps(doc, sort_keys=True))
    else:
        listener = doc.get("listener") or {}
        print("Brain channel (UDP :%s)" % doc.get("port"))
        if listener:
            print("  listener: pid %s (%s)" % (listener.get("pid"), listener.get("process")))
            print("  brain entrypoint match: %s" % listener.get("cmdline_match"))
        else:
            print("  listener: none (%s)" % doc.get("reason", "?"))
        print("  owner_is_brain: %s" % doc.get("owner_is_brain"))
        print("  this-shell secret configured: %s" % doc.get("this_shell_secret_configured"))
        if doc.get("sender_side") is not None:
            print("  sender-side daemon bit: %s" % (doc["sender_side"],))
        print("  note: %s" % doc.get("note", ""))
    if doc.get("owner_is_brain") is True:
        return 0
    if doc.get("available") is False and doc.get("listener") is None:
        return 1
    return 2


def cmd_graph(args) -> int:
    """Build the receipt-aware threat graph (EVT-165).

    Reads the newest-wins canonical log, colors edges by receipt
    evidence (legend states claim-based), writes interactive HTML.
    On-demand only. --open launches the browser (explicit gesture).
    """
    from aegisctl.graph import DEFAULT_LIMIT, DEFAULT_OUT, build_threat_graph, read_records, select_log
    out = Path(getattr(args, "out", None) or DEFAULT_OUT)
    try:
        limit = max(0, int(getattr(args, "limit", DEFAULT_LIMIT)))
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT
    log = select_log()
    records = read_records(log, limit)
    try:
        parsed, nodes, edges = build_threat_graph(records, out, limit)
    except ImportError:
        print("graph unavailable -- pip install networkx pyvis", file=sys.stderr)
        return 4
    except OSError as exc:
        print("graph write failed: %s" % exc, file=sys.stderr)
        return 1
    print("Threat graph: %s" % out)
    print("Events parsed: %d; nodes: %d; edges: %d (log: %s)" % (parsed, nodes, edges, log))
    print("Colors are claim-based triage (green=receipt, red dashed=unverified claim); authority: forensics verify.")
    if bool(getattr(args, "json", False)):
        print(json.dumps({"command": "graph", "html": str(out), "parsed": parsed,
                          "nodes": nodes, "edges": edges, "log": str(log)}, sort_keys=True))
    if bool(getattr(args, "open", False)):
        try:
            import webbrowser
            webbrowser.open(out.as_uri())
        except Exception as exc:
            print("browser open failed: %s" % exc, file=sys.stderr)
            return 1
    return 0


def cmd_console(args) -> int:
    """Interactive Command Control Center (EVT-165).

    The v8.0 menu operators miss, rewired to current contracts (never a
    second runtime; mutations need --role admin + elevation). --once
    --choice KEY runs one action non-interactively (tests drive this).
    """
    from aegisctl.console import console_menu
    role = getattr(args, "role", "operator") or "operator"
    if bool(getattr(args, "once", False)):
        return console_menu(role=role, once=True,
                            choice=getattr(args, "choice", None))
    return console_menu(role=role)


def cmd_components(args) -> int:
    """Show the five AEGIS runtime components as concepts of their own.

    EVT-162: name, language, role, version, entrypoint, and best-available
    live status per component. Thin: components_status() owns all logic.
    Deep probes (process checks) run here -- the call is one-shot, never
    a poll loop -- while the web/watch surfaces use the fast path.
    """
    if not CONTROL_API_AVAILABLE:
        return _unavailable("components", "control_api_unavailable")
    try:
        health = get_health_payload()
    except Exception:
        health = {}
    try:
        rows = components_status(health if isinstance(health, dict) else {}, deep=True)
    except Exception as exc:
        print(json.dumps({"available": False, "command": "components",
                          "reason": "components_probe_failed",
                          "error": str(exc)[:160]}, sort_keys=True))
        return 3
    if bool(getattr(args, "json", False)):
        print(json.dumps({"command": "components", "components": rows}, sort_keys=True))
        return 0
    print("AEGIS runtime components (concept + best-available status)")
    for row in rows:
        mark = {"running": "OK  ", "stopped": "DOWN ", "degraded": "DEGR ",
                "unknown": "????"}.get(row["status"], "????")
        req = "" if row["required"] else " (optional)"
        print("[%s] %s (%s) v%s - %s%s" % (
            mark, row["name"], row["language"], row["version"], row["status"], req))
        print("       role: %s" % row["role"])
        if row["detail"]:
            print("       %s" % row["detail"])
    return 0


def cmd_iptest(args) -> int:
    """Bounded control-pipe latency probe (EVT-167).

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    Exit 0 when at least one round-trip succeeded, else 1.
    """
    if not CONTROL_API_AVAILABLE:
        return _unavailable("iptest", "control_api_unavailable")
    try:
        rounds = int(getattr(args, "rounds", 20))
    except (TypeError, ValueError):
        rounds = 20
    doc = pipe_latency_probe(rounds)
    if bool(getattr(args, "json", False)):
        print(json.dumps(doc, sort_keys=True))
    else:
        print("Control-pipe latency (%d rounds, capped at %d)" % (doc["rounds"], 100))
        print("  ok %d / failed %d" % (doc["ok"], doc["failed"]))
        if doc["ok"]:
            print("  p50 %.1f ms · p99 %.1f ms · max %.1f ms" % (
                doc["p50_ms"], doc["p99_ms"], doc["max_ms"]))
        else:
            print("  no successful round-trip (pipe unknown, not measured)")
    return 0 if doc["ok"] > 0 else 1


def cmd_authority(args) -> int:
    """Verify authority invariant.

    Delegates all business logic to control_api.
    CLI is thin: just call API, display result, return exit code.
    """
    if CONTROL_API_AVAILABLE:
        invariant = verify_authority_invariant()
        print(f"\n  Authority invariant: {'HELD' if invariant else 'VIOLATED'}")
    else:
        print("\nControl API not available")
    return 0


def cmd_help(args) -> int:
    """Show help."""
    parser = argparse.ArgumentParser(description="AEGIS NIDS control plane CLI")
    parser.print_help()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS control plane CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="roles (full map: docs/OPERATOR_COMMAND_MAP.md):\n"
               "  daily     run_aegis.bat / status / bridge / components / dashboard / console\n"
               "  incident  events / alerts / forensic(s) / enforce status / block list / diagnose\n"
               "  maintain  keep / close / rules / policy / forensics verify (admin where noted)\n"
               "  lab/dev   simulate / canary / graph / federation / quarantine / builds (lab host only)\n"
               "layers: the opener owns OS processes; start/stop ask the daemon;\n"
               "restart refuses by design (needs an external service manager).",
    )
    # P1/T1-NET-019: pipe only. The unauthenticated TCP branch was removed;
    # the daemon never listens on TCP, so --transport=tcp is rejected.
    parser.add_argument(
        "--transport", "-t",
        choices=["pipe"],
        default="pipe",
        help="Transport to daemon: pipe (Windows ACL protected named pipe)",
    )
    sub = parser.add_subparsers(dest="cmd")

    # Set up subcommand parsers with help text
    status = sub.add_parser("status", help="Show subsystem status")
    status.add_argument("--component")
    status.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    status.set_defaults(func=cmd_status)
    sub.add_parser("diagnose", help="Show runtime diagnostic snapshot").set_defaults(func=cmd_diagnose)
    health = sub.add_parser("health", help="Health check")
    health.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    health.add_argument("--strict", action="store_true", help="Return exit code 1 when degraded")
    health.set_defaults(func=cmd_health)
    start = sub.add_parser("start", help="Start runtime components")
    start_group = start.add_mutually_exclusive_group(required=True)
    start_group.add_argument("--component")
    start_group.add_argument("--all", action="store_true")
    start.add_argument(
        "--skip-build",
        action="store_true",
        help="Start existing packaged binaries without invoking a build",
    )
    start.set_defaults(func=cmd_start)
    stop = sub.add_parser("stop", help="Request orderly daemon shutdown")
    stop_group = stop.add_mutually_exclusive_group(required=True)
    stop_group.add_argument("--component")
    stop_group.add_argument("--all", action="store_true")
    stop.set_defaults(func=cmd_stop)
    restart = sub.add_parser("restart", help="Restart runtime through an owning service manager")
    restart.add_argument("--component")
    restart.set_defaults(func=cmd_restart)
    version = sub.add_parser("version", help="Show component versions")
    version.add_argument("--component", choices=["core", "nose", "pep", "brain", "shield", "bridge", "aggregator"])
    version.set_defaults(func=cmd_version)
    metrics = sub.add_parser("metrics", help="Show runtime metrics snapshot")
    metrics.add_argument("--compact", action="store_true", help="Emit compact JSON")
    metrics.set_defaults(func=cmd_metrics)
    queue_p = sub.add_parser("queue", help="Show pipeline queue ingress per source plus latency snapshot")
    queue_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    queue_p.set_defaults(func=cmd_queue)
    federation = sub.add_parser("federation", help="Show federation cluster status")
    federation.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    federation.set_defaults(func=cmd_federation)
    sub.add_parser("snapshot", help="Emit one JSON runtime snapshot for dashboards").set_defaults(func=cmd_snapshot)
    readiness = sub.add_parser("readiness", help="Evaluate the production readiness gate")
    readiness.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    readiness.set_defaults(func=cmd_readiness)
    forensic = sub.add_parser("forensics", help="Inspect forensic records and hash chain")
    forensic_sub = forensic.add_subparsers(dest="forensics_command")
    flist = forensic_sub.add_parser("list", help="List forensic records")
    flist.add_argument("--limit", type=int, default=100,
                       help="Maximum records to return; capped at 1000")
    flist.add_argument("--after", type=int, default=None,
                       help="Return records with record_seq greater than this value")
    flist.add_argument("--all", action="store_true",
                       help="Follow the paging cursor until the result set is complete")
    flist.add_argument("--json", action="store_true",
                       help="Emit machine-readable JSON")
    flist.add_argument("--source", type=int,
                       help="Filter by EventSource ordinal")
    flist.add_argument("--payload-prefix",
                       help="Filter by exact ASCII payload prefix")
    fverify = forensic_sub.add_parser("verify", help="Verify forensic hash chain")
    fverify.add_argument("--json", action="store_true",
                         help="Emit machine-readable JSON")
    forensic.set_defaults(forensics_command="list", func=cmd_forensics)
    rules = sub.add_parser("rules", help="Rules management")
    rules_sub = rules.add_subparsers(dest="rules_command")
    rlist = rules_sub.add_parser("list", help="List rules"); rlist.add_argument("--severity"); rlist.add_argument("--category")
    rshow = rules_sub.add_parser("show", help="Show a rule"); rshow.add_argument("--id", required=True)
    rules_sub.add_parser("validate", help="Validate rules")
    rules_sub.add_parser("reload", help="Reload rules in the running daemon through Control Center")
    for operation in ("add", "update"):
        rmut = rules_sub.add_parser(operation, help=f"{operation.title()} a rule")
        rmut.add_argument("--id", required=True)
        rmut.add_argument("--rule-json", help="Complete rule object as JSON")
        rmut.add_argument("--name"); rmut.add_argument("--category"); rmut.add_argument("--layer")
        rmut.add_argument("--severity", choices=["Low", "Medium", "High", "Critical"])
        rmut.add_argument("--action", choices=["Pass", "Log", "Alert", "RateLimit", "Block", "Drop", "Quarantine", "Escalate"])
        rmut.add_argument("--match-pattern"); rmut.add_argument("--regex-pattern")
    rdel = rules_sub.add_parser("delete", help="Delete a rule"); rdel.add_argument("--id", required=True)
    rules.set_defaults(rules_command="list", func=cmd_rules)
    events = sub.add_parser("events", help="Inspect events")
    events_sub = events.add_subparsers(dest="events_command")
    etail = events_sub.add_parser("tail", help="Show recent events")
    etail.add_argument("--count", type=int, default=10)
    etail.add_argument("--follow", action="store_true", help="Continue watching for new events")
    etail.add_argument("--interval", type=float, default=1.0, help="Polling interval for --follow")
    etail.add_argument("--json", action="store_true", help="Emit JSON records")
    ecount = events_sub.add_parser("count", help="Count event evidence")
    ecount.add_argument("--json", action="store_true", help="Emit JSON")
    estats = events_sub.add_parser("stats", help="Summarize event evidence")
    estats.add_argument("--json", action="store_true", help="Emit JSON")
    events.set_defaults(events_command="count", func=cmd_events)
    forensic = sub.add_parser("forensic", help="Inspect forensic records")
    forensic_sub = forensic.add_subparsers(dest="forensic_command")
    fshow = forensic_sub.add_parser("show"); fshow.add_argument("--id", required=True, type=int)
    fsearch = forensic_sub.add_parser("search", help="Filter ring records (source ordinal, rule id, or payload-bytes prefix)");
    fsearch.add_argument("--field", required=True, help="source = numeric origin ordinal (9 npcap, 10 host); rule = catalog id (R9059) or integer, hashed client-side; payload_prefix = raw record-bytes prefix, not text search");
    fsearch.add_argument("--value", required=True, help="Ordinal for source; id for rule; byte prefix for payload_prefix")
    forensic_sub.add_parser("verify", help="Verify forensic hash chain")
    fexport = forensic_sub.add_parser("export"); fexport.add_argument("--output", required=True)
    forensic.set_defaults(forensic_command="list", func=cmd_forensic)
    policy = sub.add_parser("policy", help="Policy lifecycle")
    policy_sub = policy.add_subparsers(dest="policy_command")
    policy_sub.add_parser("list"); pshow = policy_sub.add_parser("show"); pshow.add_argument("--id", required=True)
    policy_sub.add_parser("verify"); policy_sub.add_parser("validate")
    preload = policy_sub.add_parser("reload"); pen = policy_sub.add_parser("enable"); pen.add_argument("--id", required=True)
    pdis = policy_sub.add_parser("disable"); pdis.add_argument("--id", required=True)
    policy.set_defaults(policy_command="list", func=cmd_policy)
    simulate = sub.add_parser("simulate", help="Generate test traffic")
    sim_sub = simulate.add_subparsers(dest="simulate_command")
    satt = sim_sub.add_parser("attack"); satt.add_argument("--type", required=True)
    spacket = sim_sub.add_parser("packet"); spacket.add_argument("--src-ip", required=True); spacket.add_argument("--dst-port", required=True); spacket.add_argument("--payload", required=True)
    sflood = sim_sub.add_parser("flood"); sflood.add_argument("--count", type=int, required=True); sflood.add_argument("--rate", type=int, required=True)
    sreplay = sim_sub.add_parser("replay"); sreplay.add_argument("--file", required=True)
    simulate.set_defaults(func=cmd_simulate)
    canary = sub.add_parser("canary", help="Run canary tests")
    canary_sub = canary.add_subparsers(dest="canary_command")
    crun = canary_sub.add_parser("run"); crun.add_argument("--test")
    canary_sub.add_parser("status"); canary_sub.add_parser("report")
    canary.set_defaults(func=cmd_canary)
    block = sub.add_parser("block", help="List block candidates (mutations need the control plane)")
    block_sub = block.add_subparsers(dest="block_command")
    badd = block_sub.add_parser("add"); badd.add_argument("--ip", required=True); badd.add_argument("--reason", default=""); badd.add_argument("--duration", type=int)
    brem = block_sub.add_parser("remove"); brem.add_argument("--ip", required=True)
    block_sub.add_parser("list"); block_sub.add_parser("clear"); block.set_defaults(func=cmd_block)
    enforce = sub.add_parser("enforce", help="PEP enforcement state")
    enforce_sub = enforce.add_subparsers(dest="enforce_command")
    enforce_sub.add_parser("status")
    etp = enforce_sub.add_parser("two-person", help="Project 3: enable/disable the two-person rule via the control plane")
    etp.add_argument("mode", choices=["on", "off"])
    eap = enforce_sub.add_parser("approve", help="Project 3: record a second-human approval via the control plane")
    eap.add_argument("request_id", type=int)
    esim = enforce_sub.add_parser("simulate", help="Project posture without enforcing (read-only, never touches PEP/WFP)")
    esim.add_argument("--action", required=True, choices=["allow", "block", "rate_limit", "quarantine"])
    esim.add_argument("--severity", required=True, type=int)
    enforce_sub.add_parser("enable", help="Unavailable in Project 2; reserved for Project 3 IPS")
    enforce_sub.add_parser("disable", help="Unavailable in Project 2; reserved for Project 3 IPS")
    epush = enforce_sub.add_parser("push", help="Unavailable in Project 2; reserved for Project 3 IPS")
    epush.add_argument("--policy", required=True)
    enforce.set_defaults(func=cmd_enforce)
    quarantine = sub.add_parser("quarantine", help="List quarantine candidates (mutations need the control plane)")
    quarantine_sub = quarantine.add_subparsers(dest="quarantine_command")
    qadd = quarantine_sub.add_parser("add"); qadd.add_argument("--ip", required=True); qadd.add_argument("--reason", default="")
    qrem = quarantine_sub.add_parser("remove"); qrem.add_argument("--ip", required=True)
    quarantine_sub.add_parser("list"); quarantine.set_defaults(func=cmd_quarantine)
    alerts_p = sub.add_parser("alerts", help="View alerts (live: rule matches from the forensic ring)")
    alerts_p.add_argument("--limit", type=int, default=20)
    alerts_p.add_argument("--json", action="store_true")
    alerts_p.set_defaults(func=cmd_alerts)
    dashboard_p = sub.add_parser("dashboard", help="Real-time dashboard")
    dashboard_p.add_argument("--watch", action="store_true", help="Refresh every --interval seconds")
    dashboard_p.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds")
    dashboard_p.add_argument("--iterations", type=int, default=None, help="Render N frames then exit (scripted use)")
    dashboard_p.set_defaults(func=cmd_dashboard)
    _bridge_p = sub.add_parser("bridge", help="Bridge IPC status")
    _bridge_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _bridge_p.set_defaults(func=cmd_bridge)
    _comp_p = sub.add_parser("components", help="The five runtime components as concepts")
    _comp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _comp_p.set_defaults(func=cmd_components)
    _graph_p = sub.add_parser("graph", help="Receipt-aware threat graph (HTML)")
    _graph_p.add_argument("--out", default=None, help="Output HTML path (default reports/threat_graph.html)")
    _graph_p.add_argument("--limit", default=500, help="Max records from the log tail")
    _graph_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _graph_p.add_argument("--open", action="store_true", help="Open the graph in a browser")
    _graph_p.set_defaults(func=cmd_graph)
    _console_p = sub.add_parser("console", help="Interactive Command Control Center")
    _console_p.add_argument("--role", choices=["operator", "admin"], default="operator",
                            help="operator = read-only views; admin unlocks mutations (needs elevation)")
    _console_p.add_argument("--once", action="store_true",
                            help="Run one --choice non-interactively and exit")
    _console_p.add_argument("--choice", default=None, help="Menu key for --once (0-9/A-C)")
    _console_p.set_defaults(func=cmd_console)
    _iptest_p = sub.add_parser("iptest", help="Bounded control-pipe latency probe")
    _iptest_p.add_argument("--rounds", default=20, help="Round-trips (1-100, default 20; never a flood)")
    _iptest_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _iptest_p.set_defaults(func=cmd_iptest)
    sub.add_parser("authority", help="Verify authority invariant").set_defaults(func=cmd_authority)
    sub.add_parser("help", help="Show help").set_defaults(func=cmd_help)

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        return 2

    # Dispatch to the appropriate command handler
    # All command handlers delegate to control_api for business logic
    func_name = f"cmd_{args.cmd}"
    if func_name in globals() and callable(globals()[func_name]):
        return globals()[func_name](args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
