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
    python tools/aegisctl.py status                    # pipe transport (default)
    python tools/aegisctl.py --transport=tcp status    # explicit TCP
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
        verify_authority_invariant,
    )
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
            verify_authority_invariant,
        )
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
        running = sum(1 for _, r, _ in statuses if r)
        total = len(statuses)
        if getattr(args, "json", False):
            print(json.dumps({"health": health, "subsystems": statuses}, sort_keys=True))
            return 0
        print(f"\n  State: {health['state']}")
        print(f"  Version: {health.get('version', 'unknown')}")
        print(f"  Uptime: {health.get('uptime_ms', 0)} ms")
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


def _print_control_query(command: str, as_json: bool = True) -> int:
    """Print a read-only control-plane response as formatted JSON."""
    if not CONTROL_API_AVAILABLE:
        print("\nControl API not available")
        return 4
    result = query_control(command)
    if result is None:
        print(f"\nControl query failed: {command}")
        return 3
    import json
    print(json.dumps(result, indent=2 if as_json else None, sort_keys=True))
    return 0


def cmd_version(args) -> int:
    """Show component versions from the control-plane contract."""
    versions = {
        "core": "5.0.0",
        "nose": "2.1.0",
        "pep": "1.0.0",
        "brain": "1.0.0",
        "shield": "0.1.0",
        "bridge": "1.0.0",
        "aggregator": "1.0.0",
    }
    component = getattr(args, "component", None)
    print("Component        Version")
    for name, version in versions.items():
        if component is None or component == name:
            print(f"{name:<16} {version}")
    return 0


def cmd_metrics(args) -> int:
    return _print_control_query("metrics.snapshot", as_json=getattr(args, "json", True))


def cmd_snapshot(args) -> int:
    """Emit one JSON snapshot for dashboards and automation."""
    import json as _json
    if not CONTROL_API_AVAILABLE:
        print(_json.dumps({"available": False, "reason": "control_api_unavailable"}, sort_keys=True))
        return 4
    try:
        health = get_health_payload()
        metrics = query_control("metrics.snapshot")
        forensic = query_control("forensics.verify")
    except Exception as exc:
        print(_json.dumps({"available": False, "reason": "control_query_exception", "error": str(exc)}, sort_keys=True))
        return 3
    if metrics is None or forensic is None:
        print(_json.dumps({"available": False, "reason": "control_query_failed", "health": health}, sort_keys=True))
        return 3
    print(_json.dumps({"available": True, "health": health, "metrics": metrics, "forensic": forensic}, sort_keys=True))
    return 0


def cmd_forensics(args) -> int:
    if args.forensics_command == "verify":
        return _print_control_query("forensics.verify", as_json=getattr(args, "json", True))
    command = "forensics.verify" if args.forensics_command == "verify" else "forensics.list"
    return _print_control_query(command, as_json=getattr(args, "json", True))


def cmd_readiness(args) -> int:
    """Machine-oriented readiness gate for operators and automation."""
    if not CONTROL_API_AVAILABLE:
        print(json.dumps({"ready": False, "reason": "control_api_unavailable"}, sort_keys=True))
        return 3
    payload = get_health_payload()
    workers = payload.get("workers", {})
    required = ["pipeline_ready", "sensor_ready", "nose_ready", "etw_ready", "fim_ready", "registry_ready"]
    missing = [name for name in required if workers.get(name) is not True]
    degraded_components = []
    for name, status in (payload.get("subsystems") or {}).items():
        if not isinstance(status, dict):
            continue
        if str(status.get("state", "")).upper() in {"DEGRADED", "FAILED", "STOPPED"}:
            degraded_components.append({"name": name, "state": status.get("state"), "error": status.get("error")})
    worker_gate = not missing and not workers.get("failed", False)
    overall_gate = payload.get("state") == "RUNNING" and not payload.get("degraded", True) and worker_gate
    reasons = list(workers.get("failure_reasons", []))
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
        return 0 if valid else 1
    if op == "reload":
        response = query_control("rules.reload") if CONTROL_API_AVAILABLE else None
        if response is None:
            print("Rules reload failed: daemon control pipe unavailable", file=sys.stderr)
            return 1
        loaded = response.get("rules_loaded", response.get("loaded", len(rules))) if isinstance(response, dict) else len(rules)
        print(f"Rules reloaded through Control Center: {loaded} rules")
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
    print(f"Rule {rid} {'deleted' if op == 'delete' else 'added' if op == 'add' else 'updated'}")
    return 0


def _event_log() -> Path:
    return TOOLS_DIR.parent / "logs" / "aegis_core.ndjson"


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
    events = _read_events()
    op = getattr(args, "events_command", "count")
    if op == "count":
        if getattr(args, "json", False):
            print(json.dumps({"events": len(events)}, sort_keys=True))
        else:
            print(f"Events: {len(events)}")
    elif op == "tail":
        count = getattr(args, "count", 10)
        if not events:
            print("No events found")
        else:
            for item in events[-count:]:
                print(json.dumps(item, sort_keys=True) if getattr(args, "json", True) else item)
            print(f"{min(count, len(events))} event(s)")
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
        else:
            levels = {}
            for item in events:
                level = item.get("level", item.get("severity", "unknown"))
                levels[str(level)] = levels.get(str(level), 0) + 1
            print("Event Statistics")
            payload = {"total": len(events), "levels": levels}
            print(json.dumps(payload, indent=2) if getattr(args, "json", True) else payload)
    return 0


def cmd_forensic(args) -> int:
    log = _event_log()
    if not log.exists():
        print("No log file")
        return 1
    records = _read_events()
    op = getattr(args, "forensic_command", "list")
    if op == "show":
        for item in records:
            if str(item.get("id", item.get("event_id", ""))) == str(args.id):
                print(json.dumps(item, indent=2))
                return 0
        print(f"Forensic record {args.id} not found")
        return 1
    if op == "search":
        found = [r for r in records if str(r.get(args.field, "")) == str(args.value)]
        for item in found:
            print(json.dumps(item))
        return 0 if found else 1
    if op == "export":
        Path(args.output).write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        print(f"Exported {len(records)} records")
        return 0
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


def cmd_policy(args) -> int:
    if getattr(args, "policy_command", "list") not in {"list", "show"}:
        return _unavailable("policy", "policy_runtime_postcondition_not_connected")
    rules = _rules()
    disabled_path = TOOLS_DIR.parent / "config" / "disabled_rules.json"
    disabled_path.parent.mkdir(parents=True, exist_ok=True)
    state = _load_state(disabled_path, {"disabled_rules": []})
    disabled = set(state.get("disabled_rules", []))
    op = args.policy_command
    if op == "list":
        print("Rule ID        State       Name")
        for r in rules:
            rid = str(r.get("rule_id", "")); print(f"{rid:14} {'DISABLED' if rid in disabled else 'ENABLED':10} {r.get('name','')}")
        print(f"Total: {len(rules)}")
        return 0
    rid = getattr(args, "id", None)
    match = next((r for r in rules if str(r.get("rule_id")) == str(rid)), None)
    if op == "show":
        if match is None: print(f"Rule {rid} not found"); return 1
        data = dict(match); data["state"] = "DISABLED" if str(rid) in disabled else "ENABLED"; print(json.dumps(data)); return 0
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
    print(json.dumps({"available": False, "command": command, "reason": reason}, sort_keys=True), file=sys.stderr)
    return 4


def cmd_simulate(args) -> int:
    return _unavailable("simulate", "use scripts/aegis_event_gen.py for controlled fixtures")


def cmd_canary(args) -> int:
    return _unavailable("canary", "end_to_end_canary_runner_not_connected")


def _ip_entries(path: Path, key: str) -> list[dict]:
    return _load_state(path, {key: []}).get(key, [])


def cmd_block(args) -> int:
    if getattr(args, "block_command", "list") not in {"list"}:
        return _unavailable("block", "pep_wfp_postcondition_not_connected")
    path = TOOLS_DIR.parent / "logs" / "blocked_ips.json"; key = "blocked_ips"
    entries = _ip_entries(path, key); op = args.block_command
    if op == "list":
        if not entries: print("No IPs in the block list")
        else:
            for e in entries: print(f"{e['ip']}  {e.get('reason','')}")
            print(f"Total: {len(entries)}")
        return 0
    if op == "clear":
        if not entries: print("Block list already empty")
        else: print(f"Cleared {len(entries)} blocked IPs")
        _save_state(path, {key: []}); return 0
    ip = args.ip
    if op == "add":
        if any(e.get("ip") == ip for e in entries): print(f"{ip} already BLOCKED"); return 0
        entries.append({"ip": ip, "reason": getattr(args, "reason", ""), "duration": getattr(args, "duration", None), "created_at": int(time.time())})
        _save_state(path, {key: entries}); print(f"{ip} BLOCKED" + (f" for {args.duration}s" if args.duration else "")); return 0
    before = len(entries); entries = [e for e in entries if e.get("ip") != ip]; _save_state(path, {key: entries})
    print(f"{ip} UNBLOCKED" if len(entries) < before else f"{ip} NOT in the block list"); return 0


def cmd_enforce(args) -> int:
    if getattr(args, "enforce_command", "status") != "status":
        return _unavailable("enforce", "pep_runtime_postcondition_not_connected")
    path = _state_file("pep_state.json"); state = _load_state(path, {"enabled": True, "mode": "FAIL_CLOSED"}); op = args.enforce_command
    if op == "status": print(f"PEP\nEnabled: {state.get('enabled', True)}\nMode: {state.get('mode','FAIL_CLOSED')}"); return 0
    if op in {"enable", "disable"}:
        value = op == "enable"
        if bool(state.get("enabled", True)) == value: print(f"Enforcement already {'ENABLED' if value else 'DISABLED'}")
        else: state["enabled"] = value; print(f"Enforcement {'ENABLED' if value else 'DISABLED'}")
        _save_state(path, state); return 0
    policy = Path(args.policy)
    if not policy.exists(): print(f"Policy file not found: {policy}"); return 1
    try: data = json.loads(policy.read_text(encoding="utf-8"))
    except json.JSONDecodeError: print("Invalid JSON policy"); return 1
    rules_path = TOOLS_DIR.parent / "config" / "Rules.json"; rules_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Policy pushed. Rules: {len(data.get('nids_rules', []))}"); return 0


def cmd_quarantine(args) -> int:
    if getattr(args, "quarantine_command", "list") not in {"list"}:
        return _unavailable("quarantine", "pep_wfp_postcondition_not_connected")
    qpath = TOOLS_DIR.parent / "logs" / "quarantine.json"; bpath = TOOLS_DIR.parent / "logs" / "blocked_ips.json"
    qs = _ip_entries(qpath, "quarantined_ips"); bs = _ip_entries(bpath, "blocked_ips"); op = args.quarantine_command
    if op == "list":
        if not qs: print("No IPs in quarantine")
        else:
            for e in qs: print(f"{e['ip']}  {e.get('reason','')}")
            print(f"Total: {len(qs)}")
        return 0
    ip = args.ip
    if op == "add":
        if any(e.get("ip") == ip for e in qs): print(f"{ip} already QUARANTINED"); return 0
        entry = {"ip": ip, "reason": f"QUARANTINE: {getattr(args,'reason','')}"}; qs.append(entry)
        if not any(e.get("ip") == ip for e in bs): bs.append(entry)
        _save_state(qpath, {"quarantined_ips": qs}); _save_state(bpath, {"blocked_ips": bs}); print(f"{ip} QUARANTINED"); return 0
    before = len(qs); qs = [e for e in qs if e.get("ip") != ip]; bs = [e for e in bs if e.get("ip") != ip]
    _save_state(qpath, {"quarantined_ips": qs}); _save_state(bpath, {"blocked_ips": bs})
    print(f"{ip} removed from quarantine" if len(qs) < before else f"{ip} NOT in the quarantine"); return 0


def cmd_alerts(args) -> int:
    """View alerts.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    return _unavailable("alerts", "alert_query_not_connected")


def cmd_dashboard(args) -> int:
    """Real-time dashboard.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    if CONTROL_API_AVAILABLE:
        statuses = get_all_status()
        defcon = get_defcon()
        print(f"\n  Dashboard: {len([s for s in statuses if s[1]])} subsystems running")
        if defcon:
            print(f"  DEFCON: {defcon[0]} ({defcon[1]})")
    else:
        print("\nControl API not available")
    return 0


def cmd_bridge(args) -> int:
    """Bridge IPC status.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    return _unavailable("bridge", "bridge_diagnostic_not_connected")


def cmd_iptest(args) -> int:
    """IPC throughput test.

    Delegates all business logic to control_api.
    CLI is thin: just call API and display structured result.
    """
    return _unavailable("iptest", "throughput_probe_not_connected")


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
    )
    # P1: Global transport flag — explicit, no fallback
    parser.add_argument(
        "--transport", "-t",
        choices=["pipe", "tcp"],
        default="pipe",
        help="Transport to daemon: pipe (default, Windows ACL protected) or tcp (diagnostic, explicit opt-in)",
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
    sub.add_parser("snapshot", help="Emit one JSON runtime snapshot for dashboards").set_defaults(func=cmd_snapshot)
    readiness = sub.add_parser("readiness", help="Evaluate the production readiness gate")
    readiness.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    readiness.set_defaults(func=cmd_readiness)
    forensic = sub.add_parser("forensics", help="Inspect forensic records and hash chain")
    forensic_sub = forensic.add_subparsers(dest="forensics_command")
    flist = forensic_sub.add_parser("list", help="List forensic records")
    flist.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    fverify = forensic_sub.add_parser("verify", help="Verify forensic hash chain")
    fverify.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
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
    fshow = forensic_sub.add_parser("show"); fshow.add_argument("--id", required=True)
    fsearch = forensic_sub.add_parser("search"); fsearch.add_argument("--field", required=True); fsearch.add_argument("--value", required=True)
    fexport = forensic_sub.add_parser("export"); fexport.add_argument("--output", required=True)
    forensic.set_defaults(forensic_command="list", func=cmd_forensic)
    policy = sub.add_parser("policy", help="Policy lifecycle")
    policy_sub = policy.add_subparsers(dest="policy_command")
    policy_sub.add_parser("list"); pshow = policy_sub.add_parser("show"); pshow.add_argument("--id", required=True)
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
    block = sub.add_parser("block", help="Block IP through PEP request")
    block_sub = block.add_subparsers(dest="block_command")
    badd = block_sub.add_parser("add"); badd.add_argument("--ip", required=True); badd.add_argument("--reason", default=""); badd.add_argument("--duration", type=int)
    brem = block_sub.add_parser("remove"); brem.add_argument("--ip", required=True)
    block_sub.add_parser("list"); block_sub.add_parser("clear"); block.set_defaults(func=cmd_block)
    enforce = sub.add_parser("enforce", help="PEP enforcement state")
    enforce_sub = enforce.add_subparsers(dest="enforce_command")
    enforce_sub.add_parser("status"); enforce_sub.add_parser("enable"); enforce_sub.add_parser("disable")
    epush = enforce_sub.add_parser("push"); epush.add_argument("--policy", required=True)
    enforce.set_defaults(func=cmd_enforce)
    quarantine = sub.add_parser("quarantine", help="Quarantine IP through PEP request")
    quarantine_sub = quarantine.add_subparsers(dest="quarantine_command")
    qadd = quarantine_sub.add_parser("add"); qadd.add_argument("--ip", required=True); qadd.add_argument("--reason", default="")
    qrem = quarantine_sub.add_parser("remove"); qrem.add_argument("--ip", required=True)
    quarantine_sub.add_parser("list"); quarantine.set_defaults(func=cmd_quarantine)
    sub.add_parser("alerts", help="View alerts").set_defaults(func=cmd_alerts)
    sub.add_parser("dashboard", help="Real-time dashboard").set_defaults(func=cmd_dashboard)
    sub.add_parser("bridge", help="Bridge IPC status").set_defaults(func=cmd_bridge)
    sub.add_parser("iptest", help="IPC throughput test").set_defaults(func=cmd_iptest)
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
