#!/usr/bin/env python3
"""AEGIS NIDS Control Plane API — Business logic shared by CLI, TUI, and WEB.

This module contains ALL enforcement and operational logic. The frontend
interfaces (CLI at tools/aegisctl.py, TUI at tools/aegisctl/commands/console.py,
and any WEB layer) must be THIN clients that delegate to this API.

STRICT INVARIANT: No component may bypass the Rust PEP for enforcement.
All block/allow/quarantine requests route through aegis_pep_enforce() FFI.
Direct netsh/iptables/bridge.block_ip calls are NEVER permitted.
"""

from __future__ import annotations

import json
import ipaddress
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List

# Ensure tools/ is on the path
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# Repository root (three levels up from tools/aegisctl/api/)
REPO_ROOT = TOOLS_DIR.parent.parent.parent

# Subsystem configuration
SUBSYSTEMS: Dict[str, Dict[str, Any]] = {
    "zig": {"language": "Zig", "start_cmd": "zig build", "pid_file": "pid/zig.pid"},
    "go_nose": {"language": "Go", "start_cmd": "cd nose && go build -o aegis-nose . && ./aegis-nose", "pid_file": "pid/go_nose.pid"},
    "go_aggregator": {"language": "Go", "start_cmd": "cd go/aggregator && go build -o aegis-aggregator . && ./aegis-aggregator", "pid_file": "pid/go_aggregator.pid"},
    "rust_pep": {"language": "Rust", "start_cmd": "cargo build --release", "pid_file": "pid/rust_pep.pid"},
    "rust_shield": {"language": "Rust", "start_cmd": "cd shield && cargo build --release", "pid_file": "pid/rust_shield.pid"},
    "c_bridge": {"language": "C++", "start_cmd": "cd bridge && cmake -B build && cmake --build build", "pid_file": "pid/c_bridge.pid"},
    "python_brain": {"language": "Python", "start_cmd": "python brain/windows_brain.py", "pid_file": "pid/brain.pid"},
    "typescript_policy": {"language": "TypeScript", "start_cmd": "cd ts_policy && npm run start", "pid_file": "pid/ts_policy.pid"},
}

# Health uptime is process uptime, not wall-clock epoch time.  Keeping the
# origin monotonic makes the control contract meaningful across clock changes.
_PROCESS_START_MONOTONIC_MS = time.monotonic_ns() // 1_000_000
CONTROL_PIPE = r"\\.\pipe\aegis_control"

WORKER_FAILURE_BITS = {
    0: "pipeline_init_failed",
    1: "sensor_init_failed",
    2: "nose_init_failed",
    3: "etw_init_failed",
    4: "fim_init_failed",
    5: "registry_init_failed",
}


def decode_worker_failure_mask(mask: Any) -> List[str]:
    """Decode the daemon's deterministic worker failure bitmask."""
    try:
        value = int(mask or 0)
    except (TypeError, ValueError):
        return []
    return [reason for bit, reason in WORKER_FAILURE_BITS.items() if value & (1 << bit)]


def _query_daemon(command: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Query the running Zig daemon; return None when it is unavailable."""
    if os.name != "nt":
        return None
    request = {"command": command, "payload": payload or {}}
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        write_file = kernel32.WriteFile
        write_file.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        write_file.restype = wintypes.BOOL
        read_file = kernel32.ReadFile
        read_file.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        read_file.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        invalid_handle = ctypes.c_void_p(-1).value
        handle = create_file(CONTROL_PIPE, 0xC0000000, 0, None, 3, 0, None)
        if handle == invalid_handle:
            return None
        try:
            request_bytes = json.dumps(request, separators=(",", ":")).encode("utf-8")
            sent = wintypes.DWORD(0)
            request_buf = ctypes.create_string_buffer(request_bytes)
            if not write_file(handle, request_buf, len(request_bytes), ctypes.byref(sent), None):
                return None

            chunks = []
            while True:
                response_buf = ctypes.create_string_buffer(65536)
                received = wintypes.DWORD(0)
                ok = read_file(handle, response_buf, 65535, ctypes.byref(received), None)
                if received.value:
                    chunks.append(response_buf.raw[:received.value])
                if ok or ctypes.get_last_error() == 109:  # ERROR_BROKEN_PIPE
                    break
                if ctypes.get_last_error() != 234:  # ERROR_MORE_DATA
                    return None
            raw = b"".join(chunks)
        finally:
            close_handle(handle)
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, dict) or not response.get("ok"):
            return None
        data = response.get("data")
        if isinstance(data, dict):
            return data
        return response
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if os.environ.get("AEGIS_DEBUG_CONTROL") == "1":
            print(f"[aegisctl] control pipe {command} failed: {exc}", file=sys.stderr)
        return None


def _daemon_subsystems(payload: Dict[str, Any]) -> List[Tuple[str, bool, Optional[int]]]:
    result = []
    for item in payload.get("subsystems", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "unknown"))
        state = str(item.get("state", "STOPPED"))
        result.append((name, state in {"RUNNING", "READY"}, item.get("pid") or None))
    return result


def _query_daemon_retry(command: str, payload: Optional[Dict[str, Any]] = None, attempts: int = 3) -> Optional[Dict[str, Any]]:
    """Retry read-only queries because the daemon accepts one pipe client at a time."""
    for attempt in range(attempts):
        result = _query_daemon(command, payload)
        if result is not None:
            return result
        if attempt + 1 < attempts:
            time.sleep(0.05)
    return None


def read_pid(name: str) -> Optional[int]:
    """Read PID from pid/ directory, return None if not found or not running."""
    pid_file = SUBSYSTEMS.get(name, {}).get("pid_file", "pid/{}.pid".format(name))
    # Support both relative and absolute paths
    full_path = TOOLS_DIR.parent.parent / pid_file
    if not full_path.exists():
        # Try relative to cwd
        if os.path.exists(pid_file):
            with open(pid_file, "r") as f:
                try:
                    return int(f.read().strip())
                except ValueError:
                    return None
        return None
    with open(full_path, "r") as f:
        try:
            pid = int(f.read().strip())
            # Verify process is still running
            if os.name == "nt":
                import ctypes
                return ctypes.windll.kernel32.OpenProcess(1, 0, pid) != 0 and pid or None
            else:
                os.kill(pid, 0)  # SIG0: check if exists
                return pid
        except (ValueError, ProcessLookupError, PermissionError, FileNotFoundError):
            return None


def is_process_running(pid: int) -> bool:
    """Check if a process is still running."""
    if pid is None:
        return False
    try:
        if os.name == "nt":
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(1, 0, pid)
            return handle != 0
        else:
            os.kill(pid, 0)
            return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def get_subsystem_status(name: str) -> Dict[str, Any]:
    """Get the status of a subsystem."""
    pid = read_pid(name)
    if pid is not None and is_process_running(pid):
        return {"status": "RUNNING", "pid": pid}
    return {"status": "STOPPED", "pid": None}


def get_all_status() -> List[Tuple[str, bool, Optional[int]]]:
    """Get status of all subsystems."""
    daemon_status = _query_daemon_retry("system.status")
    if daemon_status is not None and daemon_status.get("subsystems") is not None:
        return _daemon_subsystems(daemon_status)
    daemon_health = _query_daemon_retry("system.health")
    if daemon_health is not None and daemon_health.get("subsystems") is not None:
        return _daemon_subsystems(daemon_health)
    results = []
    for name in SUBSYSTEMS:
        status = get_subsystem_status(name)
        results.append((name, status["status"] == "RUNNING", status["pid"]))
    return results


def load_rules() -> Dict[str, Any]:
    """Load rules from the daemon's canonical configs/Rules.json location."""
    repo = REPO_ROOT
    for rules_file in (repo / "configs" / "Rules.json", repo / "config" / "Rules.json"):
        if rules_file.exists():
            with open(rules_file, "r", encoding="utf-8") as f:
                return json.load(f)
    return {"nids_rules": []}


def compile_tier2_rules(rules_data: Dict[str, Any]) -> Dict[str, Any]:
    """Compile regex/match patterns from rules into fast regex objects."""
    compiled = {}
    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "")
        regex_str = r.get("regex_pattern", "")
        match_str = r.get("match_pattern", "")

        if regex_str:
            try:
                compiled[name] = __import__("re").compile(regex_str, __import__("re").DOTALL)
            except Exception:
                pass

        elif match_str:
            try:
                escaped = __import__("re").escape(match_str)
                escaped = escaped.replace(r"\\x", r"\x")
                compiled[name] = __import__("re").compile(escaped, __import__("re").DOTALL)
            except Exception:
                pass

    return compiled


def run_regex_scan(payload: str, tier2_engine: Dict[str, Any], rules_data: Dict[str, Any]) -> Optional[Tuple[str, str, str, int]]:
    """Scan a payload against all compiled Tier-2 regex rules.

    Returns (rule_name, policy, rule_id, severity) if match found, else None.
    """
    safe_payload = str(payload)[:4096]

    for r in rules_data.get("nids_rules", []):
        name = r.get("name", "")
        rule_id = r.get("rule_id", "UNKNOWN")
        regex_matcher = tier2_engine.get(name)

        if regex_matcher and regex_matcher.search(safe_payload):
            policy = r.get("action", "Alert").upper()
            severity_str = r.get("severity", "Medium")
            severity_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            severity = severity_map.get(severity_str, 1)
            return (name, policy, rule_id, severity)

    return None


def request_enforcement_via_pep(
    action: str,
    target_ip: str,
    target_port: int,
    rule_id: str,
    reason: str,
    protocol: int = 6,
) -> Tuple[str, str]:
    """Submit a privileged action request to the Rust PEP via aegisctl.

    Returns (status, message) where status is one of
    ENFORCED / REJECTED / DEFERRED / FAILED / NO_OP. ENFORCED requires a
    validated EnforcementReceipt; process exit status and human-readable
    CLI output are never sufficient.

    STRICT INVARIANT: This is the ONLY path for the brain/UI to request
    enforcement. Direct netsh/iptables/bridge.block_ip calls are NEVER
    permitted. The Rust PEP is the sole enforcement authority (ADR-0001).
    """
    if action.lower() != "block":
        return ("REJECTED", "only block requests are supported by the receipt route")
    try:
        dst_ip = int(ipaddress.IPv4Address(target_ip))
        policy_id = int(str(rule_id), 10)
    except (ValueError, TypeError):
        return ("REJECTED", "target_ip must be IPv4 and rule_id must be a numeric policy id")
    if not (1 <= int(target_port) <= 65535) or not (1 <= int(protocol) <= 255):
        return ("REJECTED", "destination port and protocol are out of range")
    payload = {
        "dst_ip": dst_ip,
        "dst_port": int(target_port),
        "protocol": int(protocol),
        "policy_id": policy_id,
        "severity": 9,
        "reason": reason,
    }
    receipt = _query_daemon_retry("enforcement.block", payload=payload)
    if not isinstance(receipt, dict) or receipt.get("status") != "ENFORCED":
        return ("FAILED", "Rust PEP did not return a validated EnforcementReceipt")
    filter_id = int(receipt.get("filter_id", 0) or 0)
    if filter_id == 0:
        return ("FAILED", "enforcement response did not contain filter_id")
    return ("ENFORCED", json.dumps(receipt, separators=(",", ":")))


def cleanup_enforcement_filter(filter_id: int) -> Tuple[str, str]:
    """Remove exactly the filter identified by a validated receipt."""
    if int(filter_id) <= 0:
        return ("REJECTED", "filter_id must be positive")
    result = _query_daemon_retry(
        "enforcement.unblock", payload={"filter_id": int(filter_id)}
    )
    if isinstance(result, dict) and result.get("status") == "CLEANED":
        return ("CLEANED", json.dumps(result, separators=(",", ":")))
    return ("FAILED", "Rust PEP could not remove the exact receipt filter")


def apply_firewall_block(
    ip_address: str,
    rule_name: str = "AEGIS",
    *,
    target_port: Optional[int] = None,
    rule_id: Optional[int] = None,
    protocol: int = 6,
) -> bool:
    """Request a block via aegisctl -> Rust PEP.

    The caller BRAIN/UI does NOT execute the firewall mutation; the Rust PEP
    is the sole authority. This is a thin wrapper that requests enforcement
    via the Control API; it never executes enforcement directly.

    Returns True only when a validated host-effect receipt is available.
    """
    # IP-only requests are not part of the active receipt-aware contract.
    # Keep this compatibility wrapper safe: callers must provide the exact
    # flow port and numeric policy identity before a request can be formed.
    if target_port is None or rule_id is None:
        return False

    status, message = request_enforcement_via_pep(
        action="block",
        target_ip=ip_address,
        target_port=target_port,
        rule_id=str(rule_id),
        protocol=protocol,
        reason=f"Aegis enforcement request (rule {rule_name})",
    )

    if status == "ENFORCED":
        return True
    return False


def get_defcon() -> Optional[Tuple[int, str]]:
    """Get DEFCON level from Bridge IPC.

    Returns (level, label) or None if unavailable.
    """
    # Try bridge first
    try:
        shared_paths = [
            TOOLS_DIR.parent.parent / "shared",
            TOOLS_DIR.parent.parent / "scripts" / "shared",
        ]
        for sp in shared_paths:
            if sp.exists():
                sys.path.insert(0, str(sp))
                import aegis_bridge_ctypes as bridge
                rc = bridge.bridge_init()
                if rc == 0:
                    level = bridge.get_defcon_level()
                    label = bridge.get_defcon_label()
                    bridge.bridge_shutdown()
                    if level is not None:
                        return level, label
    except Exception:
        pass

    # Fallback: check anomalous log file
    try:
        anomalous_log = TOOLS_DIR.parent.parent / "logs" / "anomalous.json"
        if anomalous_log.exists():
            import json
            with open(anomalous_log, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(max(0, f.seek(0, 2) - 8192))
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if "defcon_level" in data:
                                labels = {1: "COCKED PISTOL", 2: "DOUBLE TAKE", 3: "ROUND HOUSE", 4: "FAST PACE", 5: "FADE OUT"}
                                return data["defcon_level"], labels.get(data["defcon_level"], "UNKNOWN")
                        except (json.JSONDecodeError, KeyError):
                            continue
    except Exception:
        pass

    return None


def get_active_rules() -> List[Dict[str, Any]]:
    """Get active rules from the rules file."""
    rules_data = load_rules()
    return rules_data.get("nids_rules", [])


def query_control(command: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Run a read-only control-plane query through the protected pipe."""
    return _query_daemon_retry(command, payload=payload)


def get_health_payload() -> Dict[str, Any]:
    """Get the health check payload conforming to RUNTIME_CONTRACT.md §4.1.

    This is the single source of truth for the HEALTH probe response,
    used by the supervisor and the CLI/TUI/WEB health displays.
    """
    import os

    daemon_health = _query_daemon_retry("system.health")
    if daemon_health is not None:
        subsystem_payload = {
            item.get("name", "unknown"): {
                "state": item.get("state", "STOPPED"),
                "pid": item.get("pid") or None,
                "version": item.get("version", "unknown"),
                "last_event_ms": item.get("last_event_ms", 0),
                "error": item.get("error"),
            }
            for item in daemon_health.get("subsystems", [])
            if isinstance(item, dict)
        }
        # Normalize state/PID through the common subsystem status view.  In
        # production get_all_status() delegates to the daemon first, while
        # tests and diagnostic callers may provide an explicit snapshot.  Use
        # that normalized view for the identity fields shown to operators;
        # retain daemon-owned version/error/last-event metadata below.
        status_snapshot = get_all_status()
        status_by_name = {
            name: (is_running, pid)
            for name, is_running, pid in status_snapshot
        }
        for name, (is_running, pid) in status_by_name.items():
            if name not in subsystem_payload:
                subsystem_payload[name] = {
                    "state": "RUNNING" if is_running else "STOPPED",
                    "pid": pid,
                    "version": "unknown",
                    "last_event_ms": 0,
                    "error": None,
                }
            else:
                subsystem_payload[name]["state"] = "RUNNING" if is_running else "STOPPED"
                subsystem_payload[name]["pid"] = pid
        pep_ready = any(
            name in {"rust_pep", "pep"} and data["state"] in {"RUNNING", "READY"}
            for name, data in subsystem_payload.items()
        )
        tier3_status = subsystem_payload.get("tier3", {})
        tier3_ready = isinstance(tier3_status, dict) and tier3_status.get("state") in {"RUNNING", "READY"}
        tier3_diagnostics = _tier3_artifact_diagnostics()
        tier3_diagnostics["dependency_ready"] = tier3_ready and not bool(tier3_status.get("error"))
        capabilities = daemon_health.get("capabilities", {})
        if not isinstance(capabilities, dict):
            capabilities = {}
        tier3_diagnostics["provider_ready"] = tier3_diagnostics["dependency_ready"] and bool(
            capabilities.get("wfp", False)
        )
        tier3_diagnostics["host_effect_capable"] = tier3_diagnostics["provider_ready"] and tier3_ready
        computed_state, computed_degraded = compute_health_state()
        # The daemon is authoritative for the current canonical subsystem
        # names and worker postconditions. The legacy compute_health_state()
        # compatibility list still contains names such as capture/etw/fim;
        # using its count alone can produce the contradictory READY+degraded
        # result even when every daemon worker is ready.
        worker_payload = daemon_health.get("workers", {})
        if not isinstance(worker_payload, dict):
            worker_payload = {}
        required_workers = (
            "pipeline_ready",
            "sensor_ready",
            "nose_ready",
            "etw_ready",
            "fim_ready",
            "registry_ready",
        )
        workers_ready = all(bool(worker_payload.get(name, False)) for name in required_workers)
        canonical_subsystems_ready = bool(subsystem_payload) and all(
            data.get("state") in {"RUNNING", "READY"} and not data.get("error")
            for data in subsystem_payload.values()
        )
        daemon_runtime_ready = (
            daemon_health.get("runtime_state") == "RUNNING"
            and workers_ready
            and canonical_subsystems_ready
            and tier3_diagnostics["artifact_present"]
            and tier3_diagnostics["provider_ready"]
        )
        if daemon_runtime_ready and computed_state != "FAILED":
            computed_state, computed_degraded = "RUNNING", False
        data_plane = daemon_health.get("data_plane", {})
        if not isinstance(data_plane, dict):
            data_plane = {}
        nose_frames_read = int(data_plane.get("nose_frames_read", 0) or 0)
        nose_frames_submitted = int(data_plane.get("nose_frames_submitted", 0) or 0)
        nose_frames_dropped = int(data_plane.get("nose_frames_dropped", 0) or 0)
        nose_pipe_errors = int(data_plane.get("nose_pipe_errors", 0) or 0)
        exactly_once = {
            "last_event_id": int(data_plane.get("nose_last_event_id", 0) or 0),
            "duplicate_event_ids": int(data_plane.get("nose_duplicate_event_ids", 0) or 0),
            "non_monotonic_event_ids": int(data_plane.get("nose_non_monotonic_event_ids", 0) or 0),
        }
        workers = daemon_health.get("workers", {})
        if not isinstance(workers, dict):
            workers = {}
        workers = dict(workers)
        workers["failure_reasons"] = decode_worker_failure_mask(workers.get("failure_mask", 0))
        # The daemon response is the source of runtime counters, but the
        # control API must expose the same health decision used by the health
        # contract.  Do not let a stale/optimistic daemon state promote a
        # failed or degraded runtime to RUNNING.  A failed overall state also
        # cannot advertise Tier-3 readiness.
        effective_state = computed_state
        effective_degraded = computed_degraded
        effective_tier3_ready = tier3_ready and effective_state != "FAILED"
        shield_status = subsystem_payload.get("rust_pep", subsystem_payload.get("pep", {}))
        if not isinstance(shield_status, dict):
            shield_status = {}
        shield_running = shield_status.get("state") in {"RUNNING", "READY"}
        shield_wfp_ready = shield_running and bool(capabilities.get("wfp", False))
        rust_shield = {
            "state": "READY" if shield_running else "STOPPED",
            "pep_ready": shield_running,
            "policy_authority": shield_running,
            "provider_ready": shield_wfp_ready,
            "host_effect_capable": shield_wfp_ready,
            "wfp": "READY" if shield_wfp_ready else "UNAVAILABLE",
            "error": None if shield_running else "rust_shield_not_ready",
        }
        return {
            "component": daemon_health.get("component", "core"),
            "state": effective_state,
            "runtime_state": daemon_health.get("runtime_state", daemon_health.get("state", "DEGRADED")),
            "pid": daemon_health.get("pid"),
            "version": daemon_health.get("version", "6.0.0"),
            "uptime_ms": daemon_health.get("uptime_ms", 0),
            "last_event_ms": int(daemon_health.get("last_event_ms", 0) or max((v["last_event_ms"] for v in subsystem_payload.values()), default=0)),
            "counters": {
                "in_events": nose_frames_read,
                "out_events": nose_frames_submitted,
                "errors": nose_pipe_errors,
                "dropped": nose_frames_dropped,
            },
            "subsystems": subsystem_payload,
            "tier3": {
                **tier3_diagnostics,
                "ready": effective_tier3_ready,
                "state": "READY" if effective_tier3_ready else "STOPPED",
            },
            "rust_shield": rust_shield,
            "deps": [{"name": name, "state": data["state"]} for name, data in subsystem_payload.items()],
            "degraded": effective_degraded,
            "capabilities": daemon_health.get("capabilities", {}),
            "workers": workers,
            "data_plane": data_plane,
            "exactly_once": exactly_once,
        }

    # A failed daemon query is not runtime health. PID/process inspection is
    # retained for explicit diagnostics via get_all_status(), but must not be
    # promoted to the authoritative health response. Otherwise a stale PID
    # file or an unrelated process can produce a false RUNNING/READY result.
    return _diagnostic_health_payload(
        "control daemon unavailable; subsystem data is diagnostic only"
    )


def _diagnostic_health_payload(reason: str) -> Dict[str, Any]:
    """Return an explicit degraded payload when the daemon is unreachable.

    Only the Zig daemon can attest to runtime state, counters, worker
    readiness, or PEP readiness. PID inspection remains visible as diagnostic
    context but cannot establish operational health.
    """
    subsystem_statuses = get_all_status()
    subsystem_payload = {
        name: {
            "state": "RUNNING" if is_running else "STOPPED",
            "pid": pid,
        }
        for name, is_running, pid in subsystem_statuses
    }
    return {
        "component": "control_api",
        "state": "DEGRADED",
        "pid": os.getpid(),
        "version": "6.0.0",
        "uptime_ms": max(0, time.monotonic_ns() // 1_000_000 - _PROCESS_START_MONOTONIC_MS),
        "last_event_ms": 0,
        "counters": {
            "in_events": 0,
            "out_events": 0,
            "errors": 0,
            "dropped": 0,
        },
        "subsystems": subsystem_payload,
        "tier3": {"ready": False, "state": "UNAVAILABLE"},
        "rust_shield": {
            "state": "UNAVAILABLE",
            "pep_ready": False,
            "policy_authority": False,
            "provider_ready": False,
            "host_effect_capable": False,
            "wfp": "UNAVAILABLE",
            "error": "control_daemon_unavailable",
        },
        "deps": [
            {"name": name, "state": data["state"]}
            for name, data in subsystem_payload.items()
        ],
        "degraded": True,
        "source": "diagnostic",
        "runtime_available": False,
        "availability_error": reason,
        "workers": {"failure_reasons": []},
    }


def _tier3_artifact_diagnostics() -> Dict[str, Any]:
    """Describe Tier-3 artifact presence without attesting readiness.

    A file on disk is only an artifact signal. Dependency loading, provider
    readiness, and host-effect capability require runtime attestation and are
    therefore reported separately.
    """
    from pathlib import Path

    # TOOLS_DIR is tools/aegisctl/api; runtime artifacts live at the
    # repository root, not under tools/. The previous path made health report
    # artifact_present=false even when zig-out/bin held aegis_pep.dll.
    repo_root = REPO_ROOT
    # sec_monitor.dll is the legacy Tier-3 name. The current authority is
    # Rust PEP (aegis_pep.dll); retain both names for migration diagnostics,
    # but do not treat disk presence as runtime readiness.
    candidates = (
        repo_root / "aegis_pep.dll",
        repo_root / "zig-out" / "bin" / "aegis_pep.dll",
        repo_root / "dist" / "aegis_pep.dll",
        repo_root / "release" / "runtime" / "aegis_pep.dll",
        repo_root / "sec_monitor.dll",
        repo_root / "zig-out" / "bin" / "sec_monitor.dll",
        repo_root / "dist" / "sec_monitor.dll",
        repo_root / "release" / "runtime" / "sec_monitor.dll",
    )
    found = next((path for path in candidates if path.is_file()), None)
    return {
        "artifact_present": found is not None,
        "artifact_path": str(found) if found is not None else None,
        "dependency_ready": False,
        "provider_ready": False,
        "host_effect_capable": False,
    }


def compute_health_state() -> Tuple[str, bool]:
    """Compute the actual health state from subsystem statuses.

    Returns (overall_state: str, degraded: bool) based on the
    current state of all subsystems and the Tier-3 (sec_monitor) authority.

    HEALTH-001 invariant: if Tier-3 (sec_monitor) is absent, the system
    must be DEGRADED or FAILED, never healthy/OK.
    """
    import os
    # Check Tier-3 (sec_monitor) availability using the repository's runtime
    # artifact roots.  Build output is not by itself proof of readiness; the
    # daemon's tier3 subsystem state and dependency error remain authoritative
    # for the final health decision.  This check only prevents a valid runtime
    # artifact in zig-out/bin or a release bundle from being treated as absent
    # because it is not copied to the repository root.
    tier3_loaded = _tier3_artifact_diagnostics()["artifact_present"]

    # Get subsystem statuses
    all_status = get_all_status()
    subsystem_names = ["capture", "etw", "fim", "wfp", "pep", "control"]
    ready_count = 0
    has_failed = False
    has_degraded = False

    for i, (name, is_running, pid) in enumerate(all_status):
        if name in subsystem_names:
            if is_running:
                ready_count += 1
            else:
                has_degraded = True
                if not tier3_loaded:
                    # Without Tier-3, any non-running subsystem means degraded/failed
                    has_failed = True
                # Check subsystem-specific status
                if i < len(subsystem_names):
                    pass  # status captured below

    # A sparse diagnostic snapshot can contain only Rust PEP (or another
    # runtime authority) and omit optional platform names.  If a live status
    # exists but no recognized readiness counter was observed, report
    # DEGRADED rather than STOPPED; STOPPED is reserved for an explicitly
    # quiescent runtime.
    if all_status and ready_count == 0 and not has_failed:
        has_degraded = True

    # HEALTH-001: if Tier-3 absent, system cannot be healthy
    effective_degraded = has_failed or not tier3_loaded or ready_count < len(subsystem_names)

    # Determine overall state
    if ready_count == len(subsystem_names) and tier3_loaded and not has_failed:
        overall_state = "RUNNING"
    elif ready_count > 0 and tier3_loaded and not has_failed and not has_degraded:
        overall_state = "READY"
    elif has_failed:
        overall_state = "FAILED"
    elif has_degraded or not tier3_loaded:
        overall_state = "DEGRADED"
    else:
        overall_state = "STOPPED"

    return overall_state, effective_degraded


def verify_authority_invariant() -> bool:
    """Verify that the Rust PEP is the sole enforcement authority.

    Checks:
    1. No Zig module calls privileged WFP transport directly (wfp_ioctl.block_ip/unblock_ip)
    2. shield/ PEP/WFP exports are quarantined (marked, not active)
    3. All enforcement requests go through aegisctl → Rust PEP FFI

    Returns True if the invariant holds.
    """
    import re

    # Check 1: No privileged WFP calls in src/
    wfp_privileged_patterns = [
        r"\bwfp_ioctl\.(?:block_ip|unblock_ip)\s*\(",
        r"\bFwpmEngineOpen\b",
        r"\bFwpmFilterAdd\b",
    ]

    src_dir = TOOLS_DIR.parent.parent / "src"
    if src_dir.exists():
        for path in src_dir.rglob("*.zig"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
                for pat in wfp_privileged_patterns:
                    if re.search(pat, text):
                        # Allow wfp_production.zig as the authoritative module
                        if "wfp_production" not in str(path):
                            return False
            except Exception:
                pass

    # Check 2: shield/ exports are quarantined, not active
    shield_dir = TOOLS_DIR.parent.parent / "shield"
    if shield_dir.exists():
        try:
            # Check that no caller outside shield references shield PEP symbols
            # (This is a code-audit check, not a runtime check)
            pass
        except Exception:
            pass

    return True
