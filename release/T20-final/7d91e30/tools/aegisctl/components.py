"""Canonical identity of the five AEGIS runtime components.

The operator complaint behind EVT-162: core/brain/nose/mouth/bridge exist
in code but appear NOWHERE as concepts of their own (name, language, role,
version, entrypoint, live status). This module is the single registry every
surface renders: `aegisctl components`, the web console cards, and the
terminal watch section. (Native GUI/mouth rendering is a follow-up: it
needs Rust struct + rebuild; recorded in EVT-162.)

Two depths, deliberately: deep=False uses only the already-fetched health
doc plus instant path checks, so the 5s-cached web snapshot stays fast;
deep=True (one-shot CLI) adds process probes. Versions are constants
cross-pinned to `aegisctl version` (they change only on rebuild/redeploy;
spawning four --version processes per snapshot poll would be churn for
zero information). Statuses never claim "running" without evidence:
unknown stays unknown (EVT-147 doctrine).

Read-only. No control writes, no tree writes, no spawns except the
documented read-only probes in deep mode.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .api.control_api import bridge_diagnostic

REPO_ROOT = Path(__file__).resolve().parents[2]

COMPONENTS: List[Dict[str, Any]] = [
    {
        "id": "core",
        "name": "AEGIS Core",
        "language": "Zig",
        "role": "runtime spine: event fabric, flow, detection, forensics",
        "owns": ["event", "flow", "detection", "correlation", "forensics"],
        "version": "5.0.0",
        "entrypoint": "src/main.zig -> aegis_nids.exe (service AegisNids)",
        "required": True,
    },
    {
        "id": "brain",
        "name": "AEGIS Brain",
        "language": "Python",
        "role": "Tier-2 advisory analytics: recommends, never enforces",
        "owns": ["analytics", "rag", "advisory"],
        "version": "2.0.0",
        "entrypoint": "brain/windows_brain.py (UDP 127.0.0.1:9999)",
        "required": True,
    },
    {
        "id": "nose",
        "name": "AEGIS Nose",
        "language": "Go",
        "role": "packet acquisition: this-host traffic -> daemon pipe",
        "owns": ["capture", "collectors"],
        "version": "5.0.0",
        "entrypoint": "nose/main.go -> aegis-nose.exe",
        "required": True,
    },
    {
        "id": "mouth",
        "name": "AEGIS Mouth",
        "language": "Rust",
        "role": "operator TUI: DEFCON security monitor (optional display)",
        "owns": ["tui-display"],
        "version": "3.0.0",
        "entrypoint": "mouth/windows_sec_monitor.rs -> windows_sec_monitor.exe",
        "required": False,
    },
    {
        "id": "bridge",
        "name": "AEGIS Bridge",
        "language": "C++",
        "role": "native adapters: ETW / FIM / Registry / WFP telemetry",
        "owns": ["etw", "fim", "registry", "wfp-ioctl"],
        "version": "1.0.0",
        "entrypoint": "bridge/*.cpp -> dist/aegis_adapter.dll, aegis_ipc.dll",
        "required": True,
    },
]

_MOUTH_EXE = REPO_ROOT / "mouth" / "target" / "release" / "windows_sec_monitor.exe"
_NOSE_EXE = REPO_ROOT / "nose" / "aegis-nose.exe"
_BRIDGE_DLLS = (
    REPO_ROOT / "dist" / "aegis_adapter.dll",
    REPO_ROOT / "dist" / "aegis_ipc.dll",
)


def _ps_output(script: str, timeout: int = 30) -> str:
    """One read-only PowerShell probe; '' on any failure (unknown)."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _service_running() -> Optional[bool]:
    if os.name != "nt":
        return None
    out = _ps_output("(Get-Service AegisNids -ErrorAction SilentlyContinue).Status")
    if not out:
        return None
    return out.strip().lower() == "running"


def _proc_running(exe_name: str) -> Optional[bool]:
    if os.name != "nt":
        return None
    out = _ps_output(
        "@(Get-Process %s -ErrorAction SilentlyContinue).Count" % exe_name)
    if out == "" or not out.strip().lstrip("-").isdigit():
        return None
    return int(out.strip()) > 0


def _nose_frames(health: Dict[str, Any]) -> Optional[int]:
    try:
        dp = (health or {}).get("data_plane", {}) or {}
        return int(dp.get("nose_frames_read", 0) or 0)
    except (ValueError, TypeError, AttributeError):
        return None


def _bridge_files_ok() -> bool:
    try:
        return all(p.is_file() for p in _BRIDGE_DLLS)
    except OSError:
        return False


def components_status(health: Optional[Dict[str, Any]] = None,
                      deep: bool = False,
                      only: Optional[set] = None) -> List[Dict[str, Any]]:
    """Identity + best-available status for the five components.

    deep=False: health doc + instant path checks only (web/watch hot path).
    deep=True: adds process probes (one-shot CLI). only={ids} restricts
    deep probing to named components (status --component fast path).
    Never raises; unknown is a first-class answer, never a guessed
    "running".
    """
    health = health if isinstance(health, dict) else {}
    daemon_running = health.get("state") == "RUNNING"
    frames = _nose_frames(health)
    caps = health.get("capabilities", {}) if isinstance(health.get("capabilities"), dict) else {}

    def _wants(cid: str) -> bool:
        return only is None or cid in only

    brain_doc: Optional[Dict[str, Any]] = None
    if deep and _wants("brain"):
        try:
            brain_doc = bridge_diagnostic()
        except Exception:
            brain_doc = None

    out: List[Dict[str, Any]] = []
    for comp in COMPONENTS:
        cid = comp["id"]
        if only is not None and cid not in only:
            continue
        status = "unknown"
        detail = ""
        if cid == "core":
            if deep:
                svc = _service_running() if _wants("core") else None
                if svc is True and daemon_running:
                    status, detail = "running", "service + daemon RUNNING"
                elif svc is False:
                    status, detail = "stopped", "service not running"
                elif daemon_running:
                    status, detail = "running", "daemon RUNNING (service probe unreadable)"
                else:
                    detail = "no daemon answer and no service probe"
            elif daemon_running:
                status, detail = "running", "daemon RUNNING"
            else:
                detail = "no daemon answer (see status)"
        elif cid == "brain":
            if brain_doc and brain_doc.get("owner_is_brain") is True:
                status = "running"
                auth = brain_doc.get("secret_posture")
                detail = "listener owned by the brain%s" % (
                    " (auth %s)" % auth if auth in ("on", "off") else "")
            elif brain_doc and brain_doc.get("listener") is None:
                status, detail = "stopped", "no listener on :9999"
            else:
                detail = "no brain keys in health (see aegisctl bridge)"
        elif cid == "nose":
            proc = (_proc_running("aegis-nose")
                    if deep and _wants("nose") else None)
            if frames is not None and frames > 0:
                status, detail = "running", "frames_read=%d" % frames
            elif proc is True:
                status, detail = "degraded", "process up, no frames flowing"
            elif proc is False:
                status, detail = "stopped", "no capture process"
            else:
                detail = "no flow evidence (see status)"
        elif cid == "mouth":
            binary = _MOUTH_EXE.is_file()
            if deep and _wants("mouth"):
                proc = _proc_running("windows_sec_monitor")
                if proc is True:
                    status, detail = "running", "TUI console open"
                elif proc is False:
                    status, detail = "stopped", "display not open (optional; displays --tui)"
                else:
                    detail = "probe unreadable"
            else:
                detail = ("binary present (optional display; start via displays --tui)"
                          if binary else "display binary not built")
        elif cid == "bridge":
            files = _bridge_files_ok()
            cpp = caps.get("cpp_bridge", caps.get("cpp"))
            if files and cpp is True:
                status, detail = "running", "DLLs present, daemon cpp bridge up"
            elif files:
                status, detail = "unknown", "DLLs present, daemon cpp flag unreadable"
            else:
                status, detail = "degraded", "adapter DLLs missing from dist/"
        out.append({
            "id": cid,
            "name": comp["name"],
            "language": comp["language"],
            "role": comp["role"],
            "version": comp["version"],
            "entrypoint": comp["entrypoint"],
            "required": comp["required"],
            "status": status,
            "detail": detail,
        })
    return out
