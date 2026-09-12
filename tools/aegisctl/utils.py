"""Shared utilities for aegisctl."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import (
    LOGS_DIR, PID_DIR, NDJSON_LOG, RULES_FILE, DISABLED_RULES_FILE,
    CONTROL_AUDIT_LOG, REPO_ROOT,
)


def ensure_dirs() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    PID_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def read_ndjson() -> List[Dict[str, Any]]:
    if not NDJSON_LOG.exists():
        return []
    entries = []
    for line in NDJSON_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def load_rules() -> List[Dict[str, Any]]:
    data = load_json(RULES_FILE)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return data.get("nids_rules", data.get("rules", data.get("detection_rules", [])))


def save_rules(rules: List[Dict[str, Any]]) -> None:
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps({"nids_rules": rules}, indent=2), encoding="utf-8")


def load_disabled_rules() -> List[str]:
    data = load_json(DISABLED_RULES_FILE)
    if data is None:
        return []
    return data.get("disabled_rules", [])


def save_disabled_rules(ids: List[str]) -> None:
    save_json(DISABLED_RULES_FILE, {"disabled_rules": ids})


def write_pid(name: str, pid: int) -> None:
    ensure_dirs()
    pid_file = PID_DIR / f"{name}.pid"
    pid_file.write_text(str(pid), encoding="utf-8")


def read_pid(name: str) -> Optional[int]:
    pid_file = PID_DIR / f"{name}.pid"
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def clear_pid(name: str) -> None:
    pid_file = PID_DIR / f"{name}.pid"
    if pid_file.exists():
        pid_file.unlink()


def clear_all_pids() -> None:
    if PID_DIR.exists():
        for f in PID_DIR.glob("*.pid"):
            f.unlink()


def is_process_running(pid: int) -> bool:
    if not pid:
        return False
    try:
        import psutil
        proc = psutil.Process(pid)
        return proc.is_running()
    except ImportError:
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=5,
            )
            return str(pid) in result.stdout
        except Exception:
            return False
    except Exception:
        return False


def find_pid_by_pattern(pattern: str) -> Optional[int]:
    if not pattern:
        return None
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmdline = " ".join(proc.info["cmdline"] or [])
                if pattern.lower() in cmdline.lower():
                    return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        pass
    return None


def cleanup_stale_pids(subsystems: List[Dict]) -> List[tuple]:
    cleaned = []
    for sub in subsystems:
        name = sub["name"]
        pid = read_pid(name)
        if pid is None:
            continue
        if is_process_running(pid):
            try:
                import psutil
                proc = psutil.Process(pid)
                cmdline = " ".join(proc.cmdline()).lower()
                pattern = sub.get("exe", "").lower()
                if pattern and pattern not in cmdline:
                    clear_pid(name)
                    cleaned.append((name, pid))
            except Exception:
                pass
        else:
            clear_pid(name)
            cleaned.append((name, pid))
    return cleaned


def control_request(command: str, role: str, **kwargs: Any) -> Dict[str, Any]:
    import secrets
    request_id = secrets.token_hex(16)
    nonce = secrets.token_hex(8)
    envelope = {
        "command": command,
        "role": role,
        "caller": "aegisctl",
        "request_id": request_id,
        "nonce": nonce,
        **kwargs,
    }
    CONTROL_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with CONTROL_AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(envelope) + "\n")
    return envelope


def run_command(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    defaults = {"capture_output": True, "text": True, "timeout": 30}
    defaults.update(kwargs)
    return subprocess.run(cmd, **defaults)
