"""Read-only host audit of the deployed AEGIS runtime.

Collects one JSON report covering:

  - control pipe: existence, server pid, SDDL/DACL, read-only query results
  - service: AegisNids + AegisWfp configuration and state, process/modules
  - kernel surfaces: \\\\.\\AegisWfpDevice / \\\\.\\AegisWfp open results,
    loaded Aegis kernel drivers, *.sys presence
  - ETW: running sessions and registered Aegis providers
  - provenance: installed binary hashes/versions vs repo build artifacts and
    the recorded build_manifest digest

The probe performs no mutation: it never starts, stops, installs or configures
anything, sends only read-role control commands, and writes nothing outside
the repository's admin-evidence/ directory.

Usage (elevated shell recommended for the DACL and device probes):

    python tools/audit_kernel_runtime.py [--out PATH]
"""
from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
INSTALL_CANDIDATES = (
    Path(r"C:\Program Files\AEGIS"),
    Path(r"C:\Program Files\AEGIS NIDS"),
)
PIPE = r"\\.\pipe\aegis_control"
DEVICES = (r"\\.\AegisWfpDevice", r"\\.\AegisWfp")
READ_COMMANDS = (
    "system.health",
    "system.version",
    "system.status",
    "enforcement.status",
    "metrics.snapshot",
    "events.stats",
    "rules.list",
    "federation.status",
    "forensics.verify",
)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
k32.CreateFileW.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
INVALID_HANDLE = ctypes.c_void_p(-1).value


def run(cmd: list[str], timeout: int = 40) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(REPO)
        )
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:  # noqa: BLE001 - audit must never fail hard
        return {"cmd": cmd, "error": f"{type(exc).__name__}: {exc}"}


def powershell(script: str, timeout: int = 60) -> dict[str, Any]:
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


def ps_json(script: str) -> Any:
    res = powershell(script + " | ConvertTo-Json -Compress -Depth 5")
    raw = (res.get("stdout") or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"unparsed": raw}


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def file_record(path: Path) -> dict[str, Any]:
    rec: dict[str, Any] = {"path": str(path)}
    try:
        stat = path.stat()
        rec["size"] = stat.st_size
        rec["mtime"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)
        )
        rec["sha256"] = sha256_file(path)
    except OSError as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def open_device_probe() -> list[dict[str, Any]]:
    results = []
    for name in DEVICES:
        for access, label in ((0x80000000, "GENERIC_READ"), (0, "no-access")):
            ctypes.set_last_error(0)
            handle = k32.CreateFileW(name, access, 0, None, 3, 0, None)
            err = ctypes.get_last_error()
            opened = handle != INVALID_HANDLE
            entry: dict[str, Any] = {
                "device": name,
                "access": label,
                "opened": opened,
                "winerror": err,
            }
            if opened:
                k32.CloseHandle(handle)
            results.append(entry)
    return results


def pipe_probe() -> dict[str, Any]:
    ctypes.set_last_error(0)
    handle = k32.CreateFileW(PIPE, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
    err = ctypes.get_last_error()
    report: dict[str, Any] = {
        "pipe": PIPE,
        "opened_read_write": handle != INVALID_HANDLE,
        "winerror": err,
    }
    if handle == INVALID_HANDLE:
        return report
    try:
        pid = wintypes.ULONG(0)
        if k32.GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
            report["server_pid"] = pid.value
        try:
            import win32security  # type: ignore

            sd = win32security.GetSecurityInfo(
                handle,
                win32security.SE_KERNEL_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.OWNER_SECURITY_INFORMATION,
            )
            report["sddl"] = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                sd,
                win32security.SDDL_REVISION_1,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.OWNER_SECURITY_INFORMATION,
            )
            report["owner_sid"] = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        except Exception as exc:  # noqa: BLE001
            report["security_descriptor_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        k32.CloseHandle(handle)
    return report


def control_queries() -> dict[str, Any]:
    out: dict[str, Any] = {}
    sys.path.insert(0, str(REPO))
    os.environ["AEGIS_DEBUG_CONTROL"] = "1"
    try:
        from tools.aegisctl.api import control_api  # type: ignore

        for command in READ_COMMANDS:
            try:
                out[command] = control_api.query_control(command)
            except Exception as exc:  # noqa: BLE001
                out[command] = {"exception": f"{type(exc).__name__}: {exc}"}
    except Exception as exc:  # noqa: BLE001
        out["import_error"] = f"{type(exc).__name__}: {exc}"
    return out


def service_section() -> dict[str, Any]:
    return {
        "sc_query_AegisNids": run(["sc.exe", "query", "AegisNids"]),
        "sc_qc_AegisNids": run(["sc.exe", "qc", "AegisNids"]),
        "sc_query_AegisWfp": run(["sc.exe", "query", "AegisWfp"]),
        "sc_qc_AegisWfp": run(["sc.exe", "qc", "AegisWfp"]),
        "services_matching_aegis": ps_json(
            "Get-Service | Where-Object { $_.Name -match 'aegis' } | "
            "Select-Object Name,DisplayName,Status,StartType,ServiceType"
        ),
        "drivers_matching_aegis": ps_json(
            "Get-CimInstance Win32_SystemDriver | "
            "Where-Object { $_.Name -match 'aegis' -or $_.DisplayName -match 'aegis' } | "
            "Select-Object Name,DisplayName,State,StartMode,PathName"
        ),
        "driver_files": sorted(
            str(p)
            for p in Path(r"C:\Windows\System32\drivers").glob("aegis*")
        ),
    }


def process_section() -> dict[str, Any]:
    section: dict[str, Any] = {}
    tasklist = run(
        ["tasklist", "/fi", "IMAGENAME eq aegis_nids.exe", "/fo", "csv", "/v"]
    )
    section["tasklist"] = tasklist
    pids: list[int] = []
    rows = list(csv.reader(io.StringIO(tasklist.get("stdout", ""))))
    for row in rows:
        if len(row) >= 2 and row[0].strip().lower() == "aegis_nids.exe":
            try:
                pids.append(int(row[1]))
            except ValueError:
                pass
    section["pids"] = pids
    modules = {}
    for pid in pids:
        modules[str(pid)] = {
            "image": ps_json(
                f"Get-Process -Id {pid} | "
                "Select-Object Id,ProcessName,SessionId,Path,Company,ProductVersion"
            ),
            "command_line": ps_json(
                f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | "
                "Select-Object ProcessId,ExecutablePath,CommandLine"
            ),
            "modules_matching": ps_json(
                f"Get-Process -Id {pid} | Select-Object -ExpandProperty Modules | "
                "Where-Object { $_.ModuleName -match 'aegis|pep|wfp|etw|fim' } | "
                "Select-Object ModuleName,FileName,FileVersion"
            ),
            "module_count": ps_json(
                f"(Get-Process -Id {pid} | "
                "Select-Object -ExpandProperty Modules).Count"
            ),
        }
    section["processes"] = modules
    return section


def etw_section() -> dict[str, Any]:
    sessions = run(["logman", "query", "-ets"])
    lines = [
        line.strip()
        for line in (sessions.get("stdout") or "").splitlines()
        if "aegis" in line.lower()
    ]
    providers = run(["logman", "query", "providers"])
    plines = [
        line.strip()
        for line in (providers.get("stdout") or "").splitlines()
        if "aegis" in line.lower()
    ]
    return {
        "running_sessions_matching_aegis": lines,
        "registered_providers_matching_aegis": plines,
        "sessions_returncode": sessions.get("returncode"),
        "providers_returncode": providers.get("returncode"),
    }


def wfp_state_section() -> dict[str, Any]:
    state_path = REPO / "admin-evidence" / "wfp_state.xml"
    res = run(["netsh", "wfp", "show", "state", f"file={state_path}"], timeout=180)
    report: dict[str, Any] = {"command": res}
    if state_path.exists():
        text = state_path.read_text(encoding="utf-8", errors="replace")
        report["state_file"] = str(state_path)
        report["state_file_bytes"] = state_path.stat().st_size
        report["aegis_token_count"] = text.lower().count("aegis")
        report["aegis_context_lines"] = sorted(
            {line.strip() for line in text.splitlines() if "aegis" in line.lower()}
        )[:40]
    return report


def minifilter_section() -> dict[str, Any]:
    return {
        "fltmc": run(["fltmc"], timeout=60),
        "fltmc_instances": run(["fltmc", "instances"], timeout=60),
    }


def driverquery_section() -> dict[str, Any]:
    res = run(["driverquery", "/v", "/fo", "csv"], timeout=120)
    return {
        "matching_lines": [
            line
            for line in (res.get("stdout") or "").splitlines()
            if "aegis" in line.lower()
        ],
        "returncode": res.get("returncode"),
    }


BINARY_MARKERS = (
    b"detection engine has 0 rules",
    b"refusing to start",
    b"RulesUnavailable",
    b"config resolution",
    b"build_marker",
    b"AEGIS_NIDS",
)


def binary_marker_section() -> dict[str, Any]:
    paths = [
        Path(r"C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe"),
        Path(r"C:\Program Files\AEGIS\aegis_nids.exe"),
        REPO / "zig-out" / "bin" / "aegis_nids.exe",
    ]
    report: dict[str, Any] = {}
    for path in paths:
        entry: dict[str, Any] = {}
        try:
            data = path.read_bytes()
            for marker in BINARY_MARKERS:
                entry[marker.decode(errors="replace")] = data.find(marker) >= 0
            entry["bytes"] = len(data)
        except OSError as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        report[str(path)] = entry
    return report


def process_cwd_section(pids: list[int]) -> dict[str, Any]:
    try:
        import psutil  # type: ignore
    except ImportError:
        return {"skipped": "psutil not installed"}
    out: dict[str, Any] = {}
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            out[str(pid)] = {
                "cwd": proc.cwd(),
                "exe": proc.exe(),
                "username": proc.username(),
            }
        except Exception as exc:  # noqa: BLE001
            out[str(pid)] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


def install_section() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for root in INSTALL_CANDIDATES:
        entry: dict[str, Any] = {"root": str(root), "exists": root.exists()}
        if root.exists():
            entry["files"] = [
                file_record(p) for p in sorted(root.rglob("*")) if p.is_file()
            ]
            entry["sys_files"] = [
                str(p) for p in sorted(root.rglob("*.sys"))
            ]
            entry["version_info"] = ps_json(
                f"Get-ChildItem '{root}' -Filter *.exe -ErrorAction SilentlyContinue | "
                "Select-Object Name,@{n='FileVersion';e={$_.VersionInfo.FileVersion}},"
                "@{n='ProductVersion';e={$_.VersionInfo.ProductVersion}},"
                "@{n='Company';e={$_.VersionInfo.CompanyName}}"
            )
        out[root.name] = entry
    return out


def repo_artifacts() -> dict[str, Any]:
    candidates = [
        "zig-out/bin/aegis_nids.exe",
        "target/release/aegis_pep.dll",
        "build/Release/aegis_wfp_user.dll",
        "build/Release/aegis_etw_helper.dll",
        "build/Release/aegis_fim_helper.dll",
        "dist/aegis_bridge.exe",
        "dist/aegis_ipc.dll",
        "dist/aegis_adapter.dll",
        "dist/nose_dashboard.exe",
        "dist/windows_sec_monitor.exe",
    ]
    records = {}
    for rel in candidates:
        path = REPO / rel
        records[rel] = file_record(path) if path.exists() else {"path": rel, "missing": True}
    sys_files = sorted(str(p.relative_to(REPO)) for p in REPO.rglob("*.sys"))
    return {"artifacts": records, "sys_files_in_repo": sys_files}


def manifest_lookup() -> dict[str, Any]:
    out: dict[str, Any] = {}
    manifest = REPO / "build_manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    entries = data.get("artifacts") or []
    by_path = {}
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict) and item.get("path"):
                by_path[item["path"]] = item
    for rel in ("zig-out/bin/aegis_nids.exe", "target/release/aegis_pep.dll"):
        by_path.get(rel) and out.setdefault(rel, by_path[rel])
    out["source_commit"] = data.get("source_commit")
    out["artifact_count"] = len(entries) if isinstance(entries, list) else None
    return out


def git_section() -> dict[str, Any]:
    return {
        "head": run(["git", "rev-parse", "HEAD"]).get("stdout"),
        "head_date": run(["git", "log", "-1", "--format=%cI"]).get("stdout"),
        "branch": run(["git", "branch", "--show-current"]).get("stdout"),
        "dirty": bool(run(["git", "status", "--porcelain"]).get("stdout")),
    }


def main() -> int:
    out_path = None
    argv = sys.argv[1:]
    if "--out" in argv:
        out_path = Path(argv[argv.index("--out") + 1])
    proc_section = process_section()
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "python": sys.executable,
        "git": git_section(),
        "pipe": pipe_probe(),
        "control_queries": control_queries(),
        "service": service_section(),
        "process": proc_section,
        "process_cwd": process_cwd_section(proc_section.get("pids", [])),
        "kernel": {
            "device_open": open_device_probe(),
            "wfp_state": wfp_state_section(),
            "minifilters": minifilter_section(),
            "driverquery": driverquery_section(),
        },
        "etw": etw_section(),
        "binary_markers": binary_marker_section(),
        "install": install_section(),
        "repo_artifacts": repo_artifacts(),
        "build_manifest": manifest_lookup(),
    }
    text = json.dumps(report, indent=2)
    if out_path is None:
        out_path = REPO / "admin-evidence" / time.strftime(
            "kernel-runtime-audit-%Y%m%d-%H%M%S.json"
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    print(text)
    print(f"\n[audit] wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
