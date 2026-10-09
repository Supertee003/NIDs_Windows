"""T-HYG-001: product modules must be importable with no host effects.

Pinned by the 2026-10-04 coupling investigation: the full-suite native
crash class comes from shared in-process state, so every product import
must be side-effect free (no socket bind, no serve loop, no banner on
stdout, no sys.exit under a test runner's argv). Probed in a subprocess
so the importing test process itself stays clean.
"""
from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _import_brain():
    return subprocess.run(
        [sys.executable, "-c", "import brain.windows_brain"],
        capture_output=True, text=True, timeout=120, cwd=REPO_ROOT,
    )


def _brain_port_holder_cmdline() -> str:
    """Command line of the process holding UDP 9999, or "" if free/unknown.

    A legitimately running brain (RB-017 opened system) holds this port
    by design; that is operator state, not an import side effect.
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetUDPEndpoint -LocalPort 9999 | Select-Object -ExpandProperty OwningProcess"],
            capture_output=True, text=True, timeout=30,
        ).stdout
        pids = [int(tok) for tok in out.split() if tok.strip().isdigit()]
    except Exception:
        return ""
    for pid in pids:
        try:
            cmd = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").CommandLine" % pid],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception:
            continue
        if "windows_brain" in cmd:
            return cmd.strip()
    return ""


def test_import_produces_no_banner_or_listen_claim():
    proc = _import_brain()
    assert proc.returncode == 0, proc.stderr
    assert "\u2554" not in proc.stdout, "import must not print the startup banner"
    assert "Listening for Tier-1" not in proc.stdout
    assert "UDP 127.0.0.1:9999" not in proc.stdout


def test_import_binds_no_udp_port():
    proc = _import_brain()
    assert proc.returncode == 0, proc.stderr
    holder = _brain_port_holder_cmdline()
    if holder:
        pytest.skip("brain legitimately running (RB-017 opened system): %s" % holder[:120])
    # Nothing from the import may own the brain's UDP port afterwards.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 9999))
    finally:
        s.close()
