"""T-HYG-001: product modules must be importable with no host effects.

Pinned by the 2026-10-04 coupling investigation: the full-suite native
crash class comes from shared in-process state, so every product import
must be side-effect free (no socket bind, no serve loop, no banner on
stdout, no sys.exit under a test runner's argv). Probed in a subprocess
so the importing test process itself stays clean.

EVT-179: test_import_binds_no_udp_port no longer depends on :9999 being
free and no longer skips when the production brain legitimately holds it
(RB-017 opened system). The import now runs in a child that stays alive
after importing; the parent snapshots UDP owners before/after. If the
import bound anything, the child's own pid would own a UDP endpoint.
Read-only probes, zero packets, zero prod touch.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _import_brain():
    return subprocess.run(
        [sys.executable, "-c", "import brain.windows_brain"],
        capture_output=True, text=True, timeout=120, cwd=REPO_ROOT,
    )


def _udp_owner_pids() -> set:
    """All pids currently owning a UDP endpoint (read-only snapshot)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess"],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception:
        return set()
    return {int(tok) for tok in out.split() if tok.strip().isdigit()}


def _spawn_import_probe():
    """Import the brain in a child that stays alive; returns the Popen.

    The child prints PID + READY after a successful import, then sleeps
    so the parent can inspect the child's own sockets while it lives.
    A child that never becomes READY is a genuine import failure, never
    a skip: the assertion carries the child's stderr tail.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import brain.windows_brain, os, time; "
         "print('PID=%d READY' % os.getpid(), flush=True); "
         "time.sleep(25)"],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    first: list = []
    got_ready: list = []

    def _read():
        try:
            # The import may print warnings first (e.g. missing optional
            # cython module); scan lines until the READY marker, not just
            # the first line.
            for _ in range(20):
                line = proc.stdout.readline()
                if not line:
                    break
                first.append(line)
                if "READY" in line:
                    got_ready.append(True)
                    break
        except Exception:
            pass

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout=60)
    if not got_ready:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            _, err = proc.communicate(timeout=10)
        except Exception:
            err = ""
        raise AssertionError(
            "import probe never READY in 60s; stderr tail=%r" % (err or "")[-1500:])
    pid = None
    for line in first:
        for tok in line.replace("=", " ").split():
            if tok.isdigit():
                pid = int(tok)
                break
        if pid is not None:
            break
    assert pid is not None and pid == proc.pid, (first, proc.pid)
    return proc


def test_import_produces_no_banner_or_listen_claim():
    proc = _import_brain()
    assert proc.returncode == 0, proc.stderr
    assert "\u2554" not in proc.stdout, "import must not print the startup banner"
    assert "Listening for Tier-1" not in proc.stdout
    assert "UDP 127.0.0.1:9999" not in proc.stdout


def test_import_binds_no_udp_port():
    before = _udp_owner_pids()
    proc = _spawn_import_probe()
    try:
        assert proc.poll() is None, "import probe exited early"
        time.sleep(2)
        after = _udp_owner_pids()
        assert proc.pid not in after, (
            "import bound a UDP endpoint (pid %d owns UDP)" % proc.pid)
        assert proc.pid not in (set(after) - set(before)), (
            "import opened UDP after start (pid %d)" % proc.pid)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=15)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
