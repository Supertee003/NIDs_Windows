"""NET-LOOPBACK-030: metrics exporter binds loopback only (behavioral).

scripts/aegis_metrics.py is a read-only Prometheus exporter. Its documented
contract is 127.0.0.1:9100 (COMPONENT_MATRIX.md, Operator Manual); the code
bound 0.0.0.0. This pins the loopback posture: no 0.0.0.0 surface anywhere
under scripts/, --host refuses non-loopback, and --print still works
without touching the network. E2.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
EXPORTER = REPO / "scripts" / "aegis_metrics.py"


def run(*argv: str):
    return subprocess.run(
        [sys.executable, str(EXPORTER), *argv],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def code_lines(path: Path):
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        yield i, line


def test_no_wildcard_bind_in_scripts():
    offenders = []
    for p in (REPO / "scripts").rglob("*.py"):
        for i, line in code_lines(p):
            if "0.0.0.0" in line:
                offenders.append(f"{p.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    assert offenders == [], f"wildcard bind under scripts/: {offenders}"


def test_exporter_refuses_non_loopback_host():
    proc = run("--host", "0.0.0.0", "--port", "19100")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "loopback" in proc.stderr.lower(), proc.stderr


def test_exporter_print_needs_no_network():
    proc = run("--print")
    assert proc.returncode == 0, proc.stderr
    assert "aegis_" in proc.stdout, proc.stdout[:500]


def test_exporter_serves_loopback_only():
    import socket
    import time

    port = 19101
    proc = subprocess.Popen(
        [sys.executable, "-u", str(EXPORTER), "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=REPO,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
                    s.sendall(b"GET /metrics HTTP/1.0\r\n\r\n")
                    chunks = []
                    while True:
                        try:
                            data = s.recv(65536)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
                    body = b"".join(chunks).decode("utf-8", "replace")
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise AssertionError("exporter did not answer on loopback")
        assert "200" in body.splitlines()[0], body.splitlines()[0]
        assert "aegis_" in body
    finally:
        proc.terminate()
        proc.wait(timeout=15)
    out = proc.stdout.read() if proc.stdout else ""
    assert "127.0.0.1:19101" in out, out
    assert "0.0.0.0" not in out, out
