"""Shared loopback-capture attribution helpers for the E6 host_live tests.

The control counters (`metrics`, `forensics.list`) cannot attribute a record to
a specific stimulus: ambient host traffic moves every one of them (the
2026-11-14 run measured +52 ambient anomalies in a quiet window). These
helpers make the claim attributable instead:

1. drive a SYN burst from a dedicated loopback source address (127.0.0.2),
2. read the append-only core NDJSON log from a byte offset,
3. require the R9006 rule row to name that exact source IP *and* one of the
   ephemeral source ports owned by the test sockets, and
4. run a below-threshold control from a second source (127.0.0.3) that must
   produce no such row.

This is detection-only evidence: no host effect, no WFP mutation, no wire
change. It also asserts the canonical ingress counter advanced, so the proof
covers Nose -> pipe -> Zig queue -> R9006 -> core log, not just the log tail.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CTL = ROOT / "tools" / "aegisctl.py"

R9006 = "1745456278"          # FNV-1a("R9006"), the L4 SYN-scan rule id
POSITIVE_SRC = "127.0.0.2"
NEGATIVE_SRC = "127.0.0.3"
LOOPBACK_DST = "127.0.0.1"

POSITIVE_PORTS = 40           # > rate_threshold 20 (distinct_dst_ports)
NEGATIVE_PORTS = 10           # < rate_threshold 20
RATE_WINDOW_SECONDS = 11.0    # rate_window_ms 10000 + margin between phases
SETTLE_SECONDS = 4.0


def ctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CTL), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=ROOT, timeout=120,
    )


def ctl_json(*args: str) -> dict:
    proc = ctl(*args)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-1500:]
    return json.loads(proc.stdout[proc.stdout.find("{"):])


def event_log_path() -> Path:
    """Same resolution order as `lab_attack_window.py` / `aegisctl.py events`.

    The service writes relative to its cwd (System32); an interactive run writes
    under the repo. An explicit AEGIS_EVENT_LOG is authoritative.
    """
    override = os.environ.get("AEGIS_EVENT_LOG")
    if override:
        return Path(override)
    candidates = [
        Path(r"C:\Windows\System32\logs\aegis_core.ndjson"),
        ROOT / "logs" / "aegis_core.ndjson",
    ]
    best, best_m = None, -1.0
    for path in candidates:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime > best_m:
            best, best_m = path, mtime
    return best if best is not None else candidates[-1]


def log_offset(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def rows_since(path: Path, offset: int) -> list[dict]:
    """Parse complete JSON rows appended after `offset` (trailing partial ignored)."""
    if not path.exists() or path.stat().st_size <= offset:
        return []
    with path.open("rb") as fh:
        fh.seek(offset)
        blob = fh.read()
    blob = blob[: blob.rfind(b"\n") + 1]
    rows: list[dict] = []
    for line in blob.splitlines():
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def scan(src_ip: str, first_port: int, count: int) -> tuple[set[int], list[int]]:
    """SYN burst from a dedicated source address.

    Returns (ephemeral source ports owned by these sockets, destination ports).
    A refused connect still emitted a SYN, so every destination port counts.
    """
    sports: set[int] = set()
    dst_ports: list[int] = []
    for i in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        try:
            sock.bind((src_ip, 0))
            sports.add(int(sock.getsockname()[1]))
            port = first_port + i
            dst_ports.append(port)
            try:
                sock.connect((LOOPBACK_DST, port))
            except OSError:
                pass
        except OSError:
            pass
        finally:
            sock.close()
    return sports, dst_ports


def r9006_hits(rows: list[dict], src_ip: str, sports: set[int]) -> list[dict]:
    """R9006 rows attributable to this exact source IP and test-owned port set."""
    hits: list[dict] = []
    for row in rows:
        if str(row.get("rule")) != R9006 or row.get("src_ip") != src_ip:
            continue
        try:
            sport = int(row.get("src_port") or 0)
        except (TypeError, ValueError):
            continue
        if sport in sports:
            hits.append(row)
    return hits


def npcap_pushed() -> int:
    """Canonical ingress counter: frames handed to the Zig pipeline by Nose."""
    snapshot = ctl_json("queue", "--json")
    for row in snapshot.get("by_source", []):
        if row.get("name") == "capture_npcap":
            return int(row.get("pushed") or 0)
    raise AssertionError("queue snapshot has no capture_npcap source row")
