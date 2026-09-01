"""
Shared fixtures for runtime contract tests.

This module is intentionally framework-agnostic: it works with both pytest
and unittest. It provides:

  - `RuntimeProbe`        - thin client for the health probe of any component
                             (named pipe / TCP / file-beacon / stdout JSON)
  - `COMPONENTS`          - canonical list of components under test,
                             mirrored from docs/runtime/COMPONENT_MATRIX.md
  - `assert_state_in(...)`- helper to validate a state value against the
                             closed set defined in RUNTIME_CONTRACT.md §2
  - `wait_for_state(...)` - blocking helper with bounded timeout

Nothing in this module starts or stops processes. Test cases that need a
live component should use the runbook in docs/runtime/LOCAL_RUNBOOK.md
or call `tests.runtime.harness.start_component()` (skeleton provided in
`tests/runtime/harness.py`).
"""

from __future__ import annotations

import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# Constants mirrored from docs/runtime/RUNTIME_CONTRACT.md                    #
# --------------------------------------------------------------------------- #

VALID_STATES = ("STOPPED", "STARTING", "READY", "RUNNING", "DEGRADED", "FAILED")

DEFAULT_TIMEOUTS_MS = {
    "startup":      5_000,
    "ready":        2_000,
    "health":       1_000,
    "probe":          500,
    "degrade":      5_000,
    "shutdown":     3_000,
    "grim_reap":    2_000,
}

DEFAULT_RESTART_POLICY = {
    "max_attempts":    8,
    "base_delay_ms":   250,
    "max_delay_ms": 30_000,
    "recovery_k":        3,
    "reset_window_s":    60,
}

# Mirror of docs/runtime/COMPONENT_MATRIX.md §2.1 (primary engines only;
# auxiliary and kernel components live in their own subsections and are
# tested by separate modules).
#
# G34 fix: updated binary paths to match actual build_all.bat output:
#   - bridge: built to dist/aegis_bridge.exe by bridge/CMakeLists.txt
#     (uses CMAKE_RUNTIME_OUTPUT_DIRECTORY = ${CMAKE_SOURCE_DIR}/../dist)
#   - nose:   built to dist/nose_dashboard.exe by `go build -o ..\dist\nose_dashboard.exe .`
#   - mouth:  built to dist/windows_sec_monitor.exe by `rustc -O ... -o ..\dist\windows_sec_monitor.exe`
#   - aggregator: built to go/aggregator/aegis-aggregator.exe by `go build .`
#   - shield: built to shield/target/release/sec_monitor.dll by `cargo build --release`
#     (crate lib name is "sec_monitor"; the Zig core loads this exact file)
COMPONENTS: tuple[dict[str, Any], ...] = (
    {
        "name":      "bridge",
        "binary":    "dist/aegis_bridge.exe",
        "language":   "C++",
        "health":    {"transport": "pipe", "endpoint": r"\\.\pipe\aegis-bridge-health"},
        "required":  True,
        "gate":      "A",
    },
    {
        "name":      "core",
        "binary":    "zig-out/bin/aegis-nids.exe",
        "language":   "Zig",
        "health":    {"transport": "pipe", "endpoint": r"\\.\pipe\aegis-core-health"},
        "required":  True,
        "gate":      "A",
    },
    {
        "name":      "brain",
        "binary":    "brain/windows_brain.py",
        "language":   "Python+Cython",
        "health":    {"transport": "udp", "endpoint": ("127.0.0.1", 9999)},
        "required":  True,
        "gate":      "A",
    },
    {
        "name":      "nose",
        "binary":    "dist/nose_dashboard.exe",
        "language":   "Go",
        "health":    {"transport": "stdout", "endpoint": "logs/nose.log"},
        "required":  False,
        "gate":      "A",
    },
    {
        "name":      "mouth",
        "binary":    "dist/windows_sec_monitor.exe",
        "language":   "Rust",
        "health":    {"transport": "pipe", "endpoint": r"\\.\pipe\aegis-mouth-health"},
        "required":  False,
        "gate":      "A",
    },
    {
        "name":      "shield",
        "binary":    "shield/target/release/sec_monitor.dll",
        "language":   "Rust",
        "health":    {"transport": "delegate", "endpoint": "core"},
        "required":  True,
        "gate":      "A",
    },
    {
        "name":      "aggregator",
        "binary":    "go/aggregator/aegis-aggregator.exe",
        "language":   "Go",
        "health":    {"transport": "tcp", "endpoint": ("127.0.0.1", 9200)},
        "required":  False,
        "gate":      "A",
    },
)

REQUIRED_COMPONENTS = tuple(c["name"] for c in COMPONENTS if c["required"])


# --------------------------------------------------------------------------- #
# Assertion helpers                                                           #
# --------------------------------------------------------------------------- #

def assert_state_in(state: str) -> None:
    """Raise AssertionError if `state` is not in the closed set of valid
    lifecycle states. The set is defined in RUNTIME_CONTRACT.md §2."""
    if state not in VALID_STATES:
        raise AssertionError(
            f"invalid state {state!r}; expected one of {VALID_STATES}"
        )


def wait_for_state(
    probe: "RuntimeProbe",
    target: str,
    timeout_ms: int = DEFAULT_TIMEOUTS_MS["startup"],
    interval_ms: int = 100,
) -> dict[str, Any]:
    """Block until the component reports `target` state or the timeout
    expires. Returns the last health response. Raises TimeoutError on
    timeout. Raises AssertionError if any state observed is outside the
    valid closed set."""
    assert_state_in(target)
    deadline = time.time() + (timeout_ms / 1000.0)
    last: dict[str, Any] = {}
    while time.time() < deadline:
        try:
            last = probe.health()
            assert_state_in(last.get("state", "STOPPED"))
            if last.get("state") == target:
                return last
        except (ConnectionError, OSError, json.JSONDecodeError):
            pass
        time.sleep(interval_ms / 1000.0)
    raise TimeoutError(
        f"component {probe.component!r} did not reach state {target!r} "
        f"within {timeout_ms}ms; last response: {last}"
    )


# --------------------------------------------------------------------------- #
# RuntimeProbe - one client for all four transports                           #
# --------------------------------------------------------------------------- #

@dataclass
class RuntimeProbe:
    """Thin health-probe client. Construct with `RuntimeProbe.for_component(name)`
    to look up the endpoint from the COMPONENTS table."""
    component: str
    transport: str
    endpoint: Any
    probe_timeout_ms: int = DEFAULT_TIMEOUTS_MS["probe"]

    @classmethod
    def for_component(cls, name: str) -> "RuntimeProbe":
        for c in COMPONENTS:
            if c["name"] == name:
                return cls(
                    component=c["name"],
                    transport=c["health"]["transport"],
                    endpoint=c["health"]["endpoint"],
                )
        raise KeyError(f"unknown component {name!r}")

    def health(self) -> dict[str, Any]:
        if self.transport == "pipe":
            return self._probe_pipe()
        if self.transport == "tcp":
            return self._probe_tcp()
        if self.transport == "udp":
            return self._probe_udp()
        if self.transport == "stdout":
            return self._probe_stdout()
        if self.transport == "delegate":
            return self._probe_delegate()
        raise ValueError(f"unknown transport {self.transport!r}")

    # -- transports ------------------------------------------------------- #

    def _probe_pipe(self) -> dict[str, Any]:
        # On non-Windows CI we cannot open a real Windows named pipe; the
        # contract test must be skipped via `@unittest.skipUnless`. Here we
        # implement the Windows path so the test logic is complete.
        try:
            import win32file  # type: ignore
        except ImportError as e:
            raise RuntimeError("named-pipe probe requires pywin32") from e
        pipe = self.endpoint
        # Open, write a HEALTH request, read response.
        #
        # pywintypes.error (raised by win32file.CreateFile when the pipe
        # does not exist, error code 2) is NOT a subclass of OSError on
        # Python 3.14+. We translate it to FileNotFoundError so callers
        # that catch OSError / FileNotFoundError see a consistent type.
        try:
            handle = win32file.CreateFile(
                pipe,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING, 0, None,
            )
        except Exception as e:
            # pywintypes.error exposes (winerror, funcname, strerror) on
            # the .args tuple. winerror==2 means "file not found" (the
            # pipe server is not running).
            winerror = getattr(e, "winerror", None) or (
                e.args[0] if e.args and isinstance(e.args[0], int) else None
            )
            if winerror in (2, 231, 5):
                # 2 = ERROR_FILE_NOT_FOUND (pipe server not running)
                # 231 = ERROR_PIPE_BUSY
                # 5 = ERROR_ACCESS_DENIED
                raise FileNotFoundError(
                    f"named pipe {pipe!r} not available (winerror={winerror})"
                ) from e
            raise
        try:
            win32file.WriteFile(handle, b'{"op":"HEALTH"}\n')
            _, data = win32file.ReadFile(handle, 65536)
            return json.loads(data.decode("utf-8").strip())
        finally:
            win32file.CloseHandle(handle)

    def _probe_tcp(self) -> dict[str, Any]:
        host, port = self.endpoint
        with socket.create_connection((host, port), timeout=self.probe_timeout_ms / 1000) as s:
            s.sendall(b"GET /health HTTP/1.0\r\n\r\n")
            chunks: list[bytes] = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks).decode("utf-8", errors="replace")
            # Naive HTTP response split; contract test does not need a real
            # HTTP parser. The body is the JSON after the blank line.
            if "\r\n\r\n" in raw:
                raw = raw.split("\r\n\r\n", 1)[1]
            return json.loads(raw.strip())

    def _probe_udp(self) -> dict[str, Any]:
        host, port = self.endpoint
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.probe_timeout_ms / 1000)
            s.sendto(b'{"op":"HEALTH"}', (host, port))
            data, _ = s.recvfrom(8192)
            return json.loads(data.decode("utf-8").strip())

    def _probe_stdout(self) -> dict[str, Any]:
        path = Path(self.endpoint)
        if not path.exists():
            raise FileNotFoundError(f"no stdout log at {path}")
        # The component's stdout JSON is the last line that parses.
        last_line = ""
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("{"):
                last_line = line
        if not last_line:
            raise ValueError(f"no JSON line found in {path}")
        return json.loads(last_line)

    def _probe_delegate(self) -> dict[str, Any]:
        # Delegate probe: this component's health is reported by another
        # component (e.g. shield is reported by core). Look up the delegate
        # and re-probe.
        delegate_name = self.endpoint  # type: ignore[assignment]
        return RuntimeProbe.for_component(delegate_name).health()


# --------------------------------------------------------------------------- #
# Misc helpers                                                                #
# --------------------------------------------------------------------------- #

def runtime_artifacts_dir() -> Path:
    """Returns the directory used for runtime test artifacts (audit log,
    states.json, quarantine directory). Mirrors the supervisor's layout."""
    base = Path(os.environ.get("AEGIS_LOGS_DIR", "logs")) / "runtime"
    base.mkdir(parents=True, exist_ok=True)
    return base


def audit_log_path() -> Path:
    return runtime_artifacts_dir() / "audit.ndjson"


def states_path() -> Path:
    return runtime_artifacts_dir() / "states.json"


def quarantine_dir() -> Path:
    p = runtime_artifacts_dir() / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_audit_record(from_state: str, to_state: str, reason: str,
                       component: Optional[str] = None) -> None:
    assert_state_in(from_state)
    assert_state_in(to_state)
    record = {
        "v": 1,
        "ts": int(time.time() * 1000),
        "component": component or "test",
        "from": from_state,
        "to": to_state,
        "reason": reason,
        "attempts": 1,
        "supervisor_pid": os.getpid(),
        "uuid": str(uuid.uuid4()),
    }
    with audit_log_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


__all__ = [
    "VALID_STATES",
    "DEFAULT_TIMEOUTS_MS",
    "DEFAULT_RESTART_POLICY",
    "COMPONENTS",
    "REQUIRED_COMPONENTS",
    "RuntimeProbe",
    "assert_state_in",
    "wait_for_state",
    "runtime_artifacts_dir",
    "audit_log_path",
    "states_path",
    "quarantine_dir",
    "write_audit_record",
]
