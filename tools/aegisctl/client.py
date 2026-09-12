"""AEGIS NIDS client for communicating with the Zig daemon.

SECURITY (P1): Transport is explicit — no automatic fallback.
  - Named Pipe = canonical transport (Windows ACL protected)
  - TCP = optional diagnostic transport (requires --transport=tcp)
  - Automatic fallback is REMOVED because it silently changes the security boundary

The caller must explicitly choose the transport. If pipe is unavailable,
the command fails with a clear error instead of silently using TCP.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from typing import Any, Dict, Optional

from .config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_NAMED_PIPE


class AegisCtlError(Exception):
    pass


class TransportError(AegisCtlError):
    """Raised when the chosen transport fails."""
    pass


class AegisClient:
    """Control plane client with explicit transport selection.

    Transport policy (P1):
      - pipe: Named pipe only. Fails if pipe unavailable. (default)
      - tcp:  TCP only. Fails if TCP unavailable. (requires explicit opt-in)
      - auto: DEPRECATED. Do not use. Fails with error.

    Why no fallback: Automatic pipe→TCP fallback silently changes the security
    boundary. Named pipe uses Windows ACL (SYSTEM-only). TCP is unauthenticated
    on localhost:5117. An operator must know which boundary they're using.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        timeout: float = 5.0,
        transport: str = "pipe",
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.transport = transport
        self._audit_log: list[Dict[str, Any]] = []

    def send(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a command to the daemon via the selected transport.

        Raises:
            TransportError: if the selected transport fails.
            AegisCtlError: if the command itself fails.
        """
        if self.transport == "auto":
            raise AegisCtlError(
                "transport='auto' is deprecated and removed. "
                "Use transport='pipe' (default) or transport='tcp' (explicit)."
            )

        start = time.monotonic()
        try:
            if self.transport == "pipe":
                result = self._send_pipe(command, payload)
            elif self.transport == "tcp":
                result = self._send_tcp(command, payload)
            else:
                raise AegisCtlError(f"unknown transport: {self.transport!r}")
        except AegisCtlError:
            raise
        except Exception as e:
            raise TransportError(f"{self.transport} transport failed: {e}")

        elapsed_ms = (time.monotonic() - start) * 1000
        self._audit_entry(command, self.transport, elapsed_ms, result.get("ok", False))
        return result

    def _send_pipe(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            import win32file
        except ImportError:
            raise TransportError("win32file not available — cannot use named pipe transport")

        try:
            handle = win32file.CreateFile(
                DEFAULT_NAMED_PIPE,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            req = json.dumps({"command": command, "payload": payload or {}}).encode("utf-8")
            win32file.WriteFile(handle, req)
            _, resp = win32file.ReadFile(handle, 65536)
            win32file.CloseHandle(handle)
            return json.loads(resp.decode("utf-8"))
        except Exception as e:
            raise TransportError(f"named pipe error: {e}")

    def _send_tcp(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                req = json.dumps({"command": command, "payload": payload or {}}).encode("utf-8")
                s.sendall(req)
                chunks = []
                while True:
                    data = s.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                resp = b"".join(chunks)
                return json.loads(resp.decode("utf-8"))
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            raise TransportError(f"TCP connection error: {e}")

    def _audit_entry(self, command: str, transport: str, elapsed_ms: float, ok: bool) -> None:
        self._audit_log.append({
            "ts": time.time(),
            "command": command,
            "transport": transport,
            "elapsed_ms": round(elapsed_ms, 1),
            "ok": ok,
        })


class AegisAPI:
    """Client for the Go aggregator REST API (port 9200)."""
    def __init__(self, host: str = "127.0.0.1", port: int = 9200, timeout: float = 5.0):
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout

    def _get(self, endpoint: str) -> Any:
        from urllib.request import urlopen, Request
        try:
            req = Request(f"{self.base_url}{endpoint}", method="GET")
            with urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    def is_available(self) -> bool:
        result = self._get("/api/health")
        return result is not None and result.get("status") == "healthy"

    def get_alerts(self) -> list:
        return self._get("/api/alerts") or []

    def get_critical_alerts(self) -> list:
        return self._get("/api/alerts/critical") or []

    def get_stats(self) -> dict:
        return self._get("/api/stats") or {}
