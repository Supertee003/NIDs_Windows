"""AEGIS NIDS client for communicating with the Zig daemon."""
from __future__ import annotations

import json
import os
import socket
from typing import Any, Dict, Optional

from .config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_NAMED_PIPE


class AegisCtlError(Exception):
    pass


class AegisClient:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def send(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if os.name == "nt":
            try:
                return self._send_pipe(command, payload)
            except Exception:
                pass
        return self._send_tcp(command, payload)

    def _send_pipe(self, command: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            import win32file
        except ImportError:
            raise AegisCtlError("win32file not available")
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
            raise AegisCtlError(f"named pipe error: {e}")

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
            raise AegisCtlError(f"connection error: {e}")


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
