#!/usr/bin/env python3
"""
aegis_api.py - AEGIS NIDS Go Aggregator API Client (Phase 19, GAP-2)

Unified client for querying the Go aggregator REST API (:9200).
All CLI tools should use this instead of reading NDJSON directly.

Usage:
  from aegis_api import AegisAPI

  api = AegisAPI()
  alerts = api.get_alerts()
  critical = api.get_critical_alerts()
  stats = api.get_stats()
"""

import json
import os
import sys
from typing import Optional, List, Dict, Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ============================================================
# Configuration
# ============================================================

DEFAULT_API_HOST = os.getenv("AEGIS_API_HOST", "127.0.0.1")
DEFAULT_API_PORT = int(os.getenv("AEGIS_API_PORT", "9200"))
DEFAULT_TIMEOUT = 5  # seconds


class AegisAPI:
    """Client for AEGIS Go aggregator REST API."""

    def __init__(self, host: str = None, port: int = None, timeout: int = None):
        self.host = host or DEFAULT_API_HOST
        self.port = port or DEFAULT_API_PORT
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.base_url = f"http://{self.host}:{self.port}"

    def _get(self, endpoint: str) -> Optional[Any]:
        """Make GET request to API."""
        url = f"{self.base_url}{endpoint}"
        try:
            req = Request(url, method='GET')
            with urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8'))
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            print(f"[API] Request to {url} failed: {e}", file=sys.stderr)
        return None

    def _post(self, endpoint: str, data: dict) -> bool:
        """Make POST request to API."""
        url = f"{self.base_url}{endpoint}"
        try:
            body = json.dumps(data).encode('utf-8')
            req = Request(url, data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
            with urlopen(req, timeout=self.timeout) as response:
                return response.status < 400
        except (URLError, HTTPError) as e:
            print(f"[API] POST to {url} failed: {e}", file=sys.stderr)
        return False

    def is_available(self) -> bool:
        """Check if aggregator is running."""
        result = self._get("/api/health")
        return result is not None and result.get("status") == "healthy"

    def get_alerts(self) -> List[Dict]:
        """Get all alerts (deduplicated)."""
        return self._get("/api/alerts") or []

    def get_critical_alerts(self) -> List[Dict]:
        """Get only critical-level alerts."""
        return self._get("/api/alerts/critical") or []

    def get_alert_by_hash(self, hash: str) -> Optional[Dict]:
        """Get specific alert by hash."""
        return self._get(f"/api/alerts/{hash}")

    def get_sessions(self, limit: int = 20) -> List[Dict]:
        """Get top sessions by event count."""
        return self._get("/api/sessions") or []

    def get_session_timeline(self, session_id: int) -> Optional[str]:
        """Get formatted timeline for a session."""
        url = f"{self.base_url}/api/sessions/{session_id}"
        try:
            with urlopen(url, timeout=self.timeout) as response:
                return response.read().decode('utf-8')
        except (URLError, HTTPError) as e:
            print(f"[API] Failed to get session {session_id}: {e}", file=sys.stderr)
        return None

    def get_stats(self) -> Dict:
        """Get aggregator statistics."""
        return self._get("/api/stats") or {}

    def purge_old_alerts(self, max_age_hours: int = 24) -> int:
        """Purge alerts older than specified hours. Returns count purged."""
        url = f"{self.base_url}/api/purge"
        try:
            body = json.dumps({"max_age_hours": max_age_hours}).encode('utf-8')
            req = Request(url, data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
            with urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get("purged", 0)
        except (URLError, HTTPError, json.JSONDecodeError):
            return 0


def main():
    """CLI entry point for quick API check."""
    api = AegisAPI()

    if not api.is_available():
        print("[FAIL] AEGIS aggregator not available at", api.base_url)
        print("       Is the Go aggregator running? (cd go/aggregator && go run .)")
        return 1

    print(f"[OK] AEGIS aggregator healthy at {api.base_url}")
    print()

    stats = api.get_stats()
    print(f"Total alerts:   {stats.get('total_alerts', 0)}")
    print(f"Total sessions: {stats.get('total_sessions', 0)}")

    critical = api.get_critical_alerts()
    print(f"Critical now:   {len(critical)}")

    if critical:
        print("\nLatest critical alerts:")
        for alert in critical[:5]:
            print(f"  - {alert.get('event', '?')}: rule={alert.get('rule', '?')} "
                  f"src_ip={alert.get('src_ip', '?')} count={alert.get('count', 1)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
