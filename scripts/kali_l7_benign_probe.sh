#!/usr/bin/env bash
set -euo pipefail

WINDOWS_IP="${1:?usage: $0 <windows-host-only-ip> [port]}"
PORT="${2:-49153}"

case "$PORT" in ''|*[!0-9]*) echo 'invalid port' >&2; exit 2;; esac
if (( PORT < 1 || PORT > 65535 )); then echo 'port out of range' >&2; exit 2; fi

# Benign HTTP request only. The path and headers are neutral and are not an
# attack marker or a request to the AEGIS enforcement path.
if command -v nc >/dev/null 2>&1; then
  printf 'GET /aegis-observe-only HTTP/1.1\r\nHost: aegis-hostonly\r\nUser-Agent: AEGIS-benign-qualification\r\nConnection: close\r\n\r\n' |
    nc -w 5 "$WINDOWS_IP" "$PORT" || true
else
  curl --noproxy '*' --connect-timeout 3 --max-time 5 -sS \
    -A 'AEGIS-benign-qualification' \
    "http://${WINDOWS_IP}:${PORT}/aegis-observe-only" || true
fi

echo "probe_complete=true windows_ip=$WINDOWS_IP port=$PORT"
