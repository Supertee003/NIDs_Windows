#!/usr/bin/env bash
set -euo pipefail

WINDOWS_IP="${1:?usage: $0 <windows-host-only-ip> [port] [nonce]}"
PORT="${2:-49152}"
NONCE="${3:-AEGIS_HOSTONLY_$(date -u +%Y%m%dT%H%M%SZ)}"

case "$PORT" in
  ''|*[!0-9]*) echo "invalid port" >&2; exit 2;;
esac
if (( PORT < 1 || PORT > 65535 )); then echo "port out of range" >&2; exit 2; fi

printf 'probe=benign_hostonly_tcp\nwindows_ip=%s\nport=%s\nnonce=%s\n' "$WINDOWS_IP" "$PORT" "$NONCE"
# curl sends a normal TCP connection and HTTP GET only. No exploit payload,
# no firewall command, and no enforcement request are performed.
curl --noproxy '*' --connect-timeout 3 --max-time 5 \
  -H "X-Aegis-Probe: $NONCE" \
  "http://${WINDOWS_IP}:${PORT}/?aegis_nonce=${NONCE}" \
  -o /dev/null -sS || {
    # The Windows proof listener is intentionally a raw TCP listener and may
    # close before returning an HTTP response. A successful TCP connect is the
    # relevant L4 stimulus; report curl's response separately.
    echo "note=listener may close without HTTP response; inspect Windows WFP evidence"
  }
echo "probe_complete=true"
