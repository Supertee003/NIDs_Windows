# Error Codes

**Contract ID:** ERROR_CODES
**Version:** 1.0
**Status:** FROZEN
**Languages:** All

## Purpose

Standardized error codes across all AEGIS subsystems.
Every error returned by any subsystem MUST use these codes.

## Error Code Ranges

| Range | Category | Owner |
|-------|----------|-------|
| 0 | Success | All |
| 1-99 | System errors | Zig Runtime |
| 100-199 | Capture errors | Go/C++ Sensors |
| 200-299 | Detection errors | Zig Detection |
| 300-399 | Policy errors | Zig Policy |
| 400-499 | PEP errors | Rust PEP |
| 500-599 | Forensic errors | Zig Forensic |
| 600-699 | Federation errors | Zig Federation |
| 700-799 | Control errors | Zig Control |
| 800-899 | Native adapter errors | C++ |
| 900-999 | Reserved | Future |

## System Errors (1-99)

| Code | Name | Description |
|------|------|-------------|
| 1 | SUCCESS | Operation succeeded |
| 2 | ERROR_UNKNOWN | Unknown error |
| 3 | ERROR_INVALID_ARG | Invalid argument |
| 4 | ERROR_OUT_OF_MEMORY | Out of memory |
| 5 | ERROR_BUFFER_TOO_SMALL | Buffer too small |
| 6 | ERROR_TIMEOUT | Operation timed out |
| 7 | ERROR_NOT_INITIALIZED | Subsystem not initialized |
| 8 | ERROR_ALREADY_INITIALIZED | Subsystem already initialized |
| 9 | ERROR_NOT_FOUND | Resource not found |
| 10 | ERROR_ACCESS_DENIED | Access denied |
| 11 | ERROR_BUSY | Resource busy |
| 12 | ERROR_CANCELLED | Operation cancelled |
| 13 | ERROR_ABORTED | Operation aborted |
| 14 | ERROR_OVERFLOW | Numeric overflow |
| 15 | ERROR_UNDERFLOW | Numeric underflow |

## Capture Errors (100-199)

| Code | Name | Description |
|------|------|-------------|
| 100 | ERROR_CAPTURE_OPEN | Failed to open capture device |
| 101 | ERROR_CAPTURE_READ | Failed to read from capture device |
| 102 | ERROR_CAPTURE_TIMEOUT | Capture read timed out |
| 103 | ERROR_CAPTURE_OVERFLOW | Capture buffer overflow |
| 104 | ERROR_NPCAP_NOT_FOUND | Npcap not installed |
| 105 | ERROR_NPCAP_PERMISSION | Npcap permission denied |
| 106 | ERROR_PIPE_CONNECT | Named pipe connection failed |
| 107 | ERROR_PIPE_READ | Named pipe read failed |
| 108 | ERROR_WFP_NOT_AVAILABLE | WFP not available |

## Detection Errors (200-299)

| Code | Name | Description |
|------|------|-------------|
| 200 | ERROR_RULE_LOAD | Failed to load rules |
| 201 | ERROR_RULE_PARSE | Failed to parse rule |
| 202 | ERROR_RULE_INVALID | Invalid rule format |
| 203 | ERROR_SIGNATURE_BUILD | Failed to build signature automaton |
| 204 | ERROR_ANOMALY_INIT | Failed to initialize anomaly detector |

## Policy Errors (300-399)

| Code | Name | Description |
|------|------|-------------|
| 300 | ERROR_POLICY_LOAD | Failed to load policy |
| 301 | ERROR_POLICY_PARSE | Failed to parse policy |
| 302 | ERROR_POLICY_INVALID | Invalid policy format |
| 303 | ERROR_POLICY_SIGNATURE | Policy signature verification failed |
| 304 | ERROR_POLICY_EXPIRED | Policy TTL expired |

## PEP Errors (400-499)

| Code | Name | Description |
|------|------|-------------|
| 400 | ERROR_PEP_INIT | Failed to initialize PEP |
| 401 | ERROR_PEP_ENFORCE | PEP enforcement failed |
| 402 | ERROR_PEP_UNAVAILABLE | PEP not available |
| 403 | ERROR_PEP_QUOTA | Rate-limit quota exceeded |
| 404 | ERROR_PEP_SIGNATURE | PEP response signature invalid |
| 405 | ERROR_PEP_UNAUTHORIZED | Caller not authorized |

## Forensic Errors (500-599)

| Code | Name | Description |
|------|------|-------------|
| 500 | ERROR_FORENSIC_INIT | Failed to initialize forensic ring |
| 501 | ERROR_FORENSIC_WRITE | Failed to write forensic record |
| 502 | ERROR_FORENSIC_READ | Failed to read forensic record |
| 503 | ERROR_FORENSIC_HASH | Forensic hash chain broken |
| 504 | ERROR_REPLAY_FAILED | Replay verification failed |

## Federation Errors (600-699)

| Code | Name | Description |
|------|------|-------------|
| 600 | ERROR_FEDERATION_INIT | Failed to initialize federation |
| 601 | ERROR_FEDERATION_CONNECT | Failed to connect to peer |
| 602 | ERROR_FEDERATION_TLS | TLS handshake failed |
| 603 | ERROR_FEDERATION_TIMEOUT | Federation heartbeat timeout |

## Control Errors (700-799)

| Code | Name | Description |
|------|------|-------------|
| 700 | ERROR_CONTROL_AUTH | Authorization failed |
| 701 | ERROR_CONTROL_REPLAY | Replay attack detected |
| 702 | ERROR_CONTROL_EXPIRED | Request expired |
| 703 | ERROR_CONTROL_UNKNOWN_CMD | Unknown command |

## Native Adapter Errors (800-899)

| Code | Name | Description |
|------|------|-------------|
| 800 | ERROR_ETW_SESSION | ETW session failed |
| 801 | ERROR_ETW_PROVIDER | ETW provider registration failed |
| 802 | ERROR_FIM_INIT | FIM initialization failed |
| 803 | ERROR_REGISTRY_INIT | Registry monitor initialization failed |
| 804 | ERROR_INJECTION_DETECT | Injection detection failed |

## Invariants

- Error codes are u32
- 0 is always SUCCESS
- No two subsystems share the same error code range
- Error messages are human-readable strings
- Every error is logged with subsystem context

## References

- `src/core/diagnostics.zig` - Error logging
- `CONTRACT_MAP.json` - Contract registry
