# CONTRACT-04: Control Protocol (IPC)

**Contract ID:** CONTROL_PROTOCOL
**Version:** 1.0
**Status:** FROZEN
**Languages:** TypeScript, Python, Zig

## Purpose

Defines the control-plane IPC protocol between CLI/TUI/Web and Zig Runtime.
TypeScript/Python submit commands; Zig validates and executes.
Privileged actions flow through Rust PEP (never direct to WFP).

## Transport

Named pipe: `\\.\pipe\aegis_control`
- Bidirectional
- JSON messages
- One request per connection (connect → read → respond → disconnect)

## Message Format

### Request
```json
{
    "command": "string",
    "payload": { ... }
}
```

### Response
```json
{
    "ok": true|false,
    "data": { ... } | null,
    "error": "string" | null
}
```

## Commands

| Command | Role | Description |
|---------|------|-------------|
| `status` | READ | System status (uptime, packets, flows, incidents) |
| `version` | READ | Version string |
| `health` | READ | Health check results |
| `rules.list` | READ | List loaded rules |
| `rules.reload` | OPERATE | Reload Rules.json |
| `incidents.list` | READ | List open incidents |
| `federation.status` | READ | Federation status |
| `block.request` | OPERATE | Request IP block (PEP-gated) |
| `unblock.request` | OPERATE | Request IP unblock (PEP-gated) |
| `quarantine.request` | OPERATE | Request quarantine (PEP-gated) |
| `daemon.shutdown` | PRIVILEGED | Shutdown daemon |

## Authorization

### Roles (strictly ordered)
```
READ < OPERATE < PRIVILEGED
```

### ACL
- Each caller must be explicitly allowed for a role
- No catch-all "Everyone" principal
- Privileged commands require PEP validation

### Security
- Request freshness: `now_ms` within `[issued_at_ms, issued_at_ms + timeout_ms]`
- Replay protection: `(request_id, nonce)` pair consumed once
- Audit trail: every decision logged

## Protocol Version

```json
{
    "magic": "0x4354524C",
    "version": 1,
    "request_id": "u64",
    "caller_id_hash": "u64",
    "role": "u8",
    "command": "u8",
    "issued_at_ms": "u64",
    "timeout_ms": "u32",
    "nonce": "u64"
}
```

## Invariants

- Named pipe is the ONLY control-plane transport
- Privileged actions MUST flow through Rust PEP
- No UI may become an authoritative state owner
- Every command is audited (request_id, caller, role, decision)
- Request timeout prevents stale command execution

## References

- `src/policy/control_ipc.zig` - Zig implementation
- `scripts/aegisctl.py` - Python CLI
- `ts_policy/src/` - TypeScript policy authoring
- `CONTRACT_MAP.json` - Contract registry
