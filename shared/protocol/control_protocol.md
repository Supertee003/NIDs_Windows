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
| `HEALTH` (alias `health.check`) | READ | Health check results; `data` is the RUNTIME_CONTRACT.md §4.1 payload |
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
- `tools/aegisctl.py` - Python CLI
- `ts_policy/src/` - TypeScript policy authoring
- `CONTRACT_MAP.json` - Contract registry

---

# Version 2 (ACTIVE — the daemon speaks this; v1 above is frozen history)

**Supersedes:** the v1 command table and references below remain frozen and
are kept for history. The active implementation is
`src/control/protocol.zig` (`CONTROL_PROTOCOL_VERSION = 2`) with handlers
in `src/control/handler_registry.zig`. The v1 reference
`src/policy/control_ipc.zig` (binary fixed-header design) has zero
production importers: its role/ACL/freshness concepts were inherited by the
v2 JSON protocol, but it is NOT the wire path. Transport, message format,
roles, and invariants from v1 are unchanged; what changed is the command
table (33 dotted commands + aliases) with per-command roles and
mutation/postcondition flags.

## v2 command table (authority: `Command.fromString` + `contract()`)

| Command | Role | Mutation | Description |
|---------|------|----------|-------------|
| `system.status` | READ | no | Show daemon status |
| `system.health` | READ | no | Health check |
| `system.version` | READ | no | Show version |
| `system.diagnose` | READ | no | Run diagnostics |
| `runtime.start` | PRIVILEGED | yes | Start runtime |
| `runtime.stop` | PRIVILEGED | yes | Stop runtime |
| `runtime.restart` | PRIVILEGED | yes | Restart runtime |
| `rules.list` | READ | no | List rules |
| `rules.show` | READ | no | Show rule details |
| `rules.validate` | READ | no | Validate rules |
| `rules.reload` | OPERATE | yes | Reload rules into engine |
| `events.count` | READ | no | Event count |
| `events.stats` | READ | no | Event statistics |
| `events.tail` | READ | no | Recent events |
| `queue.stats` | READ | no | Queue ingress per source plus pipeline latency snapshot |
| `incidents.list` | READ | no | List incidents |
| `incidents.show` | READ | no | Show incident details |
| `policy.list` | READ | no | List policies |
| `policy.validate` | READ | no | Validate policies |
| `policy.verify` | OPERATE | no | Verify policy signatures |
| `policy.simulate` | OPERATE | no | Simulate policy execution |
| `forensics.list` | READ | no | List forensic records |
| `forensics.show` | READ | no | Show forensic record |
| `forensics.verify` | OPERATE | no | Verify forensic integrity |
| `forensics.export` | PRIVILEGED | yes | Export forensic data |
| `forensics.replay` | PRIVILEGED | yes | Replay forensic sequence |
| `enforcement.status` | READ | no | Enforcement status |
| `enforcement.simulate` | OPERATE | no | Simulate enforcement |
| `enforcement.verify` | OPERATE | no | Verify enforcement |
| `enforcement.block` | PRIVILEGED | yes | Block an exact flow through Rust PEP |
| `enforcement.unblock` | PRIVILEGED | yes | Remove a filter by receipt filter_id |
| `enforcement.two_person` | PRIVILEGED | yes | Two-person rule on/off (Rust PEP) |
| `enforcement.approve` | PRIVILEGED | yes | One-shot second-human approval |
| `enforcement.quarantine` | PRIVILEGED | yes | Quarantine an exact flow (severity-gated, DECISION_QUARANTINE receipt) |
| `metrics.snapshot` | READ | no | Metrics snapshot |
| `logs.tail` | READ | no | Recent log entries |
| `federation.status` | READ | no | Federation cluster status |
| `daemon.shutdown` | PRIVILEGED | yes | Shutdown daemon |

Legacy aliases (accepted, same command): `status`, `health`, `health.check`,
`version`.

## Retired names (v1-era, UNKNOWN_COMMAND on v2 daemons)

These names appear in v1-era docs and the dead `tools/aegisctl/commands/`
package. Nothing in the active tree sends them and the v2 map has no
entries for them — a daemon answers UNKNOWN_COMMAND. Do not use in
runbooks or automation:

- `block.request` → use `enforcement.block` (privileged, receipt postcondition)
- `unblock.request` → use `enforcement.unblock` (privileged, by filter_id)
- `quarantine.request` → no active equivalent (list-only CLI surface)
- `block_request`, `enforce_push` (underscore variants from the dead package)

## v2 references (active)

- `src/control/protocol.zig` - command table, roles, envelope (`CONTROL_PROTOCOL_VERSION = 2`)
- `src/control/handler_registry.zig` - handlers
- `tools/aegisctl.py` - Python CLI (pipe-only client)
- `src/policy/control_ipc.zig` - UNLINKED reference (T16 concepts only, not the wire path)
