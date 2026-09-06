# P4 Enforcement Contract (Phase S / T / K)

This document is the single source of truth for the Windows
enforcement path after P4. It binds together three independently
tested implementations:

| Layer | File | Language | Verified by |
|-------|------|----------|-------------|
| Kernel producer | `kernel/wfp/aegis_wfp.c` | C (WDK) | build + sign + load |
| Userspace mirror | `core/wfp_production.zig` | Zig | `zig build test` (15 tests) |
| Enforcement adapter | `shield_rust/src/windows_enforce.rs` | Rust | `cargo test` (13 tests) |
| Progression control | `core/canary_progression.zig` | Zig | `zig build test` (15 tests) |

Any change to a wire format, IOCTL code, threshold default, or
promotion gate MUST update this document and the parity tests in the
same commit.

## 1. Device and service identity

| Item | Value |
|------|-------|
| Service name | `AegisWfp` |
| Service type | kernel, start = demand |
| Device name | `\Device\AegisWfp` |
| User symlink | `\DosDevices\AegisWfp` (userspace opens `\\.\AegisWfp`) |
| Sublayer | "AEGIS NIDS Inspection SubLayer" |
| Ring capacity | 64 MiB (`RING_BUF_SIZE`) |
| Max packet copy | 4096 bytes per packet (`MAX_PACKET_COPY`) |

## 2. Ring buffer protocol (driver -> userspace)

The ring is `AEGIS_RING_HEADER` followed by the records region.
All integers are little-endian. Both cursors are RELATIVE indices
into the records region in `[0, capacity)`.

`AEGIS_RING_HEADER` - 20 bytes:

| Offset | Field | Type | Meaning |
|--------|-------|------|---------|
| 0 | write_pos | u32 | producer cursor (kernel) |
| 4 | read_pos | u32 | consumer cursor (userspace) |
| 8 | capacity | u32 | records region size in bytes |
| 12 | packet_count | u32 | packets written (monotonic) |
| 16 | dropped_count | u32 | packets dropped when full |

Producer rules (mirrored from `aegis_classify`):

1. Free space = `capacity - (write_pos - read_pos) - 1` when
   `write_pos >= read_pos`, else `read_pos - write_pos - 1`.
   The `- 1` reserve disambiguates full from empty.
2. A record is `[AEGIS_PKT_META][payload]`; `meta.size` counts the
   whole record including the 49-byte header.
3. Records MAY straddle the ring end: the producer writes chunk1 at
   `[offset..capacity)` and chunk2 at `[0..)`. Consumers MUST decode
   wrap-safely (see `wfp_production.RingConsumer.readWrap`).
4. When `free < total`, the record is dropped and
   `dropped_count++`. Unread data is never overwritten.
5. After writing, `write_pos = (write_pos + total) % capacity`.

Consumer rules:

1. Empty means `read_pos == write_pos`.
2. After a poll, the consumer publishes its cursor back to
   `header.read_pos`.
3. Malformed records are rejected fail-soft with a deterministic
   resync: trust `meta.size` when `49 <= size <= 4145`, else advance
   exactly one metadata step (49 bytes). A per-poll step bound of
   `capacity / 49 + 2` prevents runaway scans.

`AEGIS_PKT_META` - 49 bytes, packed (`#pragma pack(1)`):

| Offset | Field | Type | Meaning |
|--------|-------|------|---------|
| 0 | size | u32 | total record bytes (>= 49) |
| 4 | orig_len | u32 | original packet length before truncation |
| 8 | timestamp | u64 | KeQueryPerformanceCounter value |
| 16 | layer_id | u16 | WFP layer that captured the packet |
| 18 | direction | u16 | 0 = inbound, 1 = outbound |
| 20 | process_id | u32 | PID from WFP classify |
| 24 | ip_proto | u16 | 6 = TCP, 17 = UDP, ... |
| 26 | _pad | u16 | alignment filler |
| 28 | src_ip | u32 | IPv4, network byte order |
| 32 | dst_ip | u32 | IPv4, network byte order |
| 36 | src_port | u16 | host byte order |
| 38 | dst_port | u16 | host byte order |
| 40 | threat_score | i32 | 0..1000, x10 fixed point (600 = 60.0) |
| 44 | confidence | u8 | 0 unknown, 1 low, 2 medium, 3 high, 4 critical |
| 45 | risk_flags | u32 | bitfield of matched rules |

Userspace validation (both Zig and Rust sides reject identically):
`direction <= 1`, `confidence <= 4`, `threat_score` in `0..1000`,
`ip_proto` in `{1, 6, 17, 47, 50, 58, 132}`.

## 3. IOCTL contract

Codes 0x800..0x807 as implemented in `aegis_dispatch_device_control`:

| Code | Name | In payload | Out payload | Effect |
|------|------|-----------|-------------|--------|
| 0x800 | GET_RING_ADDR | - | 8 (PVOID) | ring base address |
| 0x801 | GET_STATS | - | 20 (ring header) | cursor + counters snapshot |
| 0x802 | SEMI_BLOCK_IP | 4 (u32 ip) | 4 | permanent block, dedup |
| 0x803 | SEMI_UNBLOCK_IP | 4 (u32 ip) | 4 | unblock + whitelist |
| 0x804 | SEMI_SET_THRESHOLDS | 12 (3 x i32) | 12 | block/ratelimit/alert |
| 0x805 | SEMI_GET_STATE | - | 30779 | full SEMI_NIDS_STATE |
| 0x806 | SEMI_SET_FAILOPEN | 1 (BOOLEAN) | 1 | force fail-open |
| 0x807 | SEMI_WHITELIST_IP | 4 (u32 ip) | 4 | whitelist only |

IP addresses in IOCTL payloads use driver byte order: the u32 holds
four octets with the most significant byte as the first octet
(`0x7F000001` = 127.0.0.1). `windows_enforce.format_ipv4` renders
this order; Rust payloads are little-endian encoded (`to_le_bytes`).

`SEMI_NIDS_STATE` size parity (30,779 bytes) is asserted by test:

| Section | Bytes |
|---------|-------|
| 3 x LONG thresholds | 12 |
| BOOLEAN fail_open + 2 x UCHAR load | 3 |
| temp_blocks[1024] x 25 | 25600 |
| temp_block_count | 4 |
| perm_blocks[1024] x 4 | 4096 |
| perm_block_count | 4 |
| whitelist[256] x 4 | 1024 |
| whitelist_count | 4 |
| 4 x ULONG64 stats | 32 |

## 4. Decision plane parity

All three implementations decide identically. Golden vectors
(asserted in Zig test `enforcement decision matrix` and Rust test
`decision_matrix_matches_zig_parity_vectors`):

| score_x10 | confidence | fail_open | action |
|-----------|------------|-----------|--------|
| 600 | high(3) | false | block(3) |
| 950 | critical(4) | false | block(3) |
| 900 | medium(2) | false | rate_limit(2) |
| 400 | medium(2) | false | rate_limit(2) |
| 400 | low(1) | false | alert(1) |
| 200 | unknown(0) | false | alert(1) |
| 199 | critical(4) | false | allow(0) |
| 990 | critical(4) | true | allow(0) |

Rule text: fail-open allows everything; block requires
`score >= 600 AND confidence >= high`; rate limit requires
`score >= 400 AND confidence >= medium`; alert requires
`score >= 200`; anything else allows.

Fail-open triggers when CPU >= 85% OR queue >= 95%
(`FAIL_OPEN_CPU_THRESHOLD` / `FAIL_OPEN_QUEUE_THRESHOLD`).

## 5. Progression stages (Phase T)

Enforcement decisions earn real traffic through strictly ordered
stages managed by `core/canary_progression.zig`:

```
simulation -> shadow -> canary -> enforce
                                  enforce -> rolled_back
                                  rolled_back -> simulation (reset)
```

| Stage | Meaning |
|-------|---------|
| simulation | decisions computed and discarded |
| shadow | decisions logged next to the live path, not applied |
| canary | decisions applied only to TEST-NET-3 canary traffic |
| enforce | decisions applied to real traffic |
| rolled_back | auto/manual rollback landed; full reset required |

Promotion gates (all must hold, fail-closed; defaults shown):

1. `min_canary_runs >= 10` canary probes in the current stage
2. canary failure rate `<= max_fail_rate_bps` (200 bps = 2%)
3. observation window `>= min_observe_ms` (300,000 ms = 5 min)
4. human approval for `canary -> enforce` only
   (`require_human_approval = true`); approvals never leak across
   stages and are consumed on entry

Auto-rollback triggers while enforcing (fail-closed on real
traffic):

1. `consecutive_rollback_fails` (3) consecutive failed canaries
2. stage canary failure rate above `enforce_fail_rate_bps`
   (2000 bps) after `enforce_rate_min_runs` (10) runs

Manual rollback is allowed from shadow, canary and enforce. Reset
after rollback restarts the full cycle at simulation with per-stage
counters zeroed and the rollback count preserved as history.

## 6. Enforcement adapter (Phase K)

`shield_rust/src/windows_enforce.rs` owns the userspace half:

1. Decision engine - pure function, parity-tested against section 4.
2. Mirror state - perm blocks (dedup, cap 1024), temp blocks with
   expiry (0 = permanent), whitelist (unblock whitelists), fail-open
   flag. Whitelisted IPs are refused at block time (fail-closed).
3. Command encoding - `Command` maps to IOCTL codes with exact
   payload sizes (4 / 12 / 1 bytes, little-endian).
4. Kernel transport - `CreateFileW(\\\\.\\AegisWfp)` +
   `DeviceIoControl`, compiled only on Windows (`cfg(windows)`).
5. Fallback - when the kernel path is unavailable, a real netsh
   firewall command is produced
   (`netsh advfirewall firewall add rule ... action=block remoteip=...`).
6. Audit - every decision and command appends a bounded (256 entry)
   audit record with timestamp and outcome.

## 7. Build, sign, install runbook

```
scripts\wdk_build_production.ps1     build x64 aegis_wfp.sys via WDK
scripts\wfp_sign.ps1                 test-sign + install test cert
scripts\wfp_service.ps1 install       create kernel service (demand)
scripts\wfp_service.ps1 start         load the driver
scripts\wfp_service.ps1 status        query + SHA-256 of loaded binary
scripts\wfp_service.ps1 uninstall     stop + delete + remove binary
```

Order matters: build, sign, then install. Test signing requires
`bcdedit /set testsigning on` and a reboot (the sign script handles
this behind an explicit confirmation). Uninstall is idempotent and
rolls back its own partial steps (binary copy, service creation).

## 8. Provenance and release notes

The production filter set installs five WFP filters in this order,
each with a distinct sublayer weight:

1. `FWPM_LAYER_INBOUND_IPPACKET_V4` (weight 0)
2. `FWPM_LAYER_OUTBOUND_IPPACKET_V4` (weight 1)
3. `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (weight 2)
4. `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` (weight 3)
5. `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` (weight 4)

Filter lifecycle invariants (`wfp_production.FilterLifecycle`):

- install requires service running AND device open
- partial install records exactly which layers are live
- removal is reverse-order, idempotent, and only touches live layers
- service stop with live filters is refused (fail-closed guard)
- a service crash resets the installed mask (filters died with it)

Release signing for production distribution (beyond the development
test-sign path) remains a deferred item tracked by the build
manifest; this P4 path is the developer enablement route.
