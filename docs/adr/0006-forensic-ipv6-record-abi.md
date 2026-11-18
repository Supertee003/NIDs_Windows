# ADR-0006: Forensic IPv6 Record ABI

**Status:** Accepted (2026-10-06 — see Decision Log; raw-bytes-only,
no layout change, SIEM/LogEvent shipped in FOR-V6A)
**Date:** 2026-10-06

## Context

The pipeline carries full IPv6 identity in queue-frame sidecars
(`src_ipv6/dst_ipv6 ?[16]u8`, `canonical_event.zig:407`; flow keys and
the V6-DETECT-037 baseline follow them), but forensics is IPv4-only.
Investigation (code, not opinion):

1. `CanonicalEvent.source_ip/dest_ip: u32`
   (`canonical_event.zig:51-53`); `PipelineResult.source_ip/dest_ip`
   and `pep_blocked_ip: u32` (`forensics_engine.zig:45-46,72`);
   `LogEvent.src_ip: ?u32` (`forensic_log.zig:230`). v6 sidecars
   never enter any forensic struct.
2. For v6 events the u32 is the address **prefix**: the wire codec
   rejects anything else (`IpMismatch` unless `source_ip` equals the
   first 4 sidecar bytes, `canonical_event.zig:417`). Two v6 hosts in
   one /32 are indistinguishable in forensics today.
3. The evidence hash chain hashes record **content bytes**
   (`evidence_record.zig:165-184`), so any field addition changes
   hashes — a layout bump is a chain-migration event, not a free
   edit (FOR-001 integrity: sequence → hash → CRC → verify → replay).
4. SIEM has the same wart in string form: `siemForward` prints the
   u32 as a dotted quad (`event_processor.zig`), so a v6 detection
   forwards its prefix disguised as a v4 address.

## Proposal (recommendation, not decision)

- **Additive optional sidecars**: `source_ipv6/dst_ipv6: ?[16]u8` on
  `PipelineResult`, optional `src_ipv6`/`dst_ipv6` strings on
  `LogEvent` NDJSON, same on the SIEM event (text form from the
  sidecar when present, replacing the dotted-prefix print).
- **Version-tagged hash**: the chain record carries a layout version;
  the verifier dispatches v1 (current bytes) vs v2 (with sidecars).
  Old chains keep verifying; new records are v2. No rehashing.
- **Replay**: v2-aware reader; v1 records replay with null sidecars
  (exactly what they contain today — no invented identity).

## Rejected

- Silent prefix-as-address (status quo is misleading, say so or fix).
- Parallel v2 record types with dual code paths (doubles the
  forensic surface for one optional field pair).
- Rehashing old chains (rewrites immutable evidence — never).

## Open owner questions

1. Additive sidecars (recommended) vs explicit v2 records?
2. Chain cutover: dual-verify window permanently, or v1 sunset date?
3. Is the SIEM schema change (new optional string fields, no more
   dotted-prefix for v6) acceptable to current consumers?
4. NDJSON compat: optional fields outright, or a `forensic_version`
   header line per file?

## Consequences

1. Nothing changes until decided; v6 forensic blindness stands and
   is now documented instead of implied.
2. Answers unlock one implementation slice: structs + hash dispatch
   + NDJSON/SIEM text form + replay + vector updates (same patch,
   per the one-schema-N-codecs rule).
3. The SIEM dotted-prefix wart rides with that slice, not separately.

## References

- `src/contract/canonical_event.zig` (u32 fields, sidecars, line 417)
- `src/forensic/forensics_engine.zig` (`PipelineResult`, ring)
- `src/forensic/evidence_record.zig:165-184` (content-byte hash)
- `src/forensic/forensic_log.zig` (`LogEvent`)
- `src/pipeline/event_processor.zig` (`siemForward`, V6-DETECT-037)

## Decision Log (2026-10-06, FOR-V6B)

Accepted: raw-bytes-only. No header break, no payload trailer.
Grounds (corrected target map from FOR-V6A implementation work):
the ring `RecordHeader` carries no IP fields by design, the
`EvidenceRecord` hash chain is IP-free, and the u32 `ForensicsEngine`
ring is unwired — so there is no v6-hostile structure left to migrate,
only query convenience. The wired wart (SIEM/NDJSON dotted-prefix) is
fixed; parsed v6 identity is served from SIEM/LogEvent text plus
re-parseable packet bytes. An ABI break + dual-read path is rejected
as disproportionate. Open questions 2–4 (chain cutover, SIEM schema)
are closed as moot on the same grounds; question 1 resolves to "none
of the above — no layout change".
