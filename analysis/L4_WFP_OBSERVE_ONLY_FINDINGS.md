# L4/WFP Observe-Only Findings

## Current source evidence

The WFP callout classifies inbound IPv4 transport packets, extracts a five-tuple, writes a 40-byte event header to the kernel ring, and always permits the packet. This is a fail-open telemetry path; it is not an IPS decision path.

The read-only user-mode bridge exposes `GET_STATS` and `READ_EVENTS`. The observe-only proof opens `\\.\AegisWfpDevice` with `GENERIC_READ` and does not issue the block or unblock IOCTLs.

## Important limitation

`drivers/wfp_callout/aegis_wfp_comm.c:AegisWfpGetStats` currently populates only `currentUsedBytes`. The fields named `totalEventsWritten`, `totalDrops`, `totalBytesWritten`, and `totalBytesRead` are copied as zero-initialized values. Therefore a proof must not interpret those fields as real counters.

The proof script instead uses:

- successful device open;
- successful read-only `GET_STATS` response;
- successful read-only `READ_EVENTS` response and byte count when an event is required;
- the implemented `currentUsedBytes` field;
- explicit disclosure that the aggregate counters are unimplemented.

## Current acceptance boundary

A pass from `run_wfp_l4_observe_only_proof.ps1` proves only device/ring readback. It does not prove that a specific Rules.json rule matched, that payload inspection occurred, or that a WFP filter blocked traffic.

The current callout captures a 5-tuple and sets `payload_length = 0`. Consequently, Rules.json L4 rules are candidates for kernel network telemetry proof, while L7 payload rules cannot be validated by this callout alone.

## Next implementation decision

Before claiming production telemetry counters, implement and test atomic driver counters for events written, drops, bytes written, and bytes read, then expose them through the same packed ABI. Until that patch is complete, keep counter-based acceptance closed and report the limitation explicitly.
