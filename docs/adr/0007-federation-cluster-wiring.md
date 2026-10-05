# ADR-0007: Federation Cluster Wiring

**Status:** Proposed (verdict: proceed if feasible — feasibility
established here as phased, not direct; blocked on one-stack pick)
**Date:** 2026-10-06

## Context

Owner verdict: develop federation if feasible. Two-agent survey of
the family (`src/federation/*`, 8 files, ~230KB + Rust shell):

| Component | State |
|---|---|
| `federation_codec.zig` (frame `AEGI`/ver/CRC, conn mgr, outbound queue, facade) | MATURE, ~30 tests, loopback 2-node proven |
| `cluster_coord.zig` (registry, heartbeat, x-node incidents, threat-intel bcast, leader election) | LOGIC-COMPLETE, ~30 tests, no sockets by design |
| `federation_tcp.zig` (framing, server/client, reconnect) | COMPLETE, host-tested on 127.0.0.1 |
| `aggregator.zig` (dedup, per-source node count) | COMPLETE, 3 tests |
| `federation_bench.zig` + `integration_test.zig` (throughput, failover) | COMPLETE harness |
| `federation_tls.zig` (Zig) | **MOCK passthrough** — handshake succeeds instantly, no encryption; SChannel/CNG is "future work" |
| `rust-src` `federation_tls` (rustls 0.23) | **FFI SHELL** — empty roots, no client auth, untested, zero callers, no FFI exposure |
| `node_registry.zig` | Table only — no UDP beacon, no mDNS, no `cluster.json` parsing despite header |
| `federation.zig` (G17) | SUPERSEDED slim duplicate of `cluster_coord` (no threat-intel, no ingest/tick); zero importers |

Pins holding the line: `test_federation_family_has_no_production_importers`
(FED-TIDY-058, fail on any prod import), `federation.status`
read-only returning standalone (`handler_registry.zig`), daemon
`Federation/XDR (disabled)`, `FederationBackend.send_fn` never
installed (escalate = best-effort false). T13/T16 scan the TLS files
for validator properties — any edit must keep those properties true.

## Feasibility verdict

Feasible **phased**, not directly wirable. Three hard blockers make
direct wiring unsafe: (1) no real encrypted transport exists (mock
Zig TLS + shell Rust TLS — wiring either today ships plaintext or
fiction); (2) no discovery transport; (3) two parallel TLS stacks
plus a G17 duplicate plus a `NodeRegistry` name collision
(`federation/node_registry` vs `cluster_coord.NodeRegistry`).

## Phased plan (recommendation, not decision)

- **P1 consolidate (safe, no behavior change):** retire the G17
  `federation.zig` duplicate (delete only if no E2 pin reads it —
  additive-first check first), resolve the `NodeRegistry` collision
  by rename, add codec golden `.bin` vectors (the family is the one
  codec without `event_v*`-style vectors).
- **P2 one real TLS stack:** pick Rust-rustls-via-FFI (reuse tested
  premium crypto, matches PEP precedent) OR Zig-native (no FFI seam);
  kill the other stack outright. Real handshake + pinned
  CA/client-auth required before any cross-machine byte.
- **P3 discovery transport:** parse static `configs/cluster.json`
  into the registry; beacon/mDNS only if P2 demands it.
- **P4 daemon wiring:** install a verified P2 transport into
  `FederationBackend`, flip `federation.status` off standalone,
  update the forbidden-edges pin **in the same patch** (conscious
  contract change, never silent).

## Rejected

- Wiring TCP-plaintext now (violates the no-plaintext constraint).
- Wiring mock-TLS labeled as TLS (fiction in the control plane).
- Keeping both TLS stacks (two handshakes, two CA stories, zero
  shared roots — pick one, delete the other).
- Deleting the family to "simplify" (destroys tested coordination
  logic the owner just voted to develop).

## Open owner questions

1. One-stack pick: Rust-rustls-FFI or Zig-native?
2. P1 scope approved (dup retirement + rename + golden vectors)?
3. `cluster.json` schema owner (static discovery format)?
4. G17 `federation.zig`: delete or label specimen (REL-SPEC-050
   pattern)?
5. Manifest blurbs ("transport is TLS") read as current-state claims
   while standalone — reword as constraints now, or with P4?

## Consequences

1. Nothing wires until P2 answers exist; the FED-TIDY pin stays red
   on any prod import meanwhile.
2. P1 can start without further verdicts except Q2/Q4.
3. P4 is the only patch allowed to touch the pin, the handler, and
   the daemon init — together, reviewed as one contract change.

## References

- `src/federation/*` (8 files; headers carry FED-TIDY-058 status)
- `rust-src/lib.rs:737-788` (`federation_tls` shell)
- `src/policy/action_dispatcher.zig` (`FederationBackend`, no transport)
- `src/control/handler_registry.zig` (`federationStatus` standalone)
- `src/daemon.zig` (Federation/XDR disabled)
- `tests/federation/test_t13_federation_tls.py`, `test_forbidden_edges.py:284-321`
