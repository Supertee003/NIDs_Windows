# GO_ARCHITECTURE_DECISION — REBUILD-001

**Decision: DO NOT CREATE `/go`. REPAIR CI instead.**

**HEAD:** `a480efb` · **Mode:** read-only audit · **Date:** 2026-09-10

---

## Answers (required format)

**GO DECISION:** DO NOT CREATE

**REASON:** The responsibility `/go` used to hold — Go-side alert aggregation — is already owned by the canonical Zig runtime (`src/federation/aggregator.zig`, `src/federation/cluster_coord.zig`, `src/federation/node_registry.zig`, all built by `zig build` and tested by `src/tests/federation/*`). Recreating a Go aggregator today would introduce a second aggregation authority with no runtime reachability, violating the ONE-machine invariant. Separately, CI currently builds a directory that no longer exists (`go/aggregator`) and never builds the Go component that DOES exist (`nose/`) — that is a CI bug, not a reason to recreate `/go`.

**NOSE RESPONSIBILITY:** Packet acquisition + canonical event production (CONTRACT-01, 109-byte CanonicalEvent) over Npcap, delivered to the Zig runtime via named pipe (`nose/pipe_writer.go` → `src/capture/nose_pipe_reader.zig` / `nose_contract.zig`). Owns I/O-heavy, high-concurrency acquisition. Does NOT own policy, enforcement, detection, or a second event model.

**GO RESPONSIBILITY (final):** `nose/` only. There is no unmet Go responsibility. If future scale demands a separate collector process (external feed polling, multi-NIC fan-in), it should be added as a package INSIDE the `nose/` module with its own PURPOSE/OWNER/API/CONTRACT/TEST/CI/RELEASE entry — not as a resurrected top-level `/go`.

**BUILD:** `nose/` builds (`go build -o aegis-nose.exe .`, Go 1.22, module `aegis-nose`, deps: gopacket + bubbletea). `go/aggregator/` has no go.mod to build — CI job `go-build-test` is red by construction.

**TEST:** `nose/` has `canonical_test.go` (never run in CI). CI `go-build-test` runs `go test ./...` against the nonexistent `go/aggregator`.

**RUNTIME:** `nose/aegis-nose.exe` is runtime-reachable as the acquisition producer wired to the Zig Event Fabric. `go/aggregator` had no runtime reachability at deletion time (SYSTEM_MAP listed it, but nothing built or launched it — it was reference residue from the legacy federation design).

**RELEASE:** `build_truth.json` declares `nose` as a build component and explicitly notes "Source of truth: … nose/go.mod" (line 89). It does NOT declare go/aggregator. Release truth already agrees: nose in, aggregator out.

**SECURITY BOUNDARY:** Go → C ABI / named pipe → Zig only. Go never touches WFP, PEP, or policy (enforced by nose's pipe-writer design). No Go→WFP path exists or may exist.

## Required actions (next phases, not this audit)

1. **CI fix (P0-3):** change job `go-build-test` from `cd go/aggregator` to `cd nose` (`go build ./...`, `go test ./...`). This single edit turns a permanently-red job green and covers the real Go code with tests for the first time.
2. Update `SYSTEM_MAP.json` / `AUTHORITY_MAP.json` / `FLOW_MAP.json` to remove the `go_aggregator` component entry and the `files: ["go/aggregator/*.go"]` reference (they reference a directory that no longer exists — stale truth).
3. Optional: `canonical.EventSource.go_aggregator = 8` remains in the wire schema for compatibility — keep the enum value (ABI freeze), mark as reserved/legacy in comments. Do NOT renumber.
4. `go/aggregator` logic that might have value (alert fan-in rules) lives on conceptually in `src/federation/aggregator.zig`; if the old Go implementation had algorithms worth porting, recover them from git history as REFERENCE ONLY.

## Why not CREATE /go (explicit)

- Every answer to "why can't the work live elsewhere?" resolves to an existing owner: acquisition → `nose/`, aggregation → Zig federation, event model → CanonicalEvent.
- No build/test/release membership would exist on day one; it would be a directory of promises.
- The owner's goal is "smallest correct AEGIS machine" — `/go` adds a language plane with zero unique responsibility.
