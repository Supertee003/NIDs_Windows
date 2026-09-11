# GO_ARCHITECTURE_DECISION — REBUILD-001 (UPDATED)

**Decision: KEEP go/aggregator/ — it is an active sidecar with unique functionality.**

**HEAD:** `2c7cb30` · **Mode:** corrected audit · **Date:** 2026-09-11

---

## Answers (required format)

**GO DECISION:** KEEP (corrected from DO NOT CREATE)

**REASON:** go/aggregator/ is an active sidecar service with unique functionality NOT in src/federation/aggregator.zig:
- REST API server (8 endpoints on port 9200)
- NDJSON file tailing via fsnotify (watches logs/aegis_core.ndjson)
- Session timeline reconstruction across tiers
- Severity escalation on dedup
- LRU eviction with configurable max capacity (10,000 alerts)
- Health check with RUNTIME_CONTRACT.md schema

**Architecture difference:**
- Go: Standalone sidecar process, file-based protocol (watches NDJSON log)
- Zig: Embedded library, in-memory IpcEvent processing

**Status:** Marked `required: false` (optional sidecar), but builds/tested in CI.

**NOSE RESPONSIBILITY:** Packet acquisition + canonical event production (CONTRACT-01, 109-byte CanonicalEvent) over Npcap, delivered to the Zig runtime via named pipe (`nose/pipe_writer.go` → `src/capture/nose_pipe_reader.zig` / `nose_contract.zig`). Owns I/O-heavy, high-concurrency acquisition. Does NOT own policy, enforcement, detection, or a second event model.

**AGGREGATOR RESPONSIBILITY:** Alert collection, deduplication, and cross-tier correlation via REST API. Operates on file-based protocol (watches NDJSON logs). Provides HTTP endpoints for dashboard/UI integration.

**GO RESPONSIBILITY (final):**
1. `nose/` — Packet acquisition (canonical Go sensor)
2. `go/aggregator/` — Alert sidecar (REST API + NDJSON correlation)

Both are active and have unique responsibilities.

**BUILD:** 
- `nose/` builds (`go build -o aegis-nose.exe .`, Go 1.22, module `aegis-nose`, deps: gopacket + bubbletea)
- `go/aggregator/` builds (`go build -o aegis-aggregator.exe .`, Go 1.21, module `github.com/aegis-nids/aggregator`, deps: fsnotify + uuid)
- CI job `go-build-test` builds both successfully

**TEST:** 
- `nose/` has `canonical_test.go` (never run in CI)
- `go/aggregator/` has `alert_test.go` and `correlator_test.go` (run in CI)

**RUNTIME:** 
- `nose/aegis-nose.exe` is runtime-reachable as the acquisition producer
- `go/aggregator/aegis-aggregator.exe` is an optional sidecar (required: false)

**RELEASE:** 
- `build_truth.json` declares `nose` as a build component
- `runtime_manifest.json` declares `go_aggregator` as canonical entrypoint
- Both are part of the release artifact set

**SECURITY BOUNDARY:** Go → C ABI / named pipe → Zig only. Go never touches WFP, PEP, or policy (enforced by nose's pipe-writer design). No Go→WFP path exists or may exist.

## Required actions

1. **Naming consistency:** Standardize on `aegis-aggregator.exe` (not `aggregator.exe`). Update runtime_manifest.json line 136.
2. **CI optimization:** go-build-test job should build both nose/ and go/aggregator/ (currently does).
3. **Documentation:** Update SYSTEM_MAP.json, AUTHORITY_MAP.json to reflect go/aggregator as active component.
4. **Integration:** Consider integrating go/aggregator into golden data path (optional).

## Why KEEP go/aggregator (corrected from DO NOT CREATE)

- go/aggregator/ has a valid go.mod and builds successfully in CI
- It provides unique REST API functionality not in src/federation/aggregator.zig
- It operates on file-based protocol (NDJSON tailing) vs in-memory protocol (Zig)
- It is referenced in runtime_manifest.json, build_manifest.json, and components.json
- It has unit tests that run in CI
- It is marked as optional (required: false) but is actively used

## Comparison with Zig aggregator

| Dimension | Go go/aggregator/ | Zig src/federation/aggregator.zig |
|-----------|-------------------|--------------------------------------|
| Architecture | Standalone sidecar process | Embedded library (in-process) |
| Input | File-based: watches logs/aegis_core.ndjson via fsnotify | In-memory: receives IpcEvent structs via ingest() API |
| Event type | Custom Alert struct (JSON-based) | IpcEvent (binary, 109-byte canonical wire format) |
| Dedup key | SHA-256 of (rule + src_ip + event) triple | event_id (uint64) identity check |
| Correlation | Session timeline reconstruction across tiers | Cross-node federation: counts distinct origin_node_id |
| API | Full REST API (8 endpoints on port 9200) | Zero API -- library functions only |
| Protocol | REST/JSON over HTTP | Direct function calls within Zig process |
| Size | ~930 lines of Go + 273 lines of tests | ~124 lines of Zig |
| Dependencies | fsnotify, uuid (external) | Only stdlib |
