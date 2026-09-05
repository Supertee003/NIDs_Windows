# Phase G-X Execution Plan

**Date:** 2026-09-02  
**Scope:** All remaining phases (G through X)  
**Strategy:** Documentation-first, incremental proof

## Execution Strategy

Each phase follows the task execution protocol:
1. Inspect current state
2. Record baseline
3. Change one semantic unit
4. Compile
5. Test
6. Update docs
7. Commit

## Phase G: RAG Runtime Proof
**Exit condition:** RAG appears in dispatcher trace + fail-soft proof
- Deploy Phase B (dispatcher_phase_b.zig with rag_int import)
- Add test: "Phase G: RAG query called in processEvent"
- Add test: "Phase G: RAG fail-soft when unavailable"
- Add test: "Phase G: RAG context logged in forensics"
- Document canonical pipeline order in runtime-path.md

## Phase H: Brain Advisory Boundary
**Exit condition:** Brain is advisory-only with timeout + isolation
- Add timeout field to BrainAdvice
- Add test: "Phase H: brain timeout produces default advice"
- Add test: "Phase H: malformed brain advice rejected"
- Document: Brain cannot call block_ip/wfp_ioctl

## Phase I: Policy IR 2.0
**Exit condition:** Typed PolicyIR + deterministic conflict resolution
- Add PolicyValue tagged union (UInt64/Int64/Bool/String/IPv4/CIDR/Port/Enum/TimeWindow)
- Add conflict resolution: priority DESC, specificity DESC, rule_id ASC
- Add policy simulator: shows candidate rules, winner, losers, reason
- Tests: all value types, conflict permutations

## Phase J: Cryptographic Policy Signing (SECURITY GATE)
**Exit condition:** Real SHA-256 + Ed25519 + Rust verification
- Replace FNV-1a with SHA-256 canonical digest
- Implement Ed25519 signing (via Zig stdlib or Rust FFI)
- Add signature metadata: key_id, algorithm, created_at, expires_at
- Add Rust verification path
- Tests: valid sig, modified rule, wrong key, expired, replay, downgrade

## Phase K: Rust PEP Real Boundary (SECURITY GATE)
**Exit condition:** Zig -> Rust -> Windows enforcement -> Audit
- Verify Rust PEP validates: version, signature, capability, scope, expiry
- Add Windows enforcement adapter (WFP IOCTL / netsh)
- Add rollback metadata + idempotency key
- Add audit id + enforcement result
- Tests: valid/invalid capability, expired scope, rollback

## Phase L: Forensics Hash Chain
**Exit condition:** Immutable record + integrity verification
- Add previous_record_hash + record_hash to forensic records
- Add integrity verification command (aegisctl forensic verify)
- Add corruption test
- Separate REPLAY (read-only) from SHADOW (compare) from ENFORCE (real)

## Phase M: Production Lifecycle Separation
**Exit condition:** Production executable does not init test harnesses
- Create ProductionProfile struct (only: forensics, fabric, flow, detection,
  verdict, correlation, TI, RAG, brain, policy, PEP, telemetry)
- Create TestProfile struct (adds: replay, e2e, performance, canary, etc.)
- lifecycle.start() takes profile parameter
- Tests: production profile does not init e2e_harness

## Phase N: aegisctl Control Plane Refactor
**Exit condition:** aegisctl only requests, PEP only enforces
- Move COMPONENTS registry to shared/runtime/components.json
- Remove _signal_core_block() from aegisctl
- Remove direct blocked_ips.json writes
- Route enforcement through Rust PEP via IPC pipe
- Add PID validation (executable path, start time, instance id)
- Tests: aegisctl cannot directly block IP

## Phase O: Runtime Contract Tests
**Exit condition:** Every component has A-J contract suite
- A: process starts, B: health ready, C: event accepted, D: event processed
- E: shutdown clean, F: restart/recovery, G: policy request, H: enforcement result
- I: forensic trace, J: replay
- Each component exposes: liveness, readiness, version, instance_id, uptime, build_id

## Phase P: CI/CD 100%
**Exit condition:** All 15 stages are hard gates
- Stages 1-12 exist; add: 13 (installer validation), 14 (benchmark regression), 15 (artifact provenance)
- Each stage: fail hard on missing gate
- No "skip" allowed for required components

## Phase Q: Performance Contract
**Exit condition:** Benchmark matrix + regression thresholds
- Measure: ingestion rate, pipeline throughput, p50/p95/p99 latency
- Workloads: idle, 1K/s, 10K/s, 50K/s, 100K/s, burst, mixed, flow-heavy
- Set regression thresholds in CI

## Phase R: Reliability Fault Injection
**Exit condition:** Fault matrix + expected behavior verified
- Test: brain down, RAG down, PEP down, detection down, forensics down
- Test: queue full, memory pressure, policy invalid
- Each fault has defined expected behavior

## Phase S: HIDS/WFP/Drivers
**Exit condition:** Real telemetry + lifecycle + failure containment
- Nose: separate capture/normalize/validate/emit/health
- WFP: filter lifecycle (register/activate/monitor/update/rollback/unregister)
- Minifilter: produce Canonical Event (not separate schema)

## Phase T: IPS Canary -> Enforcement
**Exit condition:** Canary progression + rollback verified
- Progression: simulation -> shadow -> canary allowlist -> single target -> time-bounded -> rollback -> expand
- Canary record: canary_id, policy_version, target, start/end, expected/actual action, rollback_reason
- Tests: no unauthorized target, no bypass, rollback works, forensic trace complete

## Phase U: XDR
**Exit condition:** Cross-domain correlation + incident graph
- Network + Process + File + User/Host context -> Entity/Incident Graph
- XDR gate: network-only detected, host context enriches, same entity linked, incident ID stable

## Phase V: Installer/Release
**Exit condition:** Signed reproducible package
- Release contract: version, build_id, commit_sha, compiler versions, artifact hashes
- Installer: validate prereqs, install, set permissions, init config, verify health, rollback on failure
- No release without provenance

## Phase W: Documentation as Testable Artifact
**Exit condition:** Docs verified against implementation
- Doc checker: referenced paths exist, commands exist, components exist, gates exist
- Examples parse correctly

## Phase X: AI Governance + Final Release
**Exit condition:** Context contract template + final release evidence package
- AI context contract: system, semantic position, phase, owner language, objective
- Release evidence: repository, architecture, contracts, unit/integration/runtime/security
- Final gate: all gates pass + no P0 defects + no bypass + no silent loss
