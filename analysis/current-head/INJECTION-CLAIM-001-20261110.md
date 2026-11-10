# INJECTION-CLAIM-001 — the runtime stops advertising a detector it never runs (S2-03)

**Created:** 2026-11-10
**Build source commit:** this commit (Zig source changed: `src/daemon.zig`,
`src/contract/runtime_manifest.zig`)
**Finding:** `SYSTEM-SURVEY-001` §S2-03
**Evidence level:** E2 (`zig build`, `zig build test`, unit tests). No host window.

---

## 1. What was wrong

The survey found one shape of the defect (a detector constructed and never fed).
Re-reading the tree found the same claim in two more places, and one of them is
machine-readable — which is the one that matters:

| Where | Claim | Reality |
|---|---|---|
| `src/daemon.zig:43,618` | `InjectionDetector.init(...)` + `defer deinit()` | nothing called `ingest()`; the object existed only to be destroyed |
| `src/contract/runtime_manifest.zig:109` | `c.has_injection_detector = true;` — a **hard-coded** capability, not a probe like `has_npcap`/`has_etw_realtime` | no production path builds an `InjectionEvent`; the ETW session parses process/file/registry providers into `IpcEvent` and has no process-open / thread-create / `VirtualAllocEx` / image-load opcodes, so the detector's inputs do not exist |
| `docs/ARCHITECTURE.md:54` | "T1055 injection detector … REAL-time ETW path" | there is no ETW path; this is the sentence an operator or auditor would read |

A fourth, subtler point: `src/windows/host_telemetry_detectors.zig` contains a
*second* injection heuristic (`ProcessInjectionDetector`, inside
`EnhancedDetectorAggregator`) whose config defaults to `enabled = false` and which
is reachable only from `src/core/integration_test.zig` and a CLI demo. So the tree
had two injection detectors, neither running in production, and one of them
advertised through the capability manifest.

`runtime_manifest` is published at startup and consumed for feature negotiation:
"is feature X available?" Every consumer that believed it was answering that
question about a live detector was wrong.

## 2. What changed

| File | Change |
|---|---|
| `src/daemon.zig` | the unused import and the construct-then-destroy `InjectionDetector` are gone; the comment states what a producer would have to provide before either returns |
| `src/contract/runtime_manifest.zig` | `has_injection_detector = false` with the reason, and the note that the flag must become a probe of the producer — not a constant — when one exists |
| `docs/ARCHITECTURE.md` | rows 37E3 and 37E7 corrected: **NOT WIRED**, tested logic, no producer, no `ingest()` call site, manifest flag false |
| `tests/security/test_capability_claims.py` | new: 4 tests pinning the rule |

The tests are written so that the *repair path* is also enforced:

1. the manifest may not set `has_injection_detector = true` (mutation control:
   restoring `= true` fails this test);
2. if `InjectionDetector.init(` reappears in `src/daemon.zig`, an `.ingest(` call
   site must exist in the same file — construction without ingestion is the
   production-mock shape;
3. `src/daemon.zig` may not carry an import whose identifier is never used again
   (this is the general form of "instantiated and thrown away"; the removed
   `inj_det` import is the case that motivated it);
4. the architecture document's T1055 row must say NOT WIRED, and the
   "REAL-time ETW path" sentence may not come back.

## 3. Verification

```
zig build                       -> ok, no errors
zig build test                  -> exit 0
python -m pytest -q tests/security/test_capability_claims.py   -> 4 passed
mutation: c.has_injection_detector = true                      -> 1 failed (expected test)
```

The full-suite and truth results for this commit are recorded in the evidence
entry, not predicted here.

## 4. Limitations (stated, not hidden)

1. **The detector is still not wired.** This patch removes a false claim; it does
   not add T1055 detection. Wiring needs new ETW opcode parsing (process-open,
   thread-create, `VirtualAllocEx`, image-load) and an `InjectionEvent` producer,
   plus a detection-identity path into the pipeline — a multi-session slice with
   an E5 gate, not a two-line change.
2. **Two injection implementations still exist in source.** `ProcessInjectionDetector`
   (`windows/host_telemetry_detectors.zig`) and the T1055 detector
   (`detection/injection_detector.zig`) overlap. Choosing one is a design decision
   for the owner; this patch only stops the runtime from claiming either is live.
3. **`runtime_manifest` still hard-codes six other `true` flags** (`has_federation`,
   `has_tls`, `has_xdr`, `has_replay`, `has_forensic_pipeline`, `has_fault_injection`).
   Each needs the same treatment — probe or documented constant — and this patch
   deliberately did not widen into them; `tests/security/test_capability_claims.py`
   currently guards only the injection flag.
4. **No E5.** Nothing here was observed on a host. `zig build test` is E2.
