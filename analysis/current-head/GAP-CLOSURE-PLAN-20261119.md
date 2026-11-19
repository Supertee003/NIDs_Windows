# Gap closure plan — coverage, visibility, alerting, manageability, backpressure

**PLAN-ID:** GAP-CLOSURE-20261119  
**OWNER DIRECTIVE:** 2026-11-19 — “ทำเลยได้ไหม ไม่ต้องรอ soak แล้ว ก็ทำตามลำดับ ได้เลย” + “เขียนเลย” for records.  
**BUILD SOURCE AT PLAN TIME:** `f4cde3c503fd8b696183751a608b999768caa769`  
**RECORDS HEAD AT PLAN TIME:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40`  
**SIGNED CANDIDATE STILL ON HOST:** `release/T20-final/b597e71` (unchanged, not rebuilt, not re-signed).

---

## 1. Non-negotiable isolation rule

The owner-approved 24 h soak window `2026-11-19T04:38:09 → 2026-11-20T04:38:09`
keeps running against the **already-installed** candidate. New source work is
performed in a **separate git worktree** and must never:

- install a new binary/driver,
- restart a service or the daemon,
- change capture topology or interface selection,
- inject load,
- touch `release/T20-final/b597e71`,
- edit the saved soak baseline or delta artifacts.

Therefore the current soak remains valid proof for `f4cde3c`/`b597e71`. Any new
binary produced by this plan is **not covered by that soak** and will require its
own evidence slice before release. The board stays 5/6 until the owner decides
whether the current soak PASS closes v1.1 and this plan becomes v1.2 work, or
whether a fresh window is required for the new build source.

---

## 2. Why this plan exists

Three read-only audits completed on 2026-11-19 established that the system is
**not yet complete** in five areas:

| Audit | Source |
|---|---|
| Detection engine + sensors | `ses_e0c7ba452ffdGWhk22noIvb2li` |
| UI / alert / log / manageability | `ses_e0c7ba451ffeiEAjK4wOd3S8Xa` |
| Backpressure / bottleneck | `ses_e0c7ba44fffew6sGS6PMQ9bzmI` |

Their combined verdict: signature+stateful analysis exists but is partial;
displays and forensic logging exist but push alerting does not; rule editing is
file/CLI-only; overload is shed-and-counted but not prevented; and kernel
visibility is bounded by WFP fail-open, payload caps, shadow rows and interface
selection.

---

## 3. Slice sequence (owner-approved order)

### SLICE 1 — RULE COVERAGE + FP/FN  *(start now)*
**PATCH-ID:** `RULE-COVERAGE-001`  
**FLOW-ID:** `DETECTION-L4-KERNEL`, `DETECTION-R2003`

Close the gap that the owner named directly: “gฎที่มีอยู่ masihไม่ครอบคลุม”.

| Gap | Concrete closure | Acceptance evidence |
|---|---|---|
| `regex_pattern` in `configs/Rules.json` is display-only | Decide explicitly: either execute it via a safe regex engine or remove/mark it `advisory` so the catalog stops promising behaviour it lacks | E2 unit test + `rules validate` output |
| L4 flag rules `R9006`/`R9007` only fire on Npcap/Nose | Extract TCP flags in WFP consumer and make `l4_matcher` accept `.capture_wfp`; sidecar must stay in-memory, not on the wire | E2 test with WFP-sourced event → rule match |
| FP-1 `RULE-LAYER-SCOPE-001` — R2003 matched TLS bytes, 366 rows | Scope R2003 to HTTP/command context or add negative-control fixture; prove 0 FP on TLS corpus | E3 lab negative control |
| FN-1 — R2003 has no command line | Consume process-create command line from real ETW path; no new wire field unless all six codecs + `event_v*` vector change together | E3 lab positive control |
| 20/23 rules only E1/E2 | Generate fixture/negative-control matrix for all 23; keep R9006 E5+E6 as reference | Updated `docs/DETECTION_VALIDATION.md`, E3 where host allows |

**Out of scope for Slice 1:** installer, signatures, services, WFP enforcement,
new host effects.

---

### SLICE 2 — VISIBILITY
**PATCH-ID:** `VISIBILITY-001`

- Make WFP primary selectable (not only shadow) without removing Nose topology switch.
- Evaluate multi-interface capture or explicit operator selection.
- Add payload reassembly or document the ≤4096 B / no-reassembly boundary as a rule-scope constraint.
- Keep encrypted-payload limitation explicit; it is not solvable without endpoint/agent data.

---

### SLICE 3 — ALERT + MANAGEMENT
**PATCH-ID:** `OPERATOR-001`

- Re-enable a detection-only notifier transport (webhook/syslog) with fail-closed config.
- Turn on SIEM forwarding as opt-in and add per-threat dashboard banner.
- Add authenticated rule mutation through the control plane (web editor or documented CLI parity).
- Make `policy reload/enable/disable` real or remove the misleading commands.
- Define signed `ts_policy` IR promotion with trust check; never bypass Zig authority.

---

### SLICE 4 — BOTTLENECK + METRICS
**PATCH-ID:** `OBSERVABILITY-001`

- Add `shed_overload` to `data_integrity` in `state_machine.zig`.
- Add true Nose backpressure instead of drop-on-write.
- Add boot-id to reset counter semantics.
- Fix 6/10 latency stages stuck at 1 ns floor.
- Add resource metrics (CPU/RAM/disk/ring) and TP/FP + per-rule fire rate.

---

## 4. Patch transaction template (AGENTS.md)

Every slice must declare and produce:

```
PATCH-ID / FLOW-ID / TARGET HEAD / FINAL HEAD
TARGET FILES / TARGET SYMBOLS
IN-SCOPE / OUT-OF-SCOPE
CONTRACT IMPACT / ABI IMPACT / AUTHORITY IMPACT / STATE IMPACT
TEST IMPACT / EVIDENCE IMPACT
OLD FLOW -> NEW FLOW / INVARIANT
BUILD RESULT / TEST RESULT / WINDOWS RESULT
EVIDENCE LEVEL / EVIDENCE ARTIFACTS
ROLLBACK / REMAINING RISK / OPEN BLOCKERS / COMPLETION GATE
```

---

## 5. Current truth to preserve

- Detection-only product: no host effect, no WFP enforcement, no PEP block.
- One production runtime; Rust PEP stays detection-only authority.
- Both capture topologies remain switchable.
- No wire change without updating Zig/Go/C++/Python×2/golden tuple-map and a shared `event_v*` vector in the same patch.
- All records edits remain uncommitted until the owner authorises commit.

---

## 6. Completion gate for this plan

Not “6/6 board” by itself. The gate is:

1. Slice 1 closes rule coverage with E2/E3 evidence and no FP/FN regressions.
2. Slices 2–4 each produce their own patch transaction and evidence.
3. Owner decides soak disposition (v1.1 close vs fresh window for new build source).
4. Only then tag/publish — **never before owner confirmation**.
