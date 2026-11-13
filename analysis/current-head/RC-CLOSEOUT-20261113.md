# RC-CLOSEOUT — release candidate with a declared ETW loss envelope

**Created:** 2026-11-13
**Build source:** `a9dd914`
**Installed image:** `33223B2CC59DE177E74F107D7A95198FCD6993D6FC8E76E22E67198F1218A285`
**Decision:** the owner accepted the measured ETW loss envelope (option A,
2026-11-13). This is a **release-candidate closeout**, not a zero-loss claim and
not an E7/signed release.

---

## 1. The accepted envelope

Measured over **25.33 h** (2026-11-12 14:11:57 -> 2026-11-13 15:31:41):

| Counter | Measured | Per 24 h | Accepted budget |
|---|---:|---:|---:|
| `queue_dropped_total` (all `capture_etw/reg_change`) | 2,900 | ~2,747 | **3,500** |
| `shed_overload` (NameDelete policy shed) | 3,357 | ~3,180 | **4,000** |
| `minifilter_ring_dropped` | 0 | 0 | 0 |
| `minifilter_pipeline_dropped` | 0 | 0 | 0 |
| nose dropped / rejected / pipe errors | 0 | 0 | 0 |
| total rows pushed | 23,850,132 | ~22.6 M | — |
| accepted loss share | 0.0262 % | ~0.033 % at budget | — |

The budget is the owner's number; the measurement is `SOAK-25H`. A forward
24 h window run with `--loss-budget 3500 --shed-budget 4000` is the confirmation
form. The 25.33 h window evaluated at 0/0 remains **FAIL** and is kept as the
measurement that justified the budget.

## 2. Gates that closed

| Gate | State | Evidence |
|---|---|---|
| Deploy parity | PASS, E5 | installed == built `33223B2C…`; `deploy-window-006-result.json` |
| Boot path (R-06 / FREEZE #22) | PASS, E5 | boot 2026-11-12 14:11; drivers + daemon RUNNING; ring 0 |
| Crash-free soak (R-08) | PASS, E5 | 25.33 h, no SCM 7031/7034, all services RUNNING |
| #30 crash | CLOSED with the 25.33 h crash-free window | stale FIM helper attribution + fixed helper deployed |
| Boot-ring loss (448 / 4,012) | CLOSED, E5 | daemon-first boot + 1 s retry; ring 0 for 25.33 h |
| QLOSS / ETW loss | BOUNDED at the accepted envelope | 2,900 queue + 3,357 shed; 98.6 % reduction from 447,722 |
| Truth / digests | VALID | `truth.py verify`, 649 artifacts |
| Canonical suites | PASS | `zig build test` 2,087/10; `pytest` 1,114/4 |

## 3. Declared limitations (ship notes, not solved problems)

1. **Zero-loss is not met at 0/0.** The accepted envelope is 3,500 queue drops
   and 4,000 policy-shed rows per 24 h, all ETW admission; 0.033 % of pushed
   rows at the budget. The 25.33 h window itself is FAIL at 0/0.
2. **The daemon reports DEGRADED while any loss counter is nonzero.** The
   health/readiness path still uses `counter != 0`, not `counter > budget`, so
   a host inside the accepted envelope still shows `DEGRADED` and `readiness`
   exits nonzero. Budget-aware health is **not** in this candidate; it is the
   next design slice (read `AEGIS_LOSS_BUDGET`, compare `>`, expose it in
   health, align `host_soak_check`).
3. **Write coverage is reduced by design.** ETW file writes outside the
   rule-actionable paths are filtered at the source
   (`file_write_filtered = 6,273,495` in 25.3 h). R1001/R1003/R1004/R1005 keep
   the minifilter create/rename lane; a future rule needing arbitrary writes
   must revisit `QLOSS-ETW-WRITEFILTER-001`.
4. **Installer does not ship the boot model.** `AegisNids` is `DEMAND_START`
   on this host and the loader is an `admin-evidence` script; `tools/installer.py`
   still creates `AUTO_START` and never registers `AegisBootSequence`. A fresh
   install would reintroduce the boot gap.
5. **E7 signed release is unreachable.** No signing-key custody; drivers are
   test-signed. This candidate is E5, not E7.
6. **One lab host, 25.3 h.** No fleet or kernel qualification claim.

## 4. Completion statement

The detection-only backend is source-complete and test-green at E2; the current
candidate is deployed and has run 25.3 h without a crash or restart, with zero
ring/minifilter/nose loss. It loses a bounded, measured, attributable fraction
of ETW telemetry (0.026 % measured, 0.033 % at the accepted budget), and it
reports DEGRADED while those counters are nonzero. It is a release candidate
under a declared loss envelope, not a zero-loss or signed release.

Remaining to a production release: budget-aware health, installer boot model,
E7 signing custody, evidence debt (530 of 709 product files unnamed), fleet
qualification.

## 5. Percentage

~82 % of the project definition of done under this declared envelope; the
missing 18 % is the four items in §4 (health semantics, installer, E7, evidence
debt), not detection functionality.
