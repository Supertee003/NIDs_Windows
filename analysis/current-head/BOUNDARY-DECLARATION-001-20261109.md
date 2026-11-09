# BOUNDARY-DECLARATION-001 — rings, component standing, and the four floating components

- **Date:** 2026-11-09
- **Head (records):** `5c04071`
- **Source commit measured:** `5c04071dfcef1f37305762966d628ddfb6c4456a`
- **Evidence:** `COMPONENT-STANDING-001-E1-20261109`, `HARNESS-GATE-001-E2-20261109`, `TS-POLICY-001-E2-20261109`
- **Predecessor:** `COVERAGE-BOUNDARY-001-20261109` (survey that produced the numbers this file classifies)

This document answers one question: **for every path in the tree, what does a change to it owe?**
Before it, "no evidence" was an omission. After it, it is a declared decision, and a path with no
ring is undeclared by definition.

---

## 1. Rings (declared in `SYSTEM_MAP.json.boundary_rings`)

### Ring 1 — contract and runtime. A same-patch record is mandatory.

Ordered by blast radius, lowest layer first. A defect in any of these fails **silently**.

| # | Layer | Paths | Silent failure it can cause |
|---|---|---|---|
| 1 | Canonical contract + wire | `src/contract/`, `shared/` | ABI drift, cross-language misread, reserved-byte regression |
| 2 | Ingest / acquisition boundary | `src/capture/`, `nose/`, `bridge/` | Event loss, double attribution, wire-v2/v3 mismatch |
| 3 | Pipeline + control plane | `src/pipeline/`, `src/control/`, `src/main.zig`, `src/daemon.zig` | Dropped queue items, control command accepted but not applied |
| 4 | Detection + correlation | `src/detection/`, `src/xdr/` | Missed detection, fabricated advisory |
| 5 | Policy + PEP + trust | `src/policy/`, `rust-src/` | **Policy/PEP bypass**, unauthorized enforcement |
| 6 | Forensic record + replay | `src/forensic/` | Hash/CRC chain break, unreplayable evidence |
| 7 | Windows native adapters + drivers | `src/windows/`, `drivers/` | Missing ETW/FIM/registry evidence, kernel contract mismatch |
| 8 | Platform lifecycle | `src/platform/` | Service installed but never starts, pipe never accepts |

### Ring 2 — support. A record is owed when behavior changes.

`brain/`, `ts_policy/`, `shield/`, `go/aggregator/`, `tools/`, `src/tests/`, `tests/`, `mouth/`, `aegis_dashboard/`

Failure here degrades analytics or an operator surface. None of these may become an enforcement authority; that boundary is `AUTHORITY_MAP`, not this ring.

### Ring 3 — out of contract. No record owed; registration still owed.

`scripts/`, `analysis/`, `admin-evidence/`, `docs/`, `configs/`

A new file here still has to enter a build root or `QUARANTINED_UNREACHABLE` in
`tests/security/test_zig_test_scope.py`. "Out of contract" is not "unaccounted".

---

## 2. Component standing (measured at `5c04071`)

| Component | Ring | Measured now | Result | Record |
|---|---|---|---|---|
| `zig_core` | 1 | `zig build test` | 8/8 steps; unit green + **1233** harness tests | `HARNESS-GATE-001` |
| `rust_pep` | 1 | not re-measured this patch | — | historical |
| `go_nose` | 1 | not re-measured this patch | — | historical (`WIRE-V3-ROLLOUT-001` E5) |
| `cpp_native`, `cpp_bridge` | 1 | not re-measured this patch | — | historical |
| `ts_policy` | 2 | `npm run typecheck` + `npm run test:all` | exit 0; **76/76** pass | `TS-POLICY-001-E2` |
| `mouth` | 2 | `cargo build --release` | exit 0 (std-only) | `COMPONENT-STANDING-001` |
| `dashboard` | 2 | `cargo build --release` | exit 0 | `COMPONENT-STANDING-001` |
| `brain`, `shield`, `aggregator` | 2 | not re-measured this patch | — | historical |

"Not re-measured this patch" is stated rather than inherited: a 2026-09-11 record is not a
2026-11-09 result.

### The four components that were floating

| Was asked | Resolution |
|---|---|
| `mouth/` — keep or retire? | **Kept and declared.** A `mouth` component now exists in `SYSTEM_MAP` with its real build command; `cargo build --release` exits 0 at this HEAD, std-only, no PEP linkage. It stays OPTIONAL in classification, Ring 2 for evidence. |
| `aegis_dashboard/` — still shipped? | **Still builds.** `cargo build --release` exit 0 at this HEAD. `src/main.rs.bak` (a stale duplicate) was deleted. |
| `ts_policy/` — CANONICAL but advisory? | **Stays CANONICAL and now has a dated E2.** 76 tests were always there; nothing recorded them. The classification is about authoring authority, not enforcement. |
| `src/platform/` — 444 LOC, no record? | **Never was unused.** `win32_service.zig` is imported by `src/main.zig` and `src/daemon.zig`; `win32_pipe.zig` has a direct unit edge from `src/all_tests.zig`. Declared Ring 1 step 8. |

---

## 3. What changed in this patch (ordered)

1. **Harnesses gained a run edge** — `src/out_of_unit_tests.zig` + `zig build test-out-of-unit`, and `test` depends on it.
   Wiring it revealed the rot immediately: `golden_path_e3.zig` had **7 compile errors**, `policy_plane_proof.zig`
   asserted a signature contract the compiler deliberately retired. Both repaired; 1233/1233 pass.
2. **Scope pin told the truth again** — 39 files left `QUARANTINED_UNREACHABLE`, `flow_types.zig` left with them,
   the new runner registered as a build root.
3. **Junk removed (nothing referenced it)** — `fix_bridge_banner.py`, `fix_encoding.py`, `fix_head.py`,
   `test_needs.py`, `tests/tests/contracts/*` (duplicate fixtures; the real ones live in `tests/contracts/`),
   `aegis_dashboard/src/main.rs.bak`, `zig-out/bin/aegis_nids.old`.
4. **Boundary declared** — `SYSTEM_MAP.json.boundary_rings`, per-component `boundary_ring` + `standing`.
5. **Records** — three new evidence entries; `E1 36 / E2 181` per `scripts/check_summary.py` (`SUMMARY_VALID`).

---

## 4. Boundaries of this document

- **E1/E2 only.** No host-level claim is made here. `AegisWfp` / `AegisMinifilter` stay
  `Stopped (Manual)` and have no host E5 in this build — that is a known gap, not a ring decision.
- The never-named set from the predecessor survey is **not** closed by this patch. Declaring the ring says
  what those files owe; it does not produce the missing records. `src/detection` (13/15 files never named),
  `src/windows` (17/23), `src/core` (17/22), `src/forensic` (13/21), `src/policy` (11/18) remain open.
- Ring assignment is a judgement about failure mode. If a path moves between rings, the record that
  justifies the move belongs in the same patch.
