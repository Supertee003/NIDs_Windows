# Rust Foundation Status — current HEAD (2026-11-19)

> Records-only clarification. Build source remains `f4cde3c503fd8b696183751a608b999768caa769`
> (ADR-0008). No source, build, signature, or runtime change is made here.
> This document exists because several older docs still describe Rust as the
> WFP/host-effect enforcement authority, which contradicts the current maps.

## 1. Verdict — Rust did not disappear

Rust source, crate, DLL, FFI wiring and golden-path status all still exist.

| Question | Verdict |
|---|---|
| Rust source removed from disk? | **No.** Only a *duplicate* PEP in `shield/` was retired (`5cbca99`, PEP-001). The canonical `rust-src/lib.rs` was never deleted. |
| Rust built and linked? | **Yes.** `Cargo.toml` → `rust-src/lib.rs` → `target/release/aegis_pep.dll`, linked by `build.zig` into `aegis_nids.exe`. |
| Rust on the canonical detection path? | **Yes.** `FLOW_MAP.json` step 9 (conditional PEP guard); `runtime_manifest.json` marks `rust_pep_tier3` CANONICAL / `golden_path: true`. |
| Rust still the final *enforcement* authority? | **No — by design.** It is a **detection-only policy/evidence authority**. No component in this product authorizes a host effect. |
| Was authority transferred to Zig? | **No.** Authority was *retired outright*, not moved. Zig still may not own privileged enforcement or crypto (`AGENTS.md`, `AUTHORITY_MAP.json`). |

The "foundation disappeared" impression is **documentation drift**, not a
runtime loss. Current truth: `AUTHORITY_MAP.json` (`is_final_enforcement:
false`), `CONTRACT_MAP.json` (PEP ABI frozen, detection-only invariant),
`runtime_manifest.json` (invariant: retired by `RETIRE-HOST-EFFECT-001`).
Historical enforcement wording in older ADRs/architecture docs is marked
HISTORICAL; it is not current authority.

## 2. What happened, in dates and commits

| Date / commit | Event |
|---|---|
| `5cbca99` (2026-10-17) | PEP-001: **duplicate** `shield/src/pep.rs` stripped to advisory `screen.rs`; `shield/src/windows_enforce.rs` deleted. One PEP remains. |
| `4fa1e36` (2026-11-01) | `aegis_pep_assess` added — an evidence-only, non-mutating FFI seam. Rust capability was *added*, not removed. |
| `8c935ff` (2026-11-09) | **RETIRE-HOST-EFFECT-001 / issue #25:** product scoped to detection-only. `aegis_pep_enforce` now returns `DECISION_ESCALATE`, `reason = 8`, `filter_id = 0` for block/quarantine; `block_flow` adapter call removed but symbols retained for ABI stability. Driver block IOCTL hard-fails `STATUS_NOT_SUPPORTED`. 30 files changed; **no Rust file deleted**. |
| `159cfde` (2026-11-09) | Truth maps restamped to the detection-only authority. |
| `669c4b9` (2026-11-14) | `mouth/` and `aegis_dashboard/` crate tests gated in CI (not on golden path). |
| `aade7a3` (2026-11-17) | G2 enforcement lab retired at E5 — "CLOSED — superseded by scope retirement", not "all 7 steps passed". |

Reason, in the words of the record: detection-only IDS; host effects out of
product scope. Not a failure, not a build break, not a security incident.

## 3. Crate inventory at current HEAD

| Path | Crate / role | Classification | Golden detection path? |
|---|---|---|---|
| `Cargo.toml`, `Cargo.lock` | root `aegis_pep` 5.0.0; deps `ring`, `rustls 0.23`, `x509-parser`, `serde`, `parking_lot`, `windows 0.58`; bin `aegis-keygen` | CANONICAL | build root of the PEP DLL |
| `rust-src/lib.rs` | PEP FFI: Ed25519 policy/payload verification, TLS/federation, trust/quota/two-person logic, `aegis_pep_enforce`, `aegis_pep_assess`, keygen sibling | **CANONICAL** | **Yes — step 9** |
| `target/release/aegis_pep.dll` | built artifact (untracked), linked by `build.zig` | build artifact | Yes at link/install |
| `shield/` (`aegis-shield`, `sec_monitor.dll`) | one export `aegis_shield_screen`; advisory payload screening via `src/policy/shield_screen.zig` | SUPPORT | No — advisory, fail-safe absent |
| `rust-src/bin/aegis_keygen.rs` | offline operator key ceremony | CANONICAL source | tooling, not detection |
| `mouth/` | std-only optional DEFCON GUI; explicitly must not link `rust-src` or PEP | OPTIONAL | No |
| `aegis_dashboard/` | egui native dashboard backend | OPTIONAL | No |

## 4. Authority boundary (current)

Rust **owns**: crypto and trust (Ed25519 policy/payload signatures, TLS/federation),
detection-only PEP evaluation (`aegis_pep_enforce`, `aegis_pep_assess`),
authorization *evidence* (decision / reason / `filter_id`), offline key ceremony.

Rust **does not own**: host effects, WFP mutation, filter installation,
block/unblock execution, detection logic, policy decisions.

Retired wording that is now HISTORICAL (do not use as current truth):
`AGENTS.md` Rust row (fixed in this records patch), `SYSTEM_MAP.json`
`is_final_enforcement` (fixed to `false`), `docs/architecture/LANGUAGE_OWNERSHIP.md`
"Zig decides, Rust executes" (fixed), `docs/adr/0002`, `docs/adr/0009`,
`docs/architecture/ARCHITECTURE-TRUTH.md`, `docs/architecture/STEP-38-GOLDEN-PATH.md`.

## 5. Evidence

- E2 — `analysis/current-head/RETIRE-HOST-EFFECT-001-20261109.md` (old → new flow, invariants, `cargo build`/`cargo test` results).
- E5 — `analysis/current-head/G2-ENFORCEMENT-RETIRED-20261117.md` (direct FFI probes: `reason=8`, `filter_id=0`; lab retired).
- E1 — this document; `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `runtime_manifest.json` at build source `f4cde3c`.

## 6. Do not reintroduce host effects silently

Re-enabling a host effect is a **new product scope**: new ADR, new authority
decision, new E-evidence, new soak. It is not a reopening of G2. Any patch that
restores `block_flow`/`with_adapter` in `aegis_pep_enforce`, re-adds a second
PEP export, or flips `is_final_enforcement` to `true` must fail review.
