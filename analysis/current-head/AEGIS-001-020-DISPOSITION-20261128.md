# Disposition of the owner's AEGIS-001…020 portfolio plan (2026-11-28)

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged — records-only)  
**RECORDS TIP WHEN WRITTEN:** `adf05fb4817bbf8aed3c9e8d2dbf62d3c16a39de`  
**PURPOSE:** the owner supplied a 20-item portfolio/audit plan and asked which parts were already done. This page is the durable answer so both sides remember. It is a **records map, not new proof**: it changes no gate, evidence level, verdict, authority or source file.

## 1. Honest one-line answer

**Much of the plan was already implemented before this message.** The remaining gaps are mostly *source slices* (fields, codecs, kernel lifecycle, full host proof), not missing documents. What was genuinely missing or ambiguous — canonical scope lock, current-board gate detail, threat model, detection-coverage status vocabulary, protocol pointer pages — is added in this patch.

## 2. Item-by-item disposition

| ID | Item | Disposition | Where / boundary |
|---|---|---|---|
| AEGIS-001 | Release Status | **DONE + hardened this patch** | `release/release-status.json` is already the single source. This patch adds `scope_lock`, `current_build_source_status=qualification_in_progress`, and six named current-board gates with criteria, evidence, status, reason, checked date and commit. Published `v1.1` board remains HISTORICAL; current board stays 5/6 with `soak_24h` OPEN. |
| AEGIS-002 | Scope Consistency | **DONE + locked this patch** | New canonical `docs/SCOPE.md`: AEGIS Kernel NIDS, detection-only/observe-only, explicit exclusions. Linked from `README.md`, status JSON, verification summary, demo, operations and release gates. Pre-existing `AUTHORITY_MAP.json` already carries `host_effect_capable=false`. |
| AEGIS-003 | Runtime Health | **PARTIAL** | `docs/runtime/HEALTH_MODEL.md` maps requested vocabulary to real fields and records that `reason` is worker-scoped only, and `last_transition`, `impact`, `recovery_state`, `UNKNOWN` are **not implemented**. Adding them is a source slice with fresh E3/E4/E5 — not a docs edit. |
| AEGIS-004 | Codec Validation | **PARTIAL (documented, not re-run now)** | `docs/protocol/INDEX.md` records exact-length and reject tests in Zig/Go/C++; shared `event_v*` vectors exist. A fresh source audit of decoder trailing-byte/silent-loss behavior was **not** performed in this records patch. |
| AEGIS-005 | Wire Protocol | **DONE at documentation level** | `docs/protocol/INDEX.md` answers header size, length prefix, version location, required/optional fields, endianness, max size, unknown version and invalid-frame rejection from current codecs. Authoritative text is `shared/protocol/wire_v*.md` + shared golden vectors. Pointer pages now exist at the requested paths. |
| AEGIS-006 | Evidence Provenance | **DONE** | `EVIDENCE_INDEX.json`, `analysis/current-head/raw-*/*/verbatim-manifest.json`, `build_truth.json`, release digests. No provenance claim was added without a tracked artifact. |
| AEGIS-007 | Queue Semantics | **DONE at documentation level** | `docs/runtime/QUEUE_SEMANTICS.md` exists; bounded queue with observable shedding, **not** producer backpressure. Drop counters are in `HEALTH_MODEL.md`. |
| AEGIS-008 | Sensor Coverage | **PARTIAL** | `docs/portfolio/SENSOR_COVERAGE.md` exists. VLAN/IPv6/truncation host visibility is still `NOT_PROVEN`; source-level E2 only. No host claim added. |
| AEGIS-009 | Kernel Lifecycle | **PARTIAL** | `docs/runtime/KERNEL_LIFECYCLE.md` exists; load/unload/cleanup tests at current source are not proven. Earlier WFP/minifilter suspicions remain in the frozen source decision set (#47/#50). |
| AEGIS-010 | Detection Coverage | **PARTIAL + canonical index added** | `docs/portfolio/DETECTION_MATRIX_CURRENT.md` carries all 23 rows with data sources, tests and live-proof columns; `docs/portfolio/DETECTION_CATALOG.md` is the rule catalog. New `docs/detection/DETECTION_COVERAGE.md` defines the six status words without inventing a row. R2003 stays narrow-E5, full matrix not re-measured. Pinned strings `\| Host-evaluable \| 22/23 \|` etc. are untouched. |
| AEGIS-011 | Forensic Chain | **DONE at documented level** | Hash-chain verification, evidence receipts and the event→evidence flow are recorded in `docs/forensics/`, `EVIDENCE_INDEX.json` and current-head closeout. Not a new E5/E6 claim. |
| AEGIS-012 | Performance Report | **DONE with boundaries** | `docs/portfolio/PERFORMANCE_REPORT.md` and `OBSERVED_PERFORMANCE.md` state source, duration and counters. The `12M+`/`7M+` figures are historical observations with their own commits; no fresh measurement here. |
| AEGIS-013 | Verification Summary | **DONE** | `docs/portfolio/VERIFICATION_SUMMARY.md` is the 3–5 minute table with result/evidence/commit and an explicit "what the numbers do not prove" section. |
| AEGIS-014 | README Refactor | **PARTIAL / mostly done** | README already opens with identity, scope table, limitations near the top, proof and links. Long build/command sections remain further down; trimming them is a low-risk follow-up but not required for correctness. |
| AEGIS-015 | Documentation Cleanup | **PARTIAL — deliberately no physical moves** | Root handoff files are referenced by `inventory.json`, `reference_map.json`, `tests/docs/test_doc_truth_labels.py` and a historical boundary record. Moving them would break machine-map truth or rewrite a historical record. New `docs/history/INDEX.md` marks them historical and non-canonical instead. |
| AEGIS-016 | Threat Model | **NEW DONE this patch** | `docs/security/THREAT_MODEL.md` adds assets, actors, surfaces, trust boundaries, scenarios, controls and residual risks, including that an OS-level administrator is above this product's trust boundary. |
| AEGIS-017 | Fuzz & Fault Tests | **PARTIAL** | Deterministic E2 smoke 1,000 cases at `aa3b7b0`; coverage-guided fuzz remains `NOT_RUN`. No level promoted. |
| AEGIS-018 | CI Quality Gates | **DONE** | `docs/CI_QUALITY_GATES.md`; both workflows green at the current records tip. |
| AEGIS-019 | Windows Compatibility | **PARTIAL** | `docs/platform/` records the tested family (64-bit Windows 10/11 lab configurations); no fresh per-version matrix. |
| AEGIS-020 | Portfolio Case Study | **DONE** | `docs/portfolio/CASE_STUDY.md`, `ARCHITECTURE_EN.md`, `RESUME_PROJECT.md`, `DEMO.md`. |

## 3. What this patch actually changed

1. `docs/SCOPE.md` — canonical scope lock.
2. `release/release-status.json` — `scope_lock`, `current_build_source_status`, six current-board gate records with criteria/evidence/status/reason/date/commit.
3. `README.md` — scope-lock pointer; published-vs-current status disambiguation; four non-credit soak attempts.
4. `docs/security/THREAT_MODEL.md`, `docs/detection/DETECTION_COVERAGE.md`, `docs/protocol/{CANONICAL_EVENT,WIRE_FORMAT,GOLDEN_VECTORS}.md`, `docs/history/INDEX.md` — the missing or non-canonical surfaces, written as pointers/maps rather than duplicate specifications.
5. This disposition page and its `EVIDENCE_INDEX.json` entry.

### Verification performed for this records patch

| Command | Result |
|---|---|
| `python scripts/doc_checker.py` | 0 FAIL / 0 WARN / 23 total |
| `python scripts/check_summary.py` | SUMMARY_VALID after recomputing the E1 counter from 51 to 52 for the new record |
| `python tools/truth.py verify` | TRUTH_VALID @ `aa3b7b0` |
| `python -m pytest tests/docs -q` | 53 passed |
| `python tools/release_engineering.py --verify` | OK — 691 artifacts match digests (`source_commit=aa3b7b0`) |
| `python tools/sign_release.py --verify --dir analysis/current-head/owner-key-attestation-aa3b7b0-20261128` | PASS over `A810F023E1871427...`; public key `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=` |
| `python tools/final_audit.py --check` with `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY` set to the approved owner public key | NOT SHIPPABLE (1/6 open): only `soak_24h` OPEN. Without that env anchor the tool reports `release_signature` OPEN too (2/6) — this is the tool's designed input, not a gate change. Any T20 file drift from this command was reverted before commit. |

## 4. What was deliberately NOT done

- No source file, gate, guard, threshold, test skip/xfail or verdict changed.
- No host/service/driver/finalizer/soak action; no new soak window armed.
- No new release identity, signature, E7, signed-driver or Authenticode/catalog claim. The owner-key attestation from the previous patch remains an integrity record only.
- No physical move of root handoff files (machine-map and historical-pointer integrity).
- No claim that a documentation status closes a source-level gap. Items marked PARTIAL remain PARTIAL.

## 5. Owner-facing follow-on decisions

- **A fresh serialized soak window** remains the only blocker for `soak_24h`; the agent does not arm it without the owner's explicit go-ahead and a host-free 24 h commitment.
- **Source slices** for AEGIS-003/004/008/009 need a separate `SOURCE_PATHS` patch transaction and fresh verification, not a docs edit.
- **GitHub Connector (owner section 9)** is an owner-side access decision; the repository already exposes the source, tests, evidence index, workflows and issues publicly. No file copying is needed for an agent-side audit in this worktree.
