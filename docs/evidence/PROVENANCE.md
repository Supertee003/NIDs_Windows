# Evidence provenance — what each artifact proves and where it lives

> Scope: build source `4dd3393` (HISTORICAL at current source `c01e809`), records HEAD moves with each patch.
> E3/E4/E5 records at `43a8bcc` are HISTORICAL at that source. E3 and narrow E4/E5 at
> `7822f4c` were current at that source and are now HISTORICAL relative to `4dd3393`
> (private-pipe and elevated canonical-pipe `-inject` exact deltas with verified host restore).
> S1/S2/S3/S4 added source-level producer, replay, identity and canonical-policy bytes at E2 only.
> Full Windows E5 / kernel qualification remains **NOT_PROVEN**.
> This is an index, not a copy of evidence.
> No artifact is synthesized, cleaned, relabelled or promoted by this document.

## 1. Artifact map

| Artifact | Owner / location | Proves | Does **not** prove |
|---|---|---|---|
| `EVIDENCE_INDEX.json` | tracked; `head_sha` = build source | Entries, levels E0–E7, status and artifact pointers | That every pointer resolves in a fresh clone |
| `build_manifest.json` | tracked; `source_commit` = build source | Build command → artifact mapping | A host run |
| `runtime_manifest.json` | tracked; build source + authority invariants | Canonical entrypoints and authority statements | Current-head full Windows E5 qualification |
| `AUTHORITY_MAP.json`, `FLOW_MAP.json`, `SYSTEM_MAP.json`, `CONTRACT_MAP.json` | tracked; `head_sha` = build source | Component/flow/authority/contract truth | Runtime behavior by itself |
| `release/T20-final/466a226/signatures.json` | tracked, immutable release identity | One Ed25519 signature over `SHA256SUMS`, pinned public key | 674 separate signatures; security validation of each artifact |
| `release/T20-final/466a226/SHA256SUMS` | tracked, signed | Digests of release files | That a fresh build reproduces them byte-for-byte |
| `analysis/current-head/MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E3-20261125.md` | tracked | E3 private-pipe `-inject` exact deltas at `43a8bcc` | Elevated canonical-pipe proof |
| `analysis/current-head/MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E4E5-20261125.md` | tracked | Owner-run elevated canonical-pipe `-inject` with verified lifecycle at `43a8bcc` | Full detection matrix, soak, loss rate, install, signing, E6/E7 |
| `D:/aegis-tmp/i44_e45_43a8bcc_*.txt` | **local-only operator files**, not in repo | Raw pre-state, inject transcript, lifecycle log | Reproducibility in a fresh clone; they are intentionally unmodified |
| `admin-evidence/` owner files | ignored, owner attestation | Clean-host E5 preflight and 36.52 h soak at release identity | Reproduction from repository content |

## 2. Level discipline

- Levels are E0 (none), E1 (static), E2 (unit), E3 (component), E4 (system),
  E5 (Windows host), E6 (production simulation), E7 (release verification).
- A higher level is never claimed from a lower-level test.
- E3 at `43a8bcc` used a private pipe (`aegis_nose_i44e`) in a non-elevated session.
- E4/E5 at `43a8bcc` used the canonical pipe (`aegis_nose`) under an elevated owner
  session. Its transcript begins with a PowerShell `NativeCommandError` wrapper
  around Zig stderr output; this is a stream artifact, not a harness failure
  (exit 0, all exact deltas passed). The raw text is kept unchanged.
- `a26c573` and `03bb86d` E3/E4/E5 entries are **HISTORICAL** and are not a
  substitute for current-source proof.

## 3. Current-source status (`aa3b7b0`)

| Claim | Status |
|---|---|
| TRUTH_VALID / SUMMARY_VALID at `aa3b7b0` | PASS (`python tools/truth.py verify`; `scripts/check_summary.py`) |
| Narrow loopback E6 pair at `aa3b7b0` | PASS; two attributable R9006 rows, verified elevated restore |
| S2 replay denial / S3 durable identity at `aa3b7b0` | PASS narrow E5; exact `REPLAY_DENIED`, generation `5→6`, zero duplicates |
| Fixed-rate 100 connections/s loopback load at `aa3b7b0` | PASS narrow E5; 6000/6000, zero loss-counter deltas |
| Deterministic 1,000-case fuzz + in-process benchmarks at `aa3b7b0` | PASS E2; coverage-guided campaign **NOT_RUN** |
| Additive signed record `release/T20-final/6c94b47` | PASS E2 release-record verification only; owner anchor `DCNPphsq…` |
| Full 23-rule matrix / soak / full Windows E5 / kernel IDS / E7 at `aa3b7b0` | **NOT_PROVEN**; `soak_24h` OPEN, board 5/6 — NOT SHIPPABLE |
| Published release identity | Immutable `v1.1` / `466a226` / `a53eda8`; 6/6 PASS at that identity only, HISTORICAL at `aa3b7b0` |

## 4. Rules for adding evidence

1. Every new product file needs an entry in `EVIDENCE_INDEX.json` (scope ratchet).
2. Evidence entries carry `head_sha` = build source, not merely the records commit.
3. `evidence_level_summary` is recomputed by `python scripts/check_summary.py --write`.
4. Unresolvable artifact pointers are labelled `historical` / `missing`, never hidden.
   `python tools/verify_evidence_locators.py` reports the split read-only:
   **52** unresolved primary pointers = **4** repo-resolvable (locator is a
   tracked worktree file), **18** archive-resolvable (locator exists under the
   operator archive on this host), **30** genuinely missing (no locator, or
   locator absent here). Archive-resolvable is not fresh-clone reproducible.
5. No local-only transcript is copied into the repo and presented as if it were
   reproducible; its location and limits are stated.
6. Release identity is immutable: no new tag, signature, key or `v2.1.0` follows from
   an evidence entry.

---

Single status source: [`release/release-status.json`](../../release/release-status.json).
Detailed results: [`docs/testing/RESULTS.md`](../testing/RESULTS.md).
