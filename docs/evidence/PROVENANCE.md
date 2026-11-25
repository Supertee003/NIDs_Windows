# Evidence provenance — what each artifact proves and where it lives

> Scope: current build source `7822f4c`, records HEAD moves with each patch.
> E3/E4/E5 records at `43a8bcc` are HISTORICAL at that source; E3/E4/E5 at `7822f4c` are
> **NOT_PROVEN** until owner-run elevated re-proof. This is an index, not a copy of evidence.
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

## 3. Current-source status

| Claim | Status |
|---|---|
| TRUTH_VALID at `43a8bcc` | PASS (`python tools/truth.py verify`) |
| E3 exact-delta proof at `43a8bcc` | PASS, narrow pipe scope |
| E4/E5 canonical-pipe proof at `43a8bcc` | PASS, narrow scope; owner-run elevated |
| Detection-rule matrix / soak / loss rate at `43a8bcc` | NOT CLAIMED |
| Full current-head Windows E5 / kernel IDS qualification | NOT_PROVEN |
| Release identity | Immutable `v1.1` / `466a226` / `a53eda8`; 6/6 gates PASS at that identity |

## 4. Rules for adding evidence

1. Every new product file needs an entry in `EVIDENCE_INDEX.json` (scope ratchet).
2. Evidence entries carry `head_sha` = build source, not merely the records commit.
3. `evidence_level_summary` is recomputed by `python scripts/check_summary.py --write`.
4. Unresolvable artifact pointers are labelled `historical` / `missing`, never hidden.
5. No local-only transcript is copied into the repo and presented as if it were
   reproducible; its location and limits are stated.
6. Release identity is immutable: no new tag, signature, key or `v2.1.0` follows from
   an evidence entry.

---

Single status source: [`release/release-status.json`](../../release/release-status.json).
Detailed results: [`docs/testing/RESULTS.md`](../testing/RESULTS.md).
