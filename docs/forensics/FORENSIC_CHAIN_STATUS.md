# Forensic chain status — event to evidence at current source

> Scope: build source `4dd3393` (HISTORICAL at current source `aa3b7b0`). AEGIS-PLAN-011.
> This page maps the vertical slice and states which stages are proven at which
> level. It does not re-run a host proof and does not promote historical E5
> records to current-source proof.

## 1. The chain

```
Event -> forensic record -> sequence -> hash -> CRC -> persistence
      -> read -> verify -> replay -> audit -> CLI -> evidence
```

| Stage | Current implementation | Evidence at `4dd3393` |
|---|---|---|
| Event | `CanonicalEvent` codecs in Zig/Go/C++/Python + shared `event_v*` vectors | E2 vector equality tests |
| Forensic record | `src/forensic/` record builders | E2 (unit/structure tests) |
| Sequence | embedded hash chain, FOR-001 | E2 at `4dd3393`; historical E3/E5 at older commits |
| Hash | canonical payload hash preserved (no u64→u32 truncation in the forensic record) | E2 contract tests |
| CRC | length-aware envelope CRC; `CRC mismatch rejected` tests | E2 (`tests/contracts/test_payload_envelope_v3.py`) |
| Persistence | append-only forensic store under operator-controlled path | E2 unit tests; no new host write in this records patch |
| Read / verify | `forensic verify` CLI path in `tools/aegisctl.py` | E2 CLI contract tests; historical E5 verification on installed daemon |
| Replay | replay integrity path in `src/forensic/replay_integrity.zig` | E2 unit tests; `mismatches = undefined` footgun explicitly removed |
| Audit | evidence index + release gates | E1 records; `final_audit.py --check` exit 0 at current HEAD |
| CLI | top-level parser has forensic verbs | E1 doc pin + E2 parser tests |

## 2. Invariants

- No wire change. One schema, N codecs; all six codecs plus the golden
  tuple-map move in the same patch when the wire changes.
- No test writes to tracked tree state (`analysis/*`, `logs/*.json`,
  `tests/contracts/**/*.bin` are producer-owned).
- Detector degradation counters are deliberately outside `data_loss_observed`.
- `674/674` means artifact hashes verified against **one** Ed25519 signature
  over `SHA256SUMS`; it is not 674 signatures.

## 3. Honest limits

- FOR-001 hash-chain E3/E5 records belong to older build sources and are
  HISTORICAL relative to `4dd3393`.
- No event-to-evidence host run was performed by this records patch.
- Full current-head Windows E5 / kernel qualification remains **NOT_PROVEN**.
- Owner-attested `admin-evidence/` files are ignored/local-only and are not
  reproducible from a fresh clone; `docs/evidence/PROVENANCE.md` records the
  unresolved pointers.

## 4. Owner actions

Run the forensic verification section of
`analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`, record the
installed binary SHA-256, and attach the raw transcript locator with its own
SHA-256.

---

See also: [`../evidence/PROVENANCE.md`](../evidence/PROVENANCE.md),
[`../portfolio/VERIFICATION_SUMMARY.md`](../portfolio/VERIFICATION_SUMMARY.md),
[`../../EVIDENCE_INDEX.json`](../../EVIDENCE_INDEX.json).
