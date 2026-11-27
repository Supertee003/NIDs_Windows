# Owner-delegated current-source signature at build source `c01e809` — 2026-11-28

**RECORD-ID:** `RELEASE-SIGNATURE-C01E809-20261128`  
**BUILD SOURCE:** `c01e8091995e3afb9e93e48ea3bd1d7cb6ae5cce`  
**SIGNED RECORDS COMMIT:** `128c7f5` (short; full SHA recorded by git)  
**EVIDENCE LEVEL:** E2 for the release-record verification path only. Not E3/E4/E5/E6/E7; not a new release identity, not driver signing, not a soak PASS.

## 1. Authority and custody

The owner explicitly authorized the agent to complete the owner-only
`release_signature` work on 2026-11-28, while keeping soak as the final step.
No new key was generated. The existing owner-approved key was reused:

- private key (outside the tracked tree, never committed):
  `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519` (raw 32-byte seed)
- public trust anchor (only value recorded here):
  `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=`
- trust anchor supplied to the audit through `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY`

No private-key bytes appear in any tracked file, generated candidate, log or
this record. The published immutable identity `v1.1` / `466a226` / `a53eda8`
and its original signature were not changed.

## 2. What was built

A new, additional release candidate tree was assembled from the tree at records
commit `128c7f5`, which contains build source `c01e809`:

- tree: `release/T20-final/128c7f5`
- 270 files in the assembled tree; 206 tracked text/config files, with build
  outputs ignored by the repository rules exactly as in the `6c94b47` candidate
- `SHA256SUMS` contains 241 artifact hashes; `signatures.json` records
  `shipped_files=241`, matching the checksummed artifact count (not 241 separate
  signatures)
- `SHA256SUMS` digest signed: `EBE91BB403BFF2488E87A9F7A2E9D78AC566B612197DBE0DFF921196FCB32501`
- algorithm: Ed25519 raw 32-byte public key, detached signature over the
  `SHA256SUMS` bytes
- `signatures.json` carries the tool-owned fields (`signature`, `public_key`,
  `algorithm`, `signed_digest`, `signed_file`, `signed_at`) plus the existing
  `commit`, `policy`, `immutable` and `shipped_files` provenance fields

This is a forward signature record for the current source, not a rewrite of
history. The older `6c94b47` signature continues to verify its own historical
tree.

## 3. Commands and observed results

```text
python tools/release_candidate.py
  RC PASS: release/T20-final/128c7f5 (270 files, ee3f3bc87f8f4e59)

python tools/release_candidate.py --verify --dir release/T20-final/128c7f5
  RC VERIFY PASS

python tools/sign_release.py --sign --dir release/T20-final/128c7f5 \
    --key-file D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519
  signed SHA256SUMS -> signatures.json
  digest: EBE91BB403BFF2488E87A9F7A2E9D78AC566B612197DBE0DFF921196FCB32501
  public key: DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=

python tools/sign_release.py --verify --dir release/T20-final/128c7f5
  PASS: signatures.json signs SHA256SUMS (EBE91BB403BFF248...)

AEGIS_RELEASE_TRUSTED_PUBLIC_KEY=DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU= \
  python tools/final_audit.py --check
  PASS release_signature [owner] ... commit 128c7f5 contains runtime c01e809
  overall: NOT SHIPPABLE (1/6 gates open — soak_24h remains OPEN)
```

The signature covers the bytes of `SHA256SUMS`. Recomputing that digest is how
`final_audit.py` detects any later change to the shipped file list. The gate
independently requires the signed commit to be in HEAD's history, to contain the
current runtime commit, to verify cryptographically and to match the owner
anchor; all four conditions were observed PASS.

## 4. Gate consequence and boundaries

- `release_signature` is now **PASS** for build source `c01e809`.
- The board is **5/6 PASS, NOT SHIPPABLE**: `soak_24h` alone remains OPEN and is
  deliberately left as the final owner-armed step.
- No gate threshold, verdict rule, waiver, release identity or E-level was
  changed. A signature PASS does not close soak, does not create E7, and does
  not prove production driver/HLK/catalog/Authenticode signing.
- Full current-source Windows E5/kernel IDS qualification remains NOT_PROVEN.

## 5. Rollback / remaining risk / open blockers

- **Rollback:** remove `release/T20-final/128c7f5` and revert the records
  updates that reference it; the older `6c94b47` record then becomes the newest
  signature again and `release_signature` returns to OPEN because it predates
  `c01e809`.
- **Remaining risk:** the private key is held outside the tree and is the
  owner's custody responsibility; this record deliberately contains no key
  bytes. The candidate contains source snapshots and ignored build outputs;
  it is a signed record, not a claim that every shipped binary was rebuilt at
  this exact records commit.
- **Open blockers:** one clean serialized current-source 24 h SYSTEM soak;
  frozen #47/#50 kernel work; full current-source Windows E5/E7 and signed
  driver/HLK/catalog/Authenticode evidence.
- **Completion gate:** cryptographic release-record verification for this
  transaction only. Not a release, not E5/E6/E7, and not shippable until soak.

## 6. Patch transaction declaration

| Field | Value |
|---|---|
| PATCH-ID / FLOW-ID | `RELEASE-SIGNATURE-C01E809-20261128` / `source build -> candidate tree -> SHA256SUMS -> Ed25519 signature -> trust anchor check` |
| TARGET HEAD | `128c7f51eae33d0de8a9a52e1e68a8d228a93756` (records tip before this patch; build source `c01e809`) |
| FINAL HEAD | the records commit created by this patch (`git rev-parse HEAD` after commit); build source remains `c01e809` under ADR-0008 |
| FILES CHANGED | new signed tree `release/T20-final/128c7f5` (206 tracked text/config files plus ignored build outputs), this evidence record, `EVIDENCE_INDEX.json`, `release/release-status.json`, `AGENTS.md`, `AI_CONTEXT.md`, `docs/gates/RELEASE_TRUST_ANCHOR.md`, current-facing owner/path/source/status docs |
| OLD FLOW → NEW FLOW | newest signature `6c94b47` predates `c01e809` → `release_signature` OPEN → owner-delegated `128c7f5` tree contains `c01e809` and verifies with the owner anchor → PASS |
| INVARIANT | Build source, gate thresholds, verdicts, soak rule, published identity, authority and wire contracts unchanged; no private-key bytes in the tree |
| BUILD RESULT | No source rebuild; `release_candidate.py` RC PASS (270 assembled files) and RC verify PASS |
| TEST RESULT | `sign_release.py --verify` PASS; `final_audit.py --check` with owner anchor 5/6, `soak_24h` alone OPEN; `truth.py verify` TRUTH_VALID; `check_summary.py` SUMMARY_VALID; doc checker 0 FAIL/0 WARN/23 total; release/doc truth pytest 248 passed |
| WINDOWS RESULT | Not applicable: no service, driver, installed binary, host tool or soak window was touched |
| EVIDENCE LEVEL / ARTIFACTS | E2 only: this record, `release/T20-final/128c7f5/SHA256SUMS`, `release/T20-final/128c7f5/signatures.json`, `EVIDENCE_INDEX.json`, `release/release-status.json` |
| ROLLBACK / RISK / BLOCKERS / GATE | See §5; no E5/E6/E7, driver-signing or soak claim is made. |
