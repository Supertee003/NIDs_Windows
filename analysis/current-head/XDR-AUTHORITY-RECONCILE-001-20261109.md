# PATCH-XDR-AUTHORITY-RECONCILE-001 — Close the IDS-XDR-005 records contradiction and re-verify the advisory boundary

PATCH-ID: XDR-AUTHORITY-RECONCILE-001
FLOW-ID: IDS-XDR-005 / XDR-PROD-001 (advisory-only XDR evidence, recording-only receipt/replay)
TARGET HEAD: `6182516` (build source `bb5d780`)
FINAL SOURCE HEAD: `bb5d780dd60d85dedf0444532afedb72e84ebee1` (records-only slice; no product source changed)
TARGET FILES: `AUTHORITY_MAP.json`, `SYSTEM_MAP.json`, `tools/create_manifest.py`
TARGET SYMBOLS: map prose for `src/xdr/xdr_incident_fabric.zig`; manifest generator
`ROLE_OVERRIDES`/`AUTHORITY_CLAIMS`/`BOUNDARIES` entries for the XDR lab route

## Scope and contract

- IN-SCOPE: Remove the remaining stale "Windows E5 open" wording that contradicted
  this repository's own recorded E5 evidence, re-verify the advisory-only XDR
  boundary and runtime-manifest reachability at current HEAD, and record the
  result.
- OUT-OF-SCOPE: Any XDR behavior change, any new wiring, any change to the
  forensic ring, receipt contract, control protocol, policy/PEP/DEFCON path, or
  deployment. No E5/E7 claim is made for current HEAD.
- CONTRACT IMPACT: None.
- ABI IMPACT: None.
- AUTHORITY IMPACT: None. XDR remains advisory evidence only; the change makes
  the map prose agree with the already-recorded authority outcome.
- STATE IMPACT: None.
- TEST IMPACT: No test modified; the affected XDR/authority pins were re-run and
  pass unchanged.
- EVIDENCE IMPACT: E2 entry `XDR-AUTHORITY-RECONCILE-001-E2-20261109`; GitHub
  issue #26 closure.

## What was actually inconsistent

`AUTHORITY_MAP.json` recorded two mutually incompatible statements about the
same route:

- the Zig authority note said "Source integration is E2-proven
  (XDR-RECEIPT-002); Windows E5 host proof remains open", and
- the same file's `XDR_NON_AUTHORITATIVE_CANDIDATES` completion gate said
  "CLOSED 2026-11-05: source integration is E2-proven and Windows E5 host
  evidence is recorded (XDR-005-E5-20261105)".

`SYSTEM_MAP.json` and the manifest generator carried the same one-sided
"Windows E5 open" phrasing. The truthful reading is narrower than either
sentence: a bounded host proof of the recording-only route **was** recorded on
the deployed `fc108b0` build on 2026-11-05, and **no** current-head E5 has been
run since. All three artifacts now say exactly that.

Everything else issue #26 required was already satisfied and pinned:

1. The XDR fabric is not on the production runtime order; it is `LAB` /
   `golden_path: false` in `runtime_manifest.json`, and the audit test asserts
   no XDR module appears in the manifest's runtime order.
2. One authority is selected: `src/xdr/xdr_incident_fabric.zig`,
   advisory-only; `xdr_engine`, `xdr_harden`, `xdr_correlator`,
   `xdr_incident_graph` are recorded as NOT_SELECTED / TEST-SUPPORT ONLY.
3. No PEP-dispatch claim exists: `dispatched_to_pep` and `isEnforcement` are
   absent from the fabric, `Decision` has no action field, and tests assert the
   fabric exposes no `rate_limit`/`quarantine`/`block` action and that the
   `xdr.list` JSON carries no action/enforce key.
4. Receipt terminology requires a real receipt: `replayFromReceipt` refuses a
   receipt that is not `isNonEnforcement()`, a wrong detector id/version, and
   sequence 0, and replay re-checks the record hash, event id, incident id and
   payload hash; a tampered receipt fails with `error.ReceiptHashMismatch`.
5. `runtime_manifest.json`, `FLOW_MAP.json` (`XDR-LAB-001`, `XDR-PROD-001`) and
   the truth artifacts already describe the advisory/recording-only boundary.

## Verification performed

- `zig build`: PASS (prior run on this source tree).
- Focused XDR/authority tests, current HEAD:
  `python -m pytest tests/ips/test_t18_ips_canary_xdr.py
  tests/security/test_xdr_wire_advisory.py
  tests/security/test_map006_runtime_truth.py
  tests/e2e/test_t14_windows_golden_path.py tests/tools/test_stix_export.py -q`
  → **71 passed**.
- `python tools/rebuild_truth.py`: generated manifest + stamped maps valid.
- `python tools/truth.py verify`: TRUTH_VALID at build source `bb5d780`,
  worktree clean.
- `python scripts/check_summary.py`: SUMMARY_VALID.

## Patch result

- OLD FLOW: map prose said both "Windows E5 open" and "E5 recorded 2026-11-05"
  for the same route, and the manifest generator repeated the one-sided phrase.
- NEW FLOW: all three artifacts state the recorded host proof and the open
  current-head proof separately and identically.
- INVARIANT: no XDR module gained a decision, policy, PEP, DEFCON or host-effect
  surface; no manifest reachability claim changed from LAB/`golden_path: false`.

- BUILD RESULT: PASS (unchanged source).
- TEST RESULT: 71 focused tests passed.
- WINDOWS RESULT: Not applicable to this slice. The installed daemon remains
  source `318a10a`; no host run is claimed. Host evidence available is the
  historical `XDR-005-E5-20261105` on deployed `fc108b0`.
- EVIDENCE LEVEL: E2 for this reconciliation; the referenced host proof is the
  separate E5 entry `XDR-005-E5-20261105`.
- EVIDENCE ARTIFACTS: this report;
  `EVIDENCE_INDEX.json#XDR-AUTHORITY-RECONCILE-001-E2-20261109`.
- ROLLBACK: revert the records commit; the stale wording returns.
- REMAINING RISK: current-head Windows E5 for the recording-only route is still
  NOT_PROVEN; closing #26 does not change that.
- OPEN BLOCKERS: none for #26. #25/#28/#29/#30 and E7 signing stay exactly as
  they were.
- COMPLETION GATE: PASS for issue #26 (authority selection, evidence-only
  behavior, manifest reachability, tests, truth rebaseline).
