# PATCH-INGRESS-KIND-ATTRIBUTION-001 — Attribute queue admission loss by source and event kind

PATCH-ID: INGRESS-KIND-ATTRIBUTION-001
FLOW-ID: QLOSS-HEALTH-001 (ETW/FIM/host ingress -> bounded queue admission -> queue.stats)
TARGET HEAD: `fadfdbe71e7ca554743c5d7abc8fa055cc395d36` (build source `795246d`)
FINAL SOURCE HEAD: `2e715dfdd38a101454def530de55ae00d4b8a28a`
TARGET FILES: `src/pipeline/event_queue.zig`, `src/control/handler_registry.zig`
TARGET SYMBOLS: `g_ingress_kind_pushed`, `g_ingress_kind_dropped`,
`SOURCE_KIND_BUCKET_COUNT`, `sourceKindIndex`, `pushEventFull`, `eventKindName`,
`handlers.queueStats`

## Scope and contract

- IN-SCOPE: Count admitted and refused queue submissions in a bounded
  `(source ordinal, contract EventKind ordinal)` table, and emit the nonzero
  lanes as an additive `by_source_kind` array in `queue.stats`.
- OUT-OF-SCOPE: Any admission, shedding, or fairness decision; any change to
  queue size, caps, reservation, or drop ordering; FIM coalescing/suppression;
  driver, WFP, PEP, policy, detection, or forensic behavior; deployment.
- CONTRACT IMPACT: `queue.stats` gains one additive JSON key,
  `by_source_kind`, between `by_source` and `pipeline`. Existing keys and
  ordering are unchanged, so key-based consumers are unaffected.
- ABI IMPACT: None. No serialized event, wire frame, or exported symbol change.
  The two counter arrays are process-local statics.
- AUTHORITY IMPACT: None. Zig admission and detection authority are unchanged;
  the counters are observational and are never read by an admission decision.
- STATE IMPACT: +1 MiB of zero-initialized process static memory
  (2 x 65,536 x 8 B atomic counters). No persistent state, no file, no IPC
  payload growth beyond the response that only emits nonzero lanes.
- TEST IMPACT: The existing GAP-015 ingress-accounting test now asserts the
  kind lane for both the push and the refusal path; the `queue.stats` shape
  test asserts the new key. Full suite re-run.
- EVIDENCE IMPACT: E2 entry `INGRESS-KIND-ATTRIBUTION-001-E2-20261109`;
  this report; #29 stays OPEN.

## Flow contract

- OLD FLOW: `queue.stats.by_source` showed that a source shed rows but not
  **which class of event** was refused. FIM (file create/write/delete/rename)
  and ETW (process start, file write, registry set) each collapse into one
  source bucket, so a burst could not be attributed to a specific producer lane
  without out-of-band guessing.
- NEW FLOW: every `pushEventFull` outcome increments
  `g_ingress_kind_pushed[source*256+kind]` on success, or
  `g_ingress_kind_dropped[...]` on the IPv6-pair, queue-full, reserved-tail,
  and per-source-quota refusal paths. `queueStats` walks the bounded table,
  labels ordinals with the contract's own names
  (`legacySourceName` for the source space actually stored in `IpcEvent.source`,
  `eventKindName` for the event-kind enum) and emits only nonzero lanes.
- INVARIANT: a kind-lane counter changes if and only if the corresponding
  `pushEventFull` outcome changed, and no counter is ever consulted before an
  admission decision. Suppression remains impossible: this patch adds
  observability only.

Naming note (measured, not assumed): two source-numbering spaces exist in this
repository (contract `EventSource` and canonical `EventSource`). The table is
indexed by `@intFromEnum(ev.source)` where `ev` is the contract `IpcEvent`, and
the label is produced by `event_contract.legacySourceName`, which maps exactly
that contract space. A canonical-space name would have mislabeled every row;
the regression test pins ordinal 77 -> `unknown_77` to keep unknown lanes
visible instead of silently renamed.

## Verification performed

- `zig build`: PASS (ReleaseSafe x86_64-windows).
- `zig build test --summary all` with a **fresh cache directory**
  (`.zig-cache-scan`, removed afterwards so the tree stayed clean):
  `5/5 steps succeeded; 2062/2072 tests passed; 10 skipped`, exit 0.
  The 10 skips are the pre-existing opt-in host/hardware cases.
- Test-level pins added by this patch:
  - `GAP-015 ingress accounting counts pushes and drops by source` now also
    checks `kp0 + 2` on two admitted pushes and `kd0 + refused` on the
    calibrated refusal path.
  - `queueStats emits parseable JSON with shed and etw keys (GAP-015)` now
    asserts the response contains `by_source_kind`.
- `git diff --check`: PASS.
- Consumer audit (read-only): `tools/aegisctl.py` and
  `tools/aegisctl/web_dashboard/app.py` read `queue.stats` by key
  (`response.get("by_source", ...)`, `q.get("wfp")`, ...), so an additive key
  cannot break them; `tests/tools/test_aegisctl_queue.py` and
  `tests/tools/test_web_dashboard.py` fixtures do not assert key absence.

## Patch result

- OLD FLOW -> NEW FLOW: per-source loss only -> per-source **and per-kind**
  loss, with the refusal path distinguished from the admitted path.
- INVARIANT: observational counters only; admission behavior is byte-identical
  to the previous build.
- BUILD RESULT: PASS.
- TEST RESULT: 2,062 passed / 10 skipped / 0 failed (fresh cache).
- WINDOWS RESULT: Not applicable. The installed daemon is source `318a10a`
  (`438F9D5F...`), which does not contain this slice, so **no E5 claim** is made
  and the live host was not restarted or modified.
- EVIDENCE LEVEL: E2.
- EVIDENCE ARTIFACTS: this report; the two source regression tests;
  `EVIDENCE_INDEX.json#INGRESS-KIND-ATTRIBUTION-001-E2-20261109`.
- ROLLBACK: `git revert 2e715dfdd38a101454def530de55ae00d4b8a28a`; the response
  key disappears and the counters stop being read. No state migration is
  required.

## Records correction made in the same commit

`EVIDENCE_INDEX.json.evidence_level_summary` did not match the counting rule
that `scripts/check_summary.py` and `tests/release/test_evidence_index_valid.py`
both implement (count every level-tagged entry in **both** `evidence` and
`known_gaps`). At the parent commit the recorded values were
13/73/12/0/69/0/0 while the rule derived 34/174/17/15/158/0/1, so that release
test failed before this patch. The summary was re-derived mechanically from the
entries (now 34/175/17/15/158/0/1, the +1 E2 being this slice). This changes no
evidence entry and no claim: the derived `E7_count=1` is the historical EVT-220
traceability entry (a 6.0.0 bundle artifact verification), **not** a signed
release approval; signed-release E7 work remains open.

## Remaining work

- REMAINING RISK: the table is bounded at 65,536 lanes; a pathological producer
  using >256 distinct source ordinals would collapse into `unknown_<N>` labels
  at the label layer only (ordinals are preserved in `source_ordinal`). Real
  producers occupy ~15 source ordinals, so the emitted array stays small in
  practice; the worst-case response growth is bounded by active lanes, and the
  control path already fails closed (handler returns null) if serialization
  fails.
- OPEN BLOCKERS: issue #29 remains OPEN for the actual loss. Coalescing is
  still blocked by the producer-identity stop-line; the shipped instrument is
  what makes the next burst measurement attributable per class, which is the
  prerequisite for choosing bounded admission or throughput work.
- COMPLETION GATE: PASS for the E2 attribution slice only. No E5, no #29
  closure, no release claim.
