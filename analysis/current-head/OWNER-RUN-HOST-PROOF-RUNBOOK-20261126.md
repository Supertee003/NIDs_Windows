# Owner-run host proof runbook — current source `4dd3393` (2026-11-26)

**STATUS: PREPARED ONLY. NOTHING IN THIS DOCUMENT IS EVIDENCE OF A PASS.**
Every item below is OPEN until an elevated owner session actually performs it
and records real artifacts. This agent session is non-elevated
(`ELEVATED=False`), so none of these steps were executed here.

## Scope and pinned identity

- Build source under proof: `4dd33936909de1314099652a7523e52c40bb2c44`
  (S4 canonical policy bytes; predecessors S1 `493648f`, S2 `4bc8244`,
  S3 `f1f89c1`).
- Records head at preparation: `c447149d8a25cfe86524a7076ea59e247e2ad207`.
- Release identity remains immutable `v1.1` / `466a226` / `a53eda8` with a
  historical 6/6 result. The current-source release check is honestly
  NOT SHIPPABLE (`release_signature` and `soak_24h` predating this runtime).
- No claim here implies full Windows E5 / kernel IDS qualification, matrix
  re-measurement, soak, install, signing, E6 or E7.

## 0. Common preflight and mandatory restore

1. Work from a checkout at the pinned head. Confirm:
   ```powershell
   git rev-parse HEAD
   python tools/truth.py verify          # TRUTH_VALID at 4dd3393
   python tools/release_engineering.py --verify   # 690 artifacts match, source_commit=4dd3393
   ```
2. Rebuild from this source, never reuse an older binary:
   ```powershell
   zig build
   cargo build --release
   cmake -B build && cmake --build build
   cd nose; go build -o aegis-nose.exe .
   ```
   Record SHA256 of `zig-out/bin/aegis_nids.exe` (or built `aegis_nids.exe`),
   `target\release\aegis_pep.dll`, the three C DLLs and `aegis-nose.exe`.
3. Before any swap, capture the live baseline: service state and failure
   actions, installed binary SHA256 set, Nose command line, canonical pipe
   owner, and current `aegisctl status --json` / `system.health` response.
4. Perform every host action inside an elevated PowerShell whose `finally`
   block stops the proof processes, restores the original binaries/service
   state/Nose command line and verifies the single canonical pipe is free or
   owned by the original process. Keep raw transcripts with UTC timestamps.
5. Any mismatch in restore hashes closes the run as FAILED; do not report a
   partial PASS.

Prepared historical reference (source `7822f4c`, NOT current):
`D:\aegis-tmp\i44_e45_7822f4c_elevated_run.ps1` launched by
`D:\aegis-tmp\run_i44_e45_7822f4c_as_admin.cmd`. Reuse its lifecycle pattern
only after re-verifying harness SHA256 and rebasing the binary pins.

## 1. R2003 host E5 re-measurement (source producer `493648f` → current)

Flow: `ETW ProcessStart commandLine TLV -> kernel_process automaton -> R2003
(rule hash 2485705370) -> forensic row`.

1. Install/start the rebuilt daemon and rebuilt `aegis_etw_helper.dll` from
   step 0. Confirm health shows the ETW lane active and no DEGRADED reason
   introduced by the swap.
2. Record the baseline R2003 row count from the forensic NDJSON.
3. **Positive:** launch a long-lived PowerShell cradle whose command line
   contains an `IEX` expression with a unique marker (e.g.
   `powershell -NoProfile -Command "Start-Sleep 900"` launched by a parent
   whose command line contains the `IEX` marker). Wait for ETW delivery.
   Accept only if a new R2003 row appears with the raw `commandLine()` TLV
   containing the marker.
4. **Negative control A (wire-only):** place the same `IEX` marker in a TCP
   payload with no host process row. R2003 must stay at baseline (this is the
   FP-1 regression guard).
5. **Negative control B (benign):** start a process with a similar command
   line but without `IEX`. R2003 must stay at baseline.
6. Evidence to save: three NDJSON excerpts (positive + both negatives) with
   counts and timestamps, the exact command lines, installed binary SHA256,
   health snapshot and restore proof.
7. Gate: `PASS_E5` only when positive ≥1 new row and both negatives exactly
   zero. Otherwise record `NOT_PROVEN` with the observed counts.

## 2. S2 exact replay denial on the live rebuilt daemon

Flow: `v2 control envelope -> nonce/replay guard -> audit`. The currently
running old daemon does not enforce this; a rebuilt daemon must actually be
started for this proof.

1. Start the rebuilt daemon from step 0. Verify `tools/aegisctl.py status
   --json` works (client compatibility only).
2. Build one exact envelope with the shared builder, then send **the same
   serialized bytes twice** to `\\.\pipe\aegis_control` using raw
   `CreateFileW`/`WriteFile`/`ReadFile` (adapt `tools/probe_control_pipe.py`,
   which already shows the chunked-read pattern):
   ```python
   from aegisctl.envelope import build_v2_envelope, serialize_envelope
   env = build_v2_envelope("system.health", {})   # benign command; no shutdown
   wire = serialize_envelope(env)                 # reuse these exact bytes
   ```
   Expected: first envelope accepted; second rejected with `REPLAY_DENIED`
   and an audit entry carrying the same nonce.
3. Negative controls, each with a freshly built envelope: remove
   `protocol_version` (and set it to `1`), corrupt the 32-hex `nonce`, and set
   `issued_at_ms` outside ±60 s. All must be rejected and audited.
4. Evidence: raw request bytes for every probe, both responses verbatim,
   audit-ring excerpt, daemon SHA256, and restore proof.
5. Gate: `PASS_E3/E5` only on the rebuilt daemon with an observed exact
   `REPLAY_DENIED`. The S2 E2 source proof does not substitute for this.

## 3. S3 durable producer identity on the live current build

Flow: `Go Nose state file -> v3 provenance tuple -> Zig ingress guard ->
queue/alert/health evidence`.

1. Use the rebuilt Nose and daemon from step 0. For isolation set
   `AEGIS_NOSE_STATE_FILE` to a dedicated probe path; record the default path
   too if the override is not used.
2. Start Nose; capture the state file and a v3 frame tuple
   `(capture_sequence, producer_epoch, producer_generation, interface_id)`
   from health / alert evidence. All four fields must be nonzero.
3. Restart Nose (watcher re-arm guard may require stopping twice). `producer_
   generation` must increment in the state file and in newly admitted frames.
4. Replay or force a duplicate/regression `(capture_sequence, generation)`
   pair into `\\.\pipe\aegis_nose`. Expected: rejected before queue admission,
   with a visible reject/drop cause counter; gap and 64-key eviction counters
   remain visible, never silent. Legacy v1/v2 and metadata-only v3 frames must
   still be admitted.
5. Evidence: before/after state files, rejected frame hex, counter deltas,
   alert/health NDJSON excerpts, binary SHA256 and restore proof.
6. Gate: `PASS_E3/E5` only with observed duplicate/regression refusal on the
   rebuilt pair. Otherwise keep `NOT_PROVEN`.

## 4. 23-rule detection matrix re-measurement

1. With the same rebuilt daemon, use `docs/DETECTION_VALIDATION.md` and
   `docs/portfolio/DETECTION_MATRIX_CURRENT.md` as the 23-rule checklist; keep
   `configs/Rules.json` unchanged and record its SHA256.
2. Re-run the existing E5/E6 host probes for every rule and record observed
   row counts, rule IDs, source lanes and timestamps. Update the FP/FN
   register only from observed rows.
3. Re-run the two host-live loopback E6 tests that currently fail against the
   old daemon, at the current source:
   `tests/integration/test_e6_attack_burst.py::test_a_localhost_port_scan_is_captured_and_scored`
   and
   `tests/integration/test_e6_l4_scan_detection.py::test_a_syn_scan_is_tagged_by_an_l4_rule`.
   Record their real outcome; do not convert a failure into a PASS.
4. Gate: the "NOT RE-MEASURED at current source" marker may only be replaced
   after every rule row is evidence-backed at build source `4dd3393`. Matrix rows
   at `f4cde3c` remain HISTORICAL otherwise.

## 5. Gates that stay OPEN regardless of sections 1–4

- 24 h soak at the current source (the 36.52 h soak belongs to `a53eda8`).
- Install / production signing with an owner-provided key; no re-key or new
  tag is implied.
- E6 production simulation and E7 release verification.
- Full current-head Windows E5 / kernel IDS qualification.

## 6. Recording a real result

1. Store raw artifacts under the ignored `admin-evidence/` directory with UTC
   timestamps; never fabricate a PASS or backdate a timer.
2. Add an `EVIDENCE_INDEX.json` entry with `head_sha`
   `4dd33936909de1314099652a7523e52c40bb2c44`, the level actually achieved
   (E3/E5/E6), `files_verified`, exact test/observation list, `result`,
   limitations, and `evidence_artifact` pointing at the new record.
3. Update `docs/DETECTION_VALIDATION.md` / matrix provenance, then run:
   ```powershell
   python tools/rebuild_truth.py
   python tools/truth.py verify
   python scripts/check_summary.py
   python scripts/doc_checker.py
   python -m pytest -q -p no:cacheprovider tests/docs tests/release
   python tools/final_audit.py --release-check
   ```
4. Commit records only; do not move the build source unless source code
   actually changes. Push after the gates are green (release-check is Allowed
   to remain exit 1 while soak/signature are genuinely open).
