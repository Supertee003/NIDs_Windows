# S2/S3 host proof — active control replay + durable producer identity at build source `aa3b7b0`

**RECORD-ID:** `S2S3-HOST-PROOF-E5-AA3B7B0-20261126`
**RECORDS HEAD:** `6c94b47dc95acfef283cf24727e6edf2f2647e47`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (ADR-0008)
**EVIDENCE LEVEL:** `E5` (narrow Windows host verification of two flows). This is **not** full Windows kernel IDS qualification, not E6/E7, and not a release claim.

## Flow contracts exercised

- **S2:** operator/CLI → canonical `\\.\pipe\aegis_control` → v2 envelope validation → nonce/replay guard → JSON error envelope + audit.
- **S3:** Go Nose v3 provenance → Zig pipe ingress → durable generation/capture-sequence admission → health `data_plane` counters.

## What was installed (owner-run, elevated)

`D:\aegis-tmp\owner_s2s3.ps1` backed up the installed runtime, stopped `AegisNids`, copied the current-source binaries into `C:\Program Files\AEGIS NIDS\runtime`, set `AEGIS_NOSE_IFACE=\Device\NPF_Loopback`, started the daemon and one Nose capture process, ran the probes, then **always** restored the baseline in `finally`.

| File | Swapped SHA-256 (current source) | Restored baseline SHA-256 |
|---|---|---|
| `aegis_nids.exe` | `6F548AF7641C1C476FB591D165ED734027ED18D93F980AFEA755C20A716BBB98` | `FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474` |
| `aegis-nose.exe` | `8C05FE485D2548DF50C83F5BEA792F4228FEAE387306668A439912A39A7D24D4` | `AEAB9B6324E3A7EA0498B0A338E406C012139F15D883465AE574CAC773BC79C2` |
| `aegis_pep.dll` | `6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926` | `870CB9626EDD75AD2552F1CDFE6475D8A7804163354E3A588FED1E4360996C5E` |

`restore.verified = true`, service status `Running`, environment and machine `AEGIS_NOSE_IFACE` restored. `errors = []`.

## S2 result — PASS

Successful run: `analysis/current-head/raw-aa3b7b0-20261126/s2s3-success/result.json` (verbatim copy of `D:\aegis-tmp\owner-s2s3-20261126-162527\result.json`).

- Probe: `tools/aegisctl/envelope.py::build_v2_request("system.health", {})`; request 181 bytes, SHA-256 `FD07D4E855E1684D19F61B4217F700B23CD9D31FC911853219D337F822B92C45`.
- First request: `{"ok":true,...}` (fresh nonce accepted).
- Byte-identical replay: `{"ok":false,"code":"REPLAY_DENIED","state":"REPLAY_DENIED","data":{"message":"Nonce already used"},"audit_id":3489}`.
- Verdict: `fresh_accepted=true`, `exact_replay_denied=true`, `pass=true`.

An earlier run (`20261126-162352`) reported `fresh_accepted=true`, `exact_replay_denied=false` because the one-shot probe hit Win32 `ERROR_PIPE_BUSY` (231) while reconnecting to the single-instance pipe. That was a **probe defect**, not a bypass: the replay never reached the daemon. `D:\aegis-tmp\s2s3_probe.py` was fixed with `WaitNamedPipeW` retry (no product source change) and the run above was repeated. The failed run is preserved as `analysis/current-head/raw-aa3b7b0-20261126/s2s3-probe-defect/result.json`, not deleted or relabelled.

## S3 result — PASS

Same successful run, with a deliberate Nose restart between two health snapshots and benign loopback traffic generated around each snapshot.

- `generation_before = 5`, `generation_after = 6` — durable per-interface generation advanced across restart.
- `sequence_before = 736`, `sequence_after = 1324` — dedicated `capture_sequence` advanced.
- `nose_producer_duplicate = 0`, `nose_producer_regression = 0`, `nose_producer_invalid = 0`.
- `generation_advanced=true`, `sequence_advanced=true`, `duplicate_regression_invalid_zero=true`, `pass=true`.

The first run (`20261126-162352`) already showed `3→4` / `701→1330` with all three rejection counters at zero; it is retained as corroboration.

## Health precondition, recorded honestly

Both S2/S3 runs reported `state: DEGRADED` while `runtime_state: RUNNING`. The cause is `data_integrity.minifilter_ring_dropped = 68,740,045`, a **driver-lifetime gauge** that survives daemon restarts; the configured `loss_budget` was 3500, so the daemon correctly refused to call itself healthy. This is unrelated to S2/S3 admission/replay verdicts and was **not** hidden by raising the budget. For the subsequent 24 h soak the minifilter driver was recycled **before** the window and the gauge changed `68,740,045 → 0` with `loss_budget` still 3500 (see `owner-soak-aa3b7b0-20261126-162907/start.json`).

## Limits / remaining risk

- Verbatim copies of the raw artifacts are tracked under `analysis/current-head/raw-aa3b7b0-20261126/s2s3-success/` and `.../s2s3-probe-defect/`; the originals remain under ignored `D:\aegis-tmp\owner-s2s3-*`.
- No WFP/kernel rule-match, no host effect, no E6 production simulation and no E7 release verification is claimed here.
- The probe uses the live installed daemon; E2 unit/contract pins remain in `tests/security/test_control_replay_envelope.py` and the S3 producer-identity tests.
