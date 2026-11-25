# host_live diagnosis — why two E6 tests fail on the installed host

> Scope: build source `4dd3393`, records HEAD after the AEGIS-PLAN closure.
> This page records a **diagnosis**, not a PASS and not a source fix.
> No elevated action was taken while writing it.

## 1. Observed failures

```
tests/integration/test_e6_attack_burst.py::test_a_localhost_port_scan_is_captured_and_scored
tests/integration/test_e6_l4_scan_detection.py::test_a_syn_scan_is_tagged_by_an_l4_rule
```

Both fail with the same shape: canonical ingress advances, but no R9006
(`FNV-1a("R9006") = 1745456278`) row is attributable to the test-owned source
IP and ephemeral ports. `pytest tests/integration/test_e6_attack_burst.py
tests/integration/test_e6_l4_scan_detection.py -q` → **2 failed, 2 passed**.
The two passing tests are the detection-only invariant and the ring-liveness
precondition.

## 2. Direct probe at the current host (non-elevated, read-only stimulus)

| Measurement | Value |
|---|---|
| Log selected by `event_log_path()` | `C:\Windows\System32\logs\aegis_core.ndjson` |
| Rows appended during the 40-port burst | 16,127 |
| `capture_npcap.pushed` | 3,597,306 → 3,599,039 (**+1,733**) |
| Rule distribution in appended rows | `3813986375` × 16,124, `2` × 3 |
| Event distribution | `signature_match` × 16,124, `reg_change` × 3 |
| Rows with `src_ip=127.0.0.2` | **0** |
| Attributable R9006 rows | **0** |
| Whole-log scan (396,245 rows) | R9006 count **0**; all `src_ip=0.0.0.0` |

Rule `3813986375` is the FIM/R1001 System32 `.dll` path rule recorded in
`EVIDENCE_INDEX.json`; the appended rows are host-telemetry rows, not capture
rows. The ingress counter proves frames reached the pipeline queue, but the
audit rows in this log carry no capture source address.

## 3. Root cause: stale installed binary and unpinned interface

| Check | Result |
|---|---|
| Installed service | `AegisNids`, `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`, RUNNING |
| Installed daemon SHA-256 | `FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474` |
| What that hash is | Runtime of immutable release identity `v1.1` / `466a226` / build source `a53eda8` (recorded in `analysis/current-head/SOAK-WINDOW-466A226-20261120.md` and `tools/host_preflight.py`) |
| Current build source | `4dd33936909de1314099652a7523e52c40bb2c44` — **not** `a53eda8` |
| Nose interface selection in current source | `nose/capture.go:68-90` `firstUpDevice` excludes loopback in **auto-selection**; explicit selection is via `AEGIS_NOSE_IFACE` (`nose/main.go:38-46`) |

The installed pair predates the current source and is not pinned to
`\Device\NPF_Loopback`. The loopback E6 tests require a rebuilt daemon/Nose and
an explicit loopback interface pin. Running them against the installed release
binary therefore cannot prove a current-source defect; it also cannot be
reported as a current-source PASS.

## 4. What this does and does not establish

- **Established:** the installed binary is the historical release identity;
  the observed log rows are FIM/registry traffic; no attributable capture row
  was written during the probe.
- **Not established:** that R9006 is broken at `4dd3393`; that loopback capture
  works at `4dd3393`; any E5/E6 result at the current source.
- **Not changed:** no test was relaxed, skipped, or xfailed to hide the failure.
  No binary, service, filter, or interface pin was modified.

## 5. Owner actions to close it

1. Rebuild from `4dd3393` using step 0 of
   `analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`; record all
   binary SHA-256 values.
2. Pin Nose explicitly to `\Device\NPF_Loopback` via `AEGIS_NOSE_IFACE` and
   record the exact selector and adapter label.
3. Re-run the two tests with the rebuilt pair and record the real outcome.
4. Only then update matrix provenance. A PASS requires attributable rows with
   the exact source IP and test-owned ports plus the below-threshold control.

---

See also: [`FAULT_INJECTION_INVENTORY.md`](FAULT_INJECTION_INVENTORY.md),
[`../../analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`](../../analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md),
[`../evidence/PROVENANCE.md`](../evidence/PROVENANCE.md).
