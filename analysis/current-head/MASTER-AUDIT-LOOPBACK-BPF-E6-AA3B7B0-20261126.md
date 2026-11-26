# MASTER AUDIT — loopback BPF fix + host_live E6 PASS (2026-11-26)

## PATCH DECLARATION

```
PATCH-ID:      LOOPBACK-BPF-001
FLOW-ID:       Npcap loopback -> Go Nose BPF -> canonical pipe -> Zig queue -> R9006 -> NDJSON
TARGET HEAD:   722d5f1035526aff4dab66e88bd318096235bf9e
BUILD SOURCE:  4dd33936909de1314099652a7523e52c40bb2c44
TARGET FILES:  nose/capture.go, nose/talkers_live.go, nose/capture_visibility_test.go
TARGET SYMBOLS: noseCaptureBPF, loopbackInterface, noseLoopbackBPF, captureBPFFor, runCapture, startLiveTalkersFeed
IN-SCOPE:      BPF selector for the exact Npcap loopback adapter + unit pin
OUT-OF-SCOPE:  wire schema, rules, daemon, policy bytes, driver, signing, soak, E7
CONTRACT IMPACT: none (CanonicalEvent unchanged)
ABI IMPACT:    none
AUTHORITY IMPACT: none (Go remains acquisition-only)
STATE IMPACT:  none new; loopback capture now reaches the existing queue
TEST IMPACT:   Go unit pin + two real host_live tests
EVIDENCE IMPACT: one E6 host proof at the new build source
```

FINAL SOURCE HEAD: `aa3b7b0161e425e54155d5767737bffcde7939b5`
FINAL RECORDS HEAD: records-only commits after this source patch.

## 1. Defect found by the first owner-run

The first authorized elevated run (`D:\aegis-tmp\owner-run-e6-20261126-040608`)
swapped in current-source binaries and pinned `AEGIS_NOSE_IFACE` to
`\Device\NPF_Loopback`, but both host_live tests failed at the first assertion:
`queue snapshot has no capture_npcap source row`. Health showed
`nose_connected: false` and `wfp.mode=kernel_fallback, reason=nose_absent`.

An isolated Nose probe with redirected stderr gave the exact cause:

```
[AEGIS NOSE] capture error: nose capture: bpf: no VLAN support for BSD loopback
```

`nose/capture.go:63` applied `vlan or ip or ip6` unconditionally. Npcap's
loopback adapter is DLT_NULL; libpcap rejects the `vlan` primitive on that link
type, so Nose exited before dialing `\\.\pipe\aegis_nose`. No source claim about
R9006 was disproved — the capture path never started.

## 2. Fix

| Item | Value |
|---|---|
| Default filter (Ethernet, unknown, auto-select) | `vlan or ip or ip6` — unchanged |
| Exact `\Device\NPF_Loopback` filter | `ip or ip6` — DLT_NULL-compatible |
| Selector match | `strings.EqualFold(strings.TrimSpace(iface), loopbackInterface)` |
| Unit pin | `nose/capture_visibility_test.go::TestCaptureBPFForAdapterLinkType` |
| Wire/ABI/rules/policy | unchanged |

`zig build`, `cargo build --release` and `go build` all exited 0 after the fix.
Rebuilt identity: daemon `5ECAECE8E83248704FB7D4374BB7AA4783BDA853F94319832E4F075775A6AF3C`,
Nose `8C05FE485D2548DF50C83F5BEA792F4228FEAE387306668A439912A39A7D24D4`,
PEP `6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926`.

Isolated new-Nose probe on loopback: `ALIVE=True`,
`[NOSE CAPTURE] listening on \Device\NPF_Loopback`, `[NOSE PIPE] waiting ...`,
`packets=400 canonical=400` (private pipe, frames correctly dropped because no
consumer was present). This established that capture no longer aborts.

## 3. Authorized elevated owner-run (real host action)

Run directory: `D:\aegis-tmp\owner-run-e6-v2-20261126-152914`
(copy retained under ignored `admin-evidence/owner-run-e6-v2-20261126-152914`).

| Step | Observed |
|---|---|
| `ELEVATED` | `True` via UAC-approved shell; no UAC bypass |
| Baseline service | `AegisNids` RUNNING, historical daemon `FBD9BDB3…185474` |
| Swapped hashes | exactly the three rebuilt hashes listed above |
| Interface pin | service + machine `AEGIS_NOSE_IFACE=\Device\NPF_Loopback` |
| Nose stderr | `[NOSE PIPE] connected to \\.\pipe\aegis_nose`; `first canonical frame sent: 1193 bytes event_id=1`; `dropped=0` throughout |
| `test_a_localhost_port_scan_is_captured_and_scored` | **1 passed**, exit 0, 23.70 s |
| `test_a_syn_scan_is_tagged_by_an_l4_rule` | **1 passed**, exit 0, 23.44 s |
| Restore | `verified: true`; daemon, Nose, PEP hashes, service env and machine pin all equal baseline; service RUNNING |

Independent forensic corroboration from `C:\Windows\System32\logs\aegis_core.ndjson`:
exactly **2** rows with `rule:"1745456278"` (R9006), both with
`src_ip:"127.0.0.2"` and test-owned ephemeral source ports `50533` and `50586`.
Negative control inside each test remains active (below-threshold 10-port
phase); both tests passed with it in place.

The v2 script's own preflight poll reported `nose_connected: false` and
`queue_has_npcap: false` because its `CtlJson` helper used `$args` (a reserved
PowerShell automatic variable) and therefore never captured the CLI JSON. This
is a harness measurement defect, not a runtime observation: Nose's redirected
stderr shows the real pipe connection and zero dropped frames, and both tests
read the live queue successfully. The result JSON is retained verbatim; no
field was edited to hide the defect.

## 4. Level and limits

Evidence level: **E6 PASS, narrow** — two real host_live loopback scan tests at
the current build source, with attributable R9006 rows and the existing
below-threshold control. It is not a 23-rule matrix re-measurement, not a soak,
not a kernel driver load/unload proof, not install/signing, not E7.

Still OPEN: `release_signature`, `soak_24h` at this source, full Windows E5 /
kernel IDS qualification, S2/S3 host replay proofs, fixed-rate network
benchmark, coverage-guided fuzz campaign, production install/sign/tag.

## 5. Rebaseline gates at `aa3b7b0`

| Gate | Result |
|---|---|
| `python tools/truth.py verify` | TRUTH_VALID — maps carry `aa3b7b0` (ancestor of HEAD; source worktree clean) |
| `python scripts/check_summary.py` | SUMMARY_VALID |
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN |
| `python -m pytest tests/docs tests/release -q` | 278 passed |
| `python -m pytest -m "not host_live" -q` | 1,520 passed, 1 skipped, 18 deselected, 27 subtests |
| `go test ./... -count=1` (in `nose/`) | ok, exit 0 |
| `python tools/release_engineering.py --verify` | 691 artifacts match digests (source_commit `aa3b7b0`) |
| `python tools/final_audit.py --check` | **4/6 PASS**: truth_artifacts, component_audit, clean_host_e5, evidence_debt; exit 0 |
| WDK driver rebuild | `scripts/wdk_build_production.ps1` rebuilt `build/x64/wfp/aegis_wfp.sys` from current driver source; SHA-256 `593A1299F9A1EB84F77582FDB17AC3E20AF4CA43CB76AF43CE4E8102F9CA3895` |

The local `build/` tree had been cleaned earlier to free a full C: drive. That
removed the untracked WDK `.sys` outputs and temporarily regressed
`component_audit` Part II `Windows-Verified` to false. Rebuilding from the
current `drivers/wfp_callout/` sources with the installed WDK restored the gate
to 5/5. No archived or stale `.sys` was copied in; the recorded hash is the
fresh output. `release_signature` and `soak_24h` remain OPEN by design: the
immutable `v1.1` / `466a226` / `a53eda8` signature and the 36.52 h soak both
predate this runtime source and cannot be re-issued or re-run honestly here.

ROLLBACK: revert source commit `aa3b7b0` and rebaseline machine maps; host
state was already restored to the exact baseline by the script's `finally`
block, verified by hash and environment comparison.

REMAINING RISK: loopback now uses a narrower BPF than Ethernet; VLAN/QinQ
visibility on loopback is intentionally not claimed (DLT_NULL carries no tag).
Ethernet VLAN/QinQ code and tests are unchanged.
