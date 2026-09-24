# FIM Real Runtime Result — 2026-09-22 22:32

## Authoritative result

`FIM_REAL_PIPELINE_OBSERVE_ONLY_PASS`.

The runtime was restarted with `AEGIS_FIM_PROOF_ROOT` set before startup. The FIM proof then completed successfully and demonstrated real file notification processing through the AEGIS pipeline.

## Evidence

- Runtime state: `RUNNING`
- Degraded: `false`
- FIM worker: `fim_ready=true`
- Worker failure: `false`
- Failure mask: `0`
- Pipeline: ready
- ETW: ready
- Registry: ready
- Nose: ready
- Control: running
- Forensic subsystem: running
- Fixture events processed delta: `8`
- Forensic records delta: `8`
- Blocks delta: `0`
- Errors delta: `0`
- Forensic chain: verified
- Host effect: `none`
- Prevention gate: `closed`
- WFP block called: `false`
- PEP called: `false`

The fixture was created, modified, and renamed beneath the disposable proof root. The sensor path was `ReadDirectoryChangesW` through `aegis_fim_helper`.

## Interpretation

This proves the real path:

```text
ReadDirectoryChangesW -> FIM normalization -> IpcEvent(capture_fim) -> pipeline -> forensic record
```

It does not assert a configured Rule-22 match. The runner deliberately reports `rule_match_status=not_asserted_by_this_runner`; a rule-specific claim requires a canonical record exposing `matched_rule_id` and the expected evidence.

## Post-proof anomaly

After the successful proof and health check, an additional direct `Start-Process .\zig-out\bin\aegis_nids.exe` command was issued while the launcher-owned core was already running. The second process encountered:

```text
control pipe CreateNamedPipeW failed: win32_error=231
```

and then shut down. This is a duplicate-owner lifecycle issue, not a FIM failure and not part of the authoritative proof result. Do not start a second core directly while `run_aegis.bat` is active. Use the launcher/control lifecycle only.

## Promotion state

```text
FIM real sensor pipeline       = PASS
FIM configured rule match      = PENDING
Rules-22 synthetic             = PASS 22/22
L4 host-only transport         = PASS
prevention_gate                = CLOSED
host_effect_capable            = FALSE for this proof
```
