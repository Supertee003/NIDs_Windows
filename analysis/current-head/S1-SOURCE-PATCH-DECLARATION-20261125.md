# S1 source patch declaration — R2003 CommandLine producer (FN-1)

**TARGET HEAD:** `77cb36a1d706e4b831c3a1149507efb6ebdfd5c0`
**BUILD SOURCE BEFORE PATCH:** `7822f4c162f7867555754b7f3677ade33c9548dd`

## PATCH DECLARATION

```
PATCH-ID:             S1-R2003-CMDLINE-PRODUCER
FLOW-ID:              Kernel-Process ProcessStart -> AEGT TLV -> Zig decode -> kernel_process AC -> R2003
TARGET HEAD:          77cb36a
TARGET FILES:         src/windows/etw_native.c
                      src/windows/etw_realtime.zig
                      tests/security/test_etw_session_name.py (records/test pin)
TARGET SYMBOLS:       append_process_command_line; is_kernel_process_start; decode_tdh_properties;
                      decodeTdhPayload; EtwEventRecord.commandLine
IN-SCOPE:             read-only recovery of the started process command line on Kernel-Process
                      ProcessStart (Id 1) via NtQueryInformationProcess(ProcessCommandLineInformation),
                      carried on the existing AEGT TLV kind 2 channel; bounded pointer/length checks;
                      E2 TLV -> R2003 test; E1 source-contract pin
OUT-OF-SCOPE:         CanonicalEvent field/layout/vector/schema change; rule/pattern change; authority
                      or host-effect change; release identity/signature; other three source gaps
CONTRACT IMPACT:      none — no new wire field; AEGT ext_data is an existing payload byte array;
                      R2003 keeps `match_pattern=IEX` and rule-id hash 2485705370
ABI IMPACT:           none
AUTHORITY IMPACT:     none — Zig remains the sole verdict authority; the producer is evidence-only
STATE IMPACT:         none — process handle is opened and closed inside the ETW callback
TEST IMPACT:          pytest source-contract pin; zig build test (fresh cache); MSVC helper rebuild
EVIDENCE IMPACT:      E2 proven at the new build source; host E5 FN-1 re-measurement is owner action
```

## OLD FLOW -> NEW FLOW

- OLD: Kernel-Process ProcessStart v0..v4 carry `ImageName` and no `CommandLine`, so the
  `CommandLine` TLV was never populated and R2003 could never fire from a host process row
  (PROCESS-CMDLINE-001, accepted E5 limitation 2026-11-18).
- NEW: on ProcessStart only, the helper queries the started process with
  `NtQueryInformationProcess(ProcessCommandLineInformation)`, rejects alien pointers and
  oversized buffers, converts UTF-16LE to UTF-8, and appends the bytes as AEGT TLV kind 2.
  The existing Zig decode and kernel_process automaton evaluate those bytes unchanged.

## INVARIANT

- No `CanonicalEvent` byte layout, version, golden vector, rule ID, match pattern, policy
  authority, host-effect path, release identity or signing material changes.
- Command-line bytes are recovered read-only from the live process; no literal pattern is
  fabricated and no rule is widened to image-name matching.
- Provider events that already publish `CommandLine` keep priority; the recovery runs only
  when the provider omitted it.
- Production remains detection-only; no WFP mutation and no enforcement claim.
- Host E5 (real PowerShell cradle on the installed daemon) is **not** claimed by this patch.

## VERIFICATION GATE

1. `python -m pytest tests/security/test_etw_session_name.py -q` — 6 passed.
2. `zig build test` fresh cache — `2150/2153` shown, `2143 passed; 10 skipped; 0 failed`,
   including `windows.etw_realtime.test.PROCESS-CMDLINE-002 ... OK`.
3. `cmake -S . -B <fresh> -G "Visual Studio 17 2022" -A x64` plus
   `cmake --build <fresh> --config Release --target aegis_etw_helper` — compiled clean.
4. `zig build` — exit 0 with the rebuilt helper library.
5. Commit source, rebaseline truth, rebase records/docs/evidence, run all gates, push.
