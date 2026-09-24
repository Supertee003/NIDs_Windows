# AEGIS Milestone 3 Findings

**Scope:** `analysis/milestone-3-critical.diff` and current source files selected from the diff.

**Current verdict:** The observe-only and contract baseline is useful, but the current source is **not accepted for production IPS**. The main blockers are in the WFP/PEP mutation boundary, exact cleanup semantics, host-postcondition verification, and release dependency declaration.

## Executive conclusion

The change set improves several safety properties. It removes the direct filter-add/remove implementation from `src/windows/aegis_wfp.c`, makes the dashboard depend on daemon/control truth, and changes Gate E/F tests toward fail-closed behavior. Those are positive architectural moves.

However, the resulting implementation still exposes legacy mutation functions, requires them during provider loading, and allows the Rust PEP to treat a returned WFP filter ID as sufficient enforcement success. A filter ID is not an independently verified host postcondition. The current PEP response also lacks the complete `EnforcementReceipt v1` evidence required by the operator contract. Therefore `host_effect_capable` and `BLOCKED_CONFIRMED` must remain disabled.

## Findings

### P0 — WFP IOCTL contract is not authority-safe yet

The current `src/windows/wfp_ioctl.c` still exports `aegis_wfp_ioctl_block_ip` and `aegis_wfp_ioctl_unblock_ip` at lines 113–123. These functions send the legacy 4-byte IPv4 payload to the new `IOCTL_AEGIS_BLOCK_FLOW` and `IOCTL_AEGIS_UNBLOCK_FLOW` codes. The kernel driver now expects an 8-byte `AEGIS_WFP_FLOW_REQUEST` and an 8-byte filter ID respectively.

The Rust adapter in `rust-src/lib.rs` still loads these legacy symbols at lines 279–290 and treats their presence as a prerequisite for provider readiness. This creates an ABI-drifted compatibility surface. The legacy calls currently fail closed through buffer-size or provider errors, but they remain callable and are not a valid production contract.

**Required action:** remove the legacy symbols from the active provider contract, or make them explicit hard-fail compatibility stubs that cannot mutate WFP. Provider readiness must require only the reviewed `block_flow` and `unblock_filter` surface. Add a cross-language symbol/ABI test.

### P0 — PEP does not verify host postcondition

`rust-src/lib.rs` lines 475–511 call `adapter.block_flow()` and set `filter_id` when the provider returns an ID. No independent read-back verifies that the filter exists with the expected layer, conditions, action, owner/provider, and scope. The function then returns `DECISION_BLOCK` with `reason=0`.

This violates the required distinction:

```text
provider response != verified host effect
```

**Required action:** keep the response as pending/unverified until a provider read-back confirms the exact filter. Only then create `EnforcementReceipt v1` with `host_effect_confirmed=true`, non-zero identities, provider identity, and filter identity. Add a negative test where the provider returns an ID but read-back fails.

### P0 — Exact cleanup is not guaranteed through all exposed paths

`rust-src/lib.rs` lines 515–537 still expose `aegis_pep_unblock_ip`, which delegates to the legacy IP-based adapter cleanup. The authoritative cleanup function is `aegis_pep_unblock_filter` at lines 543–564, but the old API remains available and does not require the receipt's exact `filter_id`.

**Required action:** quarantine or remove IP-only cleanup from the production FFI. Cleanup must accept only the validated receipt `filter_id` plus authorization and freshness data. Add a test proving that an IP-only cleanup request cannot remove a filter.

### P1 — Driver filter state is global and not synchronized

`drivers/wfp_callout/aegis_wfp.c` uses global `g_FilterId` and `g_BlockedIp` and updates them in `AegisWfpBlockFlow` and `AegisWfpUnblockFlow` without a lock. Concurrent IOCTLs or repeated requests can race. The driver also appears to support only one active control filter, while the higher-level contract models request IDs and receipt identities.

The current filter is marked `FWPM_FILTER_FLAG_PERSISTENT` at the driver source, while the WFP session is dynamic. A persistent filter creates a cleanup/restart risk if the process or driver exits before exact removal is verified.

**Required action:** use an explicit synchronized filter registry or enforce one-filter serialization at the authoritative owner. Prefer dynamic ownership for the controlled proof unless persistence is explicitly required. Add crash/restart tests for stale filter cleanup.

### P1 — Python enforcement wrapper is internally inconsistent

`tools/aegisctl/api/control_api.py` lines 336–355 call `request_enforcement_via_pep()` with `target_port=0` and `rule_name` as the rule ID. The request function rejects port zero and requires a numeric rule ID. Therefore the wrapper `apply_firewall_block()` cannot produce an `ENFORCED` result with its current default signature.

**Required action:** remove this legacy wrapper from active call paths or change its API to require a validated numeric policy ID and a valid target port. It must not silently use an IP-only block route when the current provider contract is port-specific.

### P1 — Test gates changed from live behavior to unavailable behavior

`tests/runtime/test_gate_e.py` and `tests/runtime/test_gate_f.py` delete large portions of the previous command, simulation, and canary behavior tests. The replacements assert fail-closed `UNAVAILABLE` responses. This is appropriate for a safe pre-enforcement phase, but it is not equivalent coverage.

**Required action:** retain the fail-closed tests and add a separate controlled integration suite that runs only in an isolated lab. Do not count the new unavailable tests as proof that simulation, canary, or enforcement behavior works end-to-end.

### P1 — Build graph intentionally does not build the kernel driver

`CMakeLists.txt` lines 64–72 now fails when `BUILD_KERNEL_DRIVER=ON` because there is no authoritative WDK project selection. This is safer than silently building a stale graph, but it means the normal build cannot produce the required driver artifact.

**Required action:** provide one reviewed WDK build entry point with explicit source files, target architecture, signing profile, and artifact hash output. Until then, classify the driver as source-present but build-unverified.

### P1 — FFI layout tests are compile-time assertions, not cross-artifact ABI proof

The Zig tests in `src/policy/pep_bindings.zig` assert expected sizes and offsets, and the Rust structs use `#[repr(C)]`. This is useful, but it does not prove that the loaded DLL at runtime was built from the same source or exports the same ABI. `build.zig` installs the Rust DLL beside the Zig executable, which improves pairing, but provenance still requires hash and export verification.

**Required action:** add a generated ABI manifest containing sizes, offsets, ordinals, exported symbols, source commit, and artifact hashes. Verify it during release and before runtime startup.

### P2 — Flask is not declared in the Python dependency contract

The dashboard test initially failed with `ModuleNotFoundError: No module named 'flask'` and passed only after manual installation. The current source imports Flask directly in `tools/aegisctl/web_dashboard/app.py`. The repository must declare this dependency for a clean environment.

**Required action:** add Flask to the authoritative Python dependency manifest used by the project and add a clean-environment import test. Do not rely on a manually modified developer interpreter.

### P2 — Rust federation TLS is explicitly a stub

`rust-src/lib.rs` lines 602–630 construct empty/no-client-auth TLS configuration and `send_heartbeat()` returns success without opening a connection. This is outside the immediate WFP proof but is a production blocker if federation is included in the release profile.

**Required action:** mark federation as unsupported in the release manifest or implement and test certificate loading, peer authentication, and actual transport before claiming federation readiness.

## Positive changes verified from the diff

The change set makes several correct safety improvements:

1. `src/windows/aegis_wfp.c` no longer contains the previous direct filter-add/remove implementation.
2. `tools/aegisctl/api/control_api.py` returns an explicit degraded diagnostic payload when the daemon is unavailable and no longer treats PID inspection as runtime truth.
3. The dashboard uses `query_control()` and `project_operator_state()` rather than inferring a confirmed block from a log or policy label.
4. `build.zig` installs `aegis_pep.dll` beside the executable, reducing DLL/import-library pairing drift.
5. Gate E/F replacements test fail-closed behavior for mutation commands.
6. The Go/Zig pipe path adds bounded reconnect and stop-aware behavior, although Windows runtime verification is still required.

## Minimal verification plan before any patch

Run these read-only checks on the Host:

```powershell
Set-Location D:\NIDs_Windows

rg -n "aegis_wfp_ioctl_block_ip|aegis_wfp_ioctl_unblock_ip|aegis_wfp_ioctl_block_flow|aegis_wfp_ioctl_unblock_filter|apply_firewall_block|request_enforcement_via_pep" src rust-src tools brain nose tests

cargo test --manifest-path .\Cargo.toml
cargo test --manifest-path .\rust-src\shield\Cargo.toml

zig build test -Doptimize=Debug
```

If a command fails, return only its final error block and exit code. Do not run WFP block/unblock commands. Do not install or load the driver as part of this verification.

## Milestone 4 patch order

1. Remove or hard-fail legacy IP-only WFP exports and stop requiring them for provider readiness.
2. Introduce a single shared WFP ABI header or generated contract for C, Rust, and Zig.
3. Separate provider response from host-postcondition verification.
4. Make `EnforcementReceipt v1` the only confirmed-enforcement output.
5. Restrict cleanup to exact receipt `filter_id` and add negative tests.
6. Fix or quarantine the broken Python `apply_firewall_block()` wrapper.
7. Declare Flask in the project dependency manifest.
8. Restore separate integration coverage for live canary/simulation behavior without enabling host mutation.

## Production verdict

AEGIS is ready for continued **observe-only development and contract hardening**. It is not ready for production IPS or controlled host-effect testing from the current source because the WFP/PEP path still lacks independently verified host postconditions and retains legacy mutation surfaces.

## References

[1]: README.md "AEGIS NIDS for Windows official README"
[2]: docs/architecture/CONTRACTS.md "AEGIS authoritative contracts"
[3]: contracts/operator_contract_v1.json "AEGIS operator contract v1"
[4]: src/windows/wfp_ioctl.c "AEGIS WFP user-mode IOCTL bridge"
[5]: drivers/wfp_callout/aegis_wfp.c "AEGIS WFP kernel driver"
[6]: rust-src/lib.rs "AEGIS Rust PEP and WFP adapter"
[7]: tools/aegisctl/api/control_api.py "AEGIS control API"
[8]: tests/runtime/test_gate_e.py "AEGIS Gate E tests"
[9]: tests/runtime/test_gate_f.py "AEGIS Gate F tests"
[10]: build.zig "AEGIS Zig build graph"
[11]: CMakeLists.txt "AEGIS native C build graph"
