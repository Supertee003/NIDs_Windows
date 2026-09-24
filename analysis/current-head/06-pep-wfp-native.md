# AEGIS PEP/WFP/Native Production-Security Review — Current HEAD

**Review ID:** `AEGIS-CHR-06-PEP-WFP-NATIVE`  
**Repository:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`  
**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review mode:** Read-only source, build-graph, test, and artifact inspection. No source or generated truth was modified.  
**Decision:** **STOP — do not enable prevention and do not declare production-ready.**

## 1. Scope and method

This review covers only `rust-src/`, `shield/`, `src/core/rust_pep.zig`, `src/policy/pep_bindings.zig`, `src/policy/`, `bridge/`, `src/windows/`, `drivers/`, `target/helpers/`, CMake/native build references, and relevant tests/artifacts. The handoff and README were used as declared architecture and safety context, but current source and the current build graph took priority.

The review traced each relevant boundary across five questions: where the contract is defined, how it is serialized or called, which side validates it, which component owns authority, and what evidence proves the resulting host state. I separately classified **active production candidates**, **support paths**, **tooling/test paths**, **quarantined or legacy paths**, and **artifact-only evidence**. Existing DLL, SYS, LIB, PDB, and generated build directories were treated as evidence of presence only; they were not treated as proof that the current source built them, that the ABI matches, or that Windows loaded and exercised them.

The review did not execute Windows, elevated, WDK, driver, WFP, VMware, or host-network operations in this Linux sandbox. All such claims remain **UNVERIFIED**.

## 2. Executive conclusion

The repository contains a plausible Rust PEP DLL boundary and multiple WFP/native implementations, but it does not currently present one demonstrably authoritative, receipt-producing, host-effect-verified prevention path. The most serious issue is not merely missing integration: the source contains a second Zig-side enforcement model that reports `executed` after inserting an IP into an in-memory map, while the action dispatcher logs that WFP enforcement executed through Rust PEP. That is an **accepted-without-host-effect** path and is a stop-the-line defect.

The root Rust PEP is fail-closed with respect to a missing WFP DLL at the narrow `aegis_pep_enforce` block call, but it authorizes based on caller-supplied fields, returns only a 16-byte decision response, and never returns a verifiable `EnforcementReceipt`. It does not bind a Windows token/SID to the caller PID or capability mask. It does not consume signed policy bytes or a policy signature at the enforcement ABI. It has no nonce, issued-at/deadline, runtime generation, or replay-consumption contract. Its adapter returns only `0`/non-zero, so a successful IOCTL call is not independently tied to provider identity, filter identity, or a host postcondition.

The native layer contains at least two materially different WFP implementations. `src/windows/aegis_wfp.c` directly opens WFP and adds/removes filters. The driver path adds a different filter at a different layer, stores only one global filter identity, and is not wired by the root CMake file: `CMakeLists.txt` refers to `kernel/wfp_callout`, while the source is under `drivers/wfp_callout`. The driver source has both `aegis_wfp.c` and `aegis_wfp_comm.c` dispatch implementations, with different handler sets; one has an unblock handler and the other does not. Device strings in the current source use `AegisWfpDevice` consistently at the user/device-link level, but service/device/driver installation and the exact loaded endpoint are not proven. The earlier `AegisWfp` versus `AegisWfpDevice` risk therefore remains **UNVERIFIED**, not cleared.

The correct product state is a safe degraded or detection-only deployment. **Production prevention must remain closed.**

## 3. Active-path and ownership map

### 3.1 Path classification

| Classification | Source evidence | Review interpretation |
|---|---|---|
| Root Rust PEP candidate | Root `Cargo.toml` maps `[lib] path = "rust-src/lib.rs"`, crate name `aegis_pep`, `cdylib`; `rust-src/lib.rs` exports `aegis_pep_*` | Intended privileged authority. ABI and host-effect proof are incomplete. |
| Zig PEP binding candidate | `src/policy/pep_bindings.zig` declares the root PEP C ABI and dynamically loads `aegis_pep.dll` | Boundary adapter, not proof of loaded DLL or Windows authorization. |
| Zig runtime PEP/WFP candidate | `src/core/rust_pep.zig` provides `RustPep.execute`, `block_ip`, `unblock_ip`, and WFP transport helpers | Mixed model. `RustPep.execute` is an in-memory simulation/recording path; `block_ip` is a separate PEP-gated native path. They must not share a confirmed-block status. |
| Policy contract boundary | `src/policy/wfp_production.zig` says it does not mutate WFP and `submitViaPep` always returns `.unavailable` | Safety stub/support boundary; not an active host-enforcement proof. |
| Dispatcher | `src/policy/dispatcher.zig` runs policy then PEP then forensics; `src/policy/action_dispatcher.zig` logs PEP-validated block and writes forensic data | Operator/evidence path can currently claim success from decision/log flow without a receipt or host postcondition. |
| Native user helper | Root `CMakeLists.txt` builds `src/windows/aegis_wfp.c` and `wfp_ioctl.c` into `aegis_wfp_user` | Native artifact candidate. It contains both PEP-facing IOCTL exports and a separate direct WFP filter API. |
| Kernel driver source | `drivers/wfp_callout/` contains device, IOCTL, callout, filter, and INF sources | Source-only/driver candidate. Root CMake does not include this directory. Driver execution is UNVERIFIED. |
| Shield support | `shield/` exports `aegis_shield_screen`; `rust-src/shield/` documents a quarantined screening helper | Support/screening only. Neither may authorize or mutate WFP. Duplicate naming and historical/quarantined PEP-shaped code require negative-control build checks. |
| Artifacts | `target/helpers/`, `build/`, and `bridge/build/` contain native artifacts/build output | Artifact-only. Presence is not current-head, ABI, signature, load, or host-effect evidence. |

### 3.2 Traced call graph

The source-level candidate graph is:

```text
src/main.zig / build.zig
  -> Zig runtime and policy dispatcher
  -> src/policy/dispatcher.zig
       -> detection/policy
       -> processPEP(...)
       -> src/core/rust_pep.zig::RustPep.execute       [in-memory result path]
       -> forensic trace/write

privileged candidate:
src/core/rust_pep.zig::block_ip/unblock_ip
  -> src/policy/pep_bindings.zig::PepEnforcer
  -> root rust-src/lib.rs::aegis_pep_enforce / aegis_pep_unblock_ip
  -> Windows LoadLibraryW of aegis_wfp_user.dll
  -> aegis_wfp_ioctl_open
  -> DeviceIoControl(0x801/0x803)
  -> \\.\AegisWfpDevice
  -> driver WFP filter operation                         [UNVERIFIED]

separate native path:
src/windows/aegis_wfp.c::aegis_wfp_add_block/remove_filter
  -> FwpmEngineOpen0 / FwpmFilterAdd0 / FwpmFilterDeleteById0
  -> direct user-mode WFP mutation, without a PEP receipt

operator/evidence path:
src/policy/action_dispatcher.zig::dispatch(.block)
  -> log "PEP validated block; WFP enforcement executed by Rust PEP"
  -> ForensicBackend.write(ev)
  -> no receipt validation and no host postcondition check
```

The call graph is not a production proof. In particular, the in-memory path and the native path produce different semantics while using similar `executed`/`block` language.

## 4. File-level observations

### 4.1 Root Rust PEP: ABI and authorization

`rust-src/lib.rs` defines C-layout `PepContext`, `PepRequest`, and `PepResponse` and exports `aegis_pep_init`, `aegis_pep_shutdown`, `aegis_pep_enforce`, `aegis_pep_unblock_ip`, and `aegis_pep_quota_remaining`. The Zig binding tests assert sizes of 24, 64, and 16 bytes and field offsets in `src/policy/pep_bindings.zig`.

The ABI is too small for a privileged host-effect claim. `PepContext` contains `caller_pid`, a caller-supplied `caller_capability_mask`, `request_id`, and `policy_version`; `PepRequest` carries event/network/policy fields; `PepResponse` carries only `decision`, `reason`, `quota_remaining`, and `signed_by`. There is no request nonce, issued timestamp, deadline, runtime generation, policy digest, signature envelope, provider ID, filter ID, postcondition result, trace ID, audit ID, cleanup result, or receipt version. The frozen contract document `shared/abi/pep_abi.md` describes signature/freshness/replay checks, but those checks are not represented by the current request fields and are not implemented in the root PEP call.

`aegis_pep_enforce` checks only whether bit `0x01` is present in `req.ctx.caller_capability_mask` for mutating actions (`rust-src/lib.rs:L361-L369`). It does not obtain or validate a Windows access token, SID, integrity level, process handle, or caller PID. `caller_pid` is merely data supplied in the request. `aegis_pep_unblock_ip` explicitly discards `caller_pid` and `request_id` and checks only the capability bit (`rust-src/lib.rs:L429-L450`). This is not an authenticated capability binding.

The root PEP includes an Ed25519 verification helper and tests for it, but `aegis_pep_enforce` receives no policy bytes, signature, trusted-key identifier, or canonical policy digest. It initializes `signed_by` to zero and returns that value (`rust-src/lib.rs:L350-L356`, `L422-L426`). The separate Zig policy-signing module therefore is not proven to be part of the PEP authorization decision. A policy version number alone is not signed policy state.

`PepState` has a quota map and a pending-approval map, but `two_person_rule` defaults to false, there is no visible API that enables or consumes an approval, and `aegis_pep_enforce` assigns `quota_remaining = QUOTA_DEFAULT` rather than showing a decrement on a successful block. There is no consumed request/nonce set. Reusing the same request ID is not rejected. This leaves replay and freshness **UNVERIFIED and not enforced by this ABI**.

### 4.2 Rust dynamic WFP adapter

The Windows adapter in `rust-src/lib.rs` searches only for `aegis_wfp_user.dll` and `build\\Release\\aegis_wfp_user.dll` (`L228-L245`). It loads by relative name with `LoadLibraryW`, looks up `aegis_wfp_ioctl_open`, `aegis_wfp_ioctl_block_ip`, and `aegis_wfp_ioctl_unblock_ip`, and calls only the integer-returning block/unblock functions (`L248-L283`). It does not use a trusted absolute installation path, verify the DLL signature or hash, perform an ABI version handshake, query a provider identity, retrieve a filter ID, or call a close function before `FreeLibrary`.

For a block, `aegis_pep_enforce` maps any adapter failure to `DECISION_ESCALATE` with reason `4` (`rust-src/lib.rs:L404-L419`). That is safer than returning `ALLOW`, but a zero return from the adapter still means only that the helper accepted the IOCTL. It does not prove the WFP filter exists or that traffic was blocked. The `PepResponse` still has no host-effect field, so the response cannot be converted into a receipt.

### 4.3 Zig `src/core/rust_pep.zig`: accepted-without-host-effect

`RustPep` owns `blocked_ips: std.AutoHashMap(u32, void)` and counters (`L101-L119`). For a blocking decision it inserts `event.source_ip` into that map and returns `.status = .executed`, `.actual_action = decision.action`, and `message = "block executed"` (`L189-L229`). The source comment admits that this is an in-memory blocklist and that a real PEP would call WFP. It is therefore not a host block.

The duplicate case also returns `.executed` with `reason = .duplicate_block` (`L192-L202`). The local tests explicitly assert `.executed` and `isBlocked` for this map (`src/core/rust_pep.zig:L525-L610`), but those tests prove only local bookkeeping. They cannot prove WFP state, provider ownership, cleanup, or network reachability.

The same file exposes `block_ip` and `unblock_ip`, which use `pep_bindings.PepEnforcer` and the native path. `block_ip` returns `true` when the PEP decision is `.block` and comments that Rust PEP owns the WFP side effect (`L325-L367`), but it still returns only a Boolean and has no receipt or postcondition. A caller can therefore lose the distinction between “PEP authorized/provider call returned zero” and “host filter is present and traffic is blocked.”

### 4.4 `src/policy/pep_bindings.zig` and `wfp_production.zig`

`pep_bindings.zig` dynamically loads the root PEP and maps a Rust response to a Zig `PepDecision`. Its tests check structure sizes, offsets, enum values, and that declarations compile. They do not load a real current-head DLL, perform a cross-language ABI conformance test, or verify a receipt. The comment that link resolution happens at link time is not a runtime proof (`pep_bindings.zig:L226-L240`).

`src/policy/wfp_production.zig` deliberately defines a boundary that does not open WFP or mutate filters. `submitViaPep` ignores the request and returns `.unavailable` (`L1-L33`). This is correctly fail-closed, but it also means this module is not a working enforcement implementation. The root runtime must not report it as provider readiness.

`src/policy/action_dispatcher.zig` logs `"PEP validated block; WFP enforcement executed by Rust PEP"` for `.block` and writes a forensic record (`L63-L73`). It receives only a decision enum. It does not require `status == ENFORCED`, `host_effect_confirmed == true`, non-zero filter/request/event/trace/audit IDs, or a supported receipt version. This is a direct accepted-without-host-effect reporting defect.

### 4.5 User-mode WFP helper and IOCTL transport

`src/windows/aegis_wfp.c` directly opens the WFP engine, registers provider `AEGIS-NIDS-Provider` and sublayer `AEGIS-NIDS-Sublayer`, and exposes `aegis_wfp_add_block` and `aegis_wfp_remove_filter`. The add path uses `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, a five-tuple, a process-local `g_next_filter_id`, and `FwpmFilterAdd0` (`L32-L131`). The remove path enumerates at most 256 filters and deletes by returned ID, but ignores the deletion result, returns `0` even when the target was not found, and admits that it has no filter-ID-to-key ownership map (`L134-L155`). `aegis_wfp_close` closes the engine but does not remove filters, provider, or sublayer (`L54-L59`).

These are direct WFP mutation exports in the same native target that the root build calls `aegis_wfp_user`. Even if no current source reference calls `aegis_wfp_add_block`, the exported surface is a bypass candidate and is not protected by a PEP authorization contract. It must be removed, hidden behind the authenticated PEP boundary, or proven unreachable by a negative-control build test.

`src/windows/wfp_ioctl.c` opens `\\.\\AegisWfpDevice` with `GENERIC_READ | GENERIC_WRITE` and no explicit security descriptor or caller authorization (`L42-L78`). It sends IOCTLs `0x800` through `0x803` and blocks/unblocks by an IPv4 value only (`L20-L26`, `L82-L104`). No request ID, policy identity, event identity, signature, filter identity, or ownership token crosses this native boundary.

`src/policy/wfp_ioctl.zig` uses the same textual device endpoint but requests `GENERIC_READ` only and exposes read/stats operations. The root Rust adapter does not use this Zig transport for block; it loads the C helper's `aegis_wfp_ioctl_*` exports. This is a second transport representation that must be consolidated or explicitly separated as read-only telemetry.

### 4.6 Driver, device, and IOCTL ownership

`drivers/wfp_callout/aegis_wfp.h` defines `\\Device\\AegisWfpDevice`, `\\DosDevices\\AegisWfpDevice`, and the same four IOCTL numbers (`L22-L30`). The current source-level user/device-link spelling is internally consistent with `\\.\\AegisWfpDevice`; however, the review found no current-head Windows proof that service `AegisWfp`, the installed SYS, the symbolic link, and the userspace DLL all refer to the same loaded driver. The handoff's earlier `\\.\\AegisWfp` versus `\\.\\AegisWfpDevice` issue therefore remains an **UNVERIFIED stop-the-line deployment risk**, not an accepted fact.

The driver create/close path returns success without visible caller validation. No restrictive SDDL, SID check, integrity-level check, or IOCTL authorization is visible in the inspected device path. A caller able to open the device can reach a mutating IOCTL. `AegisWfpBlockFlow` accepts one `UINT32` IP, creates a filter at `FWPM_LAYER_INBOUND_TRANSPORT_V4`, and stores `g_FilterId` and `g_BlockedIp` as one global active filter (`drivers/wfp_callout/aegis_wfp_comm.c:L73-L141` and `drivers/wfp_callout/aegis_wfp.c:L376-L431`). This does not match the Rust quota/blocklist model or the user helper's ALE_AUTH_CONNECT_V4 five-tuple model.

There are two driver dispatch implementations in the source tree. `drivers/wfp_callout/aegis_wfp.c` dispatches READ, BLOCK, UNBLOCK, and STATS (`L150-L177`). `drivers/wfp_callout/aegis_wfp_comm.c` dispatches READ, BLOCK, and STATS but has no UNBLOCK case (`L170-L204`). The build graph does not establish which implementation is compiled. Root `CMakeLists.txt` has `BUILD_KERNEL_DRIVER` default `OFF` and, when enabled, adds `kernel/wfp_callout`, while the repository source is `drivers/wfp_callout` (`CMakeLists.txt:L64-L68`). A `.sys` file in the directory cannot resolve this source/build mismatch.

The driver unload path removes the single global filter and deletes the device link/device object, but it cannot prove cleanup of filters created through the direct user helper or other process generations. The native and driver paths therefore have incompatible filter ownership and cleanup semantics.

### 4.7 Shield and duplicate authority risk

The root `shield/` crate is a support screening library. `shield/src/lib.rs` exports only `aegis_shield_screen`, and its module comment says it never authorizes and never calls WFP (`L1-L23`). Its `shield/src/pep.rs` contains PEP-shaped names (`PepRequest`, `AUTH_TOKEN_SENTINEL`, `auth_token_is_valid`) but the exported behavior is payload screening only (`L3-L24`). The `auth_token_is_valid` function accepts any non-empty token other than `REPLACE_ME`; this is not authentication and must not be used for privileged authority.

`rust-src/shield/` is a separate nested support/quarantine source tree. Its comments explicitly remove WFP/PEP exports and route enforcement to `rust-src/lib.rs`. That is a useful negative-control intent, but the existence of PEP-shaped `evaluate`, `status`, and `check_permission` functions and separately named Shield crates means the build must prove that only one PEP DLL and one enforcement symbol set can enter the production image. The root support crate is built by a separate Shield Cargo manifest and is not the root PEP. Shield readiness must never be used as PEP or WFP provider readiness.

### 4.8 Policy state, receipts, forensics, and replay

The separate `src/policy/policy_signing.zig` implementation has Ed25519/rollback concepts, and `src/forensic/decision_trace.zig` can hold `pep_request_id`, `enforcement_id`, `audit_id`, policy IDs, event IDs, and trace IDs. These structures do not repair the PEP ABI: the root Rust response has no corresponding fields, and the action dispatcher does not require a finalized receipt before logging a block.

The current `SecurityDecisionTrace` initializes `enforcement_id` and `audit_id` to zero and sets PEP decision separately (`decision_trace.zig:L323-L388`). A forensic record or trace with a PEP decision is not equivalent to a host-effect receipt. The report must therefore classify all current local tests that set `.pep_status = .executed` or compare replay structs as simulation/evidence-model tests, not WFP host-effect proof.

The minimum success contract from the handoff is not met. No inspected active PEP/native response contains all of: supported receipt version, `ENFORCED`, `host_effect_confirmed`, non-zero `filter_id`, `request_id`, `event_id`, `trace_id`, and `audit_id`. Cleanup and rollback results are also absent from the native return path.

## 5. Contract and authority impact

| Contract | Current implementation | Security impact |
|---|---|---|
| PEP ABI | 64-byte request / 16-byte response with caller PID, caller mask, request ID, policy version | Layout is test-covered, but authority context and host-effect evidence are missing. |
| Capability/auth | Caller-supplied bitmask; no OS token/SID/PID binding | Any caller able to reach the boundary may present capability bit `0x01`; privileged authorization is not authenticated. |
| Signed policy | Ed25519 helper/tests exist; enforce ABI receives no bytes/signature/digest; `signed_by = 0` | A valid signature cannot be shown to have governed the action. |
| Freshness/replay | Request ID only; no nonce/deadline/generation/consumed set | Replayed or delayed requests are not rejected by the PEP boundary. |
| Provider result | Integer success/failure from IOCTL adapter | Accepted transport is not proof of filter installation or host effect. |
| Receipt | No active `EnforcementReceipt` returned by PEP/native path | UI/dispatcher can overclaim from decision/log state. |
| Filter ownership | Process-local counter, one driver-global filter, enumeration-based deletion | Stale filters, cross-process deletion, and cleanup ambiguity are possible. |
| Device/IOCTL | User link and driver link text match in source; service/build mapping unresolved; duplicate dispatch sources | Runtime endpoint remains UNVERIFIED; artifacts cannot clear the mismatch. |
| Authority | Root Rust PEP is intended authority, but Zig simulation and direct C WFP APIs coexist | Duplicate enforcement semantics violate the single-authority invariant. |

## 6. Concrete defects and severity

### P0 — Stop-the-line

1. **Accepted without host effect.** `src/core/rust_pep.zig::RustPep.execute` returns `executed` after only an in-memory map insertion (`L189-L229`), and `src/policy/action_dispatcher.zig` logs that WFP enforcement executed from a decision enum (`L69-L73`). This can present a confirmed block without a host block.

2. **No authoritative EnforcementReceipt.** `PepResponse` is only 16 bytes and has no filter/provider/postcondition/forensic linkage fields. No active path returns `host_effect_confirmed`, `filter_id`, receipt version, or cleanup result. This violates the required claim boundary.

3. **Duplicate WFP mutation surface.** `src/windows/aegis_wfp.c::aegis_wfp_add_block/remove_filter` directly mutates WFP independently of Rust PEP. Export presence plus a buildable native target is sufficient to keep this as a bypass risk, even without a current call-site proof.

4. **Unauthenticated mutating device boundary.** The inspected driver create/IOCTL path does not show restrictive SDDL or OS caller identity validation. `wfp_ioctl.c` requests read/write access and sends a raw IP to a mutating IOCTL. This violates the capability/auth binding invariant.

5. **Driver source/build mismatch and duplicate dispatch.** Root CMake does not build `drivers/wfp_callout`; it references `kernel/wfp_callout`. Two driver C implementations disagree on whether UNBLOCK is dispatched. The installed/artifact driver cannot be treated as the source-built provider.

6. **Filter ownership and cleanup are incomplete.** The user helper closes its engine without deleting filters; removal ignores errors and uses an unbounded ownership assumption; the Rust adapter drops the DLL without closing the device or removing filters; the driver tracks one global filter only. Stale filter cleanup is not proven.

### P1 — Must close before any E4/E5 claim

7. **Caller capability is caller-controlled.** The PEP checks `caller_capability_mask & 0x01` but does not derive capability from the Windows token or verify `caller_pid`. `unblock` discards both PID and request ID.

8. **Signed policy is not bound to enforcement.** The PEP signature helper is not called from `aegis_pep_enforce`, and `signed_by` remains zero. `policy_version` is not a signature or digest.

9. **Freshness/replay is absent.** No nonce, issued-at/deadline, generation, or one-time request consumption is in `PepRequest`/`PepContext`; repeated request IDs are not rejected.

10. **Provider identity and postcondition are absent.** A return code from `DeviceIoControl` is accepted as enough for `DECISION_BLOCK`. There is no WFP enumeration tied to a provider GUID/filter owner and no independent reachability test.

11. **Incompatible WFP semantics.** Direct helper uses ALE connect V4 and 5-tuple conditions; driver path uses inbound transport V4 and one remote IPv4; Rust blocklist/quota supports many entries while the driver stores one active filter. A single canonical enforcement contract is not established.

12. **Potential false health/readiness.** Shield/support artifacts and native helper files can be present while the actual Rust PEP DLL, driver, device link, and host filter path are unavailable. Artifact-only readiness must be rejected.

### P2 — Required for release assurance

13. **ABI tests are not DLL conformance tests.** Zig size/offset tests and Rust unit tests do not load the exact current-head DLL and exercise both sides with malformed, stale, replayed, and signed requests.

14. **Failure mapping is incomplete.** Unknown action maps to a reason but transport, authorization, provider, postcondition, receipt, cleanup, and forensic-write failures are not separate typed outcomes at the PEP/native boundary.

15. **Audit identity is not completed by enforcement.** Existing decision traces can carry IDs, but the native path does not return or set provider/filter identity, and the dispatcher writes evidence without validating finalized host effect.

## 7. Missing tests and proofs

The following evidence is missing or must be rerun against HEAD `46b93dcf...`:

- A Windows x64 build from the current commit for root Zig, root Rust PEP DLL, Shield support crate, CMake helper, and the actual WDK driver source. The build graph must prove exactly which `drivers/wfp_callout` source is compiled.
- ABI conformance against the exact DLL: `sizeof`, offsets, calling convention, symbol version, invalid pointers, short buffers, unknown action, invalid capability, stale policy, malformed signature, and error-code mapping.
- Authenticated caller proof: elevated authorized caller, standard user, low-integrity process, wrong SID, spoofed PID, and a caller that presents capability bit `0x01` without the required token.
- Signed-policy proof: valid Ed25519 policy, wrong key, unsigned policy, altered bytes, expired policy, rollback, policy digest mismatch, and proof that the accepted digest appears in the receipt and forensic record.
- Freshness/replay proof: duplicate `(request_id, nonce)`, reused request ID with a new payload, expired deadline, future timestamp, restart-generation reuse, and concurrent duplicate requests.
- Provider/device preflight: service name, image path, signer, device object, DOS link, IOCTL table, WFP provider GUID, sublayer GUID, filter owner, architecture, and DLL dependency resolution.
- Negative device/ACL proof: standard user cannot open or mutate `\\.\\AegisWfpDevice`; read-only telemetry cannot invoke block/unblock; malformed IOCTL cannot create a filter.
- Real host-effect proof in isolated VMware VMnet1: target reachable before block, unreachable during block, filter identity captured, receipt and forensic linkage validated, filter removed, target reachable after cleanup, and no stale AEGIS filter remains.
- Failure-injection proof: missing DLL, missing driver, wrong device, provider error, ambiguous response, filter ID zero, host postcondition false, receipt write failure, forensic write failure, cleanup failure, and restart during an active filter all remain non-confirmed and fail closed.
- Cross-path negative-control proof that Shield symbols, direct helper exports, test fixtures, and legacy dispatcher paths cannot mutate host filtering state.
- Lifecycle recovery after enforcement: old runtime exits, handles and device are released, filters are cleaned, new generation starts, and no stale ownership remains.

## 8. Prioritized fixes

### P0 — Make false success impossible

1. Remove or quarantine `RustPep.execute` from any production block claim. Rename its result to simulation/decision-recording semantics, or require a real PEP receipt before any `.executed` value can reach dispatcher, health, forensic finalization, or UI.
2. Define one canonical `EnforcementReceipt` ABI. At minimum include version, status, host-effect confirmation, request/event IDs, trace/audit IDs, signed policy digest/version, provider identity, filter ID, target tuple, runtime generation, postcondition observation, cleanup result, and typed failure reason.
3. Delete or make non-exported all direct WFP mutation APIs in `src/windows/aegis_wfp.c`. Keep only an authenticated adapter implementation owned by Rust PEP. Add a static negative-control test that fails if direct Fwpm mutation is reachable outside the PEP-owned module.
4. Select one driver implementation and correct the CMake source path. Do not ship or load the existing SYS until the source-to-driver build manifest is current and reproducible.
5. Add restrictive device security and OS identity validation at the driver boundary. Derive capability from the authenticated Windows token; do not trust PID, role, or capability values supplied by the client.
6. Implement an ownership ledger keyed by provider GUID, runtime generation, request ID, and filter ID. Cleanup must delete only owned filters, verify deletion, and return failure if any owned filter remains.

### P1 — Freeze the authority contract

7. Expand the PEP request with canonical signed policy bytes/digest, signature/key ID, nonce, issued-at, deadline, runtime generation, caller identity binding, and schema/ABI version. Reject unknown, expired, reused, or rollback-invalid requests before provider mutation.
8. Make the Rust PEP return `ENFORCEMENT_UNAVAILABLE`, `ENFORCEMENT_FAILED`, or `POSTCONDITION_FAILED` rather than an ambiguous decision when provider or host effect is not proven.
9. Have the native adapter return the actual WFP filter ID and provider identity, then independently query the WFP engine or perform a controlled target postcondition check. A zero filter ID or missing postcondition must never produce `ENFORCED`.
10. Make action dispatcher, forensic finalization, health, CLI, and UI consume only a validated receipt. Log intent and decision separately from confirmed host effect.
11. Consolidate the two WFP transports and explicitly mark `src/policy/wfp_ioctl.zig` as read-only telemetry if it is retained. Remove the one-filter driver limitation or make the canonical policy explicitly single-filter and prove its concurrency/cleanup semantics.

### P2 — Prove and package

12. Add current-head ABI harnesses and Windows integration tests to CMake/Cargo/Zig CI. Tests must use the built DLL and driver, not only source-level layout assertions.
13. Add a Shield quarantine negative-control that fails if any PEP/WFP export or linked direct WFP symbol appears in the support crate.
14. Regenerate and verify truth artifacts at HEAD. Treat `build_truth.json` metadata that names a different commit as stale until regenerated.
15. Add clean-install, signature, dependency, upgrade, rollback, uninstall, and lifecycle recovery evidence. Keep the prevention gate closed until all host-effect and cleanup evidence passes.

## 9. Exact Windows-only verification commands

The following commands are intentionally verification instructions, not evidence that they have passed. Run them from an elevated **Windows x64** terminal on a disposable host. Replace only the confirmed target address and port after the isolated lab owner approves them.

### 9.1 Current-head and clean build

```powershell
Set-Location -Path 'D:\NIDs_Windows'
git rev-parse HEAD
git status --short --untracked-files=all

zig build
zig build test

cargo test --release --manifest-path .\Cargo.toml
cargo build --release --manifest-path .\Cargo.toml

cargo test --manifest-path .\shield\Cargo.toml
cargo build --release --manifest-path .\shield\Cargo.toml

cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DBUILD_KERNEL_DRIVER=OFF
cmake --build build --config Release

cmake -S .\bridge -B .\bridge\build -G "Visual Studio 17 2022" -A x64
cmake --build .\bridge\build --config Release
```

**Expected gate:** the build must identify the exact root PEP DLL and helper DLL used by the Zig executable. A successful Shield build must be recorded as support-only, not PEP readiness.

### 9.2 Artifact, export, dependency, and signature inspection

```powershell
Get-FileHash .\target\release\aegis_pep.dll -Algorithm SHA256
Get-FileHash .\build\Release\aegis_wfp_user.dll -Algorithm SHA256
Get-AuthenticodeSignature .\target\release\aegis_pep.dll | Format-List
Get-AuthenticodeSignature .\build\Release\aegis_wfp_user.dll | Format-List

& "$env:VSINSTALLDIR\VC\Tools\MSVC\$((Get-ChildItem "$env:VSINSTALLDIR\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1).Name)\bin\Hostx64\x64\dumpbin.exe" /exports .\target\release\aegis_pep.dll
& "$env:VSINSTALLDIR\VC\Tools\MSVC\$((Get-ChildItem "$env:VSINSTALLDIR\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1).Name)\bin\Hostx64\x64\dumpbin.exe" /exports .\build\Release\aegis_wfp_user.dll
& "$env:VSINSTALLDIR\VC\Tools\MSVC\$((Get-ChildItem "$env:VSINSTALLDIR\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1).Name)\bin\Hostx64\x64\dumpbin.exe" /dependents .\build\Release\aegis_wfp_user.dll
```

The exported surface must not include an ungoverned direct WFP mutation API. If `aegis_wfp_add_block` or equivalent direct mutation exports remain, stop the release.

### 9.3 Service, driver, device, and endpoint preflight

```powershell
sc.exe query AegisWfp
sc.exe qc AegisWfp
Get-CimInstance Win32_SystemDriver -Filter "Name='AegisWfp'" | Format-List Name,State,PathName,StartMode,ServiceType
pnputil.exe /enum-drivers | Select-String -Pattern 'AEGIS|aegis_wfp' -Context 2,4

netsh wfp show filters file=$PWD\wfp-before.xml
Select-String -Path .\wfp-before.xml -Pattern 'AEGIS|AegisWfp|AEGIS-NIDS' -Context 2,3

Get-Item -LiteralPath '\\.\AegisWfpDevice' -ErrorAction Stop
```

The last command must resolve the same device link that `src/windows/wfp_ioctl.c` and `src/policy/wfp_ioctl.zig` use. If it fails, provider readiness is false regardless of DLL/SYS presence.

### 9.4 Runtime preflight and closed gate

```powershell
Start-Process -FilePath .\zig-out\bin\aegis_nids.exe -Verb RunAs
Start-Sleep -Seconds 3

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_host_production_preflight.ps1 `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

Before host-effect testing, require `runtime_available=true`, `pep_ready=true`, worker readiness, forensic verification, `host_effect_capable=false` until the proof is complete, and `overall_gate=false` until all receipt and cleanup checks pass. A timeout or missing endpoint is a failed preflight, not readiness.

### 9.5 Isolated host-effect proof — only after explicit authorization

Use only the confirmed VMnet1 target, not Wi-Fi, NAT, localhost, the VMware gateway, or a production address. The variables below are placeholders until the lab owner confirms them.

```powershell
$Target = '192.168.126.20'
$Port = 3389
$Before = Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Detailed
$Before | Format-List

# Send one authorized block request through the authenticated daemon control path.
# Do not call netsh, firewall APIs, or the WFP device directly as a substitute.
 .\tools\aegisctl.py status --json
 .\tools\aegisctl.py block --target $Target --port $Port --json

Start-Sleep -Seconds 2
$During = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
$During | Format-List
netsh wfp show filters file=$PWD\wfp-during.xml
Select-String -Path .\wfp-during.xml -Pattern 'AEGIS|AegisWfp|AEGIS-NIDS' -Context 2,4

# Validate the structured receipt and forensic linkage before cleanup.
 .\tools\aegisctl.py receipts --json
 .\tools\aegisctl.py forensic verify --json

# Remove only through the same authorized control path.
 .\tools\aegisctl.py unblock --target $Target --port $Port --json
Start-Sleep -Seconds 2
$After = Test-NetConnection -ComputerName $Target -Port $Port -WarningAction SilentlyContinue
$After | Format-List
netsh wfp show filters file=$PWD\wfp-after.xml
Select-String -Path .\wfp-after.xml -Pattern 'AEGIS|AegisWfp|AEGIS-NIDS' -Context 2,4
```

The proof passes only if the target is reachable before block, blocked during the authorized action, the receipt contains a real provider/filter identity and host postcondition, forensic linkage validates, the target is reachable after cleanup, and no owned AEGIS filter remains. If any step is unavailable, ambiguous, or cleanup fails, classify the result as `ENFORCEMENT_UNAVAILABLE` or `ENFORCEMENT_FAILED`, never `BLOCKED_CONFIRMED`.

### 9.6 Negative authorization and replay checks

Run from a standard-user and low-integrity test process, not from the elevated proof terminal:

```powershell
# The project must provide a test harness that sends these exact negative cases.
python .\tests\pep\run_negative_pep_harness.py `
  --case spoofed-pid `
  --case-capability-mask 1 `
  --case replay-request `
  --case expired-deadline `
  --case unsigned-policy `
  --case wrong-policy-key `
  --case standard-user-device-open

netsh wfp show filters file=$PWD\wfp-negative-after.xml
Select-String -Path .\wfp-negative-after.xml -Pattern 'AEGIS|AegisWfp|AEGIS-NIDS'
```

If `run_negative_pep_harness.py` does not exist at verification time, that absence is a missing proof and the gate remains closed; it must not be replaced with a source flag or artifact listing.

## 10. Final review state

The architecture intent—Zig as runtime owner, Rust PEP as sole enforcement authority, Shield as screening-only, and fail-closed provider unavailability—is visible in comments and some source-level tests. The implementation currently falls short of the required authority and evidence contract because a local Zig model can report a block without a host effect, direct WFP APIs remain exposed, caller capabilities are not OS-bound, signed policy is not bound to the PEP request, freshness/replay is absent, and the native driver/build/cleanup graph is unresolved.

**Production prevention is not approved.** The system may be evaluated as detection-only or degraded until P0 findings are closed and the Windows isolated host-effect, receipt, cleanup, recovery, and release proofs pass against the reviewed current HEAD.

## References

[1]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/rust-src/lib.rs "Root Rust PEP implementation"
[2]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/core/rust_pep.zig "Zig PEP/WFP integration and local enforcement model"
[3]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/pep_bindings.zig "Zig-to-Rust PEP ABI bindings"
[4]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/aegis_wfp.c "User-mode direct WFP helper"
[5]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/wfp_ioctl.c "User-mode WFP device IOCTL helper"
[6]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/drivers/wfp_callout/aegis_wfp.h "Kernel WFP device and IOCTL header"
[7]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/drivers/wfp_callout/aegis_wfp_comm.c "Kernel WFP communication and mutating IOCTL path"
[8]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/CMakeLists.txt "Native CMake build graph"
[9]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/shared/abi/pep_abi.md "Declared PEP ABI contract"
[10]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/action_dispatcher.zig "Policy action dispatcher and enforcement logging"
[11]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/forensic/decision_trace.zig "Forensic decision trace contract"
[12]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/Cargo.toml "Root Rust PEP Cargo manifest"
[13]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build_truth.json "Declared build truth and artifact classification"
[14]: file:///mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/runtime_manifest.json "Declared runtime manifest and open gaps"
