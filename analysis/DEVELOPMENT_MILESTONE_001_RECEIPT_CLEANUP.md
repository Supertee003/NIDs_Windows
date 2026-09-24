# AEGIS Development Milestone 001 — Receipt and Cleanup Invariants

**Date:** 2026-09-23  
**Mode:** Observe-only / prevention gate closed  
**Host mutation:** Not executed

## Implemented

The control path now requires `event_id` and `trace_id` before it can construct a linkable enforcement receipt. After the Rust PEP returns a filter ID, the Zig handler performs an exact filter query and compares provider status, destination IPv4, destination port, and protocol. It returns `ENFORCED` only after the complete receipt v1 object validates. If the query or tuple comparison fails, cleanup is attempted and the request fails closed.

The filter query boundary now preserves three states: `present`, `absent`, and `query_error`. The Rust adapter and export copy an exact absent state through the FFI instead of collapsing it into an error. Unblock now performs a second query using the same receipt filter ID and returns `ROLLED_BACK` only when `present=false` is proven. A present filter or query error produces `ROLLBACK_PENDING` / `CLEANUP_POSTCONDITION_FAILED`.

The Zig receipt contract now rejects an `enforced` receipt with `policy_id=0` or a decision other than `block`. The Python control API mirrors the new linkage requirement and no longer treats the legacy `CLEANED` status as success.

## Files changed

| Layer | File | Change |
|---|---|---|
| Control | `src/control/handler_registry.zig` | Exact post-block query, complete receipt fields, rollback-on-failure, post-cleanup absence check |
| Contract | `src/policy/enforcement_receipt.zig` | Stronger v1 validation and regression tests |
| FFI | `src/policy/pep_bindings.zig` | Tri-state filter query result |
| Rust PEP | `rust-src/lib.rs` | Preserve absent filter state across adapter/export boundary |
| Python API | `tools/aegisctl/api/control_api.py` | Require event/trace linkage and accept only verified `ROLLED_BACK` cleanup |

## Validation completed in Linux sandbox

- Python compilation passed for `tools/aegisctl/api/control_api.py`.
- Python compilation passed for `brain/enforcement_receipt.py`.
- Static invariant checks passed.
- Negative control test passed: a block request without `event_id` and `trace_id` is rejected before any daemon request.
- No prevention gate was opened and no WFP mutation was executed.

The sandbox does not contain the Zig, Rust, Go, CMake, or Windows Driver Kit toolchains, so native compilation and provider behavior remain unverified.

## Windows Admin PowerShell validation

Run from the source root. These commands are compile and negative/observe-only checks; they do not open the prevention gate or issue a valid block request.

```powershell
Set-Location D:\NIDs_Windows

python -m py_compile tools\aegisctl\api\control_api.py
python -m py_compile brain\enforcement_receipt.py

python -m pytest tests\runtime\test_operator_contracts.py -q
python -m pytest tests\runtime\test_health.py -q
python -m pytest tests\pep\test_t8_rust_pep.py -q
python -m pytest tests\wfp\test_t11_wfp_enforcement.py -q
python tools\aegisctl.py rules validate

zig build test -Doptimize=Debug
powershell -ExecutionPolicy Bypass -File scripts\wdk_build_production.ps1
```

After the compile gates pass, rebuild the user bridge and RC. Do not run the old direct ctypes host proof and do not open the prevention gate. Capture the complete output, including the first failing command if any.

## Next required implementation gate

The next source milestone is to replace the current driver-owned shadow query with provider enumeration/read-back and to resolve persistent-versus-dynamic filter ownership across restart. Only after that Windows/WDK gate passes should the approved isolated proof be considered. The proof must use a single exact scope and must produce a complete receipt, exact tuple match, benign probe result, receipt-ID cleanup, and provider-backed `present=false` postcondition.

## Windows result update

The first Windows run confirmed that Python tests, the 22-rule validation, and the WDK driver build pass. The query ABI test first reported 24 bytes and, after changing the Zig type to `packed struct`, reported 32 bytes. This confirms that relying on Zig packed-field layout is unsafe for this cross-language boundary.

The ABI representation has therefore been changed to an explicit `extern struct { bytes: [20]u8 }` with accessor methods for the documented offsets. Rust remains `#[repr(C, packed)]`, and the handler uses the accessors rather than direct fields. The expected layout is now explicit: `filter_id` at 0, `remote_ipv4` at 8, `remote_port` at 12, `protocol` at 14, `present` at 15, and `provider_status` at 16.

Run the Zig test suite again. If the ABI test passes and only the `wire_event` test remains, isolate that test with the project's Zig test filtering mechanism before changing its validator semantics. No host mutation should be performed until the complete test suite and native ABI gates pass.

## Provider-backed query update

The WFP driver query path now opens the provider engine and calls `FwpmFilterGetById0` for the requested filter ID. It validates the actual provider object, ALE connect layer, block action, and exact remote IPv4/port/protocol conditions. Driver globals are no longer used as proof of filter presence or tuple identity. The existing `g_FilterId` guard in unblock remains intentionally unchanged until an explicit provider ownership marker is added; this preserves fail-closed cleanup while restart-safe ownership is developed.

The WDK build must be rerun after this driver-only change. No driver installation or host mutation is required for this compile gate.

## WDK compatibility correction

WDK 10.0.28000.0 compiled `FwpmFilterGetById0` but did not expose the user-mode symbolic macro `FWP_E_FILTER_NOT_FOUND` through the kernel headers. The driver now defines a guarded compatibility macro with the documented value `0x80320003` only when the header does not provide it. Other provider errors remain query errors; only the documented not-found result is converted to an explicit absent state.

## Persistent ownership marker update

The proof filter now receives a stable `AEGIS_PROOF_FILTER_KEY`. Provider-backed query requires that marker in addition to the ALE connect layer, block action, and exact tuple. Unblock reads the provider object and refuses deletion when the marker does not match, rather than relying only on the in-memory `g_FilterId`. This is the first restart-safe ownership boundary; filter-ID recovery and separation from the capture filter ID remain a follow-up lifecycle task.

## Filter ID lifecycle separation

The driver now maintains `g_CaptureFilterId` for the callout capture filter and `g_ProofFilterId` for receipt-owned persistent proof filters. Callout registration/unregistration no longer overwrites or deletes the proof filter ID. Proof cleanup continues to use the receipt ID plus provider ownership marker. Runtime recovery and multiple-proof-filter policy remain pending until this separation compiles on the target WDK.

## Persistent proof-filter recovery

Callout registration now queries `FwpmFilterGetByKey0` using the stable proof filter key. If the persistent filter exists, its provider-assigned ID is recovered into `g_ProofFilterId`; the driver does not delete or recreate it. A missing key is treated as normal, while other provider errors abort registration. This prevents a restart from losing the in-memory proof ID or creating a duplicate proof filter without first resolving the existing receipt.

## ETW native ABI correction

The ETW callback boundary was corrected to use an explicit `NativeEtwEvent` mirror of the C `aegis_etw_event_t` layout. The native record now carries the provider GUID, and Zig converts it into the richer internal `EtwEventRecord` before invoking consumers. A compile-time 80-byte size guard prevents future C/Zig layout drift. This is a prerequisite for trustworthy kernel process/file telemetry; provider GUID/event decoding still requires Windows runtime evidence before rules are promoted.

## Test-output analysis and receipt postcondition guard

The Windows test output is consistent with the fail-closed contract: WFP telemetry transport opens and closes successfully; non-enforcing action paths complete; block and quarantine requests remain unconfirmed without a validated receipt; and legacy Boolean `block_ip`/`unblock_ip` remain unavailable by design. A receipt verifier was added to the Zig PEP bindings. It accepts `BLOCK` confirmation only when the receipt has a nonzero filter ID and provider read-back reports the same filter ID, destination IPv4, destination port, protocol, and `present` state. The verifier rejects absent, query-error, incomplete, or mismatched receipts.

## Receipt handoff into production pipeline

The production event processor now passes the receipt produced by its existing `PepEnforcer.enforce()` call into `ActionDispatcher.dispatchWithReceipt()`. The dispatcher verifies the provider postcondition and emits `BLOCKED_CONFIRMED` only on an exact match. It does not call `enforceFlow()` or invoke PEP a second time, preventing duplicate WFP filters. The legacy dispatcher remains available for tests and continues to report unconfirmed host effect when no receipt is supplied.

## ETW TDH property decoding

The native ETW helper now decodes an allow-listed set of event properties through TDH (`ImageName`, `CommandLine`, `FileName`, `KeyName`, and `ParentId`). Properties are converted to bounded UTF-8 or u32 values and packed into a length-delimited `AEGT` TLV payload. The Zig callback decodes this payload into `EtwEventRecord` fields before invoking consumers. Payload size is bounded by both the helper buffer and the uint16 ABI field; malformed or unknown TLVs are ignored. A host-side Zig unit test covers image and parent PID decoding. The sandbox does not contain the Zig executable, so Windows validation must compile the native helper and run the unit/integration tests on the user's machine.

## Zig 0.13 decoder compatibility correction

Windows compilation exposed that Zig 0.13 `std.mem.readInt` requires a fixed-size array pointer rather than a byte slice. The TLV decoder was changed to explicit little-endian byte helpers for u16/u32 parsing, and its unit-test payload construction no longer uses slice-based `writeInt`. This preserves the wire format while removing alignment/API-version dependence.

## Provider-gated ETW event classification

The production ETW callback now gates event-ID mapping by provider GUID. Process IDs 1/2 are classified as process events only for the kernel process provider; file IDs 0x0A/0x0B only for the kernel file provider; registry IDs 0x0E/0x0F only for the kernel registry provider. Unknown provider/event combinations are dropped rather than defaulting to process creation. This prevents cross-provider event-ID collisions from poisoning host correlation.

## ETW canonical metadata handoff

The ETW callback now reserves a monotonic AEGIS event identity independently of the provider-local ETW event ID. It also sets `IpcEvent.payload_len` and `payload_hash` from the exact bounded payload copied into the pipeline queue, preventing forensic metadata from overstating retained evidence. Provider-gated classification and payload metadata now occur before enqueue.

## Pre-attack readiness scan

A deterministic scanner validated the 22-rule qualification matrix against the 22-rule fixture manifest. The scan passed with exact rule-ID parity, inactive `synthetic_observe_only` mode, the required no-network/no-executable/no-mutation/no-enforcement safety contract, and a closed global prevention gate. Coverage is distributed across L7 (4), L4 (3), KERNEL_FILE (5), KERNEL_PROCESS (5), and L2_PIPE (5). All 22 rules remain gated by sensor-specific proof blockers; 18 are pending proof and 4 are detect-only. This result authorizes artifact-level preparation only, not attack execution or prevention promotion.

## KERNEL_FILE / FIM proof preparation

The synthetic R1001-R1005 canary initially exposed two issues: a malformed test path fixture for R1001 and an actual R1005 false positive where `hosts.bak` matched `hosts`. The fixture was corrected and the R1005 regex was tightened to exact filename semantics in both `configs/Rules.json` and the fixture manifest. The canary now passes all five positive/negative cases.

The FIM adapter was also extended with watch-root identity tracking. Parsed relative paths are qualified into full canonical Windows paths before queueing, and the handle-to-rule mapping remains correct when a watcher fails to start and handles are compacted. Full E2E qualification remains pending Windows host evidence capture; no System32/hosts/Startup mutation or enforcement request was performed.

## KERNEL_PROCESS / ETW proof preparation

The synthetic process canary initially exposed a real R2004 false positive: a generic `tool.exe -f input.txt` matched the previous pattern. The rule and manifest now require `certutil.exe` together with a download-abuse option (`-urlcache` or `-f`) in the same command line. R2001-R2005 positive and benign command-line cases now pass.

The ETW process conversion regression test now verifies `ImageName`, `CommandLine`, `ParentId`, PID, and process-create classification. No malicious process, credential tool, download, URL, or enforcement action was executed. Full process-sensor qualification remains pending Windows ETW evidence capture and canonical/forensic proof.

## L2_PIPE proof preparation

The synthetic named-pipe canary passed all five R3001-R3005 cases in both the native prefix matcher and configured rule regex layer. Source review found that `pipe_monitor.zig` currently emits log alerts only and does not enqueue canonical events into the detector/event fabric. Therefore matching is qualified, but sensor-to-pipeline and forensic proof remain blocked. No named pipe, remote-execution tool, or enforcement action was used.

## L2_PIPE event-fabric adapter

The pipe monitor now publishes a bounded observation-only `IpcEvent` with a dedicated `capture_pipe_monitor` source and pipe-name payload after native prefix matching. The existing Aho-Corasick pipeline can consume this payload and assign the matched rule before policy and forensic stages. An ASCII-bounded encoder and regression test were added. The Linux sandbox lacks Zig, so the user's Windows Zig 0.13 build must verify the adapter and queue linkage before host validation. No named pipe or remote-execution tool was created.

## Pipe queue regression coverage

A deterministic Zig regression test now drains prior queue state, publishes an `MSSE-PROOF` observation, and verifies `signature_match`, `capture_pipe_monitor`, bounded payload bytes, payload length, and FNV payload hash. This proves the adapter-to-queue boundary without creating a named pipe or invoking policy enforcement. The test must be run with the Windows Zig 0.13 toolchain.

## Zig module-boundary correction

Windows Zig 0.13 direct testing rejected the capture module's sibling `pipeline/event_queue.zig` import as outside the direct module path. The adapter was corrected to use an injected publisher callback. `pipe_monitor.zig` now remains directly testable, while `nids_main.zig` installs `event_queue.pushEvent` for production. The direct regression test verifies event kind, source, bounded payload, length, and hash through a local callback. No event semantics or frozen ABI size changed.

## Direct-module import correction: local observation contract

The direct Zig test then rejected the capture module's import of `contract/event.zig` as outside the module path. The capture module is now fully decoupled from the frozen event contract: it emits a local `PipeObservation` through the injected publisher callback. `nids_main.zig` converts that observation into `IpcEvent` and forwards it to `event_queue.pushEvent`. This preserves production semantics while allowing direct Zig 0.13 testing without sibling imports.
