# Eight-Group Run Findings — 2026-09-22

## Evidence quality

The submitted output was not a single clean run. The actual `run.log` contains three final counters, eleven group markers, and a final marker before later group sections. The original runner reused the same timestamp-only output directory, so concurrent invocations interleaved their output and caused false failures.

## Real failure

The only confirmed source failure in the actual log was Shield compilation:

```text
error[E0599]: no method named `len` found for reference `&u8`
error[E0608]: cannot index into a value of type `&u8`
```

`shield/src/lib.rs` used `ptr.as_ref()`, which produces `Option<&u8>` rather than a byte slice. The implementation was changed to reject null and oversized inputs and construct a bounded slice with `std::slice::from_raw_parts`. Regression tests now cover null, oversized, and benign FFI payloads.

## False failures caused by the overlapped run

The first interleaved section reported missing files such as `tests/runtime/test_golden_path.py`, `tests/cython/test_cython_correctness.py`, and `tests/policy_signing/test_t7_signed_policy.py`. The same log later shows those exact tests passing. It also reported `tools/aegisctl.py` under `D:\NIDs_Windows\nose`, proving that one concurrent process had the wrong working directory while another process was writing the shared log.

The runner was corrected to:

1. acquire `analysis/.eight-groups-run.lock`;
2. refuse a second active run;
3. use a timestamp plus random suffix for each output directory;
4. explicitly return to the repository root after Go Nose tests.

## Valid positive evidence from the actual log

- Provenance tools were found: Python, Cargo, Zig 0.13, Go, Node, and npm.
- Zig unit tests passed.
- Runtime health tests passed: 42 tests.
- WFP observe-only proof passed with the device opened using `GENERIC_READ`.
- The WFP proof requested only `GET_STATS` and `READ_EVENTS`; no block/unblock operation was issued by the script.
- WFP readback produced 47,616 complete 44-byte frames with no trailing bytes in the captured batch.
- FIM observe-only fixture proof passed, but it explicitly states that it proves file creation only and requires daemon counters/provenance/forensics for a real sensor proof.
- Host telemetry tests passed: 9 tests.
- Health semantics tests passed: 21 tests.
- Rust PEP passed: 19 passed, 1 intentionally ignored provider proof.
- PEP Python contract tests passed: 11 tests.
- Signed policy tests passed: 10 tests.
- Cython correctness tests passed: 16 tests.
- Detection integration tests passed: 37 passed, 3 skipped.
- TypeScript typecheck, safety, and cross-language contract tests passed.

## Safety conclusion

The run continues to support observe-only development. It does not establish production IPS acceptance. The WFP output is telemetry/readback evidence, not an EnforcementReceipt host-effect proof. `prevention_gate` remains closed.

## Next Host command

Run only the corrected runner once from an elevated Command Prompt:

```cmd
cd /d D:\NIDs_Windows
cmd /c scripts\run_eight_groups_safe.cmd
```

If it refuses because of `.eight-groups-run.lock`, verify no other run is active before removing that lock directory. Return the new `run.log` path and final `PASS/FAIL/SKIP` line.

## References

[1]: analysis/EIGHT_GROUP_STATUS.md "Eight source-analysis groups"
[2]: shield/src/lib.rs "Shield FFI boundary"
[3]: scripts/run_eight_groups_safe.cmd "Safe Host runner"
[4]: scripts/run_wfp_l4_observe_only_proof.ps1 "WFP observe-only proof"
[5]: scripts/run_fim_real_observe_only_proof.ps1 "FIM observe-only proof"
