# AEGIS Deep System Health Audit

**Date:** 2026-09-27  
**Scope:** Current repository at HEAD `7623d1cf08f9e7dc0768d1043f458cb7fa100c35`  
**Audit mode:** Read-only source, contract, static, truth, and Python verification

## Executive result

AEGIS is not showing evidence of a broken primary architecture. The authority-boundary tests, receipt tests, WFP static architecture tests, lifecycle-health tests, and contract tests passed as a selected suite of **90 tests**.

However, the project is not yet clean enough to call Production-ready. The audit found several blockers and risks:

1. The sandbox has no Zig, Go, Rust, or Cargo toolchain, so native build verification was not possible here.
2. `AGENTS.md` still declares an old HEAD `48eb2a72...`, while current generated truth is HEAD `7623d1cf...`. The truth verifier passes its own configured artifact set, but the project instruction file is contradictory and violates the stop-line rule for stale truth.
3. Full Python compilation fails in `tools/legacy/fix_console.py` due to an unterminated f-string. It is under a legacy directory, but a repository-wide compile gate cannot pass until it is fixed, excluded explicitly, or removed from the production verification surface.
4. Targeted Python AST parsing finds UTF-8 BOM characters in `brain/__init__.py`, `scripts/aegis_daemon.py`, and `scripts/tests/aegis_nose_test.py`. Python may execute some BOM files, but the source-quality gate is not clean.
5. The audit could not verify live Windows health, Npcap, service/device state, WFP provider readiness, or host-effect postconditions from the sandbox.
6. Existing authority documents contain legacy-path terminology such as `core/canonical_event.zig` and a `shield/` state that must be reconciled against the current source and current manifest. Matching HEAD SHA is necessary but not sufficient for semantic truth.

Therefore the accurate status is:

```text
Primary authority boundaries          PASS at selected static/test level
Receipt fail-closed semantics         PASS at selected static/test level
Truth verifier                        PASS for its configured artifacts
Selected Python test suite             90 passed
Native build verification              NOT RUN in sandbox
Repository-wide Python compile         FAIL
Current Windows runtime                NOT VERIFIED in this audit
WFP host effect                        NOT PROVEN
Production-ready                      NO
```

## Evidence that passed

### Truth artifacts

`python tools/truth.py verify` returned:

```text
TRUTH_VALID — all artifacts carry current HEAD
```

The following machine maps report the current HEAD:

```text
SYSTEM_MAP.json
FLOW_MAP.json
AUTHORITY_MAP.json
CONTRACT_MAP.json
EVIDENCE_INDEX.json
build_truth.json
runtime_manifest.json
```

The runtime manifest contains 61 modules, and all `canonical_path` values resolved to files during this audit.

### Selected tests

Command:

```bash
python -m pytest tests/security tests/contracts \
  tests/runtime/test_health.py \
  tests/runtime/test_lifecycle_authority.py \
  tests/runtime/test_rust_shield_lifecycle.py \
  tests/wfp/test_t11_wfp_enforcement.py -q
```

Result:

```text
90 passed in 252.73s
```

This is strong evidence for the selected Python-level contracts. It is not evidence of a successful native Windows build or real WFP host effect.

### Authority boundaries inspected

The static tests enforce these important constraints:

- Go Nose does not call PEP or WFP.
- Python brain and CLI do not directly execute firewall mutation.
- C/C++ adapters do not make policy decisions.
- Zig has one declared PEP FFI surface.
- TypeScript has no native enforcement dependency.
- The legacy bridge block/unblock functions remain fail-closed.
- No Zig module directly calls the privileged WFP transport.
- A complete receipt is required before confirmed enforcement.
- A receipt without host effect, filter identity, or forensic identity is rejected.

### Receipt semantics

The current receipt checks distinguish:

```text
policy decision       != host effect
PEP response          != host postcondition
ENFORCED              requires host_effect_confirmed
confirmed block       requires filter/request/event/trace/audit linkage
```

This boundary is structurally healthy in the inspected code and selected tests.

## Findings requiring action

### Finding F-001 — Native toolchains unavailable in sandbox

The sandbox did not contain `zig`, `go`, `rustc`, or `cargo`. Therefore these commands were not executed here:

```text
zig build
zig build test
go test ./...
cargo test
cmake --build build
```

This is an environment limitation, not proof of source failure. Windows-side build evidence is mandatory because the product depends on Windows APIs, Npcap, DLL loading, named pipes, WFP IOCTLs, and elevated privileges.

**Required Windows evidence:** record command, exit code, compiler versions, artifact paths, and binary hashes.

### Finding F-002 — AGENTS.md stale HEAD declaration

`AGENTS.md` declares:

```text
48eb2a72265a15c1b780a6bfa76d4f4dae2fc7f2
```

The repository HEAD and current generated truth are:

```text
7623d1cf08f9e7dc0768d1043f458cb7fa100c35
```

The truth verifier does not treat the AGENTS header as one of its ten checked artifacts, so `TRUTH_VALID` does not clear this contradiction. Under the project's own stop-line rule, stale source-of-truth instructions must be corrected or explicitly marked historical before further patching.

**Required action:** update `AGENTS.md` through the project's approved truth-generation/change-control process. Do not manually edit generated hashes if a generator owns the field.

### Finding F-003 — Repository-wide Python compilation fails in legacy file

The command:

```text
python -m compileall -q brain tools tests shared scripts
```

failed at:

```text
tools/legacy/fix_console.py:95
SyntaxError: unterminated string literal
```

This file is in `tools/legacy`, so it may not be part of the production runtime. Nevertheless, the repository-wide compile command is not clean. The project must choose one explicit policy:

- fix the legacy file;
- exclude `tools/legacy` from the official compile gate and document that exclusion;
- or remove/archive the broken file outside the source tree.

Silently ignoring the failure is not acceptable because the project requires explicit truth about production and legacy surfaces.

### Finding F-004 — UTF-8 BOM in Python files

Targeted AST parsing found a BOM at byte zero in:

```text
brain/__init__.py
scripts/aegis_daemon.py
scripts/tests/aegis_nose_test.py
```

The targeted parser also emitted invalid-escape warnings from ANSI strings in `brain/windows_brain.py`. These are not immediate authority failures, but they reduce source-quality confidence and may become errors under stricter tooling.

**Required action:** normalize production Python files to UTF-8 without BOM where the project convention requires it, and replace invalid escape literals with explicit ANSI escape sequences or raw strings.

### Finding F-005 — Legacy terminology and semantic map drift

Current files still contain legacy terms such as:

```text
core/canonical_event.zig
core/nose_pipe_reader.zig
shield/src/lib.rs
```

The current source and manifest also use:

```text
src/contract/event.zig
src/capture/nose_pipe_reader.zig
rust-src/lib.rs
```

Some references are historical evidence and some are compatibility aliases. The audit cannot assume all are wrong. But the system map, authority map, test expectations, and manifest must make the distinction explicit.

**Required action:** classify every legacy reference as one of:

```text
canonical production
compatibility alias
test fixture
historical evidence
forbidden duplicate
```

Then regenerate maps and run the forbidden-edge tests again.

### Finding F-006 — Windows host proof remains outstanding

No sandbox inspection can prove:

- the live named pipe is owned by the intended daemon;
- the runtime has the expected PID/generation;
- all workers are ready;
- Npcap capture works on the selected adapter;
- the Rust PEP DLL loads on Windows;
- the WFP service and device contract match;
- the provider returns a real filter identity;
- traffic is blocked on the isolated target;
- cleanup restores traffic;
- no stale filter remains after restart.

The enforcement gate must remain closed until these postconditions are collected on the Windows host and VMware VMnet1 lab.

## What “not broken” means here

The evidence supports the narrower statement:

> The selected source-level security boundaries and Python contract tests are currently coherent enough that the main architecture is not demonstrably broken by the inspected checks.

It does not support the stronger statements:

```text
The native build is verified.
The live Windows runtime is verified now.
WFP host enforcement works.
The package installs cleanly on a new host.
The system is Production-ready.
```

## Required next verification sequence on Windows

Run from an elevated PowerShell on the actual host:

```powershell
Set-Location D:\NIDs_Windows

git rev-parse HEAD
git branch --show-current
git status --short

zig version
go version
rustc --version
cargo --version

zig build
if ($LASTEXITCODE -ne 0) { throw 'zig build failed' }

zig build test
if ($LASTEXITCODE -ne 0) { throw 'zig tests failed' }

Set-Location .\nose
go test ./... -timeout 60s
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }

Set-Location ..
python -m pytest tests\security tests\contracts tests\runtime tests\wfp -q
if ($LASTEXITCODE -ne 0) { throw 'Python tests failed' }
```

Start the runtime in one elevated window:

```powershell
Set-Location D:\NIDs_Windows
zig build run
```

From a second elevated window run:

```powershell
Set-Location D:\NIDs_Windows
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_host_production_preflight.ps1 `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

Then run lifecycle recovery:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_lifecycle_recovery_proof.ps1 `
  -WaitSeconds 180
```

Only after those pass should the VMnet1 observe-only proof begin. WFP host-effect proof remains a separate gated operation.

## Final verdict

```text
ระบบไม่ได้มีหลักฐานว่าเส้นทาง architecture หลักพัง
แต่ระบบยังไม่สะอาดพอสำหรับ Production
และยังไม่มีหลักฐาน Windows host-effect ที่จะยืนยัน IPS จริง
```

The next safe engineering step is not to add features. It is to close F-001 through F-006, starting with the stale `AGENTS.md` truth declaration, the compile-gate policy, and Windows native build/runtime evidence.
