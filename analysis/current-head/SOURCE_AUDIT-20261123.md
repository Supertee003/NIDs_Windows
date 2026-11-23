# Source Audit — AEGIS NIDS Windows (2026-11-23)

| Field | Value |
|---|---|
| Audit ID | SOURCE-AUDIT-20261123 |
| Records HEAD at audit | `9411a4bd6fd2b1205b514950f846bc7f68adc643` |
| Build source (ADR-0008) | `a53eda8344a20f86ad4f4e4001e9b3d648067671` |
| Components audited | `drivers/`, `src/` (runtime, control, contract, pipeline, forensics), `nose/`, `tests/`, current-head docs |
| Method | Read-only static inspection — no build, no test run, no host verification |
| Evidence level | **E1–E2 only**. This audit does not raise Independent Verification above an owner-produced-static-review level |
| File changes during audit | None |
| Related issues | [#40](https://github.com/Supertee003/NIDs_Windows/issues/40) · [#41](https://github.com/Supertee003/NIDs_Windows/issues/41) · [#42](https://github.com/Supertee003/NIDs_Windows/issues/42) · [#43](https://github.com/Supertee003/NIDs_Windows/issues/43) |

---

## 1. Executive verdict

| Dimension | Result |
|---|---|
| Runtime is detection-only | **Yes.** No path from `src/main.zig:15-18,39` → `win32_service.zig:89,120` → `daemon.zig:249` reaches a host effect. `rust_pep.zig:191-203,291-304` refuses. `real_ips_path.zig` is a std-only model in test roots |
| Control-plane security | **Strong.** Single-owner pipe, restrictive SDDL, token-derived roles, central authorization — all match the documented claims |
| 23-rule coverage | Catalog 23/23, evaluable 23/23, host-positive proof L4 only — matches the detection catalog |
| WFP fail-open | **Yes**, three layers. But "no host-effect path" must be qualified as "no **reachable** creation path" (see §2) |
| Documentation vs source | Mostly correct, but 4 STOP-THE-LINE triggers and ~14 P0-level contradictions (see §3–4) |
| Independent verification | Still limited — this is static evidence, not a build/E5 run |

---

## 2. STOP-THE-LINE triggers found

Per `AGENTS.md`, four triggers were detected and issues were filed before any patch.

| # | Trigger | Evidence | Issue |
|---|---|---|---|
| 1 | Contradictory source-of-truth documents | `docs/USER_OPERATIONS_GUIDE.md:3,7,67,73` authorizes enforcement while the same file and README declare detection-only; `docs/architecture/CONTRACTS.md:3` is `AUTHORITATIVE` with `core/*.zig` paths that do not exist; `source_arbiter.zig:3-6` + `STEP-5-MANIFEST-STATUS.md:38` claim stream reassembly with no production caller | #40 |
| 2 | Potential silent event loss | `nose/canonical.go:673-686` + `canonical_event.zig:599-605,768-773` accept v1 frames longer than 109 bytes and ignore the tail without incrementing `nose_frames_rejected`; length-based classification in `nose_pipe_reader.zig:85-87,102-108` makes a corrupted version byte a silent evidence-loss path | #41 |
| 3 | Stale evidence | Zig counts `2116/2114/2109 passed, 11 skipped` in `EVIDENCE_INDEX.json:46,114,174` carry `head_sha f0baadf`, not build source `a53eda8` | #42 |
| 4 | Build/runtime mismatch | `ARCHITECTURE_EN.md:101-104` documents 125/149-byte framing; implemented framing is u32 LE length + payload = **113/137/169..1193** (`pipe_writer.go:163-171`, `nose_pipe_reader.zig:372-385`). Already P0 ABI-01 in `analysis/current-head/02-contracts-abi.md:15,340` | #43 |

Source-tree findings that require a future source slice are recorded in the issues, not patched here: `src/capture/source_arbiter.zig:3-6`, `src/contract/canonical_event.zig:66`, `nose/golden_path_ffi.go:6`, `nose/canonical_test.go:4-7`, `scripts/aegis_daemon.py:92`.

---

## 3. Component findings

### 3.1 `drivers/` — WFP + minifilter

**Confirmed:** `classify()` fail-open in three layers (`aegis_wfp_callout.c:323-325,675-685`, rundown gate `:271-275`); IOCTL `0x801` refused with `STATUS_NOT_SUPPORTED` (`aegis_wfp.c:923-932`); `READ_EVENTS` all-or-nothing with the read offset advanced only after a successful copy (`:1003-1020`); 4096-byte bound with no TCP reassembly and TCP flags only on outbound; minifilter is observe-only (`FLT_PREOP_SUCCESS_*`, no `FLT_PREOP_COMPLETE`); test-signing only.

**Qualification required:** the legacy `AegisWfpBlockFlow()` still contains `FWP_ACTION_BLOCK` + `FwpmFilterAdd0()` (`aegis_wfp.c:1171-1174`), unreachable from dispatch; `AegisWfpRecoverProofFilter()` (`:426-459`) can reactivate a pre-existing persistent filter at startup; `drivers/wfp_callout/quarantined/aegis_wfp_comm.c:129-143` contains real block code guarded only by a "DO NOT COMPILE" comment and the build script. Safe wording: **no reachable host-effect creation path**, not "kernel has no filter-creation code".

**Risks ranked:** unbounded `for(;;)` callout-unregister loops (`aegis_wfp_callout.c:916-928` etc.) can hang unload; proof-cleanup failure at unload is only `DbgPrint` (`:830-836`); INF `RingBufferSize` is ignored (`DriverEntry` uses `UNREFERENCED_PARAMETER(RegistryPath)` at `:682`).

### 3.2 `src/` — runtime + control plane

**Confirmed:** `CONTROL_PIPE_MAX_INSTANCES = 1` with preflight exit code 3 (`win32_pipe.zig:34,193-217`; `daemon.zig:707-710`); SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)` with fail-closed descriptor construction before `CreateNamedPipeW` (`:76,232-248`); role from `ImpersonateNamedPipeClient` → `OpenThreadToken` → `TokenElevation` (`:160-181`), JSON cannot self-declare; central `authorize()` in dispatch (`handler_registry.zig:203-220`) with unit test that every mutation is privileged (`protocol.zig:393-405`); v2 `nonce`/`issued_at_ms` are declared but unread (`:290-298`), the real v1 table is test-only (`src/policy/control_ipc.zig:312-355`); `DEGRADED` with all subsystems `RUNNING` is explained by `data_loss_observed` in `operationally_ready` (`state_machine.zig:432-434`).

**Risks:** `Authorizer.enabled` (`authorization.zig:30-36`) can disable checks — currently default-on; "backpressure" is drop-on-full with visible counters, not blocking producer backpressure; legacy entrypoint comments still name `nids_main.zig`; low-priority starvation in `priority_queue.zig:99-106`.

### 3.3 `src/` — contract, pipeline, forensics

**Confirmed (11/12):** v1=109 B, v2=133 B, v3=165+payload (≤1024), magic `0x41454731`, `struct_size=128` is in-memory and never used as wire length (`canonical_event.zig:23-25,410-446`); version dispatch and field-by-field codec with no whole-struct `memcpy` (`:599-623,627-675`); FNV-1a rule IDs (`rule_loader.zig:15-21`); Aho-Corasick in Zig, regex advisory in Python; layer fail-closed (`event_processor.zig:207-250`); L7 restricted to `.capture_npcap` (`:418-438`); 4096-byte forensic records with CRC32 + SHA-256 chain including ring-wrap handling (`forensic_pipeline.zig:11-26,531-541,605-663`); `forensics.replay` integrity-only with `events_replayed=0`, `pass=false` (`handler_registry.zig:1902-1957`); ingress claim stripping with a counter (`event_queue.zig:429-477`).

**Exception:** `stream_reassembly.zig:1-140` exists but has no production caller — only `src/all_tests.zig:24` and a test that asserts it "imports cleanly". Runtime detection uses single-packet prefixes; the "no TCP reassembly" claim in `DETECTION_CATALOG.md:48-50` is the correct one.

### 3.4 `nose/` — Go acquisition

**Confirmed:** no rule file, matcher, or verdict in `nose/`; the verdict-authority test is a static AST guard (`verdict_authority_test.go:43-104`) — the actual runtime strip is in Zig; 109-byte codec with golden-byte parity; interface selection, BPF `ip or ip6`, capture errors → `os.Exit(1)`; V3 envelope validates fail-closed; IPv6 truncation is disclosed with `ContextV6Truncated`.

**Contradictions:** framing is 4-byte LE length + payload (see §2 #4); no loopback TCP fallback in `dialPipe()` (`pipe_writer.go:103-112`); `sendWire()` does not guard `len(wire) <= 1189` before slicing; BPF filters VLAN-tagged frames at the kernel; `golden_path_ffi.go:6` claims E3 for a fixture-only test.

### 3.5 `tests/`

- `1,471 passed / 0 skipped` is a **two-phase sum** with one explicit deselect (`CAPTURE-LOOPBACK-002-FULLPATH-20261122.md:74-78`), not one `pytest` invocation. A different closeout run recorded `1456 passed, 14 skipped, 1 xfailed, 1 xpassed` at `505704f` (`V1.1-RELEASE-CLOSEOUT-20261122.md:114`).
- `test_import_hygiene.py` pins no banner and no UDP bind; "no serve loop" and "no sys.exit" are docstring intent enforced only indirectly.
- E6 host tests are genuinely host-dependent (`pytest.mark.host_live`, 40/10 SYN, exact 5-tuple, negative control) but deselected on hosted CI (`pytest.ini:5`).
- `test_t18_ips_canary_xdr.py` is ACTIVE but is a guard proving IPS stays LAB, not an enforcement proof.
- 23 rule IDs are pinned by census (`test_detection_contract_pin.py:160-173`); lab script coverage is skipped on fresh clones (`test_kali_script_coverage.py:24-31`).
- Missing: published fuzz campaign, clean install/uninstall campaign, fixed-rate offered-load ceiling, full WFP E5 for current source.

---

## 4. Doc fix register applied in the companion patch

| Priority | File | Fix |
|---|---|---|
| P0 | `README.md:25` | `6/6 gates PASS (0 open)`; v1.1 release link; test-count scope qualifier |
| P0 | `README.md` | Detection coverage table separating catalog / synthetic / live sensor / L4 / R2003 limitation |
| P0 | `README.md`, `APPLY_NOW.md`, `DEMO.md` | Demo length unified to 2:27 (verified from MP4 `mvhd`: 147.1 s); chapter headers and table rebased |
| P0 | `USER_OPERATIONS_GUIDE.md:3,7,67,73` | Enforcement activation language removed; detection-only testing added |
| P0 | `CONTRACTS.md` | Status → HISTORICAL with current-authority pointer |
| P0 | `DETECTION_CATALOG.md:27` | `L4 — network transport (3 rules)` |
| P0 | `DEMO.md:41` | Local worktree path → `<REPO_ROOT>` |
| P0 | `ARCHITECTURE_EN.md:101-105` | Framing → 4-byte length + payload (113/137/169..1193); loopback fallback marked not implemented |
| P0 | `SECURITY_BOUNDARIES.md` | "no reachable host-effect creation path" qualification |
| P0 | `APPLY_NOW.md` | Replace "shipped" / "zero loss" with scoped released-and-soak-tested wording |
| P1 | `WFP_IOCTL_STATUS.md` | Mark HISTORICAL |
| P1 | `STEP-5-MANIFEST-STATUS.md` | Reassembly → `UNWIRED / implementation-only` |
| P1 | `CANONICAL_EVENT_SCHEMA.md` | Length/version nuance; SipHash64 → FNV-1a note |
| P1 | `PRODUCTION_READINESS.md`, `10-current-phase.md` | Mark pre-release sections HISTORICAL |
| P1 | Threat model / failure matrix | "backpressure" → "bounded queue + observable shedding" |

---

## 5. Interview-safe wording after this audit

> "WFP is fail-open telemetry with **no reachable host-effect creation path** — the legacy block handler is still in the binary but unreachable, and a pre-existing persistent filter can be recovered at startup. TCP reassembly exists as a **test-only module with no production caller**; detection runs on single-packet prefixes. The Nose pipe is **4-byte length plus a 109-byte v1 frame**, not 125 bytes. `forensics.replay` is integrity-only. Control IPC has token-derived per-command authorization but **no nonce enforcement** on the active v2 path."

---

## 6. Limitations of this audit

1. No build, no test, no E5 verification was performed; all findings are E1–E2.
2. No binary analysis: the "unreachable" conclusion for the WFP block handler is from source call-graph reading, not disassembly.
3. No runtime fuzzing or fixed-rate load was used to confirm the silent-loss path is reachable in practice; it is a code-level risk.
4. Source-tree issues (#40/#41/#43 related code comments) are deliberately not patched here to keep build source at `a53eda8` and preserve `TRUTH_VALID`.
