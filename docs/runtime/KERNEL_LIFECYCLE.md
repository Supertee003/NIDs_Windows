# Kernel lifecycle — load, unload, cleanup, and proof boundary

> Scope: build source `4dd3393` (HISTORICAL at current source `aa3b7b0`). AEGIS-PLAN-009.
> This is a **contract and runbook index**, not a claim that a driver was loaded
> in this session. The agent session is non-elevated; no kernel object was
> touched while writing this page.

## 1. Canonical kernel surface

| Artifact | Canonical builder | Role |
|---|---|---|
| `aegis_minifilter.sys` | WDK / minifilter project under `drivers/minifilter/` | Host telemetry ingress into the 4 MiB ring |
| `aegis_wfp_user.dll` | root `CMakeLists.txt` | User-mode WFP telemetry bridge (read-only in current architecture) |
| `aegis_etw_helper.dll`, `aegis_fim_helper.dll` | root `CMakeLists.txt` | Native telemetry adapters |
| `aegis_nids.exe` | `zig build` | Daemon; owns ring pull and health reporting |

Language ownership and authority follow `AUTHORITY_MAP.json`: no component in
this product authorizes a host effect (RETIRE-HOST-EFFECT-001, issue #25).
"Block"/"Drop" in rules remain policy intent; production stays observe-only.

## 2. Lifecycle contract (what a proof must show)

A valid kernel lifecycle proof at a given build source must record:

1. **Pre-state** — installed driver path, SHA-256, service state, `fltmc` state,
   daemon/Nose process state, `prevention_gate`, `host_effect_capable`.
2. **Build identity** — source commit, compiler/toolchain, candidate SHA-256.
3. **Load / unload** — exact commands and exit codes for stop, unload, copy,
   service recreate, reload; installer rollback path for both install tree and
   previous driver.
4. **Cleanup** — service removed or restored, filter detached, temporary files
   removed, and a final pre-state comparison that proves the host was restored.
5. **Negative control** — no daemon means no event injection effect; no traffic
   means no new detection rows.
6. **Evidence** — raw transcript retained outside the tracked tree with its
   SHA-256, plus a tracked record that states what the transcript proves.

## 3. What exists today

- Historical E5 records at older commits document installer unload/reload with
  27/27 checks, driver signature Valid, and rollback capture. They are
  **HISTORICAL** and do not substitute for current-source proof.
- `analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md` contains the
  prepared owner-run sequence for the current source.
- A previous elevated proof aborted during preflight before takeover; the
  record explicitly states that no E5 functional capture claim was established.
  That honesty is preserved here.

## 4. Status at `4dd3393`

| Check | Status |
|---|---|
| Kernel contract documented | E1 PASS (this page) |
| Load/unload/cleanup executed at `4dd3393` | **NOT_PROVEN** |
| Signed driver at current source | **NOT_PROVEN** (immutable release identity is `v1.1` / `466a226` / `a53eda8`) |
| Full kernel IDS qualification | **NOT_PROVEN** |

## 5. Open work

Owner must run the lifecycle section elevated, attach the raw transcript
locator, and file an evidence entry at the exact build source. Agent must not
simulate `fltmc`, service control, or installer output.

---

See also: [`LIFECYCLE.md`](LIFECYCLE.md),
[`RUNTIME_CONTRACT.md`](RUNTIME_CONTRACT.md),
[`../adr/0009-kernel-ids-integrity-plane.md`](../adr/0009-kernel-ids-integrity-plane.md),
[`../../analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md`](../../analysis/current-head/OWNER-RUN-HOST-PROOF-RUNBOOK-20261126.md).
