# SYSTEM-SURVEY-001 — full-system re-survey and gap register

**Date:** 2026-11-10
**HEAD:** `9e0d8626c647e6362244e64064ed9ebd195471b7` (branch `codex/o2-etw-context`)
**Build source commit:** `a8f3abfdfd577c38618f1342200a10545c41fd5c` (`tools/truth.py verify` → `TRUTH_VALID`, exit 0)
**Worktree:** clean at survey time
**Level:** E1 (static inspection) + live host *reads* (service state, control-plane queries, event log, file hashes). No E5 claim is made or extended by this document.
**Status:** survey only. **No product file was modified.** This document closes no issue and no risk by itself.

> Purpose: answer "how much work is actually left, and what did we forget?" with
> measured evidence instead of recollection. Every claim below carries the command
> or `file:line` that produced it. Claims I could not re-verify are labelled
> **UNVERIFIED** and are never counted as fact.

---

## 0. Method and scope

Six read-only surveys were run in parallel (Zig runtime; Go/Python; native drivers +
Rust; contracts/authority; tests/evidence/release; live host). I then re-ran the
highest-consequence claims myself. Where a survey claim failed re-verification it is
recorded as **REFUTED** in §4 rather than quietly dropped.

Harness checks performed during the survey:

| Check | Result |
|---|---|
| `python tools/truth.py verify` | `TRUTH_VALID`, exit 0 |
| `python scripts/check_summary.py` | `SUMMARY_VALID` |
| `python -m pytest tests/contracts tests/security -q` | **253 passed** in 28.7 s |
| `python tools/evidence_debt.py` | 708 product files, **535 never named** (76%) |
| `python tools/release_engineering.py --verify` | **FAIL** — `scripts/package_release.ps1` drifted |

The suite gates that exist are green. The problems below are in what the gates
*measure*, not (mostly) in whether they run.

---

## 1. What is actually solid

These are the claims that survived re-verification and can be used as current truth.

| Area | Evidence | Level |
|---|---|---|
| Detection-only boundary is structural, not just config | block IOCTL hard-refused; classify callbacks return `FWP_ACTION_PERMIT`; control plane returns `DETECTION_ONLY`/`REFUSED` (`HOST-WINDOW-002` §4) | E5 (recorded) |
| No AEGIS `FWP_ACTION_BLOCK` filter on the host | `wfp-filter-audit-20261109.json`: 3,829 filters, 124 AEGIS, 0 BLOCK | E5 (recorded) |
| Runtime image parity (daemon exe) | installed `aegis_nids.exe` == repo build `D39A1D2C…` | E5 (recorded) |
| Minifilter image parity | `System32` == install tree == `10C41E8043EE…` | measured today |
| Contract + security gates | 253 passed (`tests/contracts`, `tests/security`) | E2 |
| Nose wire v3 | 4 codecs + golden vectors + live capture-path rollout | E2 + E5 (recorded) |
| Clean-clone suite | 1,029 passed / 36 skipped in a fresh clone | E2 (recorded) |

---

## 2. Confirmed findings (re-verified by me today)

Severity: **S1** = contradicts a product/evidence claim or weakens a security
boundary; **S2** = correctness/observability/operability gap; **S3** = hygiene/doc.

### S1-01 — The WFP driver that is loaded is not the driver we claim to have shipped

Three different `aegis_wfp.sys` images exist at once:

| Location | SHA-256 | Size | mtime | Signer |
|---|---|---|---|---|
| `C:\Windows\System32\drivers\aegis_wfp.sys` (service load path) | `F63195B02C87A99A…` | 45,968 | 2026-11-01 15:02 | `CN=AEGIS NIDS Test Signing` |
| `C:\Program Files\AEGIS NIDS\drivers\aegis_wfp.sys` | `06CC8E238B79BEC3…` | 42,896 | 2026-11-10 02:17 | `CN=AEGIS NIDS Test Signing` |
| `D:\NIDs_Windows\build\x64\wfp\aegis_wfp.sys` | `06CC8E238B79BEC3…` | 42,896 | 2026-11-10 02:17 | `CN=AEGIS NIDS Test Signing` |
| `D:\NIDs_Windows\drivers\wfp_callout\aegis_wfp.sys` (untracked, stale) | `EC4A5683E3072FA5…` | 28,136 | 2026-10-16 10:27 | `CN=AEGIS Test Signer` |

`HOST-WINDOW-002-20261109.md:102` states *"Both drivers loaded the current-source
builds (`06CC8E23…`, `10C41E80…`)"*. The minifilter half is true. The WFP half is
not supported: the file at the service's `BINARY_PATH_NAME`
(`sc qc AegisWfp`) is `F63195B0…`, a larger image dated **2026-11-01**, i.e. eight
days older than the bundle that the window claims was loaded.

**Mechanism (why it would look like success):** `tools/installer.py:281` copies the
driver into `System32` with `cmd /c copy /y` and then only *prints* the resulting
signature status (`:282`). A copy that fails because the image is still mapped by the
kernel leaves the old driver in place, the installer still exits 0, and the
post-install signature check inspects the *old* file (which is also Valid).

A second defect compounds it: **two installers ship different drivers.**

- `installer/aegis.nsi:72` packages `drivers\wfp_callout\aegis_wfp.sys` → the stale
  28,136-byte Oct-16 image.
- `tools/installer.py:35,251` packages `build\x64\wfp\aegis_wfp.sys` → the current
  `06CC8E23…` image.

**Why S1:** this is the AGENTS.md stop-the-line condition *build/runtime mismatch*,
and it invalidates the WFP half of every host-window claim that assumed the deployed
driver matched source. It also means the *security posture of the running driver*
cannot be derived from the repository: the loaded image is eight days older than the
tree.

**Smallest action:** deploy-time assertion that `install-tree hash == System32 hash`
and that `hash(loaded image) == installed file` (stop the service, replace, restart,
re-hash), and make the installer fail hard on a failed copy. Then re-run the WFP
audit and record the hash of the image actually in the load path.

---

### S1-02 — The release digest gate cannot fail, and does not cover any binary

`FREEZE-001-20261109.md:45` defines gate item 9 as:

```
python tools/release_engineering.py --refresh-digests   then re-verify   → 0 mismatches
```

`tools/release_engineering.py:429-492` re-records every digest **from the working
tree** (`:463-468`), writes the manifest (`:482`), and then calls
`verify_manifest()` **on that same tree** (`:492`). The re-verify therefore compares
the file against the value it was just given. Gate item 9 passes by construction for
every file that exists; it can only fail when a file is deleted mid-run.

Two aggravating facts, both measured today:

1. **No binaries in the artifact set.** `build_manifest.json` has 651 entries:
   `.zig` 287, `.py` 155, `.ps1` 59, `.go` 35, … and **zero** `.exe/.dll/.sys`
   (query in §5). The digest gate therefore proves nothing about the artifacts that
   are actually shipped or loaded — including the driver in S1-01.
   *Correction (2026-11-10, after re-reading the bundle path):* shipped binaries
   **are** hashed at the bundle layer — `tools/release_candidate.py:143-148`
   writes `SHA256SUMS` over every packaged file and `:213` verifies it. The
   manifest is source-only by design, so the real gap is narrower than first
   recorded: nothing compared the **installed** binary against the **bundled**
   one. That is exactly how `aegis_fim_helper.dll` stayed at its 2026-10-16 build
   (see `ISSUE-30-ATTRIBUTION-20261110.md`).
2. **It fails today anyway, invisibly.** `--verify` returns exit 1:
   `scripts/package_release.ps1` drifted from its recorded digest. The recorded
   digest no longer matches the clean tree, and the freeze checklist's own command
   would have silently "refreshed" that away.

**Why S1:** release-integrity evidence is currently self-certifying. A tampered or
stale artifact is laundered into "verified" by the gate's own procedure.

**Smallest action:** anchor digests to something outside the working tree (signed
manifest, or the git blob hash for source); add the shipped binaries to the artifact
set; run `--verify` on a clean checkout (the R-14 clone harness already exists) and
store that transcript as the gate evidence.

---

### S1-03 — The evidence index over-claims at scale

Measured against `EVIDENCE_INDEX.json` (193 `evidence` entries, 271 `known_gaps`):

| Fact | Measurement |
|---|---|
| Evidence entries with **no** artifact pointer | 138 / 193 |
| Evidence entries whose pointer resolves on disk | 54 / 55 pointed entries |
| E5 entries with no artifact pointer | 50 / 77 |
| Distinct `head_sha` in `evidence` that do **not** exist in this repo | **35 / 74** |
| Distinct `head_sha` across `evidence` + `known_gaps` that do not resolve | 224 / 265 |
| Entries asserting `host_effect_confirmed: true` | **4** (2 of them E5 in `evidence`) |
| `evidence_level_summary.E5_count` | 166 |

Three distinct problems:

1. **The E5 headline is not 166 evidence entries.** `scripts/check_summary.py:27-32`
   counts `level` across **both** `evidence` and `known_gaps`. `evidence` contributes
   77 E5; `known_gaps` contributes 89. The project's own debt tool takes the opposite
   (correct) view — `tools/evidence_debt.py:40-44`: *"Only evidence entries count as
   evidence. The known_gaps section is a findings log."* The two scripts disagree
   about what "evidence" means, and the release-facing one is the inflated one.
2. **Two thirds of the evidence chain does not point at an artifact.** For E5 — the
   level that asserts host verification — 50 of 77 entries cite nothing an auditor
   could open. Several are from the current window and have no artifact, e.g.
   `HOST-WINDOW-002-E5-20261109`, `KIND-ATTR-001-E5-20261109`,
   `D3-LOSS-ATTRIBUTION-E5-20261109`, `D3B-RATE-SWEEP-E5-20261109`,
   `D4-PAGEHEAP-E5-20261109`, `D6-DRIVER-ROLLBACK-E5-20261109`,
   `READINESS-001-E5-20261109`, `QLOSS-E5-STEADY-WINDOW-20261109`,
   `L4-FLAGS-R9007-LIVE-E5-VMNET1-20261108`.
3. **Committed hashes do not resolve.** 35 of 74 distinct `head_sha` values in the
   evidence section are absent from this repository's object database, and 224 of 265
   across both sections. An evidence entry whose commit cannot be checked out is not
   evidence at the level it claims.
4. **Four entries assert a host effect.** `G2-DUPFILTER-HOST-PROOF-E5-20261028` and
   `RB013-LOG-E5-20261102` (both `level: E5`, both in `evidence`, both with no
   artifact) plus `G2-RB012-013-LAB-20261021` and `G2-INBOUND-PIPELINE-20261021`
   (in `known_gaps`) carry `host_effect_confirmed: true`. They describe lab-only
   campaigns, but nothing in the index marks them historical or lab-scoped, so a
   reader of the current index sees confirmed host effects against a product whose
   stated boundary is `host_effect_confirmed=false`.

**Why S1:** release and audit decisions are being taken on a number (166 E5) that
counts open gaps, and on entries that cannot be traced to an artifact or a commit.

**Smallest action:** (a) make `check_summary.py` count `evidence` only (matching
`evidence_debt.py`), (b) add an `historical: true` / `scope: lab` field and apply it to
the four host-effect entries, (c) enforce "E5 ⇒ artifact pointer resolves" as a test,
(d) either re-anchor or retire entries whose `head_sha` does not resolve.

---

### S1-04 — Any standard local user can rewrite detection rules and apply them

Three facts combine:

1. **The control pipe admits everyone authenticated.** `src/platform/win32_pipe.zig:70`:
   `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)` — `AU` (Authenticated Users) gets
   generic-all on the pipe.
2. **The role is elevation-only.** `win32_pipe.zig:154-175` impersonates the client and
   returns `.privileged` if `TokenElevation` is set, otherwise `.operate`. There is no
   group, SID, or command-specific check. `authorization.zig:27` defaults local
   connections to `.operate`.
3. **`rules.reload` needs only `.operate`.** `src/control/protocol.zig:222`:
   `required_role = .operate`. And the rule file is user-writable:
   `Get-Acl configs\Rules.json` → `NT AUTHORITY\Authenticated Users: Modify`.

The daemon on this host resolves its runtime root to the repository
(`runtime_paths.zig:100-103`, and the live health payload reports
`repo root: D:\NIDs_Windows`), so the rules it reloads are `D:\NIDs_Windows\configs\Rules.json`
— the file any authenticated user can modify.

**Net:** a non-elevated local user can change what the NIDS detects and apply the
change to the running daemon, with no elevation prompt. (The audit row does carry
`caller_pid` as well as `caller_role` — `handler_registry.zig:207-218` — so the
request is attributable; it is the *authorization* that was missing, not the
identity.)

**Why S1:** detection integrity is the product. This is not an enforcement path, but
it is an unauthenticated-within-the-host path to changing detection behaviour.

**Smallest action:** require `.privileged` (or an explicit admin-group check) for all
mutations, tighten the pipe DACL to `SY`+`BA` for mutating commands (separate pipe or
per-command ACL), and put `configs/` under a `BA`-only ACL at install.

**Related (S2):** `handler_registry.zig:162-219` performs **no freshness/nonce/replay
check** — `protocol.zig:282` declares a `nonce` field that dispatch never reads — while
the separate policy IPC (`src/policy/control_ipc.zig:259-282,349`) does implement a
`(request_id, nonce)` replay table. The same security property is implemented in one
control path and missing in the other.

---

### S1-05 — The daemon says RUNNING and DEGRADED at the same time, and the soak tool believes RUNNING

Raw control-plane responses, taken seconds apart, same PID:

```
status -> {'state': 'RUNNING',  'uptime_ms': 33,860,334}
health -> {'state': 'DEGRADED', 'runtime_state': 'RUNNING', 'degraded': True}
```

The cause is visible in `src/control/state_machine.zig:331-341`: `data_loss_observed`
is true when **any** of the loss counters is non-zero, which flips `state` to
`DEGRADED` while `runtime_state` stays `RUNNING`. Live counters:

```
data_integrity: queue_dropped_total = 265,675
                minifilter_pipeline_dropped = 1,016
counters:       in_events = 366,559  out_events = 366,559  dropped = 0
```

Two problems follow:

1. **The health payload contradicts itself.** `counters.dropped = 0` and
   `in_events == out_events` sit in the same object as
   `queue_dropped_total = 265,675`. The `counters` block is nose-only; the loss that
   matters is in `data_integrity`. Any consumer that reads `counters` concludes "no
   loss".
2. **The soak verdict cannot see degradation.** `tools/host_soak_check.py:105-124`
   reads `status`, puts its `state` into the report (`:134`), and never includes it in
   `problems`. Its pass criteria are: four services `RUNNING`, daemon reachable, uptime
   not shorter than elapsed. **A 24-hour soak with 265,675 dropped rows and a
   `DEGRADED` daemon would report `PASS`.** It would also miss a daemon that reports
   `DEGRADED` continuously while running.

Also observed: every subsystem reports `last_event_ms: 0` after 9.3 hours of uptime
and 366k events, so per-subsystem liveness is not actually being reported; and the
readiness gate says "not ready" while naming no cause:

```
python tools/aegisctl.py readiness   →  exit 1
{"ready": false, "overall_gate": false, "state": "DEGRADED",
 "degraded_components": [], "failure_reasons": [], "missing": [],
 "worker_gate": true, "rules_loaded": 23, "policies_loaded": 6}
```

`ready: false` with `degraded_components: []` and `failure_reasons: []` is a gate an
operator cannot act on: it refuses, and it does not say why.

**Why S1:** the soak is the evidence for R-08/FREEZE #24. As written, the tool cannot
distinguish "clean 24 h" from "24 h of silent loss".

**Smallest action:** make the soak verdict require `health.state` not-DEGRADED **and**
either zero loss or an owner-approved loss budget; remove or fix `counters` so it does
not contradict `data_integrity`; fix `readiness`.

---

### S2-01 — #30 is not closed, and the host has fresh unattributed terminations

SCM `7031` (service terminated unexpectedly) for `AegisNids`, last 8 days:

```
2026-11-10 02:17:57   (2nd failure, restart in 15 s)
2026-11-10 02:14:43   (1st failure, restart in 5 s)
2026-11-09 00:33:22
2026-11-06 21:24:41
2026-11-05 17:35:01   (2nd failure)
2026-11-05 16:23:37
2026-11-04 14:21:20   (4th failure)
2026-11-03 22:22:52   (3rd failure)
2026-11-03 16:41:59   (2nd failure)
```

`HOST-WINDOW-002-20261109.md:252-275` records ten page-heap restart cycles as
"10/10 cycles RUNNING … **0 new dumps**" and concludes the trigger is not start/stop.
The two terminations at **02:14:43 and 02:17:57 on 11/10** fall inside that window and
are not reconciled with that conclusion anywhere in the record.

Application Error `1000` shows the faulting signature for two older events:
`aegis_nids.exe`, exception code **`0x80000003`** (`STATUS_BREAKPOINT` / assertion),
at fault offset `0x9346a`, on 11/5 16:23 and 11/4 14:21. Full dumps exist for exactly
those two:

```
aegis_nids.exe.16408.dmp   2026-11-05 16:23:37   289,315,496 bytes
aegis_nids.exe.16144.dmp   2026-11-04 14:21:20   289,324,215 bytes
```

No dump or WER record exists for the 11/10 terminations (the LocalDumps folder
`admin-evidence\e5-host-proof-20261026\wer-localdumps` contains nothing from 11/10).

**Why S2:** the crash is real and recurring, but it is no longer "no data" — two full
dumps with a known exception code exist. What is missing is attribution for 11/6, 11/9
and 11/10, not the ability to start.

**Smallest action:** analyse the two dumps (same offset, same exception → very likely
one bug); enable LocalDumps coverage for the currently loaded build and re-arm; then
either close #30 with a root cause or declare it a limitation **with the 11/10 events
disclosed**. Silent omission of those two events is not acceptable.

---

### S2-02 — "RUNNING after reboot" cannot pass by configuration

```
AegisWfp:         START_TYPE 3 DEMAND_START
AegisMinifilter:  START_TYPE 3 DEMAND_START
```

Nothing schedules them at boot: no service auto-start, and no scheduled task calls
`sc start`. FREEZE #22 ("drivers RUNNING after reboot") will therefore fail after a
reboot unless something else starts them; the daemon would come up degraded with no
kernel telemetry and, per S1-05, would still be able to report a passing soak.

**Smallest action:** decide the intended boot model (auto-start vs bootstrap task),
implement it, and prove it with the reboot that R-06 already needs.

---

### S2-03 — Injection detection is instantiated and thrown away

```
src/daemon.zig:618:  var inj_detector = inj_det.InjectionDetector.init(...)
src/daemon.zig:619:  defer inj_detector.deinit();
```

Those are the only two references in `daemon.zig`. Nothing calls `ingest()`; no worker
thread feeds it. `src/detection/injection_detector.zig` (create-remote-thread,
VirtualAllocEx, WriteProcessMemory, APC, hollowing, thread hijack checks) is fully
written and unit-tested but **inert in production**.

**Smallest action:** wire it to the ETW process/thread telemetry lane, or mark it
explicitly as unimplemented in the capability list. A detection module that exists,
is tested, and never runs is a "production mock" class of finding.

---

### S2-04 — KIND-ATTR-001 root cause is now exact

```
src/capture/minifilter_reader.zig:226   var ce = canonical.create(.minifilter);
                                        (… event_type never assigned …)
src/contract/canonical_event.zig:392    .event_type = .custom,     // create() default
src/contract/canonical_event.zig:321-333 EventType has no file/FIM member
src/pipeline/event_queue.zig:366-375    .custom => .packet_captured
```

So every minifilter FIM row reaches the queue as a **captured packet**, by default,
with no producer-side intent. Source attribution is still correct
(`legacySourceFor(.minifilter) → .capture_fim`, `event_queue.zig:296`), which is why
per-source counters look right while kind-based counting and any kind-based rule do
not.

This is decision-relevant for §6: option (c) "rename the kind" is not sufficient by
itself — the enum has no FIM kind to rename it to, so any fix adds a kind to the
cross-language enum (all six codecs + golden vectors in one patch, per AGENTS.md
TEST HYGIENE item 3).

---

### S2-05 — Two installers ship different driver images (detail of S1-01)

`installer/aegis.nsi:72` → `drivers\wfp_callout\aegis_wfp.sys` (stale, 28,136 B).
`tools/installer.py:35,251` → `build\x64\wfp\aegis_wfp.sys` (current, 42,896 B).
Whichever one an operator uses determines which driver is deployed; both are "the
installer" in the tree today.

---

### S3-01 — A test writes tracked-tree state

`tests/security/test_candidate_labels.py:19-20,32,60-61,75` writes and unlinks
`logs/blocked_ips.json` and `logs/quarantine.json` inside the repository. That
violates TEST HYGIENE item 2 (tests must not write tracked tree state) and can dirty
every tree / invalidate `truth.py` and release gates depending on run order.

---

## 3. Reported by the parallel surveys, not re-verified by me

Listed so nothing is lost, and explicitly **not** counted as fact. Each needs a slice
to confirm before it can drive a fix.

| ID | Claim | Where |
|---|---|---|
| N-02..N-10 | Nose emits v3 only (no fallback); `canonical` counter incremented before send and send result discarded; v3 validation failure has no drop counter; short write truncates a frame; no reconnect backoff; epoch/generation/sequence collide after restart; interface pin is process-local | `nose/capture.go`, `nose/pipe_writer.go` |
| W-01..W-06 | v2 `struct_size` drift: Python/Zig/Go expect 128, C++/brain v2 encoders preserve the caller default (109 in brain); C++ v3 decode does not validate `struct_size`; Python `decode_frame` accepts v3 but C++/Zig frame APIs do not; `CONTRACT_MAP` has no `WIRE_PROTOCOL_V3` | `shared/wire/wire_codec.h`, `brain/canonical_event.py` |
| ABI-03..ABI-09 | Minifilter rows lack operation kind / FileId / VolumeId; requestor is `PsGetCurrentProcessId`; `FLT_POST_OPERATION_DRAINING` unhandled; only `IRP_MJ_CREATE` registered; path clamp 255→219 without marker; comm port `FLT_PORT_ALL_ACCESS` | `drivers/minifilter/*` |
| LIF-04/LIF-05 | `aegis_etw_start` overwrites `consumer_thread` after a failed join (leak / double consumer); `-8` path does not free `properties` | `src/windows/etw_realtime.zig` |
| Zig dead code | Duplicate/unreachable modules (`src/contract/event_queue.zig`, `policy_engine.zig`, `dispatcher.zig`, `replay_engine.zig`, `nids_main.zig`, `xdr/*`) and a production path that bypasses `nose_contract`/`event_fabric` | `src/**` |
| ENF-11 | Legacy pre-retirement block filters can be re-adopted by a recovery path | `drivers/wfp_callout/aegis_wfp.c` |

---

## 4. Refuted by re-verification

Recorded because a survey that only adds findings is not a survey.

**REFUTED — "any local opener can reach the WFP device and issue UNBLOCK".**
`drivers/wfp_callout/aegis_wfp.c:703-714` creates the device with
`IoCreateDeviceSecure(... FILE_DEVICE_SECURE_OPEN ...)` and
`D:P(A;;GA;;;SY)(A;;GA;;;BA)` — SYSTEM and Builtin Administrators only. I also scanned
all four WFP images (including the loaded `F63195B0…`) for the UTF-16 SDDL literal;
**all four contain `D:P(A;;GA;;;SY)`**, so the loaded driver was built with the
secured device object. The residual issue is different and narrower: an
administrator-level process can issue `IOCTL_AEGIS_UNBLOCK_FLOW`
(`aegis_wfp.c:933`) with no per-request identity beyond the admin token — which is
what admin-level access already implies. Severity drops from S1 to S3, and it does
**not** belong in the release-blocking set.

**NOT REPRODUCED — "status reports RUNNING while health reports DEGRADED because of a
latch that never clears".** The split is real (S1-05) but it is not a latch bug: the
raw `status` payload simply does not carry the degraded flag, while `health` does. The
CLI's `status` command renders `DEGRADED` correctly by merging health. The defect is
in the soak tool's criteria and in the self-contradicting `counters` block, not in the
state machine.

---

## 5. Measurement appendix (reproducibles)

```powershell
# driver images and signers
foreach ($p in @('C:\Windows\System32\drivers\aegis_wfp.sys',
                 'C:\Program Files\AEGIS NIDS\drivers\aegis_wfp.sys',
                 'D:\NIDs_Windows\build\x64\wfp\aegis_wfp.sys',
                 'D:\NIDs_Windows\drivers\wfp_callout\aegis_wfp.sys')) {
  $i = Get-Item $p; $h = (Get-FileHash $p -Algorithm SHA256).Hash.Substring(0,16)
  "$h size=$($i.Length) mtime=$($i.LastWriteTime) $p  signer=$((Get-AuthenticodeSignature $p).SignerCertificate.Subject)"
}

# driver start mode
sc.exe qc AegisWfp; sc.exe qc AegisMinifilter

# raw control plane (status vs health)
python tools\aegisctl.py status
python tools\aegisctl.py health

# release digest gate
python tools\release_engineering.py --verify
python -c "import json,io;d=json.load(io.open('build_manifest.json',encoding='utf-8'));a=d['artifacts'];print(len(a),[p['path'] for p in a if p['path'].lower().endswith(('.exe','.dll','.sys'))])"

# evidence chain
python tools\evidence_debt.py          # 708 / 535
python scripts\check_summary.py        # E5_count 166 = 77 evidence + 89 known_gaps

# rule-file ACL
(Get-Acl 'D:\NIDs_Windows\configs\Rules.json').Access

# crash history
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7031; StartTime=(Get-Date).AddDays(-8)} |
  Where-Object { $_.Message -match 'AegisNids' }
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000; StartTime=(Get-Date).AddDays(-8)} |
  Where-Object { $_.Message -match 'aegis_nids' }
```

---

## 6. KIND-ATTR-001 — decision input (the reason this survey was requested)

Root cause is S2-04. The three options now have concrete consequences:

| Option | What it requires | Consequence |
|---|---|---|
| **(a)** retag minifilter as FIM + dedupe against the ETW FIM lane | add a FIM kind to `EventType` (canonical_event.zig:321) **in all six codecs + golden vectors in one patch**; set it at `minifilter_reader.zig:226`; implement dedupe identity across two lanes; new E2 vectors, new E5 pass | largest change, best semantics; two lanes still produce the same file event twice unless dedupe is proven |
| **(b)** retag + retire the ETW FIM lane | same enum/codec change **plus** removing an ETW lane and re-proving FIM coverage (no silent blind spot); E5 must show FIM events still arrive | removes duplicate-source ambiguity; highest risk of losing FIM coverage, needs a host window |
| **(c)** give the minifilter its own kind name, keep both lanes | same enum/codec change; no dedupe work | smallest behavioural change; counters stop lying, duplicates remain but are *visible* rather than hidden |

All three need a wire/schema change touching Zig + Go + C++ + Python ×2 + the shared
golden vector (AGENTS.md TEST HYGIENE item 3). None of them is a one-file edit.

My recommendation: **(c) now, (a) later** — (c) stops the counter from lying with the
least surface area and no E5 window, and (a) becomes a separate dedupe slice once the
FIM lanes are actually being used for correlation.

---

## 7. Remaining work, sized against current evidence

"Done" has three different finish lines. They are not the same date.

### Line 1 — Release Candidate (test-signed, limitations declared)

| Item | State | Work |
|---|---|---|
| #28 WFP→Zig metadata/TCP flags + R9002/R9006/R9007 through a real seam + VMnet1 visibility | open | 2–4 sessions (largest source slice left) |
| #29 threshold decision + KIND-ATTR implement + re-measure | blocked on owner | 1 session + 30–60 min host window |
| S1-01 driver mismatch | **new** | 1 host window (stop/replace/verify/re-hash) |
| S1-02 digest gate | **new** | ~1 session |
| S1-03 evidence hygiene (counts, pointers, historical markers) | **new** | 1–2 sessions |
| S1-04 control-plane mutation auth | **new** | 1 session + host check |
| S1-05 soak criteria + `readiness` | **new** | 0.5 session |
| FREEZE #22 reboot (S2-02) | needs your reboot | 15 min + 1 session |
| Soak 24 h | 9.3 h / 24 h | wall clock only |
| #30 | has 2 dumps, no attribution for 11/10 | 1–2 sessions to analyse, or declare limitation |

Estimate: **~4–7 engineering sessions + one host window + 15 h wall clock**, versus
the 2–4 sessions I estimated before this survey. The delta is entirely the four S1
findings the earlier closeout did not know about. If #30 is declared a limitation
(with the 11/10 events disclosed) the tail is shorter.

### Line 2 — Project Definition of Done (all 10 items)

Adds the evidence debt: **535 of 708 product files (76%)** are named by no evidence
entry. By directory this is concentrated in `src/` (the majority), `scripts/`,
`tools/`, `brain/`, `configs/`, `contracts/` (14/14 unnamed), `go/` and `ts_policy/`.
This is mechanical but large: **6–10 sessions**. Total for Line 2: **~2–3 weeks**.

### Line 3 — Signed E7 release

Unchanged: no signing-key custody. Declared a limitation in `FREEZE-001 §3.1`. No
date can be given until the owner provides key material.

### What is *not* on any line (and should be)

- `readiness` refuses (`ready:false`, `overall_gate:false`) while naming no reason
  (`degraded_components: []`, `failure_reasons: []`) — a release gate with no
  actionable output (S1-05).
- Injection detection is inert (S2-03).
- Two installers ship different drivers (S2-05).
- One test writes tracked-tree state (S3-01).

---

## 8. Recommended order

1. **Answer the two owner decisions**: KIND-ATTR option, and whether #30 is fixed or
   declared (with disclosure).
2. **S1-01 + S2-02 in one host window** (driver replace with hash assertions, start
   mode decision, reboot, R-06 proof). This also produces the clean 24 h soak start.
3. **S1-05 + S1-02 + S1-03 as records/tooling slices** (no host access needed, no
   source-path change to the runtime): make the soak honest, make the digest gate
   independent, make the evidence counts mean what they say.
4. **S1-04 control-plane auth** (source change, security test).
5. **#28 metadata slice**, then **#29/KIND-ATTR implementation + E5 re-measure**.
6. Evidence debt in batches, as the ratchet allows.

Rationale for this order: steps 2–3 make every later claim *checkable*. Doing #28
first would add new E5 claims on top of a soak and evidence chain that cannot
currently distinguish success from silent loss.

---

## 9. Open questions I could not settle from the tree

1. Was the WFP copy failure caused by the driver still being mapped at install time,
   or by `aegis.nsi` being used instead of `installer.py`? Both paths exist; the
   installer logs do not say which one ran.
2. Are the 11/10 02:14/02:17 `7031` events installer-driven (`taskkill`-style restart)
   or genuine crashes? No dump, no WER record, no record entry; only the event log
   distinguishes them, and it does not.
3. Did `D:\NIDs_Windows\drivers\wfp_callout\aegis_wfp.sys` (`EC4A5683…`, Oct 16) ever
   get deployed to any host? It is untracked build output, so history cannot answer.
4. Is the repository-root rule path (`configs\Rules.json`) the intended production
   layout, or an artifact of running the developer build as the service? This decides
   whether S1-04 is a dev-host condition or a shipped one.
