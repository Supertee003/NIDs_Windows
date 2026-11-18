# v1.1 backlog — everything left after v2.0.0

**Created:** 2026-11-17
**Base:** v2.0.0, build source `7c604d5`, tag `v2.0.0` → `7b484a1`
**Companion record:** `analysis/current-head/PROJECT-CLOSEOUT-20261117.md`

This file is the single list of work that v2.0.0 deliberately does not
contain. Nothing here is a defect in a detection verdict on the shipped path.
Do not patch the signed tree to close these items: any `src/` change forces a
rebuild, a re-sign and a new 24 h soak.

**How each open item can actually be closed:** see
`analysis/current-head/CLOSURE-PLAN-5GAPS-20261117.md` (rev.2; method,
acceptance criteria, cost, and what must come from the owner for each of the
five gaps and the four distribution steps).

The closure plan is written for the current test model: **the NIDS host is the
victim** and the Kali VM is the only attacker. There is no Win11 victim VM and
no second host; lab work that needs enforcement runs in an approved
maintenance window on this host with a hash-verified rollback.

## 1. Open gaps (1)

| ID | Sev | Level | What remains | Cost to close |
|---|---|---|---|---|
| `EVI-G2-PEP-CACHE-001-LAB` | — | E5 | PEP cache swap, direction verify, duplicate canary, unblock, base restore | lab window on this host: lab build + canary from Kali + documented block + hash-verified rollback (no second host) |
| `CAPTURE-DUP-WIFI-001` | P3 | E5 | This Wi-Fi adapter/Npcap delivers every frame twice | try another adapter/host config (raw 802.11, Killer prioritisation); or a bounded, counted dedup keyed by `(ip.id, tcp.seq, payload hash)` that cannot drop a real retransmission |
| ~~`RULE-LAYER-SCOPE-001`~~ | P3 | **CLOSED E5** | — (see below) | — |
| `GAP-QLOSS-ISOLATION-002` | — | E5 | Option A holds on both halves of the 20k stimulus: ETW 8,801/37,108 deletes filtered with an aggregate row, FIM 41,520 rows with 0 drops/0 quota/0 tail, ring 0, `R1002` canary passes. Option B was measured and rejected. Only the 24 h soak remains. | the single v1.1 24 h soak |
| ~~`GAP-FIM-NATIVE-OVERFLOW-003`~~ | P2 | **CLOSED E5** | — (see below) | — |

### Closed during the 2026-11-18 closure pass

`GAP-FIM-NATIVE-OVERFLOW-003` (P2) is **CLOSED at E5**: the native
`ReadDirectoryChangesW` helper counts both overflow completions
(`ERROR_NOTIFY_ENUM_DIR` and the zero-byte success), the Zig watcher publishes
the delta, and `queue.stats` exposes `fim_probe.native_overflow`. Re-measured on
the deployed build `a02fc7fb` (source `aa42fca`): the 100-file control batch
reports 0 overflows, the 20,004-file storm reports **7 discarded batches**, all
pipeline loss counters stay 0, the minifilter delivers 40,320 records for the
same operations, and `R1002` still fires. The counter is batch-level because
Windows discards the buffer contents; the lane remains a counted fallback, not
the primary FIM source. Record:
`analysis/current-head/FIM-NATIVE-OVERFLOW-001-20261118.md`.

### Closed during the 2026-11-17 closure pass

`PROCESS-CMDLINE-001` (P2) is **CLOSED at E5 as an accepted limitation**
(2026-11-18): the ETW helper was rebuilt with `WINEVENT_KEYWORD_PROCESS` and the
service restarted after install, but a marker launch produced a 306-byte process
row without the marker, and `Get-WinEvent -ListProvider
Microsoft-Windows-Kernel-Process` shows every `ProcessStart` template (v0..v4)
carries `ImageName` and no `CommandLine` field. The minifilter lane pushes only
the image path. `R2003` therefore cannot match a host process row; `R2001`,
`R2002`, `R2005` still match image names and `R2004` was proven live. A real
command-line source (NT Kernel Logger or driver enrichment) is a v1.1+ feature.
Record: `analysis/current-head/PROCESS-CMDLINE-001-20261118.md`.

`RULE-LAYER-SCOPE-001` (P3) is **CLOSED at E5**, re-measured on the running
installed binary (`ABF1A4AE...`) at 21:26 with a single VMnet1 frame that carried
both `<script>alert(1)</script>` and `IEX(New-Object Net.WebClient).DownloadString`:
six rows (both directions, `src_ip` 192.168.126.1 and .10) carried only `R9059`
(L7), and no `R2003` or any other kernel id; a payload with `IEX` alone produced no
signature match at all. Two limitations are recorded in the record:
`aegisctl forensics list --payload-prefix` returns 0 matches on this build (even for
`GET /`), so attribution was read from `aegis_core.ndjson`; and the stimulus is
host-originated on VMnet1 rather than typed inside the Kali guest, because the
guest cannot be driven here (`vmrun` file/program ops answer "file does not exist"
for `/` itself, before and after a guest restart, and the guest exposes no port to
reach it). Evidence: `RULE-LAYER-SCOPE-001-E5-20261117c`.

`REL-EOL-DIGEST-001` (P3/E1) is **CLOSED at E2**, not deferred: the signed
`SHA256SUMS` digest is the CRLF form (`9F87BF36...`) while the git blob is LF
(`668C26B1...`), so a clean checkout with `core.autocrlf=false` could not
re-derive it. `tools/verify_release_digest.py` now accepts the stored or the
LF→CRLF form, prints which form matched, and fails on tampered content; five
pins in `tests/release/test_release_digest_eol.py` cover the shipped tree, an
LF checkout, a tampered line, a missing signature and the exit code. The signed
artifact itself is unchanged. Evidence: `REL-EOL-DIGEST-001-E2-20261117`.

`CAPTURE-LOOPBACK-001` (P2) is **CLOSED at E5**: `\Device\NPF_Loopback` exists
and the shipped nose captured it (idle 66 packets/15 s; 2,378 with 200 local
HTTP requests). The gap was the sensor binding, not a missing capability;
loopback self-tests must pin `-iface "\Device\NPF_Loopback"`. No restart or
source change. Evidence: `CAPTURE-LOOPBACK-001-E5-20261117`.

`E5-RECHECK-STALE-IMAGE-20261101` is **CLOSED at E5**: an RB-022 window on the
installed image (`7955A6E3...`) with bridged Kali `192.168.1.44` produced 15
attributed rows across `R0056`/`R9059`/`R0088`/`R9064`/`10004`/`10001`/`R9002`/
`R9006`, with zero dropped/shed/quota deltas and no service restart. Evidence:
`E5-RECHECK-STALE-IMAGE-001-E5-20261117`.

`KIDS-002-20261101` is **CLOSED at E5**: the same live window recorded 11
`policy=block` rows as `enforcement_status=observed` with
`host_effect_confirmed=false`, and 4 protocol anomalies as observe-only; no row
read `enforced`. Focused tests 7/7 and the Zig fail-closed unit 1/1 passed.
Evidence: `KIDS-002-E5-20261117`.

`ADR-0012-DUP-RATIO-E5-20261108` is **CLOSED at E5, against coalescing**. A
create-once measurement on the installed image created 20,000 unique paths with
exactly one open each: 20,042 minifilter records and 12 same-path/same-PID
repeats, against 11.8 expected from a 30 s idle baseline (a 1,000-file pilot
agreed). If the delivery layer duplicated creates, a single-open unique path
would have produced a second row; none did. The 47.5% within-batch repeat ratio
is therefore distinct opens, so the proposed minifilter `(path, kind, pid)`
coalescer is rejected and no suppressing coalescer may deploy. No restart, no
source change, no re-sign. Evidence: `ADR-0012-SINGLE-HOST-E5-20261117`; record:
`ADR-0012-DECISION-20261117.md`.

## 2. v1.1 source items not yet filed as gaps

- **Stale ingress comment.** `src/pipeline/event_processor.zig:335` still says
  direct Npcap is the only ingress with a full Ethernet payload. The Nose v3
  payload path disproved that (see `IDS-L7-003-20261117.md` §2). Documentation
  fix inside `src/`.
- **Dedup, if chosen.** Only with a bound, a counter, and a proof that a real
  retransmission is never suppressed. Silent dedup is forbidden by
  `AGENTS.md` (silent event loss).
- **Preserved Copilot work.** `5e62f23` (layer-scoped AC, FIM coalescing,
  loopback prep) and `16cbbff` (loopback capture, different `test_e6` variant)
  are local-only, unvalidated, and outside the release. Adopting them is a
  v1.1 decision that requires its own build + evidence cycle.

## 3. Distribution steps (outside source scope)

1. **Driver signing.** EV certificate + Microsoft attestation/HLK. Today the
   drivers are test-signed and load only on a test-signing host.
2. **Installer.** The NSIS toolchain is present (`C:\Program Files (x86)\NSIS`)
   and `tools/installer.py` builds `aegis-installer-6.0.0.exe` (the 6.0.0 bundle line; the product/runtime versions stay 5.0.0 by design, see the operator manual)
   (6,130,207 bytes) from the current tree; the generated script embeds
   `AEGIS_COMMIT 7c604d5`. The remaining item is the **version label** — a
   `6.0.0` installer needs an explicit product version bump, which is a source
   change with its own evidence cycle — plus install/uninstall/boot coverage.
   Under the single-host model that coverage is an **in-place reinstall on this
   host** (backup → hash compare → uninstall → install → reboot → smoke), which
   is E5 but is not a clean-machine boot model; that limitation must be
   recorded, not hidden.
3. **Scanner coverage.** DONE locally on 2026-11-17: `bandit` 1.9.4 reported
   401 findings (5 HIGH, all constant `os.system('cls'/'clear')`; 27 MEDIUM
   triaged; 369 LOW) and `pip-audit` 2.10.1 reported 0 known vulnerabilities
   across 37 dependencies. Raw output is in
   `admin-evidence/dist-scanners-20261117/`; keep CI green as well.
4. **Production rebuild.** `KNOWN_LIMITATIONS.md` requires rebuilding binaries
   from source for a production cut; the signed tree is a release candidate
   assembled from the working tree.

## 4. Known environment issue (not a code defect)

`tests/release/test_native_build_and_scripts.py::test_bridge_builds_into_dist`
used to fail with `LNK1104: cannot open dist\aegis_ipc.dll` while a stray
elevated `pythonw.exe` (PID 3800, identified with the Restart Manager API; not an
AEGIS process) held the DLL.

**RESOLVED at E2 on 2026-11-17** by the isolated-output option: the test now
copies `bridge/` into `tmp_path` and builds there, so its `../dist` does not
exist yet and must be created by configure -- the clean-checkout property is
proven more strictly, and a holder on the repository's `dist/` can no longer
mask or fake the result. `tests/release/test_native_build_and_scripts.py` is
10/10 passing with PID 3800 still alive, and the test writes nothing into the
repository. Killing the stray process is no longer required for a green run;
the DLL in `dist/` is only regenerated once it is gone or on an elevated run of
the bridge build.

## 5. Worktree disposition

| Branch | Commit | Decision |
|---|---|---|
| `supertee003-repository-baseline-alignment` | `5e62f23` | keep as v1.1 archive (unvalidated) |
| `supertee003-loopback-capture-support` | `16cbbff` | keep as v1.1 archive (unvalidated) |
| `supertee003-soak-closeout-prep` | `daf9088` | keep pending owner decision — the commit is identical to `origin/main` (2026-09-24), so despite the branch name it holds no post-soak or release content |
| `copilot-prewarm-vigilant-giggle` (detached) | `2d19381` | disposable |

`daf9088` is already published as `origin/main`; the other three refs in this
table are local-only. No branch here is signed, installed, or referenced by the
release.

## 6. Suggested order if v1.1 starts

1. The stale ingress comment (cheap, no runtime behaviour). `REL-EOL-DIGEST-001`,
   `CAPTURE-LOOPBACK-001`, `E5-RECHECK-STALE-IMAGE-20261101` and `KIDS-002` are
   already closed and need no v1.1 slot.
2. `RULE-LAYER-SCOPE-001` + `CAPTURE-DUP-WIFI-001` dedup decision (both change
   detection evidence; batch them into one build).
3. `GAP-QLOSS-ISOLATION-002` (ingress volume; the ETW `NameDelete` lane, needs a
   new soak). `ADR-0012` is closed and needs no slot.
4. Distribution: the 6.0.0 version decision and an in-place reinstall test, then
   EV certificate + Microsoft attestation/HLK.
