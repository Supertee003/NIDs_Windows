# v1.1 backlog — everything left after v2.0.0

**Created:** 2026-11-17
**Base:** v2.0.0, build source `7c604d5`, tag `v2.0.0` → `7b484a1`
**Companion record:** `analysis/current-head/PROJECT-CLOSEOUT-20261117.md`

This file is the single list of work that v2.0.0 deliberately does not
contain. Nothing here is a defect in a detection verdict on the shipped path.
Do not patch the signed tree to close these items: any `src/` change forces a
rebuild, a re-sign and a new 24 h soak.

**How each open item can actually be closed:** see
`analysis/current-head/CLOSURE-PLAN-5GAPS-20261117.md` (method, acceptance
criteria, cost, and what must come from the owner for each of the five gaps
and the four distribution steps).

## 1. Open gaps (5)

| ID | Sev | Level | What remains | Cost to close |
|---|---|---|---|---|
| `EVI-G2-PEP-CACHE-001-LAB` | — | E5 | PEP cache swap, direction verify, duplicate canary, unblock, base restore | second host, PEP DLL swap, enforcement rights — out of product scope |
| `CAPTURE-DUP-WIFI-001` | P3 | E5 | This Wi-Fi adapter/Npcap delivers every frame twice | try another adapter/host config (raw 802.11, Killer prioritisation); or a bounded, counted dedup keyed by `(ip.id, tcp.seq, payload hash)` that cannot drop a real retransmission |
| `RULE-LAYER-SCOPE-001` | P3 | E1 | AC matcher applies KERNEL_PROCESS payload rules to network bytes, so TLS raises R2003 | scope the AC rule set to the event source's layer, or skip non-decoded payloads; add a pin that a TLS record cannot yield a KERNEL_PROCESS rule id |
| `GAP-QLOSS-ISOLATION-002` | — | E2 | FIM/ETW ingress volume from the storming source is not reduced | reduce ingress at the producer, then re-measure and run a new 24 h soak |
| `ADR-0012-DUP-RATIO-E5-20261108` | — | E5 | Measured FIM repeats do not establish safely coalescible volume (`MEASURED_IDENTITY_UNVERIFIED`) | resolve producer identity first; coalescing stays blocked until then |

### Closed during the 2026-11-17 closure pass

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
   and `tools/installer.py` builds `aegis-installer-5.0.0-current.exe`
   (6,130,207 bytes) from the current tree; the generated script embeds
   `AEGIS_COMMIT 7c604d5`. The remaining item is the **version label** — a
   `6.0.0` installer needs an explicit product version bump, which is a source
   change with its own evidence cycle — plus a fresh-install boot-model test.
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
fails with `LNK1104: cannot open dist\aegis_ipc.dll` while a running process
holds the DLL. 485 other tests in `tests/release tests/tools` pass. Re-run
after stopping the holder, or teach the test to build into an isolated output
directory.

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
3. `GAP-QLOSS-ISOLATION-002` / `ADR-0012` (ingress volume; needs a new soak).
4. Distribution: the 6.0.0 version decision and a fresh-install test, then
   EV certificate + Microsoft attestation/HLK.
