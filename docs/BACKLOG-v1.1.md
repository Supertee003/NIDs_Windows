# v1.1 backlog — everything left after v2.0.0

**Created:** 2026-11-17
**Base:** v2.0.0, build source `7c604d5`, tag `v2.0.0` → `7b484a1`
**Companion record:** `analysis/current-head/PROJECT-CLOSEOUT-20261117.md`

This file is the single list of work that v2.0.0 deliberately does not
contain. Nothing here is a defect in a detection verdict on the shipped path.
Do not patch the signed tree to close these items: any `src/` change forces a
rebuild, a re-sign and a new 24 h soak.

## 1. Open gaps (8)

| ID | Sev | Level | What remains | Cost to close |
|---|---|---|---|---|
| `CAPTURE-LOOPBACK-001` | **P2** | E4 | Loopback traffic is not captured by this install, so a self-test cannot feed detection | install the Npcap loopback adapter (`DLT_LOOP`), bind a second sensor instance or a lab interface, prove `npcap_sensor` rows for a loopback stimulus |
| `E5-RECHECK-STALE-IMAGE-20261101` | — | E1 | RB-021 canaries were never sent from a lab peer against the current image | a lab peer + one RB-021 window; the image half is already resolved (installed sha == build sha) |
| `EVI-G2-PEP-CACHE-001-LAB` | — | E5 | PEP cache swap, direction verify, duplicate canary, unblock, base restore | second host, PEP DLL swap, enforcement rights — out of product scope |
| `KIDS-002` | — | E2 | Host-evidence half of the gate-closed policy flow | reinstall + supervised host run; source suite is green |
| `CAPTURE-DUP-WIFI-001` | P3 | E5 | This Wi-Fi adapter/Npcap delivers every frame twice | try another adapter/host config (raw 802.11, Killer prioritisation); or a bounded, counted dedup keyed by `(ip.id, tcp.seq, payload hash)` that cannot drop a real retransmission |
| `RULE-LAYER-SCOPE-001` | P3 | E1 | AC matcher applies KERNEL_PROCESS payload rules to network bytes, so TLS raises R2003 | scope the AC rule set to the event source's layer, or skip non-decoded payloads; add a pin that a TLS record cannot yield a KERNEL_PROCESS rule id |
| `GAP-QLOSS-ISOLATION-002` | — | E2 | FIM/ETW ingress volume from the storming source is not reduced | reduce ingress at the producer, then re-measure and run a new 24 h soak |
| `ADR-0012-DUP-RATIO-E5-20261108` | — | E5 | Measured FIM repeats do not establish safely coalescible volume (`MEASURED_IDENTITY_UNVERIFIED`) | resolve producer identity first; coalescing stays blocked until then |

### Closed during the v2.0.0 closeout pass (2026-11-17)

`REL-EOL-DIGEST-001` (P3/E1) is **CLOSED at E2**, not deferred: the signed
`SHA256SUMS` digest is the CRLF form (`9F87BF36...`) while the git blob is LF
(`668C26B1...`), so a clean checkout with `core.autocrlf=false` could not
re-derive it. `tools/verify_release_digest.py` now accepts the stored or the
LF→CRLF form, prints which form matched, and fails on tampered content; five
pins in `tests/release/test_release_digest_eol.py` cover the shipped tree, an
LF checkout, a tampered line, a missing signature and the exit code. The signed
artifact itself is unchanged. Evidence: `REL-EOL-DIGEST-001-E2-20261117`.

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
2. **Installer 6.0.0.** Only `aegis-installer-5.0.0.exe` is present;
   `tools/installer.py --package` needs NSIS `makensis` and fails closed
   without it. Confirm the boot model (service start mode, boot sequence
   registration) for a fresh install.
3. **Scanner coverage.** `bandit` and `pip-audit` are not installed locally;
   rely on CI or install them before a distribution cut.
4. **Production rebuild.** `KNOWN_LIMITATIONS.md` requires rebuilding binaries
   from source for a production cut; the signed tree is a release candidate
   assembled from the working tree.

## 4. Known environment issue (not a code defect)

`tests/release/test_native_build_and_scripts.py::test_bridge_builds_into_dist`
fails with `LNK1104: cannot open dist\aegis_ipc.dll` while a running process
holds the DLL. 480 other tests in `tests/release tests/tools` pass. Re-run
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

1. The stale ingress comment (cheap, no runtime behaviour). `REL-EOL-DIGEST-001`
   is already closed and needs no v1.1 slot.
2. `RULE-LAYER-SCOPE-001` + `CAPTURE-DUP-WIFI-001` dedup decision (both change
   detection evidence; batch them into one build).
3. `GAP-QLOSS-ISOLATION-002` / `ADR-0012` (ingress volume; needs a new soak).
4. `CAPTURE-LOOPBACK-001` (adapter install; unblocks self-test).
5. Distribution: installer, scanners, then certificates.
