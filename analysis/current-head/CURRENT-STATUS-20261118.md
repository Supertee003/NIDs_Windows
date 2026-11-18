# CURRENT STATUS — 2026-11-18 (second pass)

## Identity

- **Signed candidate:** `b597e71` (records tip when signed; later records-only
  commits do not move the build source)
- **Build source HEAD:** `f4cde3c503fd8b696183751a608b999768caa769`
- **Delivery branch:** `codex/v1.1-release` (local `codex/o2-etw-context`)
- **Installed runtime:** `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`
  sha256 `0CB573EC6CF3B77BE5CBB477BA7803F4C63361F325AB22A561343092A4C0DF1F`,
  installed by the 2026-11-19 RB-024 revalidation; identical to
  `zig-out\bin\aegis_nids.exe` and `release/T20-final/b597e71/bin/aegis_nids.exe`.
- **Baseline branch:** `main` / `daf9088` (old baseline; not the release carrier)

These SHAs are intentionally different. A records-only commit does not change
the build source under ADR-0008. `SOURCE_PATHS` in `tools/truth.py` covers
`src`, `rust-src`, `shield`, `nose`, `go`, `brain`, `drivers`, `shared`,
`bridge`, `mouth`, `configs` and the build files; `tools/`, `tests/`, `docs/`
and `installer/` do not move the source commit.

## Gates measured at this pass

```
python tools/truth.py verify              -> TRUTH_VALID (source f4cde3c)
python tools/release_engineering.py --verify -> OK, 674/674 digests
python tools/final_audit.py --release-check
  PASS  truth_artifacts
  PASS  component_audit      modules 66/66, prod failures 0, part_ii 5/5
  PASS  release_signature    b597e71 signs SHA256SUMS; owner anchor recorded
  PASS  clean_host_e5        2026-11-19 preflight, loader under C:\Program Files\AEGIS NIDS
  OPEN  soak_24h             no active window: two 2026-11-19 windows voided by owner decision; one fresh window to start after remaining work
  PASS  evidence_debt        0 unnamed product files
  release: NOT SHIPPABLE (5/6)
```

`clean_host_e5` is PASS on the current build: RB-024 revalidation installed the
rebuilt `b597e71` bundle and `host_preflight` wrote
`admin-evidence/e5-clean-host-20261119-final/preflight-20261119.json`
(PASS, 0 failed checks). The evaluator reports the newest PASS preflight by its
`YYYYMMDD` stamp; the gate's rule (loader under `C:\Program Files\AEGIS NIDS`) is
unchanged. The release signature is no longer provisional: the owner approved
`txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=` in
`docs/gates/RELEASE_TRUST_ANCHOR.md`, and that key signed `b597e71` after the
fail-closed source change. RB-024 steps 1–6 are recorded in
`analysis/current-head/RB-024-F4CDE3C-20261119.md`.

## What this pass changed

1. Ported the CI staging fix: `.github/workflows/ci.yml` now runs
   `python tools/stage_helpers.py --stage` after the native build, so installer
   tests no longer fail on a missing/older `zig-out/bin`.
2. Ported detached Ed25519 verification into `tools/final_audit.py` plus the
   trust-anchor fail-closed rule (`AEGIS_RELEASE_TRUSTED_PUBLIC_KEY`). The
   signature record alone is no longer accepted as proof; the owner must
   approve the public key.
3. Ported the matching tests (`tests/tools/test_sign_release.py`,
   `tests/release/test_release_board.py`).
4. CI triggers now include `fix/**` pushes and `codex/**` pull requests.
5. Restored the records/source HEAD distinction in `AGENTS.md` and
   `AI_CONTEXT.md` with the current SHAs.
6. Corrected the unsigned driver images in the release bundle (`7d91e30` replaces
   the rejected `bece8f1`) and recorded the corrective patch in
   `analysis/current-head/RC-7D91E30-20261118.md`.
7. Made `evaluate_clean_host` report the newest PASS preflight by its
   `YYYYMMDD` stamp, so the release board cites the RB-024 artifact instead of
   the 2026-11-14 one. The gate condition itself did not change.

## Wi-Fi duplicate — corrected framing

`CAPTURE-DUP-WIFI-001` is not a VMnet1/lab-topology question. The shipped
selector (`nose/capture.go:firstUpDevice`) skips VMware/Hyper-V/Bluetooth and
captures on the physical Wi-Fi adapter; `LAB-WIFI-001` measured exactly that.
The correct lab is therefore Kali bridged over Wi-Fi (RB-022), and the Wi-Fi
adapter is both the production and the lab capture path.

The 02:39 capture remains a real capture-path duplication (5 byte-identical
`host_tx` pairs in 14 frames, 3.1-12.6 us apart). It did not reproduce in
29,070 later frames (including 1,126 fps with the nose handle attached), the
VMnet1 control had 0 pairs, and the product path is 1 event per frame
(`nose: packets=26300 canonical=26300 dropped=0`). Root cause is not claimed.

Disposition: keep the item as an **open environmental risk**, not a product
dedup change and not a closed limitation. RB-024 re-measured it on the installed
`7d91e30` build: the 5-tuple ratio reported 66 pairs in 1,084 frames, but the
byte-level probe on that same pcap reported 0 identical-byte pairs. Per RB-024
the item stays open and the pcap is retained; no new product defect is claimed.

`CAPTURE-SELECT-001` (next section) removes the one *product-side* way to arm a
second reader on an adapter the canonical reader already owns. The measured
Npcap duplicate is still unexplained and remains open on its own terms.

## Capture selection — CAPTURE-SELECT-001

Requirement from the owner: the system must genuinely support both lab
topologies and switch between them, not just one rehearsal path.

That capability already existed as two machine-scope knobs (`AEGIS_NOSE_IFACE`
for Go Nose, `AEGIS_DAEMON_IFACE` for the daemon's direct reader) but the guard
compared **spellings**. `nose=\Device\NPF\{CE375996...\}` and `daemon=VMnet1`
name one adapter, share no substring, and were therefore judged disjoint: the
direct reader would open the adapter Nose already owns and duplicate canonical
events.

This pass closes that hole and makes the decision operable:

| Surface | Change |
|---|---|
| `src/capture/npcap_adapter.zig` | `resolveSelector` (exact name, else a unique description substring; ambiguity resolves to nothing) and `selectorsResolveDisjoint` (resolved device identity). `open()` refuses `CaptureIfaceOverlapsNose` before any handle. |
| `src/daemon.zig` | Pre-check documented as spelling-level; the adapter is the authority on identity. |
| `tools/capture_select.py` | `--list/--show/--plan/--apply/--clear/--verify`; pins canonical names, refuses ambiguity and overlap, writes only the two machine variables with `--apply`, never restarts a service. |
| `docs/runbooks/RB-023` | Switching procedure between Wi-Fi bridged (RB-022) and host-only VMnet1 (RB-021), with the restart cost stated. |

Measured read-only on this host: nose pinned to the Killer Wi-Fi adapter
(target `192.168.1.39`), daemon pinned to VMnet1, `direct capture: enabled`,
ingress advancing (+54 frames), verdict `CAPTURE_SELECT_OK`. Both topologies
therefore run on this host today; switching is a validated one-command change
plus a deliberate restart.

## Release candidate and bundle — closed

`release/T20-final/ad7948c` predated the shipped runtime, so it could not close
`release_signature`. A candidate was assembled from records HEAD `bece8f1`
(build source `4169839`), but the first elevated RB-024 attempt proved its two
kernel telemetry drivers were unsigned (`WIN32_EXIT_CODE 577`). Those images
were re-signed with the already-trusted test certificates, and the corrected
candidate `7d91e30` was assembled and signed with the owner-approved key:

```
release/T20-final/7d91e30        258 files on disk, 251 checksum entries
SHA256SUMS                       43377D8775F6581F9AD64F9247D6A7F82E776E5845861B260F079351E60D4FE9
signatures.json                  ed25519, public key txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=
dist/aegis_setup_6.0.0_trial.exe 6236213 B, sha256 296780A963A3DD31F311EFE6C1FA3CFE46DEBC51ACF8633FEA23D3871111D34E
```

All 251 per-file digests recompute from the bytes on disk (0 mismatches, 0
missing). The installer packages `zig-out\bin\aegis_nids.exe` from `4169839`,
sha256 `4CDC1999D202359FCBD3B8EB32CE9BB460A49EA3C2AA108A45C92CC522ADB676`, so
the bundle and the signed tree carry the same runtime. `bece8f1` is retained as
the rejected tree; the correction and its evidence are in
`analysis/current-head/RC-7D91E30-20261118.md`.

Three defects were found by checking the artifact instead of trusting `RC PASS`:

- **SIGNED-TREE-001** — `* text eol=lf` rewrote the signed `SHA256SUMS` bytes on
  commit (`C1502245...` signed vs `0A86680F...` committed for `ad7948c`), so a
  signature verified on this machine and failed on every clone. `release/**` is
  now `-text`, every signed tree is re-staged byte-for-byte, and
  `tests/release/test_signed_tree_bytes.py` recomputes each committed digest.
- **PACKAGING-CACHE-001** — the first candidate copied
  `brain/aegis_brain_cython/.pytest_cache/` into the signed tree, making the
  bytes unreproducible and shipping local test names. `release_candidate.py`
  now ignores tool/test caches and a pin covers it; that tree was deleted and
  rebuilt.
- **DRIVER-TESTSIGN-001** — the first elevated RB-024 install left `AegisWfp`
  and `AegisMinifilter` STOPPED with exit 577 because `bece8f1` packaged the
  current WDK outputs before they were test-signed. Both images were re-signed
  with the certificates already trusted on this host, the installer and
  candidate were rebuilt, and `7d91e30` now carries `Valid` driver signatures.
  No source, policy or authority changed; build source stays `4169839`.

Gate board:

```
PASS  truth_artifacts     TRUTH_VALID at source 4169839
PASS  component_audit     66/66 modules, 0 production failures, part_ii 5/5
PASS  release_signature   7d91e30 signs SHA256SUMS; commit contains runtime 4169839
PASS  clean_host_e5       2026-11-18 preflight, loader under C:\Program Files\AEGIS NIDS
OPEN  soak_24h            no 24 h artifact covers source 4169839
PASS  evidence_debt       0 unnamed product files
```

The abandoned `e5-clean-host-20261117-soak3` window (1.28 h, runtime that no
longer exists) had its two `soak-*.json` files renamed to `abandoned-soak-*.json`
with an `ABANDONED.md`; the gate now reports the honest newest artifact
(`soak2`, 48.43 h, FAIL for a mid-soak restart) instead of a half-open window.

## CI on the pushed delivery branch

| Run | Tip | Result |
|---|---|---|
| 44314438349 | `7920b01` | FAIL: only `Python Control Plane Tests` (an ignored `dist/aegis_ipc.dll` was listed as an evidence artifact) and the aggregate matrix job that depends on it |
| 44323795191 | `6b1b664` | SUCCESS: all required jobs green; `Zig Build & Test` and `Cross-language CI Matrix` included |
| 44325060322 | `1ab2109` | SUCCESS: all required jobs green, `Zig Build & Test` 4m11s, aggregate matrix green |
| 44328263809 | `7d91e30` | SUCCESS: all required jobs green on the final pushed tip, including `Zig Build & Test` and `Cross-language CI Matrix` |

The first failure was a portability defect in `EVIDENCE_INDEX.json`, not a
product regression: the pointer was removed, all remaining pointers were checked
against `git ls-files`, and both follow-up runs passed. The WDK job and package
job are intentionally `skipped` on this public runner.

Local full suite on the same tree: 1423 passed, 4 skipped, 1 xfailed, 1 xpassed,
27 subtests passed in 304.82 s. `zig build test` is green on both passing CI
runs. Two fresh-cache local runs on source `4169839` also exited 0 with
`3337/3347 tests passed; 10 skipped`, so `SUITE-FLAKE-001` is
`CLOSED_AT_RECORDED_HEAD` in `EVIDENCE_INDEX.json` (see
`analysis/current-head/SUITE-FLAKE-RESOLUTION-20261118.md`). The root cause of
the historical deaths is not claimed and no source was changed to make them go
away.

Only one known gap remains open: `GAP-QLOSS-ISOLATION-002`, whose remaining gate
is the owner-run 24 h soak.

## RB-024 steps 1-6 — complete

One elevated window on 2026-11-18 completed the whole pre-soak procedure on the
corrected `7d91e30` bundle. Result artifact:
`admin-evidence/e5-clean-host-20261118-final/RB-024-result.json`.

- Candidate signature and board verified; only `soak_24h` OPEN.
- Both driver images `Valid` before and after install; all four services
  `RUNNING`; installed runtime sha256 `4CDC1999...`.
- `host_preflight` PASS, 0 failed checks, 5.4 min daemon uptime.
- Capture selection `CAPTURE_SELECT_OK`, two disjoint devices, ingress +432.
- Wi-Fi re-measure: 66/1084 ratio pairs but **0/1084 byte-identical pairs**. Per
  RB-024 the sighting stays open and the pcap is retained; no capture-path
  defect is claimed.
- Upgrade/rollback drill PASS, snapshot `20261118153506`, `AegisNids` RUNNING.
- `soak_started = false`.

## Remaining work (soak is the only release gate)

**Soak void notice (2026-11-19):** the window opened at `2026-11-19T00:20:11`
on the pre-change installed image is **VOIDED BY SUPERSEDED BUILD** because the
fail-closed source slice moved the build source to `f4cde3c`. It never reached
PASS and is not a failed soak. It is retained only for provenance.

**Second window also voided:** the window started `2026-11-19T01:44:10` was
stopped at 0.2 h by owner decision so every AI handoff could be audited first.
It is `VOIDED_BY_OWNER_DECISION_PENDING_HANDOFF_AUDIT` in
`admin-evidence/e5-clean-host-20261119-final/voided-soak-owner-audit-20261119.json`
(0 loss, 0 shed, no problems, 4/4 services RUNNING, never PASS). It is not a
failure and not release proof.

**Handoff audit:** `analysis/current-head/AI-HANDOFF-AUDIT-20261119.md` inspected
all 9 worktrees, the stash and all scratch locations. No genuinely unmerged
current work exists; nothing to port. The fail-open reversion in
`bsvfvv3ocng18lqju64moj` must **not** be copied.

**PR #36 conflict resolved before the soak:** `63990c8` merged `origin/main`
(`daf9088`) into `codex/v1.1-release` with `-s ours`. The release tree, build
source `f4cde3c`, signed candidate `b597e71` and installer are unchanged; only
the PR's mergeability was fixed.

1. Start one fresh 24 h window with `--baseline auto` on the unchanged build;
   record its new baseline and first delta, then recheck against **that**
   baseline. Do not install, restart, switch capture topology, or run
   adversarial load during the window. Finish with `--loss-budget 3500
   --shed-budget 20000` and follow steps 7–8 of
   `docs/runbooks/RB-024-final-release-window.md`.
2. When the soak is PASS, rerun `final_audit.py --release-check` for 6/6, record
   the final artifact paths in `EVIDENCE_INDEX.json`, merge
   `codex/v1.1-release` into `main`, tag `v1.1`, and delete the release branch.
   Do not merge or tag before then.

## Out of scope on this host (record as limitations, never as passes)

- EV code-signing certificate + Microsoft attestation/HLK (drivers stay
  test-signed).
- A true clean-machine boot model (this host has the toolchain, Npcap and a
  test certificate installed).
- Production host-effect/WFP enforcement (detection-only by design).

## AI handoff disposition (audited 2026-11-19, before the final soak)

These local-only `.manus/worktrees/*` artifacts are inventoried so no handoff is
silently lost. None is on the delivery branch and none changes the current
build source `f4cde3c`. The full read-only audit is
`analysis/current-head/AI-HANDOFF-AUDIT-20261119.md`: **no unmerged current
work; nothing to port.**

| Worktree / artifact | Disposition |
|---|---|
| `gqdpidnmund6c83v5uk40n` (`closeout/rule-layer-failclosed-001`, `3aafce0` + `e8112be`) | **INCLUDED IN v1.1 (owner decision 2026-11-19).** Ported onto current source as build source `f4cde3c` (the old patch used the pre-PROC-LAYER one-argument mapper). The fail-closed selection seam and the additive `rule_layer_unavailable_events` metric are proven at E2 in `RULE-LAYER-FAILCLOSED-001-20261119.md`. Because this moved the build source, the earlier 24 h window is voided and RB-024 + soak restart once on `f4cde3c`. |
| `bvgnivewxkgl19ends2e4n` (untracked `RELEASE-SIG-CRYPTO-BYPASS-20261118.md`, `TRUTH-AND-EVIDENCE-RECONCILIATION-20261118.md`) | **SUPERSEDED.** Written against source `b955f91` / records `ef728b3`. Their OPEN P0 claims (#33 crypto bypass, #32 source/evidence reconciliation) are resolved at release tip by the Ed25519 trust-anchor gate and the records-only truth fixes; both issues are closed on GitHub. Banners added in place; do not port as current claims. |
| `bsvfvv3ocng18lqju64moj` (detached `f01bc04`, dirty board files + dirty `event_processor.zig` + untracked `release/T20-final/09ced4f/`) | **HISTORICAL — DO NOT PORT.** The dirty Zig file **reverts** `resolveRuleAutomaton`, `g_ac_skipped_unavailable_layer` and the fail-closed test; copying it would reintroduce fail-open. Board rewrites are `final_audit.py` side-effects. Nothing needed for v1.1. |
| `crtxl0uoqqyft7d3oxbl4y` (`fix/stopline-truth-ci-signature-001`, `317693b`) | **INCORPORATED / SUPERSEDED.** Signature-verification work is in the delivery branch, which also carries the newer newest-PASS preflight selection. |
| `.manus/mcp-results`, `.cloud-attachments`, `.work`, root `AEGIS_*HANDOFF*` reports | **HISTORICAL / IGNORED SCRATCH.** Transient tool payloads, old lab scratch and 2026-09/10 handoffs; no current release claim. |

Invariant: this section is records-only. It does not move the build source,
change the signed candidate, or alter the running soak window.
