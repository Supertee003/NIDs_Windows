# CURRENT STATUS — 2026-11-18 (second pass)

## Identity

- **Records HEAD at this edit:** `c3cc44f` (records-only tip; final pointer
  commits follow it and do not move the build source)
- **Build source HEAD:** `4169839bff11937060ed4471b3a74717f11a50c3`
- **Delivery branch:** `codex/v1.1-release` (local `codex/o2-etw-context`)
- **Installed runtime:** `C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`
  sha256 `A02FC7FBDCC9B6932E735099F2D056D6B420BDB2AE074B0843E40251907E3497`,
  identical to `zig-out\bin\aegis_nids.exe`.
- **Baseline branch:** `main` / `daf9088` (old baseline; not the release carrier)

These SHAs are intentionally different. A records-only commit does not change
the build source under ADR-0008. `SOURCE_PATHS` in `tools/truth.py` covers
`src`, `rust-src`, `shield`, `nose`, `go`, `brain`, `drivers`, `shared`,
`bridge`, `mouth`, `configs` and the build files; `tools/`, `tests/`, `docs/`
and `installer/` do not move the source commit.

## Gates measured at this pass

```
python tools/truth.py verify              -> TRUTH_VALID (source 4169839)
python tools/release_engineering.py --verify -> OK, 674/674 digests
python tools/final_audit.py --release-check
  PASS  truth_artifacts
  PASS  component_audit      modules 66/66, prod failures 0, part_ii 5/5
  PASS  release_signature    bece8f1 signs SHA256SUMS; owner anchor recorded
  PASS  clean_host_e5        2026-11-14 preflight, loader under C:\Program Files\AEGIS NIDS
  OPEN  soak_24h             no 24 h artifact covers source 4169839
  PASS  evidence_debt        0 unnamed product files
  release: NOT SHIPPABLE (5/6)
```

`clean_host_e5` is reported PASS by the evaluator because it accepts any PASS
preflight artifact, but the newest PASS still predates this build. Treat it as
**provisional until RB-024 installs `bece8f1` and runs `host_preflight`**. The
release signature is no longer provisional: the owner approved
`txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=` in
`docs/gates/RELEASE_TRUST_ANCHOR.md`, the same key that signed `ad7948c`.

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
dedup change and not a closed limitation. Re-measure with `g3_dup_bytes.py` on
the current build in the same elevated window as the install, and close only on
a measured zero.

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
`release_signature`. A new candidate was assembled from records HEAD `bece8f1`
(build source `4169839`) and signed with the same ed25519 key as before:

```
release/T20-final/bece8f1        258 files on disk, 251 checksum entries
SHA256SUMS                       B008EA1CFA24A1A504E80DC950274790C1BF2B7FDAEE49B3D7BE36E8DA17C754
signatures.json                  ed25519, public key txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=
dist/aegis_setup_6.0.0_trial.exe 6233653 B, sha256 BC61B102933C30D8DD404363D088F4DEA503D825E44C8F57FFA4D1B082769C14
```

All 251 per-file digests recompute from the bytes on disk (0 mismatches, 0
missing). The installer packages `zig-out\bin\aegis_nids.exe` from `4169839`, so
the bundle and the signed tree carry the same runtime.

Two defects were found by checking the artifact instead of trusting `RC PASS`:

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

Gate board:

```
PASS  truth_artifacts     TRUTH_VALID at source 4169839
PASS  component_audit     66/66 modules, 0 production failures, part_ii 5/5
PASS  release_signature   bece8f1 signs SHA256SUMS; commit contains runtime 4169839
PASS  clean_host_e5       2026-11-14 preflight, loader under C:\Program Files\AEGIS NIDS
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

## Remaining work (soak excluded, owner runs it last)

1. Run `docs/runbooks/RB-024-final-release-window.md` in one elevated window:
   install `aegis_setup_6.0.0_trial.exe`, run `host_preflight`, confirm both
   capture topologies, re-measure the Wi-Fi byte-level duplicate with
   `g3_dup_bytes.py`, and drill upgrade/rollback.
2. Start the 24 h soak only after step 1, with nothing else touching the host.
   Score it with `--loss-budget 3500 --shed-budget 20000` against the installed
   build from `bece8f1`.
3. When the soak is PASS, rerun `final_audit.py --release-check` for 6/6, record
   the artifact paths in `EVIDENCE_INDEX.json`, then merge `codex/v1.1-release`
   into `main` and tag `v1.1`. Do not merge or tag before then.

## Out of scope on this host (record as limitations, never as passes)

- EV code-signing certificate + Microsoft attestation/HLK (drivers stay
  test-signed).
- A true clean-machine boot model (this host has the toolchain, Npcap and a
  test certificate installed).
- Production host-effect/WFP enforcement (detection-only by design).
