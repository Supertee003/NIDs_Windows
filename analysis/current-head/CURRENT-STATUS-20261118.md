# CURRENT STATUS — 2026-11-18 (second pass)

## Identity

- **Records HEAD:** `1e2da48dbd1e0068c04da455ab86ea8f9ce3d3af`
- **Build source HEAD:** `aa42fcaf65c9b2272cad34cb06ebf622180cdb0a`
- **Working branch:** `codex/o2-etw-context`
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
python tools/truth.py verify              -> TRUTH_VALID (source aa42fca)
python tools/final_audit.py --release-check
  PASS  truth_artifacts
  PASS  component_audit      modules 66/66, prod failures 0, part_ii 5/5
  OPEN  release_signature    release/T20-final/ad7948c predates source aa42fca
  PASS  clean_host_e5        STALE: the passing preflight is 2026-11-14;
                             no preflight exists for source aa42fca
  OPEN  soak_24h
  PASS  evidence_debt
  release: NOT SHIPPABLE
```

`clean_host_e5` is reported PASS by the tool because the evaluator accepts any
PASS preflight artifact. That is not current-source evidence: the newest
preflight (`admin-evidence/e5-clean-host-20261117-soak3/preflight-20261117-postlayers.json`)
predates the 2026-11-18 source slices. Treat the gate as **open** until the
current build is installed and preflighted.

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

## Remaining work (soak excluded, owner runs it last)

1. Port/commit the items above; refresh digests and rebuild truth maps.
2. Full matrix: `zig build`, `zig build test`, `cargo build/test`, `cmake`,
   `go build`, pytest sweep.
3. Push the delivery branch and get CI green on this source.
4. Rebuild the RC from `aa42fca` (or its successor), sign, verify.
5. Owner approves the release trust anchor public key.
6. Build the `6.0.0` installer from the final source.
7. In-place install + `host_preflight` + upgrade/rollback drill; re-run the
   Wi-Fi byte-level probe in the same window.
8. Re-run `clean_host_e5` against the installed current build.
9. Merge to `main` and tag `v1.1` only after the board is complete.
10. Soak 24 h alone, then close the board.

## Out of scope on this host (record as limitations, never as passes)

- EV code-signing certificate + Microsoft attestation/HLK (drivers stay
  test-signed).
- A true clean-machine boot model (this host has the toolchain, Npcap and a
  test certificate installed).
- Production host-effect/WFP enforcement (detection-only by design).
