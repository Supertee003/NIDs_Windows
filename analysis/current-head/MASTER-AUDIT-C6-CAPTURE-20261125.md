# MASTER AUDIT — C6 capture visibility, shutdown and monotonic source slice (2026-11-25)

**TARGET HEAD BEFORE SOURCE PATCH:** `46d0955df3906ab19a738fb16f688bb66f99a5c4`
**SOURCE COMMIT:** `7822f4c162f7867555754b7f3677ade33c9548dd`
**BUILD SOURCE BEFORE:** `43a8bcc02358076380fa938b0e5632870643d3c5`

## PATCH DECLARATION

```
PATCH-ID:             C6-CAPTURE-VISIBILITY-SHUTDOWN-MONOTONIC
FLOW-ID:              network frame -> Go Nose -> CanonicalEvent -> Zig decoder
TARGET HEAD:          46d0955
TARGET FILES:         nose/capture.go, nose/inject.go, nose/main.go,
                      nose/collectors.go, nose/talkers_live.go,
                      nose/capture_visibility_test.go (new),
                      src/capture/packet_decoder.zig
TARGET SYMBOLS:       noseCaptureBPF; monotonicNowNS; eventFromPacket; runCapture;
                      collectorStopped; sleepOrStop; startLiveTalkersFeed;
                      decode; decodeIpv6; walkIpv6ExtensionHeaders
IN-SCOPE:             VLAN/QinQ capture filter and two-tag decoder unwrap; bounded IPv6
                      extension-header walk; bounded collector/live-talkers stop;
                      capture error return to main; process-relative monotonic_ns producer
OUT-OF-SCOPE:         R2003 CommandLine producer (FN-1 stays open); rule/wire/golden-vector
                      change; authority and host effects; active IPC nonce/replay;
                      cross-language byte-vector ABI proof; Signed-IR promotion; new
                      release/tag/signature/key; elevated host re-proof
CONTRACT IMPACT:      none — no field, layout, vector or schema change. monotonic_ns keeps
                      its "in-process ordering" meaning; only the producer changes.
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         process-local Go state only
TEST IMPACT:          Go unit tests; Zig decoder + full `zig build test`; records gates
EVIDENCE IMPACT:      E2 unit proof at 7822f4c; E3/E4/E5 remain NOT_PROVEN there
```

## OLD FLOW -> NEW FLOW

- OLD: BPF `ip or ip6` excluded 802.1Q/802.1ad tagged frames; the Zig decoder unwrapped one
  VLAN tag and read only the fixed IPv6 header; `MonotonicNS` was stamped from wall-clock
  `time.Now().UnixNano()` despite a schema meaning of in-process ordering; the live-talkers
  goroutine had no stop channel and the capture goroutine called `os.Exit(1)` directly.
- NEW: BPF `vlan or ip or ip6` and a two-tag decoder unwrap; a bounded, fail-closed IPv6
  extension-header walk; `monotonicNowNS()` from a process-relative origin; stop channels for
  collectors and live talkers; capture errors returned to `main` for one top-level exit.

## INVARIANT

- No CanonicalEvent byte layout, version, golden vector, rule ID, match pattern, policy authority,
  host-effect path, release identity or signing material changed.
- Unknown/over-long IPv6 header chains fail closed with `decode_error`, never a silent truncation
  or a verdict.
- Production remains observe-only (`prevention_gate=closed`, `host_effect_capable=false`).
- R2003 FN-1, active nonce/replay, cross-process event identity and the Zig-vs-TS policy-hash
  byte-stream question remain open and untouched.
- E3/E4/E5 PASS at `43a8bcc` is HISTORICAL at that source and is **not** current-source proof.

## VERIFICATION (E2 only)

| Check | Result |
|---|---|
| `gofmt -l` on changed Go files (logical-diff scope; pre-existing space indentation preserved) | no new formatting drift |
| `go test ./...` (from `nose/`, TMP/GOCACHE redirected to `D:\aegis-tmp`) | `ok aegis-nose` |
| `zig test src/capture/packet_decoder.zig -OReleaseSafe` | 8/8 passed (incl. QinQ, IPv6 ext chain, fail-closed bound, no-ext regression) |
| `cargo build --release` | produced `aegis_pep.dll` + import lib (staged into gitignored `target/release`) |
| `zig build test --summary all` | 8/8 steps, **2142 passed / 10 skipped** (helper libs staged from `build/` into gitignored `target/helpers`) |
| `python tools/rebuild_truth.py` | stamped 10 artifacts to `7822f4c` |
| `python tools/release_engineering.py --refresh-digests` on a clean tree | 674 artifacts kept, 7 digests updated, 0 adopted/dropped; `verify` OK at `source_commit=7822f4c`. Records-only digest restamp; no new artifact, signature, tag or release identity. |
| `python scripts/doc_checker.py` | 0 FAIL, 0 WARN, 23 total |
| `python -m pytest tests/docs tests/release tests/security/test_scope_ratchet.py tests/security/test_evidence_index_integrity.py -q` | 273 passed |
| `python scripts/check_summary.py` | SUMMARY_VALID |
| `python tools/truth.py verify` | TRUTH_VALID @ 7822f4c |
| `git diff --check` | clean |

No elevated action, pipe proof, Npcap host capture, soak, install or signing was run by this
patch. Toolchain artifacts under `target/`, `build/Release`, `zig-out` and `.zig-cache` are
gitignored and not part of the patch.

## EVIDENCE LEVEL

**E2** — unit/component tests at the new build source. E3 (component integration), E4 (system
integration), E5 (Windows host), E6/E7 remain **NOT_PROVEN** at `7822f4c` until the owner runs
the elevated re-proof. This audit does not synthesize host evidence.

## ROLLBACK

Revert source commit `7822f4c` and this records rebaseline. No signed release artifact changes.

## REMAINING RISK

- The Zig decoder now walks common IPv6 extension headers on its direct path; gopacket handles
  them on the Go acquisition path. Neither has a host measurement at `7822f4c`.
- BPF `vlan` admits the outer tag; QinQ reachability is source-level only until host proof.
- `collectorStopped`/`sleepOrStop` are unit-tested; blocked-send behavior under a real TUI and
  elevated daemon is not measured here.
- `processStart` is per-process; event-ID continuity across process restarts is still open.

## OPEN BLOCKERS

Owner-run elevated E3/E4/E5 re-proof at `7822f4c` is required before any current-source host
claim. Active nonce/replay and cross-process monotonic identity remain later source work.

## COMPLETION GATE

**PASS for E2 only.** Full current-source qualification gate remains **OPEN / NOT_PROVEN**.
