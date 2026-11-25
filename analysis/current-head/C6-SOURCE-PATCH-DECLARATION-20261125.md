# C6 source patch declaration — capture visibility, shutdown, monotonic time

**TARGET HEAD:** `46d0955df3906ab19a738fb16f688bb66f99a5c4`
**BUILD SOURCE BEFORE PATCH:** `43a8bcc02358076380fa938b0e5632870643d3c5`

## PATCH DECLARATION

```
PATCH-ID:             C6-CAPTURE-VISIBILITY-SHUTDOWN-MONOTONIC
FLOW-ID:              network frame -> Go Nose -> CanonicalEvent -> Zig decoder
TARGET HEAD:          46d0955
TARGET FILES:         nose/capture.go
                      nose/inject.go
                      nose/main.go
                      nose/talkers_live.go
                      nose/capture_visibility_test.go (new)
                      src/capture/packet_decoder.zig
TARGET SYMBOLS:       noseCaptureBPF; monotonicNowNS; eventFromPacket; runCapture;
                      startLiveTalkersFeed; decode; decodeIpv6
IN-SCOPE:             VLAN/QinQ capture filter and decoder; bounded IPv6 extension-header
                      walk; bounded collector stop; error propagation from capture goroutine;
                      in-process monotonic_ns producer
OUT-OF-SCOPE:         R2003 command-line producer; rule/wire/golden-vector change; authority
                      and host effects; active IPC nonce/replay implementation; cross-language
                      byte-vector ABI proof; Signed-IR promotion; new release/tag/signature/key
CONTRACT IMPACT:      none — no field, layout, vector or schema change; monotonic_ns keeps its
                      documented "in-process ordering" meaning, and the producer is corrected to
                      match it.
ABI IMPACT:           none
AUTHORITY IMPACT:     none
STATE IMPACT:         process-local Go state only; no daemon state authority change
TEST IMPACT:          go test ./...; zig build test; doc/truth/release gates after rebaseline
EVIDENCE IMPACT:      E2 unit proof at the new build source; E3/E4/E5 remain NOT_PROVEN there
                      until owner-run elevated re-proof
```

## OLD FLOW -> NEW FLOW

- OLD: BPF `ip or ip6` excludes 802.1Q/802.1ad tagged frames. The Zig decoder unwrapped one
  VLAN tag only and read only the fixed IPv6 header. `MonotonicNS` was stamped from
  `time.Now().UnixNano()` (wall clock) despite the schema saying in-process ordering. The
  live-talkers collector had no stop channel; the capture goroutine called `os.Exit(1)` itself.
- NEW: a shared BPF constant admits `vlan`, the Zig decoder unwraps up to two tags and walks
  common IPv6 extension headers with bounded iterations, `MonotonicNS` comes from a
  process-relative monotonic helper, the live-talkers loop has a stop channel, and capture
  goroutine errors are returned to main for a single top-level exit.

## INVARIANT

- No `CanonicalEvent` byte layout, version, golden vector, rule ID, match pattern, policy
  authority, host-effect path, release identity or signing material changes.
- Unknown/unsupported IPv6 headers stop safely without a silent truncation: bounded decode
  errors are exposed, not converted into a verdict.
- Production remains observe-only; no WFP mutation and no enforcement claim.
- Re-proof at the new build source is **owner action**. This patch claims E2 only.

## VERIFICATION GATE

1. `gofmt -l` clean on changed Go files.
2. `go test ./...` exit 0 from `nose/`.
3. `zig build test --summary all` exit 0.
4. Commit source, then run `python tools/rebuild_truth.py` and `python tools/truth.py verify`.
5. Rebase records/docs/evidence to the new build source; run doc checker, release/docs tests,
   scope ratchet, evidence-index integrity, `git diff --check`.
6. Owner-run elevated E3/E4/E5 re-proof is a separate gate and remains NOT_PROVEN here.

## ROLLBACK

Revert the source commit and the following records commit; no signed release artifact changes.

## REMAINING RISK

- gopacket handles IPv6 extension headers on the Go path; the new Go test pins the observed
  behavior. The Zig decoder implements its own bounded walk for the disjoint direct path.
- Active IPC nonce/replay, process-local event-ID generation across restarts, and the Zig-vs-TS
  policy hash byte-stream question are deliberately untouched and remain open.
