# Canonical pipe-reader bounded shutdown + exact counter deltas — `aa3b7b0` — 2026-11-26

**RECORD-ID:** `PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`
**EVIDENCE LEVEL:** **E5 narrow** (real Windows host, elevated owner run, exact counter deltas, verified restore). This is **not** a Go Nose adapter/host-network proof, a 23-rule matrix, a soak, an install campaign or E7.

## What was proven

A fresh harness was compiled from the **current source** file
`src/tests/cli/nose_pipe_e2e_cli.zig` at `aa3b7b0` via a temporary `src/`-root
wrapper (`src/i44_e3_wrapper.zig`, created and removed in the same patch; the
worktree stayed clean). Binary SHA-256:

```text
55306B0AFBFF0B91CC45861D186D20BB6800BF6334B9CBCEEADE7B5AD6D710B3
```

An elevated owner run temporarily stopped `AegisNids` and both `aegis-nose`
processes so the harness owned the canonical `\\.\pipe\aegis_nose`, then ran
`-inject -seconds 2`. The harness feeds three deliberately failing frame shapes
and one valid frame through the **production reader loop** and asserts exact
authoritative/local counter deltas.

```text
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
info: [NOSE] Event Fabric shutdown (accepted=0 rejected=0 dropped=0)
harness exit=0
```

This closes the **current-source host gap for the canonical pipe reader's
bounded shutdown and exact loss/framing accounting**. The earlier E4/E5 records
at `43a8bcc` and `7822f4c` remain HISTORICAL and are not substituted here.

## Restoration (verified)

- SCM failure actions restored to `restart/5000/restart/15000/restart/60000`, reset 86400.
- `AegisNids` restarted and observed `RUNNING`.
- `aegis-nose` restarted with its captured command line via WMI (`ReturnValue=0`).
- Final named pipes: `aegis_nose`; final processes: daemon + one Nose.
- `errors=[]`; `DONE inject_exit=0`.

## Boundary

- No Go Nose capture-adapter shutdown on a real Ethernet adapter is proven here;
  the `capture.go` monitor-shutdown E2 pins remain E2-only.
- No VLAN/QinQ or IPv6 extension-header stimulus was generated.
- No detection matrix, throughput, soak, signed-driver lifecycle, E6 simulation or E7 claim.
- Health counters were not used as evidence; no loss budget was changed.

## Artifacts

Verbatim transcripts: `analysis/current-head/raw-aa3b7b0-20261126/shutdown-e5/`
(`i44_e45_aa3b7b0_elevated_run.txt`, `i44_e45_aa3b7b0_inject.txt`,
`i44_e45_aa3b7b0_prestate.txt`, `harness-provenance.txt`).
