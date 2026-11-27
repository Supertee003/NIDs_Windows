# Go Nose sensor coverage — E1 source audit and patch-transaction skeleton

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged — records-only)  
**RECORDS TIP WHEN WRITTEN:** `61be9bc51ba95ce8499a67a6eb7bf373e887062d`  
**SCOPE:** AEGIS-008. Read-only source inspection; no host, capture, service or
finalizer action. This is a **finding map, not new proof**. It does not promote
VLAN, IPv6-extension or truncation visibility from `NOT_PROVEN`.

`git diff aa3b7b0 -- nose` is empty; all `nose/` line numbers below are at the
exact build source.

## 1. Implemented vs E2-tested vs host-proven

| Behavior | Source | Hermetic E2 | Current-source host proof |
|---|---|---|---|
| IPv4/TCP decode, TCP flags | `nose/capture.go:310-429` | `nose/capture_hermetic_test.go:19-117` | Narrow loopback E6 only |
| Tiny-garbage no-panic (≤2 bytes) | gopacket delegated at `capture.go:207-218` | `capture_hermetic_test.go:119-129` | none |
| VLAN / QinQ decode | BPF string `capture.go:61-63`; decode delegated to gopacket at `:327` | **no** tagged-frame input to `eventFromPacket` | `NOT_PROVEN` (`docs/portfolio/SENSOR_COVERAGE.md:19-20`) |
| IPv6 extension chain | no explicit walk; `capture.go:339-363` takes first `NextHeader` | only no-chain IPv6 at `canonical_test.go:481-509` | `NOT_PROVEN` (`SENSOR_COVERAGE.md:11,19`) |
| Captured vs original length | `capture.go:268-305`, envelope validation `canonical.go:355-403` | `payload_v3_test.go:317-353`, vectors 007/008/009 | none |
| BPF / loopback DLT_NULL | `capture.go:61-84`, `talkers_live.go:179-191` | `capture_visibility_test.go:11-48` | narrow E6 PASS (loopback only) |
| `sendWire` oversize / nil / closed | `pipe_writer.go:149-173` | `pipe_writer_test.go:12-50` | indirect only |
| `sendWire` short write / write error | `writeAll` at `pipe_writer.go:55-68`, call at `:183-189` | **no** — test file says so at `pipe_writer_test.go:3-6` | none |
| Disconnect / reconnect | `ensureConnected` `pipe_writer.go:93-99`, reset on write error `:166-189` | **no** | narrow S3 restart/generation E5 only |
| Stop / goroutine leak | `capture.go:199-205,234-240`, `main.go:191-236` | helper only at `capture_visibility_test.go:64-83`; host-dependent `capture_pipe_test.go` | none |
| Drop / malformed counters | Go `capture.go:34-44`, `pipe_writer.go:35-41`; Zig `nose_pipe_reader.zig:403-554` | oversize/headless/codec tests only | narrow observations, not a matrix |

## 2. Concrete gaps found

1. No Go test feeds a single-tagged `0x8100` or double-tagged `0x8100`/`0x88a8`
   frame into `eventFromPacket`; the BPF visibility tests pin only the filter string.
2. For IPv6, `Protocol` is set from the **first** `NextHeader` (`capture.go:362`)
   and TCP/UDP cases overwrite it with 6/17 (`:366-385`); an extension chain
   terminating in another L4 protocol is not resolved. Do not turn this into a
   capability claim.
3. Completeness is computed against `ci.Length`, not `ci.CaptureLength`
   (`capture.go:298`); the assumption `len(frame) == CaptureLength` is not pinned.
   Inventing a different semantic needs a separate decision — this audit does not.
4. `pipeConn.write` is hard-wired to `*os.File` (`pipe_writer.go:43-53`), so the
   short-write loop and mid-frame error path have no hermetic seam.
5. Module comment claims "retries with backoff" (`pipe_writer.go:15-17`) and
   `nosePipeRetryDelay` (`:31-32`) is unused; the live path has no sleep/backoff.
   This is a documentation/source discrepancy, not a behavior claim to repeat.

## 3. Proposed patch transaction — NOT APPLIED

```
PATCH-ID:      AEGIS-008-SENSOR-E2-01
FLOW-ID:       network frame -> Go Nose decode -> v3 envelope -> pipe frame
TARGET HEAD:   aa3b7b0161e425e54155d5767737bffcde7939b5 (current build source)
TARGET FILES:  nose/sensor_coverage_test.go (new)
               nose/pipe_writer.go (internal sink seam, optional tier)
               nose/pipe_writer_test.go (fake-sink cases, optional tier)
TARGET SYMBOLS:eventFromPacket, captureAttachment, pipeConn.write,
               writeAll, FrameWriter.ensureConnected/sendWire
IN SCOPE:      hermetic VLAN/QinQ + IPv6 ext-chain + truncation matrix;
               short-write/write-error/reconnect framing at E2
OUT OF SCOPE:  Npcap, live adapter, named pipe, daemon, service, E3/E4/E5/E6,
               wire layout, canonical schema, rules, policy bytes, authority
CONTRACT IMPACT: none (wire v1/v2/v3 byte layouts unchanged)
ABI IMPACT:      none
AUTHORITY IMPACT:none (Go stays acquisition-only)
STATE IMPACT:    in-memory fake sinks and t.TempDir only; no tracked-tree writes
TEST IMPACT:     go test ./... in nose; go vet; test_nose_toolchain.py
EVIDENCE IMPACT: E2 only; SENSOR_COVERAGE host rows stay NOT_PROVEN
```

**Why it was not applied in this records patch:** any file under `nose/` is a
`SOURCE_PATHS` entry in `tools/truth.py:44-66`. A source commit would move the
build source off `aa3b7b0`, require full machine-map rebaselining and would make
the current signed tree `6c94b47` no longer contain the runtime — turning
`release_signature` OPEN in `final_audit.py`. That is a gate regression, not a
documentation cleanup, and is deliberately left as an explicit owner decision
(Card B) rather than done silently here.

## 4. What IS safe and recorded now

- This E1 finding map with exact source locations.
- `docs/portfolio/SENSOR_COVERAGE.md` remains the honest host-visibility surface:
  VLAN/QinQ, IPv6 extensions and snaplen truncation stay `NOT_PROVEN`.
- No counter, verdict, threshold, skip, xfail or health label was changed.

## 5. Applied transaction (2026-11-28, owner option B)

The "NOT APPLIED" status above is HISTORICAL. Under owner option B in
`docs/SOURCE-SLICE-DECISIONS.md`, `AEGIS-008-SENSOR-E2-01` was applied at source
commit `3c78c96ebf397b4e1fa052963acc4bdd6a6945d8`. Full patch declaration,
verification and limits are in
[`AEGIS-008-SENSOR-E2-20261128`](AEGIS-008-SENSOR-E2-20261128.md).

Closed at E2: hermetic single/stacked `0x8100` decode, IPv6 hop-by-hop→TCP
round-trip, tagged snaplen truncation framing, and pipe short-write/error/
reconnect frame boundaries through an in-memory sink seam. Still open and
**NOT_PROVEN**: `0x88a8` service-tag decode on the host, live Npcap visibility,
named-pipe/Zig integration at this source, full Windows E5, soak and E7. No
host row in `docs/portfolio/SENSOR_COVERAGE.md` was promoted.
