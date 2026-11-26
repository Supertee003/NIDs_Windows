# Fuzz and fault-injection inventory

> Scope: build source `4dd3393` (HISTORICAL at current source `aa3b7b0`). AEGIS-PLAN-017.
> This is an **inventory and status page**. It does not claim a fuzz campaign
> was run at the current source.

## 1. What exists

| Mechanism | Location | Level at `4dd3393` |
|---|---|---|
| Zig fuzz target | `src/fuzz_entry.zig`, `build.zig` fuzz targets | E1 (target registered), no current campaign |
| Fault-injection unit tests | `tests/reliability/` — 0% never triggers, 100% always triggers, disabled never triggers, event corruption changes bits, multiple fault kinds tracked independently, deterministic seed, counter no-overflow, `fromEnv` env var | E2 PASS |
| Envelope rejection tests | `tests/contracts/test_payload_envelope_v3.py` — trailing byte, CRC mismatch, length mismatch, metadata-only payload, unknown completeness, oversized payload, dirty v6 tail, forged version | E2 PASS |
| IPv6 wire rejection tests | `tests/contracts/test_ipv6_wire_v2.py` — over-length v1 frame rejected | E2 PASS |
| PEP ABI rejection | `tests/contracts/test_pep_abi_layout.py` — unknown action without allowing | E2 PASS |
| Handle-retry fault test | `EVIDENCE_INDEX.json` record: successful handles removed, failed handles plus root association retained for retry; ReleaseSafe x86_64 Windows build and full Zig suite pass | E2 at recorded commit, HISTORICAL relative to `4dd3393` |
| `-inject` exact-delta harness | `7822f4c` private-pipe E3 and elevated canonical-pipe narrow E4/E5, harness SHA256 `3CAB8A36…C67` | E3/E5 at `7822f4c`, HISTORICAL relative to `4dd3393` |
| Stop-failure injection | No installed-service stop failure injected; recorded honestly in evidence | NOT_PROVEN |

## 1a. Fuzz run actually performed at `4dd3393`

| Item | Value |
|---|---|
| Command | `zig build fuzz --cache-dir D:\aegis-tmp\plan_zig_cache --global-cache-dir D:\aegis-tmp\plan_zig_global` then `zig-out\bin\aegis_fuzz.exe` |
| Binary SHA-256 | `7681B52FC91CC0DE8F8A50143BC98630EB77D666275D6854CFEAE7DEE0B1C621` |
| Harness | `src/fuzz_entry.zig` → `src/tests/fuzz_main.zig`; deterministic `DefaultPrng` seed `0xDEADBEEF` |
| Iterations | 1,000 random buffers, length 1–1024, through Aho-Corasick (3 patterns) and `packet_decoder.decode` |
| Allocator | `GeneralPurposeAllocator`; `deinit() == .leak` fails the run |
| Result | exit 0, no leak, no crash |

This is a **deterministic E2 fuzz smoke run**, not a coverage-guided campaign,
not E3/E4, and not a current-host proof. No crash corpus was produced because
no crash occurred. See also `HOST_LIVE_DIAGNOSIS.md` for the separate host-live
failure diagnosis.

## 2. What is NOT claimed

- No coverage-guided fuzz campaign at `4dd3393` has been executed or published.
- No coverage-guided crash corpus is tracked as current-source evidence.
- No installed-service stop failure was injected at the current source.
- A passing unit test is E2; it is not a campaign and not E3/E4.

## 3. Required next campaign (owner)

1. Pin build source, Zig/Rust/Go versions, and harness SHA-256.
2. Run the registered Zig fuzz target for a fixed, recorded duration.
3. Run the `-inject` harness against the rebuilt daemon/Nose with negative
   controls (no traffic, no daemon).
4. Record exact deltas and host restore in a transcript locator with SHA-256.
5. File an evidence entry at the exact build source. No PASS without artifact.

---

See also: [`../runtime/QUEUE_SEMANTICS.md`](../runtime/QUEUE_SEMANTICS.md),
[`../evidence/PROVENANCE.md`](../evidence/PROVENANCE.md),
[`../../EVIDENCE_INDEX.json`](../../EVIDENCE_INDEX.json).
