# Fuzz + benchmark record at build source `aa3b7b0` — 2026-11-26

**RECORD-ID:** `FUZZ-BENCH-AA3B7B0-20261126`
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`
**EVIDENCE LEVEL:** E2 (built binaries, deterministic harness and in-process benchmarks). No E5/E6/E7 claim is made by this page.

## Build provenance

`zig build fuzz` and `zig build core-tools -Doptimize=ReleaseFast` both failed until the Rust PEP import library existed. C: was full, so the Rust build was redirected with `CARGO_TARGET_DIR=D:\aegis-tmp\cargo-target` and the resulting `aegis_pep.dll` / `aegis_pep.dll.lib` were copied into `target/release/` (the path the Zig build expects). Neither the source nor the build graph was changed to hide the dependency.

| Binary | SHA-256 |
|---|---|
| `zig-out/bin/aegis_fuzz.exe` | `B16EFBABF58FB8F1D03FAA203B6A01D3928F2EBE09E31E6D2645294D0C79A8B3` |
| `zig-out/bin/aegis_perf_bench.exe` | `7311128D733A4574E6B30849BE91F4AD537760F5058241E6B84B3590B4871480` |
| locally rebuilt `target/release/aegis_pep.dll` (link input only) | `1A254E5647A2CCB10167D12E3EC40C711652DC2F1243DFCB16803643BD272B35` |

The release tree uses the host-proven PEP digest `6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926` (see `analysis/current-head/RELEASE-SIGNATURE-AA3B7B0-20261126.md`); the different digest above is a path-metadata artefact of the redirected local build, not a second source version.

## Deterministic fuzz harness — PASS (E2, not coverage-guided)

```text
zig-out\bin\aegis_fuzz.exe
  exit 0, no stdout/stderr, no allocation leak report
```

`src/tests/fuzz_main.zig` builds an Aho-Corasick automaton with `evil` / `malware` / `exploit`, then drives **1,000** PRNG-generated buffers (length 1..1024) through both `AhoCorasick.match` and `packet_decoder.decode`. `GeneralPurposeAllocator.deinit()` is checked and exits 1 on a leak. The PRNG seed is fixed (`0xDEADBEEF`), so this is a deterministic smoke campaign: it proves no crash/leak on those 1,000 inputs, **not** coverage-guided mutation and not a claim about unseen inputs.

**Coverage-guided fuzz campaign: NOT_RUN at this source.** No coverage-guided engine is present in the toolchain (no clang/libFuzzer, AFL++, honggfuzz, cargo-fuzz/nightly or Atheris; Zig 0.13 has no `zig fuzz`), and no result is invented here. It is `CLOSED as documented gap` in `analysis/current-head/REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md` — a documentation status only; this entry's level and result stay E2 PASS for the deterministic smoke.

## In-process microbenchmarks — PASS thresholds (E2)

```text
zig-out\bin\aegis_perf_bench.exe quick     # warmup=10, iterations=100
zig-out\bin\aegis_perf_bench.exe latency   # warmup=10, iterations=200
```

`quick`:

| Benchmark | ops | ops/sec | us/op |
|---|---:|---:|---:|
| ProcessTracker (100 creates) | 100 | 26,599 | 37.60 |
| FileIntegrityStore (50 baselines + observes) | 100 | 64,608 | 15.48 |
| RegistryWatchQueue (100 enqueues) | 100 | 76,552 | 13.06 |
| Federation codec (10 encode+decode) | 100 | 1,169,591 | 0.86 (223.1 MB/s) |
| CrossNodeAggregator (50 reports) | 100 | 176,274 | 5.67 |
| Full pipeline (4 events → incidents) | 100 | 43,634 | 22.92 |

All six declared thresholds passed. `latency` (200 iterations) reported p50/p95/p99 in ns: ProcessTracker 41,300/66,700/72,900; FileIntegrityStore 15,300/19,300/27,400; RegistryWatchQueue 12,300/12,300/12,400; Federation codec 900/900/900; CrossNodeAggregator 5,000/7,600/9,400; Full pipeline 22,900/23,200/25,000.

These are **in-process** component benchmarks. They do not measure offered network load, packet loss under saturation, end-to-end host latency, or a production deployment.

## Fixed-rate loopback network benchmark — PASS (E5 narrow)

`D:\aegis-tmp\owner_net_bench.ps1` swapped the current-source runtime (daemon `6F548AF7…`, Nose `8C05FE48…`, PEP `6E05AAE1…`), recycled the driver-lifetime minifilter gauge **before** the measured window (37,361 → 0, `loss_budget` unchanged at 3500), started one Nose loopback capturer, ran `D:\aegis-tmp\net_rate_bench.py`, then restored the exact baseline (`restore.verified=true`).

- target: **100 connections/s for 60 s** (6,000 planned)
- made/accepted: **6,000 / 6,000**, zero connection errors
- elapsed 60.036 s → **99.94/s achieved** (within 2% tolerance)
- `nose_frames_read` delta **70,919**; `packets_captured` delta **70,919**
- every loss counter delta **0** (`queue_dropped_total`, `nose_frames_dropped`, `nose_frames_rejected`, `nose_pipe_errors`, `pipeline_processing_errors`, `minifilter_ring_dropped`, `minifilter_pipeline_dropped`); `shed_overload` delta **0**
- verdict `PASS`, `reasons=[]`, `bench_exit=0`

Verbatim artifacts: `analysis/current-head/raw-aa3b7b0-20261126/netbench/result.json` and `.../netbench/netbench.json`. The committed `aa3_perf_quick.log` / `aa3_perf_latency.log` were transcoded from UTF-16LE captures at `D:\aegis-tmp\aa3_perf_*.log` to UTF-8/LF for the repository encoding guard; the originals remain outside the tree and no benchmark value changed. Per-file sidecars record the exact pre-transcode SHA-256 from `848c924^` and a byte-exactness proof; see `analysis/current-head/raw-aa3b7b0-20261126/TRANSCODE-SIDECARS.md`.

An earlier attempt to run the probe against the already-swapped soak daemon was refused by its own precondition (`daemon DEGRADED`, counters moved by unrelated agent file I/O). It wrote no benchmark verdict and is not counted as a measurement. E5 here means a controlled loopback offered-load observation on this host; it is not saturation testing, E6 production simulation, or E7.
