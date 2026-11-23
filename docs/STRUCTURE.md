# AEGIS NIDS — Source Tree Structure (current HEAD)

| Field | Value |
|---|---|
| Document status | **CURRENT** — rebased on the source tree at build source `a53eda8` (ADR-0008) |
| Records HEAD at last rebase | `1184595` |
| Canonical entrypoint | `src/main.zig` (`runtime_manifest.json:4`) |
| Source of truth for roles | `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `runtime_manifest.json`, `AGENTS.md` |
| Audit basis | [`analysis/current-head/SOURCE_AUDIT-20261123.md`](../analysis/current-head/SOURCE_AUDIT-20261123.md) (E1/E2) |

> Older project maps that mention `core/*.zig`, `mouth/`, or a root `lib.rs` describe a
> pre-restructure tree. There is no tracked root `lib.rs` and no tracked `core/` directory today;
> do not use those documents to decide where to edit code. Root-level dated
> `AEGIS_*_2026-09*.md` handoff files are historical, not current truth.

---

## 1. Canonical runtime — build and artifacts

| Build command | Artifact | Layer / owner | Source root |
|---|---|---|---|
| `zig build` | `aegis_nids.exe` | Tier-1 runtime spine: event, flow, dispatcher, detection, correlation, forensics | `src/` |
| `cargo build --release` | `aegis_pep.dll` | Tier-3 detection-only policy/crypto authority (no host effects) | `rust-src/` |
| `cmake -B build && cmake --build build` | 3 native C DLLs | Windows telemetry adapters (WFP/ETW/FIM/Registry) | `bridge/`, `drivers/` user-mode helpers |
| `cd nose && go build -o aegis-nose.exe .` | `aegis-nose.exe` | Go packet acquisition only | `nose/` |
| `python brain/windows_brain.py` | interpreted | Tier-2 analytics, advisory regex, RAG | `brain/` |
| `cd ts_policy && npm run typecheck && npm run test:all` | none | Policy authoring/compiler (advisory) | `ts_policy/` |

There is **one** production runtime. WFP and minifilter kernel drivers are test-signed lab
artifacts; no EV/HLK signing or Microsoft attestation is claimed.

---

## 2. Directory map

### 2.1 Production source

| Path | Contents | Status |
|---|---|---|
| `src/main.zig` | Production entrypoint | Canonical |
| `src/contract/` | Canonical event codec, event fabric, version dispatch | Canonical; `canonical_event.zig:66` still carries a stale SipHash64 comment (actual hash: FNV-1a) |
| `src/capture/` | Nose pipe reader, WFP/NPcap readers, flow tracking, protocol parsers | Canonical; `stream_reassembly.zig` is **test-only / unwired** (no production caller) |
| `src/pipeline/` | Event queue, ingress authority stripping, runtime counters | Canonical |
| `src/detection/` | Rule engine, correlation, anomaly/proto anomaly rules | Canonical |
| `src/control/` | v2 control protocol, handler registry, authorizer, state machine | Canonical; `nonce`/`issued_at_ms` are declared but not enforced |
| `src/policy/` | Policy evaluation, Rust PEP bridge, WFP production boundary | Canonical, detection-only |
| `src/forensic/` | 4096-byte records, CRC32 + SHA-256 chain, replay verification | Canonical; replay is integrity-only |
| `src/platform/`, `src/windows/` | Named pipe, service, Windows adapters | Canonical; pipe is single-owner with token-derived roles |
| `src/federation/`, `src/core/`, `src/operator/`, `src/reliability/`, `src/xdr/`, `src/release/`, `src/lab/`, `src/tests/` | Supporting subsystems, proofs, and lab modules | Lab/test modules are not production host-effect paths |
| `nose/` | `capture.go`, `canonical.go`, `pipe_writer.go`, TUI/headless collectors | Canonical acquisition plane; TUI telemetry plane contains `Simulated`-labeled data |
| `drivers/wfp_callout/`, `drivers/minifilter/` | Kernel telemetry, observe-only callbacks, control IOCTLs | Test-signed lab drivers; the block handler is unreachable, `quarantined/aegis_wfp_comm.c` is excluded by convention |
| `rust-src/`, `shield/` | Rust PEP, trust/Ed25519/TLS helpers | Detection-only authority + crypto; no WFP mutation |
| `brain/` | `windows_brain.py`, canonical codec, Cython hot loops | Advisory analytics; Python codec is not the production codec |
| `ts_policy/` | Policy DSL/compiler, tests | Advisory authoring only |
| `tools/aegisctl.py`, `tools/aegisctl/` | Operator API, CLI, Flask web dashboard | Read-only clients of the Zig control plane |
| `scripts/` | Build, install, proof, lab stimulus, release automation | Operator tooling; no second runtime authority |

### 2.2 Contracts, configuration, tests

| Path | Contents | Status |
|---|---|---|
| `shared/protocol/`, `shared/schema/`, `shared/event/` | Wire documents, C header, canonical event description | Shared contract text; one schema, N codecs |
| `contracts/` | Machine-readable operator/state contract fixtures | Current |
| `configs/` | `Rules.json` (23 rules), deployment profile, policy sets | Current configuration |
| `config/` | Older rule/profile copies | Historical; do not edit for current runtime |
| `tests/` | Python contract/security/release/integration/host tests, vectors | Current; `host_live` tests are deselected on hosted CI |
| `pytest.ini`, `build.zig`, `CMakeLists.txt`, `Cargo.toml`, `go.mod` | Test and build roots | Current |
| `docs/` | Architecture, runbooks, gates, portfolio, audit analyses | Mixed current + explicitly labeled historical |

### 2.3 Records and generated material

| Path | Contents | Status |
|---|---|---|
| `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json` | Machine maps carrying the build source commit | Current; CONTRACT-04 is a documented stale v1 control-IPC entry |
| `EVIDENCE_INDEX.json`, `build_truth.json`, `runtime_manifest.json`, `inventory.json`, `reference_map.json`, `AI_CONTEXT.md` | Evidence index, build truth, entrypoints, file inventory, agent context | Current records (ADR-0008: records commits do not move build source) |
| `analysis/current-head/` | Source audit, coverage matrix, release closeout, ABI conflict register | Current records; `02-contracts-abi.md` contains P0 ABI-01 (framing doc mismatch) |
| `admin-evidence/`, `evidence/`, `release/`, `dist/`, `.zig-cache/`, `zig-out/`, `target/`, `build/`, `logs/` | Host evidence, signed release bundles, generated build/runtime state | Generated/operator-owned; not a source of truth for code behavior |

### 2.4 Auxiliary / not in the canonical runtime

These directories are still tracked and may be useful as historical reference, but they are **not**
part of the one production runtime described in `AGENTS.md` and `runtime_manifest.json`:

| Path | Description |
|---|---|
| `bridge/` | Older C++ IPC bridge and selftest harness; current Windows adapters live in `src/windows/` and `drivers/` |
| `go/aggregator/` | Earlier Go aggregator/console experiment; canonical Go acquisition is `nose/` |
| `mouth/` | Historical Rust DEFCON/TUI experiment |
| `lib/` | Vendored dashboard JavaScript/CSS assets |
| `aegis_dashboard/` | Optional Rust/egui operator dashboard (not the Flask dashboard used for the demo) |

---

## 3. Editing conventions

1. **One schema, N codecs.** A wire change to `CanonicalEvent` must update Zig, Go, C, Python, the golden tuple-map, and the shared `event_v*` vector in the **same** patch.
2. **No import-time host effects.** Product modules must be importable without binding sockets, serving, printing banners, or calling `sys.exit`.
3. **Tests never write tracked state.** Use `tmp_path`; result stamps and `logs/*.json` are producer-owned.
4. **No host effects.** Detection-only means no WFP mutation, no quarantine, and no `BLOCKED_CONFIRMED` claim from a `BLOCK` label.
5. **Records vs source.** A docs-only commit moves records HEAD only; machine maps keep carrying build source `a53eda8` until source actually changes (ADR-0008).
6. **Historical labels.** Mark superseded documents `HISTORICAL` rather than deleting evidence.

---

## 4. Verify after any change

```powershell
python tools/truth.py verify          # TRUTH_VALID; build source a53eda8
git ls-files | Select-String -Pattern '\.(exe|dll|pdb|obj|o|so|ilk|exp|lib)$'   # empty
python -m pytest tests/release -q     # release/index consistency gates
```

See [`docs/testing/RESULTS.md`](testing/RESULTS.md) for the evidence levels actually claimed and
[`docs/portfolio/ARCHITECTURE_EN.md`](portfolio/ARCHITECTURE_EN.md) for the plain-language flow.
