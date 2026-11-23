# Source-Level Interview Preparation

> This guide points to **real files** in this repository. For each file you should be able to
> answer: what it does, its input, its output, who calls it, its dependencies, what happens on
> failure, its security risk, its tests, why it was implemented this way, and how you would improve
> it. Nothing here is a claim that every file has been fully audited.

---

## 1. The 19 files worth knowing deeply

| # | File | Role | Why an interviewer will care |
|---|---|---|---|
| 1 | [`src/main.zig`](../../src/main.zig) | Canonical daemon entrypoint (`build.zig:30` sets it as root source) | Shows the single runtime owner and worker lifecycle |
| 2 | [`src/core/nids_main.zig`](../../src/core/nids_main.zig) | NIDS core `main()` | Where runtime composition actually happens |
| 3 | [`src/platform/win32_pipe.zig`](../../src/platform/win32_pipe.zig) | Named-pipe endpoint, DACL, token impersonation | The control-plane security boundary in code |
| 4 | [`src/control/protocol.zig`](../../src/control/protocol.zig) | v2 command table and envelope | Active protocol version; note declared-but-unenforced nonce |
| 5 | [`src/control/handler_registry.zig`](../../src/control/handler_registry.zig) | Per-command dispatch and authorization | Shows role checks and forensic verify/replay semantics |
| 6 | [`src/contract/canonical_event.zig`](../../src/contract/canonical_event.zig) | Authoritative event struct, serialization, validation | One canonical schema with codecs in Zig, Go, C and Python plus the golden tuple map; Rust codec is TBD |
| 7 | [`src/pipeline/event_processor.zig`](../../src/pipeline/event_processor.zig) | Detection authority; L7 extraction source gating | Sole verdict owner; sensor boundaries |
| 8 | [`src/pipeline/rule_loader.zig`](../../src/pipeline/rule_loader.zig) | FNV-1a rule-ID hash, layer-filtered automaton | Proves kernel patterns cannot match wire bytes |
| 9 | [`src/forensic/forensic_pipeline.zig`](../../src/forensic/forensic_pipeline.zig) | 4 KiB records, CRC32, SHA-256 chain, ring wrap | The product's tamper-evidence claim |
| 10 | [`src/forensic/forensic_log.zig`](../../src/forensic/forensic_log.zig) | Append-only NDJSON evidence log | Shows why `BLOCK` is `observed`, not `enforced` |
| 11 | [`drivers/wfp_callout/aegis_wfp_callout.c`](../../drivers/wfp_callout/aegis_wfp_callout.c) | `classify()` — fail-open telemetry | Kernel boundary; no packet modification |
| 12 | [`drivers/wfp_callout/aegis_wfp.c`](../../drivers/wfp_callout/aegis_wfp.c) | Driver entry, device, IOCTL dispatch | `BLOCK_FLOW` refused with `STATUS_NOT_SUPPORTED` |
| 13 | [`nose/main.go`](../../nose/main.go) | Go Nose entrypoint | Acquisition spoke; no verdict authority |
| 14 | [`nose/canonical.go`](../../nose/canonical.go) | 109-byte wire codec | Golden-byte parity with Zig |
| 15 | [`rust-src/lib.rs`](../../rust-src/lib.rs) | Rust PEP / crypto FFI boundary | Detection-only authority; no host-effect path |
| 16 | [`tools/aegisctl.py`](../../tools/aegisctl.py) | Operator CLI | Reads daemon snapshot; no second runtime state |
| 17 | [`tools/aegisctl/web_dashboard/app.py`](../../tools/aegisctl/web_dashboard/app.py) | Read-only web dashboard | What the demo screenshot actually renders |
| 18 | [`tests/security/test_detection_contract_pin.py`](../../tests/security/test_detection_contract_pin.py) | Detection contract pin (AC1–AC4) | One rule set, one hash, one verdict tier |
| 19 | [`tools/lab_attack_window.py`](../../tools/lab_attack_window.py) | Bounded lab measurement window | How the demo's PASS result was measured |

---

## 2. Five interview questions you must answer precisely

### Q1 — "Why six language families instead of one?"

Answer as a **component-boundary decision**: Zig owns the runtime and event pipeline (memory
control, one owner); Go is I/O-bound packet acquisition; C/C++ reach native Windows APIs and WFP;
Rust supplies a memory-safe, constrained policy/crypto authority; Python does analytics and
tooling; TypeScript authors validated policy artifacts. The hub-and-spoke shape prevents authority
sprawl. Then concede the trade-offs openly: more build steps, cross-language contracts, harder
debugging, larger dependency surface. "Six language families" groups C and C++ as one adapter
family (seven toolchains in the tree); TypeScript is advisory-only and emits no runtime artifact.
See [Technology decisions](../TECHNOLOGY_DECISIONS.md).

### Q2 — "How do you know detection works?"

Separate the evidence levels: 23/23 catalog and evaluable coverage, but host-positive proof only
for the L4 family. R9006 has E5 + E6 proof with a ≥20-port burst, a 118,632-row zero-false-positive
control, and a 10-port negative control that produced zero hits; the recorded demo reproduced that
with a bounded 40-SYN burst. Synthetic fixtures prove the other families' logic, not sensor
fidelity. R2003 has an accepted host limitation. See [Detection catalog](DETECTION_CATALOG.md) and
[Test results](../testing/RESULTS.md).

### Q3 — "Why is there no enforcement?"

Host blocking requires verified authorization, provider execution, host-postcondition verification,
cleanup, rollback, and recovery. Those are a different risk class. The product deliberately stops
at the policy decision: findings become hash-chained evidence and an IDS evidence receipt. The WFP
block IOCTL is refused in source; `prevention_gate=closed` and `host_effect_capable=false`. This is
a design decision, not an unfinished feature.

### Q4 — "What happens when a component fails?"

Use the [Failure matrix](../OPERATIONAL_FAILURE_MATRIX.md). The key nuance: fail-closed here means
**no authority escalation and no false success** — not "block all traffic". A missing sensor is
reported as degraded or unavailable rather than interpreted as "no attack". The control pipe's
security descriptor construction fails closed, and the daemon refuses to start a second instance.

### Q5 — "How do you verify the forensics?"

Four KiB records carry CRC32 plus embedded SHA-256 `prev_hash`/`current_hash` links. Verification
checks CRC, per-record hash, and chain linkage across retained records; the oldest retained
record's linkage is skipped because its predecessor may have been overwritten, and overwrite is
disclosed via `retained`/`overwritten`/`oldest_record_seq`. Be exact: `forensics.replay` is
**integrity-only** — it re-verifies the chain and re-exports the source range but does not
re-execute detection. Never say it matched original verdicts.

---

## 3. Claim guardrail — know what the code does **not** support

| Do not claim | Reality |
|---|---|
| Active IPC has nonce/freshness/replay protection | v2 declares `nonce`/`issued_at_ms` but dispatch never reads them; the v1 table is inactive |
| `CONTRACT_MAP.json` CONTRACT-04 is current control truth | It is stale v1 (claims freshness/replay and `rules.reload` at `OPERATE`) |
| EV/HLK-signed production driver, Microsoft attestation | Source/INF require test signing; these are explicitly out of scope |
| WFP E5 for the newest scope changes | E1 code-level only; no WDK build, E5, or soak for that source |
| A rule is "verified on WFP" from the scope document | That document explicitly forbids the inference |
| R2003 detects real host command lines here | ProcessStart v0–v4 have no `CommandLine`; real source not implemented |
| Zig detection uses `regex_pattern` | Zig uses `match_pattern`; Python Brain owns `regex_pattern` |
| `rules.validate` compiles regexes | It checks required fields only |
| Authoritative MITRE ATT&CK mapping exists | No technique IDs in the rule catalog; ATS keyword only |
| Replay re-executed the detection pipeline | Integrity-only observe replay; `events_replayed=0`, `pass=false` |
| Zero loss on the current lab host | Live snapshot shows `minifilter_ring_dropped` and `alert_file.failed` nonzero |
| Rust canonical event codec exists | `rust-src/canonical_event.rs` is TBD |
| Python codec is wired to production | It is analytics-only, not wired to `brain/windows_brain.py` |
| Privacy/redaction is documented in `shared/event/**` | No such contract was found |
| All 23 rules are live-proven | Catalog/evaluable 23/23; host-positive proof is L4-only |

---

## 4. A 90-second opening answer

> "AEGIS is a Windows-native, kernel-assisted NIDS I built to understand detection at the system
> level, not just call an API. Zig is the single runtime owner; Go captures packets, C/C++ adapters
> read WFP and host telemetry, Rust is a detection-only policy and crypto authority, Python does
> analytics, and TypeScript authors policy. Everything normalizes into one 109-byte canonical event
> with byte-exact codecs. Detection runs in one tier, findings become hash-chained forensic records,
> and the authority boundary is explicit: no component can turn a detection into a host block. I
> published v1.1 with a signed manifest, 674/674 verified artifacts, and a 36.5-hour owner-run
> soak PASS with zero loss **during that recorded 36.52 h window**.
> I'm candid about the gaps — only the L4 family has live positive proof, the Rust codec is still a
> gap, and the current lab host has loss counters I'd want to investigate."

---

*See also: [Architecture (English)](ARCHITECTURE_EN.md) · [Apply now](APPLY_NOW.md) ·
[Detection catalog](DETECTION_CATALOG.md)*
