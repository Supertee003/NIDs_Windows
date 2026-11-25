# Detection Validation — v1.1 branch (build source `a53eda8`)

> **Provenance.** The 23-rule matrix and FP/FN register below were measured at
> build source `f4cde3c` (the last host-verified candidate, `b597e71`). The
> source delta `f4cde3c`→`a53eda8` is additive control-plane/observability work
> (RULE-COVERAGE-001 … POLICY-MUTATE-001, all E2, no host effect, no wire/codec
> change). The matrix has **not** been re-measured on the host at `a53eda8`; no
> E5 is claimed for this branch. See `analysis/current-head/RECONCILE-DOCS-READINESS-20261119.md`.

> **Current source (P1/P8 hygiene, then 2026-11-25 C6 rebase):** `a26c573` and `43a8bcc` were
> successive build sources and are now HISTORICAL. The current build source is `7822f4c`
> (P2-44 `9105ff5` added observability counters, P2b `661fb76` tightened wire-length decoding;
> P8 source-truth `2129dcd` added only authority/quarantine disclosure comments; P8-I44 `e406cbb`
> split nose drop causes by exclusive counter, counted detector allocation failures as detection
> degradation, and named the lifecycle fresh-loss input; P8-I44-E3 `03bb86d` added an explicit
> pipe-name seam and ran the real `-inject` exact-delta harness on a private pipe at E3;
> `a26c573` removed a stale "production-ready" label and added an oversize-wire reject guard
> in the Go Nose writer; `43a8bcc` made Go comment hygiene only; `7822f4c` changed capture
> visibility, shutdown and monotonic-time producers — no rule, wire-layout or authority change).
> The matrix has **not** been re-measured at `7822f4c`. E3 and narrow elevated canonical-pipe
> E4/E5 records at `43a8bcc` are HISTORICAL at that source and prove the `-inject` lifecycle and
> exact deltas only; they do not re-run the detection matrix, soak, loss rate, install or signing.
> E3/E4/E5 at `7822f4c` are **NOT_PROVEN** until owner-run elevated re-proof. The E5/E6 rows
> below remain HISTORICAL at `f4cde3c`; no current-source detection-matrix E5 is claimed.
> `docs/portfolio/DETECTION_CATALOG.md` separates code-path 23/23 from host-evaluable 22/23
> (R2003/FN-1); the generated 23-row projection is
> [`docs/portfolio/DETECTION_MATRIX_CURRENT.md`](portfolio/DETECTION_MATRIX_CURRENT.md).

> Records-only. This document does not change rules, sensors, source, build, or
> any gate verdict. It states what is actually proven, at which E-level, and
> what remains a declared intent — so that "modules PASS" is never read as
> "every detection is proven".

## 1. Scope and vocabulary

- Product mode is **detection-only**: prevention gate closed, no host effect
  (`RETIRE-HOST-EFFECT-001`, issue #25). A configured `Block`/`Drop` action is
  an **intent**, never proof of enforcement.
- `DETECT_ONLY` = the rule is expected to emit an observe-only canonical event.
- `BLOCK_CANDIDATE_PENDING_PROOF` = intent recorded; host-effect proof is
  out of product scope and cannot close here.
- E-levels are the AGENTS.md ladder (E1 static → E7 release verification).
  A fixture manifest is **E1**. "Golden path declared" is a declaration,
  not E4 system proof.

## 2. Rule-count note (22 vs 23)

`configs/Rules.json`, the qualification matrix, and the fixture manifest all
contain **23** rules. The directory/schema name `rules22` /
`aegis.rule22-single.v1` is a legacy label for the same 23-rule set. The
authoritative count at current HEAD is **23**; do not "fix" it by deleting a
rule to match the old name. (No file or directory rename is proposed.)

## 3. Coverage matrix

Sources: `analysis/RULE_22_QUALIFICATION_MATRIX.md`,
`analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.md`,
`analysis/RULE_22_SYNTHETIC_DETECTION_EVIDENCE.json`, `configs/Rules.json`.

Legend for "Proof": `SYN` = synthetic observe-only fixture (E1/E2),
`LAB` = live lab stimulus with negative control, `SIM` = production simulation.

| Rule | Layer | Sev | Config action | Fixture | Qualification / blocker | Proof | E-level |
|---|---|---|---|---|---|---|---|
| R0056 SQLi auth bypass | L7 | Critical | Drop | FX-01 | BLOCK_CANDIDATE / L7_SENSOR_MAPPING | SYN | E1 |
| R9064 OS command injection | L7 | Critical | Drop | FX-02 | BLOCK_CANDIDATE / L7_SENSOR_MAPPING | SYN | E1 |
| R9059 XSS basic | L7 | High | Alert | FX-03 | DETECT_ONLY / L7_SENSOR_MAPPING | SYN | E1 |
| R0088 Path traversal | L7 | Critical | Block | FX-04 | BLOCK_CANDIDATE / L7_SENSOR_MAPPING | SYN | E1 |
| R0089 Remote file inclusion | L7 | Critical | Block | FX-23 | BLOCK_CANDIDATE / L7_SENSOR_MAPPING | SYN | E1 |
| R9002 ICMP flood | L4 | High | Drop | FX-05 | BLOCK_CANDIDATE / KERNEL_WFP_E2E | SYN + LAB (rate lab, 15/15 boundaries) | E1 + E5 |
| R9006 TCP SYN stealth scan | L4 | Medium | Alert | FX-06 | DETECT_ONLY / KERNEL_WFP_E2E | SYN + **LAB real ≥20-port burst**, 118,632 ordinary rows → 0 false hits + SIM 150-connect scan | E1 + **E5 + E6** |
| R9007 TCP XMAS scan | L4 | Medium | Alert | FX-07 | DETECT_ONLY / KERNEL_WFP_E2E | SYN + LAB (rate lab) | E1 + E5 |
| R1001 System32 write | KERNEL_FILE | Critical | Block | FX-08 | BLOCK_CANDIDATE / FILE_RULE_PROOF | SYN | E1 |
| R1002 Ransomware rename | KERNEL_FILE | Critical | Drop | FX-09 | BLOCK_CANDIDATE / FILE_RULE_PROOF | SYN | E1 |
| R1003 Startup folder mod | KERNEL_FILE | High | Block | FX-10 | BLOCK_CANDIDATE / FILE_RULE_PROOF | SYN | E1 |
| R1004 DLL drop in System32 | KERNEL_FILE | Critical | Drop | FX-11 | BLOCK_CANDIDATE / FILE_RULE_PROOF | SYN | E1 |
| R1005 hosts file mod | KERNEL_FILE | High | Block | FX-12 | BLOCK_CANDIDATE / FILE_RULE_PROOF | SYN | E1 |
| R2001 Mimikatz execution | KERNEL_PROCESS | Critical | Drop | FX-13 | BLOCK_CANDIDATE / PROCESS_SENSOR_PROOF | SYN | E1 |
| R2002 svchost hollowing | KERNEL_PROCESS | Critical | Drop | FX-14 | BLOCK_CANDIDATE / PROCESS_SENSOR_PROOF | SYN | E1 |
| R2003 PowerShell cradle | KERNEL_PROCESS | Critical | Block | FX-15 | BLOCK_CANDIDATE / PROCESS_SENSOR_PROOF | SYN; **FP-1 CLOSED at E5, FN-1 OPEN** (§5) | E1 |
| R2004 certutil abuse | KERNEL_PROCESS | High | Block | FX-16 | BLOCK_CANDIDATE / PROCESS_SENSOR_PROOF | SYN | E1 |
| R2005 procdump harvest | KERNEL_PROCESS | Critical | Drop | FX-17 | BLOCK_CANDIDATE / PROCESS_SENSOR_PROOF | SYN | E1 |
| R3001 Cobalt Strike pipe | L2_PIPE | Critical | Drop | FX-18 | BLOCK_CANDIDATE / PIPE_RULE_PROOF | SYN | E1 |
| R3002 PsExec pipe | L2_PIPE | High | Block | FX-19 | BLOCK_CANDIDATE / PIPE_RULE_PROOF | SYN | E1 |
| R3003 Anonymous pipe | L2_PIPE | Medium | Alert | FX-20 | DETECT_ONLY / PIPE_RULE_PROOF | SYN | E1 |
| R3004 Meterpreter pipe | L2_PIPE | Critical | Drop | FX-21 | BLOCK_CANDIDATE / PIPE_RULE_PROOF | SYN | E1 |
| R3005 atexec pipe | L2_PIPE | High | Block | FX-22 | BLOCK_CANDIDATE / PIPE_RULE_PROOF | SYN | E1 |

**Honest summary:** 23/23 have a synthetic observe-only fixture (E1/E2).
Only the L4 family has live lab proof, and only R9006 reaches E5 + E6 with a
negative control. No file/process/pipe/L7 rule has live positive-path proof on
the shipped host. `BLOCK_CANDIDATE` states must stay pending — host-effect
proof is out of product scope.

## 4. Positive and negative evidence (the proven cases)

- `analysis/current-head/DETECT-L4-001-20261116.md` — R9006 tagged a real
  ≥20-port SYN burst on the shipped Wi-Fi path; negative control: 118,632
  ordinary rows produced **0** R9006 hits. **E5**.
- `analysis/current-head/E6-BURST-001-20261114.md` — 150-connect localhost
  scan: detections +1, anomalies +52, **no enforcement**. The only E6 entry
  in `EVIDENCE_INDEX.json`. **E6**.
- `EVIDENCE_INDEX.json` rate-limit lab entry — R9002/R9006/R9007 boundaries,
  15/15 stimuli on Wi-Fi. **E5**.
- Forensic replay: `tests/forensics/test_t12_forensics_replay.py` and siblings
  prove the evidence graph/read-back path at **E2**;
  `analysis/current-head/FOR-BATCH-001-20261108.md` (batch append) and
  `analysis/current-head/CORR-SOURCE-001-20261109.md` (host telemetry cannot
  enter network correlation windows) are **E2** at their defining records —
  they do not by themselves close E4/E5.
- `tools/golden_path_evidence.py` still references removed legacy paths
  (`core/*`, duplicate `shield/src/pep.rs`). The board's
  `golden_path_declared: true` is worded honestly; treat it as declaration,
  not end-to-end verification.

## 5. Known false-positive / false-negative register (do not hide)

| ID | Class | Evidence | Status |
|---|---|---|---|
| FP-1 | `event_processor.zig:280` ran the Aho-Corasick matcher over wire payloads for non-`capture_host_net` sources without consulting rule `layer`; a `KERNEL_PROCESS` rule (R2003) matched TLS bytes in 366 rows | `analysis/current-head/RULE-LAYER-SCOPE-001-20261117.md` | **CLOSED at E5.** Fixed at build source `f4cde3c` (`ruleLayerIndexForSource`, `resolveRuleAutomaton`, `g_layer_ac[4]`). Host re-measurement: `IEX` on wire → 0 rows; mixed `<script>`+`IEX` frame → R9059 only. The 366 rows were the pre-fix measurement. Not a host-effect defect. |
| FN-1 | R2003 cannot match a host process row: ETW ProcessStart v0–v4 and the minifilter lane carry no command line | `EVIDENCE_INDEX.json` R2003 entry | Accepted limitation; qualification matrix still lists BLOCK_CANDIDATE. |
| LIM-1 | L7 payload rules need an application/proxy sensor; WFP exports a 5-tuple only | qualification matrix | Blocker `L7_SENSOR_MAPPING`; no host-effect workaround. |
| LIM-2 | E7 in this repo means release signing/rebuild, **not** field/production verification | `EVIDENCE_INDEX.json` E7 entries | State plainly in any production claim. |

## 6. Detection quality budget (proposed — not a gate)

No FP/FN budget is defined today. Proposed starting objectives, to be adopted
by owner decision **after** the release gate closes (not silently added now):

- **FP objective:** R9006-style L4 rules ≤ 1 false hit per 100,000 ordinary
  rows, measured with the same negative-control census as DETECT-L4-001.
- **FN register:** FN-1 and LIM-1 remain explicit accepted limitations in the
  qualification matrix; no rule is marked "proven" while its limitation is open.
- **Alert budget:** 0 alerts from `KERNEL_PROCESS` layer rules on wire payload
  sources (FP-1 target — achieved and E5-measured on the installed build).
- **Gate policy:** an E1 synthetic fixture may support design review but may
  never close a detection-validation gate; gates require positive + negative
  evidence at E4+.

## 7. Where to look next

- `docs/gates/PRODUCTION_READINESS.md` — how these facts feed release readiness.
- `docs/runbooks/RB-020-observability-manual.md` — metric surfaces available to
  verify detection counters live.
- `analysis/current-head/RUST-FOUNDATION-STATUS-20261119.md` — the PEP's
  evidence-only role.
