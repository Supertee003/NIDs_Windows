# RULE-COVERAGE-001 — 23-rule coverage matrix

**PATCH-ID:** RULE-COVERAGE-001  
**FLOW-ID:** DETECTION-L4-KERNEL, DETECTION-R2003  
**TARGET HEAD:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40` (detached worktree)  
**BUILD SOURCE BEFORE PATCH:** `f4cde3c503fd8b696183751a608b999768caa769`  
**STATUS:** Slice 1 code + E2 proof COMPLETE. Not E5. No binary installed. [HISTORICAL @ recorded head `f0baadf` / source `f4cde3c`: the board was 5/6 then. The immutable v1.1 release identity is 6/6 PASS (0 open) at signed candidate `466a226`; this is not a current gate claim.]

---

## 1. What "coverage" means here

Three distinct claims, deliberately not conflated:

| Term | Definition | This patch |
|---|---|---|
| **Catalog coverage** | rule_id appears in the canonical catalog, has `match_pattern` + `regex_pattern`, a fixture vector, and one shared rule-id hash | 23/23 (pre-existing E2 pins) |
| **Evaluable coverage** | the production runtime has a code path that can evaluate the rule from evidence it can actually receive | 23/23 as defined at `f4cde3c` (code path exists). The current catalog splits this into **code-path 23/23** and **host-evaluable 22/23** (R2003/FN-1); see `docs/portfolio/DETECTION_CATALOG.md` |
| **Host-positive proof** | the rule fired on the installed host with a real positive stimulus | L4 family only; unchanged by this patch |

A rule can be fully evaluable and still be unprovable on *this* host when the
sensor cannot supply the field it needs. That is recorded as a limitation, never
as a pass.

---

## 2. Per-rule matrix

Legend — **Eval**: code path exists. **Fixture**: `tests/vectors/rules22/<ID>.json`
(all 23 present; directory name is historic). **Host**: pre-existing host evidence.

| ID | Layer | Eval | Fixture | Host evidence | Limitation |
|---|---|---|---|---|---|
| R0056 | L7 | yes (network AC) | yes | E1/E2 synthetic | LIM-1: no app/proxy sensor for encrypted payloads |
| R9064 | L7 | yes (network AC) | yes | E1/E2 synthetic | LIM-1 |
| R9059 | L7 | yes (network AC) | yes | **E5** wire (`<script>`, RULE-LAYER-SCOPE-001) | — |
| R0088 | L7 | yes (network AC) | yes | **E5** wire (`../../etc/passwd`) | — |
| R0089 | L7 | yes (network AC) | yes | E1/E2 synthetic | LIM-1 |
| R9002 | L4 | yes (L4 PROTO + rate) | yes | **E5** rate lab 15/15 | no flags required |
| R9006 | L4 | **yes — Npcap, Nose and WFP** | yes | **E5 + E6** ≥20-port burst; 118,632-row 0-FP control | inbound WFP has no flags evidence (WFP delivers from L7); shadow-row topology |
| R9007 | L4 | **yes — Npcap, Nose and WFP** | yes | **E5** rate lab | same inbound-WFP boundary |
| R1001–R1005 | KERNEL_FILE | yes (kernel_file AC) | yes each | E1/E2 synthetic; R1002 E5 canary in RULE-LAYER-SCOPE-001 | no host-effect proof required (detection-only) |
| R2001, R2002, R2004, R2005 | KERNEL_PROCESS | yes (kernel_process AC over ImageName/command-line TLV) | yes each | E1/E2 synthetic | FN-1 applies to command-line-dependent cases |
| **R2003** | KERNEL_PROCESS | **yes — code path pinned at E2 this patch** | yes | E1/E2 synthetic | **FN-1 OPEN:** this host's ProcessStart v0–v4 carry no CommandLine; no positive host proof. FP-1 CLOSED (below). |
| R3001–R3005 | L2_PIPE | yes (l2_pipe AC) | yes each | E1/E2 synthetic; R3003 E5 ambient negative observation | — |

---

## 3. FP/FN register — reconciled against current source

| ID | Old record | Truth at this source | Disposition |
|---|---|---|---|
| **FP-1** `RULE-LAYER-SCOPE-001` | `DETECTION_VALIDATION.md` §5 still says "Open, deferred to v1.1" | **Already fixed at build source `f4cde3c`** (`ruleLayerIndexForSource`, `resolveRuleAutomaton`, `g_layer_ac[4]`), E5 proven twice on the installed binary: `IEX` on wire → **no match**; mixed `<script>`+`IEX` frame → R9059 only. The 366-row TLS FP was the *pre-fix* measurement. | **CLOSED at E5.** Doc row is stale and must be corrected in the records tree. |
| **FN-1** | "ETW ProcessStart v0–v4 carry no command line" | Confirmed at `etw_native.c:70-72` (PROCESS-CMDLINE-001, E5 2026-11-18). Zig consumer *does* decode `AEGIS_ETW_TLV_CMDLINE=2` when a provider supplies it; this host never does. | **OPEN, accepted limitation.** Code path pinned with a synthetic TLV fixture; no fake host positive. |
| LIM-1 | L7 needs app/proxy sensor | unchanged | OPEN, accepted |
| LIM-2 | E7 = release signing, not field verification | unchanged | stated in every claim |

---

## 4. `regex_pattern` decision (catalog no longer promises a verdict)

**Decision: advisory by ownership, not removed.** `regex_pattern` is compiled and
evaluated only by the Python Brain Tier-2 analytics path
(`brain/windows_brain.py:compile_tier2_rules`, Cython mirror). Zig's Aho-Corasick
automaton is built from `match_pattern` only and is the sole detection-verdict
authority.

Pinned at E2 by `tests/security/test_detection_contract_pin.py` (AC1–AC4):
- Zig loader reads `match_pattern` in exactly one place via `classifyRule`;
- `"regex_pattern" not in zig` — the runtime cannot compile it;
- all 23 rule-id hashes agree across Python, Zig and CLI;
- all 23 canonical rules declare both fields.

`rules.validate` (control command 302) returns `{"valid":true,"rules_checked":23}`
after checking required fields — no regex compilation is implied by "validate".

---

## 5. Evidence produced by this patch

| Artifact | Level | Result |
|---|---|---|
| `src/policy/wfp_ioctl.zig` header/flags tests | E2 | 48-byte stride pinned; absence ≠ zero flags |
| `src/capture/wfp_telemetry.zig` record→queue→L4 test | E2 | SYN flag reaches `l4.matches` |
| `tests/wfp/wfp_payload_slice_test.c` | E2 | 6 cases PASS (outbound-only flag evidence) |
| `src/windows/etw_realtime.zig` TLV decode test | E2 | CommandLine decoded when supplied; empty when absent |
| `src/pipeline/rule_loader.zig` R2003 test | E2 | R2003 matches decoded cmdline; wire bytes get no KERNEL_PROCESS id |
| `pytest tests/security/test_detection_contract_pin.py tests/lab/test_kali_script_coverage.py` | E2 | 15 passed, 3 skipped |
| `zig build` / `zig build test` | E2 | exit 0; unit 2109 passed / 11 skipped / 0 failed; out-of-unit 1234 passed |

**Not claimed:** E3/E5 for any new source change; WDK driver build; Windows host
proof; soak coverage for the new binary; board 6/6; tag or publish.

---

## 6. Truth-artifact state (explicit, expected)

`python tools/truth.py verify` returns **TRUTH_INVALID** in this worktree because
the patch leaves source/build paths uncommitted (the verifier's documented rule:
"Uncommitted source/build work is never current truth either"). Machine maps
therefore still correctly carry `f4cde3c` and must NOT be restamped here.
Rebaseline is gated on owner authorisation to commit the patch, after which
`rebuild_truth.py` moves the source commit and the maps are regenerated.
