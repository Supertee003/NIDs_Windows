# RULE-LAYER-SCOPE-001 — one automaton, every layer, every payload

**Created:** 2026-11-17
**Patch:** source applied, installed, and proven live (E5). Two live failures found and fixed two real defects; see 'Live proof' below.
**Build source:** this commit (see `git log -1`).

---

## The defect

`reloadRules()` put every non-L4 rule into one automaton (`g_active_ac`) and
`processEvent()` ran that automaton over the payload of every source except
`capture_host_net`. `configs/Rules.json` carries 23 rules across five layers
(L7, KERNEL_FILE, KERNEL_PROCESS, L2_PIPE, L4), so HTTP or TLS bytes containing
`IEX` were tagged with `R2003` — a KERNEL_PROCESS rule id — and a FIM path
containing `.locked` could be tagged with a network rule. Detection identity was
wrong in both directions, and `RULE-LAYER-SCOPE-001` recorded it at E1.

## What changed

| File | Change |
|---|---|
| `src/pipeline/runtime_state.zig` | `RuleLayer` enum, `g_layer_ac[4]`, `g_layer_rule_count[4]`, `g_ac_skipped_unknown_source` |
| `src/pipeline/rule_loader.zig` | `ruleLayer()` maps a rule's `layer` to its automaton; `reloadRules()` collects each rule's pattern while the JSON is alive and builds one automaton per non-network layer inside the same block, then swaps all four pointers under `g_ac_mutex` |
| `src/pipeline/event_processor.zig` | `ruleLayerIndexForSource()` chooses the automaton from the event's own source; a source with no layer does not match at all and increments a counter |

**Compatibility kept on purpose:**

* `g_active_ac` remains the network automaton, so readers that predate the split
  and the single-automaton tests keep working.
* `loadRulesInto()` is untouched: it is the test-facing loader and its callers
  expect one automaton.
* A rule with no `layer` field still goes to the network layer rather than being
  dropped — an older `Rules.json` must not lose rules silently. That is a
  documented default, not an accident.

## Pins (E2)

1. `ruleLayer()` maps `L7`/missing → network, `KERNEL_FILE` → kernel_file,
   `KERNEL_PROCESS` → kernel_process, `L2_PIPE` → l2_pipe.
2. A network automaton holding only `R9059` (`<script>`) does **not** match a
   payload containing `IEX`, while a kernel_process automaton holding `R2003`
   (`IEX`) does — and the network layer still matches its own rule. This is the
   defect, pinned as two automata built the way the loader builds them.
3. `ruleLayerIndexForSource()`: npcap/wfp → 0, fim/registry → 1, etw → 2,
   pipe_monitor → 3, and `capture_host_net`, `detection_brain`, `system` → null.

`zig build test` exits 0 with these included; `zig build` exits 0.

## What this does not prove

1. **No E5 yet.** The fix is verified as code and as automata, not as live
   attribution on wire bytes. The E5 check the gap asks for needs an HTTP
   listener on VMnet1 and payloads from Kali, then `aegisctl forensics` showing
   `capture_npcap` + the L7 rule id and no KERNEL_* id.
2. **The per-layer distribution inside `reloadRules()` is not unit-pinned.** It
   needs a real `Rules.json` under a runtime root; the pins cover the mapping and
   the automata, and the distribution is verified by build plus the pending live
   check. Saying it is pinned would be false.
3. **No soak.** A source change restarts the soak clock; the window has to be
   started after the rebuilt binary is installed.
4. **Fallback behaviour.** If a layer automaton fails to build, that layer reads
   as "no layered rules" and falls back to the network automaton, which is the old
   over-matching behaviour rather than matching nothing. That is fail-open for
   detection coverage and is logged; it is not silent.


---

## Live proof (E5, 2026-11-17)

**The check failed first, twice, and that is the useful part.**

1. First attempt on the installed layered build: a UDP payload carrying
   `IEX(New-Object Net.WebClient)` over VMnet1 was tagged **R2003**
   (KERNEL_PROCESS), and 1271-byte ambient traffic was tagged **R3003**
   (L2_PIPE, pattern `anonymous`). Cause: `src/daemon.zig` built a single
   automaton at startup and the pipeline fell back to it, because the layered set
   only existed after a `rules.reload`.
2. Second attempt after adding the startup reload: R2003 still fired on the wire.
   Cause: the first version of the split added every non-L4 rule to the network
   automaton **as well as** to its layer, so the kernel patterns were still
   reachable. Fixed: the network automaton now holds only network rules.

**Final measurement on the installed binary**
(`sha256 abf1a4ae469c2b01…`, service RUNNING, startup log
`layered rules at startup: loaded 23 (network=5 kernel_file=5 kernel_process=5 l2_pipe=5)`):

| stimulus | source | rule id observed |
|---|---|---|
| `<script>alert(1)</script>` in a request line, 3 frames | 192.168.126.1 / .10 | `R9059` (4009890390, L7) ×3 |
| `../../etc/passwd` in a request line, 3 frames | 192.168.126.1 | `R0088` (4254503461, L7) ×3 |
| `IEX(New-Object Net.WebClient)` in a request line, 3 frames | 192.168.126.1 | **no match at all** |
| file `canary.locked` created in `D:	mpegis-canary` | host (0.0.0.0) | `R1002` (kernel_file) |
| ambient host traffic | host (0.0.0.0) | `R1001`, `R1003` (kernel_file) |

Rule ids arrive as FNV-1a hashes in event rows and were mapped back with the same
function the loader uses.

**What is not claimed:** the R2003 positive control (a process created with `IEX`
on its command line) did not fire, so whether the ETW process payload carries the
command line is an open coverage question, not part of this fix. The stimulus came
from the host side of VMnet1, not from an HTTP client in the Kali guest, because
`vmrun runProgramInGuest` failed with `A file was not found` on this host.
