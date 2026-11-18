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

---

## Re-measurement, 2026-11-17 21:26 (records HEAD `ef728b3`, installed `ABF1A4AE`)

Run again from scratch on the still-running installed service, with a payload that
closes the one gap the first round left open: **was the `IEX` frame processed at
all, or simply not captured?** Sending both patterns in the *same* frame answers
it, because a row can only be produced for a frame the pipeline processed.

Method: UDP datagrams from the host to `192.168.126.10:8080` on VMnet1 (three
rounds, 50 ms apart), read back from `C:\Windows\System32\logs\aegis_core.ndjson`.
That last detail matters: `aegisctl forensics list --payload-prefix` returns
`records_matched: 0` on this build even for the prefix `GET /` while the ring holds
hundreds of `rule_id: 0` npcap rows, so the payload-bearing query the gap originally
asked for cannot be run here. The ndjson rows carry `src_ip`, `payload_len`,
`event_id` and the hashed rule id, which is what attribution needs.

| stimulus (UDP over VMnet1) | rows | rule id observed | src_ip |
|---|---|---|---|
| `GET /<script>alert(1)</script>` ×3 | 6 (both directions) | `R9059` 4009890390, L7 | `.1` and `.10` |
| `GET /../../etc/passwd` ×3 | 6 (both directions) | `R0088` 4254503461, L7 | `.1` and `.10` |
| `IEX(New-Object Net.WebClient)` ×9 | 0 | **no match at all** | — |
| `GET /<script>…` **and** `X-Note: IEX(New-Object Net.WebClient).DownloadString(...)` in one frame ×3 | 6 (both directions) | `R9059` only | `.1` and `.10` |

Row ids for the last two lines: `event_id` 686–691, six rows, `payload_len` 186
from `192.168.126.1` and 214 from `192.168.126.10` (the VM-facing direction is
captured too). Every row is `policy=block`, `enforcement_status=observed`,
`host_effect_confirmed=false`.

**Result:** the frame that demonstrably carried the kernel-process pattern
`IEX|DownloadString` produced an L7 id and no `R2003`/`R2001`/`R2002`/`R2004`/`R2005`.
That is the exact defect `RULE-LAYER-SCOPE-001` recorded at E1, measured on the
wire, on the shipped binary, twice.

### The Kali guest as stimulus source: closed as a limitation, not a blocker

The gap text asked for payloads "from Kali". On this host the guest cannot be
driven, and that is a limitation of the lab, not of the product:

| attempt | result |
|---|---|
| `vmrun -gu kali -gp kali runProgramInGuest` / `runScriptInGuest` | `A file was not found` |
| `vmrun fileExistsInGuest` on `/`, `/etc/passwd`, `/bin/sh` | `The file does not exist` for every path, including `/` |
| same, after a graceful guest stop/start | unchanged |
| `vmrun listProcessesInGuest` | works (204 processes) — auth and RPC are fine, only file/program ops are broken |
| `vmrun captureScreen` | works (screenshots in `admin-evidence/rule-layer-e5-20261117/`) |
| guest port scan 22/80/443/445/3389/5900/8080/… | nothing listening, so no SSH/agent channel exists |
| GUI keystroke injection via `SendKeys` + a click into the console | no effect in three attempts (screenshots kept) |

The wire bytes are nonetheless on VMnet1 and both directions are captured, so the
layer-attribution question is answered; what is missing is only the provenance
"the bytes were typed inside the guest". Anyone with console access to the Kali VM
can add that by running, on the guest:

```bash
curl -s -o /dev/null --path-as-is 'http://192.168.126.1:8099/<script>alert(1)</script>'
curl -s -o /dev/null -X POST --data-binary 'IEX(New-Object Net.WebClient)' http://192.168.126.1:8099/probe
```

and the expected outcome is already recorded: `R9059` for the first, no rule at all
for the second, never a kernel id.
