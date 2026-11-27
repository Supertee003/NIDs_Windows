# Real finalizer verdict for soak `20261126-225843` — FAIL

**RECORD-ID:** `SOAK-225843-FINALIZER-FAIL-AA3B7B0-20261127`  
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged; records-only)  
**RUN-ID:** `20261126-225843`  
**VERDICT WRITTEN:** `2026-11-27T22:59:23+07:00` — **`verdict=FAIL`**, `check_exit=3`  
**RELATED:** #54 (post-soak rebaseline), #55 (STOP-THE-LINE runtime swap), `docs/PATH-TO-COMPLETE.md`

The real finalizer artifact now exists and has been consumed. It is a **FAIL**, not a PASS. No gate is closed by it.

## Acceptance rule from #54, evaluated honestly

| Required | Observed | Result |
|---|---|---|
| `verdict=PASS` | `FAIL` | **not met** |
| `elapsed_hours>=24` | `24.0` | met |
| `problems=[]` | 7 entries | **not met** |
| `restore.verified=true` | `true` | met |
| counter deltas consistent with raw transcript | generation changed inside the window; deltas are declared meaningless by the checker | **not met** |

The result is recorded as FAIL/VOID-for-credit. It is not relabelled, relaxed or promoted.

## Verbatim verdict

| Field | Value |
|---|---|
| `check_exit` | `3` |
| `verdict` | `FAIL` |
| `soak_start` / `target_end` | `2026-11-26T22:59:10` / `2026-11-27T22:59:10` |
| `checked_at` | `2026-11-27T22:59:10` |
| `elapsed_hours` | `24.0` (required `24.0`) |
| `services` | `AegisNids`, `AegisAggregator`, `AegisWfp`, `AegisMinifilter` all `RUNNING` |
| `daemon_uptime_hours` | `1.2` |
| `daemon_state` / `daemon_health_state` | `RUNNING` / `DEGRADED` |
| `process_generation_ms` | `1795708740368 → 1795790817381` |
| `queue_dropped_total` delta | `115976` |
| `nose_frames_dropped` delta | `4904` |
| `minifilter_ring_dropped` delta | `6889891` |
| `minifilter_pipeline_dropped` delta | `29120` |
| `nose_frames_rejected`, `nose_pipe_errors`, `shed_overload` deltas | `0` |
| `nose_alive_at_end` | `true` |
| `restore.verified` | `true` |
| `errors` | `[]` |

The seven recorded problems are: daemon uptime `1.20h < 24h` (process restarted mid-soak); daemon `DEGRADED`; process generation changed inside the window so counter deltas are meaningless; `queue_dropped_total` +`115976`; `nose_frames_dropped` +`4904`; `minifilter_ring_dropped` +`6889891`; `minifilter_pipeline_dropped` +`29120`, each over the checker's loss budget `0`. No value was edited or re-labelled.

`restore` after the final check returned the install directory to the pre-soak baseline hashes `FBD9BDB3…`, `AEAB9B63…`, `870CB962…`, service `Running`, `AEGIS_LOSS_BUDGET=3500` and machine interface `\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}`. Read-only hash inspection at `23:02:39` confirmed those hashes are installed. The agent performed no restore and no host action.

## Why this window also carries no evidence credit

Independently of the FAIL verdict, the stale finalizer of the already-voided `214622` window restored its pre-soak binaries at `21:47:03`, about 72 minutes before this window's target. The binaries pinned at `225843` start (`6F548AF7…`, `8C05FE48…`, `6E05AAE1…`) were replaced by the baseline hashes. This is documented with byte-exact artifacts in `SOAK-VOID-LATE-FINALIZER-GAPS-FIRST-AA3B7B0-20261127.md` and issue #55. Any counter delta after `21:47:03` cannot be attributed to a stable current-source runtime. The window is therefore **VOID for current-source soak evidence** as well as being an honest FAIL.

The scheduled task `AegisNidsSoakFinalize_20261126-225843` was not listed by `schtasks /Query` during the window, but the finalizer process did run and wrote the artifact. No conclusion is drawn about why the task was not listed; the artifact is the authority.

## Consequences

- `soak_24h` stays **OPEN**; release board stays **5/6 — NOT SHIPPABLE**.
- No PASS, E5 host proof, E6/E7 qualification, new signature, signed driver or driver-load claim is created.
- No source, gate, guard, threshold or verdict was changed. Product-source findings (#47/#50/#51/#53), signature/E7 and rebaseline decisions remain frozen pending owner authority.
- Next owner action (issue #55): stop stale finalizers/watchers, ensure one finalizer per window, then arm a single clean 24 h window with no concurrent host work. Only a real `PASS` meeting all #54 conditions can close `soak_24h`.

## Verbatim artifacts and integrity

`analysis/current-head/raw-aa3b7b0-20261126/soak-225843-finalizer/`

| File | SHA-256 | Source equality |
|---|---|---|
| `result.json` | `19D12276FA1C143BF3383BE6486E49F0C7872D91B257878ABE0AF478C2075323` | byte-exact copy verified |
| `soak-final.json` | `56571085A57C9915ECE96680EA093438A8C6F266BC52660CC2935A4D13B9D821` | byte-exact copy verified |
| `finalize.log` | `1D61676613E31EF9897B277E4EC5E42972B90858012B0BFDD1CF69617207C555` | byte-exact copy verified |
| `verbatim-manifest.json` | records source/copy hashes, byte counts, source timestamps and the no-claim boundary | — |

Script timestamps are labelled `Z` but match the operator's `+07:00` filesystem clock; they are reported as local clock labels, not verified UTC. `finalize.log` is force-added because `.gitignore` excludes `*.log` globally; this is one verbatim evidence artifact, not runtime state.
