# QLOSS-ETW-WRITEFILTER-001 — stop ingesting file writes no rule can act on

**Created:** 2026-11-12
**Build source before this patch:** `1ca18c4`
**Finding:** the 30.8 h window (SOAK-30H) showed the ETW share held by 8.85 M
generic file writes while 1,394 registry rows were quota-dropped and 446 k rows
were policy-shed.
**Level:** E2 (unit/build). The host measurement is the next window.

---

## 1. The measurement that forced this

30.8 h on `21A875CF…` (source `1ca18c4`), `capture_etw` only:

| class | count |
|---|---:|
| `file_write` | 8,850,070 |
| `file_name_delete` | 606,234 |
| `reg_create` | 10,947,406 |
| `reg_set` | 222,425 |
| `process_start` | 10,980 |
| `file_name_create` (after minifilter dedupe) | 19 |

Loss: `queue_dropped_total=1,395` (1,394 `reg_change`), `shed_overload=446,327`.
The writes are 44 % of all ETW rows and the dominant reason the share is full
when a registry burst arrives.

## 2. Rule audit: who consumes a generic write?

`configs/Rules.json` (23 rules) and `configs/runtime.json` `fim_paths`:

| rule | signal | path |
|---|---|---|
| R1001 System32 Write Attempt | path match | `C:\Windows\System32\*` |
| R1004 DLL Drop in System32 | path match | `C:\Windows\System32\*.dll` |
| R1005 hosts File Modification | path match | `C:\Windows\System32\drivers\etc\hosts` |
| R1003 Startup Folder Modification | path match | `*\Startup\*` |
| R1002 Ransomware Rename | `.locked` / `.encrypted` / `.ransom` | create/rename, delivered by the minifilter lane |

No rule matches an arbitrary write to a user document, temp file or browser
cache. Those writes are the 8.85 M. The configured `fim_paths` are exactly the
System32 / SysWOW64 / drivers\etc trees, all covered by `isCriticalPath`.

## 3. What changed

`src/pipeline/telemetry_threads.zig`:

- new pure predicate `shouldAdmitEtwWrite(path)`:
  - admit when the path is empty (unknown evidence is never discarded);
  - admit when `event_queue.isCriticalPath(path)` (System32 / SysWOW64 /
    drivers\etc, case-insensitive);
  - admit when the path contains `\Startup\` (R1003);
  - otherwise filter.
- in `etwCallback`, Kernel-File **Write** (Id 0x10) records that fail the
  predicate are dropped before they consume the share, counted in the new
  `file_write_filtered` counter;
- `queue.stats.etw` now publishes `file_write_filtered`; the CLI prints it.

`NameDelete` (0x0B) and all registry/process rows are unchanged. An empty or
undecodable path is admitted, so a decoder regression cannot silently turn into
a total write blackout.

## 4. What this is, and what it is not

It is a **coverage decision**: AEGIS no longer ingests ETW file writes outside
the paths its rules can act on. The first write to a new document is no longer
in the pipeline unless it is in a protected tree; the create event for that
document is still delivered by the minifilter, so R1002/R1004 still see the
file's appearance.

It is **not** a zero-loss claim. The filter is counted (`file_write_filtered`),
and the 24 h gate must still show `queue_dropped_total=0` and `shed_overload=0`
on the remaining lanes. If registry still overflows, the next lever is the
256-slot ETW reserve or registry coalescing, not this filter.

## 5. Verification

```
zig build test --summary all   -> 2,087 passed / 10 skipped / 0 failed
zig build                      -> exit 0, daemon 25AB91543EBC90F5...
new tests: predicate table (critical, Startup, hosts, generic, empty) and a
callback test proving a generic write increments file_write_filtered without a
queue push, while a System32 write is admitted.
```

No wire, ABI or contract change. `queue.stats` gains one additive field.

## 6. Limitations and open decisions

1. **E2 only.** The host has not run this build; the expected effect (shed and
   registry overflow collapse) is a hypothesis until the next 24 h window.
2. **Coverage boundary.** Generic file writes are no longer evidence. If a
   future rule needs them (e.g. content-change heuristics on user documents),
   this filter is the first thing that must be revisited.
3. **Anomaly baselines shift.** The anomaly detector sees fewer `fim_change`
   rows; its thresholds were not retuned here.
4. **NameDelete still admitted.** 606 k deletes remain; if they become the new
   pressure point, the same audit must be done for them before filtering.
5. **Packaging gap is unchanged.** The boot task and start mode still live in
   `admin-evidence`; the installer does not ship them.

## 7. Acceptance for the next window

Deploy `25AB9154…`, reboot, arm a clean 24 h window at 0/0, and require:

- `queue_dropped_total = 0` (the 1,394 registry overflow is the target),
- `shed_overload = 0` (the 446 k write shed is the target),
- `minifilter_ring_dropped = 0` (must stay),
- no SCM restart.

If `file_write_filtered` is large and the two loss counters are zero, the
window passes — with the coverage boundary stated in the release note, not
hidden.
