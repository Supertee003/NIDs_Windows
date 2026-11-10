# QLOSS-ETW-PRIORITY-001 — stop the ETW share from starving the signal classes

**Created:** 2026-11-11
**Build source before this patch:** `cf041b8` (HEAD `97fd269`)
**Finding:** the live 24 h soak lost 148,217 rows, all on `capture_etw`, while
the storm policy that is supposed to shed the low-value classes never fired.
**Evidence level:** E2 (unit) only. The host re-measurement is the gate this
patch cannot close by itself.

---

## 1. What the host actually did

`queue --json` on the running daemon (source `c79c5a1`, uptime 8.93 h):

```
dropped_total      148,217
shed_overload            0
source_quota_shed  148,217
```

Attribution:

| source | kind | dropped | pushed |
|---|---|---:|---:|
| `capture_etw` | `fim_change` | 145,915 | 7,569,564 |
| `capture_etw` | `reg_change` | 2,302 | 4,493,554 |

Every other source dropped zero. The queue itself was not full at the moment
of reading (`depth 46 / 16,384`), which is why the global storm line never
fired.

## 2. Root cause: two different pressure lines

`src/pipeline/telemetry_threads.zig` already has a deliberate storm policy:

```
shouldShedWrite(depth) = depth >= PIPELINE_QUEUE_SIZE * 3 / 4   // 12,288
```

and the ETW callback shed `Kernel-File Write` / `NameDelete` only when that
line was crossed. But admission refuses a host source at a *different* line:
`SOURCE_OCCUPANCY_CAP = 7,168`, half the working host tail.

So a file-write burst could fill the ETW share (7,168) while the whole queue
still looked calm (below 12,288). At that point the sheddable writes were not
shed by policy — they were refused by the per-source quota as
`source_quota_shed`, and once the share was full the **registry and process**
rows were refused by the same quota. That is the wrong priority: the policy
already declares Write/Delete low-value, while `ProcessStart`, `CreateKey` and
`SetValueKey` are the signal-bearing classes.

The 145,915 / 2,302 split is the direct fingerprint: a file-write burst
consumed the share, and registry rows paid for it.

## 3. What changed

`src/pipeline/telemetry_threads.zig`:

- new `ETW_SHARE_MARGIN = 256` and a pure gate
  `etwSharePressure(depth, occupancy)`, true when **either** the queue is 3/4
  full **or** this source is within 256 slots of its own cap;
- the callback now sheds `Write`/`NameDelete` when `etwSharePressure(...)` is
  true, not only at the global line;
- the existing first-sighting exemption (`tryExempt`) and its 200-token /
  100-per-second bucket are unchanged, so a new file's content is still
  evaluated once even under pressure;
- a bounded 256-slot reserve is left inside the ETW share for the classes the
  policy does not declare sheddable.

This is a policy repair, not a capacity increase and not a pacing change.
Pacing the ETW callback was rejected: the callback runs on the ProcessTrace
thread, and the helper exposes no `EventsLost` counter, so a pause would turn
a **counted** queue refusal into an **uncounted** kernel-side loss. The
project's rule is that loss must be attributable; shed is attributable.

## 4. What this does and does not claim

It does **not** make the soak zero-loss. A write storm still loses rows — they
are now lost as `shed_overload` (policy, first sighting exempt) instead of
`source_quota_shed` (overflow), and the signal classes keep the reserve.

It does **not** change detection semantics for `NameCreate`: that class is
still deduped only while the minifilter lane is `ok`, and is never shed by this
gate.

It **does** make the next host window measurable in the right terms:
`queue.stats` will show whether `shed_overload` rises while `by_source_kind`
registry/process drops fall. Until that is measured, this record is E2.

## 5. Verification

```
zig build test --summary all   -> 2,085 passed / 10 skipped / 0 failed
zig build                      -> exit 0
new test: "QLOSS-ETW-PRIORITY-001 sheds low-value ETW rows when its own share
is near the cap" (global line, share line, saturation, reserve sanity)
```

No Python, wire, ABI or contract change.

## 6. Limitations and open decisions

1. **E2, not E5.** The live soak that produced the finding ran the previous
   build; this build has not been deployed or measured.
2. **Policy shift needs an owner decision.** Extending storm shed to the
   per-source boundary changes which rows are lost first. The record states
   the rule; it does not decide the loss budget.
3. **The reserve is not a guarantee.** The first-sighting bucket can release
   up to 200 writes in a burst; high-value rows can still be quota-refused
   during a registry storm.
4. **`shed_overload` is not in the health payload.** The soak tool reads
   `data_integrity`, so a soak can pass while policy shed is nonzero. That is
   a separate honesty gap (the queue surface exposes it; the soak door does
   not) and is not fixed here.
5. **No ETW lost-event counter.** Pacing remains unsafe until the helper can
   report `EventsLost`/`BuffersLost`; the alternative was not taken.
