# PROJECT SCAN — what is still not done (2026-11-18)

> **Update, later the same day.** Item 3 (forensic search) is done and proven
> live: `payload_contains` now answers by payload text (8/8 canary records, 0 for
> a nonsense value) and the gap is closed. Item 4's diagnosis is finished and
> sharper than the note here: process-create rows carry a 61-byte image path and
> are routed to the *file* layer, so `R2001–R2005` are dead on this host for two
> independent reasons — filed as `PROCESS-CMDLINE-001` with the fix options.

**HEAD at scan:** `ef728b3` on `codex/o2-etw-context`
**Purpose:** one ordered list of everything still missing before this project can be
called closed. Ordered by the time it takes, shortest first, soak last.

Everything below was measured in this session unless it says otherwise. Nothing
here is copied from an older report without saying so.

---

## 0. State at scan time (measured)

| Check | Result |
|---|---|
| `python tools/final_audit.py` | **release: NOT SHIPPABLE (1/6 gates open)** |
| gates | `truth_artifacts` PASS · `component_audit` PASS · `release_signature` PASS (`release/T20-final/ad7948c`, digest `C1502245…`) · `clean_host_e5` PASS · `evidence_debt` PASS · **`soak_24h` OPEN** |
| `pytest -q tests/release tests/security` | **580 passed, 0 failed** |
| `pytest -q tests/release/test_native_build_and_scripts.py` | **10 passed** (the bridge now builds from a scratch copy) |
| `EVIDENCE_INDEX.json` | 275 evidence entries (E5 105, E2 125, E1 24, E3 14, E4 4, E7 2, E6 1); 283 gap records — **1 OPEN**, 62 CLOSED, 220 CLOSED_AT_RECORDED_HEAD |
| `docs/gates/waivers.json` | `waivers: []` — nothing is waived |
| installed vs `zig-out` sha256 | identical, `abf1a4ae469c2b01…` |
| working tree | 8 modified + 1 untracked (`docs/adr/0014-q-loss-ingress-isolation.md`) — records work not yet committed |

---

## Tier 0 — minutes: make the tree and the record honest again

1. **Commit the pending records.** `EVIDENCE_INDEX.json`,
   `FINAL-CLOSEOUT-STATUS-20261117.md`, `CLOSURE-PLAN-5GAPS-20261117.md`,
   `RULE-LAYER-SCOPE-001-20261117.md`, `docs/BACKLOG-v1.1.md`,
   `docs/gates/T20_100pct_audit.{json,md}`, the bridge test, and the still
   **untracked `docs/adr/0014-q-loss-ingress-isolation.md`** (the ADR the whole
   QLOSS decision hangs on). Then the digest/truth chain:
   `--refresh-digests` → commit → `rebuild_truth.py` → commit → `truth.py verify`.
   *Leaving the ADR untracked means the decision document does not exist for a
   clean checkout.*

2. **Restate `DIST-DLL-LOCK-001` as it really is.** The record says stopping
   `pythonw` PID 3168 released the file. It did, and then the same class of
   session-0 process held it again (PID 3800, per the closeout note; the file
   answers `PermissionError` on append right now). What actually settled it was
   the test change: `bridge/` is now built from a scratch copy, so its `../dist`
   is scratch too and a holder on the repo `dist/` can neither fail nor fake the
   result. The gap can stay closed **because the dependency is gone**, not
   because the holder was killed — the note has to say that.

---

## Tier 1 — hours: small, closable on this host

3. **`D2` version label: 6.0.0.** Source still says 5.0.0 everywhere
   (`installer/aegis.nsi:30,37,41,99`, `tools/installer.py:125,142`). It has to
   change in the **same source tree** as the QLOSS fix, because one source change
   set = one build = one signature = one soak window.

4. **`FORENSIC-SEARCH-EMPTY-001` (new, measured now).** `aegisctl forensic search`
   returns `records_matched: 0` for things that demonstrably exist:

   ```
   aegisctl forensic search --field rule --value R9059        → 0 matched (ring 18.7 M)
   aegisctl forensic search --field payload_prefix --value "GET /scan" → 0 matched
   aegisctl events tail --count 20 --src-ip 192.168.126.1 --json → R9059 rows present
   ```

   Either the client-side rule hashing in the search path differs from
   `hashRuleId`, or the scan walks a window that does not contain those records,
   or `payload_prefix` is compared against the wrong byte span. Until this is
   fixed, "search the ring" is not a usable operator capability and the
   2026-11-17 note that `--payload-prefix` "returns 0 on this build" is an
   unexplained defect, not a usage quirk. 1–4 h to diagnose, then a pin.

5. **ETW process-create coverage (`R2003` positive control).** Closing
   `RULE-LAYER-SCOPE-001` proved network bytes never carry kernel rule ids, but
   the *positive* control never fired: launching `powershell -Command "IEX …"`
   produced no `R2003`, while `R1001/R1002/R1003` fire normally. So either the
   ETW process payload does not carry the command line, or the rule's layer is
   wired to a lane that process-create events do not reach. It is a real
   coverage question for a kernel rule that is supposed to catch exactly that.
   2–6 h to determine, then either a fix or an honest `KNOWN_LIMITATIONS` entry.

6. **Optional host cleanup.** A stray elevated `pythonw.exe` in session 0 still
   maps `D:\NIDs_Windows\dist\aegis_ipc.dll`. Killing it needs elevation
   (`Stop-Process` from this session is denied). After item 1 nothing depends on
   it, so this is hygiene, not a blocker.

---

## Tier 2 — days: the one remaining product gap, needs a decision first

7. **Owner picks the QLOSS option** in `docs/adr/0014-q-loss-ingress-isolation.md`
   (§Options, lines 46–87):

   | Option | What it does | Cost | Effect on the gap |
   |---|---|---|---|
   | **A** (recommended by the ADR) | ETW `NameDelete` whose path matches no kernel-file pattern is not enqueued; matching deletes flow unchanged; the drop is reported as `etw_delete_filtered_total` + one aggregate row with count, top-N prefixes and a sample | ~2 days + build + soak | removes ~18.1 M rows, leaves the match set identical |
   | **B** | batched forensic append (amortise the 4 KiB pass) | ~2–3 days + soak | raises the ceiling, does not bound the burst; companion to A |
   | **C** | publish the loss envelope + owner sign-off | zero code | leaves the gap open by definition, restated every release |

   The ADR cannot supply the sign-off that C needs; A is the only option that
   reduces volume without changing what detection can see.

8. **Implement the chosen option** against the ADR's acceptance criteria:
   (1) `shed_overload` and total drops below the QLOSS baseline for the same
   stimulus, (2) `canary.locked` still yields `R1002` and `R1001`/`R1004` still
   fire, (3) every suppressed row appears in a counter that `status`/`metrics`
   show and mass deletes still appear as one aggregate, (4) a 24 h soak passes on
   the new build with the same budgets.

9. **Full test matrix after the change** — `zig build`, `zig build test`,
   `cargo build --release`, `cmake`, `go build`, the pytest sweep. Proof has to
   exist before anything is signed.

---

## Tier 3 — half a day, and then the clock starts

10. **`D3` rebuild + sign + verify.** New RC from the post-QLOSS source,
    `sign_release.py --sign`, `--verify`, and `release_engineering.py --verify`
    green at the new source commit.

11. **Install on this host + `D4` drill.** In-place install of the signed build,
    `host_preflight.py` PASS, and the upgrade/rollback path exercised with a
    hash-verified snapshot (`tools/upgrade_rollback.py`), because that is the
    closest thing to a fresh-install boot model this host can prove.

12. **`soak_24h` — last, and alone.** `host_soak_check.py --start auto --baseline
    auto --hours 24 --loss-budget 3500 --shed-budget 20000`, then **nothing else
    on the host** for 24 h: the 2026-11-14 window failed at 16.95 h
    (`shed_overload` 15,163) precisely because gates were run inside it, and the
    11-15 window died on a mid-window restart. When it passes, the board is 6/6
    and the release is SHIPPABLE.

---

## Cannot be closed on this machine — record as limitations, never as passes

13. **`D1` driver signing:** EV certificate + Partner Center + HLK/attestation on
    a separate target. Needs a legal entity and hardware this host does not have.
14. **True clean-machine boot model:** this host has the toolchain, Npcap and a
    test certificate installed, so "boots on a clean Windows" is not proven here;
    `D4` is an in-place approximation and must be labelled as one.

---

## The order in one line

commit the records → restate the DLL note → 6.0.0 label → forensic search defect
→ ETW process coverage → pick QLOSS option → implement it → full matrix → rebuild
and sign → install + rollback drill → **24 h soak alone** → board 6/6.
D1 and the clean-machine model stay written down as limitations.
