# FINAL CLOSEOUT STATUS — 2026-11-17

**Read this before claiming the project is closed.** It states what is proven, what
is open, and what cannot be closed from this host at all.

---

## Release gate board (`python tools/final_audit.py --release-check`)

```
PASS  truth_artifacts     TRUTH_VALID, build source b955f91
PASS  component_audit     modules 66/66, prod failures 0, part_ii 5/5, golden path declared
PASS  release_signature   release/T20-final/ad7948c signs SHA256SUMS (C15022458409F5C9...)
                          and commit ad7948c contains runtime b955f91
PASS  clean_host_e5       preflight PASS with the boot loader under C:\Program Files\AEGIS NIDS
OPEN  soak_24h            window restarted 2026-11-17T19:21:08 on the installed image ABF1A4AE
PASS  evidence_debt       unnamed product files 0
release: NOT SHIPPABLE (1/6 gates open)
```

**The only release gate still open is the 24 h window on the final build.** It
cannot be closed by writing code: it needs 24 hours in which the daemon is not
restarted, and every install, build or reboot resets it. That is why the two
earlier windows are voids, not failures of the product:

| window | outcome | why |
|---|---|---|
| `2026-11-14T22:20` | FAIL at 16.95 h | `shed_overload` 15,163 vs 4,000 because the adversarial gates ran inside it |
| `2026-11-15T16:50` | FAIL at 48.43 h | daemon uptime 0.49 h — the process was restarted mid-window |
| `2026-11-17T17:32` | VOID | superseded: the daemon was restarted at 17:57 by the final install, so uptime was shorter than the window |
| `2026-11-17T19:21` | IN_PROGRESS | clean baseline on the installed image `ABF1A4AE`, all loss counters 0, nothing else touches the host until it closes |

Check it with:

```
python tools/host_soak_check.py --start 2026-11-17T19:21:08 \
  --baseline admin-evidence/e5-clean-host-20261117-soak3/soak-24h.baseline.json \
  --hours 24 --loss-budget 3500 --shed-budget 20000 \
  --json admin-evidence/e5-clean-host-20261117-soak3/soak-24h-delta-latest.json
```

## Open gaps (1)

### `RULE-LAYER-SCOPE-001` — CLOSED at E5 (2026-11-17 21:26, re-measured)

Layered automata are in source and in the installed binary (`ABF1A4AE...`), and the
attribution is now measured on the wire, twice. The re-measurement sent one UDP
frame over VMnet1 carrying **both** `<script>alert(1)</script>` and
`IEX(New-Object Net.WebClient).DownloadString(...)`, so the kernel-process pattern
was demonstrably inside a frame the pipeline processed: six rows (`event_id`
686–691, both directions, `src_ip` 192.168.126.1 and .10, `payload_len` 186/214)
carried only `R9059` (L7) and no `R2003` or any other `KERNEL_*` id. A payload with
`IEX` alone produced no signature match at all.

Two limitations are recorded rather than papered over:

* `aegisctl forensics list --payload-prefix` returns 0 matches on this build even
  for `GET /`, so attribution was read from `aegis_core.ndjson` (which carries
  `src_ip`, `payload_len`, `event_id` and the hashed rule id).
* The stimulus is host-originated on VMnet1, not typed inside the Kali guest: the
  guest cannot be driven on this host (`vmrun` file/program ops return "file does
  not exist" for `/` itself, before and after a guest restart; no port is open on
  the guest, so there is no SSH channel; GUI keystroke injection did not reach it).
  The frames are on the captured wire in both directions, so the layer question is
  answered; the guest-provenance variant stays a documented limitation.### 1. `GAP-QLOSS-ISOLATION-002` — needs a product decision, not just code

ETW `NameDelete` is the largest ingress lane (18.15 M rows) and the fair-share
arithmetic was already fixed at E2. Closing it is one of three deliberate choices:
filter ETW deletes that match no rule path (with a mass-delete aggregate so
ransomware stays visible), batch the forensic append, or accept an envelope with
a documented budget and an owner sign-off. Each has a different product meaning, so
this is the owner's call, not an implementation detail.

The three options, their cost and the recommendation (**A**, producer-side filter
of deletes that match no rule path, with an aggregate for mass deletes; **B**,
batched forensic append, as companion) are now written up in
`docs/adr/0014-q-loss-ingress-isolation.md`. One fact from that write-up matters
for the choice: kernel-file rules match path text, so a delete of
a matching path already produces a row today — option A removes only rows that
carry `rule_id = 0`, which is why it cannot shrink the match set.

## Not closable here at all

* **D1 — EV certificate + HLK/attestation.** Needs a legal entity, an EV cert with
  token/HSM, Partner Center access and an HLK target that is not the controller.
  Kali cannot serve as the target. A test-signed driver must never be called
  production-signed.
* **Clean-machine boot model.** This host has the toolchain, Npcap and a test cert
  by construction; an in-place reinstall is not that evidence and is recorded as a
  limitation instead.
* **D2 — 6.0.0 version bump.** Deliberately deferred into a single v1.1 batch so it
  costs one build, one signature and one window instead of two.

## Closure pass — 2026-11-17 19:30 (records HEAD `ef728b3`, build source `b955f91`)

Re-ran the board on the current tree; nothing was rebuilt, reinstalled, re-signed
or restarted. `final_audit.py --release-check` still reports **5/6 PASS**, the
same single open gate:

```
PASS  truth_artifacts     TRUTH_VALID, build source b955f91
PASS  component_audit     66/66 modules, prod failures 0, part_ii 5/5
PASS  release_signature   release/T20-final/ad7948c signs SHA256SUMS (C1502245...)
                          and commit ad7948c contains runtime b955f91
PASS  clean_host_e5       preflight PASS with the loader under C:\Program Files\AEGIS NIDS
OPEN  soak_24h            the 17:37 window is void (daemon restarted 17:57); a fresh
                          baseline was recorded 19:30 on the installed image
PASS  evidence_debt       unnamed product files 0
```

**Release identity holds end to end.** The installed image
`C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe`, `zig-out\bin\aegis_nids.exe`
and `release/T20-final/ad7948c/bin/aegis_nids.exe` are the same sha256,
`ABF1A4AE469C2B017BF387ECCA880E248D4FCAE6A31E5B4ED5596F5EF08F938A`.

### Environment defect identified (not a product defect)

`test_bridge_builds_into_dist` was still failing with `LNK1104` on
`dist\aegis_ipc.dll`. Restart Manager (`RmRegisterResources` + `RmGetList`) names
the holder: **`pythonw.exe` PID 3800**, an elevated session-0 leftover created
17:58:04, the same class of stray automation process as PID 3168 in
`DIST-DLL-LOCK-001`. It is not an AEGIS service and maps no AEGIS module. The
current session is **not elevated**, so `Stop-Process -Id 3800 -Force` fails with
Access denied.

**Fixed at E2 without elevation and without touching the holder.** The test now
copies `bridge/` into `tmp_path` and builds there, so its `../dist` does not exist
yet and configure must create it -- the clean-checkout property is proven more
strictly, and a holder on the repository's `dist/` can neither mask nor fake the
result. The test writes nothing into the repository. Killing PID 3800 is now
optional, not a prerequisite for a green suite.

### Verified in this pass (run, not claimed)

| Check | Result |
|---|---|
| `zig build` | exit 0 |
| `zig build test --summary all` | exit 0 (cache hit; inputs unchanged since the recorded 2,113-test pass) |
| `pytest tests/release tests/security tests/tools -q` | **869 passed, 0 failed** (re-ran after the isolated-output fix; the earlier run on the same tree was 868/1 with the DLL lock) |
| `python tools/release_engineering.py --verify` | OK, 648 artifacts at source `b955f91` |
| `python tools/truth.py verify` | `TRUTH_VALID` |
| installed / zig-out / RC sha256 | identical, `ABF1A4AE...` |

The two `_tmp_*` holder probes used for the investigation were deleted; the
tree carries no scratch files.

### What actually remains

1. **Soak `soak_24h` — time only.** A clean baseline on `ABF1A4AE` was recorded
   2026-11-17T19:21:08 with `--baseline auto` (uptime-derived start, all loss
   counters 0, `problems []`, `scm_restarts []`); the window closes
   2026-11-18T19:21:08 if the daemon is not restarted. Nothing else may run on
   the host in the meantime (the 16.95 h failure was caused by gates running
   inside the window). Re-check with the `host_soak_check.py` command above.
2. **`GAP-QLOSS-ISOLATION-002` — owner decision**, not code: ETW `NameDelete`
   filter with a mass-delete aggregate, batched forensic append, or an accepted
   envelope with a signed budget.
4. **D1 EV/HLK, D2 6.0.0 bump, clean-machine boot model** — outside this host.

(Item 3 — the `RULE-LAYER-SCOPE-001` E5 attribution — is now closed; see "Open
gaps" above. The list keeps the numbering for cross-references.)

## Final batch — one build, one sign, one window (owner's ordering, 2026-11-17)

The remaining work is deliberately sequenced so that the 24 h window is spent
**once**, on the build that ships. Everything that costs a restart, a rebuild or a
signature goes in the same batch, and the soak is last:

| # | Step | Why it is in this position |
|---|---|---|
| 1 | Owner picks one option in `docs/adr/0014-q-loss-ingress-isolation.md` (A / B / C) | it decides what the batch contains |
| 2 | Implement the chosen QLOSS option + the `6.0.0` label in the same source tree | one source change set = one build |
| 3 | `zig build` / `cargo build --release` / `cmake` / `go build`, full test matrix | proves the batch before it is signed |
| 4 | `release_engineering.py` rebuild + sign + verify (`D3`) | one signature, one RC |
| 5 | In-place install + `host_preflight` + `D4` fresh-install boot model on this host | restarts the daemon, so before the window |
| 6 | Start the 24 h window on the installed image and do **nothing else** on the host | the 16.95 h failure was caused by gates running inside a window |
| 7 | Close the gate board when the window passes | release becomes SHIPPABLE (6/6) |

Items that cannot enter this host's batch at all: `D1` (EV certificate + HLK on a
separate target) and the true clean-machine boot model. They stay recorded as
limitations, not as passes.

## What was verified in this session (not claimed, run)

`zig build` 0 · `zig build test` 0 (2,113 tests, includes the new layer pins) ·
`zig build test-network-integration` 0 · full pytest at the pre-layer HEAD
1,371 passed / 4 skipped / 2 xfailed · `tests/release tests/security` 580 passed
after the records work · installed sha256 equals build sha256 · `status`
RUNNING/RUNNING · `readiness` ready true, 23 rules, 6 policies ·
`host_preflight` PASS, failed [] · RC `a101c4f` rebuilt from this source, signed
and verified · `truth.py verify` TRUTH_VALID · evidence debt 0.
