# Final disposition of all AI-work claims — 2026-11-19

Owner request: "งานที่เหลือคืองานที่ผมใช้ AI หลายตัว — นำมาทำต่อให้ครบ" (the
remaining work is the work from the several AIs I used; bring it all and finish
it). A read-only audit covered every `.manus/worktrees/*`, `.cloud-attachments/`,
`.manus/mcp-results/`, `.work/`, root AI handoffs, Copilot archive worktrees,
the git stash, and issues #29–#36. Result: **every claim is now accounted for.**
No product source changed; build source remains
`f4cde3c503fd8b696183751a608b999768caa769`.

## Applied in this closeout (records/CI/tool only)

| Item | Source | Action |
|---|---|---|
| CI host-regression deps + audit path (below) | this tip | `.github/workflows/host-regression.yml` installs `-r requirements.txt` (Flask) + networkx/pyvis; `tools/final_audit.py` checks canonical `build/x64/{wfp,minifilter}/aegis_*.sys` (`REL-AUDIT-WDK-PATH-001`) |
| Manifest drift caused by the CI edits | this tip | `python tools/release_engineering.py --refresh-digests` re-stamps the two tool/workflow digests; `source_commit` stays `f4cde3c` |

## ALREADY_INCLUDED / HISTORICAL_SUPERSEDED / NO_OP (nothing left to do)

- **XDR-RECEIPT-002** (`recordXdrAdvisoryReceipt`, wire pins, incident fabric) — landed; `src/pipeline/event_processor.zig`, `src/xdr/xdr_runtime.zig`, `src/xdr/xdr_incident_fabric.zig`, `tests/security/test_xdr_wire_advisory.py`.
- **RULE-LAYER-FAILCLOSED-001** (`gqdpidn`, commits `3aafce0`/`e8112be`) — this *is* build source `f4cde3c` (fail-closed automaton selection, `g_ac_skipped_unavailable_layer`, 8 tests).
- **STOPLINE-TRUTH-CI-SIGNATURE-001** (`crtxl0u`, 5 commits) — equivalent work at tip; issues #32/#33 closed via detached Ed25519 verification + owner trust anchor.
- **12-phase production handoff / RELEASE-SIG-CRYPTO-BYPASS P0** — historical, superseded by closeout docs; issue #33 closed with real crypto proof.
- **QLOSS-ETW-DELFILTER-001** (`cc5fe84`) — behavior already present (`g_etw_classes.name_delete_filtered`, `is_name_delete` at `telemetry_threads.zig:518-524`); helper names differ but the filter works.
- **Copilot ancestor worktrees** (`2d19381`, `daf9088`) — ancestor / merged into release with `-s ours` at `63990c8`.
- **3 MCP payloads** — queued workflows only, no result artifacts; ignored scratch.
- **Issues #29/#30/#31** — throughput 4,000 op/s zero drops, FIM crash fix, `FOR-BATCH-001` all closed with code at tip.

## DO_NOT_PORT — hard stop-the-line (never adopt)

- **B4: fail-open rule-layer reversion** in `bsvfvv3` committed HEAD
  (`active_ac = state.g_layer_ac[li] orelse state.g_active_ac`, no
  `resolveRuleAutomaton`, no fail-closed tests). Reintroduces the exact policy
  bypass that `f4cde3c` fixed. Reject.
- **B3: dirty `docs/gates/T20_100pct_audit.*`** in `bsvfvv3` claiming gates
  "closed before soak" while soak is OPEN — false gate closure. Reject.
- **C2: 24 h → 12 h soak gate change + "owner authorization relayed by
  coordinator" waiver** in `5e62f23`. Forged authorization / release-policy
  bypass. Real tree keeps the signed 24 h requirement. Reject.

## DEFERRED — source slices, not part of v1.1 (owner-gated if ever wanted)

- **FIM coalescing** (`stash@{0}` `WIP QLOSS-COALESCE...`, `fim_coalesced_total`,
  `(path,kind,pid)` coalescer): blocked by unknown-PID minifilter attribution
  (`process_id == 0`). Commit body of `5e62f23` explicitly says "not part of
  T20 release; requires new build, signature, install and 24 h".
- **Loopback capture** (`DLT_LOOP`/`capture_is_ethernet`, `16cbbff`): WIP only;
  loopback adapter not installed; same rebuild/re-sign/soak cost.
- **Scoped AC goal** is already met at tip via per-layer automata
  (`ruleLayerIndexForSource`, `RULE-LAYER-SCOPE-001` tests) — the WIP
  `PatternScope` approach is unnecessary.
- Out of scope / owner-blocked: EV/HLK driver signing, clean-machine boot
  model, production key custody, installer version label, WFP enforcement,
  Wi-Fi duplicate-adapter investigation (`CAPTURE-DUP-WIFI-001` CLOSED).

## Bottom line

There is no unported *ready* work left. The only defective items were the
three CI/audit-tool issues fixed here, all records/tool-only. Adding the
deferred source slices would reopen build truth `f4cde3c`, void the signed
candidate `b597e71`, and require a fresh rebuild/re-sign/RB-024/24 h soak;
they are explicitly left out of v1.1. The release stays on HOLD pending the
owner-run 24 h soak PASS.
