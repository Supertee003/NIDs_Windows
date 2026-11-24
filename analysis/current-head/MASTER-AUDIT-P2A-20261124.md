# Master Audit — Phase 2a (Protocol docs / machine map, records-only)

**Target HEAD:** `9016ce52c59623a936c922c1e7c47279e0323527`
**Build source after this patch:** `d2f129e305c2c237ac46ee0fa0d009266e869c7f` (the commit itself)

**Correction to the initial patch classification:** this slice was labelled "records-only, build source unchanged" when it was authored. That label was wrong: `tools/truth.py:44-64` lists `shared` under `SOURCE_PATHS`, so any change under `shared/protocol/**` advances the build source under ADR-0008. The docs are non-executable, but the stamp is a mechanical consequence of the path set. The correction is recorded here rather than silently rewording history; no wire, rule, authority or runtime behavior changes.
**Date:** 2026-11-24
**Patch ID:** `P2A-PROTOCOL-DOCS-20261124`
**Classification:** "ตรวจพบ" = confirmed against current source; all nine items were confirmed read-only in the P2 audit and are closed here.

---

## 1. Scope and invariant

This patch closes carry-forward items **A1–A9** recorded in `analysis/current-head/MASTER-AUDIT-P2-20261124.md` §6a. It changes only documentation and the machine-readable contract map. No code, wire bytes, golden vectors, rules, authority, host effect, release tag, signature or key changes. Because `shared/protocol/**` is inside `SOURCE_PATHS`, the build source advances from `9105ff5` to this commit `d2f129e`; the evidence entry and machine maps are stamped accordingly.

Source truth used for every replacement:

- `src/forensic/integration_contract.zig:19-25` — active Nose pipe is a **4-byte LE length prefix + raw canonical frame**: v1 **113**, v2 **137**, v3 **169..1193** on the wire. The 16-byte WEV1 / 125-byte form is a legacy forensic container.
- `nose/pipe_writer.go:163-171` — writer emits exactly that prefix + wire frame.
- `src/control/protocol.zig` / `src/control/handler_registry.zig` — `CONTROL_PROTOCOL_VERSION = 2` is the active daemon protocol; v1 binary `control_ipc.zig` has zero production importers.
- `src/control/handler_registry.zig:2197-2208` — active v2 block/quarantine handlers refuse host effects (detection-only).
- `src/contract/canonical_event.zig:595-655` — exact length per declared version (v1 109, v2 133, v3 `165 + payload_len`), fail-closed on unknown version/length.

---

## 2. Findings and replacements

### A1 — `shared/protocol/wire_v1.md` presented legacy 125-byte framing as the single source of truth · ตรวจพบ

- **Current:** `:5-7` "single source of truth ... All languages (Zig, C++, Rust, Go, Python) MUST produce byte-identical output"; `:11` "A wire frame consists of a 16-byte header"; `:23` "Total canonical event frame = 125 bytes"; `:138` describes `wire_event.bin` as the wire-format frame.
- **Reason:** the live pipe is prefix + raw frame (113/137/169..1193), not the legacy WEV1 container. Rust has no canonical codec and Python is not production-wired, so "all languages" is a false production guarantee.
- **Replacement:** banner marking the document as the frozen v1 canonical-event encoding, not the active pipe spec; section retitled "LEGACY WEV1 ONLY" with the 4-byte-prefix paragraph; 125 bytes labelled legacy while naming 113 as the active v1 pipe frame; test-vector line labelled legacy. Language claim narrowed to implemented codecs with Rust TBD / Python non-production.
- **Acceptance:** no unqualified "125 bytes = wire frame" or "all languages MUST" remains in the file; `/path` link check passes.

### A2 — `shared/protocol/protocol.md` had the same stale framing plus wrong reserved semantics and a dead path · ตรวจพบ

- **Current:** `:7-8` "All cross-language communication uses this wire protocol / Every language ... byte-identical"; `:10,21` 125-byte active claim; `:69` "reserved (zero-filled)"; Zig row at `:78` pointed at `core/wire_event.zig`.
- **Reason:** reserved bytes are G2-frozen process/parent/event/integrity/HIDS/node/confidence data (`wire_v1.md:87-95`), not zero fill and not a v2 expansion area; `core/` is a dead tree; active framing is the length-prefix form.
- **Replacement:** top HISTORICAL banner naming the active framing and current-truth files; "LEGACY WEV1 (125 bytes total)" heading; reserved row expanded to the frozen fields; Zig row pointed at `src/contract/wire_event.zig`; byte-identical claim limited to implemented codecs.
- **Acceptance:** `rg 'core/wire_event\.zig|zero-filled|All cross-language communication'` returns nothing in this file; `tests/docs/test_stale_doc_sweep.py` passes.

### A3 — `shared/protocol/wire_v1.h` header looked like a live wire frame contract · ตรวจพบ

- **Current:** `:4-6` "C header defining the cross-language wire protocol. ALL languages ... MUST produce byte-identical output"; `:15` "Wire frame layout (125 bytes total)".
- **Reason:** same WEV1-vs-active confusion and same false all-language claim.
- **Replacement:** header marked LEGACY WEV1 frozen history, active framing named with the three on-wire sizes, codec status stated; layout comment labelled "not the active pipe frame".
- **Acceptance:** no unqualified production wire claim in the header; no source/build change (header is documentation here).

### A4 — `CONTRACT_MAP.json` called 125/149 bytes the active schema · ตรวจพบ

- **Current:** `WIRE_PROTOCOL.schema` = "Binary frame: 16-byte header + 109-byte payload = 125 bytes"; `WIRE_PROTOCOL_V2.schema` = "16-byte header + 133-byte payload = 149 bytes ...".
- **Reason:** those are nominal WEV1 totals; active on-wire frames are 113 and 137 bytes. A machine map used by documentation tests must distinguish nominal legacy from live framing.
- **Replacement:** both strings now say "LEGACY WEV1 nominal" and add the ACTIVE Nose pipe totals (113/137/169..1193; v2 137).
- **Acceptance:** `json.load` succeeds; `tests/docs/test_stale_doc_sweep.py::test_contract_map_knows_wire_v2` passes; both totals distinguished.

### A5 — `CONTRACT_MAP.json` named the dead v1 IPC file as implementation and replay as consumed · ตรวจพบ

- **Current:** `CONTRACT-04.implementation` = `src/policy/control_ipc.zig`, `version` = `1.0`, `frozen` = `true`, `authorization.freshness` = "now_ms within ...", `authorization.replay` = "(request_id, nonce) pair consumed once".
- **Reason:** active implementation is JSON control v2; v1 has zero production importers. Declared-but-unenforced freshness/replay must not be recorded as enforced — this is the same disclosure already correct in `INTERVIEW_PREP.md:17`.
- **Replacement:** implementation points to `src/control/protocol.zig` + `handler_registry.zig` with v1 explicitly unlinked; version `2.0 active; v1 frozen history`; `frozen: false` with `historical_section` note; freshness/replay rewritten as "DECLARED in frozen v1 only; NOT enforced / NOT consumed on active v2 — no active nonce/replay protection".
- **Acceptance:** no string claims active replay consumption; `tests/security/test_t16_security_hardening.py` (9 passed) still passes because those assertions concern the frozen v1 reference source, not the active map claim.

### A6 — `shared/protocol/versioning.md` compatibility rules contradicted fail-closed decoding · ตรวจพบ

- **Current:** `:24-27` "receivers can skip unknown trailing fields if struct_size > expected"; `:31-36` "Add to reserved[] (use reserved bytes first)".
- **Reason:** issue #41 fix made exact length per declared version mandatory; trailing bytes and unknown versions are rejected. Reserved bytes are frozen G2 identity, not an expansion pool.
- **Replacement:** added HISTORICAL (superseded) callouts before both sections stating the live rule (v1 109, v2 133, v3 `165 + payload_len`, fail-closed) and citing `src/contract/canonical_event.zig:595-655`. The old text is retained only as history, not removed silently.
- **Acceptance:** both historical markers present; no live guidance tells a decoder to skip trailing fields.

### A7 — "all five languages byte-identical production codecs" overclaim in three docs · ตรวจพบ

- **Current:** the "All languages ... MUST produce byte-identical output" statements in `wire_v1.md:5-7`, `protocol.md:7-8,97`, `wire_v1.h:5-6`.
- **Reason:** actual codec status is Zig authoritative + Go Nose producer; C/C++ and reference Python are test/reference; Rust canonical codec is TBD; Python brain codec is not production-wired.
- **Replacement:** every site now names implemented codecs and states the Rust/Python limitations explicitly.
- **Acceptance:** no unqualified five-language production claim remains in the three files.

### A8 — `CONTRACT_MAP.json` language list contradicted its own producer note · ตรวจพบ

- **Current:** `CONTRACT-01.languages` = `["Zig","C","Rust","Go","Python"]` while `:13` of the same entry says Rust does not implement this wire schema and Python Brain returns a separate JSON advisory event.
- **Reason:** a machine map must not list a non-existent Rust codec as if it existed.
- **Replacement:** list = `["Zig","Go","C","C++","Python"]` plus a `language_codec_status` string recording the precise status of each.
- **Acceptance:** map JSON valid; status string present; no Rust entry in that array.

### A9 — `control_protocol.md` v1 FROZEN header sat above the active v2 section without a top-level warning · ตรวจพบ

- **Current:** header `Version: 1.0 / Status: FROZEN` with no pointer to the "Version 2 (ACTIVE — ...)" section near the end; Purpose ends with "Privileged actions flow through Rust PEP (never direct to WFP)."
- **Reason:** a reader stopping at the header would treat v1 command/envelope semantics, including nonce/replay, as the live protocol; the host-effect sentence is v1 posture, not active v2 behavior.
- **Replacement:** top banner stating v1 is history, v2 is active, freshness/nonce replay declared but not enforced; host-effect sentence annotated as v1 historical posture with active v2 detection-only pointer.
- **Acceptance:** reader sees the ACTIVE marker before any v1 detail; no active enforcement claim introduced.

---

## 3. Flow / contract impact

```
OLD  protocol docs + CONTRACT_MAP  -> 125/149 bytes look active, v1 IPC looks live, replay looks enforced
NEW  protocol docs + CONTRACT_MAP  -> legacy nominal labelled LEGACY, active prefix framing named, control v2 active, replay declared-only
```

- **Wire/ABI:** none. Golden vectors, codec source and on-wire bytes are untouched.
- **Authority:** none. The correction removes an overclaim of enforcement; it does not add any host effect.
- **State:** none.
- **Tests:** `tests/docs` + `tests/contracts` 92 passed; `tests/security/test_t16_security_hardening.py` 9 passed. Full release gates re-run after commit.
- **Evidence:** E1 (static inspection + existing test suites); no new build, no E4/E5, no Windows run. Rebuilding the machine maps and refreshing digests is a records-only follow-up and does not advance the build source again.

---

## 4. Completion gate

**PASS (E1).** Build source = `d2f129e` (docs under `shared/`). Machine maps restamped and digests refreshed in follow-up records commits; final verification must show `TRUTH_VALID @ d2f129e`, 674/674 digests and no bad links. carry-forward P2b (B1–B6 helper/codec test gaps) and issue #44 follow-ups were open at recorded source `d2f129e`; both were closed by later slices, with issue #44 re-proved at current source `a26c573` in `analysis/current-head/MASTER-AUDIT-P8-I44-CURRENT-SOURCE-20261125.md`.
