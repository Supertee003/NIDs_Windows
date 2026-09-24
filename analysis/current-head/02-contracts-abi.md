# AEGIS Windows-native NIDS/IPS — Contract, ABI และ Wire Review

**Review ID:** `02-contracts-abi`  
**Scope:** `shared/`, `contracts/`, `src/contract/`, `src/policy/policy_ir.zig`, `src/policy/pep_bindings.zig`, Go Nose canonical/wire path, Rust PEP FFI types, TypeScript policy serialization, fixtures, and contract tests.  
**Repository:** `/mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows`  
**Observed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review mode:** Read-only. No source file, generated truth, fixture, or build artifact was modified by this review.

## 1. Executive conclusion

AEGIS มี contract material จำนวนมากและมี unit tests ที่ตรวจ layout บางส่วนได้ดี แต่ยังมี **contract split ที่ทำให้ไม่สามารถประกาศ production-ready ได้**. ความเสี่ยงสูงสุดไม่ได้อยู่ที่การขาดไฟล์หรือ DLL แต่อยู่ที่ active path ใช้คนละ framing และคนละ event/policy semantics กับ contract ที่เอกสารและ fixtures อ้างว่าเป็น frozen truth.

ข้อสรุปที่หยุดการรับรอง production มีดังนี้:

1. **Active Nose pipe ไม่ได้ใช้ 125-byte `WEV1` frame**. Go `nose/pipe_writer.go` ส่ง `u32 length=109` ตามด้วย payload 109 bytes รวม **113 bytes**. Zig `src/capture/nose_pipe_reader.zig` อ่านรูปแบบเดียวกัน. ในขณะเดียวกัน `src/contract/wire_event.zig` และ `shared/protocol/wire_v1.md` นิยาม header 16 bytes + payload 109 bytes รวม **125 bytes** พร้อม CRC32. ดังนั้น 125-byte wire contract เป็น support/alternate path ไม่ใช่ framing ของ active Nose ingress.
2. **Struct-size marker ไม่ตรงกับ fixtures**. Zig `CanonicalEvent.struct_size` มาจาก `@sizeOf(CanonicalEvent)` และ golden bytes ใน source ใช้ `128` (`0x80`). Go ใช้ `DefaultDevStructSize = 128`. แต่ `tests/contracts/event_vectors/event_vectors/*.bin` และ metadata ระบุ `struct_size=109`. Zig `validate()` ต้องการค่า 128 และจะ reject fixture ที่มีค่า 109; Go golden-vector reader ก็ต้องการ 128. นี่เป็น contradiction โดยตรงระหว่าง source implementation กับ fixture contract.
3. **มี event model อย่างน้อยสองชุดที่มี magic/version/size/enum ต่างกัน**. `src/contract/canonical_event.zig::CanonicalEvent` คือ 109-byte wire payload; `src/contract/event.zig::IpcEvent` คือ internal 96-byte event ที่มี magic `0xAE615011`, version 5; `src/forensic/abi_contract.zig` ประกาศสำเนา ABI อีกชุด. การแปลง 109 → 96 มีการตัดข้อมูลและการ map severity/event kind แต่ไม่มี canonical loss contract หรือ end-to-end proof.
4. **Active Nose reader ส่งเข้า `src/pipeline/event_queue.zig` แต่ active dispatcher อ่าน `event_fabric`**. `nose_pipe_reader.zig:296-304` เรียก `pipeline_queue.pushCanonicalEvent(&event)`. `dispatcher.zig:617` เรียก `fabric.popEvent()`. จาก source ที่ตรวจ ไม่พบ production consumer ของ `event_queue.popEvent()`. ดังนั้นเส้นทาง Go Nose → decode อาจจบที่ internal queue และไม่ถึง detection/policy/PEP ตาม call graph ที่ประกาศไว้.
5. **TypeScript policy action ordinals ไม่ตรงกับ `src/policy/policy_ir.zig`**. TypeScript/Zig `policy_plane` ใช้ `BLOCK=2`, `RATE_LIMIT=4`, `LOG_ONLY=5`. แต่ `src/policy/policy_ir.zig::Action` ใช้ `alert=2`, `rate_limit=3`, `block=4`, `quarantine=5`, `escalate=6`. `pep_bindings.zig` ส่งค่า `policy_ir.Action` ตรงไป Rust. ถ้า artifact จาก TypeScript ถูกอ่านด้วย `policy_ir.Policy`, ค่า `BLOCK=2` จะถูกตีความเป็น `alert`.
6. **EnforcementReceipt เป็น contract ที่ถูกทดสอบแยก แต่ไม่ได้เป็นผลลัพธ์ของ active PEP path**. Active dispatcher บันทึก `rust_pep.EnforcementResult`; Rust FFI คืน `PepResponse` ที่มี decision/reason/quota/signed_by เท่านั้น. ไม่มี `filter_id`, `host_effect_confirmed`, trace/audit linkage หรือ provider postcondition จาก Rust ไปสู่ receipt. `signed_by` ใน Rust ปัจจุบันถูกตั้งเป็นศูนย์. `BLOCK` หรือ adapter success จึงยังไม่ใช่หลักฐาน host effect.
7. **มี ABI lifetime/ownership gaps และ unchecked enum conversion**. `Policy`, `Clause`, `Predicate` และ string slices ใน `policy_ir.zig` ถูก shallow-copy และไม่มี ownership boundary ที่ชัดเจน. `pep_bindings.zig:104` ใช้ `@enumFromInt(resp.decision)` โดยไม่ reject ordinal ที่ไม่รู้จัก. Rust raw-pointer FFI ตรวจเพียง null pointer และไม่มี ABI version/struct-size field.
8. **Negative vectors ยังไม่ครอบคลุม contract ที่อันตรายที่สุด**. มี tests สำหรับ magic/version/CRC ใน helper wire codec และ enum บางส่วนใน Zig แต่ยังขาด cross-language rejection vectors สำหรับ struct-size disagreement, 113-vs-125 framing, unknown PEP decision, policy ordinal drift, replay/freshness, missing filter ID, false host-effect confirmation, ownership expiry, duplicate producer identity และ malformed length exhaustion.

สถานะโดยรวมคือ **safe degraded/observe-only candidate เท่านั้น; ไม่ใช่ Production IPS**. การมี `aegis_pep.dll`, import library, source test หรือ UI state ไม่พิสูจน์ว่า WFP host effect และ receipt contract ทำงานจริงบน Windows.

## 2. Scope และวิธีตรวจ

ตรวจจาก source, build graph, tests, fixtures และ working-tree state โดยให้ implementation มี priority เหนือ handoff/README. ตรวจ definition, serialization, validation, authority, identity, status/error mapping, offsets, sizes, versions, framing, ownership/lifetime และ evidence linkage.

คำสั่งพื้นฐานที่ตรวจได้ใน sandbox:

```text
git rev-parse HEAD
# 46b93dcf9cca17b323ddff7a4c71e33e81c37fb5

git status --short --untracked-files=no
# repository มี modified files จำนวนมาก รวม build.zig, Nose, canonical_event.zig,
# nose_pipe_reader.zig, policy_contract.zig, rust-src/lib.rs และ runtime files
```

Sandbox นี้ไม่มี `zig`, `go`, `rustc` หรือ `cargo` จึงไม่สามารถยืนยัน compile/link/runtime ของ Windows path ได้. `python3 shared/wire/wire_codec.py` ผ่าน self-test ของ **support codec** และยืนยัน 125-byte helper frame เท่านั้น ไม่ใช่ proof ของ active named-pipe path. `pytest` ไม่พร้อมใช้งาน. TypeScript test invocation ถูก block ด้วย `node_modules` ที่มี Windows `@esbuild/win32-x64` อยู่ใน Linux sandbox; จึงรายงานเป็น **UNVERIFIED** ไม่ตีความเป็น source pass/fail.

ขอบเขตนี้ไม่รวมการแก้ source. ข้อเสนอด้านล่างเป็น remediation plan เท่านั้น.

## 3. Path classification และ active call graph

### 3.1 Active production path ที่ source แสดง

```text
Npcap / Go Nose capture
  -> nose/capture.go:eventFromPacket()
  -> nose/canonical.go:CanonicalEvent.Serialize()       [109-byte payload]
  -> nose/pipe_writer.go:FrameWriter.Send()
       -> u32 little-endian length 109 + raw payload    [113-byte pipe frame]
  -> \\.\pipe\aegis_nose
  -> src/capture/nose_pipe_reader.zig:readClientLoop()
       -> read 4-byte length
       -> require frameLen == 109
       -> canonical.deserializeFromBytes()
       -> src/pipeline/event_queue.zig:pushCanonicalEvent()
            -> convert CanonicalEvent to IpcEvent            [96-byte internal model]
            -> push event_queue
```

จุดสิ้นสุดที่ source ตรวจได้คือ `event_queue`. ขณะที่ active dispatcher มีเส้นทางแยก:

```text
src/policy/dispatcher.zig:drainQueueTimed()
  -> src/contract/event_fabric.zig:popEvent()
  -> processEvent()
       -> flow -> detection -> verdict -> correlation
       -> threat intel -> RAG -> brain -> policy
       -> rust_pep integration -> forensics
```

ไม่พบ call จาก `event_queue.popEvent()` ไปยัง `event_fabric`, และ `nose_pipe_reader.zig` ไม่เรียก `nose_contract.submitEvent()` แม้ comment บรรทัด 10 ระบุว่าควรทำเช่นนั้น. นี่ทำให้ call graph ที่ประกาศใน comments ไม่ตรงกับ call graph ที่ compile/runtime source แสดง.

### 3.2 Support, tooling และ legacy paths

| Class | Paths | Finding |
|---|---|---|
| Active ingress | `nose/capture.go`, `nose/canonical.go`, `nose/pipe_writer.go`, `src/capture/nose_pipe_reader.zig` | ใช้ raw 109-byte payload และ 4-byte length prefix; ไม่มี WEV1 header/CRC |
| Active orchestration | `src/policy/dispatcher.zig`, `src/contract/event_fabric.zig`, `src/core/rust_pep.zig` | ใช้ CanonicalEvent ใน dispatcher แต่ PEP result ไม่ใช่ receipt |
| Active FFI boundary | `src/policy/pep_bindings.zig`, `rust-src/lib.rs` | Zig/Rust layouts ตั้งใจให้ตรง แต่ไม่มี runtime cross-ABI proof และไม่มี receipt ABI |
| Internal/support model | `src/contract/event.zig`, `src/pipeline/event_queue.zig` | IpcEvent 96 bytes, magic/version คนละชุด; อยู่บน active Nose conversion แต่ไม่ถูก drain โดย dispatcher ที่ตรวจพบ |
| Alternate wire helper | `src/contract/wire_event.zig`, `shared/wire/wire_codec.py`, `shared/wire/wire_codec.h`, `shared/protocol/wire_v1.md` | นิยาม WEV1 header 16 + payload 109 + CRC = 125; ไม่ใช่ active Nose frame |
| ABI/test registry | `src/forensic/abi_contract.zig`, `contracts/fixtures/`, `tests/contracts/` | duplicate declarations และ golden vectors ที่ขัดกับ source struct-size semantics |
| Policy authoring/tooling | `ts_policy/src/*`, `ts_policy/tests/*`, `src/policy/policy_plane.zig` | authoring/IR support path; byte-level serialization ยังไม่ตรงกับ Zig signing digest |
| Parallel policy path | `src/policy/policy_ir.zig`, `src/policy/policy_contract.zig` | action/status vocabularies ต่างกัน; `policy_contract` ถูกระบุเป็น replacement/legacy ใน `src/core/legacy_removal.zig` แต่ยังถูก test graph import |
| Generated truth | `inventory.json`, `reference_map.json`, `runtime_manifest.json`, build outputs | working tree มี modified generated/config files; ห้ามใช้ file presence เป็น ownership proof |

## 4. CanonicalEvent, wire offsets และ size semantics

### 4.1 Canonical 109-byte payload

`src/contract/canonical_event.zig:30-75` เป็น `extern struct` ที่มี fields ตาม wire schema. Explicit serializer ที่บรรทัด 341-390 เขียน 109 bytes ตาม offsets นี้:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `magic = 0x41454731` (`AEG1`) |
| 4 | 2 | `version = 1` |
| 6 | 2 | `struct_size` |
| 8 | 8 | `event_id` |
| 16 | 8 | `timestamp_ms` |
| 24 | 8 | `monotonic_ns` |
| 32 | 1 | `source` |
| 33 | 4 | `source_ip` |
| 37 | 2 | `source_port` |
| 39 | 4 | `dest_ip` |
| 43 | 2 | `dest_port` |
| 45 | 8 | `session_id` |
| 53 | 1 | `protocol` |
| 54 | 1 | `direction` |
| 55 | 1 | `layer_id` |
| 56 | 1 | `is_pipe` |
| 57 | 4 | `event_type` |
| 61 | 1 | `severity` |
| 62 | 4 | `rule_id` |
| 66 | 8 | `ruleset_version` |
| 74 | 4 | `payload_length` |
| 78 | 8 | `payload_hash` |
| 86 | 1 | `policy_action` |
| 87 | 1 | `enforcement_status` |
| 88 | 1 | `defcon_impact` |
| 89 | 4 | `context_flags` |
| 93 | 16 | `reserved` |

The G2 reserved map uses `reserved[0..4]` for PID, `[4..8]` for PPID, `[8]` process type, `[9]` integrity, `[10]` HIDS flag, `[11..15]` node ID, and `[15]` confidence. The node ID field and confidence byte overlap at the final reserved byte by design comments; this needs an explicit non-overlap contract because `node_id` is four bytes at offsets 11-14 and confidence is offset 15. That part is internally consistent, but the source comments should not imply `[11..15]` includes offset 15 for node ID.

### 4.2 The 109 / 113 / 125 / 128 distinction

The repository currently has four materially different sizes:

| Value | Meaning | Source evidence | Status |
|---:|---|---|---|
| 96 | `IpcEvent` in-memory/internal model | `src/contract/event.zig:10-12,96-125` | Separate internal model |
| 109 | Canonical payload | `canonical_event.zig:335-390`; Go `EventWireSize=109` | Active payload and fixture size |
| 113 | Active Nose pipe frame | `pipe_writer.go:135-143`; reader `nose_pipe_reader.zig:235-266` | Active production framing |
| 125 | WEV1 helper frame | `wire_event.zig:6-14,87-110`; `wire_v1.md:57-95` | Alternate/support wire contract |
| 128 | In-memory `@sizeOf(CanonicalEvent)` marker on current ABI | `canonical_event.zig:17,303`; embedded golden byte `0x80 0x00`; Go `DefaultDevStructSize` | Current source marker, not wire payload size |

The 109 versus 125 wording is not inherently wrong if 109 means payload and 125 means WEV1 frame. The defect is that the **active production pipe uses 113**, while comments and support tests often call the 125-byte WEV1 object the wire frame. The active reader never parses WEV1 magic `0x57455631`, payload type, or CRC32.

### 4.3 Struct-size contradiction

`canonical_event.zig:17` defines `EVENT_SCHEMA_SIZE = @sizeOf(CanonicalEvent)`. `create()` stores that value at line 303. `validate()` at lines 273-279 rejects any event whose marker is not exactly `EVENT_SCHEMA_SIZE`. The source golden vector at lines 801-815 carries `0x80 0x00`, i.e. 128.

The independent fixtures under `tests/contracts/event_vectors/event_vectors/` are 109 bytes and their metadata says `struct_size=109`. The fixture README also says each `.bin` is exactly 109 bytes. This makes the following vectors unusable as valid inputs for the current Zig validator, even though they are described as canonical v1 vectors. `src/forensic/abi_contract.zig:211-253` independently embeds a 109-byte vector but sets its struct-size field to 128, confirming that the repository contains two interpretations of the marker.

The documentation statement in `shared/protocol/wire_v1.md:138-143` says receivers may skip unknown trailing fields when `struct_size > expected`. Current `validate()` does not implement that forward-compatible behavior; it requires equality. Either the marker must mean wire payload size and always be 109, or it must mean in-memory ABI size and be 128, or a new explicit `wire_size` field/contract must separate the two. The current hybrid is unsafe.

### 4.4 Legacy raw serializer

`canonical_event.zig:459-469` retains `serialize()` and `deserialize()` that use `@ptrCast`/`@alignCast` over the in-memory struct. The explicit 109-byte serializer avoids this, but the legacy functions remain publicly callable and return/use `@sizeOf(CanonicalEvent)`. This creates a second serialization behavior with a different size and compiler-padding dependency. It must be classified as legacy and prohibited from production call sites, or removed after all callers migrate.

## 5. Event model duplication and conversion loss

### 5.1 CanonicalEvent versus IpcEvent

`src/contract/event.zig:10-12` defines `EVENT_MAGIC=0xAE615011`, `EVENT_VERSION=5`, `EVENT_SIZE=96`. `IpcEvent` at lines 96-120 has kind, severity, source, fate, flags, timestamp, event/trace/flow/incident/detection IDs, network identity, rule/policy IDs, and 32-bit payload hash.

`src/pipeline/event_queue.zig:54-103` converts the 109-byte CanonicalEvent into IpcEvent. It maps:

- `event_type` to a smaller `EventKind` vocabulary;
- canonical severity `0..3` to internal `info/warning/critical/alert`;
- canonical `payload_hash:u64` to `IpcEvent.payload_hash:u32` by truncation;
- canonical `context_flags` to `IpcEvent.flags`;
- canonical payload reference to `payload_len`.

The conversion does not preserve `session_id`, `ruleset_version`, `policy_action`, `enforcement_status`, `defcon_impact`, process/node identity, confidence, or full payload hash. `pushCanonicalEvent()` passes an empty payload at lines 62-64. The companion `pushCanonicalEventWithPayload()` exists, but the active Nose reader calls the payload-less function. The source comments acknowledge at lines 58-60 that the wire carries only a payload reference, but no evidence contract tells the detector/operator that payload bytes are unavailable on this path.

The internal model also has `trace_id`, `flow_id`, `incident_id`, and `detection_id`, while CanonicalEvent has only `session_id` and no trace/audit fields. There is no authoritative mapping document for which identity is minted at which boundary.

### 5.2 Identity ownership

Go Nose starts a process-local sequence with `atomic.AddUint64(&eventSequence, 1)` in `nose/capture.go:187`. Zig `canonical_event.zig:286-291` has a separate process-local counter. `src/core/nids_capture.zig:18-19,289-294` has another acquisition counter. `nose_pipe_reader.zig:228-233` explicitly resets monotonicity comparison per connection because a restarted Nose sequence can restart at one. This prevents a false warning but does not provide global uniqueness.

A restart can therefore reuse an `event_id`. `session_id` is present in the canonical layout but is not populated by the normal Go capture constructor. A durable producer identity must include at least producer/node identity, runtime generation or producer epoch, and local sequence, or sequence allocation must move to one Zig ingress authority. Duplicate, collision, non-monotonic, and retry/idempotency failures should be distinct states and counters.

### 5.3 Active queue disconnection

The reader comment says it submits into `nose_contract` and the Event Fabric. The implementation imports `pipeline_queue` and invokes `pipeline_queue.pushCanonicalEvent`. The dispatcher imports `event_fabric` and consumes `fabric.popEvent`; repository search found no production call to `event_queue.popEvent()`. This is a **P0 active-path defect** independent of the 109/125 framing issue. A passing reader test only proves bytes can be decoded and placed into a queue; it does not prove the event reaches detection, policy, PEP, or forensics.

## 6. Policy IR and TypeScript serialization

### 6.1 Three policy vocabularies

There are at least three policy implementations:

| Path | Action ordinals |
|---|---|
| `src/policy/policy_ir.zig::Action` | `pass=0, log=1, alert=2, rate_limit=3, block=4, quarantine=5, escalate=6` |
| `src/policy/policy_plane.zig::PolicyActionDef` | `allow=0, alert=1, block=2, quarantine=3, rate_limit=4, log_only=5` |
| TypeScript `ts_policy/src/types.ts::PolicyAction` | `ALLOW=0, ALERT=1, BLOCK=2, QUARANTINE=3, RATE_LIMIT=4, LOG_ONLY=5` |

`src/policy/policy_contract.zig::PolicyDecision` follows the second vocabulary. `src/contract/canonical_event.zig::PolicyAction` also follows `allow=0, alert=1, block=2, quarantine=3, rate_limit=4, log_only=5`.

`src/policy/pep_bindings.zig:86-96` sends `@intFromEnum(p.action)` from `policy_ir.Action` directly into `PepRequest.requested_action`. Rust constants at `rust-src/lib.rs:196-203` match the `policy_ir.Action` values, not TypeScript/canonical values. This can be internally consistent only if TypeScript IR is never fed into this binding. The repository comments and TypeScript tests claim the TypeScript IR is the cross-language artifact, so the boundary is unsafe until one vocabulary is frozen and independently validated.

The `mapAction()` function at `pep_bindings.zig:118-126` maps `policy_ir.Action` to `PepDecision`, but `PepEnforcer.enforce()` does not call it. This makes the mapping test misleading: it passes while the active function uses a raw ordinal.

### 6.2 Policy IR shape and hash drift

`src/policy/policy_plane.zig:168-180` defines a fixed `[256]PolicyRuleDef` array with pointer-bearing `[]const u8` fields. TypeScript `PolicyIR` in `ts_policy/src/types.ts:295-308` uses a variable `readonly PolicyRuleDef[]`. That is a useful authoring shape but not a binary ABI.

`src/policy/policy_plane.zig:267-287` hashes `std.mem.asBytes(&rule)`. That includes pointer-bearing slices and is not a stable cross-process representation. TypeScript `compiler.ts:268-305` instead builds a delimiter-separated textual stream, and `seal.ts:43-65` builds a different newline-separated whole-IR stream. The TypeScript test explicitly states at `cross_language_contract.test.ts:7-12` that byte-level reconciliation is deferred. Therefore the current tests prove shape and local determinism, not a shared serialization contract.

The following semantics also diverge:

- Zig `policy_plane` compiler errors are `none=0, no_rules=1, duplicate_id=2, invalid_condition=3, too_many_rules=4` (`policy_plane.zig:195-210`). TypeScript `CompileError` is `NONE=0, NO_RULES=1, TOO_MANY_RULES=2, DUPLICATE_ID=3, INVALID_CONDITION=4, INVALID_VALUE=5, INVALID_PRIORITY=6` (`compiler.ts:51-59`). Numeric error/status consumers cannot safely interchange these values.
- `src/policy/policy_ir.zig:153-161` implements `.in` as equality with one integer. It is not an actual set/range operation.
- The same function treats a string `.eq` as `actual_int == value_int OR string equality`. String fields leave `actual_int=0`; a default `value_int=0` can make a non-matching string pass. String `.ne` has the dual problem. Tests cover `.match`, but not string `.eq`/`.ne` negative cases.
- `PolicySet.add()` at lines 100-102 shallow-copies `Policy` and its slices. `PolicySet.deinit()` frees some nested allocations, but there is no declared rule that callers must transfer ownership, clone inputs, or keep borrowed slices alive. `EvalContext` also carries borrowed strings. This is an ABI/lifetime gap.
- `ttl_sec` is stored in `policy_ir.Policy` but evaluation does not enforce expiry. TypeScript scope and expiry are folded into `description` by `compiler.ts:448-468`; that is audit text, not a typed enforcement field.
- `CompileResult.dropped_rule_indices` is documented as indices but `compiler.ts:361-370` pushes rule IDs. This is a status/contract naming defect.
- TypeScript stores SHA-256-derived u64 values in JavaScript `number` (`types.ts:301-306`, `compiler.ts:387-389`, `seal.ts:105-106`). Values above `2^53-1` lose precision. A cross-language u64 field must use `bigint` internally and an explicit decimal/hex wire representation.
- Delimiter-based canonicalization does not escape delimiters or control characters. Rule names, descriptions, or string values containing `\x1f`, newline, or `|` can create ambiguous canonical streams. No negative vector covers collision-resistant serialization.

### 6.3 TypeScript authority boundary

The TypeScript source correctly contains no direct WFP/PEP call and its tests assert that authoring is not enforcement. That is a valid support/tooling invariant. However, `seal.ts` uses an HMAC key derived from the signer text and documents that it is not Ed25519. This cannot be treated as an authenticity proof for production policy loading. Rust/Zig must receive a canonical, signed, versioned artifact and independently validate magic, version, rule count, action ordinals, expiry, signer/key ID, digest, and rollback state.

## 7. Rust FFI types, ownership, and PEP authority

### 7.1 Layout observations

Zig and Rust both declare `PepContext`, `PepRequest`, and `PepResponse` with `extern struct` / `#[repr(C)]`:

- `PepContext`: expected size 24; fields at offsets 0, 4, 8, 16;
- `PepRequest`: expected size 64; `decision_kind` offset 0, `requested_action` 1, `flow_id` 8, network fields at 16–32, severity 32, context 40;
- `PepResponse`: expected size 16; decision 0, reason 4, quota 8, signed_by 12.

Zig tests in `pep_bindings.zig:164-213` assert these expected values. They do not compile a Rust-side `size_of`/offset manifest and compare it at build time, nor do they call the actual Windows DLL with known bytes. Sandbox has no Zig/Rust toolchain, and Windows DLL loading is **UNVERIFIED**.

There is no explicit ABI version, struct-size field, reserved expansion space, endianness declaration, or ownership/lifetime contract in `PepRequest`/`PepResponse`. Raw pointers are used for the synchronous call. The current implementation assumes the callee writes the complete response when return code is zero.

### 7.2 Active PEP semantics are not receipt semantics

`rust-src/lib.rs:340-426` exposes `aegis_pep_enforce`. It checks null pointers, capability for mutating actions, and on Windows calls a dynamically loaded WFP adapter. The adapter's block ABI is only `fn(u32) -> i32` (`lib.rs:211-220,271-278`). It returns a Boolean success/no-success and no filter identifier, provider version, postcondition observation, or cleanup identity.

On success Rust writes `decision=DECISION_BLOCK`, but it writes `signed_by=0` and returns no receipt. `PepResponse` cannot carry:

```text
request_id, event_id, policy_id/version/digest, trace_id, audit_id,
provider identity, filter_id, host_effect_confirmed, cleanup/rollback result
```

Therefore `DECISION_BLOCK` or a successful adapter call is not equivalent to `EnforcementReceipt.isSuccess()` and must not be rendered as confirmed host block.

The following concrete gaps remain:

- `pep_bindings.zig:104` converts an untrusted response ordinal with `@enumFromInt` without a range check. A malformed or ABI-corrupted response can produce an invalid enum/trap.
- `PepContext.policy_version` defaults to zero and `PepEnforcer.enforce()` does not populate it from policy metadata.
- Request contains no `event_id`, `trace_id`, policy digest, signature/key ID, expiry, or producer generation. Replay/freshness cannot be proven at the PEP boundary.
- `aegis_pep_unblock_ip` ignores `caller_pid` and `request_id` (`lib.rs:430-450`), so unlinkable/stale cleanup requests are accepted based mainly on capability.
- `PepState.quotas` is read by `aegis_pep_quota_remaining`, but the enforcement path shown does not decrement/update the source entry. The advertised quota semantics are not proven by the implementation.
- Windows adapter load failure after `open()` returns nonzero does not free the loaded module (`lib.rs:265-267`), creating a resource-lifetime leak on repeated initialization attempts.
- `PepEnforcer` stores only `available: bool`; DLL generation, handle ownership, shutdown state, and concurrent init/deinit are not represented. The module-level gate in `rust_pep.zig:311-323` is lazily initialized and never deinitialized in the shown path.

### 7.3 Zig-side simulation and authority confusion

`src/core/rust_pep.zig` calls itself a Rust PEP wrapper but maintains an in-memory `AutoHashMap` blocklist at lines 101-119 and 189-230. The comments correctly say this is not the real WFP effect, but its `EnforcementResult.status=.executed` is used in dispatcher logging (`dispatcher.zig:534-585`). That path can therefore produce an `EXECUTED` semantic result without the receipt/postcondition contract.

`src/policy/policy_contract.zig:217-266` is a separate PEP implementation. For `.allow` and `.log_only` it sets `event.enforcement_status=1` and returns `.skipped`; for `.alert` it returns `.success` and sets status `enforced`; for a block with no source IP it also returns `.success` and marks `enforced` because there is no IP to block. These values are not host-effect proof. `src/core/legacy_removal.zig` identifies `policy_contract.zig` as replaceable by `policy_engine.zig`, but it remains in the test graph, so its status semantics can still be mistaken for active authority.

The invariant to preserve is:

```text
DetectionResult -> policy decision -> Rust PEP authorization
-> WFP provider effect -> observed host postcondition -> EnforcementReceipt
```

No detection, TypeScript, Go Nose, Zig policy helper, or in-memory simulation may claim the last two stages.

## 8. EnforcementReceipt, forensic linkage, and health semantics

### 8.1 Receipt definition is incomplete as a success gate

`src/policy/enforcement_receipt.zig:4-27` defines statuses `pending`, `enforced`, `failed`, `unavailable`, `rolled_back`, and `simulated`; fields include request/event/policy IDs, provider, filter ID, host-effect Boolean, reason, trace/audit IDs, and version.

`isSuccess()` at lines 29-31 checks only `status == enforced and host_effect_confirmed`. `validate()` at lines 39-43 checks version and nonzero request/event IDs and prevents contradictory status/Boolean combinations. It does **not** require:

- nonempty/known provider;
- nonzero `filter_id` when status is enforced;
- nonzero `trace_id` and `audit_id` for success;
- policy revision/digest/signature;
- request freshness or runtime generation;
- provider response identity and postcondition evidence;
- cleanup/rollback state.

`isForensicallyLinkable()` adds trace and audit requirements, but `isSuccess()` does not call it. A receipt can therefore be considered successful while not forensically linkable. The tests at lines 51-93 prove only local predicate behavior; they do not prove that active PEP output is converted into this type.

### 8.2 No active receipt construction found

Repository search found the receipt type in its own tests and forensic append tests, but no active construction from `PepResponse` or `rust_pep.EnforcementResult` that fills provider, filter ID, host postcondition, trace, audit, and version. `dispatcher.zig:534-585` stores `rust_pep.EnforcementResult`, then `processForensics()` sends that result to the integration logger at lines 587-598. This is an enforcement-result path, not an authenticated receipt path.

The contract test in `src/forensic/forensic_pipeline.zig` correctly rejects an invalid receipt, but it is a consumer-side test. It cannot compensate for the missing producer-side construction and host-effect observation.

### 8.3 Status vocabulary collision

The repository uses several status sets with overlapping English meanings:

| Layer | Values | Risk |
|---|---|---|
| Canonical byte | pending/enforced/failed/rolled_back | raw numeric field; no unavailable/simulated |
| Receipt | pending/enforced/failed/unavailable/rolled_back/simulated | should be evidence-bearing |
| Zig RustPep | no_op/executed/rejected/deferred/failed | authorization/result, not host effect |
| Policy-contract result | success/failed/not_implemented/skipped | legacy/support result |
| Rust FFI decision | allow/block/rate_limit/quarantine/escalate/drop | decision, not status |
| Operator states in handoff | observed/alerted/requested/denied/unavailable/failed/confirmed/rolled_back | presentation state |

There is no one versioned mapping table or exhaustive conversion test. A log string such as `EXECUTED` can be accidentally displayed as `BLOCKED_CONFIRMED` unless the UI consumes only a validated receipt.

## 9. Framing, validation, and negative-input defects

### 9.1 Active frame parser lacks CRC and bounded malformed handling

The active reader accepts a 4-byte length and requires exactly 109. It does not parse the 16-byte WEV1 header and does not verify CRC32. On an invalid length (`nose_pipe_reader.zig:250-263`) it attempts to read and discard the declared number of bytes. A malicious or broken client can send a very large length and keep the blocking drain loop occupied. The code should immediately reject lengths outside a bounded range and close/reset the connection; it should never discard an untrusted 32-bit length without a maximum.

The support `wire_event.deserializeEvent()` verifies header magic/version/type/length/CRC, but its presence does not protect the active raw pipe. `isValidFrame()` only checks magic and version and `getFrameSize()` does not enforce `WIRE_MAX_PAYLOAD`, so even the helper API has a weaker validation predicate than its full event decoder.

### 9.2 Canonical validation is partial

Zig explicit deserialization now validates source, event type, policy action, and confidence before enum conversion (`canonical_event.zig:397-407`). It still does not constrain severity, direction, layer, `is_pipe`, enforcement status, DEFCON range, payload-length policy, or reserved bytes. Go `CanonicalEvent.Deserialize()` at `nose/canonical.go:241-276` accepts a fixed array without validating magic/version/struct-size/enums; validation is only present in the separate `golden_path_ffi.go` reader.

The canonical `deserialize()` legacy pointer path remains alignment/padding-dependent. The current test set should ensure every public decoder applies the same validation policy and returns typed errors, not just null.

### 9.3 Fixture validity is ambiguous

The fixture directory contains five 109-byte payloads. The edge vector `event_v1_005.bin` deliberately carries confidence `255`, while current Go and Zig serializers/decoders reject confidence above 100. That can be a valid negative vector only if metadata explicitly declares `expected_accept=false`; current metadata describes it as an edge case without a rejection contract. `event_v1_004.bin` uses `event_id=0` and `defcon_impact=0`, but the validators do not consistently define whether those are legal.

The source golden vector uses struct-size 128 while external fixture metadata uses 109. These are not interchangeable positive vectors. A fixture manifest must carry `valid`, expected error class, exact framing, and the implementation versions that consume it.

## 10. Concrete defects and severity

Severity uses `P0` for a stop-the-line contract/authority defect, `P1` for a release-blocking correctness/security defect, and `P2` for a hardening or maintainability defect.

| ID | Severity | Defect | Evidence | Impact |
|---|---|---|---|---|
| ABI-01 | **P0** | Active Nose path is 113-byte raw frame, while WEV1 support contract is 125 bytes; no single framing authority | `nose/pipe_writer.go:113-154`; `nose_pipe_reader.zig:235-275`; `wire_event.zig:6-14,87-143` | Cross-language clients can be accepted by one path and rejected by another; CRC/header assumptions are false on active ingress |
| ABI-02 | **P0** | `struct_size` is 128 in current Zig/Go source but 109 in external fixtures | `canonical_event.zig:17,303,273-279`; `nose/canonical.go:188,199-202`; fixture metadata | Canonical fixture replay and cross-language validation fail or mean different things |
| ABI-03 | **P0** | Active Nose reader queues into `event_queue`, while dispatcher consumes `event_fabric` | `nose_pipe_reader.zig:21-23,296-304`; `dispatcher.zig:24,617-630` | Observed events may never reach detection/policy/PEP/forensics; end-to-end claim is unproven |
| ABI-04 | **P0** | TypeScript/canonical action ordinals differ from `policy_ir.Action` and Rust PEP interpretation | `policy_ir.zig:18-26`; `policy_plane.zig:111-129`; `types.ts:87-94`; `lib.rs:196-203` | `BLOCK` can be interpreted as `ALERT`; privileged action semantics can silently drift |
| ABI-05 | **P0** | PEP response is not an `EnforcementReceipt`; no filter ID or host postcondition is returned | `pep_bindings.zig:46-58,79-105`; `rust-src/lib.rs:178-184,404-426` | `DECISION_BLOCK`/adapter success cannot support a confirmed host-block claim |
| ABI-06 | **P1** | Receipt success predicate does not require filter/provider/trace/audit linkage | `enforcement_receipt.zig:29-43` | A semantically successful but unauditable/identity-less receipt can pass local validation |
| ABI-07 | **P1** | PEP response decision ordinal is converted without range validation | `pep_bindings.zig:98-105` | ABI corruption or malicious DLL response can trap or create invalid authority state |
| ABI-08 | **P1** | Event identity is process-local and reset across Nose/runtime restarts; connection reset only hides regression | `nose/capture.go:187`; `canonical_event.zig:286-291`; `nose_pipe_reader.zig:228-233` | Duplicate identity, replay ambiguity, and non-idempotent side effects across generations |
| ABI-09 | **P1** | Policy hash/signature serialization differs across TypeScript and Zig; TS test explicitly defers byte reconciliation | `compiler.ts:268-305,376-403`; `policy_plane.zig:267-287`; `seal.ts:43-65` | Same logical policy can have different digest/signature; loader authority cannot be deterministic |
| ABI-10 | **P1** | `policy_ir` string equality and `in` semantics are incorrect/underspecified | `policy_ir.zig:134-161` | Rules can match unrelated strings or fail to implement set semantics |
| ABI-11 | **P1** | Active canonical-to-Ipc conversion drops payload and multiple identity/evidence fields | `event_queue.zig:54-103` | Detection and forensic consumers see a lossy event while operators may assume canonical evidence was retained |
| ABI-12 | **P1** | Malformed active frame length is discarded without an upper bound | `nose_pipe_reader.zig:250-263` | Named-pipe reader can be held in a long/blocking discard loop; DoS and recovery risk |
| ABI-13 | **P1** | Multiple result/status vocabularies have no exhaustive mapping contract | `canonical_event.zig:65-68`; `enforcement_receipt.zig:4-11`; `rust_pep.zig:31-45`; `policy_contract.zig:197-202`; `lib.rs:186-203` | `EXECUTED`, `SUCCESS`, and `ENFORCED` can be incorrectly treated as the same fact |
| ABI-14 | **P1** | FFI request lacks policy version/digest, event/trace/audit identity, freshness and replay fields | `pep_bindings.zig:33-44`; `rust-src/lib.rs:164-176` | Rust cannot authenticate the exact policy/event request or reject replay at the boundary |
| ABI-15 | **P2** | TypeScript u64 hash/signature fields use JavaScript `number` | `types.ts:301-306`; `compiler.ts:387-389`; `seal.ts:105-106` | Values above `2^53-1` can round before signing or verification |
| ABI-16 | **P2** | Legacy raw `@ptrCast` serializer remains publicly callable beside explicit serializer | `canonical_event.zig:459-469` | A caller can silently produce a compiler-layout-dependent 128-byte object instead of the 109-byte payload |
| ABI-17 | **P2** | Fixture validity and expected rejection are not declared | `tests/contracts/event_vectors/event_vectors/golden_vectors.json`; `event_v1_005.bin` | CI can treat an intentionally invalid edge case as a positive vector or vice versa |

## 11. Missing tests and proofs

The existing tests are useful local checks, but they do not establish one cross-language production contract. The following proofs are missing or currently **UNVERIFIED**:

### Contract and fixture proofs

1. A single generated manifest must state the authoritative framing (`raw-109 + u32 length` or `WEV1-125`) and must be consumed by Go, Zig, Rust, C/C++, Python, and TypeScript tests. The manifest must contain exact offsets, endianness, enum ordinals, allowed ranges, and whether each vector is positive or negative.
2. A positive vector must be accepted identically by Go, Zig, Python, Rust, and C/C++. A 109-byte payload with `struct_size=109` and one with `struct_size=128` must have explicit expected outcomes; neither may be left to implementation inference.
3. A full active-pipe vector must prove the 4-byte length prefix, partial writes, partial reads, reconnect, EOF, malformed length, oversized length, truncated payload, and connection reset behavior. It must also show whether CRC is required.
4. A conversion vector must prove every CanonicalEvent-to-IpcEvent mapping and enumerate every intentionally dropped field. If payload bytes are absent, the downstream event must carry an explicit `payload_unavailable` condition rather than silently looking complete.

### Identity, policy, and status proofs

1. Cross-restart identity tests must prove uniqueness and idempotency with two Nose generations, two runtime generations, reconnect retries, duplicate frames, and sequence reset to one.
2. A policy action vector must feed the same artifact through TypeScript compilation, Zig loading, `policy_ir`, Rust PEP, and canonical event mapping. It must assert that `BLOCK` remains `BLOCK`, `RATE_LIMIT` remains `RATE_LIMIT`, and `LOG_ONLY` remains `LOG_ONLY`.
3. Canonical digest tests must compare bytes, not only object shape. The vector must contain names and descriptions with delimiters, Unicode, newline, NUL, and maximum lengths. It must exercise `u64` values above `2^53-1`.
4. Policy evaluation negatives must cover string `eq` and `ne`, `.in` as a real set/range operation, disabled rules, empty conditions, TTL expiry, scope expiry, duplicate IDs, unknown fields/operators, and error ordinal mappings.
5. Status mapping tests must prove that `DetectionResult`, `PolicyDecision`, PEP decision, provider response, `EnforcementResult`, `EnforcementReceipt`, and operator state are distinct and mapped exhaustively. There must be no path from `executed`, `success`, `accepted`, or `block` to `BLOCKED_CONFIRMED` without a validated receipt.

### FFI and receipt proofs

1. The build must generate a Rust `size_of`/offset manifest and compare it with Zig `@sizeOf`/`@offsetOf` at CI time for every ABI struct and enum. The comparison must run against the same target architecture as the release DLL.
2. The FFI must be tested with null pointers, short/partial responses, unknown decision ordinals, nonzero return codes, stale request IDs, replayed request IDs, policy-version mismatch, and concurrent init/shutdown.
3. A Windows host test must show that `aegis_pep_enforce` returns a provider identity and filter ID, observes the actual WFP postcondition, constructs a receipt, appends it to forensics, and removes the filter using the same request/receipt linkage.
4. Receipt tests must reject `enforced` with zero filter ID, empty provider, zero trace/audit IDs, unsupported version, stale generation, mismatched event/request/policy IDs, and `host_effect_confirmed=true` for any non-enforced status.
5. Cleanup tests must prove that a failed cleanup is not reported as `ROLLED_BACK`, that stale filters do not survive restart, and that a second identical request is idempotent or explicitly rejected.

## 12. Prioritized fixes

### P0 — stop the line before any production IPS claim

1. **Choose one event transport contract.** The smallest-change option is to formally name the current active path `NoseRawEventFrameV1`: `u32_le payload_length=109` followed by the 109-byte canonical payload. If WEV1/CRC is required, change both Go and Zig active paths together. Do not keep 113-byte active framing and 125-byte documentation both labelled “the wire frame.”
2. **Resolve `struct_size`.** Prefer separate constants such as `WIRE_PAYLOAD_SIZE=109` and `ABI_MEMORY_SIZE=128`, then define whether `struct_size` carries wire size, ABI size, or a versioned schema length. Regenerate all fixtures from that decision and make `validate()` implement the documented forward-compatibility rule, or remove that rule from documentation.
3. **Connect active ingress to the active fabric.** Either have `nose_pipe_reader.zig` call the canonical `nose_contract.submitEvent()`/`event_fabric` ingress or add a proven consumer that drains `event_queue` into the dispatcher. Add a runtime counter that increments at ingress, fabric, detection, policy, PEP, and forensics for the same event identity.
4. **Freeze one policy action vocabulary.** Remove raw ordinal reuse across `policy_ir`, `policy_plane`, canonical event, TypeScript, and Rust. Use one generated enum map and reject unknown ordinals at every boundary. Make the active `PepEnforcer.enforce()` call the explicit mapping function or eliminate the unused mapping function.
5. **Make Rust PEP return an authoritative receipt or a typed non-success.** Extend the ABI with request/event/policy/trace identity, provider identity, filter ID, receipt version, and postcondition state. Until the provider can supply those fields, return `unavailable` or `failed`; never expose `executed`/`block` as confirmed host effect.

### P1 — release-blocking hardening

1. Replace process-local event IDs with a producer identity plus epoch/generation and sequence. Define duplicate/replay/idempotency behavior at the ingress boundary.
2. Put a strict maximum on active frame length before any discard, close malformed connections, and use bounded/cancellable reads for shutdown.
3. Remove or quarantine the raw `@ptrCast` serializer. Make all public decoders return the same typed validation errors and apply the same range checks.
4. Define ownership for policy slices. Either deep-copy into an owned IR, use arena lifetime tied to the policy generation, or make all fields borrowed with an explicit owner object and atomic reload lifetime.
5. Replace pointer-bearing `std.mem.asBytes` policy hashing with one canonical byte encoder shared by TypeScript, Zig, Rust, and Python. Use fixed-width unsigned representations and `bigint`/byte arrays for u64 values.
6. Make `EnforcementReceipt.isSuccess()` require the complete production success invariant, including provider, nonzero filter ID, trace/audit linkage, supported version, and validated host postcondition.
7. Add an explicit event-loss record for payload truncation or absent payload. Preserve full payload hash and all identity fields needed for forensics.

### P2 — cleanup and maintainability

1. Mark `src/contract/event.zig`, `src/policy/policy_contract.zig`, `src/core/rust_pep.zig` simulation types, `wire_event.zig`, and raw serializers as active, support, or legacy in a machine-readable manifest. Remove claims that a module is canonical unless the build graph proves it.
2. Rename TypeScript `dropped_rule_indices` to `dropped_rule_ids` or change the implementation to return indices.
3. Add structured error codes instead of null-only decoder failures and align Zig/Go/Rust/Python error classes.
4. Close Rust adapter module handles on every failed initialization path and make PEP init/deinit ownership explicit.
5. Regenerate inventory, reference map, runtime manifest, and fixture hashes only through project generators after the contract decision is merged.

## 13. Exact Windows-only verification commands

The following commands are intentionally exact and should be run in an elevated Windows PowerShell from a clean checkout at the reviewed commit. Results are **UNVERIFIED in this sandbox**. A timeout, missing DLL, missing Npcap, missing provider, or missing named pipe is a failed proof, not readiness.

### 13.1 Toolchain, commit, and clean-state verification

```powershell
Set-Location -Path 'D:\NIDs_Windows'

git rev-parse HEAD
git status --short
git diff --check

zig version
go version
rustc --version
cargo --version
python --version
node --version
npm --version
```

Expected commit for this review is `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`. Any source or generated-truth diff must be recorded before interpreting subsequent results.

### 13.2 Cross-language contract tests

```powershell
Set-Location -Path 'D:\NIDs_Windows'

cargo test --manifest-path rust-src\Cargo.toml
zig build test
go test ./nose

Set-Location .\ts_policy
npm ci
npm test
Set-Location ..

python -m unittest discover -s tests\contracts -p 'test*.py' -v
python -m unittest tests.runtime.test_wire -v
```

The CI acceptance must additionally compare generated byte fixtures across languages. A passing local Python codec self-test is not sufficient because it exercises the support 125-byte codec, not the active 113-byte Nose frame.

### 13.3 Fixture and framing probes

```powershell
Set-Location -Path 'D:\NIDs_Windows'

python .\tests\contracts\event_vectors\generate_test_vectors.py
Get-ChildItem .\tests\contracts\event_vectors\event_vectors\*.bin |
  Select-Object Name,Length

python .\shared\wire\wire_codec.py

# Build the active binaries before the pipe probe.
zig build
go build -o .\dist\aegis-nose.exe .\nose

# Active raw Nose frame must be exactly 4 + 109 = 113 bytes.
# Capture stdout/stderr and inspect the first-frame log.
.\dist\aegis-nose.exe --headless --inject-observe --inject-count 1 2> .\logs\nose-contract.stderr
Select-String -Path .\logs\nose-contract.stderr -Pattern 'first canonical frame sent: 113 bytes'
```

If the selected contract is changed to WEV1, replace the assertion with a 125-byte frame and require `WEV1`, payload type, payload length, and CRC32 checks at the active reader. Do not accept both silently.

### 13.4 Runtime ingress-to-forensics proof

```powershell
Set-Location -Path 'D:\NIDs_Windows'

zig build run -- --headless 2> .\logs\core-contract.stderr
```

In a second elevated PowerShell:

```powershell
Set-Location -Path 'D:\NIDs_Windows'

Get-Item '\\.\pipe\aegis_nose'
Get-Process aegis_nids,aegis-nose -ErrorAction SilentlyContinue |
  Select-Object Id,ProcessName,StartTime

python .\tools\aegisctl.py health --json > .\logs\health-before.json
python .\tools\aegisctl.py events tail --count 1 --json > .\logs\events-before.json

# Use the project-supported observe-only injection command.
python .\tools\aegisctl.py nose inject-observe --count 1

Start-Sleep -Seconds 2
python .\tools\aegisctl.py health --json > .\logs\health-after.json
python .\tools\aegisctl.py events tail --count 20 --json > .\logs\events-after.json
Select-String -Path .\logs\core-contract.stderr -Pattern 'NOSE PIPE|event_id|FORENSICS|POLICY|RUST-PEP'
```

Acceptance requires one event ID to be visible at reader acceptance, fabric/dispatcher input, detection or benign processing, policy result, PEP result, and forensic record. If the event appears only in Nose or `event_queue` counters, the active call graph is not proven.

### 13.5 FFI layout and DLL verification

```powershell
Set-Location -Path 'D:\NIDs_Windows'

cargo build --release --manifest-path rust-src\Cargo.toml
Get-Item .\target\release\aegis_pep.dll
Get-Item .\target\release\aegis_pep.dll.lib

dumpbin /headers .\target\release\aegis_pep.dll
dumpbin /exports .\target\release\aegis_pep.dll |
  Select-String 'aegis_pep_(init|shutdown|enforce|unblock_ip|quota_remaining)'

zig build test -Dtarget=x86_64-windows
```

The release evidence must include a generated size/offset table for `PepContext`, `PepRequest`, `PepResponse`, all decision ordinals, and the receipt ABI. DLL existence or export presence alone is not a successful FFI proof.

### 13.6 PEP unavailable and fail-closed proof

```powershell
Set-Location -Path 'D:\NIDs_Windows'

Rename-Item .\target\release\aegis_pep.dll aegis_pep.dll.disabled
try {
  .\zig-out\bin\aegis_nids.exe --contract-pep-negative-test
  if ($LASTEXITCODE -eq 0) { throw 'negative PEP test unexpectedly succeeded' }
} finally {
  Rename-Item .\target\release\aegis_pep.dll.disabled aegis_pep.dll
}
```

Expected result: block requests become `ENFORCEMENT_UNAVAILABLE`/`FAILED`, no WFP filter is created, no receipt claims enforced host effect, and the process remains operational in degraded mode.

### 13.7 WFP provider and receipt proof — isolated VMware lab only

Run only after exact target, cleanup command, and isolated VMnet1 topology are confirmed. Do not use Wi-Fi, NAT, the host gateway, localhost, or a production address.

```powershell
Set-Location -Path 'D:\NIDs_Windows'

Get-NetIPAddress -AddressFamily IPv4 |
  Sort-Object InterfaceAlias,IPAddress |
  Format-Table InterfaceAlias,IPAddress,PrefixLength
Get-Service | Where-Object { $_.Name -match 'Aegis|Wfp' } |
  Select-Object Name,Status,StartType
Get-NetFirewallRule -DisplayName '*Aegis*' -ErrorAction SilentlyContinue

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_host_production_preflight.ps1 `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

After observe-only reachability is recorded, execute the project-authorized host-effect proof with the exact disposable target parameters supplied by the lab owner. The evidence must record:

```text
health before -> request ID -> PEP authorization -> provider response
-> nonzero filter ID -> receipt validation -> target blocked
-> forensic linkage -> cleanup receipt -> target reachable
-> no stale filter -> runtime restart/recovery
```

No command that merely prints `block`, `executed`, or `accepted` is sufficient. This proof remains **UNVERIFIED** until run on the elevated Windows host with the isolated VMware topology.

## 14. Final release gate

The contract gate remains closed until all P0 defects are resolved and the following evidence exists at one commit:

1. One canonical event framing and one struct-size interpretation are generated into every language fixture.
2. One active Nose event is proven from named pipe through the same fabric consumed by dispatcher, then through policy, Rust PEP, and forensics.
3. TypeScript policy bytes, Zig policy bytes, Rust verification, action ordinals, and error/status codes match.
4. Rust PEP is the only privileged authority, and every host-effect claim is a validated `EnforcementReceipt` with provider/filter/postcondition and forensic linkage.
5. Negative vectors prove fail-closed behavior for malformed frames, unavailable PEP/WFP, unknown ordinals, stale/replayed requests, invalid receipts, cleanup failures, and restart identity collisions.
6. Windows elevated and VMware-only checks pass, including real reversible WFP effect and cleanup. Source tests, DLL presence, generated manifests, and UI labels cannot substitute for that proof.

**Production decision:** Do not declare Production-ready. The defensible current product state is **observe-only / alert-only with enforcement gate closed** until the above contract, active-path, receipt, and host-effect evidence is complete.

## References

[1]: https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page "Windows Filtering Platform documentation"
[2]: https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilea "CreateFile documentation"
[3]: https://docs.vmware.com/ "VMware documentation"
