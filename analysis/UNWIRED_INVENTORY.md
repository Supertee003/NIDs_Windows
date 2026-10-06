# AEGIS Unwired-Module Inventory (living checklist)

**HEAD:** `aba9727` · **Updated:** 2026-10-04
**Rule:** every module is either ON the daemon path, TEST-ONLY (harness with
no production importer), QUARANTINED (naming/doc hazard, must stay
unlinked), or CONNECT-PLANNED (tracked slice). Anything else is a finding.

## ON PATH (golden — do not duplicate)
- `src/daemon.zig`, `src/main.zig`, `src/pipeline/*`, `src/capture/*`
  (flow_table, nose_pipe_reader, pipe_monitor), `src/detection/*`
  (signature_engine, anomaly_detector, correlator ← T1-CORR-010,
  threat_tracker, rag_engine[advisor]), `src/contract/*`,
  `src/policy/{pep_bindings,tier3_state,action_dispatcher,policy_ir,
  enforcement_receipt}`, `src/forensic/forensic_pipeline.zig`,
  `src/control/*`, `src/platform/*`, `src/windows/{etw_realtime,fim,
  registry_monitor,cpp_adapter}`, `src/reliability/{watchdog,
  security_check,fault_injection}`, `src/core/{diagnostics,memory_pool,
  bridge_init,rust_pep,runtime_paths,integration_test(main harness only)}`
- `rust-src/lib.rs` (PEP), `nose/{main,capture,canonical,pipe_writer,
  signature_classifier}`, `brain/windows_brain.py` (advisory),
  `tools/aegisctl*` (control plane), dashboards (readers)

## TEST-ONLY (harness, never wire into daemon)
- `src/federation/*` (7 files: codec, tcp, tls, cluster, registry,
  aggregator, bench) + `src/tests/cli/federation_*.zig`
- `src/xdr/*` (engine, correlator, graph, fabric, harden)
- `src/tests/cli/*` (17 demo harnesses), `src/tests/proofs/*`,
  `src/tests/integration/*`, `src/core/{integration_test (harness),
  perf_benchmark}`
- `src/forensic/{replay_engine,replay_verifier,replay_integrity,
  replayable_security,decision_trace(advisory),siem_forwarder(library)}`
- `src/policy/{dispatcher,dispatcher_phase_b}` + `src/reliability/
  lifecycle.zig` — quarantined orchestrators (headers + NEG pin)
- `src/windows/{host_telemetry_mock,host_telemetry_scenarios,
  windows_adapters,hids_process_monitor}`, `src/core/{brain_engine,
  real_ips_path,nids_analyze,nids_capture,nids_main(windows_capture)}`
- `src/detection/{detection_engine,ml_detector,verdict_aggregator,
  threat_intel,rag_intelligence,proto_anomaly(partial)}`
- `mouth/` (standalone TUI), `go/aggregator/` (SUPPORT sidecar),
  `aegis_dashboard/` (reader), `ts_policy/` (advisory compiler)

## QUARANTINED (must stay unlinked — pins enforce)
- `shield/src/{pep,windows_enforce}.rs` naming (screening only)
- `drivers/wfp_callout/quarantined/aegis_wfp_comm.c` (duplicate BlockFlow)
- `aegis_bridge block_ip/unblock_ip` externs (removed from Zig contracts)
- `scripts/{aegis_block,aegis_unblock}.py` (refuse mutations)
- `configs/aegis.conf [ips]` (no reader; must stay disabled)
- `installer.nsi` fossil, `tools/legacy/*`, `release/T20-final/*`
- TCP control transport (removed), web 0.0.0.0 bind (loopback only)
- `AEGIS_FAIL_OPEN` (removed), `mouth/enforced.json` (renamed)

## CONNECT-PLANNED (needs a design slice, NOT ad-hoc wiring)
- [x] TS-IR exporter → `policy_ir.json` (T3-TSIR-025: exporter fixture +
  Zig verify-only loader + daemon mirror + metrics; hash recompute +
  seal contract = T7 follow-up)
- [x] Brain→daemon return contract (B2-BRAIN-024 daemon UDP offer +
  T2-BRAIN-023 sensor-pipe return; both opt-in, loop closed)
- [x] SIEM pipeline wiring (T1-SIEM-020/020b/021/022/021b: spill, honest
  transports, auto-replay, daemon env wiring, metrics)
- [x] Gate-E canary runner (CLI `canary run/status/report` verifies
  definitions vs Rules.json + live engine count; read-only). Investigated
  2026-10: the 2 drifts were NOT severity typos — both payloads miss their
  named rules by match_pattern AND regex (rfi_basic vs R0088 traversal,
  data_exfil vs R9059 XSS), so neither could ever fire. Quarantined with
  reasons (reported, never graded).
  Real RFI rule LANDED as R0089 (RFI-RULE-071: Injection/L7/Critical/
  Block, `?file=http://` + scheme-required regex, FNV 4237725842;
  canary unquarantined with a payload that truly matches). DNS-exfil
  stays quarantined: length heuristics cannot be expressed in the
  substring-only tiers — needs a length-capability design slice.
- [x] `forensics.replay` handler ← replay_verifier (wired: integrity-only
  observe replay T1-REPLAY-021 — export ring + re-verify CRC/hash chain;
  pipeline re-execution deliberately NOT performed, events_replayed stays 0,
  pass stays false. A deterministic re-execution harness would be a second
  enforcement path, so this is the safe terminal state, not a gap.)
- [x] FED-XDR verdict: PROCEED if feasible (owner 2026-10-06) — feasible
  phased per docs/adr/0007-federation-cluster-wiring.md (mature codec/
  coord/TCP vs mock-TLS x2 + no discovery transport). FED-P1A landed:
  G17 federation.zig labeled specimen (REL-SPEC-050 pattern),
  NodeRegistry collision resolved (discovery table is now
  DiscoveryRegistry; coordination keeps cluster_coord.NodeRegistry).
  FED-P1B landed: frozen fed_v1_*.bin golden vectors (generator +
  Python reference codec + Zig decode pins, both directions agree).
  FED-P2A landed: Rust federation_tls is real crypto (PEM roots/chain
  fail closed, mTLS honored, 8 loopback proofs incl. untrusted/wrong-CN/
  missing-client rejection; rcgen dev-dep for test PKI only) — still
  unwired (no FFI, no caller). FED-P2B1 landed: narrow outbound-only C
  ABI (connect/send/recv/close, opaque handles, fail-closed codes) with
  in-crate FFI round-trip + misuse proofs; still no Zig caller. FED-P2B2
  landed: one-stack cutover — Zig mock TLS + CLI deleted, Transport
  delegates via aegis_fed_* FFI, T13/T16/config/manifest pins retargeted,
  revocation gap open to P4. FED-P3A landed: static discovery
  (canonical cluster.json v1, u32 ids per verdict, fail-closed atomic
  loader + proofs incl. example-drift pin; live file gitignored).
  FED-P3B landed: optional display `name` labels in cluster.json v1
  (numeric id stays the authority — wire + Go canonical already u32,
  no other tier processes node IDs; overlong names fail closed).
  FED-P4 landed: daemon wiring — AEGIS_CLUSTER=1 enables the uplink
  (static peers from cluster.json, TLS material from env PEM paths
  fail-closed, outbound-only publish of detection reports, no listener,
  no policy authority). federation.status reports live state. Pin
  flipped: cluster_uplink is the only federation module the daemon may
  import.
- [ ] policy_signing onto enforcement path + trust_store CNG + two-person API.
  POL-SIGN-078 landed the verify half: policy_signing tests wired into
  `zig build test` (were never compiled), mock trust_store labeled
  (canonical policy store is policy_signing), Rust aegis_policy_verify
  FFI proven (roundtrip + misuse codes) but unwired. POL-SIGN-079A
  landed the Rust-authority path: verifyViaRust (ring via FFI, agrees
  with native) + sidecar v1 envelope + strict loader, still unwired
  (no daemon caller). POL-SIGN-079B landed the observe-only daemon end:
  sidecar + AEGIS_POLICY_PUBKEY verified at startup into
  metrics.policy_ir.verified (RB-011 step 8); enforcement untouched.
  TS-SIGN-080 landed the author half: ed25519.ts (operator key in,
  never stored; stdlib only) + 5 tests incl. committed golden triple
  that Zig verifies too (76/76). CUSTODY-081 landed the anchor file:
  configs/policy_trust.json (gitignored live, example tracks shape),
  strict loader (unique non-zero ids, no zero keys), rotation by
  side-by-side key_ids, file-wins-over-env with loud broken-file
  failure. TRUST-WIRE-082 landed the opt-in enforcement end:
  AEGIS_POLICY_ENFORCE_TRUSTED=1 + policies.sig.json over exact
  policies.json bytes + anchors marks PolicySet trusted (RB-011 step
  10); default absent = byte-identical behavior. CEREMONY-083 landed
  the operator tool: aegis-keygen (genkey/sign/verify, offline-only,
  no new deps, 3 proofs) so custody is executable, not just
  documented. FED-LSTN-085 landed the listener half: loopback-only
  listen/accept/port/close FFI + Zig server delegate (fail-closed
  paths proven; full-duplex loopback proven in Rust, which caught and
  fixed a real table-lock deadlock in send/recv); nothing in the
  daemon listens. TEST-SCOPE-085 wired every runnable unit test into
  `zig build test` (~290 newly executing, incl. the 4th silent-death
  catch on federation_rust_tls) with a registry pin for deliberate
  outs (integration/proofs/specimen/quarantine). ROADMAP-086
  decisions: (1) custody = two humans (Key Officer + Witness, RB-011
  §11 ceremony record, CNG-backed) with staged flip + rollback
  criteria — mechanism complete, appointments pending; (2) N=100/60s
  locked fail-safe pending lab exit criteria (benign baseline →
  attack validation → matrix; no-guess tuning is repo law, now
  checkable via `.github/PULL_REQUEST_TEMPLATE.md` (dataset +
  before/after + FP/FN + safety floor + rollback statement required
  on every tuning PR));
  (3) single-host freeze at P4 — no listener wiring, no new ports;
  (4) every tuning ships dataset + before/after + matrix. Still
  open: the human appointments, the lab itself, multi-host scope.
- [x] IPv6 full (contract v2) — wire v2 decode-ready T2-V6-022a (Go/Zig/
  C++/Python dispatch + 006 vector + bit2 preserved) + nose live emit
  T2-V6-022b (`eventFromPacket` sidecars, `Send` dispatches v2).
  REMAINING: detection/flow/forensic plumbing of full addresses
  (u32 identity + bit2 guard unchanged)
- [x] duplicate `dispatcher` confusion — RESOLVED without deletion:
  T14/T12/T10 pins migrated to production files (`event_processor`,
  `action_dispatcher`); both dispatcher files RESTORED as quarantined
  Universe-B wiring reference (additive-first rule — the subsystems they
  orchestrate still exist and may integrate one day; prod imports remain
  pinned by forbidden-edges). Deletion commit `4eac987` remains in history
  as the audit trail.
- [x] Go aggregator loopback bind (GO-LOOPBACK-031: `apiAddr` pins
  `127.0.0.1:port`, bare `:port` never constructed; matches the documented
  `127.0.0.1:9200` contract and every in-tree client).
- [x] Mouth version drift — RESOLVED with evidence (not a guess): Cargo
  3.0.0 + file header v3.0 + v3.0 redesign notes agree; only the two print
  sites said 1.0.0. Bumped both to 3.0.0, verified `aegis-mouth 3.0.0`
  from a real rustc build, pinned against Cargo. (Side note: rustc to
  %Temp% is blocked on this host — build to dist/ instead.)
- [ ] flow `is_ipv6` plumbing (normalize hardcodes false)

## COUPLING MAP (deep investigation 2026-10-04 — read before refactoring)

- Zig hubs (272 files): `contract/canonical_event.zig` 52 importers,
  `contract/event.zig` 27, `core/diagnostics.zig` 23. The spine is real;
  touch these only with cross-module evidence.
- Legacy fan-in: `core/rust_pep.zig` (shim, NOT the authority) is
  imported 15× across policy/forensic/windows/xdr/dispatcher; `daemon.zig`
  imports `core/{bridge_init,diagnostics,memory_pool,nids_capture,
  runtime_paths}` directly. Legacy-core never died — quarantine is by
  convention + NEG pins, not by graph.
- Test→tree writes (15 files): lab reruns restamp
  `analysis/PHASE8_*`, evidence-graph/pagination/policy-signing tests
  rewrite fixtures. Tests are NOT hermetic; a green run can dirty the
  tree and invalidate truth/release gates — verify `git status` after
  every matrix run and revert producer-owned stamps.
- Import-time effects (pinned): `brain/windows_brain.py` import runs
  sys.path edits + warning prints (banner/UDP/loop correctly gated
  behind `__main__`). Pin: `tests/brain/test_import_hygiene.py`.
- Full-suite teardown AV (RESOLVED 2026-10-04): combined `tests/` run
  segfaulted nondeterministically at/after teardown while all 546+ tests
  passed (summaries printed). cdb native stack: AV in `Py_Dealloc` during
  `Py_RunMain` teardown, pure python314.dll frames, no product DLL;
  reproduced on 3.11 and with/without `.pyd` files (Cython exonerated).
  Root-cause class: lingering pipe-drain threads blocked in readline()
  across interpreter teardown (bisect: every subset green, only the full
  set crashed). Fix: `tests/runtime/conftest.py::pytest_sessionfinish`
  reaps straggler procs and joins drain threads (T-HYG-002). Evidence:
  two consecutive full runs green after the fix (555 passed, exit 0).
  Remaining flake (separate, needs live daemon): pagination volume tests.

## FULL-SYSTEM SCAN (2026-10-04 — dead code, coverage gaps, drift)

- Dead orphans (zero importers, even tests): `policy/{dispatcher_phase_b,
  shadow_decision, control_ipc, wfp_production}`, `federation/federation.zig`
  (dup of cluster_coord), `windows/{hids_process_monitor, cpp_adapter,
  ips_canary_order}`, `xdr/{dr_incident_graph, dr_incident_fabric,
  dr_correlator}`, `forensic/replayable_security`, `reliability/lifecycle`.
  NOTE: `serializeV2` "dead in Zig" is a false positive — its caller is Go.
  Removal is BLOCKED wherever E2 pins read the file (dispatcher precedent);
  orphans without pins are quarantine candidates, not silent deletions.
- Test-graph gaps (in-file tests NEVER execute under `zig build test`):
  `capture/npcap_capture`, `detection/rag_intelligence`, `policy/
  {dispatcher, control_ipc, policy_plane, policy_signing, shadow_decision,
  wfp_production}`, `forensic/replayable_security`, `contract/{event_fabric,
  runtime_spine}`, `windows/{cpp_adapter, hids_engine, hids_process_monitor,
  ips_canary, ips_canary_order, ips_simulation}`, `xdr/{correlator, harden,
  incident_fabric, incident_graph}`, `federation/federation`,
  `reliability/{fault_matrix, lifecycle, release_engineering,
  release_provenance, reliability}`, `platform/{win32_pipe, win32_service}`,
  `pipeline/{packet_callback, telemetry_threads}`; Go: nose TUI/collectors/
  pipe_writer/ipc_reader/inject/main; Python: `golden_path_ffi.py`,
  aegisctl `client/config/utils`. 30/36 control commands lack contract or
  handler pins (see T3-TWOP-023 pattern for how to add them).
- Drift FIXED this pass: Nose `2.1.0` → `5.0.0` (daemon/state_machine/
  version-handler vs `nose/main.go` + version.md); sensor-pipe `_t1`
  suffix in 3 stale comments.
- Drift (resolved items struck through in place so history stays readable):
  `EVENT_VERSION` 5-vs-1 → VER-NS-039 (separate namespaces, pinned disjoint);
  CONTROL_PROTOCOL v2 code vs v1.0 doc → CTL-DOC-040 (active v2 section added,
  v1 frozen intact); `zig-0.13` vs `zig-0.13.0` → VER-BUILD-054 (both stamps
  now 0.13.0, pinned to release record); FIM non-ASCII/long-path →
  FIM-LONGPATH-044; registry re-arm → REG-STUB-045 (prod re-arms, stub
  labeled); ETW session-name UB → ETW-STR-046.
  Still OPEN (needs owner decision, not silent edit): POL1 vs POLI
  (pinned MISMATCH test, intentional).
  (DOC-SYNC-077: mouth version strings struck — resolved by
  MOUTH-VER-057, checkbox at line 93; the entry above was stale.)
  (`struct_size` 128-vs-109 closed T2-V6-022c: generator stamps 128,
  vectors regenerated, strict gates hold; CANARY_MAGIC ×3 closed
  CANARY-MAGIC-055: single value pinned, copies intentional.)

## KNOWN-OPEN robustness (filed, unscheduled — closed items struck with slice IDs)

Resolved since filing: FIM non-ASCII/long-path caps (FIM-LONGPATH-044),
registry re-arm failure silent (REG-STUB-045 + prod re-arms in
pollNative), ETW session-name UB (ETW-STR-046; TLV bounds pre-existing),
nose frameLen stall (NOSE-DISC-042), pipe_monitor prefix-only
(PIPE-SUB-043), brain 4096 truncation/log growth/Rules hot-reload crash
(B2-SCANVIS-048/B2-LOGTH-041/B2-HOTRL-034), siem_config dead transports
(SIEM-CFG-033), watchdog toothless (WD-BEAT-049), `blocked_ips.json`
candidate confusion (BLOCK-LABEL-038), `anomalies_emitted` never
incremented (ANOM-COUNT-035), RAG wildcard overmatch (RAG-BOUND-052),
flow identity dst-only (FLOW-ID-051), metrics u64→u32 truncation
(METR-U64-061), incident cap fail-open (INCIDENT-CAP-063, TTL sweep still
open), `config/Rules.json` mirror drift (single-authority pin held
through the R0089 ripple and MIRROR-SYNC-075 refreshed the mirror
byte-identical), nose log flood (LOG-FLOOD-062; pipeline AUDIT line
intentionally kept — needs observability-UX verdict), `g_ac_mutex`
copy-then-use (retain policy in rule_loader, documented), canary
severity drifts (CANARY-QUAR-056 quarantined; rfi_basic graduated to
R0089 by RFI-RULE-071; data_exfil stays quarantined but the path is now
open: CORR-DNS-080 wired the dns_query classifier + rule 9003
(100/60s initial, synthetic-proven). ROADMAP-086 locks N=100 pending
lab exit criteria (benign baseline → attack validation → evidence
matrix); graduation still needs sensor proof + multi-event canary
support (single-event canaries cannot fire count rules) — owner
verdict in docs/adr/0004-dns-exfiltration-detection.md), mouth
version drift
(MOUTH-VER-057), CANARY_MAGIC ×3 (CANARY-MAGIC-055 pinned), per-call
WFP DLL load (PEP-ADAPTER-CACHE-073: cached bridge handle, re-probe
on failure), legacy whole-struct `serialize` memcpy path
(CODEC-CLEAN-067: deleted; remaining @memcpy are field copies inside
the explicit wire codec), go.sum/Go split (GO-SPLIT-083: both Go
modules complete — nose + aggregator go.mod/go.sum tracked, `go
build` + `go test -count=1` green both; .exes gitignored),
forensic `append catch 0` (FOR-HARD-084: `!u64` was infallible —
ring overwrites, writes are bounds-checked — so the error union is
gone and every `catch 0`/`try` at call sites with it), framed-reader
oversize guard (FOR-HARD-084: length-prefix bound proven by test;
TLS-stub parser it was filed against is deleted).

Investigated, no action (with reason): `security_check` hard-coded pass
claim is wrong (gating/advisory split is real); `getFrameSize` +
`successRate` dead-but-tested utils (harmless); `AEGISCTL_PATH` is read
by brain (stale backlog line); nose_dashboard.exe duality not found in
tree (desktop + web dashboards are intentional); `aegis_graph.py` already
bounds at 1000 with truncated flag; `policy reload` CLI parsers already
gate to _unavailable; `RuleAction` vocab gap closed by AC5 pin;
`beat()` on drop is intentional (controlled action, not stall);
`spill disk-full` accounted (failed++ on spill failure, at-least-once
documented); `successRate` pending-blind accepted (unused helper).

Still OPEN: flow pointer lock-escape (single-threaded today),
correlator/AC per-packet allocator (needs profiling,
not guesses), receipt validator
reconciliation (BE-RCPT-091: policy_signing.verifyEnvelope is the one
canonical routine — daemon startup trust blocks + policy.verify handler
share it; policy.validate does structural dry-run; CLI verify/validate
branches route read-only; pinned by tmp-dir Zig tests with red-green
proof + tests/runtime/test_policy_verify.py. Rust FFI cutover
explicitly out — native stays canonical for the control plane), disabled_rules end-to-end (BE-DIS-089: daemon
startup + rules.reload now skip configs/disabled_rules.json IDs;
CLI constant + list command canonicalized to the same file with a
daemon-authoritative count; live file gitignored; Zig membership +
skip-semantics tests + tests/security/test_disabled_rules_authority.py),
DEFCON unification (FE-DEF-095a: daemon owns the single ladder —
src/control/defcon.zig over g_critical_detections +
g_confirmed_blocks atomics, carried by healthJson defcon_level/label
per RUNTIME_CONTRACT §4.1; CLI get_defcon + web threat prefer it with
a labeled file-ladder fallback; pinned by tests/runtime/
test_defcon_authority.py. FE-DEF-095b closed the Rust surfaces:
desktop egui prefers snapshot defcon with a source tag (resolve_defcon
+ cargo tests); mouth queries system.health over the control pipe and
projects daemon DEFCON with a source tag, falling back to the labeled
file ladder (daemon_pipe client + strict pair validation, F3 canonical
log default, F4 receipt-only blocked counting shared with the
mitigation feed, F5 honest core-state attestation, 9 cargo tests;
stale sole-owner claims in aegis_mouth_test.py + STRUCTURE.md
corrected). Mouth-local kernel>=3 term stays in the fallback ladder
only (documented in the manual script replica), evidence feed
darkness (BE-EVI-097: daemon projects detections to
logs/aegis_core.ndjson — stage-10 evidenceLog with the v1 schema incl.
full receipt set, default ON with AEGIS_EVIDENCE_LOG=0 opt-out,
drop-on-error; dispatchWithReceipt returns the confirmed verdict gating
the enforced claim; forensic_log wired into all_tests (5th silent-death
catch); mouth reads canonical keys + case-insensitive policy; web
forwards policy_id/decision/provider so receipt_valid can hold; desktop
+ mouth + web recipe proofs; Go aggregator schema-compatible unchanged.
Live tail proof pending daemon rebuild+restart — human step before
attack tests), spool replay automation (BE-SPOOL-092: live round-trip
proven — refused TCP collector spills 2 events, same forwarder replays
to file on next flush with spool acked by deletion; counters
read/spooled/forwarded/failed asserted; empty-replay no-op negative
control; tmp-dir hermetic with red-green proof; metrics.snapshot
already exposes spool counters, no Python change),
 reload names skips (BE-DRIFT-098: shared classifyRule for startup +
reload with ReloadReport — loaded + per-reason counts + first-16 IDs
with truncation flag and completeness invariant; rules.reload response
carries skipped/skipped_ids/skipped_truncated additively; daemon
startup warns skipped IDs; CLI passes the report through (gap the new
pin caught: explicit result dict stripped unknown keys); Zig
classifier + end-to-end + escape tests with red-green proof), SBOM salt (SBOM-SALT-087: builtin
hash() is per-process salted — replaced with SHA-256 path IDs, proven
identical across hash seeds on all 554 packages), CI truth/Trivy
gates, web SSE backpressure (FE-SSE-090: disconnect ends the
generator explicitly via GeneratorExit + one failed snapshot emits
an error event instead of killing the stream + retry hint, pinned
by tests/runtime/test_web_sse.py; per-message snapshot cost
unchanged by design — shared-cache needs profiling, not guesses), fault-maybeCorrupt post-validation
(by design), quarantine federation best-effort (send failures stay
false; status reports live since FED-P4),
rust query unauthenticated (pipe ACL + role gates cover; FFI change is
ABI break — accepted risk), single g_ProofFilterId, provider GUID split,
ring stats partial, single-slot globals, query vs present tri-state
callers (exists), PepContext policy_version=0 + signed_by / TS u64
seal precision (T7: see docs/adr/0005-policy-signing-seal-and-custody.md
— Rust verifies but uncalled, TS emits 8-byte hints, Zig gates but
cannot verify; format + custody verdicts pending), Pro Console no live watch (UX design),
graph readability at 100+ records (UX design), brain UDP auth LANDED
(B2-AUTH-076: HMAC-SHA256 shared secret via AEGIS_BRAIN_SECRET, HEALTH
stays open by design), run_aegis.bat 5-subsystem model + wmic,
`D:\NIDs_Windows` hardcodes, Kali script default target, VMware
auto-select fallback, ETW Linux stub reporting running,
`last_event_ms` dual-clock, severity collapse, legacySource downgrade (pinned best-effort),
stream-reassembly stall/no-evict, DNS compression blind, HTTP unbounded
headers, RDP/Kerberos single-magic FP, nose TUI synthetic counters, C++
DNS port compare, IPC short framing, WFP unload leak
(drivers quarantined — do not touch), rule FNV collisions,
golden-table drift, `threat_score`/`weight` fixed, INCIDENT_TTL
unenforced (eviction-policy verdict needed), IPv4-only evidence ring
(see docs/adr/0006-forensic-ipv6-record-abi.md — corrected map in
FOR-V6A: the ring RecordHeader carries NO IP fields by design (identity
is the raw packet payload, which keeps full v6 bytes); the EvidenceRecord
hash chain is likewise IP-free, and the u32 ForensicsEngine ring is
unwired. The real wired wart was SIEM/NDJSON printing the /32 prefix
as a dotted quad — fixed: SIEM forwards full v6 text from sidecars,
LogEvent takes optional src_ipv6/dst_ipv6 strings. Framing DECIDED
(FOR-V6B): raw-bytes-only accepted — no header break, no payload
trailer; parsed v6 identity is served from SIEM/LogEvent text plus
re-parseable packet bytes. Rationale: an ABI break + dual-read for a
query convenience is not worth it while the header is IP-free by
design), wire CRC-no-HMAC (needs key design), event_queue
1500 truncation vs len claim (by wire design: length+hash only).
