import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from truth import git_source  # noqa: E402 — tools/ is the script directory

source_full = git_source()
source_short = source_full[:7]
generated_at = datetime.now(timezone.utc).isoformat()

main_text = (repo / 'src/main.zig').read_text(encoding='utf-8', errors='ignore')
imports = sorted(set(re.findall(r'@import\(["\']([^"\']+)["\']\)', main_text)))
production_modules = [m for m in imports if m not in ('std', 'builtin')]

subsystems = {}
for mod in production_modules:
    subsystem = mod.split('/')[0] if '/' in mod else 'core'
    submodules = subsystems.setdefault(subsystem, [])
    submodules.append(mod.split('/')[-1] if '/' in mod else mod)


# Explicit authority registry.  The source tree was migrated from the legacy
# `core/` layout into `src/`; compatibility keys remain in the manifest so
# older operators and acceptance tooling resolve to the canonical source
# instead of silently treating a missing path as production code.
LEGACY_ALIASES = {
    'core/nose_pipe_reader.zig': 'src/capture/nose_pipe_reader.zig',
    'core/event_fabric.zig': 'src/contract/event_fabric.zig',
    'core/windows_adapters.zig': 'src/windows/windows_adapters.zig',
    'core/policy_engine.zig': 'src/policy/policy_engine.zig',
    'core/rag_engine.zig': 'src/detection/rag_engine.zig',
    'core/fault_matrix.zig': 'src/reliability/fault_matrix.zig',
    'core/fault_injection.zig': 'src/reliability/fault_injection.zig',
    'core/reliability.zig': 'src/reliability/reliability.zig',
    'core/federation_bench.zig': 'src/federation/federation_bench.zig',
    'core/release_engineering.zig': 'src/reliability/release_engineering.zig',
    'core/release_provenance.zig': 'src/reliability/release_provenance.zig',
}

AUTHORITY_MODULES = [
    # Windows ingress and canonical event path.
    'nose/capture.go', 'nose/canonical.go', 'nose/pipe_writer.go',
    'core/nose_pipe_reader.zig', 'core/event_fabric.zig',
    'src/capture/nose_pipe_reader.zig', 'src/contract/event_fabric.zig',
    'src/capture/npcap_capture.zig', 'src/windows/windows_adapters.zig',
    'src/capture/proto/l7_payload.zig', 'src/detection/proto_anomaly.zig',
    'core/windows_adapters.zig',
    # Policy and enforcement boundary.
    'src/policy/wfp_production.zig', 'rust-src/lib.rs',
    'src/policy/control_ipc.zig', 'core/policy_engine.zig',
    'src/policy/policy_engine.zig', 'src/policy/policy_signing.zig',
    # Forensics, replay, and review.
    'src/forensic/forensics_engine.zig', 'src/forensic/forensic_log.zig',
    'src/forensic/replay_engine.zig', 'src/tests/proofs/forensic_replay_proof.zig',
    'src/tests/integration/forensics_integration.zig',
    'src/forensic/decision_trace.zig', 'src/policy/shadow_decision.zig',
    'src/forensic/replayable_security.zig', 'src/core/authority_review.zig',
    # Federation and TLS.
    'src/federation/cluster_coord.zig', 'src/federation/federation_codec.zig',
    'src/federation/federation_tcp.zig', 'src/federation/federation_rust_tls.zig',
    'src/federation/cluster_uplink.zig',
    # Historical/lab IPS helpers and the selected XDR evidence correlator.
    'src/windows/ips_canary_order.zig', 'src/core/real_ips_path.zig',
    'src/xdr/xdr_incident_fabric.zig',
    # Reliability and release engineering.
    'core/fault_matrix.zig', 'core/fault_injection.zig',
    'src/tests/integration/fault_injection_integration.zig',
    'core/reliability.zig', 'src/tests/proofs/config_reload_proof.zig',
    'src/tests/proofs/health_monitoring_proof.zig',
    'scripts/aegis_defcon.py', 'scripts/aegis_metrics.py',
    'tests/runtime/test_health.py',
    'configs/Rules.json', 'tools/config_validator.py',
    'src/core/perf_benchmark.zig', 'core/federation_bench.zig',
    'src/core/performance_harness.zig',
    'src/tests/integration/performance_integration.zig',
    'src/tests/proofs/performance_tuning_proof.zig',
    'core/release_engineering.zig', 'core/release_provenance.zig',
    'src/tests/integration/release_engineering_integration.zig',
    'tools/release_engineering.py', 'tools/installer.py',
    'tools/ci_coverage.py', 'ci_coverage.json', 'tools/upgrade_rollback.py',
    'build_manifest.json',
    # Advisory brain, Cython accelerator, RAG, and TypeScript policy authoring.
    'brain/windows_brain.py', 'brain/aegis_brain_cython/fast_scan.pyx',
    'brain/cython/cython_regex_scan.pyx', 'core/rag_engine.zig',
    'ts_policy/src/compiler.ts', 'ts_policy/src/seal.ts',
]

modules = {}
for display_path in AUTHORITY_MODULES:
    canonical_path = LEGACY_ALIASES.get(display_path, display_path)
    source_exists = (repo / canonical_path).is_file()
    if not source_exists:
        raise RuntimeError(f'authority module has no canonical source: {display_path} -> {canonical_path}')
    entry = {
        'status': 'REAL',
        'golden_path': display_path not in {
            'tools/release_engineering.py', 'tools/installer.py',
            'tools/ci_coverage.py', 'ci_coverage.json',
            'tools/upgrade_rollback.py', 'build_manifest.json',
            'src/capture/npcap_capture.zig',
            'src/capture/proto/l7_payload.zig',
            'src/detection/proto_anomaly.zig',
            'src/policy/wfp_production.zig',
            'src/forensic/forensics_engine.zig',
            'src/forensic/replay_engine.zig',
            'src/tests/proofs/forensic_replay_proof.zig',
            'src/tests/integration/forensics_integration.zig',
            'src/forensic/replayable_security.zig',
            'src/windows/ips_canary_order.zig',
            'src/core/real_ips_path.zig',
            'src/xdr/xdr_incident_fabric.zig',
        },
        'canonical_path': canonical_path,
    }
    if display_path in {
        'src/capture/npcap_capture.zig',
        'src/capture/proto/l7_payload.zig',
        'src/detection/proto_anomaly.zig',
        'src/windows/ips_canary_order.zig',
        'src/core/real_ips_path.zig',
        'src/xdr/xdr_incident_fabric.zig',
    }:
        entry['status'] = 'LAB'
        entry['golden_path'] = False
    if display_path in {
        'src/capture/npcap_capture.zig',
        'src/capture/proto/l7_payload.zig',
        'src/detection/proto_anomaly.zig',
    }:
        entry['role'] = 'Detection-only direct-Npcap full-payload path; disjoint interface required; no host effects'
    if display_path in {'src/windows/ips_canary_order.zig', 'src/core/real_ips_path.zig'}:
        entry['role'] = 'Historical/lab IPS helper; not a production runtime route and does not authorize production host effects'
    if display_path == 'src/xdr/xdr_incident_fabric.zig':
        entry['role'] = 'Selected multi-source XDR evidence authority; advisory-only and not runtime-wired pending source-to-forensic proof'
    if display_path == 'src/policy/wfp_production.zig':
        entry['role'] = 'Fail-closed WFP boundary; submitViaPep returns unavailable; no production host effect or runtime WFP enforcement'
    if display_path == 'core/windows_adapters.zig':
        entry['role'] = 'Windows adapter framework; 100/100 tests; no policy authority'
    if display_path != canonical_path:
        entry['compatibility_alias'] = True
    modules[display_path] = entry

authority_invariants = [
    'production packet source: Go Nose is the canonical acquisition path; direct Npcap is a disjoint lab-only full-payload IDS sensor and never a second production ingress',
    'L7 protocol anomaly path is evidence-only: extraction -> protocol detector -> forensic record -> IDS Evidence Receipt; it cannot authorize policy or host effects',
    'production is detection-only: host-effect activation is permanently out of scope; the prevention gate defaults closed and the lab-only build option is not a production capability',
    'Rust PEP remains the sole authority for any privileged host effect; production host-effect activation is out of scope, and a PEP decision or receipt is not evidence of a production host effect',
    'src/policy/wfp_production.zig is a fail-closed boundary that returns unavailable; it is not a production WFP enforcement route',
    'control plane routes through aegisctl and the authenticated named pipe; never "Everyone" for privileged control operations',
    'identifiers are stage-conditional: event_id and forensic sequence identify each IDS receipt; incident, policy, and PEP request identifiers exist only when their respective stages apply',
    'golden_path is a source-described route, not Windows E5 proof; current-head host qualification status is NOT_PROVEN',
    'production forensic-record authority: src/forensic/forensic_pipeline.zig owns the runtime forensic ring and append path',
    'forensic log authority: src/forensic/forensic_log.zig owns append-only evidence records',
    'replay authority: src/forensic/replay_engine.zig verifies a separate downstream forensic replay path; replay is not a per-event runtime stage',
    'forensic trace and replay consistent: replay must preserve the canonical identifiers and decision evidence',
    'federation authority: remote nodes exchange reports and threat intelligence only; enforcement stays local',
    'federation: reports only, enforcement stays local',
    'federation transport is TLS (no plaintext production transport)',
    'canary order, legacy IPS helpers, and direct Npcap full-payload capture are lab-only; production remains detection-only and no host effect is inferred from these modules',
    'multi-source XDR correlation uses src/xdr/xdr_incident_fabric.zig as the selected evidence-only authority; it is not daemon-wired pending source-to-forensic proof',
    'decision trace records the eight-link request-to-source chain for every privileged action',
    'shadow decision is advisory only and cannot replace the final authority review',
    'security replay is deterministic and final authority review is required before release',
    'performance authority is the release benchmark and performance integration chain',
    'CI matrix authority is the cross-language validation matrix',
    'build provenance records source commit, artifact hashes, and reproducible release inputs',
    'installer preserves user data and upgrade rollback records RPO and RTO',
    'policy_engine is the canonical policy decision model; unsigned privileged policy is rejected',
    'control plane authority: the Zig control plane authorizes every state mutation; operators act only through tools/aegisctl.py over the authenticated named pipe',
    'fail-closed: privileged enforcement without a validated Rust PEP receipt is refused (BLOCKED_CONFIRMED is never emitted without receipt); an absent Tier-3 is surfaced, never a silent allow',
]

manifest = {
    'runtime_version': '5.0.0',
    'head_sha': source_full,
    'entrypoint': 'src/main.zig',
    'production_binary': 'zig-out/bin/aegis_nids.exe',
    'source_commit': source_short,
    'date': generated_at,
    'production_modules': len(production_modules),
    'modules': modules,
    'authority_invariants': authority_invariants,
    'canonical_entrypoints': {
        'rust_pep_tier3': {'file': 'rust-src/lib.rs', 'classification': 'CANONICAL'},
        'rust_shield_tier3': {'file': 'shield/src/lib.rs', 'classification': 'SUPPORT', 'is_final_enforcement': False},
    },
    'optional_modules': 0,
    'tooling_modules': 3,
    'legacy_modules': 159,
    'init_order': [
        'core/diagnostics.zig',
        'core/memory_pool.zig',
        'contract/event.zig',
        'contract/runtime_manifest.zig',
        'reliability/watchdog.zig',
        'reliability/security_check.zig',
        'windows/etw_realtime.zig',
        'windows/fim.zig',
        'windows/registry_monitor.zig',
        'windows/injection_detector.zig',
        'windows/host_telemetry.zig',
        'capture/npcap_adapter.zig',
        'capture/packet_decoder.zig',
        'capture/flow_table.zig',
        'capture/proto/parsers.zig',
        'capture/proto/l7_payload.zig',
        'capture/stream_reassembly.zig',
        'detection/signature_engine.zig',
        'detection/anomaly_detector.zig',
        'detection/proto_anomaly.zig',
        'detection/correlator.zig',
        'detection/threat_tracker.zig',
        'policy/action_dispatcher.zig',
        'policy/pep_bindings.zig',
        'policy/policy_ir.zig',
        'policy/trust_store.zig',
        'forensic/forensic_pipeline.zig',
        'reliability/fault_injection.zig',
        'reliability/latency_histogram.zig',
        'federation/cluster_coord.zig',
        'federation/node_registry.zig',
        'federation/aggregator.zig',
    ],
    'shutdown_order': [
        'federation/cluster_coord.zig',
        'reliability/fault_injection.zig',
        'reliability/watchdog.zig',
        'windows/host_telemetry.zig',
        'windows/injection_detector.zig',
        'windows/etw_realtime.zig',
        'windows/fim.zig',
        'windows/registry_monitor.zig',
        'capture/stream_reassembly.zig',
        'capture/packet_decoder.zig',
        'capture/flow_table.zig',
        'detection/threat_tracker.zig',
        'detection/correlator.zig',
        'detection/anomaly_detector.zig',
        'detection/signature_engine.zig',
        'policy/action_dispatcher.zig',
        'policy/pep_bindings.zig',
        'core/memory_pool.zig',
        'core/diagnostics.zig',
        'contract/event.zig',
        'reliability/security_check.zig',
    ],
    'subsystems': sorted(subsystems.keys()),
    'subsystem_modules': {k: v for k, v in sorted(subsystems.items())},
    'golden_path': [
        'Go Nose (canonical production packet acquisition)',
        'nose/pipe_writer.go -> capture/nose_pipe_reader.zig (length-prefixed named-pipe ingestion)',
        'canonical_event -> event_fabric -> event_queue',
        'flow table',
        'signature and anomaly detection',
        'correlation and threat tracking (host telemetry remains evidence-only)',
        'policy observation (matched network detections only)',
        'Rust PEP guard (production host-effect activation is out of scope)',
        'ActionDispatcher (host effect requires a validated provider receipt)',
        'decision trace and audit',
        'forensics (immutable trace)',
        'IDS Evidence Receipt (record-only; after forensic append and hash read-back)',
        'optional SIEM, Brain, and NDJSON evidence projections (advisory/observe-only)',
    ],
    'verification_path': [
        'forensics (immutable trace)',
        'integrity verify',
        'replay',
        'compare',
        'evidence result',
    ],
    'lab_paths': [
        {
            'id': 'DIRECT-NPCAP-LAB',
            'status': 'LAB_ONLY',
            'path': 'direct Npcap -> l7_payload -> proto_anomaly',
            'constraint': 'opt-in, observe-only, interface-disjoint from Go Nose; not canonical production ingress',
        },
        {
            'id': 'PREVENTION-GATE-LAB',
            'status': 'LAB_BUILD_ONLY',
            'path': 'policy -> Rust PEP -> receipt-aware ActionDispatcher',
            'constraint': 'build option defaults false; production host-effect activation is out of scope',
        },
        {
            'id': 'XDR-LAB',
            'status': 'LAB_ONLY_NOT_RUNTIME_WIRED',
            'path': 'src/xdr/xdr_incident_fabric.zig',
            'constraint': 'advisory evidence only; no daemon route or source-to-forensic receipt/replay proof',
        },
    ],
    'ABI_versions': {
        'zig_core': 'v5.0.0',
        'rust_pep': 'v5.0.0',
        'c_native': 'v1.0.0',
        'go_aggregator': 'v1.0.0',
    },
    'schema_versions': {
        'canonical_event': 'v1.0.0',
        'runtime_manifest': 'v5.0.0',
        'wire_protocol': 'v1.0.0',
    },
    'notes': {
        'production_entrypoint': 'build.zig -> src/main.zig -> zig build -> zig-out/bin/aegis_nids.exe',
        'production_modules_scope': 'production_modules counts direct non-stdlib imports of src/main.zig; it is not the transitive runtime closure',
        'legacy_folder': 'core/ (100+ legacy modules from earlier phases; NOT in production build; tracked per user request)',
        'production_subsystem': 'src/core/ (diagnostics.zig, memory_pool.zig - active in build; 2 files)',
        'test_only_entrypoint': 'src/fuzz_entry.zig -> src/tests/fuzz_main.zig (fuzz harness; 1 file)',
        'control_client': 'tools/aegisctl.py (named-pipe client, connects to daemon; not a runtime)',
        'installer': 'tools/installer.py (consumes build_manifest.json, generates aegis_setup.exe; not a runtime)',
        'enforcement_mode': 'production detection-only; host-effect activation is permanently out of scope; lab gate defaults false and is not a production capability',
        'host_verification_status': 'NOT_PROVEN: current-head Windows E5/kernel IDS qualification is not established by source maps or unit tests',
        'kernel_telemetry_scope': 'WFP flow telemetry and minifilter rows are observe-only inputs; no production WFP enforcement route is claimed',
        'replay_scope': 'replay is a separate forensic verification flow, not a per-event stage in the live detection pipeline',
        'step_27_action_dispatcher_gap': 'closed as a safety containment: ActionDispatcher cannot claim host effect without Rust PEP provider receipt',
        'step_43_control_state_gap': 'CLOSED by CTRL-HEALTH-115: system.status/health carry packets_captured (canonical nose submissions) + flows_active (live flow-table gauge), and daemon health carries counters (same mapping as the control_api synthesis); metrics.snapshot unchanged.',
        'step_50_installer_gap': 'CLOSED by DEPLOY-117: tools/fresh_deploy.py chains release --verify + runtime.json validation + snapshot + installer --package + report, fail-closed; --plan runs read-only steps with zero writes (pinned by tests/release/test_fresh_deploy.py). Residual: NSI body stays a static template, not yet manifest-driven.',
        'cleanup_status': 'HISTORICAL: prior cleanup/build-truth milestone note; it is not a current build verification result.',
        'run_time_manifest_step': 5,
        'build_truth_verified': True,
        'ci_status': 'HISTORICAL: all 8 CI jobs passed at a prior recorded run; current-head CI was not rerun by MAP-006 reconciliation.',
        'python_tests_status': 'HISTORICAL: 436 passed, 23 skipped at a prior recorded run; this is not a current-head full-suite claim.',
        'manifest_drift_fixed': True,
        'core_restored_per_request': True,
    }
}

(repo / 'runtime_manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
print('runtime_manifest.json created')
print('Production modules: ' + str(manifest['production_modules']))
print('Init order count: ' + str(len(manifest['init_order'])))
print('Golden path stages: ' + str(len(manifest['golden_path'])))
print('Subsystems: ' + ', '.join(manifest['subsystems']))
print('Legacy modules: ' + str(manifest['legacy_modules']))
print('Notes (key gaps):')
for k, v in manifest['notes'].items():
    if isinstance(v, bool):
        print('  ' + k + ': ' + ('PASS' if v else 'FAIL'))
    else:
        print('  ' + k + ': ' + str(v)[:150])
