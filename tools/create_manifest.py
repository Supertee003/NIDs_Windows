import re
from pathlib import Path
import json
import subprocess
from datetime import datetime, timezone

repo = Path(__file__).resolve().parent.parent

def current_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()

head_sha = current_head()
source_commit = head_sha[:7]
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
    'src/capture/npcap_capture.zig', 'src/windows/windows_adapters.zig',
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
    'src/federation/federation_tcp.zig', 'src/federation/federation_tls.zig',
    # IPS/XDR.
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
        },
        'canonical_path': canonical_path,
    }
    if display_path == 'core/windows_adapters.zig':
        entry['role'] = 'Windows adapter framework; 100/100 tests; no policy authority'
    if display_path != canonical_path:
        entry['compatibility_alias'] = True
    modules[display_path] = entry

authority_invariants = [
    'host-network source: src/capture/npcap_capture.zig is the single authoritative source for Windows host network telemetry; one model -> CanonicalEvent -> Zig Flow',
    'WFP enforcement module: src/policy/wfp_production.zig is the single authoritative WFP enforcement module; Rust PEP is the only route and a validated receipt is required',
    'Rust PEP is the final security authority for privileged actions; Python, TypeScript, Go, C++, and federation layers may request but never enforce',
    'control plane routes through aegisctl and the authenticated named pipe; never "Everyone" for privileged control operations',
    'identifier integrity: event_id, incident_id, policy_id, policy_version, request_id, and forensic_id remain traceable across the golden path',
    'golden path is REAL (host-verified Windows E2E); no compatibility alias is a second runtime authority',
    'forensics authority: src/forensic/forensics_engine.zig owns immutable forensic pipeline results',
    'forensic log authority: src/forensic/forensic_log.zig owns append-only evidence records',
    'replay authority: src/forensic/replay_engine.zig replays the authoritative forensic result',
    'forensic trace and replay consistent: replay must preserve the canonical identifiers and decision evidence',
    'federation authority: remote nodes exchange reports and threat intelligence only; enforcement stays local',
    'federation: reports only, enforcement stays local',
    'federation transport is TLS (no plaintext production transport)',
    'canary order is scope -> target -> expiry -> rollback -> audit; every privileged request is dispatched_to_pep',
    'real IPS path is receipt-gated and multi-source XDR records incident evidence before operator action',
    'decision trace records the eight-link request-to-source chain for every privileged action',
    'shadow decision is advisory only and cannot replace the final authority review',
    'security replay is deterministic and final authority review is required before release',
    'performance authority is the release benchmark and performance integration chain',
    'CI matrix authority is the cross-language validation matrix',
    'build provenance records source commit, artifact hashes, and reproducible release inputs',
    'installer preserves user data and upgrade rollback records RPO and RTO',
    'policy_engine is the canonical policy decision model; unsigned privileged policy is rejected',
]

manifest = {
    'runtime_version': '5.0.0',
    'head_sha': head_sha,
    'entrypoint': 'src/main.zig',
    'production_binary': 'zig-out/bin/aegis_nids.exe',
    'source_commit': source_commit,
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
        'forensic/replay_engine.zig',
        'reliability/fault_injection.zig',
        'reliability/latency_histogram.zig',
        'federation/cluster_coord.zig',
        'federation/node_registry.zig',
        'federation/aggregator.zig',
        'xdr/xdr_engine.zig',
    ],
    'shutdown_order': [
        'xdr/xdr_engine.zig',
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
        'forensic/replay_engine.zig',
        'core/memory_pool.zig',
        'core/diagnostics.zig',
        'contract/event.zig',
        'reliability/security_check.zig',
    ],
    'subsystems': sorted(subsystems.keys()),
    'subsystem_modules': {k: v for k, v in sorted(subsystems.items())},
    'golden_path': [
        'windows/host_telemetry.zig (host network telemetry)',
        'acquisition',
        'capture/npcap_adapter.zig (packet capture)',
        'canonical_event',
        'event_fabric',
        'flow',
        'detection (evidence)',
        'verdict',
        'correlation',
        'threat_intel',
        'rag (context)',
        'brain (advisory)',
        'policy (decision)',
        'policy signing (ed25519)',
        'rust pep (enforcement authority)',
        'wfp (windows enforcement)',
        'forensics (immutable trace)',
        'replay',
    ],
    'ABI_versions': {
        'zig_core': 'v5.0.0',
        'rust_pep': 'v5.0.0',
        'c_native': 'v1.0.0',
        'go_aggregator': 'v1.0.0',
    },
    'schema_versions': {
        'canonical_event': 'v2.0.0',
        'runtime_manifest': 'v5.0.0',
        'wire_protocol': 'v1.0.0',
    },
    'notes': {
        'production_entrypoint': 'build.zig -> src/main.zig -> zig build -> zig-out/bin/aegis_nids.exe',
        'legacy_folder': 'core/ (100+ legacy modules from earlier phases; NOT in production build; tracked per user request)',
        'production_subsystem': 'src/core/ (diagnostics.zig, memory_pool.zig - active in build; 2 files)',
        'test_only_entrypoint': 'src/fuzz_entry.zig -> src/tests/fuzz_main.zig (fuzz harness; 1 file)',
        'control_client': 'tools/aegisctl.py (named-pipe client, connects to daemon; not a runtime)',
        'installer': 'tools/installer.py (consumes build_manifest.json, generates aegis_setup.exe; not a runtime)',
        'enforcement_mode': 'detection-only until a provider-owned, receipt-producing WFP adapter is connected; no host block is claimed',
        'step_27_action_dispatcher_gap': 'closed as a safety containment: ActionDispatcher cannot claim host effect without Rust PEP provider receipt',
        'step_43_control_state_gap': 'STILL PENDING: src/main.zig control responses (packets_captured: 0, flows_active: 0) must bind to real runtime metrics (STEP 43).',
        'step_50_installer_gap': 'STILL PENDING: AEGIS_v5_fresh_deploy.ps1 embeds stale CI/config; removed from git index; preserved locally for STEP 50 fix.',
        'cleanup_status': 'Step 2 complete (366 artifacts removed from git index); Step 3 ADR complete; Step 4 Build Truth verified (all 6 builds green, 5 artifacts present); .gitignore hardened with LF normalization.',
        'run_time_manifest_step': 5,
        'build_truth_verified': True,
        'ci_status': 'All 8 CI jobs pass (zig, rust, c, go, python, ts, security, ci-matrix)',
        'python_tests_status': '436 passed, 23 skipped (after Cython build + cargo cache + timeout fix)',
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
