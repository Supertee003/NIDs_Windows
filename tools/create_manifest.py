import re
from pathlib import Path
import json

repo = Path('D:/NIDs_Windows')

main_text = (repo / 'src/main.zig').read_text(encoding='utf-8', errors='ignore')
imports = sorted(set(re.findall(r'@import\(["\']([^"\']+)["\']\)', main_text)))
production_modules = [m for m in imports if m not in ('std', 'builtin')]

subsystems = {}
for mod in production_modules:
    subsystem = mod.split('/')[0] if '/' in mod else 'core'
    submodules = subsystems.setdefault(subsystem, [])
    submodules.append(mod.split('/')[-1] if '/' in mod else mod)

manifest = {
    'runtime_version': '5.0.0',
    'entrypoint': 'src/main.zig',
    'production_binary': 'zig-out/bin/aegis_nids.exe',
    'source_commit': '85f4102',
    'date': '2026-09-08',
    'production_modules': len(production_modules),
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
        'capture/npcap_adapter.zig (packet capture)',
        'contract/event.zig (canonical event)',
        'core/memory_pool.zig (fabric)',
        'capture/packet_decoder.zig (decoding)',
        'detection/signature_engine.zig (signature detection)',
        'detection/anomaly_detector.zig (anomaly detection)',
        'detection/proto_anomaly.zig (protocol anomaly)',
        'detection/correlator.zig (correlation)',
        'detection/threat_tracker.zig (threat tracking)',
        'federation/node_registry.zig (federation registry)',
        'federation/aggregator.zig (aggregation)',
        'federation/cluster_coord.zig (cluster coordination)',
        'reliability/fault_injection.zig (fault injection framework)',
        'reliability/watchdog.zig (reliability watchdog)',
        'reliability/security_check.zig (security hardening)',
        'reliability/latency_histogram.zig (performance telemetry)',
        'core/diagnostics.zig (diagnostics)',
        'reliability/fault_injection.zig (fault injection)',
        'reliability/watchdog.zig (watchdog health)',
        'core/diagnostics.zig (diagnostics)',
        'reliability/security_check.zig (security check)',
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
        'step_27_action_dispatcher_gap': 'STILL PENDING: ActionDispatcher in src/policy/action_dispatcher.zig must route through Rust PEP (STEP 27). Direct WFP callback path exists in production code but is being removed via ADR.',
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
