//! SCOPE-103: execution aggregator for the integration/proof harnesses.
//!
//! `zig build test` owns the unit suite (src/all_tests.zig). The operator
//! harnesses below carried ~350 inline `test` blocks that no gate ever
//! executed: `core-tools` only compiled two CLIs and `compile_only_imports`
//! type-checks without running. That meant a rotted harness assertion was
//! invisible until an operator ran it by hand.
//!
//! This root gives them a real run edge (`zig build test-out-of-unit`).
//! Their scopes stay declared in tests/security/test_zig_test_scope.py:
//!   integration — executed here
//!   proof       — executed here
//!   bench       — NOT here (timing-sensitive; `core-tools` builds the CLIs)
//!   specimen    — NOT here (intentionally uncompiled design reference)
//!   quarantine  — NOT here (harness orchestrators, never production)
//!
//! No production module imports this file; it exists only as a test root.

const std = @import("std");

comptime {
    // ---- integration harnesses (operator-run scenario suites) ----
    _ = @import("tests/integration/brain_integration.zig");
    _ = @import("tests/integration/concurrency_harden_integration.zig");
    _ = @import("tests/integration/correlation_integration.zig");
    _ = @import("tests/integration/detection_integration.zig");
    _ = @import("tests/integration/e2e_harness_integration.zig");
    _ = @import("tests/integration/fault_injection_integration.zig");
    _ = @import("tests/integration/flow_integration.zig");
    _ = @import("tests/integration/forensics_integration.zig");
    _ = @import("tests/integration/golden_path_e3.zig");
    _ = @import("tests/integration/hids_integration.zig");
    _ = @import("tests/integration/ips_canary_integration.zig");
    _ = @import("tests/integration/ips_simulation_integration.zig");
    _ = @import("tests/integration/nose_integration.zig");
    _ = @import("tests/integration/performance_integration.zig");
    _ = @import("tests/integration/policy_integration.zig");
    _ = @import("tests/integration/policy_plane_integration.zig");
    _ = @import("tests/integration/rag_integration.zig");
    _ = @import("tests/integration/release_engineering_integration.zig");
    _ = @import("tests/integration/replay_integration.zig");
    _ = @import("tests/integration/rust_pep_integration.zig");
    _ = @import("tests/integration/threat_intel_integration.zig");
    _ = @import("tests/integration/xdr_harden_integration.zig");
    _ = @import("core/e2e_harness.zig");
    _ = @import("core/integration_test.zig");

    // ---- proof CLIs (same standing as integration) ----
    _ = @import("tests/proofs/audit_trail_proof.zig");
    _ = @import("tests/proofs/brain_proof.zig");
    _ = @import("tests/proofs/compliance_proof.zig");
    _ = @import("tests/proofs/config_reload_proof.zig");
    _ = @import("tests/proofs/correlation_proof.zig");
    _ = @import("tests/proofs/detection_fabric_proof.zig");
    _ = @import("tests/proofs/documentation_proof.zig");
    _ = @import("tests/proofs/final_integration_proof.zig");
    _ = @import("tests/proofs/flow_state_proof.zig");
    _ = @import("tests/proofs/forensic_replay_proof.zig");
    _ = @import("tests/proofs/health_monitoring_proof.zig");
    _ = @import("tests/proofs/intelligence_proof.zig");
    _ = @import("tests/proofs/pep_enforcement_proof.zig");
    _ = @import("tests/proofs/performance_tuning_proof.zig");
    _ = @import("tests/proofs/policy_plane_proof.zig");
    _ = @import("tests/proofs/siem_integration_proof.zig");
    _ = @import("tests/proofs/telemetry_export_proof.zig");
}

test "out-of-unit harness aggregator resolves" {
    try std.testing.expect(true);
}
