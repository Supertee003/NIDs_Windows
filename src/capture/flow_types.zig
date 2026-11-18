//! flow_types.zig - AEGIS Flow Types (compatibility shim)
//!
//! This module re-exports everything from flow_engine.zig so that legacy
//! code that imports `flow_types.FlowUpdate` resolves to the same type
//! as `flow_engine.FlowUpdate`.
//!
//! Background: older dispatchers referenced flow_types.zig directly;
//! newer ones use flow_engine.zig. This shim makes both resolve to
//! the same underlying struct, eliminating the type-mismatch error:
//!   "expected '?flow_types.FlowUpdate', found '?flow_engine.FlowUpdate'"
//!
//! Status (DEADCODE-QUARANTINE 2026-10-19): no production importer remains.
//! The only consumers are quarantined harnesses (policy/dispatcher.zig,
//! policy/dispatcher_phase_b.zig, tests/proofs/detection_fabric_proof.zig).
//! Registered unreachable in tests/security/test_zig_test_scope.py; do not
//! wire it into the runtime without a conscious promotion patch.

pub usingnamespace @import("flow_engine.zig");
