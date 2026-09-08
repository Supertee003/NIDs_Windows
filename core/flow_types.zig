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

pub usingnamespace @import("flow_engine.zig");
