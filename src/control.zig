//! control.zig — AEGIS NIDS Control Plane Module Root
//!
//! Exports the protocol, authorization, audit, handler registry, and state machine.

pub const protocol = @import("control/protocol.zig");
pub const authorization = @import("control/authorization.zig");
pub const audit = @import("control/audit.zig");
pub const handler_registry = @import("control/handler_registry.zig");
pub const state_machine = @import("control/state_machine.zig");
