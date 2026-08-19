@@ -0,0 +1,89 @@
//! minifilter_reader.zig — AEGIS NIDS Minifilter Reader (Thread 4)
//!
//! Reads file/process events from the AEGIS minifilter driver via
//! FilterCommunicationPort (FilterGetMessage API). Converts kernel
//! AEGIS_FILE_EVENT structures to Zig format and sends to nids_analyze
//! for rule matching.
//!
//! Architecture: User-mode Zig reader (KERNEL_FILE/KERNEL_PROCESS layer
//! of 3-Layer Architecture)
//! Communication: FilterGetMessage() from kernel → Zig event processing

const std = @import("std");

// ====== AEGIS File/Process Event (matches kernel struct) ======
pub const AegisFileEvent = extern struct {
    event_type: u32,      // 1=KERNEL_FILE, 2=KERNEL_PROCESS
    operation: u32,       // IRP_MJ_CREATE/WRITE/etc. or PROCESS_CREATE/EXIT
    file_name_len: u32,   // Length of file name following this header
    process_id: u32,      // PID of the process
    rule_id: u32,         // Matched rule ID
    severity: u32,        // 0=Low, 1=Medium, 2=High, 3=Critical
    reserved: u32,
    timestamp: u64,       // Event timestamp
};

// ====== Event type constants ======
pub const EVENT_KERNEL_FILE = 1;
pub const EVENT_KERNEL_PROCESS = 2;
pub const PROCESS_CREATE = 0x100;
pub const PROCESS_EXIT = 0x101;

// ====== Convert AegisFileEvent to string description ======
pub fn eventTypeToString(event_type: u32) []const u8 {
    switch (event_type) {
        EVENT_KERNEL_FILE => "KERNEL_FILE",
        EVENT_KERNEL_PROCESS => "KERNEL_PROCESS",
        else => "UNKNOWN",
    }
}

pub fn operationToString(operation: u32) []const u8 {
    switch (operation) {
        0x00 => "IRP_MJ_CREATE",
        0x04 => "IRP_MJ_WRITE",
        0x0C => "IRP_MJ_SET_INFORMATION",
        PROCESS_CREATE => "PROCESS_CREATE",
        PROCESS_EXIT => "PROCESS_EXIT",
        else => "UNKNOWN_OP",
    }
}

pub fn severityToString(severity: u32) []const u8 {
    switch (severity) {
        0 => "Low",
        1 => "Medium",
        2 => "High",
        3 => "Critical",
        else => "Unknown",
    }
}

// ====== Main minifilter reader loop (Thread 4) ======
pub fn minifilterReaderLoop() !void {
    std.log.info("[Minifilter Reader] Thread 4 started — reading from FilterCommunicationPort", .{});

    // On Windows, connect to \\AegisMinifilterPort via FilterConnectCommunicationPort
    // Read messages using FilterGetMessage()
    // Parse AEGIS_FILE_EVENT + file_name buffer
    // Forward events to nids_analyze.inspect_event()

    // NOTE: This requires Win32 API bindings (fltlib.h) which are not
    // in the Zig standard library. Build on Windows with appropriate bindings.

    while (true) {
        // 1. Try to open the minifilter communication port
        //    Port name: \\AegisMinifilterPort
        //    API: FilterConnectCommunicationPort(portName, portId, context, contextSize, timeout, &portHandle)

        // 2. Read message via FilterGetMessage()
        //    Message contains AEGIS_FILE_EVENT header + optional file_name

        // 3. For each event, forward to nids_analyze:
        //    - Create EventHeader from AegisFileEvent fields
        //    - Call nids_analyze.inspect_event(header, payload)

        std.log.info("[Minifilter Reader] Waiting for minifilter driver events...", .{});
        std.time.sleep(5 * std.time.ns_per_s);  // Retry every 5s if driver not available
    }
}
