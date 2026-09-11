//! siem_integration_proof.zig - AEGIS G16 SIEM Integration Proof (v5.0 Section 59-61)
//!
//! F19: SIEM ingestion - CEF, LEEF, KEY-VALUE formats normalized to internal event.
//!
//! v5.0 Section 59: CEF (Common Event Format) ingestion - parse incoming CEF events
//!                  from network sensors, firewalls, IDS/IPS into internal events.
//! v5.0 Section 60: LEEF (Log Event Extended Format) ingestion - IBM QRadar format
//!                  with tab-separated key=value extensions.
//! v5.0 Section 61: G16 Exit Gate - KEY-VALUE ingestion - generic key=value format,
//!                  plus multi-format normalization (all 3 -> NormalizedEvent).
//!
//! Architecture (Phase 19 xdr_harden + Phase 22 rag_engine + SIEM ingestion):
//!   External SIEM -> [CEF | LEEF | KEY-VALUE] parser -> NormalizedEvent -> pipeline
//!
//! Safety pattern: all parsed slices point INTO the input []const u8 (caller-owned).
//! The input must remain alive as long as the NormalizedEvent is used. No local
//! array allocations -- avoids the dangling slice pitfall.
//!
//! This module proves:
//!   1. CEF parsing: header (8 pipe-delimited fields) + extension (key=value)
//!   2. LEEF parsing: header (5 pipe-delimited fields) + extension (tab-separated key=value)
//!   3. KEY-VALUE parsing: space-separated key=value pairs
//!   4. Multi-format normalization: all 3 formats -> NormalizedEvent (single internal type)

const std = @import("std");

// ============================================================
// Normalized Event (internal representation)
// ============================================================
// v5.0 Section 61: "Single internal type for all ingested events."
// All parsed slices point INTO the original input []const u8 (caller-owned).

pub const MAX_EXTENSIONS: usize = 16;
pub const MAX_KEY_LEN: usize = 32;
pub const MAX_VAL_LEN: usize = 128;

pub const Extension = struct {
    key: []const u8,
    value: []const u8,
};

pub const NormalizedEvent = struct {
    /// Vendor (e.g., "AEGIS", "Cisco", "PaloAlto").
    vendor: []const u8,
    /// Product (e.g., "NIDS", "ASA", "NGFW").
    product: []const u8,
    /// Device version (e.g., "1.0").
    dev_version: []const u8,
    /// Signature ID (rule_id equivalent).
    sig_id: []const u8,
    /// Event name.
    name: []const u8,
    /// Severity (0-9, normalized).
    severity: u8,
    /// Source format (CEF, LEEF, KEYVAL).
    source_format: SourceFormat,
    /// Extension fields (inline array to avoid dangling slice).
    extensions: [MAX_EXTENSIONS]Extension,
    /// Number of valid extensions.
    extension_count: usize,
    /// Raw input (for audit trail -- caller-owned).
    raw_input: []const u8,
};

pub const SourceFormat = enum(u8) {
    cef = 0,
    leef = 1,
    keyval = 2,
    unknown = 3,

    pub fn toString(self: SourceFormat) []const u8 {
        return switch (self) {
            .cef => "CEF",
            .leef => "LEEF",
            .keyval => "KEYVAL",
            .unknown => "UNKNOWN",
        };
    }
};

/// Create an empty NormalizedEvent (all fields zeroed/empty).
fn emptyNormalizedEvent(raw: []const u8) NormalizedEvent {
    var empty_ext: [MAX_EXTENSIONS]Extension = undefined;
    var i: usize = 0;
    while (i < MAX_EXTENSIONS) : (i += 1) {
        empty_ext[i] = .{ .key = "", .value = "" };
    }
    return .{
        .vendor = "",
        .product = "",
        .dev_version = "",
        .sig_id = "",
        .name = "",
        .severity = 0,
        .source_format = .unknown,
        .extensions = empty_ext,
        .extension_count = 0,
        .raw_input = raw,
    };
}

// ============================================================
// Parsing helpers
// ============================================================

/// Find the first occurrence of `delim` in `s`, returning the index.
/// Returns s.len if not found.
fn findChar(s: []const u8, delim: u8) usize {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == delim) return i;
    }
    return s.len;
}

/// Split `s` at the first occurrence of `delim`, returning (before, after).
/// If `delim` not found, returns (s, "").
fn splitOnce(s: []const u8, delim: u8) struct { before: []const u8, after: []const u8 } {
    const idx = findChar(s, delim);
    if (idx >= s.len) {
        return .{ .before = s, .after = "" };
    }
    return .{ .before = s[0..idx], .after = s[idx + 1 ..] };
}

/// Parse a key=value pair from `s` (e.g., "src=10.0.0.1").
/// Returns null if no '=' found.
fn parseKeyValue(s: []const u8) ?Extension {
    const eq_idx = findChar(s, '=');
    if (eq_idx >= s.len) return null;
    return .{
        .key = s[0..eq_idx],
        .value = s[eq_idx + 1 ..],
    };
}

/// Add an extension to a NormalizedEvent. Returns false if full.
fn addExtension(event: *NormalizedEvent, ext: Extension) bool {
    if (event.extension_count >= MAX_EXTENSIONS) return false;
    event.extensions[event.extension_count] = ext;
    event.extension_count += 1;
    return true;
}

// ============================================================
// CEF Parsing (v5.0 Section 59)
// ============================================================
// v5.0: "CEF:version|vendor|product|dev_version|sig_id|name|severity|extension"
// Example: CEF:0|AEGIS|NIDS|1.0|100|SQL Injection|9|src=10.0.0.1 act=block

/// Parse a CEF-formatted string into a NormalizedEvent.
/// Returns null if the input is not valid CEF.
pub fn parseCef(input: []const u8) ?NormalizedEvent {
    // Must start with "CEF:".
    if (input.len < 4) return null;
    if (!std.mem.eql(u8, input[0..4], "CEF:")) return null;

    var event = emptyNormalizedEvent(input);
    event.source_format = .cef;

    // Skip "CEF:" prefix.
    var rest = input[4..];

    // Field 1: version (single digit, followed by '|').
    const v_split = splitOnce(rest, '|');
    if (v_split.after.len == 0 and rest.len > 0 and findChar(rest, '|') >= rest.len) {
        return null; // no pipe found
    }
    event.dev_version = v_split.before; // temporarily store version here; will re-parse
    rest = v_split.after;

    // Field 2: vendor.
    const vendor_split = splitOnce(rest, '|');
    event.vendor = vendor_split.before;
    rest = vendor_split.after;

    // Field 3: product.
    const product_split = splitOnce(rest, '|');
    event.product = product_split.before;
    rest = product_split.after;

    // Field 4: dev_version.
    const dv_split = splitOnce(rest, '|');
    event.dev_version = dv_split.before;
    rest = dv_split.after;

    // Field 5: sig_id.
    const sig_split = splitOnce(rest, '|');
    event.sig_id = sig_split.before;
    rest = sig_split.after;

    // Field 6: name.
    const name_split = splitOnce(rest, '|');
    event.name = name_split.before;
    rest = name_split.after;

    // Field 7: severity.
    const sev_split = splitOnce(rest, '|');
    event.severity = parseSeverity(sev_split.before);
    rest = sev_split.after;

    // Field 8: extension (space-separated key=value pairs).
    var ext_str = rest;
    while (ext_str.len > 0) {
        const kv_split = splitOnce(ext_str, ' ');
        if (kv_split.before.len > 0) {
            if (parseKeyValue(kv_split.before)) |ext| {
                _ = addExtension(&event, ext);
            }
        }
        ext_str = kv_split.after;
    }

    return event;
}

/// Parse a severity string into a u8 (0-9).
fn parseSeverity(s: []const u8) u8 {
    if (s.len == 0) return 0;
    // Single digit severity.
    if (s.len == 1 and s[0] >= '0' and s[0] <= '9') {
        return s[0] - '0';
    }
    // Named severity.
    if (std.mem.eql(u8, s, "low")) return 3;
    if (std.mem.eql(u8, s, "medium")) return 5;
    if (std.mem.eql(u8, s, "high")) return 7;
    if (std.mem.eql(u8, s, "critical")) return 9;
    return 0;
}

// ============================================================
// LEEF Parsing (v5.0 Section 60)
// ============================================================
// v5.0: "LEEF:version|vendor|product|dev_version|extension"
// Extension is tab-separated key=value pairs.
// Example: LEEF:1.0|AEGIS|NIDS|1.0|src=10.0.0.1\tact=block\tsev=9

/// Parse a LEEF-formatted string into a NormalizedEvent.
/// Returns null if the input is not valid LEEF.
pub fn parseLeef(input: []const u8) ?NormalizedEvent {
    // Must start with "LEEF:".
    if (input.len < 5) return null;
    if (!std.mem.eql(u8, input[0..5], "LEEF:")) return null;

    var event = emptyNormalizedEvent(input);
    event.source_format = .leef;

    // Skip "LEEF:" prefix.
    var rest = input[5..];

    // Field 1: version.
    const v_split = splitOnce(rest, '|');
    if (v_split.after.len == 0 and findChar(rest, '|') >= rest.len) {
        return null;
    }
    event.dev_version = v_split.before; // temporarily store version
    rest = v_split.after;

    // Field 2: vendor.
    const vendor_split = splitOnce(rest, '|');
    event.vendor = vendor_split.before;
    rest = vendor_split.after;

    // Field 3: product.
    const product_split = splitOnce(rest, '|');
    event.product = product_split.before;
    rest = product_split.after;

    // Field 4: dev_version.
    const dv_split = splitOnce(rest, '|');
    event.dev_version = dv_split.before;
    rest = dv_split.after;

    // Field 5: extension (tab-separated key=value pairs).
    // LEEF uses tab (0x09) as separator.
    var ext_str = rest;
    while (ext_str.len > 0) {
        const kv_split = splitOnce(ext_str, '\t');
        if (kv_split.before.len > 0) {
            if (parseKeyValue(kv_split.before)) |ext| {
                _ = addExtension(&event, ext);
            }
        }
        ext_str = kv_split.after;
    }

    // Try to extract severity from extensions.
    var i: usize = 0;
    while (i < event.extension_count) : (i += 1) {
        if (std.mem.eql(u8, event.extensions[i].key, "sev")) {
            event.severity = parseSeverity(event.extensions[i].value);
            break;
        }
    }

    // Use vendor as name placeholder (LEEF doesn't have a name field).
    event.name = event.product;
    event.sig_id = "0";

    return event;
}

// ============================================================
// KEY-VALUE Parsing (v5.0 Section 61)
// ============================================================
// v5.0: "Generic key=value format, space-separated."
// Example: src=10.0.0.1 act=block sev=9 rule=100

/// Parse a KEY-VALUE formatted string into a NormalizedEvent.
/// Returns null if the input has no key=value pairs.
pub fn parseKeyVal(input: []const u8) ?NormalizedEvent {
    var event = emptyNormalizedEvent(input);
    event.source_format = .keyval;
    event.vendor = "unknown";
    event.product = "unknown";
    event.dev_version = "0";
    event.sig_id = "0";
    event.name = "keyval_event";

    var rest = input;
    var found_any = false;

    while (rest.len > 0) {
        const kv_split = splitOnce(rest, ' ');
        if (kv_split.before.len > 0) {
            if (parseKeyValue(kv_split.before)) |ext| {
                if (std.mem.eql(u8, ext.key, "sev")) {
                    event.severity = parseSeverity(ext.value);
                }
                _ = addExtension(&event, ext);
                found_any = true;
            }
        }
        rest = kv_split.after;
    }

    if (!found_any) return null;
    return event;
}

// ============================================================
// CEF Proof (v5.0 Section 59)
// ============================================================

pub const CefParseCheck = struct {
    cef_prefix_detected: bool,
    header_8_fields_parsed: bool,
    severity_parsed: bool,
    extensions_parsed: bool,
    cef_parse_ok: bool,

    pub fn isPassed(self: CefParseCheck) bool {
        return self.cef_parse_ok;
    }
};

/// Verify CEF parsing.
/// v5.0 Section 59: CEF format ingestion.
pub fn verifyCefParse() CefParseCheck {
    const input = "CEF:0|AEGIS|NIDS|1.0|100|SQL Injection|9|src=10.0.0.1 act=block cnf=85";

    const event = parseCef(input) orelse return .{
        .cef_prefix_detected = false,
        .header_8_fields_parsed = false,
        .severity_parsed = false,
        .extensions_parsed = false,
        .cef_parse_ok = false,
    };

    // CEF prefix detected.
    const cef_prefix_detected = event.source_format == .cef;

    // Header fields parsed.
    const header_8_fields_parsed = std.mem.eql(u8, event.vendor, "AEGIS") and
        std.mem.eql(u8, event.product, "NIDS") and
        std.mem.eql(u8, event.dev_version, "1.0") and
        std.mem.eql(u8, event.sig_id, "100") and
        std.mem.eql(u8, event.name, "SQL Injection");

    // Severity parsed (9 -> 9).
    const severity_parsed = event.severity == 9;

    // Extensions parsed (src=, act=, cnf=).
    const extensions_parsed = event.extension_count == 3;

    return .{
        .cef_prefix_detected = cef_prefix_detected,
        .header_8_fields_parsed = header_8_fields_parsed,
        .severity_parsed = severity_parsed,
        .extensions_parsed = extensions_parsed,
        .cef_parse_ok = cef_prefix_detected and header_8_fields_parsed and
            severity_parsed and extensions_parsed,
    };
}

// ============================================================
// LEEF Proof (v5.0 Section 60)
// ============================================================

pub const LeefParseCheck = struct {
    leef_prefix_detected: bool,
    header_5_fields_parsed: bool,
    tab_separated_extensions: bool,
    severity_from_extension: bool,
    leef_parse_ok: bool,

    pub fn isPassed(self: LeefParseCheck) bool {
        return self.leef_parse_ok;
    }
};

/// Verify LEEF parsing.
/// v5.0 Section 60: LEEF format ingestion (IBM QRadar).
pub fn verifyLeefParse() LeefParseCheck {
    // LEEF uses tab (0x09) separators in extension.
    const input = "LEEF:1.0|AEGIS|NIDS|1.0|src=10.0.0.1\tact=block\tsev=9";

    const event = parseLeef(input) orelse return .{
        .leef_prefix_detected = false,
        .header_5_fields_parsed = false,
        .tab_separated_extensions = false,
        .severity_from_extension = false,
        .leef_parse_ok = false,
    };

    // LEEF prefix detected.
    const leef_prefix_detected = event.source_format == .leef;

    // Header fields parsed.
    const header_5_fields_parsed = std.mem.eql(u8, event.vendor, "AEGIS") and
        std.mem.eql(u8, event.product, "NIDS") and
        std.mem.eql(u8, event.dev_version, "1.0");

    // Tab-separated extensions parsed (3 extensions).
    const tab_separated_extensions = event.extension_count == 3;

    // Severity extracted from "sev" extension.
    const severity_from_extension = event.severity == 9;

    return .{
        .leef_prefix_detected = leef_prefix_detected,
        .header_5_fields_parsed = header_5_fields_parsed,
        .tab_separated_extensions = tab_separated_extensions,
        .severity_from_extension = severity_from_extension,
        .leef_parse_ok = leef_prefix_detected and header_5_fields_parsed and
            tab_separated_extensions and severity_from_extension,
    };
}

// ============================================================
// KEY-VALUE Proof (v5.0 Section 61)
// ============================================================

pub const KeyValParseCheck = struct {
    keyval_format_detected: bool,
    space_separated_pairs: bool,
    severity_extracted: bool,
    empty_input_rejected: bool,
    keyval_parse_ok: bool,

    pub fn isPassed(self: KeyValParseCheck) bool {
        return self.keyval_parse_ok;
    }
};

/// Verify KEY-VALUE parsing.
/// v5.0 Section 61: generic key=value ingestion.
pub fn verifyKeyValParse() KeyValParseCheck {
    const input = "src=10.0.0.1 act=block sev=9 rule=100";

    const event = parseKeyVal(input) orelse return .{
        .keyval_format_detected = false,
        .space_separated_pairs = false,
        .severity_extracted = false,
        .empty_input_rejected = false,
        .keyval_parse_ok = false,
    };

    // KEYVAL format detected.
    const keyval_format_detected = event.source_format == .keyval;

    // 4 space-separated pairs parsed.
    const space_separated_pairs = event.extension_count == 4;

    // Severity extracted from "sev" key.
    const severity_extracted = event.severity == 9;

    // Empty input rejected (returns null).
    const empty_event = parseKeyVal("");
    const empty_input_rejected = empty_event == null;

    return .{
        .keyval_format_detected = keyval_format_detected,
        .space_separated_pairs = space_separated_pairs,
        .severity_extracted = severity_extracted,
        .empty_input_rejected = empty_input_rejected,
        .keyval_parse_ok = keyval_format_detected and space_separated_pairs and
            severity_extracted and empty_input_rejected,
    };
}

// ============================================================
// Multi-Format Normalization (v5.0 Section 61) - G16 Exit Gate
// ============================================================
// v5.0: "All 3 formats normalize to a single internal NormalizedEvent type."

pub const NormalizationCheck = struct {
    cef_normalizes: bool,
    leef_normalizes: bool,
    keyval_normalizes: bool,
    all_produce_same_type: bool,
    normalization_ok: bool,

    pub fn isPassed(self: NormalizationCheck) bool {
        return self.normalization_ok;
    }
};

/// Verify all 3 formats normalize to NormalizedEvent.
/// v5.0 Section 61: G16 Exit Gate - multi-format normalization.
pub fn verifyNormalization() NormalizationCheck {
    // Same logical event expressed in 3 formats.
    const cef_input = "CEF:0|AEGIS|NIDS|1.0|100|SQL Injection|9|src=10.0.0.1 act=block";
    const leef_input = "LEEF:1.0|AEGIS|NIDS|1.0|src=10.0.0.1\tact=block\tsev=9";
    const keyval_input = "src=10.0.0.1 act=block sev=9";

    const cef_event = parseCef(cef_input);
    const leef_event = parseLeef(leef_input);
    const keyval_event = parseKeyVal(keyval_input);

    // All 3 parse successfully.
    const cef_normalizes = cef_event != null;
    const leef_normalizes = leef_event != null;
    const keyval_normalizes = keyval_event != null;

    // All produce the same NormalizedEvent type (with source_format distinguishing).
    // Check that severity=9 across all 3 (same logical event).
    const all_produce_same_type = cef_event != null and leef_event != null and
        keyval_event != null and
        cef_event.?.severity == 9 and
        leef_event.?.severity == 9 and
        keyval_event.?.severity == 9 and
        cef_event.?.source_format == .cef and
        leef_event.?.source_format == .leef and
        keyval_event.?.source_format == .keyval;

    return .{
        .cef_normalizes = cef_normalizes,
        .leef_normalizes = leef_normalizes,
        .keyval_normalizes = keyval_normalizes,
        .all_produce_same_type = all_produce_same_type,
        .normalization_ok = cef_normalizes and leef_normalizes and
            keyval_normalizes and all_produce_same_type,
    };
}

// ============================================================
// G16 Report
// ============================================================

pub const G16Report = struct {
    cef_parse_ok: bool,
    leef_parse_ok: bool,
    keyval_parse_ok: bool,
    normalization_ok: bool,

    pub fn isComplete(self: G16Report) bool {
        return self.cef_parse_ok and self.leef_parse_ok and
            self.keyval_parse_ok and self.normalization_ok;
    }
};

pub fn generateReport() G16Report {
    return .{
        .cef_parse_ok = verifyCefParse().isPassed(),
        .leef_parse_ok = verifyLeefParse().isPassed(),
        .keyval_parse_ok = verifyKeyValParse().isPassed(),
        .normalization_ok = verifyNormalization().isPassed(),
    };
}

// ============================================================
// Tests
// ============================================================

test "SourceFormat.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, SourceFormat.cef.toString(), "CEF"));
    try std.testing.expect(std.mem.eql(u8, SourceFormat.leef.toString(), "LEEF"));
    try std.testing.expect(std.mem.eql(u8, SourceFormat.keyval.toString(), "KEYVAL"));
    try std.testing.expect(std.mem.eql(u8, SourceFormat.unknown.toString(), "UNKNOWN"));
}

test "findChar finds delimiter" {
    try std.testing.expect(findChar("hello|world", '|') == 5);
    try std.testing.expect(findChar("hello", '|') == 5); // not found -> len
    try std.testing.expect(findChar("", '|') == 0);
}

test "splitOnce splits at delimiter" {
    const r1 = splitOnce("a|b|c", '|');
    try std.testing.expect(std.mem.eql(u8, r1.before, "a"));
    try std.testing.expect(std.mem.eql(u8, r1.after, "b|c"));

    const r2 = splitOnce("no-delimiter", '|');
    try std.testing.expect(std.mem.eql(u8, r2.before, "no-delimiter"));
    try std.testing.expect(std.mem.eql(u8, r2.after, ""));
}

test "parseKeyValue parses key=value" {
    const ext = parseKeyValue("src=10.0.0.1").?;
    try std.testing.expect(std.mem.eql(u8, ext.key, "src"));
    try std.testing.expect(std.mem.eql(u8, ext.value, "10.0.0.1"));
}

test "parseKeyValue returns null for no equals" {
    try std.testing.expect(parseKeyValue("no-equals") == null);
    try std.testing.expect(parseKeyValue("") == null);
}

test "parseSeverity parses single digit" {
    try std.testing.expect(parseSeverity("0") == 0);
    try std.testing.expect(parseSeverity("5") == 5);
    try std.testing.expect(parseSeverity("9") == 9);
}

test "parseSeverity parses named severity" {
    try std.testing.expect(parseSeverity("low") == 3);
    try std.testing.expect(parseSeverity("medium") == 5);
    try std.testing.expect(parseSeverity("high") == 7);
    try std.testing.expect(parseSeverity("critical") == 9);
}

test "parseSeverity returns 0 for unknown" {
    try std.testing.expect(parseSeverity("") == 0);
    try std.testing.expect(parseSeverity("unknown") == 0);
}

test "parseCef parses valid CEF input" {
    const input = "CEF:0|AEGIS|NIDS|1.0|100|SQL Injection|9|src=10.0.0.1 act=block";
    const event = parseCef(input).?;
    try std.testing.expect(event.source_format == .cef);
    try std.testing.expect(std.mem.eql(u8, event.vendor, "AEGIS"));
    try std.testing.expect(std.mem.eql(u8, event.product, "NIDS"));
    try std.testing.expect(std.mem.eql(u8, event.dev_version, "1.0"));
    try std.testing.expect(std.mem.eql(u8, event.sig_id, "100"));
    try std.testing.expect(std.mem.eql(u8, event.name, "SQL Injection"));
    try std.testing.expect(event.severity == 9);
    try std.testing.expect(event.extension_count == 2);
}

test "parseCef returns null for non-CEF input" {
    try std.testing.expect(parseCef("not CEF") == null);
    try std.testing.expect(parseCef("") == null);
    try std.testing.expect(parseCef("LEEF:1.0|...") == null);
}

test "parseCef parses extensions" {
    const input = "CEF:0|AEGIS|NIDS|1.0|100|Test|5|src=10.0.0.1 act=block cnf=85 rule=R100";
    const event = parseCef(input).?;
    try std.testing.expect(event.extension_count == 4);
    try std.testing.expect(std.mem.eql(u8, event.extensions[0].key, "src"));
    try std.testing.expect(std.mem.eql(u8, event.extensions[0].value, "10.0.0.1"));
    try std.testing.expect(std.mem.eql(u8, event.extensions[1].key, "act"));
    try std.testing.expect(std.mem.eql(u8, event.extensions[1].value, "block"));
}

test "verifyCefParse passes (v5.0 Section 59)" {
    const check = verifyCefParse();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.cef_prefix_detected);
    try std.testing.expect(check.header_8_fields_parsed);
    try std.testing.expect(check.severity_parsed);
    try std.testing.expect(check.extensions_parsed);
}

test "parseLeef parses valid LEEF input" {
    const input = "LEEF:1.0|AEGIS|NIDS|1.0|src=10.0.0.1\tact=block\tsev=9";
    const event = parseLeef(input).?;
    try std.testing.expect(event.source_format == .leef);
    try std.testing.expect(std.mem.eql(u8, event.vendor, "AEGIS"));
    try std.testing.expect(std.mem.eql(u8, event.product, "NIDS"));
    try std.testing.expect(std.mem.eql(u8, event.dev_version, "1.0"));
    try std.testing.expect(event.extension_count == 3);
    try std.testing.expect(event.severity == 9); // from sev= extension
}

test "parseLeef returns null for non-LEEF input" {
    try std.testing.expect(parseLeef("not LEEF") == null);
    try std.testing.expect(parseLeef("") == null);
    try std.testing.expect(parseLeef("CEF:0|...") == null);
}

test "verifyLeefParse passes (v5.0 Section 60)" {
    const check = verifyLeefParse();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.leef_prefix_detected);
    try std.testing.expect(check.header_5_fields_parsed);
    try std.testing.expect(check.tab_separated_extensions);
    try std.testing.expect(check.severity_from_extension);
}

test "parseKeyVal parses valid key=value input" {
    const input = "src=10.0.0.1 act=block sev=9 rule=100";
    const event = parseKeyVal(input).?;
    try std.testing.expect(event.source_format == .keyval);
    try std.testing.expect(event.extension_count == 4);
    try std.testing.expect(event.severity == 9); // from sev= key
}

test "parseKeyVal returns null for empty input" {
    try std.testing.expect(parseKeyVal("") == null);
    try std.testing.expect(parseKeyVal("no key value pairs") == null);
}

test "verifyKeyValParse passes (v5.0 Section 61)" {
    const check = verifyKeyValParse();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.keyval_format_detected);
    try std.testing.expect(check.space_separated_pairs);
    try std.testing.expect(check.severity_extracted);
    try std.testing.expect(check.empty_input_rejected);
}

test "verifyNormalization passes (G16 Exit Gate)" {
    // v5.0 Section 61: "All 3 formats normalize to NormalizedEvent."
    const check = verifyNormalization();
    try std.testing.expect(check.isPassed());
    try std.testing.expect(check.cef_normalizes);
    try std.testing.expect(check.leef_normalizes);
    try std.testing.expect(check.keyval_normalizes);
    try std.testing.expect(check.all_produce_same_type);
}

test "generateReport is complete" {
    const report = generateReport();
    try std.testing.expect(report.cef_parse_ok);
    try std.testing.expect(report.leef_parse_ok);
    try std.testing.expect(report.keyval_parse_ok);
    try std.testing.expect(report.normalization_ok);
    try std.testing.expect(report.isComplete());
}

test "NormalizedEvent extensions are inline (no dangling slice)" {
    // Verify the safety pattern: extensions are stored inline, not as a slice.
    const input = "CEF:0|AEGIS|NIDS|1.0|100|Test|5|src=10.0.0.1 act=block";
    const event = parseCef(input).?;

    // The extensions array is inline (fixed-size [MAX_EXTENSIONS]Extension).
    // Accessing event.extensions[0] should work even after the parser returns
    // because the data lives inside the struct.
    try std.testing.expect(event.extension_count >= 1);
    try std.testing.expect(std.mem.eql(u8, event.extensions[0].key, "src"));
    try std.testing.expect(std.mem.eql(u8, event.extensions[0].value, "10.0.0.1"));
}

test "MAX_EXTENSIONS limits extension count" {
    // Build a CEF event with more than MAX_EXTENSIONS extension pairs.
    // Only the first MAX_EXTENSIONS should be stored.
    const input = "CEF:0|AEGIS|NIDS|1.0|100|Test|5|k1=v1 k2=v2 k3=v3 k4=v4 k5=v5 k6=v6 k7=v7 k8=v8 k9=v9 k10=v10 k11=v11 k12=v12 k13=v13 k14=v14 k15=v15 k16=v16 k17=v17 k18=v18";
    const event = parseCef(input).?;
    try std.testing.expect(event.extension_count == MAX_EXTENSIONS);
}

test "G16 Exit Gate: full SIEM ingestion flow" {
    // v5.0 Section 59-61: ingest from 3 SIEM formats -> normalize -> pipeline
    const cef_input = "CEF:0|Cisco|ASA|9.1|100|Connection Denied|7|src=192.168.1.10 act=deny dst=10.0.0.1";
    const leef_input = "LEEF:1.0|IBM|QRadar|1.0|src=192.168.1.10\tact=deny\tsev=7\tdst=10.0.0.1";
    const keyval_input = "src=192.168.1.10 act=deny sev=7 dst=10.0.0.1";

    // Step 1: parse all 3 formats.
    const cef_event = parseCef(cef_input).?;
    const leef_event = parseLeef(leef_input).?;
    const keyval_event = parseKeyVal(keyval_input).?;

    // Step 2: verify all normalize to severity=7 (same logical event).
    try std.testing.expect(cef_event.severity == 7);
    try std.testing.expect(leef_event.severity == 7);
    try std.testing.expect(keyval_event.severity == 7);

    // Step 3: verify source formats are tracked.
    try std.testing.expect(cef_event.source_format == .cef);
    try std.testing.expect(leef_event.source_format == .leef);
    try std.testing.expect(keyval_event.source_format == .keyval);

    // Step 4: verify extensions are accessible (inline, no dangling slice).
    // CEF: src, act, dst (3 extensions).
    try std.testing.expect(cef_event.extension_count == 3);
    try std.testing.expect(std.mem.eql(u8, cef_event.extensions[0].key, "src"));
    try std.testing.expect(std.mem.eql(u8, cef_event.extensions[0].value, "192.168.1.10"));

    // LEEF: src, act, sev, dst (4 extensions).
    try std.testing.expect(leef_event.extension_count == 4);

    // KEYVAL: src, act, sev, dst (4 extensions).
    try std.testing.expect(keyval_event.extension_count == 4);
}
