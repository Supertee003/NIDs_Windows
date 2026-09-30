from pathlib import Path
import re

path = Path('src/control/handler_registry.zig')
text = path.read_text(encoding='utf-8-sig')

replacement = r'''    fn forensicsList(a: std.mem.Allocator, payload: std.json.Value, _: *HandlerContext) ?[]const u8 {
        const requested_source = payloadU64(payload, "source");
        const requested_prefix: []const u8 = if (payload == .object) blk: {
            if (payload.object.get("payload_prefix")) |value| {
                break :blk switch (value) {
                    .string => |s| s,
                    else => "",
                };
            }
            break :blk "";
        } else "";

        const requested_limit: u64 = @min(
            payloadU64(payload, "limit") orelse 100,
            1000,
        );
        const requested_after = payloadU64(payload, "after");

        const ring = state_mod.g_forensic_ring orelse
            return "{\"available\":false,\"records\":[],\"records_returned\":0,\"integrity\":\"unavailable\",\"verified\":false}";

        const count = ring.recordCount();
        const slots = ring.capacity() / forensic_pipeline.RECORD_BYTES;
        const oldest: u64 = if (count > slots) count - slots else 0;
        const chain_verified = ring.verifyHashChain();

        var out = std.ArrayList(u8).init(a);
        errdefer out.deinit();
        var writer = out.writer();

        writer.writeAll("{\"available\":true,\"records\":[") catch return null;
        var returned: u64 = 0;
        var index = oldest;
        var first = true;

        while (index < count and returned < requested_limit) : (index += 1) {
            const record = ring.readRecord(index, a) orelse continue;
            defer a.free(record);

            if (record.len < forensic_pipeline.HEADER_BYTES) continue;
            if (!forensic_pipeline.ForensicRing.verifyRecord(record)) continue;

            const header = std.mem.bytesAsValue(
                forensic_pipeline.RecordHeader,
                record[0..forensic_pipeline.HEADER_BYTES],
            );

            if (requested_after) |after| {
                if (header.record_seq <= after) continue;
            }

            if (requested_source) |source| {
                if (source > std.math.maxInt(u8) or
                    header.reserved[6] != @as(u8, @intCast(source))) continue;
            }

            const payload_start = forensic_pipeline.HEADER_BYTES;
            const payload_end = payload_start + @as(usize, header.payload_len);
            if (payload_end > record.len) continue;

            if (requested_prefix.len > 0 and
                (requested_prefix.len > @as(usize, header.payload_len) or
                !std.mem.eql(u8, record[payload_start .. payload_start + requested_prefix.len], requested_prefix))) continue;

            if (!first) writer.writeByte(',') catch return null;
            first = false;
            writer.print(
                "{{\"record_seq\":{},\"event_id\":{},\"rule_id\":{},\"source\":{},\"payload_len\":{},\"verified\":true}}",
                .{
                    header.record_seq,
                    header.ev_id,
                    header.rule_id,
                    header.reserved[6],
                    header.payload_len,
                },
            ) catch return null;
            returned += 1;
        }

        writer.print(
            "],\"records_returned\":{},\"integrity\":\"{s}\",\"verified\":{}}}",
            .{
                returned,
                if (chain_verified) "ok" else "failed",
                chain_verified,
            },
        ) catch return null;

        return out.toOwnedSlice() catch null;
    }

'''

pattern = re.compile(r'(?ms)^    fn forensicsList\(.*?^    fn forensicsShow\(')
match = pattern.search(text)
if not match:
    raise SystemExit('FORENSICS_LIST_FUNCTION_NOT_FOUND')

replacement_with_next = replacement + '    fn forensicsShow('
text = text[:match.start()] + replacement_with_next + text[match.end():]
path.write_text(text, encoding='utf-8', newline='')
print('PATCH_OK: Zig forensicsList now returns bounded verified records array')
