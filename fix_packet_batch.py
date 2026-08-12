"""
Fix PacketBatch stack overflow by converting fixed arrays to heap-allocated slices.

Also finds constants CAPTURE_BATCH_SIZE, MAX_PAYLOAD_SIZE, etc.

Usage on Windows:
    python fix_packet_batch.py
"""

import os
import re

FILE = r"D:\NIDs_Windows\nids_capture.zig"


def find_constants(content: str) -> dict:
    """Find all constant definitions in the file."""
    consts = {}
    # Match: const NAME = value  or  pub const NAME = value
    pattern = re.compile(r'(?:pub\s+)?const\s+(\w+)\s*=\s*(\d+)')
    for m in pattern.finditer(content):
        consts[m.group(1)] = int(m.group(2))
    return consts


def fix(filepath: str) -> None:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content
    changes = []

    # First, show constants
    consts = find_constants(content)
    print("Constants found:")
    interesting = ['CAPTURE_BATCH_SIZE', 'MAX_PAYLOAD_SIZE', 'AHOCORASICK_MAX_STATES',
                   'AHOCORASICK_ALPHABET', 'MAX_PATTERN_MATCHES']
    for name in interesting:
        if name in consts:
            print(f"  {name} = {consts[name]}")
        else:
            print(f"  {name} = NOT FOUND (checking file...)")

    # Show ALL constants with values >= 64
    print("\nAll constants >= 64:")
    for name, val in sorted(consts.items(), key=lambda x: -x[1]):
        if val >= 64:
            print(f"  {name} = {val}")

    # =============================================
    # Fix 1: PacketBatch struct fields
    # =============================================

    # metas: [CAPTURE_BATCH_SIZE]AegisPktMeta -> metas: []AegisPktMeta
    old = 'metas: [CAPTURE_BATCH_SIZE]AegisPktMeta'
    new = 'metas: []AegisPktMeta'
    if old in content:
        content = content.replace(old, new)
        changes.append("PacketBatch.metas: fixed array -> slice")

    # payloads: [CAPTURE_BATCH_SIZE][MAX_PAYLOAD_SIZE]u8 -> payloads: [][MAX_PAYLOAD_SIZE]u8
    old = 'payloads: [CAPTURE_BATCH_SIZE][MAX_PAYLOAD_SIZE]u8'
    new = 'payloads: [][MAX_PAYLOAD_SIZE]u8'
    if old in content:
        content = content.replace(old, new)
        changes.append("PacketBatch.payloads: fixed array -> slice")

    # payload_lens: [CAPTURE_BATCH_SIZE]u32 -> payload_lens: []u32
    old = 'payload_lens: [CAPTURE_BATCH_SIZE]u32'
    new = 'payload_lens: []u32'
    if old in content:
        content = content.replace(old, new)
        changes.append("PacketBatch.payload_lens: fixed array -> slice")

    # Add allocator field to PacketBatch
    old_pb_struct = '''pub const PacketBatch = struct {
    metas: []AegisPktMeta,
    payloads: [][MAX_PAYLOAD_SIZE]u8,
    payload_lens: []u32,
    count: usize,'''

    new_pb_struct = '''pub const PacketBatch = struct {
    metas: []AegisPktMeta,
    payloads: [][MAX_PAYLOAD_SIZE]u8,
    payload_lens: []u32,
    count: usize,
    allocator: std.mem.Allocator,'''

    if old_pb_struct in content:
        content = content.replace(old_pb_struct, new_pb_struct)
        changes.append("PacketBatch: added allocator field")

    # =============================================
    # Fix 2: PacketBatch.init() - allocate on heap
    # =============================================

    old_init = '''    fn init() PacketBatch {
        return .{
            .metas = undefined,
            .payloads = undefined,
            .payload_lens = undefined,
            .count = 0,
        };
    }'''

    new_init = '''    fn init(allocator: std.mem.Allocator) !PacketBatch {
        return .{
            .metas = try allocator.alloc(AegisPktMeta, CAPTURE_BATCH_SIZE),
            .payloads = try allocator.alloc([MAX_PAYLOAD_SIZE]u8, CAPTURE_BATCH_SIZE),
            .payload_lens = try allocator.alloc(u32, CAPTURE_BATCH_SIZE),
            .count = 0,
            .allocator = allocator,
        };
    }'''

    if old_init in content:
        content = content.replace(old_init, new_init)
        changes.append("PacketBatch.init(): stack alloc -> heap alloc")
    else:
        print("[WARN] PacketBatch.init() exact match not found, trying flexible...")
        # Try flexible match
        pb_init_pattern = re.compile(
            r'fn init\(\)\s*PacketBatch\s*\{[^}]*?\.metas\s*=\s*undefined[^}]*?\.payloads\s*=\s*undefined[^}]*?\.payload_lens\s*=\s*undefined[^}]*?\.count\s*=\s*0[^}]*?\}[;\s]*',
            re.DOTALL
        )
        m = pb_init_pattern.search(content)
        if m:
            content = content[:m.start()] + new_init + content[m.end():]
            changes.append("PacketBatch.init(): stack alloc -> heap alloc (flexible)")
        else:
            print("[WARN] Could not auto-fix PacketBatch.init()")

    # =============================================
    # Fix 3: Add PacketBatch.deinit()
    # =============================================

    old_reset = '''    fn reset(self: *PacketBatch) void {
        self.count = 0;
    }'''

    new_reset_and_deinit = '''    fn reset(self: *PacketBatch) void {
        self.count = 0;
    }

    fn deinit(self: *PacketBatch) void {
        self.allocator.free(self.metas);
        self.allocator.free(self.payloads);
        self.allocator.free(self.payload_lens);
    }'''

    if old_reset in content:
        content = content.replace(old_reset, new_reset_and_deinit)
        changes.append("PacketBatch: added deinit() method")

    # =============================================
    # Fix 4: Update CaptureEngine.init() call
    # =============================================

    # .batch = PacketBatch.init()  ->  .batch = try PacketBatch.init(allocator)
    old_call = '.batch = PacketBatch.init()'
    new_call = '.batch = try PacketBatch.init(allocator)'
    if old_call in content:
        content = content.replace(old_call, new_call)
        changes.append("CaptureEngine.init(): PacketBatch.init() -> try PacketBatch.init(allocator)")

    # =============================================
    # Fix 5: Update CaptureEngine.deinit() if it exists
    # =============================================

    # Look for CaptureEngine deinit and add batch.deinit() call
    # This is harder to do automatically, let's look for the pattern
    ce_deinit_pattern = re.compile(r'(fn deinit\(self:\s*\*CaptureEngine\)\s*void\s*\{)(.*?)(\n\s*\})', re.DOTALL)
    m = ce_deinit_pattern.search(content)
    if m:
        body = m.group(2)
        if 'batch' not in body or 'deinit' not in body:
            new_body = '\n        self.batch.deinit();' + body
            content = content[:m.start()] + m.group(1) + new_body + m.group(3) + content[m.end():]
            changes.append("CaptureEngine.deinit(): added self.batch.deinit()")

    # =============================================
    # Fix 6: Also fix g_engine assignment pattern
    # =============================================
    # g_engine = try CaptureEngine.init(allocator, patterns);
    # This should be fine since CaptureEngine.init() now returns by value
    # and with NRVO the struct is constructed in g_engine directly.

    if content == original and not changes:
        print("[WARN] No changes applied!")
        return

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n[FIXED] {os.path.basename(filepath)}:")
    for c in changes:
        print(f"  - {c}")


def main():
    print("=" * 65)
    print("Fix PacketBatch Stack Overflow")
    print()
    print("PROBLEM: PacketBatch has huge embedded arrays:")
    print("  payloads: [BATCH_SIZE][MAX_PAYLOAD]u8  (e.g. 64x65535 = 4MB)")
    print()
    print("FIX: Convert to heap-allocated slices")
    print("=" * 65)
    print()

    if not os.path.exists(FILE):
        print(f"[ERROR] File not found: {FILE}")
        return

    fix(FILE)
    print("\nDone! Now run:  zig build run")


if __name__ == '__main__':
    main()
