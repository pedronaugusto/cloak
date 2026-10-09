//! Bounded textual armor. Decoded buffers belong to the caller.
const std = @import("std");
const SecretBytes = @import("aegis").SecretBytes;
const Pem = @This();
const Base64 = @import("Base64.zig");
text: []const u8,
offset: usize = 0,
pub const Error = error{ InvalidPem, InputLimit, OutOfMemory };
pub const Block = struct {
    label: []const u8,
    der: []u8,
    // The slice is a borrow; this descriptor alone owns the full DER allocation.
    storage: SecretBytes,
    legacy: bool = false,
    dek: ?[]const u8 = null,
    pub fn deinit(b: *Block, _: std.mem.Allocator) void {
        @setRuntimeSafety(true);
        b.storage.deinit();
        b.* = undefined;
    }
};
pub fn init(text: []const u8) Pem {
    @setRuntimeSafety(true);
    return .{ .text = text };
}
pub fn next(it: *Pem, gpa: std.mem.Allocator, max_bytes: usize) Error!?Block {
    @setRuntimeSafety(true);
    if (it.text.len > max_bytes) return error.InputLimit;
    const rest = std.mem.trim(u8, it.text[it.offset..], " \t\r\n");
    if (rest.len == 0) return null;
    const begin = "-----BEGIN ";
    if (!std.mem.startsWith(u8, rest, begin)) return error.InvalidPem;
    const cut = std.mem.find(u8, rest[begin.len..], "-----") orelse return error.InvalidPem;
    const label = rest[begin.len..][0..cut];
    if (label.len == 0 or label.len > 64) return error.InvalidPem;
    // Public grammar bounds the marker at 8 + 64 + 5 bytes; no heap owner needed.
    var ending_buffer: [77]u8 = undefined;
    const ending = std.mem.print(&ending_buffer, "-----END {s}-----", .{label}) catch return error.InvalidPem;
    const body_start = begin.len + cut + 5;
    const end = std.mem.findPos(u8, rest, body_start, ending) orelse return error.InvalidPem;
    var compact_owner = try SecretBytes.init(gpa, end - body_start);
    defer compact_owner.deinit();
    compact_owner.resizeWithinCapacity(end - body_start) catch return error.InputLimit;
    const compact = compact_owner.exposeMut();
    var len: usize = 0;
    var legacy = false;
    var dek: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, rest[body_start..end], '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "Proc-Type:")) {
            if (legacy or len != 0 or !std.mem.eql(u8, line, "Proc-Type: 4,ENCRYPTED")) return error.InvalidPem;
            legacy = true;
        } else if (std.mem.startsWith(u8, line, "DEK-Info:")) {
            if (dek != null or len != 0) return error.InvalidPem;
            dek = std.mem.trim(u8, line[9..], " \t");
        } else {
            for (line) |c| {
                if (std.ascii.isWhitespace(c)) continue;
                compact[len] = c;
                len += 1;
            }
        }
    }
    if (legacy != (dek != null)) return error.InvalidPem;
    const size = Base64.size(compact[0..len]) catch return error.InvalidPem;
    if (size == 0 or size > max_bytes) return error.InputLimit;
    var storage = try SecretBytes.init(gpa, size);
    errdefer storage.deinit();
    storage.resizeWithinCapacity(size) catch return error.InputLimit;
    const der = storage.exposeMut();
    Base64.decode(der, compact[0..len]) catch return error.InvalidPem;
    it.offset = it.text.len - rest.len + end + ending.len;
    var block: Block = .{ .label = label, .der = der, .storage = undefined, .legacy = legacy, .dek = dek };
    storage.moveInto(&block.storage);
    return block;
}
test {
    @setRuntimeSafety(true);
    _ = Base64;
    _ = @import("Pem_test.zig");
}
