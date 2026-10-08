//! Bounded textual armor. Decoded buffers belong to the caller.
const std = @import("std");
const Pem = @This();
text: []const u8,
offset: usize = 0,
pub const Error = error{ InvalidPem, InputLimit, OutOfMemory };
pub const Block = struct {
    label: []const u8,
    der: []u8,
    legacy: bool = false,
    dek: ?[]const u8 = null,
    pub fn deinit(b: *Block, gpa: std.mem.Allocator) void {
        @setRuntimeSafety(true);
        std.crypto.secureZero(u8, b.der);
        gpa.free(b.der);
        b.* = undefined;
    }
};
pub fn init(text: []const u8) Pem {
    @setRuntimeSafety(true);
    return .{ .text = text };
}
pub fn next(it: *Pem, gpa: std.mem.Allocator, max_bytes: usize) Error!?Block {
    @setRuntimeSafety(true);
    const rest = std.mem.trim(u8, it.text[it.offset..], " \t\r\n");
    if (rest.len == 0) return null;
    if (it.text.len > max_bytes) return error.InputLimit;
    const begin = "-----BEGIN ";
    if (!std.mem.startsWith(u8, rest, begin)) return error.InvalidPem;
    const cut = std.mem.find(u8, rest[begin.len..], "-----") orelse return error.InvalidPem;
    const label = rest[begin.len..][0..cut];
    if (label.len == 0 or label.len > 64) return error.InvalidPem;
    const ending = try gpa.print("-----END {s}-----", .{label});
    defer gpa.free(ending);
    const body_start = begin.len + cut + 5;
    const end = std.mem.findPos(u8, rest, body_start, ending) orelse return error.InvalidPem;
    const compact = try gpa.alloc(u8, end - body_start);
    defer {
        std.crypto.secureZero(u8, compact);
        gpa.free(compact);
    }
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
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(compact[0..len]) catch return error.InvalidPem;
    if (size == 0 or size > max_bytes) return error.InputLimit;
    const der = try gpa.alloc(u8, size);
    errdefer {
        std.crypto.secureZero(u8, der);
        gpa.free(der);
    }
    decoder.decode(der, compact[0..len]) catch return error.InvalidPem;
    it.offset = it.text.len - rest.len + end + ending.len;
    return .{ .label = label, .der = der, .legacy = legacy, .dek = dek };
}
test {
    @setRuntimeSafety(true);
    _ = @import("Pem_test.zig");
}
