//! Strict enclosing-length cursor for untrusted TLS fields; no retained owner.
const std = @import("std");
pub const ReadError = error{InvalidLength};
bytes: []const u8,
pos: usize = 0,
const Self = @This();
pub fn take(self: *Self, len: usize) ReadError![]const u8 {
    @setRuntimeSafety(true);
    if (len > self.bytes.len - self.pos) return error.InvalidLength;
    defer self.pos += len;
    return self.bytes[self.pos..][0..len];
}
pub fn int(self: *Self, comptime T: type) ReadError!T {
    @setRuntimeSafety(true);
    const len = @divExact(@bitSizeOf(T), 8);
    return std.mem.readInt(T, (try self.take(len))[0..len], .big);
}
pub fn vector(self: *Self, comptime T: type) ReadError!Self {
    @setRuntimeSafety(true);
    return .{ .bytes = try self.take(try self.int(T)) };
}
pub fn finish(self: Self) ReadError!void {
    if (self.pos != self.bytes.len) return error.InvalidLength;
}
