//! Bounded internal TLS encoder. Output is not leased until construction succeeds.
const std = @import("std");
pub const WriteError = error{BufferTooSmall};
bytes: []u8,
pos: usize = 0,
const Self = @This();
pub fn put(self: *Self, bytes: []const u8) WriteError!void {
    @setRuntimeSafety(true);
    if (bytes.len > self.bytes.len - self.pos) return error.BufferTooSmall;
    @memcpy(self.bytes[self.pos..][0..bytes.len], bytes);
    self.pos += bytes.len;
}
pub fn int(self: *Self, comptime T: type, value: T) WriteError!void {
    var bytes: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try self.put(&bytes);
}
pub fn vector(self: *Self, comptime T: type, bytes: []const u8) WriteError!void {
    @setRuntimeSafety(true);
    if (bytes.len > std.math.maxInt(T)) return error.BufferTooSmall;
    // safe: length was checked against the chosen wire integer's maximum.
    try self.int(T, @intCast(bytes.len));
    try self.put(bytes);
}
