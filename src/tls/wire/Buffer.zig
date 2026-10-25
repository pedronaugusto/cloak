//! A buffer for bytes that may be secret (a record opened in place, a handshake message as it
//! arrives), held by an aegis `SecretBytes` from its first byte: growing keeps what it holds and
//! erases the storage it leaves, and `free` erases it before returning it. Nothing is allocated
//! until the first `ensure`. Its allocator is its holder's, passed in, as aegis's owners take it.
const std = @import("std");
const aegis = @import("aegis");
const Buffer = @This();

owner: aegis.SecretBytes = .empty,

/// The whole allocation; empty before the first `ensure`.
pub fn bytes(self: *Buffer) []u8 {
    return self.owner.exposeMut(); // aegis: design: the buffer's own borrow, as SecretBytes lends it; it ends at the next `ensure` or `free`
}

/// `bytes`, read only.
pub fn view(self: *const Buffer) []const u8 {
    return self.owner.expose(); // aegis: design: as `bytes`
}

/// At least `len` bytes, what the buffer held kept at their offsets.
pub fn ensure(self: *Buffer, gpa: std.mem.Allocator, len: usize) std.mem.Allocator.Error![]u8 {
    @setRuntimeSafety(true);
    try self.owner.reserve(gpa, len);
    // unreachable: the live prefix grows to the capacity it is within.
    self.owner.resizeWithinCapacity(self.owner.capacity()) catch unreachable;
    return self.owner.exposeMut(); // aegis: design: as `bytes`
}

/// Erases and returns the allocation to `gpa`, which made it; the buffer is empty again.
pub fn free(self: *Buffer, gpa: std.mem.Allocator) void {
    self.owner.deinit(gpa);
    self.owner = .empty;
}

test "a buffer keeps its bytes as it grows, and is empty again once freed" {
    const gpa = std.testing.allocator;
    var buffer: Buffer = .{};
    defer buffer.free(gpa);
    try std.testing.expectEqual(@as(usize, 0), buffer.view().len);
    @memcpy((try buffer.ensure(gpa, 4))[0..4], "abcd");
    try std.testing.expectEqual(@as(usize, 4), buffer.view().len);
    const grown = try buffer.ensure(gpa, 100);
    try std.testing.expect(grown.len >= 100);
    try std.testing.expectEqualSlices(u8, "abcd", grown[0..4]);
    try std.testing.expectEqual(grown.len, (try buffer.ensure(gpa, 8)).len);
    buffer.free(gpa);
    try std.testing.expectEqual(@as(usize, 0), buffer.bytes().len);
}
