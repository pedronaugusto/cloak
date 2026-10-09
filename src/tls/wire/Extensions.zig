//! Every ID, including unknown and GREASE, participates in duplicate rejection.
const R = @import("Reader.zig");
pub const Extension = struct { id: u16, bytes: []const u8 };
pub const NextError = R.ReadError || error{ DuplicateExtension, ExtensionLimit };
reader: R,
seen: [64]u16 = undefined,
count: usize = 0,
const Self = @This();
pub fn next(self: *Self) NextError!?Extension {
    @setRuntimeSafety(true);
    if (self.reader.pos == self.reader.bytes.len) return null;
    if (self.count == self.seen.len) return error.ExtensionLimit;
    const id = try self.reader.int(u16);
    const bytes = (try self.reader.vector(u16)).bytes;
    for (self.seen[0..self.count]) |old| if (id == old) return error.DuplicateExtension;
    self.seen[self.count] = id;
    self.count += 1;
    return .{ .id = id, .bytes = bytes };
}
test {
    _ = @import("Extensions_test.zig");
}
