//! Every ID, including unknown and GREASE, participates in duplicate rejection, however many
//! extensions a block holds (a 64 KiB block holds up to 16,383). The first 64 IDs are checked
//! against a table as they come; a block with more is checked whole once, 4,096 IDs at a time
//! in a 512-byte bit set, sixteen passes: linear in the block, with bounded memory. The same
//! walk serves any list of entries tagged by a unique u16 with a u16 length: a key_share list
//! (RFC 8446 section 4.2.8) is one.
const std = @import("std");
const R = @import("../../wire/Reader.zig");
pub const Extension = struct { id: u16, bytes: []const u8 };
pub const NextError = R.ReadError || error{DuplicateExtension};
reader: R,
seen: [64]u16 = undefined,
count: usize = 0,
/// The whole block was checked: no ID repeats in it.
unique: bool = false,
const Self = @This();
pub fn next(self: *Self) NextError!?Extension {
    @setRuntimeSafety(true);
    if (self.reader.pos == self.reader.bytes.len) return null;
    if (self.count == self.seen.len and !self.unique) {
        try uniqueBlock(self.reader.bytes);
        self.unique = true;
    }
    const id = try self.reader.int(u16);
    const bytes = (try self.reader.vector(u16)).bytes;
    if (!self.unique) {
        for (self.seen[0..self.count]) |old| if (id == old) return error.DuplicateExtension;
        self.seen[self.count] = id;
    }
    self.count += 1;
    return .{ .id = id, .bytes = bytes };
}
/// Whether an ID repeats among the block's well-formed entries; a malformed tail is left to
/// `next`, which refuses it when it gets there.
fn uniqueBlock(block: []const u8) error{DuplicateExtension}!void {
    @setRuntimeSafety(true);
    for (0..16) |high| {
        var ids: std.bit_set.Static(4096) = .empty;
        var r: R = .{ .bytes = block };
        while (r.pos < block.len) {
            const id = r.int(u16) catch break;
            _ = r.vector(u16) catch break;
            if (id >> 12 != high) continue;
            if (ids.isSet(id & 0xfff)) return error.DuplicateExtension;
            ids.set(id & 0xfff);
        }
    }
}
test {
    _ = @import("Extensions_test.zig");
}
