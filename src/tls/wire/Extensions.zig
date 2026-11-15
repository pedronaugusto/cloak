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
/// A block's well-formed entries in order, from `pos`: the scan ends at the block's end or at the
/// first entry that is not whole, with nothing to refuse. For a block already checked (a parsed
/// hello's, one cloak wrote) or a pass that leaves a malformed tail to `next`.
pub const Scan = struct {
    bytes: []const u8,
    /// Where the next entry starts.
    pos: usize = 0,

    pub fn next(self: *Scan) ?Extension {
        @setRuntimeSafety(true);
        const rest = self.bytes[self.pos..];
        if (rest.len < 4) return null;
        const len = std.mem.readInt(u16, rest[2..4], .big);
        if (rest.len - 4 < len) return null;
        self.pos += 4 + len;
        return .{ .id = std.mem.readInt(u16, rest[0..2], .big), .bytes = rest[4..][0..len] };
    }
};
/// Whether an ID repeats among the block's well-formed entries; a malformed tail is left to
/// `next`, which refuses it when it gets there.
fn uniqueBlock(block: []const u8) error{DuplicateExtension}!void {
    @setRuntimeSafety(true);
    for (0..16) |high| {
        var ids: std.bit_set.Static(4096) = .empty;
        var scan: Scan = .{ .bytes = block };
        while (scan.next()) |entry| {
            if (entry.id >> 12 != high) continue;
            if (ids.isSet(entry.id & 0xfff)) return error.DuplicateExtension;
            ids.set(entry.id & 0xfff);
        }
    }
}
test {
    _ = @import("Extensions_test.zig");
}
