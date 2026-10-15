//! The replay window of one receiving epoch (RFC 9147 section 4.5.1, RFC 4303 section 3.4.3): the
//! highest authenticated record sequence and which of the 127 before it arrived. A record is
//! checked before it is opened and marked only after it authenticates, so a forgery moves nothing.
const std = @import("std");
const aegis = @import("aegis");

const Window = @This();

pub const size = 128;

/// The highest sequence marked; null before the first.
highest: ?u64 = null,
/// Bit i: sequence `highest - i` was marked.
seen: u128 = 0,

/// Whether `sequence` may still be accepted: right of the window, or inside it and unseen.
pub fn fresh(self: *const Window, sequence: u64) bool {
    const top = self.highest orelse return true;
    if (sequence > top) return true;
    const behind = top - sequence;
    if (behind >= size) return false;
    return self.seen & (@as(u128, 1) << @intCast(behind)) == 0;
}

/// Records an authenticated `sequence`, which `fresh` admitted.
pub fn mark(self: *Window, sequence: u64) void {
    const top = self.highest orelse {
        self.highest = sequence;
        self.seen = 1;
        return;
    };
    if (sequence > top) {
        const ahead = sequence - top;
        self.seen = if (ahead >= size) 1 else (self.seen << @intCast(ahead)) | 1;
        self.highest = sequence;
        return;
    }
    const behind = top - sequence;
    aegis.assert.invariant(behind < size, "a record behind the top is within the window");
    self.seen |= @as(u128, 1) << @intCast(behind);
}

/// The full sequence a received low part most likely names: the one with these low `bits` bits
/// closest to one past the highest marked (RFC 9147 section 4.2.2).
pub fn reconstruct(self: *const Window, low: u64, bits: u6) u64 {
    const expected = if (self.highest) |top| top +% 1 else 0;
    const span = @as(u64, 1) << bits;
    const mask = span - 1;
    const base = expected & ~mask;
    var candidate = base | (low & mask);
    // Pick among the candidate, one span below and one above, the nearest to `expected`.
    if (candidate > expected and candidate - expected > span / 2 and candidate >= span) {
        candidate -= span;
    } else if (candidate < expected and expected - candidate > span / 2 and candidate <= std.math.maxInt(u64) - span) {
        candidate += span;
    }
    return candidate;
}

test "C8 the replay window admits new records once and nothing it has slid past" {
    var window: Window = .{};
    try std.testing.expect(window.fresh(5));
    window.mark(5);
    try std.testing.expect(!window.fresh(5));
    try std.testing.expect(window.fresh(4));
    try std.testing.expect(window.fresh(6));
    window.mark(200);
    try std.testing.expect(!window.fresh(5));
    try std.testing.expect(!window.fresh(72));
    try std.testing.expect(window.fresh(73));
    window.mark(73);
    try std.testing.expect(!window.fresh(73));
    try std.testing.expect(!window.fresh(200));
    try std.testing.expect(window.fresh(199));
    window.mark(std.math.maxInt(u64));
    try std.testing.expect(!window.fresh(std.math.maxInt(u64)));
    try std.testing.expect(!window.fresh(199));
}

test "C8 a truncated record number is read as the nearest one past the highest" {
    var window: Window = .{};
    try std.testing.expectEqual(@as(u64, 3), window.reconstruct(3, 16));
    window.mark(0xfffe);
    try std.testing.expectEqual(@as(u64, 0x1_0002), window.reconstruct(2, 16));
    try std.testing.expectEqual(@as(u64, 0xfff0), window.reconstruct(0xfff0, 16));
    window.mark(0x1_0005);
    try std.testing.expectEqual(@as(u64, 0xffff), window.reconstruct(0xff, 8));
    try std.testing.expectEqual(@as(u64, 0x1_0001), window.reconstruct(0x01, 8));
}
