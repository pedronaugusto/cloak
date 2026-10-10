//! The running handshake hash. Until a hello names the suite both candidate hashes run;
//! the choice then fixes one and erases the other.
const std = @import("std");
const Transcript = @import("Transcript.zig").Transcript;
const Suite = @import("../crypto/Suite.zig").Suite;
const suites = @import("../crypto/Suite.zig");

const Sha256 = Transcript(std.crypto.hash.sha2.Sha256);
const Sha384 = Transcript(std.crypto.hash.sha2.Sha384);

pub const max_digest = std.crypto.hash.sha2.Sha384.digest_length;
pub const CommitError = @import("Transcript.zig").CommitError;

state: union(enum) {
    pending: struct { sha256: Sha256 = .{}, sha384: Sha384 = .{} },
    sha256: Sha256,
    sha384: Sha384,
} = .{ .pending = .{} },

const Self = @This();

/// Fixes the hash once; a later call must name the same hash family.
pub fn select(self: *Self, suite: Suite) void {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => |*both| {
            const hash384 = suites.digestLength(suite) == 48;
            const keep = both.*;
            std.crypto.secureZero(u8, std.mem.asBytes(&self.state));
            self.state = if (hash384) .{ .sha384 = keep.sha384 } else .{ .sha256 = keep.sha256 };
        },
        .sha256 => std.debug.assert(suites.digestLength(suite) == 32),
        .sha384 => std.debug.assert(suites.digestLength(suite) == 48),
    }
}

pub fn commit(self: *Self, message: []const u8) CommitError!void {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => |*both| {
            try both.sha256.commit(message);
            try both.sha384.commit(message);
        },
        .sha256 => |*t| try t.commit(message),
        .sha384 => |*t| try t.commit(message),
    }
}

/// Replaces the ClientHello by its synthetic message_hash and commits the retry request.
pub fn retry(self: *Self, hrr: []const u8) CommitError!void {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => unreachable, // the suite is selected before a retry request is committed
        .sha256 => |*t| try t.retry(hrr),
        .sha384 => |*t| try t.retry(hrr),
    }
}

/// Digest of everything committed so far; only meaningful once the hash is selected.
pub fn digest(self: *const Self, out: *[max_digest]u8) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => unreachable, // callers digest only after the suite is known
        .sha256 => |t| {
            const d = t.digest();
            out[0..d.len].* = d;
            return out[0..d.len];
        },
        .sha384 => |t| {
            const d = t.digest();
            out[0..d.len].* = d;
            return out[0..d.len];
        },
    }
}

test "C2 transcripts select the suite hash and erase the other" {
    var transcripts: Self = .{};
    try transcripts.commit("\x01\x00\x00\x02hi");
    transcripts.select(.aes_256_gcm_sha384);
    var out: [max_digest]u8 = undefined;
    var expected: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("\x01\x00\x00\x02hi", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, transcripts.digest(&out));
    var other: Self = .{};
    try other.commit("\x01\x00\x00\x02hi");
    other.select(.chacha20_poly1305_sha256);
    var short: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("\x01\x00\x00\x02hi", &short, .{});
    try std.testing.expectEqualSlices(u8, &short, other.digest(&out));
}
