//! The running handshake hash. Until a hello names the suite both candidate hashes run;
//! the choice then fixes one and erases the other.
const std = @import("std");
const Transcript = @import("Transcript.zig").Transcript;
const Suite13 = @import("../crypto/Suite.zig").Suite13;
const suites = @import("../crypto/Suite.zig");

const Sha256 = Transcript(std.crypto.hash.sha2.Sha256);
const Sha384 = Transcript(std.crypto.hash.sha2.Sha384);

pub const max_digest = std.crypto.hash.sha2.Sha384.digest_length;
pub const CommitError = @import("Transcript.zig").CommitError || std.mem.Allocator.Error;

/// Keeps every message committed from now on, as well as hashing it.
pub fn keep(self: *Self, gpa: std.mem.Allocator) void {
    self.keeper = gpa;
}

/// Every message kept so far, in order.
pub fn keptBytes(self: *const Self) []const u8 {
    return self.kept.items;
}

/// Erases and frees the kept messages and stops keeping.
pub fn release(self: *Self) void {
    @setRuntimeSafety(true);
    const gpa = self.keeper orelse return;
    std.crypto.secureZero(u8, self.kept.allocatedSlice());
    self.kept.deinit(gpa);
    self.kept = .empty;
    self.keeper = null;
}

state: union(enum) {
    pending: struct { sha256: Sha256 = .{}, sha384: Sha384 = .{} },
    sha256: Sha256,
    sha384: Sha384,
} = .{ .pending = .{} },
/// The messages themselves, kept while `keeper` is set: a TLS 1.2 CertificateVerify by Ed25519
/// signs the handshake messages, not a digest of them (RFC 8422 section 5.10).
kept: std.ArrayList(u8) = .empty,
keeper: ?std.mem.Allocator = null,

const Self = @This();

/// Fixes the hash once; a later call must name the same hash family. TLS 1.3 needs no messages
/// kept.
pub fn select(self: *Self, suite: Suite13) void {
    @setRuntimeSafety(true);
    self.release();
    switch (self.state) {
        .pending => |*both| {
            const hash384 = suites.digestLength(suite) == 48;
            const hashes = both.*;
            std.crypto.secureZero(u8, std.mem.asBytes(&self.state));
            self.state = if (hash384) .{ .sha384 = hashes.sha384 } else .{ .sha256 = hashes.sha256 };
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
    // The transcript's own bounds, checked above, hold the kept bytes to the handshake limit.
    if (self.keeper) |gpa| try self.kept.appendSlice(gpa, message);
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

/// Digest of everything committed so far under the hash of `len` bytes (32 or 48). TLS 1.2
/// keeps both hashes running: its PRF hash and a CertificateVerify's hash can differ.
pub fn digestOf(self: *const Self, out: *[max_digest]u8, len: usize) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => |both| {
            if (len == 48) {
                out.* = both.sha384.digest();
                return out[0..48];
            }
            std.debug.assert(len == 32);
            out[0..32].* = both.sha256.digest();
            return out[0..32];
        },
        else => {
            const d = self.digest(out);
            std.debug.assert(d.len == len);
            return d;
        },
    }
}

/// Digest under the hash of `len` bytes of everything committed so far followed by `extra`, which
/// is not committed: a ClientHello up to its PSK binders, which the binders themselves cover.
pub fn digestWith(self: *const Self, out: *[max_digest]u8, len: usize, extra: []const u8) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state) {
        .pending => |*both| return if (len == 48) finishWith(Sha384, &both.sha384, out, extra) else finishWith(Sha256, &both.sha256, out, extra),
        .sha256 => |*t| {
            std.debug.assert(len == 32);
            return finishWith(Sha256, t, out, extra);
        },
        .sha384 => |*t| {
            std.debug.assert(len == 48);
            return finishWith(Sha384, t, out, extra);
        },
    }
}

fn finishWith(comptime T: type, transcript: *const T, out: *[max_digest]u8, extra: []const u8) []const u8 {
    var hash = transcript.hash;
    hash.update(extra);
    const n = @TypeOf(hash).digest_length;
    hash.final(out[0..n]);
    return out[0..n];
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
