//! One direction's record protection for whichever suite was negotiated.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Epoch = @import("Epoch.zig");
const Suite = suites.Suite;

pub const Limits = Epoch.Limits;
pub const Content = Epoch.Content;
pub const Plaintext = Epoch.Plaintext;
pub const InitError = Epoch.InitError;
pub const SealError = Epoch.SealError;
pub const OpenError = Epoch.OpenError;
pub const UpdateError = Epoch.Epoch(.aes_128_gcm_sha256).UpdateError;

const Protection = @This();

state: union(Suite) {
    aes_128_gcm_sha256: Epoch.Epoch(.aes_128_gcm_sha256),
    aes_256_gcm_sha384: Epoch.Epoch(.aes_256_gcm_sha384),
    chacha20_poly1305_sha256: Epoch.Epoch(.chacha20_poly1305_sha256),
},

/// Keys derived from a traffic secret of the suite's hash length; the copy is erased.
pub fn init(suite: Suite, secret: []const u8, limits: Limits) InitError!Protection {
    @setRuntimeSafety(true);
    switch (suite) {
        inline else => |tag| {
            const Hash = suites.Hash(tag);
            std.debug.assert(secret.len == Hash.digest_length);
            var holder = aegis.Secret([Hash.digest_length]u8).init(secret[0..Hash.digest_length].*);
            defer holder.deinit();
            return .{ .state = @unionInit(@FieldType(Protection, "state"), @tagName(tag), try Epoch.Epoch(tag).initTraffic(&holder, limits)) };
        },
    }
}

pub fn seal(self: *Protection, content: Content, input: []const u8, padding: usize, out: []u8) SealError![]u8 {
    @setRuntimeSafety(true);
    return switch (self.state) {
        inline else => |*e| e.seal(content, input, padding, out),
    };
}

pub fn open(self: *Protection, wire: []const u8, out: []u8) OpenError!Plaintext {
    @setRuntimeSafety(true);
    return switch (self.state) {
        inline else => |*e| e.open(wire, out),
    };
}

pub fn update(self: *Protection) UpdateError!void {
    @setRuntimeSafety(true);
    switch (self.state) {
        inline else => |*e| try e.update(),
    }
}

/// Records and plaintext bytes still available before the epoch must be replaced.
pub fn remaining(self: *const Protection) struct { records: u64, bytes: u64 } {
    @setRuntimeSafety(true);
    return switch (self.state) {
        inline else => |*e| .{
            .records = e.limits.records.raw() -| e.sequence.raw(),
            .bytes = e.limits.bytes.raw() -| e.bytes.raw(),
        },
    };
}

pub fn closed(self: *const Protection) bool {
    return switch (self.state) {
        inline else => |*e| e.closed,
    };
}

pub fn negotiated(self: *const Protection) Suite {
    return std.meta.activeTag(self.state);
}

pub fn deinit(self: *Protection) void {
    @setRuntimeSafety(true);
    switch (self.state) {
        inline else => |*e| e.deinit(),
    }
}
