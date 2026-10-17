//! One direction's record protection for whichever version and suite was negotiated.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Epoch = @import("Epoch.zig");
const Epoch12 = @import("Epoch12.zig").Epoch12;
const Suite13 = suites.Suite13;
const Keys = @import("../offload/Keys.zig");

pub const Limits = Epoch.Limits;
pub const Content = Epoch.Content;
pub const Plaintext = Epoch.Plaintext;
pub const InitError = Epoch.InitError;
pub const SealError = Epoch.SealError;
pub const OpenError = Epoch.OpenError;
pub const TrialError = Epoch.TrialError;
pub const Owner = Epoch.Owner;
pub const UpdateError = Epoch.Epoch(.aes_128_gcm_sha256).UpdateError || error{NoKeyUpdate};

/// The most bytes protection adds around a plaintext fragment in either version.
pub const max_overhead = 5 + 8 + 16 + 1;

const Protection = @This();

state: union(enum) {
    aes_128_gcm_sha256: Epoch.Epoch(.aes_128_gcm_sha256),
    aes_256_gcm_sha384: Epoch.Epoch(.aes_256_gcm_sha384),
    chacha20_poly1305_sha256: Epoch.Epoch(.chacha20_poly1305_sha256),
    aes_128_ccm_sha256: Epoch.Epoch(.aes_128_ccm_sha256),
    tls12_aes_128_gcm: Epoch12(.aes_128_gcm),
    tls12_aes_256_gcm: Epoch12(.aes_256_gcm),
    tls12_chacha20_poly1305: Epoch12(.chacha20_poly1305),
    tls12_aes_128_ccm: Epoch12(.aes_128_ccm),
    tls12_aes_256_ccm: Epoch12(.aes_256_ccm),
    tls12_aes_128_ccm_8: Epoch12(.aes_128_ccm_8),
},

/// TLS 1.3 keys derived from a traffic secret of the suite's hash length; the copy is erased.
pub fn init(suite: Suite13, secret: []const u8, limits: Limits) InitError!Protection {
    @setRuntimeSafety(true);
    switch (suite) {
        inline else => |tag| {
            const Hash = suites.Hash(tag);
            aegis.assert.invariant(secret.len == Hash.digest_length, "a traffic secret is the suite's hash length");
            var holder = aegis.Secret([Hash.digest_length]u8).init(secret[0..Hash.digest_length].*);
            defer holder.deinit();
            return .{ .state = @unionInit(@FieldType(Protection, "state"), @tagName(tag), try Epoch.Epoch(tag).initTraffic(&holder, limits)) };
        },
    }
}

/// TLS 1.2 keys from the key block: the cipher's key and fixed IV.
pub fn init12(cipher: suites.Cipher, key: []const u8, iv: []const u8, limits: Limits) InitError!Protection {
    @setRuntimeSafety(true);
    switch (cipher) {
        inline else => |tag| {
            const E = Epoch12(tag);
            aegis.assert.invariant(key.len == E.key_length and iv.len == E.iv_length, "TLS 1.2 keys are the cipher's lengths");
            return .{ .state = @unionInit(@FieldType(Protection, "state"), "tls12_" ++ @tagName(tag), try E.init(key[0..E.key_length], iv[0..E.iv_length], limits)) };
        },
    }
}

/// Whether this protects TLS 1.2 records.
pub fn tls12(self: *const Protection) bool {
    return switch (self.state) {
        .tls12_aes_128_gcm, .tls12_aes_256_gcm, .tls12_chacha20_poly1305, .tls12_aes_128_ccm, .tls12_aes_256_ccm, .tls12_aes_128_ccm_8 => true,
        else => false,
    };
}

/// Who seals or opens this direction's records now.
pub fn owner(self: *const Protection) Owner {
    return switch (self.state) {
        inline else => |*e| e.owner,
    };
}

/// The cipher a kernel would run for these records; null when no kernel record layer has it.
pub fn kernelCipher(self: *const Protection) ?Keys.Cipher {
    return switch (self.state) {
        inline else => |_, tag| comptime Keys.Cipher.of(cipherOfTag(tag)),
    };
}

/// Copies the version, cipher, keys and next record number into `keys`; `release` gives them
/// up once a kernel holds them. The cipher must be one `kernelCipher` names.
pub fn exportKeys(self: *const Protection, keys: *Keys) void {
    @setRuntimeSafety(true);
    const cipher = self.kernelCipher();
    aegis.assert.pre(cipher != null, "keys are exported only for a cipher a kernel runs");
    keys.cipher = cipher.?;
    keys.version = if (self.tls12()) .tls12 else .tls13;
    switch (self.state) {
        inline else => |*e| e.exportKeys(keys),
    }
}

/// The number of the next record: sealed or opened here, or counted by the kernel.
pub fn records(self: *const Protection) u64 {
    return switch (self.state) {
        inline else => |*e| e.sequence.raw(),
    };
}

/// The epoch's record limit.
pub fn recordLimit(self: *const Protection) u64 {
    return switch (self.state) {
        inline else => |*e| e.limits.records.raw(),
    };
}

/// Erases the keys a kernel now holds; the kernel seals or opens from here.
pub fn release(self: *Protection) void {
    switch (self.state) {
        inline else => |*e| e.release(),
    }
}

/// The kernel's record count under the keys it holds, read from it, for the budget.
pub fn account(self: *Protection, count: u64) void {
    switch (self.state) {
        inline else => |*e| e.account(count),
    }
}

fn cipherOfTag(comptime tag: @typeInfo(@FieldType(Protection, "state")).@"union".tag_type.?) suites.Cipher {
    const name = @tagName(tag);
    if (comptime std.mem.startsWith(u8, name, "tls12_")) return @field(suites.Cipher, name["tls12_".len..]);
    return suites.cipherOf(@field(Suite13, name));
}

pub fn seal(self: *Protection, content: Content, input: []const u8, padding: usize, out: []u8) SealError![]u8 {
    @setRuntimeSafety(true);
    switch (self.state) {
        inline else => |*e, tag| {
            if (comptime std.mem.startsWith(u8, @tagName(tag), "tls12_")) {
                // TLS 1.2 records have no padding.
                if (padding != 0) return error.InvalidLength;
                return e.seal(content, input, out);
            }
            return e.seal(content, input, padding, out);
        },
    }
}

pub fn open(self: *Protection, wire: []const u8, out: []u8) OpenError!Plaintext {
    @setRuntimeSafety(true);
    return switch (self.state) {
        inline else => |*e| e.open(wire, out),
    };
}

/// A trial open of a TLS 1.3 record (see `Epoch.trialOpen`); TLS 1.2 has no early data.
pub fn trialOpen(self: *Protection, wire: []const u8, out: []u8) TrialError!Plaintext {
    @setRuntimeSafety(true);
    return switch (self.state) {
        inline else => |*e, tag| if (comptime std.mem.startsWith(u8, @tagName(tag), "tls12_")) e.open(wire, out) else e.trialOpen(wire, out),
    };
}

/// A TLS 1.3 key update; TLS 1.2 has none.
pub fn update(self: *Protection) UpdateError!void {
    @setRuntimeSafety(true);
    switch (self.state) {
        inline else => |*e, tag| {
            if (comptime std.mem.startsWith(u8, @tagName(tag), "tls12_")) return error.NoKeyUpdate;
            try e.update();
        },
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

pub fn deinit(self: *Protection) void {
    @setRuntimeSafety(true);
    switch (self.state) {
        inline else => |*e| e.deinit(),
    }
    self.* = undefined;
}
