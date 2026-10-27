//! Bounded offline PBKDF2/HMAC orchestration with owned, erased working state.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const aegis = @import("aegis");
pub const DeriveError = error{KdfLimit};
/// The longest key `derive` makes: SHA-512's output, as PBMAC1 over HMAC-SHA-512 asks.
pub const max_key = 64;
pub fn derive(comptime Hash: type, out: []u8, password: []const u8, salt: []const u8, rounds: u32) DeriveError!void {
    @setRuntimeSafety(true);
    const bounded_rounds = aegis.int.Ranged(u32, 1, std.math.maxInt(u32)).init(rounds) catch return error.KdfLimit;
    if (out.len == 0 or out.len > max_key or password.len > 4096 or salt.len > 1024) return error.KdfLimit;
    // The password's pads absorbed once: every round costs two compressions, not four.
    var keyed_owner = aegis.Secret(Keyed(Hash)).init(undefined);
    defer keyed_owner.deinit();
    const keyed = keyed_owner.exposeMut();
    keyed.init(password);
    var previous_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer previous_owner.deinit();
    const previous = previous_owner.exposeMut();
    var offset: usize = 0;
    var block: u32 = 1;
    while (offset < out.len) : (block += 1) {
        var index: [4]u8 = undefined;
        std.mem.writeInt(u32, &index, block, .big);
        keyed.mac(previous, salt, &index);
        const len = @min(out.len - offset, Hash.digest_length);
        @memcpy(out[offset..][0..len], previous[0..len]);
        for (1..bounded_rounds.raw()) |_| {
            keyed.mac(previous, previous, "");
            for (out[offset..][0..len], previous[0..len]) |*a, b| a.* ^= b;
        }
        offset += len;
    }
}

/// HMAC (RFC 2104) with the key's inner and outer pads absorbed once, kept in the states it
/// copies for each message. The owner holds key-equivalent state: callers keep it in a secret
/// owner, and every copy is erased.
pub fn Keyed(comptime Hash: type) type {
    return struct {
        inner: Hash,
        outer: Hash,
        const Self = @This();
        pub fn init(self: *Self, key: []const u8) void {
            @setRuntimeSafety(true);
            var pad_owner = aegis.Secret([Hash.block_length]u8).init(@splat(0));
            defer pad_owner.deinit();
            const pad = pad_owner.exposeMut();
            if (key.len > pad.len) {
                var h_owner: Secret(Hash) = .init(Hash.init(.{}));
                defer h_owner.deinit();
                const h = h_owner.exposeMut();
                h.update(key);
                h.final(pad[0..Hash.digest_length]);
            } else @memcpy(pad[0..key.len], key);
            for (pad) |*byte| byte.* ^= 0x36;
            self.inner = Hash.init(.{});
            self.inner.update(pad);
            for (pad) |*byte| byte.* ^= 0x36 ^ 0x5c;
            self.outer = Hash.init(.{});
            self.outer.update(pad);
        }
        /// The MAC of `first || last` in `out`, which may alias either input.
        pub fn mac(self: *const Self, out: *[Hash.digest_length]u8, first: []const u8, last: []const u8) void {
            @setRuntimeSafety(true);
            var h_owner: Secret(Hash) = .init(self.inner);
            defer h_owner.deinit();
            const h = h_owner.exposeMut();
            h.update(first);
            h.update(last);
            var digest_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
            defer digest_owner.deinit();
            const digest = digest_owner.exposeMut();
            h.final(digest);
            h.* = self.outer;
            h.update(digest);
            h.final(out);
        }
    };
}
test {
    _ = @import("Kdf_test.zig");
}
