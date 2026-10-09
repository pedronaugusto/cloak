//! Bounded offline PBKDF2/HMAC orchestration with owned, erased working state.
const std = @import("std");
const aegis = @import("aegis");
pub const DeriveError = error{KdfLimit};
pub fn derive(comptime Hash: type, out: []u8, password: []const u8, salt: []const u8, rounds: u32) DeriveError!void {
    @setRuntimeSafety(true);
    const bounded_rounds = aegis.int.Ranged(u32, 1, std.math.maxInt(u32)).init(rounds) catch return error.KdfLimit;
    if (out.len == 0 or out.len > 32 or password.len > 4096 or salt.len > 1024) return error.KdfLimit;
    var previous_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer previous_owner.deinit();
    const previous = previous_owner.exposeMut();
    var next_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer next_owner.deinit();
    const next = next_owner.exposeMut();
    var offset: usize = 0;
    var block: u32 = 1;
    while (offset < out.len) : (block += 1) {
        var index: [4]u8 = undefined;
        std.mem.writeInt(u32, &index, block, .big);
        mac(Hash, previous, password, salt, &index);
        const len = @min(out.len - offset, Hash.digest_length);
        @memcpy(out[offset..][0..len], previous[0..len]);
        for (1..bounded_rounds.raw()) |_| {
            mac(Hash, next, password, previous, "");
            previous.* = next.*;
            for (out[offset..][0..len], next[0..len]) |*a, b| a.* ^= b;
        }
        offset += len;
    }
}
fn mac(comptime Hash: type, out: *[Hash.digest_length]u8, key: []const u8, first: []const u8, last: []const u8) void {
    @setRuntimeSafety(true);
    var pad_owner = aegis.Secret([Hash.block_length]u8).init(@splat(0));
    defer pad_owner.deinit();
    const pad = pad_owner.exposeMut();
    var digest_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer digest_owner.deinit();
    const digest = digest_owner.exposeMut();
    var inner = Hash.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&inner));
    if (key.len > pad.len) {
        inner.update(key);
        inner.final(digest);
        @memcpy(pad[0..digest.len], digest);
        inner = Hash.init(.{});
    } else @memcpy(pad[0..key.len], key);
    for (pad) |*byte| byte.* ^= 0x36;
    inner.update(pad);
    inner.update(first);
    inner.update(last);
    inner.final(digest);
    for (pad) |*byte| byte.* ^= 0x36 ^ 0x5c;
    var outer = Hash.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&outer));
    outer.update(pad);
    outer.update(digest);
    outer.final(out);
}
test {
    _ = @import("Kdf_test.zig");
}
