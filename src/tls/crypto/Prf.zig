//! The TLS 1.2 pseudorandom function (RFC 5246 section 5) and what a connection derives with
//! it: the extended master secret (RFC 7627), the key block, Finished verify_data and keying
//! material exports (RFC 5705). HMAC states and the chained A(i) values are erased.
const std = @import("std");
const aegis = @import("aegis");

pub const master_length = 48;
pub const verify_length = 12;

/// P_hash(secret, label || seeds...) truncated to `out.len`.
pub fn prf(comptime Hash: type, out: []u8, secret: []const u8, label: []const u8, seeds: []const []const u8) void {
    @setRuntimeSafety(true);
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    var a = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer a.deinit();
    var block = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer block.deinit();
    // A(1) = HMAC(secret, seed).
    {
        var h = Hmac.init(secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        h.update(label);
        for (seeds) |seed| h.update(seed);
        h.final(a.exposeMut());
    }
    var offset: usize = 0;
    while (offset < out.len) {
        {
            var h = Hmac.init(secret);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
            h.update(a.expose());
            h.update(label);
            for (seeds) |seed| h.update(seed);
            h.final(block.exposeMut());
        }
        const n = @min(Hash.digest_length, out.len - offset);
        @memcpy(out[offset..][0..n], block.expose()[0..n]);
        offset += n;
        if (offset == out.len) break;
        // A(i + 1) = HMAC(secret, A(i)).
        var h = Hmac.init(secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        h.update(a.expose());
        h.final(a.exposeMut());
    }
}

/// The extended master secret: PRF(premaster, "extended master secret", session_hash), where
/// the session hash covers the handshake through ClientKeyExchange.
pub fn masterSecret(comptime Hash: type, out: *[master_length]u8, premaster: []const u8, session_hash: []const u8) void {
    prf(Hash, out, premaster, "extended master secret", &.{session_hash});
}

/// The key block: PRF(master, "key expansion", server_random || client_random).
pub fn keyBlock(comptime Hash: type, out: []u8, master: *const [master_length]u8, server_random: *const [32]u8, client_random: *const [32]u8) void {
    prf(Hash, out, master, "key expansion", &.{ server_random, client_random });
}

/// verify_data of a Finished: PRF(master, finished_label, Hash(handshake_messages))[0..12].
pub fn finished(comptime Hash: type, out: *[verify_length]u8, master: *const [master_length]u8, client: bool, transcript: []const u8) void {
    prf(Hash, out, master, if (client) "client finished" else "server finished", &.{transcript});
}

pub const CheckError = error{BadFinished};

/// Checks a received verify_data in constant time.
pub fn checkFinished(comptime Hash: type, master: *const [master_length]u8, client: bool, transcript: []const u8, received: []const u8) CheckError!void {
    @setRuntimeSafety(true);
    if (received.len != verify_length) return error.BadFinished;
    var expected = aegis.Secret([verify_length]u8).init(undefined);
    defer expected.deinit();
    finished(Hash, expected.exposeMut(), master, client, transcript);
    if (!std.crypto.timing_safe.eql([verify_length]u8, expected.expose().*, received[0..verify_length].*)) return error.BadFinished;
}

pub const ExportError = error{ InvalidLabel, ReservedLabel };

/// RFC 5705 exporter over the extended master secret: PRF(master, label, client_random ||
/// server_random [|| uint16 length || context]). Labels the TLS PRF itself uses are refused.
pub fn exporter(comptime Hash: type, out: []u8, master: *const [master_length]u8, label: []const u8, client_random: *const [32]u8, server_random: *const [32]u8, context: ?[]const u8) ExportError!void {
    @setRuntimeSafety(true);
    if (label.len == 0 or label.len > 255) return error.InvalidLabel;
    for ([_][]const u8{ "client finished", "server finished", "master secret", "extended master secret", "key expansion" }) |reserved| {
        if (std.mem.eql(u8, label, reserved)) return error.ReservedLabel;
    }
    if (context) |bytes| {
        if (bytes.len > 65535) return error.InvalidLabel;
        var length: [2]u8 = undefined;
        // safe: the context was just bounded by the u16 maximum.
        std.mem.writeInt(u16, &length, @intCast(bytes.len), .big);
        prf(Hash, out, master, label, &.{ client_random, server_random, &length, bytes });
    } else prf(Hash, out, master, label, &.{ client_random, server_random });
}

test {
    _ = @import("Prf_test.zig");
}
