//! Bounded TLS 1.3 HKDF labels, with erased HMAC state and intermediate blocks.
const std = @import("std");
const aegis = @import("aegis");
pub const ExpandError = error{InvalidLabel};
/// The label prefix of HKDF-Expand-Label: "tls13 " for TLS 1.3, "dtls13" for DTLS 1.3 (RFC 9147
/// section 5.9). Both are six bytes, so the labels' bounds are the same.
pub const Prefix = enum {
    tls13,
    dtls13,
    pub fn bytes(prefix: Prefix) *const [6]u8 {
        return switch (prefix) {
            .tls13 => "tls13 ",
            .dtls13 => "dtls13",
        };
    }
};
/// HKDF-Expand-Label with the TLS 1.3 prefix.
pub fn expand(comptime Hash: type, out: []u8, secret: *const [Hash.digest_length]u8, label: []const u8, context: []const u8) ExpandError!void {
    return expandWith(Hash, .tls13, out, secret, label, context);
}
pub fn expandWith(comptime Hash: type, prefix: Prefix, out: []u8, secret: *const [Hash.digest_length]u8, label: []const u8, context: []const u8) ExpandError!void {
    @setRuntimeSafety(true);
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    if (label.len == 0 or label.len > 249 or context.len > 255 or out.len > 255 * Hash.digest_length) return error.InvalidLabel;
    var info: [514]u8 = undefined;
    // safe: HKDF output is bounded by 255 * Hash.digest_length, below u16 max.
    std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    // safe: label plus six-byte prefix was checked against the u8 wire bound.
    info[2] = @intCast(label.len + 6);
    @memcpy(info[3..9], prefix.bytes());
    @memcpy(info[9..][0..label.len], label);
    const ctx_at = 9 + label.len;
    // safe: context was checked against the u8 wire bound.
    info[ctx_at] = @intCast(context.len);
    @memcpy(info[ctx_at + 1 ..][0..context.len], context);
    var block = aegis.Secret([Hash.digest_length]u8).init(@splat(0));
    defer block.deinit();
    var offset: usize = 0;
    var counter: u8 = 1;
    while (offset < out.len) {
        var h = Hmac.init(secret);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        if (offset != 0) h.update(block.expose());
        h.update(info[0 .. ctx_at + 1 + context.len]);
        h.update(&.{counter});
        h.final(block.exposeMut());
        const len = @min(Hash.digest_length, out.len - offset);
        @memcpy(out[offset..][0..len], block.expose()[0..len]);
        offset += len;
        counter +%= 1;
    }
}
pub fn extract(comptime Hash: type, out: *[Hash.digest_length]u8, salt: []const u8, input: []const u8) void {
    var h = std.crypto.auth.hmac.Hmac(Hash).init(salt);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(input);
    h.final(out);
}
pub fn finished(comptime Hash: type, prefix: Prefix, out: *[Hash.digest_length]u8, traffic: *const [Hash.digest_length]u8, transcript: *const [Hash.digest_length]u8) void {
    var key = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer key.deinit();
    // unreachable: the fixed label/context and hash-sized output meet expand bounds.
    expandWith(Hash, prefix, key.exposeMut(), traffic, "finished", "") catch unreachable;
    extract(Hash, out, key.expose(), transcript);
}
pub const CheckError = error{BadFinished};
pub fn checkFinished(comptime Hash: type, prefix: Prefix, traffic: *const [Hash.digest_length]u8, transcript: *const [Hash.digest_length]u8, received: []const u8) CheckError!void {
    @setRuntimeSafety(true);
    if (received.len != Hash.digest_length) return error.BadFinished;
    var expected = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer expected.deinit();
    finished(Hash, prefix, expected.exposeMut(), traffic, transcript);
    if (!aegis.secret.equal(Hash.digest_length, expected.expose(), received[0..Hash.digest_length]).declassify("a bad Finished ends the handshake")) return error.BadFinished;
}
test {
    _ = @import("Labels_test.zig");
}
