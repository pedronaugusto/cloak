const std = @import("std");
const Prf = @import("Prf.zig");

fn unhex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

// Expected outputs from OpenSSL 3.6.5's TLS1-PRF KDF (`openssl kdf -keylen N -kdfopt digest:SHA256
// -kdfopt hexsecret:... -kdfopt seed:"test label" -kdfopt hexseed:... TLS1-PRF`); the SHA-256 case
// is also the widely circulated TLS 1.2 PRF test vector.
test "C4 TLS 1.2 PRF matches OpenSSL for SHA-256 and SHA-384" {
    var out256: [100]u8 = undefined;
    Prf.prf(std.crypto.hash.sha2.Sha256, &out256, &unhex("9bbe436ba940f017b17652849a71db35"), "test label", &.{&unhex("a0ba9f936cda311827a6f796ffd5198c")});
    try std.testing.expectEqualSlices(u8, &unhex("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"), &out256);
    var out384: [148]u8 = undefined;
    // The seed may be split across the two seed arguments without changing the output.
    Prf.prf(std.crypto.hash.sha2.Sha384, &out384, &unhex("b80b733d6ceefcdc71566ea48e5567df"), "test label", &.{ &unhex("cd665cf6a8447dd6"), &unhex("ff8b27555edb7465") });
    try std.testing.expectEqualSlices(u8, &unhex("7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f"), &out384);
}

test "C4 TLS 1.2 Finished checks its length and value and the exporter refuses PRF labels" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const master: [48]u8 = @splat(7);
    const transcript: [32]u8 = @splat(9);
    var data: [12]u8 = undefined;
    Prf.finished(Sha256, &data, &master, true, &transcript);
    try Prf.checkFinished(Sha256, &master, true, &transcript, &data);
    try std.testing.expectError(error.BadFinished, Prf.checkFinished(Sha256, &master, false, &transcript, &data));
    try std.testing.expectError(error.BadFinished, Prf.checkFinished(Sha256, &master, true, &transcript, data[0..11]));
    data[0] ^= 1;
    try std.testing.expectError(error.BadFinished, Prf.checkFinished(Sha256, &master, true, &transcript, &data));
    var out: [32]u8 = undefined;
    const random: [32]u8 = @splat(1);
    try std.testing.expectError(error.ReservedLabel, Prf.exporter(Sha256, &out, &master, "key expansion", &random, &random, null));
    try Prf.exporter(Sha256, &out, &master, "EXPORTER-test", &random, &random, null);
    var with_context: [32]u8 = undefined;
    try Prf.exporter(Sha256, &with_context, &master, "EXPORTER-test", &random, &random, "");
    // An empty context is not the same as no context (RFC 5705 section 4).
    try std.testing.expect(!std.mem.eql(u8, &out, &with_context));
}
