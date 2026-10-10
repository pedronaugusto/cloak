const std = @import("std");
const Messages12 = @import("Messages12.zig");

test "C4 TLS 1.2 messages round-trip and refuse lengths past their parent" {
    var buffer: [512]u8 = undefined;
    // Certificate: no context and no entry extensions.
    const built = try Messages12.buildCertificate(&buffer, &.{ "leaf", "intermediate" });
    var out: [Messages12.max_certificates][]const u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try Messages12.certificate(built, 16, 65536, &out));
    try std.testing.expectEqualSlices(u8, "intermediate", out[1]);
    try std.testing.expectError(error.CertificateLimit, Messages12.certificate(built, 1, 65536, &out));
    try std.testing.expectError(error.InvalidLength, Messages12.certificate("\x0b\x00\x00\x06\x00\x00\x09\x00\x00\x09", 16, 65536, &out));
    // ServerKeyExchange: named curve only, exact point length, a signature.
    var params_buffer: [128]u8 = undefined;
    const key: [32]u8 = @splat(9);
    const params = try Messages12.buildParams(&params_buffer, .x25519, &key);
    var ske_buffer: [256]u8 = undefined;
    const ske = try Messages12.buildServerKeyExchange(&ske_buffer, params, 0x0403, "sig");
    const parsed = try Messages12.serverKeyExchange(ske);
    try std.testing.expectEqual(.x25519, parsed.group);
    try std.testing.expectEqualSlices(u8, params, parsed.params);
    try std.testing.expectEqualSlices(u8, "sig", parsed.signature);
    // Explicit curves, the hybrid group and short points are refused.
    try std.testing.expectError(error.IllegalParameter, Messages12.serverKeyExchange("\x0c\x00\x00\x08\x01\x00\x1d\x00\x04\x03\x00\x00"));
    try std.testing.expectError(error.IllegalParameter, Messages12.serverKeyExchange("\x0c\x00\x00\x09\x03\x11\xec\x01\x00\x04\x03\x00\x01"));
    try std.testing.expectError(error.IllegalParameter, Messages12.serverKeyExchange("\x0c\x00\x00\x09\x03\x00\x1d\x01\xaa\x04\x03\x00\x01"));
    // CertificateRequest and ServerHelloDone.
    const request = try Messages12.buildCertificateRequest(&buffer, &.{ 0x0403, 0x0804 });
    const cr = try Messages12.certificateRequest(request);
    try std.testing.expect(cr.accepts(0x0804) and !cr.accepts(0x0807));
    try std.testing.expectError(error.InvalidMessage, Messages12.serverHelloDone("\x0e\x00\x00\x01\x00"));
    try Messages12.serverHelloDone(try Messages12.buildServerHelloDone(&buffer));
    // ClientKeyExchange: exactly the group's length.
    const cke = try Messages12.buildClientKeyExchange(&buffer, &key);
    try std.testing.expectEqualSlices(u8, &key, try Messages12.clientKeyExchange(cke, .x25519));
    try std.testing.expectError(error.IllegalParameter, Messages12.clientKeyExchange(cke, .p256));
}
