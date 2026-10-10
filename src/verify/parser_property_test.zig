const std = @import("std");
const shakedown = @import("shakedown");
const C = @import("../certificate.zig");
const V = @import("Verifier.zig");
const T = @import("../types.zig");
const leaf = @embedFile("fixtures/vectors/leaf.der");
const anchor = @embedFile("fixtures/vectors/p256.der");
test "certificate parser bounded mutations cannot manufacture authentication" {
    try shakedown.check(std.testing.allocator, {}, mutate, .{ .cases = 4096, .seed = 0xc10a5 });
}
fn mutate(_: void, case: *shakedown.Case) !void {
    var bytes = leaf.*;
    const mutations = shakedown.gen.intRange(case.source, usize, 1, 8);
    for (0..mutations) |_| {
        const offset = shakedown.gen.intRange(case.source, usize, 0, bytes.len - 1);
        bytes[offset] ^= shakedown.gen.int(case.source, u8);
    }
    const length = shakedown.gen.intRange(case.source, usize, 0, bytes.len);
    const input = bytes[0..length];
    const now = try std.fmt.parseInt(i64, @embedFile("fixtures/vectors/time.txt"), 10);
    const req: T.Request = .{ .chain = &.{input}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, now) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    if (V.verify(case.gpa, req, &.{anchor})) |receipt_value| {
        var receipt = receipt_value;
        defer receipt.deinit();
        try std.testing.expectEqualSlices(u8, (try C.parse(leaf, .{})).tbs, (try C.parse(input, .{})).tbs);
        try receipt.check(req);
    } else |_| {}
    if (C.parse(input, .{})) |cert| {
        try std.testing.expect(cert.der.len == input.len);
        try std.testing.expect(cert.tbs.len <= cert.der.len and cert.spki.len <= cert.tbs.len);
    } else |_| {}
}
