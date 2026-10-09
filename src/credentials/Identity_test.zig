const std = @import("std");
const shakedown = @import("shakedown");
const Identity = @import("../Identity.zig");
const ClientAuth = @import("../ClientAuth.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Pem = @import("Pem.zig");
test "credential identity owns chain and shares retained private owner" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), lifetime, .{});
}
fn lifetime(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/ed25519.cert.pem"));
    var block = (try pem.next(gpa, 65536)).?;
    defer block.deinit(gpa);
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    const identity = try Identity.init(gpa, &.{block.der}, key, .{ .generation = .fromRaw(7) });
    const held = identity.retain();
    identity.deinit();
    defer held.deinit();
    const auth = try ClientAuth.init(gpa, held.chain(), key, .{});
    defer auth.deinit();
    @memset(block.der, 0);
    try std.testing.expectEqual(@as(u64, 7), held.generation().raw());
    try std.testing.expectEqual(@as(usize, 1), held.chain().len);
    try std.testing.expectEqualSlices(u8, held.chain()[0], held.certificateList()[3..]);
    try std.testing.expect(key.matches(auth.chain()[0]));
}
test "credential identity rejects mismatched leaf and empty chain" {
    @setRuntimeSafety(true);
    const key = try PrivateKey.parse(std.testing.allocator, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    try rejectIdentity(error.EmptyChain, Identity.init(std.testing.allocator, &.{}, key, .{}));
    var pem = Pem.init(@embedFile("testdata/p256.cert.pem"));
    var block = (try pem.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    try rejectIdentity(error.KeyMismatch, Identity.init(std.testing.allocator, &.{block.der}, key, .{}));
    try rejectIdentity(error.IdentityLimit, Identity.init(std.testing.allocator, &.{block.der}, key, .{ .chain_bytes = 1 }));
}

fn rejectIdentity(expected: anyerror, result: anyerror!Identity) !void {
    @setRuntimeSafety(true);
    if (result) |unexpected| {
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(expected, err);
}
