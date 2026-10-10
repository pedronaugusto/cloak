//! Executable freestanding vectors: caller storage, explicit trust/time, no Io.
const std = @import("std");
const probes = @import("probes");
const cloak = probes.certificates;
export fn cloakCoreVectors() u32 {
    @setRuntimeSafety(true);
    var backing: [256 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    const gpa = fixed.allocator();
    var trust = cloak.Trust.init(gpa);
    defer trust.deinit();
    trust.addDer(@embedFile("data/anchor.der"), .{}) catch return 1;
    const snapshot = trust.freeze() catch return 2;
    defer snapshot.deinit();
    const request: cloak.types.Request = .{ .chain = &.{@embedFile("data/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, std.fmt.parseInt(i64, @embedFile("data/time.txt"), 10) catch return 3) * std.time.ns_per_s), .trust_generation = snapshot.generation(), .policy_generation = .fromRaw(1) };
    var receipt = cloak.verify.verify(gpa, request, snapshot.anchors()) catch return 4;
    defer receipt.deinit();
    receipt.check(request) catch return 5;
    if (!receipt.authenticated or receipt.path.len != 2) return 6;
    const key = cloak.PrivateKey.parse(gpa, @embedFile("data/ed25519.pem"), .{}) catch return 7;
    defer key.deinit();
    const identity = cloak.Identity.init(gpa, &.{@embedFile("data/ed25519.der")}, key, .{}) catch return 8;
    defer identity.deinit();
    if (identity.chain().len != 1) return 9;
    inline for (.{ @embedFile("data/p256.pem"), @embedFile("data/p384.pem") }, .{ @embedFile("data/p256.der"), @embedFile("data/p384.der") }) |pem, certificate| {
        const curve_key = cloak.PrivateKey.parse(gpa, pem, .{}) catch return 10;
        defer curve_key.deinit();
        if (!curve_key.matches(certificate)) return 11;
        // Exercise actual public caller dispatch and owned release on portable builds.
    }
    const tls_result = probes.tls.vectors();
    if (tls_result != 0) return 100 + tls_result;
    return 0;
}
