const std = @import("std");
const T = @import("../types.zig");
test "verification request digest binds token name time policy pins and evidence" {
    var a: T.Request = .{ .chain = &.{"leaf"}, .time = 1, .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3) };
    const digest = a.digest();
    a.time = 2;
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.time = 1;
    a.token.id = .fromRaw(1);
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.token.id = .fromRaw(0);
    a.identity = .{ .dns = "example.com" };
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.identity = .none;
    a.evidence.ocsp = &.{"staple"};
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
}

test "verification request digest binds every public work limit" {
    const request: T.Request = .{ .chain = &.{"leaf"}, .time = 1, .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3) };
    const digest = request.digest();
    inline for (@typeInfo(T.Limits).@"struct".field_names) |field| {
        var changed = request;
        @field(changed.limits, field) += 1;
        try std.testing.expect(!std.mem.eql(u8, &digest, &changed.digest()));
    }
}

test "W0 receipt domains retain ABI and cannot alias request trust or policy IDs" {
    @setRuntimeSafety(true);
    comptime {
        if (T.ConnectionGeneration == T.RequestId or T.TrustGeneration == T.PolicyGeneration or T.IdentityGeneration == T.TrustGeneration) @compileError("receipt domains overlap");
        if (@sizeOf(T.Token) != 16 or @alignOf(T.Token) != @alignOf(u64)) @compileError("token representation changed");
    }
    var a: T.Request = .{ .chain = &.{"leaf"}, .time = 1, .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3) };
    const original = a.digest();
    a.token.generation = .fromRaw(std.math.maxInt(u64));
    try std.testing.expect(!std.mem.eql(u8, &original, &a.digest()));
    a.token = .{};
    a.trust_generation = .fromRaw(3);
    a.policy_generation = .fromRaw(2);
    try std.testing.expect(!std.mem.eql(u8, &original, &a.digest()));
}
