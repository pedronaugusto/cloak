const std = @import("std");
const T = @import("../types.zig");
test "verification request digest binds token name time policy pins and evidence" {
    var a: T.Request = .{ .chain = &.{"leaf"}, .time = 1, .trust_generation = 2, .policy_generation = 3 };
    const digest = a.digest();
    a.time = 2;
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.time = 1;
    a.token.id = 1;
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.token.id = 0;
    a.identity = .{ .dns = "example.com" };
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
    a.identity = .none;
    a.evidence.ocsp = &.{"staple"};
    try std.testing.expect(!std.mem.eql(u8, &digest, &a.digest()));
}

test "verification request digest binds every public work limit" {
    const request: T.Request = .{ .chain = &.{"leaf"}, .time = 1, .trust_generation = 2, .policy_generation = 3 };
    const digest = request.digest();
    inline for (@typeInfo(T.Limits).@"struct".field_names) |field| {
        var changed = request;
        @field(changed.limits, field) += 1;
        try std.testing.expect(!std.mem.eql(u8, &digest, &changed.digest()));
    }
}
