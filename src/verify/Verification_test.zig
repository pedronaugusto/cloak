const std = @import("std");
const V = @import("../types.zig").Verification;
const T = @import("../types.zig");
test "receipt owns path and reference and rejects another pending request" {
    var input = [_]u8{ 'a', 'b' };
    const request: T.Request = .{ .chain = &.{&input}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(1 * std.time.ns_per_s), .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3) };
    var receipt = try V.init(std.testing.allocator, request, request.chain, true, .fromNanoseconds(2 * std.time.ns_per_s));
    defer receipt.deinit();
    try receipt.check(request);
    var empty = request;
    empty.chain = &.{};
    try std.testing.expectError(error.WrongVerificationRequest, receipt.check(empty));
    input[0] = 'z';
    try std.testing.expectEqualStrings("ab", receipt.path[0]);
    try std.testing.expectError(error.WrongVerificationRequest, receipt.check(request));
}

test "receipt bounds include DNS and descriptors and none cannot claim authentication" {
    const request: T.Request = .{ .chain = &.{"ab"}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(1 * std.time.ns_per_s), .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3), .mode = .none };
    var receipt = try V.init(std.testing.allocator, request, request.chain, true, .fromNanoseconds(2 * std.time.ns_per_s));
    defer receipt.deinit();
    try std.testing.expect(!receipt.authenticated);
    var capped = request;
    capped.limits.receipt_bytes = 2;
    try std.testing.expectError(error.VerificationLimit, V.init(std.testing.allocator, capped, request.chain, true, .fromNanoseconds(2 * std.time.ns_per_s)));
    try std.testing.expectError(error.VerificationLimit, V.init(std.testing.allocator, request, &.{}, true, .fromNanoseconds(2 * std.time.ns_per_s)));
}
