const std = @import("std");
const cloak = @import("cloak");

// --- README:usage ---
pub fn authenticate(
    gpa: std.mem.Allocator,
    roots: []const []const u8,
    chain: []const []const u8,
    name: []const u8,
    time: i64,
    token: cloak.types.Token,
) !cloak.types.Verification {
    @setRuntimeSafety(true);
    var trust = cloak.Trust.init(gpa);
    defer trust.deinit();
    for (roots) |der| try trust.addDer(der, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    return cloak.verify.indexed(gpa, .{
        .chain = chain,
        .identity = .{ .dns = name },
        .time = time,
        .trust_generation = snapshot.generation(),
        .policy_generation = 1,
        .token = token,
    }, snapshot.issuers());
}
// --- README:usage ---

test "documented verifier authenticates the selected path and rejects the wrong name" {
    @setRuntimeSafety(true);
    const time = try std.fmt.parseInt(i64, @embedFile("data/time.txt"), 10);
    const roots = &.{@embedFile("data/anchor.der")};
    const chain = &.{@embedFile("data/leaf.der")};
    var receipt = try authenticate(std.testing.allocator, roots, chain, "example.com", time, .{ .generation = 1, .id = 1 });
    defer receipt.deinit();
    try std.testing.expect(receipt.authenticated);
    try std.testing.expectEqual(@as(usize, 2), receipt.path.len);
    const rejected = authenticate(std.testing.allocator, roots, chain, "other.example", time, .{});
    if (rejected) |owned| {
        var unexpected = owned;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}
