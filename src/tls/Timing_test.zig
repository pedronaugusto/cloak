//! Every cloak call that computes with a secret runs under the processor's data-independent
//! timing mode (aegis `Timing`, Arm's FEAT_DIT) and leaves it as it found it. The timing campaign
//! (`zig build timing`) found std's X25519 timed apart by its secret on an Apple M3 without the
//! mode; these check the mode is on where cloak calls back into its caller mid-computation.
const std = @import("std");
const aegis = @import("aegis");
const Pair = @import("../testing/Pair.zig").Pair;
const ServerPair = @import("../testing/ServerPair.zig").ServerPair;

const Seen = struct {
    lines: usize = 0,
    outside: usize = 0,
    key_log: @import("Connection.zig").KeyLog = .{ .write = write },
    fn write(log: *@import("Connection.zig").KeyLog, line: []const u8) void {
        _ = line;
        const self: *Seen = @fieldParentPtr("key_log", log);
        self.lines += 1;
        if (aegis.secret.Timing.supported() and !aegis.secret.Timing.active()) self.outside += 1;
    }
};

test "F03 catalogue_compiler_preserves_secret_operations (a handshake's secret computations run under data-independent timing, client and server; the built binary's evidence is `zig build timing`)" {
    const before = aegis.secret.Timing.active();
    {
        var seen: Seen = .{};
        const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .key_log = &seen.key_log });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expect(seen.lines >= 5);
        try std.testing.expectEqual(@as(usize, 0), seen.outside);
        try std.testing.expectEqual(before, aegis.secret.Timing.active());
    }
    {
        var seen: Seen = .{};
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .key_log = &seen.key_log });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(seen.lines >= 5);
        try std.testing.expectEqual(@as(usize, 0), seen.outside);
        try std.testing.expectEqual(before, aegis.secret.Timing.active());
    }
}
