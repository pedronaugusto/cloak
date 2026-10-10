const std = @import("std");
const cloak = @import("cloak");

// --- README:session ---
pub fn fetch(
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    roots: cloak.Trust.Snapshot,
    host: []const u8,
) !void {
    @setRuntimeSafety(true);
    var transport_in: [16 * 1024]u8 = undefined;
    var transport_out: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &transport_in);
    var writer = stream.writer(io, &transport_out);
    var session: cloak.tls.Session = undefined;
    var plain_in: [4096]u8 = undefined;
    var plain_out: [4096]u8 = undefined;
    try session.open(gpa, io, &reader.interface, &writer.interface, .{
        .identity = .{ .dns = host },
        .trust = .{ .snapshot = roots },
        .alpn = &.{"http/1.1"},
    }, &plain_in, &plain_out);
    defer session.deinit();
    try session.writer().print("GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host});
    try session.writer().flush();
    var response: [4096]u8 = undefined;
    const n = try session.reader().readSliceShort(&response);
    std.mem.doNotOptimizeAway(response[0..n]);
    try session.finish();
}
// --- README:session ---

test "documented session compiles against the public surface" {
    _ = &fetch;
}
