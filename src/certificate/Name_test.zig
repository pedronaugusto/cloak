const std = @import("std");
const N = @import("Name.zig");
test "SAN DNS identity uses complete labels and normalized A-labels" {
    try std.testing.expect(N.dnsMatch("a.example.com.", "*.EXAMPLE.com"));
    for ([_][]const u8{ "example.com", "a.b.example.com", "example.com.attacker", "xn--bcher-kva.example.com" }) |name| try std.testing.expect(!N.dnsMatch(name, "*.example.com"));
    for ([_][]const u8{ "", "a..b", "-a.com", "a-.com", "xn--.com", "xn--abc-.com", "a\x00.com", "*.example.com" }) |name| try std.testing.expectError(error.InvalidName, N.canonicalDns(name, false));
    _ = try N.canonicalDns("xn--bcher-kva.example", false);
}
