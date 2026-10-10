const std = @import("std");
const Server = @import("Server.zig");

test "C3 server names match exactly, case-insensitively, or by a one-label wildcard" {
    try std.testing.expect(Server.nameMatches("example.com", "Example.COM"));
    try std.testing.expect(!Server.nameMatches("example.com", "www.example.com"));
    try std.testing.expect(Server.nameMatches("*.example.com", "www.example.com"));
    try std.testing.expect(!Server.nameMatches("*.example.com", "example.com"));
    try std.testing.expect(!Server.nameMatches("*.example.com", "a.b.example.com"));
    try std.testing.expect(!Server.nameMatches("*.example.com", ".example.com"));
    try std.testing.expect(!Server.nameMatches("example.com", ""));
}
