//! Client credentials retain the same immutable identity owner as servers.
const std = @import("std");
const Identity = @import("Identity.zig");
const PrivateKey = @import("PrivateKey.zig");
const ClientAuth = @This();
/// Private: the owned identity survives reloads and caller buffer release.
identity: Identity,
pub const InitError = Identity.InitError;
pub const Options = Identity.Options;
pub fn init(gpa: std.mem.Allocator, certificates: []const []const u8, key: PrivateKey, options: Options) InitError!ClientAuth {
    @setRuntimeSafety(true);
    return .{ .identity = try Identity.init(gpa, certificates, key, options) };
}
pub fn retain(auth: ClientAuth) ClientAuth {
    @setRuntimeSafety(true);
    return .{ .identity = auth.identity.retain() };
}
pub fn deinit(auth: ClientAuth) void {
    @setRuntimeSafety(true);
    auth.identity.deinit();
}
pub fn chain(auth: ClientAuth) []const []const u8 {
    @setRuntimeSafety(true);
    return auth.identity.chain();
}
pub fn generation(auth: ClientAuth) u64 {
    @setRuntimeSafety(true);
    return auth.identity.generation();
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Identity_test.zig");
}
