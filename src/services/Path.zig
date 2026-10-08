//! Owned OS-selected path. Native success remains provisional until portable floors.
const std = @import("std");
const types = @import("../types.zig");
const Path = @This();
gpa: std.mem.Allocator,
chain: []const []const u8,
storage: []u8,
request_digest: [32]u8,
token: types.Token,
pub const InitError = std.mem.Allocator.Error || error{ ServiceLimit, NativeEvidenceUnavailable };
pub fn init(gpa: std.mem.Allocator, request: types.Request, chain: []const []const u8) InitError!Path {
    @setRuntimeSafety(true);
    if (chain.len == 0 or chain.len > request.limits.depth) return error.NativeEvidenceUnavailable;
    var bytes: usize = 0;
    for (chain) |der| bytes = std.math.add(usize, bytes, der.len) catch return error.ServiceLimit;
    if (bytes > request.limits.receipt_bytes) return error.ServiceLimit;
    const storage = try gpa.alloc(u8, bytes);
    errdefer gpa.free(storage);
    const owned = try gpa.alloc([]const u8, chain.len);
    var cursor: usize = 0;
    for (chain, owned) |der, *out| {
        out.* = storage[cursor..][0..der.len];
        @memcpy(storage[cursor..][0..der.len], der);
        cursor += der.len;
    }
    return .{ .gpa = gpa, .chain = owned, .storage = storage, .request_digest = request.digest(), .token = request.token };
}
pub const CheckError = error{WrongVerificationRequest};
pub fn check(path: Path, request: types.Request) CheckError!void {
    @setRuntimeSafety(true);
    if (!std.crypto.timing_safe.eql([32]u8, path.request_digest, request.digest()) or path.token.generation != request.token.generation or path.token.id != request.token.id) return error.WrongVerificationRequest;
}
pub fn deinit(path: *Path) void {
    @setRuntimeSafety(true);
    path.gpa.free(path.chain);
    path.gpa.free(path.storage);
    path.* = undefined;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Path_test.zig");
}
