//! A selected native chain is provisional until cloak checks the same path.
const std = @import("std");
const builtin = @import("builtin");
const types = @import("../types.zig");
const Path = @import("Path.zig");
const macos = @import("macos.zig");
const windows = @import("windows.zig");
pub const EvaluateError = macos.Error || windows.Error || error{UnsupportedPlatform};
pub fn evaluate(gpa: std.mem.Allocator, request: types.Request, anchors: []const []const u8) EvaluateError!Path {
    @setRuntimeSafety(true);
    return switch (builtin.os.tag) {
        .macos => macos.evaluate(gpa, request, anchors),
        .windows => windows.evaluate(gpa, request, anchors),
        else => error.UnsupportedPlatform,
    };
}
