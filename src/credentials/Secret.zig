//! Local aegis replacement: an owned value with explicit, unconditional erasure.
//! Move/borrow discipline remains a caller contract until aegis/glint exist.
const std = @import("std");
pub fn Secret(comptime T: type) type {
    @setRuntimeSafety(true);
    return struct {
        const Self = @This();
        value: T,
        pub fn deinit(secret: *Self) void {
            @setRuntimeSafety(true);
            std.crypto.secureZero(u8, std.mem.asBytes(&secret.value));
            secret.* = undefined;
        }
        /// Formatting never observes the secret; logging this value fails closed.
        pub fn format(_: *const Self, _: *std.Io.Writer) error{SecretNotFormattable}!void {
            @setRuntimeSafety(true);
            return error.SecretNotFormattable;
        }
    };
}
