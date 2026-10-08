//! Caller-supplied CSPRNG for independent primality witnesses, never retained.
const std = @import("std");
const Entropy = @This();
context: *const anyopaque,
fill: *const fn (*const anyopaque, []u8) FillError!void,
pub const FillError = error{EntropyUnavailable};
/// The Io value must outlive this parse call; no Io is stored in a private key.
pub fn fromIo(io: *const std.Io) Entropy {
    @setRuntimeSafety(true);
    return .{ .context = io, .fill = ioFill };
}
fn ioFill(context: *const anyopaque, output: []u8) FillError!void {
    @setRuntimeSafety(true); // fromIo supplies an aligned pointer to this exact Io value.
    const io: *const std.Io = @ptrCast(@alignCast(context)); // safe: fromIo supplies the aligned exact Io pointer for this parse lifetime
    io.randomSecure(output) catch return error.EntropyUnavailable;
}
