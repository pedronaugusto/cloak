//! Tasks a test started, reaped on its way out.
const std = @import("std");

/// Cancels the task behind `future` and reads what it returned. Being cancelled is the reaping
/// itself; any other failure is a second one, printed beside the test's own rather than dropped.
pub fn reap(comptime T: type, io: std.Io, future: *std.Io.Future(T)) void {
    if (future.cancel(io)) |_| {} else |err| {
        if (@as(anyerror, err) != error.Canceled) std.debug.print("a reaped task failed too: {s}\n", .{@errorName(err)});
    }
}

/// What `function` returns: the `T` of the future `io.concurrent(function, ...)` gives.
pub fn Result(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}
