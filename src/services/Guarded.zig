//! Local aegis replacement: one owner exposes mutable data only through a lock guard.
const std = @import("std");
pub fn Guarded(comptime T: type) type {
    @setRuntimeSafety(true);
    return struct {
        const Self = @This();
        lock: std.atomic.Value(bool) = .init(false),
        data: T,
        pub fn init(value: T) Self {
            @setRuntimeSafety(true);
            return .{ .data = value };
        }
        pub fn acquire(owner: *Self) Guard {
            @setRuntimeSafety(true);
            while (owner.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
            return .{ .owner = owner };
        }
        pub const Guard = struct {
            owner: *Self,
            pub fn value(guard: Guard) *T {
                @setRuntimeSafety(true);
                return &guard.owner.data;
            }
            pub fn deinit(guard: *Guard) void {
                @setRuntimeSafety(true);
                guard.owner.lock.store(false, .release);
                guard.* = undefined;
            }
        };
    };
}
