//! Committed ciphertext awaiting the transport. Records are sealed once, here, and kept
//! byte for byte until acknowledged, so a partial write never re-seals.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{OutputFull};

buf: []u8 = &.{},
start: usize = 0,
end: usize = 0,

const Outbox = @This();

pub fn pending(self: *const Outbox) []const u8 {
    return self.buf[self.start..self.end];
}

pub fn acknowledge(self: *Outbox, n: usize) void {
    @setRuntimeSafety(true);
    std.debug.assert(n <= self.end - self.start);
    self.start += n;
    if (self.start == self.end) {
        self.start = 0;
        self.end = 0;
    }
}

/// Free space for `want` more bytes, compacting or growing within `cap`.
pub fn tail(self: *Outbox, gpa: std.mem.Allocator, want: usize, cap: usize) Error![]u8 {
    @setRuntimeSafety(true);
    const live = self.end - self.start;
    if (want > cap or live > cap - want) return error.OutputFull;
    if (self.buf.len - self.end < want) {
        if (self.start != 0) {
            std.mem.copyForwards(u8, self.buf[0..live], self.buf[self.start..self.end]);
            self.start = 0;
            self.end = live;
        }
        if (self.buf.len - self.end < want) {
            const capacity = @min(cap, @max(live + want, @max(4096, self.buf.len * 2)));
            const grown = try gpa.alloc(u8, capacity);
            @memcpy(grown[0..live], self.buf[self.start..self.end]);
            gpa.free(self.buf);
            self.buf = grown;
            self.start = 0;
            self.end = live;
        }
    }
    return self.buf[self.end..];
}

pub fn commit(self: *Outbox, n: usize) void {
    @setRuntimeSafety(true);
    std.debug.assert(n <= self.buf.len - self.end);
    self.end += n;
}

/// Frees the buffer when nothing is pending.
pub fn trim(self: *Outbox, gpa: std.mem.Allocator) void {
    @setRuntimeSafety(true);
    if (self.start != self.end) return;
    gpa.free(self.buf);
    self.* = .{};
}

pub fn deinit(self: *Outbox, gpa: std.mem.Allocator) void {
    gpa.free(self.buf);
    self.* = .{};
}
