//! What a handshake machine hands to its driver: a bounded queue of outputs and the bytes of
//! the messages among them. Both roles queue the same things: messages to send, traffic
//! secrets to install, and completion; the driver turns them into records or QUIC events.
const std = @import("std");
const aegis = @import("aegis");
const State = @import("State.zig");
const Suite13 = @import("../crypto/Suite.zig").Suite13;
const Transcripts = @import("Transcripts.zig");

pub const Epoch = State.Epoch;
pub const Direction = enum { read, write };

/// A secret to install. The receiver owns and erases it.
pub const Traffic = struct {
    suite: Suite13,
    secret: aegis.Secret([Transcripts.max_digest]u8),
    len: u8,
};

pub const Emit = union(enum) {
    /// A complete handshake message at `start` in the flight buffer.
    message: struct { epoch: Epoch, start: u32, len: u32 },
    secret: struct { direction: Direction, epoch: Epoch, traffic: Traffic },
    /// Send one compatibility change_cipher_spec record now.
    compat_ccs,
    /// A peer KeyUpdate: update the read keys, and answer with an update if asked.
    key_update: struct { request_peer: bool },
    /// A well-formed NewSessionTicket was received (not used before resumption).
    ticket,
    /// Everything this side owes has been queued and the peer is authenticated.
    complete,
};

pub fn eraseEmit(emit: *Emit) void {
    switch (emit.*) {
        .secret => |*s| s.traffic.secret.deinit(),
        else => {},
    }
}

pub const Error = error{ QueueFull, HandshakeLimit, OutOfMemory };

const Flight = @This();

queue: [16]?Emit = @splat(null),
head: usize = 0,
len: usize = 0,
buf: []u8 = &.{},
used: usize = 0,

pub fn push(self: *Flight, emit: Emit) error{QueueFull}!void {
    @setRuntimeSafety(true);
    if (self.len == self.queue.len) return error.QueueFull;
    self.queue[(self.head + self.len) % self.queue.len] = emit;
    self.len += 1;
}

pub fn pop(self: *Flight) ?Emit {
    @setRuntimeSafety(true);
    if (self.len == 0) return null;
    const emit = self.queue[self.head].?;
    self.queue[self.head] = null;
    self.head = (self.head + 1) % self.queue.len;
    self.len -= 1;
    return emit;
}

pub fn pending(self: *const Flight) bool {
    return self.len != 0;
}

/// Room for `want` more bytes at the end of the flight buffer, within `cap`.
pub fn reserve(self: *Flight, gpa: std.mem.Allocator, want: usize, cap: usize) Error![]u8 {
    @setRuntimeSafety(true);
    const needed = std.math.add(usize, self.used, want) catch return error.HandshakeLimit;
    if (needed > self.buf.len) {
        if (needed > cap) return error.HandshakeLimit;
        const capacity = @min(cap, @max(needed, @max(4096, self.buf.len * 2)));
        const grown = try gpa.alloc(u8, capacity);
        @memcpy(grown[0..self.used], self.buf[0..self.used]);
        std.crypto.secureZero(u8, self.buf);
        gpa.free(self.buf);
        self.buf = grown;
    }
    return self.buf[self.used..];
}

/// The `n` bytes just written at the end of the buffer are a message to send at `epoch`.
pub fn queueMessage(self: *Flight, epoch: Epoch, n: usize) error{QueueFull}!void {
    @setRuntimeSafety(true);
    // safe: the flight buffer is bounded by the handshake limit, well below 4 GiB.
    try self.push(.{ .message = .{ .epoch = epoch, .start = @intCast(self.used), .len = @intCast(n) } });
    self.used += n;
}

/// Bytes of a queued message; valid until `recycle` or the next reservation.
pub fn bytes(self: *const Flight, start: u32, len: u32) []const u8 {
    @setRuntimeSafety(true);
    return self.buf[start..][0..len];
}

/// Releases the buffer for reuse once every message queued so far was read.
pub fn recycle(self: *Flight) void {
    if (!self.pending()) self.used = 0;
}

/// Erases queued secrets and the buffer, and frees it.
pub fn deinit(self: *Flight, gpa: std.mem.Allocator) void {
    @setRuntimeSafety(true);
    for (&self.queue) |*slot| if (slot.*) |*emit| eraseEmit(emit);
    std.crypto.secureZero(u8, self.buf);
    gpa.free(self.buf);
    self.* = undefined;
}
