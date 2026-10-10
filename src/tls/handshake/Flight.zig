//! What a handshake machine hands to its driver: a bounded queue of outputs and the bytes of
//! the messages among them. Both roles queue the same things: messages to send, traffic
//! secrets to install, and completion; the driver turns them into records or QUIC events.
const std = @import("std");
const aegis = @import("aegis");
const State = @import("State.zig");
const suites = @import("../crypto/Suite.zig");
const Suite13 = suites.Suite13;
const Transcripts = @import("Transcripts.zig");

pub const Epoch = State.Epoch;
pub const Direction = enum { read, write };

/// A secret to install. The receiver owns and erases it.
pub const Traffic = struct {
    suite: Suite13,
    secret: aegis.Secret([Transcripts.max_digest]u8),
    len: u8,
};

/// TLS 1.2 record keys from the key block: the cipher's key and its fixed IV. The receiver owns
/// and erases them.
pub const Keys12 = struct {
    cipher: suites.Cipher,
    key: aegis.Secret([32]u8),
    iv: aegis.Secret([12]u8),

    pub fn keyBytes(self: *const Keys12) []const u8 {
        return self.key.expose()[0..keyLength(self.cipher)];
    }

    pub fn ivBytes(self: *const Keys12) []const u8 {
        return self.iv.expose()[0..self.cipher.fixedIvLength12()];
    }

    pub fn keyLength(cipher: suites.Cipher) usize {
        return if (cipher == .aes_128_gcm) 16 else 32;
    }

    pub fn deinit(self: *Keys12) void {
        self.key.deinit();
        self.iv.deinit();
    }
};

/// What a TLS 1.2 connection keeps beyond its handshake scratch: the extended master secret
/// and both randoms (for the key block and the exporter), and the record keys that wait for a
/// ChangeCipherSpec. Allocated only when TLS 1.2 is negotiated; erased when destroyed.
pub const Secrets12 = struct {
    master: aegis.Secret([48]u8) = .init(@splat(0)),
    /// client_random || server_random.
    randoms: [64]u8 = @splat(0),
    /// The peer's write keys, installed at its ChangeCipherSpec.
    read: ?Keys12 = null,
    /// The server's own write keys, installed when it sends its ChangeCipherSpec.
    write: ?Keys12 = null,

    pub fn create(gpa: std.mem.Allocator) error{OutOfMemory}!*Secrets12 {
        const secrets = try gpa.create(Secrets12);
        secrets.* = .{};
        return secrets;
    }

    pub fn clientRandom(self: *const Secrets12) *const [32]u8 {
        return self.randoms[0..32];
    }

    pub fn serverRandom(self: *const Secrets12) *const [32]u8 {
        return self.randoms[32..64];
    }

    pub fn destroy(self: *Secrets12, gpa: std.mem.Allocator) void {
        self.master.deinit();
        if (self.read) |*keys| keys.deinit();
        if (self.write) |*keys| keys.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        gpa.destroy(self);
    }
};

pub const Emit = union(enum) {
    /// A complete handshake message at `start` in the flight buffer.
    message: struct { epoch: Epoch, start: u32, len: u32 },
    secret: struct { direction: Direction, epoch: Epoch, traffic: Traffic },
    /// TLS 1.2: install these keys for `direction`; they protect the application epoch.
    keys12: struct { direction: Direction, keys: Keys12 },
    /// TLS 1.2: send a ChangeCipherSpec record now, under the current write state.
    change_cipher_spec,
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
        .keys12 => |*k| k.keys.deinit(),
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
