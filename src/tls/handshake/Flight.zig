//! What a handshake machine hands to its driver: a bounded queue of outputs and the bytes of
//! the messages among them. Both roles queue the same things: messages to send, traffic
//! secrets to install, and completion; the driver turns them into records or QUIC events.
const std = @import("std");
const aegis = @import("aegis");
const State = @import("State.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
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
        return self.key.expose()[0..self.cipher.keyLength()];
    }

    pub fn ivBytes(self: *const Keys12) []const u8 {
        return self.iv.expose()[0..self.cipher.fixedIvLength12()];
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

    /// The record keys of both directions from the key block (RFC 5246 section 6.3), written
    /// straight into the slots: `read` holds the peer's write keys, `write` this side's.
    pub fn deriveKeys(self: *Secrets12, comptime Hash: type, comptime suite: suites.Suite12, role: enum { client, server }) void {
        @setRuntimeSafety(true);
        const cipher = comptime suite.cipher();
        const key_len = comptime cipher.keyLength();
        const iv_len = comptime cipher.fixedIvLength12();
        var block = aegis.Secret([2 * (key_len + iv_len)]u8).init(undefined);
        defer block.deinit();
        Prf.keyBlock(Hash, block.exposeMut(), self.master.expose(), self.serverRandom(), self.clientRandom());
        const b = block.expose();
        const client, const server = switch (role) {
            .client => .{ &self.write, &self.read },
            .server => .{ &self.read, &self.write },
        };
        for ([_]*?Keys12{ client, server }) |slot| {
            if (slot.*) |*old| old.deinit();
            slot.* = .{ .cipher = cipher, .key = .init(@splat(0)), .iv = .init(@splat(0)) };
        }
        @memcpy(client.*.?.key.exposeMut()[0..key_len], b[0..key_len]);
        @memcpy(server.*.?.key.exposeMut()[0..key_len], b[key_len..][0..key_len]);
        @memcpy(client.*.?.iv.exposeMut()[0..iv_len], b[2 * key_len ..][0..iv_len]);
        @memcpy(server.*.?.iv.exposeMut()[0..iv_len], b[2 * key_len + iv_len ..][0..iv_len]);
    }

    /// Hands the keys in `slot` to the driver for `direction` and erases the slot.
    pub fn release(self: *Secrets12, machine: anytype, direction: Direction) !void {
        const slot = switch (direction) {
            .read => &self.read,
            .write => &self.write,
        };
        defer if (slot.*) |*keys| {
            keys.deinit();
            slot.* = null;
        };
        const keys = if (slot.*) |*keys| keys else return error.UnexpectedMessage;
        try machine.push(.{ .keys12 = .{ .direction = direction, .keys = keys.* } });
    }

    pub fn clientRandom(self: *const Secrets12) *const [32]u8 {
        return self.randoms[0..32];
    }

    pub fn serverRandom(self: *const Secrets12) *const [32]u8 {
        return self.randoms[32..64];
    }

    /// RFC 5705 keying material over the extended master secret. A context, even an empty one,
    /// enters the seed with its length; null leaves it out, as RFC 5705 distinguishes (DTLS-SRTP's
    /// "EXTRACTOR-dtls_srtp" takes none, RFC 5764 section 4.2).
    pub fn exportKeyingMaterial(self: *const Secrets12, suite: suites.Suite12, out: []u8, label: []const u8, context: ?[]const u8) Prf.ExportError!void {
        @setRuntimeSafety(true);
        switch (suite) {
            inline else => |tag| try Prf.exporter(suites.Hash12(tag), out, self.master.expose(), label, self.clientRandom(), self.serverRandom(), context),
        }
    }

    pub fn destroy(self: *Secrets12, gpa: std.mem.Allocator) void {
        self.master.deinit();
        if (self.read) |*keys| keys.deinit();
        if (self.write) |*keys| keys.deinit();
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        gpa.destroy(self);
    }
};

pub const RecordLimits = @import("RecordLimits.zig");

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
    /// TLS 1.2: the peer asked to renegotiate after the handshake. Answer with a warning
    /// no_renegotiation (always a warning, RFC 5246 section 7.2.2) and go on.
    refuse_renegotiation,
    /// RFC 8449: the record size limits this handshake negotiated, before the first record
    /// they bound.
    record_limits: RecordLimits,
    /// Everything this side owes has been queued and the peer is authenticated.
    complete,
    /// A client's answer to a post-handshake CertificateRequest is ready for the write half,
    /// which ends it with a Finished under its current keys (stream TLS 1.3 only).
    auth_response,
    /// A client's post-handshake Finished arrived: the read half checks it under its current
    /// keys before the authentication counts (stream TLS 1.3 only).
    auth_finished,
};

pub fn eraseEmit(emit: *Emit) void {
    switch (emit.*) {
        .secret => |*s| s.traffic.secret.deinit(),
        .keys12 => |*k| k.keys.deinit(),
        else => {},
    }
}

pub const Error = error{ QueueFull, OutOfMemory };

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

/// Moves the next output into `out`, which the caller then owns and erases with `eraseEmit`,
/// and erases the queue slot it came from. False when nothing is queued.
pub fn pop(self: *Flight, out: *Emit) bool {
    @setRuntimeSafety(true);
    if (self.len == 0) return false;
    const slot = &self.queue[self.head];
    out.* = slot.*.?;
    std.crypto.secureZero(u8, std.mem.asBytes(slot));
    slot.* = null;
    self.head = (self.head + 1) % self.queue.len;
    self.len -= 1;
    return true;
}

pub fn pending(self: *const Flight) bool {
    return self.len != 0;
}

/// Room for `want` more bytes at the end of the flight buffer, within `cap`. A flight past it is
/// this end's own output: QueueFull, an internal error, never the peer's.
pub fn reserve(self: *Flight, gpa: std.mem.Allocator, want: usize, cap: usize) Error![]u8 {
    @setRuntimeSafety(true);
    const needed = (aegis.int.Checked(usize).init(self.used).add(want) catch return error.QueueFull).raw();
    if (needed > self.buf.len) {
        if (needed > cap) return error.QueueFull;
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
