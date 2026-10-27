//! What a handshake machine hands to its driver: a bounded queue of outputs and the bytes of
//! the messages among them. Both roles queue the same things: messages to send, traffic
//! secrets to install, and completion; the driver turns them into records or QUIC events.
const std = @import("std");
const aegis = @import("aegis");
const Buffer = @import("../wire/Buffer.zig");
const State = @import("State.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
const Suite13 = suites.Suite13;
const Transcripts = @import("Transcripts.zig");

pub const Epoch = State.Epoch;
pub const Direction = enum { read, write };

/// A secret to install. The receiver owns and erases it. Holders are made where they are kept
/// and moved, never copied: each copy of a secret is one more to erase.
pub const Traffic = struct {
    suite: Suite13,
    secret: aegis.Secret([Transcripts.max_digest]u8),
    len: u8,

    /// Makes `self` a holder of `secret`, a digest of `suite`'s hash.
    pub fn init(self: *Traffic, suite: Suite13, secret: []const u8) void {
        @setRuntimeSafety(true);
        // safe: the secret length is a digest length, at most 48.
        self.* = .{ .suite = suite, .secret = .init(@splat(0)), .len = @intCast(secret.len) };
        @memcpy(self.secret.exposeMut()[0..secret.len], secret);
    }

    /// Moves the secret into `out` and erases it here.
    pub fn moveInto(self: *Traffic, out: *Traffic) void {
        out.suite = self.suite;
        out.len = self.len;
        self.secret.moveInto(&out.secret);
    }
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

    /// Moves the keys into `out` and erases them here.
    pub fn moveInto(self: *Keys12, out: *Keys12) void {
        out.cipher = self.cipher;
        self.key.moveInto(&out.key);
        self.iv.moveInto(&out.iv);
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
        const emit = try machine.claim();
        emit.* = .{ .keys12 = .{ .direction = direction, .keys = undefined } };
        keys.moveInto(&emit.keys12.keys);
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
        // The randoms went in the clear in both hellos: the owners above held every secret.
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
    /// A client's handshake with its outer hello is complete and the server rejected ECH: the
    /// connection ends now with ech_required (`EchRejected`), its flight already queued (RFC 9849
    /// section 6.1.6).
    rejected,
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

/// Moves `from` into `to`, its secrets by their owners' `moveInto`, which erases them in `from`.
pub fn moveEmit(from: *Emit, to: *Emit) void {
    switch (from.*) {
        .secret => |*s| {
            to.* = .{ .secret = .{ .direction = s.direction, .epoch = s.epoch, .traffic = undefined } };
            s.traffic.moveInto(&to.secret.traffic);
        },
        .keys12 => |*k| {
            to.* = .{ .keys12 = .{ .direction = k.direction, .keys = undefined } };
            k.keys.moveInto(&to.keys12.keys);
        },
        else => to.* = from.*,
    }
}

pub const Error = error{ QueueFull, OutOfMemory };

const Flight = @This();

queue: [16]?Emit = @splat(null),
head: usize = 0,
len: usize = 0,
/// The messages queued, which carry handshake plaintext.
buf: Buffer = .{},
used: usize = 0,

/// Queues `emit`, which carries no secret.
pub fn push(self: *Flight, emit: Emit) error{QueueFull}!void {
    (try self.claim()).* = emit;
}

/// Claims the next queue slot for an output made in place: a secret is written straight into
/// its slot, never passed by value.
pub fn claim(self: *Flight) error{QueueFull}!*Emit {
    @setRuntimeSafety(true);
    if (self.len == self.queue.len) return error.QueueFull;
    const claimed = &self.queue[(self.head + self.len) % self.queue.len];
    claimed.* = @as(Emit, .complete);
    self.len += 1;
    return &claimed.*.?;
}

/// Moves the next output into `out`, which the caller then owns and erases with `eraseEmit`,
/// and erases the queue slot it came from. False when nothing is queued.
pub fn pop(self: *Flight, out: *Emit) bool {
    @setRuntimeSafety(true);
    if (self.len == 0) return false;
    const slot = &self.queue[self.head];
    moveEmit(&slot.*.?, out);
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
    if (needed > self.buf.view().len) {
        if (needed > cap) return error.QueueFull;
        _ = try self.buf.ensure(gpa, @min(cap, @max(needed, @max(4096, self.buf.view().len * 2))));
    }
    return self.buf.bytes()[self.used..];
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
    return self.buf.view()[start..][0..len];
}

/// Releases the buffer for reuse once every message queued so far was read.
pub fn recycle(self: *Flight) void {
    if (!self.pending()) self.used = 0;
}

/// Erases queued secrets and the buffer, and frees it.
pub fn deinit(self: *Flight, gpa: std.mem.Allocator) void {
    @setRuntimeSafety(true);
    for (&self.queue) |*slot| if (slot.*) |*emit| eraseEmit(emit);
    self.buf.free(gpa);
    self.* = undefined;
}
