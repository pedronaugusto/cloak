//! The running handshake hash. Until a hello names the suite both candidate hashes run;
//! the choice then fixes one and erases the other.
const std = @import("std");
const aegis = @import("aegis");
const Transcript = @import("Transcript.zig").Transcript;
const Suite13 = @import("../crypto/Suite.zig").Suite13;
const suites = @import("../crypto/Suite.zig");

const Sha256 = Transcript(std.crypto.hash.sha2.Sha256);
const Sha384 = Transcript(std.crypto.hash.sha2.Sha384);

pub const max_digest = std.crypto.hash.sha2.Sha384.digest_length;
pub const CommitError = @import("Transcript.zig").CommitError || std.mem.Allocator.Error;

/// Keeps every message committed from now on, as well as hashing it.
pub fn keep(self: *Self, gpa: std.mem.Allocator) void {
    self.keeper = gpa;
}

/// Every message kept so far, in order.
pub fn keptBytes(self: *const Self) []const u8 {
    return self.kept.expose(); // aegis: design: the kept messages, lent until the transcript is released
}

/// Erases and frees the kept messages and stops keeping.
pub fn release(self: *Self) void {
    @setRuntimeSafety(true);
    if (self.keeper) |gpa| self.kept.deinit(gpa);
    self.kept = .empty;
    self.keeper = null;
}

/// Erases the hashes and the kept messages.
pub fn deinit(self: *Self) void {
    @setRuntimeSafety(true);
    self.release();
    self.state.deinit();
    if (self.datagram12) |*datagram| if (datagram.shadow) |*shadow| shadow.deinit();
    self.* = undefined;
}

/// Moves the transcript into `destination`, its hashes by their owners' `moveInto`, which erases
/// them here.
pub fn moveInto(self: *Self, destination: *Self) void {
    @setRuntimeSafety(true);
    destination.* = .{ .state = undefined, .kept = self.kept, .keeper = self.keeper };
    self.state.moveInto(&destination.state);
    if (self.datagram12) |*datagram| {
        destination.datagram12 = .{ .own = datagram.own, .peer = datagram.peer, .shadow = null };
        if (datagram.shadow) |*shadow| {
            destination.datagram12.?.shadow = @as(aegis.Secret(Both), undefined);
            shadow.moveInto(&destination.datagram12.?.shadow.?);
        }
    }
    self.* = undefined;
}

/// A TLS 1.3 transcript over the same messages, to be continued apart: the hashes copied into an
/// owner of its own, nothing kept. The caller deinits it.
pub fn fork(self: *const Self) Self {
    aegis.assert.pre(self.datagram12 == null, "a forked transcript has no DTLS 1.2 form");
    return .{ .state = .init(self.state.expose().*) };
}

/// Both candidate hashes, run until a hello names the suite.
const Both = struct { sha256: Sha256 = .{}, sha384: Sha384 = .{} };
const State = union(enum) {
    pending: Both,
    sha256: Sha256,
    sha384: Sha384,
};

/// The hashes run over the handshake's plaintext: a secret, as everything derived from it is.
state: aegis.Secret(State) = .init(.{ .pending = .{} }),
/// A datagram handshake that may be DTLS 1.2, whose transcript hashes each message with its
/// DTLS header (RFC 6347 section 4.2.6); null for TLS, QUIC and DTLS 1.3.
datagram12: ?Datagram12 = null,
/// The messages themselves, kept while `keeper` is set: a TLS 1.2 CertificateVerify by Ed25519
/// signs the handshake messages, not a digest of them (RFC 8422 section 5.10).
kept: aegis.SecretBytes = .empty,
keeper: ?std.mem.Allocator = null,

const Self = @This();

/// DTLS 1.2's numbering and, while the version is open, its form of the transcript.
pub const Datagram12 = struct {
    /// The message_seq of the next message this side sends, and of the next the peer sends.
    own: u16,
    peer: u16,
    /// The DTLS 1.2 form run beside `state` (which holds the TLS form) while a client that
    /// offered both versions waits for the ServerHello; null once `state` holds the DTLS form.
    shadow: ?aegis.Secret(Both),
};

pub const Side = enum { own, peer };

/// Numbers messages from `own` and `peer` and hashes them in their DTLS 1.2 form: beside the
/// TLS form when the version is still open (`open`), instead of it otherwise. Called before the
/// first commit.
pub fn startDatagram(self: *Self, own: u16, peer: u16, open: bool) void {
    aegis.assert.invariant(self.messages() == 0, "a datagram transcript starts before its first message");
    self.datagram12 = .{ .own = own, .peer = peer, .shadow = if (open) .init(.{}) else null };
}

/// The datagram handshake is DTLS 1.2: the DTLS form becomes the transcript.
pub fn choose12(self: *Self) void {
    @setRuntimeSafety(true);
    const datagram = &(self.datagram12 orelse return);
    const shadow = &(datagram.shadow orelse return);
    self.replace(.{ .pending = shadow.expose().* });
    shadow.deinit();
    datagram.shadow = null;
}

/// A HelloVerifyRequest arrived (DTLS 1.2): the first hello and the request leave the
/// transcript (RFC 6347 section 4.2.1); the numbering goes on, the request counted.
pub fn restart(self: *Self) void {
    @setRuntimeSafety(true);
    const datagram = &(self.datagram12 orelse return);
    datagram.peer +%= 1;
    self.replace(.{ .pending = .{} });
    if (datagram.shadow) |*shadow| {
        shadow.deinit();
        shadow.* = .init(.{});
    }
    // unreachable: a shrink is within the capacity; it erases what it drops.
    self.kept.resizeWithinCapacity(0) catch unreachable;
}

/// Erases every byte of the state, the larger variant's included, before it takes `next`.
fn replace(self: *Self, next: State) void {
    self.state.deinit();
    self.state = .init(next);
}

/// Appends `bytes` to the kept messages; growing erases the storage it leaves.
fn keepBytes(self: *Self, gpa: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
    @setRuntimeSafety(true);
    self.kept.appendSlice(gpa, bytes) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // unreachable: a committed message is never inside the buffer it is kept in.
        error.Overlap => unreachable,
    };
}

fn messages(self: *const Self) usize {
    return switch (self.state.expose().*) {
        .pending => |*both| both.sha256.messages,
        inline else => |*t| t.messages,
    };
}

/// Fixes the hash once; a later call must name the same hash family. TLS 1.3 needs no messages
/// kept.
pub fn select(self: *Self, suite: Suite13) void {
    @setRuntimeSafety(true);
    self.release();
    // TLS 1.3 hashes the TLS form, in DTLS too (RFC 9147 section 5.2).
    self.datagram12 = null;
    switch (self.state.expose().*) {
        .pending => |*both| {
            const hash384 = suites.digestLength(suite) == 48;
            var hashes: aegis.Secret(Both) = .init(both.*);
            defer hashes.deinit();
            self.replace(if (hash384) .{ .sha384 = hashes.expose().sha384 } else .{ .sha256 = hashes.expose().sha256 });
        },
        .sha256 => aegis.assert.invariant(suites.digestLength(suite) == 32, "a SHA-256 suite has 32-byte digests"),
        .sha384 => aegis.assert.invariant(suites.digestLength(suite) == 48, "a SHA-384 suite has 48-byte digests"),
    }
}

/// Commits a message the peer sent.
pub fn commit(self: *Self, message: []const u8) CommitError!void {
    return self.commitFrom(.peer, message);
}

/// Commits a message this side sends.
pub fn commitOwn(self: *Self, message: []const u8) CommitError!void {
    return self.commitFrom(.own, message);
}

fn commitFrom(self: *Self, side: Side, message: []const u8) CommitError!void {
    @setRuntimeSafety(true);
    const datagram = if (self.datagram12) |*d| d else {
        try commitTo(self.state.exposeMut(), message, null);
        // The transcript's own bounds, checked above, hold the kept bytes to the handshake limit.
        if (self.keeper) |gpa| try self.keepBytes(gpa, message);
        return;
    };
    const counter = switch (side) {
        .own => &datagram.own,
        .peer => &datagram.peer,
    };
    const sequence = counter.*;
    if (datagram.shadow) |*shadow| {
        // The version is open: the TLS form in `state`, the DTLS form beside it.
        try commitTo(self.state.exposeMut(), message, null);
        try shadow.exposeMut().sha256.commitDatagram(message, sequence);
        try shadow.exposeMut().sha384.commitDatagram(message, sequence);
    } else try commitTo(self.state.exposeMut(), message, sequence);
    counter.* +%= 1;
    // Only DTLS 1.2 uses the kept messages, so they are kept in its form.
    if (self.keeper) |gpa| {
        var header: [12]u8 = undefined;
        @import("Transcript.zig").datagramHeader(&header, message, sequence);
        try self.keepBytes(gpa, &header);
        try self.keepBytes(gpa, message[4..]);
    }
}

fn commitTo(state: *State, message: []const u8, datagram: ?u16) CommitError!void {
    switch (state.*) {
        .pending => |*both| {
            if (datagram) |sequence| {
                try both.sha256.commitDatagram(message, sequence);
                try both.sha384.commitDatagram(message, sequence);
            } else {
                try both.sha256.commit(message);
                try both.sha384.commit(message);
            }
        },
        inline .sha256, .sha384 => |*t| if (datagram) |sequence| try t.commitDatagram(message, sequence) else try t.commit(message),
    }
}

/// A transcript that starts at a retry request sent without state: the first hello's hash under
/// `suite`'s hash, then the request (DTLS's stateless cookie exchange).
pub fn restoreRetry(self: *Self, suite: Suite13, hello_hash: []const u8, hrr: []const u8) CommitError!void {
    @setRuntimeSafety(true);
    self.select(suite);
    switch (self.state.exposeMut().*) {
        .pending => unreachable, // selected above
        .sha256 => |*t| try t.restoreRetry(hello_hash, hrr),
        .sha384 => |*t| try t.restoreRetry(hello_hash, hrr),
    }
}

/// Replaces the ClientHello by its synthetic message_hash and commits the retry request.
pub fn retry(self: *Self, hrr: []const u8) CommitError!void {
    @setRuntimeSafety(true);
    switch (self.state.exposeMut().*) {
        .pending => unreachable, // the suite is selected before a retry request is committed
        .sha256 => |*t| try t.retry(hrr),
        .sha384 => |*t| try t.retry(hrr),
    }
}

/// Digest of everything committed so far under the hash of `len` bytes (32 or 48). TLS 1.2
/// keeps both hashes running: its PRF hash and a CertificateVerify's hash can differ.
pub fn digestOf(self: *const Self, out: *[max_digest]u8, len: usize) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state.expose().*) {
        .pending => |*both| {
            if (len == 48) {
                out.* = both.sha384.digest();
                return out[0..48];
            }
            aegis.assert.invariant(len == 32, "the other digest is SHA-256's");
            out[0..32].* = both.sha256.digest();
            return out[0..32];
        },
        else => {
            const d = self.digest(out);
            aegis.assert.invariant(d.len == len, "the digest is the length asked for");
            return d;
        },
    }
}

/// Digest under the hash of `len` bytes of everything committed so far followed by `extra`, which
/// is not committed: a ClientHello up to its PSK binders, which the binders themselves cover.
pub fn digestWith(self: *const Self, out: *[max_digest]u8, len: usize, extra: []const u8) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state.expose().*) {
        .pending => |*both| return if (len == 48) finishWith(Sha384, &both.sha384, out, extra) else finishWith(Sha256, &both.sha256, out, extra),
        .sha256 => |*t| {
            aegis.assert.invariant(len == 32, "a SHA-256 transcript gives 32 bytes");
            return finishWith(Sha256, t, out, extra);
        },
        .sha384 => |*t| {
            aegis.assert.invariant(len == 48, "a SHA-384 transcript gives 48 bytes");
            return finishWith(Sha384, t, out, extra);
        },
    }
}

fn finishWith(comptime T: type, transcript: *const T, out: *[max_digest]u8, extra: []const u8) []const u8 {
    var hash = transcript.hash;
    hash.update(extra);
    const n = @TypeOf(hash).digest_length;
    hash.final(out[0..n]);
    return out[0..n];
}

/// Digest of everything committed so far; only meaningful once the hash is selected.
pub fn digest(self: *const Self, out: *[max_digest]u8) []const u8 {
    @setRuntimeSafety(true);
    switch (self.state.expose().*) {
        .pending => unreachable, // callers digest only after the suite is known
        .sha256 => |*t| {
            const d = t.digest();
            out[0..d.len].* = d;
            return out[0..d.len];
        },
        .sha384 => |*t| {
            const d = t.digest();
            out[0..d.len].* = d;
            return out[0..d.len];
        },
    }
}

/// The TLS 1.3 transcript once its hash is chosen, without the rest a running handshake keeps:
/// what a post-handshake authentication starts every exchange from (RFC 8446 section 4.4).
pub const Selected = union(enum) {
    sha256: Sha256,
    sha384: Sha384,

    pub fn commit(self: *Selected, message: []const u8) CommitError!void {
        switch (self.*) {
            inline else => |*t| try t.commit(message),
        }
    }

    /// Digest of everything committed so far, the suite's hash length.
    pub fn digest(self: *const Selected, out: *[max_digest]u8) []const u8 {
        switch (self.*) {
            inline else => |*t| {
                const d = t.digest();
                out[0..d.len].* = d;
                return out[0..d.len];
            },
        }
    }
};

/// The chosen hash's state, to be continued apart from this transcript. Only once the suite is
/// selected, and never for a datagram transcript of DTLS 1.2.
pub fn selected(self: *const Self) Selected {
    aegis.assert.pre(self.datagram12 == null, "a TLS 1.3 transcript has no DTLS 1.2 form");
    return switch (self.state.expose().*) {
        .pending => unreachable, // unreachable: the suite is selected before the handshake completes
        .sha256 => |t| .{ .sha256 = t },
        .sha384 => |t| .{ .sha384 = t },
    };
}

test "C2 transcripts select the suite hash and erase the other" {
    var transcripts: Self = .{};
    try transcripts.commit("\x01\x00\x00\x02hi");
    transcripts.select(.aes_256_gcm_sha384);
    var out: [max_digest]u8 = undefined;
    var expected: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("\x01\x00\x00\x02hi", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, transcripts.digest(&out));
    var other: Self = .{};
    try other.commit("\x01\x00\x00\x02hi");
    other.select(.chacha20_poly1305_sha256);
    var short: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("\x01\x00\x00\x02hi", &short, .{});
    try std.testing.expectEqualSlices(u8, &short, other.digest(&out));
}
