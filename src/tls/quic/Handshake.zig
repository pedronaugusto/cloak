//! A QUIC client handshake (RFC 9001). The caller feeds the contiguous CRYPTO bytes of each
//! level to `receive`, drains `next` events (handshake bytes to send per level, traffic
//! secrets to install, the peer's transport parameters, authentication) and answers each
//! `request`. There is no TLS record, ChangeCipherSpec, KeyUpdate or close_notify here.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("cloak.certificates");
const types = certificates.types;
const Client = @import("../handshake/Client.zig");
const Services = @import("../handshake/Services.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Group = @import("../crypto/Group.zig").Group;
const Alert = @import("../wire/Alert.zig").Alert;

pub const Level = enum { initial, handshake, application };
pub const Direction = Client.Direction;
pub const Verify = Client.Verify;
pub const KeyLog = Client.KeyLog;
pub const Info = Client.Info;
pub const Request = Services.Request;
pub const Answer = Services.Answer;
pub const Service = Services.Service;
pub const VerifyFailure = Services.VerifyFailure;

pub const Options = struct {
    identity: types.Identity,
    verify: Verify,
    /// The caller's QUIC transport parameters: the quic_transport_parameters extension body.
    parameters: []const u8,
    /// Application protocols, required: QUIC runs only under ALPN.
    alpn: []const []const u8,
    server_name: ServerName = .identity,
    suites: []const Suite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    require_hybrid: bool = false,
    auth: ?certificates.ClientAuth = null,
    limits: Client.Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const ServerName = union(enum) {
    identity,
    name: []const u8,
    none,
};

/// A unit of work for the caller. Borrowed bytes stay valid until `ack`.
pub const Event = union(enum) {
    /// Handshake bytes to send as CRYPTO data at `level`. `flight_end` hints that nothing
    /// more is queued now: a scheduling hint, not a packet boundary.
    handshake_data: struct { level: Level, bytes: []const u8, flight_end: bool },
    /// A traffic secret (a hash-length byte string) to derive packet keys from. Copy it
    /// before `ack`, which erases it. Direction is relative to this endpoint.
    secret: struct { level: Level, direction: Direction, suite: Suite, bytes: []const u8 },
    /// The server's transport parameters, provisional until authentication; answer with
    /// `acceptParameters` or `rejectParameters`.
    peer_parameters: []const u8,
    /// The server is authenticated and Finished verified; the local Finished is queued.
    authenticated: Info,
    /// The handshake failed with this description (QUIC crypto error 0x100 plus it).
    alert: Alert,
};

pub const InitError = Client.InitError;
pub const Error = Client.Error || error{ Closed, StaleToken, NoRequest, LevelClosed, EventPending };

const Handshake = @This();

const Current = union(enum) {
    data: struct { level: Level, start: u32, len: u32, acked: u32, flight_end: bool },
    secret: struct { level: Level, direction: Direction, traffic: Client.Traffic },
    parameters,
    authenticated,
    alert: Alert,
};

const Partial = struct {
    buf: []u8 = &.{},
    have: usize = 0,
    total: usize = 0,
    /// A key-changing message ended this level: nothing more may follow at it.
    closed: bool = false,
};

gpa: std.mem.Allocator,
hs: *Client,
services: Services,
partial: [3]Partial = @splat(.{}),
current: ?Current = null,
failed: bool = false,
alert: ?Alert = null,
parameters_offered: bool = false,

pub fn client(gpa: std.mem.Allocator, options: Options) InitError!Handshake {
    @setRuntimeSafety(true);
    if (options.alpn.len == 0) return error.InvalidOptions;
    const sni: []const u8 = switch (options.server_name) {
        .identity => switch (options.identity) {
            .dns => |name| name,
            else => "",
        },
        .name => |name| name,
        .none => "",
    };
    const hs = try Client.init(gpa, .{
        .hello = .{
            .suites = options.suites,
            .groups = options.groups,
            .sni = sni,
            .alpn = options.alpn,
            .require_alpn = true,
            .require_hybrid = options.require_hybrid,
            .quic = true,
            .parameters = options.parameters,
        },
        .identity = options.identity,
        .verify = options.verify,
        .auth = options.auth,
        .limits = options.limits,
        .compat = false,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = hs, .services = .init(options.generation) };
}

pub fn deinit(self: *Handshake) void {
    @setRuntimeSafety(true);
    if (self.current) |*current| if (current.* == .secret) current.secret.traffic.secret.deinit();
    for (&self.partial) |*p| if (p.buf.len != 0) {
        std.crypto.secureZero(u8, p.buf);
        self.gpa.free(p.buf);
    };
    self.hs.deinit();
    self.* = undefined;
}

/// Negotiated parameters; null before authentication.
pub fn info(self: *const Handshake) ?Info {
    if (self.failed) return null;
    return self.hs.info();
}

pub fn failure(self: *const Handshake) ?Alert {
    return self.alert;
}

pub const ExportError = Client.ExportError;
pub fn exportKeyingMaterial(self: *const Handshake, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    return self.hs.exportKeyingMaterial(out, label, context);
}

// ---------------------------------------------------------------- services

pub fn request(self: *Handshake) ?Request {
    if (self.failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Handshake, token: types.Token, answer: Answer) Error!void {
    @setRuntimeSafety(true);
    if (self.failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.abort(fatal),
    };
}

/// The peer's transport parameters are acceptable; the handshake may continue.
pub fn acceptParameters(self: *Handshake) Error!void {
    @setRuntimeSafety(true);
    if (self.failed) return error.Closed;
    self.hs.provideParameters(true) catch |err| return self.abort(err);
}

/// The peer's transport parameters are not: the handshake ends with `alert`.
pub fn rejectParameters(self: *Handshake, alert: Alert) void {
    @setRuntimeSafety(true);
    self.fail(alert);
}

fn abort(self: *Handshake, err: Error) Error {
    self.fail(self.services.alertFor(err));
    return err;
}

fn fail(self: *Handshake, alert: Alert) void {
    @setRuntimeSafety(true);
    if (self.failed) return;
    self.failed = true;
    self.alert = alert;
    if (self.current) |*current| if (current.* == .secret) current.secret.traffic.secret.deinit();
    self.current = .{ .alert = alert };
    self.hs.wipe();
}

// ---------------------------------------------------------------- input

fn epoch(level: Level) Client.Epoch {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
}

fn blocked(self: *const Handshake) bool {
    return self.failed or self.current != null or self.hs.need() != .none or self.hs.pending();
}

/// Takes the contiguous handshake bytes of `level`, starting where the last call at that
/// level ended, and processes each complete message. It consumes less than all of `bytes`
/// when events or a request are outstanding; drain them and call again with the rest.
pub fn receive(self: *Handshake, level: Level, bytes: []const u8) Error!usize {
    @setRuntimeSafety(true);
    if (self.failed) return error.Closed;
    return self.receiveChecked(level, bytes) catch |err| return self.abort(err);
}

fn receiveChecked(self: *Handshake, level: Level, bytes: []const u8) Error!usize {
    @setRuntimeSafety(true);
    const slot = &self.partial[@backingInt(level)];
    if (slot.closed and bytes.len != 0) return error.LevelClosed;
    var consumed: usize = 0;
    while (consumed < bytes.len and !self.blocked()) {
        // A message may not straddle two levels.
        for (&self.partial, 0..) |*other, i| {
            if (i != @backingInt(level) and other.have != 0) return error.UnexpectedMessage;
        }
        consumed += try self.take(slot, bytes[consumed..]);
        if (slot.total == 0 or slot.have != slot.total) continue;
        const message = slot.buf[0..slot.total];
        const boundary = consumed == bytes.len;
        slot.have = 0;
        slot.total = 0;
        try self.hs.receive(message, epoch(level), boundary);
        // A message that changes keys ends its level: nothing may follow it there. A retry
        // request does not change keys, and the real ServerHello follows it at the same level.
        if ((message[0] == 2 and self.hs.group != null) or (message[0] == 20 and level == .handshake)) slot.closed = true;
        if (slot.closed and consumed != bytes.len) return error.RecordAlignment;
    }
    return consumed;
}

/// Copies the next part of a message into the level's buffer: its header first, then its body.
fn take(self: *Handshake, slot: *Partial, bytes: []const u8) Error!usize {
    @setRuntimeSafety(true);
    var used: usize = 0;
    if (slot.have < 4) {
        if (slot.buf.len < 4) slot.buf = try self.gpa.alloc(u8, 4);
        const n = @min(4 - slot.have, bytes.len);
        @memcpy(slot.buf[slot.have..][0..n], bytes[0..n]);
        slot.have += n;
        used = n;
        if (slot.have < 4) return used;
        const total = 4 + @as(usize, std.mem.readInt(u24, slot.buf[1..4], .big));
        if (total > self.hs.options.limits.message) return error.HandshakeLimit;
        if (slot.buf.len < total) {
            const grown = try self.gpa.alloc(u8, total);
            @memcpy(grown[0..4], slot.buf[0..4]);
            self.gpa.free(slot.buf);
            slot.buf = grown;
        }
        slot.total = total;
    }
    const n = @min(slot.total - slot.have, bytes.len - used);
    @memcpy(slot.buf[slot.have..][0..n], bytes[used..][0..n]);
    slot.have += n;
    return used + n;
}

// ---------------------------------------------------------------- output

/// The next event, or null when there is none. The same event is returned until `ack`.
pub fn next(self: *Handshake) ?Event {
    @setRuntimeSafety(true);
    if (self.current == null) self.advance();
    const current = &(self.current orelse return null);
    return switch (current.*) {
        .data => |d| .{ .handshake_data = .{ .level = d.level, .bytes = self.hs.flightBytes(d.start + d.acked, d.len - d.acked), .flight_end = d.flight_end } },
        .secret => |*s| .{ .secret = .{ .level = s.level, .direction = s.direction, .suite = s.traffic.suite, .bytes = s.traffic.secret.expose()[0..s.traffic.len] } },
        .parameters => .{ .peer_parameters = self.hs.peer_parameters },
        .authenticated => .{ .authenticated = self.hs.info().? },
        .alert => |alert| .{ .alert = alert },
    };
}

fn levelOf(e: Client.Epoch) Level {
    return switch (e) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
}

/// Takes the next queued output as the current event.
fn advance(self: *Handshake) void {
    @setRuntimeSafety(true);
    while (self.hs.pop()) |emit| switch (emit) {
        .message => |m| {
            // safe: the flight buffer is bounded by the handshake limit, below 4 GiB.
            self.current = .{ .data = .{ .level = levelOf(m.epoch), .start = m.start, .len = m.len, .acked = 0, .flight_end = !self.hs.pending() } };
            return;
        },
        .secret => |s| {
            self.current = .{ .secret = .{ .level = levelOf(s.epoch), .direction = s.direction, .traffic = s.traffic } };
            return;
        },
        .complete => {
            self.current = .authenticated;
            return;
        },
        .ticket => {},
        .compat_ccs, .key_update => {
            // Neither exists in QUIC: the state table rejects them before they can be queued.
            self.fail(.internal_error);
            return;
        },
    };
    if (self.hs.need() == .parameters and !self.parameters_offered) {
        self.parameters_offered = true;
        self.current = .parameters;
    }
}

/// Acknowledges `consumed` bytes of a handshake_data event, or releases any other event.
/// A secret event is erased. Partial acknowledgement keeps the rest as the same event.
pub fn ack(self: *Handshake, consumed: usize) void {
    @setRuntimeSafety(true);
    const current = &(self.current orelse return);
    switch (current.*) {
        .data => |*d| {
            std.debug.assert(consumed <= d.len - d.acked);
            // safe: the remainder of a message is at most its u32 length.
            d.acked += @intCast(consumed);
            if (d.acked < d.len) return;
            self.current = null;
            self.hs.recycle();
        },
        .secret => |*s| {
            s.traffic.secret.deinit();
            self.current = null;
        },
        .parameters, .authenticated, .alert => self.current = null,
    }
}

test {
    _ = @import("Handshake_test.zig");
}
