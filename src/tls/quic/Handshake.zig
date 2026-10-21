//! A QUIC handshake of either role (RFC 9001). The caller feeds the contiguous CRYPTO bytes of each
//! level to `receive`, drains `next` events (handshake bytes to send per level, traffic
//! secrets to install, the peer's transport parameters, authentication) and answers each
//! `request`. There is no TLS record, ChangeCipherSpec, KeyUpdate or close_notify here.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const Client = @import("../handshake/Client.zig");
const Machine = @import("../handshake/Machine.zig");
const Emit = @import("../handshake/Flight.zig").Emit;
const Server = @import("../handshake/Server.zig");
const Services = @import("../handshake/Services.zig");
const Suite13 = @import("../crypto/Suite.zig").Suite13;
const Suite = @import("../crypto/Suite.zig").Suite;
const Group = @import("../crypto/Group.zig").Group;
const Alert = @import("../wire/Alert.zig").Alert;
const Ech = @import("../handshake/Ech.zig");
const Compression = @import("../handshake/Compression.zig");
const Psk = @import("../handshake/Psk.zig");

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
    /// TLS 1.3 suites only: QUIC is TLS 1.3.
    suites: []const Suite = Suite.tls13_only,
    groups: []const Group = Group.default,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA, its whole path to the anchor (TLS 1.3); a server
    /// requiring it of clients needs a required, verified client certificate.
    require_pq_auth: bool = false,
    /// The signature schemes taken from the peer, in this end's order, restricting cloak's and
    /// never adding to them (FIPS, CNSA or the caller's own policy); borrowed, at most 16.
    peer_schemes: []const @import("../handshake/Hello.zig").SignatureScheme = &.{},
    /// What a CertificateRequest is answered with, in this client's order, each with its
    /// delegated credential (RFC 9345): the first the request takes that chains to an authority
    /// it names (RFC 8446 section 4.2.4), else the first; borrowed. At most 32, certificates or
    /// raw keys (RFC 7250) or both, of the type the server selects.
    credentials: []const @import("../handshake/Client.zig").Credential = &.{},
    /// certificate_authorities (RFC 8446 section 4.2.4): the DER Names of the anchors this client
    /// trusts, named in a hello offering TLS 1.3, a server's preference among its credentials;
    /// borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a server's delegated credential (RFC 9345): its key proves possession for the
    /// verified certificate that signed it. TLS 1.3, with full verification.
    accept_delegated: bool = false,
    /// TLS 1.3 session resumption from a ticket cache (no early data: QUIC 0-RTT is not offered).
    resumption: ?Client.Resumption = null,
    /// Encrypted Client Hello (RFC 9849); a config list makes it required.
    ech: Ech.Mode = .off,
    /// GREASE (RFC 8701): reserved values in the hello, which servers must ignore, drawn per
    /// connection; a server that refuses them is found now rather than when a real one comes.
    grease: bool = false,
    /// Certificate decoders to offer (RFC 8879); borrowed.
    certificate_compression: []const Compression.Codec = &.{},
    /// Provisioned keys to offer (PSK-DHE), plain or imported (RFC 9258); borrowed.
    external_psks: []const Psk.External = &.{},
    limits: Client.Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const ServerOptions = struct {
    /// Chains the server can present, with the names each answers for. At least one.
    credentials: []const Server.Credential,
    /// The server's transport parameters: the quic_transport_parameters extension body.
    parameters: []const u8,
    /// Application protocols in the server's order of preference, required.
    alpn: []const []const u8,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    /// TLS 1.3 suites only: QUIC is TLS 1.3.
    suites: []const Suite = Suite.tls13_only,
    groups: []const Group = Group.default,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA, its whole path to the anchor (TLS 1.3); a server
    /// requiring it of clients needs a required, verified client certificate.
    require_pq_auth: bool = false,
    /// The signature schemes taken from the peer, in this end's order, restricting cloak's and
    /// never adding to them (FIPS, CNSA or the caller's own policy); borrowed, at most 16.
    peer_schemes: []const @import("../handshake/Hello.zig").SignatureScheme = &.{},
    client_auth: Server.Auth = .none,
    client_verify: Verify = .none,
    /// certificate_authorities (RFC 8446 section 4.2.4; RFC 5246 section 7.4.4 in TLS 1.2): the
    /// DER Names of the client anchors every CertificateRequest names, a client's preference
    /// among its credentials; borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a client's delegated credential (RFC 9345): TLS 1.3, a client certificate asked for
    /// and fully verified.
    accept_delegated: bool = false,
    /// Session tickets to issue and resume from; tickets never permit 0-RTT.
    tickets: ?*Server.TicketKeys = null,
    /// Encrypted Client Hello keys (RFC 9849), borrowed for the life of the handshake.
    ech_keys: []const Ech.Key = &.{},
    /// Certificate encoders (RFC 8879) in the server's order of preference; borrowed.
    certificate_compression: []const Compression.Codec = &.{},
    /// Provisioned keys, looked up by the offered identity (PSK-DHE).
    external_psk: ?Psk.Lookup = null,
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
    secret: struct { level: Level, direction: Direction, suite: Suite13, bytes: []const u8 },
    /// The peer's transport parameters, provisional until it is authenticated (a server is
    /// authenticated by its certificate, a client by its Finished); answer with
    /// `acceptParameters` or `rejectParameters`.
    peer_parameters: []const u8,
    /// The peer is authenticated and its Finished verified; the handshake is complete.
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
hs: Machine,
services: Services,
partial: [3]Partial = @splat(.{}),
current: ?Current = null,
failed: bool = false,
alert: ?Alert = null,
parameters_offered: bool = false,

pub fn client(gpa: std.mem.Allocator, options: Options) InitError!Handshake {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
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
            .require_pq_auth = options.require_pq_auth,
            .peer_schemes = options.peer_schemes,
            .accept_delegated = options.accept_delegated,
            .certificate_authorities = options.certificate_authorities,
            .transport = .quic,
            .parameters = options.parameters,
            .certificate_compression = options.certificate_compression,
        },
        .resumption = options.resumption,
        .ech = options.ech,
        .external_psks = options.external_psks,
        .grease = options.grease,
        .identity = options.identity,
        .verify = options.verify,
        .credentials = options.credentials,
        .limits = options.limits,
        .compat = false,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = Machine.forClient(hs), .services = .init(options.generation) };
}

/// A server handshake. The client's transport parameters arrive as a `peer_parameters` event.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions) InitError!Handshake {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (options.alpn.len == 0) return error.InvalidOptions;
    const hs = try Server.init(gpa, .{
        .suites = options.suites,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = true,
        .require_hybrid = options.require_hybrid,
        .require_pq_auth = options.require_pq_auth,
        .peer_schemes = options.peer_schemes,
        .transport = .quic,
        .parameters = options.parameters,
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .client_auth = options.client_auth,
        .client_verify = options.client_verify,
        .certificate_authorities = options.certificate_authorities,
        .accept_delegated = options.accept_delegated,
        .tickets = options.tickets,
        .ech_keys = options.ech_keys,
        .certificate_compression = options.certificate_compression,
        .external_psk = options.external_psk,
        .limits = options.limits,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = .{ .state = .{ .server = hs } }, .services = .init(options.generation) };
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

/// After an ech_required failure: the authenticated retry configurations; see
/// `Connection.echRetryConfigs`.
pub fn echRetryConfigs(self: *const Handshake) ?[]const u8 {
    return self.hs.echRetryConfigs();
}

pub const ExportError = Client.ExportError;
pub fn exportKeyingMaterial(self: *const Handshake, out: []u8, label: []const u8, context: ?[]const u8) ExportError!void {
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    return self.hs.exportKeyingMaterial(out, label, context);
}

// ---------------------------------------------------------------- services

pub fn request(self: *Handshake) ?Request {
    if (self.failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Handshake, token: types.Token, answer: Answer) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.abort(fatal),
    };
}

/// The peer's transport parameters are acceptable; the handshake may continue.
pub fn acceptParameters(self: *Handshake) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.failed) return error.Closed;
    self.hs.provideParameters(true) catch |err| return self.abort(err);
}

/// The peer's transport parameters are not: the handshake ends with `alert`.
pub fn rejectParameters(self: *Handshake, alert: Alert) void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
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
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
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
        // request does not change keys, and the real ServerHello follows it at the same level;
        // the second ClientHello is likewise sent again at the initial level.
        const opening: u8 = if (self.hs.role() == .server) 1 else 2;
        if ((message[0] == opening and self.hs.negotiated()) or (message[0] == 20 and level == .handshake)) slot.closed = true;
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
        if (total > self.hs.messageLimit()) return error.HandshakeLimit;
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
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.current == null) self.advance();
    const current = &(self.current orelse return null);
    return switch (current.*) {
        .data => |d| .{ .handshake_data = .{ .level = d.level, .bytes = self.hs.flightBytes(d.start + d.acked, d.len - d.acked), .flight_end = d.flight_end } },
        .secret => |*s| .{ .secret = .{ .level = s.level, .direction = s.direction, .suite = s.traffic.suite, .bytes = s.traffic.secret.expose()[0..s.traffic.len] } },
        .parameters => .{ .peer_parameters = self.hs.peerParameters() },
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
    var emit: Emit = undefined;
    while (self.hs.pop(&emit)) switch (emit) {
        .message => |m| {
            // safe: the flight buffer is bounded by the handshake limit, below 4 GiB.
            self.current = .{ .data = .{ .level = levelOf(m.epoch), .start = m.start, .len = m.len, .acked = 0, .flight_end = !self.hs.pending() } };
            return;
        },
        .secret => |*s| {
            // The secret moves to the event; the copy it came in is erased.
            self.current = .{ .secret = .{ .level = levelOf(s.epoch), .direction = s.direction, .traffic = s.traffic } };
            std.crypto.secureZero(u8, std.mem.asBytes(&emit));
            return;
        },
        .complete => {
            self.current = .authenticated;
            return;
        },
        // The client's flight to a server that rejected ECH is queued above: ech_required now.
        .rejected => {
            self.fail(.ech_required);
            return;
        },
        .ticket => {},
        .compat_ccs, .key_update, .keys12, .change_cipher_spec, .refuse_renegotiation, .auth_response, .auth_finished, .record_limits => {
            // None exists in QUIC: the state table rejects them before they can be queued, and
            // post-handshake authentication is never offered or kept (RFC 9001 section 4.4).
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
            aegis.assert.pre(consumed <= d.len - d.acked, "the caller acknowledges at most the event's data");
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
    _ = @import("ServerHandshake_test.zig");
    _ = @import("Admission_test.zig");
}
