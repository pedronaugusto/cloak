//! A sans-I/O TLS connection, client or server, TLS 1.3 or 1.2. The caller feeds wire bytes to
//! `receive`, writes what `output` holds and acknowledges it, answers each `request` through
//! `provide`, and reads authenticated plaintext from `readable`. The connection owns record
//! keys, sequence numbers and the handshake; it never touches a socket, a clock or a random
//! source.
//!
//! The handshake runs on one task. Once it completes the connection is two halves with record
//! states of their own: the read half (`receive`, `readable`, `consume`, `trim`, `receiveEof`)
//! and the write half (`send`, `keyUpdate`, `finish`, `output`, `acknowledge`, `trimOutput`).
//! One task may use each at the same time as another uses the other. What the read half owes the
//! write half (the KeyUpdate a peer's request asks for, a key update of its own, a warning, the
//! fatal alert a read failure sends) crosses through atomic state and is written by the write
//! half at its next call, `output` included; status (`phase`, `diagnostics`, `readClosed`) may be
//! read from either. `info`, `certificateRequested` and `exportKeyingMaterial` read what the
//! handshake fixed and may be called from either task while the connection lives.
const std = @import("std");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Client = @import("handshake/Client.zig");
const Machine = @import("handshake/Machine.zig");
const Server = @import("handshake/Server.zig");
const Services = @import("handshake/Services.zig");
const Messages = @import("handshake/Messages.zig");
const Group = @import("crypto/Group.zig").Group;
const Suite = @import("crypto/Suite.zig").Suite;
const Version = @import("crypto/Suite.zig").Version;
const Protection = @import("record/Protection.zig");
const Alert = @import("wire/Alert.zig").Alert;
const Outbox = @import("connection/Outbox.zig");
const Flight = @import("handshake/Flight.zig");

pub const Epoch = Client.Epoch;
pub const Verify = Client.Verify;
pub const Resumption = Client.Resumption;
pub const SessionCache = @import("resumption/SessionCache.zig");
pub const TicketKeys = Server.TicketKeys;
pub const KeyLog = Client.KeyLog;
pub const Info = Client.Info;
pub const SignRequest = Client.SignRequest;

pub const Limits = struct {
    handshake: Client.Limits = .{},
    /// Records and plaintext bytes per direction and epoch before a key update; tests lower them.
    records: u64 = 1 << 24,
    bytes: u64 = 1 << 38,
    /// Committed ciphertext awaiting the transport.
    output: usize = 128 * 1024,
    /// Control messages (tickets, key updates) accepted in a row without application data.
    control: usize = 64,
    /// Records processed by one `receive` before it returns.
    step_records: usize = 64,
};

pub const ServerName = union(enum) {
    /// The reference identity when it is a DNS name; none for an address.
    identity,
    name: []const u8,
    none,
};

pub const ClientOptions = struct {
    /// What the server certificate must identify. Required for full verification.
    identity: types.Identity,
    /// The peer-verification policy. Required: there is no implicit default.
    verify: Verify,
    server_name: ServerName = .identity,
    /// Suites of both versions in preference order; the version follows from the suite.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions. `min_version = .tls13` refuses TLS 1.2 peers;
    /// `max_version = .tls12` speaks only TLS 1.2.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    auth: ?certificates.ClientAuth = null,
    /// TLS 1.3 session resumption from a ticket cache.
    resumption: ?Resumption = null,
    limits: Limits = .{},
    /// Send a random legacy session id and one change_cipher_spec for middleboxes.
    compat: bool = true,
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Service = Services.Service;
pub const Request = Services.Request;
pub const VerifyFailure = Services.VerifyFailure;
pub const Answer = Services.Answer;

pub const Phase = enum(u8) { handshaking, connected, closed, failed };

pub const Diagnostics = struct {
    phase: Phase,
    reason: ?Error,
    alert_sent: ?Alert,
    alert_received: ?Alert,
};

pub const InitError = Client.InitError || error{InvalidOptions};
/// Everything that ends a connection, local or from the peer.
pub const Error = Client.Error || Protection.InitError || Protection.SealError || Protection.OpenError || Protection.UpdateError || Outbox.Error || error{
    BadRecord,
    RecordOverflow,
    RecordLimit,
    PeerAlert,
    UnexpectedRecord,
    ControlFlood,
    Truncated,
    Closed,
    EarlyDataLimit,
};
pub const ProvideError = Error || error{ StaleToken, NoRequest };
pub const ReceiveError = Error;
pub const SendError = Error || error{ NotConnected, WriteClosed };
pub const FinishError = SendError;

const max_content = 1 << 14;
/// Early data a server skips, in record bytes, before the client's real flight (design 5.5).
pub const max_early_skip = 64 * 1024;
const max_record = 5 + max_content + 256;
/// The most a record adds around a plaintext fragment: header, TLS 1.3 inner content type or
/// TLS 1.2 explicit nonce, and AEAD tag.
const record_overhead = Protection.max_overhead;
const Connection = @This();

gpa: std.mem.Allocator,
hs: Machine,
limits: Limits,
rx: ?Protection = null,
tx: ?Protection = null,
rx_epoch: Epoch = .initial,
tx_epoch: Epoch = .initial,
phase_now: std.atomic.Value(Phase) = .init(.handshaking),
/// Set once the handshake completes: from then on the halves may run on two tasks.
split: bool = false,
/// What the handshake negotiated, taken as it completes, before the halves may run on two
/// tasks: either may read it while the read half goes on using the handshake's state.
negotiated: ?Info = null,
services: Services,
// Inbound record and handshake message reassembly.
record: []u8 = &.{},
head: [5]u8 = undefined,
record_have: usize = 0,
plain_kind: ?Protection.Content = null,
plain_pos: usize = 0,
plain_end: usize = 0,
header: [4]u8 = undefined,
header_have: u8 = 0,
message: []u8 = &.{},
message_total: usize = 0,
message_have: usize = 0,
seen_ccs: bool = false,
sent_hello: bool = false,
control_run: usize = 0,
alerts_ignored: u8 = 0,
/// Early data skipped so far, and whether the client's handshake records have begun.
early_skipped: usize = 0,
early_done: bool = false,
// Outbound.
outbox: Outbox = .{},
read_done: std.atomic.Value(bool) = .init(false),
write_done: std.atomic.Value(bool) = .init(false),
rx_asked_update: bool = false,
/// The first failure, as an error value's integer; zero for none.
failure: std.atomic.Value(u16) = .init(0),
alert_sent: std.atomic.Value(u16) = .init(no_alert),
alert_received: std.atomic.Value(u16) = .init(no_alert),
/// What the read half owes the write half (`owe_*` bits), and the fatal alert it owes.
owed: std.atomic.Value(u8) = .init(0),
owed_alert: std.atomic.Value(u8) = .init(0),

const no_alert: u16 = 0x100;
const owe_key_update: u8 = 1;
const owe_update_request: u8 = 2;
const owe_no_renegotiation: u8 = 4;
const owe_fatal: u8 = 8;
/// The connection failed in the read half: the write half erases its keys.
const owe_teardown: u8 = 16;

pub fn client(gpa: std.mem.Allocator, options: ClientOptions) InitError!Connection {
    @setRuntimeSafety(true);
    // A fully qualified name's trailing dot names the same host; neither the server name
    // sent (RFC 6066 section 3) nor a certificate's names carry it.
    const identity: types.Identity = switch (options.identity) {
        .dns => |name| if (name.len > 1 and name[name.len - 1] == '.') .{ .dns = name[0 .. name.len - 1] } else options.identity,
        else => options.identity,
    };
    const sni: []const u8 = switch (options.server_name) {
        .identity => switch (identity) {
            .dns => |name| name,
            else => "",
        },
        .name => |name| name,
        .none => "",
    };
    const hs = try Client.init(gpa, .{
        .hello = .{
            .suites = options.suites,
            .min_version = options.min_version,
            .max_version = options.max_version,
            .groups = options.groups,
            .sni = sni,
            .alpn = options.alpn,
            .require_alpn = options.require_alpn,
            .require_hybrid = options.require_hybrid,
        },
        .resumption = options.resumption,
        .identity = identity,
        .verify = options.verify,
        .auth = options.auth,
        .limits = options.limits.handshake,
        .compat = options.compat,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = .{ .state = .{ .client = hs } }, .limits = options.limits, .services = .init(options.generation) };
}

pub const ServerOptions = struct {
    /// Chains the server can present, with the names each answers for. At least one.
    credentials: []const Server.Credential,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    /// Suites of both versions in preference order; the version follows from the suite.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions. `min_version = .tls13` refuses TLS 1.2 peers;
    /// `max_version = .tls12` speaks only TLS 1.2.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    /// Application protocols in the server's order of preference.
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    client_auth: Server.Auth = .none,
    /// How a presented client chain is checked; required for authenticated client identities.
    client_verify: Verify = .none,
    /// Session tickets to issue and resume from; shared, and outliving the connection.
    tickets: ?*Server.TicketKeys = null,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

/// A server connection: the same record, request and key handling around the server handshake.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions) InitError!Connection {
    @setRuntimeSafety(true);
    const hs = try Server.init(gpa, .{
        .suites = options.suites,
        .min_version = options.min_version,
        .max_version = options.max_version,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .client_auth = options.client_auth,
        .client_verify = options.client_verify,
        .tickets = options.tickets,
        .limits = options.limits.handshake,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = .{ .state = .{ .server = hs } }, .limits = options.limits, .services = .init(options.generation) };
}

pub fn deinit(self: *Connection) void {
    @setRuntimeSafety(true);
    if (self.rx) |*p| p.deinit();
    if (self.tx) |*p| p.deinit();
    self.hs.deinit();
    if (self.record.len != 0) {
        std.crypto.secureZero(u8, self.record);
        self.gpa.free(self.record);
    }
    if (self.message.len != 0) {
        std.crypto.secureZero(u8, self.message);
        self.gpa.free(self.message);
    }
    self.outbox.deinit(self.gpa);
    self.* = undefined;
}

// ---------------------------------------------------------------- status

pub fn phase(self: *const Connection) Phase {
    return self.phase_now.load(.acquire);
}

pub fn diagnostics(self: *const Connection) Diagnostics {
    // A fatal alert the read half owes is the one this side sends, written or not yet.
    const sent = if (self.owed.load(.acquire) & owe_fatal != 0) self.owed_alert.load(.acquire) else self.alert_sent.load(.acquire);
    return .{ .phase = self.phase(), .reason = self.failureError(), .alert_sent = alertOf(sent), .alert_received = alertOf(self.alert_received.load(.acquire)) };
}

fn alertOf(code: u16) ?Alert {
    if (code == no_alert) return null;
    return @fromBackingInt(@as(u8, @intCast(code))); // safe: stored codes are alert bytes or no_alert
}

fn failureError(self: *const Connection) ?Error {
    const code = self.failure.load(.acquire);
    if (code == 0) return null;
    return @errorCast(@errorFromInt(code));
}

/// Records the first failure; a later one, from the other half, keeps it.
fn recordFailure(self: *Connection, err: Error) void {
    _ = self.failure.cmpxchgStrong(0, @intFromError(err), .acq_rel, .acquire);
    self.phase_now.store(.failed, .release);
}

/// Whether the server asked this client for a certificate (or this server asks its client for
/// one), whether or not the handshake completed.
pub fn certificateRequested(self: *const Connection) bool {
    return self.hs.certificateRequested();
}

/// Negotiated parameters; null before the handshake completes and after a failure.
pub fn info(self: *const Connection) ?Info {
    if (self.phase() == .failed) return null;
    return self.negotiated;
}

/// True once the peer sent close_notify: no more plaintext will arrive.
pub fn readClosed(self: *const Connection) bool {
    return self.read_done.load(.acquire);
}

pub const ExportError = Client.ExportError;
pub fn exportKeyingMaterial(self: *const Connection, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    if (self.phase() == .failed) return error.WrongPhase;
    return self.hs.exportKeyingMaterial(out, label, context);
}

/// Returns the read half's idle buffers: the record and message buffers when no partial input
/// is held, and the handshake scratch once it is established; before the handshake completes,
/// the output buffer too. Safe to call at any time; the next input acquires them again.
pub fn trim(self: *Connection) void {
    @setRuntimeSafety(true);
    if (self.record_have == 0 and self.plain_kind == null and self.record.len != 0) {
        std.crypto.secureZero(u8, self.record);
        self.gpa.free(self.record);
        self.record = &.{};
    }
    if (self.message_total == 0 and self.header_have == 0 and self.message.len != 0) {
        std.crypto.secureZero(u8, self.message);
        self.gpa.free(self.message);
        self.message = &.{};
    }
    if (!self.split) self.outbox.trim(self.gpa);
    self.hs.settle();
}

/// Returns the output buffer when nothing is pending; the write half's `trim`.
pub fn trimOutput(self: *Connection) void {
    self.outbox.trim(self.gpa);
}

// ---------------------------------------------------------------- services

/// The service the engine is waiting for, if any. Answer it with `provide`.
pub fn request(self: *Connection) ?Request {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Connection, token: types.Token, answer: Answer) ProvideError!void {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        // These leave the request open: a wrong token or a rejected scalar draw is not fatal.
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.readFailed(fatal),
    };
    self.drain() catch |err| return self.readFailed(err);
    // Plaintext buffered while the engine waited continues without new input.
    _ = self.receiveChecked(&.{}) catch |err| return self.readFailed(err);
}

// ---------------------------------------------------------------- failure

fn alertFor(self: *const Connection, err: Error) Alert {
    return switch (err) {
        error.BadRecord => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.UnexpectedRecord, error.ControlFlood, error.EarlyDataLimit => .unexpected_message,
        else => self.services.alertFor(err),
    };
}

/// Whether a failure tells the peer with a fatal alert: not the peer's own alert, nor a close.
fn alerts(err: Error) bool {
    return err != error.PeerAlert and err != error.Closed;
}

/// A failure of the read half (or of the handshake): it ends the connection. Before the
/// handshake completes one task holds both halves, and the fatal alert goes out now; after it,
/// the alert is owed to the write half, which sends it at its next call and erases its keys.
fn failRead(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (!self.split) return self.failWhole(err);
    if (self.phase() == .failed and self.rx == null) return;
    self.recordFailure(err);
    if (alerts(err)) self.owed_alert.store(@backingInt(self.alertFor(err)), .release);
    _ = self.owed.fetchOr(if (alerts(err)) owe_fatal | owe_teardown else owe_teardown, .seq_cst);
    if (self.rx) |*p| p.deinit();
    self.rx = null;
    self.plain_kind = null;
}

/// A failure of the write half ends the connection: one fatal alert under the write keys while
/// they last, then they are erased. The read half sees the failure at its next call.
fn failWrite(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (!self.split) return self.failWhole(err);
    if (self.phase() == .failed and self.tx == null) return;
    self.recordFailure(err);
    if (alerts(err) and self.tx != null) self.sendAlert(2, self.alertFor(err));
    if (self.tx) |*p| p.deinit();
    self.tx = null;
}

/// Ends a connection one task holds whole: one fatal alert when keys allow it, and every secret
/// erased.
fn failWhole(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return;
    self.recordFailure(err);
    if (alerts(err)) self.sendAlert(2, self.alertFor(err));
    if (self.rx) |*p| p.deinit();
    if (self.tx) |*p| p.deinit();
    self.rx = null;
    self.tx = null;
    self.hs.wipe();
    self.plain_kind = null;
}

fn sendAlert(self: *Connection, level: u8, alert: Alert) void {
    @setRuntimeSafety(true);
    const body = [2]u8{ level, @backingInt(alert) };
    const dst = self.outbox.tail(self.gpa, body.len + record_overhead, self.limits.output + max_record) catch return;
    const wire = self.sealRecord(.alert, &body, dst) catch return;
    self.outbox.commit(wire.len);
    self.alert_sent.store(@backingInt(alert), .release);
}

/// Writes what the read half owes, in the write half: a fatal alert (then the write keys go), a
/// KeyUpdate answering or asking for one, a warning no_renegotiation.
fn writeOwed(self: *Connection) void {
    @setRuntimeSafety(true);
    const bits = self.owed.swap(0, .acq_rel);
    if (bits & owe_fatal != 0) {
        if (self.tx != null) self.sendAlert(2, @fromBackingInt(self.owed_alert.load(.acquire)));
    }
    if (self.phase() == .failed) {
        if (self.tx) |*p| p.deinit();
        self.tx = null;
        return;
    }
    if (self.write_done.load(.acquire)) return;
    if (bits & owe_no_renegotiation != 0) self.sendAlert(1, .no_renegotiation);
    if (bits & (owe_key_update | owe_update_request) != 0) {
        self.sendKeyUpdate(bits & owe_update_request != 0) catch |err| self.failWrite(err);
    }
}

/// Owes the write half `bits`; written at once before the handshake completes.
fn owe(self: *Connection, bits: u8) Error!void {
    if (!self.split) {
        _ = self.owed.fetchOr(bits, .seq_cst);
        self.writeOwed();
        if (self.failureError()) |err| return err;
        return;
    }
    _ = self.owed.fetchOr(bits, .seq_cst);
}

/// One record of `content` in the current transmit epoch.
fn sealRecord(self: *Connection, content: Protection.Content, body: []const u8, dst: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (self.tx) |*protection| return protection.seal(content, body, 0, dst);
    dst[0] = @backingInt(content);
    dst[1..3].* = .{ 3, 3 };
    // safe: plaintext fragments are at most 2^14 bytes.
    std.mem.writeInt(u16, dst[3..5], @intCast(body.len), .big);
    @memcpy(dst[5..][0..body.len], body);
    return dst[0 .. 5 + body.len];
}

// ---------------------------------------------------------------- outbound

/// Whether the read half owes the write half something to send: a KeyUpdate, a warning, the
/// fatal alert of a failure. `output` writes it. A read-modify-write, so that a task that
/// releases the write half and then asks cannot miss what the other task owed meanwhile.
pub fn owes(self: *Connection) bool {
    return self.owed.fetchOr(0, .seq_cst) != 0;
}

/// Ciphertext to write to the transport, after what the read half owes is written.
pub fn output(self: *Connection) []const u8 {
    if (self.owes()) self.writeOwed();
    return self.outbox.pending();
}

pub fn acknowledge(self: *Connection, n: usize) void {
    self.outbox.acknowledge(n);
}

fn sealMessage(self: *Connection, epoch: Epoch, message: []const u8) Error!void {
    @setRuntimeSafety(true);
    // Handshake messages are the handshake's; after it the read half queues none.
    std.debug.assert(!self.split);
    if (epoch != self.tx_epoch) return error.UnexpectedRecord;
    var rest = message;
    while (rest.len != 0) {
        const n = @min(rest.len, max_content);
        const dst = try self.outbox.tail(self.gpa, n + record_overhead, self.limits.output + max_record);
        const wire = try self.sealRecord(.handshake, rest[0..n], dst);
        if (self.tx == null and !self.sent_hello and self.hs.role() == .client) {
            // The first record of a ClientHello may carry the older legacy version.
            dst[1..3].* = .{ 3, 1 };
        }
        self.outbox.commit(wire.len);
        rest = rest[n..];
    }
    if (epoch == .initial) self.sent_hello = true;
}

fn sealCompatCcs(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const dst = try self.outbox.tail(self.gpa, 6, self.limits.output + max_record);
    dst[0..6].* = .{ 20, 3, 3, 0, 1, 1 };
    self.outbox.commit(6);
}

/// Installs a traffic secret; `drain` erases the output that carried it.
fn install(self: *Connection, s: anytype) Error!void {
    @setRuntimeSafety(true);
    const traffic = &s.traffic;
    var protection = try Protection.init(traffic.suite, traffic.secret.expose()[0..traffic.len], .{ .records = self.limits.records, .bytes = self.limits.bytes });
    errdefer protection.deinit();
    switch (s.direction) {
        .read => {
            if (self.rx) |*old| old.deinit();
            self.rx = protection;
            self.rx_epoch = s.epoch;
            self.rx_asked_update = false;
        },
        .write => {
            if (self.tx) |*old| old.deinit();
            self.tx = protection;
            self.tx_epoch = s.epoch;
        },
    }
}

/// TLS 1.2 record keys for one direction; they protect the application epoch.
fn install12(self: *Connection, direction: Flight.Direction, keys: *const Flight.Keys12) Error!void {
    @setRuntimeSafety(true);
    var protection = try Protection.init12(keys.cipher, keys.keyBytes(), keys.ivBytes(), .{ .records = self.limits.records, .bytes = self.limits.bytes });
    errdefer protection.deinit();
    switch (direction) {
        .read => {
            if (self.rx) |*old| old.deinit();
            self.rx = protection;
            self.rx_epoch = .application;
        },
        .write => {
            if (self.tx) |*old| old.deinit();
            self.tx = protection;
            self.tx_epoch = .application;
        },
    }
}

/// Moves everything the handshake queued onto the wire and into the key slots, in order.
fn drain(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    // One named copy of each output, erased once used: a secret or key passes through here.
    var emit: Flight.Emit = undefined;
    while (self.hs.pop(&emit)) {
        defer Flight.eraseEmit(&emit);
        switch (emit) {
            .message => |m| try self.sealMessage(m.epoch, self.hs.flightBytes(m.start, m.len)),
            .secret => |*s| try self.install(s),
            .compat_ccs, .change_cipher_spec => try self.sealCompatCcs(),
            .keys12 => |*k| try self.install12(k.direction, &k.keys),
            .key_update => |u| try self.onPeerKeyUpdate(u.request_peer),
            .ticket => try self.onControl(),
            .refuse_renegotiation => {
                try self.onControl();
                try self.owe(owe_no_renegotiation);
            },
            .complete => {
                self.hs.settle();
                self.negotiated = self.hs.info();
                self.phase_now.store(.connected, .release);
                self.split = true;
            },
        }
    }
    self.hs.recycle();
}

fn onControl(self: *Connection) Error!void {
    self.control_run += 1;
    if (self.control_run > self.limits.control) return error.ControlFlood;
}

fn onPeerKeyUpdate(self: *Connection, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    try self.onControl();
    try self.rx.?.update();
    self.rx_asked_update = false;
    if (request_peer) try self.owe(owe_key_update);
}

/// KeyUpdate under the old write key, then the next write secret (RFC 8446 section 4.6.3).
fn sendKeyUpdate(self: *Connection, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    // TLS 1.2 has no key update; its connection closes before the record or byte cap instead.
    if (self.tx.?.tls12()) return error.NoKeyUpdate;
    var message_buf: [5]u8 = undefined;
    const message = try Messages.buildKeyUpdate(&message_buf, request_peer);
    const dst = try self.outbox.tail(self.gpa, message.len + record_overhead, self.limits.output + max_record);
    const wire = try self.tx.?.seal(.handshake, message, 0, dst);
    self.outbox.commit(wire.len);
    try self.tx.?.update();
}

/// Queues a key update before the write epoch can run out of records or bytes.
fn budgetWrite(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const left = self.tx.?.remaining();
    if (left.records < 4 or left.bytes < 2 * max_content) {
        if (self.tx.?.tls12()) return error.RecordLimit;
        try self.sendKeyUpdate(false);
    }
}

/// Accepts the longest prefix of `plaintext` that fits one record; returns its length. Zero
/// means the output backlog must drain first.
pub fn send(self: *Connection, plaintext: []const u8) SendError!usize {
    @setRuntimeSafety(true);
    self.writeOwed();
    if (self.phase() == .failed) return error.Closed;
    if (self.phase() != .connected) return error.NotConnected;
    if (self.write_done.load(.acquire)) return error.WriteClosed;
    if (plaintext.len == 0) return 0;
    const n = @min(plaintext.len, max_content);
    if (self.outbox.pending().len + n + record_overhead > self.limits.output) return 0;
    self.budgetWrite() catch |err| return self.writeFailed(err);
    const dst = self.outbox.tail(self.gpa, n + record_overhead, self.limits.output + max_record) catch |err| return self.writeFailed(err);
    const wire = self.tx.?.seal(.application, plaintext[0..n], 0, dst) catch |err| return self.writeFailed(err);
    self.outbox.commit(wire.len);
    return n;
}

/// A local failure while writing is terminal for the connection.
fn writeFailed(self: *Connection, err: Error) Error {
    self.failWrite(err);
    return err;
}

/// A failure while reading or in the handshake is terminal for the connection.
fn readFailed(self: *Connection, err: Error) Error {
    self.failRead(err);
    return err;
}

/// Asks for new keys in one direction or both (`request_peer`).
pub fn keyUpdate(self: *Connection, request_peer: bool) SendError!void {
    @setRuntimeSafety(true);
    self.writeOwed();
    if (self.phase() != .connected) return error.NotConnected;
    if (self.write_done.load(.acquire)) return error.WriteClosed;
    // TLS 1.2 has none: a refusal, not a failure of the connection.
    if (self.tx.?.tls12()) return error.NoKeyUpdate;
    self.sendKeyUpdate(request_peer) catch |err| return self.writeFailed(err);
}

/// Queues close_notify. The write side is finished; reading continues until the peer's own.
pub fn finish(self: *Connection) FinishError!void {
    @setRuntimeSafety(true);
    self.writeOwed();
    if (self.phase() == .failed) return error.Closed;
    if (self.write_done.load(.acquire)) return;
    if (self.phase() == .connected) {
        self.sendAlert(1, .close_notify);
    }
    self.write_done.store(true, .release);
    self.settlePhase();
}

/// Closed once both halves are done; either half may be the second.
fn settlePhase(self: *Connection) void {
    if (self.read_done.load(.acquire) and self.write_done.load(.acquire)) {
        _ = self.phase_now.cmpxchgStrong(.connected, .closed, .acq_rel, .acquire);
    }
}

// ---------------------------------------------------------------- inbound

/// Plaintext waiting for the application; empty when none.
pub fn readable(self: *const Connection) []const u8 {
    @setRuntimeSafety(true);
    if (self.plain_kind != .application) return &.{};
    return self.record[self.plain_pos..self.plain_end];
}

pub fn consume(self: *Connection, n: usize) void {
    @setRuntimeSafety(true);
    std.debug.assert(n <= self.plain_end - self.plain_pos);
    self.plain_pos += n;
    if (self.plain_pos == self.plain_end and self.plain_kind == .application) self.clearRecord();
}

fn clearRecord(self: *Connection) void {
    self.plain_kind = null;
    self.plain_pos = 0;
    self.plain_end = 0;
    self.record_have = 0;
}

fn blocked(self: *const Connection) bool {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return true;
    if (self.plain_kind == .application) return true;
    if (self.hs.need() != .none) return true;
    // The handshake's output must drain before more input; after it, the output is the write
    // half's, and what the read half owes it is a few bits that do not grow.
    return !self.split and self.outbox.pending().len > self.limits.output;
}

/// Consumes wire bytes, decrypting and processing whole records. It returns early when the
/// engine is waiting for an answer, plaintext is unread, or output must drain; call it again
/// with the unconsumed remainder.
pub fn receive(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) {
        // The write half failed: the read keys go too.
        if (self.rx) |*p| p.deinit();
        self.rx = null;
        self.plain_kind = null;
        return error.Closed;
    }
    if (self.read_done.load(.acquire)) return error.Closed;
    return self.receiveChecked(input) catch |err| return self.readFailed(err);
}

fn receiveChecked(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    var consumed: usize = 0;
    var records: usize = 0;
    while (true) {
        if (self.blocked() or self.read_done.load(.acquire)) return consumed;
        if (self.plain_kind != null) {
            try self.dispatch();
            continue;
        }
        if (consumed == input.len or records == self.limits.step_records) return consumed;
        consumed += try self.fill(input[consumed..]);
        if (self.recordComplete()) {
            records += 1;
            try self.openRecord();
        }
    }
}

fn recordComplete(self: *const Connection) bool {
    return self.record_have >= 5 and self.record_have == 5 + std.mem.readInt(u16, self.record[3..5], .big);
}

/// Copies the next part of a record: its header first, then a buffer sized to its length.
fn fill(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    var used: usize = 0;
    if (self.record_have < 5) {
        const n = @min(5 - self.record_have, input.len);
        @memcpy(self.head[self.record_have..][0..n], input[0..n]);
        self.record_have += n;
        used = n;
        if (self.record_have < 5) return used;
        try self.checkHeader();
        const total = 5 + @as(usize, std.mem.readInt(u16, self.head[3..5], .big));
        if (self.record.len < total) {
            if (self.record.len != 0) self.gpa.free(self.record);
            self.record = &.{};
            self.record = try self.gpa.alloc(u8, total);
        }
        @memcpy(self.record[0..5], &self.head);
    }
    const total = 5 + @as(usize, std.mem.readInt(u16, self.record[3..5], .big));
    const n = @min(total - self.record_have, input.len - used);
    @memcpy(self.record[self.record_have..][0..n], input[used..][0..n]);
    self.record_have += n;
    return used + n;
}

fn checkHeader(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    const kind = self.head[0];
    const length = std.mem.readInt(u16, self.head[3..5], .big);
    // Before any key the record version is legacy and only TLS-shaped (RFC 8446 section 5.1):
    // a ClientHello, or a refusal, may come as TLS 1.0 to 1.2. Protected records say TLS 1.2.
    const plaintext = self.rx == null and kind != 23;
    const version_ok = std.mem.eql(u8, self.head[1..3], &.{ 3, 3 }) or (plaintext and self.head[1] == 3 and self.head[2] >= 1 and self.head[2] <= 2);
    if (!version_ok) return error.UnexpectedRecord;
    // Under TLS 1.2 keys, alerts and handshake records are encrypted like application data.
    const sealed12 = if (self.rx) |*p| p.tls12() else false;
    switch (kind) {
        20 => if (length == 0 or length > max_content) return error.RecordOverflow,
        21, 22 => if (sealed12) {
            if (length > max_content + 256) return error.RecordOverflow;
            if (length < 16) return error.BadRecord;
        } else if (length == 0 or length > max_content) return error.RecordOverflow,
        23 => {
            if (length > max_content + 256) return error.RecordOverflow;
            // A TLS 1.3 record holds at least its content type and tag; a TLS 1.2 one its tag.
            if (length < @as(u16, if (sealed12) 16 else 17)) return error.BadRecord;
        },
        else => return error.UnexpectedRecord,
    }
}

/// Where opened plaintext starts in the record buffer: after the header, and after a TLS 1.2
/// explicit nonce.
fn offsetOf(self: *const Connection, plain: []const u8) usize {
    return @intFromPtr(plain.ptr) - @intFromPtr(self.record.ptr); // safe: the plaintext is a slice of the record buffer, so its address is not below the buffer's
}

fn openRecord(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const wire = self.record[0..self.record_have];
    switch (wire[0]) {
        20 => {
            if (self.hs.version() == .tls12) {
                // TLS 1.2: the one ChangeCipherSpec, plaintext, between messages, where the state
                // table expects it; anywhere else it is an injection (CVE-2014-0224).
                if (wire.len != 6 or wire[5] != 1 or self.rx != null or self.message_total != 0 or self.header_have != 0) return error.UnexpectedRecord;
                self.record_have = 0;
                try self.hs.receiveCcs();
                try self.drain();
                return;
            }
            // A single compatibility change_cipher_spec, only before the peer's Finished and
            // only between messages, is ignored (RFC 8446 appendix D.4).
            const allowed = self.hs.compat() and !self.seen_ccs and self.phase() == .handshaking and
                self.message_total == 0 and self.header_have == 0 and wire.len == 6 and wire[5] == 1;
            if (!allowed) return error.UnexpectedRecord;
            self.seen_ccs = true;
            self.record_have = 0;
        },
        21, 22 => {
            if (self.rx) |*protection| {
                if (!protection.tls12()) return error.UnexpectedRecord;
                const plain = try protection.open(wire, self.record[5..]);
                self.plain_kind = plain.content;
                self.plain_pos = self.offsetOf(plain.bytes);
                self.plain_end = self.plain_pos + plain.bytes.len;
                return;
            }
            self.plain_kind = if (wire[0] == 21) .alert else .handshake;
            self.plain_pos = 5;
            self.plain_end = wire.len;
        },
        else => {
            const skip = if (self.early_done) .none else self.hs.earlySkip();
            const protection = &(self.rx orelse {
                // Early data before the server's handshake keys: after a retry request, every
                // protected record before the second hello is the client's declined early data.
                if (skip != .none) return self.skipEarly(wire.len);
                return error.UnexpectedRecord;
            });
            const plain = if (skip == .trial and self.rx_epoch == .handshake) trial: {
                // Declined early data fails under the handshake keys and is skipped; the first
                // record that opens begins the client's flight, and skipping ends.
                const opened = protection.trialOpen(wire, self.record[5..]) catch |err| switch (err) {
                    error.Undecryptable => return self.skipEarly(wire.len),
                    else => |e| return e,
                };
                self.early_done = true;
                break :trial opened;
            } else try protection.open(wire, self.record[5..]);
            if (plain.content == .application) {
                if (self.phase() != .connected) return error.UnexpectedRecord;
                self.control_run = 0;
            }
            self.plain_kind = plain.content;
            self.plain_pos = self.offsetOf(plain.bytes);
            self.plain_end = self.plain_pos + plain.bytes.len;
            if (plain.content == .application and plain.bytes.len == 0) self.clearRecord();
            try self.askForUpdate();
        },
    }
}

/// Passes over one record of declined early data, within the bound.
fn skipEarly(self: *Connection, len: usize) Error!void {
    self.early_skipped += len;
    if (self.early_skipped > max_early_skip) return error.EarlyDataLimit;
    self.record_have = 0;
}

/// Requests the peer's next write keys before this read epoch runs out.
fn askForUpdate(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    if (self.rx_asked_update or self.phase() != .connected or self.write_done.load(.acquire) or self.rx.?.tls12()) return;
    const left = self.rx.?.remaining();
    if (left.records < 1024 or left.bytes < 64 * max_content) {
        self.rx_asked_update = true;
        try self.owe(owe_update_request);
    }
}

fn dispatch(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    switch (self.plain_kind.?) {
        .handshake => try self.feedHandshake(),
        .alert => try self.onAlert(),
        .application => unreachable, // `blocked` holds the loop while plaintext is unread
    }
}

fn onAlert(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    const body = self.record[self.plain_pos..self.plain_end];
    self.clearRecord();
    if (body.len != 2 or (body[0] != 1 and body[0] != 2)) return error.UnexpectedRecord;
    const alert: Alert = @fromBackingInt(@intCast(body[1]));
    self.alert_received.store(@backingInt(alert), .release);
    if (alert == .close_notify and self.phase() == .connected) {
        self.read_done.store(true, .release);
        self.settlePhase();
        return;
    }
    // A warning is passed over a few times, then the run of them is a flood.
    const ignorable = alert == .user_canceled or (alert != .close_notify and self.hs.warningsAllowed());
    if (ignorable and body[0] == 1 and self.alerts_ignored < 4) {
        self.alerts_ignored += 1;
        return;
    }
    return error.PeerAlert;
}

fn feedHandshake(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    while (self.plain_pos < self.plain_end) {
        if (self.message_total == 0) {
            const take = @min(4 - self.header_have, self.plain_end - self.plain_pos);
            @memcpy(self.header[self.header_have..][0..take], self.record[self.plain_pos..][0..take]);
            self.header_have += @intCast(take);
            self.plain_pos += take;
            if (self.header_have < 4) break;
            const total = 4 + @as(usize, std.mem.readInt(u24, self.header[1..4], .big));
            if (total > self.limits.handshake.message) return error.HandshakeLimit;
            if (self.message.len < total) {
                if (self.message.len != 0) self.gpa.free(self.message);
                self.message = &.{};
                self.message = try self.gpa.alloc(u8, total);
            }
            @memcpy(self.message[0..4], &self.header);
            self.message_total = total;
            self.message_have = 4;
            self.header_have = 0;
        }
        const take = @min(self.message_total - self.message_have, self.plain_end - self.plain_pos);
        @memcpy(self.message[self.message_have..][0..take], self.record[self.plain_pos..][0..take]);
        self.message_have += take;
        self.plain_pos += take;
        if (self.message_have == self.message_total) {
            const total = self.message_total;
            self.message_total = 0;
            self.message_have = 0;
            const boundary = self.plain_pos == self.plain_end and self.header_have == 0;
            try self.hs.receive(self.message[0..total], self.rx_epoch, boundary);
            try self.drain();
            if (self.hs.need() != .none) break;
        }
    }
    if (self.plain_pos == self.plain_end) self.clearRecord();
}

/// The transport ended. A close_notify must have arrived; anything else is truncation.
pub fn receiveEof(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    if (self.read_done.load(.acquire)) return;
    if (self.phase() != .failed) {
        self.failRead(error.Truncated);
    }
    return error.Truncated;
}

test {
    _ = @import("Connection_test.zig");
    _ = @import("ServerConnection_test.zig");
}
