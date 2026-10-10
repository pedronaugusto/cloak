//! A sans-I/O TLS 1.3 client connection. The caller feeds wire bytes to `receive`, writes
//! what `output` holds and acknowledges it, answers each `request` through `provide`, and
//! reads authenticated plaintext from `readable`. The connection owns record keys, sequence
//! numbers and the handshake; it never touches a socket, a clock or a random source.
const std = @import("std");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Client = @import("handshake/Client.zig");
const Machine = @import("handshake/Machine.zig");
const Server = @import("handshake/Server.zig");
const Services = @import("handshake/Services.zig");
const Messages = @import("handshake/Messages.zig");
const Group = @import("crypto/Group.zig").Group;
const Suite13 = @import("crypto/Suite.zig").Suite13;
const Protection = @import("record/Protection.zig");
const Alert = @import("wire/Alert.zig").Alert;
const Outbox = @import("connection/Outbox.zig");

pub const Epoch = Client.Epoch;
pub const Verify = Client.Verify;
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
    suites: []const Suite13 = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    auth: ?certificates.ClientAuth = null,
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

pub const Phase = enum { handshaking, connected, closed, failed };

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
};
pub const ProvideError = Error || error{ StaleToken, NoRequest };
pub const ReceiveError = Error;
pub const SendError = Error || error{ NotConnected, WriteClosed };
pub const FinishError = SendError;

const max_content = 1 << 14;
const max_record = 5 + max_content + 256;
/// Header, inner content type and AEAD tag around a plaintext fragment.
const record_overhead = 5 + 1 + 16;
const Connection = @This();

gpa: std.mem.Allocator,
hs: Machine,
limits: Limits,
rx: ?Protection = null,
tx: ?Protection = null,
rx_epoch: Epoch = .initial,
tx_epoch: Epoch = .initial,
phase_now: Phase = .handshaking,
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
// Outbound.
outbox: Outbox = .{},
read_done: bool = false,
write_done: bool = false,
rx_asked_update: bool = false,
failure: ?Error = null,
alert_sent: ?Alert = null,
alert_received: ?Alert = null,

pub fn client(gpa: std.mem.Allocator, options: ClientOptions) InitError!Connection {
    @setRuntimeSafety(true);
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
            .require_alpn = options.require_alpn,
            .require_hybrid = options.require_hybrid,
        },
        .identity = options.identity,
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
    suites: []const Suite13 = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    /// Application protocols in the server's order of preference.
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    client_auth: Server.Auth = .none,
    /// How a presented client chain is checked; required for authenticated client identities.
    client_verify: Verify = .none,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

/// A server connection: the same record, request and key handling around the server handshake.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions) InitError!Connection {
    @setRuntimeSafety(true);
    const hs = try Server.init(gpa, .{
        .suites = options.suites,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .client_auth = options.client_auth,
        .client_verify = options.client_verify,
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
    return self.phase_now;
}

pub fn diagnostics(self: *const Connection) Diagnostics {
    return .{ .phase = self.phase_now, .reason = self.failure, .alert_sent = self.alert_sent, .alert_received = self.alert_received };
}

/// Whether the server asked this client for a certificate (or this server asks its client for
/// one), whether or not the handshake completed.
pub fn certificateRequested(self: *const Connection) bool {
    return self.hs.certificateRequested();
}

/// Negotiated parameters; null before the handshake completes.
pub fn info(self: *const Connection) ?Info {
    return self.hs.info();
}

/// True once the peer sent close_notify: no more plaintext will arrive.
pub fn readClosed(self: *const Connection) bool {
    return self.read_done;
}

pub const ExportError = Client.ExportError;
pub fn exportKeyingMaterial(self: *const Connection, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    return self.hs.exportKeyingMaterial(out, label, context);
}

/// Returns idle buffers: the record and message buffers when no partial input is held, the
/// output buffer when nothing is pending, and the handshake scratch once it is established.
/// Safe to call at any time; the next input or output acquires them again.
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
    self.outbox.trim(self.gpa);
    self.hs.settle();
}

// ---------------------------------------------------------------- services

/// The service the engine is waiting for, if any. Answer it with `provide`.
pub fn request(self: *Connection) ?Request {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Connection, token: types.Token, answer: Answer) ProvideError!void {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        // These leave the request open: a wrong token or a rejected scalar draw is not fatal.
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.failed(fatal),
    };
    self.drain() catch |err| return self.failed(err);
    // Plaintext buffered while the engine waited continues without new input.
    _ = self.receiveChecked(&.{}) catch |err| return self.failed(err);
}

// ---------------------------------------------------------------- failure

fn alertFor(self: *const Connection, err: Error) Alert {
    return switch (err) {
        error.BadRecord => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.UnexpectedRecord, error.ControlFlood => .unexpected_message,
        else => self.services.alertFor(err),
    };
}

/// Ends the connection: queues one fatal alert when keys allow it and erases secrets.
fn fail(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return;
    self.phase_now = .failed;
    self.failure = err;
    if (err != error.PeerAlert and err != error.Closed) self.sendAlert(2, self.alertFor(err));
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
    self.alert_sent = alert;
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

pub fn output(self: *const Connection) []const u8 {
    return self.outbox.pending();
}

pub fn acknowledge(self: *Connection, n: usize) void {
    self.outbox.acknowledge(n);
}

fn sealMessage(self: *Connection, epoch: Epoch, message: []const u8) Error!void {
    @setRuntimeSafety(true);
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

fn install(self: *Connection, s: anytype) Error!void {
    @setRuntimeSafety(true);
    var traffic = s.traffic;
    defer traffic.secret.deinit();
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

/// Moves everything the handshake queued onto the wire and into the key slots, in order.
fn drain(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    while (self.hs.pop()) |emit| switch (emit) {
        .message => |m| try self.sealMessage(m.epoch, self.hs.flightBytes(m.start, m.len)),
        .secret => |s| try self.install(s),
        .compat_ccs => try self.sealCompatCcs(),
        .key_update => |u| try self.onPeerKeyUpdate(u.request_peer),
        .ticket => try self.onControl(),
        .complete => {
            self.phase_now = .connected;
            self.hs.settle();
        },
    };
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
    if (request_peer) try self.sendKeyUpdate(false);
}

/// KeyUpdate under the old write key, then the next write secret (RFC 8446 section 4.6.3).
fn sendKeyUpdate(self: *Connection, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
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
    if (left.records < 4 or left.bytes < 2 * max_content) try self.sendKeyUpdate(false);
}

/// Accepts the longest prefix of `plaintext` that fits one record; returns its length. Zero
/// means the output backlog must drain first.
pub fn send(self: *Connection, plaintext: []const u8) SendError!usize {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return error.Closed;
    if (self.phase_now != .connected) return error.NotConnected;
    if (self.write_done) return error.WriteClosed;
    if (plaintext.len == 0) return 0;
    const n = @min(plaintext.len, max_content);
    if (self.outbox.pending().len + n + record_overhead > self.limits.output) return 0;
    self.budgetWrite() catch |err| return self.failed(err);
    const dst = self.outbox.tail(self.gpa, n + record_overhead, self.limits.output + max_record) catch |err| return self.failed(err);
    const wire = self.tx.?.seal(.application, plaintext[0..n], 0, dst) catch |err| return self.failed(err);
    self.outbox.commit(wire.len);
    return n;
}

/// A local failure while writing is terminal for the connection.
fn failed(self: *Connection, err: Error) Error {
    self.fail(err);
    return err;
}

/// Asks for new keys in one direction or both (`request_peer`).
pub fn keyUpdate(self: *Connection, request_peer: bool) SendError!void {
    @setRuntimeSafety(true);
    if (self.phase_now != .connected) return error.NotConnected;
    if (self.write_done) return error.WriteClosed;
    self.sendKeyUpdate(request_peer) catch |err| return self.failed(err);
}

/// Queues close_notify. The write side is finished; reading continues until the peer's own.
pub fn finish(self: *Connection) FinishError!void {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return error.Closed;
    if (self.write_done) return;
    if (self.phase_now == .connected) {
        self.sendAlert(1, .close_notify);
    }
    self.write_done = true;
    self.settlePhase();
}

fn settlePhase(self: *Connection) void {
    if (self.phase_now == .connected and self.read_done and self.write_done) self.phase_now = .closed;
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
    if (self.phase_now == .failed) return true;
    if (self.plain_kind == .application) return true;
    if (self.hs.need() != .none) return true;
    return self.outbox.pending().len > self.limits.output;
}

/// Consumes wire bytes, decrypting and processing whole records. It returns early when the
/// engine is waiting for an answer, plaintext is unread, or output must drain; call it again
/// with the unconsumed remainder.
pub fn receive(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return error.Closed;
    if (self.read_done) return error.Closed;
    return self.receiveChecked(input) catch |err| return self.failed(err);
}

fn receiveChecked(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    var consumed: usize = 0;
    var records: usize = 0;
    while (true) {
        if (self.blocked() or self.read_done) return consumed;
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
    // A client's first records may carry the older legacy version (RFC 8446 section 5.1).
    const first_flight = self.hs.role() == .server and self.rx == null and kind == 22;
    const version_ok = std.mem.eql(u8, self.head[1..3], &.{ 3, 3 }) or (first_flight and std.mem.eql(u8, self.head[1..3], &.{ 3, 1 }));
    if (!version_ok) return error.UnexpectedRecord;
    switch (kind) {
        20, 21, 22 => if (length == 0 or length > max_content) return error.RecordOverflow,
        23 => {
            if (length > max_content + 256) return error.RecordOverflow;
            if (length < 17) return error.BadRecord;
        },
        else => return error.UnexpectedRecord,
    }
}

fn openRecord(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const wire = self.record[0..self.record_have];
    switch (wire[0]) {
        20 => {
            // A single compatibility change_cipher_spec, only before the peer's Finished and
            // only between messages, is ignored (RFC 8446 appendix D.4).
            const allowed = self.hs.compat() and !self.seen_ccs and self.phase_now == .handshaking and
                self.message_total == 0 and self.header_have == 0 and wire.len == 6 and wire[5] == 1;
            if (!allowed) return error.UnexpectedRecord;
            self.seen_ccs = true;
            self.record_have = 0;
        },
        21, 22 => {
            if (self.rx != null) return error.UnexpectedRecord;
            self.plain_kind = if (wire[0] == 21) .alert else .handshake;
            self.plain_pos = 5;
            self.plain_end = wire.len;
        },
        else => {
            const protection = &(self.rx orelse return error.UnexpectedRecord);
            const plain = try protection.open(wire, self.record[5..]);
            if (plain.content == .application) {
                if (self.phase_now != .connected) return error.UnexpectedRecord;
                self.control_run = 0;
            }
            self.plain_kind = plain.content;
            self.plain_pos = 5;
            self.plain_end = 5 + plain.bytes.len;
            if (plain.content == .application and plain.bytes.len == 0) self.clearRecord();
            try self.askForUpdate();
        },
    }
}

/// Requests the peer's next write keys before this read epoch runs out.
fn askForUpdate(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    if (self.rx_asked_update or self.phase_now != .connected or self.write_done) return;
    const left = self.rx.?.remaining();
    if (left.records < 1024 or left.bytes < 64 * max_content) {
        self.rx_asked_update = true;
        try self.sendKeyUpdate(true);
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
    self.alert_received = alert;
    if (alert == .close_notify and self.phase_now == .connected) {
        self.read_done = true;
        self.settlePhase();
        return;
    }
    if (alert == .user_canceled and body[0] == 1 and self.alerts_ignored < 4) {
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
    if (self.read_done) return;
    if (self.phase_now != .failed) {
        self.fail(error.Truncated);
    }
    return error.Truncated;
}

test {
    _ = @import("Connection_test.zig");
    _ = @import("ServerConnection_test.zig");
}
