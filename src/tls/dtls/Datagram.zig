//! A DTLS association of either role, DTLS 1.3 (RFC 9147) or DTLS 1.2 (RFC 6347): the third
//! carrier of the one handshake, beside `Connection`'s stream records and `quic.Handshake`'s
//! levels. The caller hands it whole datagrams with `receive`, sends what `send` writes into its
//! buffer, calls `send` again when `timeout` passes, answers each `request` through `provide`,
//! seals application datagrams with `write` and takes received ones from `read`. It owns the
//! records, epochs, replay windows, message sequence, reassembly, the flight and its
//! retransmission timer and the DTLS 1.3 ACKs; it performs no I/O and keeps no clock: every call
//! that can arm or fire the timer takes the caller's monotonic `now`.
//!
//! Invalid datagrams are dropped, never fatal: a record that does not parse, authenticate or
//! clear the replay window leaves the association, its timer and its handshake as they were. A
//! handshake message that the engine refuses ends the association as in TLS.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;
const Client = @import("../handshake/Client.zig");
const Server = @import("../handshake/Server.zig");
const Machine = @import("../handshake/Machine.zig");
const Flight = @import("../handshake/Flight.zig");
const Services = @import("../handshake/Services.zig");
const Messages = @import("../handshake/Messages.zig");
const Alert = @import("../wire/Alert.zig").Alert;
const Record = @import("Record.zig");
const Hello = @import("../handshake/Hello.zig");
pub const Admission = @import("Admission.zig");

pub const Suite = suites.Suite;
pub const Version = suites.Version;
pub const Verify = Client.Verify;
pub const Resumption = Client.Resumption;
pub const KeyLog = Client.KeyLog;
pub const Info = Client.Info;
pub const Request = Services.Request;
pub const Answer = Services.Answer;
pub const Service = Services.Service;
pub const VerifyFailure = Services.VerifyFailure;
pub const Credential = Server.Credential;
pub const TicketKeys = Server.TicketKeys;

/// The retransmission timer (RFC 9147 section 5.8.2): the first wait, its doubling cap, and how
/// many retransmissions before the handshake gives up.
pub const Timing = struct {
    initial: std.Io.Duration = .fromSeconds(1),
    max: std.Io.Duration = .fromSeconds(60),
    retransmissions: u8 = 7,
};

pub const Limits = struct {
    handshake: Client.Limits = .{},
    /// Handshake messages buffered ahead of the next expected one, and their bytes.
    incomplete: usize = 16,
    reassembly: usize = 256 * 1024,
    /// The sent flight kept for retransmission.
    flight: usize = 256 * 1024,
};

pub const ServerName = union(enum) {
    identity,
    name: []const u8,
    none,
};

pub const Options = struct {
    identity: types.Identity,
    verify: Verify,
    server_name: ServerName = .identity,
    suites: []const Suite = Suite.default,
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    auth: ?certificates.ClientAuth = null,
    resumption: ?Resumption = null,
    /// The largest datagram this end sends, without IP and UDP headers.
    mtu: u16 = 1200,
    timing: Timing = .{},
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const ServerOptions = struct {
    credentials: []const Credential,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    suites: []const Suite = Suite.default,
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    client_auth: Server.Auth = .none,
    client_verify: Verify = .none,
    tickets: ?*TicketKeys = null,
    tls12_tickets: bool = false,
    mtu: u16 = 1200,
    timing: Timing = .{},
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Phase = enum(u8) { handshaking, connected, closed, failed };

pub const InitError = Client.InitError || error{InvalidOptions};
pub const Error = Client.Error || Record.SealError || error{
    PeerAlert,
    HandshakeTimeout,
    FlightLimit,
    Closed,
    NotConnected,
    /// A key failed to open as many records as its AEAD allows (RFC 9147 section 4.5.3).
    ForgeryLimit,
    /// A key update is still waiting for its acknowledgement.
    UpdatePending,
};
pub const ProvideError = Error || error{ StaleToken, NoRequest };

const Datagram = @This();

const min_mtu = 256;
const max_mtu = 16 * 1024;
/// Records of application data `receive` holds for `read` per call.
const max_readable = 32;

/// A sent message or ChangeCipherSpec, kept until the peer's answer or ACK covers it.
const Sent = struct {
    kind: enum { message, ccs },
    sequence: u16 = 0,
    /// The record epoch it went out under: 0, 1 (DTLS 1.2) or 2 and up (DTLS 1.3).
    epoch: u64,
    /// The message in its TLS form: type, 24-bit length, body.
    bytes: []u8 = &.{},
    /// Bytes of the body this transmission has sent, and whether it has more (or, for an empty
    /// message, its one fragment) to send.
    cursor: usize = 0,
    pending: bool = true,
    acked: bool = false,
    /// DTLS 1.3: one bit per body byte an ACK covered, allocated at the first partial ACK.
    covered: []u8 = &.{},
    /// A KeyUpdate: the write keys move on once it is acknowledged.
    key_update: bool = false,
};

/// Which fragment a sent record carried, for the ACKs that name records (RFC 9147 section 7).
const Sent_record = struct { epoch: u64, sequence: u64, entry: u16, offset: u32, len: u32 };

/// A handshake message being reassembled, held as the TLS-form message.
const Partial = struct {
    sequence: u16,
    kind: u8,
    epoch: u64,
    /// Type and length header, then the body.
    buf: []u8,
    /// One bit per body byte received.
    have: []u8,
    received: usize = 0,

    fn total(self: *const Partial) usize {
        return self.buf.len - 4;
    }
};

const Readable = struct { bytes: []u8 };

gpa: std.mem.Allocator,
hs: Machine,
services: Services,
role: Machine.Role,
mtu: u16,
timing: Timing,
limits: Limits,
phase_now: Phase = .handshaking,
failure_now: ?Error = null,
alert_sent: ?Alert = null,
alert_received: ?Alert = null,
negotiated: ?Info = null,
// Records.
/// The next record sequence of epoch 0.
plain_sequence: u64 = 0,
/// Write and read epochs, keyed by their number; at most a handshake epoch and two application
/// epochs live at once.
writers: [3]?Record.Epoch = @splat(null),
readers: [3]?Record.Epoch = @splat(null),
/// The epoch new handshake messages and application data go out under.
write_current: u64 = 0,
// Handshake messages.
send_sequence: u16 = 0,
receive_sequence: u16 = 0,
partials: std.ArrayList(Partial) = .empty,
partial_bytes: usize = 0,
/// The flight this side sent last, kept for retransmission.
flight: std.ArrayList(Sent) = .empty,
flight_bytes: usize = 0,
/// The peer's first message_seq of the flight answering ours (RFC 9147 section 5.8.1): a message
/// below it is one our flight answered, one from it on answers ours.
answer_from: u16 = 0,
/// Part of the peer's answer to our flight arrived. The timer runs on until the whole answer has
/// made the engine speak again (or the handshake ends); then our flight is done.
answered: bool = false,
/// The flight goes out now: `send` writes its fragments.
transmitting: bool = false,
deadline: ?std.Io.Timestamp = null,
backoff: std.Io.Duration,
retransmissions: u8 = 0,
/// The peer's ChangeCipherSpec (DTLS 1.2) arrived before the message preceding it.
ccs_waiting: bool = false,
/// DTLS 1.3: records of the peer's handshake flight to acknowledge, and whether an ACK is due.
acks: std.ArrayList([2]u64) = .empty,
ack_due: bool = false,
/// A handshake record joined `acks` in the datagram being received.
acked_now: bool = false,
/// The records the flight went out in, newest last, for the peer's ACKs to name.
sent_records: [64]Sent_record = undefined,
sent_records_len: usize = 0,
sent_records_at: usize = 0,
/// The server has taken the client's first hello: its message_seq numbers the handshake.
started: bool = false,
/// The peer's address is proven (a cookie, a path validated otherwise, or its handshake keys);
/// until then a server sends at most three times what it received (RFC 9147 section 5.1).
validated: bool = true,
received_bytes: usize = 0,
sent_bytes: usize = 0,
// Application data.
readable: [max_readable]Readable = undefined,
readable_len: usize = 0,
readable_at: usize = 0,
close_due: bool = false,
fatal_due: ?Alert = null,

pub fn client(gpa: std.mem.Allocator, options: Options) InitError!Datagram {
    @setRuntimeSafety(true);
    try checkCommon(options.mtu, options.timing);
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
            .transport = .datagram,
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
        .identity = options.identity,
        .verify = options.verify,
        .auth = options.auth,
        .limits = options.limits.handshake,
        .compat = false,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    return .{
        .gpa = gpa,
        .hs = Machine.forClient(hs),
        .services = .init(options.generation),
        .role = .client,
        .mtu = options.mtu,
        .timing = options.timing,
        .limits = options.limits,
        .backoff = options.timing.initial,
    };
}

/// A server association for a client `Cookies.check` admitted, or one on a path validated
/// otherwise (`.{}`). With no admission the address is unproven: the association answers at most
/// three times the bytes it received until the client's handshake keys prove it.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions, admission: ?Admission) InitError!Datagram {
    @setRuntimeSafety(true);
    try checkCommon(options.mtu, options.timing);
    const hs = try Server.init(gpa, .{
        .transport = .datagram,
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
        .tls12_tickets = options.tls12_tickets,
        .limits = options.limits.handshake,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    var self: Datagram = .{
        .gpa = gpa,
        .hs = .{ .state = .{ .server = hs } },
        .services = .init(options.generation),
        .role = .server,
        .mtu = options.mtu,
        .timing = options.timing,
        .limits = options.limits,
        .backoff = options.timing.initial,
        .validated = admission != null,
    };
    errdefer self.hs.deinit();
    if (admission) |admitted| if (admitted.retry) |*retry| {
        // The association starts where the stateless retry request left the handshake.
        var buffer: [256]u8 = undefined;
        const hrr = Hello.buildRetry(&buffer, .datagram, "", retry.suite, if (retry.asked) retry.group else null, retry.cookieBytes(), false) catch return error.InvalidOptions;
        self.hs.resumeRetry(retry.suite, retry.group, retry.helloHash(), retry.fingerprint, hrr) catch return error.InvalidOptions;
    };
    return self;
}

fn checkCommon(mtu: u16, timing: Timing) InitError!void {
    if (mtu < min_mtu or mtu > max_mtu) return error.InvalidOptions;
    if (timing.initial.nanoseconds <= 0 or timing.max.nanoseconds < timing.initial.nanoseconds) return error.InvalidOptions;
}

pub fn deinit(self: *Datagram) void {
    @setRuntimeSafety(true);
    for (&self.writers) |*slot| if (slot.*) |*e| e.deinit();
    for (&self.readers) |*slot| if (slot.*) |*e| e.deinit();
    self.dropPartials();
    self.partials.deinit(self.gpa);
    self.clearFlight();
    self.flight.deinit(self.gpa);
    self.acks.deinit(self.gpa);
    self.hs.deinit();
    self.* = undefined;
}

pub fn phase(self: *const Datagram) Phase {
    return self.phase_now;
}

/// The first failure, if the association failed.
pub fn failure(self: *const Datagram) ?Error {
    return self.failure_now;
}

pub fn alerts(self: *const Datagram) struct { sent: ?Alert, received: ?Alert } {
    return .{ .sent = self.alert_sent, .received = self.alert_received };
}

/// What the handshake negotiated; null before it completes and after a failure.
pub fn info(self: *const Datagram) ?Info {
    if (self.phase_now == .failed) return null;
    return self.negotiated;
}

pub fn exportKeyingMaterial(self: *const Datagram, out: []u8, label: []const u8, context: []const u8) Client.ExportError!void {
    if (self.phase_now == .failed) return error.WrongPhase;
    return self.hs.exportKeyingMaterial(out, label, context);
}

/// The DTLS version, once the hellos chose it.
fn dtls13(self: *const Datagram) bool {
    return self.hs.version() == .tls13;
}

// ---------------------------------------------------------------- services

pub fn request(self: *Datagram) ?Request {
    if (self.phase_now == .failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Datagram, token: types.Token, answer: Answer) ProvideError!void {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.fail(fatal),
    };
    self.pump() catch |err| return self.fail(err);
}

fn fail(self: *Datagram, err: Error) Error {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return err;
    self.failure_now = err;
    if (err != error.PeerAlert and err != error.HandshakeTimeout and err != error.Closed) {
        self.fatal_due = switch (err) {
            error.FlightLimit => .internal_error,
            else => self.services.alertFor(err),
        };
    }
    self.phase_now = .failed;
    self.hs.wipe();
    self.dropPartials();
    self.clearFlight();
    self.transmitting = false;
    self.deadline = null;
    return err;
}

// ---------------------------------------------------------------- the engine

/// Delivers buffered complete messages in order, then moves the engine's outputs into the flight
/// and the key slots, until the engine waits on a service or on the peer.
fn pump(self: *Datagram) Error!void {
    @setRuntimeSafety(true);
    while (true) {
        try self.drainEngine();
        if (self.phase_now == .failed) return;
        if (self.hs.need() != .none or self.hs.pending()) return;
        if (self.ccs_waiting and self.hs.awaitingCcs()) {
            self.ccs_waiting = false;
            try self.hs.receiveCcs();
            continue;
        }
        if (!try self.deliverNext()) return;
    }
}

/// Hands the engine the next message if it is complete.
fn deliverNext(self: *Datagram) Error!bool {
    @setRuntimeSafety(true);
    const index = for (self.partials.items, 0..) |p, i| {
        if (p.sequence == self.receive_sequence) break i;
    } else return false;
    const partial = &self.partials.items[index];
    if (partial.received != partial.total()) return false;
    const taken = self.partials.orderedRemove(index);
    defer self.freePartial(taken);
    self.receive_sequence +%= 1;
    // A DTLS 1.3 server ACKs the client's final flight, and either side a post-handshake message.
    try self.hs.receive(taken.buf, self.engineEpoch(taken.epoch), true);
    return true;
}

/// The engine's epoch of a record epoch: plaintext, handshake keys, application keys.
fn engineEpoch(self: *const Datagram, epoch: u64) Flight.Epoch {
    if (epoch == 0) return .initial;
    if (!self.dtls13()) return .application;
    return if (epoch == 2) .handshake else .application;
}

fn drainEngine(self: *Datagram) Error!void {
    @setRuntimeSafety(true);
    var emit: Flight.Emit = undefined;
    while (self.hs.pop(&emit)) {
        defer Flight.eraseEmit(&emit);
        switch (emit) {
            .message => |m| try self.queueMessage(m.epoch, self.hs.flightBytes(m.start, m.len)),
            .secret => |*s| try self.installSecret(s.direction, s.epoch, &s.traffic),
            .keys12 => |*k| try self.install12(k.direction, &k.keys),
            .change_cipher_spec => try self.queue(.{ .kind = .ccs, .epoch = 0 }),
            .compat_ccs => return error.UnexpectedMessage,
            .key_update => |u| try self.onPeerKeyUpdate(u.request_peer),
            .ticket => {},
            .refuse_renegotiation => {},
            .complete => {
                self.hs.settle();
                self.negotiated = self.hs.info();
                self.phase_now = .connected;
            },
        }
    }
    self.hs.recycle();
}

fn installSecret(self: *Datagram, direction: Flight.Direction, epoch: Flight.Epoch, traffic: *const Flight.Traffic) Error!void {
    @setRuntimeSafety(true);
    const number: u64 = switch (epoch) {
        .initial => unreachable, // the engine installs no plaintext keys
        .handshake => 2,
        .application => 3,
    };
    const keys = Record.Epoch.init13(traffic.suite, number, traffic.secret.expose()[0..traffic.len]);
    switch (direction) {
        .read => put(&self.readers, keys),
        .write => {
            put(&self.writers, keys);
            // Application data waits for the application epoch; the handshake epoch carries the
            // rest of the flight until then.
            if (number > self.write_current) self.write_current = number;
        },
    }
}

fn install12(self: *Datagram, direction: Flight.Direction, keys: *const Flight.Keys12) Error!void {
    @setRuntimeSafety(true);
    const epoch = Record.Epoch.init12(keys.cipher, keys.keyBytes(), keys.ivBytes());
    switch (direction) {
        .read => put(&self.readers, epoch),
        .write => {
            put(&self.writers, epoch);
            self.write_current = 1;
        },
    }
}

/// Keeps `keys` in a slot: a free one, or the oldest epoch's, which it erases.
fn put(slots: *[3]?Record.Epoch, keys: Record.Epoch) void {
    var oldest: usize = 0;
    for (slots, 0..) |*slot, i| {
        const held = slot.* orelse {
            slot.* = keys;
            return;
        };
        if (held.number == keys.number) {
            slot.*.?.deinit();
            slot.* = keys;
            return;
        }
        if (held.number < slots[oldest].?.number) oldest = i;
    }
    slots[oldest].?.deinit();
    slots[oldest] = keys;
}

fn find(slots: *[3]?Record.Epoch, number: u64) ?*Record.Epoch {
    for (slots) |*slot| if (slot.*) |*e| if (e.number == number) return e;
    return null;
}

fn onPeerKeyUpdate(self: *Datagram, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    // The next read epoch joins the current one, which stays until a record opens under the new.
    const current = self.highestRead() orelse return error.UnexpectedMessage;
    const next = current.next();
    put(&self.readers, next);
    // A request while our own update is still unacknowledged is answered by that one.
    if (request_peer) self.keyUpdate(false) catch |err| switch (err) {
        error.UpdatePending => {},
        else => |e| return e,
    };
}

fn highestRead(self: *Datagram) ?*Record.Epoch {
    var best: ?*Record.Epoch = null;
    for (&self.readers) |*slot| if (slot.*) |*e| {
        if (best == null or e.number > best.?.number) best = e;
    };
    return best;
}

/// The engine's message joins the flight under the epoch it names.
fn queueMessage(self: *Datagram, epoch: Flight.Epoch, message: []const u8) Error!void {
    @setRuntimeSafety(true);
    const number: u64 = switch (epoch) {
        .initial => 0,
        .handshake => 2,
        .application => if (self.dtls13()) self.write_current else 1,
    };
    const bytes = try self.gpa.dupe(u8, message);
    errdefer self.gpa.free(bytes);
    try self.queue(.{ .kind = .message, .epoch = number, .bytes = bytes, .sequence = self.send_sequence });
    self.send_sequence +%= 1;
}

fn queue(self: *Datagram, entry: Sent) Error!void {
    @setRuntimeSafety(true);
    // Output after the peer spoke, or after our last flight was done with, starts a new flight:
    // the old one is acknowledged by it.
    if (self.answered or self.receive_sequence != self.answer_from or self.flightDone()) {
        self.clearFlight();
        self.answered = false;
        self.retransmissions = 0;
        self.backoff = self.timing.initial;
        // A handshake flight acknowledges the peer's before it implicitly (RFC 9147 section 7.1).
        if (self.phase_now == .handshaking) self.acks.clearRetainingCapacity();
    }
    if (self.flight_bytes + entry.bytes.len > self.limits.flight) return error.FlightLimit;
    try self.flight.append(self.gpa, entry);
    self.flight_bytes += entry.bytes.len;
    self.transmitting = true;
    self.deadline = null;
    // The peer's answer to this flight starts at the message it sends next.
    self.answer_from = self.receive_sequence;
}

/// Whether the flight held is over: none, or all of it acknowledged.
fn flightDone(self: *const Datagram) bool {
    for (self.flight.items) |entry| if (!entry.acked) return false;
    return true;
}

fn clearFlight(self: *Datagram) void {
    for (self.flight.items) |entry| {
        if (entry.bytes.len != 0) {
            std.crypto.secureZero(u8, entry.bytes);
            self.gpa.free(entry.bytes);
        }
        if (entry.covered.len != 0) self.gpa.free(entry.covered);
    }
    self.flight.clearRetainingCapacity();
    self.flight_bytes = 0;
    self.sent_records_len = 0;
    self.sent_records_at = 0;
}

fn dropPartials(self: *Datagram) void {
    for (self.partials.items) |p| self.freePartial(p);
    self.partials.clearRetainingCapacity();
}

fn freePartial(self: *Datagram, p: Partial) void {
    std.crypto.secureZero(u8, p.buf);
    self.gpa.free(p.buf);
    self.gpa.free(p.have);
    self.partial_bytes -= p.buf.len + p.have.len;
}

// ---------------------------------------------------------------- receiving

/// Processes one datagram from the peer, in place: its records are opened in `datagram`, and the
/// application data `read` returns points into it until the next `receive`.
pub fn receive(self: *Datagram, datagram: []u8, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed or self.phase_now == .closed) return error.Closed;
    self.readable_len = 0;
    self.readable_at = 0;
    self.received_bytes +|= datagram.len;
    self.acked_now = false;
    var rest = datagram;
    while (Record.split(rest, 0)) |next| {
        rest = next.rest;
        self.onRecord(next, now) catch |err| return self.fail(err);
        if (self.phase_now == .failed or self.phase_now == .closed) return;
        // Each record's messages reach the engine before the next record is opened: the keys a
        // ServerHello or ChangeCipherSpec brings open the records after it in the same datagram.
        self.pump() catch |err| return self.fail(err);
    }
    if (self.phase_now == .connected) {
        // The handshake is over and the peer answered our last flight: it needs no more.
        if (self.answered) {
            self.deadline = null;
            self.transmitting = false;
            self.clearFlight();
            self.answered = false;
        }
        // What no flight of ours answers is ACKed: the client's final flight at a server, and
        // every message after the handshake (RFC 9147 section 7.1).
        if (self.dtls13() and self.acked_now) self.ack_due = true;
    }
}

fn onRecord(self: *Datagram, next: Record.Split, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    switch (next.kind) {
        .classic => |header| {
            if (header.epoch == 0) return self.onPlaintext(next.record, header, now);
            if (header.cid_len != 0) return;
            const keys = find(&self.readers, header.epoch) orelse return;
            if (keys.version != .dtls12) return;
            const opened = keys.open12(next.record, header) catch {
                if (keys.exhausted()) return error.ForgeryLimit;
                return;
            };
            self.validated = true;
            try self.onOpened(opened, header.epoch, now);
        },
        .unified => |header| {
            const keys = self.readEpoch(header.epoch_bits) orelse return;
            const opened = keys.open13(next.record, header) catch {
                if (keys.exhausted()) return error.ForgeryLimit;
                return;
            };
            const number = keys.number;
            // Only the client's handshake keys open this: its address is proven.
            self.validated = true;
            // A record under a newer read epoch retires the ones before it (RFC 9147 section 8).
            if (number >= 3) self.retireReadBefore(number);
            try self.onOpened(opened, number, now);
        },
    }
}

/// The read epoch whose low two bits match: the newest, during and after the handshake.
fn readEpoch(self: *Datagram, bits: u2) ?*Record.Epoch {
    var best: ?*Record.Epoch = null;
    for (&self.readers) |*slot| if (slot.*) |*e| {
        if (e.version != .dtls13 or @as(u2, @truncate(e.number)) != bits) continue;
        if (best == null or e.number > best.?.number) best = e;
    };
    return best;
}

fn retireReadBefore(self: *Datagram, number: u64) void {
    for (&self.readers) |*slot| if (slot.*) |*e| {
        // The handshake epoch stays while the handshake may still retransmit into it.
        if (e.number >= 3 and e.number < number) {
            e.deinit();
            slot.* = null;
        }
    };
}

fn onPlaintext(self: *Datagram, record: []u8, header: Record.Header12, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    const body = record[header.length..];
    switch (record[0]) {
        22 => try self.onHandshake(body, 0, header.sequence, now),
        20 => {
            // DTLS 1.2's ChangeCipherSpec: one byte, 1. It takes effect in message order.
            if (body.len != 1 or body[0] != 1 or self.dtls13()) return;
            if (self.hs.awaitingCcs()) try self.hs.receiveCcs() else self.ccs_waiting = true;
        },
        21 => {
            // An alert before any key: believed only while the handshake has no keys to check it.
            if (body.len != 2 or self.readers[0] != null or self.readers[1] != null or self.readers[2] != null) return;
            try self.onAlert(body);
        },
        else => {},
    }
}

fn onOpened(self: *Datagram, opened: Record.Opened, epoch: u64, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    switch (opened.content) {
        .handshake => try self.onHandshake(opened.bytes, epoch, opened.sequence, now),
        .application => {
            // Application data only once the peer's Finished has been verified.
            if (self.phase_now != .connected or self.readable_len == max_readable) return;
            // The peer's application keys at work: it has our final flight (RFC 9147 section
            // 5.8.1), whose ACK is then no longer awaited.
            if (self.dtls13() and !self.flightDone() and !self.flightHasKeyUpdate()) try self.flightAcknowledged();
            self.readable[self.readable_len] = .{ .bytes = opened.bytes };
            self.readable_len += 1;
        },
        .alert => if (opened.bytes.len == 2) try self.onAlert(opened.bytes),
        .ack => if (self.dtls13()) try self.onAck(opened.bytes),
        else => {},
    }
}

fn onAlert(self: *Datagram, body: []const u8) Error!void {
    const alert: Alert = @fromBackingInt(@intCast(body[1]));
    self.alert_received = alert;
    if (alert == .close_notify) {
        self.phase_now = .closed;
        return;
    }
    // A warning is passed over in DTLS 1.2; every other alert ends the association.
    if (body[0] == 1 and !self.dtls13() and alert != .close_notify) return;
    return error.PeerAlert;
}

/// Handshake fragments of one record (RFC 9147 section 5.5).
fn onHandshake(self: *Datagram, body: []const u8, epoch: u64, record_sequence: ?u64, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    var rest = body;
    var any_new = false;
    while (rest.len != 0) {
        if (rest.len < 12) return;
        const kind = rest[0];
        const length = std.mem.readInt(u24, rest[1..4], .big);
        const sequence = std.mem.readInt(u16, rest[4..6], .big);
        const offset = std.mem.readInt(u24, rest[6..9], .big);
        const fragment_len = std.mem.readInt(u24, rest[9..12], .big);
        if (rest.len - 12 < fragment_len) return;
        const fragment = rest[12..][0..fragment_len];
        rest = rest[12 + fragment_len ..];
        // The fragment must lie inside its message.
        if (@as(u32, offset) + fragment_len > length) return;
        // In usize: a 24-bit length plus its header can pass 2^24 (F77).
        if (@as(usize, length) + 4 > self.limits.handshake.message) return;
        // A server numbers the handshake from the client's first hello it takes: 0, or 1 and up
        // after a cookie exchange (RFC 6347 section 4.2.2).
        if (self.role == .server and !self.started) {
            if (kind != 1 or epoch != 0 or sequence > 3) continue;
            self.started = true;
            self.receive_sequence = sequence;
            self.send_sequence = sequence;
            self.answer_from = sequence;
            self.hs.firstSequence(sequence);
            // The server's first record carries the hello's record sequence (RFC 6347 section
            // 4.2.1), whatever a stateless exchange before it used.
            if (record_sequence) |number| self.plain_sequence = number;
        }
        const ahead = sequence -% self.receive_sequence;
        if (ahead >= 0x8000) {
            // An older message: the peer retransmitted, so our answer to it was lost.
            self.onRetransmission(sequence, now);
            continue;
        }
        // New plaintext messages end where keys begin: once the peer's keys are in, a plaintext
        // message can only be forged, and it is dropped rather than refused, which would end the
        // association (F82).
        if (epoch == 0 and self.plaintextClosed()) continue;
        if (ahead >= self.limits.incomplete) continue;
        if (try self.absorb(kind, length, sequence, offset, fragment, epoch)) any_new = true;
    }
    // Part of the peer's answer: our flight need not go again whole, but the timer runs on until
    // the answer is complete (DTLS 1.3 then ACKs what it has instead).
    if (any_new) {
        self.answered = true;
        if (epoch != 0) if (record_sequence) |number| try self.noteAck(epoch, number);
    }
}

/// Whether the peer's plaintext messages are over: its handshake (DTLS 1.3) or ChangeCipherSpec
/// (DTLS 1.2) keys are in, or the handshake is done.
fn plaintextClosed(self: *const Datagram) bool {
    if (self.phase_now != .handshaking) return true;
    for (self.readers) |slot| if (slot != null) return true;
    return false;
}

/// Copies a fragment into its message; true when it brought bytes not held before.
///
/// Every fragment of a message names the same type, length and epoch, and bytes that overlap
/// agree (F77). A fragment that disagrees with what is held is dropped when what is held came
/// under keys; plaintext held is no evidence against plaintext arriving, so there the newer wins
/// and a forged fragment that came first is undone by the genuine one after it; a fragment under
/// keys always wins over plaintext.
fn absorb(self: *Datagram, kind: u8, length: u24, sequence: u16, offset: u24, fragment: []const u8, epoch: u64) Error!bool {
    @setRuntimeSafety(true);
    for (self.partials.items, 0..) |*p, i| {
        if (p.sequence != sequence) continue;
        const agrees = p.kind == kind and p.total() == length and p.epoch == epoch and overlapAgrees(p, offset, fragment);
        if (agrees) break;
        if (epoch < p.epoch or (epoch == p.epoch and epoch != 0)) return false;
        self.freePartial(self.partials.orderedRemove(i));
        break;
    }
    const partial = for (self.partials.items) |*p| {
        if (p.sequence == sequence) break p;
    } else blk: {
        const need = 4 + @as(usize, length) + (@as(usize, length) + 7) / 8;
        if (self.partials.items.len == self.limits.incomplete or self.partial_bytes + need > self.limits.reassembly) return false;
        const buf = try self.gpa.alloc(u8, 4 + @as(usize, length));
        errdefer self.gpa.free(buf);
        const have = try self.gpa.alloc(u8, (@as(usize, length) + 7) / 8);
        errdefer self.gpa.free(have);
        @memset(have, 0);
        buf[0] = kind;
        std.mem.writeInt(u24, buf[1..4], length, .big);
        try self.partials.append(self.gpa, .{ .sequence = sequence, .kind = kind, .epoch = epoch, .buf = buf, .have = have });
        self.partial_bytes += buf.len + have.len;
        break :blk &self.partials.items[self.partials.items.len - 1];
    };
    var added = false;
    for (fragment, 0..) |byte, i| {
        const at = @as(usize, offset) + i;
        const bit = @as(u8, 1) << @intCast(at % 8);
        if (partial.have[at / 8] & bit != 0) continue;
        partial.buf[4 + at] = byte;
        partial.have[at / 8] |= bit;
        partial.received += 1;
        added = true;
    }
    return added;
}

/// Whether the bytes of a fragment that are already held are the same.
fn overlapAgrees(partial: *const Partial, offset: u24, fragment: []const u8) bool {
    for (fragment, 0..) |byte, i| {
        const at = @as(usize, offset) + i;
        if (partial.have[at / 8] & (@as(u8, 1) << @intCast(at % 8)) != 0 and partial.buf[4 + at] != byte) return false;
    }
    return true;
}

/// The peer sent an old message again. One our flight answers means our flight was lost: it
/// goes again, at most once a timer period. One that answered our flight was covered by our ACK
/// (DTLS 1.3), which was lost: the ACK goes again.
fn onRetransmission(self: *Datagram, sequence: u16, now: std.Io.Timestamp) void {
    if (sequence -% self.answer_from < 0x8000) {
        if (self.dtls13() and self.acks.items.len != 0) self.ack_due = true;
        return;
    }
    if (self.flight.items.len == 0 or self.transmitting) return;
    if (self.deadline) |when| if (when.nanoseconds - now.nanoseconds > @divTrunc(self.backoff.nanoseconds, 2)) {
        // Retransmitted within half a period of our own: the timer will do it.
        return;
    };
    self.restartTransmission();
}

fn restartTransmission(self: *Datagram) void {
    for (self.flight.items) |*entry| if (!entry.acked) {
        entry.cursor = 0;
        entry.pending = true;
    };
    self.transmitting = true;
}

fn noteAck(self: *Datagram, epoch: u64, sequence: u64) Error!void {
    if (!self.dtls13() or epoch < 2) return;
    // The newest 64 records: an older one dropped from the list is ACKed no more, and its sender
    // retransmits it.
    if (self.acks.items.len == 64) _ = self.acks.orderedRemove(0);
    try self.acks.append(self.gpa, .{ epoch, sequence });
    self.acked_now = true;
}

fn onAck(self: *Datagram, body: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (body.len < 2) return;
    const len = std.mem.readInt(u16, body[0..2], .big);
    if (len % 16 != 0 or body.len != 2 + @as(usize, len)) return;
    if (self.flight.items.len == 0) return;
    var at: usize = 2;
    while (at < body.len) : (at += 16) {
        const epoch = std.mem.readInt(u64, body[at..][0..8], .big);
        const sequence = std.mem.readInt(u64, body[at + 8 ..][0..8], .big);
        for (self.sent_records[0..self.sent_records_len]) |sent| {
            if (sent.epoch != epoch or sent.sequence != sequence) continue;
            try self.cover(sent);
        }
    }
    for (self.flight.items) |entry| if (!entry.acked) return;
    try self.flightAcknowledged();
}

/// Marks the bytes a record carried as received by the peer.
fn cover(self: *Datagram, sent: Sent_record) Error!void {
    @setRuntimeSafety(true);
    if (sent.entry >= self.flight.items.len) return;
    const entry = &self.flight.items[sent.entry];
    if (entry.acked) return;
    const body = bodyLength(entry.*);
    if (sent.offset == 0 and sent.len == body) {
        entry.acked = true;
        return;
    }
    if (entry.covered.len == 0) {
        entry.covered = try self.gpa.alloc(u8, (body + 7) / 8);
        @memset(entry.covered, 0);
    }
    for (sent.offset..sent.offset + sent.len) |i| entry.covered[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    for (0..body) |i| if (entry.covered[i / 8] & (@as(u8, 1) << @intCast(i % 8)) == 0) return;
    entry.acked = true;
}

/// The whole flight is acknowledged: no timer, and a KeyUpdate in it moves the write keys on.
fn flightAcknowledged(self: *Datagram) Error!void {
    @setRuntimeSafety(true);
    self.deadline = null;
    self.transmitting = false;
    var updated = false;
    for (self.flight.items) |*entry| {
        entry.acked = true;
        if (entry.key_update) updated = true;
    }
    self.clearFlight();
    if (updated) {
        const current = find(&self.writers, self.write_current) orelse return error.UnexpectedMessage;
        // Epochs never wrap; a sender stops at 2^48 (RFC 9147 section 8).
        if (current.number + 1 >= 1 << 48) return error.RecordLimit;
        const next = current.next();
        self.write_current = next.number;
        put(&self.writers, next);
    }
}

/// The next application datagram the last `receive` opened, or null.
pub fn read(self: *Datagram) ?[]const u8 {
    if (self.readable_at == self.readable_len) return null;
    defer self.readable_at += 1;
    return self.readable[self.readable_at].bytes;
}

// ---------------------------------------------------------------- sending

/// When `send` must be called again to retransmit, if a flight waits on the peer.
pub fn timeout(self: *const Datagram) ?std.Io.Timestamp {
    if (self.phase_now == .failed or self.transmitting) return null;
    return self.deadline;
}

/// Writes the next datagram to send into `out` (at least the MTU), or returns null when nothing
/// is due. A passed `timeout` makes the flight due again, with the wait doubled.
pub fn send(self: *Datagram, out: []u8, now: std.Io.Timestamp) Error!?[]u8 {
    @setRuntimeSafety(true);
    if (out.len < self.mtu) return error.BufferTooSmall;
    if (self.fatal_due) |alert| {
        self.fatal_due = null;
        return self.alertDatagram(2, alert, out);
    }
    if (self.phase_now == .failed) return null;
    if (self.deadline) |when| if (!self.transmitting and now.nanoseconds >= when.nanoseconds) {
        self.retransmissions += 1;
        if (self.retransmissions > self.timing.retransmissions) {
            // A handshake gives up; after it, a flight whose ACK never came (the final flight,
            // a ticket, a key update) is only given up on: the association is established.
            if (self.phase_now != .connected) return self.fail(error.HandshakeTimeout);
            self.deadline = null;
            self.clearFlight();
            return null;
        }
        self.backoff = .{ .nanoseconds = @min(self.backoff.nanoseconds * 2, self.timing.max.nanoseconds) };
        self.deadline = null;
        if (self.answered and self.dtls13() and self.acks.items.len != 0) {
            // Part of the answer came: ACK it, and the peer resends the rest (RFC 9147 section 7.1).
            self.ack_due = true;
            self.deadline = .{ .nanoseconds = now.nanoseconds + self.backoff.nanoseconds };
        } else self.restartTransmission();
    };
    var budget: usize = self.mtu;
    if (!self.validated) {
        // An unproven address gets three times what it sent, and no more (RFC 9147 section 5.1).
        const allowance = (3 *| self.received_bytes) -| self.sent_bytes;
        if (allowance < min_mtu) return null;
        budget = @min(budget, allowance);
    }
    const datagram = out[0..budget];
    var used: usize = 0;
    if (self.transmitting) {
        used = try self.packFlight(datagram);
        if (self.flightSent()) {
            self.transmitting = false;
            if (self.expectsAnswer()) {
                self.deadline = .{ .nanoseconds = now.nanoseconds + self.backoff.nanoseconds };
            }
        }
    }
    if (self.ack_due and self.dtls13()) {
        const written = self.writeAck(datagram[used..]) catch 0;
        if (written != 0) {
            used += written;
            self.ack_due = false;
            // The records stay listed: a peer that lost this ACK repeats its flight and gets it again.
        }
    }
    if (self.close_due and !self.transmitting and used == 0) {
        self.close_due = false;
        const alert = try self.alertDatagram(1, .close_notify, out);
        self.phase_now = .closed;
        return alert;
    }
    if (used == 0) return null;
    self.sent_bytes +|= used;
    return datagram[0..used];
}

fn flightHasKeyUpdate(self: *const Datagram) bool {
    for (self.flight.items) |entry| if (entry.key_update) return true;
    return false;
}

fn flightSent(self: *const Datagram) bool {
    for (self.flight.items) |entry| if (!entry.acked and entry.pending) return false;
    return true;
}

fn bodyLength(entry: Sent) usize {
    return switch (entry.kind) {
        .message => entry.bytes.len - 4,
        .ccs => 1,
    };
}

/// Whether the flight just sent waits for an answer or an ACK: every flight but DTLS 1.2's last
/// (RFC 6347 section 4.2.4), which is resent only when the peer repeats its own.
fn expectsAnswer(self: *const Datagram) bool {
    if (self.phase_now != .connected) return true;
    return self.dtls13();
}

/// Fragments of the flight into `out`, record by record, until it is full.
fn packFlight(self: *Datagram, out: []u8) Error!usize {
    @setRuntimeSafety(true);
    var used: usize = 0;
    for (self.flight.items, 0..) |*entry, index| {
        if (entry.acked) continue;
        while (entry.pending) {
            const overhead = self.recordOverhead(entry.epoch);
            const room = out.len - used;
            switch (entry.kind) {
                .ccs => {
                    if (room < Record.header12 + 1) return used;
                    const record = try Record.plaintext(.change_cipher_spec, self.nextPlainSequence(), &.{1}, out[used..]);
                    used += record.len;
                    entry.cursor = 1;
                    entry.pending = false;
                },
                .message => {
                    const body = entry.bytes[4..];
                    const left = body.len - entry.cursor;
                    // A fragment worth sending: the rest, or at least 64 bytes of it.
                    if (room <= overhead + 12 or (room - overhead - 12 < left and room - overhead - 12 < 64)) return used;
                    const n = @min(left, room - overhead - 12, Record.max_content - 12);
                    var fragment: [12]u8 = undefined;
                    fragment[0] = entry.bytes[0];
                    fragment[1..4].* = entry.bytes[1..4].*;
                    std.mem.writeInt(u16, fragment[4..6], entry.sequence, .big);
                    // safe: offsets and lengths are below the 24-bit message length.
                    std.mem.writeInt(u24, fragment[6..9], @intCast(entry.cursor), .big);
                    std.mem.writeInt(u24, fragment[9..12], @intCast(n), .big);
                    const number = self.nextRecordNumber(entry.epoch);
                    const record = try self.sealHandshake(entry.epoch, &fragment, body[entry.cursor..][0..n], out[used..]);
                    used += record.len;
                    // safe: the flight holds at most a few dozen entries and 256 KiB.
                    self.logRecord(.{ .epoch = entry.epoch, .sequence = number, .entry = @intCast(index), .offset = @intCast(entry.cursor), .len = @intCast(n) });
                    entry.cursor += n;
                    if (entry.cursor == body.len) entry.pending = false;
                },
            }
        }
    }
    return used;
}

/// The record number the next record of `epoch` gets.
fn nextRecordNumber(self: *Datagram, epoch: u64) u64 {
    if (epoch == 0) return self.plain_sequence;
    const keys = find(&self.writers, epoch) orelse return 0;
    return keys.sequence;
}

fn logRecord(self: *Datagram, record: Sent_record) void {
    self.sent_records[self.sent_records_at] = record;
    self.sent_records_at = (self.sent_records_at + 1) % self.sent_records.len;
    self.sent_records_len = @min(self.sent_records_len + 1, self.sent_records.len);
}

fn nextPlainSequence(self: *Datagram) u64 {
    defer self.plain_sequence += 1;
    return self.plain_sequence;
}

/// What a record of `epoch` adds around its content.
fn recordOverhead(self: *Datagram, epoch: u64) usize {
    if (epoch == 0) return Record.header12;
    const keys = find(&self.writers, epoch) orelse return Record.header12 + 64;
    return switch (keys.version) {
        .dtls13 => Record.overhead13(0),
        .dtls12 => Record.overhead12(keys.cipher, 0),
    };
}

/// One handshake fragment as a record of `epoch`: the twelve-byte DTLS header, then its bytes.
fn sealHandshake(self: *Datagram, epoch: u64, header: *const [12]u8, bytes: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (epoch == 0) {
        if (out.len < Record.header12 + 12 + bytes.len) return error.BufferTooSmall;
        @memcpy(out[Record.header12..][0..12], header);
        @memcpy(out[Record.header12 + 12 ..][0..bytes.len], bytes);
        return Record.plaintext(.handshake, self.nextPlainSequence(), out[Record.header12..][0 .. 12 + bytes.len], out);
    }
    const keys = find(&self.writers, epoch) orelse return error.UnexpectedMessage;
    // The content is assembled where the record's body goes, then sealed in place.
    const at = switch (keys.version) {
        .dtls13 => 5,
        .dtls12 => Record.header12 + keys.cipher.explicitNonceLength12(),
    };
    if (out.len < at + 12 + bytes.len + Record.tag_length + 1) return error.BufferTooSmall;
    @memcpy(out[at..][0..12], header);
    @memcpy(out[at + 12 ..][0..bytes.len], bytes);
    const content = out[at..][0 .. 12 + bytes.len];
    return switch (keys.version) {
        .dtls13 => keys.seal13(.handshake, content, "", out),
        .dtls12 => keys.seal12(.handshake, content, "", out),
    };
}

fn writeAck(self: *Datagram, out: []u8) Error!usize {
    @setRuntimeSafety(true);
    const keys = find(&self.writers, self.write_current) orelse return 0;
    var body: [2 + 16 * 64]u8 = undefined;
    // safe: at most 64 records.
    std.mem.writeInt(u16, body[0..2], @intCast(self.acks.items.len * 16), .big);
    for (self.acks.items, 0..) |number, i| {
        std.mem.writeInt(u64, body[2 + 16 * i ..][0..8], number[0], .big);
        std.mem.writeInt(u64, body[2 + 16 * i + 8 ..][0..8], number[1], .big);
    }
    const len = 2 + 16 * self.acks.items.len;
    if (out.len < len + Record.overhead13(0)) return 0;
    const record = try keys.seal13(.ack, body[0..len], "", out);
    return record.len;
}

fn alertDatagram(self: *Datagram, level: u8, alert: Alert, out: []u8) Error!?[]u8 {
    @setRuntimeSafety(true);
    const body = [2]u8{ level, @backingInt(alert) };
    self.alert_sent = alert;
    if (self.write_current == 0) return try Record.plaintext(.alert, self.nextPlainSequence(), &body, out);
    const keys = find(&self.writers, self.write_current) orelse return null;
    return switch (keys.version) {
        .dtls13 => try keys.seal13(.alert, &body, "", out),
        .dtls12 => try keys.seal12(.alert, &body, "", out),
    };
}

/// Seals `plaintext` as one application record, the whole of a datagram, into `out`.
pub fn write(self: *Datagram, plaintext: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (self.phase_now != .connected) return if (self.phase_now == .handshaking) error.NotConnected else error.Closed;
    // DTLS 1.3 updates its keys while an eighth of their records is left; DTLS 1.2 has no update
    // and its association ends at the limit.
    if (find(&self.writers, self.write_current)) |current| if (current.version == .dtls13 and current.remaining() < current.record_limit / 8) self.keyUpdate(false) catch |err| switch (err) {
        error.UpdatePending => {},
        else => |e| return e,
    };
    const keys = find(&self.writers, self.write_current) orelse return error.NotConnected;
    return switch (keys.version) {
        .dtls13 => keys.seal13(.application, plaintext, "", out),
        .dtls12 => keys.seal12(.application, plaintext, "", out),
    };
}

/// Sets the largest datagram from now on, as the path's MTU changes (RFC 9147 section 4.4): a
/// flight being sent or resent is cut anew from its cached messages, never from what went before.
pub fn setMtu(self: *Datagram, mtu: u16) InitError!void {
    if (mtu < min_mtu or mtu > max_mtu) return error.InvalidOptions;
    self.mtu = mtu;
}

/// Ends the association with close_notify, which the next `send` writes.
pub fn close(self: *Datagram) void {
    if (self.phase_now == .connected) self.close_due = true;
}

/// DTLS 1.3: updates this end's write keys, asking the peer to update its own when
/// `request_peer`. The KeyUpdate goes out under the current keys; the new ones take over when the
/// peer acknowledges it.
pub fn keyUpdate(self: *Datagram, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.phase_now != .connected) return error.NotConnected;
    if (!self.dtls13()) return error.UnexpectedMessage;
    // One at a time: the next waits for the last one's ACK (RFC 9147 section 8).
    if (self.flightHasKeyUpdate() and !self.flightDone()) return error.UpdatePending;
    var buffer: [5]u8 = undefined;
    const message = try Messages.buildKeyUpdate(&buffer, request_peer);
    const bytes = try self.gpa.dupe(u8, message);
    errdefer self.gpa.free(bytes);
    try self.queue(.{ .kind = .message, .epoch = self.write_current, .bytes = bytes, .sequence = self.send_sequence, .key_update = true });
    self.send_sequence +%= 1;
}

test {
    _ = @import("Datagram_test.zig");
}
