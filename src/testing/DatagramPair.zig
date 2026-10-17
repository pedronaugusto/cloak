//! Two DTLS `Datagram`s, a client and a server, joined by a simulated network that can lose,
//! repeat, reorder and resize datagrams, with a clock the test advances. Requests are answered from
//! the fixture PKI. It drives both ends the way a UDP caller would: receive, answer, send, and
//! send again at the timeout.
const std = @import("std");
const certificates = @import("../certificates.zig");
const peer_module = @import("Peer.zig");
const Datagram = @import("../tls/dtls/Datagram.zig");
const Cookies = @import("../tls/dtls/Cookies.zig");
const suites = @import("../tls/crypto/Suite.zig");
const Group = @import("../tls/crypto/Group.zig").Group;
const Record = @import("../tls/dtls/Record.zig");
const SessionCache = @import("../tls/resumption/SessionCache.zig");
const TicketKeys = @import("../tls/resumption/TicketKeys.zig");

pub const pki = peer_module.pki;

pub const Options = struct {
    seed: u64 = 11,
    client_suites: []const suites.Suite = suites.Suite.default,
    server_suites: []const suites.Suite = suites.Suite.default,
    client_min: suites.Version = .tls12,
    client_max: suites.Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    /// The server's groups when they differ from the client's.
    server_groups: ?[]const Group = null,
    /// Resumption: the client's ticket cache and the server's ticket keys.
    cache: ?*SessionCache = null,
    tickets: ?*TicketKeys = null,
    mutual: bool = false,
    mtu: u16 = 1200,
    /// Per mille of datagrams lost, repeated, and held back to arrive after the next.
    loss: u16 = 0,
    duplicate: u16 = 0,
    reorder: u16 = 0,
    /// Drop the first `drop_first` datagrams each side sends.
    drop_first: usize = 0,
    /// Datagrams lost by number, counting from 1, of those each side sends.
    drop_client: []const usize = &.{},
    drop_server: []const usize = &.{},
    /// Prints each datagram's records as it goes, for a failing test.
    trace: bool = false,
    /// How the server meets its client: a stateless cookie check first, a path validated
    /// otherwise, or an unproven address held to three times what it sent.
    admission: enum { cookies, validated, unvalidated } = .cookies,
    /// Connection IDs each end receives with (null: not offered or not answered).
    client_cid: ?[]const u8 = null,
    server_cid: ?[]const u8 = null,
    /// use_srtp profiles each end offers or accepts.
    client_srtp: []const Datagram.Srtp = &.{},
    server_srtp: []const Datagram.Srtp = &.{},
    /// Raw public keys (RFC 7250): the server presents its key, which the client pins; with
    /// `mutual`, the client presents its key too, which the server pins.
    raw_keys: bool = false,
};

const Packet = struct { bytes: []u8 };

pub const Side = struct {
    dtls: Datagram,
    inbox: std.ArrayList(Packet) = .empty,
    held: ?Packet = null,
    sent: usize = 0,
    received: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Side, gpa: std.mem.Allocator) void {
        for (self.inbox.items) |p| gpa.free(p.bytes);
        self.inbox.deinit(gpa);
        if (self.held) |p| gpa.free(p.bytes);
        for (self.received.items) |r| gpa.free(r);
        self.received.deinit(gpa);
        self.dtls.deinit();
    }
};

const Pair = @This();

gpa: std.mem.Allocator,
rng: std.Random.DefaultPrng,
options: Options,
now: std.Io.Timestamp = .fromNanoseconds(1_000_000_000),
trust: certificates.Trust,
snapshot: certificates.Trust.Snapshot,
identity: certificates.Identity,
credential: [1]Datagram.Credential = undefined,
client_auth: ?certificates.ClientAuth = null,
client: Side,
server: Side,
server_pin: [1][32]u8 = undefined,
client_pin: [1][32]u8 = undefined,
/// The server association exists: a cookie admitted the client, or none was asked for.
server_ready: bool = false,
cookies: Cookies = .{},
/// Datagrams the stateless check answered, and what it dropped.
cookie_answers: usize = 0,
/// `run` goes on through every timer until nothing is left to send, not only until both ends
/// are connected and quiet.
settle: bool = false,

pub fn init(gpa: std.mem.Allocator, options: Options) !*Pair {
    const self = try gpa.create(Pair);
    errdefer gpa.destroy(self);
    self.* = .{ .gpa = gpa, .rng = .init(options.seed), .options = options, .trust = certificates.Trust.init(gpa), .snapshot = undefined, .identity = undefined, .client = undefined, .server = undefined };
    errdefer self.trust.deinit();
    try self.trust.addDer(pki.ca, .{});
    self.snapshot = try self.trust.freeze();
    errdefer self.snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const server_spki = (try certificates.certificate.parse(pki.p256, .{})).spki;
    const client_spki = (try certificates.certificate.parse(pki.client, .{})).spki;
    std.crypto.hash.sha2.Sha256.hash(server_spki, &self.server_pin[0], .{});
    std.crypto.hash.sha2.Sha256.hash(client_spki, &self.client_pin[0], .{});
    self.identity = if (options.raw_keys) try certificates.Identity.initRawKey(gpa, server_spki, key, .{}) else try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    errdefer self.identity.deinit();
    if (options.mutual) {
        const client_key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
        defer client_key.deinit();
        self.client_auth = if (options.raw_keys) try certificates.ClientAuth.initRawKey(gpa, client_spki, client_key, .{}) else try certificates.ClientAuth.init(gpa, &.{pki.client}, client_key, .{});
    }
    errdefer if (self.client_auth) |auth| auth.deinit();
    self.client = .{ .dtls = try Datagram.client(gpa, .{
        .identity = .{ .dns = "example.com" },
        .verify = if (options.raw_keys) .{ .raw_key = .{ .pins = &self.server_pin } } else .{ .full = .{ .trust_generation = self.snapshot.generation() } },
        .suites = options.client_suites,
        .min_version = options.client_min,
        .max_version = options.client_max,
        .groups = options.groups,
        .auth = self.client_auth,
        .resumption = if (options.cache) |cache| .{ .cache = cache } else null,
        .mtu = options.mtu,
        .generation = .fromRaw(21),
        .connection_id = options.client_cid,
        .srtp = options.client_srtp,
    }) };
    errdefer self.client.dtls.deinit();
    self.server = .{ .dtls = undefined };
    var material: [32]u8 = undefined;
    self.rng.random().bytes(&material);
    try self.cookies.rotate(material);
    if (options.admission != .cookies) try self.startServer(if (options.admission == .validated) .{} else null);
    return self;
}

pub fn serverOptions(self: *const Pair) Datagram.ServerOptions {
    return .{
        .credentials = &self.credential,
        .suites = self.options.server_suites,
        .groups = self.options.server_groups orelse self.options.groups,
        .client_auth = if (self.options.mutual) .required else .none,
        .client_verify = if (!self.options.mutual) .none else if (self.options.raw_keys) .{ .raw_key = .{ .pins = &self.client_pin } } else .{ .full = .{ .trust_generation = self.snapshot.generation() } },
        .tickets = self.options.tickets,
        .mtu = self.options.mtu,
        .generation = .fromRaw(23),
        .connection_id = self.options.server_cid,
        .srtp = self.options.server_srtp,
    };
}

fn startServer(self: *Pair, admission: ?Cookies.Admission) !void {
    self.credential = .{.{ .identity = self.identity }};
    self.server.dtls = try Datagram.server(self.gpa, self.serverOptions(), admission);
    self.server_ready = true;
}

pub fn deinit(self: *Pair) void {
    const gpa = self.gpa;
    self.client.deinit(gpa);
    if (self.server_ready) self.server.deinit(gpa) else {
        for (self.server.inbox.items) |p| gpa.free(p.bytes);
        self.server.inbox.deinit(gpa);
        if (self.server.held) |p| gpa.free(p.bytes);
    }
    self.cookies.deinit();
    if (self.client_auth) |auth| auth.deinit();
    self.identity.deinit();
    self.snapshot.deinit();
    self.trust.deinit();
    gpa.destroy(self);
}

fn chance(self: *Pair, per_mille: u16) bool {
    return per_mille != 0 and self.rng.random().uintLessThan(u16, 1000) < per_mille;
}

/// Answers the client's requests.
pub fn serveClient(self: *Pair) !void {
    try self.serve(&self.client);
}

/// Answers the server's requests.
pub fn serveServer(self: *Pair) !void {
    try self.serve(&self.server);
}

fn serve(self: *Pair, side: *Side) !void {
    while (side.dtls.request()) |request| switch (request.service) {
        .entropy => |len| {
            var bytes: [2048]u8 = undefined;
            self.rng.random().bytes(bytes[0..len]);
            try side.dtls.provide(request.token, .{ .entropy = bytes[0..len] });
        },
        .time => try side.dtls.provide(request.token, .{ .time = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) }),
        .verify => |verify_request| {
            var receipt = try certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers());
            defer receipt.deinit();
            try side.dtls.provide(request.token, .{ .verified = &receipt });
        },
        .sign => return error.UnexpectedSign,
    };
}

/// Moves what `side` sends onto the network toward `other`.
fn transmit(self: *Pair, side: *Side, other: *Side) !bool {
    var moved = false;
    var buffer: [16 * 1024]u8 = undefined;
    while (try side.dtls.send(&buffer, self.now)) |datagram| {
        moved = true;
        side.sent += 1;
        if (self.options.trace) self.show(side, datagram);
        const lost = if (side == &self.client) self.options.drop_client else self.options.drop_server;
        if (std.mem.findScalar(usize, lost, side.sent) != null) continue;
        if (side.sent <= self.options.drop_first or self.chance(self.options.loss)) continue;
        const copy = try self.gpa.dupe(u8, datagram);
        if (self.chance(self.options.reorder) and other.held == null) {
            other.held = .{ .bytes = copy };
            continue;
        }
        try other.inbox.append(self.gpa, .{ .bytes = copy });
        if (other.held) |held| {
            try other.inbox.append(self.gpa, held);
            other.held = null;
        }
        if (self.chance(self.options.duplicate)) try other.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, datagram) });
    }
    return moved;
}

fn show(self: *Pair, side: *Side, datagram: []const u8) void {
    var copy: [16 * 1024]u8 = undefined;
    @memcpy(copy[0..datagram.len], datagram);
    var rest: []u8 = copy[0..datagram.len];
    std.debug.print("t={d}ms {s} sends {d} bytes:", .{ @divTrunc(self.now.nanoseconds, std.time.ns_per_ms), if (side == &self.client) "client" else "server", datagram.len });
    // Records carry the connection ID of the end they go to.
    const ready = side != &self.server or self.server_ready;
    const cid_len: usize = if (ready and side.dtls.cids_agreed) side.dtls.peer_cid_len else 0;
    while (Record.split(rest, cid_len)) |next| {
        rest = next.rest;
        switch (next.kind) {
            .classic => |h| {
                std.debug.print(" [type {d} epoch {d} seq {d} len {d}", .{ next.record[0], h.epoch, h.sequence, next.record.len - h.length });
                if (next.record[0] == 22 and h.epoch == 0) std.debug.print(" msg {d} seq {d} off {d} frag {d}", .{ next.record[13], std.mem.readInt(u16, next.record[17..19], .big), std.mem.readInt(u24, next.record[19..22], .big), std.mem.readInt(u24, next.record[22..25], .big) });
                std.debug.print("]", .{});
            },
            .unified => |h| std.debug.print(" [unified epoch bits {d} len {d}]", .{ h.epoch_bits, next.record.len - h.length }),
        }
    }
    std.debug.print(" | client {s} server {s}\n", .{ @tagName(self.client.dtls.phase()), if (self.server_ready) @tagName(self.server.dtls.phase()) else "unborn" });
}

fn deliver(self: *Pair, side: *Side) !bool {
    if (side.inbox.items.len == 0) return false;
    const packet = side.inbox.orderedRemove(0);
    defer self.gpa.free(packet.bytes);
    if (side == &self.server and !self.server_ready) {
        // The stateless check meets the client first.
        var out: [16 * 1024]u8 = undefined;
        const options = self.serverOptions();
        switch (self.cookies.check(&options, "client:1", self.now, packet.bytes, &out)) {
            .respond => |answer| {
                self.cookie_answers += 1;
                if (self.options.trace) self.show(&self.server, answer);
                try self.client.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, answer) });
                return true;
            },
            .drop => return true,
            .admit => |admission| try self.startServer(admission),
        }
    }
    side.dtls.receive(packet.bytes, self.now) catch |err| return err;
    while (side.dtls.read()) |plain| try side.received.append(self.gpa, try self.gpa.dupe(u8, plain));
    return true;
}

pub fn step(self: *Pair) !bool {
    var moved = false;
    inline for (.{ .{ &self.client, &self.server }, .{ &self.server, &self.client } }) |sides| {
        const ready = sides[0] != &self.server or self.server_ready;
        if (ready) try self.serve(sides[0]);
        if (ready and try self.transmit(sides[0], sides[1])) moved = true;
        if (try self.deliver(sides[0])) moved = true;
        if (sides[0] != &self.server or self.server_ready) {
            try self.serve(sides[0]);
            if (try self.transmit(sides[0], sides[1])) moved = true;
        }
    }
    return moved;
}

/// Moves datagrams until nothing moves, without advancing the clock.
pub fn flush(self: *Pair) !void {
    while (try self.step()) {}
}

/// Runs until both ends are connected and quiet, advancing the clock to the next timeout when
/// nothing moves.
pub fn run(self: *Pair) !void {
    var rounds: usize = 0;
    while (rounds < 10_000) : (rounds += 1) {
        if (try self.step()) continue;
        if (self.client.held) |held| {
            try self.client.inbox.append(self.gpa, held);
            self.client.held = null;
            continue;
        }
        if (self.server.held) |held| {
            try self.server.inbox.append(self.gpa, held);
            self.server.held = null;
            continue;
        }
        const connected = self.server_ready and self.client.dtls.phase() == .connected and self.server.dtls.phase() == .connected;
        const next = earliest(self.client.dtls.timeout(), if (self.server_ready) self.server.dtls.timeout() else null) orelse {
            if (connected) return;
            if (self.client.dtls.failure()) |err| return err;
            if (self.server_ready) if (self.server.dtls.failure()) |err| return err;
            return error.Stalled;
        };
        if (connected and self.client.inbox.items.len == 0 and self.server.inbox.items.len == 0 and rounds > 0 and next.nanoseconds - self.now.nanoseconds > 0 and self.options.loss == 0 and self.options.drop_first == 0 and !self.settle) return;
        self.now = next;
    }
    return error.Stalled;
}

fn earliest(a: ?std.Io.Timestamp, b: ?std.Io.Timestamp) ?std.Io.Timestamp {
    const x = a orelse return b;
    const y = b orelse return x;
    return if (x.nanoseconds <= y.nanoseconds) x else y;
}

/// Sends `message` from one side as an application datagram and runs the network.
pub fn exchange(self: *Pair, from: *Side, message: []const u8) !void {
    var buffer: [16 * 1024 + 64]u8 = undefined;
    const record = try from.dtls.write(message, &buffer);
    const to = if (from == &self.client) &self.server else &self.client;
    try to.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, record) });
    _ = try self.deliver(to);
}
