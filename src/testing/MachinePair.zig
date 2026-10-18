//! Two handshake machines, a client and a server, wired message to message with no record or
//! level between them: what a carrier would hand each side, in order. It checks that both roles
//! agree on a transport's handshake (its transcript, labels and edges) apart from any carrier.
//! Requests are answered from the fixture PKI.
const std = @import("std");
const certificates = @import("../certificates.zig");
const peer_module = @import("Peer.zig");
const suites = @import("../tls/crypto/Suite.zig");
const Group = @import("../tls/crypto/Group.zig").Group;
const Client = @import("../tls/handshake/Client.zig");
const Server = @import("../tls/handshake/Server.zig");
const Machine = @import("../tls/handshake/Machine.zig");
const Flight = @import("../tls/handshake/Flight.zig");
const Services = @import("../tls/handshake/Services.zig");

pub const pki = peer_module.pki;

pub const Options = struct {
    transport: suites.Transport = .datagram,
    client_suites: []const suites.Suite = suites.Suite.default,
    server_suites: []const suites.Suite = suites.Suite.default,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    client_auth: Server.Auth = .none,
    seed: u64 = 7,
};

/// A message or a ChangeCipherSpec, as a carrier would deliver it.
const Item = struct { bytes: []u8, epoch: Flight.Epoch, ccs: bool };

pub const Side = struct {
    machine: Machine,
    services: Services,
    inbox: std.ArrayList(Item) = .empty,
    complete: bool = false,
    /// Messages this side sent, in order, as the carrier saw them.
    sent: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Side, gpa: std.mem.Allocator) void {
        for (self.inbox.items) |item| gpa.free(item.bytes);
        self.inbox.deinit(gpa);
        for (self.sent.items) |bytes| gpa.free(bytes);
        self.sent.deinit(gpa);
        self.machine.deinit();
    }
};

const Pair = @This();

gpa: std.mem.Allocator,
rng: std.Random.DefaultPrng,
trust: certificates.Trust,
snapshot: certificates.Trust.Snapshot,
identity: certificates.Identity,
client: Side,
server: Side,
/// Holds the client's messages back from the server: a test answers them itself.
hold_client: bool = false,
transport: suites.Transport,

pub fn init(gpa: std.mem.Allocator, options: Options) !*Pair {
    const self = try gpa.create(Pair);
    errdefer gpa.destroy(self);
    self.gpa = gpa;
    self.rng = .init(options.seed);
    self.hold_client = false;
    self.transport = options.transport;
    self.trust = certificates.Trust.init(gpa);
    errdefer self.trust.deinit();
    try self.trust.addDer(pki.ca, .{});
    self.snapshot = try self.trust.freeze();
    errdefer self.snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    self.identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    errdefer self.identity.deinit();
    const client = try Client.init(gpa, .{
        .hello = .{ .transport = options.transport, .suites = options.client_suites, .groups = options.groups, .sni = "example.com" },
        .identity = .{ .dns = "example.com" },
        .verify = .{ .full = .{ .trust_generation = self.snapshot.generation() } },
        .compat = options.transport == .stream,
        .generation = .fromRaw(3),
    });
    errdefer client.deinit();
    const server = try Server.init(gpa, .{
        .transport = options.transport,
        .suites = options.server_suites,
        .groups = options.groups,
        .credentials = &.{.{ .identity = self.identity }},
        .client_auth = options.client_auth,
        .generation = .fromRaw(5),
    });
    self.client = .{ .machine = Machine.forClient(client), .services = .init(.fromRaw(3)) };
    self.server = .{ .machine = .{ .state = .{ .server = server } }, .services = .init(.fromRaw(5)) };
    return self;
}

pub fn deinit(self: *Pair) void {
    const gpa = self.gpa;
    self.client.deinit(gpa);
    self.server.deinit(gpa);
    self.identity.deinit();
    self.snapshot.deinit();
    self.trust.deinit();
    gpa.destroy(self);
}

fn serve(self: *Pair, side: *Side) !bool {
    var answered = false;
    while (side.services.request(side.machine)) |request| {
        answered = true;
        switch (request.service) {
            .entropy => |len| {
                var bytes: [2048]u8 = undefined;
                self.rng.random().bytes(bytes[0..len]);
                try side.services.answer(side.machine, request.token, .{ .entropy = bytes[0..len] });
            },
            .time => try side.services.answer(side.machine, request.token, .{ .time = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) }),
            .verify => |verify_request| {
                var receipt = try certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers());
                defer receipt.deinit();
                try side.services.answer(side.machine, request.token, .{ .verified = &receipt });
            },
            .sign => return error.UnexpectedSign,
        }
    }
    return answered;
}

/// Moves `side`'s outputs to `other`'s inbox; secrets and keys are erased, as a carrier that
/// installs them would.
fn drain(self: *Pair, side: *Side, other: *Side) !bool {
    var moved = false;
    var emit: Flight.Emit = undefined;
    while (side.machine.pop(&emit)) {
        moved = true;
        defer Flight.eraseEmit(&emit);
        switch (emit) {
            .message => |m| {
                const bytes = side.machine.flightBytes(m.start, m.len);
                try side.sent.append(self.gpa, try self.gpa.dupe(u8, bytes));
                if (side == &self.client and self.hold_client) continue;
                try other.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, bytes), .epoch = m.epoch, .ccs = false });
            },
            .change_cipher_spec => try other.inbox.append(self.gpa, .{ .bytes = &.{}, .epoch = .initial, .ccs = true }),
            // A stream's compatibility record carries nothing; a datagram must never have one.
            .compat_ccs => if (self.transport != .stream) return error.CompatChangeCipherSpec,
            .complete => side.complete = true,
            .secret, .keys12, .key_update, .ticket, .refuse_renegotiation, .auth_response, .auth_finished, .record_limits => {},
        }
    }
    side.machine.recycle();
    return moved;
}

/// Hands `side` one waiting item.
fn feed(self: *Pair, side: *Side) !bool {
    if (side.inbox.items.len == 0 or side.machine.need() != .none or side.machine.pending()) return false;
    const item = side.inbox.orderedRemove(0);
    defer self.gpa.free(item.bytes);
    if (item.ccs) try side.machine.receiveCcs() else try side.machine.receive(item.bytes, item.epoch, true);
    return true;
}

/// Delivers `message` to the client as if the server had sent it.
pub fn toClient(self: *Pair, message: []const u8) !void {
    try self.client.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, message), .epoch = .initial, .ccs = false });
}

/// Delivers the client's last sent message to the server.
pub fn forwardLast(self: *Pair) !void {
    const last = self.client.sent.items[self.client.sent.items.len - 1];
    try self.server.inbox.append(self.gpa, .{ .bytes = try self.gpa.dupe(u8, last), .epoch = .initial, .ccs = false });
}

pub fn step(self: *Pair) !bool {
    var moved = false;
    inline for (.{ .{ &self.client, &self.server }, .{ &self.server, &self.client } }) |sides| {
        if (try self.serve(sides[0])) moved = true;
        if (try self.drain(sides[0], sides[1])) moved = true;
        if (try self.feed(sides[0])) moved = true;
        if (try self.drain(sides[0], sides[1])) moved = true;
    }
    return moved;
}

pub fn run(self: *Pair) !void {
    var rounds: usize = 0;
    while (rounds < 10_000) : (rounds += 1) {
        if (!try self.step()) {
            if (self.client.complete and self.server.complete) return;
            return error.Stalled;
        }
    }
    return error.Stalled;
}
