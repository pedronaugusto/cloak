//! A cloak client against a cloak server in memory, each answering its own requests the way a
//! driver would: deterministic entropy, a fixed clock and the portable verifier over the test
//! root. For version and suite coverage the scripted peers do not reach (TLS 1.2); external
//! peers in the trials campaign check what two cloak ends cannot.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Connection = @import("../tls/Connection.zig");
const Server = @import("../tls/handshake/Server.zig");
const Suite = @import("../tls/crypto/Suite.zig").Suite;
const Version = @import("../tls/crypto/Suite.zig").Version;
const Group = @import("../tls/crypto/Group.zig").Group;
const SessionCache = @import("../tls/resumption/SessionCache.zig");
const TicketKeys = @import("../tls/resumption/TicketKeys.zig");
pub const pki = @import("Peer.zig").pki;

pub const Cert = enum { p256, p384, ed25519, rsa };

pub const Options = struct {
    seed: u64 = 1,
    cert: Cert = .p256,
    client_suites: []const Suite = Suite.default,
    server_suites: []const Suite = Suite.default,
    client_min: Version = .tls12,
    client_max: Version = .tls13,
    server_max: Version = .tls13,
    server_min: Version = .tls12,
    client_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    server_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    client_alpn: []const []const u8 = &.{},
    server_alpn: []const []const u8 = &.{},
    client_auth: Server.Auth = .none,
    /// The client offers its certificate when asked.
    client_cert: bool = false,
    /// Bytes moved per receive call, to cut records and messages at every boundary.
    chunk: usize = 1 << 20,
    /// Resumption: the client's ticket cache and the server's ticket keys.
    cache: ?*SessionCache = null,
    namespace: []const u8 = "",
    max_age: std.Io.Duration = .fromSeconds(7 * 24 * 60 * 60),
    tickets: ?*TicketKeys = null,
    /// TLS 1.2 tickets at the client and at the server.
    client_tls12_tickets: bool = false,
    server_tls12_tickets: bool = false,
    /// The calendar time both ends are told, in seconds.
    time: i64 = pki.time,
    /// The verification policy generations of the client and of the server's client checks.
    client_policy_generation: u64 = 1,
    server_policy_generation: u64 = 1,
    pins: []const [32]u8 = &.{},
    identity: []const u8 = "example.com",
    /// Overrides when the server's verdict on the client's certificate expires, in seconds.
    receipt_expires: ?i64 = null,
    /// Overrides when the client's verdict on the server's certificate expires, in seconds.
    server_receipt_expires: ?i64 = null,
};

const Duo = @This();

gpa: std.mem.Allocator,
client: Connection,
server: Connection,
trust: certificates.Trust,
snapshot: certificates.Trust.Snapshot,
identity: certificates.Identity,
auth: ?certificates.ClientAuth = null,
rng: std.Random.DefaultPrng,
options: Options,

pub fn init(gpa: std.mem.Allocator, options: Options) !*Duo {
    const self = try gpa.create(Duo);
    errdefer gpa.destroy(self);
    self.* = undefined;
    self.gpa = gpa;
    self.options = options;
    self.rng = .init(options.seed);
    self.trust = certificates.Trust.init(gpa);
    errdefer self.trust.deinit();
    try self.trust.addDer(pki.ca, .{});
    self.snapshot = try self.trust.freeze();
    errdefer self.snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, switch (options.cert) {
        .p256 => pki.p256_pem,
        .p384 => pki.p384_pem,
        .ed25519 => pki.ed25519_pem,
        .rsa => pki.rsa_pem,
    }, .{});
    defer key.deinit();
    const leaf = switch (options.cert) {
        .p256 => pki.p256,
        .p384 => pki.p384,
        .ed25519 => pki.ed25519,
        .rsa => pki.rsa,
    };
    self.identity = try certificates.Identity.init(gpa, &.{ leaf, pki.ca }, key, .{});
    errdefer self.identity.deinit();
    self.auth = null;
    if (options.client_cert) {
        const client_key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
        defer client_key.deinit();
        self.auth = try certificates.ClientAuth.init(gpa, &.{ pki.client, pki.ca }, client_key, .{});
    }
    errdefer if (self.auth) |auth| auth.deinit();
    self.client = try Connection.client(gpa, .{
        .identity = .{ .dns = options.identity },
        .verify = .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.client_policy_generation), .pins = options.pins } },
        .resumption = if (options.cache) |cache| .{ .cache = cache, .namespace = options.namespace, .max_age = options.max_age, .tls12 = options.client_tls12_tickets } else null,
        .suites = options.client_suites,
        .min_version = options.client_min,
        .max_version = options.client_max,
        .groups = options.client_groups,
        .alpn = options.client_alpn,
        .auth = self.auth,
    });
    errdefer self.client.deinit();
    self.server = try Connection.server(gpa, .{
        .credentials = &.{.{ .identity = self.identity }},
        .suites = options.server_suites,
        .min_version = options.server_min,
        .max_version = options.server_max,
        .groups = options.server_groups,
        .alpn = options.server_alpn,
        .client_auth = options.client_auth,
        .client_verify = if (options.client_auth != .none) .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.server_policy_generation) } } else .none,
        .tickets = options.tickets,
        .tls12_tickets = options.server_tls12_tickets,
    });
    return self;
}

pub fn deinit(self: *Duo) void {
    const gpa = self.gpa;
    self.client.deinit();
    self.server.deinit();
    if (self.auth) |auth| auth.deinit();
    self.identity.deinit();
    self.snapshot.deinit();
    self.trust.deinit();
    gpa.destroy(self);
}

fn serve(self: *Duo, conn: *Connection) !void {
    while (conn.request()) |request| switch (request.service) {
        .entropy => |len| {
            var bytes: [512]u8 = undefined;
            self.rng.random().bytes(bytes[0..len]);
            conn.provide(request.token, .{ .entropy = bytes[0..len] }) catch |err| switch (err) {
                // A scalar draw outside its range: draw again.
                error.InvalidEntropy => continue,
                else => return err,
            };
        },
        .time => try conn.provide(request.token, .{ .time = .fromNanoseconds(@as(i96, self.options.time) * std.time.ns_per_s) }),
        .verify => |verify_request| {
            if (certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers())) |receipt| {
                var owned = receipt;
                defer owned.deinit();
                const override = if (conn == &self.server) self.options.receipt_expires else self.options.server_receipt_expires;
                if (override) |expires| owned.expires = certificates.types.instant(expires);
                try conn.provide(request.token, .{ .verified = &owned });
            } else |_| try conn.provide(request.token, .{ .verification_failed = .untrusted });
        },
        .sign => return error.UnexpectedSignRequest,
    };
}

/// Moves `from`'s output into `to`, `chunk` bytes per receive call.
fn move(self: *Duo, from: *Connection, to: *Connection) !bool {
    const bytes = from.output();
    if (bytes.len == 0) return false;
    var at: usize = 0;
    while (at < bytes.len) {
        const end = @min(bytes.len, at + self.options.chunk);
        const n = try to.receive(bytes[at..end]);
        at += n;
        if (n == 0) {
            if (to.request() == null) return error.Stalled;
            try self.serve(to);
        }
    }
    from.acknowledge(bytes.len);
    return true;
}

/// Runs both ends until both are connected and nothing is left to send.
pub fn handshake(self: *Duo) !void {
    for (0..64) |_| {
        try self.serve(&self.client);
        const sent = try self.move(&self.client, &self.server);
        try self.serve(&self.server);
        const answered = try self.move(&self.server, &self.client);
        if (self.client.phase() == .connected and self.server.phase() == .connected and
            self.client.output().len == 0 and self.server.output().len == 0) return;
        if (!sent and !answered) return error.Stalled;
    }
    return error.Stalled;
}

/// Sends `message` from `from` to `to` and reads it back out.
pub fn echo(self: *Duo, from: *Connection, to: *Connection, message: []const u8, out: []u8) ![]u8 {
    var at: usize = 0;
    while (at < message.len) at += try from.send(message[at..]);
    _ = try self.move(from, to);
    var got: usize = 0;
    while (got < message.len) {
        const view = to.readable();
        if (view.len == 0) return error.Stalled;
        @memcpy(out[got..][0..view.len], view);
        to.consume(view.len);
        got += view.len;
    }
    return out[0..got];
}

/// Runs until the server's first flight is waiting in its output, not yet delivered.
pub fn handshakeUntilServerFlight(self: *Duo) !void {
    try self.serve(&self.client);
    _ = try self.move(&self.client, &self.server);
    try self.serve(&self.server);
    if (self.server.output().len == 0) return error.Stalled;
}

/// Moves the client's pending output to the server, after `edit` changes it in place.
pub fn deliverEdited(self: *Duo, edit: *const fn (bytes: []u8) void) !void {
    try self.serve(&self.client);
    const bytes = self.client.output();
    const copy = try self.gpa.dupe(u8, bytes);
    defer self.gpa.free(copy);
    self.client.acknowledge(bytes.len);
    edit(copy);
    var at: usize = 0;
    while (at < copy.len) {
        const n = try self.server.receive(copy[at..]);
        at += n;
        if (n == 0) {
            if (self.server.request() == null) return error.Stalled;
            try self.serve(&self.server);
        }
    }
    try self.serve(&self.server);
}

/// Answers whatever the client asks for now.
pub fn serveClient(self: *Duo) !void {
    try self.serve(&self.client);
}

/// Answers whatever the server asks for now.
pub fn serveServer(self: *Duo) !void {
    try self.serve(&self.server);
}
