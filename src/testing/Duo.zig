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
    }, .{ .entropy = certificates.PrivateKey.Entropy.fromIo(&std.testing.io) });
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
        .identity = .{ .dns = "example.com" },
        .verify = .{ .full = .{ .trust_generation = self.snapshot.generation() } },
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
        .client_verify = if (options.client_auth != .none) .{ .full = .{ .trust_generation = self.snapshot.generation() } } else .none,
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
        .time => try conn.provide(request.token, .{ .time = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) }),
        .verify => |verify_request| {
            if (certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers())) |receipt| {
                var owned = receipt;
                defer owned.deinit();
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
