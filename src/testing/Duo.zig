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
const Ech = @import("../tls/handshake/Ech.zig");
const Compression = @import("../tls/handshake/Compression.zig");
const Psk = @import("../tls/handshake/Psk.zig");
pub const pki = @import("Peer.zig").pki;

pub const Cert = enum { p256, p384, ed25519, rsa, mldsa44, mldsa65, mldsa87, mldsa44_classical, p256_pqca };

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
    client_require_hybrid: bool = false,
    server_require_hybrid: bool = false,
    client_alpn: []const []const u8 = &.{},
    server_alpn: []const []const u8 = &.{},
    client_auth: Server.Auth = .none,
    /// The client offers its certificate when asked.
    client_cert: bool = false,
    /// That certificate's key is Ed25519 (P-256 otherwise).
    client_ed25519: bool = false,
    /// That certificate is ML-DSA-65 under the ML-DSA root.
    client_mldsa: bool = false,
    /// Post-quantum authentication required of the server (client) and of the client (server).
    client_require_pq_auth: bool = false,
    server_require_pq_auth: bool = false,
    /// The client's key is held elsewhere: the harness signs (Ed25519 only).
    client_external: bool = false,
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
    /// Encrypted Client Hello at the client and the server.
    client_ech: Ech.Mode = .off,
    server_ech: []const Ech.Key = &.{},
    /// Verify nothing at the client.
    client_verify_none: bool = false,
    /// Certificate codecs: the client's decoders and the server's encoders.
    client_codecs: []const Compression.Codec = &.{},
    server_codecs: []const Compression.Codec = &.{},
    /// Provisioned keys: the client's and the server's lookup.
    client_psk: ?Psk.External = null,
    server_psk: ?Psk.Lookup = null,
    /// What the client connection allocates from, to measure it; the harness's own otherwise.
    client_gpa: ?std.mem.Allocator = null,
    /// Raw public keys (RFC 7250): the server's credentials (its certificate's, or the raw key of
    /// the same key alone, or the raw key first and the certificate after), the pins the client
    /// trusts the server's key by, the client's credential as a raw key, and the pins the server
    /// trusts the client's key by.
    server_raw: enum { none, only, both } = .none,
    client_raw_pins: ?[]const [32]u8 = null,
    client_raw: bool = false,
    server_raw_pins: ?[]const [32]u8 = null,
};

/// The SHA-256 of a certificate's SubjectPublicKeyInfo: the pin of its key as a raw public key.
pub fn pinOf(der: []const u8) [32]u8 {
    const cert = certificates.certificate.parse(der, .{}) catch unreachable; // unreachable: test PKI
    var pin: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &pin, .{});
    return pin;
}

const Duo = @This();

gpa: std.mem.Allocator,
client: Connection,
server: Connection,
trust: certificates.Trust,
snapshot: certificates.Trust.Snapshot,
identity: certificates.Identity,
raw_identity: ?certificates.Identity = null,
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
    try self.trust.addDer(pki.mldsa_ca, .{});
    try self.trust.addDer(pki.mixed_ca, .{});
    self.snapshot = try self.trust.freeze();
    errdefer self.snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, switch (options.cert) {
        .p256 => pki.p256_pem,
        .p384 => pki.p384_pem,
        .ed25519 => pki.ed25519_pem,
        .rsa => pki.rsa_pem,
        .mldsa44 => pki.mldsa44_pem,
        .mldsa65 => pki.mldsa65_pem,
        .mldsa87 => pki.mldsa87_pem,
        .mldsa44_classical => pki.mldsa44_classical_pem,
        .p256_pqca => pki.p256_pqca_pem,
    }, .{});
    defer key.deinit();
    const leaf = switch (options.cert) {
        .p256 => pki.p256,
        .p384 => pki.p384,
        .ed25519 => pki.ed25519,
        .rsa => pki.rsa,
        .mldsa44 => pki.mldsa44,
        .mldsa65 => pki.mldsa65,
        .mldsa87 => pki.mldsa87,
        .mldsa44_classical => pki.mldsa44_classical,
        .p256_pqca => pki.p256_pqca,
    };
    const root = switch (options.cert) {
        .mldsa44, .mldsa65, .mldsa87, .p256_pqca => pki.mldsa_ca,
        .mldsa44_classical => pki.mixed_ca,
        else => pki.ca,
    };
    self.identity = try certificates.Identity.init(gpa, &.{ leaf, root }, key, .{});
    errdefer self.identity.deinit();
    self.raw_identity = if (options.server_raw != .none) try certificates.Identity.initRawKey(gpa, (try certificates.certificate.parse(leaf, .{})).spki, key, .{}) else null;
    errdefer if (self.raw_identity) |raw| raw.deinit();
    self.auth = null;
    if (options.client_cert) {
        const client_key = try certificates.PrivateKey.parse(gpa, if (options.client_mldsa) pki.client_mldsa65_pem else if (options.client_ed25519) pki.client_ed25519_pem else pki.client_pem, .{});
        defer client_key.deinit();
        const chain: []const []const u8 = if (options.client_mldsa) &.{ pki.client_mldsa65, pki.mldsa_ca } else &.{ if (options.client_ed25519) pki.client_ed25519 else pki.client, pki.ca };
        self.auth = if (options.client_raw)
            try certificates.ClientAuth.initRawKey(gpa, (try certificates.certificate.parse(chain[0], .{})).spki, client_key, .{})
        else if (options.client_external)
            try certificates.ClientAuth.initExternal(gpa, chain, .{})
        else
            try certificates.ClientAuth.init(gpa, chain, client_key, .{});
    }
    errdefer if (self.auth) |auth| auth.deinit();
    self.client = try Connection.client(options.client_gpa orelse gpa, .{
        .identity = .{ .dns = options.identity },
        .verify = if (options.client_raw_pins) |pins| .{ .raw_key = .{ .pins = pins } } else if (options.client_verify_none) .none else .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.client_policy_generation), .pins = options.pins } },
        .ech = options.client_ech,
        .certificate_compression = options.client_codecs,
        .external_psk = options.client_psk,
        .resumption = if (options.cache) |cache| .{ .cache = cache, .namespace = options.namespace, .max_age = options.max_age, .tls12 = options.client_tls12_tickets } else null,
        .suites = options.client_suites,
        .min_version = options.client_min,
        .max_version = options.client_max,
        .groups = options.client_groups,
        .require_hybrid = options.client_require_hybrid,
        .require_pq_auth = options.client_require_pq_auth,
        .alpn = options.client_alpn,
        .auth = self.auth,
    });
    errdefer self.client.deinit();
    self.server = try Connection.server(gpa, .{
        .credentials = switch (options.server_raw) {
            .none => &.{.{ .identity = self.identity }},
            .only => &.{.{ .identity = self.raw_identity.? }},
            .both => &.{ .{ .identity = self.raw_identity.? }, .{ .identity = self.identity } },
        },
        .suites = options.server_suites,
        .min_version = options.server_min,
        .max_version = options.server_max,
        .groups = options.server_groups,
        .require_hybrid = options.server_require_hybrid,
        .require_pq_auth = options.server_require_pq_auth,
        .alpn = options.server_alpn,
        .client_auth = options.client_auth,
        .client_verify = if (options.server_raw_pins) |pins| .{ .raw_key = .{ .pins = pins } } else if (options.client_auth != .none) .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.server_policy_generation) } } else .none,
        .tickets = options.tickets,
        .tls12_tickets = options.server_tls12_tickets,
        .ech_keys = options.server_ech,
        .certificate_compression = options.server_codecs,
        .external_psk = options.server_psk,
    });
    return self;
}

pub fn deinit(self: *Duo) void {
    const gpa = self.gpa;
    self.client.deinit();
    self.server.deinit();
    if (self.auth) |auth| auth.deinit();
    if (self.raw_identity) |raw| raw.deinit();
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
        .sign => |request_| {
            if (!self.options.client_external or request_.scheme != .ed25519 or request_.prehashed) return error.UnexpectedSignRequest;
            const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.client_ed25519_secret[0..32].*);
            const sig = (try kp.sign(request_.content, null)).toBytes();
            try conn.provide(request.token, .{ .signature = &sig });
        },
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

/// Moves the server's pending output to the client and answers what it then asks for.
pub fn deliverServer(self: *Duo) !void {
    _ = try self.move(&self.server, &self.client);
    try self.serve(&self.client);
}

/// Moves the server's pending output to the client after `edit` changes it in place.
pub fn deliverServerEdited(self: *Duo, edit: *const fn (bytes: []u8) void) !void {
    const bytes = self.server.output();
    const copy = try self.gpa.dupe(u8, bytes);
    defer self.gpa.free(copy);
    self.server.acknowledge(bytes.len);
    edit(copy);
    var at: usize = 0;
    while (at < copy.len) {
        const n = try self.client.receive(copy[at..]);
        at += n;
        if (n == 0) {
            if (self.client.request() == null) return error.Stalled;
            try self.serve(&self.client);
        }
    }
    try self.serve(&self.client);
}

/// Answers whatever the client asks for now.
pub fn serveClient(self: *Duo) !void {
    try self.serve(&self.client);
}

/// Answers whatever the server asks for now.
pub fn serveServer(self: *Duo) !void {
    try self.serve(&self.server);
}
