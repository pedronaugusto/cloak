//! Drives a server `Connection` against a scripted `ClientPeer`, answering every request like
//! a real driver: deterministic entropy, a fixed clock, the portable verifier for a client's
//! chain, and, for identities without a key, server signatures from the fixture keys.
const std = @import("std");
const SuiteAll = @import("../tls/crypto/Suite.zig").Suite;
const certificates = @import("../certificates.zig");
const peer_module = @import("Peer.zig");
const client_module = @import("ClientPeer.zig");
const Connection = @import("../tls/Connection.zig");
const Server = @import("../tls/handshake/Server.zig");
const Suite13 = @import("../tls/crypto/Suite.zig").Suite13;
const Group = @import("../tls/crypto/Group.zig").Group;

pub const pki = peer_module.pki;
pub const Cert = peer_module.Cert;

pub const Options = struct {
    seed: u64 = 1,
    time: i64 = pki.time,
    /// Bytes handed to `receive` and to the peer at a time.
    chunk: usize = 1 << 20,
    cert: Cert = .p256,
    /// Several credentials: the first answers unknown names.
    extra: bool = false,
    names: []const []const u8 = &.{},
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    client_auth: Server.Auth = .none,
    verify_clients: bool = true,
    limits: Connection.Limits = .{},
    /// The identities carry no key: every signature comes from the harness, as for a key held elsewhere.
    external: bool = false,
    /// Answer signing requests with a bad signature; implies `external`.
    bad_signature: bool = false,
    key_log: ?Connection.KeyLog = null,
    /// The allocator the connection uses, to measure it; the harness uses `gpa` otherwise.
    conn_gpa: ?std.mem.Allocator = null,
    /// Trust no root, so any client chain fails to verify.
    distrust: bool = false,
};

pub fn ServerPair(comptime suite: Suite13) type {
    return struct {
        const Self = @This();
        pub const ClientType = client_module.ClientPeer(suite);

        gpa: std.mem.Allocator,
        conn: Connection,
        client: ClientType,
        trust: certificates.Trust,
        snapshot: certificates.Trust.Snapshot,
        rng: std.Random.DefaultPrng,
        options: Options,
        identities: [3]?certificates.Identity = .{ null, null, null },
        signed: usize = 0,
        /// The size of the last entropy request.
        entropy_requested: usize = 0,
        verified: usize = 0,
        /// Set to time the server side: the nanoseconds spent inside its calls and the services it
        /// asked for (entropy, client verification, signing), the scripted client excluded.
        clock: ?std.Io = null,
        server_ns: u64 = 0,

        pub fn init(gpa: std.mem.Allocator, config: client_module.Config, options: Options) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.gpa = gpa;
            self.options = options;
            self.rng = .init(options.seed ^ 0x5eed);
            self.signed = 0;
            self.entropy_requested = 0;
            self.verified = 0;
            self.server_ns = 0;
            self.clock = null;
            self.identities = .{ null, null, null };
            self.trust = certificates.Trust.init(gpa);
            errdefer self.trust.deinit();
            try self.trust.addDer(if (options.distrust) pki.p384 else pki.ca, .{});
            self.snapshot = try self.trust.freeze();
            errdefer self.snapshot.deinit();
            self.client = ClientType.init(gpa, config, options.seed);
            errdefer self.client.deinit();
            errdefer self.dropIdentities();
            self.identities[0] = try identityFor(gpa, options.cert, options.external or options.bad_signature);
            var credentials: [2]Server.Credential = undefined;
            credentials[0] = .{ .identity = self.identities[0].?, .names = options.names };
            var count: usize = 1;
            if (options.extra) {
                self.identities[1] = try identityFor(gpa, .ed25519, options.external or options.bad_signature);
                credentials[1] = .{ .identity = self.identities[1].?, .names = &.{"other.example.com"} };
                count = 2;
            }
            self.conn = try Connection.server(options.conn_gpa orelse gpa, .{
                .credentials = credentials[0..count],
                .unknown_name = options.unknown_name,
                .alpn = options.alpn,
                .require_alpn = options.require_alpn,
                .require_hybrid = options.require_hybrid,
                .groups = options.groups,
                .suites = &.{comptime SuiteAll.from13(suite)},
                .client_auth = options.client_auth,
                .client_verify = if (options.client_auth != .none and options.verify_clients) .{ .full = .{ .trust_generation = self.snapshot.generation() } } else .none,
                .limits = options.limits,
                .key_log = options.key_log,
                .generation = .fromRaw(11),
            });
            return self;
        }

        fn identityFor(gpa: std.mem.Allocator, cert: Cert, external: bool) !certificates.Identity {
            const key = try certificates.PrivateKey.parse(gpa, switch (cert) {
                .p256 => pki.p256_pem,
                .p384 => pki.p384_pem,
                .ed25519 => pki.ed25519_pem,
            }, .{});
            defer key.deinit();
            const leaf = switch (cert) {
                .p256 => pki.p256,
                .p384 => pki.p384,
                .ed25519 => pki.ed25519,
            };
            if (external) return certificates.Identity.initExternal(gpa, &.{ leaf, pki.ca }, .{});
            return certificates.Identity.init(gpa, &.{ leaf, pki.ca }, key, .{});
        }

        fn dropIdentities(self: *Self) void {
            for (&self.identities) |*slot| if (slot.*) |identity| {
                identity.deinit();
                slot.* = null;
            };
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.conn.deinit();
            self.dropIdentities();
            self.client.deinit();
            self.snapshot.deinit();
            self.trust.deinit();
            gpa.destroy(self);
        }

        fn signWith(self: *Self, cert: Cert, content: []const u8, out: *[128]u8) !usize {
            var len: usize = 0;
            switch (cert) {
                .p256 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.p256_secret[0..32].*));
                    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const sig = (try kp.sign(content, null)).toDer(&der);
                    @memcpy(out[0..sig.len], sig);
                    len = sig.len;
                },
                .p384 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
                    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.p384_secret[0..48].*));
                    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const sig = (try kp.sign(content, null)).toDer(&der);
                    @memcpy(out[0..sig.len], sig);
                    len = sig.len;
                },
                .ed25519 => {
                    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.ed25519_secret[0..32].*);
                    const sig = (try kp.sign(content, null)).toBytes();
                    @memcpy(out[0..64], &sig);
                    len = 64;
                },
            }
            if (self.options.bad_signature) out[len - 1] ^= 1;
            return len;
        }

        /// The fixture key that signs for the credential the server picked.
        fn credentialCert(self: *Self, scheme: u16) Cert {
            _ = self;
            return switch (scheme) {
                0x0403 => .p256,
                0x0503 => .p384,
                else => .ed25519,
            };
        }

        fn now(self: *const Self) u64 {
            const io = self.clock orelse return 0;
            // safe: monotonic nanoseconds since an arbitrary origin are positive and below 2^64.
            return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
        }

        pub fn service(self: *Self) !bool {
            const start = self.now();
            defer self.server_ns += self.now() - start;
            return self.serveAll();
        }

        fn serveAll(self: *Self) !bool {
            var answered = false;
            while (self.conn.request()) |request| {
                answered = true;
                switch (request.service) {
                    .entropy => |len| {
                        self.entropy_requested = len;
                        var bytes: [512]u8 = undefined;
                        self.rng.random().bytes(bytes[0..len]);
                        try self.conn.provide(request.token, .{ .entropy = bytes[0..len] });
                    },
                    .time => try self.conn.provide(request.token, .{ .time = .fromNanoseconds(@as(i96, self.options.time) * std.time.ns_per_s) }),
                    .verify => |verify_request| {
                        if (certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers())) |receipt| {
                            var owned = receipt;
                            defer owned.deinit();
                            self.verified += 1;
                            try self.conn.provide(request.token, .{ .verified = &owned });
                        } else |err| {
                            if (err == error.OutOfMemory) return err;
                            try self.conn.provide(request.token, .{ .verification_failed = switch (err) {
                                error.NoTrustedPath => .untrusted,
                                error.InvalidValidity => .expired,
                                else => .bad_certificate,
                            } });
                        }
                    },
                    .sign => |signing| {
                        var sig: [128]u8 = undefined;
                        const cert = self.credentialCert(@backingInt(signing.scheme));
                        const n = try self.signWith(cert, signing.content, &sig);
                        self.signed += 1;
                        try self.conn.provide(request.token, .{ .signature = sig[0..n] });
                    },
                }
            }
            return answered;
        }

        /// One round: services, client to server, server to client. False when nothing moved.
        pub fn step(self: *Self) !bool {
            var moved = try self.service();
            const chunk = self.options.chunk;
            const from_client = self.client.pending();
            if (from_client.len != 0) {
                const start = self.now();
                defer self.server_ns += self.now() - start;
                const take = from_client[0..@min(from_client.len, chunk)];
                const n = self.conn.receive(take) catch |err| {
                    self.client.drained(from_client.len);
                    return err;
                };
                if (n != 0) moved = true;
                self.client.drained(n);
            }
            if (try self.service()) moved = true;
            const out = self.conn.output();
            if (out.len != 0) {
                var at: usize = 0;
                while (at < out.len) : (at += chunk) try self.client.feed(out[at..@min(out.len, at + chunk)]);
                self.conn.acknowledge(out.len);
                moved = true;
            }
            return moved;
        }

        pub fn run(self: *Self) !void {
            try self.client.start();
            var rounds: usize = 0;
            while (rounds < 100_000) : (rounds += 1) {
                if (self.conn.phase() == .connected and self.client.connected and self.client.pending().len == 0 and self.conn.output().len == 0) return;
                if (!try self.step()) {
                    if (self.conn.phase() == .connected and self.client.connected) return;
                    return error.Stalled;
                }
            }
            return error.Stalled;
        }

        /// Plaintext the server can read now, copied out.
        pub fn read(self: *Self, out: []u8) !usize {
            var total: usize = 0;
            while (total < out.len) {
                const view = self.conn.readable();
                if (view.len == 0) {
                    const from_client = self.client.pending();
                    if (from_client.len == 0) break;
                    const n = try self.conn.receive(from_client[0..@min(from_client.len, self.options.chunk)]);
                    self.client.drained(n);
                    if (n == 0 and self.conn.readable().len == 0) break;
                    continue;
                }
                const n = @min(view.len, out.len - total);
                @memcpy(out[total..][0..n], view[0..n]);
                self.conn.consume(n);
                total += n;
            }
            return total;
        }

        /// Delivers what the server wrote to the client.
        pub fn flush(self: *Self) !void {
            const out = self.conn.output();
            try self.client.feed(out);
            self.conn.acknowledge(out.len);
        }
    };
}
