//! Drives a client `Connection` against a scripted `Peer` in memory, answering every service
//! request the way a real driver would: deterministic entropy, a fixed clock, the portable
//! verifier over a snapshot of the test root, and signatures from the fixture client keys.
const std = @import("std");
const certificates = @import("../certificates.zig");
const peer_module = @import("Peer.zig");
const Connection = @import("../tls/Connection.zig");
const Suite = @import("../tls/crypto/Suite.zig").Suite;
const Group = @import("../tls/crypto/Group.zig").Group;

pub const pki = peer_module.pki;

pub const Options = struct {
    /// Bytes handed to `receive` at a time, and to the peer.
    chunk: usize = 1 << 20,
    seed: u64 = 1,
    time: i64 = pki.time,
    /// Reference identity for the server certificate.
    identity: certificates.types.Identity = .{ .dns = "example.com" },
    client_auth: ?certificates.ClientAuth = null,
    sign_with: enum { p256, ed25519 } = .p256,
    verify_none: bool = false,
    pins: []const [32]u8 = &.{},
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    limits: Connection.Limits = .{},
    compat: bool = true,
    /// Suites the client offers; the peer always selects the pair's suite.
    offer: ?[]const Suite = null,
    trusted_root: ?[]const u8 = null,
    key_log: ?Connection.KeyLog = null,
    /// Leave signing requests open so a test can answer them itself.
    hold_sign: bool = false,
    /// The allocator behind the connection alone, to measure what it holds.
    client_gpa: ?std.mem.Allocator = null,
};

pub fn Pair(comptime suite: Suite) type {
    return struct {
        const Self = @This();
        pub const PeerType = peer_module.Peer(suite);

        gpa: std.mem.Allocator,
        conn: Connection,
        peer: PeerType,
        trust: certificates.Trust,
        snapshot: certificates.Trust.Snapshot,
        rng: std.Random.DefaultPrng,
        options: Options,
        verified: usize = 0,
        /// Time spent inside the client connection's calls, for benchmarks.
        client_ns: u64 = 0,
        clock: ?std.Io = null,
        last_verification_error: ?anyerror = null,
        entropy_requests: usize = 0,

        pub fn init(gpa: std.mem.Allocator, config: peer_module.Config, options: Options) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.gpa = gpa;
            self.options = options;
            self.verified = 0;
            self.client_ns = 0;
            self.clock = null;
            self.last_verification_error = null;
            self.entropy_requests = 0;
            self.rng = .init(options.seed);
            self.trust = certificates.Trust.init(gpa);
            errdefer self.trust.deinit();
            try self.trust.addDer(options.trusted_root orelse pki.ca, .{});
            self.snapshot = try self.trust.freeze();
            errdefer self.snapshot.deinit();
            self.peer = PeerType.init(gpa, config);
            errdefer self.peer.deinit();
            self.conn = try Connection.client(options.client_gpa orelse gpa, .{
                .identity = options.identity,
                .verify = if (options.verify_none) .none else .{ .full = .{ .trust_generation = self.snapshot.generation(), .pins = options.pins } },
                .suites = options.offer orelse &.{suite},
                .groups = options.groups,
                .alpn = options.alpn,
                .require_alpn = options.require_alpn,
                .require_hybrid = options.require_hybrid,
                .auth = options.client_auth,
                .limits = options.limits,
                .compat = options.compat,
                .key_log = options.key_log,
                .generation = .fromRaw(7),
            });
            return self;
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.conn.deinit();
            self.peer.deinit();
            self.snapshot.deinit();
            self.trust.deinit();
            gpa.destroy(self);
        }

        fn now(self: *const Self) u64 {
            const io = self.clock orelse return 0;
            // safe: monotonic nanoseconds since an arbitrary origin are positive and below 2^64.
            return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
        }

        /// Answers every open request. Returns whether any was answered.
        pub fn service(self: *Self) !bool {
            const start = self.now();
            defer self.client_ns += self.now() - start;
            return self.serveAll();
        }

        fn serveAll(self: *Self) !bool {
            var answered = false;
            while (self.conn.request()) |request| {
                if (request.service == .sign and self.options.hold_sign) return answered;
                answered = true;
                switch (request.service) {
                    .entropy => |len| {
                        self.entropy_requests += 1;
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
                            self.last_verification_error = err;
                            try self.conn.provide(request.token, .{ .verification_failed = failure(err) });
                        }
                    },
                    .sign => |signing| {
                        const signature = try self.sign(signing.content);
                        try self.conn.provide(request.token, .{ .signature = signature.bytes[0..signature.len] });
                    },
                }
            }
            return answered;
        }

        fn failure(err: anyerror) Connection.VerifyFailure {
            return switch (err) {
                error.NoTrustedPath => .untrusted,
                error.InvalidValidity => .expired,
                else => .bad_certificate,
            };
        }

        const Signature = struct { bytes: [128]u8 = undefined, len: usize = 0 };

        fn sign(self: *Self, content: []const u8) !Signature {
            var out: Signature = .{};
            switch (self.options.sign_with) {
                .p256 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.client_secret[0..32].*));
                    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const sig = (try kp.sign(content, null)).toDer(&der);
                    @memcpy(out.bytes[0..sig.len], sig);
                    out.len = sig.len;
                },
                .ed25519 => {
                    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.client_ed25519_secret[0..32].*);
                    const sig = (try kp.sign(content, null)).toBytes();
                    @memcpy(out.bytes[0..64], &sig);
                    out.len = 64;
                },
            }
            return out;
        }

        /// One round: services, client to peer, peer to client. False when nothing moved.
        pub fn step(self: *Self) !bool {
            var moved = try self.service();
            const chunk = self.options.chunk;
            const out = self.conn.output();
            if (out.len != 0) {
                var at: usize = 0;
                while (at < out.len) : (at += chunk) try self.peer.feed(out[at..@min(out.len, at + chunk)]);
                self.conn.acknowledge(out.len);
                moved = true;
            }
            const in = self.peer.pending();
            if (in.len != 0) {
                const start = self.now();
                defer self.client_ns += self.now() - start;
                const n = self.conn.receive(in[0..@min(in.len, chunk)]) catch |err| {
                    // A failed connection may still hold an alert for the peer.
                    self.peer.drained(in.len);
                    return err;
                };
                if (n != 0) moved = true;
                self.peer.drained(n);
            }
            if (try self.service()) moved = true;
            return moved;
        }

        /// Runs until the handshake completes or nothing moves.
        pub fn handshake(self: *Self) !void {
            var rounds: usize = 0;
            while (rounds < 100_000) : (rounds += 1) {
                if (self.conn.phase() == .connected and self.peer.pending().len == 0 and self.conn.output().len == 0 and self.peer.connected) return;
                if (!try self.step()) {
                    if (self.conn.phase() == .connected and self.peer.connected) return;
                    return error.Stalled;
                }
            }
            return error.Stalled;
        }

        /// Everything the client sent that the peer has not yet read, delivered.
        pub fn flush(self: *Self) !void {
            const out = self.conn.output();
            try self.peer.feed(out);
            self.conn.acknowledge(out.len);
        }

        /// Plaintext the client can read now, copied out.
        pub fn read(self: *Self, out: []u8) !usize {
            var total: usize = 0;
            while (total < out.len) {
                const view = self.conn.readable();
                if (view.len == 0) {
                    const in = self.peer.pending();
                    if (in.len == 0) break;
                    const n = try self.conn.receive(in[0..@min(in.len, self.options.chunk)]);
                    self.peer.drained(n);
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
    };
}
