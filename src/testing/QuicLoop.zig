//! Two record-free QUIC `Handshake`s, a client and a server, wired together the way a QUIC stack
//! would: each side's CRYPTO bytes per level reach the other side's `receive`, secrets are
//! recorded, and requests are answered from fixture keys. The scripted-peer tests pin each role
//! to independent code; this checks that the two roles agree with each other.
const std = @import("std");
const certificates = @import("cloak.certificates");
const peer_module = @import("Peer.zig");
const Handshake = @import("../tls/quic/Handshake.zig");
const Server = @import("../tls/handshake/Server.zig");
const Suite = @import("../tls/crypto/Suite.zig").Suite;
const Group = @import("../tls/crypto/Group.zig").Group;
const Alert = @import("../tls/wire/Alert.zig").Alert;

pub const pki = peer_module.pki;

pub const Options = struct {
    seed: u64 = 1,
    time: i64 = pki.time,
    client_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    server_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    client_alpn: []const []const u8 = &.{"h3"},
    server_alpn: []const []const u8 = &.{"h3"},
    client_parameters: []const u8 = "client-params",
    server_parameters: []const u8 = "server-params",
    /// The server requires and verifies a client certificate; the client has one.
    mutual: bool = false,
    /// The server asks for a certificate the client does not have.
    mutual_without_identity: bool = false,
    reject_client_parameters: bool = false,
    reject_server_parameters: bool = false,
    server_name: []const u8 = "example.com",
    /// Trust no root on the client, so the server chain fails.
    distrust: bool = false,
    chunk: usize = 1 << 20,
};

pub const Secret = struct { level: Handshake.Level, direction: Handshake.Direction, bytes: [48]u8, len: usize };

const Side = struct {
    hs: Handshake,
    inbox: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    secrets: std.ArrayList(Secret) = .empty,
    events: std.ArrayList(u8) = .empty,
    peer_parameters: std.ArrayList(u8) = .empty,
    authenticated: bool = false,
    alert: ?Alert = null,
    signed: usize = 0,
    verified: usize = 0,

    fn deinit(self: *Side, gpa: std.mem.Allocator) void {
        self.hs.deinit();
        for (&self.inbox) |*list| list.deinit(gpa);
        self.secrets.deinit(gpa);
        self.events.deinit(gpa);
        self.peer_parameters.deinit(gpa);
        self.* = undefined;
    }
};

pub fn QuicLoop(comptime suite: Suite) type {
    return struct {
        const Self = @This();

        gpa: std.mem.Allocator,
        client: Side,
        server: Side,
        trust: certificates.Trust,
        snapshot: certificates.Trust.Snapshot,
        server_identity: certificates.Identity,
        client_auth: ?certificates.ClientAuth = null,
        rng: std.Random.DefaultPrng,
        options: Options,

        pub fn init(gpa: std.mem.Allocator, options: Options) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.gpa = gpa;
            self.options = options;
            self.rng = .init(options.seed);
            self.client_auth = null;
            self.trust = certificates.Trust.init(gpa);
            errdefer self.trust.deinit();
            try self.trust.addDer(if (options.distrust) pki.p384 else pki.ca, .{});
            self.snapshot = try self.trust.freeze();
            errdefer self.snapshot.deinit();
            const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
            defer key.deinit();
            self.server_identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
            errdefer self.server_identity.deinit();
            if (options.mutual) {
                const client_key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
                defer client_key.deinit();
                self.client_auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, client_key, .{});
            }
            errdefer if (self.client_auth) |auth| auth.deinit();
            const creds = [_]Server.Credential{.{ .identity = self.server_identity }};
            self.client = .{ .hs = try Handshake.client(gpa, .{
                .identity = .{ .dns = options.server_name },
                .verify = .{ .full = .{ .trust_generation = self.snapshot.generation() } },
                .parameters = options.client_parameters,
                .alpn = options.client_alpn,
                .suites = &.{suite},
                .groups = options.client_groups,
                .auth = self.client_auth,
                .generation = .fromRaw(9),
            }) };
            errdefer self.client.deinit(gpa);
            self.server = .{ .hs = try Handshake.server(gpa, .{
                .credentials = &creds,
                .parameters = options.server_parameters,
                .alpn = options.server_alpn,
                .suites = &.{suite},
                .groups = options.server_groups,
                .client_auth = if (options.mutual or options.mutual_without_identity) .required else .none,
                .client_verify = if (options.mutual or options.mutual_without_identity) .{ .full = .{ .trust_generation = self.snapshot.generation() } } else .none,
                .generation = .fromRaw(11),
            }) };
            return self;
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.client.deinit(gpa);
            self.server.deinit(gpa);
            if (self.client_auth) |auth| auth.deinit();
            self.server_identity.deinit();
            self.snapshot.deinit();
            self.trust.deinit();
            gpa.destroy(self);
        }

        fn sign(self: *Self, side: *const Side, content: []const u8, out: *[128]u8) !usize {
            const secret = if (side == &self.client) pki.client_secret else pki.p256_secret;
            const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(secret[0..32].*));
            var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
            const sig = (try kp.sign(content, null)).toDer(&der);
            @memcpy(out[0..sig.len], sig);
            return sig.len;
        }

        pub fn service(self: *Self, side: *Side) !bool {
            var answered = false;
            while (side.hs.request()) |request| {
                answered = true;
                switch (request.service) {
                    .entropy => |len| {
                        var bytes: [512]u8 = undefined;
                        self.rng.random().bytes(bytes[0..len]);
                        try side.hs.provide(request.token, .{ .entropy = bytes[0..len] });
                    },
                    .time => try side.hs.provide(request.token, .{ .time = self.options.time }),
                    .verify => |verify_request| {
                        if (certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers())) |receipt| {
                            var owned = receipt;
                            defer owned.deinit();
                            side.verified += 1;
                            try side.hs.provide(request.token, .{ .verified = &owned });
                        } else |err| {
                            if (err == error.OutOfMemory) return err;
                            try side.hs.provide(request.token, .{ .verification_failed = .untrusted });
                        }
                    },
                    .sign => |signing| {
                        var sig: [128]u8 = undefined;
                        const n = try self.sign(side, signing.content, &sig);
                        side.signed += 1;
                        try side.hs.provide(request.token, .{ .signature = sig[0..n] });
                    },
                }
            }
            return answered;
        }

        pub fn drain(self: *Self, side: *Side, other: *Side) !bool {
            const reject = if (side == &self.client) self.options.reject_server_parameters else self.options.reject_client_parameters;
            var any = false;
            while (side.hs.next()) |event| {
                any = true;
                switch (event) {
                    .handshake_data => |d| {
                        const take = @min(d.bytes.len, self.options.chunk);
                        try other.inbox[@backingInt(d.level)].appendSlice(self.gpa, d.bytes[0..take]);
                        try side.events.append(self.gpa, 'd');
                        side.hs.ack(take);
                    },
                    .secret => |s| {
                        var entry: Secret = .{ .level = s.level, .direction = s.direction, .bytes = @splat(0), .len = s.bytes.len };
                        @memcpy(entry.bytes[0..s.bytes.len], s.bytes);
                        try side.secrets.append(self.gpa, entry);
                        try side.events.append(self.gpa, if (s.direction == .read) 'r' else 'w');
                        side.hs.ack(0);
                    },
                    .peer_parameters => |p| {
                        try side.peer_parameters.appendSlice(self.gpa, p);
                        try side.events.append(self.gpa, 'p');
                        side.hs.ack(0);
                        if (reject) side.hs.rejectParameters(.illegal_parameter) else try side.hs.acceptParameters();
                    },
                    .authenticated => {
                        side.authenticated = true;
                        try side.events.append(self.gpa, 'a');
                        side.hs.ack(0);
                    },
                    .alert => |alert| {
                        side.alert = alert;
                        try side.events.append(self.gpa, 'x');
                        side.hs.ack(0);
                    },
                }
            }
            return any;
        }

        /// One side's turn: services, events, then the lowest level with bytes waiting.
        fn turn(self: *Self, side: *Side, other: *Side) !bool {
            var moved = try self.service(side);
            if (try self.drain(side, other)) moved = true;
            inline for (.{ Handshake.Level.initial, Handshake.Level.handshake, Handshake.Level.application }) |level| {
                const list = &side.inbox[@backingInt(level)];
                if (list.items.len != 0) {
                    const take = list.items[0..@min(list.items.len, self.options.chunk)];
                    const n = side.hs.receive(level, take) catch |err| {
                        _ = try self.drain(side, other);
                        return err;
                    };
                    if (n != 0) moved = true;
                    list.replaceRange(self.gpa, 0, n, &.{}) catch unreachable; // unreachable: removing bytes never allocates
                    break;
                }
            }
            if (try self.drain(side, other)) moved = true;
            if (try self.service(side)) moved = true;
            return moved;
        }

        pub fn step(self: *Self) !bool {
            var moved = try self.turn(&self.client, &self.server);
            if (try self.turn(&self.server, &self.client)) moved = true;
            return moved;
        }

        pub fn run(self: *Self) !void {
            var rounds: usize = 0;
            while (rounds < 100_000) : (rounds += 1) {
                if (!try self.step()) {
                    if (self.client.authenticated and self.server.authenticated) return;
                    // A side that failed left an alert for its QUIC stack to send.
                    if (self.client.alert != null or self.server.alert != null) return error.Closed;
                    return error.Stalled;
                }
            }
            return error.Stalled;
        }
    };
}
