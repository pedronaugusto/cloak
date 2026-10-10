//! Drives a record-free QUIC `Handshake` against a scripted `Peer` speaking the QUIC dialect,
//! answering requests like a real driver and recording every event it sees.
const std = @import("std");
const certificates = @import("cloak.certificates");
const peer_module = @import("Peer.zig");
const Handshake = @import("../tls/quic/Handshake.zig");
const Suite = @import("../tls/crypto/Suite.zig").Suite;
const Group = @import("../tls/crypto/Group.zig").Group;
const Alert = @import("../tls/wire/Alert.zig").Alert;

pub const pki = peer_module.pki;

pub const Options = struct {
    seed: u64 = 1,
    time: i64 = pki.time,
    identity: certificates.types.Identity = .{ .dns = "example.com" },
    alpn: []const []const u8 = &.{"h3"},
    parameters: []const u8 = "client-params",
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    require_hybrid: bool = false,
    /// Bytes handed to `receive` and acknowledged at a time.
    chunk: usize = 1 << 20,
    reject_parameters: bool = false,
    client_auth: ?certificates.ClientAuth = null,
};

pub const Secret = struct { level: Handshake.Level, direction: Handshake.Direction, bytes: [48]u8, len: usize };

pub fn QuicPair(comptime suite: Suite) type {
    return struct {
        const Self = @This();
        pub const PeerType = peer_module.Peer(suite);

        gpa: std.mem.Allocator,
        hs: Handshake,
        peer: PeerType,
        trust: certificates.Trust,
        snapshot: certificates.Trust.Snapshot,
        rng: std.Random.DefaultPrng,
        options: Options,
        sent: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
        secrets: std.ArrayList(Secret) = .empty,
        events: std.ArrayList(u8) = .empty,
        peer_parameters: std.ArrayList(u8) = .empty,
        authenticated: bool = false,
        alert: ?Alert = null,

        pub fn init(gpa: std.mem.Allocator, config: peer_module.Config, options: Options) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            self.* = .{ .gpa = gpa, .hs = undefined, .peer = undefined, .trust = undefined, .snapshot = undefined, .rng = .init(options.seed), .options = options };
            self.trust = certificates.Trust.init(gpa);
            errdefer self.trust.deinit();
            try self.trust.addDer(pki.ca, .{});
            self.snapshot = try self.trust.freeze();
            errdefer self.snapshot.deinit();
            var quic_config = config;
            quic_config.quic = true;
            self.peer = PeerType.init(gpa, quic_config);
            errdefer self.peer.deinit();
            self.hs = try Handshake.client(gpa, .{
                .identity = options.identity,
                .verify = .{ .full = .{ .trust_generation = self.snapshot.generation() } },
                .parameters = options.parameters,
                .alpn = options.alpn,
                .suites = &.{suite},
                .groups = options.groups,
                .require_hybrid = options.require_hybrid,
                .auth = options.client_auth,
                .generation = .fromRaw(9),
            });
            return self;
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            self.hs.deinit();
            self.peer.deinit();
            self.snapshot.deinit();
            self.trust.deinit();
            for (&self.sent) |*list| list.deinit(gpa);
            self.secrets.deinit(gpa);
            self.events.deinit(gpa);
            self.peer_parameters.deinit(gpa);
            gpa.destroy(self);
        }

        fn note(self: *Self, tag: u8) !void {
            try self.events.append(self.gpa, tag);
        }

        pub fn service(self: *Self) !bool {
            var answered = false;
            while (self.hs.request()) |request| {
                answered = true;
                switch (request.service) {
                    .entropy => |len| {
                        var bytes: [512]u8 = undefined;
                        self.rng.random().bytes(bytes[0..len]);
                        try self.hs.provide(request.token, .{ .entropy = bytes[0..len] });
                    },
                    .time => try self.hs.provide(request.token, .{ .time = self.options.time }),
                    .verify => |verify_request| {
                        var receipt = try certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers());
                        defer receipt.deinit();
                        try self.hs.provide(request.token, .{ .verified = &receipt });
                    },
                    .sign => |signing| {
                        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                        const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.client_secret[0..32].*));
                        var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                        const sig = (try kp.sign(signing.content, null)).toDer(&der);
                        try self.hs.provide(request.token, .{ .signature = sig });
                    },
                }
            }
            return answered;
        }

        /// Handles every event; false when none was pending.
        pub fn drain(self: *Self) !bool {
            var any = false;
            while (self.hs.next()) |event| {
                any = true;
                switch (event) {
                    .handshake_data => |d| {
                        const take = @min(d.bytes.len, self.options.chunk);
                        try self.sent[@backingInt(d.level)].appendSlice(self.gpa, d.bytes[0..take]);
                        try self.peer.feedLevel(@fromBackingInt(@intCast(@backingInt(d.level))), d.bytes[0..take]);
                        try self.note('d');
                        self.hs.ack(take);
                    },
                    .secret => |s| {
                        var entry: Secret = .{ .level = s.level, .direction = s.direction, .bytes = @splat(0), .len = s.bytes.len };
                        @memcpy(entry.bytes[0..s.bytes.len], s.bytes);
                        try self.secrets.append(self.gpa, entry);
                        try self.note(if (s.direction == .read) 'r' else 'w');
                        self.hs.ack(0);
                    },
                    .peer_parameters => |p| {
                        try self.peer_parameters.appendSlice(self.gpa, p);
                        try self.note('p');
                        self.hs.ack(0);
                        if (self.options.reject_parameters) {
                            self.hs.rejectParameters(.illegal_parameter);
                        } else try self.hs.acceptParameters();
                    },
                    .authenticated => {
                        self.authenticated = true;
                        try self.note('a');
                        self.hs.ack(0);
                    },
                    .alert => |alert| {
                        self.alert = alert;
                        try self.note('x');
                        self.hs.ack(0);
                    },
                }
            }
            return any;
        }

        /// The client's first flight: services and events, no peer bytes delivered yet.
        pub fn start(self: *Self) !void {
            _ = try self.service();
            _ = try self.drain();
        }

        /// One round of services, events and peer bytes. False when nothing moved.
        pub fn step(self: *Self) !bool {
            var moved = try self.service();
            if (try self.drain()) moved = true;
            // A level is released only after the one before it was fully delivered, as a QUIC
            // stack holds data it cannot yet decrypt.
            inline for (.{ PeerType.Level.initial, PeerType.Level.handshake, PeerType.Level.application }) |which| {
                const bytes = self.peer.level(which);
                if (bytes.len != 0) {
                    const take = bytes[0..@min(bytes.len, self.options.chunk)];
                    const n = try self.hs.receive(@fromBackingInt(@intCast(@backingInt(which))), take);
                    if (n != 0) moved = true;
                    self.peer.levelDrained(which, n);
                    break;
                }
            }
            if (try self.drain()) moved = true;
            if (try self.service()) moved = true;
            return moved;
        }

        pub fn run(self: *Self) !void {
            var rounds: usize = 0;
            while (rounds < 100_000) : (rounds += 1) {
                if (!try self.step()) {
                    if (self.authenticated and self.peer.connected) return;
                    return error.Stalled;
                }
            }
            return error.Stalled;
        }
    };
}
