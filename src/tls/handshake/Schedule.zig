//! One handshake key-schedule owner. Traffic holders transfer to the transport; the
//! resumption master secret stays for the tickets that follow the handshake.
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
pub const InitError = error{InvalidSharedSecret};
pub const AdvanceError = error{WrongPhase};
pub const ExportError = AdvanceError || Labels.ExpandError;
/// Which binder key: a ticket's ("res binder") or a provisioned key's ("ext binder"), so a key of
/// one kind never passes for the other (RFC 8446 section 7.1).
pub const BinderKind = enum { resumption, external };
pub fn Schedule(comptime suite: suites.Suite13) type {
    const Hash = suites.Hash(suite);
    const Secret = aegis.Secret([Hash.digest_length]u8);
    return struct {
        const Self = @This();
        pub const Traffic = struct {
            client: Secret = .init(undefined),
            server: Secret = .init(undefined),
            pub fn deinit(self: *Traffic) void {
                self.client.deinit();
                self.server.deinit();
            }
        };
        pub const length = Hash.digest_length;
        /// "tls13 " or "dtls13": every label this schedule and its traffic derive.
        prefix: Labels.Prefix,
        root: Secret,
        exporter: Secret = .init(undefined),
        /// RFC 8446 section 7.1 resumption_master_secret, derived at completion.
        resumption: Secret = .init(@splat(0)),
        phase: enum { handshake, application, complete, erased } = .handshake,
        /// The handshake secrets from a resumption `psk` (null for a full handshake, whose early
        /// secret extracts zeros) and the (EC)DHE `shared` secret: PSK-DHE only, never PSK alone.
        pub fn init(prefix: Labels.Prefix, psk: ?*const [length]u8, shared: []const u8, hello_hash: *const [length]u8, traffic: *Traffic) InitError!Self {
            @setRuntimeSafety(true);
            if (shared.len != 32 and shared.len != 48 and shared.len != 64 and shared.len != 80) return error.InvalidSharedSecret;
            var early = Secret.init(undefined);
            defer early.deinit();
            var derived = Secret.init(undefined);
            defer derived.deinit();
            const zero: [length]u8 = @splat(0);
            Labels.extract(Hash, early.exposeMut(), &zero, if (psk) |key| key else &zero);
            expand(prefix, derived.exposeMut(), early.expose(), "derived", &emptyHash());
            var self: Self = .{ .prefix = prefix, .root = .init(undefined) };
            errdefer self.deinit();
            Labels.extract(Hash, self.root.exposeMut(), derived.expose(), shared);
            self.deriveTraffic(traffic, "c hs traffic", "s hs traffic", hello_hash);
            return self;
        }
        pub fn application(self: *Self, server_finished_hash: *const [Hash.digest_length]u8, traffic: *Traffic) AdvanceError!void {
            @setRuntimeSafety(true);
            if (self.phase != .handshake) return error.WrongPhase;
            var derived = Secret.init(undefined);
            defer derived.deinit();
            expand(self.prefix, derived.exposeMut(), self.root.expose(), "derived", &emptyHash());
            self.root.deinit();
            self.root = .init(undefined);
            Labels.extract(Hash, self.root.exposeMut(), derived.expose(), &@as([Hash.digest_length]u8, @splat(0)));
            self.deriveTraffic(traffic, "c ap traffic", "s ap traffic", server_finished_hash);
            expand(self.prefix, self.exporter.exposeMut(), self.root.expose(), "exp master", server_finished_hash);
            self.phase = .application;
        }
        /// Called only after the handshake owner has accepted peer proof and
        /// transferred its local Finished output. This primitive supplies no auth.
        /// `client_finished_hash` covers the transcript through the client's Finished; the
        /// resumption master secret comes from it before the master secret is erased.
        pub fn complete(self: *Self, client_finished_hash: *const [length]u8) AdvanceError!void {
            @setRuntimeSafety(true);
            if (self.phase != .application) return error.WrongPhase;
            expand(self.prefix, self.resumption.exposeMut(), self.root.expose(), "res master", client_finished_hash);
            self.root.deinit();
            self.phase = .complete;
        }
        /// The PSK a NewSessionTicket with `nonce` carries (RFC 8446 section 4.6.1).
        pub fn ticketSecret(self: *const Self, nonce: []const u8, out: *[length]u8) ExportError!void {
            @setRuntimeSafety(true);
            if (self.phase != .complete) return error.WrongPhase;
            try Labels.expandWith(Hash, self.prefix, out, self.resumption.expose(), "resumption", nonce);
        }
        /// The PSK binder over `truncated_hash`, the transcript through the ClientHello up to its
        /// binders (RFC 8446 section 4.2.11.2), for a resumption PSK.
        pub fn binder(prefix: Labels.Prefix, psk: *const [length]u8, truncated_hash: *const [length]u8, out: *[length]u8) void {
            binderOf(prefix, .resumption, psk, truncated_hash, out);
        }
        pub fn binderOf(prefix: Labels.Prefix, kind: BinderKind, psk: *const [length]u8, truncated_hash: *const [length]u8, out: *[length]u8) void {
            @setRuntimeSafety(true);
            var early = Secret.init(undefined);
            defer early.deinit();
            var key = Secret.init(undefined);
            defer key.deinit();
            const zero: [length]u8 = @splat(0);
            Labels.extract(Hash, early.exposeMut(), &zero, psk);
            expand(prefix, key.exposeMut(), early.expose(), if (kind == .external) "ext binder" else "res binder", &emptyHash());
            Labels.finished(Hash, prefix, out, key.expose(), truncated_hash);
        }
        pub const BinderError = error{BadBinder};
        /// Checks a received binder in constant time; only the verdict is released.
        pub fn checkBinder(prefix: Labels.Prefix, psk: *const [length]u8, truncated_hash: *const [length]u8, received: []const u8) BinderError!void {
            return checkBinderOf(prefix, .resumption, psk, truncated_hash, received);
        }
        pub fn checkBinderOf(prefix: Labels.Prefix, kind: BinderKind, psk: *const [length]u8, truncated_hash: *const [length]u8, received: []const u8) BinderError!void {
            @setRuntimeSafety(true);
            if (received.len != length) return error.BadBinder;
            var expected = Secret.init(undefined);
            defer expected.deinit();
            binderOf(prefix, kind, psk, truncated_hash, expected.exposeMut());
            if (!aegis.secret.equal(length, expected.expose(), received[0..length]).declassify("a bad binder ends the handshake")) return error.BadBinder;
        }
        pub fn exportBytes(self: *const Self, out: []u8, label: []const u8, context: []const u8) ExportError!void {
            @setRuntimeSafety(true);
            if (self.phase != .complete) return error.WrongPhase;
            if (label.len > 249 or context.len > 65535 or out.len > 255 * Hash.digest_length) return error.InvalidLabel;
            var derived = Secret.init(undefined);
            defer derived.deinit();
            expand(self.prefix, derived.exposeMut(), self.exporter.expose(), label, &emptyHash());
            var context_hash: [Hash.digest_length]u8 = undefined;
            Hash.hash(context, &context_hash, .{});
            try Labels.expandWith(Hash, self.prefix, out, derived.expose(), "exporter", &context_hash);
        }
        pub fn deinit(self: *Self) void {
            if (self.phase != .complete and self.phase != .erased) self.root.deinit();
            self.exporter.deinit();
            self.resumption.deinit();
            self.phase = .erased;
        }
        fn deriveTraffic(self: *const Self, out: *Traffic, client: []const u8, server: []const u8, hash: *const [Hash.digest_length]u8) void {
            out.client.deinit();
            out.server.deinit();
            out.client = .init(undefined);
            out.server = .init(undefined);
            expand(self.prefix, out.client.exposeMut(), self.root.expose(), client, hash);
            expand(self.prefix, out.server.exposeMut(), self.root.expose(), server, hash);
        }
        fn emptyHash() [Hash.digest_length]u8 {
            var hash: [Hash.digest_length]u8 = undefined;
            Hash.hash("", &hash, .{});
            return hash;
        }
        fn expand(prefix: Labels.Prefix, out: []u8, secret: *const [Hash.digest_length]u8, label: []const u8, context: []const u8) void {
            // unreachable: internal labels are <=249 bytes, contexts and outputs are hash-sized.
            Labels.expandWith(Hash, prefix, out, secret, label, context) catch unreachable;
        }
    };
}
test {
    _ = @import("Schedule_test.zig");
}
