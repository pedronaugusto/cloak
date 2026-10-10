//! One handshake key-schedule owner. Traffic holders transfer to the transport.
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
pub const InitError = error{InvalidSharedSecret};
pub const AdvanceError = error{WrongPhase};
pub const ExportError = AdvanceError || Labels.ExpandError;
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
        root: Secret,
        exporter: Secret = .init(undefined),
        phase: enum { handshake, application, complete, erased } = .handshake,
        pub fn init(shared: []const u8, hello_hash: *const [Hash.digest_length]u8, traffic: *Traffic) InitError!Self {
            @setRuntimeSafety(true);
            if (shared.len != 32 and shared.len != 48 and shared.len != 64) return error.InvalidSharedSecret;
            var early = Secret.init(undefined);
            defer early.deinit();
            var derived = Secret.init(undefined);
            defer derived.deinit();
            const zero: [Hash.digest_length]u8 = @splat(0);
            Labels.extract(Hash, early.exposeMut(), &zero, &zero);
            expand(derived.exposeMut(), early.expose(), "derived", &emptyHash());
            var self: Self = .{ .root = .init(undefined) };
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
            expand(derived.exposeMut(), self.root.expose(), "derived", &emptyHash());
            self.root.deinit();
            self.root = .init(undefined);
            Labels.extract(Hash, self.root.exposeMut(), derived.expose(), &@as([Hash.digest_length]u8, @splat(0)));
            self.deriveTraffic(traffic, "c ap traffic", "s ap traffic", server_finished_hash);
            expand(self.exporter.exposeMut(), self.root.expose(), "exp master", server_finished_hash);
            self.phase = .application;
        }
        /// Called only after the handshake owner has accepted peer proof and
        /// transferred its local Finished output. This primitive supplies no auth.
        pub fn complete(self: *Self) AdvanceError!void {
            if (self.phase != .application) return error.WrongPhase;
            self.root.deinit();
            self.phase = .complete;
        }
        pub fn exportBytes(self: *const Self, out: []u8, label: []const u8, context: []const u8) ExportError!void {
            @setRuntimeSafety(true);
            if (self.phase != .complete) return error.WrongPhase;
            if (label.len == 0 or label.len > 249 or context.len > 65535 or out.len > 255 * Hash.digest_length) return error.InvalidLabel;
            var derived = Secret.init(undefined);
            defer derived.deinit();
            expand(derived.exposeMut(), self.exporter.expose(), label, &emptyHash());
            var context_hash: [Hash.digest_length]u8 = undefined;
            Hash.hash(context, &context_hash, .{});
            try Labels.expand(Hash, out, derived.expose(), "exporter", &context_hash);
        }
        pub fn deinit(self: *Self) void {
            if (self.phase != .complete and self.phase != .erased) self.root.deinit();
            self.exporter.deinit();
            self.phase = .erased;
        }
        fn deriveTraffic(self: *const Self, out: *Traffic, client: []const u8, server: []const u8, hash: *const [Hash.digest_length]u8) void {
            out.client.deinit();
            out.server.deinit();
            out.client = .init(undefined);
            out.server = .init(undefined);
            expand(out.client.exposeMut(), self.root.expose(), client, hash);
            expand(out.server.exposeMut(), self.root.expose(), server, hash);
        }
        fn emptyHash() [Hash.digest_length]u8 {
            var hash: [Hash.digest_length]u8 = undefined;
            Hash.hash("", &hash, .{});
            return hash;
        }
        fn expand(out: []u8, secret: *const [Hash.digest_length]u8, label: []const u8, context: []const u8) void {
            // unreachable: internal labels are nonempty, <=249 bytes, contexts and outputs are hash-sized.
            Labels.expand(Hash, out, secret, label, context) catch unreachable;
        }
    };
}
test {
    _ = @import("Schedule_test.zig");
}
