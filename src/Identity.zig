//! Shared immutable identity: owned DER chain, encoded certificate list and key.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("types.zig");
const certificate = @import("certificate.zig");
const PrivateKey = @import("PrivateKey.zig");
const Identity = @This();
/// Private: immutable material is wiped/released by the final owner.
state: *State,
pub const Options = struct { chain_bytes: usize = 65536, certificates: usize = 16, generation: types.IdentityGeneration = .fromRaw(1) };
pub const InitError = std.mem.Allocator.Error || certificate.ParseError || error{ IdentityLimit, EmptyChain, KeyMismatch };
const State = struct { gpa: std.mem.Allocator, refs: std.atomic.Value(usize) = .init(1), chain: []const []const u8, storage: []u8, flight: []u8, key: PrivateKey, generation: types.IdentityGeneration, expires: types.RealSeconds };
pub fn init(gpa: std.mem.Allocator, certificates: []const []const u8, key: PrivateKey, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    if (certificates.len == 0) return error.EmptyChain;
    if (certificates.len > options.certificates) return error.IdentityLimit;
    var bytes: usize = 0;
    var expiry: i64 = std.math.maxInt(i64);
    for (certificates) |der| {
        bytes = std.math.add(usize, bytes, der.len) catch return error.IdentityLimit;
        if (der.len > 0xffffff or bytes > options.chain_bytes) return error.IdentityLimit;
        const cert = try certificate.parse(der, .{});
        expiry = @min(expiry, cert.not_after);
    }
    if (!key.matches(certificates[0])) return error.KeyMismatch;
    const overhead = (aegis.int.Checked(usize).init(certificates.len).mul(3) catch return error.IdentityLimit).raw();
    const flight_size = (aegis.int.Checked(usize).init(bytes).add(overhead) catch return error.IdentityLimit).raw();
    if (flight_size > 0xffffff) return error.IdentityLimit;
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    const owned = try gpa.alloc([]const u8, certificates.len);
    errdefer gpa.free(owned);
    const storage = try gpa.alloc(u8, bytes);
    errdefer gpa.free(storage);
    const flight = try gpa.alloc(u8, flight_size);
    errdefer gpa.free(flight);
    var at: usize = 0;
    var wire: usize = 0;
    for (certificates, owned) |der, *entry| {
        @memcpy(storage[at..][0..der.len], der);
        entry.* = storage[at..][0..der.len];
        at += der.len;
        std.mem.writeInt(u24, flight[wire..][0..3], @intCast(der.len), .big); // safe: certificate length was checked against u24 above
        wire += 3;
        @memcpy(flight[wire..][0..der.len], der);
        wire += der.len;
    }
    state.* = .{ .gpa = gpa, .chain = owned, .storage = storage, .flight = flight, .key = key.retain(), .generation = options.generation, .expires = .fromRaw(expiry) };
    return .{ .state = state };
}
pub fn retain(identity: Identity) Identity {
    @setRuntimeSafety(true);
    var count = identity.state.refs.load(.monotonic);
    while (true) {
        if (count == 0 or count == std.math.maxInt(usize)) @panic("cloak retained owner exhausted");
        if (identity.state.refs.cmpxchgWeak(count, count + 1, .monotonic, .monotonic)) |actual| count = actual else break;
    }
    return identity;
}
pub fn deinit(identity: Identity) void {
    @setRuntimeSafety(true);
    if (identity.state.refs.fetchSub(1, .acq_rel) != 1) return;
    const state = identity.state;
    const gpa = state.gpa;
    state.key.deinit();
    gpa.free(state.chain);
    gpa.free(state.storage);
    gpa.free(state.flight);
    gpa.destroy(state);
}
pub fn chain(identity: Identity) []const []const u8 {
    @setRuntimeSafety(true);
    return identity.state.chain;
}
/// TLS CertificateList entries: three-byte DER length followed by DER.
/// Version-specific message headers and extensions remain handshake work.
pub fn certificateList(identity: Identity) []const u8 {
    @setRuntimeSafety(true);
    return identity.state.flight;
}
pub fn generation(identity: Identity) types.IdentityGeneration {
    @setRuntimeSafety(true);
    return identity.state.generation;
}
pub fn expires(identity: Identity) i64 {
    @setRuntimeSafety(true);
    return identity.state.expires.raw();
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Identity_test.zig");
}
