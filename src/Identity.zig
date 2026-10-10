//! Shared immutable identity: owned DER chain, encoded certificate list and key.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("types.zig");
const certificate = @import("certificate.zig");
const PrivateKey = @import("PrivateKey.zig");
const Pem = @import("credentials/Pem.zig");
const Identity = @This();
/// Private: immutable material is wiped/released by the final owner.
state: *State,
pub const Options = struct { chain_bytes: usize = 65536, certificates: usize = 16, generation: types.IdentityGeneration = .fromRaw(1) };
pub const InitError = std.mem.Allocator.Error || certificate.ParseError || error{ IdentityLimit, EmptyChain, KeyMismatch };
pub const InitPemError = InitError || Pem.Error || error{NotCertificate};
const State = struct { gpa: std.mem.Allocator, refs: std.atomic.Value(usize) = .init(1), chain: []const []const u8, storage: []u8, flight: []u8, key: ?PrivateKey, generation: types.IdentityGeneration, expires: types.RealSeconds };
/// A chain and the key that signs for its leaf; the key is retained and must match the leaf.
pub fn init(gpa: std.mem.Allocator, certificates: []const []const u8, key: PrivateKey, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    return build(gpa, certificates, key, options);
}

/// `init` over a chain in PEM: every block is a CERTIFICATE, the leaf first, as the usual
/// `cert.pem` of a leaf and its intermediates lays them out.
pub fn initPem(gpa: std.mem.Allocator, chain_pem: []const u8, key: PrivateKey, options: Options) InitPemError!Identity {
    @setRuntimeSafety(true);
    var blocks: std.ArrayList(Pem.Block) = .empty;
    defer {
        for (blocks.items) |*block| block.deinit(gpa);
        blocks.deinit(gpa);
    }
    var ders: std.ArrayList([]const u8) = .empty;
    defer ders.deinit(gpa);
    var reader = Pem.init(chain_pem);
    // Armor is a third larger than the DER it carries, and its markers add a little.
    const limit = std.math.add(usize, options.chain_bytes / 3 * 4, 4096) catch return error.IdentityLimit;
    while (try reader.next(gpa, limit)) |block| {
        var owned = block;
        errdefer owned.deinit(gpa);
        if (!std.mem.eql(u8, owned.label, "CERTIFICATE")) return error.NotCertificate;
        if (blocks.items.len == options.certificates) return error.IdentityLimit;
        try blocks.append(gpa, owned);
        errdefer _ = blocks.pop();
        try ders.append(gpa, owned.der);
    }
    return init(gpa, ders.items, key, options);
}

/// A chain whose key is held elsewhere (a module, another process): cloak never signs for it,
/// and every handshake asks the caller for the signature through a `sign` request. The leaf
/// must still parse, since its public key fixes the signature schemes the peer can be offered.
pub fn initExternal(gpa: std.mem.Allocator, certificates: []const []const u8, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    return build(gpa, certificates, null, options);
}

fn build(gpa: std.mem.Allocator, certificates: []const []const u8, key: ?PrivateKey, options: Options) InitError!Identity {
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
    if (key) |owned| if (!owned.matches(certificates[0])) return error.KeyMismatch;
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
    state.* = .{ .gpa = gpa, .chain = owned, .storage = storage, .flight = flight, .key = if (key) |held| held.retain() else null, .generation = options.generation, .expires = .fromRaw(expiry) };
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
    if (state.key) |key| key.deinit();
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
/// How many bytes of fresh noise one signature draws, or null when cloak does not sign for this
/// identity (its key is held elsewhere, or is a kind cloak does not sign with yet).
pub fn noiseLength(identity: Identity) ?usize {
    @setRuntimeSafety(true);
    const key = identity.state.key orelse return null;
    return key.noiseLength();
}
/// Signs `message` with the identity's key; see `PrivateKey.sign`.
pub fn sign(identity: Identity, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[PrivateKey.max_signature]u8) PrivateKey.SignError![]const u8 {
    @setRuntimeSafety(true);
    const key = identity.state.key orelse return error.UnsupportedAlgorithm;
    return key.sign(algorithm, message, noise, out);
}
pub fn generation(identity: Identity) types.IdentityGeneration {
    @setRuntimeSafety(true);
    return identity.state.generation;
}
/// The start of the last second every certificate in the chain is valid for.
pub fn expires(identity: Identity) std.Io.Timestamp {
    @setRuntimeSafety(true);
    return types.instant(identity.state.expires.raw());
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Identity_test.zig");
}
