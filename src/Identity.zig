//! Shared immutable identity: owned DER chain, encoded certificate list and key; or a raw
//! public key (RFC 7250) and its key, with no certificate at all.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("types.zig");
const certificate = @import("certificate.zig");
const PrivateKey = @import("PrivateKey.zig");
const Pem = @import("credentials/Pem.zig");
const Identity = @This();
/// Private: immutable material is wiped/released by the final owner.
state: Handle,
pub const Options = struct {
    chain_bytes: usize = 65536,
    certificates: usize = 16,
    generation: types.IdentityGeneration = .fromRaw(1),
    /// What `initPem` does with a block that is not a CERTIFICATE: `skip` reads a file that
    /// holds the key too, as OpenSSL's chain reader does.
    other_blocks: OtherBlocks = .refuse,

    pub const OtherBlocks = enum { refuse, skip };
};
pub const InitError = std.mem.Allocator.Error || certificate.ParseError || error{ IdentityLimit, EmptyChain, KeyMismatch };
pub const InitPemError = InitError || Pem.Error || error{NotCertificate};
const Handle = aegis.Shared(State, release);
const State = struct { gpa: std.mem.Allocator, chain: []const []const u8, storage: []u8, flight: []u8, key: ?PrivateKey, generation: types.IdentityGeneration, expires: types.RealSeconds, raw: ?[]const u8 = null, public_key: certificate.PublicKey, issuers: []const []const u8 = &.{} };
/// What an identity presents: certificates (X.509), or a raw public key (RFC 7250), which a
/// peer trusts by its pin and never as a certificate.
pub const Form = enum { x509, raw_public_key };
/// A chain and the key that signs for its leaf; the key is retained and must match the leaf.
pub fn init(gpa: std.mem.Allocator, certificates: []const []const u8, key: PrivateKey, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    return build(gpa, certificates, key, options);
}

/// `init` over a chain in PEM: the CERTIFICATE blocks, the leaf first, as the usual
/// `cert.pem` of a leaf and its intermediates lays them out. Another block is refused or
/// skipped as `options.other_blocks` says; text between blocks is skipped.
pub fn initPem(gpa: std.mem.Allocator, chain_pem: []const u8, key: PrivateKey, options: Options) InitPemError!Identity {
    @setRuntimeSafety(true);
    return buildPem(gpa, chain_pem, key, options);
}

/// `initExternal` over a chain in PEM, read as `initPem` reads it.
pub fn initExternalPem(gpa: std.mem.Allocator, chain_pem: []const u8, options: Options) InitPemError!Identity {
    @setRuntimeSafety(true);
    return buildPem(gpa, chain_pem, null, options);
}

fn buildPem(gpa: std.mem.Allocator, chain_pem: []const u8, key: ?PrivateKey, options: Options) InitPemError!Identity {
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
    const limit = (aegis.int.Checked(usize).init(options.chain_bytes / 3 * 4).add(4096) catch return error.IdentityLimit).raw();
    while (try reader.next(gpa, limit)) |block| {
        var owned = block;
        errdefer owned.deinit(gpa);
        if (!std.mem.eql(u8, owned.label, "CERTIFICATE")) switch (options.other_blocks) {
            .refuse => return error.NotCertificate,
            .skip => {
                owned.deinit(gpa);
                continue;
            },
        };
        if (blocks.items.len == options.certificates) return error.IdentityLimit;
        try blocks.append(gpa, owned);
        errdefer _ = blocks.pop();
        try ders.append(gpa, owned.der);
    }
    return build(gpa, ders.items, key, options);
}

/// A raw public key (RFC 7250, TLS 1.3 and 1.2): `spki`, a DER SubjectPublicKeyInfo, and the key that
/// signs for it, which must match. There is no certificate: no name, no issuer, no expiry; a
/// peer trusts the key by its pin (the SHA-256 of `spki`) and nothing else.
pub fn initRawKey(gpa: std.mem.Allocator, spki: []const u8, key: PrivateKey, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    return buildRaw(gpa, spki, key, options);
}

/// A raw public key whose private key is held elsewhere; see `initExternal`.
pub fn initRawKeyExternal(gpa: std.mem.Allocator, spki: []const u8, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    return buildRaw(gpa, spki, null, options);
}

fn buildRaw(gpa: std.mem.Allocator, spki: []const u8, key: ?PrivateKey, options: Options) InitError!Identity {
    @setRuntimeSafety(true);
    if (spki.len == 0) return error.EmptyChain;
    if (spki.len > options.chain_bytes or spki.len > 0xffffff) return error.IdentityLimit;
    const public_key = try certificate.parsePublicKey(spki);
    if (key) |owned| if (!owned.matchesKey(public_key)) return error.KeyMismatch;
    const storage = try gpa.dupe(u8, spki);
    errdefer gpa.free(storage);
    const flight = try gpa.alloc(u8, 3 + spki.len);
    errdefer gpa.free(flight);
    std.mem.writeInt(u24, flight[0..3], @intCast(spki.len), .big); // bounded to u24 above
    @memcpy(flight[3..], spki);
    const held = if (key) |owned| owned.retain() else null;
    errdefer if (held) |owned| owned.deinit();
    // The key parsed above borrows the caller's bytes: parse it again from the owned copy.
    return .{ .state = try .create(gpa, .{ .gpa = gpa, .chain = &.{}, .storage = storage, .flight = flight, .key = held, .generation = options.generation, .expires = .fromRaw(std.math.maxInt(i64)), .raw = storage, .public_key = certificate.parsePublicKey(storage) catch unreachable }) }; // unreachable: the same bytes parsed above
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
    // Each certificate's issuer Name, in the caller's bytes until the chain is copied.
    const names = try gpa.alloc([]const u8, certificates.len);
    errdefer gpa.free(names);
    var bytes: usize = 0;
    var expiry: i64 = std.math.maxInt(i64);
    for (certificates, names) |der, *issuer| {
        bytes = (aegis.int.Checked(usize).init(bytes).add(der.len) catch return error.IdentityLimit).raw();
        if (der.len > 0xffffff or bytes > options.chain_bytes) return error.IdentityLimit;
        const cert = try certificate.parse(der, .{});
        expiry = @min(expiry, cert.not_after);
        issuer.* = cert.issuer;
    }
    if (key) |owned| if (!owned.matches(certificates[0])) return error.KeyMismatch;
    const overhead = (aegis.int.Checked(usize).init(certificates.len).mul(3) catch return error.IdentityLimit).raw();
    const flight_size = (aegis.int.Checked(usize).init(bytes).add(overhead) catch return error.IdentityLimit).raw();
    if (flight_size > 0xffffff) return error.IdentityLimit;
    const owned = try gpa.alloc([]const u8, certificates.len);
    errdefer gpa.free(owned);
    const storage = try gpa.alloc(u8, bytes);
    errdefer gpa.free(storage);
    const flight = try gpa.alloc(u8, flight_size);
    errdefer gpa.free(flight);
    var at: usize = 0;
    var wire: usize = 0;
    for (certificates, owned, names) |der, *entry, *issuer| {
        @memcpy(storage[at..][0..der.len], der);
        entry.* = storage[at..][0..der.len];
        // The issuer moves with its certificate into the owned copy.
        issuer.* = entry.*[@intFromPtr(issuer.ptr) - @intFromPtr(der.ptr) ..][0..issuer.len]; // the issuer lies within its certificate's bytes
        at += der.len;
        std.mem.writeInt(u24, flight[wire..][0..3], @intCast(der.len), .big); // certificate length was checked against u24 above
        wire += 3;
        @memcpy(flight[wire..][0..der.len], der);
        wire += der.len;
    }
    // The leaf's key borrows the owned copy, not the caller's bytes.
    const public_key = (certificate.parse(owned[0], .{}) catch unreachable).public_key; // unreachable: the same bytes parsed above
    const held = if (key) |signer| signer.retain() else null;
    errdefer if (held) |signer| signer.deinit();
    return .{ .state = try .create(gpa, .{ .gpa = gpa, .chain = owned, .storage = storage, .flight = flight, .key = held, .generation = options.generation, .expires = .fromRaw(expiry), .public_key = public_key, .issuers = names }) };
}
pub fn retain(identity: Identity) Identity {
    return .{ .state = identity.state.retain() };
}
pub fn deinit(identity: Identity) void {
    var handle = identity.state;
    handle.release();
}
/// The last handle's cleanup.
fn release(state: *State) void {
    @setRuntimeSafety(true);
    const gpa = state.gpa;
    if (state.key) |key| key.deinit();
    gpa.free(state.chain);
    gpa.free(state.issuers);
    gpa.free(state.storage);
    gpa.free(state.flight);
}
/// The certificates, leaf first; empty for a raw public key.
pub fn chain(identity: Identity) []const []const u8 {
    @setRuntimeSafety(true);
    return identity.state.get().chain;
}
/// Each certificate's issuer Name (DER), in chain order; empty for a raw public key. What a
/// peer's certificate_authorities is matched against (RFC 8446 section 4.2.4).
pub fn issuers(identity: Identity) []const []const u8 {
    @setRuntimeSafety(true);
    return identity.state.get().issuers;
}
pub fn form(identity: Identity) Form {
    return if (identity.state.get().raw != null) .raw_public_key else .x509;
}
/// The raw public key's SubjectPublicKeyInfo; null for certificates.
pub fn rawKey(identity: Identity) ?[]const u8 {
    return identity.state.get().raw;
}
/// What a TLS Certificate message carries for this identity: the chain, or the one raw key.
pub fn entries(identity: Identity) []const []const u8 {
    @setRuntimeSafety(true);
    const state = identity.state.get();
    return if (state.raw) |*raw| raw[0..1] else state.chain;
}
/// The public key that signs for this identity: the leaf's, or the raw one. It borrows the
/// identity's storage.
pub fn publicKey(identity: Identity) certificate.PublicKey {
    return identity.state.get().public_key;
}
/// TLS CertificateList entries: three-byte DER length followed by DER.
/// Version-specific message headers and extensions remain handshake work.
pub fn certificateList(identity: Identity) []const u8 {
    @setRuntimeSafety(true);
    return identity.state.get().flight;
}
/// How many bytes of fresh noise one signature draws, or null when cloak does not sign for this
/// identity: its key is held elsewhere.
pub fn noiseLength(identity: Identity) ?usize {
    @setRuntimeSafety(true);
    const key = identity.state.get().key orelse return null;
    return key.noiseLength();
}
/// Signs `message` with the identity's key; see `PrivateKey.sign`.
pub fn sign(identity: Identity, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[PrivateKey.max_signature]u8) PrivateKey.SignError![]const u8 {
    @setRuntimeSafety(true);
    const key = identity.state.get().key orelse return error.UnsupportedAlgorithm;
    return key.sign(algorithm, message, noise, out);
}
/// Signs a digest with the key this identity holds; see `PrivateKey.signDigest`.
pub fn signDigest(identity: Identity, algorithm: certificate.Algorithm.Signature, digest: []const u8, noise: []const u8, out: *[PrivateKey.max_signature]u8) PrivateKey.SignDigestError![]const u8 {
    @setRuntimeSafety(true);
    const key = identity.state.get().key orelse return error.UnsupportedAlgorithm;
    return key.signDigest(algorithm, digest, noise, out);
}
pub fn generation(identity: Identity) types.IdentityGeneration {
    @setRuntimeSafety(true);
    return identity.state.get().generation;
}
/// The start of the last second every certificate in the chain is valid for; a raw public key
/// has no expiry of its own.
pub fn expires(identity: Identity) std.Io.Timestamp {
    @setRuntimeSafety(true);
    return types.instant(identity.state.get().expires.raw());
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Identity_test.zig");
}
