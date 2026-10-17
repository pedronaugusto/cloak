//! Client key shares: one owner per offered group's private half, its wire form and agreement.
//! Entropy is an explicit input; nothing here reads a generator or a clock.
const std = @import("std");
const aegis = @import("aegis");
const ecdh = @import("../../credentials/Ecdh.zig");
const Group = @import("Group.zig").Group;

const X25519 = std.crypto.dh.X25519;
const MlKem = std.crypto.kem.ml_kem.MLKem768;
const MlKem1024 = std.crypto.kem.ml_kem.MLKem1024;

/// Largest agreed secret: P-384's then ML-KEM-1024's.
pub const max_secret = ecdh.P384.scalar_length + MlKem1024.shared_length;
/// Largest key_share entry, either side.
pub const max_share = Group.secp384r1_mlkem1024.clientShareLength().?;

/// The NIST-curve hybrids (draft-ietf-tls-ecdhe-mlkem): the ECDH value then the ML-KEM one, on
/// the wire and in the secret, the reverse of X25519MLKEM768's order.
fn NistHybrid(comptime G: type, comptime K: type) type {
    return struct {
        pub const Curve = G;
        pub const Kem = K;
        pub const entropy = G.scalar_length + K.seed_length;
        pub const respond_entropy = G.scalar_length + K.encaps_seed_length;
        pub const client_length = G.public_length + K.PublicKey.encoded_length;
        pub const server_length = G.public_length + K.ciphertext_length;
        pub const secret_length = G.scalar_length + K.shared_length;
        /// ML-KEM-1024's expanded secret key would make every share (and the handshake's two)
        /// several kilobytes larger, so that hybrid keeps the key's seed and expands it again to
        /// decapsulate; ML-KEM-768's key is no larger than X25519MLKEM768's, and is kept.
        pub const keeps_seed = K.SecretKey != MlKem.SecretKey;
        pub const KemSecret = if (keeps_seed) [K.seed_length]u8 else K.SecretKey;
        pub const Private = struct { kem: aegis.Secret(KemSecret), ec: aegis.Secret([G.scalar_length]u8) };
    };
}
const P256MlKem768 = NistHybrid(ecdh.P256, MlKem);
const P384MlKem1024 = NistHybrid(ecdh.P384, MlKem1024);

/// Pure ML-KEM (draft-ietf-tls-mlkem): the encapsulation key from the client, the ciphertext from
/// the server, and the ML-KEM secret alone. The client keeps what the matching hybrid keeps: the
/// expanded ML-KEM-768 key, the ML-KEM-1024 seed.
fn Pure(comptime K: type) type {
    return struct {
        pub const Kem = K;
        pub const keeps_seed = K.SecretKey != MlKem.SecretKey;
        pub const Private = aegis.Secret(if (keeps_seed) [K.seed_length]u8 else K.SecretKey);
    };
}
const PureMlKem768 = Pure(MlKem);
const PureMlKem1024 = Pure(MlKem1024);

comptime {
    std.debug.assert(P256MlKem768.client_length == Group.secp256r1_mlkem768.clientShareLength().?);
    std.debug.assert(P256MlKem768.server_length == Group.secp256r1_mlkem768.serverShareLength().?);
    std.debug.assert(P384MlKem1024.client_length == Group.secp384r1_mlkem1024.clientShareLength().?);
    std.debug.assert(P384MlKem1024.server_length == Group.secp384r1_mlkem1024.serverShareLength().?);
    std.debug.assert(MlKem.PublicKey.encoded_length == Group.mlkem768.clientShareLength().?);
    std.debug.assert(MlKem.ciphertext_length == Group.mlkem768.serverShareLength().?);
    std.debug.assert(MlKem1024.PublicKey.encoded_length == Group.mlkem1024.clientShareLength().?);
    std.debug.assert(MlKem1024.ciphertext_length == Group.mlkem1024.serverShareLength().?);
}

pub const InitError = error{ InvalidEntropy, WeakKey };

/// The stack one group's kernels reach, which `aegis.secret.scrubbed` erases after each (and runs
/// them under data-independent timing). Each group is its own instance, so X25519 erases what
/// X25519 used, not what ML-KEM-1024 would; the ML-KEM key generations are the deepest. A test
/// holds every bound.
fn depth(comptime group: Group) usize {
    const debug = @import("builtin").mode == .debug;
    return switch (group) {
        .x25519 => if (debug) 64 * 1024 else 32 * 1024,
        .p256, .p384 => if (debug) 128 * 1024 else 64 * 1024,
        .x25519_mlkem768, .secp256r1_mlkem768, .mlkem768 => if (debug) 384 * 1024 else 144 * 1024,
        .secp384r1_mlkem1024, .mlkem1024 => if (debug) 480 * 1024 else 192 * 1024,
        _ => unsupported(),
    };
}
pub const AgreeError = error{ InvalidShare, WeakKey };

/// Fresh CSPRNG bytes `Share.init` needs for a group.
pub fn entropyLength(group: Group) usize {
    return switch (group) {
        .x25519 => X25519.seed_length,
        .p256 => ecdh.P256.scalar_length,
        .p384 => ecdh.P384.scalar_length,
        .x25519_mlkem768 => MlKem.seed_length + X25519.seed_length,
        .secp256r1_mlkem768 => P256MlKem768.entropy,
        .secp384r1_mlkem1024 => P384MlKem1024.entropy,
        .mlkem768 => MlKem.seed_length,
        .mlkem1024 => MlKem1024.seed_length,
        _ => unsupported(),
    };
}

/// Every group reaching an exchange is one cloak speaks: options are checked for it, and a peer's
/// choice is checked against what this end offered or listed.
fn unsupported() noreturn {
    aegis.assert.never("an exchange's group is one cloak speaks");
}

fn shareLength(length: ?usize) usize {
    return length orelse unsupported();
}

pub const Secret = aegis.Secret([max_secret]u8);

/// An agreed secret and its length.
pub const Agreed = struct {
    secret: Secret,
    len: usize,
    pub fn bytes(self: *const Agreed) []const u8 {
        return self.secret.expose()[0..self.len];
    }
    pub fn deinit(self: *Agreed) void {
        self.secret.deinit();
        self.* = undefined;
    }
};

const Private = union(enum) {
    x25519: aegis.Secret([X25519.secret_length]u8),
    p256: aegis.Secret([ecdh.P256.scalar_length]u8),
    p384: aegis.Secret([ecdh.P384.scalar_length]u8),
    x25519_mlkem768: struct {
        kem: aegis.Secret(MlKem.SecretKey),
        x25519: aegis.Secret([X25519.secret_length]u8),
    },
    secp256r1_mlkem768: P256MlKem768.Private,
    secp384r1_mlkem1024: P384MlKem1024.Private,
    mlkem768: PureMlKem768.Private,
    mlkem1024: PureMlKem1024.Private,
};

/// One offered key share. The private half never leaves; `deinit` erases it.
pub const Share = struct {
    group: Group,
    private: Private,
    public: [max_share]u8,

    /// `entropy` must hold exactly `entropyLength(group)` fresh bytes. A rejection
    /// (`InvalidEntropy`) is public: the draw fell outside the group's scalar range, and
    /// the driver supplies a new draw. The caller's entropy is not modified.
    pub fn init(group: Group, entropy: []const u8) InitError!Share {
        return switch (group) {
            inline .x25519, .p256, .p384, .x25519_mlkem768, .secp256r1_mlkem768, .secp384r1_mlkem1024, .mlkem768, .mlkem1024 => |g| aegis.secret.scrubbed(depth(g), initShare, .{ g, entropy }),
            _ => unsupported(),
        };
    }

    fn initShare(comptime group: Group, entropy: []const u8) InitError!Share {
        @setRuntimeSafety(true);
        if (entropy.len != entropyLength(group)) return error.InvalidEntropy;
        var self: Share = .{ .group = group, .private = undefined, .public = @splat(0) };
        switch (group) {
            .x25519 => {
                var key = X25519.KeyPair.generateDeterministic(entropy[0..X25519.seed_length].*);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
                self.private = .{ .x25519 = .init(key.secret_key) };
                self.public[0..32].* = key.public_key;
            },
            .p256 => try initCurve(ecdh.P256, &self, entropy),
            .p384 => try initCurve(ecdh.P384, &self, entropy),
            .x25519_mlkem768 => {
                var pair = MlKem.KeyPair.generateDeterministic(entropy[0..MlKem.seed_length].*) catch return error.InvalidEntropy;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
                var key = X25519.KeyPair.generateDeterministic(entropy[MlKem.seed_length..][0..X25519.seed_length].*);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
                self.private = .{ .x25519_mlkem768 = .{ .kem = .init(pair.secret_key), .x25519 = .init(key.secret_key) } };
                const ek = pair.public_key.toBytes();
                self.public[0..ek.len].* = ek;
                self.public[ek.len..][0..32].* = key.public_key;
            },
            .secp256r1_mlkem768 => try initNist(P256MlKem768, &self, entropy),
            .secp384r1_mlkem1024 => try initNist(P384MlKem1024, &self, entropy),
            .mlkem768 => self.private = .{ .mlkem768 = try initPure(PureMlKem768, &self, entropy) },
            .mlkem1024 => self.private = .{ .mlkem1024 = try initPure(PureMlKem1024, &self, entropy) },
            _ => unsupported(),
        }
        return self;
    }

    fn initPure(comptime P: type, self: *Share, entropy: []const u8) InitError!P.Private {
        @setRuntimeSafety(true);
        const seed = entropy[0..P.Kem.seed_length];
        var pair = P.Kem.KeyPair.generateDeterministic(seed.*) catch return error.InvalidEntropy;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        const ek = pair.public_key.toBytes();
        self.public[0..ek.len].* = ek;
        return .init(if (P.keeps_seed) seed.* else pair.secret_key);
    }

    fn initNist(comptime H: type, self: *Share, entropy: []const u8) InitError!void {
        @setRuntimeSafety(true);
        const scalar = entropy[0..H.Curve.scalar_length];
        H.Curve.publicKey(scalar, self.public[0..H.Curve.public_length]) catch return error.InvalidEntropy;
        const seed = entropy[H.Curve.scalar_length..][0..H.Kem.seed_length];
        var pair = H.Kem.KeyPair.generateDeterministic(seed.*) catch return error.InvalidEntropy;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        const ek = pair.public_key.toBytes();
        self.public[H.Curve.public_length..][0..ek.len].* = ek;
        const private: H.Private = .{ .kem = .init(if (H.keeps_seed) seed.* else pair.secret_key), .ec = .init(scalar.*) };
        self.private = if (H == P256MlKem768) .{ .secp256r1_mlkem768 = private } else .{ .secp384r1_mlkem1024 = private };
    }

    fn initCurve(comptime G: type, self: *Share, entropy: []const u8) InitError!void {
        @setRuntimeSafety(true);
        const scalar = entropy[0..G.scalar_length];
        G.publicKey(scalar, self.public[0..G.public_length]) catch return error.InvalidEntropy;
        self.private = if (G == ecdh.P256) .{ .p256 = .init(scalar.*) } else .{ .p384 = .init(scalar.*) };
    }

    /// The `key_exchange` bytes of the client's key_share entry.
    pub fn wire(self: *const Share) []const u8 {
        return self.public[0..shareLength(self.group.clientShareLength())];
    }

    /// Combines the private half with the server's `key_exchange` bytes.
    pub fn agree(self: *const Share, peer: []const u8) AgreeError!Agreed {
        if (peer.len != shareLength(self.group.serverShareLength())) return error.InvalidShare;
        return switch (self.private) {
            inline else => |*key, tag| aegis.secret.scrubbed(depth(@field(Group, @tagName(tag))), agreeShare, .{ tag, key, peer }),
        };
    }

    fn agreeShare(comptime tag: @typeInfo(Private).@"union".tag_type.?, key: *const @FieldType(Private, @tagName(tag)), peer: []const u8) AgreeError!Agreed {
        @setRuntimeSafety(true);
        var out: Agreed = .{ .secret = .init(@splat(0)), .len = 0 };
        errdefer out.deinit();
        const into = out.secret.exposeMut();
        switch (tag) {
            .x25519 => {
                out.len = try x25519(key, peer[0..32], into[0..32]);
            },
            .p256 => {
                ecdh.P256.agree(key.expose(), peer, into[0..ecdh.P256.scalar_length]) catch |err| return mapCurve(err);
                out.len = ecdh.P256.scalar_length;
            },
            .p384 => {
                ecdh.P384.agree(key.expose(), peer, into[0..ecdh.P384.scalar_length]) catch |err| return mapCurve(err);
                out.len = ecdh.P384.scalar_length;
            },
            .x25519_mlkem768 => {
                // ML-KEM decapsulation never signals an invalid ciphertext: FIPS 203 implicit
                // rejection returns a pseudorandom key, so validity is not an oracle.
                var kem = key.kem.expose().decaps(peer[0..MlKem.ciphertext_length]) catch return error.InvalidShare;
                defer std.crypto.secureZero(u8, &kem);
                into[0..kem.len].* = kem;
                _ = try x25519(&key.x25519, peer[MlKem.ciphertext_length..][0..32], into[kem.len..][0..32]);
                out.len = kem.len + 32;
            },
            .secp256r1_mlkem768 => out.len = try agreeNist(P256MlKem768, key, peer, into),
            .secp384r1_mlkem1024 => out.len = try agreeNist(P384MlKem1024, key, peer, into),
            .mlkem768 => out.len = try agreePure(PureMlKem768, key, peer, into),
            .mlkem1024 => out.len = try agreePure(PureMlKem1024, key, peer, into),
        }
        return out;
    }

    fn agreePure(comptime P: type, key: *const P.Private, peer: []const u8, into: *[max_secret]u8) AgreeError!usize {
        @setRuntimeSafety(true);
        // Implicit rejection: a damaged ciphertext yields an unrelated secret, never an error.
        var kem = try decaps(P.Kem, P.keeps_seed, key.expose(), peer[0..P.Kem.ciphertext_length]);
        defer std.crypto.secureZero(u8, &kem);
        into[0..kem.len].* = kem;
        return kem.len;
    }

    /// Decapsulates under a kept ML-KEM key, or under the key expanded again from its kept seed.
    fn decaps(comptime K: type, comptime from_seed: bool, key: anytype, ciphertext: *const [K.ciphertext_length]u8) AgreeError![K.shared_length]u8 {
        @setRuntimeSafety(true);
        if (from_seed) {
            var pair = K.KeyPair.generateDeterministic(key.*) catch return error.InvalidShare;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
            return pair.secret_key.decaps(ciphertext) catch error.InvalidShare;
        } else return key.decaps(ciphertext) catch error.InvalidShare;
    }

    fn agreeNist(comptime H: type, key: *const H.Private, peer: []const u8, into: *[max_secret]u8) AgreeError!usize {
        @setRuntimeSafety(true);
        const n = H.Curve.scalar_length;
        H.Curve.agree(key.ec.expose(), peer[0..H.Curve.public_length], into[0..n]) catch |err| return mapCurve(err);
        // Implicit rejection, as for X25519MLKEM768: no validity oracle from the ciphertext.
        const ciphertext = peer[H.Curve.public_length..][0..H.Kem.ciphertext_length];
        var kem = try decaps(H.Kem, H.keeps_seed, key.kem.expose(), ciphertext);
        defer std.crypto.secureZero(u8, &kem);
        into[n..][0..kem.len].* = kem;
        return n + kem.len;
    }

    fn x25519(key: *const aegis.Secret([32]u8), peer: *const [32]u8, out: *[32]u8) AgreeError!usize {
        @setRuntimeSafety(true);
        // scalarmult rejects the all-zero output of a low-order peer share.
        var shared = X25519.scalarmult(key.expose().*, peer.*) catch return error.WeakKey;
        defer std.crypto.secureZero(u8, &shared);
        out.* = shared;
        return shared.len;
    }

    fn mapCurve(err: ecdh.Error) AgreeError {
        return switch (err) {
            error.InvalidPublicKey => error.InvalidShare,
            error.InvalidScalar, error.IdentityElement => error.WeakKey,
        };
    }

    pub fn deinit(self: *Share) void {
        switch (self.private) {
            .x25519 => |*key| key.deinit(),
            .p256 => |*key| key.deinit(),
            .p384 => |*key| key.deinit(),
            .x25519_mlkem768 => |*key| {
                key.kem.deinit();
                key.x25519.deinit();
            },
            inline .secp256r1_mlkem768, .secp384r1_mlkem1024 => |*key| {
                key.kem.deinit();
                key.ec.deinit();
            },
            inline .mlkem768, .mlkem1024 => |*key| key.deinit(),
        }
        std.crypto.secureZero(u8, &self.public);
        self.* = undefined;
    }
};

/// Fresh CSPRNG bytes `respond` needs for a group.
pub fn respondEntropyLength(group: Group) usize {
    return switch (group) {
        .x25519 => X25519.seed_length,
        .p256 => ecdh.P256.scalar_length,
        .p384 => ecdh.P384.scalar_length,
        .x25519_mlkem768 => MlKem.encaps_seed_length + X25519.seed_length,
        .secp256r1_mlkem768 => P256MlKem768.respond_entropy,
        .secp384r1_mlkem1024 => P384MlKem1024.respond_entropy,
        .mlkem768 => MlKem.encaps_seed_length,
        .mlkem1024 => MlKem1024.encaps_seed_length,
        _ => unsupported(),
    };
}

/// The server's half of an exchange: the `key_exchange` bytes to send and the agreed secret.
pub const Response = struct {
    public: [max_share]u8,
    public_len: usize,
    agreed: Agreed,
    pub fn wire(self: *const Response) []const u8 {
        return self.public[0..self.public_len];
    }
    pub fn deinit(self: *Response) void {
        self.agreed.deinit();
        std.crypto.secureZero(u8, &self.public);
        self.* = undefined;
    }
};

/// Answers a client's key_share entry for `group`. `entropy` must hold exactly
/// `respondEntropyLength(group)` fresh bytes; `InvalidEntropy` (a scalar draw outside its range)
/// is public and the caller draws again. A malformed or small-order client share is `InvalidShare`
/// or `WeakKey`, never an agreed secret.
pub fn respond(group: Group, client_share: []const u8, entropy: []const u8) (InitError || AgreeError)!Response {
    return switch (group) {
        inline .x25519, .p256, .p384, .x25519_mlkem768, .secp256r1_mlkem768, .secp384r1_mlkem1024, .mlkem768, .mlkem1024 => |g| aegis.secret.scrubbed(depth(g), respondShare, .{ g, client_share, entropy }),
        _ => unsupported(),
    };
}

fn respondShare(comptime group: Group, client_share: []const u8, entropy: []const u8) (InitError || AgreeError)!Response {
    @setRuntimeSafety(true);
    if (entropy.len != respondEntropyLength(group)) return error.InvalidEntropy;
    if (client_share.len != shareLength(group.clientShareLength())) return error.InvalidShare;
    var out: Response = .{ .public = @splat(0), .public_len = shareLength(group.serverShareLength()), .agreed = .{ .secret = .init(@splat(0)), .len = 0 } };
    errdefer out.deinit();
    const into = out.agreed.secret.exposeMut();
    switch (group) {
        .x25519 => {
            var key = X25519.KeyPair.generateDeterministic(entropy[0..X25519.seed_length].*);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
            out.public[0..32].* = key.public_key;
            var shared = X25519.scalarmult(key.secret_key, client_share[0..32].*) catch return error.WeakKey;
            defer std.crypto.secureZero(u8, &shared);
            into[0..32].* = shared;
            out.agreed.len = 32;
        },
        .x25519_mlkem768 => {
            const ek = MlKem.PublicKey.fromBytes(client_share[0..MlKem.PublicKey.encoded_length]) catch return error.InvalidShare;
            var sealed = ek.encapsDeterministic(entropy[0..MlKem.encaps_seed_length]);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sealed));
            var key = X25519.KeyPair.generateDeterministic(entropy[MlKem.encaps_seed_length..][0..X25519.seed_length].*);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
            var shared = X25519.scalarmult(key.secret_key, client_share[MlKem.PublicKey.encoded_length..][0..32].*) catch return error.WeakKey;
            defer std.crypto.secureZero(u8, &shared);
            out.public[0..MlKem.ciphertext_length].* = sealed.ciphertext;
            out.public[MlKem.ciphertext_length..][0..32].* = key.public_key;
            into[0..32].* = sealed.shared_secret;
            into[32..64].* = shared;
            out.agreed.len = 64;
        },
        .p256 => try respondCurve(ecdh.P256, &out, client_share, entropy),
        .p384 => try respondCurve(ecdh.P384, &out, client_share, entropy),
        .secp256r1_mlkem768 => try respondNist(P256MlKem768, &out, client_share, entropy),
        .secp384r1_mlkem1024 => try respondNist(P384MlKem1024, &out, client_share, entropy),
        .mlkem768 => try respondPure(MlKem, &out, client_share, entropy),
        .mlkem1024 => try respondPure(MlKem1024, &out, client_share, entropy),
        _ => unsupported(),
    }
    return out;
}

/// Encapsulates to the client's key after FIPS 203's encapsulation key check (`fromBytes` refuses
/// a coefficient at or above q), so a malformed key is `InvalidShare`, never a secret.
fn respondPure(comptime K: type, out: *Response, client_share: []const u8, entropy: []const u8) AgreeError!void {
    @setRuntimeSafety(true);
    const ek = K.PublicKey.fromBytes(client_share[0..K.PublicKey.encoded_length]) catch return error.InvalidShare;
    var sealed = ek.encapsDeterministic(entropy[0..K.encaps_seed_length]);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&sealed));
    out.public[0..K.ciphertext_length].* = sealed.ciphertext;
    out.agreed.secret.exposeMut()[0..K.shared_length].* = sealed.shared_secret;
    out.agreed.len = K.shared_length;
}

fn respondNist(comptime H: type, out: *Response, client_share: []const u8, entropy: []const u8) (InitError || AgreeError)!void {
    @setRuntimeSafety(true);
    const n = H.Curve.scalar_length;
    var scalar: [n]u8 = entropy[0..n].*;
    defer std.crypto.secureZero(u8, &scalar);
    H.Curve.publicKey(&scalar, out.public[0..H.Curve.public_length]) catch return error.InvalidEntropy;
    const into = out.agreed.secret.exposeMut();
    H.Curve.agree(&scalar, client_share[0..H.Curve.public_length], into[0..n]) catch |err| return switch (err) {
        error.InvalidPublicKey => error.InvalidShare,
        error.InvalidScalar, error.IdentityElement => error.WeakKey,
    };
    const ek = H.Kem.PublicKey.fromBytes(client_share[H.Curve.public_length..][0..H.Kem.PublicKey.encoded_length]) catch return error.InvalidShare;
    var sealed = ek.encapsDeterministic(entropy[n..][0..H.Kem.encaps_seed_length]);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&sealed));
    out.public[H.Curve.public_length..][0..H.Kem.ciphertext_length].* = sealed.ciphertext;
    into[n..][0..H.Kem.shared_length].* = sealed.shared_secret;
    out.agreed.len = n + H.Kem.shared_length;
}

fn respondCurve(comptime G: type, out: *Response, client_share: []const u8, entropy: []const u8) (InitError || AgreeError)!void {
    @setRuntimeSafety(true);
    var scalar: [G.scalar_length]u8 = entropy[0..G.scalar_length].*;
    defer std.crypto.secureZero(u8, &scalar);
    G.publicKey(&scalar, out.public[0..G.public_length]) catch return error.InvalidEntropy;
    G.agree(&scalar, client_share, out.agreed.secret.exposeMut()[0..G.scalar_length]) catch |err| return switch (err) {
        error.InvalidPublicKey => error.InvalidShare,
        error.InvalidScalar, error.IdentityElement => error.WeakKey,
    };
    out.agreed.len = G.scalar_length;
}

test {
    _ = @import("Exchange_test.zig");
}

test "the exchange kernels reach less stack than the depth that erases them" {
    var entropy: [128]u8 = @splat(0x35);
    var respond_entropy: [128]u8 = @splat(0x36);
    inline for (comptime std.enums.values(Group)) |group| {
        const init_entropy = entropy[0..entropyLength(group)];
        const respond_with = respond_entropy[0..respondEntropyLength(group)];
        var share = try Share.initShare(group, init_entropy);
        defer share.deinit();
        var response = try respondShare(group, share.wire(), respond_with);
        defer response.deinit();
        const key = &@field(share.private, @tagName(group));
        const reach = [3]usize{
            aegis.secret.stackReach(4 * depth(group), Share.initShare, .{ group, init_entropy }),
            aegis.secret.stackReach(4 * depth(group), respondShare, .{ group, share.wire(), respond_with }),
            aegis.secret.stackReach(4 * depth(group), Share.agreeShare, .{ @field(@typeInfo(Private).@"union".tag_type.?, @tagName(group)), key, response.wire() }),
        };
        std.testing.expect(@max(reach[0], reach[1], reach[2]) < depth(group)) catch |err| {
            std.debug.print("{s}: init {d}, respond {d}, agree {d} of {d}\n", .{ @tagName(group), reach[0], reach[1], reach[2], depth(group) });
            return err;
        };
    }
}
