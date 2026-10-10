//! Client key shares: one owner per offered group's private half, its wire form and agreement.
//! Entropy is an explicit input; nothing here reads a generator or a clock.
const std = @import("std");
const aegis = @import("aegis");
const ecdh = @import("cloak.certificates").ecdh;
const Group = @import("Group.zig").Group;

const X25519 = std.crypto.dh.X25519;
const MlKem = std.crypto.kem.ml_kem.MLKem768;

/// Largest agreed secret: ML-KEM-768 then X25519 for the hybrid group.
pub const max_secret = MlKem.shared_length + X25519.shared_length;
/// Largest client key_share entry.
pub const max_share = Group.x25519_mlkem768.clientShareLength();

pub const InitError = error{ InvalidEntropy, WeakKey };
pub const AgreeError = error{ InvalidShare, WeakKey };

/// Fresh CSPRNG bytes `Share.init` needs for a group.
pub fn entropyLength(group: Group) usize {
    return switch (group) {
        .x25519 => X25519.seed_length,
        .p256 => ecdh.P256.scalar_length,
        .p384 => ecdh.P384.scalar_length,
        .x25519_mlkem768 => MlKem.seed_length + X25519.seed_length,
    };
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

const Private = union(Group) {
    x25519: aegis.Secret([X25519.secret_length]u8),
    p256: aegis.Secret([ecdh.P256.scalar_length]u8),
    p384: aegis.Secret([ecdh.P384.scalar_length]u8),
    x25519_mlkem768: struct {
        kem: aegis.Secret(MlKem.SecretKey),
        x25519: aegis.Secret([X25519.secret_length]u8),
    },
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
        }
        return self;
    }

    fn initCurve(comptime G: type, self: *Share, entropy: []const u8) InitError!void {
        @setRuntimeSafety(true);
        const scalar = entropy[0..G.scalar_length];
        G.publicKey(scalar, self.public[0..G.public_length]) catch return error.InvalidEntropy;
        self.private = if (G == ecdh.P256) .{ .p256 = .init(scalar.*) } else .{ .p384 = .init(scalar.*) };
    }

    /// The `key_exchange` bytes of the client's key_share entry.
    pub fn wire(self: *const Share) []const u8 {
        return self.public[0..self.group.clientShareLength()];
    }

    /// Combines the private half with the server's `key_exchange` bytes.
    pub fn agree(self: *const Share, peer: []const u8) AgreeError!Agreed {
        @setRuntimeSafety(true);
        if (peer.len != self.group.serverShareLength()) return error.InvalidShare;
        var out: Agreed = .{ .secret = .init(@splat(0)), .len = 0 };
        errdefer out.deinit();
        const into = out.secret.exposeMut();
        switch (self.private) {
            .x25519 => |*key| {
                out.len = try x25519(key, peer[0..32], into[0..32]);
            },
            .p256 => |*key| {
                ecdh.P256.agree(key.expose(), peer, into[0..ecdh.P256.scalar_length]) catch |err| return mapCurve(err);
                out.len = ecdh.P256.scalar_length;
            },
            .p384 => |*key| {
                ecdh.P384.agree(key.expose(), peer, into[0..ecdh.P384.scalar_length]) catch |err| return mapCurve(err);
                out.len = ecdh.P384.scalar_length;
            },
            .x25519_mlkem768 => |*key| {
                // ML-KEM decapsulation never signals an invalid ciphertext: FIPS 203 implicit
                // rejection returns a pseudorandom key, so validity is not an oracle.
                var kem = key.kem.expose().decaps(peer[0..MlKem.ciphertext_length]) catch return error.InvalidShare;
                defer std.crypto.secureZero(u8, &kem);
                into[0..kem.len].* = kem;
                _ = try x25519(&key.x25519, peer[MlKem.ciphertext_length..][0..32], into[kem.len..][0..32]);
                out.len = kem.len + 32;
            },
        }
        return out;
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
        }
        std.crypto.secureZero(u8, &self.public);
        self.* = undefined;
    }
};

test {
    _ = @import("Exchange_test.zig");
}
