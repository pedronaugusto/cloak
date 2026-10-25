//! Public-key encryption to a parsed key: RSAES-OAEP (RFC 8017 7.1.1), the encoding
//! `crypto/pkcs1.zig`'s and the public operation std's, as signature verification takes it.
//! No private operation here: decryption is `PrivateKey.decrypt`'s.
const std = @import("std");
const A = @import("../certificate/Algorithm.zig");
const pkcs1 = @import("../crypto/pkcs1.zig");

pub const Error = error{
    /// Not an RSA key, or one restricted to RSASSA-PSS (a signing key).
    UnsupportedAlgorithm,
    /// Not a key RSA signatures would be verified under: 2048 to 4096 bits, an odd exponent of
    /// at least 3, no ROCA fingerprint.
    InvalidPublicKey,
    /// Longer than the key carries: `k - 2 * hLen - 2` bytes for a `k`-byte modulus.
    MessageTooLong,
    /// The seed is not `seedLength(scheme)` bytes.
    InvalidSeed,
};

/// The longest ciphertext: a 4096-bit modulus's length.
pub const max_ciphertext = pkcs1.max_em;

/// How many fresh bytes one encryption under `scheme` draws: OAEP's seed, its hash's length.
pub fn seedLength(scheme: A.Encryption) usize {
    return switch (scheme) {
        .oaep => |oaep| oaep.hash.length(),
    };
}

/// Encrypts `message` to `key` under `scheme`, `seed` exactly `seedLength(scheme)` fresh bytes.
/// Returns the ciphertext, as long as the modulus, in `out`.
pub fn encrypt(key: A.PublicKey, scheme: A.Encryption, message: []const u8, seed: []const u8, out: *[max_ciphertext]u8) Error![]const u8 {
    @setRuntimeSafety(true);
    const rsa = switch (key) {
        .rsa => |rsa| if (rsa.pss_only) return error.UnsupportedAlgorithm else rsa,
        else => return error.UnsupportedAlgorithm,
    };
    try A.checkRsa(rsa.modulus, rsa.exponent);
    const k = rsa.modulus.len;
    var em: [pkcs1.max_em]u8 = undefined;
    // The encoding holds the message: erased with it.
    defer std.crypto.secureZero(u8, em[0..k]);
    switch (scheme) {
        .oaep => |oaep| try pkcs1.encode(oaep, message, seed, em[0..k]),
    }
    const Modulus = std.crypto.ff.Modulus(4096);
    // unreachable: checkRsa held the modulus odd, 2048 to 4096 bits, and the exponent below it.
    const n = Modulus.fromBytes(rsa.modulus, .big) catch unreachable;
    // unreachable: EM's leading byte is zero, so it is below n.
    const m = Modulus.Fe.fromBytes(n, em[0..k], .big) catch unreachable;
    // unreachable: as above.
    const e = Modulus.Fe.fromBytes(n, rsa.exponent, .big) catch unreachable;
    // unreachable: a nonzero exponent, which checkRsa held.
    const c = n.powPublic(m, e) catch unreachable;
    // unreachable: c is below n, which is k bytes.
    c.toBytes(out[0..k], .big) catch unreachable;
    return out[0..k];
}
