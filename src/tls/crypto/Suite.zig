//! The suites cloak speaks: the three TLS 1.3 suites and the six modern TLS 1.2 ECDHE suites
//! with AEAD ciphers. Availability is not policy permission.
const std = @import("std");

/// Protocol versions, by their wire number.
pub const Version = enum(u16) {
    tls12 = 0x0303,
    tls13 = 0x0304,
};

/// Every suite of either version, by its IANA number.
pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,

    /// The default offer and preference: TLS 1.3 first, AES-128-GCM first within each version.
    pub const default: []const Suite = &.{
        .aes_128_gcm_sha256,
        .chacha20_poly1305_sha256,
        .aes_256_gcm_sha384,
        .ecdhe_ecdsa_aes_128_gcm_sha256,
        .ecdhe_rsa_aes_128_gcm_sha256,
        .ecdhe_ecdsa_chacha20_poly1305_sha256,
        .ecdhe_rsa_chacha20_poly1305_sha256,
        .ecdhe_ecdsa_aes_256_gcm_sha384,
        .ecdhe_rsa_aes_256_gcm_sha384,
    };

    /// The TLS 1.3 suites alone, for QUIC and other TLS 1.3-only policies.
    pub const tls13_only: []const Suite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 };

    pub fn version(suite: Suite) Version {
        return if (suite.tls13() != null) .tls13 else .tls12;
    }

    pub fn tls13(suite: Suite) ?Suite13 {
        return std.enums.fromInt(Suite13, @backingInt(suite));
    }

    pub fn tls12(suite: Suite) ?Suite12 {
        return std.enums.fromInt(Suite12, @backingInt(suite));
    }

    pub fn from13(suite: Suite13) Suite {
        return @fromBackingInt(@backingInt(suite));
    }

    pub fn from12(suite: Suite12) Suite {
        return @fromBackingInt(@backingInt(suite));
    }
};

/// The TLS 1.3 suites.
pub const Suite13 = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};

/// The TLS 1.2 suites: ECDHE, an ECDSA (or EdDSA) or RSA certificate, an AEAD.
pub const Suite12 = enum(u16) {
    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,

    pub fn cipher(suite: Suite12) Cipher {
        return switch (suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_rsa_aes_128_gcm_sha256 => .aes_128_gcm,
            .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_rsa_aes_256_gcm_sha384 => .aes_256_gcm,
            .ecdhe_rsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_chacha20_poly1305_sha256 => .chacha20_poly1305,
        };
    }

    /// The PRF hash's digest length: 48 for the SHA-384 suites, 32 otherwise.
    pub fn digestLength(suite: Suite12) usize {
        return if (suite == .ecdhe_ecdsa_aes_256_gcm_sha384 or suite == .ecdhe_rsa_aes_256_gcm_sha384) 48 else 32;
    }

    /// The kind of certificate key the suite authenticates with. EdDSA keys use the ECDSA suites
    /// (RFC 8422 section 5.1).
    pub fn authentication(suite: Suite12) enum { ecdsa, rsa } {
        return switch (suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256 => .ecdsa,
            .ecdhe_rsa_aes_128_gcm_sha256, .ecdhe_rsa_aes_256_gcm_sha384, .ecdhe_rsa_chacha20_poly1305_sha256 => .rsa,
        };
    }
};

/// The record ciphers both versions use.
pub const Cipher = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    /// Bytes of the fixed IV a TLS 1.2 key block supplies: GCM keeps a four-byte salt and sends
    /// an eight-byte explicit nonce; ChaCha20-Poly1305 derives its whole nonce (RFC 7905).
    pub fn fixedIvLength12(cipher: Cipher) usize {
        return if (cipher == .chacha20_poly1305) 12 else 4;
    }

    /// Bytes of explicit nonce a TLS 1.2 record carries.
    pub fn explicitNonceLength12(cipher: Cipher) usize {
        return if (cipher == .chacha20_poly1305) 0 else 8;
    }
};

/// Digest length of the suite's hash, known at run time.
pub fn digestLength(suite: Suite13) usize {
    return if (suite == .aes_256_gcm_sha384) 48 else 32;
}

pub fn cipherOf(suite: Suite13) Cipher {
    return switch (suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm,
        .aes_256_gcm_sha384 => .aes_256_gcm,
        .chacha20_poly1305_sha256 => .chacha20_poly1305,
    };
}

pub fn AeadOf(comptime cipher: Cipher) type {
    comptime {
        if (std.options.side_channels_mitigations == .none)
            @compileError("cloak TLS requires std side-channel mitigations");
    }
    return switch (cipher) {
        .aes_128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm,
        .aes_256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm,
        .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    };
}

pub fn Aead(comptime suite: Suite13) type {
    return AeadOf(cipherOf(suite));
}

pub fn Hash(comptime suite: Suite13) type {
    return if (suite == .aes_256_gcm_sha384) std.crypto.hash.sha2.Sha384 else std.crypto.hash.sha2.Sha256;
}

/// The PRF hash of a TLS 1.2 suite.
pub fn Hash12(comptime suite: Suite12) type {
    return if (suite.digestLength() == 48) std.crypto.hash.sha2.Sha384 else std.crypto.hash.sha2.Sha256;
}

comptime {
    for (std.enums.values(Cipher)) |cipher| {
        std.debug.assert(AeadOf(cipher).tag_length == 16);
        std.debug.assert(AeadOf(cipher).nonce_length == 12);
    }
    for (std.enums.values(Suite)) |suite| std.debug.assert((suite.tls13() == null) != (suite.tls12() == null));
}
