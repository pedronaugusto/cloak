//! The suites cloak speaks: the TLS 1.3 suites and the modern TLS 1.2 ECDHE suites with AEAD
//! ciphers. The AES-CCM ones (RFC 8446, RFC 7251) are spoken only when listed: they are for
//! devices whose AES has no fast GHASH, and the default offer leaves them out. CCM_8, the 8-byte
//! tag the CoAP and LwM2M profiles require (RFC 7925), is TLS 1.2's only and spoken only when
//! listed; a datagram key under it ends its association after 2^7 records fail to open (RFC 9147
//! appendix B.3). Availability is not policy permission.
const std = @import("std");
const ccm = @import("Ccm.zig");

/// Protocol versions, by their wire number on a stream. DTLS shares them: DTLS 1.2 and 1.3 are
/// these versions carried in datagrams, with wire numbers of their own (`Transport.wire`).
pub const Version = enum(u16) {
    tls12 = 0x0303,
    tls13 = 0x0304,
};

/// What carries the handshake: TLS records on a stream, QUIC's levels, or DTLS records in
/// datagrams. A carrier sets it; it decides the wire versions and the label prefix.
pub const Transport = enum(u8) {
    stream,
    quic,
    datagram,

    /// The number a version has on this transport's wire (RFC 9147 section 5.3: DTLS 1.2 is
    /// 0xfefd, DTLS 1.3 0xfefc).
    pub fn wire(transport: Transport, version: Version) u16 {
        return switch (transport) {
            .stream, .quic => @backingInt(version),
            .datagram => switch (version) {
                .tls12 => 0xfefd,
                .tls13 => 0xfefc,
            },
        };
    }

    /// The legacy_version of a hello: TLS 1.2's or DTLS 1.2's number.
    pub fn legacy(transport: Transport) u16 {
        return transport.wire(.tls12);
    }

    /// The HKDF-Expand-Label prefix of TLS 1.3 on this transport.
    pub fn prefix(transport: Transport) @import("Labels.zig").Prefix {
        return if (transport == .datagram) .dtls13 else .tls13;
    }
};

/// A cipher suite of either version by its IANA number (TLS Cipher Suites). The type is open: any
/// number is a `Suite`, and a suite named later is no break; `supported` says whether cloak
/// speaks it.
pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    aes_128_ccm_sha256 = 0x1304,
    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,
    ecdhe_ecdsa_aes_128_ccm = 0xc0ac,
    ecdhe_ecdsa_aes_256_ccm = 0xc0ad,
    ecdhe_ecdsa_aes_128_ccm_8 = 0xc0ae,
    _,

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

    /// Whether cloak speaks this suite: one of the named ones.
    pub fn supported(suite: Suite) bool {
        return suite.version() != null;
    }

    /// The version the suite belongs to; null for one cloak does not speak.
    pub fn version(suite: Suite) ?Version {
        if (suite.tls13() != null) return .tls13;
        if (suite.tls12() != null) return .tls12;
        return null;
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
    aes_128_ccm_sha256 = 0x1304,
};

/// The TLS 1.2 suites: ECDHE, an ECDSA (or EdDSA) or RSA certificate, an AEAD.
pub const Suite12 = enum(u16) {
    ecdhe_ecdsa_aes_128_gcm_sha256 = 0xc02b,
    ecdhe_ecdsa_aes_256_gcm_sha384 = 0xc02c,
    ecdhe_rsa_aes_128_gcm_sha256 = 0xc02f,
    ecdhe_rsa_aes_256_gcm_sha384 = 0xc030,
    ecdhe_rsa_chacha20_poly1305_sha256 = 0xcca8,
    ecdhe_ecdsa_chacha20_poly1305_sha256 = 0xcca9,
    ecdhe_ecdsa_aes_128_ccm = 0xc0ac,
    ecdhe_ecdsa_aes_256_ccm = 0xc0ad,
    /// RFC 7251: CoAP's and LwM2M's mandatory suite for raw keys and certificates (RFC 7925).
    ecdhe_ecdsa_aes_128_ccm_8 = 0xc0ae,

    pub fn cipher(suite: Suite12) Cipher {
        return switch (suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_rsa_aes_128_gcm_sha256 => .aes_128_gcm,
            .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_rsa_aes_256_gcm_sha384 => .aes_256_gcm,
            .ecdhe_rsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_chacha20_poly1305_sha256 => .chacha20_poly1305,
            .ecdhe_ecdsa_aes_128_ccm => .aes_128_ccm,
            .ecdhe_ecdsa_aes_256_ccm => .aes_256_ccm,
            .ecdhe_ecdsa_aes_128_ccm_8 => .aes_128_ccm_8,
        };
    }

    /// The PRF hash's digest length: 48 for the SHA-384 suites, 32 otherwise (the CCM suites'
    /// PRF is SHA-256 at either key size, RFC 7251 section 2).
    pub fn digestLength(suite: Suite12) usize {
        return if (suite == .ecdhe_ecdsa_aes_256_gcm_sha384 or suite == .ecdhe_rsa_aes_256_gcm_sha384) 48 else 32;
    }

    /// The kind of certificate key the suite authenticates with. EdDSA keys use the ECDSA suites
    /// (RFC 8422 section 5.1).
    pub fn authentication(suite: Suite12) enum { ecdsa, rsa } {
        return switch (suite) {
            .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_aes_128_ccm, .ecdhe_ecdsa_aes_256_ccm, .ecdhe_ecdsa_aes_128_ccm_8 => .ecdsa,
            .ecdhe_rsa_aes_128_gcm_sha256, .ecdhe_rsa_aes_256_gcm_sha384, .ecdhe_rsa_chacha20_poly1305_sha256 => .rsa,
        };
    }
};

/// The record ciphers both versions use.
pub const Cipher = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    aes_128_ccm,
    aes_256_ccm,
    /// AEAD_AES_128_CCM_8: CCM with an 8-byte tag (RFC 6655), TLS 1.2's only.
    aes_128_ccm_8,

    /// The most records one key may protect: TLS's 2^24 below RFC 8446's GCM bound, and 2^23 for
    /// CCM, which keeps CCM's confidentiality margin at GCM's (RFC 9147 appendix B).
    pub fn recordLimit(cipher: Cipher) u64 {
        return switch (cipher) {
            .aes_128_ccm, .aes_256_ccm, .aes_128_ccm_8 => 1 << 23,
            else => 1 << 24,
        };
    }

    /// Bytes of the cipher's key.
    pub fn keyLength(cipher: Cipher) usize {
        return switch (cipher) {
            .aes_128_gcm, .aes_128_ccm, .aes_128_ccm_8 => 16,
            .aes_256_gcm, .aes_256_ccm, .chacha20_poly1305 => 32,
        };
    }

    /// Bytes of the authentication tag a record carries.
    pub fn tagLength(cipher: Cipher) usize {
        return if (cipher == .aes_128_ccm_8) 8 else 16;
    }

    /// Bytes of the fixed IV a TLS 1.2 key block supplies: GCM and CCM keep a four-byte salt and
    /// send an eight-byte explicit nonce (RFC 5288, RFC 6655); ChaCha20-Poly1305 derives its
    /// whole nonce (RFC 7905).
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
        .aes_128_ccm_sha256 => .aes_128_ccm,
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
        .aes_128_ccm => ccm.Aes128Ccm,
        .aes_256_ccm => ccm.Aes256Ccm,
        .aes_128_ccm_8 => ccm.Aes128Ccm8,
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
        std.debug.assert(AeadOf(cipher).tag_length == cipher.tagLength());
        std.debug.assert(AeadOf(cipher).key_length == cipher.keyLength());
        std.debug.assert(AeadOf(cipher).nonce_length == 12);
    }
    for (std.enums.values(Suite)) |suite| std.debug.assert((suite.tls13() == null) != (suite.tls12() == null));
    std.debug.assert(std.enums.values(Suite).len == std.enums.values(Suite13).len + std.enums.values(Suite12).len);
}
