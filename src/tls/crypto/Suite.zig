//! Positive TLS 1.3 suite table; algorithm availability is not policy permission.
const std = @import("std");
pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};
/// Digest length of the suite's hash, known at run time.
pub fn digestLength(suite: Suite) usize {
    return if (suite == .aes_256_gcm_sha384) 48 else 32;
}
pub fn Aead(comptime suite: Suite) type {
    comptime {
        if (std.options.side_channels_mitigations == .none)
            @compileError("cloak TLS requires std side-channel mitigations");
    }
    return switch (suite) {
        .aes_128_gcm_sha256 => std.crypto.aead.aes_gcm.Aes128Gcm,
        .aes_256_gcm_sha384 => std.crypto.aead.aes_gcm.Aes256Gcm,
        .chacha20_poly1305_sha256 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    };
}
pub fn Hash(comptime suite: Suite) type {
    return if (suite == .aes_256_gcm_sha384) std.crypto.hash.sha2.Sha384 else std.crypto.hash.sha2.Sha256;
}
comptime {
    for (std.enums.values(Suite)) |suite| {
        std.debug.assert(Aead(suite).tag_length == 16);
        std.debug.assert(Aead(suite).nonce_length == 12);
    }
}
