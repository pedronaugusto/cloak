//! Key possession: CertificateVerify scheme restrictions and signature checks. The TLS
//! scheme is bound to the key's type and curve here, separately from certificate policy.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const Scheme = @import("Hello.zig").SignatureScheme;

const Algorithm = certificates.certificate.Algorithm;

pub const Error = error{ UnofferedScheme, SchemeKeyMismatch, BadSignature, UnsupportedKey } || certificates.certificate.ParseError;

/// Checks `signature` over `content` under `scheme` with the public key of `leaf_der`.
/// `offered` is the schemes the local side advertised; TLS 1.3 forbids any other.
pub fn verify(scheme_id: u16, offered: []const Scheme, leaf_der: []const u8, content: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme = std.enums.fromInt(Scheme, scheme_id) orelse return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    const cert = try certificates.certificate.parse(leaf_der, .{});
    const algorithm = try bind(scheme, cert.public_key);
    certificates.signature.verify(cert.public_key, algorithm, content, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// The certificate-signature algorithm a scheme denotes, only for a key it may use.
pub fn bind(scheme: Scheme, key: Algorithm.PublicKey) Error!Algorithm.Signature {
    @setRuntimeSafety(true);
    return switch (scheme) {
        .ecdsa_p256_sha256 => if (key == .ec and key.ec.curve == .p256) .{ .ecdsa = .sha256 } else error.SchemeKeyMismatch,
        .ecdsa_p384_sha384 => if (key == .ec and key.ec.curve == .p384) .{ .ecdsa = .sha384 } else error.SchemeKeyMismatch,
        .ed25519 => if (key == .ed25519) .ed25519 else error.SchemeKeyMismatch,
        .rsa_pss_rsae_sha256 => try pss(key, false, .sha256, 32),
        .rsa_pss_rsae_sha384 => try pss(key, false, .sha384, 48),
        .rsa_pss_rsae_sha512 => try pss(key, false, .sha512, 64),
        .rsa_pss_pss_sha256 => try pss(key, true, .sha256, 32),
        .rsa_pss_pss_sha384 => try pss(key, true, .sha384, 48),
        .rsa_pss_pss_sha512 => try pss(key, true, .sha512, 64),
    };
}

fn pss(key: Algorithm.PublicKey, restricted: bool, hash: Algorithm.Hash, salt: usize) Error!Algorithm.Signature {
    @setRuntimeSafety(true);
    if (key != .rsa or key.rsa.pss_only != restricted) return error.SchemeKeyMismatch;
    return .{ .pss = .{ .hash = hash, .mgf_hash = hash, .salt_length = salt } };
}

/// The scheme a client uses for a leaf, in preference order, among those the server lists.
pub fn choose(key: Algorithm.PublicKey, accepts: anytype) ?Scheme {
    @setRuntimeSafety(true);
    const order: []const Scheme = switch (key) {
        .ec => |ec| if (ec.curve == .p256) &.{.ecdsa_p256_sha256} else &.{.ecdsa_p384_sha384},
        .ed25519 => &.{.ed25519},
        .rsa => |rsa| if (rsa.pss_only) &.{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 } else &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme))) return scheme;
    return null;
}

test {
    _ = @import("Possession_test.zig");
}
