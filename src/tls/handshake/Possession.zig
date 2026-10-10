//! Key possession: CertificateVerify scheme restrictions and signature checks. The TLS
//! scheme is bound to the key's type and curve here, separately from certificate policy.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const Scheme = @import("Hello.zig").SignatureScheme;

const Algorithm = certificates.certificate.Algorithm;

pub const SignError = error{SigningFailed};
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

/// Signs `content` under `scheme` with an identity cloak holds the key of. `noise` is
/// `identity.noiseLength()` fresh bytes.
pub fn sign(identity: certificates.Identity, scheme: Scheme, content: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const leaf = certificates.certificate.parse(identity.chain()[0], .{}) catch return error.SigningFailed;
    const algorithm = bind(scheme, leaf.public_key) catch return error.SigningFailed;
    return identity.sign(algorithm, content, noise, out) catch error.SigningFailed;
}

/// The certificate-signature algorithm a scheme denotes, only for a key it may use.
pub fn bind(scheme: Scheme, key: Algorithm.PublicKey) Error!Algorithm.Signature {
    @setRuntimeSafety(true);
    return switch (scheme) {
        .rsa_pkcs1_sha256 => if (key == .rsa and !key.rsa.pss_only) .{ .rsa = .sha256 } else error.SchemeKeyMismatch,
        .rsa_pkcs1_sha384 => if (key == .rsa and !key.rsa.pss_only) .{ .rsa = .sha384 } else error.SchemeKeyMismatch,
        .rsa_pkcs1_sha512 => if (key == .rsa and !key.rsa.pss_only) .{ .rsa = .sha512 } else error.SchemeKeyMismatch,
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

// ---------------------------------------------------------------- TLS 1.2

/// TLS 1.2 binds an ECDSA scheme to its hash only, not to the key's curve (RFC 5246 section
/// 7.4.1.4.1); every other scheme binds as in TLS 1.3, and PKCS#1 v1.5 RSA is allowed.
pub fn bind12(scheme: Scheme, key: Algorithm.PublicKey) Error!Algorithm.Signature {
    @setRuntimeSafety(true);
    return switch (scheme) {
        .ecdsa_p256_sha256 => if (key == .ec) .{ .ecdsa = .sha256 } else error.SchemeKeyMismatch,
        .ecdsa_p384_sha384 => if (key == .ec) .{ .ecdsa = .sha384 } else error.SchemeKeyMismatch,
        else => bind(scheme, key),
    };
}

/// Bytes of the hash a TLS 1.2 CertificateVerify signs under `scheme`, among the transcript
/// hashes cloak keeps (SHA-256 and SHA-384); null for the rest.
pub fn transcriptHash12(scheme: Scheme) ?usize {
    return switch (scheme) {
        .ecdsa_p256_sha256, .rsa_pss_rsae_sha256, .rsa_pss_pss_sha256, .rsa_pkcs1_sha256 => 32,
        .ecdsa_p384_sha384, .rsa_pss_rsae_sha384, .rsa_pss_pss_sha384, .rsa_pkcs1_sha384 => 48,
        else => null,
    };
}

/// Checks a TLS 1.2 ServerKeyExchange signature over `content` (the randoms and parameters).
pub fn verifyMessage12(scheme_id: u16, offered: []const Scheme, leaf_der: []const u8, content: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme = std.enums.fromInt(Scheme, scheme_id) orelse return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    const cert = try certificates.certificate.parse(leaf_der, .{});
    const algorithm = try bind12(scheme, cert.public_key);
    certificates.signature.verify(cert.public_key, algorithm, content, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// Checks a TLS 1.2 CertificateVerify signature over a transcript `digest` of the scheme's hash.
pub fn verifyDigest12(scheme_id: u16, offered: []const Scheme, leaf_der: []const u8, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme = std.enums.fromInt(Scheme, scheme_id) orelse return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    if (transcriptHash12(scheme) != digest.len) return error.UnofferedScheme;
    const cert = try certificates.certificate.parse(leaf_der, .{});
    const algorithm = try bind12(scheme, cert.public_key);
    certificates.signature.verifyDigest(cert.public_key, algorithm, digest, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// Signs TLS 1.2 ServerKeyExchange content with a key cloak holds.
pub fn sign12(identity: certificates.Identity, scheme: Scheme, content: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const leaf = certificates.certificate.parse(identity.chain()[0], .{}) catch return error.SigningFailed;
    const algorithm = bind12(scheme, leaf.public_key) catch return error.SigningFailed;
    return identity.sign(algorithm, content, noise, out) catch error.SigningFailed;
}

/// Signs a TLS 1.2 CertificateVerify transcript digest with a key cloak holds.
pub fn signDigest12(identity: certificates.Identity, scheme: Scheme, digest: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const leaf = certificates.certificate.parse(identity.chain()[0], .{}) catch return error.SigningFailed;
    const algorithm = bind12(scheme, leaf.public_key) catch return error.SigningFailed;
    return identity.signDigest(algorithm, digest, noise, out) catch error.SigningFailed;
}

/// The ServerKeyExchange scheme for a leaf among those the client lists, in cloak's order: the
/// key's own curve hash first, then PSS, then PKCS#1 v1.5 for RSA.
pub fn chooseServer12(key: Algorithm.PublicKey, accepts: anytype) ?Scheme {
    @setRuntimeSafety(true);
    const order: []const Scheme = switch (key) {
        .ec => |ec| if (ec.curve == .p256) &.{ .ecdsa_p256_sha256, .ecdsa_p384_sha384 } else &.{ .ecdsa_p384_sha384, .ecdsa_p256_sha256 },
        .ed25519 => &.{.ed25519},
        .rsa => |rsa| if (rsa.pss_only) &.{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 } else &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 },
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme))) return scheme;
    return null;
}

/// The CertificateVerify scheme for a client leaf among those the server lists. It must hash
/// with SHA-256 or SHA-384, the transcript hashes cloak keeps; an Ed25519 key has none.
pub fn chooseClient12(key: Algorithm.PublicKey, accepts: anytype) ?Scheme {
    @setRuntimeSafety(true);
    const order: []const Scheme = switch (key) {
        .ec => |ec| if (ec.curve == .p256) &.{.ecdsa_p256_sha256} else &.{.ecdsa_p384_sha384},
        .ed25519 => &.{},
        .rsa => |rsa| if (rsa.pss_only) &.{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384 } else &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384 },
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme))) return scheme;
    return null;
}
test {
    _ = @import("Possession_test.zig");
}
