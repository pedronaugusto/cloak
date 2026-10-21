//! Key possession: CertificateVerify scheme restrictions and signature checks. The TLS
//! scheme is bound to the key's type and curve here, separately from certificate policy.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const aegis = @import("aegis");
const Scheme = @import("Hello.zig").SignatureScheme;

const Algorithm = certificates.certificate.Algorithm;

pub const SignError = error{SigningFailed};
pub const Error = error{ UnofferedScheme, SchemeKeyMismatch, BadSignature, UnsupportedKey } || certificates.certificate.ParseError;
/// A peer's key as its Certificate carries it: one entry where a raw key is expected, a key that
/// parses, and a pin that names it.
pub const KeyError = error{ IllegalParameter, InvalidCertificate, PinMismatch } || certificates.certificate.ParseError;

/// Checks `signature` over `content` under `scheme` with the public key of `leaf_der`.
/// `offered` is the schemes the local side advertised; TLS 1.3 forbids any other.
pub fn verify(scheme_id: u16, offered: []const Scheme, leaf_der: []const u8, content: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme: Scheme = @fromBackingInt(scheme_id);
    if (!scheme.supported()) return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    const cert = try certificates.certificate.parse(leaf_der, .{});
    return verifyKey(scheme_id, offered, cert.public_key, content, signature);
}

/// `verify` with the key itself: a raw public key (RFC 7250), or one an identity holds.
pub fn verifyKey(scheme_id: u16, offered: []const Scheme, key: Algorithm.PublicKey, content: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme: Scheme = @fromBackingInt(scheme_id);
    if (!scheme.supported()) return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    const algorithm = try bind(scheme, key);
    certificates.signature.verify(key, algorithm, content, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// Signs `content` under `scheme` with an identity cloak holds the key of. `noise` is
/// `identity.noiseLength()` fresh bytes.
pub fn sign(identity: certificates.Identity, scheme: Scheme, content: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const algorithm = bind(scheme, identity.publicKey()) catch return error.SigningFailed;
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
        .mldsa44 => mldsa(key, .mldsa44),
        .mldsa65 => mldsa(key, .mldsa65),
        .mldsa87 => mldsa(key, .mldsa87),
        .rsa_pss_rsae_sha256 => try pss(key, false, .sha256, 32),
        .rsa_pss_rsae_sha384 => try pss(key, false, .sha384, 48),
        .rsa_pss_rsae_sha512 => try pss(key, false, .sha512, 64),
        .rsa_pss_pss_sha256 => try pss(key, true, .sha256, 32),
        .rsa_pss_pss_sha384 => try pss(key, true, .sha384, 48),
        .rsa_pss_pss_sha512 => try pss(key, true, .sha512, 64),
        // Never offered, so never one a peer may use or a request may name.
        _ => error.UnofferedScheme,
    };
}

fn mldsa(key: Algorithm.PublicKey, level: Algorithm.MlDsa) Error!Algorithm.Signature {
    return if (key == .mldsa and key.mldsa.level == level) .{ .mldsa = level } else error.SchemeKeyMismatch;
}

/// The TLS scheme of an ML-DSA parameter set.
pub fn mldsaScheme(level: Algorithm.MlDsa) Scheme {
    return switch (level) {
        .mldsa44 => .mldsa44,
        .mldsa65 => .mldsa65,
        .mldsa87 => .mldsa87,
    };
}

fn pss(key: Algorithm.PublicKey, restricted: bool, hash: Algorithm.Hash, salt: usize) Error!Algorithm.Signature {
    @setRuntimeSafety(true);
    if (key != .rsa or key.rsa.pss_only != restricted) return error.SchemeKeyMismatch;
    // A key restricted to PSS parameters signs only with those: its hash and mask hash, and a
    // salt at least as long as the one it names (RFC 4055 section 3.1; RFC 8446 section 4.2.3).
    if (key.rsa.pss) |only| {
        if (only.hash != hash or only.mgf_hash != hash or salt < only.salt_length) return error.SchemeKeyMismatch;
    }
    return .{ .pss = .{ .hash = hash, .mgf_hash = hash, .salt_length = salt } };
}

/// Whether a verified leaf's key may sign the handshake: RFC 8446 section 4.4.2.2 (and TLS 1.2's
/// signing suites) ask digitalSignature when Key Usage is present. Checked on every verified chain,
/// since a caller's verifier may not (F152); a leaf that does not parse is that error.
pub fn signs(leaf_der: []const u8) certificates.certificate.ParseError!bool {
    @setRuntimeSafety(true);
    const cert = try certificates.certificate.parse(leaf_der, .{});
    const usage = cert.x509(0x0f) orelse return true;
    const mask = try certificates.certificate.Extensions.keyUsage(usage.value);
    return mask & 1 != 0;
}

/// Whether a verified path (leaf first, the trust anchor last) is signed with ML-DSA at every
/// link: each certificate but the anchor carries an ML-DSA signature. The anchor's own signature
/// authenticates nothing; the leaf's key is checked by its CertificateVerify scheme.
pub fn postQuantumPath(path: []const []const u8) bool {
    @setRuntimeSafety(true);
    if (path.len == 0) return false;
    for (path[0 .. path.len - 1]) |der| {
        const cert = certificates.certificate.parse(der, .{}) catch return false;
        if (cert.signature_algorithm != .mldsa) return false;
    }
    return true;
}

/// How a server's credential proves possession to a client: the scheme it signs under, and
/// whether its delegated credential's key signs (RFC 9345, TLS 1.3) rather than the certificate's.
pub const Fit = struct { scheme: Scheme, delegating: bool = false };

/// The scheme a client uses for a leaf, in preference order, among those the server lists.
pub fn choose(key: Algorithm.PublicKey, accepts: anytype) ?Scheme {
    @setRuntimeSafety(true);
    const order: []const Scheme = switch (key) {
        .ec => |ec| if (ec.curve == .p256) &.{.ecdsa_p256_sha256} else &.{.ecdsa_p384_sha384},
        .ed25519 => &.{.ed25519},
        .rsa => |rsa| if (rsa.pss_only) &.{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 } else &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        .mldsa => |m| switch (m.level) {
            inline else => |level| &.{comptime mldsaScheme(level)},
        },
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme)) and usable(bind, scheme, key)) return scheme;
    return null;
}

/// Whether `key` may sign under `scheme`: a PSS-restricted key rules out schemes its
/// parameters do not name.
fn usable(comptime binding: fn (Scheme, Algorithm.PublicKey) Error!Algorithm.Signature, scheme: Scheme, key: Algorithm.PublicKey) bool {
    _ = binding(scheme, key) catch return false;
    return true;
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

/// Checks a TLS 1.2 ServerKeyExchange signature over `content` (the randoms and parameters), or
/// an Ed25519 CertificateVerify over the messages, by the peer's key: its leaf's or its raw key.
pub fn verifyMessage12(scheme_id: u16, offered: []const Scheme, key: Algorithm.PublicKey, content: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme: Scheme = @fromBackingInt(scheme_id);
    if (!scheme.supported()) return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    const algorithm = try bind12(scheme, key);
    certificates.signature.verify(key, algorithm, content, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// Checks a TLS 1.2 CertificateVerify signature over a transcript `digest` of the scheme's hash.
pub fn verifyDigest12(scheme_id: u16, offered: []const Scheme, key: Algorithm.PublicKey, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scheme: Scheme = @fromBackingInt(scheme_id);
    if (!scheme.supported()) return error.UnofferedScheme;
    if (!std.mem.containsAtLeast(Scheme, offered, 1, &.{scheme})) return error.UnofferedScheme;
    if (transcriptHash12(scheme) != digest.len) return error.UnofferedScheme;
    const algorithm = try bind12(scheme, key);
    certificates.signature.verifyDigest(key, algorithm, digest, signature) catch |err| return switch (err) {
        error.InvalidSignature => error.BadSignature,
        error.UnsupportedAlgorithm, error.InvalidPublicKey => error.UnsupportedKey,
    };
}

/// Signs TLS 1.2 ServerKeyExchange content with a key cloak holds.
pub fn sign12(identity: certificates.Identity, scheme: Scheme, content: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const algorithm = bind12(scheme, identity.publicKey()) catch return error.SigningFailed;
    return identity.sign(algorithm, content, noise, out) catch error.SigningFailed;
}

/// Signs a TLS 1.2 CertificateVerify transcript digest with a key cloak holds.
pub fn signDigest12(identity: certificates.Identity, scheme: Scheme, digest: []const u8, noise: []const u8, out: *[certificates.PrivateKey.max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const algorithm = bind12(scheme, identity.publicKey()) catch return error.SigningFailed;
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
        // TLS 1.3's only.
        .mldsa => &.{},
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme)) and usable(bind12, scheme, key)) return scheme;
    return null;
}

/// The CertificateVerify scheme for a client leaf among those the server lists, in cloak's order
/// as `chooseServer12`. It must hash with SHA-256 or SHA-384, the transcript hashes cloak keeps;
/// an Ed25519 key has none.
pub fn chooseClient12(key: Algorithm.PublicKey, accepts: anytype) ?Scheme {
    @setRuntimeSafety(true);
    const order: []const Scheme = switch (key) {
        .ec => |ec| if (ec.curve == .p256) &.{ .ecdsa_p256_sha256, .ecdsa_p384_sha384 } else &.{ .ecdsa_p384_sha384, .ecdsa_p256_sha256 },
        .ed25519 => &.{.ed25519},
        .rsa => |rsa| if (rsa.pss_only) &.{ .rsa_pss_pss_sha256, .rsa_pss_pss_sha384 } else &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384 },
        .mldsa => &.{},
    };
    for (order) |scheme| if (accepts.accepts(@backingInt(scheme)) and usable(bind12, scheme, key)) return scheme;
    return null;
}
test {
    _ = @import("Possession_test.zig");
}

/// The index of the pin naming the one raw public key a Certificate carries; shared by both roles.
pub fn pinnedKey(entries: []const []const u8, pins: []const [32]u8) KeyError!u16 {
    @setRuntimeSafety(true);
    if (entries.len != 1) return error.IllegalParameter;
    _ = certificates.certificate.parsePublicKey(entries[0]) catch return error.InvalidCertificate;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entries[0], &hash, .{});
    for (pins, 0..) |*pin, i| {
        if (aegis.secret.equal(32, &hash, pin).declassify("which pinned key the peer holds is reported")) return @intCast(i); // safe: at most max_pins
    }
    return error.PinMismatch;
}

/// The index of the pin naming a leaf certificate's key (`Verify.leaf_key`): the SHA-256 of its
/// SubjectPublicKeyInfo; shared by both roles and versions.
pub fn pinnedLeaf(leaf: []const u8, pins: []const [32]u8) KeyError!u16 {
    @setRuntimeSafety(true);
    const cert = certificates.certificate.parse(leaf, .{}) catch return error.InvalidCertificate;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &hash, .{});
    for (pins, 0..) |*pin, i| {
        if (aegis.secret.equal(32, &hash, pin).declassify("which pinned key the peer holds is reported")) return @intCast(i); // safe: at most max_pins
    }
    return error.PinMismatch;
}

/// The key a peer's first Certificate entry carries: a leaf's, or a raw key's (RFC 7250).
pub fn peerKey(entry: []const u8, raw: bool) KeyError!certificates.certificate.PublicKey {
    @setRuntimeSafety(true);
    if (raw) return certificates.certificate.parsePublicKey(entry) catch error.InvalidCertificate;
    return (try certificates.certificate.parse(entry, .{})).public_key;
}
