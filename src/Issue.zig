//! Certificates and certification requests, written and signed: a `Template` through the
//! certificate layer's encoder, a key's signature, and before anything is returned, cloak's own
//! parser and a verification of the signature under the issuer's public key. See docs/design.md
//! "Issuing certificates".
const std = @import("std");
const certificate = @import("certificate.zig");
const Template = @import("certificate/Template.zig");
const Request = @import("certificate/Request.zig");
const Extensions = @import("certificate/Extensions.zig");
const Builder = @import("wire/Builder.zig");
const Der = @import("wire/Der.zig");
const signature = @import("verify/signature.zig");
const PrivateKey = @import("PrivateKey.zig");
const Algorithm = certificate.Algorithm;

pub const Issuer = struct {
    key: PrivateKey,
    /// The issuer's certificate, whose key `key` must be: its subject becomes the issuer Name and
    /// its key identifier the authority key identifier. Null when self-signed: the template's
    /// subject is the issuer and the subject key must be `key`'s.
    certificate: ?[]const u8 = null,
    /// The signature algorithm; null picks the key's (`defaultAlgorithm`).
    algorithm: ?Algorithm.Signature = null,
};

pub const Error = Template.Error || certificate.ParseError || error{ EntropyUnavailable, KeyMismatch, IssuerNotCa, UnsupportedAlgorithm, SigningFailed, InvalidSignature };

/// The signature a key makes by default: Ed25519; ECDSA with the curve's hash; RSA PKCS#1 v1.5
/// with SHA-256 (Go's); ML-DSA of its parameter set.
pub fn defaultAlgorithm(key: PrivateKey) Algorithm.Signature {
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    // unreachable: cloak encoded it.
    const public = certificate.parsePublicKey(key.publicKeyInfo(&buffer)) catch unreachable;
    return switch (public) {
        .rsa => .{ .rsa = .sha256 },
        .ec => |ec| .{ .ecdsa = switch (ec.curve) {
            .p256 => .sha256,
            .p384 => .sha384,
        } },
        .ed25519 => .ed25519,
        .mldsa => |m| .{ .mldsa = m.level },
    };
}

/// Writes and signs a certificate saying `template` about `subject_key` (a DER
/// SubjectPublicKeyInfo), issued by `issuer`. The DER is the caller's.
pub fn issue(gpa: std.mem.Allocator, io: std.Io, template: *const Template.Certificate, subject_key: []const u8, issuer: Issuer) Error![]u8 {
    @setRuntimeSafety(true);
    _ = try certificate.parsePublicKey(subject_key);
    var own_buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const own_key = issuer.key.publicKeyInfo(&own_buffer);
    // The issuer's Name, its public key's SPKI, and the key identifier the AKI carries.
    var issuer_name: []const u8 = undefined;
    var issuer_spki: []const u8 = own_key;
    var authority_id: ?[]const u8 = null;
    var computed_authority: [20]u8 = undefined;
    var name_builder = Builder.init(gpa);
    defer name_builder.deinit();
    if (issuer.certificate) |der| {
        const cert = try certificate.parse(der, .{});
        if (!issuer.key.matchesKey(cert.public_key)) return error.KeyMismatch;
        // A CA, with keyCertSign when it states key usage (RFC 5280 4.2.1.9, 4.2.1.3).
        const basic = cert.x509(19) orelse return error.IssuerNotCa;
        if (!(try Extensions.basic(basic.value)).ca) return error.IssuerNotCa;
        if (cert.x509(15)) |usage| if (try Extensions.keyUsage(usage.value) & (1 << 5) == 0) return error.IssuerNotCa;
        issuer_name = cert.subject;
        issuer_spki = cert.spki;
        if (cert.x509(14)) |ski| {
            authority_id = (try Der.single(ski.value, 0x04)).value;
        } else {
            computed_authority = Template.keyIdentifier(cert.spki) catch return error.InvalidPublicKey;
            authority_id = &computed_authority;
        }
    } else {
        if (!std.mem.eql(u8, subject_key, own_key)) {
            // The same key in another encoding is still the issuer's own.
            if (!issuer.key.matchesKey(try certificate.parsePublicKey(subject_key))) return error.KeyMismatch;
        }
        try Template.name(&name_builder, template.subject);
        issuer_name = name_builder.bytes.items;
    }
    const algorithm = issuer.algorithm orelse defaultAlgorithm(issuer.key);
    const algorithm_der = Template.signatureAlgorithm(algorithm) catch return error.UnsupportedAlgorithm;
    var subject_id_buffer: [20]u8 = undefined;
    const subject_id: ?[]const u8 = switch (template.subject_key_identifier) {
        .none => null,
        .bytes => |id| id,
        .always => blk: {
            subject_id_buffer = Template.keyIdentifier(subject_key) catch return error.InvalidPublicKey;
            break :blk &subject_id_buffer;
        },
        .auto => if (template.ca == null) null else blk: {
            subject_id_buffer = Template.keyIdentifier(subject_key) catch return error.InvalidPublicKey;
            break :blk &subject_id_buffer;
        },
    };
    var serial_buffer: [16]u8 = undefined;
    const serial = template.serial orelse blk: {
        io.randomSecure(&serial_buffer) catch return error.EntropyUnavailable;
        // Positive, and sixteen bytes long: the top bit clear, the next set.
        serial_buffer[0] = (serial_buffer[0] & 0x7f) | 0x40;
        break :blk &serial_buffer;
    };
    if (serial.len == 0 or serial.len > 20 or std.mem.allEqual(u8, serial, 0) or (serial.len == 20 and serial[0] & 0x80 != 0)) return error.InvalidSerial;
    var b = Builder.init(gpa);
    defer b.deinit();
    const outer = try b.open(0x30);
    const tbs_at = b.bytes.items.len;
    try Template.tbs(&b, template, serial, issuer_name, subject_key, algorithm_der, subject_id, if (issuer.certificate == null) null else authority_id);
    const tbs_end = b.bytes.items.len;
    try b.raw(algorithm_der);
    var signature_buffer: [PrivateKey.max_signature]u8 = undefined;
    // The signature is over the TBS, copied out: the builder may grow under it.
    const tbs = try gpa.dupe(u8, b.bytes.items[tbs_at..tbs_end]);
    defer gpa.free(tbs);
    const signed = try sign(io, issuer.key, algorithm, tbs, &signature_buffer);
    try b.bits(signed);
    try b.close(outer);
    const der = try b.toOwnedSlice();
    errdefer gpa.free(der);
    // What leaves is what cloak reads, signed by the issuer's key.
    const made = try certificate.parse(der, .{});
    signature.verify(try certificate.parsePublicKey(issuer_spki), made.signature_algorithm, made.tbs, made.signature) catch return error.SigningFailed;
    return der;
}

/// Writes and signs a PKCS#10 certification request for `key`'s public half saying `template`.
pub fn request(gpa: std.mem.Allocator, io: std.Io, template: *const Template.Request, key: PrivateKey, algorithm: ?Algorithm.Signature) Error![]u8 {
    @setRuntimeSafety(true);
    var spki_buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const spki = key.publicKeyInfo(&spki_buffer);
    const chosen = algorithm orelse defaultAlgorithm(key);
    const algorithm_der = Template.signatureAlgorithm(chosen) catch return error.UnsupportedAlgorithm;
    var b = Builder.init(gpa);
    defer b.deinit();
    const outer = try b.open(0x30);
    const info_at = b.bytes.items.len;
    try Template.requestInfo(&b, template, spki);
    const info = try gpa.dupe(u8, b.bytes.items[info_at..]);
    defer gpa.free(info);
    try b.raw(algorithm_der);
    var signature_buffer: [PrivateKey.max_signature]u8 = undefined;
    try b.bits(try sign(io, key, chosen, info, &signature_buffer));
    try b.close(outer);
    const der = try b.toOwnedSlice();
    errdefer gpa.free(der);
    const made = Request.parse(der, .{}) catch return error.SigningFailed;
    verifyRequest(&made) catch return error.SigningFailed;
    return der;
}

/// Whether `parsed` is signed by the key it carries: proof its requester holds that key.
pub fn verifyRequest(parsed: *const Request) signature.Error!void {
    return signature.verify(parsed.public_key, parsed.signature_algorithm, parsed.info, parsed.signature);
}

fn sign(io: std.Io, key: PrivateKey, algorithm: Algorithm.Signature, message: []const u8, out: *[PrivateKey.max_signature]u8) Error![]const u8 {
    @setRuntimeSafety(true);
    var noise: [PrivateKey.max_noise]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise);
    const length = key.noiseLength();
    io.randomSecure(noise[0..length]) catch return error.EntropyUnavailable;
    return key.sign(algorithm, message, noise[0..length], out) catch |err| switch (err) {
        error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
        else => error.SigningFailed,
    };
}

test {
    _ = @import("Issue_test.zig");
}
