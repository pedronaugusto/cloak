//! A CMS signature (RFC 5652 SignedData) verified: its content, as a signer whose
//! certificate chains to the caller's roots signed it, at the time an RFC 3161 timestamp
//! proves or the caller gives. See docs/design.md "CMS".
//!
//! It fails closed, with no fallback: a digest that is not the content's, a chain or a
//! timestamp it cannot prove, or a signed attribute it must read and cannot. DER only; a BER
//! signature is refused. The roots are the caller's alone: nothing here reads a system store.
//!
//! One signer, the content embedded. Unsigned attributes are the signer's to add to and
//! anyone's to strip, so only the timestamp is read among them, and it proves itself: a
//! repository's countersignature (as NuGet adds) is left unread, and changes nothing here.
const std = @import("std");
const aegis = @import("aegis");
const Der = @import("wire/Der.zig");
const certificate = @import("certificate.zig");
const Algorithm = certificate.Algorithm;
const Certificate = certificate.Certificate;
const signatures = @import("verify/signature.zig");
const chains = @import("verify/Verifier.zig");
const T = @import("types.zig");
const Allocator = std.mem.Allocator;

pub const Options = struct {
    /// The DER certificates a signer must chain to.
    roots: []const []const u8,
    /// What the signer's certificate must allow.
    purpose: T.Purpose = .code_signing,
    /// What a timestamp's signer must chain to; null: `roots`.
    timestamp_roots: ?[]const []const u8 = null,
    /// The time the chain is checked at when the signature carries no timestamp. Null:
    /// a timestamp is required, and a signature without one is `error.TimestampRequired`.
    time: ?std.Io.Timestamp = null,
    /// How large a signature may be.
    max_bytes: aegis.units.Bytes(usize) = .literal("1MiB"),
};

/// What a signature proved. Slices are of the bytes given to `verify`.
pub const Verified = struct {
    /// The signed content (`encapContentInfo`'s).
    content: []const u8,
    /// The DER certificate of the signer.
    signer: []const u8,
    /// The time its chain was checked at.
    time: std.Io.Timestamp,
    /// Whether an RFC 3161 timestamp proved `time`, rather than the caller giving it.
    timestamped: bool,
};

pub const Error = chains.VerifyError || Der.Error || Algorithm.Error || signatures.Error || Allocator.Error || error{
    /// Not a SignedData of the shape RFC 5652 lays out.
    InvalidCms,
    /// A form this reader will not vouch for: several signers, detached content, a digest or
    /// `signingCertificate` it does not read.
    UnsupportedCms,
    /// A signed attribute named twice, or with other than one value (RFC 5652 11).
    InvalidAttributes,
    /// No certificate the signature carries is the signer it names.
    SignerNotFound,
    /// `messageDigest` is not the content's, or `contentType` not the content's type.
    DigestMismatch,
    /// `signingCertificateV2` does not name the signer's certificate (RFC 5035).
    SigningCertificateMismatch,
    /// The signature's algorithm is not of its digest, or the signature does not verify.
    SignatureMismatch,
    /// A timestamp that does not cover this signature, or is not a timestamp at all.
    InvalidTimestamp,
    TimestampRequired,
};

const signed_data_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
const content_type_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03";
const message_digest_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04";
const signing_certificate_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0c";
const signing_certificate_v2_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x2f";
const timestamp_token_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
const tst_info_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04";

/// The most certificates one signature may carry.
const max_certificates = 32;

const Parsed = struct {
    content: []const u8,
    content_type: []const u8,
    certificates: [max_certificates][]const u8 = undefined,
    certificate_count: usize = 0,
    signer: Signer,
};

const Signer = struct {
    /// Exactly one of them names the certificate.
    issuer: ?[]const u8 = null,
    serial: ?[]const u8 = null,
    key_id: ?[]const u8 = null,
    digest: Algorithm.Hash,
    /// The whole `[0]`, its tag rewritten for the signature.
    attributes: Der.Element,
    algorithm: []const u8,
    signature: []const u8,
    unsigned: ?Der.Element,
};

/// Verifies `bytes`, a DER ContentInfo holding a SignedData.
pub fn verify(gpa: Allocator, bytes: []const u8, options: Options) Error!Verified {
    if (aegis.units.Bytes(usize).fromRaw(bytes.len).compare(options.max_bytes) == .gt) return error.DerLimit;
    const parsed = try gpa.create(Parsed);
    defer gpa.destroy(parsed);
    parsed.* = try aegis.input.Untrusted([]const u8).init(bytes).parse({}, parseSignedData);
    const proved = try timeOf(gpa, parsed, options);
    const signer = try checkSigner(gpa, parsed);
    try checkChain(gpa, parsed, signer, options.purpose, proved.time, options.roots);
    return .{ .content = parsed.content, .signer = signer, .time = proved.time, .timestamped = proved.timestamped };
}

fn expectOid(r: *Der.Reader, wanted: []const u8) Error!void {
    if (!std.mem.eql(u8, (try r.expect(6)).value, wanted)) return error.InvalidCms;
}

fn parseSignedData(_: void, bytes: []const u8) Error!Parsed {
    var info = (try Der.single(bytes, 0x30)).reader();
    try expectOid(&info, signed_data_oid);
    var wrapper = (try info.expect(0xa0)).reader();
    try info.finish();
    var data = (try wrapper.expect(0x30)).reader();
    try wrapper.finish();
    _ = try Der.number((try data.expect(2)).value);
    _ = try data.expect(0x31); // Each signer names its own digest, which is the one used.
    var encapsulated = (try data.expect(0x30)).reader();
    const content_type = (try encapsulated.expect(6)).value;
    // A detached signature has no content here to prove.
    if (encapsulated.empty()) return error.UnsupportedCms;
    var explicit = (try encapsulated.expect(0xa0)).reader();
    try encapsulated.finish();
    const content = (try explicit.expect(0x04)).value;
    try explicit.finish();
    var out: Parsed = .{ .content = content, .content_type = content_type, .signer = undefined };
    if (data.peek() == @as(u8, 0xa0)) {
        var certificates = (try data.next()).reader();
        while (!certificates.empty()) {
            if (out.certificate_count == max_certificates) return error.DerLimit;
            // The other CertificateChoices are forms no signer here is named in.
            out.certificates[out.certificate_count] = (try certificates.expect(0x30)).encoded;
            out.certificate_count += 1;
        }
    }
    if (data.peek() == @as(u8, 0xa1)) _ = try data.next(); // Revocation is not checked here.
    var signers = (try data.expect(0x31)).reader();
    try data.finish();
    const one = try signers.expect(0x30);
    if (!signers.empty()) return error.UnsupportedCms;
    out.signer = try parseSigner(one);
    return out;
}

fn parseSigner(element: Der.Element) Error!Signer {
    var r = element.reader();
    _ = try Der.number((try r.expect(2)).value);
    var signer: Signer = .{ .digest = undefined, .attributes = undefined, .algorithm = undefined, .signature = undefined, .unsigned = null };
    const id = try r.next();
    switch (id.tag) {
        0x30 => {
            var named = id.reader();
            signer.issuer = (try named.expect(0x30)).encoded;
            signer.serial = (try named.expect(2)).value;
            try named.finish();
        },
        0x80 => signer.key_id = id.value,
        else => return error.InvalidCms,
    }
    signer.digest = try hashOf((try r.expect(0x30)));
    // Without signed attributes the signature is over the content directly, and nothing
    // says what the content is or which certificate was meant: not vouched for.
    if (r.peek() != @as(u8, 0xa0)) return error.UnsupportedCms;
    signer.attributes = try r.next();
    signer.algorithm = (try r.expect(0x30)).encoded;
    signer.signature = (try r.expect(0x04)).value;
    if (r.peek() == @as(u8, 0xa1)) signer.unsigned = try r.next();
    try r.finish();
    return signer;
}

/// The hash an AlgorithmIdentifier names, its parameters absent or NULL.
fn hashOf(element: Der.Element) Error!Algorithm.Hash {
    var r = element.reader();
    const id = (try r.expect(6)).value;
    if (!r.empty()) {
        const parameter = try r.next();
        if (parameter.tag != 5 or parameter.value.len != 0) return error.InvalidCms;
    }
    try r.finish();
    if (std.mem.eql(u8, id, "\x60\x86\x48\x01\x65\x03\x04\x02\x01")) return .sha256;
    if (std.mem.eql(u8, id, "\x60\x86\x48\x01\x65\x03\x04\x02\x02")) return .sha384;
    if (std.mem.eql(u8, id, "\x60\x86\x48\x01\x65\x03\x04\x02\x03")) return .sha512;
    return error.UnsupportedCms;
}

const max_digest = 64;

fn digest(hash: Algorithm.Hash, bytes: []const u8, out: *[max_digest]u8) []const u8 {
    switch (hash) {
        .sha256 => {
            std.crypto.hash.sha2.Sha256.hash(bytes, out[0..32], .{});
            return out[0..32];
        },
        .sha384 => {
            std.crypto.hash.sha2.Sha384.hash(bytes, out[0..48], .{});
            return out[0..48];
        },
        .sha512 => {
            std.crypto.hash.sha2.Sha512.hash(bytes, out[0..64], .{});
            return out[0..64];
        },
    }
}

/// The signer's certificate, among those the signature carries.
fn findSigner(parsed: *const Parsed) Error![]const u8 {
    const signer = &parsed.signer;
    for (parsed.certificates[0..parsed.certificate_count]) |der| {
        // glint-ignore: Z026 -- a carried certificate that does not parse is not the signer's: the next one is tried
        const cert = Certificate.parse(der, .{}) catch continue;
        if (signer.key_id) |wanted| {
            const extension = cert.x509(14) orelse continue;
            // glint-ignore: Z026 -- a certificate whose subject key identifier does not parse is not the one the signer names
            const key_id = Der.single(extension.value, 0x04) catch continue;
            if (std.mem.eql(u8, key_id.value, wanted)) return der;
        } else if (std.mem.eql(u8, cert.issuer, signer.issuer.?) and std.mem.eql(u8, cert.serial, signer.serial.?)) return der;
    }
    return error.SignerNotFound;
}

/// The value of an attribute: one, in its SET.
fn onlyValue(values: Der.Element) Error!Der.Element {
    var r = values.reader();
    const value = try r.next();
    if (!r.empty()) return error.InvalidAttributes;
    return value;
}

/// The signature checked, and everything it signs: the attributes it needs say this is the
/// content and this the signer. The signer's DER, of the bytes `verify` was given.
fn checkSigner(gpa: Allocator, parsed: *const Parsed) Error![]const u8 {
    const signer = &parsed.signer;
    const signer_der = try findSigner(parsed);
    const cert = try Certificate.parse(signer_der, .{});
    var content_type: ?Der.Element = null;
    var message_digest: ?Der.Element = null;
    var signing_certificate: ?Der.Element = null;
    var sha1_signing_certificate = false;
    var attributes = signer.attributes.reader();
    while (!attributes.empty()) {
        var attribute = (try attributes.expect(0x30)).reader();
        const id = (try attribute.expect(6)).value;
        const values = try attribute.expect(0x31);
        try attribute.finish();
        const slot: ?*?Der.Element = if (std.mem.eql(u8, id, content_type_oid))
            &content_type
        else if (std.mem.eql(u8, id, message_digest_oid))
            &message_digest
        else if (std.mem.eql(u8, id, signing_certificate_v2_oid))
            &signing_certificate
        else if (std.mem.eql(u8, id, signing_certificate_oid)) blk: {
            if (sha1_signing_certificate) return error.InvalidAttributes;
            sha1_signing_certificate = true;
            break :blk null;
        } else null;
        if (slot) |s| {
            if (s.* != null) return error.InvalidAttributes;
            s.* = try onlyValue(values);
        }
    }
    const named_type = content_type orelse return error.InvalidAttributes;
    if (named_type.tag != 6 or !std.mem.eql(u8, named_type.value, parsed.content_type)) return error.DigestMismatch;
    const named_digest = message_digest orelse return error.InvalidAttributes;
    if (named_digest.tag != 4) return error.InvalidAttributes;
    var computed: [max_digest]u8 = undefined;
    if (!std.mem.eql(u8, named_digest.value, digest(signer.digest, parsed.content, &computed))) return error.DigestMismatch;
    // RFC 5035's binding is read; SHA-1's (RFC 2634) only beside it, as timestamping
    // authorities write both: alone, it is not a binding to stand on.
    if (signing_certificate) |value| try checkSigningCertificate(value, signer_der) else if (sha1_signing_certificate) return error.UnsupportedCms;

    const algorithm = try signatureAlgorithm(signer);
    // What is signed is the attributes as a SET OF, not as the `[0]` they are written in
    // (RFC 5652 5.4): the one tag byte rewritten.
    const signed = try gpa.dupe(u8, signer.attributes.encoded);
    defer gpa.free(signed);
    signed[0] = 0x31;
    signatures.verify(cert.public_key, algorithm, signed, signer.signature) catch return error.SignatureMismatch;
    return signer_der;
}

/// RFC 5035's binding: the first ESSCertIDv2 names the signer's certificate by its hash.
fn checkSigningCertificate(value: Der.Element, signer: []const u8) Error!void {
    if (value.tag != 0x30) return error.InvalidAttributes;
    var outer = value.reader();
    var ids = (try outer.expect(0x30)).reader();
    var id = (try ids.expect(0x30)).reader();
    var hash: Algorithm.Hash = .sha256; // DEFAULT, RFC 5035 4.
    if (id.peek() == @as(u8, 0x30)) hash = try hashOf(try id.next());
    const named = (try id.expect(0x04)).value;
    var computed: [max_digest]u8 = undefined;
    if (!std.mem.eql(u8, named, digest(hash, signer, &computed))) return error.SigningCertificateMismatch;
}

/// The signature's algorithm, held to the signer's digest. `rsaEncryption` names no hash of
/// its own, as CMS allows: the digest's is the one.
fn signatureAlgorithm(signer: *const Signer) Error!Algorithm.Signature {
    var r = (try Der.single(signer.algorithm, 0x30)).reader();
    if (std.mem.eql(u8, (try r.expect(6)).value, Algorithm.rsa_oid)) return .{ .rsa = signer.digest };
    const algorithm = try Algorithm.signature(signer.algorithm);
    const named: ?Algorithm.Hash = switch (algorithm) {
        .rsa => |h| h,
        .ecdsa => |h| h,
        .pss => |p| p.hash,
        else => null,
    };
    if (named) |h| if (h != signer.digest) return error.SignatureMismatch;
    return algorithm;
}

const Proved = struct { time: std.Io.Timestamp, timestamped: bool };

/// The time the signer's chain is checked at: its timestamp's, proved, or the caller's when
/// it carries none. A timestamp that is there and cannot be proved fails: it is not ignored.
fn timeOf(gpa: Allocator, parsed: *const Parsed, options: Options) Error!Proved {
    var token: ?Der.Element = null;
    if (parsed.signer.unsigned) |unsigned| {
        var attributes = unsigned.reader();
        while (!attributes.empty()) {
            var attribute = (try attributes.expect(0x30)).reader();
            const id = (try attribute.expect(6)).value;
            const values = try attribute.expect(0x31);
            if (!std.mem.eql(u8, id, timestamp_token_oid)) continue;
            if (token != null) return error.InvalidTimestamp;
            token = try onlyValue(values);
        }
    }
    const held = token orelse return .{ .time = options.time orelse return error.TimestampRequired, .timestamped = false };
    return .{ .time = try checkTimestamp(gpa, held.encoded, parsed.signer.signature, options), .timestamped = true };
}

/// An RFC 3161 token over `covered`, a signer's signature: a SignedData of a TSTInfo, whose
/// own signer holds a timestamping certificate that chains at the time it states.
fn checkTimestamp(gpa: Allocator, token: []const u8, covered: []const u8, options: Options) Error!std.Io.Timestamp {
    const parsed = try gpa.create(Parsed);
    defer gpa.destroy(parsed);
    parsed.* = try aegis.input.Untrusted([]const u8).init(token).parse({}, parseSignedData);
    if (!std.mem.eql(u8, parsed.content_type, tst_info_oid)) return error.InvalidTimestamp;
    var info = (try Der.single(parsed.content, 0x30)).reader();
    _ = try Der.number((try info.expect(2)).value);
    _ = try info.expect(6); // The authority's policy, which it answers for.
    var imprint = (try info.expect(0x30)).reader();
    const hash = try hashOf(try imprint.expect(0x30));
    const named = (try imprint.expect(0x04)).value;
    try imprint.finish();
    var computed: [max_digest]u8 = undefined;
    if (!std.mem.eql(u8, named, digest(hash, covered, &computed))) return error.InvalidTimestamp;
    _ = try info.expect(2); // The serial number.
    const when = try info.expect(0x18);
    const seconds = Certificate.evidenceTime(when) catch return error.InvalidTimestamp;
    const time = T.instant(seconds);
    const signer = try checkSigner(gpa, parsed);
    try checkChain(gpa, parsed, signer, .time_stamping, time, options.timestamp_roots orelse options.roots);
    return time;
}

/// The signer's chain to `roots` at `time`, through the certificates the signature carries.
fn checkChain(gpa: Allocator, parsed: *const Parsed, signer: []const u8, purpose: T.Purpose, time: std.Io.Timestamp, roots: []const []const u8) Error!void {
    var chain: [max_certificates][]const u8 = undefined;
    chain[0] = signer;
    var n: usize = 1;
    for (parsed.certificates[0..parsed.certificate_count]) |der| {
        if (der.ptr == signer.ptr) continue;
        chain[n] = der;
        n += 1;
    }
    var receipt = try chains.verify(gpa, .{
        .chain = chain[0..n],
        .purpose = purpose,
        .time = time,
        .trust_generation = .fromRaw(1),
        .policy_generation = .fromRaw(1),
    }, roots);
    receipt.deinit();
}
