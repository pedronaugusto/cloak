//! Delegated credentials (RFC 9345): a short-lived key the holder of an end-entity certificate
//! signs for, so a TLS 1.3 endpoint proves possession with it instead of the certificate's key.
//! The format, the checks a receiver makes, and `Credential`, the owned credential an endpoint
//! presents with its certificate. One module serves both roles; only the signed label differs.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const Reader = @import("../../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Hello = @import("Hello.zig");
const Possession = @import("Possession.zig");

const Scheme = Hello.SignatureScheme;
const PublicKey = certificates.certificate.PublicKey;
const PrivateKey = certificates.PrivateKey;

/// The longest a receiver lets a credential still run (RFC 9345 section 4.1.3, its default).
pub const max_validity: i64 = 7 * 24 * 60 * 60;
/// DelegationUsage, 1.3.6.1.4.1.44363.44 (RFC 9345 section 4.2).
pub const delegation_usage = "\x2b\x06\x01\x04\x01\x82\xda\x4b\x2c";

/// Whose possession the credential proves: the label its signature binds.
pub const Role = enum {
    server,
    client,

    fn label(role: Role) []const u8 {
        return switch (role) {
            .server => "TLS, server delegated credentials",
            .client => "TLS, client delegated credentials",
        };
    }
};

/// The schemes a credential's key may use (dc_cert_verify_algorithm); Hello owns the tables.
pub const schemes = Hello.credential_schemes;
/// The credential schemes an extension lists under a policy.
pub const offered = Hello.credentialSchemes;

/// Whether a credential's key may use `scheme`.
pub fn allowed(scheme: Scheme) bool {
    return std.mem.containsAtLeast(Scheme, &schemes, 1, &.{scheme});
}

/// A DelegatedCredential's fields, borrowing its bytes.
pub const View = struct {
    /// Seconds after the delegating certificate's notBefore at which the credential expires.
    valid_time: u32,
    /// dc_cert_verify_algorithm: the scheme the credential's key signs CertificateVerify with.
    scheme: u16,
    /// The credential's SubjectPublicKeyInfo.
    spki: []const u8,
    /// The encoded Credential, which the delegation signs.
    credential: []const u8,
    /// The scheme the certificate's key signed the delegation with.
    algorithm: u16,
    signature: []const u8,
};

pub const ParseError = error{InvalidCredential};

/// Parses a DelegatedCredential exactly: every length within its parent, nothing after it.
pub fn parse(bytes: []const u8) ParseError!View {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = bytes };
    const valid_time = r.int(u32) catch return error.InvalidCredential;
    const scheme = r.int(u16) catch return error.InvalidCredential;
    const spki = (r.vector(u24) catch return error.InvalidCredential).bytes;
    const credential = bytes[0..r.pos];
    const algorithm = r.int(u16) catch return error.InvalidCredential;
    const signature = (r.vector(u16) catch return error.InvalidCredential).bytes;
    r.finish() catch return error.InvalidCredential;
    if (spki.len == 0 or signature.len == 0) return error.InvalidCredential;
    return .{ .valid_time = valid_time, .scheme = scheme, .spki = spki, .credential = credential, .algorithm = algorithm, .signature = signature };
}

/// Whether a certificate may delegate (RFC 9345 section 4.2): it carries DelegationUsage, NULL
/// and non-critical, and the digitalSignature key usage.
pub fn delegator(leaf: *const certificates.certificate.Certificate) bool {
    @setRuntimeSafety(true);
    const usage = leaf.extension(delegation_usage) orelse return false;
    if (usage.critical or !std.mem.eql(u8, usage.value, "\x05\x00")) return false;
    const key_usage = leaf.x509(0x0f) orelse return false;
    const mask = certificates.certificate.Extensions.keyUsage(key_usage.value) catch return false;
    return mask & 1 != 0;
}

/// The bytes a delegation signs: 64 spaces, the role's label, a zero, the certificate, the
/// Credential and the algorithm (RFC 9345 section 4). Allocated: the certificate is unbounded here.
pub fn signedContent(gpa: std.mem.Allocator, role: Role, leaf_der: []const u8, credential: []const u8, algorithm: u16) std.mem.Allocator.Error![]u8 {
    @setRuntimeSafety(true);
    const label = role.label();
    const out = try gpa.alloc(u8, 64 + label.len + 1 + leaf_der.len + credential.len + 2);
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..label.len], label);
    out[64 + label.len] = 0;
    var at = 65 + label.len;
    @memcpy(out[at..][0..leaf_der.len], leaf_der);
    at += leaf_der.len;
    @memcpy(out[at..][0..credential.len], credential);
    at += credential.len;
    std.mem.writeInt(u16, out[at..][0..2], algorithm, .big);
    return out;
}

/// When a credential of `leaf` expires, in seconds: notBefore plus valid_time.
pub fn expiry(leaf: *const certificates.certificate.Certificate, valid_time: u32) i64 {
    return leaf.not_before +| @as(i64, valid_time);
}

/// What a checked credential proves with.
pub const Checked = struct {
    key: PublicKey,
    scheme: Scheme,
    /// Seconds: the credential is not valid from here on.
    expires: i64,
};

pub const CheckError = std.mem.Allocator.Error || error{IllegalParameter};

/// The checks of RFC 9345 sections 4.1.1-4.1.3 a receiver makes once the certificate chain is
/// verified, but the one against the CertificateVerify scheme, which comes with that message: the
/// credential's scheme is one this end listed for credentials and may use, the delegation's one it
/// listed in signature_algorithms; the certificate may delegate; the credential has not expired,
/// runs at most `max_validity` past `now` and expires before the certificate does; and the
/// certificate's key signed it. Every failure is illegal_parameter.
pub fn check(gpa: std.mem.Allocator, view: View, leaf_der: []const u8, role: Role, now: i64, signature_schemes: []const Scheme, credential_schemes: []const Scheme) CheckError!Checked {
    @setRuntimeSafety(true);
    const scheme: Scheme = @fromBackingInt(view.scheme);
    if (!allowed(scheme) or !std.mem.containsAtLeast(Scheme, credential_schemes, 1, &.{scheme})) return error.IllegalParameter;
    const leaf = certificates.certificate.parse(leaf_der, .{}) catch return error.IllegalParameter;
    if (!delegator(&leaf)) return error.IllegalParameter;
    const expires = expiry(&leaf, view.valid_time);
    if (now >= expires or expires > now +| max_validity or expires >= leaf.not_after) return error.IllegalParameter;
    const key = certificates.certificate.parsePublicKey(view.spki) catch return error.IllegalParameter;
    _ = Possession.bind(scheme, key) catch return error.IllegalParameter;
    const content = try signedContent(gpa, role, leaf_der, view.credential, view.algorithm);
    defer gpa.free(content);
    Possession.verifyKey(view.algorithm, signature_schemes, leaf.public_key, content, view.signature) catch return error.IllegalParameter;
    return .{ .key = key, .scheme = scheme, .expires = expires };
}

/// Whether `list` (a SignatureSchemeList body, two bytes each) names `scheme`.
pub fn lists(list: []const u8, scheme: u16) bool {
    @setRuntimeSafety(true);
    var at: usize = 0;
    while (at + 2 <= list.len) : (at += 2) {
        if (std.mem.readInt(u16, list[at..][0..2], .big) == scheme) return true;
    }
    return false;
}

/// A delegated credential an endpoint presents, with the private key it proves possession with:
/// shared, immutable and reference counted, like the identity it belongs to. It is checked when
/// made against the certificate that signed it, so a credential that no peer could accept is
/// refused here rather than at every handshake.
pub const Credential = struct {
    state: *State,

    const State = struct {
        gpa: std.mem.Allocator,
        refs: std.atomic.Value(usize) = .init(1),
        bytes: []u8,
        view: View,
        key: PrivateKey,
        role: Role,
        /// The SHA-256 of the certificate that signed it.
        leaf: [32]u8,
        expires: i64,
    };

    pub const InitError = std.mem.Allocator.Error || ParseError || error{ NotDelegator, KeyMismatch, BadDelegation, UnsupportedScheme, OutlivesCertificate };

    /// Takes the credential's wire bytes (a DelegatedCredential) for `identity`'s certificate and
    /// the key its SubjectPublicKeyInfo names. The certificate must carry DelegationUsage and
    /// digitalSignature, the scheme must suit the key, the delegation must verify under the
    /// certificate's key, and the credential must expire before the certificate.
    pub fn init(gpa: std.mem.Allocator, identity: certificates.Identity, bytes: []const u8, key: PrivateKey, role: Role) InitError!Credential {
        @setRuntimeSafety(true);
        if (identity.form() != .x509) return error.NotDelegator;
        const leaf_der = identity.chain()[0];
        const leaf = certificates.certificate.parse(leaf_der, .{}) catch unreachable; // unreachable: the identity parsed it
        if (!delegator(&leaf)) return error.NotDelegator;
        const view = try parse(bytes);
        const scheme: Scheme = @fromBackingInt(view.scheme);
        if (!allowed(scheme)) return error.UnsupportedScheme;
        const public_key = certificates.certificate.parsePublicKey(view.spki) catch return error.UnsupportedScheme;
        _ = Possession.bind(scheme, public_key) catch return error.UnsupportedScheme;
        if (!key.matchesKey(public_key)) return error.KeyMismatch;
        const expires = expiry(&leaf, view.valid_time);
        if (expires >= leaf.not_after) return error.OutlivesCertificate;
        const content = try signedContent(gpa, role, leaf_der, view.credential, view.algorithm);
        defer gpa.free(content);
        Possession.verifyKey(view.algorithm, &Hello.schemes, leaf.public_key, content, view.signature) catch return error.BadDelegation;
        const state = try gpa.create(State);
        errdefer gpa.destroy(state);
        const owned = try gpa.dupe(u8, bytes);
        var leaf_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(leaf_der, &leaf_hash, .{});
        state.* = .{ .gpa = gpa, .bytes = owned, .view = parse(owned) catch unreachable, .key = key.retain(), .role = role, .leaf = leaf_hash, .expires = expires }; // unreachable: the same bytes parsed above
        return .{ .state = state };
    }

    pub fn retain(self: Credential) Credential {
        @setRuntimeSafety(true);
        var n = self.state.refs.load(.monotonic);
        while (true) {
            if (n == 0 or n == std.math.maxInt(usize)) @panic("cloak retained owner exhausted");
            if (self.state.refs.cmpxchgWeak(n, n + 1, .monotonic, .monotonic)) |actual| n = actual else break;
        }
        return self;
    }

    pub fn deinit(self: Credential) void {
        @setRuntimeSafety(true);
        if (self.state.refs.fetchSub(1, .acq_rel) != 1) return;
        const state = self.state;
        state.key.deinit();
        state.gpa.free(state.bytes);
        state.gpa.destroy(state);
    }

    /// The wire bytes, for the leaf's CertificateEntry.
    pub fn wire(self: Credential) []const u8 {
        return self.state.bytes;
    }

    /// The scheme its key signs CertificateVerify with.
    pub fn keyScheme(self: Credential) Scheme {
        return @fromBackingInt(self.state.view.scheme);
    }

    pub fn side(self: Credential) Role {
        return self.state.role;
    }

    /// When it expires: notBefore of its certificate plus its valid_time.
    pub fn expiresAt(self: Credential) std.Io.Timestamp {
        return certificates.types.instant(self.state.expires);
    }

    /// Whether it was made for `identity`'s certificate.
    pub fn belongsTo(self: Credential, identity: certificates.Identity) bool {
        @setRuntimeSafety(true);
        if (identity.form() != .x509) return false;
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(identity.chain()[0], &hash, .{});
        return std.mem.eql(u8, &hash, &self.state.leaf);
    }

    /// Whether a peer that listed `credential_schemes` for credentials and `accepts` signature
    /// schemes takes it at `now` (seconds): the peer would accept it by the checks of `check`.
    pub fn usable(self: Credential, now: i64, credential_schemes: []const u8, accepts: anytype) bool {
        @setRuntimeSafety(true);
        const state = self.state;
        if (now >= state.expires or state.expires > now +| max_validity) return false;
        return lists(credential_schemes, state.view.scheme) and accepts.accepts(state.view.algorithm);
    }

    /// Fresh noise one signature by its key draws.
    pub fn noiseLength(self: Credential) usize {
        return self.state.key.noiseLength();
    }

    /// Signs CertificateVerify content with its key, under its scheme.
    pub fn sign(self: Credential, content: []const u8, noise: []const u8, out: *[PrivateKey.max_signature]u8) Possession.SignError![]const u8 {
        @setRuntimeSafety(true);
        const public_key = certificates.certificate.parsePublicKey(self.state.view.spki) catch return error.SigningFailed;
        const algorithm = Possession.bind(self.keyScheme(), public_key) catch return error.SigningFailed;
        return self.state.key.sign(algorithm, content, noise, out) catch error.SigningFailed;
    }
};

/// What `issue` makes.
pub const Spec = struct {
    role: Role,
    /// The credential's SubjectPublicKeyInfo and the scheme its key signs with.
    spki: []const u8,
    scheme: Scheme,
    /// The scheme the certificate's key signs the delegation with.
    algorithm: Scheme,
    /// When it expires: after the certificate's notBefore, before its notAfter.
    expires: std.Io.Timestamp,
};

pub const IssueError = std.mem.Allocator.Error || error{ NotDelegator, KeyHeldElsewhere, UnsupportedScheme, OutlivesCertificate, SigningFailed };

/// Issues a delegated credential with the key of `identity`'s certificate, which cloak must hold:
/// the DelegatedCredential's bytes, owned by the caller. `noise` is `identity.noiseLength()` fresh
/// bytes. A peer accepts it only while it has at most `max_validity` left to run.
pub fn issue(gpa: std.mem.Allocator, identity: certificates.Identity, spec: Spec, noise: []const u8) IssueError![]u8 {
    @setRuntimeSafety(true);
    if (identity.form() != .x509) return error.NotDelegator;
    if (identity.noiseLength() == null) return error.KeyHeldElsewhere;
    const leaf_der = identity.chain()[0];
    const leaf = certificates.certificate.parse(leaf_der, .{}) catch unreachable; // unreachable: the identity parsed it
    if (!delegator(&leaf)) return error.NotDelegator;
    if (!allowed(spec.scheme)) return error.UnsupportedScheme;
    const public_key = certificates.certificate.parsePublicKey(spec.spki) catch return error.UnsupportedScheme;
    _ = Possession.bind(spec.scheme, public_key) catch return error.UnsupportedScheme;
    if (!std.mem.containsAtLeast(Scheme, &Hello.schemes, 1, &.{spec.algorithm})) return error.UnsupportedScheme;
    const signing = Possession.bind(spec.algorithm, identity.publicKey()) catch return error.UnsupportedScheme;
    const expires = certificates.types.seconds(spec.expires);
    if (expires <= leaf.not_before or expires >= leaf.not_after) return error.OutlivesCertificate;
    const valid_time = std.math.cast(u32, expires - leaf.not_before) orelse return error.OutlivesCertificate;
    if (spec.spki.len > 0xffffff) return error.UnsupportedScheme;
    const credential = try gpa.alloc(u8, 4 + 2 + 3 + spec.spki.len);
    defer gpa.free(credential);
    var w: Writer = .{ .bytes = credential };
    w.int(u32, valid_time) catch unreachable; // unreachable: sized above
    w.int(u16, @backingInt(spec.scheme)) catch unreachable; // unreachable: sized above
    w.vector(u24, spec.spki) catch unreachable; // unreachable: sized above
    const content = try signedContent(gpa, spec.role, leaf_der, credential, @backingInt(spec.algorithm));
    defer gpa.free(content);
    var signature_buf: [PrivateKey.max_signature]u8 = undefined;
    const signature = identity.sign(signing, content, noise, &signature_buf) catch return error.SigningFailed;
    const out = try gpa.alloc(u8, credential.len + 2 + 2 + signature.len);
    var o: Writer = .{ .bytes = out };
    o.put(credential) catch unreachable; // unreachable: sized above
    o.int(u16, @backingInt(spec.algorithm)) catch unreachable; // unreachable: sized above
    o.vector(u16, signature) catch unreachable; // unreachable: sized above
    return out;
}

test {
    _ = @import("Delegation_test.zig");
}
