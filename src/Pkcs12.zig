//! A PKCS#12 file (PFX, `.p12`, RFC 7292) read into what cloak's owners take: its private key
//! and its certificates, the key's own first and then the chain above it. The MAC is checked
//! before anything is decrypted; see docs/design.md "PKCS#12".
const std = @import("std");
const aegis = @import("aegis");
const certificate = @import("certificate.zig");
const PrivateKey = @import("PrivateKey.zig");
const walker = @import("credentials/Pkcs12.zig");
const Pbe = @import("credentials/Pbe.zig");
const Pkcs12 = @This();

/// The file's key, if it holds one: released by `deinit`, so `retain` it to keep it longer.
key: ?PrivateKey,
/// Every certificate, DER: with a key, the certificate whose public key is the key's first, then
/// its issuers in chain order, then the file's others in file order; without one, file order.
certificates: []const []const u8,
/// How many of `certificates` are the key's chain.
chain_length: usize,
gpa: std.mem.Allocator,

pub const Limits = walker.Limits;
pub const Options = struct {
    /// The file's password, UTF-8. Null reads as the empty password.
    passphrase: ?[]const u8 = null,
    /// A file without a MAC (`openssl pkcs12 -nomac`) is refused unless this is false: its
    /// contents would be decrypted unauthenticated.
    require_mac: bool = true,
    limits: Limits = .{},
    /// The most certificates a file may hold.
    certificates: usize = 64,
};

pub const ParseError = walker.Error || PrivateKey.ParseError || certificate.ParseError || error{ MultipleKeys, KeyMismatch, Empty, CertificateLimit };

/// Reads `bytes`, a PFX in DER or BER. The key goes through the key parser's checks, and every
/// certificate through the certificate parser's, before either is returned.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: Options) ParseError!Pkcs12 {
    // The bags' passwords, derived keys and plaintext reach these frames: erased on return.
    return aegis.secret.scrubbed(parse_stack, parseFile, .{ gpa, bytes, options });
}

const parse_stack: usize = if (@import("builtin").mode == .debug) 128 * 1024 else 64 * 1024;

/// The key's certificate and its issuers, leaf first: what `Identity.init` takes.
pub fn chain(self: *const Pkcs12) []const []const u8 {
    return self.certificates[0..self.chain_length];
}

pub fn deinit(self: *const Pkcs12) void {
    @setRuntimeSafety(true);
    if (self.key) |key| key.deinit();
    for (self.certificates) |der| self.gpa.free(der);
    self.gpa.free(self.certificates);
}

/// The walk's sink: the key and certificates as they are met. Package-internal.
pub const Collector = struct {
    gpa: std.mem.Allocator,
    options: *const Options,
    held: ?PrivateKey = null,
    found: std.ArrayList([]const u8) = .empty,

    const Error = PrivateKey.ParseError || certificate.ParseError || error{ MultipleKeys, CertificateLimit };

    pub fn onKey(self: *Collector, bag: []const u8, shrouded: bool, password: *const Pbe.Password) Error!void {
        @setRuntimeSafety(true);
        // One identity, one key: several would leave the leaf a guess.
        if (self.held != null) return error.MultipleKeys;
        const limits = self.options.limits;
        self.held = try PrivateKey.parseBag(self.gpa, bag, shrouded, password, .{ .iterations = limits.iterations, .salt_bytes = limits.salt_bytes, .password_bytes = limits.password_bytes });
    }

    pub fn onCertificate(self: *Collector, der: []const u8) Error!void {
        @setRuntimeSafety(true);
        if (self.found.items.len == self.options.certificates) return error.CertificateLimit;
        _ = try certificate.parse(der, .{});
        const owned = try self.gpa.dupe(u8, der);
        errdefer self.gpa.free(owned);
        try self.found.append(self.gpa, owned);
    }

    fn deinit(self: *Collector) void {
        if (self.held) |held| held.deinit();
        for (self.found.items) |der| self.gpa.free(der);
        self.found.deinit(self.gpa);
    }
};

fn parseFile(gpa: std.mem.Allocator, bytes: []const u8, options: Options) ParseError!Pkcs12 {
    @setRuntimeSafety(true);
    var collector: Collector = .{ .gpa = gpa, .options = &options };
    errdefer collector.deinit();
    try walker.walk(gpa, bytes, .{ .passphrase = options.passphrase, .require_mac = options.require_mac, .limits = options.limits }, Collector.Error, &collector);
    const found = collector.found.items;
    if (collector.held == null and found.len == 0) return error.Empty;
    var chain_length: usize = 0;
    if (collector.held != null and found.len != 0) {
        // The leaf is the certificate the key signs for; localKeyId is only a label. The key's
        // public half is encoded once and each certificate's compared with it.
        var info_buffer: [PrivateKey.max_public_key_info]u8 = undefined;
        const own = certificate.parsePublicKey(collector.held.?.publicKeyInfo(&info_buffer)) catch unreachable; // unreachable: cloak encoded it
        const leaf = for (found, 0..) |der, i| {
            const cert = certificate.parse(der, .{}) catch unreachable; // unreachable: parsed when collected
            if (samePublicKey(own, cert.public_key)) break i;
        } else return error.KeyMismatch;
        std.mem.swap([]const u8, &found[0], &found[leaf]);
        chain_length = 1;
        // Each issuer by Name, as path building matches them, until a self-issued certificate.
        while (true) {
            const current = certificate.parse(found[chain_length - 1], .{}) catch unreachable; // unreachable: parsed when collected
            if (current.selfIssued()) break;
            const next = for (found[chain_length..], chain_length..) |der, i| {
                const candidate = certificate.parse(der, .{}) catch unreachable; // unreachable: parsed when collected
                if (certificate.Name.equal(candidate.subject, current.issuer)) break i;
            } else break;
            // Keep the rest in file order: rotate the issuer to the front of the remainder.
            std.mem.rotate([]const u8, found[chain_length .. next + 1], next - chain_length);
            chain_length += 1;
        }
    }
    const certificates = try collector.found.toOwnedSlice(gpa);
    return .{ .key = collector.held, .certificates = certificates, .chain_length = chain_length, .gpa = gpa };
}

/// Whether two parsed public keys are one key: the same kind, parameters and key bytes.
fn samePublicKey(a: certificate.PublicKey, b: certificate.PublicKey) bool {
    const eql = std.mem.eql;
    return switch (a) {
        .rsa => |x| b == .rsa and eql(u8, x.modulus, b.rsa.modulus) and eql(u8, x.exponent, b.rsa.exponent),
        .ec => |x| b == .ec and x.curve == b.ec.curve and eql(u8, x.bytes, b.ec.bytes),
        .ed25519 => |x| b == .ed25519 and eql(u8, x, b.ed25519),
        .mldsa => |x| b == .mldsa and x.level == b.mldsa.level and eql(u8, x.bytes, b.mldsa.bytes),
    };
}

test {
    _ = @import("Pkcs12_test.zig");
    _ = @import("credentials/Pkcs12.zig");
    _ = Pbe;
}
