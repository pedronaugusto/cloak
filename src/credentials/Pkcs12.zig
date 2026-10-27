//! The PKCS#12 container (RFC 7292): its MAC checked before anything is decrypted, then the
//! authenticated safe's contents, plain or password-encrypted, and their bags handed to a sink
//! as they are met. BER is normalised to DER once per encoded layer, so the strict reader reads
//! every byte. This file owns the walk; the key bags' parsing is the key parser's and the
//! certificates' ordering is `Pkcs12`'s.
const std = @import("std");
const aegis = @import("aegis");
const SecretBytes = aegis.SecretBytes;
const Der = @import("../wire/Der.zig");
const Ber = @import("../wire/Ber.zig");
const Pbe = @import("Pbe.zig");
const Kdf = @import("Kdf.zig");
const Sha1 = @import("../crypto/sha1.zig").Sha1;

pub const Limits = struct {
    bytes: usize = 1 << 20,
    iterations: usize = 1_000_000,
    salt_bytes: usize = 1024,
    password_bytes: usize = 4096,
    bags: usize = 64,
    nesting: usize = 4,
};

pub const Options = struct {
    /// Null reads as the empty password; a MAC that fails under it is `PasswordRequired`.
    passphrase: ?[]const u8 = null,
    /// A file without a MAC is `Unauthenticated` unless this is false.
    require_mac: bool = true,
    limits: Limits = .{},
};

pub const Error = Pbe.Error || error{ InvalidPkcs12, PasswordRequired, BadPassword, Unauthenticated, BagLimit };

const oid_data = "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
const oid_encrypted_data = "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06";
/// pkcs-12-bagtypes, the last byte apart: 1 keyBag, 2 pkcs8ShroudedKeyBag, 3 certBag, 4 crlBag,
/// 5 secretBag, 6 safeContentsBag.
const oid_bag_prefix = "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01";
const oid_x509_certificate = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16\x01";
const oid_pbmac1 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0e";
const oid_pbkdf2 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c";
const oid_sha1 = "\x2b\x0e\x03\x02\x1a";
const oid_sha2_prefix = "\x60\x86\x48\x01\x65\x03\x04\x02";

/// Walks `bytes`, a PFX in BER or DER, calling `sink.onKey(bag, shrouded, password)` for each key
/// bag (a PrivateKeyInfo, or when shrouded an EncryptedPrivateKeyInfo to open with `password`,
/// the form the MAC verified) and `sink.onCertificate(der)` for each X.509 certificate bag. Both
/// borrow their bytes for the call only.
pub fn walk(gpa: std.mem.Allocator, bytes: []const u8, options: Options, comptime SinkError: type, sink: anytype) (Error || SinkError)!void {
    @setRuntimeSafety(true);
    const limits = options.limits;
    if (bytes.len > limits.bytes) return error.InputLimit;
    const pbe_limits: Pbe.Limits = .{ .iterations = limits.iterations, .salt_bytes = limits.salt_bytes, .password_bytes = limits.password_bytes };
    const pfx = try normalise(gpa, bytes);
    defer gpa.free(pfx);
    var outer = (Der.single(pfx, 0x30) catch return error.InvalidPkcs12).reader();
    if ((Der.number((try outer.expect(2)).value) catch return error.InvalidPkcs12) != 3) return error.InvalidPkcs12;
    const authenticated = try dataContent(try outer.expect(0x30));
    const mac_data = if (!outer.empty()) try outer.expect(0x30) else null;
    try outer.finish();

    // The empty password has two encodings (RFC 7292 B.1 asks for a NUL; some writers use no
    // bytes at all); the MAC says which one the file was made with.
    const passphrase = options.passphrase orelse "";
    var candidates: [2]Pbe.Password = undefined;
    var count: usize = 0;
    defer for (candidates[0..count]) |*candidate| candidate.deinit(gpa);
    candidates[0] = try Pbe.Password.init(gpa, passphrase, false, pbe_limits);
    count = 1;
    if (passphrase.len == 0) {
        candidates[1] = try Pbe.Password.init(gpa, passphrase, true, pbe_limits);
        count = 2;
    }
    var chosen: *const Pbe.Password = &candidates[0];
    if (mac_data) |data| {
        const verified = for (candidates[0..count]) |*candidate| {
            if (try checkMac(gpa, data, authenticated, candidate, limits)) break candidate;
        } else return if (options.passphrase == null) error.PasswordRequired else error.BadPassword;
        chosen = verified;
    } else if (options.require_mac) return error.Unauthenticated;

    var bags: usize = 0;
    const safe = try normalise(gpa, authenticated);
    defer gpa.free(safe);
    var contents = (Der.single(safe, 0x30) catch return error.InvalidPkcs12).reader();
    while (!contents.empty()) {
        var info = (try contents.expect(0x30)).reader();
        const kind = (try info.expect(6)).value;
        if (std.mem.eql(u8, kind, oid_data)) {
            const content = try Der.single((try info.expect(0xa0)).value, 0x04);
            try info.finish();
            const plain = try normalise(gpa, content.value);
            defer gpa.free(plain);
            try safeContents(plain, chosen, limits, &bags, 0, SinkError, sink);
        } else if (std.mem.eql(u8, kind, oid_encrypted_data)) {
            if (options.passphrase == null and passphrase.len == 0 and mac_data == null) return error.PasswordRequired;
            var decrypted = try encryptedContent(gpa, try info.expect(0xa0), chosen, pbe_limits);
            defer decrypted.deinit(gpa);
            try info.finish();
            try safeContents(decrypted.expose(), chosen, limits, &bags, 0, SinkError, sink);
        } else return error.UnsupportedEncryption;
    }
}

/// The content octets of a ContentInfo of type data: what the MAC covers.
fn dataContent(element: Der.Element) Error![]const u8 {
    @setRuntimeSafety(true);
    var r = element.reader();
    // signedData integrity (public-key mode) has no writer in common use.
    if (!std.mem.eql(u8, (try r.expect(6)).value, oid_data)) return error.UnsupportedEncryption;
    const content = try Der.single((try r.expect(0xa0)).value, 0x04);
    try r.finish();
    return content.value;
}

/// Whether `mac_data` verifies `content` under `password`: HMAC under the appendix B KDF, or
/// PBMAC1 (RFC 9579).
fn checkMac(gpa: std.mem.Allocator, mac_data: Der.Element, content: []const u8, password: *const Pbe.Password, limits: Limits) Error!bool {
    @setRuntimeSafety(true);
    var r = mac_data.reader();
    var digest_info = (try r.expect(0x30)).reader();
    var algorithm = (try digest_info.expect(0x30)).reader();
    const id = (try algorithm.expect(6)).value;
    const parameters = if (!algorithm.empty()) try algorithm.next() else null;
    try algorithm.finish();
    const expected = (try digest_info.expect(4)).value;
    try digest_info.finish();
    const salt = (try r.expect(4)).value;
    const iterations = if (r.peek() == 2) try Der.number((try r.next()).value) else 1;
    try r.finish();
    if (std.mem.eql(u8, id, oid_pbmac1)) return pbmac1(parameters orelse return error.InvalidPkcs12, content, expected, password.utf8, limits);
    if (parameters) |p| if (p.tag != 5 or p.value.len != 0) return error.InvalidPkcs12;
    if (salt.len > limits.salt_bytes or iterations == 0 or iterations > limits.iterations) return error.KdfLimit;
    const rounds = aegis.int.cast(u32, iterations) catch return error.KdfLimit; // safe: checked narrowing at the KDF boundary
    const bmp = try password.bmpForm();
    if (std.mem.eql(u8, id, oid_sha1)) return hmacMac(Sha1, gpa, bmp, salt, rounds, content, expected);
    if (id.len == oid_sha2_prefix.len + 1 and std.mem.eql(u8, id[0..oid_sha2_prefix.len], oid_sha2_prefix)) return switch (id[oid_sha2_prefix.len]) {
        1 => hmacMac(std.crypto.hash.sha2.Sha256, gpa, bmp, salt, rounds, content, expected),
        2 => hmacMac(std.crypto.hash.sha2.Sha384, gpa, bmp, salt, rounds, content, expected),
        3 => hmacMac(std.crypto.hash.sha2.Sha512, gpa, bmp, salt, rounds, content, expected),
        4 => hmacMac(std.crypto.hash.sha2.Sha224, gpa, bmp, salt, rounds, content, expected),
        else => error.UnsupportedEncryption,
    };
    return error.UnsupportedEncryption;
}

fn hmacMac(comptime Hash: type, gpa: std.mem.Allocator, bmp: []const u8, salt: []const u8, rounds: u32, content: []const u8, expected: []const u8) Error!bool {
    @setRuntimeSafety(true);
    if (expected.len != Hash.digest_length) return error.InvalidPkcs12;
    var key_owner = aegis.Secret([Hash.digest_length]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    try Pbe.pkcs12Kdf(Hash, gpa, 3, bmp, salt, rounds, key);
    return macEqual(Hash, key, content, expected);
}

/// RFC 9579: PBKDF2 (keyLength required) keys the HMAC its messageAuthScheme names; the
/// MacData's own salt and count are not used.
fn pbmac1(parameters: Der.Element, content: []const u8, expected: []const u8, password: []const u8, limits: Limits) Error!bool {
    @setRuntimeSafety(true);
    if (parameters.tag != 0x30) return error.InvalidPkcs12;
    var p = parameters.reader();
    var kdf = (try p.expect(0x30)).reader();
    if (!std.mem.eql(u8, (try kdf.expect(6)).value, oid_pbkdf2)) return error.UnsupportedEncryption;
    var kp = (try kdf.expect(0x30)).reader();
    try kdf.finish();
    const salt = (try kp.expect(4)).value;
    const iterations = try Der.number((try kp.expect(2)).value);
    const key_length = Der.number((kp.expect(2) catch return error.InvalidPkcs12).value) catch return error.InvalidPkcs12;
    const kdf_hash = if (kp.peek() == 0x30) try Pbe.prf((try kp.next()).encoded) else Pbe.Prf.sha1;
    try kp.finish();
    const scheme = try Pbe.prf((try p.expect(0x30)).encoded);
    try p.finish();
    if (salt.len > limits.salt_bytes or iterations == 0 or iterations > limits.iterations or iterations > std.math.maxInt(u32)) return error.KdfLimit;
    if (key_length == 0 or key_length > Kdf.max_key) return error.InvalidPkcs12;
    const rounds = aegis.int.cast(u32, iterations) catch return error.KdfLimit; // safe: checked narrowing at the KDF boundary
    var key_owner = aegis.Secret([Kdf.max_key]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut()[0..key_length];
    try Pbe.pbkdf2(kdf_hash, key, password, salt, rounds);
    return switch (scheme) {
        .sha1 => macEqual(Sha1, key, content, expected),
        .sha256 => macEqual(std.crypto.hash.sha2.Sha256, key, content, expected),
        .sha384 => macEqual(std.crypto.hash.sha2.Sha384, key, content, expected),
        .sha512 => macEqual(std.crypto.hash.sha2.Sha512, key, content, expected),
    };
}

/// HMAC-`Hash` of `content` under `key`, compared with `expected` in constant time.
fn macEqual(comptime Hash: type, key: []const u8, content: []const u8, expected: []const u8) Error!bool {
    @setRuntimeSafety(true);
    if (expected.len != Hash.digest_length) return error.InvalidPkcs12;
    var keyed_owner = aegis.Secret(Kdf.Keyed(Hash)).init(undefined);
    defer keyed_owner.deinit();
    const keyed = keyed_owner.exposeMut();
    keyed.init(key);
    var mac: [Hash.digest_length]u8 = undefined;
    keyed.mac(&mac, content, "");
    return aegis.secret.equal(Hash.digest_length, &mac, expected[0..Hash.digest_length]).declassify("the MAC's verdict decides whether the file is read");
}

/// EncryptedData (RFC 5652 8) holding SafeContents: decrypted, then normalised to DER, in a
/// secret owner (a key bag may sit inside).
fn encryptedContent(gpa: std.mem.Allocator, wrapper: Der.Element, password: *const Pbe.Password, limits: Pbe.Limits) Error!SecretBytes {
    @setRuntimeSafety(true);
    var data = (try Der.single(wrapper.value, 0x30)).reader();
    const version = Der.number((try data.expect(2)).value) catch return error.InvalidPkcs12;
    if (version != 0 and version != 2) return error.InvalidPkcs12;
    var info = (try data.expect(0x30)).reader();
    // unprotectedAttrs [1], when present, protect nothing.
    if (data.peek() == 0xa1) _ = try data.next();
    try data.finish();
    if (!std.mem.eql(u8, (try info.expect(6)).value, oid_data)) return error.InvalidPkcs12;
    const algorithm = try info.expect(0x30);
    // encryptedContent [0] IMPLICIT OCTET STRING: primitive, or constructed of OCTET STRINGs as a
    // BER writer leaves it (the normaliser keeps a context tag's chunks).
    const encrypted = try info.next();
    try info.finish();
    var joined: ?[]u8 = null;
    defer if (joined) |j| gpa.free(j);
    const ciphertext = switch (encrypted.tag) {
        0x80 => encrypted.value,
        0xa0 => blk: {
            var total: usize = 0;
            var chunks = encrypted.reader();
            while (!chunks.empty()) total += (try chunks.expect(0x04)).value.len;
            const out = try gpa.alloc(u8, total);
            joined = out;
            var at: usize = 0;
            chunks = encrypted.reader();
            while (!chunks.empty()) {
                const chunk = (try chunks.expect(0x04)).value;
                @memcpy(out[at..][0..chunk.len], chunk);
                at += chunk.len;
            }
            break :blk out;
        },
        else => return error.InvalidPkcs12,
    };
    var plain = try Pbe.decrypt(gpa, algorithm.encoded, ciphertext, password, limits);
    defer plain.deinit(gpa);
    const length = Ber.measure(plain.expose(), .{}) catch return error.BadPassword;
    var der = try SecretBytes.init(gpa, length);
    errdefer der.deinit(gpa);
    der.resizeWithinCapacity(length) catch return error.InputLimit;
    Ber.write(plain.expose(), .{}, der.exposeMut()) catch return error.BadPassword;
    return der;
}

/// SafeContents: each bag to the sink; nested SafeContents to `nesting` levels.
fn safeContents(bytes: []const u8, password: *const Pbe.Password, limits: Limits, bags: *usize, nesting: usize, comptime SinkError: type, sink: anytype) (Error || SinkError)!void {
    @setRuntimeSafety(true);
    var r = (Der.single(bytes, 0x30) catch return error.InvalidPkcs12).reader();
    while (!r.empty()) {
        if (bags.* == limits.bags) return error.BagLimit;
        bags.* += 1;
        var bag = (try r.expect(0x30)).reader();
        const id = (try bag.expect(6)).value;
        const value = try only((try bag.expect(0xa0)).value);
        // bagAttributes (friendlyName, localKeyId): possession, not a label, matches a key.
        if (!bag.empty()) _ = try bag.expect(0x31);
        try bag.finish();
        if (id.len != oid_bag_prefix.len + 1 or !std.mem.eql(u8, id[0..oid_bag_prefix.len], oid_bag_prefix)) continue;
        switch (id[oid_bag_prefix.len]) {
            1 => try sink.onKey(value.encoded, false, password),
            2 => try sink.onKey(value.encoded, true, password),
            3 => {
                if (value.tag != 0x30) return error.InvalidPkcs12;
                var cert = value.reader();
                const kind = (try cert.expect(6)).value;
                const der = try Der.single((try cert.expect(0xa0)).value, 0x04);
                try cert.finish();
                // sdsiCertificate has no writer in use; only X.509 is a certificate here.
                if (std.mem.eql(u8, kind, oid_x509_certificate)) try sink.onCertificate(der.value);
            },
            6 => {
                if (nesting + 1 >= limits.nesting) return error.BagLimit;
                try safeContents(value.encoded, password, limits, bags, nesting + 1, SinkError, sink);
            },
            // crlBag and secretBag carry nothing an identity holds.
            else => {},
        }
    }
}

/// The one element `bytes` holds.
fn only(bytes: []const u8) Error!Der.Element {
    @setRuntimeSafety(true);
    var r: Der.Reader = .{ .bytes = bytes };
    const element = try r.next();
    try r.finish();
    return element;
}

/// `bytes` as DER, in a new allocation.
fn normalise(gpa: std.mem.Allocator, bytes: []const u8) Error![]u8 {
    @setRuntimeSafety(true);
    return Ber.toDer(gpa, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidPkcs12,
    };
}
