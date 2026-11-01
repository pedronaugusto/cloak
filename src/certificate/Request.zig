//! A PKCS#10 certification request (RFC 2986), read: its subject, key and requested extensions,
//! and the signature that proves the requester holds the key, which `issue.verifyRequest` checks.
//! Borrows the caller's bytes. A CA reads hostile input here; nothing is trusted until verified.
const std = @import("std");
const Der = @import("../wire/Der.zig");
const Algorithm = @import("Algorithm.zig");
const Name = @import("Name.zig");
const fields = @import("fields.zig");
const Extensions = @import("Extensions.zig");
const Request = @This();

/// The whole request.
der: []const u8,
/// The signed CertificationRequestInfo.
info: []const u8,
/// The subject Name's DER, which a template's `.subject = .{ .der = ... }` takes.
subject: []const u8,
/// The SubjectPublicKeyInfo's DER, and the key it holds.
spki: []const u8,
public_key: Algorithm.PublicKey,
signature_algorithm: Algorithm.Signature,
signature: []const u8,
/// The extensions an extensionRequest attribute asks for, validated as a certificate's are.
extensions: [max_extensions]fields.Extension = undefined,
extension_count: usize = 0,

pub const max_extensions = 32;
pub const ParseError = fields.ParseError || error{InvalidRequest};
const oid_extension_request = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e";

pub fn parse(bytes: []const u8, limits: fields.Limits) ParseError!Request {
    @setRuntimeSafety(true);
    try Der.validate(bytes, .{ .bytes = limits.bytes, .elements = limits.elements, .depth = limits.depth });
    var outer = (try Der.single(bytes, 0x30)).reader();
    const info = try outer.expect(0x30);
    const algorithm = try outer.expect(0x30);
    const signature = try Der.octetBits((try outer.expect(3)).value);
    try outer.finish();
    var r = info.reader();
    if (try Der.number((try r.expect(2)).value) != 0) return error.InvalidRequest;
    const subject = try r.expect(0x30);
    try Name.validate(subject.encoded);
    const spki = try r.expect(0x30);
    var request: Request = .{ .der = bytes, .info = info.encoded, .subject = subject.encoded, .spki = spki.encoded, .public_key = try Algorithm.publicKey(spki.encoded), .signature_algorithm = try Algorithm.signature(algorithm.encoded), .signature = signature };
    // attributes [0] IMPLICIT SET OF Attribute: required, possibly empty.
    var attributes = (try r.expect(0xa0)).reader();
    try r.finish();
    var seen_request = false;
    while (!attributes.empty()) {
        var attribute = (try attributes.expect(0x30)).reader();
        const id = (try attribute.expect(6)).value;
        var values = (try attribute.expect(0x31)).reader();
        try attribute.finish();
        if (values.empty()) return error.InvalidRequest;
        // Other attributes (challengePassword, unstructuredName) ask nothing of a certificate.
        if (!std.mem.eql(u8, id, oid_extension_request)) continue;
        if (seen_request) return error.InvalidRequest;
        seen_request = true;
        var list = (try values.expect(0x30)).reader();
        try values.finish();
        while (!list.empty()) {
            if (request.extension_count >= @min(limits.extensions, max_extensions)) return error.DerLimit;
            var er = (try list.expect(0x30)).reader();
            const oid = (try er.expect(6)).value;
            var critical = false;
            if (er.peek() == 1) {
                critical = try Der.boolean((try er.next()).value);
                if (!critical) return error.InvalidDer;
            }
            const value = (try er.expect(4)).value;
            try er.finish();
            if (request.extension(oid) != null) return error.DuplicateExtension;
            const parsed: fields.Extension = .{ .oid = oid, .critical = critical, .value = value };
            try Extensions.validate(parsed, limits);
            request.extensions[request.extension_count] = parsed;
            request.extension_count += 1;
        }
    }
    return request;
}

/// The requested extension with `oid`, if asked for.
pub fn extension(self: *const Request, oid: []const u8) ?fields.Extension {
    for (self.extensions[0..self.extension_count]) |e| if (std.mem.eql(u8, e.oid, oid)) return e;
    return null;
}

test {
    _ = @import("Request_test.zig");
}
