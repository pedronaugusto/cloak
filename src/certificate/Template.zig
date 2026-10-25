//! What a certificate or a certification request says, and its DER: the TBSCertificate (RFC
//! 5280 section 4.1) and the CertificationRequestInfo (RFC 2986 section 4.1). No key and no
//! signature here: `issue` signs. The bytes follow Go's crypto/x509 (extension order, string
//! types), so a template both write is byte-equal. Everything a verifier would refuse is
//! refused here first.
const std = @import("std");
const Builder = @import("../wire/Builder.zig");
const Algorithm = @import("Algorithm.zig");

/// One attribute of a subject Name, each its own RelativeDistinguishedName, in the order given.
pub const Attribute = union(enum) {
    common_name: []const u8,
    organization: []const u8,
    organizational_unit: []const u8,
    country: []const u8,
    state: []const u8,
    locality: []const u8,
    street: []const u8,
    postal_code: []const u8,
    serial_number: []const u8,
    domain_component: []const u8,
    email: []const u8,
    /// Any other attribute: its OID's content bytes and its value's DER.
    other: struct { oid: []const u8, value: []const u8 },
};

/// A subject: attributes to encode, or a Name already in DER (a request's, an issuer's).
pub const Subject = union(enum) {
    attributes: []const Attribute,
    der: []const u8,
};

/// A subjectAltName entry.
pub const AltName = union(enum) {
    dns: []const u8,
    /// Four or sixteen bytes.
    ip: []const u8,
    email: []const u8,
    uri: []const u8,
};

/// The keyUsage bits (RFC 5280 4.2.1.3).
pub const KeyUsage = packed struct(u9) {
    digital_signature: bool = false,
    content_commitment: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,
};

/// An extendedKeyUsage purpose (RFC 5280 4.2.1.12).
pub const Purpose = union(enum) {
    any,
    server_auth,
    client_auth,
    code_signing,
    email_protection,
    time_stamping,
    ocsp_signing,
    /// Another purpose: its OID's content bytes.
    other: []const u8,
};

pub const Ca = struct { path_length: ?u8 = null };

/// A name-constraints subtree base: a DNS suffix, an email domain or mailbox, a URI host, or an
/// IP network as address then mask (8 or 32 bytes).
pub const Subtree = union(enum) { dns: []const u8, email: []const u8, uri: []const u8, ip: []const u8 };
pub const NameConstraints = struct {
    permitted: []const Subtree = &.{},
    excluded: []const Subtree = &.{},
    critical: bool = true,
};

pub const KeyIdentifier = union(enum) {
    /// On a CA's certificate, RFC 7093 method 1 over its key (as Go); none on others.
    auto,
    always,
    none,
    bytes: []const u8,
};

/// An extension written as given: its OID's content bytes and its value's DER.
pub const Extension = struct { oid: []const u8, critical: bool = false, value: []const u8 };

/// A certificate's contents, apart from its key, issuer and signature.
pub const Certificate = struct {
    /// Positive, at most 20 bytes; null draws 16 random bytes.
    serial: ?[]const u8 = null,
    subject: Subject,
    not_before: std.Io.Timestamp,
    not_after: std.Io.Timestamp,
    names: []const AltName = &.{},
    /// Present: a CA (basicConstraints critical, cA true).
    ca: ?Ca = null,
    key_usage: ?KeyUsage = null,
    purposes: []const Purpose = &.{},
    subject_key_identifier: KeyIdentifier = .auto,
    /// authorityInfoAccess: OCSP responders and CA issuer URLs.
    ocsp: []const []const u8 = &.{},
    ca_issuers: []const []const u8 = &.{},
    crl_distribution_points: []const []const u8 = &.{},
    /// certificatePolicies: each policy's OID content bytes.
    policies: []const []const u8 = &.{},
    name_constraints: ?NameConstraints = null,
    extensions: []const Extension = &.{},
};

/// A certification request's contents: the subject and the extensions it asks for.
pub const Request = struct {
    subject: Subject,
    names: []const AltName = &.{},
    key_usage: ?KeyUsage = null,
    purposes: []const Purpose = &.{},
    extensions: []const Extension = &.{},
};

pub const Error = Builder.Error || error{ InvalidName, InvalidSerial, InvalidValidity, InvalidTemplate };

const oid_attribute = "\x55\x04";
const oid_domain_component = "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19";
const oid_email = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01";
const oid_extension_request = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e";
const oid_key_usage = "\x55\x1d\x0f";
const oid_ext_key_usage = "\x55\x1d\x25";
const oid_basic_constraints = "\x55\x1d\x13";
const oid_ski = "\x55\x1d\x0e";
const oid_aki = "\x55\x1d\x23";
const oid_aia = "\x2b\x06\x01\x05\x05\x07\x01\x01";
const oid_san = "\x55\x1d\x11";
const oid_policies = "\x55\x1d\x20";
const oid_name_constraints = "\x55\x1d\x1e";
const oid_crl_dp = "\x55\x1d\x1f";
const oid_ocsp = "\x2b\x06\x01\x05\x05\x07\x30\x01";
const oid_ca_issuers = "\x2b\x06\x01\x05\x05\x07\x30\x02";
const oid_purpose_prefix = "\x2b\x06\x01\x05\x05\x07\x03";

/// Writes `subject` as a Name.
pub fn name(b: *Builder, subject: Subject) Error!void {
    @setRuntimeSafety(true);
    switch (subject) {
        .der => |der| {
            @import("Name.zig").validate(der) catch return error.InvalidName;
            try b.raw(der);
        },
        .attributes => |attributes| {
            const sequence = try b.open(0x30);
            for (attributes) |attribute| {
                const set = try b.open(0x31);
                const pair = try b.open(0x30);
                switch (attribute) {
                    .other => |other| {
                        if (other.oid.len == 0 or other.value.len == 0) return error.InvalidName;
                        try b.element(0x06, other.oid);
                        try b.raw(other.value);
                    },
                    inline else => |value, tag| {
                        if (value.len == 0) return error.InvalidName;
                        const oid: []const u8, const kind: enum { directory, printable, ia5 } = switch (tag) {
                            .common_name => .{ oid_attribute ++ "\x03", .directory },
                            .serial_number => .{ oid_attribute ++ "\x05", .printable },
                            .country => .{ oid_attribute ++ "\x06", .printable },
                            .locality => .{ oid_attribute ++ "\x07", .directory },
                            .state => .{ oid_attribute ++ "\x08", .directory },
                            .street => .{ oid_attribute ++ "\x09", .directory },
                            .organization => .{ oid_attribute ++ "\x0a", .directory },
                            .organizational_unit => .{ oid_attribute ++ "\x0b", .directory },
                            .postal_code => .{ oid_attribute ++ "\x11", .directory },
                            .domain_component => .{ oid_domain_component, .ia5 },
                            .email => .{ oid_email, .ia5 },
                            .other => unreachable,
                        };
                        try b.element(0x06, oid);
                        switch (kind) {
                            .printable => {
                                if (!printable(value) or (tag == .country and value.len != 2)) return error.InvalidName;
                                try b.element(0x13, value);
                            },
                            .ia5 => {
                                for (value) |c| if (c == 0 or c > 127) return error.InvalidName;
                                try b.element(0x16, value);
                            },
                            // PrintableString when every character is one, else UTF8String (Go's choice).
                            .directory => {
                                if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidName;
                                try b.element(if (printable(value)) 0x13 else 0x0c, value);
                            },
                        }
                    },
                }
                try b.close(pair);
                try b.close(set);
            }
            try b.close(sequence);
        },
    }
}

fn printable(value: []const u8) bool {
    for (value) |c| {
        if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, " '()+,-./:=?", c) == null) return false;
    }
    return true;
}

/// Writes a TBSCertificate: `serial` already checked or drawn, `issuer` the issuer's Name DER,
/// `spki` the subject's key, `algorithm` the signature AlgorithmIdentifier DER, `ski` and `aki`
/// the key identifiers to write (or none).
pub fn tbs(b: *Builder, template: *const Certificate, serial: []const u8, issuer: []const u8, spki: []const u8, algorithm: []const u8, ski: ?[]const u8, aki: ?[]const u8) Error!void {
    @setRuntimeSafety(true);
    try checkCertificate(template);
    const sequence = try b.open(0x30);
    const version = try b.open(0xa0);
    try b.small(2);
    try b.close(version);
    try b.unsigned(serial);
    try b.raw(algorithm);
    try b.raw(issuer);
    const validity = try b.open(0x30);
    try time(b, template.not_before);
    try time(b, template.not_after);
    try b.close(validity);
    try name(b, template.subject);
    try b.raw(spki);
    const any = template.key_usage != null or template.purposes.len != 0 or template.ca != null or ski != null or aki != null or template.ocsp.len != 0 or template.ca_issuers.len != 0 or template.names.len != 0 or template.policies.len != 0 or template.name_constraints != null or template.crl_distribution_points.len != 0 or template.extensions.len != 0;
    if (any) {
        const wrapper = try b.open(0xa3);
        const list = try b.open(0x30);
        try extensions(b, template.subject, template.key_usage, template.purposes, template.ca, ski, aki, template.ocsp, template.ca_issuers, template.names, template.policies, template.name_constraints, template.crl_distribution_points, template.extensions);
        try b.close(list);
        try b.close(wrapper);
    }
    try b.close(sequence);
}

/// Writes a CertificationRequestInfo: version 0, the subject, its key and the extensionRequest.
pub fn requestInfo(b: *Builder, template: *const Request, spki: []const u8) Error!void {
    @setRuntimeSafety(true);
    try checkNames(template.names);
    try checkSubject(template.subject, template.names);
    try checkExtensions(template.extensions);
    const sequence = try b.open(0x30);
    try b.small(0);
    try name(b, template.subject);
    try b.raw(spki);
    const attributes = try b.open(0xa0);
    if (template.key_usage != null or template.purposes.len != 0 or template.names.len != 0 or template.extensions.len != 0) {
        const attribute = try b.open(0x30);
        try b.element(0x06, oid_extension_request);
        const values = try b.open(0x31);
        const list = try b.open(0x30);
        try extensions(b, template.subject, template.key_usage, template.purposes, null, null, null, &.{}, &.{}, template.names, &.{}, null, &.{}, template.extensions);
        try b.close(list);
        try b.close(values);
        try b.close(attribute);
    }
    try b.close(attributes);
    try b.close(sequence);
}

/// The extensions, in Go's order, then the template's own.
fn extensions(b: *Builder, subject: Subject, key_usage: ?KeyUsage, purposes: []const Purpose, ca: ?Ca, ski: ?[]const u8, aki: ?[]const u8, ocsp: []const []const u8, ca_issuers: []const []const u8, names: []const AltName, policies: []const []const u8, constraints: ?NameConstraints, crl: []const []const u8, extra: []const Extension) Error!void {
    @setRuntimeSafety(true);
    if (key_usage) |usage| {
        const e = try begin(b, oid_key_usage, true);
        try b.namedBits(@as(u9, @bitCast(usage)));
        try end(b, e);
    }
    if (purposes.len != 0) {
        const e = try begin(b, oid_ext_key_usage, false);
        const list = try b.open(0x30);
        for (purposes) |purpose| switch (purpose) {
            .any => try b.element(0x06, "\x55\x1d\x25\x00"),
            .other => |oid| try b.element(0x06, oid),
            inline else => |_, tag| try b.element(0x06, oid_purpose_prefix ++ [_]u8{switch (tag) {
                .server_auth => 1,
                .client_auth => 2,
                .code_signing => 3,
                .email_protection => 4,
                .time_stamping => 8,
                .ocsp_signing => 9,
                else => unreachable,
            }}),
        };
        try b.close(list);
        try end(b, e);
    }
    if (ca) |authority| {
        const e = try begin(b, oid_basic_constraints, true);
        const list = try b.open(0x30);
        try b.boolean(true);
        if (authority.path_length) |length| try b.small(length);
        try b.close(list);
        try end(b, e);
    }
    if (ski) |id| {
        const e = try begin(b, oid_ski, false);
        try b.element(0x04, id);
        try end(b, e);
    }
    if (aki) |id| {
        const e = try begin(b, oid_aki, false);
        const list = try b.open(0x30);
        try b.element(0x80, id);
        try b.close(list);
        try end(b, e);
    }
    if (ocsp.len != 0 or ca_issuers.len != 0) {
        const e = try begin(b, oid_aia, false);
        const list = try b.open(0x30);
        for ([_][]const []const u8{ ocsp, ca_issuers }, [_][]const u8{ oid_ocsp, oid_ca_issuers }) |urls, method| for (urls) |url| {
            try checkUri(url);
            const description = try b.open(0x30);
            try b.element(0x06, method);
            try b.element(0x86, url);
            try b.close(description);
        };
        try b.close(list);
        try end(b, e);
    }
    if (names.len != 0) {
        // Critical when the subject is empty (RFC 5280 4.2.1.6).
        const e = try begin(b, oid_san, subjectEmpty(subject));
        const list = try b.open(0x30);
        for (names) |entry| switch (entry) {
            .email => |v| try b.element(0x81, v),
            .dns => |v| try b.element(0x82, v),
            .uri => |v| try b.element(0x86, v),
            .ip => |v| try b.element(0x87, v),
        };
        try b.close(list);
        try end(b, e);
    }
    if (policies.len != 0) {
        const e = try begin(b, oid_policies, false);
        const list = try b.open(0x30);
        for (policies) |oid| {
            if (oid.len == 0) return error.InvalidTemplate;
            const information = try b.open(0x30);
            try b.element(0x06, oid);
            try b.close(information);
        }
        try b.close(list);
        try end(b, e);
    }
    if (constraints) |c| {
        if (c.permitted.len == 0 and c.excluded.len == 0) return error.InvalidTemplate;
        const e = try begin(b, oid_name_constraints, c.critical);
        const list = try b.open(0x30);
        for ([_][]const Subtree{ c.permitted, c.excluded }, [_]u8{ 0xa0, 0xa1 }) |trees, tag| {
            if (trees.len == 0) continue;
            const group = try b.open(tag);
            for (trees) |tree| {
                const subtree = try b.open(0x30);
                switch (tree) {
                    .dns => |v| try b.element(0x82, v),
                    .email => |v| try b.element(0x81, v),
                    .uri => |v| try b.element(0x86, v),
                    .ip => |v| {
                        if (v.len != 8 and v.len != 32) return error.InvalidName;
                        try b.element(0x87, v);
                    },
                }
                try b.close(subtree);
            }
            try b.close(group);
        }
        try b.close(list);
        try end(b, e);
    }
    if (crl.len != 0) {
        const e = try begin(b, oid_crl_dp, false);
        const list = try b.open(0x30);
        for (crl) |url| {
            try checkUri(url);
            const point = try b.open(0x30);
            const name_field = try b.open(0xa0);
            const full = try b.open(0xa0);
            try b.element(0x86, url);
            try b.close(full);
            try b.close(name_field);
            try b.close(point);
        }
        try b.close(list);
        try end(b, e);
    }
    for (extra) |extension| {
        const e = try begin(b, extension.oid, extension.critical);
        try b.raw(extension.value);
        try end(b, e);
    }
}

const Open = struct { extension: Builder.Mark, value: Builder.Mark };
fn begin(b: *Builder, oid: []const u8, critical: bool) Error!Open {
    const extension = try b.open(0x30);
    try b.element(0x06, oid);
    if (critical) try b.boolean(true);
    return .{ .extension = extension, .value = try b.open(0x04) };
}
fn end(b: *Builder, open: Open) Error!void {
    try b.close(open.value);
    try b.close(open.extension);
}

/// UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 4.1.2.5), whole seconds, Z.
fn time(b: *Builder, at: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    const seconds = std.math.cast(u64, at.toSeconds()) orelse return error.InvalidValidity;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const day = epoch.getEpochDay().calculateYearDay();
    const month = day.calculateMonthDay();
    const clock = epoch.getDaySeconds();
    const year = day.year;
    if (year > 9999) return error.InvalidValidity;
    var buffer: [15]u8 = undefined;
    if (year < 2050) {
        const text = std.fmt.bufPrint(&buffer, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ year % 100, month.month.numeric(), month.day_index + 1, clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute() }) catch unreachable; // unreachable: 13 bytes
        try b.element(0x17, text);
    } else {
        const text = std.fmt.bufPrint(&buffer, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ year, month.month.numeric(), month.day_index + 1, clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute() }) catch unreachable; // unreachable: 15 bytes
        try b.element(0x18, text);
    }
}

fn subjectEmpty(subject: Subject) bool {
    return switch (subject) {
        .attributes => |a| a.len == 0,
        .der => |d| d.len == 2,
    };
}

/// The checks a verifier would make of what the template says, before anything is written.
pub fn checkCertificate(template: *const Certificate) Error!void {
    @setRuntimeSafety(true);
    if (template.not_after.toSeconds() <= template.not_before.toSeconds() or template.not_before.toSeconds() < 0) return error.InvalidValidity;
    try checkNames(template.names);
    try checkSubject(template.subject, template.names);
    if (template.key_usage) |usage| {
        if (@as(u9, @bitCast(usage)) == 0) return error.InvalidTemplate;
        // keyCertSign only on a CA (RFC 5280 4.2.1.3).
        if (usage.key_cert_sign and template.ca == null) return error.InvalidTemplate;
    }
    switch (template.subject_key_identifier) {
        .bytes => |id| if (id.len == 0) return error.InvalidTemplate,
        else => {},
    }
    try checkExtensions(template.extensions);
}

/// An empty subject needs a subjectAltName (RFC 5280 4.1.2.6).
fn checkSubject(subject: Subject, names: []const AltName) Error!void {
    if (subjectEmpty(subject) and names.len == 0) return error.InvalidName;
}

fn checkExtensions(extra: []const Extension) Error!void {
    for (extra) |extension| {
        if (extension.oid.len == 0 or extension.value.len == 0) return error.InvalidTemplate;
        // One extension of a kind: the template's own fields write these.
        for ([_][]const u8{ oid_key_usage, oid_ext_key_usage, oid_basic_constraints, oid_ski, oid_aki, oid_aia, oid_san, oid_policies, oid_name_constraints, oid_crl_dp }) |owned| {
            if (std.mem.eql(u8, extension.oid, owned)) return error.InvalidTemplate;
        }
    }
    for (extra, 0..) |a, i| for (extra[i + 1 ..]) |b| if (std.mem.eql(u8, a.oid, b.oid)) return error.InvalidTemplate;
}

/// subjectAltName entries as cloak's verifier reads them.
pub fn checkNames(names: []const AltName) Error!void {
    @setRuntimeSafety(true);
    for (names) |entry| switch (entry) {
        .dns => |v| try checkDns(v),
        .ip => |v| if (v.len != 4 and v.len != 16) return error.InvalidName,
        .email => |v| {
            const at = std.mem.findScalar(u8, v, '@') orelse return error.InvalidName;
            if (at == 0) return error.InvalidName;
            for (v) |c| if (c <= 32 or c > 126) return error.InvalidName;
            try checkDns(v[at + 1 ..]);
        },
        .uri => |v| try checkUri(v),
    };
}

/// A DNS name of letters, digits and hyphens in labels of 1 to 63, at most 253 bytes, a
/// leading `*.` label allowed.
fn checkDns(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var rest = value;
    if (std.mem.startsWith(u8, rest, "*.")) rest = rest[2..];
    if (rest.len == 0 or value.len > 253) return error.InvalidName;
    var labels = std.mem.splitScalar(u8, rest, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return error.InvalidName;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidName;
    }
}

/// An absolute URI: a scheme (RFC 3986 3.1), a colon, and printable ASCII.
fn checkUri(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    const colon = std.mem.findScalar(u8, value, ':') orelse return error.InvalidName;
    if (colon == 0 or !std.ascii.isAlphabetic(value[0])) return error.InvalidName;
    for (value[0..colon]) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return error.InvalidName;
    for (value) |c| if (c <= 32 or c > 126) return error.InvalidName;
}

/// RFC 7093 section 2 method 1: the leftmost 160 bits of the SHA-256 of the subjectPublicKey
/// BIT STRING's value, as Go writes a CA's.
pub fn keyIdentifier(spki: []const u8) error{InvalidPublicKey}![20]u8 {
    @setRuntimeSafety(true);
    const Der = @import("../wire/Der.zig");
    var r = (Der.single(spki, 0x30) catch return error.InvalidPublicKey).reader();
    _ = r.expect(0x30) catch return error.InvalidPublicKey;
    const key = Der.octetBits((r.expect(0x03) catch return error.InvalidPublicKey).value) catch return error.InvalidPublicKey;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
    return digest[0..20].*;
}

/// The AlgorithmIdentifier DER a certificate's signature under `algorithm` carries.
pub fn signatureAlgorithm(algorithm: Algorithm.Signature) error{UnsupportedAlgorithm}![]const u8 {
    return switch (algorithm) {
        .ed25519 => "\x30\x05\x06\x03\x2b\x65\x70",
        .ecdsa => |hash| switch (hash) {
            .sha256 => "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02",
            .sha384 => "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03",
            .sha512 => "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04",
        },
        .rsa => |hash| switch (hash) {
            .sha256 => "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00",
            .sha384 => "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c\x05\x00",
            .sha512 => "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d\x05\x00",
        },
        // RSASSA-PSS with MGF1 on the same hash and a salt as long as it (RFC 4055), as Go writes.
        .pss => |p| if (p.mgf_hash != p.hash or p.trailer != 1) error.UnsupportedAlgorithm else switch (p.hash) {
            .sha256 => if (p.salt_length == 32) "\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20" else error.UnsupportedAlgorithm,
            .sha384 => if (p.salt_length == 48) "\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\xa2\x03\x02\x01\x30" else error.UnsupportedAlgorithm,
            .sha512 => if (p.salt_length == 64) "\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\xa2\x03\x02\x01\x40" else error.UnsupportedAlgorithm,
        },
        .mldsa => |level| switch (level) {
            .mldsa44 => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11",
            .mldsa65 => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12",
            .mldsa87 => "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13",
        },
        .ecdsa_p1363, .unsupported => error.UnsupportedAlgorithm,
    };
}

test {
    _ = @import("Template_test.zig");
}
