//! Every departure has a named profile reason and a checked expected verdict.
//! No failing IN algorithm or constraint is suppressed.
const std = @import("std");
const Mapping = struct { id: []const u8, accept: bool, reason: []const u8 };
pub const mappings = [_]Mapping{
    .{ .id = "rfc5280::nc::nc-forbids-othername-noop", .accept = false, .reason = "Unsupported critical otherName constraints fail closed even when that form is absent" },
    .{ .id = "rfc5280::aki::cross-signed-root-missing-aki", .accept = true, .reason = "Explicit anchor issuer/self-signature metadata is not path authorization" },
    .{ .id = "webpki::nc::permitted-dns-match-noncritical", .accept = false, .reason = "Strict RFC 5280 requires critical nameConstraints" },
    .{ .id = "crl::structure::crl-very-large", .accept = false, .reason = "10,000 entries exceed configured evidence byte/entry caps" },
    .{ .id = "pathlen::validation-ignores-pathlen-in-leaf", .accept = false, .reason = "TLS possession requires digitalSignature when KU is present" },
    .{ .id = "rfc5280::ca-as-leaf", .accept = false, .reason = "TLS possession requires digitalSignature when KU is present" },
    .{ .id = "rfc5280::nc::permitted-dn-match", .accept = false, .reason = "TLS server authentication requires an explicit DNS/IP reference" },
    .{ .id = "rfc5280::ski::root-missing-ski", .accept = true, .reason = "Explicit anchor metadata is not a CA-issued certificate" },
    .{ .id = "rfc5280::validity::expired-root", .accept = true, .reason = "Anchor validity is opt-in" },
    .{ .id = "rfc5280::root-missing-basic-constraints", .accept = true, .reason = "Explicit anchors do not need CA basicConstraints" },
    .{ .id = "rfc5280::root-non-critical-basic-constraints", .accept = true, .reason = "Explicit anchor constraints are enforced independent of extension criticality" },
    .{ .id = "rfc9881::ml-dsa-44", .accept = false, .reason = "ML-DSA authentication is C10" },
    .{ .id = "rfc9881::ml-dsa-65", .accept = false, .reason = "ML-DSA authentication is C10" },
    .{ .id = "rfc9881::ml-dsa-87", .accept = false, .reason = "ML-DSA authentication is C10" },
    .{ .id = "webpki::aki::root-with-aki-all-fields", .accept = true, .reason = "Anchor AKI is only a search hint" },
    .{ .id = "webpki::aki::root-with-aki-ski-mismatch", .accept = true, .reason = "Anchor AKI is only a search hint" },
    .{ .id = "webpki::cn::ipv4-hex-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::ipv4-leading-zeros-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::ipv6-uppercase-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::ipv6-uncompressed-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::ipv6-non-rfc5952-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::punycode-not-in-san", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::utf8-vs-punycode-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::not-in-san", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::cn::case-mismatch", .accept = true, .reason = "CN is irrelevant to SAN-only identity" },
    .{ .id = "webpki::eku::ee-anyeku", .accept = true, .reason = "RFC 5280 anyExtendedKeyUsage allows either TLS purpose" },
    .{ .id = "webpki::eku::ee-critical-eku", .accept = true, .reason = "A supported critical EKU is understood" },
    .{ .id = "webpki::eku::ee-without-eku", .accept = true, .reason = "Absent EKU does not restrict purpose" },
    .{ .id = "webpki::eku::root-has-eku", .accept = true, .reason = "Anchor EKU is permitted and enforced" },
    .{ .id = "webpki::san::public-suffix-multi-label-wildcard-san", .accept = true, .reason = "Public-suffix distribution is outside explicit portable trust" },
    .{ .id = "webpki::san::public-suffix-private-namespace-wildcard-san", .accept = true, .reason = "Public-suffix distribution is outside explicit portable trust" },
    .{ .id = "webpki::san::san-critical-with-nonempty-subject", .accept = true, .reason = "Supported critical SAN is understood" },
    .{ .id = "webpki::forbidden-rsa-not-divisible-by-8-in-root", .accept = true, .reason = "Modern RSA floor is 2048 bits, not an extra CABF byte-alignment rule" },
    .{ .id = "webpki::forbidden-rsa-key-not-divisible-by-8-in-leaf", .accept = true, .reason = "Modern RSA floor is 2048 bits, not an extra CABF byte-alignment rule" },
    .{ .id = "webpki::ee-basicconstraints-ca", .accept = true, .reason = "CA leaf with digitalSignature is permitted by explicit portable policy" },
};
pub fn expected(id: []const u8) ?bool {
    @setRuntimeSafety(true);
    for (mappings) |m| if (std.mem.eql(u8, id, m.id)) return m.accept;
    return null;
}
