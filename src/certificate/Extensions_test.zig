const std = @import("std");
const E = @import("Extensions.zig");
test "F10 catalogue_ca_bit_usage_and_pathlen (basicConstraints and key usage reject noncanonical defaults, impossible usages and unsupported subtree distances)" {
    try std.testing.expectError(error.InvalidDer, E.basic(&.{ 0x30, 3, 1, 1, 0 }));
    try std.testing.expectError(error.InvalidCertificate, E.basic(&.{ 0x30, 3, 2, 1, 0 }));
    try std.testing.expectEqual(@as(u16, 0x21), try E.keyUsage(&.{ 3, 2, 2, 0x84 }));
    try std.testing.expectError(error.InvalidDer, E.keyUsage(&.{ 3, 2, 0, 0x80 }));
    try std.testing.expectError(error.UnsupportedName, E.nameConstraints(&.{ 0x30, 11, 0xa0, 9, 0x30, 7, 0x82, 2, 'a', 'b', 0x80, 1, 0 }));
}

test "F19 catalogue_general_name_syntax_and_constraint_forms (unsupported critical constraint forms and malformed policy notices fail closed)" {
    try std.testing.expectError(error.UnsupportedName, E.nameConstraints("\x30\x09\xa0\x07\x30\x05\x88\x03\x2a\x03\x04"));
    // A recognized userNotice OID cannot hide an INTEGER instead of DisplayText.
    const malformed = "\x30\x1a\x30\x18\x06\x03\x2a\x03\x04\x30\x11\x30\x0f\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x02\x30\x03\x02\x01\x01";
    try std.testing.expectError(error.InvalidCertificate, E.validate(.{ .oid = "\x55\x1d\x20", .critical = true, .value = malformed }, .{}));
    try std.testing.expectError(error.InvalidCertificate, E.validate(.{ .oid = "\x55\x1d\x23", .critical = false, .value = "\x30\x03\x82\x01\x01" }, .{}));
}

test "F20 catalogue_crldp_generalname_and_expansion_budget (distribution points are never expanded or fetched; odd name forms are typed)" {
    const crldp = "\x55\x1d\x1f";
    // A distribution point list of EDIPartyName and X.400 names beside a thousand relative
    // names: not read as a non-critical extension, refused as a critical one.
    var big: [4 + 1000 * 2 + 32]u8 = undefined;
    var at: usize = 4;
    const odd = "\x30\x0e\xa0\x0c\xa0\x0a\xa5\x04\xa1\x02\x0c\x00\xa3\x02\x30\x00";
    @memcpy(big[at..][0..odd.len], odd);
    at += odd.len;
    for (0..1000) |_| {
        big[at..][0..2].* = .{ 0x30, 0x00 };
        at += 2;
    }
    big[0..4].* = .{ 0x30, 0x82, @truncate((at - 4) >> 8), @truncate(at - 4) };
    try E.validate(.{ .oid = crldp, .critical = false, .value = big[0..at] }, .{});
    try std.testing.expectError(error.UnknownCriticalExtension, E.validate(.{ .oid = crldp, .critical = true, .value = big[0..at] }, .{}));
    // The same forms as subject alternative names: X.400 is outside the profile, an
    // EDIPartyName must hold its party name and nothing else.
    const Der = @import("../wire/Der.zig");
    try std.testing.expectError(error.UnsupportedName, E.general(try Der.single("\xa3\x02\x30\x00", 0xa3), false));
    try E.general(try Der.single("\xa5\x05\xa1\x03\x0c\x01x", 0xa5), false);
    try std.testing.expect(std.meta.isError(E.general(try Der.single("\xa5\x02\xa0\x00", 0xa5), false)));
    try std.testing.expect(std.meta.isError(E.general(try Der.single("\xa5\x08\xa1\x03\x0c\x01x\x02\x01\x01", 0xa5), false)));
    try std.testing.expect(std.meta.isError(E.general(try Der.single("\xa5\x05\xa1\x03\x02\x01\x01", 0xa5), false)));
}
