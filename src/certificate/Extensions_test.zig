const std = @import("std");
const E = @import("Extensions.zig");
test "constraints reject impossible usages defaults and unsupported subtree distances" {
    try std.testing.expectError(error.InvalidDer, E.basic(&.{ 0x30, 3, 1, 1, 0 }));
    try std.testing.expectError(error.InvalidCertificate, E.basic(&.{ 0x30, 3, 2, 1, 0 }));
    try std.testing.expectEqual(@as(u16, 0x21), try E.keyUsage(&.{ 3, 2, 2, 0x84 }));
    try std.testing.expectError(error.InvalidDer, E.keyUsage(&.{ 3, 2, 0, 0x80 }));
    try std.testing.expectError(error.UnsupportedName, E.nameConstraints(&.{ 0x30, 11, 0xa0, 9, 0x30, 7, 0x82, 2, 'a', 'b', 0x80, 1, 0 }));
}

test "unsupported critical constraint forms and malformed policy notices fail closed" {
    try std.testing.expectError(error.UnsupportedName, E.nameConstraints("\x30\x09\xa0\x07\x30\x05\x88\x03\x2a\x03\x04"));
    // A recognized userNotice OID cannot hide an INTEGER instead of DisplayText.
    const malformed = "\x30\x1a\x30\x18\x06\x03\x2a\x03\x04\x30\x11\x30\x0f\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x02\x30\x03\x02\x01\x01";
    try std.testing.expectError(error.InvalidCertificate, E.validate(.{ .oid = "\x55\x1d\x20", .critical = true, .value = malformed }, .{}));
    try std.testing.expectError(error.InvalidCertificate, E.validate(.{ .oid = "\x55\x1d\x23", .critical = false, .value = "\x30\x03\x82\x01\x01" }, .{}));
}
