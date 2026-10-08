const std = @import("std");
const constraints = @import("constraints.zig");
const C = @import("../certificate.zig");
test "directoryName matching normalizes ASCII strings and retains RDN boundaries" {
    const a = "\x30\x0f\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04Test";
    const b = "\x30\x0f\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x13\x04tEST";
    try std.testing.expect(C.Name.equal(a, b));
}

test "wildcard constraints exclude intersecting hosts and preserve label depth" {
    var leaf = try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{});
    var ca = try C.parse(@embedFile("fixtures/vectors/p256.der"), .{});
    leaf.extensions[leaf.extension_count] = .{ .oid = "\x55\x1d\x11", .critical = false, .value = "\x30\x0f\x82\x0d*.example.com" };
    leaf.extension_count += 1;
    ca.extensions[ca.extension_count] = .{ .oid = "\x55\x1d\x1e", .critical = true, .value = "\x30\x19\xa1\x17\x30\x15\x82\x13sub.foo.example.com" };
    ca.extension_count += 1;
    // Use only the synthetic SAN, replacing the original parsed leaf SAN.
    for (leaf.extensions[0 .. leaf.extension_count - 1]) |*e| if (std.mem.eql(u8, e.oid, "\x55\x1d\x11")) {
        e.value = leaf.extensions[leaf.extension_count - 1].value;
    };
    try constraints.check(&.{ leaf, ca }, &.{});
    ca.extensions[ca.extension_count - 1].value = "\x30\x15\xa1\x13\x30\x11\x82\x0ffoo.example.com";
    try std.testing.expectError(error.NameConstraintViolation, constraints.check(&.{ leaf, ca }, &.{}));
}
