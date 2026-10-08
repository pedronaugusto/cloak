const std = @import("std");
const C = @import("Certificate.zig");
const Der = @import("../wire/Der.zig");
test "certificate time validates calendar and canonical UTC representation" {
    try std.testing.expectEqual(@as(i64, 0), try C.time(try Der.single("\x17\x0d700101000000Z", 0x17)));
    try std.testing.expectError(error.InvalidTime, C.time(try Der.single("\x17\x0d230229000000Z", 0x17)));
    try std.testing.expectError(error.InvalidTime, C.time(try Der.single("\x18\x0f20490101000000Z", 0x18)));
}
