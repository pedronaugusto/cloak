const std = @import("std");
const Authorities = @import("Authorities.zig");

test "C7 certificate_authorities: a walk takes the first preferred candidate, else the first" {
    var pick: Authorities.Pick(u8) = .{};
    try std.testing.expect(!pick.offer(3, 'a', false));
    try std.testing.expect(pick.offer(5, 'b', true));
    try std.testing.expectEqual(@as(usize, 5), pick.chosen().?.index);
    var none: Authorities.Pick(u8) = .{};
    _ = none.offer(2, 'a', false);
    _ = none.offer(4, 'b', false);
    try std.testing.expectEqual(@as(usize, 2), none.chosen().?.index);
    try std.testing.expect(Authorities.marked(null, 7));
    try std.testing.expect(Authorities.marked(Authorities.bit(31), 31) and !Authorities.marked(Authorities.bit(31), 30));
}
