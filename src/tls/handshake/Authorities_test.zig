const std = @import("std");
const shakedown = @import("shakedown");
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

test "Authorities property: a body parses exactly when it is authorities<3..2^16-1> of names<1..2^16-1>, to its list whole" {
    // parse's promise: the names of an extension body, the list filling it and every name whole and
    // of a byte or more; anything else is DecodeError. Lists drawn well formed and then, half the
    // time, one byte changed, cut short or lengthened, against a decoder written from the RFC.
    try shakedown.check(std.testing.allocator, {}, authorities, .{ .cases = 2048, .seed = 0xca47 });
}

/// The list of `authorities<3..2^16-1>` filling `body`, read by position from the RFC's grammar.
fn modelAuthorities(body: []const u8) ?[]const u8 {
    if (body.len < 2) return null;
    const len = std.mem.readInt(u16, body[0..2], .big);
    if (body.len != 2 + len or len < 3) return null;
    const list = body[2..];
    var at: usize = 0;
    while (at < list.len) {
        if (at + 2 > list.len) return null;
        const n = std.mem.readInt(u16, list[at..][0..2], .big);
        if (n == 0 or at + 2 + n > list.len) return null;
        at += 2 + n;
    }
    return list;
}

fn authorities(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    var buf: [256]u8 = undefined;
    var w: usize = 2;
    for (0..shakedown.gen.intRange(s, usize, 0, 5)) |_| {
        // Now and then an empty name, which the grammar refuses.
        const n = if (shakedown.gen.intRange(s, u8, 0, 15) == 0) 0 else shakedown.gen.intRange(s, usize, 1, 30);
        std.mem.writeInt(u16, buf[w..][0..2], @intCast(n), .big);
        for (buf[w + 2 ..][0..n]) |*b| b.* = shakedown.gen.int(s, u8);
        w += 2 + n;
    }
    std.mem.writeInt(u16, buf[0..2], @intCast(w - 2), .big);
    var body: []u8 = buf[0..w];
    switch (shakedown.gen.intRange(s, u8, 0, 5)) {
        0 => body[shakedown.gen.intRange(s, usize, 0, body.len - 1)] ^= shakedown.gen.intRange(s, u8, 1, 255),
        1 => body = body[0..shakedown.gen.intRange(s, usize, 0, body.len - 1)],
        2 => {
            buf[w] = shakedown.gen.int(s, u8);
            body = buf[0 .. w + 1];
        },
        else => {},
    }
    const model = modelAuthorities(body);
    const list = Authorities.parse(body) catch |err| {
        try std.testing.expectEqual(error.DecodeError, err);
        try std.testing.expect(model == null);
        return;
    };
    try std.testing.expectEqualSlices(u8, model orelse return error.TestUnexpectedResult, list);
    try std.testing.expect(list.ptr == body.ptr + 2);
}
