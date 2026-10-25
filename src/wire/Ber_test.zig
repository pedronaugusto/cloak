const std = @import("std");
const Ber = @import("Ber.zig");
const Der = @import("Der.zig");

fn expectDer(ber: []const u8, der: []const u8) !void {
    const out = try Ber.toDer(std.testing.allocator, ber, .{});
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, der, out);
}

test "BER to DER keeps DER as it is" {
    const der = "\x30\x0a\x02\x01\x05\x04\x03abc\x05\x00";
    try expectDer(der, der);
}

test "BER to DER makes indefinite lengths definite" {
    try expectDer("\x30\x80\x02\x01\x05\x30\x80\x05\x00\x00\x00\x00\x00", "\x30\x07\x02\x01\x05\x30\x02\x05\x00");
}

test "BER to DER joins a constructed OCTET STRING, nested and indefinite" {
    try expectDer("\x24\x80\x04\x02ab\x24\x03\x04\x01c\x04\x00\x00\x00", "\x04\x03abc");
    // An implicit context tag stays constructed: its reader joins it.
    try expectDer("\xa0\x80\x04\x01a\x04\x01b\x00\x00", "\xa0\x06\x04\x01a\x04\x01b");
}

test "BER to DER makes non-minimal lengths minimal and long contents long-form" {
    try expectDer("\x04\x81\x01z", "\x04\x01z");
    var ber: [3 + 200]u8 = undefined;
    ber[0..3].* = "\x04\x81\xc8".*;
    @memset(ber[3..], 'x');
    var der: [3 + 200]u8 = undefined;
    der[0..3].* = "\x04\x81\xc8".*;
    @memset(der[3..], 'x');
    try expectDer(&ber, &der);
    var chunked: [2 + 2 * (2 + 100) + 2]u8 = undefined;
    chunked[0..2].* = "\x24\x80".*;
    for (0..2) |i| {
        chunked[2 + i * 102 ..][0..2].* = "\x04\x64".*;
        @memset(chunked[4 + i * 102 ..][0..100], 'x');
    }
    chunked[chunked.len - 2 ..][0..2].* = "\x00\x00".*;
    try expectDer(&chunked, &der);
}

test "BER to DER refuses what BER does not allow" {
    const bad = [_][]const u8{
        "\x04\x80\x00\x00", // indefinite primitive
        "\x30\x80\x02\x01\x05", // no end-of-contents
        "\x24\x80\x02\x01\x05\x00\x00", // a string's chunk of another type
        "\x1f\x01\x00", // high tag number
        "\x30\x05\x02\x01", // past the end
        "\x00\x00",
    };
    for (bad) |input| try std.testing.expectError(error.InvalidDer, Ber.measure(input, .{}));
    var deep: [2 * 30 + 2 * 30]u8 = undefined;
    for (0..30) |i| deep[2 * i ..][0..2].* = "\x30\x80".*;
    for (0..30) |i| deep[60 + 2 * i ..][0..2].* = "\x00\x00".*;
    try std.testing.expectError(error.DerLimit, Ber.measure(&deep, .{ .depth = 24 }));
    try std.testing.expectError(error.DerLimit, Ber.measure("\x30\x06\x05\x00\x05\x00\x05\x00", .{ .elements = 3 }));
}

test "fuzz BER normalisation is DER the strict reader takes, and stable" {
    const shakedown = @import("shakedown");
    try shakedown.check(std.testing.allocator, {}, struct {
        fn run(_: void, case: *shakedown.Case) !void {
            const inputs = @import("../testing/inputs.zig");
            var buffer: [4096]u8 = undefined;
            const examples = [_][]const u8{ "\x30\x80\x02\x01\x05\x30\x80\x05\x00\x00\x00\x00\x00", "\x24\x80\x04\x02ab\x24\x03\x04\x01c\x04\x00\x00\x00", "\xa0\x80\x04\x01a\x04\x01b\x00\x00" };
            const input = inputs.draw(case, &buffer, &examples, 24);
            const der = Ber.toDer(std.testing.allocator, input, .{}) catch return;
            defer std.testing.allocator.free(der);
            // Normalising DER changes nothing, and the result reads as DER element by element.
            const again = try Ber.toDer(std.testing.allocator, der, .{});
            defer std.testing.allocator.free(again);
            try std.testing.expectEqualSlices(u8, der, again);
            var r: Der.Reader = .{ .bytes = der };
            while (!r.empty()) _ = try r.next();
        }
    }.run, .{ .cases = 256 });
}
