const std = @import("std");
const Base64 = @import("Base64.zig");
const shakedown = @import("shakedown");

test "catalogue_key_import_base64_all_characters_match_standard" {
    @setRuntimeSafety(true);
    var source: [4]u8 = @splat('A');
    for (0..4) |position| {
        for (0..256) |byte| {
            source = @splat('A');
            source[position] = @intCast(byte); // safe: exhaustive byte loop is below 256
            try compare(&source);
        }
    }
    for ([_][]const u8{ "", "AA==", "AAA=", "AAAA", "AB==", "AAB=", "A===", "====", "AA=A", "AA==AAAA", "AAAAAA==", "AAAAAAA=", "A", "AA", "AAA" }) |source_text| try compare(source_text);
}
fn compare(source: []const u8) !void {
    @setRuntimeSafety(true);
    var standard: [12]u8 = @splat(0);
    var owned: [12]u8 = @splat(0xa5);
    const a_size = std.base64.standard.Decoder.calcSizeForSlice(source) catch {
        try std.testing.expectError(error.InvalidBase64, Base64.size(source));
        return;
    };
    const b_size = try Base64.size(source);
    try std.testing.expectEqual(a_size, b_size);
    if (std.base64.standard.Decoder.decode(standard[0..a_size], source)) |_| {
        try Base64.decode(owned[0..b_size], source);
        try std.testing.expect(std.mem.eql(u8, standard[0..a_size], owned[0..b_size]));
    } else |_| {
        try std.testing.expectError(error.InvalidBase64, Base64.decode(owned[0..b_size], source));
        try std.testing.expect(std.mem.allEqual(u8, owned[0..b_size], 0));
    }
}

test "catalogue_key_import_base64_byte_roundtrip_and_erasure" {
    @setRuntimeSafety(true);
    var input: [256]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i); // safe: array positions cover exactly the byte range
    var encoded: [344]u8 = undefined;
    var output: [256]u8 = undefined;
    for (0..input.len + 1) |len| {
        const text = std.base64.standard.Encoder.encode(&encoded, input[0..len]);
        try std.testing.expectEqual(len, try Base64.size(text));
        try Base64.decode(output[0..len], text);
        try std.testing.expect(std.mem.eql(u8, input[0..len], output[0..len]));
    }
    @memset(&output, 0xa5);
    try std.testing.expectError(error.InvalidBase64, Base64.decode(&output, "AA=="));
    try std.testing.expect(std.mem.allEqual(u8, &output, 0));
}

test "catalogue_key_import_base64_generated_roundtrip" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, roundtrip, .{ .cases = 1024, .seed = 0xc1b640 });
}
fn roundtrip(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    var input: [1024]u8 = undefined;
    const len = shakedown.gen.intRange(case.source, usize, 0, input.len);
    for (input[0..len]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var encoded: [1368]u8 = undefined;
    var output: [1024]u8 = undefined;
    const text = std.base64.standard.Encoder.encode(&encoded, input[0..len]);
    try Base64.decode(output[0..len], text);
    try std.testing.expect(std.mem.eql(u8, input[0..len], output[0..len]));
}
