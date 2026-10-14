const std = @import("std");
const ccm = @import("Ccm.zig");

const Vector = struct { tcId: usize, key: []const u8, iv: []const u8, aad: []const u8, msg: []const u8, ct: []const u8, tag: []const u8, result: []const u8 };
const Group = struct { keySize: usize, ivSize: usize, tagSize: usize, tests: []Vector };

fn unhex(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, text.len / 2);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}

fn run(comptime A: type, gpa: std.mem.Allocator, v: Vector) !void {
    const key = try unhex(gpa, v.key);
    defer gpa.free(key);
    const iv = try unhex(gpa, v.iv);
    defer gpa.free(iv);
    const aad = try unhex(gpa, v.aad);
    defer gpa.free(aad);
    const msg = try unhex(gpa, v.msg);
    defer gpa.free(msg);
    const ct = try unhex(gpa, v.ct);
    defer gpa.free(ct);
    const tag = try unhex(gpa, v.tag);
    defer gpa.free(tag);
    const valid = std.mem.eql(u8, v.result, "valid");
    // Wycheproof's invalid cases here are tampered ciphertexts or tags: opening fails, nothing
    // is released.
    const opened = try gpa.alloc(u8, ct.len);
    defer gpa.free(opened);
    const result = A.decrypt(opened, ct, tag[0..16].*, aad, iv[0..12].*, key[0..A.key_length].*);
    if (valid) {
        try result;
        try std.testing.expectEqualSlices(u8, msg, opened);
        const sealed = try gpa.alloc(u8, msg.len);
        defer gpa.free(sealed);
        var got: [16]u8 = undefined;
        A.encrypt(sealed, &got, msg, aad, iv[0..12].*, key[0..A.key_length].*);
        try std.testing.expectEqualSlices(u8, ct, sealed);
        try std.testing.expectEqualSlices(u8, tag, &got);
    } else {
        try std.testing.expectError(error.AuthenticationFailed, result);
        for (opened) |b| try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "C8 AES-CCM with a 12-byte nonce and 16-byte tag passes Wycheproof" {
    const gpa = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(struct { numberOfTests: usize, testGroups: []Group }, gpa, @embedFile("testdata/aes_ccm_test.json"), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var count: usize = 0;
    for (parsed.value.testGroups) |group| {
        try std.testing.expect(group.ivSize == 96 and group.tagSize == 128);
        for (group.tests) |v| {
            switch (group.keySize) {
                128 => try run(ccm.Aes128Ccm, gpa, v),
                256 => try run(ccm.Aes256Ccm, gpa, v),
                else => return error.UnexpectedGroup,
            }
            count += 1;
        }
    }
    try std.testing.expectEqual(parsed.value.numberOfTests, count);
}

test "C8 AES-CCM seals and opens in place, and a flipped bit anywhere fails and erases" {
    const A = ccm.Aes128Ccm;
    const key: [16]u8 = @splat(0x11);
    const nonce: [12]u8 = @splat(0x22);
    const ad = "header";
    var buffer: [37]u8 = undefined;
    for (&buffer, 0..) |*b, i| b.* = @truncate(i);
    const plain = buffer;
    var tag: [16]u8 = undefined;
    A.encrypt(&buffer, &tag, &buffer, ad, nonce, key);
    try std.testing.expect(!std.mem.eql(u8, &plain, &buffer));
    const sealed = buffer;
    try A.decrypt(&buffer, &buffer, tag, ad, nonce, key);
    try std.testing.expectEqualSlices(u8, &plain, &buffer);
    for (0..sealed.len * 8) |bit| {
        var bad = sealed;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var out: [37]u8 = @splat(0xaa);
        try std.testing.expectError(error.AuthenticationFailed, A.decrypt(&out, &bad, tag, ad, nonce, key));
        try std.testing.expectEqualSlices(u8, &@as([37]u8, @splat(0)), &out);
    }
    for (0..128) |bit| {
        var bad = tag;
        bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var out: [37]u8 = undefined;
        try std.testing.expectError(error.AuthenticationFailed, A.decrypt(&out, &sealed, bad, ad, nonce, key));
    }
    var out: [37]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, A.decrypt(&out, &sealed, tag, "headex", nonce, key));
    var other = nonce;
    other[11] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, A.decrypt(&out, &sealed, tag, ad, other, key));
}
