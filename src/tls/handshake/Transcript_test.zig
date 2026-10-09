const std = @import("std");
const T = @import("Transcript.zig");
const R = @import("../record/Epoch.zig");
const L = @import("../crypto/Labels.zig");
fn hex(comptime value: []const u8) [value.len / 2]u8 {
    var out: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, value) catch unreachable;
    return out;
}
test "C2 RFC8448 transcript protected server flight and Finished" {
    const H = std.crypto.hash.sha2.Sha256;
    var transcript: T.Transcript(H) = .{};
    try transcript.commit(@embedFile("testdata/client-hello.bin"));
    try transcript.commit(@embedFile("testdata/server-hello.bin"));
    try std.testing.expectEqualSlices(u8, &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"), &transcript.digest());
    const traffic = hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    try L.expand(H, &key, &traffic, "key", "");
    try L.expand(H, &iv, &traffic, "iv", "");
    var rx = try R.Epoch(.aes_128_gcm_sha256).init(key, iv, .{});
    defer rx.deinit();
    var out: [658]u8 = undefined;
    const plain = try rx.open(@embedFile("testdata/server-record.bin"), &out);
    try std.testing.expectEqualSlices(u8, @embedFile("testdata/server-flight.bin"), plain.bytes);
    var pos: usize = 0;
    while (pos < plain.bytes.len) {
        const size = 4 + @as(usize, std.mem.readInt(u24, plain.bytes[pos + 1 ..][0..3], .big));
        const message = plain.bytes[pos..][0..size];
        if (message[0] == 20) try L.checkFinished(H, &traffic, &transcript.digest(), message[4..]);
        try transcript.commit(message);
        pos += size;
    }
    try std.testing.expectEqualSlices(u8, &hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"), &transcript.digest());
    var tx = try R.Epoch(.aes_128_gcm_sha256).init(key, iv, .{});
    defer tx.deinit();
    var wire: [679]u8 = undefined;
    try std.testing.expectEqualSlices(u8, @embedFile("testdata/server-record.bin"), try tx.seal(.handshake, plain.bytes, 0, &wire));
}
test "C2 catalogue_hrr_illegal_group_ch2_and_reallocation" {
    // Transcript component of F31: exact synthetic message_hash, once only.
    // Group/CH2 validation awaits the ClientHello/ServerHello parser integration.
    inline for (.{ std.crypto.hash.sha2.Sha256, std.crypto.hash.sha2.Sha384 }) |H| {
        var transcript: T.Transcript(H) = .{};
        const ch = @embedFile("testdata/client-hello.bin");
        const hrr = "\x02\x00\x00\x03hrr";
        try transcript.commit(ch);
        var reference = H.init(.{});
        var hash: [H.digest_length]u8 = undefined;
        H.hash(ch, &hash, .{});
        reference.update(&.{ 254, 0, 0, H.digest_length });
        reference.update(&hash);
        reference.update(hrr);
        try transcript.retry(hrr);
        try std.testing.expectEqualSlices(u8, &reference.finalResult(), &transcript.digest());
        const unchanged = transcript.digest();
        try std.testing.expectError(error.InvalidRetry, transcript.retry(hrr));
        try std.testing.expectEqualSlices(u8, &unchanged, &transcript.digest());
        var fresh: T.Transcript(H) = .{};
        try std.testing.expectError(error.InvalidRetry, fresh.retry(hrr));
        try std.testing.expectError(error.InvalidLength, fresh.commit("\x01\xff\xff\xfftiny"));
    }
}
