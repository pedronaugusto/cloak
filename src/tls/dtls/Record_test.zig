const std = @import("std");
const Record = @import("Record.zig");
const suites = @import("../crypto/Suite.zig");

const all13 = [_]suites.Suite13{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256, .aes_128_ccm_sha256 };
const all12 = [_]suites.Cipher{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305, .aes_128_ccm, .aes_256_ccm, .aes_128_ccm_8 };

fn pair13(suite: suites.Suite13) [2]Record.Epoch {
    const secret: [48]u8 = @splat(0x5a);
    const len = suites.digestLength(suite);
    return .{ Record.Epoch.init13(suite, 3, secret[0..len]), Record.Epoch.init13(suite, 3, secret[0..len]) };
}

test "C8 DTLS 1.3 records seal and open under every suite, with and without a connection ID" {
    for (all13) |suite| for ([_][]const u8{ "", "cid-7" }) |cid| {
        var ends = pair13(suite);
        defer for (&ends) |*e| e.deinit();
        var out: [256]u8 = undefined;
        for (0..3) |i| {
            const record = try ends[0].seal13(.application, "hello datagram", cid, &out);
            // Flags 001CSLEE: a CID when there is one, a 16-bit sequence, a length, epoch 3's bits.
            try std.testing.expectEqual(@as(u8, 0x20 | @as(u8, if (cid.len != 0) 0x10 else 0) | 0x0c | 3), record[0]);
            try std.testing.expectEqualSlices(u8, cid, record[1..][0..cid.len]);
            const parsed = Record.split(record, cid.len).?;
            try std.testing.expectEqual(@as(usize, 0), parsed.rest.len);
            const opened = try ends[1].open13(parsed.record, parsed.kind.unified);
            try std.testing.expectEqual(Record.Content.application, opened.content);
            try std.testing.expectEqualSlices(u8, "hello datagram", opened.bytes);
            try std.testing.expectEqual(@as(u64, i), opened.sequence);
        }
    };
}

test "C8 a DTLS 1.3 record number is masked: the wire never shows the sequence after the first" {
    var ends = pair13(.aes_128_gcm_sha256);
    defer for (&ends) |*e| e.deinit();
    var seen_plain = true;
    var out: [128]u8 = undefined;
    for (0..8) |i| {
        const record = try ends[0].seal13(.application, "x", "", &out);
        if (std.mem.readInt(u16, record[1..3], .big) != i) seen_plain = false;
    }
    try std.testing.expect(!seen_plain);
}

test "C8 catalogue_dtls_short_aead_ccm_tag_and_survival: a bad DTLS 1.3 record is dropped, the epoch lives on" {
    for (all13) |suite| {
        var ends = pair13(suite);
        defer for (&ends) |*e| e.deinit();
        var out: [128]u8 = undefined;
        const good = try ends[0].seal13(.application, "payload", "", &out);
        var keep: [128]u8 = undefined;
        @memcpy(keep[0..good.len], good);
        // Every length shorter than the 16 bytes a mask needs, or than a tag, is dropped.
        for (0..good.len) |len| {
            var copy: [128]u8 = undefined;
            @memcpy(copy[0..len], keep[0..len]);
            std.mem.writeInt(u16, copy[3..5], @intCast(len -| 5), .big);
            if (Record.split(copy[0..len], 0)) |parsed| {
                try std.testing.expectError(error.Drop, ends[1].open13(parsed.record, parsed.kind.unified));
            }
        }
        // A flipped bit anywhere fails and is counted; nothing is marked in the window.
        for (0..good.len * 8) |bit| {
            var copy: [128]u8 = undefined;
            @memcpy(copy[0..good.len], keep[0..good.len]);
            copy[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
            if (Record.split(copy[0..good.len], 0)) |parsed| switch (parsed.kind) {
                .unified => |header| try std.testing.expectError(error.Drop, ends[1].open13(parsed.record, header)),
                .classic => {},
            };
        }
        try std.testing.expect(ends[1].failures > 0);
        // The genuine record still opens, once.
        var copy: [128]u8 = undefined;
        @memcpy(copy[0..good.len], keep[0..good.len]);
        const parsed = Record.split(copy[0..good.len], 0).?;
        _ = try ends[1].open13(parsed.record, parsed.kind.unified);
        @memcpy(copy[0..good.len], keep[0..good.len]);
        const again = Record.split(copy[0..good.len], 0).?;
        try std.testing.expectError(error.Drop, ends[1].open13(again.record, again.kind.unified));
    }
}

test "C8 a DTLS 1.3 key update moves both ends to the same next epoch" {
    var ends = pair13(.chacha20_poly1305_sha256);
    defer for (&ends) |*e| e.deinit();
    var next = [2]Record.Epoch{ ends[0].next(), ends[1].next() };
    defer for (&next) |*e| e.deinit();
    try std.testing.expectEqual(@as(u64, 4), next[0].number);
    try std.testing.expect(!std.mem.eql(u8, &ends[0].key.expose().*, &next[0].key.expose().*));
    var out: [128]u8 = undefined;
    const record = try next[0].seal13(.application, "after update", "", &out);
    try std.testing.expectEqual(@as(u8, 0), record[0] & 3);
    const parsed = Record.split(record, 0).?;
    try std.testing.expectEqualSlices(u8, "after update", (try next[1].open13(parsed.record, parsed.kind.unified)).bytes);
}

fn pair12(cipher: suites.Cipher) [2]Record.Epoch {
    const key: [32]u8 = @splat(0x33);
    const iv: [12]u8 = @splat(0x44);
    const key_len = cipher.keyLength();
    const iv_len = cipher.fixedIvLength12();
    return .{ Record.Epoch.init12(cipher, key[0..key_len], iv[0..iv_len]), Record.Epoch.init12(cipher, key[0..key_len], iv[0..iv_len]) };
}

test "C8 DTLS 1.2 records seal and open under every cipher, with and without a connection ID" {
    for (all12) |cipher| for ([_][]const u8{ "", "abc" }) |cid| {
        var ends = pair12(cipher);
        defer for (&ends) |*e| e.deinit();
        var out: [256]u8 = undefined;
        for (0..3) |i| {
            const record = try ends[0].seal12(.application, "hello 1.2", cid, &out);
            try std.testing.expectEqual(@as(u8, if (cid.len != 0) Record.tls12_cid else 23), record[0]);
            // Epoch 1, sequence i, in the clear.
            try std.testing.expectEqual((@as(u64, 1) << 48) | i, std.mem.readInt(u64, record[3..11], .big));
            const parsed = Record.split(record, cid.len).?;
            const opened = try ends[1].open12(parsed.record, parsed.kind.classic);
            try std.testing.expectEqual(Record.Content.application, opened.content);
            try std.testing.expectEqualSlices(u8, "hello 1.2", opened.bytes);
        }
    };
}

test "C8 a DTLS 1.2 CCM_8 record carries an 8-byte tag, and its key tolerates 2^7 failed openings" {
    var ends = pair12(.aes_128_ccm_8);
    defer for (&ends) |*e| e.deinit();
    var out: [128]u8 = undefined;
    const record = try ends[0].seal12(.application, "tiny", "", &out);
    // Header, explicit nonce, the content and an 8-byte tag.
    try std.testing.expectEqual(Record.header12 + 8 + 4 + 8, record.len);
    try std.testing.expectEqual(Record.overhead12(.aes_128_ccm_8, 0) + 4, record.len);
    try std.testing.expectEqual(@as(u64, 1 << 7), Record.failureLimit(.aes_128_ccm_8));
    var keep: [128]u8 = undefined;
    @memcpy(keep[0..record.len], record);
    for (0..128) |i| {
        try std.testing.expect(!ends[1].exhausted());
        @memcpy(out[0..record.len], keep[0..record.len]);
        out[record.len - 1 - i % 8] ^= 0x10;
        const parsed = Record.split(out[0..record.len], 0).?;
        try std.testing.expectError(error.Drop, ends[1].open12(parsed.record, parsed.kind.classic));
    }
    try std.testing.expect(ends[1].exhausted());
}

test "C8 a DTLS 1.2 record is dropped when replayed or tampered" {
    for (all12) |cipher| {
        var ends = pair12(cipher);
        defer for (&ends) |*e| e.deinit();
        var out: [128]u8 = undefined;
        const record = try ends[0].seal12(.handshake, "finished", "", &out);
        var keep: [128]u8 = undefined;
        @memcpy(keep[0..record.len], record);
        for (0..record.len * 8) |bit| {
            var copy: [128]u8 = undefined;
            @memcpy(copy[0..record.len], keep[0..record.len]);
            copy[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
            if (Record.split(copy[0..record.len], 0)) |parsed| switch (parsed.kind) {
                .classic => |header| if (header.epoch == 1) try std.testing.expectError(error.Drop, ends[1].open12(parsed.record, header)),
                .unified => {},
            };
        }
        var copy: [128]u8 = undefined;
        @memcpy(copy[0..record.len], keep[0..record.len]);
        var parsed = Record.split(copy[0..record.len], 0).?;
        try std.testing.expectEqualSlices(u8, "finished", (try ends[1].open12(parsed.record, parsed.kind.classic)).bytes);
        @memcpy(copy[0..record.len], keep[0..record.len]);
        parsed = Record.split(copy[0..record.len], 0).?;
        try std.testing.expectError(error.Drop, ends[1].open12(parsed.record, parsed.kind.classic));
    }
}

test "C8 a datagram splits into its records, and junk after them is dropped with the rest" {
    var out: [512]u8 = undefined;
    const first = try Record.plaintext(.handshake, 7, "abc", out[0..]);
    const second = try Record.plaintext(.alert, 8, "\x01\x00", out[first.len..]);
    const total = first.len + second.len;
    var datagram = out[0..total];
    const one = Record.split(datagram, 0).?;
    try std.testing.expectEqual(@as(u64, 7), one.kind.classic.sequence);
    const two = Record.split(one.rest, 0).?;
    try std.testing.expectEqual(@as(u8, 21), two.record[0]);
    try std.testing.expectEqual(@as(usize, 0), two.rest.len);
    // A length past the datagram, an unknown type, a CID the receiver did not ask for: no record.
    datagram[12] = 0xff;
    try std.testing.expect(Record.split(datagram, 0) == null);
    var junk = [_]u8{ 0x40, 1, 2, 3 };
    try std.testing.expect(Record.split(&junk, 0) == null);
    var cid = [_]u8{ 0x3c, 1, 2, 0, 0 };
    try std.testing.expect(Record.split(&cid, 0) == null);
    var tiny = [_]u8{ Record.tls12_cid, 0xfe, 0xfd };
    try std.testing.expect(Record.split(&tiny, 4) == null);
}
