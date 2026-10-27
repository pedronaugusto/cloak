//! `cipher` against Wycheproof's AES-GCM, AES key wrap and A*CBC-HS* files (C2SP
//! testvectors_v1, the commit `verify/fixtures/wycheproof/provenance.txt` names): every valid
//! case sealed byte for byte and opened, every invalid one refused. AES-192 cases are counted
//! as not offered.
const std = @import("std");
const cipher = @import("cipher.zig");

const gpa = std.testing.allocator;

fn hex(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try arena.alloc(u8, text.len / 2);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}

const Case = struct { tcId: u32, key: []const u8, iv: []const u8 = "", aad: []const u8 = "", msg: []const u8, ct: []const u8, tag: []const u8 = "", result: []const u8 };
const Group = struct { keySize: u32, ivSize: u32 = 0, tagSize: u32 = 0, tests: []const Case };
const File = struct { numberOfTests: u32, testGroups: []const Group };

fn load(arena: std.mem.Allocator, comptime name: []const u8) !File {
    return std.json.parseFromSliceLeaky(File, arena, @embedFile("verify/fixtures/wycheproof/" ++ name), .{ .ignore_unknown_fields = true });
}

test "Wycheproof aes_gcm: every 128- and 256-bit case with a 96-bit nonce sealed and opened as the file says" {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try load(arena, "aes_gcm_test.json");
    var ran: usize = 0;
    var not_offered: usize = 0;
    for (file.testGroups) |g| for (g.tests) |t| {
        if ((g.keySize != 128 and g.keySize != 256) or g.ivSize != 96 or g.tagSize != 128) {
            not_offered += 1;
            continue;
        }
        ran += 1;
        const key = try hex(arena, t.key);
        const iv = try hex(arena, t.iv);
        const aad = try hex(arena, t.aad);
        const msg = try hex(arena, t.msg);
        const ct = try hex(arena, t.ct);
        const tag = try hex(arena, t.tag);
        const out = try arena.alloc(u8, ct.len);
        const valid = !std.mem.eql(u8, t.result, "invalid");
        switch (g.keySize) {
            inline 128, 256 => |bits| {
                const G = cipher.AesGcm(bits);
                const opened = G.open(out, ct, tag[0..16], aad, iv[0..12], key[0..G.key_length]);
                if (valid) {
                    try opened;
                    try std.testing.expectEqualSlices(u8, msg, out);
                    var sealed_tag: [16]u8 = undefined;
                    const sealed = try arena.alloc(u8, msg.len);
                    G.seal(sealed, &sealed_tag, msg, aad, iv[0..12], key[0..G.key_length]);
                    try std.testing.expectEqualSlices(u8, ct, sealed);
                    try std.testing.expectEqualSlices(u8, tag, &sealed_tag);
                } else {
                    std.testing.expectError(error.AuthenticationFailed, opened) catch |err| {
                        std.debug.print("aes_gcm tcId {d} opened\n", .{t.tcId});
                        return err;
                    };
                    // The tag is checked before any block: no plaintext reached `out`.
                    if (msg.len != 0) try std.testing.expect(!std.mem.eql(u8, msg, out));
                }
            },
            else => unreachable, // unreachable: filtered above
        }
    };
    try std.testing.expect(ran > 100);
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran + not_offered);
}

test "Wycheproof aes_wrap: valid keys wrapped byte for byte and unwrapped, every invalid wrap refused" {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try load(arena, "aes_wrap_test.json");
    var ran: usize = 0;
    var not_offered: usize = 0;
    for (file.testGroups) |g| for (g.tests) |t| {
        if (g.keySize == 192) {
            not_offered += 1;
            continue;
        }
        ran += 1;
        const kek = try hex(arena, t.key);
        const msg = try hex(arena, t.msg);
        const ct = try hex(arena, t.ct);
        const valid = !std.mem.eql(u8, t.result, "invalid");
        // "acceptable": a key shorter than RFC 3394's two blocks, which may be refused.
        if (std.mem.eql(u8, t.result, "acceptable") and msg.len < 16) {
            const wrapped = try arena.alloc(u8, msg.len + 8);
            try std.testing.expectError(error.InvalidLength, cipher.keyWrap.wrap(kek, msg, wrapped));
            continue;
        }
        if (valid) {
            const wrapped = try arena.alloc(u8, msg.len + 8);
            try cipher.keyWrap.wrap(kek, msg, wrapped);
            try std.testing.expectEqualSlices(u8, ct, wrapped);
            const unwrapped = try arena.alloc(u8, msg.len);
            try cipher.keyWrap.unwrap(kek, ct, unwrapped);
            try std.testing.expectEqualSlices(u8, msg, unwrapped);
        } else {
            const out = try arena.alloc(u8, if (ct.len >= 8) ct.len - 8 else 0);
            @memset(out, 0x5c);
            if (cipher.keyWrap.unwrap(kek, ct, out)) |_| {
                std.debug.print("aes_wrap tcId {d} unwrapped\n", .{t.tcId});
                return error.InvalidUnwrapped;
            } else |err| switch (err) {
                // A refusal leaves `out` as it was.
                error.AuthenticationFailed => for (out) |b| try std.testing.expectEqual(@as(u8, 0x5c), b),
                error.InvalidLength => {},
            }
        }
    };
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran + not_offered);
}

fn compositeFile(comptime name: []const u8, comptime which: anytype) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try load(arena, name);
    const C = cipher.CbcHmac(which);
    var ran: usize = 0;
    for (file.testGroups) |g| for (g.tests) |t| {
        ran += 1;
        const key = try hex(arena, t.key);
        const iv = try hex(arena, t.iv);
        const aad = try hex(arena, t.aad);
        const msg = try hex(arena, t.msg);
        const ct = try hex(arena, t.ct);
        const tag = try hex(arena, t.tag);
        const valid = !std.mem.eql(u8, t.result, "invalid");
        if (key.len != C.key_length or iv.len != C.iv_length or tag.len != C.tag_length) {
            // A key, IV or tag of another length is no case of this cipher.
            try std.testing.expect(!valid);
            continue;
        }
        const out = try arena.alloc(u8, ct.len);
        @memset(out, 0x5c);
        const opened = C.open(out, ct, tag[0..C.tag_length], aad, iv[0..16], key[0..C.key_length]);
        if (valid) {
            try std.testing.expectEqualSlices(u8, msg, try opened);
            const sealed = try arena.alloc(u8, C.ciphertextLength(msg.len));
            var sealed_tag: [C.tag_length]u8 = undefined;
            C.seal(sealed, &sealed_tag, msg, aad, iv[0..16], key[0..C.key_length]);
            try std.testing.expectEqualSlices(u8, ct, sealed);
            try std.testing.expectEqualSlices(u8, tag, &sealed_tag);
        } else {
            std.testing.expectError(error.AuthenticationFailed, opened) catch |err| {
                std.debug.print("{s} tcId {d} opened\n", .{ name, t.tcId });
                return err;
            };
            // A refusal, by tag or by padding, leaves `out` as it was.
            for (out) |b| try std.testing.expectEqual(@as(u8, 0x5c), b);
        }
    };
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran);
}

test "Wycheproof a128cbc_hs256 and a256cbc_hs512: RFC 7518 5.2's composite, the tag checked before any block" {
    try compositeFile("a128cbc_hs256_test.json", .a128cbc_hs256);
    try compositeFile("a256cbc_hs512_test.json", .a256cbc_hs512);
}
