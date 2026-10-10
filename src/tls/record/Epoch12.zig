//! One direction of TLS 1.2 AEAD record protection. GCM records carry an eight-byte explicit
//! nonce (the record sequence number, so it never repeats under a key) after the header
//! (RFC 5288); ChaCha20-Poly1305 derives the whole nonce from the fixed IV and the sequence
//! (RFC 7905). The additional data is the sequence, type, version and plaintext length.
//! Only connection orchestration seals and opens.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Epoch = @import("Epoch.zig");

pub const Content = Epoch.Content;
pub const Plaintext = Epoch.Plaintext;
pub const Limits = Epoch.Limits;
pub const InitError = Epoch.InitError;
pub const SealError = Epoch.SealError;
pub const OpenError = Epoch.OpenError;
pub const max_content = Epoch.max_content;

pub fn Epoch12(comptime cipher: suites.Cipher) type {
    const A = suites.AeadOf(cipher);
    const explicit = cipher.explicitNonceLength12();
    const fixed = cipher.fixedIvLength12();
    return struct {
        const Self = @This();
        pub const key_length = A.key_length;
        pub const iv_length = fixed;
        /// Header, explicit nonce and tag around a plaintext fragment.
        pub const overhead = 5 + explicit + A.tag_length;
        key: aegis.Secret([A.key_length]u8),
        iv: aegis.Secret([12]u8),
        sequence: Epoch.RecordCount = .fromRaw(0),
        bytes: Epoch.ByteCount = .fromRaw(0),
        limits: struct { records: Epoch.RecordCount, bytes: Epoch.ByteCount },
        closed: bool = false,

        /// `iv` is the key block's fixed IV: four bytes for GCM, twelve for ChaCha20-Poly1305.
        pub fn init(key: *const [A.key_length]u8, iv: *const [fixed]u8, limits: Limits) InitError!Self {
            @setRuntimeSafety(true);
            if (limits.records == 0 or limits.records > 1 << 24 or limits.bytes == 0 or limits.bytes > 1 << 38) return error.InvalidLimits;
            var full: [12]u8 = @splat(0);
            @memcpy(full[0..fixed], iv);
            defer std.crypto.secureZero(u8, &full);
            return .{ .key = .init(key.*), .iv = .init(full), .limits = .{ .records = .fromRaw(limits.records), .bytes = .fromRaw(limits.bytes) } };
        }

        pub fn deinit(self: *Self) void {
            self.key.deinit();
            self.iv.deinit();
            self.closed = true;
        }

        fn nonce(self: *const Self) [12]u8 {
            @setRuntimeSafety(true);
            var value = self.iv.expose().*;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, self.sequence.raw(), .big);
            if (explicit == 0) {
                for (value[4..], counter) |*byte, n| byte.* ^= n;
            } else value[4..12].* = counter;
            return value;
        }

        fn additional(self: *const Self, content: Content, len: usize) [13]u8 {
            @setRuntimeSafety(true);
            var ad: [13]u8 = undefined;
            std.mem.writeInt(u64, ad[0..8], self.sequence.raw(), .big);
            ad[8] = @backingInt(content);
            ad[9..11].* = .{ 3, 3 };
            // safe: callers bound the plaintext at 2^14 bytes.
            std.mem.writeInt(u16, ad[11..13], @intCast(len), .big);
            return ad;
        }

        fn admit(self: *Self, len: usize) error{RecordLimit}!void {
            @setRuntimeSafety(true);
            if (self.sequence.raw() >= self.limits.records.raw() or len > self.limits.bytes.raw() - self.bytes.raw()) {
                self.deinit();
                return error.RecordLimit;
            }
        }

        /// Seals one record of `content` into `out`. Exact alias means input starts at
        /// out.ptr + 5 + explicit nonce; other overlap is refused.
        pub fn seal(self: *Self, content: Content, input: []const u8, out: []u8) SealError![]u8 {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (content != .application and input.len == 0) return error.InvalidLength;
            if (input.len > max_content) return error.InvalidLength;
            const wire_len = overhead + input.len;
            if (out.len < wire_len) return error.BufferTooSmall;
            const wire = out[0..wire_len];
            const body = wire[5 + explicit ..][0..input.len];
            if (overlap(input, wire) and input.ptr != body.ptr) return error.PartialOverlap;
            try self.admit(input.len);
            wire[0] = @backingInt(content);
            wire[1..3].* = .{ 3, 3 };
            // safe: bounded by 2^14 plus the record overhead.
            std.mem.writeInt(u16, wire[3..5], @intCast(wire_len - 5), .big);
            const n = self.nonce();
            if (explicit != 0) wire[5..][0..explicit].* = n[4..12].*;
            if (input.ptr != body.ptr) @memcpy(body, input);
            A.encrypt(body, wire[wire_len - A.tag_length ..][0..A.tag_length], body, &self.additional(content, input.len), n, self.key.expose().*);
            self.sequence = .fromRaw(self.sequence.raw() + 1);
            self.bytes = .fromRaw(self.bytes.raw() + input.len);
            return wire;
        }

        /// Opens one record into `out` after checking the tag; any failure erases the epoch.
        pub fn open(self: *Self, wire: []const u8, out: []u8) OpenError!Plaintext {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (wire.len < overhead or wire.len > overhead + max_content) return self.bad();
            if (!std.mem.eql(u8, wire[1..3], &.{ 3, 3 }) or std.mem.readInt(u16, wire[3..5], .big) != wire.len - 5) return self.bad();
            const content = std.enums.fromInt(Content, wire[0]) orelse return self.bad();
            const len = wire.len - overhead;
            if (content != .application and len == 0) return self.bad();
            if (out.len < len) return error.BufferTooSmall;
            const plain = out[0..len];
            const cipher_text = wire[5 + explicit ..][0..len];
            if (overlap(wire, plain) and plain.ptr != cipher_text.ptr) return error.PartialOverlap;
            try self.admit(len);
            var n = self.nonce();
            // The peer chooses the explicit nonce; it is authenticated through the tag.
            if (explicit != 0) n[4..12].* = wire[5..13].*;
            A.decrypt(plain, cipher_text, wire[wire.len - A.tag_length ..][0..A.tag_length].*, &self.additional(content, len), n, self.key.expose().*) catch {
                std.crypto.secureZero(u8, plain);
                return self.bad();
            };
            self.sequence = .fromRaw(self.sequence.raw() + 1);
            self.bytes = .fromRaw(self.bytes.raw() + len);
            return .{ .content = content, .bytes = plain };
        }

        fn bad(self: *Self) error{BadRecord} {
            self.deinit();
            return error.BadRecord;
        }
    };
}

fn overlap(a: []const u8, b: []const u8) bool {
    @setRuntimeSafety(true);
    if (a.len == 0 or b.len == 0) return false;
    const x = @intFromPtr(a.ptr); // safe: live address used only for overlap validation.
    const y = @intFromPtr(b.ptr); // safe: live address used only for overlap validation.
    return if (x <= y) y - x < a.len else x - y < b.len;
}

test {
    _ = @import("Epoch12_test.zig");
}
