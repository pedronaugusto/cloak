//! Private directional record owner. Only connection orchestration may seal/open.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
pub const RecordCount = aegis.units.Count(struct {}, u64);
pub const ByteCount = aegis.units.Count(struct {}, u64);
pub const Content = enum(u8) { alert = 21, handshake = 22, application = 23 };
pub const max_content = 1 << 14;
pub const max_inner = max_content + 1;
pub const max_ciphertext = max_content + 256;
pub const Limits = struct { records: u64 = 1 << 24, bytes: u64 = 1 << 38 };
pub const InitError = error{InvalidLimits};
pub const SealError = error{ Closed, RecordLimit, BufferTooSmall, InvalidLength, PartialOverlap };
pub const OpenError = error{ Closed, RecordLimit, BufferTooSmall, BadRecord, PartialOverlap };
pub const Plaintext = struct { content: Content, bytes: []u8 };

pub fn Epoch(comptime suite: suites.Suite) type {
    const A = suites.Aead(suite);
    const Hash = suites.Hash(suite);
    return struct {
        const Self = @This();
        /// The traffic secret an epoch consumes.
        pub const TrafficSecret = aegis.Secret([Hash.digest_length]u8);
        key: aegis.Secret([A.key_length]u8),
        iv: aegis.Secret([12]u8),
        traffic: ?TrafficSecret = null,
        sequence: RecordCount = .fromRaw(0),
        bytes: ByteCount = .fromRaw(0),
        limits: struct { records: RecordCount, bytes: ByteCount },
        closed: bool = false,
        pub fn init(key: [A.key_length]u8, iv: [12]u8, limits: Limits) InitError!Self {
            @setRuntimeSafety(true);
            if (limits.records == 0 or limits.records > 1 << 24 or limits.bytes == 0 or limits.bytes > 1 << 38) return error.InvalidLimits;
            return .{ .key = .init(key), .iv = .init(iv), .limits = .{ .records = .fromRaw(limits.records), .bytes = .fromRaw(limits.bytes) } };
        }
        /// Consumes the supplied traffic owner on success; error leaves it owned.
        pub fn initTraffic(traffic: *TrafficSecret, limits: Limits) InitError!Self {
            var key = aegis.Secret([A.key_length]u8).init(undefined);
            defer key.deinit();
            var iv = aegis.Secret([12]u8).init(undefined);
            defer iv.deinit();
            derive(traffic.expose(), key.exposeMut(), iv.exposeMut());
            var result = try Self.init(key.expose().*, iv.expose().*, limits);
            errdefer result.deinit();
            result.traffic = .init(undefined);
            traffic.moveInto(&result.traffic.?);
            return result;
        }
        pub const UpdateError = error{ Closed, MissingTraffic };
        /// The connection calls this only after committing/accepting the complete
        /// old-key KeyUpdate record. No public caller may install an epoch.
        pub fn update(self: *Self) UpdateError!void {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (self.traffic == null) return error.MissingTraffic;
            var next = TrafficSecret.init(undefined);
            defer next.deinit();
            // unreachable: fixed label and hash-sized output meet the HKDF bounds.
            Labels.expand(Hash, next.exposeMut(), self.traffic.?.expose(), "traffic upd", "") catch unreachable;
            var key = aegis.Secret([A.key_length]u8).init(undefined);
            defer key.deinit();
            var iv = aegis.Secret([12]u8).init(undefined);
            defer iv.deinit();
            derive(next.expose(), key.exposeMut(), iv.exposeMut());
            self.key.deinit();
            self.iv.deinit();
            self.traffic.?.deinit();
            self.key = .init(key.expose().*);
            self.iv = .init(iv.expose().*);
            self.traffic = .init(next.expose().*);
            self.sequence = .fromRaw(0);
            self.bytes = .fromRaw(0);
        }
        fn derive(secret: *const [Hash.digest_length]u8, key: *[A.key_length]u8, iv: *[12]u8) void {
            // unreachable: fixed label and AEAD-sized output meet the HKDF bounds.
            Labels.expand(Hash, key, secret, "key", "") catch unreachable;
            // unreachable: fixed label and twelve-byte output meet the HKDF bounds.
            Labels.expand(Hash, iv, secret, "iv", "") catch unreachable;
        }
        pub fn deinit(self: *Self) void {
            self.key.deinit();
            self.iv.deinit();
            if (self.traffic) |*traffic| traffic.deinit();
            self.traffic = null;
            self.closed = true;
        }
        fn nonce(self: *const Self) [12]u8 {
            @setRuntimeSafety(true);
            var value = self.iv.expose().*;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, self.sequence.raw(), .big);
            for (value[4..], counter) |*byte, n| byte.* ^= n;
            return value;
        }
        fn admit(self: *Self, len: usize) error{RecordLimit}!void {
            @setRuntimeSafety(true);
            if (self.sequence.raw() >= self.limits.records.raw() or len > self.limits.bytes.raw() - self.bytes.raw()) {
                self.deinit();
                return error.RecordLimit;
            }
        }
        /// Commit consumes one nonce, irrespective of subsequent transport acks.
        /// Exact alias means input starts at out.ptr + 5; other overlap is refused.
        pub fn seal(self: *Self, content: Content, input: []const u8, padding: usize, out: []u8) SealError![]u8 {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (content != .application and input.len == 0) return error.InvalidLength;
            if (input.len > max_content or padding > max_content - input.len) return error.InvalidLength;
            const inner_len = input.len + 1 + padding;
            const wire_len = 5 + inner_len + A.tag_length;
            if (out.len < wire_len) return error.BufferTooSmall;
            const wire = out[0..wire_len];
            if (overlap(input, wire) and @intFromPtr(input.ptr) != @intFromPtr(wire.ptr) + 5) return error.PartialOverlap; // safe: compare live addresses only to permit exact ciphertext-body alias.
            try self.admit(inner_len);
            wire[0..3].* = .{ 23, 3, 3 };
            // safe: bounded by max_inner + the fixed 16-byte AEAD tag.
            std.mem.writeInt(u16, wire[3..5], @intCast(inner_len + A.tag_length), .big);
            const inner = wire[5..][0..inner_len];
            if (input.ptr != inner.ptr) @memcpy(inner[0..input.len], input);
            inner[input.len] = @backingInt(content);
            @memset(inner[input.len + 1 ..], 0);
            A.encrypt(inner, wire[5 + inner_len ..][0..16], inner, wire[0..5], self.nonce(), self.key.expose().*);
            self.sequence = .fromRaw(self.sequence.raw() + 1);
            self.bytes = .fromRaw(self.bytes.raw() + inner_len);
            return wire;
        }
        /// Tag verification precedes release. Any peer failure erases this epoch.
        pub fn open(self: *Self, wire: []const u8, out: []u8) OpenError!Plaintext {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (wire.len < 5 + 17 or wire.len > 5 + max_ciphertext) return self.bad();
            if (!std.mem.eql(u8, wire[0..3], &.{ 23, 3, 3 }) or std.mem.readInt(u16, wire[3..5], .big) != wire.len - 5) return self.bad();
            const len = wire.len - 5 - A.tag_length;
            if (len > max_inner) return self.bad();
            if (out.len < len) return error.BufferTooSmall;
            const plain = out[0..len];
            const cipher = wire[5..][0..len];
            if (overlap(wire, plain) and plain.ptr != cipher.ptr) return error.PartialOverlap;
            try self.admit(len);
            A.decrypt(plain, cipher, wire[wire.len - 16 ..][0..16].*, wire[0..5], self.nonce(), self.key.expose().*) catch {
                std.crypto.secureZero(u8, plain);
                return self.bad();
            };
            var end = len;
            while (end > 0 and plain[end - 1] == 0) end -= 1;
            if (end == 0) {
                std.crypto.secureZero(u8, plain);
                return self.bad();
            }
            const content = std.enums.fromInt(Content, plain[end - 1]) orelse {
                std.crypto.secureZero(u8, plain);
                return self.bad();
            };
            if (content != .application and end == 1) {
                std.crypto.secureZero(u8, plain);
                return self.bad();
            }
            self.sequence = .fromRaw(self.sequence.raw() + 1);
            self.bytes = .fromRaw(self.bytes.raw() + len);
            return .{ .content = content, .bytes = plain[0 .. end - 1] };
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
comptime {
    std.debug.assert(max_inner + 16 <= max_ciphertext);
    for (std.enums.values(suites.Suite)) |suite| std.debug.assert(@sizeOf(Epoch(suite)) <= 192);
}
test {
    _ = @import("Epoch_test.zig");
}
