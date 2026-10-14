//! Bounded logical-message transcript; adapters never hash record fragments.
const std = @import("std");
const aegis = @import("aegis");
pub const CommitError = error{ InvalidLength, HandshakeLimit, InvalidRetry };
pub fn Transcript(comptime Hash: type) type {
    return struct {
        const Self = @This();
        hash: Hash = .init(.{}),
        bytes: usize = 0,
        messages: usize = 0,
        retried: bool = false,
        pub fn digest(self: Self) [Hash.digest_length]u8 {
            var copy = self.hash;
            return copy.finalResult();
        }
        pub fn commit(self: *Self, message: []const u8) CommitError!void {
            @setRuntimeSafety(true);
            if (message.len < 4 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
            if (message.len > 128 * 1024) return error.HandshakeLimit;
            const count = (aegis.int.Checked(usize).init(self.bytes).add(message.len) catch return error.HandshakeLimit).raw();
            if (count > 256 * 1024) return error.HandshakeLimit;
            self.hash.update(message);
            self.bytes = count;
            self.messages += 1;
        }
        /// Commits a TLS-form message in its DTLS 1.2 form: the twelve-byte header with
        /// `sequence`, offset zero and the whole length, as if sent unfragmented (RFC 6347
        /// section 4.2.6).
        pub fn commitDatagram(self: *Self, message: []const u8, sequence: u16) CommitError!void {
            @setRuntimeSafety(true);
            if (message.len < 4 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
            if (message.len > 128 * 1024) return error.HandshakeLimit;
            const count = (aegis.int.Checked(usize).init(self.bytes).add(message.len + 8) catch return error.HandshakeLimit).raw();
            if (count > 256 * 1024 + 8 * 64) return error.HandshakeLimit;
            var header: [12]u8 = undefined;
            datagramHeader(&header, message, sequence);
            self.hash.update(&header);
            self.hash.update(message[4..]);
            self.bytes = count;
            self.messages += 1;
        }
        pub fn retry(self: *Self, hrr: []const u8) CommitError!void {
            @setRuntimeSafety(true);
            if (self.retried or self.messages != 1 or hrr.len < 4 or hrr[0] != 2) return error.InvalidRetry;
            // Validate and admit before replacing the original ClientHello hash.
            if (std.mem.readInt(u24, hrr[1..4], .big) != hrr.len - 4) return error.InvalidLength;
            if (hrr.len > 128 * 1024 or hrr.len > 256 * 1024 - self.bytes) return error.HandshakeLimit;
            const ch = self.digest();
            self.hash = Hash.init(.{});
            self.hash.update(&.{ 254, 0, 0, Hash.digest_length });
            self.hash.update(&ch);
            try self.commit(hrr);
            self.retried = true;
        }
    };
}
/// The DTLS handshake header of an unfragmented message: type, length, `sequence`, offset zero,
/// fragment length the whole length.
pub fn datagramHeader(out: *[12]u8, message: []const u8, sequence: u16) void {
    out[0..4].* = message[0..4].*;
    std.mem.writeInt(u16, out[4..6], sequence, .big);
    out[6..9].* = .{ 0, 0, 0 };
    out[9..12].* = message[1..4].*;
}
test {
    _ = @import("Transcript_test.zig");
}
