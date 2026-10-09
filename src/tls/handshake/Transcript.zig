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
test {
    _ = @import("Transcript_test.zig");
}
