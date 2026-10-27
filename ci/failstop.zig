//! A caller that breaks a precondition of cloak's API is stopped, in ReleaseFast as in Debug: the
//! check is aegis's fail-stop, not an assertion the optimizer may assume and build on. Each case
//! runs in a child process of this program, built in ReleaseFast, which must die with the
//! precondition's message.
const std = @import("std");
const cloak = @import("cloak");

const cases = [_]struct { name: []const u8, message: []const u8 }{
    .{ .name = "consume", .message = "the caller consumes at most what is readable" },
    .{ .name = "acknowledge", .message = "the caller acknowledges at most what is pending" },
    .{ .name = "control", .message = "control records go to a kernel that holds the write keys" },
    .{ .name = "receiveControl", .message = "control records come from a kernel that holds the read keys" },
    .{ .name = "gcmSeal", .message = "an AES-GCM ciphertext buffer is as long as the message" },
    .{ .name = "gcmOpen", .message = "an AES-GCM message buffer is as long as the ciphertext" },
    .{ .name = "cbcSeal", .message = "a CBC-HMAC ciphertext buffer is ciphertextLength(message) bytes" },
    .{ .name = "cbcOpen", .message = "a CBC-HMAC message buffer is as long as the ciphertext" },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2) return misuse(init.gpa, args[1]);
    for (cases) |case| {
        const result = try std.process.run(init.gpa, init.io, .{ .argv = &.{ args[0], case.name }, .stdout_limit = .limited(4096), .stderr_limit = .limited(65536) });
        defer init.gpa.free(result.stdout);
        defer init.gpa.free(result.stderr);
        if (result.term == .exited) {
            var err = std.Io.File.stderr().writer(init.io, &.{});
            try err.interface.print("{s}: the misuse ran on (exit {d})\n", .{ case.name, result.term.exited });
            return error.MisuseNotStopped;
        }
        if (std.mem.find(u8, result.stderr, case.message) == null) {
            var err = std.Io.File.stderr().writer(init.io, &.{});
            try err.interface.print("{s}: stopped without its message:\n{s}\n", .{ case.name, result.stderr });
            return error.WrongStop;
        }
    }
}

fn misuse(gpa: std.mem.Allocator, name: []const u8) !void {
    // A buffer one byte short of what the cipher writes.
    const key: [64]u8 = @splat(7);
    const iv: [16]u8 = @splat(9);
    var tag: [32]u8 = @splat(0);
    var buffer: [64]u8 = @splat(0);
    const G = cloak.cipher.AesGcm(128);
    const C = cloak.cipher.CbcHmac(.a128cbc_hs256);
    if (std.mem.eql(u8, name, "gcmSeal")) G.seal(buffer[0..15], tag[0..16], buffer[16..32], "", iv[0..12], key[0..16]);
    // The call never returns: the precondition stops it before the tag is read.
    if (std.mem.eql(u8, name, "gcmOpen")) try G.open(buffer[0..15], buffer[16..32], tag[0..16], "", iv[0..12], key[0..16]);
    if (std.mem.eql(u8, name, "cbcSeal")) C.seal(buffer[0..16], tag[0..16], buffer[32..48], "", &iv, key[0..32]);
    if (std.mem.eql(u8, name, "cbcOpen")) _ = try C.open(buffer[0..15], buffer[16..32], tag[0..16], "", &iv, key[0..32]);
    var conn = try cloak.tls.Connection.client(gpa, .{ .identity = .{ .dns = "example.com" }, .verify = .none });
    defer conn.deinit();
    // Nothing is readable or pending yet: one byte is past either end.
    if (std.mem.eql(u8, name, "consume")) conn.consume(1);
    if (std.mem.eql(u8, name, "acknowledge")) conn.acknowledge(1);
    // No direction is with a kernel: there are no control records to take or give.
    if (std.mem.eql(u8, name, "control")) _ = conn.control();
    if (std.mem.eql(u8, name, "receiveControl")) try conn.receiveControl(21, &.{ 1, 0 });
}
