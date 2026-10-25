//! PKCS#12 reads: OpenSSL 4.0.3's default (PBES2 AES-256-CBC, PBKDF2 and a SHA-256 MAC, 2048
//! rounds each), its legacy form (3DES key, RC2-40 certificates, SHA-1 MAC) and a MAC-only file,
//! each a leaf, its intermediate and root: the cost is the KDF rounds. The rivals' harness (the
//! same files through OpenSSL's and BoringSSL's `PKCS12_parse`) is in trials `cloak/pkcs12`.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    gpa: std.mem.Allocator,
    bytes: []const u8,
    fn parse(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            const p12 = try cloak.Pkcs12.parse(context.gpa, context.bytes, .{ .passphrase = "correct-horse" });
            if (p12.key == null or p12.chain().len != 3) return error.WrongContents;
            p12.deinit();
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    const io = init.io;
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &buffer);
    const files = [_][]const u8{ @embedFile("data/pkcs12/p256.default.p12"), @embedFile("data/pkcs12/p256.legacy.p12"), @embedFile("data/pkcs12/p256.noenc.p12"), @embedFile("data/pkcs12/rsa.default.p12") };
    const names = [_][]const u8{ "P-256 AES-256/SHA-256 2048", "P-256 legacy 3DES/RC2-40/SHA-1 2048", "P-256 MAC only SHA-256 2048", "RSA-2048 AES-256/SHA-256 2048" };
    for (files, names) |bytes, name| {
        var context: Context = .{ .gpa = init.gpa, .bytes = bytes };
        const row = try init.arena.allocator().print("PKCS#12 read {s}", .{name});
        try shakedown.bench.run(@typeInfo(@typeInfo(@TypeOf(Context.parse)).@"fn".return_type.?).error_union.error_set, init.gpa, io, &out.interface, &context, &.{.{ .name = row, .unit = "file", .run = Context.parse }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    }
    try out.interface.flush();
}
