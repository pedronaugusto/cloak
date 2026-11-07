//! `cloak-nuget-check --root <der> --root-sha256 <hex> <package.nupkg>`: a NuGet package's
//! author signature verified, and the package held to it. What bay runs as a pinned tool for
//! a NuGet pin that names a root (bay's design §11): bay carries no CMS of its own.
//!
//! The root is a file the pin names by its SHA-256, checked here before it is trusted. The
//! package's `.signature.p7s` must verify against it alone (`cloak.cms`, code signing, its time
//! proved by its timestamp), and the hash its signed manifest names must be the package's as
//! NuGet computes it: the archive without the signature's entry. Exit 0 and one line on
//! success; 1 and the reason otherwise. Nothing is ever taken on trust, and nothing is retried.
const std = @import("std");
const cloak = @import("cloak");
const Io = std.Io;

const usage = "usage: cloak-nuget-check --root <der> --root-sha256 <hex> <package.nupkg>\n";
const max_package = 1 << 31;

const Failure = error{ Usage, RootMismatch, NotAPackage, Zip64Unsupported, NoSignature, SignatureCompressed, ManifestInvalid, UnsupportedHash, PackageMismatch };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [512]u8 = undefined;
    var out = Io.File.stdout().writer(io, &buffer);
    var err_buffer: [512]u8 = undefined;
    var err_out = Io.File.stderr().writer(io, &err_buffer);
    const result = run(gpa, io, arena, try init.minimal.args.toSlice(arena));
    if (result) |line| {
        try out.interface.print("{s}\n", .{line});
        try out.interface.flush();
        return 0;
    } else |err| {
        if (err == error.Usage) try err_out.interface.writeAll(usage) else try err_out.interface.print("cloak-nuget-check: {t}\n", .{err});
        try err_out.interface.flush();
        return 1;
    }
}

fn run(gpa: std.mem.Allocator, io: Io, arena: std.mem.Allocator, args: []const [:0]const u8) ![]const u8 {
    var root_path: ?[]const u8 = null;
    var root_hex: ?[]const u8 = null;
    var package_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--root") and i + 1 < args.len) {
            i += 1;
            root_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--root-sha256") and i + 1 < args.len) {
            i += 1;
            root_hex = args[i];
        } else if (package_path == null and args[i].len != 0 and args[i][0] != '-') {
            package_path = args[i];
        } else return error.Usage;
    }
    const root = try Io.Dir.cwd().readFileAlloc(io, root_path orelse return error.Usage, arena, .limited(1 << 16));
    var wanted: [32]u8 = undefined;
    const hex = root_hex orelse return error.Usage;
    if (hex.len != 64) return error.Usage;
    _ = std.fmt.hexToBytes(&wanted, hex) catch return error.Usage;
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(root, &actual, .{});
    if (!std.mem.eql(u8, &actual, &wanted)) return error.RootMismatch;

    const package = try Io.Dir.cwd().readFileAlloc(io, package_path orelse return error.Usage, arena, .limited(max_package));
    const archive = try Archive.read(package);
    const verified = try cloak.cms.verify(gpa, archive.signature, .{ .roots = &.{root} });
    const named = try manifestHash(verified.content);
    var computed: [32]u8 = undefined;
    archive.unsignedHash(&computed);
    if (!std.mem.eql(u8, &computed, &named)) return error.PackageMismatch;
    return std.fmt.allocPrint(arena, "verified: signed {d}, timestamped {}, package sha256 {x}", .{
        @divFloor(verified.time.toNanoseconds(), std.time.ns_per_s), verified.timestamped, computed,
    });
}

/// NuGet's signature manifest (`Version:1`, then `<hash OID>-Hash:<base64>`): the package hash
/// it names, SHA-256's, the one hash this reads.
fn manifestHash(content: []const u8) Failure![32]u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, lines.next() orelse "", "\r"), "Version:1")) return error.ManifestInvalid;
    var found: ?[32]u8 = null;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.ManifestInvalid;
        const name = line[0..colon];
        if (!std.mem.endsWith(u8, name, "-Hash")) continue;
        if (!std.mem.eql(u8, name, "2.16.840.1.101.3.4.2.1-Hash")) return error.UnsupportedHash;
        if (found != null) return error.ManifestInvalid;
        var hash: [32]u8 = undefined;
        const text = line[colon + 1 ..];
        if ((std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.ManifestInvalid) != 32) return error.ManifestInvalid;
        std.base64.standard.Decoder.decode(&hash, text) catch return error.ManifestInvalid;
        found = hash;
    }
    return found orelse error.ManifestInvalid;
}

/// The archive as NuGet signs it: its signature's entry, stored and last, and everything else.
const Archive = struct {
    bytes: []const u8,
    signature: []const u8,
    /// The signature's local entry, where the signed bytes stop.
    local: usize,
    directory: usize,
    directory_len: usize,
    /// The signature's central record.
    record: usize,
    record_len: usize,
    end: usize,
    entries: u16,

    const name = ".signature.p7s";

    fn int(comptime T: type, bytes: []const u8, at: usize) Failure!T {
        if (at + @sizeOf(T) > bytes.len) return error.NotAPackage;
        return std.mem.readInt(T, bytes[at..][0..@sizeOf(T)], .little);
    }

    fn read(bytes: []const u8) Failure!Archive {
        if (bytes.len < 22) return error.NotAPackage;
        // The end record, with no comment: a signed package has none.
        const end = bytes.len - 22;
        if (try int(u32, bytes, end) != 0x06054b50) return error.NotAPackage;
        const entries = try int(u16, bytes, end + 10);
        const directory_len = try int(u32, bytes, end + 12);
        const directory = try int(u32, bytes, end + 16);
        if (entries == 0xffff or directory == 0xffffffff or directory_len == 0xffffffff) return error.Zip64Unsupported;
        if (@as(u64, directory) + directory_len != end) return error.NotAPackage;
        var at: usize = directory;
        var found: ?struct { record: usize, len: usize, local: usize } = null;
        var last_local: usize = 0;
        for (0..entries) |_| {
            if (try int(u32, bytes, at) != 0x02014b50) return error.NotAPackage;
            const name_len = try int(u16, bytes, at + 28);
            const extra_len = try int(u16, bytes, at + 30);
            const comment_len = try int(u16, bytes, at + 32);
            const local = try int(u32, bytes, at + 42);
            const len = 46 + @as(usize, name_len) + extra_len + comment_len;
            if (at + len > end) return error.NotAPackage;
            last_local = @max(last_local, local);
            if (std.mem.eql(u8, bytes[at + 46 ..][0..name_len], name)) {
                if (found != null) return error.NotAPackage;
                found = .{ .record = at, .len = len, .local = local };
            }
            at += len;
        }
        const signature = found orelse return error.NoSignature;
        // The signature is the archive's last entry, so what it signs is all before it.
        if (signature.local != last_local) return error.NotAPackage;
        const l = signature.local;
        if (try int(u32, bytes, l) != 0x04034b50) return error.NotAPackage;
        if (try int(u16, bytes, l + 8) != 0) return error.SignatureCompressed;
        const size = try int(u32, bytes, l + 18);
        const data = l + 30 + @as(usize, try int(u16, bytes, l + 26)) + try int(u16, bytes, l + 28);
        if (data + size > directory) return error.NotAPackage;
        return .{
            .bytes = bytes,
            .signature = bytes[data..][0..size],
            .local = l,
            .directory = directory,
            .directory_len = directory_len,
            .record = signature.record,
            .record_len = signature.len,
            .end = end,
            .entries = entries,
        };
    }

    /// SHA-256 of the archive as it was before it was signed: the entries before the
    /// signature's, the central directory without its record, and the end record counting one
    /// entry fewer, the directory where the signature's entry began.
    fn unsignedHash(a: Archive, out: *[32]u8) void {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(a.bytes[0..a.local]);
        h.update(a.bytes[a.directory..a.record]);
        h.update(a.bytes[a.record + a.record_len .. a.end]);
        var end: [22]u8 = a.bytes[a.end..][0..22].*;
        std.mem.writeInt(u16, end[8..10], a.entries - 1, .little);
        std.mem.writeInt(u16, end[10..12], a.entries - 1, .little);
        std.mem.writeInt(u32, end[12..16], @intCast(a.directory_len - a.record_len), .little);
        std.mem.writeInt(u32, end[16..20], @intCast(a.local), .little);
        h.update(&end);
        h.final(out);
    }
};
