//! F93: secrets in diagnostics and on release. Public diagnostics are flat typed records that hold
//! no bytes; every owner a connection releases is wiped before its memory goes back, on every
//! carrier, at every point a caller may let it go: mid-handshake, connected, after key updates,
//! closed or failed. The key log is the one intentional export of secrets: its sink is the
//! caller's, outside cloak's confidentiality, and these tests read their needles from it.
const std = @import("std");
const Connection = @import("Connection.zig");
const Session = @import("Session.zig");
const Datagram = @import("dtls/Datagram.zig");
const QuicHandshake = @import("quic/Handshake.zig");
const Labels = @import("crypto/Labels.zig");
const Prf = @import("crypto/Prf.zig");
const Duo = @import("../testing/Duo.zig");
const DatagramPair = @import("../testing/DatagramPair.zig");
const QuicLoop = @import("../testing/QuicLoop.zig").QuicLoop;
const pki = Duo.pki;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Whether a value of `T` can carry bytes: flags, numbers, enums and errors, and records and
/// optionals of them, cannot.
fn holdsNoBytes(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .bool, .int, .@"enum", .error_set, .void => true,
        .optional => |o| holdsNoBytes(o.child),
        .@"struct" => |s| inline for (s.field_types) |field| {
            if (!holdsNoBytes(field)) break false;
        } else true,
        else => false,
    };
}

fn Returns(comptime function: anytype) type {
    return @typeInfo(@TypeOf(function)).@"fn".return_type.?;
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (public diagnostics hold no bytes: flags, numbers, enums and errors only, every carrier)" {
    inline for (.{
        Returns(Connection.diagnostics),
        Returns(Session.diagnostics),
        Returns(Session.failure),
        Returns(Datagram.failure),
        Returns(Datagram.alerts),
        Returns(QuicHandshake.failure),
    }) |T| try std.testing.expect(comptime holdsNoBytes(T));
    // What the check refuses: anything that points at or holds bytes.
    try std.testing.expect(!holdsNoBytes(struct { reason: ?[]const u8 }));
    try std.testing.expect(!holdsNoBytes(struct { secret: [32]u8 }));
    try std.testing.expect(!holdsNoBytes(union(enum) { line: []const u8 }));
}

/// Keeps a copy of every block freed through it, for a search once the owners are released. It
/// refuses to shrink or move a block in place, so every byte an owner gives up passes `free`, and
/// hands out every byte zeroed, so a block holds only what its owner wrote, never what an earlier
/// owner left in the memory beneath it. Freed blocks are kept, filled, until the end: nothing
/// reuses them, and a write after release, which the copy would miss, shows in the fill.
const Graveyard = struct {
    child: std.mem.Allocator,
    buried: std.ArrayList(u8) = .empty,
    graves: std.ArrayList(Grave) = .empty,
    const Grave = struct { memory: []u8, alignment: std.mem.Alignment };
    const fill = 0x5c;

    fn allocator(self: *Graveyard) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn deinit(self: *Graveyard) void {
        std.crypto.secureZero(u8, self.buried.items);
        self.buried.deinit(self.child);
        for (self.graves.items) |grave| self.child.rawFree(grave.memory, grave.alignment, @returnAddress());
        self.graves.deinit(self.child);
    }

    /// No released block was written after its release.
    fn expectUntouched(self: *const Graveyard) !void {
        for (self.graves.items) |grave| if (std.mem.findNone(u8, grave.memory, &.{fill}) != null) return error.WrittenAfterRelease;
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Graveyard = @ptrCast(@alignCast(context));
        const memory = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        @memset(memory[0..len], 0);
        return memory;
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Graveyard = @ptrCast(@alignCast(context));
        if (new_len < memory.len or !self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        @memset(memory.ptr[memory.len..new_len], 0);
        return true;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, _: usize) void {
        const self: *Graveyard = @ptrCast(@alignCast(context));
        self.buried.appendSlice(self.child, memory) catch @panic("the graveyard is out of memory");
        @memset(memory, fill);
        self.graves.append(self.child, .{ .memory = memory, .alignment = alignment }) catch @panic("the graveyard is out of memory");
    }
};

/// An NSS key log sink: the caller's, holding what cloak hands it.
const Lines = struct {
    text: std.ArrayList(u8) = .empty,

    fn write(context: ?*anyopaque, line: []const u8) void {
        const self: *Lines = @ptrCast(@alignCast(context.?));
        self.text.appendSlice(std.testing.allocator, line) catch @panic("the key log is out of memory");
    }

    fn log(self: *Lines) Connection.KeyLog {
        return .{ .context = self, .write = write };
    }
};

/// The byte strings no released memory may hold.
const Needles = struct {
    const Needle = struct { bytes: [64]u8 = undefined, len: usize };
    list: std.ArrayList(Needle) = .empty,

    fn deinit(self: *Needles) void {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.list.items));
        self.list.deinit(std.testing.allocator);
    }

    fn add(self: *Needles, bytes: []const u8) !void {
        var needle: Needle = .{ .len = bytes.len };
        @memcpy(needle.bytes[0..bytes.len], bytes);
        try self.list.append(std.testing.allocator, needle);
    }

    /// A traffic secret with its record key and IV (and DTLS 1.3's sequence number key), and
    /// those of the next three generations a key update makes.
    fn traffic(self: *Needles, prefix: Labels.Prefix, secret: *const [32]u8, key_len: usize) !void {
        var current = secret.*;
        for (0..4) |_| {
            try self.add(&current);
            var key: [32]u8 = undefined;
            try Labels.expandWith(Sha256, prefix, key[0..key_len], &current, "key", "");
            try self.add(key[0..key_len]);
            var iv: [12]u8 = undefined;
            try Labels.expandWith(Sha256, prefix, &iv, &current, "iv", "");
            try self.add(&iv);
            if (prefix == .dtls13) {
                try Labels.expandWith(Sha256, prefix, key[0..key_len], &current, "sn", "");
                try self.add(key[0..key_len]);
            }
            var next: [32]u8 = undefined;
            try Labels.expandWith(Sha256, prefix, &next, &current, "traffic upd", "");
            current = next;
        }
    }

    /// Every secret of NSS key log lines: TLS 1.3's traffic secrets with their keys, the
    /// exporter secret, and TLS 1.2's master secret with its write keys when the server's random
    /// is known (SHA-256 suites).
    fn keyLog(self: *Needles, text: []const u8, prefix: Labels.Prefix, key_len: usize, server_random: ?*const [32]u8) !void {
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            var fields = std.mem.tokenizeScalar(u8, line, ' ');
            const label = fields.next().?;
            const random_hex = fields.next().?;
            var buffer: [48]u8 = undefined;
            const secret = try std.fmt.hexToBytes(&buffer, fields.next().?);
            if (std.mem.eql(u8, label, "CLIENT_RANDOM")) {
                try self.add(secret);
                const random = server_random orelse continue;
                var client_random: [32]u8 = undefined;
                _ = try std.fmt.hexToBytes(&client_random, random_hex);
                var block: [64]u8 = undefined;
                Prf.keyBlock(Sha256, block[0 .. 2 * key_len], secret[0..48], random, &client_random);
                try self.add(block[0..key_len]);
                try self.add(block[key_len .. 2 * key_len]);
            } else if (std.mem.endsWith(u8, label, "TRAFFIC_SECRET") or std.mem.endsWith(u8, label, "TRAFFIC_SECRET_0")) {
                try self.traffic(prefix, secret[0..32], key_len);
            } else try self.add(secret);
        }
    }

    fn expectAbsent(self: *const Needles, memory: []const u8, where: []const u8) !void {
        for (self.list.items, 0..) |needle, i| {
            if (std.mem.find(u8, memory, needle.bytes[0..needle.len])) |at| {
                std.debug.print("\nneedle {d} ({d} bytes) left in {s} at {d}\n", .{ i, needle.len, where, at });
                return error.SecretLeft;
            }
        }
    }
};

/// Released memory is searched only in the builds that ship (the ReleaseFast tier): with runtime
/// safety on, `Allocator.free` and `self.* = undefined` overwrite it before the allocator sees it,
/// so it would show nothing of what an owner left. The stack is searched in every build.
const heap_searched = !std.debug.runtime_safety;

/// The stack below a caller's frame as the calls it made left it: a frame at the depth of those
/// calls overlays theirs. What no owner names (by-value arguments and results, std's key
/// schedules and hash states, spills) is erased by the scrubbed kernels, so no secret may remain.
/// The buffer is taken before the calls, so taking it overwrites nothing of theirs.
const Stack = struct {
    const window = 512 * 1024;
    bytes: *[window]u8,

    fn init() !Stack {
        return .{ .bytes = try std.heap.page_allocator.create([window]u8) };
    }

    fn deinit(self: *Stack) void {
        std.crypto.secureZero(u8, self.bytes);
        std.heap.page_allocator.destroy(self.bytes);
    }

    noinline fn capture(self: *Stack) void {
        var below: [window]u8 = undefined;
        // The window's bytes are whatever the returned calls wrote: the compiler must read them.
        asm volatile (""
            :
            : [below] "r" (&below),
            : .{ .memory = true });
        @memcpy(self.bytes, &below);
    }
};

/// Where a stream connection's caller lets both ends go.
const Cut = enum { created, server_flight, client_flight, connected, updated, closed, tampered };

fn flipLast(bytes: []u8) void {
    bytes[bytes.len - 1] ^= 1;
}

/// A cloak client and server, released at `cut`: both connections, their credentials and the
/// harness itself come from the graveyard. Neither the stack nor released memory holds a secret.
fn releaseStream(options: Duo.Options, cut: Cut, key_len: usize) !void {
    var stack: Stack = try .init();
    defer stack.deinit();
    var grave: Graveyard = .{ .child = std.testing.allocator };
    defer grave.deinit();
    var logs: [2]Lines = .{ .{}, .{} };
    defer for (&logs) |*lines| lines.text.deinit(std.testing.allocator);
    var with_logs = options;
    with_logs.client_key_log = logs[0].log();
    with_logs.server_key_log = logs[1].log();
    var server_random: ?[32]u8 = null;
    {
        const duo = try Duo.init(grave.allocator(), with_logs);
        defer duo.deinit();
        script: {
            if (cut == .created) break :script;
            try duo.handshakeUntilServerFlight();
            server_random = duo.server.output()[11..43].*;
            if (cut == .server_flight) break :script;
            try duo.deliverServer();
            if (cut == .client_flight) break :script;
            try duo.handshake();
            if (cut == .connected) break :script;
            if (cut == .tampered) {
                _ = try duo.client.send("ping");
                if (duo.deliverEdited(&flipLast)) |_| return error.TamperedRecordTaken else |_| {}
                try std.testing.expect(duo.server.diagnostics().reason != null);
                break :script;
            }
            var buffer: [16]u8 = undefined;
            _ = try duo.echo(&duo.client, &duo.server, "ping", &buffer);
            _ = try duo.echo(&duo.server, &duo.client, "pong", &buffer);
            if (options.client_max == .tls13) {
                try duo.client.keyUpdate(true);
                try duo.pump();
                try duo.server.keyUpdate(false);
                try duo.pump();
                _ = try duo.echo(&duo.client, &duo.server, "ping", &buffer);
                _ = try duo.echo(&duo.server, &duo.client, "pong", &buffer);
            }
            if (cut == .updated) break :script;
            try duo.client.finish();
            try duo.pump();
            try duo.server.finish();
            try duo.pump();
        }
    }
    stack.capture();
    var needles: Needles = .{};
    defer needles.deinit();
    for (&logs) |*lines| try needles.keyLog(lines.text.items, .tls13, key_len, if (server_random) |*random| random else null);
    if (cut != .created and cut != .server_flight) try std.testing.expect(needles.list.items.len != 0);
    try needles.add(pki.p256_secret[0..32]);
    if (options.client_cert) try needles.add(pki.client_secret[0..32]);
    try needles.expectAbsent(stack.bytes, "the stack");
    if (heap_searched) try needles.expectAbsent(grave.buried.items, "released memory");
    try grave.expectUntouched();
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (streams: both ends released at every cut, TLS 1.3 and 1.2, leave no secret on the stack or in released memory)" {
    const configs = [_]struct { options: Duo.Options, key_len: usize }{
        .{ .options = .{ .client_suites = &.{.aes_128_gcm_sha256}, .client_auth = .required, .client_cert = true }, .key_len = 16 },
        .{ .options = .{ .client_suites = &.{.chacha20_poly1305_sha256} }, .key_len = 32 },
        .{ .options = .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_auth = .required, .client_cert = true }, .key_len = 16 },
    };
    for (configs) |config| {
        for (std.enums.values(Cut)) |cut| releaseStream(config.options, cut, config.key_len) catch |err| {
            std.debug.print("\n{t} released at {t}: {t}\n", .{ config.options.client_suites[0], cut, err });
            return err;
        };
    }
}

/// The keys of every epoch `dtls` holds: record keys, DTLS 1.3's sequence number keys and
/// traffic secrets, and full IVs (TLS 1.2 GCM's four-byte salt is too short to search for).
fn epochNeedles(needles: *Needles, dtls: *const Datagram) !void {
    for ([_]*const [3]?@import("dtls/Record.zig").Epoch{ &dtls.readers, &dtls.writers }) |slots| for (slots) |*slot| if (slot.*) |*epoch| {
        const key_len = epoch.cipher.keyLength();
        try needles.add(epoch.key.expose()[0..key_len]);
        if (epoch.version == .dtls13) {
            try needles.add(epoch.iv.expose());
            try needles.add(epoch.sn.expose()[0..key_len]);
            try needles.add(epoch.traffic.expose()[0..32]);
        } else if (epoch.cipher.fixedIvLength12() == 12) try needles.add(epoch.iv.expose());
    };
}

/// A DTLS client and server with client certificates, both released after `step` steps of the
/// handshake, or once connected, after an exchange each way: both ends, their credentials and the
/// harness come from the graveyard. Neither the stack nor released memory holds a secret. Whether
/// the run had steps left.
fn releaseDatagram(options: DatagramPair.Options, step: usize) !bool {
    var stack: Stack = try .init();
    defer stack.deinit();
    var grave: Graveyard = .{ .child = std.testing.allocator };
    defer grave.deinit();
    var logs: [2]Lines = .{ .{}, .{} };
    defer for (&logs) |*lines| lines.text.deinit(std.testing.allocator);
    var with_logs = options;
    with_logs.mutual = true;
    with_logs.client_key_log = logs[0].log();
    with_logs.server_key_log = logs[1].log();
    var needles: Needles = .{};
    defer needles.deinit();
    var more = true;
    {
        const pair = try DatagramPair.init(grave.allocator(), with_logs);
        defer pair.deinit();
        for (0..step) |_| if (!try pair.step()) break;
        if (!try pair.step()) {
            try pair.run();
            try pair.exchange(&pair.client, "ping");
            try pair.exchange(&pair.server, "pong");
            more = false;
        }
        try epochNeedles(&needles, &pair.client.dtls);
        if (pair.server_ready) try epochNeedles(&needles, &pair.server.dtls);
    }
    stack.capture();
    const prefix: Labels.Prefix = if (options.client_max == .tls13) .dtls13 else .tls13;
    for (&logs) |*lines| try needles.keyLog(lines.text.items, prefix, 16, null);
    try needles.add(pki.p256_secret[0..32]);
    try needles.add(pki.client_secret[0..32]);
    needles.expectAbsent(stack.bytes, "the stack") catch |err| {
        std.debug.print("\nDTLS {t} after step {d}\n", .{ options.client_max, step });
        return err;
    };
    if (heap_searched) needles.expectAbsent(grave.buried.items, "released memory") catch |err| {
        std.debug.print("\nDTLS {t} released after step {d}\n", .{ options.client_max, step });
        return err;
    };
    try grave.expectUntouched();
    return more;
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (DTLS 1.3: both ends released after every step leave no secret on the stack or in released memory)" {
    var step: usize = 0;
    while (try releaseDatagram(.{ .client_min = .tls13, .client_suites = &.{.aes_128_gcm_sha256}, .server_suites = &.{.aes_128_gcm_sha256} }, step)) step += 1;
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (DTLS 1.2: both ends released after every step leave no secret on the stack or in released memory)" {
    var step: usize = 0;
    while (try releaseDatagram(.{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }, step)) step += 1;
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (QUIC: both handshakes released after every step leave no secret on the stack or in released memory)" {
    var step: usize = 0;
    var done = false;
    while (!done) : (step += 1) {
        var stack: Stack = try .init();
        defer stack.deinit();
        var grave: Graveyard = .{ .child = std.testing.allocator };
        defer grave.deinit();
        var needles: Needles = .{};
        defer needles.deinit();
        {
            const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .mutual = true, .handshake_gpa = grave.allocator() });
            defer pair.deinit();
            for (0..step) |_| if (!try pair.step()) break;
            done = !try pair.step();
            for ([_]*const @TypeOf(pair.client){ &pair.client, &pair.server }) |side| {
                for (side.secrets.items) |secret| try needles.add(secret.bytes[0..secret.len]);
            }
        }
        stack.capture();
        try needles.add(pki.p256_secret[0..32]);
        try needles.add(pki.client_secret[0..32]);
        needles.expectAbsent(stack.bytes, "the stack") catch |err| {
            std.debug.print("\nQUIC after step {d}\n", .{step});
            return err;
        };
        if (heap_searched) needles.expectAbsent(grave.buried.items, "released memory") catch |err| {
            std.debug.print("\nQUIC released after step {d}\n", .{step});
            return err;
        };
        try grave.expectUntouched();
    }
}
