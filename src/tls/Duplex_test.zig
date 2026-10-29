//! A session read by one task while another writes, both ends: the data crosses whole and in
//! order while key updates (asked for, answered and forced by low record limits) and a close in
//! one direction happen mid-stream. The hardened tier runs it under ThreadSanitizer.
const std = @import("std");
const tasks = @import("../testing/tasks.zig");
const certificates = @import("../certificates.zig");
const Session = @import("Session.zig");
const Server = @import("handshake/Server.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Pipe = @import("../testing/Pipe.zig");
const pki = @import("../testing/Peer.zig").pki;

/// Bytes each direction carries: enough records to cross the lowered key limits many times.
const volume = 1 << 20;
const chunk = 1000;

fn pattern(direction: u8, at: usize) u8 {
    return @truncate(at *% 131 +% direction *% 7 +% (at >> 9));
}

fn writeAll(session: *Session, direction: u8, update_every: usize) !void {
    var buffer: [chunk]u8 = undefined;
    var at: usize = 0;
    var updates: usize = 0;
    while (at < volume) {
        const n = @min(chunk, volume - at);
        for (buffer[0..n], at..) |*byte, i| byte.* = pattern(direction, i);
        try session.writer().writeAll(buffer[0..n]);
        at += n;
        if (update_every != 0 and at / update_every > updates) {
            updates = at / update_every;
            // Every other one asks the peer for new keys too.
            try session.keyUpdate(updates % 2 == 0);
        }
    }
    try session.writer().flush();
    // The close goes out while the other direction is still streaming.
    try session.finish();
}

fn readAll(session: *Session, direction: u8) !void {
    var buffer: [4096]u8 = undefined;
    var at: usize = 0;
    while (true) {
        const n = try session.reader().readSliceShort(&buffer);
        if (n == 0) break;
        for (buffer[0..n], at..) |byte, i| if (byte != pattern(direction, i)) return error.Corrupted;
        at += n;
    }
    if (at != volume) return error.ShortRead;
    if (!session.closeNotified()) return error.Truncated;
}

const End = struct {
    session: Session = undefined,
    read_buffer: [512]u8 = undefined,
    write_buffer: [512]u8 = undefined,
};

fn acceptAndRun(end: *End, io: std.Io, input: *std.Io.Reader, output: *std.Io.Writer, out_pipe: *Pipe, credentials: []const Server.Credential, suites: []const Suite, records: u64) !void {
    const gpa = std.testing.allocator;
    try end.session.accept(gpa, io, input, output, &end.read_buffer, &end.write_buffer, .{
        .credentials = credentials,
        .suites = suites,
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
        .limits = .{ .records = records },
    });
    defer out_pipe.close();
    try run(end, io, 2, 1, if (records < 1 << 24) 96 * 1024 else 0);
}

/// Reads `in_direction` on a task of its own while this task writes `out_direction`.
fn run(end: *End, io: std.Io, out_direction: u8, in_direction: u8, update_every: usize) !void {
    var reading = try io.concurrent(readAll, .{ &end.session, in_direction });
    errdefer tasks.reap(tasks.Result(readAll), io, &reading);
    try writeAll(&end.session, out_direction, update_every);
    try reading.await(io);
}

/// `records` lowers the key limits so that both ends update keys on their own as well as when
/// asked; TLS 1.2, which has no key update, keeps the default.
fn duplex(suites: []const Suite, update_every: usize, records: u64) !void {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};

    // client -> server and server -> client.
    var up_ring: [24 * 1024]u8 = undefined;
    var down_ring: [24 * 1024]u8 = undefined;
    var up_bufs: [2][4096]u8 = undefined;
    var down_bufs: [2][4096]u8 = undefined;
    var up: Pipe = undefined;
    up.init(io, &up_ring, &up_bufs[0], &up_bufs[1]);
    var down: Pipe = undefined;
    down.init(io, &down_ring, &down_bufs[0], &down_bufs[1]);

    var server: End = .{};
    var serving = try io.concurrent(acceptAndRun, .{ &server, io, &up.reader, &down.writer, &down, &credentials, suites, records });
    var client: End = .{};
    var opened = true;
    client.session.open(gpa, io, &down.reader, &up.writer, &client.read_buffer, &client.write_buffer, .{
        .identity = .{ .dns = "example.com" },
        .trust = .{ .snapshot = snapshot },
        .suites = suites,
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
        .limits = .{ .records = records },
    }) catch |err| {
        opened = false;
        up.close();
        down.close();
        tasks.reap(tasks.Result(acceptAndRun), io, &serving);
        return err;
    };
    defer client.session.deinit();
    const ran = run(&client, io, 1, 2, update_every);
    up.close();
    // A failed end must not leave the other blocked on a pipe nobody reads.
    if (std.meta.isError(ran)) down.close();
    const served = serving.await(io);
    if (opened) server.session.deinit();
    try ran;
    try served;
}

test "C4 concurrent reading and writing of a TLS 1.3 session, through key updates and a close mid-stream" {
    try duplex(Suite.tls13_only, 64 * 1024, 1500);
}

test "C4 concurrent reading and writing of a TLS 1.2 session, with a close mid-stream" {
    try duplex(&.{.ecdhe_ecdsa_aes_128_gcm_sha256}, 0, 1 << 24);
}

const ResumeEnd = struct {
    session: Session = undefined,
    read_buffer: [512]u8 = undefined,
    write_buffer: [512]u8 = undefined,
    resumed: bool = false,
};

fn serveOnce(end: *ResumeEnd, io: std.Io, input: *std.Io.Reader, output: *std.Io.Writer, out_pipe: *Pipe, credentials: []const Server.Credential, tickets: *Session.TicketKeys) !void {
    defer out_pipe.close();
    try end.session.accept(std.testing.allocator, io, input, output, &end.read_buffer, &end.write_buffer, .{
        .credentials = credentials,
        .tickets = tickets,
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
    });
    defer end.session.deinit();
    end.resumed = end.session.info().?.resumed;
    try end.session.writer().writeAll("hello");
    try end.session.writer().flush();
    try end.session.finish();
    var buffer: [16]u8 = undefined;
    while (try end.session.reader().readSliceShort(&buffer) != 0) {}
}

test "C5 sessions over std.Io resume: the client keeps the server's tickets as it reads" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    var cache = try Session.SessionCache.init(gpa, .{});
    defer cache.deinit();
    var tickets = try Session.TicketKeys.init(gpa, .{});
    defer tickets.deinit();
    var material: [32]u8 = undefined;
    io.random(&material);
    try tickets.rotate(&material, .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s));
    for (0..2) |round| {
        var up_ring: [24 * 1024]u8 = undefined;
        var down_ring: [24 * 1024]u8 = undefined;
        var up_bufs: [2][4096]u8 = undefined;
        var down_bufs: [2][4096]u8 = undefined;
        var up: Pipe = undefined;
        up.init(io, &up_ring, &up_bufs[0], &up_bufs[1]);
        var down: Pipe = undefined;
        down.init(io, &down_ring, &down_bufs[0], &down_bufs[1]);
        var server: ResumeEnd = .{};
        var serving = try io.concurrent(serveOnce, .{ &server, io, &up.reader, &down.writer, &down, &credentials, &tickets });
        var client: ResumeEnd = .{};
        client.session.open(gpa, io, &down.reader, &up.writer, &client.read_buffer, &client.write_buffer, .{
            .identity = .{ .dns = "example.com" },
            .trust = .{ .snapshot = snapshot },
            .resumption = .{ .cache = &cache },
            .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
        }) catch |err| {
            up.close();
            down.close();
            tasks.reap(tasks.Result(serveOnce), io, &serving);
            return err;
        };
        const resumed = client.session.info().?.resumed;
        var buffer: [16]u8 = undefined;
        const n = client.session.reader().readSliceShort(&buffer) catch |err| {
            client.session.deinit();
            up.close();
            tasks.reap(tasks.Result(serveOnce), io, &serving);
            return err;
        };
        client.session.finish() catch |err| {
            client.session.deinit();
            up.close();
            tasks.reap(tasks.Result(serveOnce), io, &serving);
            return err;
        };
        client.session.deinit();
        up.close();
        try serving.await(io);
        try std.testing.expectEqualSlices(u8, "hello", buffer[0..n]);
        try std.testing.expectEqual(round == 1, resumed);
        try std.testing.expectEqual(round == 1, server.resumed);
    }
}
