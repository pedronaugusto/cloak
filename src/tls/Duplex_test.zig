//! A session read by one task while another writes, both ends: the data crosses whole and in
//! order while key updates (asked for, answered and forced by low record limits) and a close in
//! one direction happen mid-stream. The hardened tier runs it under ThreadSanitizer.
const std = @import("std");
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
    errdefer _ = reading.cancel(io) catch {}; // glint-ignore: Z026 -- a test already failing reaps its reader
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
        _ = serving.cancel(io) catch {}; // glint-ignore: Z026 -- the handshake already failed; the server's end of it is reaped
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
