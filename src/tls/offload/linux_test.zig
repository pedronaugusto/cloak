//! A connection's directions on the running Linux kernel's record layer, over a loopback TCP
//! connection: the server's both directions offloaded, the client in software. What the kernel
//! takes decides what each test expects: a kernel that takes TLS 1.3 key updates (6.14 and
//! later) goes on under the next keys, one that does not ends the connection. A kernel without
//! the "tls" module skips these.
const std = @import("std");
const Duo = @import("../../testing/Duo.zig");
const Connection = @import("../Connection.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Keys = @import("Keys.zig");
const ktls = @import("linux.zig");

const linux = std.os.linux;
const gpa = std.testing.allocator;

fn check(rc: usize) !usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        else => |e| {
            std.debug.print("syscall failed: {s}\n", .{@tagName(e)});
            return error.Syscall;
        },
    };
}

/// A loopback TCP connection: the client's end and the server's.
const Tcp = struct {
    client: linux.fd_t,
    server: linux.fd_t,

    fn open() !Tcp {
        const listener: linux.fd_t = @intCast(try check(linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)));
        defer _ = linux.close(listener);
        var address: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        _ = try check(linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in)));
        _ = try check(linux.listen(listener, 1));
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        _ = try check(linux.getsockname(listener, @ptrCast(&address), &len));
        const client: linux.fd_t = @intCast(try check(linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0)));
        errdefer _ = linux.close(client);
        _ = try check(linux.connect(client, @ptrCast(&address), @sizeOf(linux.sockaddr.in)));
        const server: linux.fd_t = @intCast(try check(linux.accept4(listener, null, null, linux.SOCK.CLOEXEC)));
        return .{ .client = client, .server = server };
    }

    fn close(self: Tcp) void {
        _ = linux.close(self.client);
        _ = linux.close(self.server);
    }
};

fn writeAll(fd: linux.fd_t, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) at += try check(linux.write(fd, bytes[at..].ptr, bytes.len - at));
}

/// One record through the kernel with its record type (TLS_SET_RECORD_TYPE).
fn sendRecord(fd: linux.fd_t, record_type: u8, bytes: []const u8) !void {
    var control: [32]u8 align(8) = @splat(0);
    const header: *linux.cmsghdr = @ptrCast(&control);
    header.* = .{ .len = @sizeOf(linux.cmsghdr) + 1, .level = ktls.sol_tls, .type = ktls.set_record_type };
    control[@sizeOf(linux.cmsghdr)] = record_type;
    var iov = [_]std.posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    const msg: linux.msghdr_const = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &control, .controllen = std.mem.alignForward(usize, @sizeOf(linux.cmsghdr) + 1, @sizeOf(usize)), .flags = 0 };
    const n = try check(linux.sendmsg(fd, &msg, 0));
    if (n != bytes.len) return error.ShortSend;
}

const Received = struct { record_type: u8, bytes: []u8 };

/// What the kernel opened next, with its record type (TLS_GET_RECORD_TYPE).
fn receiveRecord(fd: linux.fd_t, buffer: []u8) !Received {
    var control: [32]u8 align(8) = @splat(0);
    var iov = [_]std.posix.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
    var msg: linux.msghdr = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
    const n = try check(linux.recvmsg(fd, &msg, 0));
    var record_type: u8 = 23;
    if (msg.controllen >= @sizeOf(linux.cmsghdr)) {
        const header: *const linux.cmsghdr = @ptrCast(&control);
        if (header.level == ktls.sol_tls and header.type == ktls.get_record_type) record_type = control[@sizeOf(linux.cmsghdr)];
    }
    return .{ .record_type = record_type, .bytes = buffer[0..n] };
}

/// The software client's output onto its socket.
fn flushClient(client: *Connection, fd: linux.fd_t) !void {
    const bytes = client.output();
    try writeAll(fd, bytes);
    client.acknowledge(bytes.len);
}

/// Reads the client's socket into the client until `want` bytes of plaintext are readable or
/// it fails; returns the plaintext.
fn clientReads(duo: *Duo, fd: linux.fd_t, want: usize, out: []u8) ![]u8 {
    var got: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (got < want) {
        while (duo.client.readable().len != 0) {
            const view = duo.client.readable();
            @memcpy(out[got..][0..view.len], view);
            got += view.len;
            duo.client.consume(view.len);
        }
        if (got >= want or duo.client.readClosed()) break;
        const n = try check(linux.read(fd, &buffer, buffer.len));
        if (n == 0) return error.EndOfStream;
        var at: usize = 0;
        while (at < n) {
            const used = try duo.client.receive(buffer[at..n]);
            at += used;
            if (used == 0) {
                if (duo.client.readable().len != 0) {
                    const view = duo.client.readable();
                    @memcpy(out[got..][0..view.len], view);
                    got += view.len;
                    duo.client.consume(view.len);
                } else try duo.serveClient();
            }
        }
    }
    return out[0..got];
}

/// The server's control records through its kernel, giving the kernel each key update's keys.
fn serverControl(duo: *Duo, socket: *ktls.Socket) !void {
    while (true) {
        if (duo.server.control()) |record| {
            try sendRecord(socket.fd, record.record_type, record.bytes);
            duo.server.acknowledgeControl();
        } else if (duo.server.offloadPending(.write)) {
            try duo.server.offload(.write, socket.installer());
        } else return;
    }
}

/// The server's application reads `want` bytes from the kernel; control records on the way go
/// to the connection.
fn serverReads(duo: *Duo, fd: linux.fd_t, want: usize, out: []u8) ![]u8 {
    var got: usize = 0;
    while (got < want) {
        const record = try receiveRecord(fd, out[got..]);
        if (record.record_type == 23) {
            if (record.bytes.len == 0) return error.EndOfStream;
            got += record.bytes.len;
        } else {
            var copy: [1 << 14]u8 = undefined;
            @memcpy(copy[0..record.bytes.len], record.bytes);
            try duo.server.receiveControl(record.record_type, copy[0..record.bytes.len]);
            try duo.serveServer();
            if (duo.server.readClosed()) break;
            if (duo.server.offloadPending(.read)) return out[0..got];
        }
    }
    return out[0..got];
}

var probed: ?ktls.Capabilities = null;

fn capabilities() ktls.Capabilities {
    if (probed == null) probed = ktls.probe();
    return probed.?;
}

fn run(suite: Suite) !void {
    const caps = capabilities();
    const version: Keys.Version = suite.version().?;
    const cipher = (Keys.Cipher.of(switch (suite) {
        .aes_128_gcm_sha256, .ecdhe_ecdsa_aes_128_gcm_sha256 => .aes_128_gcm,
        .aes_256_gcm_sha384, .ecdhe_ecdsa_aes_256_gcm_sha384 => .aes_256_gcm,
        .chacha20_poly1305_sha256, .ecdhe_ecdsa_chacha20_poly1305_sha256 => .chacha20_poly1305,
        else => .aes_128_ccm,
    })).?;
    if (!caps.supports(version, cipher, .read) or !caps.supports(version, cipher, .write)) return error.SkipZigTest;
    var duo = try Duo.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite} });
    defer duo.deinit();
    try duo.handshake();
    const tcp = try Tcp.open();
    defer tcp.close();
    var socket: ktls.Socket = .{ .fd = tcp.server };
    var out: [1 << 16]u8 = undefined;
    // A record each way in software over the socket, then both directions move.
    _ = try duo.client.send("soft");
    try flushClient(&duo.client, tcp.client);
    {
        var buffer: [64]u8 = undefined;
        const n = try check(linux.read(tcp.server, &buffer, buffer.len));
        _ = try duo.server.receive(buffer[0..n]);
        try std.testing.expectEqualSlices(u8, "soft", duo.server.readable());
        duo.server.consume(4);
    }
    try duo.server.offload(.read, socket.installer());
    try duo.server.offload(.write, socket.installer());
    try std.testing.expectEqual(@as(u64, if (version == .tls12) 2 else 1), try socket.records(.read));
    // Data both ways through the kernel.
    _ = try duo.client.send("hello kernel");
    try flushClient(&duo.client, tcp.client);
    try std.testing.expectEqualSlices(u8, "hello kernel", try serverReads(duo, tcp.server, 12, &out));
    try writeAll(tcp.server, "hello software");
    try std.testing.expectEqualSlices(u8, "hello software", try clientReads(duo, tcp.client, 14, &out));
    // sendfile through the kernel's write path: the file's bytes as they were when sent.
    {
        const fd: linux.fd_t = @intCast(try check(linux.memfd_create("cloak-ktls", 0)));
        defer _ = linux.close(fd);
        var content: [40000]u8 = undefined;
        for (&content, 0..) |*b, i| b.* = @truncate(i *% 7 +% (i >> 8));
        try writeAll(fd, &content);
        var offset: linux.off_t = 0;
        var sent: usize = 0;
        while (sent < content.len) sent += try check(linux.sendfile(tcp.server, fd, &offset, content.len - sent));
        // The file changes once sendfile returns: the records already hold what was sent
        // (the kernel's software path seals into records of its own; a NIC's zero-copy mode,
        // TLS_TX_ZEROCOPY_RO, is never asked for).
        var changed: [40000]u8 = @splat(0xee);
        var at: usize = 0;
        while (at < changed.len) at += try check(linux.pwrite(fd, changed[at..].ptr, changed.len - at, @intCast(at)));
        try std.testing.expectEqualSlices(u8, &content, try clientReads(duo, tcp.client, content.len, &out));
    }
    try duo.server.offloadRecords(.write, try socket.records(.write));
    try duo.server.offloadRecords(.read, try socket.records(.read));
    if (version == .tls13) {
        // The client updates its keys and asks the server to: the kernel stops at the
        // KeyUpdate, and takes the next read keys only if it has key updates.
        try duo.client.keyUpdate(true);
        try flushClient(&duo.client, tcp.client);
        _ = try serverReads(duo, tcp.server, 1, &out);
        try std.testing.expect(duo.server.offloadPending(.read));
        if (!caps.rekeys(.read)) {
            try std.testing.expectError(error.RekeyUnsupported, duo.server.offload(.read, socket.installer()));
            try std.testing.expectEqual(error.NoKeyUpdate, duo.server.diagnostics().reason.?);
            // The fatal alert still goes out under the write keys the kernel holds.
            try serverControl(duo, &socket);
            try std.testing.expectError(error.PeerAlert, clientReads(duo, tcp.client, 1, &out));
            return;
        }
        try duo.server.offload(.read, socket.installer());
        try std.testing.expectEqual(@as(u64, 0), try socket.records(.read));
        try serverControl(duo, &socket);
        try std.testing.expectEqual(@as(u64, 0), try socket.records(.write));
        _ = try duo.client.send("after the update");
        try flushClient(&duo.client, tcp.client);
        try std.testing.expectEqualSlices(u8, "after the update", try serverReads(duo, tcp.server, 16, &out));
        try writeAll(tcp.server, "answered");
        try std.testing.expectEqualSlices(u8, "answered", try clientReads(duo, tcp.client, 8, &out));
    }
    // The client's close_notify comes up as a control record; the server's goes down as one.
    try duo.client.finish();
    try flushClient(&duo.client, tcp.client);
    _ = try serverReads(duo, tcp.server, 1, &out);
    try std.testing.expect(duo.server.readClosed());
    try duo.server.finish();
    try serverControl(duo, &socket);
    _ = try clientReads(duo, tcp.client, 1, &out);
    try std.testing.expect(duo.client.readClosed());
}

test "C9 a key update of the server's own through the Linux kernel: the next keys, or the end where the kernel has none" {
    const caps = capabilities();
    if (!caps.supports(.tls13, .aes_128_gcm, .write)) return error.SkipZigTest;
    var duo = try Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .server_suites = &.{.aes_128_gcm_sha256} });
    defer duo.deinit();
    try duo.handshake();
    const tcp = try Tcp.open();
    defer tcp.close();
    var socket: ktls.Socket = .{ .fd = tcp.server };
    var out: [64]u8 = undefined;
    try duo.server.offload(.write, socket.installer());
    try writeAll(tcp.server, "before");
    try std.testing.expectEqualSlices(u8, "before", try clientReads(duo, tcp.client, 6, &out));
    try duo.server.keyUpdate(false);
    if (!caps.rekeys(.write)) {
        try std.testing.expectError(error.RekeyUnsupported, serverControl(duo, &socket));
        try std.testing.expectEqual(Connection.Phase.failed, duo.server.phase());
        try std.testing.expect(duo.server.control() == null);
        return;
    }
    try serverControl(duo, &socket);
    try writeAll(tcp.server, "after");
    try std.testing.expectEqualSlices(u8, "after", try clientReads(duo, tcp.client, 5, &out));
}

test "C9 the kernel probe: what this kernel's record layer takes" {
    const caps = capabilities();
    std.debug.print("\nC9 kTLS probe: TLS 1.2 read {d} write {d} ciphers, TLS 1.3 read {d} write {d}, key updates read {} write {}\n", .{
        caps.ciphers[0][0].count(), caps.ciphers[0][1].count(), caps.ciphers[1][0].count(), caps.ciphers[1][1].count(), caps.rekeys(.read), caps.rekeys(.write),
    });
    // A kernel with a record layer at all has its first cipher, AES-128-GCM for TLS 1.2 sends.
    var any = false;
    for (caps.ciphers) |per_version| for (per_version) |set| {
        any = any or set.count() != 0;
    };
    if (any) try std.testing.expect(caps.supports(.tls12, .aes_128_gcm, .write));
    // A key update needs the version that has one.
    if (caps.rekeys(.write)) try std.testing.expect(caps.supports(.tls13, .aes_128_gcm, .write));
}

test "C9 TLS 1.3 on the Linux kernel record layer, every cipher it has" {
    for ([_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256, .aes_128_ccm_sha256 }) |suite| {
        run(suite) catch |err| switch (err) {
            error.SkipZigTest => continue,
            else => return err,
        };
    }
}

test "C9 TLS 1.2 on the Linux kernel record layer, every cipher it has" {
    for ([_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_aes_128_ccm }) |suite| {
        run(suite) catch |err| switch (err) {
            error.SkipZigTest => continue,
            else => return err,
        };
    }
}

test "C7 record_size_limit through the Linux kernel: the kernel seals within the client's limit (TLS_TX_MAX_PAYLOAD_LEN)" {
    for ([_]Suite{ .aes_128_gcm_sha256, .ecdhe_ecdsa_aes_128_gcm_sha256 }) |suite| {
        const version: Keys.Version = suite.version().?;
        if (!capabilities().supports(version, .aes_128_gcm, .write)) return error.SkipZigTest;
        var duo = try Duo.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite}, .client_record_size_limit = 200 });
        defer duo.deinit();
        try duo.handshake();
        const tcp = try Tcp.open();
        defer tcp.close();
        var socket: ktls.Socket = .{ .fd = tcp.server };
        // A kernel before 6.18 has no payload limit: the keys stay in software.
        duo.server.offload(.write, socket.installer()) catch |err| switch (err) {
            error.Unsupported => return error.SkipZigTest,
            else => return err,
        };
        var message: [3000]u8 = undefined;
        for (&message, 0..) |*b, i| b.* = @truncate(i);
        try writeAll(tcp.server, &message);
        // Every record the kernel wrote: TLS 1.3's inner plaintext within 200 bytes and its tag;
        // TLS 1.2's 200 bytes of plaintext, its explicit nonce and its tag.
        var wire: [8192]u8 = undefined;
        var have: usize = 0;
        var records: usize = 0;
        var at: usize = 0;
        var plaintext: usize = 0;
        while (plaintext < message.len) {
            while (have - at < 5 or have - at < 5 + @as(usize, std.mem.readInt(u16, wire[at + 3 ..][0..2], .big))) {
                const n = try check(linux.read(tcp.client, wire[have..].ptr, wire.len - have));
                if (n == 0) return error.EndOfStream;
                have += n;
            }
            const len = std.mem.readInt(u16, wire[at + 3 ..][0..2], .big);
            try std.testing.expect(len <= @as(usize, if (version == .tls13) 200 + 16 else 200 + 8 + 16));
            plaintext += len - @as(usize, if (version == .tls13) 17 else 24);
            records += 1;
            at += 5 + len;
        }
        try std.testing.expect(records >= message.len / 200);
        var out: [4096]u8 = undefined;
        var fed: usize = 0;
        var got: usize = 0;
        while (fed < have) {
            fed += try duo.client.receive(wire[fed..have]);
            const view = duo.client.readable();
            @memcpy(out[got..][0..view.len], view);
            got += view.len;
            duo.client.consume(view.len);
        }
        try std.testing.expectEqualSlices(u8, &message, out[0..got]);
    }
}
