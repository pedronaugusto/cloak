//! FreeBSD's kernel record layer (design C9.1): the `struct tls_enable` a direction's keys
//! become and the write direction's count from bytes, on every OS; on FreeBSD the running
//! kernel's probe and installs, and a connection's records through it over a loopback TCP
//! connection: the server's both directions in the kernel, the client in software, each
//! checking the other's bytes. A kernel without ktls skips these.
const std = @import("std");
const builtin = @import("builtin");
const Duo = @import("../../testing/Duo.zig");
const Connection = @import("../Connection.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Keys = @import("Keys.zig");
const ktls = @import("freebsd.zig");

const c = std.c;
const gpa = std.testing.allocator;

fn keysOf(version: Keys.Version, cipher: Keys.Cipher, sequence: u64) Keys {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i + 1);
    var iv: [12]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast(0xa0 + i);
    return .{ .version = version, .cipher = cipher, .key = .init(key), .iv = .init(iv), .sequence = sequence };
}

test "C9.1 a tls_enable carries the cipher's key, the IV its version takes and the next record's number" {
    const cases = [_]struct { version: Keys.Version, cipher: Keys.Cipher, algorithm: c_int, key_len: c_int, iv_len: c_int, minor: u8 }{
        .{ .version = .tls13, .cipher = .aes_128_gcm, .algorithm = 25, .key_len = 16, .iv_len = 12, .minor = 4 },
        .{ .version = .tls13, .cipher = .aes_256_gcm, .algorithm = 25, .key_len = 32, .iv_len = 12, .minor = 4 },
        .{ .version = .tls13, .cipher = .chacha20_poly1305, .algorithm = 41, .key_len = 32, .iv_len = 12, .minor = 4 },
        // TLS 1.2 GCM: the salt alone; FreeBSD makes the explicit nonce.
        .{ .version = .tls12, .cipher = .aes_128_gcm, .algorithm = 25, .key_len = 16, .iv_len = 4, .minor = 3 },
        .{ .version = .tls12, .cipher = .aes_256_gcm, .algorithm = 25, .key_len = 32, .iv_len = 4, .minor = 3 },
        .{ .version = .tls12, .cipher = .chacha20_poly1305, .algorithm = 41, .key_len = 32, .iv_len = 12, .minor = 3 },
    };
    for (cases) |case| {
        var keys = keysOf(case.version, case.cipher, 0x0102030405060708);
        defer keys.deinit();
        const enable = ktls.TlsEnable.of(&keys).?;
        try std.testing.expectEqual(case.algorithm, enable.cipher_algorithm);
        try std.testing.expectEqual(case.key_len, enable.cipher_key_len);
        try std.testing.expectEqual(case.iv_len, enable.iv_len);
        try std.testing.expectEqual(@as(c_int, 0), enable.auth_algorithm);
        try std.testing.expectEqual(@as(c_int, 0), enable.auth_key_len);
        try std.testing.expectEqual(@as(c_int, 0), enable.flags);
        try std.testing.expectEqual(@as(u8, 3), enable.tls_vmajor);
        try std.testing.expectEqual(case.minor, enable.tls_vminor);
        try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &enable.rec_seq);
        try std.testing.expectEqualSlices(u8, keys.keyBytes(), enable.cipher_key[0..@intCast(enable.cipher_key_len)]);
        try std.testing.expectEqualSlices(u8, keys.iv.expose()[0..@intCast(enable.iv_len)], enable.iv[0..@intCast(enable.iv_len)]);
    }
    // FreeBSD has no CCM.
    var ccm = keysOf(.tls13, .aes_128_ccm, 0);
    defer ccm.deinit();
    try std.testing.expect(ktls.TlsEnable.of(&ccm) == null);
}

test "C9.1 the write direction's count from bytes: ceil(2n / 1025) full-size records" {
    try std.testing.expectEqual(@as(u64, 0), Keys.equivalentRecords(0));
    // A one-byte record costs 2 of σ + q, under one full record's 1025.
    try std.testing.expectEqual(@as(u64, 1), Keys.equivalentRecords(1));
    try std.testing.expectEqual(@as(u64, 1), Keys.equivalentRecords(512));
    try std.testing.expectEqual(@as(u64, 2), Keys.equivalentRecords(513));
    // A full-size record's bytes count as 32 records: the bound is sound for any framing.
    try std.testing.expectEqual(@as(u64, 32), Keys.equivalentRecords(1 << 14));
    // About 6.4 GB reach three quarters of 2^24.
    try std.testing.expectEqual(@as(u64, 3 << 22), Keys.equivalentRecords((3 << 22) * 1025 / 2));
    try std.testing.expectEqual(@as(u64, (2 * @as(u128, std.math.maxInt(u64)) + 1024) / 1025), Keys.equivalentRecords(std.math.maxInt(u64)));
}

test "C9.1 the kernel probe: what this FreeBSD kernel's record layer takes, keys once a direction" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    const caps = ktls.probe();
    var any = false;
    for ([_]Keys.Version{ .tls12, .tls13 }) |version| for (std.enums.values(Keys.Cipher)) |cipher| for ([_]Keys.Direction{ .read, .write }) |direction| {
        const takes = caps.supports(version, cipher, direction);
        any = any or takes;
        std.debug.print("ktls {s} {s} {s}: {}\n", .{ @tagName(version), @tagName(cipher), @tagName(direction), takes });
        // No CCM in FreeBSD's kernel.
        if (cipher == .aes_128_ccm) try std.testing.expect(!takes);
    };
    if (!any) return error.SkipZigTest;
    // Keys go in once: no TLS 1.3 key update.
    try std.testing.expect(!caps.rekeys(.read));
    try std.testing.expect(!caps.rekeys(.write));
}

test "C9.1 a record size limit keeps FreeBSD's write direction in software" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    var keys = keysOf(.tls13, .aes_128_gcm, 0);
    defer keys.deinit();
    keys.max_payload = 1024;
    // Refused before any socket call: the descriptor is never used.
    const socket: ktls.Socket = .{ .fd = -1 };
    try std.testing.expectError(error.Unsupported, socket.install(.write, &keys));
}

fn check(rc: anytype) !usize {
    if (rc < 0) {
        std.debug.print("syscall failed: {t}\n", .{c.errno(rc)});
        return error.Syscall;
    }
    return @intCast(rc);
}

/// A loopback TCP connection: the client's end and the server's.
const Tcp = struct {
    client: c.fd_t,
    server: c.fd_t,

    fn open() !Tcp {
        const listener: c.fd_t = @intCast(try check(c.socket(c.AF.INET, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0)));
        defer _ = c.close(listener);
        var address: c.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        _ = try check(c.bind(listener, @ptrCast(&address), @sizeOf(c.sockaddr.in)));
        _ = try check(c.listen(listener, 1));
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        _ = try check(c.getsockname(listener, @ptrCast(&address), &len));
        const client: c.fd_t = @intCast(try check(c.socket(c.AF.INET, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0)));
        errdefer _ = c.close(client);
        _ = try check(c.connect(client, @ptrCast(&address), @sizeOf(c.sockaddr.in)));
        const server: c.fd_t = @intCast(try check(c.accept4(listener, null, null, c.SOCK.CLOEXEC)));
        return .{ .client = client, .server = server };
    }

    fn close(self: Tcp) void {
        _ = c.close(self.client);
        _ = c.close(self.server);
    }
};

fn writeAll(fd: c.fd_t, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) at += try check(c.write(fd, bytes[at..].ptr, bytes.len - at));
}

/// A control message's data: after FreeBSD's 12-byte header, at the next pointer boundary
/// (sys/socket.h's CMSG_DATA).
const cmsg_data = std.mem.alignForward(usize, @sizeOf(c.cmsghdr), @sizeOf(usize));

/// One record through the kernel with its record type (TLS_SET_RECORD_TYPE).
fn sendRecord(fd: c.fd_t, record_type: u8, bytes: []const u8) !void {
    var control: [cmsg_data + @sizeOf(usize)]u8 align(@alignOf(usize)) = @splat(0);
    const header: *c.cmsghdr = @ptrCast(&control);
    header.* = .{ .len = cmsg_data + 1, .level = c.IPPROTO.TCP, .type = ktls.set_record_type };
    control[cmsg_data] = record_type;
    var iov = [_]c.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    const msg: c.msghdr_const = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
    if (try check(c.sendmsg(fd, &msg, 0)) != bytes.len) return error.ShortSend;
}

const Received = struct { record_type: u8, bytes: []u8 };

/// The next record the kernel opened: its plaintext and its type, from the TLS_GET_RECORD
/// control message (`struct tls_get_record`, the type first) every record carries.
fn receiveRecord(fd: c.fd_t, buffer: []u8) !Received {
    var control: [64]u8 align(@alignOf(usize)) = @splat(0);
    var iov = [_]c.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
    var msg: c.msghdr = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
    const n = try check(c.recvmsg(fd, &msg, 0));
    if (n == 0 and msg.controllen == 0) return error.EndOfStream;
    const header: *const c.cmsghdr = @ptrCast(&control);
    if (msg.controllen < cmsg_data + 1 or header.level != c.IPPROTO.TCP or header.type != ktls.get_record_type) return error.NoRecordType;
    return .{ .record_type = control[cmsg_data], .bytes = buffer[0..n] };
}

/// The software client's output onto its socket.
fn flushClient(client: *Connection, fd: c.fd_t) !void {
    const bytes = client.output();
    try writeAll(fd, bytes);
    client.acknowledge(bytes.len);
}

/// The client's application data in records of at most 2^14 bytes, as it seals them.
fn clientSends(duo: *Duo, fd: c.fd_t, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) {
        at += try duo.client.send(bytes[at..]);
        try flushClient(&duo.client, fd);
    }
}

/// The client's end of the wire: what it has read and not yet given the client.
const ClientEnd = struct {
    fd: c.fd_t,
    /// What a record adds to its plaintext on the wire: TLS 1.3's inner type and tag; TLS
    /// 1.2's tag, and GCM's explicit nonce.
    overhead: usize,
    wire: [1 << 16]u8 = undefined,
    have: usize = 0,

    /// Reads whole records until `want` bytes of plaintext have come out of the client or its
    /// read side has closed; each record's plaintext length goes to `lengths`.
    fn read(self: *ClientEnd, duo: *Duo, want: usize, out: []u8, lengths: *std.ArrayList(usize)) ![]u8 {
        var got: usize = 0;
        while (got < want and !duo.client.readClosed()) {
            while (self.have < 5 or self.have < 5 + @as(usize, std.mem.readInt(u16, self.wire[3..5], .big))) {
                const n = try check(c.read(self.fd, self.wire[self.have..].ptr, self.wire.len - self.have));
                if (n == 0) return error.EndOfStream;
                self.have += n;
            }
            const len = 5 + @as(usize, std.mem.readInt(u16, self.wire[3..5], .big));
            try lengths.append(gpa, len - 5 - self.overhead);
            var fed: usize = 0;
            while (fed < len) {
                const used = try duo.client.receive(self.wire[fed..len]);
                fed += used;
                while (duo.client.readable().len != 0) {
                    const view = duo.client.readable();
                    @memcpy(out[got..][0..view.len], view);
                    got += view.len;
                    duo.client.consume(view.len);
                }
                if (used == 0) try duo.serveClient();
            }
            @memmove(self.wire[0 .. self.have - len], self.wire[len..self.have]);
            self.have -= len;
        }
        return out[0..got];
    }
};

/// The server's control records through its kernel.
fn serverControl(duo: *Duo, fd: c.fd_t) !void {
    while (duo.server.control()) |record| {
        try sendRecord(fd, record.record_type, record.bytes);
        duo.server.acknowledgeControl();
    }
}

/// The server's application reads `want` bytes from the kernel, a record a `recvmsg`, each
/// record's length to `lengths`; control records on the way go to the connection.
fn serverReads(duo: *Duo, fd: c.fd_t, want: usize, out: []u8, lengths: *std.ArrayList(usize)) ![]u8 {
    var got: usize = 0;
    while (got < want) {
        const record = try receiveRecord(fd, out[got..]);
        if (record.record_type == 23) {
            try lengths.append(gpa, record.bytes.len);
            got += record.bytes.len;
        } else {
            var copy: [1 << 14]u8 = undefined;
            @memcpy(copy[0..record.bytes.len], record.bytes);
            try duo.server.receiveControl(record.record_type, copy[0..record.bytes.len]);
            try duo.serveServer();
            if (duo.server.readClosed() or duo.server.offloadPending(.read)) break;
        }
    }
    return out[0..got];
}

/// A handshake in software, a record each way in software over the socket, then the server's
/// both directions in the kernel at the next record numbers.
fn connect(duo: *Duo, tcp: Tcp, socket: *ktls.Socket) !void {
    try duo.handshake();
    var buffer: [256]u8 = undefined;
    try clientSends(duo, tcp.client, "soft");
    var n = try check(c.read(tcp.server, &buffer, buffer.len));
    _ = try duo.server.receive(buffer[0..n]);
    try std.testing.expectEqualSlices(u8, "soft", duo.server.readable());
    duo.server.consume(4);
    _ = try duo.server.send("soft back");
    try flushClient(&duo.server, tcp.server);
    n = try check(c.read(tcp.client, &buffer, buffer.len));
    _ = try duo.client.receive(buffer[0..n]);
    try std.testing.expectEqualSlices(u8, "soft back", duo.client.readable());
    duo.client.consume(9);
    try duo.server.offload(.read, &socket.installer);
    try duo.server.offload(.write, &socket.installer);
}

fn cipherOf(suite: Suite) Keys.Cipher {
    return switch (suite) {
        .aes_128_gcm_sha256, .ecdhe_ecdsa_aes_128_gcm_sha256 => .aes_128_gcm,
        .aes_256_gcm_sha384, .ecdhe_ecdsa_aes_256_gcm_sha384 => .aes_256_gcm,
        else => .chacha20_poly1305,
    };
}

/// The sizes each direction carries: a byte, a typical record, a full 2^14-byte record and one
/// byte past it, which takes two.
const sizes = [_]usize{ 1, 1200, 1 << 14, (1 << 14) + 1 };

fn records(size: usize) []const usize {
    return switch (size) {
        1 << 14 => &.{1 << 14},
        (1 << 14) + 1 => &.{ 1 << 14, 1 },
        else => &.{size},
    };
}

fn run(suite: Suite) !void {
    const version: Keys.Version = suite.version().?;
    const cipher = cipherOf(suite);
    const caps = ktls.probe();
    if (!caps.supports(version, cipher, .read) or !caps.supports(version, cipher, .write)) return error.SkipZigTest;
    var duo = try Duo.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite} });
    defer duo.deinit();
    const tcp = try Tcp.open();
    defer tcp.close();
    var socket: ktls.Socket = .{ .fd = tcp.server };
    try connect(duo, tcp, &socket);
    var client_end: ClientEnd = .{ .fd = tcp.client, .overhead = if (version == .tls13) 17 else if (cipher == .chacha20_poly1305) 16 else 24 };
    var message: [(1 << 14) + 1]u8 = undefined;
    var out: [1 << 16]u8 = undefined;
    var lengths: std.ArrayList(usize) = .empty;
    defer lengths.deinit(gpa);
    for (sizes, 0..) |size, round| {
        for (message[0..size], 0..) |*b, i| b.* = @truncate(i *% 31 +% round);
        // The client's records, opened by the kernel: one a recvmsg, each whole.
        lengths.clearRetainingCapacity();
        try clientSends(duo, tcp.client, message[0..size]);
        try std.testing.expectEqualSlices(u8, message[0..size], try serverReads(duo, tcp.server, size, &out, &lengths));
        try std.testing.expectEqualSlices(usize, records(size), lengths.items);
        // The kernel's records, sealed from a write of the server's plaintext and opened by the
        // client: within 2^14 bytes each, a full one at 2^14.
        lengths.clearRetainingCapacity();
        for (message[0..size]) |*b| b.* +%= 1;
        try writeAll(tcp.server, message[0..size]);
        try std.testing.expectEqualSlices(u8, message[0..size], try client_end.read(duo, size, &out, &lengths));
        try std.testing.expectEqualSlices(usize, records(size), lengths.items);
    }
    // The client's close_notify comes up as an alert record; the server's goes down as one.
    try duo.client.finish();
    try flushClient(&duo.client, tcp.client);
    _ = try serverReads(duo, tcp.server, 1, &out, &lengths);
    try std.testing.expect(duo.server.readClosed());
    try duo.server.finish();
    try serverControl(duo, tcp.server);
    _ = try client_end.read(duo, 1, &out, &lengths);
    try std.testing.expect(duo.client.readClosed());
    try std.testing.expect(duo.client.diagnostics().alert_received.? == .close_notify);
}

test "C9.1 TLS 1.3 through FreeBSD's kernel record layer, every cipher it has: records of 1, 1200, 2^14 and 2^14 + 1 bytes each way, then close_notify" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    var ran: usize = 0;
    for ([_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        run(suite) catch |err| switch (err) {
            error.SkipZigTest => continue,
            else => return err,
        };
        ran += 1;
    }
    if (ran == 0) return error.SkipZigTest;
}

test "C9.1 TLS 1.2 through FreeBSD's kernel record layer, every cipher it has: records of 1, 1200, 2^14 and 2^14 + 1 bytes each way, then close_notify" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    var ran: usize = 0;
    for ([_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256 }) |suite| {
        run(suite) catch |err| switch (err) {
            error.SkipZigTest => continue,
            else => return err,
        };
        ran += 1;
    }
    if (ran == 0) return error.SkipZigTest;
}

test "C9.1 a KeyUpdate under FreeBSD's kernel, which takes keys once: the peer's ends the connection with an alert the kernel seals; its own is refused and the close goes out" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    if (!ktls.probe().supports(.tls13, .aes_128_gcm, .read)) return error.SkipZigTest;
    var out: [1 << 16]u8 = undefined;
    var lengths: std.ArrayList(usize) = .empty;
    defer lengths.deinit(gpa);
    // The peer's: the kernel opens the KeyUpdate and refuses the next read keys.
    {
        var duo = try Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .server_suites = &.{.aes_128_gcm_sha256} });
        defer duo.deinit();
        const tcp = try Tcp.open();
        defer tcp.close();
        var socket: ktls.Socket = .{ .fd = tcp.server };
        try connect(duo, tcp, &socket);
        var client_end: ClientEnd = .{ .fd = tcp.client, .overhead = 17 };
        try duo.client.keyUpdate(false);
        try flushClient(&duo.client, tcp.client);
        _ = try serverReads(duo, tcp.server, 1, &out, &lengths);
        try std.testing.expect(duo.server.offloadPending(.read));
        try std.testing.expectError(error.RekeyUnsupported, duo.server.offload(.read, &socket.installer));
        try std.testing.expectEqual(Connection.Phase.failed, duo.server.phase());
        try std.testing.expectEqual(error.NoKeyUpdate, duo.server.diagnostics().reason.?);
        try serverControl(duo, tcp.server);
        try std.testing.expectError(error.PeerAlert, client_end.read(duo, 1, &out, &lengths));
    }
    // Its own: refused before anything goes out; the close goes out under the kernel's keys.
    {
        var duo = try Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .server_suites = &.{.aes_128_gcm_sha256} });
        defer duo.deinit();
        const tcp = try Tcp.open();
        defer tcp.close();
        var socket: ktls.Socket = .{ .fd = tcp.server };
        try connect(duo, tcp, &socket);
        var client_end: ClientEnd = .{ .fd = tcp.client, .overhead = 17 };
        try std.testing.expectError(error.NoKeyUpdate, duo.server.keyUpdate(false));
        try std.testing.expectEqual(Connection.Phase.connected, duo.server.phase());
        try duo.server.finish();
        try serverControl(duo, tcp.server);
        _ = try client_end.read(duo, 1, &out, &lengths);
        try std.testing.expect(duo.client.diagnostics().alert_received.? == .close_notify);
    }
}
