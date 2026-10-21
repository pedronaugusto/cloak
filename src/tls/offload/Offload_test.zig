//! A connection's directions moved to a kernel record layer (design section 8.2), against a
//! kernel the tests play (testing/Kernel.zig): the clean boundary, the keys and record numbers
//! handed over, control records both ways, key updates through the kernel and a kernel that
//! refuses them, and the record budget kept from the kernel's counts. The server end moves; the
//! client stays in software and checks every record with the keys it derived itself.
const std = @import("std");
const Duo = @import("../../testing/Duo.zig");
const Kernel = @import("../../testing/Kernel.zig");
const Connection = @import("../Connection.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Psk = @import("../handshake/Psk.zig");

const gpa = std.testing.allocator;

/// A handshake of the one suite listed, owned by the caller: a PSK suite's on a provisioned key,
/// the rest on the test certificate.
fn duoOptions(listed: *const [1]Suite) Duo.Options {
    const suite = listed[0];
    const Keys = struct {
        const psk: Psk.External = .{ .identity = "kernel", .secret = &@as([16]u8, @splat(0x4b)), .version = .tls12 };
        fn find(_: ?*anyopaque, _: Psk.Query) ?Psk.External {
            return psk;
        }
    };
    const psk = if (suite.tls12()) |s12| s12.authentication() == .psk else false;
    if (!psk) return .{ .client_suites = listed, .server_suites = listed };
    return .{ .client_suites = listed, .server_suites = listed, .client_psks = &.{Keys.psk}, .server_psk = .{ .find = Keys.find }, .server_psk_only = true, .client_verify_none = true };
}

/// A finished handshake, with the server's kernel.
const Setup = struct {
    duo: *Duo,
    kernel: Kernel = .{},

    fn init(suite: Suite, limits: Connection.Limits) !Setup {
        const listed: [1]Suite = .{suite};
        const duo = try Duo.init(gpa, duoOptions(&listed));
        errdefer duo.deinit();
        duo.server.limits = limits;
        try duo.handshake();
        return .{ .duo = duo };
    }

    fn deinit(self: *Setup) void {
        self.kernel.deinit();
        self.duo.deinit();
    }

    fn client(self: *Setup) *Connection {
        return &self.duo.client;
    }

    fn server(self: *Setup) *Connection {
        return &self.duo.server;
    }

    /// The client's output, one record at a time, into the server's kernel: application data
    /// must read `expect`, and control records go to the server.
    fn clientToKernel(self: *Setup, expect: []const u8) !void {
        const bytes = self.client().output();
        var at: usize = 0;
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(gpa);
        while (at < bytes.len) {
            const len = 5 + @as(usize, std.mem.readInt(u16, bytes[at + 3 ..][0..2], .big));
            const opened = try self.kernel.open(gpa, bytes[at..][0..len]);
            defer gpa.free(opened.bytes);
            at += len;
            if (opened.record_type == 23) {
                try data.appendSlice(gpa, opened.bytes);
            } else {
                try self.server().receiveControl(opened.record_type, opened.bytes);
                try self.duo.serveServer();
            }
        }
        self.client().acknowledge(bytes.len);
        try std.testing.expectEqualSlices(u8, expect, data.items);
    }

    /// The application writes `message` through the kernel; the client reads it.
    fn kernelToClient(self: *Setup, message: []const u8) !void {
        const wire = try self.kernel.seal(gpa, 23, message);
        defer gpa.free(wire);
        try self.deliver(wire);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(gpa);
        while (self.client().readable().len != 0) {
            const view = self.client().readable();
            try got.appendSlice(gpa, view);
            self.client().consume(view.len);
        }
        try std.testing.expectEqualSlices(u8, message, got.items);
    }

    /// The server's control records, sealed by its kernel, to the client; each key update's
    /// next keys go to the kernel when the connection says. Returns the record types sent.
    fn controlToClient(self: *Setup, types: []u8) ![]u8 {
        var n: usize = 0;
        while (true) {
            if (self.server().control()) |record| {
                const wire = try self.kernel.seal(gpa, record.record_type, record.bytes);
                defer gpa.free(wire);
                types[n] = record.record_type;
                n += 1;
                self.server().acknowledgeControl();
                try self.deliver(wire);
            } else if (self.server().offloadPending(.write)) {
                try self.server().offload(.write, self.kernel.installer());
            } else break;
        }
        return types[0..n];
    }

    fn deliver(self: *Setup, wire: []const u8) !void {
        var at: usize = 0;
        while (at < wire.len) {
            const n = try self.client().receive(wire[at..]);
            at += n;
            if (n == 0) try self.duo.serveClient();
        }
    }

    /// The client sends `message` in software.
    fn clientSends(self: *Setup, message: []const u8) !void {
        var at: usize = 0;
        while (at < message.len) at += try self.client().send(message[at..]);
    }
};

const tls13_suites = [_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256, .aes_128_ccm_sha256 };
const tls12_suites = [_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_aes_128_ccm, .psk_aes_128_ccm };

test "C9 both directions move to a kernel mid-stream, every suite a kernel runs, and data and close cross" {
    for (tls13_suites ++ tls12_suites) |suite| {
        var setup = try Setup.init(suite, .{});
        defer setup.deinit();
        // Records in software first, so the kernel starts at a record number past zero (past
        // the Finished too in TLS 1.2, which its application keys protect).
        var buf: [16]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "one", try setup.duo.echo(setup.client(), setup.server(), "one", &buf));
        try std.testing.expectEqualSlices(u8, "two", try setup.duo.echo(setup.server(), setup.client(), "two", &buf));
        const next: u64 = if (suite.version() == .tls12) 2 else 1;
        try setup.server().offload(.read, setup.kernel.installer());
        try std.testing.expectEqual(next, setup.kernel.last.?.sequence);
        try setup.server().offload(.write, setup.kernel.installer());
        try std.testing.expectEqual(next, setup.kernel.last.?.sequence);
        try std.testing.expect(setup.server().offloaded(.read) and setup.server().offloaded(.write));
        try std.testing.expectEqual(suite.version(), setup.kernel.last.?.version);
        // The handed-over keys are this connection's: the software peer opens what the kernel
        // seals, and the kernel opens what the peer seals.
        try setup.clientSends("three");
        try setup.clientToKernel("three");
        try setup.kernelToClient("four");
        // A close each way: the client's close_notify is a control record the kernel opens; the
        // server's goes out through the kernel.
        try setup.client().finish();
        try setup.clientToKernel("");
        try std.testing.expect(setup.server().readClosed());
        try setup.server().finish();
        var types: [4]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &.{21}, try setup.controlToClient(&types));
        try std.testing.expect(setup.client().readClosed());
        try std.testing.expectEqual(Connection.Phase.closed, setup.server().phase());
    }
}

test "F83 catalogue_ktls_partial_handoff_sequence_owner: a direction moves only at a clean boundary, whole, once" {
    var setup = try Setup.init(.aes_128_gcm_sha256, .{});
    defer setup.deinit();
    // Half a record read: the read keys stay, and the record completes in software.
    try setup.clientSends("partial");
    const bytes = setup.client().output();
    _ = try setup.server().receive(bytes[0..9]);
    try std.testing.expectError(error.Unclean, setup.server().offload(.read, setup.kernel.installer()));
    _ = try setup.server().receive(bytes[9..]);
    setup.client().acknowledge(bytes.len);
    // Plaintext not yet consumed: still not clean.
    try std.testing.expectError(error.Unclean, setup.server().offload(.read, setup.kernel.installer()));
    try std.testing.expectEqualSlices(u8, "partial", setup.server().readable());
    setup.server().consume(7);
    try std.testing.expectEqual(@as(usize, 0), setup.kernel.installs);
    // Output not yet acknowledged: the write keys stay.
    _ = try setup.server().send("queued");
    try std.testing.expectError(error.Unclean, setup.server().offload(.write, setup.kernel.installer()));
    var buf: [16]u8 = undefined;
    _ = try setup.duo.echo(setup.server(), setup.client(), "", &buf);
    try std.testing.expectEqualSlices(u8, "queued", setup.client().readable());
    setup.client().consume(6);
    // A kernel that refuses the keys leaves the direction in software, as it was.
    setup.kernel.refuse = error.Unsupported;
    try std.testing.expectError(error.Unsupported, setup.server().offload(.write, setup.kernel.installer()));
    try std.testing.expect(!setup.server().offloaded(.write));
    try std.testing.expectEqualSlices(u8, "still", try setup.duo.echo(setup.server(), setup.client(), "still", &buf));
    // Moved: the kernel numbers from where software stopped, and the keys are gone here.
    try setup.server().offload(.write, setup.kernel.installer());
    try std.testing.expectEqual(@as(u64, 2), setup.kernel.last.?.sequence);
    try std.testing.expectError(error.Offloaded, setup.server().offload(.write, setup.kernel.installer()));
    try setup.kernelToClient("kernel");
    try setup.server().offload(.read, setup.kernel.installer());
    try std.testing.expectEqual(@as(u64, 1), setup.kernel.last.?.sequence);
    try std.testing.expectError(error.Offloaded, setup.server().offload(.read, setup.kernel.installer()));
    try setup.clientSends("kernel too");
    try setup.clientToKernel("kernel too");
}

test "C9 a direction moves only once the handshake completes, and AES-256-CCM and CCM_8 stay in software" {
    for ([_]Suite{ .ecdhe_ecdsa_aes_256_ccm, .ecdhe_ecdsa_aes_128_ccm_8, .psk_aes_128_ccm_8 }) |suite| try staysInSoftware(suite);
}

fn staysInSoftware(suite: Suite) !void {
    const listed: [1]Suite = .{suite};
    var duo = try Duo.init(gpa, duoOptions(&listed));
    defer duo.deinit();
    var kernel: Kernel = .{};
    defer kernel.deinit();
    try std.testing.expectError(error.NotConnected, duo.server.offload(.read, kernel.installer()));
    try duo.handshake();
    try std.testing.expectError(error.Unsupported, duo.server.offload(.read, kernel.installer()));
    try std.testing.expectError(error.Unsupported, duo.server.offload(.write, kernel.installer()));
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "ccm256", try duo.echo(&duo.client, &duo.server, "ccm256", &buf));
}

test "C9 TLS 1.2 GCM keys carry the next record's number as the explicit nonce" {
    var setup = try Setup.init(.ecdhe_ecdsa_aes_128_gcm_sha256, .{});
    defer setup.deinit();
    var buf: [8]u8 = undefined;
    for (0..3) |_| _ = try setup.duo.echo(setup.server(), setup.client(), "x", &buf);
    try setup.server().offload(.write, setup.kernel.installer());
    // The Finished and three records.
    const last = setup.kernel.last.?;
    try std.testing.expectEqual(@as(u64, 4), last.sequence);
    try std.testing.expectEqual(@as(u64, 4), std.mem.readInt(u64, last.iv[4..12], .big));
}

test "C9 key updates both ways through a kernel that takes them" {
    for (tls13_suites) |suite| {
        var setup = try Setup.init(suite, .{});
        defer setup.deinit();
        try setup.server().offload(.read, setup.kernel.installer());
        try setup.server().offload(.write, setup.kernel.installer());
        // The peer updates and asks for an update: its KeyUpdate is a control record; the read
        // keys turn at once and wait for the kernel.
        try setup.client().keyUpdate(true);
        try setup.clientToKernel("");
        try std.testing.expect(setup.server().offloadPending(.read));
        try setup.server().offload(.read, setup.kernel.installer());
        try std.testing.expectEqual(@as(u64, 0), setup.kernel.last.?.sequence);
        try std.testing.expect(!setup.server().offloadPending(.read));
        try setup.clientSends("after");
        try setup.clientToKernel("after");
        // The answer goes out under the kernel's old keys, then the kernel takes the next.
        try std.testing.expect(setup.server().owes());
        var types: [4]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &.{22}, try setup.controlToClient(&types));
        try std.testing.expectEqual(@as(u64, 0), setup.kernel.records(.write));
        try setup.kernelToClient("answered");
        // An update of its own, with a close behind it: the close waits for the new keys.
        try setup.server().keyUpdate(false);
        try setup.server().finish();
        const first = setup.server().control().?;
        try std.testing.expectEqual(@as(u8, 22), first.record_type);
        const wire = try setup.kernel.seal(gpa, first.record_type, first.bytes);
        defer gpa.free(wire);
        try std.testing.expect(!setup.server().offloadPending(.write));
        setup.server().acknowledgeControl();
        try std.testing.expect(setup.server().offloadPending(.write));
        try std.testing.expect(setup.server().control() == null);
        try setup.deliver(wire);
        try std.testing.expectEqualSlices(u8, &.{21}, try setup.controlToClient(&types));
        try std.testing.expect(setup.client().readClosed());
    }
}

test "F84 catalogue_ktls_rekey_failure_and_sendfile_immutability: a kernel without key updates ends the connection, never reverting" {
    // The peer's KeyUpdate: the old read keys are gone, the kernel refuses the next ones, and
    // the connection fails with a fatal alert under the write keys the kernel still holds.
    {
        var setup = try Setup.init(.aes_128_gcm_sha256, .{});
        defer setup.deinit();
        setup.kernel.rekeys = false;
        try setup.server().offload(.read, setup.kernel.installer());
        try setup.server().offload(.write, setup.kernel.installer());
        try setup.client().keyUpdate(false);
        try setup.clientToKernel("");
        try std.testing.expectError(error.RekeyUnsupported, setup.server().offload(.read, setup.kernel.installer()));
        try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
        try std.testing.expectEqual(error.NoKeyUpdate, setup.server().diagnostics().reason.?);
        const alert = setup.server().control().?;
        try std.testing.expectEqual(@as(u8, 21), alert.record_type);
        try std.testing.expectEqual(@as(u8, 2), alert.bytes[0]);
        const wire = try setup.kernel.seal(gpa, alert.record_type, alert.bytes);
        defer gpa.free(wire);
        setup.server().acknowledgeControl();
        try std.testing.expect(setup.server().control() == null);
        try std.testing.expectError(error.PeerAlert, setup.client().receive(wire));
    }
    // Its own KeyUpdate sent: the peer reads under the next keys, the kernel keeps the old ones,
    // so nothing more goes out, the close behind it included.
    {
        var setup = try Setup.init(.aes_128_gcm_sha256, .{});
        defer setup.deinit();
        setup.kernel.rekeys = false;
        try setup.server().offload(.write, setup.kernel.installer());
        try setup.server().keyUpdate(false);
        try setup.server().finish();
        const update = setup.server().control().?;
        try std.testing.expectEqual(@as(u8, 22), update.record_type);
        const wire = try setup.kernel.seal(gpa, update.record_type, update.bytes);
        defer gpa.free(wire);
        setup.server().acknowledgeControl();
        try setup.deliver(wire);
        try std.testing.expect(setup.server().offloadPending(.write));
        try std.testing.expectError(error.RekeyUnsupported, setup.server().offload(.write, setup.kernel.installer()));
        try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
        try std.testing.expect(setup.server().control() == null);
    }
    // A KeyUpdate must be a record of its own: Linux stops reading after a record that starts
    // with one, and only there. Not alone, or a record that starts with its type but is
    // something else, ends the connection rather than leave the kernel stopped or reading on
    // under the old keys.
    {
        const records = [_][]const u8{
            &.{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 },
            &.{ 24, 0, 0, 2, 0, 0 },
            &.{ 24, 0, 0 },
        };
        for (records) |record| {
            var setup = try Setup.init(.aes_128_gcm_sha256, .{});
            defer setup.deinit();
            try setup.server().offload(.read, setup.kernel.installer());
            try std.testing.expectError(error.UnexpectedRecord, setup.server().receiveControl(22, record));
            try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
        }
    }
    // At a client: a NewSessionTicket and then a KeyUpdate in one record. Linux would not
    // stop at it and would go on opening under keys the peer has dropped.
    {
        var setup = try Setup.init(.aes_128_gcm_sha256, .{});
        defer setup.deinit();
        try setup.client().offload(.read, setup.kernel.installer());
        const ticket = [_]u8{ 4, 0, 0, 15, 0, 0, 0x0e, 0x10, 1, 2, 3, 4, 1, 0, 0, 1, 7, 0, 0 };
        try setup.client().receiveControl(22, &ticket);
        try setup.duo.serveClient();
        try std.testing.expectEqual(Connection.Phase.connected, setup.client().phase());
        try std.testing.expectError(error.UnexpectedRecord, setup.client().receiveControl(22, &ticket ++ [_]u8{ 24, 0, 0, 1, 0 }));
        try std.testing.expectEqual(Connection.Phase.failed, setup.client().phase());
    }
    // A record the kernel opened under the old keys after the peer's KeyUpdate is out of order.
    {
        var setup = try Setup.init(.aes_128_gcm_sha256, .{});
        defer setup.deinit();
        try setup.server().offload(.read, setup.kernel.installer());
        try setup.client().keyUpdate(false);
        try setup.clientToKernel("");
        try std.testing.expectError(error.UnexpectedRecord, setup.server().receiveControl(21, &.{ 1, 0 }));
        try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
    }
}

test "C9 the record budget follows the kernel's counts" {
    // TLS 1.3: a quarter of the limit left, the write keys update and the peer is asked to
    // update its own.
    {
        var setup = try Setup.init(.aes_128_gcm_sha256, .{ .records = 64 });
        defer setup.deinit();
        try setup.server().offload(.read, setup.kernel.installer());
        try setup.server().offload(.write, setup.kernel.installer());
        try std.testing.expectEqual(@as(u64, 16), setup.server().offloadInterval(.write));
        try setup.server().offloadRecords(.write, 40);
        try std.testing.expect(setup.server().control() == null);
        try setup.server().offloadRecords(.write, 48);
        const record = setup.server().control().?;
        try std.testing.expectEqual(@as(u8, 22), record.record_type);
        try std.testing.expectEqual(@as(u8, 0), record.bytes[4]);
        // The kernel took the next keys and counts from zero again.
        var types: [4]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &.{22}, try setup.controlToClient(&types));
        try setup.server().offloadRecords(.write, 10);
        try std.testing.expect(setup.server().control() == null);
        try setup.server().offloadRecords(.read, 48);
        const ask = setup.server().control().?;
        try std.testing.expectEqual(@as(u8, 1), ask.bytes[4]);
    }
    // TLS 1.2 has no key update: the connection ends there.
    {
        var setup = try Setup.init(.ecdhe_ecdsa_aes_128_gcm_sha256, .{ .records = 64 });
        defer setup.deinit();
        try setup.server().offload(.write, setup.kernel.installer());
        try std.testing.expectError(error.RecordLimit, setup.server().offloadRecords(.write, 48));
        try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
    }
}

test "C9 a TLS 1.2 client under a kernel refuses a HelloRequest with no_renegotiation through it" {
    var setup = try Setup.init(.ecdhe_ecdsa_aes_128_gcm_sha256, .{});
    defer setup.deinit();
    try setup.client().offload(.read, setup.kernel.installer());
    try setup.client().offload(.write, setup.kernel.installer());
    try setup.client().receiveControl(22, &.{ 0, 0, 0, 0 });
    const refusal = setup.client().control().?;
    try std.testing.expectEqual(@as(u8, 21), refusal.record_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 100 }, refusal.bytes);
    setup.client().acknowledgeControl();
    try std.testing.expectEqual(Connection.Phase.connected, setup.client().phase());
    // Closed for writing: a report of the kernel's count asks for nothing more.
    try setup.client().finish();
    _ = setup.client().control().?;
    setup.client().acknowledgeControl();
    try setup.client().offloadRecords(.write, (1 << 24) - 1);
    try std.testing.expect(setup.client().control() == null);
    try std.testing.expectEqual(Connection.Phase.connected, setup.client().phase());
}

test "C9 TLS 1.2 control records through a kernel: a warning passes, application data is no control record" {
    var setup = try Setup.init(.ecdhe_ecdsa_chacha20_poly1305_sha256, .{});
    defer setup.deinit();
    try setup.server().offload(.read, setup.kernel.installer());
    try setup.server().offload(.write, setup.kernel.installer());
    try setup.server().receiveControl(21, &.{ 1, 90 });
    try std.testing.expectEqual(Connection.Phase.connected, setup.server().phase());
    try std.testing.expectError(error.UnexpectedRecord, setup.server().receiveControl(23, "data"));
    try std.testing.expectEqual(Connection.Phase.failed, setup.server().phase());
}

test "C7 record_size_limit under a kernel: the write direction takes the peer's limit, a read direction under a lower own limit stays in software" {
    for ([_]Suite{ .aes_128_gcm_sha256, .ecdhe_ecdsa_aes_128_gcm_sha256 }) |suite| {
        const listed: [1]Suite = .{suite};
        var options = duoOptions(&listed);
        options.client_record_size_limit = 500;
        options.server_record_size_limit = 600;
        const duo = try Duo.init(gpa, options);
        defer duo.deinit();
        try duo.handshake();
        var kernel: Kernel = .{};
        defer kernel.deinit();
        try duo.server.offload(.write, kernel.installer());
        // TLS 1.3 counts the content type in the limit; the kernel's payload is the rest.
        const tls13 = suite.tls12() == null;
        try std.testing.expectEqual(@as(?u16, if (tls13) 499 else 500), kernel.last.?.max_payload);
        // The kernel opens up to 2^14 bytes whatever this end named: the read keys stay here.
        try std.testing.expectError(error.Unsupported, duo.server.offload(.read, kernel.installer()));
        try std.testing.expect(!duo.server.offloaded(.read));
    }
    // Under the version's maximum nothing is limited, and both directions move.
    const listed: [1]Suite = .{.aes_128_gcm_sha256};
    var plain = try Setup.init(listed[0], .{});
    defer plain.deinit();
    try plain.server().offload(.write, plain.kernel.installer());
    try std.testing.expectEqual(@as(?u16, null), plain.kernel.last.?.max_payload);
    try plain.server().offload(.read, plain.kernel.installer());
}
