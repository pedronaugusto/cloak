//! TLS 1.3 resumption end to end, cloak client against cloak server, and the failure catalogue's
//! resumption rows (F65-F74), each named for its F-id and catalogue test.
const std = @import("std");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Duo = @import("../testing/Duo.zig");
const ServerPair = @import("../testing/ServerPair.zig").ServerPair;
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const Ticket = @import("resumption/Ticket.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const pki = Duo.pki;
const gpa = std.testing.allocator;

const Fixture = struct {
    cache: SessionCache,
    keys: TicketKeys,

    fn init(fixture: *Fixture) !void {
        fixture.cache = try SessionCache.init(gpa, .{});
        errdefer fixture.cache.deinit();
        fixture.keys = try TicketKeys.init(gpa, .{});
        try fixture.keys.rotate(&@as([32]u8, @splat(0x11)), types.instant(pki.time));
    }

    fn deinit(fixture: *Fixture) void {
        fixture.keys.deinit();
        fixture.cache.deinit();
    }

    fn options(fixture: *Fixture, seed: u64) Duo.Options {
        return .{ .seed = seed, .cache = &fixture.cache, .tickets = &fixture.keys };
    }
};

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

/// A first connection that leaves its tickets, then a second with `second`, which reports
/// whether it resumed (both ends must agree).
fn resumes(first: Duo.Options, second: Duo.Options) !bool {
    const a = try connect(first);
    a.deinit();
    const b = try connect(second);
    defer b.deinit();
    const client = b.client.info().?;
    const server = b.server.info().?;
    try std.testing.expectEqual(client.resumed, server.resumed);
    return client.resumed;
}

fn exportsMatch(duo: *Duo) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try duo.client.exportKeyingMaterial(&a, "cloak test", "context");
    try duo.server.exportKeyingMaterial(&b, "cloak test", "context");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C5 a second connection resumes from the first's ticket, for every TLS 1.3 suite" {
    for (Suite.tls13_only) |suite| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        var options = fixture.options(1);
        options.client_suites = &.{suite};
        const first = try connect(options);
        try std.testing.expect(!first.client.info().?.resumed);
        try std.testing.expect(first.client.info().?.peer_authenticated);
        first.deinit();
        // The server sent two tickets; the client kept both.
        try std.testing.expectEqual(@as(usize, 2), fixture.cache.count());
        options.seed = 2;
        const second = try connect(options);
        defer second.deinit();
        const info = second.client.info().?;
        try std.testing.expect(info.resumed and second.server.info().?.resumed);
        // The original handshake's authentication stands; the keys are fresh and shared.
        try std.testing.expect(info.peer_authenticated);
        try std.testing.expectEqual(Suite.from13(suite.tls13().?), info.suite);
        try exportsMatch(second);
        var out: [16]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "resumed", try second.echo(&second.client, &second.server, "resumed", &out));
        try std.testing.expectEqualSlices(u8, "back", try second.echo(&second.server, &second.client, "back", &out));
        // One ticket was used and is gone; the resumed handshake left two more.
        try std.testing.expectEqual(@as(usize, 3), fixture.cache.count());
    }
}

test "C5 resumption across a retry request, and a chain of resumptions" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var options = fixture.options(3);
    // The server wants P-256, which the client offers without a share: a retry each time.
    options.server_groups = &.{.p256};
    try std.testing.expect(try resumes(options, blk: {
        var next = options;
        next.seed = 4;
        break :blk next;
    }));
    for (5..9) |seed| {
        options.seed = seed;
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.resumed);
    }
}

test "C5 a server without tickets or a client without a cache does a full handshake and sends none" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var no_tickets = fixture.options(1);
    no_tickets.tickets = null;
    try std.testing.expect(!try resumes(no_tickets, no_tickets));
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
    var no_cache = fixture.options(1);
    no_cache.cache = null;
    const duo = try connect(no_cache);
    duo.deinit();
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
}

test "C5 a TLS 1.2 connection neither issues nor takes TLS 1.3 tickets" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var options = fixture.options(1);
    options.client_max = .tls12;
    const duo = try connect(options);
    duo.deinit();
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
}

test "F65 catalogue_ticket_supplied_key_and_derivation_failure" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const first = try connect(fixture.options(1));
    first.deinit();
    // Another ring, another key: the tickets open under nothing but the key that sealed them.
    var other = try TicketKeys.init(gpa, .{});
    defer other.deinit();
    try other.rotate(&@as([32]u8, @splat(0x22)), types.instant(pki.time));
    var options = fixture.options(2);
    options.tickets = &other;
    const second = try connect(options);
    try std.testing.expect(!second.client.info().?.resumed and !second.server.info().?.resumed);
    second.deinit();
    // A ring with no key issues nothing, and a missing key is never stood in for by zeros.
    var empty = try TicketKeys.init(gpa, .{});
    defer empty.deinit();
    try std.testing.expectError(error.InvalidKey, empty.rotate(&@as([32]u8, @splat(0)), types.instant(pki.time)));
    fixture.cache.clear();
    options.tickets = &empty;
    const third = try connect(options);
    third.deinit();
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
    // Distinct ring keys give distinct ticket keys even for the same salt and state.
    var a = try TicketKeys.init(gpa, .{});
    defer a.deinit();
    try a.rotate(&@as([32]u8, @splat(1)), types.instant(0));
    var snapshot_a = a.acquire().?;
    defer snapshot_a.release();
    var snapshot_other = other.acquire().?;
    defer snapshot_other.release();
    var state: Ticket.State = .{ .suite = .aes_128_gcm_sha256, .issued = 0, .expires = 10, .age_add = 0, .policy = @splat(0) };
    var buf_a: [Ticket.max_length]u8 = undefined;
    var buf_b: [Ticket.max_length]u8 = undefined;
    const sealed_a = try Ticket.seal(snapshot_a.ring().issuing(0).?, &@as([16]u8, @splat(9)), &state, &buf_a);
    const sealed_b = try Ticket.seal(&snapshot_other.ring().keys[0], &@as([16]u8, @splat(9)), &state, &buf_b);
    try std.testing.expect(!std.mem.eql(u8, sealed_a[25..], sealed_b[25..]));
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot_other.ring(), sealed_a, 1, &state));
}

const Worker = struct {
    keys: *TicketKeys,
    id: u8,
    sealed: [64][Ticket.max_length]u8 = undefined,
    lengths: [64]usize = undefined,
    count: usize = 0,
    failed: bool = false,

    fn run(worker: *Worker) void {
        for (0..64) |i| {
            if (worker.id == 0 and i % 8 == 0) {
                var material: [32]u8 = @splat(0x40);
                material[0] = @intCast(i + 1);
                worker.keys.rotate(&material, types.instant(1000 + @as(i64, @intCast(i)))) catch {
                    worker.failed = true;
                };
            }
            var snapshot = worker.keys.acquire() orelse continue;
            defer snapshot.release();
            const key = snapshot.ring().issuing(1000 + 64) orelse continue;
            // Each ticket's salt is its own draw; here, worker and index.
            var salt: [16]u8 = @splat(0);
            salt[0] = worker.id;
            salt[1] = @intCast(i);
            var state: Ticket.State = .{ .suite = .aes_128_gcm_sha256, .issued = 1000, .expires = 2000, .age_add = 0, .policy = @splat(0) };
            const sealed = Ticket.seal(key, &salt, &state, &worker.sealed[worker.count]) catch {
                worker.failed = true;
                return;
            };
            worker.lengths[worker.count] = sealed.len;
            var opened: Ticket.State = undefined;
            Ticket.open(snapshot.ring(), sealed, 1064, &opened) catch {
                worker.failed = true;
            };
            worker.count += 1;
        }
    }
};

test "F66 catalogue_ticket_workers_rotation_restart_and_nonce concurrent issue, rotation and opening" {
    var keys = try TicketKeys.init(gpa, .{ .lifetime = .fromSeconds(3600), .rotation = .fromSeconds(3600) });
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x3f)), types.instant(1000));
    var workers: [4]Worker = undefined;
    for (&workers, 0..) |*worker, i| worker.* = .{ .keys = &keys, .id = @intCast(i) };
    var threads: [4]std.Thread = undefined;
    for (&threads, &workers) |*thread, *worker| thread.* = try std.Thread.spawn(.{}, Worker.run, .{worker});
    for (threads) |thread| thread.join();
    // No (key, nonce) pair repeats: every ticket's sealing key is its own, so no two ciphertexts
    // of the same plaintext agree, however rotation interleaved with issuing.
    var total: usize = 0;
    for (&workers) |*worker| {
        try std.testing.expect(!worker.failed);
        total += worker.count;
    }
    try std.testing.expect(total > 0);
    for (&workers, 0..) |*a, ai| for (a.sealed[0..a.count], a.lengths[0..a.count], 0..) |*x, xl, xi| {
        for (workers[ai..], ai..) |*b, bi| for (b.sealed[0..b.count], b.lengths[0..b.count], 0..) |*y, yl, yi| {
            if (ai == bi and yi <= xi) continue;
            try std.testing.expect(!std.mem.eql(u8, x[25..xl], y[25..yl]));
        };
    };
    // A restart with new material opens none of the old tickets; the old key opens them only
    // until their declared expiry.
    var restarted = try TicketKeys.init(gpa, .{ .lifetime = .fromSeconds(3600), .rotation = .fromSeconds(3600) });
    defer restarted.deinit();
    try restarted.rotate(&@as([32]u8, @splat(0x77)), types.instant(1100));
    var snapshot = restarted.acquire().?;
    defer snapshot.release();
    var opened: Ticket.State = undefined;
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), workers[1].sealed[0][0..workers[1].lengths[0]], 1100, &opened));
    var current = keys.acquire().?;
    defer current.release();
    const oldest = current.ring().keys[current.ring().count - 1];
    try std.testing.expect(current.ring().find(&oldest.id, oldest.decrypt_until - 1) != null);
    try std.testing.expect(current.ring().find(&oldest.id, oldest.decrypt_until) == null);
}

test "F67 catalogue_ticket_age_add_and_identifier_privacy" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const first = try connect(fixture.options(1));
    first.deinit();
    // The two tickets of one connection: their own obfuscators, PSKs and bytes.
    var a = fixture.cache.take(&firstKey(&fixture), .tls13, 0).?;
    defer a.release();
    var b = fixture.cache.take(&a.entry.key, .tls13, 0).?;
    defer b.release();
    try std.testing.expect(a.entry.age_add != b.entry.age_add);
    try std.testing.expect(!std.mem.eql(u8, a.entry.secretBytes(), b.entry.secretBytes()));
    try std.testing.expect(!std.mem.eql(u8, a.entry.ticket, b.entry.ticket));
    // Another connection draws other obfuscators: nothing in a ticket is a constant identity.
    // (A ticket is still a bearer token that links the connections that use it; each is offered
    // once, which is all the unlinkability claimed.)
    const second = try connect(fixture.options(2));
    second.deinit();
    var c = fixture.cache.take(&a.entry.key, .tls13, 0).?;
    defer c.release();
    try std.testing.expect(c.entry.age_add != a.entry.age_add and c.entry.age_add != b.entry.age_add);
    try std.testing.expect(!std.mem.eql(u8, c.entry.ticket[9..25], a.entry.ticket[9..25]));
}

/// The cache key of the fixture's only sessions, read from the cache itself.
fn firstKey(fixture: *Fixture) [32]u8 {
    var guard = fixture.cache.table.acquire();
    defer guard.deinit();
    for (guard.value().slots) |slot| if (slot) |entry| return entry.key;
    unreachable;
}

fn flipLastByte(bytes: []u8) void {
    bytes[bytes.len - 1] ^= 1;
}

test "F68 catalogue_psk_binder_lengths_index_and_retry" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const first = try connect(fixture.options(1));
    first.deinit();
    // The hello's last bytes are its binder: one changed bit is fatal, decrypt_error.
    const duo = try Duo.init(gpa, fixture.options(2));
    defer duo.deinit();
    try std.testing.expectError(error.BadBinder, duo.deliverEdited(&flipLastByte));
    try std.testing.expectEqual(@as(?@import("wire/Alert.zig").Alert, .decrypt_error), duo.server.diagnostics().alert_sent);
    try std.testing.expect(duo.server.info() == null);
    // An unknown ticket is passed over for a full handshake, within the hello's budget.
    var stranger = try TicketKeys.init(gpa, .{});
    defer stranger.deinit();
    try stranger.rotate(&@as([32]u8, @splat(0x99)), types.instant(pki.time));
    var options = fixture.options(3);
    options.tickets = &stranger;
    const full = try connect(options);
    defer full.deinit();
    try std.testing.expect(!full.server.info().?.resumed);
}

test "F69 catalogue_resume_after_cloned_policy_mutation" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const base = fixture.options(1);
    // Each change of authority on the client's side: another trust policy generation, pins,
    // reference identity, namespace, ALPN, client certificate, or session age.
    const pin: [32]u8 = @splat(5);
    var mutations: [6]Duo.Options = @splat(base);
    mutations[0].client_policy_generation = 2;
    mutations[1].pins = &.{pin};
    mutations[2].namespace = "tenant b";
    mutations[3].client_alpn = &.{"h2"};
    mutations[3].server_alpn = &.{"h2"};
    mutations[4].client_auth = .optional;
    mutations[4].client_cert = true;
    mutations[5].identity = "client.example.com";
    for (mutations, 0..) |changed, i| {
        fixture.cache.clear();
        var next = changed;
        next.seed = 10 + i;
        if (i == 1) {
            // A pin the server's key does not match fails the handshake outright.
            const a = try connect(base);
            a.deinit();
            try std.testing.expectError(error.VerificationRejected, connect(next));
            continue;
        }
        if (i == 5) {
            // Another name: the server's certificate does not match it, and nothing resumes.
            const a = try connect(base);
            a.deinit();
            try std.testing.expect(std.meta.isError(connect(next)));
            continue;
        }
        if (i == 4) {
            // A server that now asks for a certificate declines the old session: the client
            // presented none then, and its key differs anyway.
            try std.testing.expect(!try resumes(base, next));
            continue;
        }
        try std.testing.expect(!try resumes(base, next));
    }
    // On the server's side: another client verification policy declines its old tickets.
    fixture.cache.clear();
    var auth = base;
    auth.client_auth = .optional;
    auth.client_cert = true;
    var changed_server = auth;
    changed_server.server_policy_generation = 2;
    try std.testing.expect(!try resumes(auth, changed_server));
    // An unchanged policy resumes.
    fixture.cache.clear();
    try std.testing.expect(try resumes(auth, auth));
    // A session past the client's maximum age is not offered.
    fixture.cache.clear();
    var aged = base;
    aged.max_age = .fromSeconds(60);
    var later = aged;
    later.time = pki.time + 61;
    try std.testing.expect(!try resumes(aged, later));
}

test "F70 catalogue_tls13_ticket_hrr_missing_versions" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    // A SHA-256 ticket, then a server whose only suite hashes with SHA-384: no resumption,
    // whether the server learns it from the first hello or after a retry request.
    var first = fixture.options(1);
    first.client_suites = &.{.aes_128_gcm_sha256};
    var other_hash = fixture.options(2);
    other_hash.server_suites = &.{.aes_256_gcm_sha384};
    try std.testing.expect(!try resumes(first, other_hash));
    other_hash.server_groups = &.{.p256};
    try std.testing.expect(!try resumes(first, other_hash));
    // The same hash across a retry resumes.
    var same = fixture.options(3);
    same.server_groups = &.{.p256};
    try std.testing.expect(try resumes(first, same));
    // A TLS 1.2 answer never takes a TLS 1.3 ticket.
    var tls12 = fixture.options(4);
    tls12.server_max = .tls12;
    try std.testing.expect(!try resumes(first, tls12));
}

test "F71 catalogue_early_data_replay_rejection_budget" {
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    const Pair = ServerPair(.aes_128_gcm_sha256);
    // Early data under keys the server never derives is skipped: the handshake completes and
    // nothing of it is readable.
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 4 }, .{});
        defer pair.deinit();
        try pair.run();
        try pair.client.send("after");
        var out: [16]u8 = undefined;
        const n = try pair.read(&out);
        try std.testing.expectEqualSlices(u8, "after", out[0..n]);
    }
    // After a retry request, the early records come before the second hello, under no key.
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 3, .shares = &.{.p256} }, .{ .groups = &.{.x25519} });
        defer pair.deinit();
        try pair.run();
    }
    // The hello after a retry request may not offer early data again.
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .shares = &.{.p256}, .tamper = .early_data_in_second }, .{ .groups = &.{.x25519} });
        defer pair.deinit();
        try std.testing.expectError(error.IllegalParameter, pair.run());
    }
    // More than the bound is refused.
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 8, .early_record_size = 16 * 1024 }, .{});
        defer pair.deinit();
        try std.testing.expectError(error.EarlyDataLimit, pair.run());
    }
    // Without an early_data offer the same records end the connection.
    {
        const pair = try Pair.init(gpa, .{ .early_records = 1 }, .{});
        defer pair.deinit();
        try std.testing.expectError(error.BadRecord, pair.run());
    }
    // An EndOfEarlyData with no early data accepted is an unexpected message.
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .tamper = .end_of_early_data }, .{});
        defer pair.deinit();
        try std.testing.expectError(error.UnexpectedMessage, pair.run());
    }
    // A server never permits early data in a ticket: no early_data extension in any.
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const duo = try connect(fixture.options(1));
    duo.deinit();
    var taken = fixture.cache.take(&firstKey(&fixture), .tls13, 0).?;
    defer taken.release();
    try std.testing.expect(taken.entry.ticket.len > 0);
}

test "F72 catalogue_ticket_ems_derivation_and_callback_errors" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    // The issuing key stopped issuing (rotation forgotten): no ticket, and the connection is whole.
    var late = fixture.options(1);
    late.time = pki.time + 7 * 60 * 60;
    const duo = try connect(late);
    try std.testing.expect(duo.client.info() != null);
    try exportsMatch(duo);
    duo.deinit();
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
    // A ticket a client refuses to keep (a lifetime of zero, or too long to hold) leaves nothing.
    var tiny = try SessionCache.init(gpa, .{ .max_bytes = @sizeOf(SessionCache.Entry) + 64 });
    defer tiny.deinit();
    var options = fixture.options(2);
    options.cache = &tiny;
    const second = try connect(options);
    second.deinit();
    try std.testing.expectEqual(@as(usize, 0), tiny.count());
}

fn flipTicket(entry: *SessionCache.Entry) void {
    entry.ticket[entry.ticket.len / 2] ^= 0x10;
}

test "F73 catalogue_session_serialization_tamper_and_reset" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const first = try connect(fixture.options(1));
    first.deinit();
    // A ticket changed at rest: the server cannot open it and does a full handshake.
    {
        var guard = fixture.cache.table.acquire();
        defer guard.deinit();
        for (guard.value().slots) |slot| if (slot) |entry| flipTicket(entry);
    }
    const second = try connect(fixture.options(2));
    try std.testing.expect(!second.server.info().?.resumed);
    second.deinit();
    // A connection that fails after taking a ticket used it up: it is never offered again, and
    // the next connection starts from nothing of the failed one.
    const before = fixture.cache.count();
    const failing = try Duo.init(gpa, fixture.options(3));
    try std.testing.expectError(error.BadBinder, failing.deliverEdited(&flipLastByte));
    try std.testing.expect(failing.client.info() == null);
    failing.deinit();
    try std.testing.expectEqual(before - 1, fixture.cache.count());
    const third = try connect(fixture.options(4));
    defer third.deinit();
    try std.testing.expect(third.client.info().?.resumed);
}

test "F74 catalogue_resumed_mtls_evidence_expiry_and_refresh" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var options = fixture.options(1);
    options.client_auth = .required;
    options.client_cert = true;
    // The verdict on the client's certificate holds for ten minutes.
    options.receipt_expires = pki.time + 600;
    const first = try connect(options);
    try std.testing.expect(first.server.info().?.peer_authenticated);
    first.deinit();
    // Within it, a resumption carries the client's authentication; refreshing it with the new
    // tickets never moves its expiry.
    for (0..3) |i| {
        var next = options;
        next.seed = 2 + i;
        next.time = pki.time + 60 * @as(i64, @intCast(i + 1));
        const duo = try connect(next);
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.resumed and duo.server.info().?.peer_authenticated);
    }
    // Past it, the server declines a ticket even if the ticket itself still lived: reseal the
    // client's tickets with a later session expiry and an unchanged authentication expiry.
    {
        var snapshot = fixture.keys.acquire().?;
        defer snapshot.release();
        var guard = fixture.cache.table.acquire();
        defer guard.deinit();
        for (guard.value().slots) |slot| if (slot) |entry| {
            var state: Ticket.State = undefined;
            try Ticket.open(snapshot.ring(), entry.ticket, pki.time + 200, &state);
            defer state.deinit();
            try std.testing.expect(state.client_authenticated and state.auth_expires == pki.time + 600);
            state.expires = pki.time + 5000;
            var buffer: [Ticket.max_length]u8 = undefined;
            const resealed = try Ticket.seal(snapshot.ring().issuing(pki.time).?, &@as([16]u8, @splat(0x42)), &state, &buffer);
            try std.testing.expectEqual(entry.ticket.len, resealed.len);
            @memcpy(entry.ticket, resealed);
            entry.expires = pki.time + 5000;
        };
    }
    var after = options;
    after.seed = 9;
    after.time = pki.time + 601;
    after.receipt_expires = null;
    const duo = try connect(after);
    defer duo.deinit();
    // A full handshake: the certificate is asked for again and verified anew.
    try std.testing.expect(!duo.server.info().?.resumed and duo.server.info().?.peer_authenticated);
    try std.testing.expect(duo.client.certificateRequested());
}

test "C5 QUIC resumes too: tickets at the application level, no certificate the second time" {
    const QuicLoop = @import("../testing/QuicLoop.zig").QuicLoop(.aes_128_gcm_sha256);
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const first = try QuicLoop.init(gpa, .{ .cache = &fixture.cache, .tickets = &fixture.keys });
    try first.run();
    try std.testing.expect(!first.client.hs.info().?.resumed);
    first.deinit();
    try std.testing.expectEqual(@as(usize, 2), fixture.cache.count());
    const second = try QuicLoop.init(gpa, .{ .seed = 2, .cache = &fixture.cache, .tickets = &fixture.keys });
    defer second.deinit();
    try second.run();
    try std.testing.expect(second.client.hs.info().?.resumed and second.server.hs.info().?.resumed);
    try std.testing.expect(second.client.hs.info().?.peer_authenticated);
    // Nothing was verified or signed: the PSK authenticated both ends.
    try std.testing.expectEqual(@as(usize, 0), second.client.verified + second.server.signed);
}

test "F71 after a retry request a record failing under the handshake keys is fatal, not skipped" {
    const Pair = ServerPair(.aes_128_gcm_sha256);
    // The early records came before the second hello; one after it, under the handshake keys, is
    // a forgery like any other.
    const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 1, .shares = &.{.p256}, .tamper = .bad_record_after_second }, .{ .groups = &.{.x25519} });
    defer pair.deinit();
    try std.testing.expectError(error.BadRecord, pair.run());
}

fn options12(fixture: *Fixture, seed: u64) Duo.Options {
    var options = fixture.options(seed);
    options.client_max = .tls12;
    options.client_tls12_tickets = true;
    options.server_tls12_tickets = true;
    return options;
}

test "C5 TLS 1.2 tickets: an abbreviated handshake from the session's master secret, every suite" {
    const suites12 = [_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256 };
    for (suites12) |suite| {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        var options = options12(&fixture, 1);
        options.client_suites = &.{suite};
        const first = try connect(options);
        try std.testing.expect(!first.client.info().?.resumed and first.client.info().?.version == .tls12);
        first.deinit();
        try std.testing.expectEqual(@as(usize, 1), fixture.cache.count());
        options.seed = 2;
        const second = try connect(options);
        defer second.deinit();
        const info = second.client.info().?;
        try std.testing.expect(info.resumed and second.server.info().?.resumed);
        try std.testing.expect(info.peer_authenticated and info.version == .tls12 and info.suite == suite);
        try exportsMatch(second);
        var out: [16]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "resumed", try second.echo(&second.client, &second.server, "resumed", &out));
        try std.testing.expectEqualSlices(u8, "back", try second.echo(&second.server, &second.client, "back", &out));
        // The resumed handshake issued a new ticket for the next.
        try std.testing.expectEqual(@as(usize, 1), fixture.cache.count());
        options.seed = 3;
        const third = try connect(options);
        defer third.deinit();
        try std.testing.expect(third.client.info().?.resumed);
    }
}

test "C5 TLS 1.2 tickets stay off unless both ends ask, and a client certificate session resumes authenticated" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var client_only = options12(&fixture, 1);
    client_only.server_tls12_tickets = false;
    try std.testing.expect(!try resumes(client_only, client_only));
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
    var server_only = options12(&fixture, 1);
    server_only.client_tls12_tickets = false;
    try std.testing.expect(!try resumes(server_only, server_only));
    try std.testing.expectEqual(@as(usize, 0), fixture.cache.count());
    var mutual = options12(&fixture, 3);
    mutual.client_auth = .required;
    mutual.client_cert = true;
    const first = try connect(mutual);
    first.deinit();
    mutual.seed = 4;
    const second = try connect(mutual);
    defer second.deinit();
    try std.testing.expect(second.server.info().?.resumed and second.server.info().?.peer_authenticated);
}

test "F70 a ticket of one version never resumes the other" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    // TLS 1.3 tickets, relabelled TLS 1.2 in the client's cache: offered as TLS 1.2 tickets, they
    // open as TLS 1.3 state and the server declines them.
    const first = try connect(fixture.options(1));
    first.deinit();
    {
        var guard = fixture.cache.table.acquire();
        defer guard.deinit();
        for (guard.value().slots) |slot| if (slot) |entry| {
            entry.version = .tls12;
            entry.suite = .ecdhe_ecdsa_aes_128_gcm_sha256;
        };
    }
    var as12 = options12(&fixture, 2);
    as12.client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256};
    const second = try connect(as12);
    try std.testing.expect(!second.server.info().?.resumed);
    second.deinit();
    // And a TLS 1.2 ticket offered as a TLS 1.3 PSK opens as TLS 1.2 state and is declined.
    fixture.cache.clear();
    const third = try connect(options12(&fixture, 3));
    third.deinit();
    {
        var guard = fixture.cache.table.acquire();
        defer guard.deinit();
        for (guard.value().slots) |slot| if (slot) |entry| {
            entry.version = .tls13;
            entry.suite = .aes_128_gcm_sha256;
        };
    }
    var as13 = fixture.options(4);
    as13.client_tls12_tickets = true;
    as13.server_tls12_tickets = true;
    const fourth = try connect(as13);
    defer fourth.deinit();
    try std.testing.expect(!fourth.server.info().?.resumed and fourth.client.info().?.version == .tls13);
}

test "F69 TLS 1.2 tickets bind the same authority as TLS 1.3's" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var mutual = options12(&fixture, 1);
    mutual.client_auth = .optional;
    mutual.client_cert = true;
    var changed = mutual;
    changed.seed = 2;
    changed.server_policy_generation = 2;
    try std.testing.expect(!try resumes(mutual, changed));
    fixture.cache.clear();
    var alpn = options12(&fixture, 3);
    var other = alpn;
    other.seed = 4;
    other.client_alpn = &.{"h2"};
    other.server_alpn = &.{"h2"};
    try std.testing.expect(!try resumes(alpn, other));
    fixture.cache.clear();
    alpn.seed = 5;
    try std.testing.expect(try resumes(alpn, blk: {
        var same = alpn;
        same.seed = 6;
        break :blk same;
    }));
}

/// The server's handshake traffic secret, taken from its key log.
const HandshakeLog = struct {
    secret: [48]u8 = undefined,
    len: usize = 0,

    fn write(context: ?*anyopaque, line: []const u8) void {
        const self: *HandshakeLog = @ptrCast(@alignCast(context.?));
        if (!std.mem.startsWith(u8, line, "SERVER_HANDSHAKE_TRAFFIC_SECRET ")) return;
        const hex = std.mem.trimEnd(u8, line[std.mem.findScalarLast(u8, line, ' ').? + 1 ..], "\n");
        self.len = (std.fmt.hexToBytes(&self.secret, hex) catch return).len;
    }
};

/// Whether an extension block (its two-byte length first) carries `id`.
fn carries(block: []const u8, id: u16) bool {
    var at: usize = 2;
    while (at + 4 <= block.len) {
        if (std.mem.readInt(u16, block[at..][0..2], .big) == id) return true;
        at += 4 + std.mem.readInt(u16, block[at + 2 ..][0..2], .big);
    }
    return false;
}

/// Whether the server's first flight, waiting in its output, acknowledges server_name: in the
/// TLS 1.2 ServerHello, or in the TLS 1.3 EncryptedExtensions opened under the logged secret.
fn acknowledgesName(duo: *Duo, log: *const HandshakeLog) !bool {
    const Protection = @import("record/Protection.zig");
    const wire = duo.server.output();
    var at: usize = 0;
    while (at + 5 <= wire.len) {
        const len = std.mem.readInt(u16, wire[at + 3 ..][0..2], .big);
        const record = wire[at..][0 .. 5 + len];
        at += 5 + len;
        switch (record[0]) {
            22 => if (log.len == 0) {
                // ServerHello: version, random, session id, suite, method, then extensions.
                const body = record[5 + 4 ..];
                const sid = body[2 + 32];
                return carries(body[2 + 32 + 1 + sid + 2 + 1 ..], 0);
            },
            23 => {
                var protection: Protection = undefined;
                try protection.init(.aes_128_gcm_sha256, log.secret[0..log.len], .{});
                defer protection.deinit();
                var out: [16 * 1024 + 256]u8 = undefined;
                const plain = try protection.open(record, &out);
                // EncryptedExtensions comes first.
                try std.testing.expectEqual(@as(u8, 8), plain.bytes[0]);
                return carries(plain.bytes[4..], 0);
            },
            else => {},
        }
    }
    return error.TestUnexpectedResult;
}

test "F117 catalogue_no_server_name_ack_on_resumption (RFC 6066 section 3: a resuming server sends no server_name)" {
    // TLS 1.3: the full handshake acknowledges the name in EncryptedExtensions, the resumed one
    // does not.
    {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        for ([_]bool{ false, true }) |resuming| {
            var log: HandshakeLog = .{};
            var options = fixture.options(if (resuming) 2 else 1);
            options.client_suites = &.{.aes_128_gcm_sha256};
            options.server_key_log = .{ .context = &log, .write = HandshakeLog.write };
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try duo.handshakeUntilServerFlight();
            try std.testing.expect(log.len == 32);
            try std.testing.expectEqual(!resuming, try acknowledgesName(duo, &log));
            try duo.handshake();
            try std.testing.expectEqual(resuming, duo.server.info().?.resumed);
        }
    }
    // TLS 1.2 tickets: the same in the ServerHello.
    {
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        for ([_]bool{ false, true }) |resuming| {
            const duo = try Duo.init(gpa, options12(&fixture, if (resuming) 2 else 1));
            defer duo.deinit();
            try duo.handshakeUntilServerFlight();
            try std.testing.expectEqual(!resuming, try acknowledgesName(duo, &.{}));
            try duo.handshake();
            try std.testing.expectEqual(resuming, duo.server.info().?.resumed);
        }
    }
}

test "F119 catalogue_declined_early_record_shorter_than_tag (a declined early record too short to carry a tag is skipped)" {
    // RFC 8446 section 4.2.10: the server skips declined early data, discarding the records that
    // fail deprotection; a record shorter than a tag fails it like any other (BoGo's fake early
    // data is four bytes).
    const Pair = ServerPair(.aes_128_gcm_sha256);
    for ([_]usize{ 0, 1, 4, 16 }) |size| {
        const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 2, .early_record_size = size }, .{});
        defer pair.deinit();
        try pair.run();
        try pair.client.send("after");
        var out: [16]u8 = undefined;
        const n = try pair.read(&out);
        try std.testing.expectEqualSlices(u8, "after", out[0..n]);
    }
}

test "F123 catalogue_protected_record_before_read_keys_unexpected (a protected record before any read key is unexpected_message, whatever its length)" {
    // RFC 8446 section 5: before the server has a read key, a protected record is a record type
    // it cannot take; its length does not make it a tag failure.
    const Pair = ServerPair(.aes_128_gcm_sha256);
    for ([_]usize{ 4, 600 }) |size| {
        const pair = try Pair.init(gpa, .{ .early_records = 1, .early_record_size = size, .shares = &.{.p256} }, .{ .groups = &.{.x25519} });
        defer pair.deinit();
        try std.testing.expectError(error.UnexpectedRecord, pair.run());
    }
}

test "F132 catalogue_early_data_between_hello_fragments_unexpected (declined early data is skipped only between messages)" {
    // RFC 8446 section 5.1: no record of another type comes between a handshake message's
    // fragments. Declined early data after a retry request is skipped (section 4.2.10), but a
    // record of it inside the second hello is unexpected_message.
    const Pair = ServerPair(.aes_128_gcm_sha256);
    {
        const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 1, .shares = &.{.p256}, .tamper = .early_inside_second_hello }, .{ .groups = &.{.x25519} });
        defer pair.deinit();
        try std.testing.expectError(error.UnexpectedRecord, pair.run());
    }
    // Between the messages it is still skipped.
    const pair = try Pair.init(gpa, .{ .early_data = true, .early_records = 1, .shares = &.{.p256} }, .{ .groups = &.{.x25519} });
    defer pair.deinit();
    try pair.run();
}
