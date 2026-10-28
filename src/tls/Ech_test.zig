//! Encrypted Client Hello end to end, cloak client against cloak server, and the failure
//! catalogue's ECH rows (F75, F76).
const std = @import("std");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Duo = @import("../testing/Duo.zig");
const Ech = @import("handshake/Ech.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Alert = @import("wire/Alert.zig").Alert;
const pki = Duo.pki;
const gpa = std.testing.allocator;

/// The test certificate answers for example.com and *.example.org: the inner name is the first,
/// the public name one of the second.
const public_name = "public.example.org";

const Keys = @import("../testing/EchKeys.zig");

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

fn roundTrip(duo: *Duo) !void {
    var out: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "inner", try duo.echo(&duo.client, &duo.server, "inner", &out));
    try std.testing.expectEqualSlices(u8, "back", try duo.echo(&duo.server, &duo.client, "back", &out));
}

test "C6 ECH accepted for every TLS 1.3 suite: the inner name is served, both ends agree" {
    var keys: Keys = undefined;
    try keys.init(1, 7, public_name);
    defer keys.deinit();
    for (Suite.tls13_only) |suite| {
        const duo = try connect(.{ .client_suites = &.{suite}, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
        defer duo.deinit();
        const client = duo.client.info().?;
        const server = duo.server.info().?;
        try std.testing.expect(client.ech_accepted and server.ech_accepted);
        try std.testing.expect(client.peer_authenticated);
        try std.testing.expectEqualStrings("example.com", server.server_name);
        try std.testing.expectEqual(Suite.from13(suite.tls13().?), client.suite);
        try roundTrip(duo);
    }
}

test "C6 ECH accepted across a retry request, and with one-byte delivery" {
    var keys: Keys = undefined;
    try keys.init(2, 9, public_name);
    defer keys.deinit();
    for ([_]usize{ 1 << 20, 1 }) |chunk| {
        const duo = try connect(.{ .seed = 5, .server_groups = &.{.p256}, .chunk = chunk, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted and duo.server.info().?.ech_accepted);
        try std.testing.expectEqual(.p256, duo.client.info().?.group);
        try roundTrip(duo);
    }
}

test "C6 ECH with ALPN and a client certificate: the inner hello's choices hold" {
    var keys: Keys = undefined;
    try keys.init(3, 1, public_name);
    defer keys.deinit();
    const duo = try connect(.{ .client_alpn = &.{ "h2", "http/1.1" }, .server_alpn = &.{"h2"}, .client_auth = .required, .client_cert = true, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
    defer duo.deinit();
    const server = duo.server.info().?;
    try std.testing.expect(server.ech_accepted and server.peer_authenticated);
    try std.testing.expectEqualStrings("h2", duo.client.info().?.alpn);
}

test "C6 ECH with certificate compression offered, used or not: the inner hello the server rebuilds is the client's" {
    var keys: Keys = undefined;
    try keys.init(4, 2, public_name);
    defer keys.deinit();
    const Zlib = @import("../testing/Zlib.zig");
    var zlib = Zlib.codec;
    const codec = &zlib;
    // The client offers the codec; the server compresses with it, or has none. With a retry
    // request too, whose second inner hello is encoded again.
    for ([_][]const *@import("handshake/Compression.zig").Codec{ &.{codec}, &.{} }) |server_codecs| for ([_][]const @import("crypto/Group.zig").Group{ &.{ .x25519_mlkem768, .x25519 }, &.{.p256} }) |server_groups| {
        const duo = try connect(.{ .server_groups = server_groups, .client_codecs = &.{codec}, .server_codecs = server_codecs, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted and duo.server.info().?.ech_accepted);
        try std.testing.expect(duo.client.info().?.peer_authenticated);
        try roundTrip(duo);
    };
}

test "F157 catalogue_ech_inner_hello_order" {
    var keys: Keys = undefined;
    try keys.init(5, 3, public_name);
    defer keys.deinit();
    const root = (try certificates.certificate.parse(pki.ca, .{})).subject;
    for ([_][]const @import("crypto/Group.zig").Group{ &.{ .x25519_mlkem768, .x25519 }, &.{.p256} }) |server_groups| {
        const duo = try connect(.{ .server_groups = server_groups, .client_authorities = &.{root}, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted and duo.server.info().?.ech_accepted);
        try roundTrip(duo);
    }
}

test "C6 ECH required: a client offers only TLS 1.3, and a config list with nothing usable is refused" {
    var keys: Keys = undefined;
    try keys.init(4, 1, public_name);
    defer keys.deinit();
    // A TLS 1.2-only server cannot accept: the client offered TLS 1.3 alone.
    {
        const duo = try Duo.init(gpa, .{ .server_max = .tls12, .client_ech = .{ .config_list = keys.list } });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedVersion, duo.handshake());
    }
    // Lists without a usable config: garbage, an unknown version, an IPv4-like public name.
    var bad = keys.list_buf;
    bad[2] = 0xfe;
    bad[3] = 0x0c;
    for ([_][]const u8{ "", &.{ 0, 1, 0 }, bad[0..keys.list.len] }) |list| {
        try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_ech = .{ .config_list = list } }));
    }
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_max = .tls12, .client_ech = .{ .config_list = keys.list } }));
}

/// A client with `client` keys' config against a server with `server` keys: the server cannot
/// decrypt, answers with the outer hello and offers its own config for a retry.
fn rejected(client: *const Keys, server: *const Keys, options: Duo.Options) !*Duo {
    var with = options;
    with.client_ech = .{ .config_list = client.list };
    with.server_ech = &.{server.key()};
    const duo = try Duo.init(gpa, with);
    errdefer duo.deinit();
    try std.testing.expectError(error.EchRejected, duo.handshake());
    return duo;
}

test "F75 catalogue_ech_rejection_no_target_authority" {
    var stale: Keys = undefined;
    try stale.init(5, 1, public_name);
    defer stale.deinit();
    var current: Keys = undefined;
    try current.init(6, 2, public_name);
    defer current.deinit();
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var tickets = try TicketKeys.init(gpa, .{});
    defer tickets.deinit();
    try tickets.rotate(&@as([32]u8, @splat(0x22)), types.instant(pki.time));

    // Rejected, the public name authenticated: the retry configs are released, and nothing
    // else is: no connection, no target authentication, no plaintext, no ticket.
    {
        const duo = try rejected(&stale, &current, .{ .cache = &cache, .tickets = &tickets, .client_auth = .required, .client_cert = true });
        defer duo.deinit();
        try std.testing.expectEqualSlices(u8, current.list, duo.client.echRetryConfigs().?);
        try std.testing.expectEqual(null, duo.client.info());
        try std.testing.expect(duo.client.phase() == .failed);
        try std.testing.expectEqual(Alert.ech_required, duo.client.diagnostics().alert_sent.?);
        try std.testing.expectEqual(0, duo.client.readable().len);
        var out: [8]u8 = undefined;
        try std.testing.expectError(error.WrongPhase, duo.client.exportKeyingMaterial(&out, "label", ""));
        try std.testing.expectEqual(0, cache.count());
        // The server never saw a certificate: the outer handshake asked for one and the client
        // answered with an empty Certificate (F154), which this server requires.
        try std.testing.expect(duo.server.phase() != .connected);
    }
    // Rejected over a retry request: the same, the outer hello answering both.
    {
        const duo = try rejected(&stale, &current, .{ .server_groups = &.{.p256} });
        defer duo.deinit();
        try std.testing.expectEqualSlices(u8, current.list, duo.client.echRetryConfigs().?);
    }
    // A server whose keys are all off the retry list securely disables ECH: authenticated,
    // empty retry configs.
    {
        var server_key = current.key();
        server_key.retry = false;
        const duo = try Duo.init(gpa, .{ .client_ech = .{ .config_list = stale.list }, .server_ech = &.{server_key} });
        defer duo.deinit();
        try std.testing.expectError(error.EchRejected, duo.handshake());
        try std.testing.expectEqual(0, duo.client.echRetryConfigs().?.len);
    }
    // A server without ECH at all: the same.
    {
        const duo = try Duo.init(gpa, .{ .client_ech = .{ .config_list = stale.list } });
        defer duo.deinit();
        try std.testing.expectError(error.EchRejected, duo.handshake());
        try std.testing.expectEqual(0, duo.client.echRetryConfigs().?.len);
    }
    // The public name not authenticated (the certificate does not carry it): the handshake
    // fails as any failed verification does, and the retry configs are never released.
    {
        var other: Keys = undefined;
        try other.init(7, 1, "public.example.net");
        defer other.deinit();
        const duo = try Duo.init(gpa, .{ .client_ech = .{ .config_list = other.list }, .server_ech = &.{current.key()} });
        defer duo.deinit();
        try std.testing.expectError(error.VerificationRejected, duo.handshake());
        try std.testing.expectEqual(null, duo.client.echRetryConfigs());
    }
    // An unverifying client cannot authenticate the public name: no retry configs either.
    {
        const duo = try rejected(&stale, &current, .{ .client_verify_none = true });
        defer duo.deinit();
        try std.testing.expectEqual(null, duo.client.echRetryConfigs());
    }
    // The origin's pins do not apply to the public name, and do not authenticate it either.
    {
        const pin: [32]u8 = @splat(0x5a);
        const duo = try rejected(&stale, &current, .{ .pins = &.{pin} });
        defer duo.deinit();
        try std.testing.expectEqualSlices(u8, current.list, duo.client.echRetryConfigs().?);
    }
}

test "C6 ECH GREASE looks like ECH and changes nothing, with or without a retry request" {
    var keys: Keys = undefined;
    try keys.init(8, 3, public_name);
    defer keys.deinit();
    const servers = [_][]const Ech.Key{ &.{}, &.{keys.key()} };
    for (servers) |server_keys| for ([_]bool{ false, true }) |retry| {
        var options: Duo.Options = .{ .client_ech = .grease, .server_ech = server_keys };
        if (retry) options.server_groups = &.{.p256};
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.ech_accepted and !duo.server.info().?.ech_accepted);
        try std.testing.expect(duo.client.info().?.peer_authenticated);
        try std.testing.expectEqualStrings("example.com", duo.server.info().?.server_name);
        try std.testing.expectEqual(null, duo.client.echRetryConfigs());
        try roundTrip(duo);
    };
    // GREASE rides on TLS 1.2 offers too, and a TLS 1.2 server ignores it.
    const duo = try connect(.{ .client_ech = .grease, .server_max = .tls12 });
    defer duo.deinit();
    try std.testing.expectEqual(.tls12, duo.client.info().?.version);
}

const ClientHello = @import("handshake/ClientHello.zig");
const Ticket = @import("resumption/Ticket.zig");

/// The ClientHello in a client's first output: one plaintext handshake record.
fn firstHello(output: []const u8) ![]const u8 {
    if (output.len < 9 or output[0] != 22) return error.NoHello;
    const len = std.mem.readInt(u16, output[3..5], .big);
    return output[5..][0..len];
}

/// A real ticket an attacker harvested, put in place of the outer hello's GREASE PSK identity.
var harvested: []const u8 = "";

fn swapIdentity(bytes: []u8) void {
    const hello = ClientHello.parse(bytes[5..][0..std.mem.readInt(u16, bytes[3..5], .big)], .stream) catch unreachable;
    const identity = hello.pskIdentity(0).?.identity;
    std.debug.assert(identity.len == harvested.len);
    const at = @intFromPtr(identity.ptr) - @intFromPtr(bytes.ptr);
    @memcpy(bytes[at..][0..harvested.len], harvested);
}

test "F76 catalogue_ech_outer_psk_identity_and_guess_oracle" {
    var keys: Keys = undefined;
    try keys.init(9, 4, public_name);
    defer keys.deinit();
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var tickets = try TicketKeys.init(gpa, .{});
    defer tickets.deinit();
    try tickets.rotate(&@as([32]u8, @splat(0x33)), types.instant(pki.time));
    const options: Duo.Options = .{ .cache = &cache, .tickets = &tickets, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} };

    // A first ECH connection leaves its tickets.
    {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted);
    }
    try std.testing.expectEqual(2, cache.count());

    // The second resumes inside ECH. On the wire: the public name, never the true one, and a PSK
    // offer that is no ticket of this server.
    {
        var second = options;
        second.seed = 2;
        const duo = try Duo.init(gpa, second);
        defer duo.deinit();
        try duo.serveClient();
        const wire = try firstHello(duo.client.output());
        try std.testing.expect(std.mem.find(u8, wire, "example.com") == null);
        try std.testing.expect(std.mem.find(u8, wire, public_name) != null);
        const outer = try ClientHello.parse(wire, .stream);
        const offer = outer.pskIdentity(0).?;
        var snapshot = tickets.acquire().?;
        defer snapshot.release();
        var state: Ticket.State = undefined;
        try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), offer.identity, pki.time, &state));
        try duo.handshake();
        const client = duo.client.info().?;
        try std.testing.expect(client.resumed and client.ech_accepted and duo.server.info().?.resumed);
        try roundTrip(duo);
    }

    // An attacker puts a real ticket for the true name into the outer hello, to learn whether the
    // inner name is the ticket's. The outer hello is the payload's associated data, so the server
    // cannot decrypt and answers the outer hello, whose public name the ticket does not match:
    // a full handshake to the public name, no binder checked, nothing to tell guesses apart.
    {
        const client_key = blk: {
            const probe = try Duo.init(gpa, options);
            defer probe.deinit();
            break :blk probe.client.hs.state.client.cache_key;
        };
        var taken = cache.take(&client_key, .tls13, pki.time).?;
        defer taken.release();
        harvested = try gpa.dupe(u8, taken.entry.ticket);
        defer gpa.free(harvested);
        var third = options;
        third.seed = 3;
        const duo = try Duo.init(gpa, third);
        defer duo.deinit();
        try duo.deliverEdited(&swapIdentity);
        const server = duo.server.hs.state.server;
        try std.testing.expect(duo.server.diagnostics().alert_sent == null);
        try std.testing.expect(server.scratch.?.ech.status == .rejected and !server.resumed);
        // The client's transcript holds the hello it sent, not the edited one: the handshake
        // keys differ and its first protected record fails, as for any edited hello.
        try std.testing.expectError(error.BadRecord, duo.handshake());
    }
}

fn flipOuterRandom(bytes: []u8) void {
    bytes[5 + 4 + 2] ^= 1;
}

fn flipLast(bytes: []u8) void {
    bytes[bytes.len - 1] ^= 1;
}

fn innerType(bytes: []u8) void {
    const hello = ClientHello.parse(bytes[5..][0..std.mem.readInt(u16, bytes[3..5], .big)], .stream) catch unreachable;
    const body = hello.ech.?;
    bytes[@intFromPtr(body.ptr) - @intFromPtr(bytes.ptr)] = 2;
}

fn flipConfirmation(bytes: []u8) void {
    // The ServerHello leads the flight: record header, message header, version, then the random,
    // whose last byte is the confirmation's.
    bytes[5 + 4 + 2 + 31] ^= 1;
}

test "F75 a retry request that accepted ECH binds the ServerHello to accept it too" {
    var keys: Keys = undefined;
    try keys.init(12, 7, public_name);
    defer keys.deinit();
    const duo = try Duo.init(gpa, .{ .server_groups = &.{.p256}, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
    defer duo.deinit();
    try duo.handshakeUntilServerFlight();
    try duo.deliverServer();
    try duo.deliverEdited(&unchanged);
    try std.testing.expectError(error.IllegalParameter, duo.deliverServerEdited(&flipConfirmation));
    try std.testing.expectEqual(Alert.illegal_parameter, duo.client.diagnostics().alert_sent.?);
}

fn unchanged(_: []u8) void {}

test "C6 ECH server: a tampered outer hello is not decrypted, a tampered second one is fatal" {
    var keys: Keys = undefined;
    try keys.init(10, 5, public_name);
    defer keys.deinit();
    const options: Duo.Options = .{ .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} };
    // Any change to the outer hello breaks the payload's associated data: not decrypted, so the
    // server goes on with the outer hello (and the client then fails on the changed transcript).
    {
        const duo = try Duo.init(gpa, options);
        defer duo.deinit();
        try duo.deliverEdited(&flipOuterRandom);
        try std.testing.expect(duo.server.hs.state.server.scratch.?.ech.status == .rejected);
        try std.testing.expect(duo.server.diagnostics().alert_sent == null);
    }
    // An unknown ECHClientHello type is illegal_parameter.
    {
        const duo = try Duo.init(gpa, options);
        defer duo.deinit();
        try std.testing.expectError(error.IllegalParameter, duo.deliverEdited(&innerType));
    }
    // After a retry request that accepted ECH, the second outer hello must open under the first
    // one's context: a flipped payload byte is decrypt_error.
    {
        var retry = options;
        retry.server_groups = &.{.p256};
        const duo = try Duo.init(gpa, retry);
        defer duo.deinit();
        try duo.handshakeUntilServerFlight();
        try duo.deliverServer();
        try std.testing.expectError(error.EchDecryptFailed, duo.deliverEdited(&flipLast));
        try std.testing.expectEqual(Alert.decrypt_error, duo.server.diagnostics().alert_sent.?);
    }
}

const Session = @import("Session.zig");
const peer_module = @import("../testing/Peer.zig");
const Loopback = @import("../testing/Loopback.zig").Loopback;

test "F154 catalogue_ech_rejection_answers_a_certificate_request" {
    // RFC 9849 sections 6.1.6 and 6.1.7: rejected, the client completes the handshake with the
    // outer hello, answers a CertificateRequest with an empty Certificate (never its own
    // certificate, for a name it did not ask for) and its Finished, and only then ends with
    // ech_required. It ended before its flight, so the server never saw the empty Certificate
    // the RFC requires.
    var stale: Keys = undefined;
    try stale.init(5, 1, public_name);
    defer stale.deinit();
    var current: Keys = undefined;
    try current.init(6, 2, public_name);
    defer current.deinit();
    const duo = try rejected(&stale, &current, .{ .client_auth = .required, .client_cert = true });
    defer duo.deinit();
    // The server fails on the empty Certificate it requires: the pump's error is that failure.
    try std.testing.expectError(error.CertificateRequired, duo.pump());
    // The server took the client's empty Certificate, and a server requiring one refuses it.
    try std.testing.expectEqual(@as(?Alert, .certificate_required), duo.server.diagnostics().alert_sent);
    try std.testing.expectEqualSlices(u8, current.list, duo.client.echRetryConfigs().?);
    try std.testing.expectEqual(Alert.ech_required, duo.client.diagnostics().alert_sent.?);
}

test "C6 ECH session: a rejection fails open and hands the caller the retry configs" {
    var keys: Keys = undefined;
    try keys.init(11, 6, public_name);
    defer keys.deinit();
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    // The scripted peer knows no ECH: it answers the outer hello, as the public name.
    var peer = peer_module.Peer(.aes_128_gcm_sha256).init(gpa, .{});
    defer peer.deinit();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    var retry: []u8 = undefined;
    var report: Session.Diagnostics = undefined;
    try std.testing.expectError(error.EchRejected, session.open(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &write_buffer, .{
        .identity = .{ .dns = "example.com" },
        .trust = .{ .snapshot = snapshot },
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
        .ech = .{ .config_list = keys.list },
        .ech_retry = &retry,
        .diagnostics = &report,
    }));
    defer gpa.free(retry);
    // Authenticated as the public name, with no configs offered: ECH securely disabled.
    try std.testing.expectEqual(0, retry.len);
    try std.testing.expectEqual(Alert.ech_required, report.alert_sent.?);
}
