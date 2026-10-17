//! Certificate Transparency (RFC 6962) end to end, cloak client against cloak server: SCTs
//! embedded in the certificate or delivered in the handshake (TLS 1.3 in the leaf's entry, TLS 1.2
//! in the ServerHello), asked for only under a policy that requires them, and resumption held to
//! the log list's life (F88).
const std = @import("std");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const Hello = @import("handshake/Hello.zig");
const Messages = @import("handshake/Messages.zig");
const ClientHello = @import("handshake/ClientHello.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const types = certificates.types;
const pki = Duo.pki;
const gpa = std.testing.allocator;

const logs = [_]types.TransparencyLog{
    .{ .key = pki.ct_logs[0], .operator = "alpha" },
    .{ .key = pki.ct_logs[1], .operator = "beta" },
    .{ .key = pki.ct_logs[2], .operator = "alpha" },
    .{ .key = pki.ct_logs[3], .operator = "gamma" },
};
const required: types.TransparencyPolicy = .{ .logs = &logs };

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C10 Certificate Transparency: SCTs embedded in the certificate, or delivered in either version's handshake" {
    inline for (.{ .tls13, .tls12 }) |version| {
        // Embedded: nothing to deliver.
        {
            const duo = try connect(.{ .cert = .ct_leaf, .client_max = version, .client_transparency = &required });
            defer duo.deinit();
            try std.testing.expect(duo.client.info().?.peer_authenticated);
            try std.testing.expectEqual(version, duo.client.info().?.version);
        }
        // Delivered: the TLS 1.3 leaf's entry, the TLS 1.2 ServerHello.
        {
            const duo = try connect(.{ .cert = .ct_plain, .server_scts = pki.ct_plain_scts, .client_max = version, .client_transparency = &required });
            defer duo.deinit();
            try std.testing.expect(duo.client.info().?.peer_authenticated);
        }
        // Neither: the policy fails the handshake.
        {
            const duo = try Duo.init(gpa, .{ .cert = .ct_plain, .client_max = version, .client_transparency = &required });
            defer duo.deinit();
            try std.testing.expectError(error.VerificationRejected, duo.handshake());
        }
        // A server holding SCTs sends them only when asked: the client would refuse them unasked.
        {
            const duo = try connect(.{ .cert = .ct_plain, .server_scts = pki.ct_plain_scts, .client_max = version });
            defer duo.deinit();
            try std.testing.expect(duo.client.info().?.peer_authenticated);
        }
    }
}

test "C10 Certificate Transparency: options that cannot hold are refused" {
    // A policy that cannot decide.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_transparency = &.{} }));
    // SCTs for a credential with no certificate, malformed, or too long.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_raw = .only, .server_scts = pki.ct_plain_scts }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .cert = .ct_plain, .server_scts = pki.ct_plain_scts[0 .. pki.ct_plain_scts.len - 1] }));
    const long: [@import("handshake/Server.zig").Credential.max_scts + 1]u8 = @splat(0);
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .cert = .ct_plain, .server_scts = &long }));
}

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (the handshake: SCTs only where asked, on the leaf alone)" {
    // The hello asks with an empty extension, only under a policy requiring SCTs.
    var buffer: [2048]u8 = undefined;
    const random: [32]u8 = @splat(1);
    const share_bytes: [32]u8 = @splat(9);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share_bytes }};
    const asking = try Hello.client(&buffer, &random, "", "", &shares, "", .{ .groups = &.{.x25519}, .request_scts = true }, .{});
    try std.testing.expect((try ClientHello.parse(asking, .stream)).scts);
    const quiet = try Hello.client(&buffer, &random, "", "", &shares, "", .{ .groups = &.{.x25519} }, .{});
    try std.testing.expect(!(try ClientHello.parse(quiet, .stream)).scts);

    // Certificate: unasked SCTs are unsolicited; on an entry past the leaf illegal; empty, malformed.
    var out: [Messages.max_certificates][]const u8 = undefined;
    var message: [1024]u8 = undefined;
    const list = pki.ct_plain_scts;
    const leaf_only = try Messages.buildCertificate(&message, "", &.{ "leaf", "ca" }, .{ .scts = list });
    try std.testing.expectError(error.UnsolicitedExtension, Messages.certificate(leaf_only, 16, 65536, &out, .{}));
    try std.testing.expectError(error.UnsolicitedExtension, Messages.certificate(leaf_only, 16, 65536, &out, .{ .delegated = true }));
    try std.testing.expectEqualSlices(u8, list, (try Messages.certificate(leaf_only, 16, 65536, &out, .{ .scts = true })).leaf.scts.?);
    // Two entries, "a" bare and "b" carrying an SCT extension.
    const second = [_]u8{ 11, 0, 0, 22, 0, 0, 0, 18, 0, 0, 1, 'a', 0, 0, 0, 0, 1, 'b', 0, 6, 0, 18, 0, 2, 0xaa, 0xbb };
    try std.testing.expectError(error.IllegalParameter, Messages.certificate(&second, 16, 65536, &out, .{ .scts = true }));
    // One entry whose SCT extension is empty.
    const empty = [_]u8{ 11, 0, 0, 14, 0, 0, 0, 10, 0, 0, 1, 'a', 0, 4, 0, 18, 0, 0 };
    try std.testing.expectError(error.InvalidMessage, Messages.certificate(&empty, 16, 65536, &out, .{ .scts = true }));
}

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (resumption: no ticket outlives the log list or crosses policies)" {
    const hour = 60 * 60;
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var ring = try TicketKeys.init(gpa, .{});
    defer ring.deinit();
    try ring.rotate(&@as([32]u8, @splat(0x55)), types.instant(pki.time));
    var policy = required;
    policy.expires = types.instant(pki.time + 2 * hour);
    const options: Duo.Options = .{ .cert = .ct_leaf, .client_transparency = &policy, .cache = &cache, .tickets = &ring };
    {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    {
        // Within the log list's life a ticket resumes.
        var later = options;
        later.time = pki.time + hour;
        const duo = try connect(later);
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.resumed);
    }
    {
        // Past it the ticket is not offered: the full handshake meets a stale list and fails,
        // where a ticket would have stretched the verdict.
        var later = options;
        later.time = pki.time + 3 * hour;
        const duo = try Duo.init(gpa, later);
        defer duo.deinit();
        try std.testing.expectError(error.VerificationRejected, duo.handshake());
    }
    {
        // A new log list is another policy: its sessions start afresh.
        var renewed = policy;
        renewed.expires = types.instant(pki.time + 10 * hour);
        var later = options;
        later.client_transparency = &renewed;
        later.time = pki.time + hour;
        const duo = try connect(later);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    {
        // A session verified without Certificate Transparency never stands in for one with it.
        var plain_cache = try SessionCache.init(gpa, .{});
        defer plain_cache.deinit();
        var first = options;
        first.cert = .ct_plain;
        first.client_transparency = null;
        first.cache = &plain_cache;
        const duo = try connect(first);
        duo.deinit();
        var later = first;
        later.client_transparency = &required;
        later.time = pki.time + hour;
        const strict = try Duo.init(gpa, later);
        defer strict.deinit();
        try std.testing.expectError(error.VerificationRejected, strict.handshake());
    }
}
