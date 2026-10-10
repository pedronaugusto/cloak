const std = @import("std");
const Client = @import("Client.zig");
const Hello = @import("Hello.zig");
const Alert = @import("../wire/Alert.zig").Alert;

fn options(hello: Hello.Options) Client.Options {
    return .{ .hello = hello, .identity = .{ .dns = "example.com" }, .verify = .{ .full = .{ .trust_generation = .fromRaw(1) } } };
}

test "C2 client options are validated before any state exists" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidOptions, Client.init(gpa, .{ .verify = .{ .full = .{ .trust_generation = .fromRaw(1) } } }));
    try std.testing.expectError(error.InvalidOptions, Client.init(gpa, .{ .hello = .{ .quic = true, .alpn = &.{"h3"} }, .verify = .none, .compat = true }));
    try std.testing.expectError(error.InvalidOptions, Client.init(gpa, .{ .hello = .{ .suites = &.{} }, .verify = .none }));
    try std.testing.expectError(error.InvalidOptions, Client.init(gpa, .{ .verify = .none, .limits = .{ .message = 10 } }));
    try std.testing.expectError(error.InvalidOptions, Client.init(gpa, .{ .verify = .none, .limits = .{ .certificates = 0 } }));
    var ok = try Client.init(gpa, .{ .verify = .none });
    ok.deinit();
}

test "C2 client asks for exactly the entropy its first flight needs" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { hello: Hello.Options, compat: bool, expected: usize }{
        // random + session id + (ML-KEM seed + X25519) + X25519
        .{ .hello = .{}, .compat = true, .expected = 32 + 32 + 96 + 32 },
        .{ .hello = .{}, .compat = false, .expected = 32 + 96 + 32 },
        .{ .hello = .{ .groups = &.{.x25519} }, .compat = true, .expected = 32 + 32 + 32 },
        .{ .hello = .{ .groups = &.{.p256} }, .compat = true, .expected = 32 + 32 + 32 },
        .{ .hello = .{ .groups = &.{.p384} }, .compat = false, .expected = 32 + 48 },
        .{ .hello = .{ .groups = &.{ .p256, .x25519_mlkem768 } }, .compat = false, .expected = 32 + 96 },
    };
    for (cases) |case| {
        var o = options(case.hello);
        o.compat = case.compat;
        const client = try Client.init(gpa, o);
        defer client.deinit();
        try std.testing.expectEqual(case.expected, client.need().entropy.len);
        // The wrong amount is refused and leaves the request open.
        try std.testing.expectError(error.InvalidEntropy, client.provideEntropy(&@as([5]u8, @splat(1))));
        try std.testing.expectEqual(case.expected, client.need().entropy.len);
    }
}

test "C2 a rejected scalar draw leaves the entropy request open for a fresh one" {
    const gpa = std.testing.allocator;
    const client = try Client.init(gpa, options(.{ .groups = &.{.p256} }));
    defer client.deinit();
    var zeros: [128]u8 = @splat(0);
    try std.testing.expectError(error.InvalidEntropy, client.provideEntropy(zeros[0..client.need().entropy.len]));
    try std.testing.expect(client.need() == .entropy);
    try std.testing.expect(!client.pending());
    var good: [128]u8 = @splat(7);
    try client.provideEntropy(good[0..client.need().entropy.len]);
    try std.testing.expect(client.need() == .none);
    const emit = client.pop().?;
    try std.testing.expectEqual(Client.Epoch.initial, emit.message.epoch);
    const hello = client.flightBytes(emit.message.start, emit.message.len);
    try std.testing.expectEqual(@as(u8, 1), hello[0]);
    try std.testing.expect(client.pop() == null);
}

test "C2 a message while a service answer is owed is refused" {
    const gpa = std.testing.allocator;
    const client = try Client.init(gpa, options(.{}));
    defer client.deinit();
    try std.testing.expectError(error.Pending, client.receive("\x02\x00\x00\x00", .initial, true));
    // Services outside the request kind are refused too.
    try std.testing.expectError(error.UnexpectedService, client.provideTime(5));
    try std.testing.expectError(error.UnexpectedService, client.provideSignature("sig"));
    try std.testing.expectError(error.UnexpectedService, client.provideParameters(true));
}

test "C2 a message after a failure is refused as closed" {
    const gpa = std.testing.allocator;
    const client = try Client.init(gpa, .{ .verify = .none });
    defer client.deinit();
    client.state.fail();
    try std.testing.expectError(error.Closed, client.receive("\x02\x00\x00\x00", .initial, true));
}

test "C2 alert mapping names the right description for each failure class" {
    const cases = [_]struct { err: anyerror, alert: Alert }{
        .{ .err = error.UnexpectedMessage, .alert = .unexpected_message },
        .{ .err = error.RecordAlignment, .alert = .unexpected_message },
        .{ .err = error.InvalidLength, .alert = .decode_error },
        .{ .err = error.EmptyCertificate, .alert = .decode_error },
        .{ .err = error.DuplicateExtension, .alert = .illegal_parameter },
        .{ .err = error.WeakKey, .alert = .illegal_parameter },
        .{ .err = error.UnsolicitedExtension, .alert = .unsupported_extension },
        .{ .err = error.MissingExtension, .alert = .missing_extension },
        .{ .err = error.HybridRequired, .alert = .insufficient_security },
        .{ .err = error.UnsupportedVersion, .alert = .protocol_version },
        .{ .err = error.NoApplicationProtocol, .alert = .no_application_protocol },
        .{ .err = error.BadFinished, .alert = .decrypt_error },
        .{ .err = error.BadSignature, .alert = .decrypt_error },
        .{ .err = error.OutOfMemory, .alert = .internal_error },
        .{ .err = error.EntropyUnavailable, .alert = .internal_error },
    };
    for (cases) |case| try std.testing.expectEqual(case.alert, Client.alertFor(case.err));
}

test "C2 settle releases scratch only after the connection is established" {
    const gpa = std.testing.allocator;
    const client = try Client.init(gpa, .{ .verify = .none });
    defer client.deinit();
    client.settle();
    try std.testing.expect(client.info() == null);
}
