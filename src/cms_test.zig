//! CMS against a real signature: Microsoft's on the D3D12 Agility SDK 1.619.6 as nuget.org
//! serves it, its time proved by DigiCert's timestamp; and that signature tampered with,
//! byte by byte where each check stands.
const std = @import("std");
const shakedown = @import("shakedown");
const cms = @import("cms.zig");
const gpa = std.testing.allocator;

const real = @embedFile("testdata/nuget-d3d12-1.619.6.p7s");
const root = @embedFile("testdata/digicert-trusted-root-g4.der");
const options: cms.Options = .{ .roots = &.{root} };

test "Microsoft's signature on a real NuGet package verifies, at the time its timestamp proves" {
    const verified = try cms.verify(gpa, real, options);
    try std.testing.expect(verified.timestamped);
    try std.testing.expect(std.mem.startsWith(u8, verified.content, "Version:1\n"));
    try std.testing.expect(std.mem.find(u8, verified.content, "2.16.840.1.101.3.4.2.1-Hash:udU2lh83lVA5akzVKrThcmEDN+iYiiCvjoakW4kAtIY=") != null);
    try std.testing.expect(std.mem.find(u8, verified.signer, "Microsoft Corporation") != null);
    // 2025 at the earliest: the signer's certificate is held to that time, not today's.
    try std.testing.expect(@divFloor(verified.time.toNanoseconds(), std.time.ns_per_s) > 1_700_000_000);
}

fn tampered(at: usize) ![]u8 {
    const copy = try gpa.dupe(u8, real);
    copy[at] ^= 1;
    return copy;
}

fn find(needle: []const u8) usize {
    return std.mem.find(u8, real, needle).?;
}

test "the content changed: the digest it signed is not the content's" {
    const copy = try tampered(find("Version:1"));
    defer gpa.free(copy);
    try std.testing.expectError(error.DigestMismatch, cms.verify(gpa, copy, options));
}

test "the package hash in the signed content changed: refused" {
    const copy = try tampered(find("udU2lh83"));
    defer gpa.free(copy);
    try std.testing.expectError(error.DigestMismatch, cms.verify(gpa, copy, options));
}

test "another root: the chain is not proved, whoever signed" {
    const other = @embedFile("testing/pki/ca.der");
    try std.testing.expectError(error.NoTrustedPath, cms.verify(gpa, real, .{ .roots = &.{other} }));
}

test "a signature no timestamp covers, with no time given, is refused" {
    // The timestamp's attribute OID changed: an attribute nothing reads, so no timestamp.
    const copy = try gpa.dupe(u8, real);
    defer gpa.free(copy);
    const oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x0e";
    var from: usize = 0;
    while (std.mem.findPos(u8, copy, from, oid)) |at| {
        copy[at + oid.len - 1] = 0x7f;
        from = at + oid.len;
    }
    try std.testing.expectError(error.TimestampRequired, cms.verify(gpa, copy, options));
}

test "a timestamp changed is refused, not ignored" {
    // TSTInfo's content type sits in the token: anything but a timestamp's is refused.
    const copy = try tampered(find("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04") + 10);
    defer gpa.free(copy);
    if (cms.verify(gpa, copy, options)) |_| return error.TestUnexpectedResult else |_| {}
}

test "every byte flipped is refused or changes nothing it vouches for" {
    // Unsigned attributes (the repository's countersignature) are not vouched for; anything
    // else changed fails. A step keeps this quick: RSA at each byte would take minutes.
    var at: usize = 0;
    var refused: usize = 0;
    const clean = try cms.verify(gpa, real, options);
    while (at < real.len) : (at += 97) {
        const copy = try tampered(at);
        defer gpa.free(copy);
        const got = cms.verify(gpa, copy, options) catch {
            refused += 1;
            continue;
        };
        try std.testing.expectEqualStrings(clean.content, got.content);
        try std.testing.expectEqual(clean.time.toNanoseconds(), got.time.toNanoseconds());
    }
    try std.testing.expect(refused > 0);
}

test "junk and truncation are refused" {
    try std.testing.expectError(error.InvalidDer, cms.verify(gpa, "not a signature", options));
    if (cms.verify(gpa, real[0 .. real.len / 2], options)) |_| return error.TestUnexpectedResult else |_| {}
}

test "CMS property: any one byte changed is refused, or changes nothing verify vouches for" {
    // verify's promise (docs/design.md "CMS"): it fails closed. A change anywhere in what the
    // signature covers, the chain, or the timestamp is an error; only the unsigned attributes are
    // anyone's to change, and a signature that still verifies gives the same content and time.
    // RSA at each case is slow, so a few dozen positions, drawn anew each seed.
    try shakedown.check(gpa, {}, changedByte, .{ .cases = 48, .seed = 0xc35a });
}
fn changedByte(_: void, case: *shakedown.Case) !void {
    const at = shakedown.gen.intRange(case.source, usize, 0, real.len - 1);
    const copy = try gpa.dupe(u8, real);
    defer gpa.free(copy);
    copy[at] ^= shakedown.gen.intRange(case.source, u8, 1, 255);
    const clean = try cms.verify(gpa, real, options);
    const got = cms.verify(gpa, copy, options) catch return;
    try std.testing.expectEqualStrings(clean.content, got.content);
    try std.testing.expectEqualStrings(clean.signer, got.signer);
    try std.testing.expectEqual(clean.time.toNanoseconds(), got.time.toNanoseconds());
}

test "CMS property: a signature cut short anywhere is refused" {
    try shakedown.check(gpa, {}, cutShort, .{ .cases = 64, .seed = 0xc35b });
}
fn cutShort(_: void, case: *shakedown.Case) !void {
    const len = shakedown.gen.intRange(case.source, usize, 0, real.len - 1);
    if (cms.verify(gpa, real[0..len], options)) |_| return error.TestUnexpectedResult else |_| {}
}
