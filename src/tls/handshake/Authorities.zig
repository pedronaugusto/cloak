//! certificate_authorities (RFC 8446 section 4.2.4) and a TLS 1.2 CertificateRequest's field of
//! the same name (RFC 5246 section 7.4.4): the Distinguished Names of the anchors a peer trusts.
//! A received list is a preference in credential choice, never a refusal; a list is sent only
//! when the caller names one. Names are compared as bytes, never parsed.
const std = @import("std");
const Reader = @import("../../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const certificates = @import("../../certificates.zig");

/// The extension's number.
pub const extension = 47;

/// The most bytes the names a caller lists take on the wire, each with its two-byte length: about
/// a hundred names. A system store's ~150 anchors are past what a hello should carry, and a
/// server's list is the caller's choice of the anchors it names.
pub const max_bytes = 8192;

/// The names of an extension body, `authorities<3..2^16-1>` filling it: the list's contents, each
/// name with its length.
pub fn parse(body: []const u8) error{DecodeError}![]const u8 {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = body };
    const list = (r.vector(u16) catch return error.DecodeError).bytes;
    r.finish() catch return error.DecodeError;
    if (list.len == 0) return error.DecodeError;
    try check(list);
    return list;
}

/// Every name of a list's contents whole and of at least one byte (`DistinguishedName<1..2^16-1>`).
pub fn check(list: []const u8) error{DecodeError}!void {
    @setRuntimeSafety(true);
    var names: Reader = .{ .bytes = list };
    while (names.pos != list.len) {
        const name = names.vector(u16) catch return error.DecodeError;
        if (name.bytes.len == 0) return error.DecodeError;
    }
}

/// Whether `identity` chains to a named authority: a certificate of its chain, the leaf included,
/// has an issuer Name byte-equal to one in `list`, a checked list's contents (as Go's
/// `SupportsCertificate`). A raw public key never does: it has no issuer.
pub fn chains(identity: certificates.Identity, list: []const u8) bool {
    @setRuntimeSafety(true);
    for (identity.issuers()) |issuer| {
        var names: Reader = .{ .bytes = list };
        while (names.pos != list.len) {
            // The list was checked when it was read.
            const name = (names.vector(u16) catch return false).bytes;
            if (std.mem.eql(u8, name, issuer)) return true;
        }
    }
    return false;
}

/// Whether a peer that sent `list` (null: none) prefers `identity`: it named no authorities, or
/// `identity` chains to one of them.
pub fn prefers(identity: certificates.Identity, list: ?[]const u8) bool {
    @setRuntimeSafety(true);
    return if (list) |names| chains(identity, names) else true;
}

/// Credential `i`'s bit in a set of at most 32 that chain to the named authorities.
pub fn bit(i: usize) u32 {
    return @as(u32, 1) << @intCast(i); // safe: client credentials are at most 32
}

/// Whether credential `i` is preferred under `named`, the set that chains to the names a peer
/// sent: every credential when it sent none.
pub fn marked(named: ?u32, i: usize) bool {
    const set = named orelse return true;
    return set & bit(i) != 0;
}

/// A credential walk's choice: of the candidates that fit, offered in order, the first the peer
/// prefers, else the first.
pub fn Pick(comptime T: type) type {
    return struct {
        first: ?Choice = null,
        preferred: ?Choice = null,

        pub const Choice = struct { index: usize, value: T };

        /// Offers the candidate at `index` that fits with `value`; true when the walk can stop.
        pub fn offer(self: *@This(), index: usize, value: T, preferred: bool) bool {
            @setRuntimeSafety(true);
            if (self.first == null) self.first = .{ .index = index, .value = value };
            if (!preferred) return false;
            self.preferred = .{ .index = index, .value = value };
            return true;
        }

        pub fn chosen(self: @This()) ?Choice {
            return self.preferred orelse self.first;
        }
    };
}

/// The names a caller lists: each a DER Name, all within `max_bytes` on the wire.
pub fn validate(names: []const []const u8) error{InvalidOptions}!void {
    @setRuntimeSafety(true);
    if (wireLength(names) > max_bytes) return error.InvalidOptions;
    for (names) |name| {
        if (name.len == 0) return error.InvalidOptions;
        certificates.certificate.Name.validate(name) catch return error.InvalidOptions;
    }
}

/// The bytes of the list's contents: each name and its two-byte length.
pub fn wireLength(names: []const []const u8) usize {
    @setRuntimeSafety(true);
    var total: usize = 0;
    for (names) |name| total +|= 2 +| name.len;
    return total;
}

/// The list's contents, each name with its length; the caller writes the list's own length.
pub fn write(w: *Writer, names: []const []const u8) Writer.WriteError!void {
    @setRuntimeSafety(true);
    // safe: `validate` held each name and the whole list within `max_bytes`.
    for (names) |name| try w.vector(u16, name);
}

test {
    _ = @import("Authorities_test.zig");
}
