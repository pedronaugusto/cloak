//! A hostile ClientHello, parsed once into borrowed views. This checks structure and
//! uniqueness, never policy: which suite, group or identity to pick is the server's.
const std = @import("std");
const Reader = @import("../wire/Reader.zig");
const Extensions = @import("../wire/Extensions.zig");
const Group = @import("../crypto/Group.zig").Group;

pub const ParseError = Reader.ReadError || Extensions.NextError || error{
    InvalidHello,
    IllegalParameter,
    MissingExtension,
    DecodeError,
};

const ClientHello = @This();

random: []const u8,
session: []const u8,
/// Two-byte cipher suite identifiers, in the client's order.
suites: []const u8,
/// supported_groups identifiers, two bytes each; empty when the extension is absent.
groups: []const u8,
/// key_share entries: group, then a two-byte length and the key_exchange bytes.
shares: []const u8,
/// signature_algorithms identifiers, two bytes each.
schemes: []const u8,
/// supported_versions identifiers, two bytes each.
versions: []const u8,
/// The host_name from server_name, or empty.
server_name: []const u8,
/// ProtocolNameList entries: one-byte length then name; empty when absent.
alpn: []const u8,
/// The quic_transport_parameters body, when sent.
parameters: ?[]const u8,
cookie: []const u8,
early_data: bool,
has_psk: bool,
has_groups: bool,
has_shares: bool,
has_schemes: bool,
/// The whole extension block, for the comparison a retry requires.
extensions: []const u8,

pub fn parse(message: []const u8) ParseError!ClientHello {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 1 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    _ = try r.int(u16); // legacy_version: ignored when supported_versions is present
    var self: ClientHello = undefined;
    self.random = try r.take(32);
    self.session = (try r.vector(u8)).bytes;
    if (self.session.len > 32) return error.DecodeError;
    self.suites = (try r.vector(u16)).bytes;
    if (self.suites.len < 2 or self.suites.len % 2 != 0) return error.DecodeError;
    const compression = (try r.vector(u8)).bytes;
    if (compression.len != 1 or compression[0] != 0) return error.IllegalParameter;
    // A TLS 1.2 hello may carry no extensions at all; the caller refuses it by its versions.
    const block: Reader = if (r.pos == r.bytes.len) .{ .bytes = "" } else try r.vector(u16);
    self.extensions = block.bytes;
    try r.finish();
    self.groups = "";
    self.shares = "";
    self.schemes = "";
    self.versions = "";
    self.server_name = "";
    self.alpn = "";
    self.parameters = null;
    self.cookie = "";
    self.early_data = false;
    self.has_psk = false;
    self.has_groups = false;
    self.has_shares = false;
    self.has_schemes = false;
    var modes = false;
    var ext: Extensions = .{ .reader = block };
    var last: u16 = 0;
    while (try ext.next()) |item| {
        last = item.id;
        try self.extension(item.id, item.bytes, &modes);
    }
    if (self.has_psk) {
        // pre_shared_key must be the last extension, and needs its exchange modes.
        if (last != 41) return error.IllegalParameter;
        if (!modes) return error.MissingExtension;
    }
    return self;
}

fn extension(self: *ClientHello, id: u16, bytes: []const u8, modes: *bool) ParseError!void {
    @setRuntimeSafety(true);
    var value: Reader = .{ .bytes = bytes };
    switch (id) {
        0 => {
            var list = try value.vector(u16);
            try value.finish();
            var seen = false;
            while (list.pos != list.bytes.len) {
                const kind = try list.int(u8);
                const name = (try list.vector(u16)).bytes;
                if (kind != 0) continue;
                if (seen or !hostName(name)) return error.IllegalParameter;
                seen = true;
                self.server_name = name;
            }
            if (!seen) return error.IllegalParameter;
        },
        10 => {
            self.groups = (try value.vector(u16)).bytes;
            try value.finish();
            if (self.groups.len < 2 or self.groups.len % 2 != 0) return error.DecodeError;
            self.has_groups = true;
        },
        13 => {
            self.schemes = (try value.vector(u16)).bytes;
            try value.finish();
            if (self.schemes.len < 2 or self.schemes.len % 2 != 0) return error.DecodeError;
            self.has_schemes = true;
        },
        16 => {
            const list = (try value.vector(u16)).bytes;
            try value.finish();
            if (list.len == 0) return error.DecodeError;
            var names: Reader = .{ .bytes = list };
            while (names.pos != names.bytes.len) {
                if ((try names.vector(u8)).bytes.len == 0) return error.DecodeError;
            }
            self.alpn = list;
        },
        41 => {
            if (bytes.len == 0) return error.DecodeError;
            self.has_psk = true;
        },
        42 => {
            if (bytes.len != 0) return error.DecodeError;
            self.early_data = true;
        },
        43 => {
            self.versions = (try value.vector(u8)).bytes;
            try value.finish();
            if (self.versions.len < 2 or self.versions.len % 2 != 0) return error.DecodeError;
        },
        44 => {
            self.cookie = (try value.vector(u16)).bytes;
            try value.finish();
            if (self.cookie.len == 0) return error.DecodeError;
        },
        45 => {
            if ((try value.vector(u8)).bytes.len == 0) return error.DecodeError;
            try value.finish();
            modes.* = true;
        },
        51 => {
            self.shares = (try value.vector(u16)).bytes;
            try value.finish();
            var entries: Reader = .{ .bytes = self.shares };
            var groups_seen: [32]u16 = undefined;
            var count: usize = 0;
            while (entries.pos != entries.bytes.len) {
                const group = try entries.int(u16);
                if ((try entries.vector(u16)).bytes.len == 0) return error.DecodeError;
                if (std.mem.containsAtLeast(u16, groups_seen[0..count], 1, &.{group})) return error.IllegalParameter;
                if (count == groups_seen.len) return error.IllegalParameter;
                groups_seen[count] = group;
                count += 1;
            }
            self.has_shares = true;
        },
        57 => self.parameters = bytes,
        else => {},
    }
}

/// Letters, digits, hyphen and underscore in labels of at most 63 bytes, 253 in all.
fn hostName(name: []const u8) bool {
    @setRuntimeSafety(true);
    if (name.len == 0 or name.len > 253) return false;
    var label: usize = 0;
    for (name) |c| {
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
        } else {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
            label += 1;
            if (label > 63) return false;
        }
    }
    return label != 0;
}

pub fn offersVersion(self: *const ClientHello, version: u16) bool {
    return containsU16(self.versions, version);
}

pub fn offersSuite(self: *const ClientHello, id: u16) bool {
    return containsU16(self.suites, id);
}

pub fn offersGroup(self: *const ClientHello, group: Group) bool {
    return containsU16(self.groups, @backingInt(group));
}

pub fn accepts(self: *const ClientHello, scheme: u16) bool {
    return containsU16(self.schemes, scheme);
}

/// The key_exchange bytes the client sent for `group`, if any.
pub fn shareFor(self: *const ClientHello, group: Group) ?[]const u8 {
    @setRuntimeSafety(true);
    var entries: Reader = .{ .bytes = self.shares };
    while (entries.pos != entries.bytes.len) {
        // The entries were validated while parsing.
        const id = entries.int(u16) catch return null;
        const bytes = entries.vector(u16) catch return null;
        if (id == @backingInt(group)) return bytes.bytes;
    }
    return null;
}

/// Whether a share was sent for a group that supported_groups does not list (illegal).
pub fn sharesOutsideGroups(self: *const ClientHello) bool {
    @setRuntimeSafety(true);
    var entries: Reader = .{ .bytes = self.shares };
    while (entries.pos != entries.bytes.len) {
        const id = entries.int(u16) catch return true;
        _ = entries.vector(u16) catch return true;
        if (!containsU16(self.groups, id)) return true;
    }
    return false;
}

/// The offered protocol equal to one of `preference`, in the server's order.
pub fn selectAlpn(self: *const ClientHello, preference: []const []const u8) ?[]const u8 {
    @setRuntimeSafety(true);
    for (preference) |wanted| {
        var names: Reader = .{ .bytes = self.alpn };
        while (names.pos != names.bytes.len) {
            const name = names.vector(u8) catch return null;
            if (std.mem.eql(u8, name.bytes, wanted)) return wanted;
        }
    }
    return null;
}

fn containsU16(list: []const u8, id: u16) bool {
    @setRuntimeSafety(true);
    var at: usize = 0;
    while (at + 2 <= list.len) : (at += 2) {
        if (std.mem.readInt(u16, list[at..][0..2], .big) == id) return true;
    }
    return false;
}

/// A digest of everything a retry's second ClientHello may not change: the random, session id,
/// suites and every extension except the key share, cookie, early data, PSK and padding
/// (RFC 8446 section 4.1.2). Extension order is not part of it.
pub fn fingerprint(self: *const ClientHello) [32]u8 {
    @setRuntimeSafety(true);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(self.random);
    h.update(&.{@intCast(self.session.len)}); // safe: parsing bounds the session id at 32 bytes
    h.update(self.session);
    h.update(self.suites);
    const Entry = struct { id: u16, bytes: []const u8 };
    var entries: [64]Entry = undefined;
    var count: usize = 0;
    var ext: Extensions = .{ .reader = .{ .bytes = self.extensions } };
    // The block was validated when parsed; an iteration error cannot occur.
    while (ext.next() catch null) |item| {
        if (exempt(item.id)) continue;
        var at = count;
        while (at > 0 and entries[at - 1].id > item.id) : (at -= 1) entries[at] = entries[at - 1];
        entries[at] = .{ .id = item.id, .bytes = item.bytes };
        count += 1;
    }
    for (entries[0..count]) |entry| {
        var head: [6]u8 = undefined;
        std.mem.writeInt(u16, head[0..2], entry.id, .big);
        std.mem.writeInt(u32, head[2..6], @intCast(entry.bytes.len), .big); // safe: an extension is at most 65,535 bytes
        h.update(&head);
        h.update(entry.bytes);
    }
    return h.finalResult();
}

fn exempt(id: u16) bool {
    return id == 51 or id == 44 or id == 42 or id == 41 or id == 21;
}

test {
    _ = @import("ClientHello_test.zig");
}
