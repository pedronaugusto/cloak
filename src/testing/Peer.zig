//! A scripted TLS 1.3 server for tests. It speaks real records and real messages so the
//! client under test sees exactly what a peer sends, and it can misbehave in named ways. It
//! reuses cloak's HKDF, key schedule and record protection, which the RFC 8448 vectors pin
//! independently; its hello parsing, message assembly and signatures are its own.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../tls/crypto/Suite.zig");
const Labels = @import("../tls/crypto/Labels.zig");
const Group = @import("../tls/crypto/Group.zig").Group;
const Epoch = @import("../tls/record/Epoch.zig");
const Schedule = @import("../tls/handshake/Schedule.zig");
const Transcript = @import("../tls/handshake/Transcript.zig").Transcript;
const Suite = suites.Suite;

pub const pki = struct {
    pub const ca = @embedFile("pki/ca.der");
    pub const p256 = @embedFile("pki/p256.der");
    pub const p384 = @embedFile("pki/p384.der");
    pub const ed25519 = @embedFile("pki/ed25519.der");
    pub const rsa = @embedFile("pki/rsa.der");
    pub const client = @embedFile("pki/client.der");
    pub const client_ed25519 = @embedFile("pki/client_ed25519.der");
    pub const p256_secret = @embedFile("pki/p256.secret");
    pub const p384_secret = @embedFile("pki/p384.secret");
    pub const ed25519_secret = @embedFile("pki/ed25519.secret");
    pub const client_secret = @embedFile("pki/client.secret");
    pub const client_ed25519_secret = @embedFile("pki/client_ed25519.secret");
    pub const p256_pem = @embedFile("pki/p256.key.pem");
    pub const p384_pem = @embedFile("pki/p384.key.pem");
    pub const ed25519_pem = @embedFile("pki/ed25519.key.pem");
    pub const rsa_pem = @embedFile("pki/rsa.key.pem");
    pub const client_pem = @embedFile("pki/client.key.pem");
    pub const client_ed25519_pem = @embedFile("pki/client_ed25519.key.pem");
    /// A time inside every fixture's validity.
    pub const time: i64 = 1_800_000_000;
};

pub const Cert = enum { p256, p384, ed25519 };

/// How the server flight is cut into records.
pub const Layout = union(enum) {
    /// EncryptedExtensions through Finished in one record.
    coalesced,
    /// One record per message.
    separate,
    /// Records of at most this many bytes, ignoring message boundaries.
    fragments: usize,
};

pub const Tamper = enum {
    none,
    bad_finished,
    bad_signature,
    missing_certificate_verify,
    scheme_not_offered,
    scheme_curve_mismatch,
    duplicate_extension_in_encrypted,
    unoffered_alpn,
    extension_in_certificate_entry,
    wrong_session_id,
    unoffered_group,
    second_retry,
    plaintext_encrypted_extensions,
    encrypted_extensions_in_hello_record,
    finished_not_at_record_end,
    application_before_finished,
    empty_certificate_list,
    nonempty_certificate_context,
    zero_key_share,
    bad_tag,
    ticket_flood,
    key_update_flood,
    certificate_request_late,
    ccs_after_finished,
    /// A TLS 1.2 ServerHello: no supported_versions.
    legacy_server_hello,
    /// A TLS 1.2 ServerHello carrying the downgrade sentinel in its random.
    downgrade_sentinel,
};

pub const Config = struct {
    cert: Cert = .p256,
    group: Group = .x25519,
    /// Ask for this group in a HelloRetryRequest before the real hello.
    retry: ?Group = null,
    alpn: ?[]const u8 = null,
    request_client_cert: bool = false,
    /// The signature_algorithms of that CertificateRequest.
    request_schemes: []const u16 = &.{0x0403},
    layout: Layout = .coalesced,
    ccs: bool = true,
    tickets: usize = 1,
    tamper: Tamper = .none,
    cookie: []const u8 = "",
    /// Only the cookie in the retry request, no group change.
    cookie_only: bool = false,
    /// Speak the record-free QUIC dialect: messages per level, no records, no CCS.
    quic: bool = false,
    /// The transport parameters the server sends in EncryptedExtensions (QUIC only).
    quic_parameters: []const u8 = "server-params",
    /// Omit the transport parameters extension (QUIC only).
    omit_quic_parameters: bool = false,
    duplicate_quic_parameters: bool = false,
    /// Send these bytes, sealed under the handshake keys, instead of the real server flight.
    raw_flight: ?[]const u8 = null,
};

/// What the peer parsed from the client's hello, for assertions.
pub const Seen = struct {
    session_id_len: usize = 0,
    sni: [64]u8 = undefined,
    sni_len: usize = 0,
    alpn: [8][16]u8 = undefined,
    alpn_len: [8]u8 = @splat(0),
    alpn_count: usize = 0,
    groups: [8]u16 = @splat(0),
    group_count: usize = 0,
    shares: [4]u16 = @splat(0),
    share_count: usize = 0,
    versions_only_13: bool = false,
    extension_ids: [24]u16 = @splat(0),
    extension_count: usize = 0,
    suites: [8]u16 = @splat(0),
    suite_count: usize = 0,
    has_psk: bool = false,
    has_early_data: bool = false,
    legacy_version: u16 = 0,
    random: [32]u8 = @splat(0),
    cookie_len: usize = 0,
    hellos: usize = 0,
    ccs: usize = 0,
    first_hello_record_version: u16 = 0,
    quic_parameters: [64]u8 = undefined,
    quic_parameters_len: usize = 0,
    has_quic_parameters: bool = false,

    pub fn offeredGroup(self: *const Seen, group: Group) bool {
        for (self.groups[0..self.group_count]) |g| if (g == @backingInt(group)) return true;
        return false;
    }
    pub fn sharedGroup(self: *const Seen, group: Group) bool {
        for (self.shares[0..self.share_count]) |g| if (g == @backingInt(group)) return true;
        return false;
    }
    pub fn offeredAlpn(self: *const Seen, name: []const u8) bool {
        for (0..self.alpn_count) |i| if (std.mem.eql(u8, self.alpn[i][0..self.alpn_len[i]], name)) return true;
        return false;
    }
};

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,
    fn put(w: *Writer, b: []const u8) void {
        @memcpy(w.bytes[w.pos..][0..b.len], b);
        w.pos += b.len;
    }
    fn int(w: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, w.bytes[w.pos..][0..@sizeOf(T)], v, .big);
        w.pos += @sizeOf(T);
    }
};

fn appendMessage(gpa: std.mem.Allocator, list: *std.ArrayList(u8), kind: u8, body: []const u8) !void {
    try list.append(gpa, kind);
    var len: [3]u8 = undefined;
    std.mem.writeInt(u24, &len, @intCast(body.len), .big);
    try list.appendSlice(gpa, &len);
    try list.appendSlice(gpa, body);
}

/// A CertificateRequest body: an empty context and only signature_algorithms.
fn certificateRequest(gpa: std.mem.Allocator, list: *std.ArrayList(u8), schemes: []const u16) !void {
    var body: [9 + 2 * 16]u8 = undefined;
    std.debug.assert(schemes.len <= 16);
    const list_len = 2 * schemes.len;
    body[0] = 0;
    std.mem.writeInt(u16, body[1..3], @intCast(list_len + 6), .big);
    std.mem.writeInt(u16, body[3..5], 13, .big);
    std.mem.writeInt(u16, body[5..7], @intCast(list_len + 2), .big);
    std.mem.writeInt(u16, body[7..9], @intCast(list_len), .big);
    for (schemes, 0..) |scheme, i| std.mem.writeInt(u16, body[9 + 2 * i ..][0..2], scheme, .big);
    try appendMessage(gpa, list, 13, body[0 .. 9 + list_len]);
}

pub fn rsaPssScheme(scheme: u16) bool {
    return scheme >= 0x0804 and scheme <= 0x0806;
}

/// An rsa_pss_rsae signature by the key of the certificate `der`, checked by std alone.
pub fn verifyRsaPss(der: []const u8, scheme: u16, sig: []const u8, content: []const u8) bool {
    const StdCertificate = std.crypto.Certificate;
    const sha2 = std.crypto.hash.sha2;
    const parsed = (StdCertificate{ .buffer = der, .index = 0 }).parse() catch return false;
    const parts = StdCertificate.rsa.PublicKey.parseDer(parsed.pubKey()) catch return false;
    const key = StdCertificate.rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch return false;
    inline for (.{ 256, 384, 512 }) |len| if (sig.len == len) {
        const result = switch (scheme) {
            0x0804 => StdCertificate.rsa.PSSSignature.verify(len, sig[0..len], content, key, sha2.Sha256),
            0x0805 => StdCertificate.rsa.PSSSignature.verify(len, sig[0..len], content, key, sha2.Sha384),
            else => StdCertificate.rsa.PSSSignature.verify(len, sig[0..len], content, key, sha2.Sha512),
        };
        result catch return false;
        return true;
    };
    return false;
}

fn signedContent(digest: []const u8, server: bool, out: *[64 + 34 + 48]u8) []const u8 {
    const label = if (server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..label.len], label);
    out[64 + label.len] = 0;
    @memcpy(out[65 + label.len ..][0..digest.len], digest);
    return out[0 .. 65 + label.len + digest.len];
}

pub fn Peer(comptime suite: Suite) type {
    const K = Schedule.Schedule(suite);
    const Hash = suites.Hash(suite);
    const E = Epoch.Epoch(suite);
    return struct {
        const Self = @This();
        const MlKem = std.crypto.kem.ml_kem.MLKem768;
        const X25519 = std.crypto.dh.X25519;
        const Secret = [Hash.digest_length]u8;

        gpa: std.mem.Allocator,
        config: Config,
        input: std.ArrayList(u8) = .empty,
        out: std.ArrayList(u8) = .empty,
        hello_bytes: std.ArrayList(u8) = .empty,
        client_flight: std.ArrayList(u8) = .empty,
        transcript: Transcript(Hash) = .{},
        sent_retry: bool = false,
        sent_ccs: bool = false,
        sent_second_retry: bool = false,
        connected: bool = false,
        seen: Seen = .{},
        session_id: [32]u8 = undefined,
        session_len: usize = 0,
        schedule: ?K = null,
        tx: ?E = null,
        rx: ?E = null,
        client_hs: Secret = undefined,
        level_out: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
        quic_client_messages: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
        server_hs: Secret = undefined,
        client_app: Secret = undefined,
        server_app: Secret = undefined,
        exporter: Secret = undefined,
        server_finished_hash: Secret = undefined,
        // What the client did.
        received: std.ArrayList(u8) = .empty,
        client_chain: std.ArrayList(u8) = .empty,
        client_certificates: usize = 0,
        client_signature_ok: bool = false,
        client_finished_ok: bool = false,
        close_notify: bool = false,
        alert: ?u8 = null,
        key_updates_seen: usize = 0,

        pub fn init(gpa: std.mem.Allocator, config: Config) Self {
            return .{ .gpa = gpa, .config = config };
        }

        pub fn deinit(self: *Self) void {
            self.input.deinit(self.gpa);
            self.out.deinit(self.gpa);
            self.hello_bytes.deinit(self.gpa);
            self.client_flight.deinit(self.gpa);
            self.received.deinit(self.gpa);
            for (&self.level_out) |*list| list.deinit(self.gpa);
            for (&self.quic_client_messages) |*list| list.deinit(self.gpa);
            self.client_chain.deinit(self.gpa);
            if (self.schedule) |*s| s.deinit();
            if (self.tx) |*e| e.deinit();
            if (self.rx) |*e| e.deinit();
            std.crypto.secureZero(u8, std.mem.asBytes(&self.client_hs));
        }

        /// Bytes for the client.
        pub fn pending(self: *const Self) []const u8 {
            return self.out.items;
        }
        pub fn drained(self: *Self, n: usize) void {
            const rest = self.out.items.len - n;
            @memmove(self.out.items[0..rest], self.out.items[n..]);
            self.out.shrinkRetainingCapacity(rest);
        }

        fn epochFrom(secret: *const Secret) !E {
            var holder = aegis.Secret(Secret).init(secret.*);
            defer holder.deinit();
            return E.initTraffic(&holder, .{});
        }

        // ------------------------------------------------------------ input

        pub fn feed(self: *Self, wire: []const u8) !void {
            try self.input.appendSlice(self.gpa, wire);
            while (true) {
                const bytes = self.input.items;
                if (bytes.len < 5) return;
                const length = std.mem.readInt(u16, bytes[3..5], .big);
                if (bytes.len < 5 + length) return;
                const record = try self.gpa.dupe(u8, bytes[0 .. 5 + length]);
                defer self.gpa.free(record);
                const rest = bytes.len - record.len;
                @memmove(self.input.items[0..rest], bytes[record.len..]);
                self.input.shrinkRetainingCapacity(rest);
                try self.onRecord(record);
            }
        }

        fn onRecord(self: *Self, wire: []u8) !void {
            switch (wire[0]) {
                20 => self.seen.ccs += 1,
                21 => self.alert = wire[6],
                22 => {
                    if (self.seen.hellos == 0) self.seen.first_hello_record_version = std.mem.readInt(u16, wire[1..3], .big);
                    try self.onHelloBytes(wire[5..]);
                },
                23 => {
                    const plain = try self.rx.?.open(wire, wire[5..]);
                    switch (plain.content) {
                        .handshake => try self.onClientHandshake(plain.bytes),
                        .application => try self.received.appendSlice(self.gpa, plain.bytes),
                        .alert => {
                            self.alert = plain.bytes[1];
                            if (plain.bytes[1] == 0) self.close_notify = true;
                        },
                    }
                },
                else => return error.PeerBadRecord,
            }
        }

        fn onHelloBytes(self: *Self, bytes: []const u8) !void {
            try self.hello_bytes.appendSlice(self.gpa, bytes);
            if (self.hello_bytes.items.len < 4) return;
            const total = 4 + @as(usize, std.mem.readInt(u24, self.hello_bytes.items[1..4], .big));
            if (self.hello_bytes.items.len < total) return;
            const hello = try self.gpa.dupe(u8, self.hello_bytes.items[0..total]);
            defer self.gpa.free(hello);
            self.hello_bytes.clearRetainingCapacity();
            try self.onClientHello(hello);
        }

        // ------------------------------------------------------------ hello

        fn onClientHello(self: *Self, hello: []const u8) !void {
            if (hello[0] != 1) return error.PeerUnexpected;
            const seen = &self.seen;
            seen.hellos += 1;
            var at: usize = 4;
            seen.legacy_version = std.mem.readInt(u16, hello[at..][0..2], .big);
            at += 2;
            seen.random = hello[at..][0..32].*;
            at += 32;
            const sid = hello[at];
            at += 1;
            @memcpy(self.session_id[0..sid], hello[at..][0..sid]);
            self.session_len = sid;
            seen.session_id_len = sid;
            at += sid;
            const suites_len = std.mem.readInt(u16, hello[at..][0..2], .big);
            at += 2;
            seen.suite_count = 0;
            var i: usize = 0;
            while (i < suites_len) : (i += 2) {
                if (seen.suite_count < seen.suites.len) {
                    seen.suites[seen.suite_count] = std.mem.readInt(u16, hello[at + i ..][0..2], .big);
                    seen.suite_count += 1;
                }
            }
            at += suites_len;
            at += 1 + hello[at];
            const ext_len = std.mem.readInt(u16, hello[at..][0..2], .big);
            at += 2;
            const end = at + ext_len;
            seen.extension_count = 0;
            seen.share_count = 0;
            seen.group_count = 0;
            seen.alpn_count = 0;
            seen.sni_len = 0;
            seen.cookie_len = 0;
            var shares: [4]struct { group: u16, bytes: []const u8 } = undefined;
            while (at < end) {
                const id = std.mem.readInt(u16, hello[at..][0..2], .big);
                const len = std.mem.readInt(u16, hello[at + 2 ..][0..2], .big);
                const body = hello[at + 4 ..][0..len];
                at += 4 + len;
                if (seen.extension_count < seen.extension_ids.len) {
                    seen.extension_ids[seen.extension_count] = id;
                    seen.extension_count += 1;
                }
                switch (id) {
                    0 => {
                        const n = std.mem.readInt(u16, body[3..5], .big);
                        @memcpy(seen.sni[0..n], body[5..][0..n]);
                        seen.sni_len = n;
                    },
                    10 => {
                        var g: usize = 2;
                        while (g < body.len) : (g += 2) {
                            if (seen.group_count < seen.groups.len) {
                                seen.groups[seen.group_count] = std.mem.readInt(u16, body[g..][0..2], .big);
                                seen.group_count += 1;
                            }
                        }
                    },
                    16 => {
                        var p: usize = 2;
                        while (p < body.len) {
                            const n = body[p];
                            if (seen.alpn_count < 8 and n <= 16) {
                                @memcpy(seen.alpn[seen.alpn_count][0..n], body[p + 1 ..][0..n]);
                                seen.alpn_len[seen.alpn_count] = n;
                                seen.alpn_count += 1;
                            }
                            p += 1 + n;
                        }
                    },
                    43 => seen.versions_only_13 = body.len == 3 and body[0] == 2 and body[1] == 3 and body[2] == 4,
                    41 => seen.has_psk = true,
                    57 => {
                        seen.has_quic_parameters = true;
                        seen.quic_parameters_len = body.len;
                        @memcpy(seen.quic_parameters[0..@min(body.len, 64)], body[0..@min(body.len, 64)]);
                    },
                    42 => seen.has_early_data = true,
                    44 => seen.cookie_len = std.mem.readInt(u16, body[0..2], .big),
                    51 => {
                        var s: usize = 2;
                        while (s < body.len) {
                            const group = std.mem.readInt(u16, body[s..][0..2], .big);
                            const n = std.mem.readInt(u16, body[s + 2 ..][0..2], .big);
                            if (seen.share_count < 4) {
                                shares[seen.share_count] = .{ .group = group, .bytes = body[s + 4 ..][0..n] };
                                seen.shares[seen.share_count] = group;
                                seen.share_count += 1;
                            }
                            s += 4 + n;
                        }
                    },
                    else => {},
                }
            }
            try self.transcript.commit(hello);
            if (self.config.retry) |wanted| if (!self.sent_retry) {
                self.sent_retry = true;
                return self.sendRetry(wanted);
            };
            if (self.config.tamper == .second_retry and self.sent_retry == false) {
                self.sent_retry = true;
                return self.sendRetry(self.config.group);
            }
            if (self.config.tamper == .second_retry and seen.hellos == 2) return self.sendRetry(.p384);
            const want = @backingInt(self.config.group);
            for (shares[0..seen.share_count]) |share| if (share.group == want) return self.sendFlight(share.bytes);
            return error.PeerNoMatchingShare;
        }

        fn sendRetry(self: *Self, group: Group) !void {
            var message: [4200]u8 = undefined;
            var w: Writer = .{ .bytes = &message };
            w.put(&.{ 2, 0, 0, 0, 3, 3 });
            w.put(&std.crypto.tls.hello_retry_request_sequence);
            w.put(&.{@intCast(self.session_len)});
            w.put(self.session_id[0..self.session_len]);
            w.int(u16, @backingInt(suite));
            w.put(&.{0});
            const ext_at = w.pos;
            w.int(u16, 0);
            w.put(&.{ 0, 43, 0, 2, 3, 4 });
            if (!self.config.cookie_only) {
                w.put(&.{ 0, 51, 0, 2 });
                w.int(u16, @backingInt(group));
            }
            if (self.config.cookie.len != 0) {
                w.int(u16, 44);
                w.int(u16, @intCast(self.config.cookie.len + 2));
                w.int(u16, @intCast(self.config.cookie.len));
                w.put(self.config.cookie);
            }
            std.mem.writeInt(u16, message[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
            std.mem.writeInt(u24, message[1..4], @intCast(w.pos - 4), .big);
            const hrr = message[0..w.pos];
            if (self.sent_second_retry) {} else if (self.seen.hellos == 2) self.sent_second_retry = true else try self.transcript.retry(hrr);
            if (self.config.quic) return self.emit(.initial, hrr);
            try self.plainRecord(hrr);
            try self.compatCcs();
        }

        /// A server sends its one compatibility change_cipher_spec after its first message.
        fn compatCcs(self: *Self) !void {
            if (!self.config.ccs or self.session_len == 0 or self.sent_ccs) return;
            self.sent_ccs = true;
            try self.out.appendSlice(self.gpa, &.{ 20, 3, 3, 0, 1, 1 });
        }

        pub const Level = enum { initial, handshake, application };

        /// QUIC: server handshake bytes for a level, to be delivered to the client's `receive`.
        pub fn level(self: *const Self, which: Level) []const u8 {
            return self.level_out[@backingInt(which)].items;
        }
        pub fn levelDrained(self: *Self, which: Level, n: usize) void {
            const list = &self.level_out[@backingInt(which)];
            const rest = list.items.len - n;
            @memmove(list.items[0..rest], list.items[n..]);
            list.shrinkRetainingCapacity(rest);
        }
        fn emit(self: *Self, which: Level, bytes: []const u8) !void {
            try self.level_out[@backingInt(which)].appendSlice(self.gpa, bytes);
        }

        /// QUIC: the client's handshake bytes at a level.
        pub fn feedLevel(self: *Self, which: Level, bytes: []const u8) !void {
            switch (which) {
                .initial => try self.onHelloBytes(bytes),
                .handshake => try self.onClientHandshake(bytes),
                .application => {},
            }
        }

        fn plainRecord(self: *Self, body: []const u8) !void {
            try self.out.appendSlice(self.gpa, &.{ 22, 3, 3 });
            var len: [2]u8 = undefined;
            std.mem.writeInt(u16, &len, @intCast(body.len), .big);
            try self.out.appendSlice(self.gpa, &len);
            try self.out.appendSlice(self.gpa, body);
        }

        const Exchange = struct { public: [1120]u8 = undefined, public_len: usize = 0, secret: [64]u8 = @splat(0), secret_len: usize = 0 };

        fn exchange(self: *const Self, share: []const u8) !Exchange {
            var result: Exchange = .{};
            switch (self.config.group) {
                .x25519 => {
                    const kp = X25519.KeyPair.generateDeterministic(@splat(0x51));
                    result.public[0..32].* = kp.public_key;
                    result.public_len = 32;
                    result.secret[0..32].* = try X25519.scalarmult(kp.secret_key, share[0..32].*);
                    result.secret_len = 32;
                },
                .x25519_mlkem768 => {
                    const ek = try MlKem.PublicKey.fromBytes(share[0..1184]);
                    const enc = ek.encapsDeterministic(&@as([MlKem.encaps_seed_length]u8, @splat(0x33)));
                    const kp = X25519.KeyPair.generateDeterministic(@splat(0x52));
                    result.public[0..1088].* = enc.ciphertext;
                    result.public[1088..1120].* = kp.public_key;
                    result.public_len = 1120;
                    result.secret[0..32].* = enc.shared_secret;
                    result.secret[32..64].* = try X25519.scalarmult(kp.secret_key, share[1184..][0..32].*);
                    result.secret_len = 64;
                },
                .p256 => try curve(std.crypto.sign.ecdsa.EcdsaP256Sha256, 0x61, share, &result),
                .p384 => try curve(std.crypto.sign.ecdsa.EcdsaP384Sha384, 0x62, share, &result),
            }
            return result;
        }

        fn curve(comptime Ecdsa: type, seed: u8, share: []const u8, result: *Exchange) !void {
            const kp = try Ecdsa.KeyPair.generateDeterministic(@splat(seed));
            const public = kp.public_key.toUncompressedSec1();
            @memcpy(result.public[0..public.len], &public);
            result.public_len = public.len;
            const peer = try Ecdsa.PublicKey.fromSec1(share);
            const product = try peer.p.mulPublic(kp.secret_key.bytes, .big);
            const x = product.affineCoordinates().x.toBytes(.big);
            @memcpy(result.secret[0..x.len], &x);
            result.secret_len = x.len;
        }

        fn sendLegacy(self: *Self) !void {
            var hello: [128]u8 = undefined;
            var w: Writer = .{ .bytes = &hello };
            w.put(&.{ 2, 0, 0, 0, 3, 3 });
            var random: [32]u8 = @splat(0x77);
            if (self.config.tamper == .downgrade_sentinel) @memcpy(random[24..], "DOWNGRD\x01");
            w.put(&random);
            w.put(&.{@intCast(self.session_len)});
            w.put(self.session_id[0..self.session_len]);
            w.put(&.{ 0xc0, 0x2f, 0, 0, 0 });
            std.mem.writeInt(u24, hello[1..4], @intCast(w.pos - 4), .big);
            try self.plainRecord(hello[0..w.pos]);
        }

        /// The ServerHello for `kex`, written into `hello`.
        fn serverHello(self: *const Self, hello: *[1400]u8, kex: *const Exchange) []u8 {
            var w: Writer = .{ .bytes = hello };
            w.put(&.{ 2, 0, 0, 0, 3, 3 });
            w.put(&@as([32]u8, @splat(0x77)));
            const sid_len: u8 = @intCast(self.session_len);
            w.put(&.{sid_len});
            var echoed = self.session_id;
            if (self.config.tamper == .wrong_session_id and sid_len != 0) echoed[0] ^= 0xff;
            w.put(echoed[0..sid_len]);
            w.int(u16, @backingInt(suite));
            w.put(&.{0});
            const ext_at = w.pos;
            w.int(u16, 0);
            w.put(&.{ 0, 43, 0, 2, 3, 4 });
            w.put(&.{ 0, 51 });
            const advertised: Group = if (self.config.tamper == .unoffered_group) .p384 else self.config.group;
            const share_len = if (self.config.tamper == .zero_key_share) 32 else kex.public_len;
            w.int(u16, @intCast(4 + share_len));
            w.int(u16, @backingInt(advertised));
            w.int(u16, @intCast(share_len));
            if (self.config.tamper == .zero_key_share) {
                w.put(&@as([32]u8, @splat(0)));
            } else w.put(kex.public[0..kex.public_len]);
            std.mem.writeInt(u16, hello[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
            std.mem.writeInt(u24, hello[1..4], @intCast(w.pos - 4), .big);
            return hello[0..w.pos];
        }

        fn sendFlight(self: *Self, share: []const u8) !void {
            if (self.config.tamper == .legacy_server_hello or self.config.tamper == .downgrade_sentinel) return self.sendLegacy();
            var kex = try self.exchange(share);
            defer std.crypto.secureZero(u8, &kex.secret);
            var hello_buffer: [1400]u8 = undefined;
            const server_hello = self.serverHello(&hello_buffer, &kex);
            try self.transcript.commit(server_hello);

            const hello_hash = self.transcript.digest();
            var traffic: K.Traffic = .{};
            defer traffic.deinit();
            self.schedule = try K.init(kex.secret[0..kex.secret_len], &hello_hash, &traffic);
            self.client_hs = traffic.client.expose().*;
            self.server_hs = traffic.server.expose().*;
            if (!self.config.quic) {
                self.tx = try epochFrom(&self.server_hs);
                self.rx = try epochFrom(&self.client_hs);
            }

            if (self.config.raw_flight) |raw| {
                if (self.config.quic) {
                    try self.emit(.initial, server_hello);
                    return self.emit(.handshake, raw);
                }
                try self.plainRecord(server_hello);
                try self.compatCcs();
                return self.sealFlight(raw, &.{});
            }
            try self.sendEncrypted(server_hello);
            try self.deriveApplication();
        }

        fn sendEncrypted(self: *Self, server_hello: []const u8) !void {
            var flight: std.ArrayList(u8) = .empty;
            defer flight.deinit(self.gpa);
            var marks: [8]usize = undefined;
            var mark_count: usize = 0;
            var hello_record: std.ArrayList(u8) = .empty;
            defer hello_record.deinit(self.gpa);
            try hello_record.appendSlice(self.gpa, server_hello);
            if (self.config.tamper == .encrypted_extensions_in_hello_record) {
                try self.encryptedExtensions(&hello_record);
                try self.transcript.commit(hello_record.items[server_hello.len..]);
            } else {
                try self.encryptedExtensions(&flight);
                marks[mark_count] = flight.items.len;
                mark_count += 1;
                try self.commitAll(flight.items);
            }
            if (self.config.quic) {
                try self.emit(.initial, hello_record.items);
            } else {
                try self.plainRecord(hello_record.items);
                try self.compatCcs();
            }

            var start = flight.items.len;
            if (self.config.request_client_cert and self.config.tamper != .certificate_request_late) {
                try certificateRequest(self.gpa, &flight, self.config.request_schemes);
                marks[mark_count] = flight.items.len;
                mark_count += 1;
            }
            try self.certificateMessage(&flight);
            marks[mark_count] = flight.items.len;
            mark_count += 1;
            if (self.config.tamper == .certificate_request_late) {
                try self.commitAll(flight.items[start..]);
                start = flight.items.len;
                try certificateRequest(self.gpa, &flight, self.config.request_schemes);
                marks[mark_count] = flight.items.len;
                mark_count += 1;
            }
            try self.commitAll(flight.items[start..]);
            if (self.config.tamper != .missing_certificate_verify) {
                start = flight.items.len;
                const digest = self.transcript.digest();
                try self.certificateVerify(&flight, &digest);
                try self.commitAll(flight.items[start..]);
                marks[mark_count] = flight.items.len;
                mark_count += 1;
            }
            const digest = self.transcript.digest();
            var verify_data: Secret = undefined;
            Labels.finished(Hash, &verify_data, &self.server_hs, &digest);
            if (self.config.tamper == .bad_finished) verify_data[0] ^= 1;
            start = flight.items.len;
            try appendMessage(self.gpa, &flight, 20, &verify_data);
            try self.commitAll(flight.items[start..]);
            marks[mark_count] = flight.items.len;
            mark_count += 1;
            self.server_finished_hash = self.transcript.digest();
            if (self.config.tamper == .finished_not_at_record_end) {
                try appendMessage(self.gpa, &flight, 4, &.{ 0, 0, 0x1c, 0x20, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0 });
            }
            if (self.config.tamper == .application_before_finished) try self.sealOne(.application, "early");
            if (self.config.quic) {
                try self.emit(.handshake, flight.items);
            } else {
                try self.sealFlight(flight.items, marks[0..mark_count]);
            }
            if (self.config.tamper == .bad_tag) self.out.items[self.out.items.len - 1] ^= 1;
        }

        fn deriveApplication(self: *Self) !void {
            var app: K.Traffic = .{};
            defer app.deinit();
            try self.schedule.?.application(&self.server_finished_hash, &app);
            self.client_app = app.client.expose().*;
            self.server_app = app.server.expose().*;
            self.exporter = self.schedule.?.exporter.expose().*;
        }

        fn commitAll(self: *Self, bytes: []const u8) !void {
            var at: usize = 0;
            while (at < bytes.len) {
                const len = 4 + @as(usize, std.mem.readInt(u24, bytes[at + 1 ..][0..3], .big));
                try self.transcript.commit(bytes[at..][0..len]);
                at += len;
            }
        }

        fn encryptedExtensions(self: *Self, list: *std.ArrayList(u8)) !void {
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            try body.appendSlice(self.gpa, &.{ 0, 0 });
            if (self.config.alpn) |alpn| {
                const advertised = if (self.config.tamper == .unoffered_alpn) "zz" else alpn;
                try body.appendSlice(self.gpa, &.{ 0, 16, 0, @intCast(advertised.len + 3), 0, @intCast(advertised.len + 1), @intCast(advertised.len) });
                try body.appendSlice(self.gpa, advertised);
            }
            if (self.config.quic and !self.config.omit_quic_parameters) {
                const params = self.config.quic_parameters;
                const copies: usize = if (self.config.duplicate_quic_parameters) 2 else 1;
                for (0..copies) |_| {
                    try body.appendSlice(self.gpa, &.{ 0, 57, @intCast(params.len >> 8), @intCast(params.len & 255) });
                    try body.appendSlice(self.gpa, params);
                }
            }
            if (self.config.tamper == .duplicate_extension_in_encrypted) {
                try body.appendSlice(self.gpa, &.{ 0, 10, 0, 4, 0, 2, 0, 29 });
                try body.appendSlice(self.gpa, &.{ 0, 10, 0, 4, 0, 2, 0, 29 });
            }
            std.mem.writeInt(u16, body.items[0..2], @intCast(body.items.len - 2), .big);
            try appendMessage(self.gpa, list, 8, body.items);
        }

        fn certificateMessage(self: *Self, list: *std.ArrayList(u8)) !void {
            const leaf = switch (self.config.cert) {
                .p256 => pki.p256,
                .p384 => pki.p384,
                .ed25519 => pki.ed25519,
            };
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(self.gpa);
            if (self.config.tamper == .nonempty_certificate_context) {
                try body.appendSlice(self.gpa, &.{ 2, 'h', 'i' });
            } else try body.append(self.gpa, 0);
            var entries: std.ArrayList(u8) = .empty;
            defer entries.deinit(self.gpa);
            if (self.config.tamper != .empty_certificate_list) {
                inline for (.{ leaf, pki.ca }) |der| {
                    var len: [3]u8 = undefined;
                    std.mem.writeInt(u24, &len, @intCast(der.len), .big);
                    try entries.appendSlice(self.gpa, &len);
                    try entries.appendSlice(self.gpa, der);
                    if (self.config.tamper == .extension_in_certificate_entry) {
                        try entries.appendSlice(self.gpa, &.{ 0, 9, 0, 5, 1, 0, 0, 0, 0 });
                    } else try entries.appendSlice(self.gpa, &.{ 0, 0 });
                }
            }
            var len: [3]u8 = undefined;
            std.mem.writeInt(u24, &len, @intCast(entries.items.len), .big);
            try body.appendSlice(self.gpa, &len);
            try body.appendSlice(self.gpa, entries.items);
            try appendMessage(self.gpa, list, 11, body.items);
        }

        fn certificateVerify(self: *Self, list: *std.ArrayList(u8), digest: []const u8) !void {
            var content_buf: [64 + 34 + 48]u8 = undefined;
            const content = signedContent(digest, true, &content_buf);
            var scheme: u16 = undefined;
            var signature: [128]u8 = undefined;
            var signature_len: usize = 0;
            switch (self.config.cert) {
                .p256 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.p256_secret[0..32].*));
                    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const sig = (try kp.sign(content, null)).toDer(&der);
                    @memcpy(signature[0..sig.len], sig);
                    signature_len = sig.len;
                    scheme = 0x0403;
                },
                .p384 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
                    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.p384_secret[0..48].*));
                    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const sig = (try kp.sign(content, null)).toDer(&der);
                    @memcpy(signature[0..sig.len], sig);
                    signature_len = sig.len;
                    scheme = 0x0503;
                },
                .ed25519 => {
                    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.ed25519_secret[0..32].*);
                    const sig = (try kp.sign(content, null)).toBytes();
                    @memcpy(signature[0..64], &sig);
                    signature_len = 64;
                    scheme = 0x0807;
                },
            }
            switch (self.config.tamper) {
                .bad_signature => signature[signature_len - 1] ^= 1,
                .scheme_not_offered => scheme = 0x0201,
                .scheme_curve_mismatch => scheme = if (self.config.cert == .p256) 0x0503 else 0x0403,
                else => {},
            }
            var body: [4 + 128]u8 = undefined;
            std.mem.writeInt(u16, body[0..2], scheme, .big);
            std.mem.writeInt(u16, body[2..4], @intCast(signature_len), .big);
            @memcpy(body[4..][0..signature_len], signature[0..signature_len]);
            try appendMessage(self.gpa, list, 15, body[0 .. 4 + signature_len]);
        }

        fn sealFlight(self: *Self, bytes: []const u8, marks: []const usize) !void {
            if (self.config.tamper == .plaintext_encrypted_extensions) return self.plainRecord(bytes);
            switch (self.config.layout) {
                .coalesced => try self.sealChunks(bytes),
                .separate => {
                    var start: usize = 0;
                    for (marks) |mark| {
                        try self.sealChunks(bytes[start..mark]);
                        start = mark;
                    }
                    if (start < bytes.len) try self.sealChunks(bytes[start..]);
                },
                .fragments => |n| {
                    var at: usize = 0;
                    while (at < bytes.len) : (at += n) try self.sealChunks(bytes[at..@min(bytes.len, at + n)]);
                },
            }
        }

        fn sealChunks(self: *Self, bytes: []const u8) !void {
            var at: usize = 0;
            while (at < bytes.len) {
                const n = @min(bytes.len - at, 1 << 14);
                try self.sealOne(.handshake, bytes[at..][0..n]);
                at += n;
            }
        }

        pub fn sealOne(self: *Self, content: Epoch.Content, bytes: []const u8) !void {
            var wire: [5 + (1 << 14) + 256]u8 = undefined;
            const sealed = try self.tx.?.seal(content, bytes, 0, &wire);
            try self.out.appendSlice(self.gpa, sealed);
        }

        // ------------------------------------------------------------ client flight

        fn onClientHandshake(self: *Self, bytes: []const u8) !void {
            try self.client_flight.appendSlice(self.gpa, bytes);
            while (self.client_flight.items.len >= 4) {
                const items = self.client_flight.items;
                const len = 4 + @as(usize, std.mem.readInt(u24, items[1..4], .big));
                if (items.len < len) return;
                const message = try self.gpa.dupe(u8, items[0..len]);
                defer self.gpa.free(message);
                const rest = items.len - len;
                @memmove(self.client_flight.items[0..rest], items[len..]);
                self.client_flight.shrinkRetainingCapacity(rest);
                try self.onClientMessage(message);
            }
        }

        fn onClientMessage(self: *Self, message: []const u8) !void {
            if (self.connected and message[0] == 24) {
                self.key_updates_seen += 1;
                try self.rx.?.update();
                if (message[4] == 1) try self.keyUpdate(false);
                return;
            }
            switch (message[0]) {
                11 => {
                    const context = message[4];
                    const list_len = std.mem.readInt(u24, message[5 + context ..][0..3], .big);
                    if (list_len != 0) {
                        const der_len = std.mem.readInt(u24, message[8 + context ..][0..3], .big);
                        try self.client_chain.appendSlice(self.gpa, message[11 + context ..][0..der_len]);
                        self.client_certificates += 1;
                    }
                    try self.transcript.commit(message);
                },
                15 => {
                    const digest = self.transcript.digest();
                    var content_buf: [64 + 34 + 48]u8 = undefined;
                    const content = signedContent(&digest, false, &content_buf);
                    const scheme = std.mem.readInt(u16, message[4..6], .big);
                    const sig_len = std.mem.readInt(u16, message[6..8], .big);
                    self.client_signature_ok = verifyClient(scheme, message[8..][0..sig_len], content);
                    try self.transcript.commit(message);
                },
                20 => {
                    const digest = self.transcript.digest();
                    Labels.checkFinished(Hash, &self.client_hs, &digest, message[4..]) catch {
                        self.alert = 51;
                        return;
                    };
                    self.client_finished_ok = true;
                    try self.transcript.commit(message);
                    try self.connect();
                },
                4 => {},
                else => self.alert = 10,
            }
        }

        fn verifyClient(scheme: u16, sig: []const u8, content: []const u8) bool {
            if (rsaPssScheme(scheme)) return verifyRsaPss(pki.rsa, scheme, sig, content);
            if (scheme == 0x0403) {
                const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                const kp = Ecdsa.KeyPair.fromSecretKey(Ecdsa.SecretKey.fromBytes(pki.client_secret[0..32].*) catch return false) catch return false;
                const parsed = Ecdsa.Signature.fromDer(sig) catch return false;
                parsed.verify(content, kp.public_key) catch return false;
                return true;
            }
            if (scheme == 0x0807) {
                const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.client_ed25519_secret[0..32].*) catch return false;
                if (sig.len != 64) return false;
                std.crypto.sign.Ed25519.Signature.fromBytes(sig[0..64].*).verify(content, kp.public_key) catch return false;
                return true;
            }
            return false;
        }

        fn connect(self: *Self) !void {
            self.connected = true;
            if (self.config.quic) {
                const ticket = [_]u8{ 4, 0, 0, 18, 0, 0, 0x1c, 0x20, 0x12, 0x34, 0x56, 0x78, 1, 7, 0, 4, 't', 'k', 't', '!', 0, 0 };
                for (0..self.config.tickets) |_| try self.emit(.application, &ticket);
                return;
            }
            self.tx.?.deinit();
            self.rx.?.deinit();
            self.tx = try epochFrom(&self.server_app);
            self.rx = try epochFrom(&self.client_app);
            const ticket = [_]u8{ 4, 0, 0, 18, 0, 0, 0x1c, 0x20, 0x12, 0x34, 0x56, 0x78, 1, 7, 0, 4, 't', 'k', 't', '!', 0, 0 };
            for (0..self.config.tickets) |_| try self.sealOne(.handshake, &ticket);
            if (self.config.tamper == .ticket_flood) for (0..200) |_| try self.sealOne(.handshake, &ticket);
            if (self.config.tamper == .key_update_flood) for (0..200) |_| try self.keyUpdate(true);
            if (self.config.tamper == .ccs_after_finished) try self.out.appendSlice(self.gpa, &.{ 20, 3, 3, 0, 1, 1 });
        }

        // ------------------------------------------------------------ after the handshake

        pub fn send(self: *Self, bytes: []const u8) !void {
            try self.sealOne(.application, bytes);
        }

        /// A KeyUpdate under the old keys, then the next write keys.
        pub fn keyUpdate(self: *Self, request: bool) !void {
            try self.sealOne(.handshake, &.{ 24, 0, 0, 1, @intFromBool(request) });
            try self.tx.?.update();
        }

        pub fn closeNotify(self: *Self) !void {
            try self.sealOne(.alert, &.{ 1, 0 });
        }

        /// RFC 8446 section 7.5 from the peer's exporter secret, for cross-checks.
        pub fn exportKey(self: *const Self, out: []u8, label: []const u8, context: []const u8) !void {
            var derived: Secret = undefined;
            var empty: Secret = undefined;
            Hash.hash("", &empty, .{});
            try Labels.expand(Hash, &derived, &self.exporter, label, &empty);
            var context_hash: Secret = undefined;
            Hash.hash(context, &context_hash, .{});
            try Labels.expand(Hash, out, &derived, "exporter", &context_hash);
        }
    };
}
