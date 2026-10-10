//! A scripted TLS 1.3 client for testing servers. It speaks real records, verifies what the
//! server sends with its own checks, and can send a hostile ClientHello or client flight in
//! named ways. It reuses cloak's key schedule, HKDF, record protection and key shares, which
//! the RFC 8448 vectors and the exchange tests pin; the messages and checks are its own.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../tls/crypto/Suite.zig");
const Labels = @import("../tls/crypto/Labels.zig");
const Exchange = @import("../tls/crypto/Exchange.zig");
const Group = @import("../tls/crypto/Group.zig").Group;
const Epoch = @import("../tls/record/Epoch.zig");
const Schedule = @import("../tls/handshake/Schedule.zig");
const Transcript = @import("../tls/handshake/Transcript.zig").Transcript;
const peer_module = @import("Peer.zig");
const Suite13 = suites.Suite13;

pub const pki = peer_module.pki;

pub const Tamper = enum {
    none,
    /// A TLS 1.2 ClientHello: no supported_versions.
    no_versions,
    /// key_share without supported_groups.
    no_groups,
    no_signature_algorithms,
    duplicate_extension,
    bad_compression,
    /// A share for a group supported_groups does not list.
    share_outside_groups,
    /// A second ClientHello that differs from the first.
    changed_second_hello,
    /// A second ClientHello without the requested share.
    second_without_share,
    cookie_in_first,
    /// pre_shared_key that is not the last extension.
    psk_not_last,
    bad_finished,
    /// Present a certificate and omit its CertificateVerify.
    no_certificate_verify,
    bad_certificate_verify,
    /// Send Finished immediately after the ServerHello, skipping everything.
    finished_early,
    /// Application data before Finished.
    application_early,
    /// A second change_cipher_spec.
    double_ccs,
    /// Send the ClientHello twice without waiting.
    two_hellos,
    /// A ClientHello longer than one record, split in fragments of this many bytes.
    fragmented_hello,
    /// A certificate with a nonempty request context.
    certificate_context,
    /// A large client record before the handshake.
    oversize_record,
};

pub const Config = struct {
    /// Groups offered in supported_groups, in order.
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    /// Groups a key share is sent for.
    shares: []const Group = &.{ .x25519_mlkem768, .x25519 },
    sni: []const u8 = "example.com",
    alpn: []const []const u8 = &.{},
    schemes: []const u16 = &.{ 0x0403, 0x0503, 0x0804, 0x0807 },
    /// Cipher suites offered (the pair's suite, plus the others unless trimmed).
    other_suites: bool = true,
    compat: bool = true,
    /// Answer a CertificateRequest with this client's certificate.
    client_cert: bool = false,
    tamper: Tamper = .none,
    fragment: usize = 0,
    early_data: bool = false,
    /// The record version of the first record.
    first_record_version: u16 = 0x0301,
};

pub fn ClientPeer(comptime suite: Suite13) type {
    const K = Schedule.Schedule(suite);
    const Hash = suites.Hash(suite);
    const E = Epoch.Epoch(suite);
    return struct {
        const Self = @This();
        const Secret = [Hash.digest_length]u8;

        gpa: std.mem.Allocator,
        config: Config,
        rng: std.Random.DefaultPrng,
        out: std.ArrayList(u8) = .empty,
        input: std.ArrayList(u8) = .empty,
        flight: std.ArrayList(u8) = .empty,
        transcript: Transcript(Hash) = .{},
        shares: [3]?Exchange.Share = @splat(null),
        random: [32]u8 = undefined,
        session: [32]u8 = undefined,
        session_len: usize = 0,
        schedule: ?K = null,
        tx: ?E = null,
        rx: ?E = null,
        client_hs: Secret = undefined,
        server_hs: Secret = undefined,
        client_app: Secret = undefined,
        server_app: Secret = undefined,
        exporter: Secret = undefined,
        retry_group: ?Group = null,
        hellos_sent: usize = 0,
        // What the server did.
        got_server_hello: bool = false,
        got_retry: bool = false,
        server_group: u16 = 0,
        server_suite: u16 = 0,
        session_echo_ok: bool = false,
        alpn: [32]u8 = undefined,
        alpn_len: usize = 0,
        server_name_ack: bool = false,
        quic_parameters: [64]u8 = undefined,
        quic_parameters_len: usize = 0,
        requested_certificate: bool = false,
        chain: std.ArrayList(u8) = .empty,
        certificate_verify_ok: bool = false,
        /// The scheme of the server's CertificateVerify.
        certificate_verify_scheme: u16 = 0,
        server_finished_ok: bool = false,
        connected: bool = false,
        received: std.ArrayList(u8) = .empty,
        alert: ?u8 = null,
        close_notify: bool = false,
        plain_alert: ?u8 = null,
        ccs_seen: usize = 0,
        ticket_count: usize = 0,
        key_updates_seen: usize = 0,
        extra_after: std.ArrayList(u8) = .empty,

        pub fn init(gpa: std.mem.Allocator, config: Config, seed: u64) Self {
            return .{ .gpa = gpa, .config = config, .rng = .init(seed) };
        }

        pub fn deinit(self: *Self) void {
            self.out.deinit(self.gpa);
            self.input.deinit(self.gpa);
            self.flight.deinit(self.gpa);
            self.chain.deinit(self.gpa);
            self.received.deinit(self.gpa);
            self.extra_after.deinit(self.gpa);
            for (&self.shares) |*slot| if (slot.*) |*share| share.deinit();
            if (self.schedule) |*s| s.deinit();
            if (self.tx) |*e| e.deinit();
            if (self.rx) |*e| e.deinit();
        }

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

        fn appendMessage(self: *Self, list: *std.ArrayList(u8), kind: u8, body: []const u8) !void {
            try list.append(self.gpa, kind);
            var len: [3]u8 = undefined;
            std.mem.writeInt(u24, &len, @intCast(body.len), .big);
            try list.appendSlice(self.gpa, &len);
            try list.appendSlice(self.gpa, body);
        }

        fn plainRecord(self: *Self, kind: u8, version: u16, body: []const u8) !void {
            try self.out.append(self.gpa, kind);
            var head: [4]u8 = undefined;
            std.mem.writeInt(u16, head[0..2], version, .big);
            std.mem.writeInt(u16, head[2..4], @intCast(body.len), .big);
            try self.out.appendSlice(self.gpa, &head);
            try self.out.appendSlice(self.gpa, body);
        }

        fn sealOne(self: *Self, content: Epoch.Content, bytes: []const u8) !void {
            var wire: [5 + (1 << 14) + 256]u8 = undefined;
            const sealed = try self.tx.?.seal(content, bytes, 0, &wire);
            try self.out.appendSlice(self.gpa, sealed);
        }

        // ------------------------------------------------------------ the hello

        const Ext = struct {
            fn put(list: *std.ArrayList(u8), gpa: std.mem.Allocator, id: u16, body: []const u8) !void {
                var head: [4]u8 = undefined;
                std.mem.writeInt(u16, head[0..2], id, .big);
                std.mem.writeInt(u16, head[2..4], @intCast(body.len), .big);
                try list.appendSlice(gpa, &head);
                try list.appendSlice(gpa, body);
            }
        };

        fn u16s(list: *std.ArrayList(u8), gpa: std.mem.Allocator, values: []const u16) !void {
            var tmp: [2]u8 = undefined;
            std.mem.writeInt(u16, &tmp, @intCast(values.len * 2), .big);
            try list.appendSlice(gpa, &tmp);
            for (values) |v| {
                std.mem.writeInt(u16, &tmp, v, .big);
                try list.appendSlice(gpa, &tmp);
            }
        }

        fn buildHello(self: *Self, second: bool) ![]u8 {
            const gpa = self.gpa;
            const t = self.config.tamper;
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(gpa);
            try body.appendSlice(gpa, &.{ 3, 3 });
            try body.appendSlice(gpa, &self.random);
            try body.append(gpa, @intCast(self.session_len));
            try body.appendSlice(gpa, self.session[0..self.session_len]);
            var offered: [3]u16 = .{ @backingInt(suite), 0x1301, 0x1303 };
            if (!self.config.other_suites) {
                try u16s(&body, gpa, offered[0..1]);
            } else {
                offered = .{ @backingInt(suite), if (suite == .aes_128_gcm_sha256) 0x1303 else 0x1301, if (suite == .aes_256_gcm_sha384) 0x1303 else 0x1302 };
                try u16s(&body, gpa, &offered);
            }
            if (t == .bad_compression) {
                try body.appendSlice(gpa, &.{ 2, 0, 1 });
            } else try body.appendSlice(gpa, &.{ 1, 0 });
            var ext: std.ArrayList(u8) = .empty;
            defer ext.deinit(gpa);
            if (self.config.sni.len != 0) {
                var sni: std.ArrayList(u8) = .empty;
                defer sni.deinit(gpa);
                try sni.appendSlice(gpa, &.{ @intCast((self.config.sni.len + 3) >> 8), @intCast((self.config.sni.len + 3) & 255), 0, @intCast(self.config.sni.len >> 8), @intCast(self.config.sni.len & 255) });
                try sni.appendSlice(gpa, self.config.sni);
                try Ext.put(&ext, gpa, 0, sni.items);
            }
            if (t != .no_groups) {
                var groups: std.ArrayList(u8) = .empty;
                defer groups.deinit(gpa);
                var ids: [8]u16 = undefined;
                for (self.config.groups, 0..) |g, i| ids[i] = @backingInt(g);
                try u16s(&groups, gpa, ids[0..self.config.groups.len]);
                try Ext.put(&ext, gpa, 10, groups.items);
            }
            if (t != .no_signature_algorithms) {
                var sigs: std.ArrayList(u8) = .empty;
                defer sigs.deinit(gpa);
                try u16s(&sigs, gpa, self.config.schemes);
                try Ext.put(&ext, gpa, 13, sigs.items);
            }
            if (t == .no_versions) {} else try Ext.put(&ext, gpa, 43, &.{ 2, 3, 4 });
            if (self.config.alpn.len != 0) {
                var alpn: std.ArrayList(u8) = .empty;
                defer alpn.deinit(gpa);
                try alpn.appendSlice(gpa, &.{ 0, 0 });
                for (self.config.alpn) |name| {
                    try alpn.append(gpa, @intCast(name.len));
                    try alpn.appendSlice(gpa, name);
                }
                std.mem.writeInt(u16, alpn.items[0..2], @intCast(alpn.items.len - 2), .big);
                try Ext.put(&ext, gpa, 16, alpn.items);
            }
            if (t == .cookie_in_first and !second) try Ext.put(&ext, gpa, 44, &.{ 0, 1, 'x' });
            if (t == .duplicate_extension) try Ext.put(&ext, gpa, 43, &.{ 2, 3, 4 });
            if (self.config.early_data) try Ext.put(&ext, gpa, 42, &.{});
            // Key shares: the first hello sends the configured groups, the second only the requested one.
            var share_body: std.ArrayList(u8) = .empty;
            defer share_body.deinit(gpa);
            try share_body.appendSlice(gpa, &.{ 0, 0 });
            for (&self.shares) |*slot| if (slot.*) |*share| {
                var head: [4]u8 = undefined;
                std.mem.writeInt(u16, head[0..2], @backingInt(share.group), .big);
                std.mem.writeInt(u16, head[2..4], @intCast(share.wire().len), .big);
                try share_body.appendSlice(gpa, &head);
                try share_body.appendSlice(gpa, share.wire());
            };
            if (t == .share_outside_groups) try share_body.appendSlice(gpa, &.{ 0x01, 0x00, 0, 1, 0x55 });
            std.mem.writeInt(u16, share_body.items[0..2], @intCast(share_body.items.len - 2), .big);
            if (!(t == .second_without_share and second)) try Ext.put(&ext, gpa, 51, share_body.items);
            if (t == .changed_second_hello and second) try Ext.put(&ext, gpa, 16, &.{ 0, 3, 2, 'z', 'z' });
            if (t == .psk_not_last) {
                try Ext.put(&ext, gpa, 41, &.{ 0, 1, 'x' });
                try Ext.put(&ext, gpa, 45, &.{ 1, 1 });
            }
            var tmp: [2]u8 = undefined;
            std.mem.writeInt(u16, &tmp, @intCast(ext.items.len), .big);
            try body.appendSlice(gpa, &tmp);
            try body.appendSlice(gpa, ext.items);
            var message: std.ArrayList(u8) = .empty;
            errdefer message.deinit(gpa);
            try self.appendMessage(&message, 1, body.items);
            return message.toOwnedSlice(gpa);
        }

        /// Starts the connection: draws randomness and key shares, sends the first hello.
        pub fn start(self: *Self) !void {
            self.rng.random().bytes(&self.random);
            if (self.config.compat) {
                self.rng.random().bytes(&self.session);
                self.session_len = 32;
            }
            for (self.config.shares, 0..) |group, i| {
                var entropy: [128]u8 = undefined;
                self.rng.random().bytes(&entropy);
                self.shares[i] = try Exchange.Share.init(group, entropy[0..Exchange.entropyLength(group)]);
            }
            try self.sendHello(false);
        }

        fn sendHello(self: *Self, second: bool) !void {
            const message = try self.buildHello(second);
            defer self.gpa.free(message);
            try self.transcript.commit(message);
            self.hellos_sent += 1;
            const version = if (second) 0x0303 else self.config.first_record_version;
            if (self.config.tamper == .fragmented_hello and self.config.fragment != 0) {
                var at: usize = 0;
                while (at < message.len) : (at += self.config.fragment) {
                    try self.plainRecord(22, version, message[at..@min(message.len, at + self.config.fragment)]);
                }
            } else try self.plainRecord(22, version, message);
            if (self.config.tamper == .two_hellos and !second) try self.plainRecord(22, version, message);
            if (self.config.tamper == .oversize_record and !second) {
                var big: [(1 << 14) + 1]u8 = @splat(0);
                try self.plainRecord(22, 0x0303, &big);
            }
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
                20 => self.ccs_seen += 1,
                21 => {
                    if (self.rx == null) {
                        self.plain_alert = wire[6];
                        self.alert = wire[6];
                    } else return error.ClientPlaintextAlert;
                },
                22 => try self.onServerBytes(wire[5..], true),
                23 => {
                    const plain = try self.rx.?.open(wire, wire[5..]);
                    switch (plain.content) {
                        .handshake => try self.onServerBytes(plain.bytes, false),
                        .application => try self.received.appendSlice(self.gpa, plain.bytes),
                        .alert => {
                            self.alert = plain.bytes[1];
                            if (plain.bytes[1] == 0) self.close_notify = true;
                        },
                    }
                },
                else => return error.ClientBadRecord,
            }
        }

        fn onServerBytes(self: *Self, bytes: []const u8, plaintext: bool) !void {
            _ = plaintext;
            try self.flight.appendSlice(self.gpa, bytes);
            while (self.flight.items.len >= 4) {
                const items = self.flight.items;
                const len = 4 + @as(usize, std.mem.readInt(u24, items[1..4], .big));
                if (items.len < len) return;
                const message = try self.gpa.dupe(u8, items[0..len]);
                defer self.gpa.free(message);
                const rest = items.len - len;
                @memmove(self.flight.items[0..rest], items[len..]);
                self.flight.shrinkRetainingCapacity(rest);
                try self.onMessage(message);
            }
        }

        fn onMessage(self: *Self, message: []const u8) !void {
            switch (message[0]) {
                2 => try self.onServerHello(message),
                8 => try self.onEncrypted(message),
                13 => {
                    self.requested_certificate = true;
                    try self.transcript.commit(message);
                },
                11 => {
                    const ctx = message[4];
                    const list_len = std.mem.readInt(u24, message[5 + ctx ..][0..3], .big);
                    if (list_len != 0) {
                        const der_len = std.mem.readInt(u24, message[8 + ctx ..][0..3], .big);
                        try self.chain.appendSlice(self.gpa, message[11 + ctx ..][0..der_len]);
                    }
                    try self.transcript.commit(message);
                },
                15 => try self.onCertificateVerify(message),
                20 => try self.onServerFinished(message),
                4 => self.ticket_count += 1,
                24 => {
                    self.key_updates_seen += 1;
                    try self.rx.?.update();
                    if (message[4] == 1) try self.keyUpdate(false);
                },
                else => self.alert = 10,
            }
        }

        fn onServerHello(self: *Self, message: []const u8) !void {
            var at: usize = 4 + 2;
            const random = message[at..][0..32];
            at += 32;
            const sid = message[at];
            at += 1;
            self.session_echo_ok = sid == self.session_len and std.mem.eql(u8, message[at..][0..sid], self.session[0..self.session_len]);
            at += sid;
            self.server_suite = std.mem.readInt(u16, message[at..][0..2], .big);
            at += 3;
            const ext_len = std.mem.readInt(u16, message[at..][0..2], .big);
            at += 2;
            const end = at + ext_len;
            var group: u16 = 0;
            var share: []const u8 = "";
            while (at < end) {
                const id = std.mem.readInt(u16, message[at..][0..2], .big);
                const len = std.mem.readInt(u16, message[at + 2 ..][0..2], .big);
                const ext_body = message[at + 4 ..][0..len];
                at += 4 + len;
                if (id == 51) {
                    group = std.mem.readInt(u16, ext_body[0..2], .big);
                    if (len > 2) share = ext_body[4..];
                }
            }
            self.server_group = group;
            if (std.mem.eql(u8, random, &std.crypto.tls.hello_retry_request_sequence)) {
                self.got_retry = true;
                self.retry_group = std.enums.fromInt(Group, group);
                try self.transcript.retry(message);
                // Fresh material for the requested group, then the second hello.
                for (&self.shares) |*slot| if (slot.*) |*s| {
                    s.deinit();
                    slot.* = null;
                };
                var entropy: [128]u8 = undefined;
                self.rng.random().bytes(&entropy);
                const requested = self.retry_group.?;
                self.shares[0] = try Exchange.Share.init(requested, entropy[0..Exchange.entropyLength(requested)]);
                return self.sendHello(true);
            }
            self.got_server_hello = true;
            try self.transcript.commit(message);
            var agreed: ?Exchange.Agreed = null;
            for (&self.shares) |*slot| if (slot.*) |*s| {
                if (@backingInt(s.group) == group) agreed = try s.agree(share);
            };
            var secret = agreed orelse return error.ServerChoseUnsentGroup;
            defer secret.deinit();
            const hello_hash = self.transcript.digest();
            var traffic: K.Traffic = .{};
            defer traffic.deinit();
            self.schedule = try K.init(secret.bytes(), &hello_hash, &traffic);
            self.client_hs = traffic.client.expose().*;
            self.server_hs = traffic.server.expose().*;
            self.rx = try epochFrom(&self.server_hs);
            // The client's own writes switch to the handshake keys when it sends its flight.
            if (self.config.tamper == .finished_early) {
                self.tx = try epochFrom(&self.client_hs);
                var verify_data: Secret = undefined;
                const digest = self.transcript.digest();
                Labels.finished(Hash, &verify_data, &self.client_hs, &digest);
                var finished: std.ArrayList(u8) = .empty;
                defer finished.deinit(self.gpa);
                try self.appendMessage(&finished, 20, &verify_data);
                try self.sealOne(.handshake, finished.items);
            }
        }

        fn onEncrypted(self: *Self, message: []const u8) !void {
            try self.transcript.commit(message);
            var at: usize = 6;
            const end = 4 + 2 + std.mem.readInt(u16, message[4..6], .big);
            while (at < end) {
                const id = std.mem.readInt(u16, message[at..][0..2], .big);
                const len = std.mem.readInt(u16, message[at + 2 ..][0..2], .big);
                const ext_body = message[at + 4 ..][0..len];
                at += 4 + len;
                switch (id) {
                    0 => self.server_name_ack = true,
                    16 => {
                        const n = ext_body[2];
                        self.alpn_len = n;
                        @memcpy(self.alpn[0..n], ext_body[3..][0..n]);
                    },
                    57 => {
                        self.quic_parameters_len = @min(len, 64);
                        @memcpy(self.quic_parameters[0..self.quic_parameters_len], ext_body[0..self.quic_parameters_len]);
                    },
                    else => {},
                }
            }
        }

        fn signedContent(digest: []const u8, server: bool, out: *[64 + 34 + 48]u8) []const u8 {
            const label = if (server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
            @memset(out[0..64], 0x20);
            @memcpy(out[64..][0..label.len], label);
            out[64 + label.len] = 0;
            @memcpy(out[65 + label.len ..][0..digest.len], digest);
            return out[0 .. 65 + label.len + digest.len];
        }

        fn onCertificateVerify(self: *Self, message: []const u8) !void {
            const digest = self.transcript.digest();
            var content_buf: [64 + 34 + 48]u8 = undefined;
            const content = signedContent(&digest, true, &content_buf);
            const scheme = std.mem.readInt(u16, message[4..6], .big);
            const sig_len = std.mem.readInt(u16, message[6..8], .big);
            const sig = message[8..][0..sig_len];
            self.certificate_verify_scheme = scheme;
            self.certificate_verify_ok = verifyServer(scheme, sig, content);
            try self.transcript.commit(message);
        }

        /// Verifies with the fixture keys, independently of cloak's verifier.
        fn verifyServer(scheme: u16, sig: []const u8, content: []const u8) bool {
            if (peer_module.rsaPssScheme(scheme)) return peer_module.verifyRsaPss(pki.rsa, scheme, sig, content);
            switch (scheme) {
                0x0403 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                    const kp = Ecdsa.KeyPair.fromSecretKey(Ecdsa.SecretKey.fromBytes(pki.p256_secret[0..32].*) catch return false) catch return false;
                    const parsed = Ecdsa.Signature.fromDer(sig) catch return false;
                    parsed.verify(content, kp.public_key) catch return false;
                    return true;
                },
                0x0503 => {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
                    const kp = Ecdsa.KeyPair.fromSecretKey(Ecdsa.SecretKey.fromBytes(pki.p384_secret[0..48].*) catch return false) catch return false;
                    const parsed = Ecdsa.Signature.fromDer(sig) catch return false;
                    parsed.verify(content, kp.public_key) catch return false;
                    return true;
                },
                0x0807 => {
                    const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.ed25519_secret[0..32].*) catch return false;
                    if (sig.len != 64) return false;
                    std.crypto.sign.Ed25519.Signature.fromBytes(sig[0..64].*).verify(content, kp.public_key) catch return false;
                    return true;
                },
                else => return false,
            }
        }

        fn onServerFinished(self: *Self, message: []const u8) !void {
            const digest = self.transcript.digest();
            Labels.checkFinished(Hash, &self.server_hs, &digest, message[4..]) catch {
                self.alert = 51;
                return;
            };
            self.server_finished_ok = true;
            try self.transcript.commit(message);
            const server_finished_hash = self.transcript.digest();
            var app: K.Traffic = .{};
            defer app.deinit();
            try self.schedule.?.application(&server_finished_hash, &app);
            self.client_app = app.client.expose().*;
            self.server_app = app.server.expose().*;
            self.exporter = self.schedule.?.exporter.expose().*;
            try self.sendClientFlight();
        }

        fn sendClientFlight(self: *Self) !void {
            const t = self.config.tamper;
            if (self.config.compat and self.session_len != 0) try self.out.appendSlice(self.gpa, &.{ 20, 3, 3, 0, 1, 1 });
            if (t == .double_ccs) try self.out.appendSlice(self.gpa, &.{ 20, 3, 3, 0, 1, 1 });
            if (self.tx == null) self.tx = try epochFrom(&self.client_hs);
            var flight: std.ArrayList(u8) = .empty;
            defer flight.deinit(self.gpa);
            if (self.requested_certificate) {
                if (self.config.client_cert) {
                    var body: std.ArrayList(u8) = .empty;
                    defer body.deinit(self.gpa);
                    if (t == .certificate_context) {
                        try body.appendSlice(self.gpa, &.{ 2, 'h', 'i' });
                    } else try body.append(self.gpa, 0);
                    var len: [3]u8 = undefined;
                    std.mem.writeInt(u24, &len, @intCast(pki.client.len + 5), .big);
                    try body.appendSlice(self.gpa, &len);
                    std.mem.writeInt(u24, &len, @intCast(pki.client.len), .big);
                    try body.appendSlice(self.gpa, &len);
                    try body.appendSlice(self.gpa, pki.client);
                    try body.appendSlice(self.gpa, &.{ 0, 0 });
                    const cert_start = flight.items.len;
                    try self.appendMessage(&flight, 11, body.items);
                    try self.transcript.commit(flight.items[cert_start..]);
                    if (t != .no_certificate_verify) {
                        const digest = self.transcript.digest();
                        var content_buf: [64 + 34 + 48]u8 = undefined;
                        const content = signedContent(&digest, false, &content_buf);
                        const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                        const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.client_secret[0..32].*));
                        var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                        const sig = (try kp.sign(content, null)).toDer(&der);
                        var cv: [4 + 80]u8 = undefined;
                        std.mem.writeInt(u16, cv[0..2], 0x0403, .big);
                        std.mem.writeInt(u16, cv[2..4], @intCast(sig.len), .big);
                        @memcpy(cv[4..][0..sig.len], sig);
                        if (t == .bad_certificate_verify) cv[4 + sig.len - 1] ^= 1;
                        const cv_start = flight.items.len;
                        try self.appendMessage(&flight, 15, cv[0 .. 4 + sig.len]);
                        try self.transcript.commit(flight.items[cv_start..]);
                    }
                } else {
                    const empty_start = flight.items.len;
                    try self.appendMessage(&flight, 11, &.{ 0, 0, 0, 0 });
                    try self.transcript.commit(flight.items[empty_start..]);
                }
            }
            const digest = self.transcript.digest();
            var verify_data: Secret = undefined;
            Labels.finished(Hash, &verify_data, &self.client_hs, &digest);
            if (t == .bad_finished) verify_data[0] ^= 1;
            const fin_start = flight.items.len;
            try self.appendMessage(&flight, 20, &verify_data);
            try self.transcript.commit(flight.items[fin_start..]);
            if (t == .application_early) try self.sealOne(.application, "too early");
            if (self.config.fragment != 0 and t != .fragmented_hello) {
                var at: usize = 0;
                while (at < flight.items.len) : (at += self.config.fragment) try self.sealOne(.handshake, flight.items[at..@min(flight.items.len, at + self.config.fragment)]);
            } else try self.sealOne(.handshake, flight.items);
            // Application keys after the flight.
            self.tx.?.deinit();
            self.rx.?.deinit();
            self.tx = try epochFrom(&self.client_app);
            self.rx = try epochFrom(&self.server_app);
            self.connected = true;
        }

        // ------------------------------------------------------------ after the handshake

        pub fn send(self: *Self, bytes: []const u8) !void {
            try self.sealOne(.application, bytes);
        }

        pub fn keyUpdate(self: *Self, request: bool) !void {
            try self.sealOne(.handshake, &.{ 24, 0, 0, 1, @intFromBool(request) });
            try self.tx.?.update();
        }

        pub fn closeNotify(self: *Self) !void {
            try self.sealOne(.alert, &.{ 1, 0 });
        }

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
