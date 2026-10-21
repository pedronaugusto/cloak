//! DTLS record protection, one epoch and one direction: DTLS 1.3's unified header with its
//! encrypted record number (RFC 9147 section 4) and DTLS 1.2's explicit epoch and sequence
//! (RFC 6347 section 4.1, with RFC 9146's connection-ID records). A record that fails to parse, to
//! authenticate or to clear the replay window is dropped (`error.Drop`) with nothing released and
//! nothing about the epoch changed but its count of failed openings; unlike TLS, the association
//! survives it (RFC 9147 section 4.5.2). Only the datagram carrier seals and opens.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
const Kernels = @import("../crypto/Kernels.zig");
const Window = @import("Window.zig");

const Cipher = suites.Cipher;
const Suite13 = suites.Suite13;

pub const Content = enum(u8) { change_cipher_spec = 20, alert = 21, handshake = 22, application = 23, ack = 26, _ };

/// DTLS 1.2's content type of a record with a connection ID (RFC 9146 section 4).
pub const tls12_cid: u8 = 25;
pub const max_content = 1 << 14;
/// The longest connection ID a record carries (RFC 9146: an opaque<0..2^8-1>).
pub const max_cid = 255;
/// The tag of every DTLS 1.3 suite; DTLS 1.2's is its cipher's (`Cipher.tagLength`: CCM_8's is 8).
pub const tag_length = 16;
/// DTLS 1.2's record header: type, version, epoch, 48-bit sequence, length.
pub const header12 = 13;
/// What a DTLS 1.3 record adds to its content at most here: header (flags, a CID, 16-bit sequence,
/// length), content type and tag.
pub fn overhead13(cid: usize) usize {
    return 1 + cid + 2 + 2 + 1 + tag_length;
}
/// What a DTLS 1.2 record adds: header, a CID and its inner type, explicit nonce and tag.
pub fn overhead12(cipher: Cipher, cid: usize) usize {
    return header12 + cid + @as(usize, if (cid != 0) 1 else 0) + cipher.explicitNonceLength12() + cipher.tagLength();
}

pub const SealError = error{ BufferTooSmall, InvalidLength, RecordLimit };
/// The record is dropped; the association goes on.
pub const OpenError = error{Drop};

pub const Version = enum { dtls12, dtls13 };

/// The forgery limits of RFC 9147 section 4.5.3: failed openings tolerated per key. CCM_8's
/// keeps the same 2^-57 margin as every other cipher (RFC 9147 appendix B.3): with a 64-bit tag
/// that is 2^7 failures, after which the association ends. The price is availability: whoever can
/// put 128 datagrams on the association's path ends it, which is why CCM_8 is never a default.
pub fn failureLimit(cipher: Cipher) u64 {
    return switch (cipher) {
        // 2^23.5, rounded down.
        .aes_128_ccm, .aes_256_ccm => 11_863_283,
        .aes_128_ccm_8 => 1 << 7,
        else => 1 << 36,
    };
}

/// One epoch of one direction: its keys, its next sequence to send or its replay window, and
/// its failed openings.
pub const Epoch = struct {
    version: Version,
    cipher: Cipher,
    /// The full epoch number: 2, 3, 4... in DTLS 1.3, 1 in DTLS 1.2.
    number: u64,
    key: aegis.Secret([32]u8),
    iv: aegis.Secret([12]u8),
    /// DTLS 1.3: the record-number key.
    sn: aegis.Secret([32]u8),
    /// DTLS 1.3: the traffic secret, for the next epoch's keys after a key update.
    traffic: aegis.Secret([48]u8),
    suite: ?Suite13 = null,
    sequence: u64 = 0,
    window: Window = .{},
    failures: u64 = 0,
    record_limit: u64,

    /// Makes `self` the DTLS 1.3 keys of epoch `number` from a traffic secret ("dtls13" labels).
    /// Epochs are made where they are kept and never copied: each copy of a key is one more to
    /// erase.
    pub fn init13(self: *Epoch, suite: Suite13, number: u64, secret: []const u8) void {
        @setRuntimeSafety(true);
        const cipher = suites.cipherOf(suite);
        self.* = .{
            .version = .dtls13,
            .cipher = cipher,
            .number = number,
            .key = .init(@splat(0)),
            .iv = .init(@splat(0)),
            .sn = .init(@splat(0)),
            .traffic = .init(@splat(0)),
            .suite = suite,
            .record_limit = cipher.recordLimit(),
        };
        @memcpy(self.traffic.exposeMut()[0..secret.len], secret);
        self.derive();
    }

    /// Makes `self` the DTLS 1.2 keys of epoch 1 from the key block.
    pub fn init12(self: *Epoch, cipher: Cipher, key: []const u8, iv: []const u8) void {
        @setRuntimeSafety(true);
        self.* = .{
            .version = .dtls12,
            .cipher = cipher,
            .number = 1,
            .key = .init(@splat(0)),
            .iv = .init(@splat(0)),
            .sn = .init(@splat(0)),
            .traffic = .init(@splat(0)),
            .record_limit = cipher.recordLimit(),
        };
        @memcpy(self.key.exposeMut()[0..key.len], key);
        @memcpy(self.iv.exposeMut()[0..iv.len], iv);
    }

    fn derive(self: *Epoch) void {
        @setRuntimeSafety(true);
        const key_len = self.cipher.keyLength();
        switch (self.suite.?) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                const secret = self.traffic.expose()[0..Hash.digest_length];
                // unreachable: fixed labels and key-sized outputs meet the HKDF bounds.
                Labels.expandWith(Hash, .dtls13, self.key.exposeMut()[0..key_len], secret, "key", "") catch unreachable;
                // unreachable: a fixed label and a twelve-byte output meet the HKDF bounds.
                Labels.expandWith(Hash, .dtls13, self.iv.exposeMut(), secret, "iv", "") catch unreachable;
                // unreachable: a fixed label and a key-sized output meet the HKDF bounds.
                Labels.expandWith(Hash, .dtls13, self.sn.exposeMut()[0..key_len], secret, "sn", "") catch unreachable;
            },
        }
    }

    /// Makes `out` the epoch a DTLS 1.3 key update moves to: the next traffic secret, its keys, a
    /// fresh sequence and window.
    pub fn next(self: *const Epoch, out: *Epoch) void {
        @setRuntimeSafety(true);
        aegis.assert.invariant(self.version == .dtls13, "only DTLS 1.3 epochs advance this way");
        out.* = .{
            .version = .dtls13,
            .cipher = self.cipher,
            .number = self.number + 1,
            .key = .init(@splat(0)),
            .iv = .init(@splat(0)),
            .sn = .init(@splat(0)),
            .traffic = .init(@splat(0)),
            .suite = self.suite,
            .record_limit = self.record_limit,
        };
        switch (self.suite.?) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                // unreachable: the fixed label and hash-sized output meet the HKDF bounds.
                Labels.expandWith(Hash, .dtls13, out.traffic.exposeMut()[0..Hash.digest_length], self.traffic.expose()[0..Hash.digest_length], "traffic upd", "") catch unreachable;
            },
        }
        out.derive();
    }

    pub fn deinit(self: *Epoch) void {
        self.key.deinit();
        self.iv.deinit();
        self.sn.deinit();
        self.traffic.deinit();
        self.* = undefined;
    }

    /// Records left before this key must be replaced (DTLS 1.3) or the association closed.
    pub fn remaining(self: *const Epoch) u64 {
        return self.record_limit -| self.sequence;
    }

    /// Whether this key has failed to open as many records as its AEAD allows.
    pub fn exhausted(self: *const Epoch) bool {
        return self.failures >= failureLimit(self.cipher);
    }

    /// The mask of a DTLS 1.3 record number (RFC 9147 section 4.2.3) from the first 16 bytes of
    /// the ciphertext.
    fn mask(self: *const Epoch, sample: *const [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        switch (self.cipher) {
            .aes_128_gcm, .aes_128_ccm, .aes_128_ccm_8 => Kernels.mask(.aes128, self.sn.expose(), sample, &out),
            .aes_256_gcm, .aes_256_ccm => Kernels.mask(.aes256, self.sn.expose(), sample, &out),
            .chacha20_poly1305 => Kernels.mask(.chacha20, self.sn.expose(), sample, &out),
        }
        return out;
    }

    /// `tag` is the cipher's tag length. The nonce is the IV xor `counter` in its last eight
    /// bytes: DTLS 1.3's record number, DTLS 1.2's epoch and sequence (the explicit nonce of GCM
    /// and CCM, over an IV whose tail is zero, is the same xor; ChaCha20-Poly1305 masks the IV
    /// with them, RFC 7905).
    fn encrypt(self: *const Epoch, out: []u8, tag: []u8, plain: []const u8, ad: []const u8, counter: u64) void {
        switch (self.cipher) {
            inline else => |cipher| {
                const A = suites.AeadOf(cipher);
                Kernels.seal(A, out, tag[0..A.tag_length], plain, ad, self.iv.expose(), counter, self.key.expose()[0..A.key_length]);
            },
        }
    }

    fn decrypt(self: *const Epoch, out: []u8, cipher_bytes: []const u8, tag: []const u8, ad: []const u8, counter: u64) error{AuthenticationFailed}!void {
        switch (self.cipher) {
            inline else => |cipher| {
                const A = suites.AeadOf(cipher);
                return Kernels.open(A, out, cipher_bytes, tag[0..A.tag_length], ad, self.iv.expose(), counter, self.key.expose()[0..A.key_length]);
            },
        }
    }

    /// Seals one DTLS 1.3 record of `content` into `out`: the unified header with a 16-bit
    /// sequence and a length, `cid` (the peer's) when there is one, and the record number
    /// masked. One sequence is spent whatever the caller then does with the record.
    pub fn seal13(self: *Epoch, content: Content, plain: []const u8, cid: []const u8, out: []u8) SealError![]u8 {
        @setRuntimeSafety(true);
        aegis.assert.invariant(self.version == .dtls13, "a DTLS 1.3 record");
        if (plain.len > max_content or cid.len > max_cid) return error.InvalidLength;
        if (content != .application and plain.len == 0) return error.InvalidLength;
        if (self.sequence >= self.record_limit) return error.RecordLimit;
        const head = 1 + cid.len + 2 + 2;
        const inner = plain.len + 1;
        const total = head + inner + tag_length;
        if (out.len < total) return error.BufferTooSmall;
        const record = out[0..total];
        // safe: two low bits of the epoch, and flags fixed by this encoder.
        record[0] = 0b0010_0000 | @as(u8, if (cid.len != 0) 0x10 else 0) | 0x08 | 0x04 | @as(u8, @truncate(self.number & 3));
        @memcpy(record[1..][0..cid.len], cid);
        std.mem.writeInt(u16, record[1 + cid.len ..][0..2], @truncate(self.sequence), .big);
        // safe: at most 2^14 + 17 bytes.
        std.mem.writeInt(u16, record[3 + cid.len ..][0..2], @intCast(inner + tag_length), .big);
        const body = record[head..][0..inner];
        if (plain.ptr != body.ptr) @memmove(body[0..plain.len], plain);
        body[plain.len] = @backingInt(content);
        self.encrypt(body, record[head + inner ..][0..tag_length], body, record[0..head], self.sequence);
        const masked = self.mask(record[head..][0..16]);
        record[1 + cid.len] ^= masked[0];
        record[2 + cid.len] ^= masked[1];
        self.sequence += 1;
        return record;
    }

    /// Opens a DTLS 1.3 record in place: `record` is the whole record (header, `cid_len` bytes of
    /// CID, sequence, length and ciphertext) as `Header.parse13` found it. The plaintext and its
    /// content type are returned only after the tag and the replay window pass.
    pub fn open13(self: *Epoch, record: []u8, header: Header13) OpenError!Opened {
        @setRuntimeSafety(true);
        aegis.assert.invariant(self.version == .dtls13, "a DTLS 1.3 record");
        const ciphertext = record[header.length..];
        if (ciphertext.len < 16 or ciphertext.len < tag_length + 1) return error.Drop;
        const masked = self.mask(ciphertext[0..16]);
        const seq_at = header.length - header.sequence_bytes - @as(usize, if (header.has_length) 2 else 0);
        var low: u64 = 0;
        for (record[seq_at..][0..header.sequence_bytes], 0..) |*byte, i| {
            byte.* ^= masked[i];
            low = (low << 8) | byte.*;
        }
        const sequence = self.window.reconstruct(low, if (header.sequence_bytes == 2) 16 else 8);
        if (!self.window.fresh(sequence)) return error.Drop;
        const sealed_len = ciphertext.len - tag_length;
        const tag = ciphertext[sealed_len..][0..tag_length];
        self.decrypt(ciphertext[0..sealed_len], ciphertext[0..sealed_len], tag, record[0..header.length], sequence) catch {
            self.failures +|= 1;
            return error.Drop;
        };
        self.window.mark(sequence);
        var end = sealed_len;
        while (end > 0 and ciphertext[end - 1] == 0) end -= 1;
        if (end == 0) return error.Drop;
        return .{ .content = @fromBackingInt(@intCast(ciphertext[end - 1])), .bytes = ciphertext[0 .. end - 1], .sequence = sequence };
    }

    /// Seals one DTLS 1.2 record (RFC 6347 section 4.1.2.1; RFC 9146 section 5.3 when `cid` is
    /// set).
    pub fn seal12(self: *Epoch, content: Content, plain: []const u8, cid: []const u8, out: []u8) SealError![]u8 {
        @setRuntimeSafety(true);
        aegis.assert.invariant(self.version == .dtls12, "a DTLS 1.2 record");
        if (plain.len > max_content or cid.len > max_cid) return error.InvalidLength;
        if (self.sequence >= self.record_limit or self.sequence >= 1 << 48) return error.RecordLimit;
        const explicit = self.cipher.explicitNonceLength12();
        const tag_len = self.cipher.tagLength();
        const with_cid = cid.len != 0;
        const head = header12 + cid.len;
        const inner = plain.len + @as(usize, if (with_cid) 1 else 0);
        const total = head + explicit + inner + tag_len;
        if (out.len < total) return error.BufferTooSmall;
        const record = out[0..total];
        const number = (self.number << 48) | self.sequence;
        record[0] = if (with_cid) tls12_cid else @backingInt(content);
        record[1..3].* = .{ 0xfe, 0xfd };
        std.mem.writeInt(u64, record[3..11], number, .big);
        @memcpy(record[11..][0..cid.len], cid);
        // safe: at most 2^14 + 25 bytes.
        std.mem.writeInt(u16, record[11 + cid.len ..][0..2], @intCast(explicit + inner + tag_len), .big);
        if (explicit != 0) std.mem.writeInt(u64, record[head..][0..8], number, .big);
        const body = record[head + explicit ..][0..inner];
        if (plain.ptr != body.ptr) @memmove(body[0..plain.len], plain);
        if (with_cid) body[plain.len] = @backingInt(content);
        var ad: [23 + max_cid]u8 = undefined;
        const additional = additional12(&ad, @backingInt(content), .{ 0xfe, 0xfd }, number, cid, inner);
        self.encrypt(body, record[head + explicit + inner ..][0..tag_len], body, additional, number);
        self.sequence += 1;
        return record;
    }

    /// Opens a DTLS 1.2 record in place, as `Header.parse12` found it.
    pub fn open12(self: *Epoch, record: []u8, header: Header12) OpenError!Opened {
        @setRuntimeSafety(true);
        aegis.assert.invariant(self.version == .dtls12, "a DTLS 1.2 record");
        const explicit = self.cipher.explicitNonceLength12();
        const tag_len = self.cipher.tagLength();
        const payload = record[header.length..];
        if (payload.len < explicit + tag_len + @as(usize, if (header.cid_len != 0) 1 else 0)) return error.Drop;
        if (!self.window.fresh(header.sequence)) return error.Drop;
        const number = (self.number << 48) | header.sequence;
        // GCM and CCM carry the nonce's explicit part on the wire: any value the sender never
        // repeats (RFC 5288 section 3), not necessarily the record number, which the additional
        // data binds anyway.
        const counter = if (explicit != 0) std.mem.readInt(u64, payload[0..8], .big) else number;
        const sealed = payload[explicit .. payload.len - tag_len];
        const tag = payload[payload.len - tag_len ..];
        const outer: u8 = if (header.cid_len != 0) tls12_cid else record[0];
        var ad: [23 + max_cid]u8 = undefined;
        // The additional data names the record's own type and version as they came.
        const additional = additional12(&ad, outer, record[1..3].*, number, record[11..][0..header.cid_len], sealed.len);
        self.decrypt(sealed, sealed, tag, additional, counter) catch {
            self.failures +|= 1;
            return error.Drop;
        };
        self.window.mark(header.sequence);
        if (header.cid_len == 0) return .{ .content = @fromBackingInt(@intCast(record[0])), .bytes = sealed, .sequence = header.sequence };
        // DTLSInnerPlaintext: the content, its real type, then zeros.
        var end = sealed.len;
        while (end > 0 and sealed[end - 1] == 0) end -= 1;
        if (end == 0) return error.Drop;
        return .{ .content = @fromBackingInt(@intCast(sealed[end - 1])), .bytes = sealed[0 .. end - 1], .sequence = header.sequence };
    }
};

/// DTLS 1.2 additional data: the epoch and sequence, type, version and plaintext length
/// (RFC 6347), or RFC 9146's form for a record with a connection ID.
fn additional12(out: *[23 + max_cid]u8, content: u8, version: [2]u8, number: u64, cid: []const u8, len: usize) []const u8 {
    if (cid.len == 0) {
        std.mem.writeInt(u64, out[0..8], number, .big);
        out[8] = content;
        out[9..11].* = version;
        // safe: callers bound the plaintext at 2^14.
        std.mem.writeInt(u16, out[11..13], @intCast(len), .big);
        return out[0..13];
    }
    // seq_num_placeholder, tls12_cid, cid_length, tls12_cid, version, epoch and sequence, cid,
    // length_of_DTLSInnerPlaintext (RFC 9146 section 5.3).
    @memset(out[0..8], 0xff);
    out[8] = tls12_cid;
    // safe: a CID is at most 255 bytes.
    out[9] = @intCast(cid.len);
    out[10] = tls12_cid;
    out[11..13].* = version;
    std.mem.writeInt(u64, out[13..21], number, .big);
    @memcpy(out[21..][0..cid.len], cid);
    // safe: callers bound the inner plaintext at 2^14 + 1.
    std.mem.writeInt(u16, out[21 + cid.len ..][0..2], @intCast(len), .big);
    return out[0 .. 23 + cid.len];
}

pub const Opened = struct { content: Content, bytes: []u8, sequence: u64 };

/// A DTLS 1.3 record's unified header, parsed but not unmasked.
pub const Header13 = struct {
    /// Bytes from the record's start to its ciphertext.
    length: usize,
    epoch_bits: u2,
    sequence_bytes: usize,
    has_length: bool,
    cid: []const u8,
};

/// A DTLS 1.2 or plaintext record header.
pub const Header12 = struct {
    length: usize,
    epoch: u16,
    sequence: u64,
    cid_len: usize,
};

/// What the first byte of a record says it is (RFC 9147 section 4.1, figure 5).
pub const Kind = union(enum) {
    /// DTLSPlaintext, or a DTLS 1.2 record, protected when its epoch is not zero; with
    /// `cid_len` bytes of connection ID when its type is tls12_cid.
    classic: Header12,
    /// A DTLS 1.3 protected record.
    unified: Header13,
};

pub const Split = struct { record: []u8, kind: Kind, rest: []u8 };

/// Splits off the first record of `datagram`. `cid_len` is the length of the connection ID this
/// end asked its peer to put on records (none says its own length). Null when what is left cannot
/// be a record, and the rest of the datagram is dropped with it.
pub fn split(datagram: []u8, cid_len: usize) ?Split {
    @setRuntimeSafety(true);
    if (datagram.len == 0) return null;
    const first = datagram[0];
    switch (first) {
        20, 21, 22, 23, 26, tls12_cid => {
            const cid = if (first == tls12_cid) cid_len else 0;
            if (first == tls12_cid and cid_len == 0) return null;
            const head = header12 + cid;
            if (datagram.len < head) return null;
            const length = std.mem.readInt(u16, datagram[head - 2 ..][0..2], .big);
            if (length > max_content + 2048 or datagram.len - head < length) return null;
            const number = std.mem.readInt(u64, datagram[3..11], .big);
            const total = head + length;
            return .{
                .record = datagram[0..total],
                .kind = .{ .classic = .{ .length = head, .epoch = @truncate(number >> 48), .sequence = number & ((1 << 48) - 1), .cid_len = cid } },
                .rest = datagram[total..],
            };
        },
        else => {
            if (first & 0xe0 != 0x20) return null;
            const has_cid = first & 0x10 != 0;
            if (has_cid and cid_len == 0) return null;
            const cid = if (has_cid) cid_len else 0;
            const sequence_bytes: usize = if (first & 0x08 != 0) 2 else 1;
            const has_length = first & 0x04 != 0;
            const head = 1 + cid + sequence_bytes + @as(usize, if (has_length) 2 else 0);
            if (datagram.len < head) return null;
            const length: usize = if (has_length) std.mem.readInt(u16, datagram[head - 2 ..][0..2], .big) else datagram.len - head;
            if (length > max_content + 256 or datagram.len - head < length) return null;
            const total = head + length;
            return .{
                .record = datagram[0..total],
                .kind = .{ .unified = .{ .length = head, .epoch_bits = @truncate(first & 3), .sequence_bytes = sequence_bytes, .has_length = has_length, .cid = datagram[1..][0..cid] } },
                .rest = datagram[total..],
            };
        },
    }
}

/// Writes a DTLSPlaintext record: epoch 0 and a 48-bit sequence (RFC 9147 section 4).
pub fn plaintext(content: Content, sequence: u64, body: []const u8, out: []u8) SealError![]u8 {
    @setRuntimeSafety(true);
    if (body.len > max_content) return error.InvalidLength;
    if (sequence >= 1 << 48) return error.RecordLimit;
    if (out.len < header12 + body.len) return error.BufferTooSmall;
    out[0] = @backingInt(content);
    out[1..3].* = .{ 0xfe, 0xfd };
    std.mem.writeInt(u64, out[3..11], sequence, .big);
    // safe: bounded at 2^14 above.
    std.mem.writeInt(u16, out[11..13], @intCast(body.len), .big);
    if (body.ptr != out[header12..].ptr) @memmove(out[header12..][0..body.len], body);
    return out[0 .. header12 + body.len];
}

test {
    _ = @import("Record_test.zig");
}
