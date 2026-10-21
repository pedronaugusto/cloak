//! Private directional record owner. Only connection orchestration may seal/open.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
const Keys = @import("../offload/Keys.zig");
pub const RecordCount = aegis.units.Count(struct {}, u64);
pub const ByteCount = aegis.units.Count(struct {}, u64);
pub const Content = enum(u8) { alert = 21, handshake = 22, application = 23 };
pub const max_content = 1 << 14;
pub const max_inner = max_content + 1;
pub const max_ciphertext = max_content + 256;
pub const Limits = struct { records: u64 = 1 << 24, bytes: u64 = 1 << 38 };
pub const InitError = error{InvalidLimits};
pub const SealError = error{ Closed, RecordLimit, BufferTooSmall, InvalidLength, PartialOverlap };
/// `BadRecord` is a record that fails its tag (or is no TLS 1.3 ciphertext); `UnexpectedRecord` an
/// authenticated one whose inner plaintext names no content type or an unknown one, or is an empty
/// alert or handshake fragment (RFC 8446 sections 5.1, 5.4: unexpected_message, not bad_record_mac);
/// `RecordOverflow` one whose inner plaintext would pass 2^14 + 1 bytes (section 5.4).
pub const OpenError = error{ Closed, RecordLimit, BufferTooSmall, BadRecord, UnexpectedRecord, PartialOverlap, RecordOverflow };
pub const Plaintext = struct { content: Content, bytes: []u8 };
pub const TrialError = OpenError || error{Undecryptable};
/// Who seals or opens an epoch's records: the epoch itself, or a kernel record layer that holds
/// its keys (`kernel`), or a kernel that has yet to take the keys a key update made (`next`).
pub const Owner = enum(u8) { software, kernel, next };

pub fn Epoch(comptime suite: suites.Suite13) type {
    const A = suites.Aead(suite);
    const Hash = suites.Hash(suite);
    return struct {
        const Self = @This();
        /// The traffic secret an epoch consumes.
        pub const TrafficSecret = aegis.Secret([Hash.digest_length]u8);
        key: aegis.Secret([A.key_length]u8),
        iv: aegis.Secret([12]u8),
        traffic: ?TrafficSecret = null,
        sequence: RecordCount = .fromRaw(0),
        bytes: ByteCount = .fromRaw(0),
        limits: struct { records: RecordCount, bytes: ByteCount },
        closed: bool = false,
        owner: Owner = .software,
        pub fn init(key: [A.key_length]u8, iv: [12]u8, limits: Limits) InitError!Self {
            @setRuntimeSafety(true);
            if (limits.records == 0 or limits.records > 1 << 24 or limits.bytes == 0 or limits.bytes > 1 << 38) return error.InvalidLimits;
            // A cipher with a lower record bound (CCM) caps the caller's.
            const records = @min(limits.records, comptime suites.cipherOf(suite).recordLimit());
            return .{ .key = .init(key), .iv = .init(iv), .limits = .{ .records = .fromRaw(records), .bytes = .fromRaw(limits.bytes) } };
        }
        /// Consumes the supplied traffic owner on success; error leaves it owned.
        pub fn initTraffic(traffic: *TrafficSecret, limits: Limits) InitError!Self {
            var key = aegis.Secret([A.key_length]u8).init(undefined);
            defer key.deinit();
            var iv = aegis.Secret([12]u8).init(undefined);
            defer iv.deinit();
            derive(traffic.expose(), key.exposeMut(), iv.exposeMut());
            var result = try Self.init(key.expose().*, iv.expose().*, limits);
            errdefer result.deinit();
            result.traffic = .init(undefined);
            traffic.moveInto(&result.traffic.?);
            return result;
        }
        /// Copies the record keys and the next record's number into `keys` for a kernel to
        /// take; nothing changes here until `release`.
        pub fn exportKeys(self: *const Self, keys: *Keys) void {
            @setRuntimeSafety(true);
            aegis.assert.pre(!self.closed and self.owner != .kernel, "only keys this epoch holds are exported");
            @memcpy(keys.key.exposeMut()[0..A.key_length], self.key.expose());
            keys.iv.exposeMut().* = self.iv.expose().*;
            keys.sequence = self.sequence.raw();
        }
        /// The kernel holds the keys: they are erased here, and its records are the kernel's to
        /// seal or open. The traffic secret stays, for the next key update.
        pub fn release(self: *Self) void {
            self.key.deinit();
            self.iv.deinit();
            self.owner = .kernel;
        }
        /// The kernel's count of records under these keys, read from it: the budget follows the
        /// records it sealed or opened. A count below the one known is stale and changes nothing.
        pub fn account(self: *Self, records: u64) void {
            if (self.owner == .kernel and RecordCount.fromRaw(records).compare(self.sequence) == .gt) self.sequence = .fromRaw(records);
        }
        pub const UpdateError = error{ Closed, MissingTraffic };
        /// The connection calls this only after committing/accepting the complete
        /// old-key KeyUpdate record. No public caller may install an epoch.
        pub fn update(self: *Self) UpdateError!void {
            @setRuntimeSafety(true);
            if (self.closed) return error.Closed;
            if (self.traffic == null) return error.MissingTraffic;
            // A kernel takes one key update at a time: the next keys wait for it.
            aegis.assert.pre(self.owner != .next, "a kernel takes the next keys before another update");
            var next = TrafficSecret.init(undefined);
            defer next.deinit();
            // unreachable: fixed label and hash-sized output meet the HKDF bounds.
            Labels.expand(Hash, next.exposeMut(), self.traffic.?.expose(), "traffic upd", "") catch unreachable;
            var key = aegis.Secret([A.key_length]u8).init(undefined);
            defer key.deinit();
            var iv = aegis.Secret([12]u8).init(undefined);
            defer iv.deinit();
            derive(next.expose(), key.exposeMut(), iv.exposeMut());
            self.key.deinit();
            self.iv.deinit();
            self.traffic.?.deinit();
            self.key = .init(key.expose().*);
            self.iv = .init(iv.expose().*);
            self.traffic = .init(next.expose().*);
            self.sequence = .fromRaw(0);
            self.bytes = .fromRaw(0);
            if (self.owner == .kernel) self.owner = .next;
        }
        /// The Finished of a post-handshake authentication sent under this epoch: the MAC of
        /// `transcript` under the finished key of the current traffic secret (RFC 8446 section
        /// 4.4: client_application_traffic_secret_N). The secret never leaves the epoch; a kernel
        /// holding the keys leaves it here too. Only an open epoch made from a traffic secret.
        pub fn finished(self: *const Self, transcript: *const [Hash.digest_length]u8, out: *[Hash.digest_length]u8) void {
            @setRuntimeSafety(true);
            aegis.assert.pre(!self.closed and self.traffic != null, "a Finished is made under an open epoch's traffic secret");
            Labels.finished(Hash, .tls13, out, self.traffic.?.expose(), transcript);
        }
        /// Checks a post-handshake Finished received under this epoch, in constant time.
        pub fn checkFinished(self: *const Self, transcript: *const [Hash.digest_length]u8, received: []const u8) Labels.CheckError!void {
            @setRuntimeSafety(true);
            aegis.assert.pre(!self.closed and self.traffic != null, "a Finished is checked under an open epoch's traffic secret");
            return Labels.checkFinished(Hash, .tls13, self.traffic.?.expose(), transcript, received);
        }
        fn derive(secret: *const [Hash.digest_length]u8, key: *[A.key_length]u8, iv: *[12]u8) void {
            // unreachable: fixed label and AEAD-sized output meet the HKDF bounds.
            Labels.expand(Hash, key, secret, "key", "") catch unreachable;
            // unreachable: fixed label and twelve-byte output meet the HKDF bounds.
            Labels.expand(Hash, iv, secret, "iv", "") catch unreachable;
        }
        pub fn deinit(self: *Self) void {
            self.key.deinit();
            self.iv.deinit();
            if (self.traffic) |*traffic| traffic.deinit();
            self.traffic = null;
            self.closed = true;
        }
        fn nonce(self: *const Self) [12]u8 {
            @setRuntimeSafety(true);
            var value = self.iv.expose().*;
            var counter: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter, self.sequence.raw(), .big);
            for (value[4..], counter) |*byte, n| byte.* ^= n;
            return value;
        }
        fn admit(self: *Self, len: usize) error{RecordLimit}!void {
            @setRuntimeSafety(true);
            // unreachable: every admitted record kept the bytes within the limit.
            const room = self.limits.bytes.sub(self.bytes) catch unreachable;
            if (self.sequence.compare(self.limits.records) != .lt or ByteCount.fromRaw(len).compare(room) == .gt) {
                self.deinit();
                return error.RecordLimit;
            }
        }
        /// Commit consumes one nonce, irrespective of subsequent transport acks.
        /// Exact alias means input starts at out.ptr + 5; other overlap is refused.
        pub fn seal(self: *Self, content: Content, input: []const u8, padding: usize, out: []u8) SealError![]u8 {
            @setRuntimeSafety(true);
            if (self.closed or self.owner != .software) return error.Closed;
            if (content != .application and input.len == 0) return error.InvalidLength;
            if (input.len > max_content or padding > max_content - input.len) return error.InvalidLength;
            const inner_len = input.len + 1 + padding;
            const wire_len = 5 + inner_len + A.tag_length;
            if (out.len < wire_len) return error.BufferTooSmall;
            const wire = out[0..wire_len];
            if (overlap(input, wire) and @intFromPtr(input.ptr) != @intFromPtr(wire.ptr) + 5) return error.PartialOverlap; // safe: compare live addresses only to permit exact ciphertext-body alias.
            try self.admit(inner_len);
            wire[0..3].* = .{ 23, 3, 3 };
            // safe: bounded by max_inner + the fixed 16-byte AEAD tag.
            std.mem.writeInt(u16, wire[3..5], @intCast(inner_len + A.tag_length), .big);
            const inner = wire[5..][0..inner_len];
            if (input.ptr != inner.ptr) @memcpy(inner[0..input.len], input);
            inner[input.len] = @backingInt(content);
            @memset(inner[input.len + 1 ..], 0);
            A.encrypt(inner, wire[5 + inner_len ..][0..16], inner, wire[0..5], self.nonce(), self.key.expose().*);
            self.sequence = self.sequence.add(.fromRaw(1)) catch unreachable; // unreachable: admit refused the record at the count limit
            self.bytes = self.bytes.add(.fromRaw(inner_len)) catch unreachable; // unreachable: admit kept the bytes within the limit
            return wire;
        }
        /// Tag verification precedes release. Any peer failure erases this epoch.
        pub fn open(self: *Self, wire: []const u8, out: []u8) OpenError!Plaintext {
            return self.openChecked(wire, out, false) catch |err| switch (err) {
                error.Undecryptable => unreachable, // unreachable: only a trial reports it
                else => |e| return e,
            };
        }
        /// `open` for a record that may belong to an epoch this one never sees: early data a server
        /// declined, under keys it does not have. A record whose tag fails is `Undecryptable` and
        /// leaves the epoch as it was, with nothing released; every other failure is `open`'s.
        pub fn trialOpen(self: *Self, wire: []const u8, out: []u8) TrialError!Plaintext {
            return self.openChecked(wire, out, true);
        }
        fn openChecked(self: *Self, wire: []const u8, out: []u8, trial: bool) TrialError!Plaintext {
            @setRuntimeSafety(true);
            if (self.closed or self.owner != .software) return error.Closed;
            // Too short for a tag and a content type: it fails deprotection, which a trial reports
            // as for a tag that fails (declined early data of any length is skipped).
            if (wire.len < 5 + 17) return if (trial) error.Undecryptable else self.bad();
            if (!std.mem.eql(u8, wire[0..3], &.{ 23, 3, 3 }) or std.mem.readInt(u16, wire[3..5], .big) != wire.len - 5) return self.bad();
            const len = wire.len - 5 - A.tag_length;
            // A ciphertext past 2^14 + 256 bytes, or one whose inner plaintext (content, type and
            // padding) would pass 2^14 + 1 bytes, is record_overflow (RFC 8446 sections 5.2, 5.4
            // and 6.2): its length says so before any decryption work.
            if (len > max_inner) {
                self.deinit();
                return error.RecordOverflow;
            }
            if (out.len < len) return error.BufferTooSmall;
            const plain = out[0..len];
            const cipher = wire[5..][0..len];
            if (overlap(wire, plain) and plain.ptr != cipher.ptr) return error.PartialOverlap;
            try self.admit(len);
            A.decrypt(plain, cipher, wire[wire.len - 16 ..][0..16].*, wire[0..5], self.nonce(), self.key.expose().*) catch {
                std.crypto.secureZero(u8, plain);
                if (trial) return error.Undecryptable;
                return self.bad();
            };
            var end = len;
            while (end > 0 and plain[end - 1] == 0) end -= 1;
            if (end == 0) return self.unexpected(plain);
            const content = std.enums.fromInt(Content, plain[end - 1]) orelse return self.unexpected(plain);
            if (content != .application and end == 1) return self.unexpected(plain);
            self.sequence = self.sequence.add(.fromRaw(1)) catch unreachable; // unreachable: admit refused the record at the count limit
            self.bytes = self.bytes.add(.fromRaw(len)) catch unreachable; // unreachable: admit kept the bytes within the limit
            return .{ .content = content, .bytes = plain[0 .. end - 1] };
        }
        fn bad(self: *Self) error{BadRecord} {
            self.deinit();
            return error.BadRecord;
        }
        /// An authenticated record the protocol forbids: its plaintext is erased with the epoch.
        fn unexpected(self: *Self, plain: []u8) error{UnexpectedRecord} {
            std.crypto.secureZero(u8, plain);
            self.deinit();
            return error.UnexpectedRecord;
        }
    };
}
fn overlap(a: []const u8, b: []const u8) bool {
    @setRuntimeSafety(true);
    if (a.len == 0 or b.len == 0) return false;
    const x = @intFromPtr(a.ptr); // safe: live address used only for overlap validation.
    const y = @intFromPtr(b.ptr); // safe: live address used only for overlap validation.
    return if (x <= y) y - x < a.len else x - y < b.len;
}
comptime {
    std.debug.assert(max_inner + 16 <= max_ciphertext);
    for (std.enums.values(suites.Suite13)) |suite| std.debug.assert(@sizeOf(Epoch(suite)) <= 192);
}
test {
    _ = @import("Epoch_test.zig");
}
