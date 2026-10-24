//! The secret kernels: where record and ticket keys meet std's ciphers. std's primitives take
//! keys and nonces by value and keep key schedules, counter blocks and hash states in their own
//! frames, which no owner names; each kernel here runs in a frame of its own under
//! `aegis.secret.scrubbed`, which zeroes `depth` bytes below its entry when it returns (and runs
//! it under data-independent timing). The nonce is made inside, from the IV and the public counter,
//! so neither leaves a copy in the caller's frame. HMAC over a secret (HKDF, the TLS 1.2 PRF, the
//! cookie and ticket-key MACs) runs under the same depth from its own module. A test holds the
//! bound for every kernel and cipher in the build mode it runs in.
const std = @import("std");
const aegis = @import("aegis");
const builtin = @import("builtin");

/// The stack HMAC over a secret reaches, with room (about 3.5 KiB optimized on AArch64, the
/// TLS 1.2 PRF the deepest; Debug frames are several times larger).
pub const depth = if (builtin.mode == .debug) 32 * 1024 else 8 * 1024;
/// The stack a record or mask kernel reaches, with room (under 2 KiB optimized): every record
/// pays for this scrub, so it is the records' own.
pub const record_depth = if (builtin.mode == .debug) 32 * 1024 else 4 * 1024;
/// The stack an AES kernel reaches where std runs AES in software (x86_64 without AES-NI and
/// AVX, AArch64 without its AES instructions), with room: the software rounds keep the key
/// schedule and their tables in std's frames, about 19 KiB optimized and 88 KiB in Debug on
/// x86_64 (AES-256-GCM the deepest). There the AES kernels erase this; ChaCha20's keep the
/// records' own.
pub const software_aes_depth = if (builtin.mode == .debug) 128 * 1024 else 32 * 1024;

/// What a kernel of the AEAD `A` erases: every AEAD here but ChaCha20-Poly1305 is AES's.
fn aeadDepth(comptime A: type) usize {
    return if (A == std.crypto.aead.chacha_poly.ChaCha20Poly1305) record_depth else aesDepth();
}

fn maskDepth(comptime cipher: MaskCipher) usize {
    return if (cipher == .chacha20) record_depth else aesDepth();
}

fn aesDepth() usize {
    return if (std.crypto.core.aes.has_hardware_support) record_depth else software_aes_depth;
}

/// AEAD-encrypts `m` into `c` under `key`, with the nonce `iv` xor `counter` in its last eight
/// bytes (RFC 8446 section 5.3; TLS 1.2's explicit nonce over an IV whose tail is zero is the
/// same xor).
pub fn seal(comptime A: type, c: []u8, tag: *[A.tag_length]u8, m: []const u8, ad: []const u8, iv: *const [12]u8, counter: u64, key: *const [A.key_length]u8) void {
    aegis.secret.scrubbed(aeadDepth(A), sealKernel, .{ A, c, tag, m, ad, iv, counter, key });
}

/// Checks the tag and decrypts `c` into `m`; see `seal`.
pub fn open(comptime A: type, m: []u8, c: []const u8, tag: *const [A.tag_length]u8, ad: []const u8, iv: *const [12]u8, counter: u64, key: *const [A.key_length]u8) error{AuthenticationFailed}!void {
    return aegis.secret.scrubbed(aeadDepth(A), openKernel, .{ A, m, c, tag, ad, iv, counter, key });
}

/// The DTLS 1.3 record-number mask (RFC 9147 section 4.2.3): AES-ECB of the sample under the
/// `sn` key, or the ChaCha20 keystream the sample selects.
pub fn mask(comptime cipher: MaskCipher, sn: *const [32]u8, sample: *const [16]u8, out: *[16]u8) void {
    aegis.secret.scrubbed(maskDepth(cipher), maskKernel, .{ cipher, sn, sample, out });
}

pub const MaskCipher = enum { aes128, aes256, chacha20 };

fn nonceOf(iv: *const [12]u8, counter: u64) [12]u8 {
    var nonce = iv.*;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, counter, .big);
    for (nonce[4..], bytes) |*byte, n| byte.* ^= n;
    return nonce;
}

fn sealKernel(comptime A: type, c: []u8, tag: *[A.tag_length]u8, m: []const u8, ad: []const u8, iv: *const [12]u8, counter: u64, key: *const [A.key_length]u8) void {
    A.encrypt(c, tag, m, ad, nonceOf(iv, counter), key.*);
}

fn openKernel(comptime A: type, m: []u8, c: []const u8, tag: *const [A.tag_length]u8, ad: []const u8, iv: *const [12]u8, counter: u64, key: *const [A.key_length]u8) error{AuthenticationFailed}!void {
    return A.decrypt(m, c, tag.*, ad, nonceOf(iv, counter), key.*);
}

fn maskKernel(comptime cipher: MaskCipher, sn: *const [32]u8, sample: *const [16]u8, out: *[16]u8) void {
    switch (cipher) {
        .aes128 => std.crypto.core.aes.Aes128.initEnc(sn[0..16].*).encrypt(out, sample),
        .aes256 => std.crypto.core.aes.Aes256.initEnc(sn.*).encrypt(out, sample),
        .chacha20 => std.crypto.stream.chacha.ChaCha20IETF.xor(out, &@as([16]u8, @splat(0)), std.mem.readInt(u32, sample[0..4], .little), sn.*, sample[4..16].*),
    }
}

test "F93 catalogue_secret_diagnostics_and_release_campaign (each record and mask kernel reaches less stack than the depth that erases it)" {
    const suites = @import("Suite.zig");
    const key: [32]u8 = @splat(7);
    const iv: [12]u8 = @splat(9);
    var buffer: [512]u8 = @splat(1);
    const expectWithin = struct {
        fn check(name: []const u8, erased: usize, reached: usize) !void {
            std.testing.expect(reached < erased) catch |err| {
                std.debug.print("{s} reaches {d} bytes of stack, past the {d} that are erased\n", .{ name, reached, erased });
                return err;
            };
        }
    }.check;
    inline for (comptime std.enums.values(suites.Cipher)) |cipher| {
        const A = suites.AeadOf(cipher);
        var tag: [A.tag_length]u8 = @splat(0);
        try expectWithin(@tagName(cipher), aeadDepth(A), aegis.secret.stackReach(4 * aeadDepth(A), sealKernel, .{ A, buffer[0..], &tag, buffer[0..], "ad", &iv, 5, key[0..A.key_length] }));
        try expectWithin(@tagName(cipher), aeadDepth(A), aegis.secret.stackReach(4 * aeadDepth(A), openKernel, .{ A, buffer[0..], buffer[0..], &tag, "ad", &iv, 5, key[0..A.key_length] }));
    }
    inline for (comptime std.enums.values(MaskCipher)) |cipher| {
        var out: [16]u8 = undefined;
        try expectWithin(@tagName(cipher), maskDepth(cipher), aegis.secret.stackReach(4 * maskDepth(cipher), maskKernel, .{ cipher, &key, buffer[0..16], &out }));
    }
}
