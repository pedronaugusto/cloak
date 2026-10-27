//! X25519 (RFC 7748 5): s2n-bignum's verified ladder on x86_64 and AArch64, the RFC's Montgomery
//! ladder over fiat-crypto's verified curve25519 field (`field/curve25519.zig`) everywhere else
//! and as the reference the assembly is tested against. Both clamp the scalar and mask the
//! u-coordinate's top bit as the RFC says, accept non-canonical u-coordinates, and return the
//! all-zero output for a point of small order: the 6.1 check is the caller's (`Ecdh.X25519`).
//!
//! Every operation runs the same instructions for every scalar. The assembly writes its
//! temporaries to the stack: callers run it inside `aegis.secret.scrubbed`.
const std = @import("std");
const s2n = @import("field/s2n.zig");
const Fe = @import("field/curve25519.zig").Fe;
const Secret = @import("aegis").secret.Secret;

pub const length = 32;

pub const Backend = enum { fiat, s2n };

/// The backend this build computes with.
pub const backend: Backend = if (s2n.assembly) .s2n else .fiat;

/// X25519(scalar, u).
pub fn scalarmult(out: *[length]u8, scalar: *const [length]u8, u: *const [length]u8) void {
    With(backend, null).scalarmult(out, scalar, u);
}

/// X25519(scalar, 9): the public key of `scalar`.
pub fn base(out: *[length]u8, scalar: *const [length]u8) void {
    With(backend, null).base(out, scalar);
}

/// A backend, and for s2n-bignum its variant (null is the build's choice), for testing and
/// measuring each.
pub fn With(comptime chosen: Backend, comptime variant: ?s2n.Variant) type {
    if (chosen == .s2n and !s2n.assembly) @compileError("s2n-bignum's assembly is not in this build");
    return struct {
        pub fn scalarmult(out: *[length]u8, scalar: *const [length]u8, u: *const [length]u8) void {
            switch (chosen) {
                .fiat => ladder(out, scalar, u),
                .s2n => {
                    // The scalar, the result, and the u-coordinate beside them.
                    var owner: Secret([3][4]u64) = .init(undefined);
                    defer owner.deinit();
                    const words = owner.exposeMut();
                    words[1] = toWords(scalar);
                    words[2] = toWords(u);
                    const F = fn (*[4]u64, *const [4]u64, *const [4]u64) callconv(.c) void;
                    if ((variant orelse s2n.chosen()) == .plain) {
                        s2n.routine(F, "curve25519_x25519")(&words[0], &words[1], &words[2]);
                    } else s2n.routine(F, "curve25519_x25519_alt")(&words[0], &words[1], &words[2]);
                    out.* = fromWords(&words[0]);
                },
            }
        }

        pub fn base(out: *[length]u8, scalar: *const [length]u8) void {
            switch (chosen) {
                .fiat => ladder(out, scalar, &nine),
                .s2n => {
                    var owner: Secret([2][4]u64) = .init(undefined);
                    defer owner.deinit();
                    const words = owner.exposeMut();
                    words[1] = toWords(scalar);
                    const F = fn (*[4]u64, *const [4]u64) callconv(.c) void;
                    if ((variant orelse s2n.chosen()) == .plain) {
                        s2n.routine(F, "curve25519_x25519base")(&words[0], &words[1]);
                    } else s2n.routine(F, "curve25519_x25519base_alt")(&words[0], &words[1]);
                    out.* = fromWords(&words[0]);
                },
            }
        }
    };
}

/// The surface the key exchanges, HPKE and key loading call, in std's names so each call site
/// reads as it did: a key pair from a seed (the seed is the secret key), the public key of a
/// secret, and the shared secret, refused when it is all zeros (RFC 7748 6.1: a peer of small
/// order would fix it whatever the scalar). Callers run these inside `aegis.secret.scrubbed`.
pub const Dh = struct {
    pub const seed_length = length;
    pub const secret_length = length;
    pub const public_length = length;

    pub const KeyPair = struct {
        secret_key: [length]u8,
        public_key: [length]u8,

        pub fn generateDeterministic(seed: [seed_length]u8) KeyPair {
            return .{ .secret_key = seed, .public_key = recoverPublicKey(seed) };
        }
    };

    pub fn recoverPublicKey(secret: [secret_length]u8) [public_length]u8 {
        var out: [public_length]u8 = undefined;
        base(&out, &secret);
        return out;
    }

    pub fn scalarmult(secret: [secret_length]u8, public: [public_length]u8) error{IdentityElement}![length]u8 {
        var out: [length]u8 = undefined;
        x25519Into(&out, &secret, &public);
        // Only the verdict of the all-zero check leaves.
        var any: u8 = 0;
        for (out) |byte| any |= byte;
        if (any == 0) return error.IdentityElement;
        return out;
    }
};

fn x25519Into(out: *[length]u8, secret: *const [length]u8, public: *const [length]u8) void {
    scalarmult(out, secret, public);
}

const nine: [length]u8 = .{9} ++ @as([length - 1]u8, @splat(0));

fn toWords(bytes: *const [length]u8) [4]u64 {
    var words: [4]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
    return words;
}

fn fromWords(words: *const [4]u64) [length]u8 {
    var bytes: [length]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u64, bytes[8 * i ..][0..8], word, .little);
    return bytes;
}

// ---------------------------------------------------------------- the portable ladder

const LadderState = struct { k: [length]u8, x1: Fe, x2: Fe, z2: Fe, x3: Fe, z3: Fe };

/// RFC 7748 5's ladder, step for step.
fn ladder(out: *[length]u8, scalar: *const [length]u8, u: *const [length]u8) void {
    var owner: Secret(LadderState) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    s.k = scalar.*;
    s.k[0] &= 248;
    s.k[31] &= 127;
    s.k[31] |= 64;
    s.x1 = Fe.fromBytes(u);
    s.x2 = Fe.one;
    s.z2 = Fe.zero;
    s.x3 = s.x1;
    s.z3 = Fe.one;
    var swap: u1 = 0;
    var t: usize = 255;
    while (t > 0) {
        t -= 1;
        const k_t: u1 = @truncate(s.k[t / 8] >> @intCast(t % 8)); // safe: one bit of the scalar
        swap ^= k_t;
        Fe.cswap(swap, &s.x2, &s.x3);
        Fe.cswap(swap, &s.z2, &s.z3);
        swap = k_t;
        const a = s.x2.add(&s.z2);
        const aa = a.sqr();
        const b = s.x2.sub(&s.z2);
        const bb = b.sqr();
        const e = aa.sub(&bb);
        const c = s.x3.add(&s.z3);
        const d = s.x3.sub(&s.z3);
        const da = d.mul(&a);
        const cb = c.mul(&b);
        s.x3 = da.add(&cb).sqr();
        s.z3 = s.x1.mul(&da.sub(&cb).sqr());
        s.x2 = aa.mul(&bb);
        // z2 = E * (AA + a24 * E) with a24 = 121665, as E * (BB + 121666 * E).
        s.z2 = e.mul(&bb.add(&e.mul121666()));
    }
    Fe.cswap(swap, &s.x2, &s.x3);
    Fe.cswap(swap, &s.z2, &s.z3);
    out.* = s.x2.mul(&s.z2.invert()).toBytes();
}

test {
    _ = @import("x25519_test.zig");
}
