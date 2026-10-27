//! ML-DSA (FIPS 204) for certificates and CertificateVerify: key generation from a seed, the
//! expanded private key checked against itself, hedged signing and verification, for
//! ML-DSA-44, -65 and -87.
//!
//! The matrix A is never held: each of its polynomials is expanded from rho when it is used,
//! so verification needs about (k + 3) KiB of stack and signing about (k + 6) KiB, where std's
//! implementation caches A in its key types and puts several hundred KiB on the stack for
//! ML-DSA-87. Every operation on secret values (s1, s2, t0, y, w0, the hint before it is
//! released) is branch-free and index-free; what branches is public (A, c, the signature, a
//! rejected candidate's verdict) or the rejection sampling of ExpandS over the seed's own
//! SHAKE stream, as FIPS 204's reference does. The arithmetic follows std's (from CIRCL), whose
//! bounds it keeps: coefficients below 2q into the inverse NTT.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const aegis = @import("aegis");
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;

pub const Level = enum { mldsa44, mldsa65, mldsa87 };

const n = 256;
const q: u32 = 8380417;
const d = 13;
/// -q^-1 mod 2^32, for Montgomery reduction.
const q_inv: u32 = 4236238847;
/// 256^-1 * R^2 mod q: the inverse NTT's final scaling, R = 2^32.
const r_over_256: u32 = 41978;
const zeta: u32 = 1753;

const Poly = [n]u32;

pub fn Scheme(comptime level: Level) type {
    return struct {
        pub const k: usize = switch (level) {
            .mldsa44 => 4,
            .mldsa65 => 6,
            .mldsa87 => 8,
        };
        pub const l: usize = switch (level) {
            .mldsa44 => 4,
            .mldsa65 => 5,
            .mldsa87 => 7,
        };
        const eta: u32 = if (level == .mldsa65) 4 else 2;
        const tau: u32 = switch (level) {
            .mldsa44 => 39,
            .mldsa65 => 49,
            .mldsa87 => 60,
        };
        const beta: u32 = tau * eta;
        const gamma1_bits: u5 = if (level == .mldsa44) 17 else 19;
        const gamma1: u32 = @as(u32, 1) << gamma1_bits;
        const gamma2: u32 = if (level == .mldsa44) (q - 1) / 88 else (q - 1) / 32;
        const omega: usize = switch (level) {
            .mldsa44 => 80,
            .mldsa65 => 55,
            .mldsa87 => 75,
        };
        const ctilde: usize = switch (level) {
            .mldsa44 => 32,
            .mldsa65 => 48,
            .mldsa87 => 64,
        };
        const eta_bytes: usize = if (eta == 2) 96 else 128;
        const t1_bytes: usize = 320;
        const t0_bytes: usize = 416;
        const z_bytes: usize = @as(usize, gamma1_bits + 1) * n / 8;
        const w1_bytes: usize = if (level == .mldsa44) 192 else 128;

        pub const seed_length = 32;
        pub const public_key_length = 32 + t1_bytes * k;
        pub const secret_key_length = 32 + 32 + 64 + eta_bytes * (l + k) + t0_bytes * k;
        pub const signature_length = ctilde + z_bytes * l + omega + k;
        /// Fresh bytes one hedged signature draws.
        pub const noise_length = 32;

        // Where the expanded private key keeps its parts (FIPS 204 skEncode).
        const sk_rho = 0;
        const sk_key = 32;
        const sk_tr = 64;
        const sk_s1 = 128;
        const sk_s2 = sk_s1 + eta_bytes * l;
        const sk_t0 = sk_s2 + eta_bytes * k;

        /// ML-DSA.KeyGen_internal from a 32-byte seed: the public key and the expanded private
        /// key (FIPS 204 Algorithm 6).
        pub fn keyFromSeed(seed: *const [seed_length]u8, pk: *[public_key_length]u8, sk: *[secret_key_length]u8) void {
            @setRuntimeSafety(true);
            var expanded_owner: Secret([128]u8) = .init(undefined);
            defer expanded_owner.deinit();
            const expanded = expanded_owner.exposeMut();
            var h = Shake256.init(.{});
            h.update(seed);
            h.update(&.{ @as(u8, k), @as(u8, l) });
            h.squeeze(expanded);
            const rho = expanded[0..32];
            const rho_prime = expanded[32..96];
            pk[0..32].* = rho.*;
            sk[sk_rho..][0..32].* = rho.*;
            sk[sk_key..][0..32].* = expanded[96..128].*;
            var acc_owner: Secret([k]Poly) = .init(undefined);
            defer acc_owner.deinit();
            const acc = acc_owner.exposeMut();
            var s_owner: Secret(Poly) = .init(undefined);
            defer s_owner.deinit();
            const s = s_owner.exposeMut();
            var a: Poly = undefined;
            for (acc) |*p| p.* = @splat(0);
            for (0..l) |j| {
                expandS(s, rho_prime, @intCast(j));
                packEta(s, sk[sk_s1 + eta_bytes * j ..][0..eta_bytes]);
                ntt(s);
                for (0..k) |i| {
                    expandA(&a, rho, i, j);
                    mulAdd(&acc[i], &a, s);
                }
            }
            for (0..k) |i| {
                reduceLe2q(&acc[i]);
                invNtt(&acc[i]);
                expandS(s, rho_prime, @intCast(l + i));
                packEta(s, sk[sk_s2 + eta_bytes * i ..][0..eta_bytes]);
                // t = A s1 + s2, split into t1 (public) and t0 (secret).
                for (&acc[i], s) |*t, si| t.* = modQ(t.* +% si);
                var t1: Poly = undefined;
                for (&acc[i], &t1) |*t, *hi| {
                    const split = power2Round(t.*);
                    t.* = split.low_plus_q;
                    hi.* = split.high;
                }
                packT1(&t1, pk[32 + t1_bytes * i ..][0..t1_bytes]);
                packT0(&acc[i], sk[sk_t0 + t0_bytes * i ..][0..t0_bytes]);
            }
            var tr: [64]u8 = undefined;
            Shake256.hash(pk, &tr, .{});
            sk[sk_tr..][0..64].* = tr;
        }

        pub const KeyError = error{InvalidKey};

        /// The public key of an expanded private key, after checking the key against itself:
        /// s1 and s2 within [-eta, eta], t0 the low bits of A s1 + s2, and tr the hash of the
        /// public key that follows. A key that fails any of these signs nothing.
        pub fn publicKey(sk: *const [secret_key_length]u8, pk: *[public_key_length]u8) KeyError!void {
            @setRuntimeSafety(true);
            if (!etaInRange(sk[sk_s1..sk_t0])) return error.InvalidKey;
            const rho = sk[sk_rho..][0..32];
            pk[0..32].* = rho.*;
            var acc_owner: Secret([k]Poly) = .init(undefined);
            defer acc_owner.deinit();
            const acc = acc_owner.exposeMut();
            var s_owner: Secret(Poly) = .init(undefined);
            defer s_owner.deinit();
            const s = s_owner.exposeMut();
            var a: Poly = undefined;
            for (acc) |*p| p.* = @splat(0);
            for (0..l) |j| {
                unpackEta(sk[sk_s1 + eta_bytes * j ..][0..eta_bytes], s);
                ntt(s);
                for (0..k) |i| {
                    expandA(&a, rho, i, j);
                    mulAdd(&acc[i], &a, s);
                }
            }
            var t0_matches = aegis.secret.equal(1, &.{0}, &.{0});
            for (0..k) |i| {
                reduceLe2q(&acc[i]);
                invNtt(&acc[i]);
                unpackEta(sk[sk_s2 + eta_bytes * i ..][0..eta_bytes], s);
                for (&acc[i], s) |*t, si| t.* = modQ(t.* +% si);
                var t1: Poly = undefined;
                for (&acc[i], &t1) |*t, *hi| {
                    const split = power2Round(t.*);
                    t.* = split.low_plus_q;
                    hi.* = split.high;
                }
                packT1(&t1, pk[32 + t1_bytes * i ..][0..t1_bytes]);
                var t0_owner: Secret([t0_bytes]u8) = .init(undefined);
                defer t0_owner.deinit();
                const t0 = t0_owner.exposeMut();
                packT0(&acc[i], t0);
                t0_matches = t0_matches.@"and"(aegis.secret.equal(t0_bytes, t0, sk[sk_t0 + t0_bytes * i ..][0..t0_bytes]));
            }
            var tr: [64]u8 = undefined;
            Shake256.hash(pk, &tr, .{});
            const tr_matches = aegis.secret.equal(64, &tr, sk[sk_tr..][0..64]);
            if (!t0_matches.@"and"(tr_matches).declassify("a private key that is not its own is refused whole")) return error.InvalidKey;
        }

        /// Whether every packed s1 and s2 coefficient is within [-eta, eta]: the packed value
        /// is at most 2 eta. A refusal only says the key is malformed.
        fn etaInRange(bytes: []const u8) bool {
            @setRuntimeSafety(true);
            var bad: u32 = 0;
            if (eta == 2) {
                var i: usize = 0;
                while (i < bytes.len) : (i += 3) {
                    const v = @as(u32, bytes[i]) | @as(u32, bytes[i + 1]) << 8 | @as(u32, bytes[i + 2]) << 16;
                    for (0..8) |c| bad |= over(v >> @intCast(3 * c) & 7, 2 * eta);
                }
            } else {
                for (bytes) |b| bad |= over(b & 15, 2 * eta) | over(b >> 4, 2 * eta);
            }
            return bad == 0;
        }

        /// ML-DSA.Sign (FIPS 204 Algorithm 2, pure, with a context of at most 255 bytes) with an
        /// expanded private key `publicKey` has checked. `noise` is 32 fresh bytes (hedged), or
        /// zeros for the deterministic variant.
        pub fn sign(sk: *const [secret_key_length]u8, message: []const u8, context: []const u8, noise: *const [noise_length]u8, sig: *[signature_length]u8) void {
            @setRuntimeSafety(true);
            aegis.assert.pre(context.len <= 255, "an ML-DSA context is at most 255 bytes");
            const rho = sk[sk_rho..][0..32];
            var mu: [64]u8 = undefined;
            messageHash(sk[sk_tr..][0..64], message, context, &mu);
            var rho2_owner: Secret([64]u8) = .init(undefined);
            defer rho2_owner.deinit();
            const rho2 = rho2_owner.exposeMut();
            {
                var h = Shake256.init(.{});
                h.update(sk[sk_key..][0..32]);
                h.update(noise);
                h.update(&mu);
                h.squeeze(rho2);
            }
            // w and then w0, one polynomial per row; w1 packed as it is hashed.
            var w_owner: Secret([k]Poly) = .init(undefined);
            defer w_owner.deinit();
            const w = w_owner.exposeMut();
            var w1_owner: Secret([k * w1_bytes]u8) = .init(undefined);
            defer w1_owner.deinit();
            const w1 = w1_owner.exposeMut();
            var hints_owner: Secret([k][n / 64]u64) = .init(undefined);
            defer hints_owner.deinit();
            const hints = hints_owner.exposeMut();
            var y_owner: Secret(Poly) = .init(undefined);
            defer y_owner.deinit();
            const y = y_owner.exposeMut();
            var s_owner: Secret(Poly) = .init(undefined);
            defer s_owner.deinit();
            const s = s_owner.exposeMut();
            var a: Poly = undefined;
            var c: Poly = undefined;
            var kappa: u16 = 0;
            // (6/7)^576 < 2^-128 for every level: a key that rejects this often is not a key.
            for (0..1000) |_| {
                defer kappa += @intCast(l);
                for (w) |*p| p.* = @splat(0);
                for (0..l) |j| {
                    expandMask(y, rho2, kappa + @as(u16, @intCast(j)));
                    ntt(y);
                    for (0..k) |i| {
                        expandA(&a, rho, i, j);
                        mulAdd(&w[i], &a, y);
                    }
                }
                var h = Shake256.init(.{});
                h.update(&mu);
                for (0..k) |i| {
                    reduceLe2q(&w[i]);
                    invNtt(&w[i]);
                    normalize(&w[i]);
                    var hi: Poly = undefined;
                    for (&w[i], &hi) |*wc, *hc| {
                        const parts = decompose(wc.*);
                        wc.* = parts.low_plus_q;
                        hc.* = parts.high;
                    }
                    packW1(&hi, w1[w1_bytes * i ..][0..w1_bytes]);
                }
                h.update(w1);
                h.squeeze(sig[0..ctilde]);
                sampleInBall(&c, sig[0..ctilde]);
                ntt(&c);
                // z = y + c s1, packed as it goes; any coefficient past gamma1 - beta rejects.
                var reject: u32 = 0;
                for (0..l) |j| {
                    unpackEta(sk[sk_s1 + eta_bytes * j ..][0..eta_bytes], s);
                    ntt(s);
                    mulPoint(s, &c);
                    invNtt(s);
                    expandMask(y, rho2, kappa + @as(u16, @intCast(j)));
                    for (s, y) |*z, yc| z.* = modQ(z.* +% yc);
                    reject |= exceeds(s, gamma1 - beta);
                    packZ(s, sig[ctilde + z_bytes * j ..][0..z_bytes]);
                }
                if (reject != 0) continue;
                // r0 = w0 - c s2 within gamma2 - beta; then c t0 within gamma2, and the hints.
                var count: u32 = 0;
                for (0..k) |i| {
                    unpackEta(sk[sk_s2 + eta_bytes * i ..][0..eta_bytes], s);
                    ntt(s);
                    mulPoint(s, &c);
                    invNtt(s);
                    for (&w[i], s) |*r, cs| r.* = modQ(r.* +% (2 * q -% cs));
                    reject |= exceeds(&w[i], gamma2 - beta);
                    unpackT0(sk[sk_t0 + t0_bytes * i ..][0..t0_bytes], s);
                    ntt(s);
                    mulPoint(s, &c);
                    invNtt(s);
                    normalize(s);
                    reject |= exceeds(s, gamma2);
                    hints[i] = @splat(0);
                    for (0..n) |m| {
                        const z0 = modQ(w[i][m] +% s[m]);
                        const bit = makeHint(z0, w1Coefficient(w1, i, m));
                        hints[i][m / 64] |= @as(u64, bit) << @intCast(m % 64);
                        count += bit;
                    }
                }
                reject |= over(count, omega);
                if (reject != 0) continue;
                // Accepted: the hints are part of the signature from here on.
                packHints(hints, sig[ctilde + z_bytes * l ..][0 .. omega + k]);
                return;
            }
            // safe: the loop ends with probability below 2^-128 per signature.
            aegis.assert.invariant(false, "ML-DSA signing ends within its rejection bound");
        }

        pub const VerifyError = error{InvalidSignature};

        /// ML-DSA.Verify (FIPS 204 Algorithm 3, pure, with a context of at most 255 bytes).
        pub fn verify(pk: *const [public_key_length]u8, message: []const u8, context: []const u8, sig: *const [signature_length]u8) VerifyError!void {
            @setRuntimeSafety(true);
            if (context.len > 255) return error.InvalidSignature;
            if (!hintsValid(sig[ctilde + z_bytes * l ..][0 .. omega + k])) return error.InvalidSignature;
            const rho = pk[0..32];
            var tr: [64]u8 = undefined;
            Shake256.hash(pk, &tr, .{});
            var mu: [64]u8 = undefined;
            messageHash(&tr, message, context, &mu);
            var c: Poly = undefined;
            sampleInBall(&c, sig[0..ctilde]);
            ntt(&c);
            var acc: [k]Poly = undefined;
            for (&acc) |*p| p.* = @splat(0);
            var z: Poly = undefined;
            var a: Poly = undefined;
            for (0..l) |j| {
                unpackZ(sig[ctilde + z_bytes * j ..][0..z_bytes], &z);
                if (exceeds(&z, gamma1 - beta) != 0) return error.InvalidSignature;
                ntt(&z);
                for (0..k) |i| {
                    expandA(&a, rho, i, j);
                    mulAdd(&acc[i], &a, &z);
                }
            }
            var h = Shake256.init(.{});
            h.update(&mu);
            const hint_bytes = sig[ctilde + z_bytes * l ..][0 .. omega + k];
            for (0..k) |i| {
                // w' = A z - c t1 2^d, then the hints recover w1.
                unpackT1(pk[32 + t1_bytes * i ..][0..t1_bytes], &a);
                for (&a) |*t| t.* <<= d;
                ntt(&a);
                mulPoint(&a, &c);
                for (&acc[i], a) |*w, ct| w.* = w.* +% (2 * q -% ct);
                reduceLe2q(&acc[i]);
                invNtt(&acc[i]);
                normalizeLe2q(&acc[i]);
                const first: usize = if (i == 0) 0 else hint_bytes[omega + i - 1];
                const last: usize = hint_bytes[omega + i];
                var hint_at = first;
                var hi: Poly = undefined;
                for (&acc[i], &hi, 0..) |wc, *out, m| {
                    const hint: u32 = if (hint_at < last and hint_bytes[hint_at] == m) 1 else 0;
                    hint_at += hint;
                    out.* = useHint(wc, hint);
                }
                var packed_w1: [w1_bytes]u8 = undefined;
                packW1(&hi, &packed_w1);
                h.update(&packed_w1);
            }
            var expected: [ctilde]u8 = undefined;
            h.squeeze(&expected);
            if (!std.mem.eql(u8, &expected, sig[0..ctilde])) return error.InvalidSignature;
        }

        /// HintBitUnpack's checks (FIPS 204 Algorithm 21): each row's end at or after the
        /// last and at most omega, indices strictly increasing within a row, zeros after.
        fn hintsValid(bytes: *const [omega + k]u8) bool {
            var index: usize = 0;
            for (0..k) |i| {
                const end = bytes[omega + i];
                if (end < index or end > omega) return false;
                const first = index;
                while (index < end) : (index += 1) {
                    if (index > first and bytes[index - 1] >= bytes[index]) return false;
                }
            }
            for (bytes[index..omega]) |b| if (b != 0) return false;
            return true;
        }

        fn packHints(hints: *const [k][n / 64]u64, out: *[omega + k]u8) void {
            @memset(out, 0);
            var index: usize = 0;
            for (hints, 0..) |row, i| {
                for (0..n) |m| {
                    if (row[m / 64] >> @intCast(m % 64) & 1 != 0) {
                        out[index] = @intCast(m);
                        index += 1;
                    }
                }
                out[omega + i] = @intCast(index);
            }
        }

        fn decompose(a: u32) @TypeOf(decomposeWith(gamma2, 0)) {
            return decomposeWith(gamma2, a);
        }

        fn exceeds(p: *const Poly, bound: u32) u32 {
            return exceedsWith(p, bound);
        }

        /// MakeHint, branch-free: one unless z0 (w0 - c s2 + c t0, in [0, q)) keeps w's high
        /// bits r1: z0 <= gamma2, or z0 > q - gamma2, or z0 == q - gamma2 with r1 zero.
        fn makeHint(z0: u32, r1: u32) u32 {
            const keeps = (over(z0, gamma2) ^ 1) | over(z0, q - gamma2) | (isZero(z0 ^ (q - gamma2)) & isZero(r1));
            return keeps ^ 1;
        }

        /// UseHint (FIPS 204 Algorithm 40), on public values.
        fn useHint(r: u32, hint: u32) u32 {
            const parts = decompose(r);
            if (hint == 0) return parts.high;
            const up = parts.low_plus_q > q;
            if (gamma2 == (q - 1) / 32) return (if (up) parts.high + 1 else parts.high -% 1) & 15;
            if (up) return if (parts.high == 43) 0 else parts.high + 1;
            return if (parts.high == 0) 43 else parts.high - 1;
        }

        fn w1Coefficient(w1: *const [k * w1_bytes]u8, i: usize, m: usize) u32 {
            const row = w1[w1_bytes * i ..][0..w1_bytes];
            if (level == .mldsa44) {
                // Six bits each, four coefficients in three bytes.
                const at = m / 4 * 3;
                const v = @as(u32, row[at]) | @as(u32, row[at + 1]) << 8 | @as(u32, row[at + 2]) << 16;
                return v >> @intCast(6 * (m % 4)) & 63;
            }
            return row[m / 2] >> @intCast(4 * (m % 2)) & 15;
        }

        fn expandMask(p: *Poly, seed: *const [64]u8, nonce: u16) void {
            @setRuntimeSafety(true);
            var buf_owner: Secret([z_bytes]u8) = .init(undefined);
            defer buf_owner.deinit();
            const buf = buf_owner.exposeMut();
            var h = Shake256.init(.{});
            h.update(seed);
            h.update(&.{ @truncate(nonce), @truncate(nonce >> 8) });
            h.squeeze(buf);
            unpackZ(buf, p);
        }

        fn expandS(p: *Poly, seed: *const [64]u8, nonce: u16) void {
            @setRuntimeSafety(true);
            var buf_owner: Secret([Shake256.block_length]u8) = .init(undefined);
            defer buf_owner.deinit();
            const buf = buf_owner.exposeMut();
            var h = Shake256.init(.{});
            h.update(seed);
            h.update(&.{ @truncate(nonce), @truncate(nonce >> 8) });
            var i: usize = 0;
            while (i < n) {
                h.squeeze(buf);
                for (buf) |b| {
                    inline for (.{ b & 15, b >> 4 }) |t| {
                        // RejBoundedPoly: a nibble is kept below 15 (eta 2, then mod 5) or 9.
                        if (i < n and t < (if (eta == 2) 15 else 9)) {
                            const r: u32 = if (eta == 2) t - (@as(u32, t) * 205 >> 10) * 5 else t;
                            p[i] = q + eta - r;
                            i += 1;
                        }
                    }
                }
            }
        }

        fn sampleInBall(p: *Poly, seed: []const u8) void {
            @setRuntimeSafety(true);
            p.* = @splat(0);
            var buf: [Shake256.block_length]u8 = undefined;
            var h = Shake256.init(.{});
            h.update(seed);
            h.squeeze(&buf);
            var signs = std.mem.readInt(u64, buf[0..8], .little);
            var at: usize = 8;
            var i: usize = n - tau;
            while (i < n) : (i += 1) {
                var b: usize = undefined;
                while (true) {
                    if (at == buf.len) {
                        h.squeeze(&buf);
                        at = 0;
                    }
                    b = buf[at];
                    at += 1;
                    if (b <= i) break;
                }
                p[i] = p[b];
                p[b] = if (signs & 1 != 0) q - 1 else 1;
                signs >>= 1;
            }
        }

        fn packZ(p: *const Poly, out: *[z_bytes]u8) void {
            if (gamma1_bits == 17) {
                var j: usize = 0;
                var i: usize = 0;
                while (i < out.len) : (i += 9) {
                    const p0 = centered(p[j]);
                    const p1 = centered(p[j + 1]);
                    const p2 = centered(p[j + 2]);
                    const p3 = centered(p[j + 3]);
                    out[i] = @truncate(p0);
                    out[i + 1] = @truncate(p0 >> 8);
                    out[i + 2] = @truncate(p0 >> 16 | p1 << 2);
                    out[i + 3] = @truncate(p1 >> 6);
                    out[i + 4] = @truncate(p1 >> 14 | p2 << 4);
                    out[i + 5] = @truncate(p2 >> 4);
                    out[i + 6] = @truncate(p2 >> 12 | p3 << 6);
                    out[i + 7] = @truncate(p3 >> 2);
                    out[i + 8] = @truncate(p3 >> 10);
                    j += 4;
                }
            } else {
                var j: usize = 0;
                var i: usize = 0;
                while (i < out.len) : (i += 5) {
                    const p0 = centered(p[j]);
                    const p1 = centered(p[j + 1]);
                    out[i] = @truncate(p0);
                    out[i + 1] = @truncate(p0 >> 8);
                    out[i + 2] = @truncate(p0 >> 16 | p1 << 4);
                    out[i + 3] = @truncate(p1 >> 4);
                    out[i + 4] = @truncate(p1 >> 12);
                    j += 2;
                }
            }
        }

        fn unpackZ(bytes: *const [z_bytes]u8, p: *Poly) void {
            if (gamma1_bits == 17) {
                var j: usize = 0;
                var i: usize = 0;
                while (i < bytes.len) : (i += 9) {
                    const b = bytes[i..][0..9];
                    p[j] = centered(@as(u32, b[0]) | @as(u32, b[1]) << 8 | (@as(u32, b[2]) & 0x3) << 16);
                    p[j + 1] = centered(@as(u32, b[2]) >> 2 | @as(u32, b[3]) << 6 | (@as(u32, b[4]) & 0xf) << 14);
                    p[j + 2] = centered(@as(u32, b[4]) >> 4 | @as(u32, b[5]) << 4 | (@as(u32, b[6]) & 0x3f) << 12);
                    p[j + 3] = centered(@as(u32, b[6]) >> 6 | @as(u32, b[7]) << 2 | @as(u32, b[8]) << 10);
                    j += 4;
                }
            } else {
                var j: usize = 0;
                var i: usize = 0;
                while (i < bytes.len) : (i += 5) {
                    const b = bytes[i..][0..5];
                    p[j] = centered(@as(u32, b[0]) | @as(u32, b[1]) << 8 | (@as(u32, b[2]) & 0xf) << 16);
                    p[j + 1] = centered(@as(u32, b[2]) >> 4 | @as(u32, b[3]) << 4 | @as(u32, b[4]) << 12);
                    j += 2;
                }
            }
        }

        /// gamma1 - v mod q: between a packed value in [0, 2 gamma1) and a coefficient.
        fn centered(v: u32) u32 {
            const r = gamma1 -% v;
            return r +% (signMask(r) & q);
        }

        fn packW1(p: *const Poly, out: *[w1_bytes]u8) void {
            if (level == .mldsa44) {
                var j: usize = 0;
                var i: usize = 0;
                while (i < out.len) : (i += 3) {
                    out[i] = @truncate(p[j] | p[j + 1] << 6);
                    out[i + 1] = @truncate(p[j + 1] >> 2 | p[j + 2] << 4);
                    out[i + 2] = @truncate(p[j + 2] >> 4 | p[j + 3] << 2);
                    j += 4;
                }
            } else {
                for (out, 0..) |*b, i| b.* = @truncate(p[2 * i] | p[2 * i + 1] << 4);
            }
        }

        fn packEta(p: *const Poly, out: *[eta_bytes]u8) void {
            if (eta == 2) {
                var j: usize = 0;
                var i: usize = 0;
                while (i < out.len) : (i += 3) {
                    var c: [8]u32 = undefined;
                    for (&c, 0..) |*v, m| v.* = q + eta -% p[j + m];
                    out[i] = @truncate(c[0] | c[1] << 3 | c[2] << 6);
                    out[i + 1] = @truncate(c[2] >> 2 | c[3] << 1 | c[4] << 4 | c[5] << 7);
                    out[i + 2] = @truncate(c[5] >> 1 | c[6] << 2 | c[7] << 5);
                    j += 8;
                }
            } else {
                for (out, 0..) |*b, i| b.* = @truncate((q + eta -% p[2 * i]) | (q + eta -% p[2 * i + 1]) << 4);
            }
        }

        fn unpackEta(bytes: *const [eta_bytes]u8, p: *Poly) void {
            if (eta == 2) {
                var j: usize = 0;
                var i: usize = 0;
                while (i < bytes.len) : (i += 3) {
                    const v = @as(u32, bytes[i]) | @as(u32, bytes[i + 1]) << 8 | @as(u32, bytes[i + 2]) << 16;
                    for (0..8) |m| p[j + m] = q + eta - (v >> @intCast(3 * m) & 7);
                    j += 8;
                }
            } else {
                for (bytes, 0..) |b, i| {
                    p[2 * i] = q + eta - (b & 15);
                    p[2 * i + 1] = q + eta - (b >> 4);
                }
            }
        }
    };
}

/// The message representative mu = H(tr || 0 || |ctx| || ctx || M, 64) of pure ML-DSA.
fn messageHash(tr: *const [64]u8, message: []const u8, context: []const u8, mu: *[64]u8) void {
    var h = Shake256.init(.{});
    h.update(tr);
    h.update(&.{ 0, @intCast(context.len) });
    h.update(context);
    h.update(message);
    h.squeeze(mu);
}

/// RejNTTPoly over rho || column || row: the matrix entry at (row, column), public.
fn expandA(p: *Poly, rho: *const [32]u8, row: usize, column: usize) void {
    var h = Shake128.init(.{});
    h.update(rho);
    h.update(&.{ @intCast(column), @intCast(row) });
    var buf: [Shake128.block_length]u8 = undefined;
    var i: usize = 0;
    while (i < n) {
        h.squeeze(&buf);
        var j: usize = 0;
        while (j < buf.len and i < n) : (j += 3) {
            const t = (@as(u32, buf[j]) | @as(u32, buf[j + 1]) << 8 | @as(u32, buf[j + 2]) << 16) & 0x7fffff;
            if (t < q) {
                p[i] = t;
                i += 1;
            }
        }
    }
}

fn packT1(p: *const Poly, out: *[320]u8) void {
    var j: usize = 0;
    var i: usize = 0;
    while (i < out.len) : (i += 5) {
        out[i] = @truncate(p[j]);
        out[i + 1] = @truncate(p[j] >> 8 | p[j + 1] << 2);
        out[i + 2] = @truncate(p[j + 1] >> 6 | p[j + 2] << 4);
        out[i + 3] = @truncate(p[j + 2] >> 4 | p[j + 3] << 6);
        out[i + 4] = @truncate(p[j + 3] >> 2);
        j += 4;
    }
}

fn unpackT1(bytes: *const [320]u8, p: *Poly) void {
    var j: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 5) {
        const b = bytes[i..][0..5];
        p[j] = (@as(u32, b[0]) | @as(u32, b[1]) << 8) & 0x3ff;
        p[j + 1] = (@as(u32, b[1]) >> 2 | @as(u32, b[2]) << 6) & 0x3ff;
        p[j + 2] = (@as(u32, b[2]) >> 4 | @as(u32, b[3]) << 4) & 0x3ff;
        p[j + 3] = (@as(u32, b[3]) >> 6 | @as(u32, b[4]) << 2) & 0x3ff;
        j += 4;
    }
}

/// t0 in (-2^12, 2^12], kept as t0 + q, packed as 2^12 - t0 in thirteen bits.
fn packT0(p: *const Poly, out: *[416]u8) void {
    const bound: u32 = 1 << (d - 1);
    var j: usize = 0;
    var i: usize = 0;
    while (i < out.len) : (i += 13) {
        var c: [8]u32 = undefined;
        for (&c, 0..) |*v, m| v.* = q + bound -% p[j + m];
        out[i] = @truncate(c[0]);
        out[i + 1] = @truncate(c[0] >> 8 | c[1] << 5);
        out[i + 2] = @truncate(c[1] >> 3);
        out[i + 3] = @truncate(c[1] >> 11 | c[2] << 2);
        out[i + 4] = @truncate(c[2] >> 6 | c[3] << 7);
        out[i + 5] = @truncate(c[3] >> 1);
        out[i + 6] = @truncate(c[3] >> 9 | c[4] << 4);
        out[i + 7] = @truncate(c[4] >> 4);
        out[i + 8] = @truncate(c[4] >> 12 | c[5] << 1);
        out[i + 9] = @truncate(c[5] >> 7 | c[6] << 6);
        out[i + 10] = @truncate(c[6] >> 2);
        out[i + 11] = @truncate(c[6] >> 10 | c[7] << 3);
        out[i + 12] = @truncate(c[7] >> 5);
        j += 8;
    }
}

fn unpackT0(bytes: *const [416]u8, p: *Poly) void {
    const bound: u32 = 1 << (d - 1);
    var j: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) : (i += 13) {
        const b = bytes[i..][0..13];
        p[j] = q + bound - ((@as(u32, b[0]) | @as(u32, b[1]) << 8) & 0x1fff);
        p[j + 1] = q + bound - ((@as(u32, b[1]) >> 5 | @as(u32, b[2]) << 3 | @as(u32, b[3]) << 11) & 0x1fff);
        p[j + 2] = q + bound - ((@as(u32, b[3]) >> 2 | @as(u32, b[4]) << 6) & 0x1fff);
        p[j + 3] = q + bound - ((@as(u32, b[4]) >> 7 | @as(u32, b[5]) << 1 | @as(u32, b[6]) << 9) & 0x1fff);
        p[j + 4] = q + bound - ((@as(u32, b[6]) >> 4 | @as(u32, b[7]) << 4 | @as(u32, b[8]) << 12) & 0x1fff);
        p[j + 5] = q + bound - ((@as(u32, b[8]) >> 1 | @as(u32, b[9]) << 7) & 0x1fff);
        p[j + 6] = q + bound - ((@as(u32, b[9]) >> 6 | @as(u32, b[10]) << 2 | @as(u32, b[11]) << 10) & 0x1fff);
        p[j + 7] = q + bound - ((@as(u32, b[11]) >> 3 | @as(u32, b[12]) << 5) & 0x1fff);
        j += 8;
    }
}

// ---------------------------------------------------------------- arithmetic

/// All ones when the top bit of `x` is set, zero otherwise.
fn signMask(x: u32) u32 {
    return @bitCast(@as(i32, @bitCast(x)) >> 31);
}

/// One when x is zero, for x below 2^31, without a branch.
fn isZero(x: u32) u32 {
    return ((x | (0 -% x)) >> 31) ^ 1;
}

/// One when x > bound, both below 2^31, without a branch.
fn over(x: u32, bound: u32) u32 {
    return (bound -% x) >> 31;
}

/// Below 2q, congruent mod q.
fn le2q(x: u32) u32 {
    const high = x >> 23;
    const low = x & 0x7fffff;
    return low +% (high << 13) -% high;
}

/// Below q, from below 2q.
fn le2qModQ(x: u32) u32 {
    const r = x -% q;
    return r +% (signMask(r) & q);
}

fn modQ(x: u32) u32 {
    return le2qModQ(le2q(x));
}

/// x R^-1 mod q, below 2q, for x below q 2^32.
fn montReduce(x: u64) u32 {
    const m = (x *% q_inv) & 0xffffffff;
    return @truncate((x +% m * q) >> 32);
}

fn reduceLe2q(p: *Poly) void {
    for (p) |*c| c.* = le2q(c.*);
}

fn normalize(p: *Poly) void {
    for (p) |*c| c.* = modQ(c.*);
}

fn normalizeLe2q(p: *Poly) void {
    for (p) |*c| c.* = le2qModQ(c.*);
}

/// acc += a * b, pointwise in the NTT domain (each product below 2q).
fn mulAdd(acc: *Poly, a: *const Poly, b: *const Poly) void {
    for (acc, a, b) |*r, x, y| r.* +%= montReduce(@as(u64, x) * y);
}

/// a = a * b pointwise in the NTT domain.
fn mulPoint(a: *Poly, b: *const Poly) void {
    for (a, b) |*x, y| x.* = montReduce(@as(u64, x.*) * y);
}

const zetas = computeZetas(false);
const inv_zetas = computeZetas(true);

fn computeZetas(comptime inverse: bool) [n]u32 {
    @setEvalBranchQuota(1_000_000);
    var out: [n]u32 = undefined;
    const r_mod_q: u64 = (@as(u64, 1) << 32) % q;
    const inv_zeta = powMod(zeta, q - 2);
    for (0..n) |i| {
        const power = if (inverse) powMod(inv_zeta, 256 - @as(u64, @bitReverse(@as(u8, @intCast(255 - i))))) else powMod(zeta, @bitReverse(@as(u8, @intCast(i))));
        out[i] = @intCast(power * r_mod_q % q);
    }
    return out;
}

fn powMod(base: u64, exponent: u64) u64 {
    var result: u64 = 1;
    var b = base % q;
    var e = exponent;
    while (e != 0) : (e >>= 1) {
        if (e & 1 != 0) result = result * b % q;
        b = b * b % q;
    }
    return result;
}

/// Forward NTT; inputs below about 9q, as std's.
fn ntt(p: *Poly) void {
    var k: usize = 0;
    var len: usize = n / 2;
    while (len > 0) : (len >>= 1) {
        var offset: usize = 0;
        while (offset < n - len) : (offset += 2 * len) {
            k += 1;
            const z: u64 = zetas[k];
            for (offset..offset + len) |j| {
                const t = montReduce(z * p[j + len]);
                p[j + len] = p[j] +% (2 * q -% t);
                p[j] +%= t;
            }
        }
    }
}

/// Inverse NTT with the 256^-1 R scaling; inputs below 2q, outputs below 2q.
fn invNtt(p: *Poly) void {
    var k: usize = 0;
    var len: usize = 1;
    while (len < n) : (len <<= 1) {
        var offset: usize = 0;
        while (offset < n - len) : (offset += 2 * len) {
            const z: u64 = inv_zetas[k];
            k += 1;
            for (offset..offset + len) |j| {
                const t = p[j];
                p[j] = t +% p[j + len];
                p[j + len] = montReduce(z * (t +% 256 * q -% p[j + len]));
            }
        }
    }
    for (p) |*c| c.* = montReduce(@as(u64, r_over_256) * c.*);
}

/// Power2Round (FIPS 204 Algorithm 35) for 0 <= a < q: a = high 2^d + low.
fn power2Round(a: u32) struct { low_plus_q: u32, high: u32 } {
    var low = a & ((1 << d) - 1);
    low -%= (1 << (d - 1)) + 1;
    low +%= signMask(low) & (1 << d);
    low -%= (1 << (d - 1)) - 1;
    return .{ .low_plus_q = q +% low, .high = (a -% low) >> d };
}

/// Decompose (FIPS 204 Algorithm 36) for 0 <= a < q, branch-free: high in [0, (q-1)/2gamma2)
/// and low + q, low in (-gamma2, gamma2] (or [-gamma2, 0) at the wrap).
fn decomposeWith(comptime gamma2: u32, a: u32) struct { low_plus_q: u32, high: u32 } {
    var high = (a + 127) >> 7;
    if (gamma2 == (q - 1) / 32) {
        high = (high * 1025 + (1 << 21)) >> 22;
        high &= 15;
    } else {
        high = (high * 11275 + (1 << 23)) >> 24;
        high ^= signMask(43 -% high) & high;
    }
    var low = a -% high * 2 * gamma2;
    low +%= signMask(low -% (q - 1) / 2) & q;
    return .{ .low_plus_q = low, .high = high };
}

fn exceedsWith(p: *const Poly, bound: u32) u32 {
    var result: u32 = 0;
    for (p) |c| {
        // |c mod± q| from c in [0, q), without a branch on its sign.
        const x: i32 = @as(i32, (q - 1) / 2) - @as(i32, @intCast(c));
        const magnitude = x ^ (x >> 31);
        const norm: u32 = @intCast(@as(i32, (q - 1) / 2) - magnitude);
        result |= over(norm +% 1, bound);
    }
    return result;
}
