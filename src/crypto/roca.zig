//! The ROCA fingerprint (CVE-2017-15361; Nemec, Sys, Svenda, Klinec, Matyas, "The Return of
//! Coppersmith's Attack", ACM CCS 2017): Infineon's RSA library made each prime as
//! k * M + (65537^a mod M), M the product of the first primes, so anyone factors the modulus
//! from the public key alone. Such a modulus is 65537^c modulo each of those primes; a random
//! one is that with probability below 2^-150 over the primes up to 167. This is the published
//! detector's moduli test (crocs-muni/roca, `has_fingerprint_moduli`), its masks derived here
//! from their definition and checked against the published ones in the test.

/// The primes the published detector tests: 3 to 167.
pub const primes = [_]u8{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167 };

/// For each prime p, bit r set when r is a power of 65537 modulo p: the residues a fingerprinted
/// modulus can have.
pub const masks: [primes.len]u256 = blk: {
    @setEvalBranchQuota(10_000);
    var out: [primes.len]u256 = undefined;
    for (primes, &out) |p, *mask| {
        mask.* = 0;
        var r: u16 = 1;
        while (true) {
            mask.* |= @as(u256, 1) << r;
            r = @intCast((@as(u32, r) * (65537 % @as(u32, p))) % p);
            if (r == 1) break;
        }
    }
    break :blk out;
};

/// Whether a modulus (unsigned big-endian bytes, public) has the fingerprint: a key anyone can
/// factor, never to be trusted or used.
pub fn fingerprinted(modulus: []const u8) bool {
    @setRuntimeSafety(true);
    for (primes, masks) |p, mask| {
        var r: u32 = 0;
        for (modulus) |byte| r = (r * 256 + byte) % p;
        if ((mask >> @intCast(r)) & 1 == 0) return false;
    }
    return true;
}

test {
    _ = @import("roca_test.zig");
}
