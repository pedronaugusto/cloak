//! The P-256 field (p = 2^256 - 2^224 + 2^192 + 2^96 - 1) on AArch64: Montgomery multiplication,
//! squaring, addition and subtraction in inline assembly. The reduction uses the shape of p (its
//! Montgomery factor is the low limb itself, and q * p needs only shifts); the final subtraction
//! of p selects with `csel`, which does not branch. Each function equals its portable twin in
//! `Montgomery.zig` for every input below p (tested).

pub const Limbs = [4]u64;

pub inline fn mul(a: Limbs, b: Limbs) Limbs {
    var c0: u64 = undefined;
    var c1: u64 = undefined;
    var c2: u64 = undefined;
    var c3: u64 = undefined;
    var c4: u64 = undefined;
    var l0: u64 = undefined;
    var l1: u64 = undefined;
    var l2: u64 = undefined;
    var l3: u64 = undefined;
    var h0: u64 = undefined;
    var h1: u64 = undefined;
    var h2: u64 = undefined;
    var h3: u64 = undefined;
    asm (
        \\ mul   %[c0], %[a0], %[b0]
        \\ umulh %[h0], %[a0], %[b0]
        \\ mul   %[c1], %[a0], %[b1]
        \\ umulh %[h1], %[a0], %[b1]
        \\ mul   %[c2], %[a0], %[b2]
        \\ umulh %[h2], %[a0], %[b2]
        \\ mul   %[c3], %[a0], %[b3]
        \\ umulh %[h3], %[a0], %[b3]
        \\ adds  %[c1], %[c1], %[h0]
        \\ adcs  %[c2], %[c2], %[h1]
        \\ adcs  %[c3], %[c3], %[h2]
        \\ adc   %[c4], %[h3], xzr
        // reduce q = c0
        \\ lsl   %[l0], %[c0], #32
        \\ lsr   %[l1], %[c0], #32
        \\ subs  %[l2], %[c0], %[l0]
        \\ sbc   %[l3], %[c0], %[l1]
        \\ adds  %[c0], %[c1], %[l0]
        \\ adcs  %[c1], %[c2], %[l1]
        \\ adcs  %[c2], %[c3], %[l2]
        \\ adcs  %[c3], %[c4], %[l3]
        \\ adc   %[c4], xzr, xzr
        // i = 1
        \\ mul   %[l0], %[a1], %[b0]
        \\ mul   %[l1], %[a1], %[b1]
        \\ mul   %[l2], %[a1], %[b2]
        \\ mul   %[l3], %[a1], %[b3]
        \\ umulh %[h0], %[a1], %[b0]
        \\ umulh %[h1], %[a1], %[b1]
        \\ umulh %[h2], %[a1], %[b2]
        \\ umulh %[h3], %[a1], %[b3]
        \\ adds  %[c0], %[c0], %[l0]
        \\ adcs  %[c1], %[c1], %[l1]
        \\ adcs  %[c2], %[c2], %[l2]
        \\ adcs  %[c3], %[c3], %[l3]
        \\ adc   %[c4], %[c4], xzr
        \\ adds  %[c1], %[c1], %[h0]
        \\ adcs  %[c2], %[c2], %[h1]
        \\ adcs  %[c3], %[c3], %[h2]
        \\ adc   %[c4], %[c4], %[h3]
        \\ lsl   %[l0], %[c0], #32
        \\ lsr   %[l1], %[c0], #32
        \\ subs  %[l2], %[c0], %[l0]
        \\ sbc   %[l3], %[c0], %[l1]
        \\ adds  %[c0], %[c1], %[l0]
        \\ adcs  %[c1], %[c2], %[l1]
        \\ adcs  %[c2], %[c3], %[l2]
        \\ adcs  %[c3], %[c4], %[l3]
        \\ adc   %[c4], xzr, xzr
        // i = 2
        \\ mul   %[l0], %[a2], %[b0]
        \\ mul   %[l1], %[a2], %[b1]
        \\ mul   %[l2], %[a2], %[b2]
        \\ mul   %[l3], %[a2], %[b3]
        \\ umulh %[h0], %[a2], %[b0]
        \\ umulh %[h1], %[a2], %[b1]
        \\ umulh %[h2], %[a2], %[b2]
        \\ umulh %[h3], %[a2], %[b3]
        \\ adds  %[c0], %[c0], %[l0]
        \\ adcs  %[c1], %[c1], %[l1]
        \\ adcs  %[c2], %[c2], %[l2]
        \\ adcs  %[c3], %[c3], %[l3]
        \\ adc   %[c4], %[c4], xzr
        \\ adds  %[c1], %[c1], %[h0]
        \\ adcs  %[c2], %[c2], %[h1]
        \\ adcs  %[c3], %[c3], %[h2]
        \\ adc   %[c4], %[c4], %[h3]
        \\ lsl   %[l0], %[c0], #32
        \\ lsr   %[l1], %[c0], #32
        \\ subs  %[l2], %[c0], %[l0]
        \\ sbc   %[l3], %[c0], %[l1]
        \\ adds  %[c0], %[c1], %[l0]
        \\ adcs  %[c1], %[c2], %[l1]
        \\ adcs  %[c2], %[c3], %[l2]
        \\ adcs  %[c3], %[c4], %[l3]
        \\ adc   %[c4], xzr, xzr
        // i = 3
        \\ mul   %[l0], %[a3], %[b0]
        \\ mul   %[l1], %[a3], %[b1]
        \\ mul   %[l2], %[a3], %[b2]
        \\ mul   %[l3], %[a3], %[b3]
        \\ umulh %[h0], %[a3], %[b0]
        \\ umulh %[h1], %[a3], %[b1]
        \\ umulh %[h2], %[a3], %[b2]
        \\ umulh %[h3], %[a3], %[b3]
        \\ adds  %[c0], %[c0], %[l0]
        \\ adcs  %[c1], %[c1], %[l1]
        \\ adcs  %[c2], %[c2], %[l2]
        \\ adcs  %[c3], %[c3], %[l3]
        \\ adc   %[c4], %[c4], xzr
        \\ adds  %[c1], %[c1], %[h0]
        \\ adcs  %[c2], %[c2], %[h1]
        \\ adcs  %[c3], %[c3], %[h2]
        \\ adc   %[c4], %[c4], %[h3]
        \\ lsl   %[l0], %[c0], #32
        \\ lsr   %[l1], %[c0], #32
        \\ subs  %[l2], %[c0], %[l0]
        \\ sbc   %[l3], %[c0], %[l1]
        \\ adds  %[c0], %[c1], %[l0]
        \\ adcs  %[c1], %[c2], %[l1]
        \\ adcs  %[c2], %[c3], %[l2]
        \\ adcs  %[c3], %[c4], %[l3]
        \\ adc   %[c4], xzr, xzr
        // final: subtract p if c >= p
        \\ mov   %[h1], #0xffffffff
        \\ mov   %[h3], #-4294967295
        \\ adds  %[l0], %[c0], #1
        \\ sbcs  %[l1], %[c1], %[h1]
        \\ sbcs  %[l2], %[c2], xzr
        \\ sbcs  %[l3], %[c3], %[h3]
        \\ sbcs  xzr, %[c4], xzr
        \\ csel  %[l0], %[c0], %[l0], lo
        \\ csel  %[l1], %[c1], %[l1], lo
        \\ csel  %[l2], %[c2], %[l2], lo
        \\ csel  %[l3], %[c3], %[l3], lo
        : [c0] "=&r" (c0),
          [c1] "=&r" (c1),
          [c2] "=&r" (c2),
          [c3] "=&r" (c3),
          [c4] "=&r" (c4),
          [l0] "=&r" (l0),
          [l1] "=&r" (l1),
          [l2] "=&r" (l2),
          [l3] "=&r" (l3),
          [h0] "=&r" (h0),
          [h1] "=&r" (h1),
          [h2] "=&r" (h2),
          [h3] "=&r" (h3),
        : [a0] "r" (a[0]),
          [a1] "r" (a[1]),
          [a2] "r" (a[2]),
          [a3] "r" (a[3]),
          [b0] "r" (b[0]),
          [b1] "r" (b[1]),
          [b2] "r" (b[2]),
          [b3] "r" (b[3]),
        : .{ .nzcv = true });
    return .{ l0, l1, l2, l3 };
}

pub inline fn sqr(a: Limbs) Limbs {
    var c0: u64 = undefined;
    var c1: u64 = undefined;
    var c2: u64 = undefined;
    var c3: u64 = undefined;
    var c4: u64 = undefined;
    var c5: u64 = undefined;
    var c6: u64 = undefined;
    var c7: u64 = undefined;
    var t0: u64 = undefined;
    var t1: u64 = undefined;
    var t2: u64 = undefined;
    var t3: u64 = undefined;
    asm (
    // cross products: c1..c6 = sum_{i<j} a_i a_j 2^(64(i+j))
        \\ mul   %[c1], %[a1], %[a0]
        \\ umulh %[t1], %[a1], %[a0]
        \\ mul   %[c2], %[a2], %[a0]
        \\ umulh %[t2], %[a2], %[a0]
        \\ mul   %[c3], %[a3], %[a0]
        \\ umulh %[c4], %[a3], %[a0]
        \\ adds  %[c2], %[c2], %[t1]
        \\ mul   %[t0], %[a2], %[a1]
        \\ umulh %[t1], %[a2], %[a1]
        \\ adcs  %[c3], %[c3], %[t2]
        \\ mul   %[t2], %[a3], %[a1]
        \\ umulh %[t3], %[a3], %[a1]
        \\ adc   %[c4], %[c4], xzr
        \\ mul   %[c5], %[a3], %[a2]
        \\ umulh %[c6], %[a3], %[a2]
        // t1:t2 = a2a1 high + a3a1 low; t3 = a3a1 high
        \\ adds  %[t1], %[t1], %[t2]
        \\ adc   %[t2], %[t3], xzr
        \\ adds  %[c3], %[c3], %[t0]
        \\ adcs  %[c4], %[c4], %[t1]
        \\ adcs  %[c5], %[c5], %[t2]
        \\ adc   %[c6], %[c6], xzr
        // double
        \\ adds  %[c1], %[c1], %[c1]
        \\ adcs  %[c2], %[c2], %[c2]
        \\ adcs  %[c3], %[c3], %[c3]
        \\ adcs  %[c4], %[c4], %[c4]
        \\ adcs  %[c5], %[c5], %[c5]
        \\ adcs  %[c6], %[c6], %[c6]
        \\ adc   %[c7], xzr, xzr
        // squares
        \\ mul   %[c0], %[a0], %[a0]
        \\ umulh %[t0], %[a0], %[a0]
        \\ mul   %[t1], %[a1], %[a1]
        \\ umulh %[t2], %[a1], %[a1]
        \\ adds  %[c1], %[c1], %[t0]
        \\ adcs  %[c2], %[c2], %[t1]
        \\ adcs  %[c3], %[c3], %[t2]
        \\ mul   %[t0], %[a2], %[a2]
        \\ umulh %[t1], %[a2], %[a2]
        \\ mul   %[t2], %[a3], %[a3]
        \\ umulh %[t3], %[a3], %[a3]
        \\ adcs  %[c4], %[c4], %[t0]
        \\ adcs  %[c5], %[c5], %[t1]
        \\ adcs  %[c6], %[c6], %[t2]
        \\ adc   %[c7], %[c7], %[t3]
        // four reduction steps on c0..c3 (each result stays below 2^256)
        \\ lsl   %[t0], %[c0], #32
        \\ lsr   %[t1], %[c0], #32
        \\ subs  %[t2], %[c0], %[t0]
        \\ sbc   %[t3], %[c0], %[t1]
        \\ adds  %[c0], %[c1], %[t0]
        \\ adcs  %[c1], %[c2], %[t1]
        \\ adcs  %[c2], %[c3], %[t2]
        \\ adc   %[c3], %[t3], xzr
        \\ lsl   %[t0], %[c0], #32
        \\ lsr   %[t1], %[c0], #32
        \\ subs  %[t2], %[c0], %[t0]
        \\ sbc   %[t3], %[c0], %[t1]
        \\ adds  %[c0], %[c1], %[t0]
        \\ adcs  %[c1], %[c2], %[t1]
        \\ adcs  %[c2], %[c3], %[t2]
        \\ adc   %[c3], %[t3], xzr
        \\ lsl   %[t0], %[c0], #32
        \\ lsr   %[t1], %[c0], #32
        \\ subs  %[t2], %[c0], %[t0]
        \\ sbc   %[t3], %[c0], %[t1]
        \\ adds  %[c0], %[c1], %[t0]
        \\ adcs  %[c1], %[c2], %[t1]
        \\ adcs  %[c2], %[c3], %[t2]
        \\ adc   %[c3], %[t3], xzr
        \\ lsl   %[t0], %[c0], #32
        \\ lsr   %[t1], %[c0], #32
        \\ subs  %[t2], %[c0], %[t0]
        \\ sbc   %[t3], %[c0], %[t1]
        \\ adds  %[c0], %[c1], %[t0]
        \\ adcs  %[c1], %[c2], %[t1]
        \\ adcs  %[c2], %[c3], %[t2]
        \\ adc   %[c3], %[t3], xzr
        // add the high half
        \\ adds  %[c0], %[c0], %[c4]
        \\ adcs  %[c1], %[c1], %[c5]
        \\ adcs  %[c2], %[c2], %[c6]
        \\ adcs  %[c3], %[c3], %[c7]
        \\ adc   %[c4], xzr, xzr
        // final subtraction of p
        \\ mov   %[c5], #0xffffffff
        \\ mov   %[c6], #-4294967295
        \\ adds  %[t0], %[c0], #1
        \\ sbcs  %[t1], %[c1], %[c5]
        \\ sbcs  %[t2], %[c2], xzr
        \\ sbcs  %[t3], %[c3], %[c6]
        \\ sbcs  xzr, %[c4], xzr
        \\ csel  %[t0], %[c0], %[t0], lo
        \\ csel  %[t1], %[c1], %[t1], lo
        \\ csel  %[t2], %[c2], %[t2], lo
        \\ csel  %[t3], %[c3], %[t3], lo
        : [c0] "=&r" (c0),
          [c1] "=&r" (c1),
          [c2] "=&r" (c2),
          [c3] "=&r" (c3),
          [c4] "=&r" (c4),
          [c5] "=&r" (c5),
          [c6] "=&r" (c6),
          [c7] "=&r" (c7),
          [t0] "=&r" (t0),
          [t1] "=&r" (t1),
          [t2] "=&r" (t2),
          [t3] "=&r" (t3),
        : [a0] "r" (a[0]),
          [a1] "r" (a[1]),
          [a2] "r" (a[2]),
          [a3] "r" (a[3]),
        : .{ .nzcv = true });
    return .{ t0, t1, t2, t3 };
}

/// a + b mod p
pub inline fn add(a: Limbs, b: Limbs) Limbs {
    var c0: u64 = undefined;
    var c1: u64 = undefined;
    var c2: u64 = undefined;
    var c3: u64 = undefined;
    var c4: u64 = undefined;
    var t0: u64 = undefined;
    var t1: u64 = undefined;
    var t2: u64 = undefined;
    var t3: u64 = undefined;
    asm (
        \\ adds  %[c0], %[a0], %[b0]
        \\ adcs  %[c1], %[a1], %[b1]
        \\ adcs  %[c2], %[a2], %[b2]
        \\ adcs  %[c3], %[a3], %[b3]
        \\ adc   %[c4], xzr, xzr
        \\ mov   %[t1], #0xffffffff
        \\ mov   %[t3], #-4294967295
        \\ adds  %[t0], %[c0], #1
        \\ sbcs  %[t1], %[c1], %[t1]
        \\ sbcs  %[t2], %[c2], xzr
        \\ sbcs  %[t3], %[c3], %[t3]
        \\ sbcs  xzr, %[c4], xzr
        \\ csel  %[t0], %[c0], %[t0], lo
        \\ csel  %[t1], %[c1], %[t1], lo
        \\ csel  %[t2], %[c2], %[t2], lo
        \\ csel  %[t3], %[c3], %[t3], lo
        : [c0] "=&r" (c0),
          [c1] "=&r" (c1),
          [c2] "=&r" (c2),
          [c3] "=&r" (c3),
          [c4] "=&r" (c4),
          [t0] "=&r" (t0),
          [t1] "=&r" (t1),
          [t2] "=&r" (t2),
          [t3] "=&r" (t3),
        : [a0] "r" (a[0]),
          [a1] "r" (a[1]),
          [a2] "r" (a[2]),
          [a3] "r" (a[3]),
          [b0] "r" (b[0]),
          [b1] "r" (b[1]),
          [b2] "r" (b[2]),
          [b3] "r" (b[3]),
        : .{ .nzcv = true });
    return .{ t0, t1, t2, t3 };
}

/// a - b mod p
pub inline fn sub(a: Limbs, b: Limbs) Limbs {
    var c0: u64 = undefined;
    var c1: u64 = undefined;
    var c2: u64 = undefined;
    var c3: u64 = undefined;
    var t0: u64 = undefined;
    var t1: u64 = undefined;
    var t3: u64 = undefined;
    asm (
        \\ subs  %[c0], %[a0], %[b0]
        \\ sbcs  %[c1], %[a1], %[b1]
        \\ sbcs  %[c2], %[a2], %[b2]
        \\ sbcs  %[c3], %[a3], %[b3]
        // on a borrow add p = (2^64-1, 2^32-1, 0, 0xffffffff00000001); else add 0
        \\ csetm %[t0], lo
        \\ lsr   %[t1], %[t0], #32
        \\ and   %[t3], %[t0], #0xffffffff00000001
        \\ adds  %[c0], %[c0], %[t0]
        \\ adcs  %[c1], %[c1], %[t1]
        \\ adcs  %[c2], %[c2], xzr
        \\ adc   %[c3], %[c3], %[t3]
        : [c0] "=&r" (c0),
          [c1] "=&r" (c1),
          [c2] "=&r" (c2),
          [c3] "=&r" (c3),
          [t0] "=&r" (t0),
          [t1] "=&r" (t1),
          [t3] "=&r" (t3),
        : [a0] "r" (a[0]),
          [a1] "r" (a[1]),
          [a2] "r" (a[2]),
          [a3] "r" (a[3]),
          [b0] "r" (b[0]),
          [b1] "r" (b[1]),
          [b2] "r" (b[2]),
          [b3] "r" (b[3]),
        : .{ .nzcv = true });
    return .{ c0, c1, c2, c3 };
}
