//! The ARMv8 Cryptography Extensions' SHA-1 instructions (sha1h, sha1c, sha1p, sha1m, sha1su0,
//! sha1su1), each on registers alone, no memory: the raw instructions std does not declare,
//! which `sha1.zig`'s compression calls. A seam of glint.json's (P007).

/// Four 32-bit words in one vector register.
pub const V = @Vector(4, u32);

pub fn h(e: u32) u32 {
    return asm ("sha1h %[out:s], %[in:s]"
        : [out] "=w" (-> u32),
        : [in] "w" (e),
    );
}
pub fn c(abcd: V, e: u32, wk: V) V {
    return asm ("sha1c %[x:q], %[e:s], %[w].4s"
        : [x] "=w" (-> V),
        : [_] "0" (abcd),
          [e] "w" (e),
          [w] "w" (wk),
    );
}
pub fn p(abcd: V, e: u32, wk: V) V {
    return asm ("sha1p %[x:q], %[e:s], %[w].4s"
        : [x] "=w" (-> V),
        : [_] "0" (abcd),
          [e] "w" (e),
          [w] "w" (wk),
    );
}
pub fn m(abcd: V, e: u32, wk: V) V {
    return asm ("sha1m %[x:q], %[e:s], %[w].4s"
        : [x] "=w" (-> V),
        : [_] "0" (abcd),
          [e] "w" (e),
          [w] "w" (wk),
    );
}
pub fn su0(a: V, b: V, c_: V) V {
    return asm ("sha1su0 %[a].4s, %[b].4s, %[c].4s"
        : [a] "=w" (-> V),
        : [_] "0" (a),
          [b] "w" (b),
          [c] "w" (c_),
    );
}
pub fn su1(a: V, b: V) V {
    return asm ("sha1su1 %[a].4s, %[b].4s"
        : [a] "=w" (-> V),
        : [_] "0" (a),
          [b] "w" (b),
    );
}
