//! The optimization barrier the constant-time selections rest on: an empty asm that ties a value
//! to a register, which std does not declare. A seam of glint.json's (P007).
const builtin = @import("builtin");

/// Hides a mask from the optimizer so a selection stays a selection and never becomes a branch.
pub inline fn barrier(value: u64) u64 {
    var v = value;
    if (@inComptime()) return v;
    switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => asm volatile (""
            : [v] "+r" (v),
        ),
        else => {
            const slot: *volatile u64 = &v;
            return slot.*;
        },
    }
    return v;
}
