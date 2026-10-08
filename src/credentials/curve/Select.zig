//! A value barrier prevents LLVM from turning secret masks into carry branches.
const std = @import("std");
const builtin = @import("builtin");
pub inline fn mask(choice: u1) u64 {
    @setRuntimeSafety(true);
    var value = 0 -% @as(u64, choice);
    defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&value));
    if (@inComptime()) return value;
    switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => {
            // The empty tied-register asm preserves bits; its output is opaque to LLVM.
            asm volatile (""
                : [value] "+r" (value),
            );
            return value;
        },
        else => {
            // Other backends get a lawful live owned volatile slot, wiped before return.
            const slot: *volatile u64 = &value;
            const result = slot.*;
            slot.* = 0;
            return result;
        },
    }
}
