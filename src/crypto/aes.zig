//! How deep std's AES reaches: the stack a kernel running it must erase, for JOSE's
//! constructions (`cipher.zig`). The record kernels (`tls/crypto/Kernels.zig`) build in a module
//! of their own and keep their copy; a test holds the two equal.
const std = @import("std");
const builtin = @import("builtin");

/// The stack a record or mask kernel reaches, with room (under 2 KiB optimized): every record
/// pays for this scrub, so it is the records' own.
pub const record_depth = if (builtin.mode == .debug) 32 * 1024 else 4 * 1024;
/// The stack an AES kernel reaches where std runs AES in software (x86_64 without AES-NI and
/// AVX, AArch64 without its AES instructions), with room: the software rounds keep the key
/// schedule and their tables in std's frames, about 19 KiB optimized and 88 KiB in Debug on
/// x86_64 (AES-256-GCM the deepest).
pub const software_depth = if (builtin.mode == .debug) 128 * 1024 else 32 * 1024;

/// What a kernel running std's AES erases.
pub fn depth() usize {
    return if (std.crypto.core.aes.has_hardware_support) record_depth else software_depth;
}
