//! Optimized private-decoder inspection without process or hosted I/O.
const Base64 = @import("armor_decode");
pub export fn cloakArmor(out: [*]u8, out_len: usize, text: [*]const u8, text_len: usize) u8 {
    @setRuntimeSafety(true);
    Base64.decode(out[0..out_len], text[0..text_len]) catch return 1;
    return 0;
}
