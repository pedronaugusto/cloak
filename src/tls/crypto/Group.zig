//! Named key-exchange groups and their fixed wire sizes.
pub const Group = enum(u16) {
    x25519 = 29,
    p256 = 23,
    p384 = 24,
    x25519_mlkem768 = 4588,

    /// Bytes of a client key_share entry for this group.
    pub fn clientShareLength(group: Group) usize {
        return switch (group) {
            .x25519 => 32,
            .p256 => 65,
            .p384 => 97,
            .x25519_mlkem768 => 1216,
        };
    }
    /// Bytes of a server key_share entry for this group.
    pub fn serverShareLength(group: Group) usize {
        return switch (group) {
            .x25519 => 32,
            .p256 => 65,
            .p384 => 97,
            .x25519_mlkem768 => 1120,
        };
    }
};
