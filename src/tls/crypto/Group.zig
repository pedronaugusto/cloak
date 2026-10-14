//! Named key-exchange groups and their fixed wire sizes.
pub const Group = enum(u16) {
    x25519 = 29,
    p256 = 23,
    p384 = 24,
    x25519_mlkem768 = 4588,
    /// P-256 and ML-KEM-768, the ECDH value first (draft-ietf-tls-ecdhe-mlkem).
    secp256r1_mlkem768 = 4587,
    /// P-384 and ML-KEM-1024, the ECDH value first.
    secp384r1_mlkem1024 = 4589,

    /// A post-quantum hybrid: an ML-KEM exchange beside an elliptic-curve one.
    pub fn hybrid(group: Group) bool {
        return switch (group) {
            .x25519_mlkem768, .secp256r1_mlkem768, .secp384r1_mlkem1024 => true,
            .x25519, .p256, .p384 => false,
        };
    }

    /// Bytes of a client key_share entry for this group.
    pub fn clientShareLength(group: Group) usize {
        return switch (group) {
            .x25519 => 32,
            .p256 => 65,
            .p384 => 97,
            .x25519_mlkem768 => 1216,
            .secp256r1_mlkem768 => 65 + 1184,
            .secp384r1_mlkem1024 => 97 + 1568,
        };
    }
    /// Bytes of a server key_share entry for this group.
    pub fn serverShareLength(group: Group) usize {
        return switch (group) {
            .x25519 => 32,
            .p256 => 65,
            .p384 => 97,
            .x25519_mlkem768 => 1120,
            .secp256r1_mlkem768 => 65 + 1088,
            .secp384r1_mlkem1024 => 97 + 1568,
        };
    }
};
