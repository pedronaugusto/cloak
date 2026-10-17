//! One direction's record keys on their way from a connection to a kernel's record layer (kTLS):
//! the cipher, its key and IV, and the number of the next record. Only the handshake's own
//! keys travel; a connection hands them out once per epoch and erases its copy when the kernel
//! holds them.
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");

pub const Version = suites.Version;

/// The record ciphers a kernel record layer takes. AES-256-CCM has no kernel cipher, so its
/// suites stay in software.
pub const Cipher = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    aes_128_ccm,

    /// The kernel cipher for a record cipher, if there is one.
    pub fn of(cipher: suites.Cipher) ?Cipher {
        return switch (cipher) {
            .aes_128_gcm => .aes_128_gcm,
            .aes_256_gcm => .aes_256_gcm,
            .chacha20_poly1305 => .chacha20_poly1305,
            .aes_128_ccm => .aes_128_ccm,
            .aes_256_ccm => null,
        };
    }

    pub fn keyLength(cipher: Cipher) usize {
        return switch (cipher) {
            .aes_128_gcm, .aes_128_ccm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    /// The record cipher it is.
    pub fn record(cipher: Cipher) suites.Cipher {
        return switch (cipher) {
            inline else => |tag| @field(suites.Cipher, @tagName(tag)),
        };
    }
};

pub const Direction = enum { read, write };

const Keys = @This();

version: Version,
cipher: Cipher,
/// The first `cipher.keyLength()` bytes are the key.
key: aegis.Secret([32]u8),
/// TLS 1.3: the static IV the record number is mixed into. TLS 1.2: the key block's fixed IV
/// (four bytes for GCM and CCM, twelve for ChaCha20-Poly1305), and for GCM and CCM the explicit
/// nonce of the next record after it, which is that record's number.
iv: aegis.Secret([12]u8),
/// The number of the next record in this direction.
sequence: u64,

pub fn keyBytes(self: *const Keys) []const u8 {
    return self.key.expose()[0..self.cipher.keyLength()];
}

/// Erases the key and IV.
pub fn deinit(self: *Keys) void {
    self.key.deinit();
    self.iv.deinit();
    self.* = undefined;
}

/// What carries keys to a kernel: `install` gives the kernel a direction's keys, the first time
/// or as a key update. On an error the kernel holds none of them, and on success all.
pub const Installer = struct {
    context: *anyopaque,
    installFn: *const fn (context: *anyopaque, direction: Direction, keys: *const Keys) InstallError!void,

    pub fn install(self: Installer, direction: Direction, keys: *const Keys) InstallError!void {
        return self.installFn(self.context, direction, keys);
    }
};

pub const InstallError = error{
    /// The kernel has no record layer for this version, cipher or direction, or none for this
    /// socket.
    Unsupported,
    /// The kernel holds this direction's keys and takes no replacement: it has no TLS 1.3 key
    /// update.
    RekeyUnsupported,
    /// The descriptor is not a connected TCP socket.
    InvalidSocket,
    OutOfMemory,
};
