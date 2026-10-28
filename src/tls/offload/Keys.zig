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
            // Linux has no CCM with an 8-byte tag: it stays in software.
            .aes_128_ccm_8 => null,
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
/// The write direction's first install: the most plaintext a record the kernel seals may carry,
/// when the peer named a record_size_limit below the version's maximum (RFC 8449); null for
/// 2^14 bytes. The kernel must take it before the keys, or the keys stay here.
max_payload: ?u16 = null,

/// What a kernel that cannot count the records it seals reports to `offloadRecords` for the
/// `bytes` of plaintext it has been handed under the current keys, whatever its framing:
/// ceil(2n / 1025) full-size records. A record of k ≥ 1 bytes costs at most 2k of the AEAD
/// bound's blocks and records (σ + q), a full-size record at least 1025 (design C9.1).
pub fn equivalentRecords(bytes: u64) u64 {
    const cost = 2 * @as(u128, bytes);
    // safe: (2^65 + 1024) / 1025 is below 2^64.
    return @intCast((cost + 1024) / 1025);
}

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
/// or as a key update. On an error the kernel holds none of them, and on success all. `rekeys`
/// says whether the kernel takes a direction's keys again, as a TLS 1.3 key update: the
/// kernel's own answer (its probe), never a caller's guess, since a connection that sends a
/// KeyUpdate its kernel cannot follow ends in a truncated stream. It is a field of the kernel's
/// own type, which `installFn` and `rekeysFn` recover with `@fieldParentPtr`.
pub const Installer = struct {
    installFn: *const fn (installer: *Installer, direction: Direction, keys: *const Keys) InstallError!void,
    rekeysFn: *const fn (installer: *Installer, direction: Direction) bool,

    pub fn install(self: *Installer, direction: Direction, keys: *const Keys) InstallError!void {
        return self.installFn(self, direction, keys);
    }

    pub fn rekeys(self: *Installer, direction: Direction) bool {
        return self.rekeysFn(self, direction);
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
