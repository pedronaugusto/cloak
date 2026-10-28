//! The FreeBSD kernel record layer (ktls(4), FreeBSD 13 and later): a connection's keys
//! installed on a connected TCP socket (IPPROTO_TCP TCP_TXTLS_ENABLE or TCP_RXTLS_ENABLE, a
//! `struct tls_enable`), and a probe of what the running kernel takes. The control messages
//! that carry record types (TLS_SET_RECORD_TYPE on send, TLS_GET_RECORD on every record
//! received) are the caller's I/O, as are sendfile and counting records (design C9.1): the
//! kernel reads no count back, so the read direction counts one per `recvmsg` and the write
//! direction reports `Keys.equivalentRecords` of the bytes it has handed over.
//!
//! Keys go in once per direction: FreeBSD has no TLS 1.3 key update, and a second install is
//! EALREADY (`RekeyUnsupported`). It has no CCM, and no per-connection limit on a record's
//! plaintext, so a peer's record_size_limit keeps the write direction in software.
const std = @import("std");
const Keys = @import("Keys.zig");

const c = std.c;

/// IPPROTO_TCP options (sys/netinet/tcp.h).
pub const tcp_txtls_enable = 39;
pub const tcp_rxtls_enable = 41;
/// The control message types, at level IPPROTO_TCP, that carry a record's type.
pub const set_record_type = 1;
pub const get_record_type = 2;

/// The cipher identifiers ktls takes (sys/opencrypto/cryptodev.h).
const crypto_aes_nist_gcm_16 = 25;
const crypto_chacha20_poly1305 = 41;

/// `struct tls_enable` (sys/sys/ktls.h): the keys by pointer, the cipher, the version's two
/// bytes and the next record's number.
pub const TlsEnable = extern struct {
    cipher_key: [*]const u8,
    /// The implicit IV: TLS 1.2 GCM's four-byte salt, or all twelve bytes.
    iv: [*]const u8,
    auth_key: ?[*]const u8 = null,
    cipher_algorithm: c_int,
    cipher_key_len: c_int,
    iv_len: c_int,
    auth_algorithm: c_int = 0,
    auth_key_len: c_int = 0,
    flags: c_int = 0,
    tls_vmajor: u8 = 3,
    tls_vminor: u8,
    /// Big-endian.
    rec_seq: [8]u8,

    /// The struct for `keys`, pointing into them: valid while they are. Null for a cipher
    /// FreeBSD has no kernel cipher for.
    pub fn of(keys: *const Keys) ?TlsEnable {
        const algorithm: c_int = switch (keys.cipher) {
            .aes_128_gcm, .aes_256_gcm => crypto_aes_nist_gcm_16,
            .chacha20_poly1305 => crypto_chacha20_poly1305,
            .aes_128_ccm => return null,
        };
        // TLS 1.2 GCM's IV is its salt; FreeBSD makes the explicit nonce itself.
        const iv_len: c_int = if (keys.version == .tls12 and keys.cipher != .chacha20_poly1305) 4 else 12;
        var sequence: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence, keys.sequence, .big);
        return .{
            .cipher_key = keys.keyBytes().ptr,
            .iv = keys.iv.expose(),
            .cipher_algorithm = algorithm,
            .cipher_key_len = @intCast(keys.cipher.keyLength()), // safe: 16 or 32
            .iv_len = iv_len,
            .tls_vminor = if (keys.version == .tls13) 4 else 3,
            .rec_seq = sequence,
        };
    }
};

fn optionOf(direction: Keys.Direction) u32 {
    return switch (direction) {
        .read => tcp_rxtls_enable,
        .write => tcp_txtls_enable,
    };
}

/// A connected TCP socket a connection's directions move to.
pub const Socket = struct {
    fd: c.fd_t,
    /// What `Connection.offload` installs through.
    installer: Keys.Installer = .{ .installFn = installKeys, .rekeysFn = never },

    /// FreeBSD takes a direction's keys once.
    fn never(_: *Keys.Installer, _: Keys.Direction) bool {
        return false;
    }

    fn installKeys(installer: *Keys.Installer, direction: Keys.Direction, keys: *const Keys) Keys.InstallError!void {
        const self: *Socket = @fieldParentPtr("installer", installer);
        return self.install(direction, keys);
    }

    /// Gives the kernel `direction`'s keys. A second install of a direction is refused
    /// (`RekeyUnsupported`): FreeBSD takes keys once.
    pub fn install(self: Socket, direction: Keys.Direction, keys: *const Keys) Keys.InstallError!void {
        @setRuntimeSafety(true);
        // No per-connection record size: the kernel frames kern.ipc.tls.maxlen bytes.
        if (keys.max_payload != null) return error.Unsupported;
        const enable = TlsEnable.of(keys) orelse return error.Unsupported;
        const rc = c.setsockopt(self.fd, c.IPPROTO.TCP, optionOf(direction), &enable, @sizeOf(TlsEnable));
        return switch (c.errno(rc)) {
            .SUCCESS => {},
            .ALREADY => error.RekeyUnsupported,
            .NOMEM, .NOBUFS => error.OutOfMemory,
            .BADF, .NOTSOCK, .NOTCONN => error.InvalidSocket,
            else => error.Unsupported,
        };
    }
};

/// What the running kernel's record layer takes.
pub const Capabilities = struct {
    /// Per version (TLS 1.2, TLS 1.3) and direction (read, write): the ciphers it installs.
    ciphers: [2][2]std.EnumSet(Keys.Cipher) = @splat(@splat(.empty)),
    /// Per direction: whether it takes a TLS 1.3 key update.
    rekey: [2]bool = .{ false, false },

    pub fn supports(self: Capabilities, version: Keys.Version, cipher: Keys.Cipher, direction: Keys.Direction) bool {
        return self.ciphers[@intFromBool(version == .tls13)][@backingInt(direction)].contains(cipher);
    }

    pub fn rekeys(self: Capabilities, direction: Keys.Direction) bool {
        return self.rekey[@backingInt(direction)];
    }
};

/// Probes the running kernel on loopback TCP connections: every version, cipher and direction
/// installed once with throwaway keys, and for TLS 1.3 installed again, as a key update would.
/// Nothing is sent. A kernel without ktls, one with `kern.ipc.tls.enable` or
/// `kern.ipc.tls.rx_enable` off, or a process that may not open sockets, takes what it takes.
pub fn probe() Capabilities {
    @setRuntimeSafety(true);
    var result: Capabilities = .{};
    const listener = Listener.open() catch return result;
    defer listener.close();
    for ([_]Keys.Version{ .tls12, .tls13 }) |version| {
        for (std.enums.values(Keys.Cipher)) |cipher| {
            // One connection a direction: a refused install leaves nothing behind, but an
            // accepted one is the socket's for good.
            for ([_]Keys.Direction{ .read, .write }) |direction| {
                var pair = listener.pair() catch return result;
                defer pair.close();
                const socket: Socket = .{ .fd = pair.client };
                var keys: Keys = .{ .version = version, .cipher = cipher, .key = .init(@splat(0)), .iv = .init(@splat(0)), .sequence = 0 };
                defer keys.deinit();
                socket.install(direction, &keys) catch continue;
                result.ciphers[@intFromBool(version == .tls13)][@backingInt(direction)].insert(cipher);
                if (version == .tls13) {
                    if (socket.install(direction, &keys)) |_| {
                        result.rekey[@backingInt(direction)] = true;
                    } else |_| {}
                }
            }
        }
    }
    return result;
}

/// A loopback listener for the probe's connections.
const Listener = struct {
    fd: c.fd_t,
    address: c.sockaddr.in,

    fn open() error{ProbeFailed}!Listener {
        const fd = try openSocket();
        errdefer _ = c.close(fd);
        var address: c.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        const any: *c.sockaddr = @ptrCast(&address); // aegis: boundary: sockaddr.in begins with the length and family, as every sockaddr does
        try check(c.bind(fd, any, @sizeOf(c.sockaddr.in)));
        try check(c.listen(fd, 4));
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        try check(c.getsockname(fd, any, &len));
        return .{ .fd = fd, .address = address };
    }

    fn close(self: Listener) void {
        _ = c.close(self.fd);
    }

    const Pair = struct {
        client: c.fd_t,
        server: c.fd_t,

        fn close(self: Pair) void {
            _ = c.close(self.client);
            _ = c.close(self.server);
        }
    };

    fn pair(self: *const Listener) error{ProbeFailed}!Pair {
        const client = try openSocket();
        errdefer _ = c.close(client);
        const any: *const c.sockaddr = @ptrCast(&self.address); // aegis: boundary: sockaddr.in begins with the length and family, as every sockaddr does
        try check(c.connect(client, any, @sizeOf(c.sockaddr.in)));
        const server = c.accept4(self.fd, null, null, c.SOCK.CLOEXEC);
        if (server < 0) return error.ProbeFailed;
        return .{ .client = client, .server = server };
    }
};

fn openSocket() error{ProbeFailed}!c.fd_t {
    const fd = c.socket(c.AF.INET, c.SOCK.STREAM | c.SOCK.CLOEXEC, 0);
    if (fd < 0) return error.ProbeFailed;
    return fd;
}

fn check(rc: c_int) error{ProbeFailed}!void {
    if (c.errno(rc) != .SUCCESS) return error.ProbeFailed;
}

comptime {
    // The C struct on a 64-bit FreeBSD: three pointers, six ints, two bytes and eight, padded.
    if (@sizeOf(usize) == 8) std.debug.assert(@sizeOf(TlsEnable) == 64);
}
