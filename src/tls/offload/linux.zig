//! The Linux kernel record layer (kTLS): a connection's keys installed on a connected TCP
//! socket (the "tls" upper-layer protocol, then SOL_TLS TLS_TX or TLS_RX), the kernel's record
//! counts read back, and a probe of what the running kernel takes. The control messages that
//! carry record types (TLS_SET_RECORD_TYPE on send, TLS_GET_RECORD_TYPE on receive) are the
//! caller's I/O, as are sendfile and the wait for new read keys.
//!
//! Capabilities are what the kernel does, not what its version says: `probe` installs keys on a
//! loopback connection and reports which versions, ciphers and directions it takes, and whether
//! it takes a TLS 1.3 key update (Linux 6.14 added it; before, a second install is EBUSY).
const std = @import("std");
const builtin = @import("builtin");
const aegis = @import("aegis");
const Keys = @import("Keys.zig");

const linux = std.os.linux;
/// The probe's sockets are made, accepted and closed through the C library where one is
/// linked, as std's are, so that what keeps a record of each descriptor there sees them:
/// ThreadSanitizer forgets a descriptor only at a close it sees, and one closed past it
/// and reused by another thread reads as a race. Without one they are the kernel's calls.
const descriptors = if (builtin.link_libc) std.c else linux;

/// SOL_TLS and its options (include/uapi/linux/tls.h).
pub const sol_tls = linux.SOL.TLS;
pub const tls_tx = 1;
pub const tls_rx = 2;
/// The most plaintext a record the kernel sends carries (Linux 6.18; RFC 8449's limit, less TLS
/// 1.3's content type).
pub const tls_tx_max_payload_len = 5;
/// The control message types, at level `sol_tls`, that carry a record's type.
pub const set_record_type = 1;
pub const get_record_type = 2;

const tls_1_2_version: u16 = 0x0303;
const tls_1_3_version: u16 = 0x0304;

fn cipherType(cipher: Keys.Cipher) u16 {
    return switch (cipher) {
        .aes_128_gcm => 51,
        .aes_256_gcm => 52,
        .aes_128_ccm => 53,
        .chacha20_poly1305 => 54,
    };
}

/// Where each field of the uAPI's `tls12_crypto_info_*` lies, for one cipher: after the four
/// bytes of version and cipher type, the IV, the key, the salt and the record number.
const Layout = struct {
    iv: usize,
    key: usize,
    salt: usize,
    sequence: usize,
    len: usize,

    fn of(cipher: Keys.Cipher) Layout {
        const iv_len: usize = if (cipher == .chacha20_poly1305) 12 else 8;
        const salt_len: usize = if (cipher == .chacha20_poly1305) 0 else 4;
        const key = 4 + iv_len;
        const salt = key + cipher.keyLength();
        return .{ .iv = 4, .key = key, .salt = salt, .sequence = salt + salt_len, .len = salt + salt_len + 8 };
    }
};

/// The bytes the kernel takes for one direction's keys: the uAPI struct for the cipher.
pub const CryptoInfo = struct {
    bytes: aegis.Secret([56]u8),
    len: u8,

    /// TLS 1.3, and TLS 1.2 GCM and CCM: the IV's first four bytes are the salt and the last
    /// eight the IV (the static IV's tail, or TLS 1.2's next explicit nonce). ChaCha20-Poly1305
    /// takes all twelve as the IV.
    pub fn encode(keys: *const Keys) CryptoInfo {
        @setRuntimeSafety(true);
        const layout = Layout.of(keys.cipher);
        var out: CryptoInfo = .{ .bytes = .init(@splat(0)), .len = @intCast(layout.len) };
        const b = out.bytes.exposeMut();
        std.mem.writeInt(u16, b[0..2], if (keys.version == .tls13) tls_1_3_version else tls_1_2_version, builtin.cpu.arch.endian());
        std.mem.writeInt(u16, b[2..4], cipherType(keys.cipher), builtin.cpu.arch.endian());
        const iv = keys.iv.expose();
        if (keys.cipher == .chacha20_poly1305) {
            b[layout.iv..][0..12].* = iv.*;
        } else {
            b[layout.iv..][0..8].* = iv[4..12].*;
            b[layout.salt..][0..4].* = iv[0..4].*;
        }
        @memcpy(b[layout.key..][0..keys.cipher.keyLength()], keys.keyBytes());
        std.mem.writeInt(u64, b[layout.sequence..][0..8], keys.sequence, .big);
        return out;
    }

    pub fn slice(self: *const CryptoInfo) []const u8 {
        return self.bytes.expose()[0..self.len];
    }

    pub fn deinit(self: *CryptoInfo) void {
        self.bytes.deinit();
        self.* = undefined;
    }
};

fn optionOf(direction: Keys.Direction) u32 {
    return switch (direction) {
        .read => tls_rx,
        .write => tls_tx,
    };
}

/// A connected TCP socket a connection's directions move to.
pub const Socket = struct {
    fd: linux.fd_t,
    /// What `Connection.offload` installs through.
    installer: Keys.Installer = .{ .installFn = installKeys },

    fn installKeys(installer: *Keys.Installer, direction: Keys.Direction, keys: *const Keys) Keys.InstallError!void {
        const self: *Socket = @fieldParentPtr("installer", installer);
        return self.install(direction, keys);
    }

    /// Gives the kernel `direction`'s keys: attaches the "tls" upper-layer protocol if the
    /// socket has none yet, then installs. A second install of a direction is a TLS 1.3 key
    /// update, which kernels before 6.14 refuse (`RekeyUnsupported`).
    pub fn install(self: Socket, direction: Keys.Direction, keys: *const Keys) Keys.InstallError!void {
        @setRuntimeSafety(true);
        try self.attach();
        if (keys.max_payload) |payload| try self.limitPayload(payload);
        var info = CryptoInfo.encode(keys);
        defer info.deinit();
        const bytes = info.slice();
        // The struct is at most 56 bytes.
        const rc = linux.setsockopt(self.fd, sol_tls, optionOf(direction), bytes.ptr, @intCast(bytes.len));
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .BUSY => error.RekeyUnsupported,
            .NOMEM, .NOBUFS => error.OutOfMemory,
            .BADF, .NOTSOCK, .NOTCONN => error.InvalidSocket,
            else => error.Unsupported,
        };
    }

    /// Holds the records the kernel will send to `payload` plaintext bytes, before it has their
    /// keys: a kernel without the option refuses, and the keys stay in software.
    fn limitPayload(self: Socket, payload: u16) Keys.InstallError!void {
        @setRuntimeSafety(true);
        const value: u16 = payload;
        const rc = linux.setsockopt(self.fd, sol_tls, tls_tx_max_payload_len, std.mem.asBytes(&value), @sizeOf(u16));
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOMEM, .NOBUFS => error.OutOfMemory,
            .BADF, .NOTSOCK, .NOTCONN => error.InvalidSocket,
            else => error.Unsupported,
        };
    }

    fn attach(self: Socket) Keys.InstallError!void {
        @setRuntimeSafety(true);
        const rc = linux.setsockopt(self.fd, linux.IPPROTO.TCP, linux.TCP.ULP, "tls", 3);
        return switch (linux.errno(rc)) {
            // EEXIST: the socket has it from the other direction's install.
            .SUCCESS, .EXIST => {},
            .NOMEM, .NOBUFS => error.OutOfMemory,
            .BADF, .NOTSOCK, .NOTCONN => error.InvalidSocket,
            else => error.Unsupported,
        };
    }

    pub const RecordsError = error{ Unsupported, InvalidSocket };

    /// The kernel's count of records in `direction` under its current keys: the number of the
    /// next one, for `Connection.offloadRecords`.
    pub fn records(self: Socket, direction: Keys.Direction) RecordsError!u64 {
        @setRuntimeSafety(true);
        // The kernel answers only a buffer of its struct's exact size: the version and cipher
        // first, then the whole crypto state, keys included, which is erased once read.
        var head: [4]u8 = undefined;
        var head_len: linux.socklen_t = head.len;
        try sockopt(linux.getsockopt(self.fd, sol_tls, optionOf(direction), &head, &head_len));
        const cipher: Keys.Cipher = switch (std.mem.readInt(u16, head[2..4], builtin.cpu.arch.endian())) {
            51 => .aes_128_gcm,
            52 => .aes_256_gcm,
            53 => .aes_128_ccm,
            54 => .chacha20_poly1305,
            else => return error.Unsupported,
        };
        const layout = Layout.of(cipher);
        var state = aegis.Secret([56]u8).init(@splat(0));
        defer state.deinit();
        // The struct is at most 56 bytes.
        var len: linux.socklen_t = @intCast(layout.len);
        try sockopt(linux.getsockopt(self.fd, sol_tls, optionOf(direction), state.exposeMut(), &len));
        if (len != layout.len) return error.Unsupported;
        return std.mem.readInt(u64, state.expose()[layout.sequence..][0..8], .big);
    }

    fn sockopt(rc: usize) RecordsError!void {
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
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
/// Nothing is sent. A kernel without the "tls" module, or a process that may not open sockets,
/// takes nothing.
pub fn probe() Capabilities {
    @setRuntimeSafety(true);
    var result: Capabilities = .{};
    const listener = Listener.open() catch return result;
    defer listener.close();
    for ([_]Keys.Version{ .tls12, .tls13 }) |version| {
        for (std.enums.values(Keys.Cipher)) |cipher| {
            var pair = listener.pair() catch return result;
            defer pair.close();
            var socket: Socket = .{ .fd = pair.client };
            for ([_]Keys.Direction{ .read, .write }) |direction| {
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
    fd: linux.fd_t,
    address: linux.sockaddr.in,

    fn open() !Listener {
        const fd = try openSocket();
        errdefer _ = descriptors.close(fd);
        var address: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
        const any: *linux.sockaddr = @ptrCast(&address); // aegis: boundary: sockaddr.in begins with the family, as every sockaddr does
        try check(linux.bind(fd, any, @sizeOf(linux.sockaddr.in)));
        try check(linux.listen(fd, 4));
        var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        try check(linux.getsockname(fd, any, &len));
        return .{ .fd = fd, .address = address };
    }

    fn close(self: Listener) void {
        _ = descriptors.close(self.fd);
    }

    const Pair = struct {
        client: linux.fd_t,
        server: linux.fd_t,

        fn close(self: Pair) void {
            _ = descriptors.close(self.client);
            _ = descriptors.close(self.server);
        }
    };

    fn pair(self: *const Listener) !Pair {
        const client = try openSocket();
        errdefer _ = descriptors.close(client);
        try check(linux.connect(client, &self.address, @sizeOf(linux.sockaddr.in)));
        const server = try descriptor(descriptors.accept4(self.fd, null, null, linux.SOCK.CLOEXEC));
        return .{ .client = client, .server = server };
    }
};

fn openSocket() error{ProbeFailed}!linux.fd_t {
    return descriptor(descriptors.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0));
}

/// The descriptor a `descriptors` call made: the kernel's return or the C library's.
fn descriptor(rc: anytype) error{ProbeFailed}!linux.fd_t {
    if (@TypeOf(rc) == usize) {
        try check(rc);
        return @intCast(rc); // a successful call returns a descriptor
    }
    if (rc < 0) return error.ProbeFailed;
    return rc;
}

fn check(rc: usize) error{ProbeFailed}!void {
    if (linux.errno(rc) != .SUCCESS) return error.ProbeFailed;
}
