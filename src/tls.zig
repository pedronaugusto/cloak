//! TLS 1.3 and TLS 1.2 for Zig. Connections are sans-I/O; callers drive them with bytes,
//! entropy, time and verification answers.
/// Cipher suites of both versions, by IANA number.
pub const Suite = @import("tls/crypto/Suite.zig").Suite;
/// Protocol versions.
pub const Version = @import("tls/crypto/Suite.zig").Version;
/// Key-exchange groups.
pub const Group = @import("tls/crypto/Group.zig").Group;
/// Signature schemes a signing request names.
pub const SignatureScheme = @import("tls/handshake/Hello.zig").SignatureScheme;
/// Alert descriptions.
pub const Alert = @import("tls/wire/Alert.zig").Alert;
/// A certificate chain a server can present, with the names it answers for.
pub const Credential = @import("tls/handshake/Server.zig").Credential;
/// Whether a server asks for a client certificate.
pub const ClientCertificate = @import("tls/handshake/Server.zig").Auth;
/// A sans-I/O connection, client or server.
pub const Connection = @import("tls/Connection.zig");
/// The record-free handshake for QUIC.
pub const quic = @import("tls/quic.zig");
/// DTLS 1.3 and 1.2: the handshake over datagrams.
pub const dtls = @import("tls/dtls.zig");
/// A client's cache of session tickets for resumption.
pub const SessionCache = @import("tls/resumption.zig").SessionCache;
/// A server's session-ticket keys.
pub const TicketKeys = @import("tls/resumption.zig").TicketKeys;
/// Encrypted Client Hello (RFC 9849): what a client is given and what a server holds. A client
/// takes the server's ECHConfigList (from its HTTPS record; finding it is the caller's) as
/// `Mode.config_list`, or sends GREASE. A server holds `Key`s: each an ECHConfig and the X25519
/// secret of its public key, made with `keyPair` and `writeConfig`.
pub const ech = struct {
    const Ech = @import("tls/handshake/Ech.zig");
    const Hpke = @import("tls/crypto/Hpke.zig");
    pub const Mode = Ech.Mode;
    pub const Key = Ech.Key;
    pub const ConfigSpec = Ech.ConfigSpec;
    pub const Suite = Hpke.Suite;
    pub const Kdf = Hpke.Kdf;
    pub const Aead = Hpke.Aead;
    pub const KeyPair = Hpke.KeyPair;
    pub const max_keys = Ech.max_keys;
    pub const writeConfig = Ech.writeConfig;
    pub const writeList = Ech.writeList;
    pub const checkList = Ech.checkList;

    /// An X25519 key pair for a config, derived from 32 or more bytes of fresh secret input
    /// (RFC 9180 DeriveKeyPair).
    pub fn keyPair(ikm: []const u8) KeyPair {
        return Hpke.deriveKeyPair(ikm);
    }
};
/// Certificate compression (RFC 8879) through codecs the caller supplies: a client offers its
/// decoders, a server compresses with its encoders. cloak holds no codec.
pub const certificate_compression = struct {
    const Compression = @import("tls/handshake/Compression.zig");
    pub const Codec = Compression.Codec;
    pub const Algorithm = Compression.Algorithm;
    pub const Error = Compression.Error;
    pub const max_codecs = Compression.max_codecs;
};
/// Provisioned (external) PSKs, PSK-DHE only: a client's key and a server's lookup.
pub const psk = struct {
    const Psk = @import("tls/handshake/Psk.zig");
    pub const External = Psk.External;
    pub const Lookup = Psk.Lookup;
    pub const Query = Psk.Query;
    pub const Hash = Psk.Hash;
    pub const max_identity = Psk.max_identity;
};
/// Kernel record layers (kTLS): after the handshake a connection's direction moves to the kernel,
/// which seals or opens its records (`Connection.offload`); the connection keeps the rest.
pub const offload = struct {
    pub const Keys = @import("tls/offload/Keys.zig");
    pub const Cipher = Keys.Cipher;
    pub const Direction = Keys.Direction;
    pub const Installer = Keys.Installer;
    pub const InstallError = Keys.InstallError;
    /// Linux's: keys installed on a TCP socket, record counts read back, the kernel probed.
    pub const linux = if (@import("builtin").os.tag == .linux) @import("tls/offload/linux.zig") else struct {};
};
/// A client stream over `std.Io` readers and writers.
pub const Session = @import("tls/Session.zig");
test {
    _ = @import("tls/record.zig");
    _ = @import("tls/resumption.zig");
    _ = @import("tls/catalogue_test.zig");
    _ = @import("tls/Tls12_test.zig");
    _ = @import("tls/Ccm_test.zig");
    _ = @import("tls/catalogue12_test.zig");
    _ = @import("tls/Resumption_test.zig");
    _ = @import("tls/Ech_test.zig");
    _ = @import("tls/CertificateCompression_test.zig");
    _ = @import("tls/Pq_test.zig");
    _ = @import("tls/Psk_test.zig");
    _ = @import("tls/CodePoints_test.zig");
    _ = @import("tls/Timing_test.zig");
    _ = @import("tls/wire.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("tls/crypto.zig");
    _ = Connection;
    _ = Session;
    _ = quic;
    _ = dtls;
    _ = @import("tls/offload.zig");
}
